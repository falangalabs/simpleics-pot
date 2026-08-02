"""Deterministic synthetic wet-well process model."""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass

from .register_map import RegisterDefinition, RegisterMap


class ProcessWriteError(ValueError):
    """Raised when a Modbus write is not valid for the process model."""


@dataclass(frozen=True, slots=True)
class WriteTransition:
    """Audit-friendly result of a validated command or setpoint write."""

    key: str
    old_raw: int | bool
    requested_raw: int | bool
    stored_raw: int | bool
    write_effect: str


class WetWellProcess:
    """Small stateful process with delayed actuator feedback and hard bounds."""

    def __init__(self, register_map: RegisterMap | None = None):
        self.register_map = register_map or RegisterMap.load()
        process = self.register_map.document["process"]
        self.capacity_liters = float(process["capacity_liters"])
        self.max_pump_flow_lps = float(process["max_pump_flow_lps"])
        self.nominal_inlet_flow_lps = float(process["nominal_inlet_flow_lps"])
        self.auto_hysteresis_raw = int(process["auto_hysteresis_raw"])
        self.actuator_delay_seconds = float(process["actuator_delay_seconds"])
        self._lock = threading.RLock()
        self.reset()

    def reset(self) -> None:
        """Restore the exact checked-in initial state."""
        with self._lock:
            defaults = {item.key: item.default for item in self.register_map.definitions}
            self.elapsed_seconds = 0.0
            self._level_raw = float(defaults["tank_level_pv"])
            self.level_setpoint = int(defaults["level_setpoint"])
            self.control_mode = int(defaults["control_mode"])
            self.pump_speed_setpoint = int(defaults["pump_speed_setpoint"])
            self.pump_start_count = int(defaults["pump_start_count"])

            self.pump_command = bool(defaults["pump_command"])
            self.inlet_valve_command = bool(defaults["inlet_valve_command"])
            self.alarm_acknowledge = False

            self.pump_feedback = bool(defaults["pump_feedback"])
            self.inlet_valve_feedback = bool(defaults["inlet_valve_feedback"])
            self.pump_fault = bool(defaults["pump_fault"])
            self._pump_target = self.pump_feedback
            self._valve_target = self.inlet_valve_feedback
            self._pump_delay_remaining = 0.0
            self._valve_delay_remaining = 0.0

            self.high_level_alarm = False
            self.low_level_alarm = False
            self.high_alarm_acknowledged = False
            self.low_alarm_acknowledged = False

            self.inlet_flow_raw = int(defaults["inlet_flow_pv"])
            self.outlet_flow_raw = int(defaults["outlet_flow_pv"])
            self.pump_current_raw = int(defaults["pump_current_pv"])
            self.process_temperature_raw = int(defaults["process_temperature_pv"])

    @staticmethod
    def _coerce_write(definition: RegisterDefinition, value: int | bool) -> int | bool:
        if definition.data_type == "bool":
            if value not in (False, True, 0, 1):
                raise ProcessWriteError(f"{definition.key} requires boolean 0/1")
            normalized: int | bool = bool(value)
        else:
            if isinstance(value, bool) or not isinstance(value, int):
                raise ProcessWriteError(f"{definition.key} requires an integer raw value")
            normalized = value

        numeric = int(normalized)
        if not definition.minimum <= numeric <= definition.maximum:
            raise ProcessWriteError(
                f"{definition.key} value {numeric} outside "
                f"[{definition.minimum}, {definition.maximum}]"
            )
        return normalized

    def write_raw(self, key: str, value: int | bool) -> WriteTransition:
        """Apply one whitelisted raw Modbus value to a command or setpoint."""
        definition = self.register_map.require_key(key)
        if not definition.writable or not definition.write_effect:
            raise ProcessWriteError(f"{key} is read-only")
        normalized = self._coerce_write(definition, value)

        with self._lock:
            old = self.snapshot_raw()[key]
            if key == "level_setpoint":
                self.level_setpoint = int(normalized)
            elif key == "control_mode":
                self.control_mode = int(normalized)
            elif key == "pump_speed_setpoint":
                self.pump_speed_setpoint = int(normalized)
            elif key == "pump_command":
                self.pump_command = bool(normalized)
            elif key == "inlet_valve_command":
                self.inlet_valve_command = bool(normalized)
            elif key == "alarm_acknowledge":
                if bool(normalized):
                    self.high_alarm_acknowledged = self.high_level_alarm
                    self.low_alarm_acknowledged = self.low_level_alarm
                self.alarm_acknowledge = False  # pulse is consumed immediately
            else:  # Manifest and implementation must fail closed if they diverge.
                raise ProcessWriteError(f"{key} has no process write handler")

            stored = self.snapshot_raw()[key]
            return WriteTransition(key, old, normalized, stored, definition.write_effect)

    def _request_pump(self, target: bool) -> None:
        if target != self._pump_target:
            self._pump_target = target
            self._pump_delay_remaining = self.actuator_delay_seconds

    def _request_valve(self, target: bool) -> None:
        if target != self._valve_target:
            self._valve_target = target
            self._valve_delay_remaining = self.actuator_delay_seconds

    def _advance_actuators(self, seconds: float) -> None:
        if self._pump_delay_remaining > 0:
            self._pump_delay_remaining = max(0.0, self._pump_delay_remaining - seconds)
            if self._pump_delay_remaining == 0.0:
                previous = self.pump_feedback
                self.pump_feedback = self._pump_target and not self.pump_fault
                if self.pump_feedback and not previous:
                    self.pump_start_count = min(65535, self.pump_start_count + 1)

        if self._valve_delay_remaining > 0:
            self._valve_delay_remaining = max(0.0, self._valve_delay_remaining - seconds)
            if self._valve_delay_remaining == 0.0:
                self.inlet_valve_feedback = self._valve_target

    def _desired_pump_state(self) -> bool:
        if self.control_mode == 0:  # MANUAL
            return self.pump_command
        if self.pump_feedback or self._pump_target:
            return self._level_raw > self.level_setpoint - self.auto_hysteresis_raw
        return self._level_raw >= self.level_setpoint + self.auto_hysteresis_raw

    def tick(self, seconds: float = 1.0) -> None:
        """Advance the model by a bounded deterministic interval."""
        if not isinstance(seconds, (int, float)) or not math.isfinite(seconds):
            raise ValueError("tick seconds must be finite")
        if seconds <= 0 or seconds > 10:
            raise ValueError("tick seconds must be greater than 0 and at most 10")

        with self._lock:
            self._request_valve(self.inlet_valve_command)
            self._request_pump(self._desired_pump_state())
            self._advance_actuators(float(seconds))

            inlet_lps = self.nominal_inlet_flow_lps if self.inlet_valve_feedback else 0.0
            speed_fraction = self.pump_speed_setpoint / 10_000.0
            outlet_lps = self.max_pump_flow_lps * speed_fraction if self.pump_feedback else 0.0

            level_delta_raw = ((inlet_lps - outlet_lps) * seconds / self.capacity_liters) * 10_000.0
            self._level_raw = min(10_000.0, max(0.0, self._level_raw + level_delta_raw))
            self.inlet_flow_raw = round(inlet_lps * 100)
            self.outlet_flow_raw = round(outlet_lps * 100)
            self.pump_current_raw = round(300 + 1_200 * speed_fraction) if self.pump_feedback else 0

            # Small deterministic thermal cycle without random global state.
            phase = int((self.elapsed_seconds + seconds) // 60) % 20
            temperature_base = int(
                self.register_map.require_key("process_temperature_pv").default
            )
            self.process_temperature_raw = temperature_base + (
                phase if phase <= 10 else 20 - phase
            )

            level = round(self._level_raw)
            high_limit = int(self.register_map.require_key("high_alarm_limit").default)
            low_limit = int(self.register_map.require_key("low_alarm_limit").default)
            new_high = level >= high_limit
            new_low = level <= low_limit
            if not new_high:
                self.high_alarm_acknowledged = False
            if not new_low:
                self.low_alarm_acknowledged = False
            self.high_level_alarm = new_high
            self.low_level_alarm = new_low
            self.elapsed_seconds += float(seconds)

            self._assert_invariants()

    def _assert_invariants(self) -> None:
        if not 0.0 <= self._level_raw <= 10_000.0:
            raise RuntimeError("tank level escaped physical bounds")
        if self.control_mode not in (0, 1):
            raise RuntimeError("control mode escaped enum")
        if self.pump_fault and self.pump_feedback:
            raise RuntimeError("faulted pump cannot report running feedback")
        if any(value < 0 for value in (self.inlet_flow_raw, self.outlet_flow_raw, self.pump_current_raw)):
            raise RuntimeError("derived process value became negative")

    def snapshot_raw(self) -> dict[str, int | bool]:
        """Return an atomic raw-value snapshot matching every manifest key."""
        with self._lock:
            values: dict[str, int | bool] = {
                "tank_level_pv": round(self._level_raw),
                "inlet_flow_pv": self.inlet_flow_raw,
                "outlet_flow_pv": self.outlet_flow_raw,
                "pump_current_pv": self.pump_current_raw,
                "process_temperature_pv": self.process_temperature_raw,
                "level_setpoint": self.level_setpoint,
                "high_alarm_limit": int(self.register_map.require_key("high_alarm_limit").default),
                "low_alarm_limit": int(self.register_map.require_key("low_alarm_limit").default),
                "pump_start_count": self.pump_start_count,
                "control_mode": self.control_mode,
                "pump_speed_setpoint": self.pump_speed_setpoint,
                "firmware_major_minor": int(
                    self.register_map.require_key("firmware_major_minor").default
                ),
                "pump_command": self.pump_command,
                "inlet_valve_command": self.inlet_valve_command,
                "alarm_acknowledge": self.alarm_acknowledge,
                "pump_feedback": self.pump_feedback,
                "inlet_valve_feedback": self.inlet_valve_feedback,
                "high_level_alarm": self.high_level_alarm,
                "low_level_alarm": self.low_level_alarm,
                "pump_fault": self.pump_fault,
                "auto_control_active": self.control_mode == 1,
            }
            expected = set(self.register_map.by_key)
            if set(values) != expected:
                missing = sorted(expected - set(values))
                extra = sorted(set(values) - expected)
                raise RuntimeError(f"model/register map mismatch; missing={missing}, extra={extra}")
            return values
