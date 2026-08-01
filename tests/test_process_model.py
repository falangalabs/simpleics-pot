from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from simpleics_pot.model import ProcessWriteError, WetWellProcess  # noqa: E402
from simpleics_pot.register_map import RegisterMap  # noqa: E402


class ProcessModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = WetWellProcess()

    def test_snapshot_covers_exact_register_map(self) -> None:
        self.assertEqual(set(RegisterMap.load().by_key), set(self.model.snapshot_raw()))

    def test_same_inputs_produce_same_state(self) -> None:
        left = WetWellProcess()
        right = WetWellProcess()
        for model in (left, right):
            model.write_raw("control_mode", 0)
            model.write_raw("pump_command", 1)
            model.write_raw("pump_speed_setpoint", 8000)
            for _ in range(30):
                model.tick()
        self.assertEqual(left.snapshot_raw(), right.snapshot_raw())

    def test_manual_pump_has_delayed_feedback_and_lowers_level(self) -> None:
        self.model.write_raw("control_mode", 0)
        self.model.write_raw("pump_command", 1)
        initial = self.model.snapshot_raw()["tank_level_pv"]

        self.model.tick(1)
        self.assertFalse(self.model.snapshot_raw()["pump_feedback"])
        self.model.tick(1)
        self.assertTrue(self.model.snapshot_raw()["pump_feedback"])
        for _ in range(20):
            self.model.tick()

        snapshot = self.model.snapshot_raw()
        self.assertLess(snapshot["tank_level_pv"], initial)
        self.assertGreater(snapshot["outlet_flow_pv"], snapshot["inlet_flow_pv"])

    def test_auto_mode_starts_only_above_upper_hysteresis(self) -> None:
        self.model.write_raw("level_setpoint", 5000)
        for _ in range(25):
            self.model.tick()
        self.assertTrue(self.model.snapshot_raw()["pump_feedback"])

    def test_valve_feedback_is_delayed(self) -> None:
        self.model.write_raw("inlet_valve_command", 0)
        self.model.tick()
        self.assertTrue(self.model.snapshot_raw()["inlet_valve_feedback"])
        self.model.tick()
        self.assertFalse(self.model.snapshot_raw()["inlet_valve_feedback"])

    def test_read_only_write_is_rejected(self) -> None:
        with self.assertRaisesRegex(ProcessWriteError, "read-only"):
            self.model.write_raw("tank_level_pv", 5000)

    def test_out_of_range_setpoint_is_rejected_without_change(self) -> None:
        before = self.model.snapshot_raw()["level_setpoint"]
        with self.assertRaisesRegex(ProcessWriteError, "outside"):
            self.model.write_raw("level_setpoint", 9000)
        self.assertEqual(before, self.model.snapshot_raw()["level_setpoint"])

    def test_boolean_command_rejects_non_boolean_integer(self) -> None:
        with self.assertRaisesRegex(ProcessWriteError, "boolean"):
            self.model.write_raw("pump_command", 2)

    def test_alarm_acknowledge_is_a_self_resetting_pulse(self) -> None:
        self.model._level_raw = 9000  # Controlled white-box setup for alarm behavior.
        self.model.tick()
        self.assertTrue(self.model.snapshot_raw()["high_level_alarm"])
        transition = self.model.write_raw("alarm_acknowledge", 1)
        self.assertTrue(transition.requested_raw)
        self.assertFalse(transition.stored_raw)
        self.assertTrue(self.model.high_alarm_acknowledged)

    def test_level_never_exceeds_physical_bounds(self) -> None:
        self.model.write_raw("control_mode", 0)
        self.model.write_raw("pump_command", 0)
        for _ in range(4_000):
            self.model.tick(10)
        self.assertEqual(10000, self.model.snapshot_raw()["tank_level_pv"])

        self.model.write_raw("pump_command", 1)
        self.model.write_raw("inlet_valve_command", 0)
        for _ in range(4_000):
            self.model.tick(10)
        self.assertEqual(0, self.model.snapshot_raw()["tank_level_pv"])

    def test_invalid_tick_is_rejected(self) -> None:
        for value in (0, -1, 11, float("inf"), float("nan")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.model.tick(value)


if __name__ == "__main__":
    unittest.main()
