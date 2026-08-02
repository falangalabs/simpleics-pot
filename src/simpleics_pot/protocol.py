"""PyModbus adapter backed by the deterministic process model."""

from __future__ import annotations

import logging
from collections.abc import MutableSequence

from pymodbus.constants import ExcCodes
from pymodbus.datastore import ModbusServerContext
from pymodbus.exceptions import NoSuchIdException
from pymodbus.pdu.device import ModbusDeviceIdentification
from pymodbus.simulator.simcore import SimCore
from pymodbus.simulator.simdata import SimData
from pymodbus.simulator.simdevice import SimDevice
from pymodbus.simulator.simutils import DataType, SimUtils

from .model import ProcessWriteError, WetWellProcess
from .register_map import RegisterDefinition, RegisterMap
from .telemetry import EventFactory, EventSink


FUNCTION_AREA = {
    1: "coil",
    2: "discrete_input",
    3: "holding_register",
    4: "input_register",
    5: "coil",
    6: "holding_register",
    15: "coil",
    16: "holding_register",
}
WRITE_FUNCTIONS = {5, 6, 15, 16}
AREA_ORDER = ("coil", "discrete_input", "holding_register", "input_register")
LOG = logging.getLogger("simpleics_pot.telemetry")


def _sim_datatype(definition: RegisterDefinition) -> DataType:
    if definition.data_type == "bool":
        return DataType.BITS
    if definition.data_type == "int16":
        return DataType.INT16
    return DataType.UINT16


def _encode_register(value: int | bool) -> int:
    return int(value) & 0xFFFF


class StrictSimContext(ModbusServerContext):
    """Adapt new SimDevice memory while rejecting unknown Unit IDs cleanly.

    PyModbus 3.13 SimCore falls back to device 0 for unknown IDs even when no
    device 0 exists, producing a KeyError and server-failure response. This
    wrapper raises the documented NoSuchIdException so the server can silently
    ignore an unknown Unit ID without a traceback.
    """

    def __init__(self, device: SimDevice):
        # Do not call deprecated ModbusServerContext initialization. Inheriting
        # supplies the public server context type expected by ModbusBaseServer.
        self.simdevices: list[SimDevice] = []
        self._core = SimCore(device)
        self._device_ids = frozenset(self._core.device_ids())

    def _require_device(self, device_id: int) -> None:
        if device_id not in self._device_ids:
            raise NoSuchIdException(f"unknown Modbus device id: {device_id}")

    def device_ids(self) -> list[int]:
        return sorted(self._device_ids)

    async def async_getValues(
        self, device_id: int, func_code: int, address: int, count: int = 1
    ) -> list[int] | list[bool] | ExcCodes:
        self._require_device(device_id)
        return await self._core.async_getValues(device_id, func_code, address, count)

    async def async_setValues(
        self,
        device_id: int,
        func_code: int,
        address: int,
        values: list[int] | list[bool],
    ) -> None | ExcCodes:
        self._require_device(device_id)
        return await self._core.async_setValues(device_id, func_code, address, values)


class ProcessProtocolAdapter:
    """Synchronize PyModbus runtime memory with one process model."""

    def __init__(
        self,
        model: WetWellProcess,
        register_map: RegisterMap | None = None,
        event_sink: EventSink | None = None,
    ):
        self.model = model
        self.register_map = register_map or model.register_map
        self.identity = self._build_identity()
        self.event_sink = event_sink
        self.event_factory = EventFactory()

    def _emit_event(self, **fields: object) -> None:
        if self.event_sink is None:
            return
        try:
            self.event_sink(self.event_factory.create(**fields))  # type: ignore[arg-type]
        except Exception:
            # Telemetry must never break or delay the protocol path. The runtime
            # sink is non-blocking logging; future remote transport uses a queue.
            LOG.exception("application event sink failed")

    def _build_identity(self) -> ModbusDeviceIdentification:
        """Build one explicitly synthetic but internally consistent identity."""
        device_data = self.register_map.document["device"]
        return ModbusDeviceIdentification(info_name={
            "VendorName": str(device_data["vendor_name"]),
            "ProductCode": str(device_data["product_code"]),
            "MajorMinorRevision": str(device_data["revision"]),
            "VendorUrl": str(device_data["vendor_url"]),
            "ProductName": str(device_data["product_name"]),
            "ModelName": str(device_data["model_name"]),
            "UserApplicationName": str(device_data["user_application_name"]),
        })

    def _sync_register_area(
        self,
        area: str,
        start_address: int,
        current_registers: MutableSequence[int],
        snapshot: dict[str, int | bool],
    ) -> None:
        for definition in self.register_map.for_area(area):
            index = definition.address - start_address
            if 0 <= index < len(current_registers):
                current_registers[index] = _encode_register(snapshot[definition.key])

    def _sync_bit_area(
        self,
        area: str,
        start_address: int,
        current_registers: MutableSequence[int],
        snapshot: dict[str, int | bool],
    ) -> None:
        bits = SimUtils.registersToBits(list(current_registers))
        bit_base = start_address * 16
        for definition in self.register_map.for_area(area):
            index = definition.address - bit_base
            if 0 <= index < len(bits):
                bits[index] = bool(snapshot[definition.key])
        current_registers[:] = SimUtils.bitsToRegisters(bits)

    def sync_area(
        self,
        area: str,
        start_address: int,
        current_registers: MutableSequence[int],
    ) -> dict[str, int | bool]:
        snapshot = self.model.snapshot_raw()
        if area in {"coil", "discrete_input"}:
            self._sync_bit_area(area, start_address, current_registers, snapshot)
        else:
            self._sync_register_area(area, start_address, current_registers, snapshot)
        return snapshot

    async def action(
        self,
        function_code: int,
        start_address: int,
        address: int,
        count: int,
        current_registers: list[int],
        set_values: list[int] | list[bool] | None,
    ) -> ExcCodes | None:
        """PyModbus SimDevice hook for process synchronization and writes."""
        area = FUNCTION_AREA.get(function_code)
        if area is None:
            self._emit_event(
                unit_id=self.register_map.unit_id,
                function_code=function_code,
                operation="unknown",
                area=None,
                address=address,
                count=count,
                result="exception",
                exception_code=int(ExcCodes.ILLEGAL_FUNCTION),
            )
            return ExcCodes.ILLEGAL_FUNCTION

        served_snapshot = self.sync_area(area, start_address, current_registers)
        # PyModbus calls the action hook again with no values while it reads
        # back FC5/6/15/16 memory to construct the write response. This is not
        # a second client request and must not become a false telemetry read.
        if function_code in WRITE_FUNCTIONS and set_values is None:
            return None

        if function_code not in WRITE_FUNCTIONS:
            keys = []
            for offset in range(count):
                definition = self.register_map.by_location.get((area, address + offset))
                if definition is not None:
                    keys.append(definition.key)
            self._emit_event(
                unit_id=self.register_map.unit_id,
                function_code=function_code,
                operation="read",
                area=area,
                address=address,
                count=count,
                register_keys=keys,
                response_values={key: served_snapshot[key] for key in keys},
            )
            return None

        before_snapshot = self.model.snapshot_raw()
        definitions: list[RegisterDefinition] = []
        for offset in range(len(set_values)):
            try:
                definition = self.register_map.require_location(area, address + offset)
            except KeyError:
                self._emit_event(
                    unit_id=self.register_map.unit_id,
                    function_code=function_code,
                    operation="write",
                    area=area,
                    address=address,
                    count=len(set_values),
                    register_keys=[item.key for item in definitions],
                    requested_values=set_values,
                    result="exception",
                    exception_code=int(ExcCodes.ILLEGAL_ADDRESS),
                )
                return ExcCodes.ILLEGAL_ADDRESS
            if not definition.writable:
                self._emit_event(
                    unit_id=self.register_map.unit_id,
                    function_code=function_code,
                    operation="write",
                    area=area,
                    address=address,
                    count=len(set_values),
                    register_keys=[definition.key],
                    requested_values=set_values,
                    result="exception",
                    exception_code=int(ExcCodes.ILLEGAL_ADDRESS),
                )
                return ExcCodes.ILLEGAL_ADDRESS
            definitions.append(definition)

        # Validate all values before mutating any state so multi-write is atomic on error.
        normalized_values: list[int | bool] = []
        try:
            for definition, value in zip(definitions, set_values, strict=True):
                normalized_values.append(self.model._coerce_write(definition, value))
        except ProcessWriteError:
            self._emit_event(
                unit_id=self.register_map.unit_id,
                function_code=function_code,
                operation="write",
                area=area,
                address=address,
                count=len(set_values),
                register_keys=[item.key for item in definitions],
                requested_values=set_values,
                result="exception",
                exception_code=int(ExcCodes.ILLEGAL_VALUE),
            )
            return ExcCodes.ILLEGAL_VALUE

        try:
            for definition, value in zip(definitions, normalized_values, strict=True):
                self.model.write_raw(definition.key, value)
        except ProcessWriteError:
            return ExcCodes.SERVER_FAILURE

        self.sync_area(area, start_address, current_registers)
        keys = [definition.key for definition in definitions]
        after_snapshot = self.model.snapshot_raw()
        self._emit_event(
            unit_id=self.register_map.unit_id,
            function_code=function_code,
            operation="write",
            area=area,
            address=address,
            count=len(normalized_values),
            register_keys=keys,
            requested_values=normalized_values,
            before={key: before_snapshot[key] for key in keys},
            after={key: after_snapshot[key] for key in keys},
        )
        return None

    def build_device(self) -> SimDevice:
        snapshot = self.model.snapshot_raw()
        blocks: list[list[SimData]] = []
        for area in AREA_ORDER:
            entries = []
            for definition in self.register_map.for_area(area):
                entries.append(
                    SimData(
                        address=definition.address,
                        values=snapshot[definition.key],
                        datatype=_sim_datatype(definition),
                        readonly=not definition.writable,
                    )
                )
            if not entries:
                raise ValueError(f"register map area is empty: {area}")
            blocks.append(entries)

        return SimDevice(
            id=self.register_map.unit_id,
            simdata=(blocks[0], blocks[1], blocks[2], blocks[3]),
            identity=self.identity,
            action=self.action,
        )

    def build_context(self) -> StrictSimContext:
        return StrictSimContext(self.build_device())
