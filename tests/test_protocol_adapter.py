from __future__ import annotations

import asyncio
import socket
import struct
import sys
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pymodbus.client import ModbusTcpClient  # noqa: E402
from pymodbus.exceptions import ModbusIOException  # noqa: E402
from simpleics_pot.model import WetWellProcess  # noqa: E402
from simpleics_pot.protocol import ProcessProtocolAdapter  # noqa: E402
from simpleics_pot.register_map import RegisterMap  # noqa: E402
from simpleics_pot.runtime import parse_args  # noqa: E402
from simpleics_pot.server import ContextAwareModbusTcpServer  # noqa: E402


_MAP = RegisterMap.load()
UNIT_ID = _MAP.unit_id


def area_base(area: str) -> int:
    """First address of an area, read from the map rather than assumed.

    The layout is part of the persona and differs between deployments -- the
    published community profile deliberately does not sit where any private
    one does. A test that hardcodes 0 passes only for whoever happens to start
    there and fails for everyone who re-personas the device, which is the one
    thing this edition is meant to make easy.
    """
    return min(item.address for item in _MAP.definitions if item.area == area)


def index_of(key: str) -> int:
    """Offset of one register inside its own area block."""
    definition = _MAP.require_key(key)
    return definition.address - area_base(definition.area)


def addr(key: str) -> int:
    """Absolute address of one register, whatever persona is loaded."""
    return _MAP.require_key(key).address


def first_key(area: str) -> str:
    """Which register a block read reports on.

    A bit read reaches the adapter as one register, so the event it emits
    describes the register at the start of the block -- whichever one the
    loaded persona happens to put there. Asserting on a name instead would be
    asserting on the layout, which is exactly the thing allowed to change.
    """
    base = area_base(area)
    return next(
        item.key for item in _MAP.definitions if item.area == area and item.address == base
    )


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _recv_modbus_frame(connection: socket.socket) -> bytes:
    header = bytearray()
    while len(header) < 7:
        chunk = connection.recv(7 - len(header))
        if not chunk:
            raise AssertionError(f"short Modbus header: {header.hex()}")
        header.extend(chunk)
    remaining = int.from_bytes(header[4:6], "big") - 1
    payload = bytearray()
    while len(payload) < remaining:
        chunk = connection.recv(remaining - len(payload))
        if not chunk:
            raise AssertionError("connection closed during Modbus response")
        payload.extend(chunk)
    return bytes(header) + bytes(payload)


class RuntimeGuardTests(unittest.TestCase):
    def test_default_bind_is_unprivileged_loopback(self) -> None:
        args = parse_args([])
        self.assertEqual("127.0.0.1", args.host)
        self.assertEqual(1502, args.port)

    def test_non_loopback_requires_explicit_acknowledgement(self) -> None:
        with self.assertRaises(SystemExit):
            parse_args(["--host", "0.0.0.0"])
        args = parse_args(["--host", "0.0.0.0", "--allow-non-loopback"])
        self.assertEqual("0.0.0.0", args.host)


class ProtocolBlackBoxTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.model = WetWellProcess()
        self.register_map = self.model.register_map
        self.events = []
        self.adapter = ProcessProtocolAdapter(self.model, event_sink=self.events.append)
        self.port = _free_loopback_port()
        self.server = ContextAwareModbusTcpServer(
            self.adapter.build_context(),
            address=("127.0.0.1", self.port),
            identity=self.adapter.identity,
            ignore_missing_devices=True,
        )
        await self.server.serve_forever(background=True)

    async def asyncTearDown(self) -> None:
        await self.server.shutdown()

    def _client_sequence(self, operation):
        client = ModbusTcpClient("127.0.0.1", port=self.port, timeout=0.2, retries=0)
        try:
            if not client.connect():
                raise AssertionError("black-box client could not connect")
            return operation(client)
        finally:
            client.close()

    async def _run_client(self, operation):
        return await asyncio.to_thread(self._client_sequence, operation)

    async def test_reads_all_four_address_areas(self) -> None:
        def operation(client: ModbusTcpClient):
            return (
                client.read_input_registers(
                    area_base("input_register"), count=5, device_id=UNIT_ID
                ),
                client.read_holding_registers(
                    area_base("holding_register"), count=7, device_id=UNIT_ID
                ),
                client.read_coils(area_base("coil"), count=3, device_id=UNIT_ID),
                client.read_discrete_inputs(
                    area_base("discrete_input"), count=6, device_id=UNIT_ID
                ),
            )

        responses = await self._run_client(operation)
        for response in responses:
            self.assertFalse(response.isError(), response)
        self.assertEqual(
            self.register_map.require_key("tank_level_pv").default,
            responses[0].registers[index_of("tank_level_pv")],
        )
        self.assertEqual(
            self.register_map.require_key("level_setpoint").default,
            responses[1].registers[index_of("level_setpoint")],
        )
        self.assertEqual(
            self.register_map.require_key("pump_command").default,
            responses[2].bits[index_of("pump_command")],
        )
        self.assertEqual(
            self.register_map.require_key("pump_feedback").default,
            responses[3].bits[index_of("pump_feedback")],
        )
        self.assertEqual("1.2.0", self.events[0].schema_version)
        self.assertEqual(
            responses[0].registers[index_of("tank_level_pv")],
            self.events[0].response_values["tank_level_pv"],
        )
        self.assertEqual(
            responses[1].registers[index_of("level_setpoint")],
            self.events[1].response_values["level_setpoint"],
        )
        self.assertEqual(
            self.register_map.require_key(first_key("coil")).default,
            self.events[2].response_values[first_key("coil")],
        )
        self.assertEqual(
            self.register_map.require_key(first_key("discrete_input")).default,
            self.events[3].response_values[first_key("discrete_input")],
        )

    async def test_reports_consistent_synthetic_device_identity(self) -> None:
        response = await self._run_client(
            lambda client: client.read_device_information(device_id=UNIT_ID)
        )
        self.assertFalse(response.isError(), response)
        device = self.register_map.document["device"]
        self.assertEqual(device["vendor_name"].encode(), response.information[0])
        self.assertEqual(device["product_code"].encode(), response.information[1])
        self.assertEqual(device["revision"].encode(), response.information[2])

    async def test_event_contains_tcp_peer_transaction_and_session(self) -> None:
        def operation(client: ModbusTcpClient):
            first = client.read_holding_registers(
                addr("level_setpoint"), count=1, device_id=UNIT_ID
            )
            second = client.read_input_registers(
                addr("tank_level_pv"), count=1, device_id=UNIT_ID
            )
            return first, second

        first, second = await self._run_client(operation)
        self.assertFalse(first.isError(), first)
        self.assertFalse(second.isError(), second)
        self.assertEqual(2, len(self.events))

        first_event, second_event = self.events
        self.assertEqual("127.0.0.1", first_event.source_ip)
        self.assertIsInstance(first_event.source_port, int)
        self.assertGreater(first_event.source_port or 0, 0)
        self.assertEqual(first.transaction_id, first_event.transaction_id)
        self.assertEqual(second.transaction_id, second_event.transaction_id)
        self.assertEqual(first_event.session_id, second_event.session_id)
        uuid.UUID(first_event.session_id or "")
        self.assertEqual("pymodbus_request_handler", first_event.transport_context)
        self.assertEqual(
            {"level_setpoint": self.register_map.require_key("level_setpoint").default},
            first_event.response_values,
        )
        self.assertEqual(
            {"tank_level_pv": self.register_map.require_key("tank_level_pv").default},
            second_event.response_values,
        )

    async def test_separate_tcp_clients_receive_separate_sessions(self) -> None:
        def operation(client: ModbusTcpClient):
            return client.read_holding_registers(
                area_base("holding_register"), count=1, device_id=UNIT_ID
            )

        first, second = await asyncio.gather(
            self._run_client(operation),
            self._run_client(operation),
        )
        self.assertFalse(first.isError(), first)
        self.assertFalse(second.isError(), second)
        self.assertEqual(2, len(self.events))
        self.assertEqual(2, len({event.session_id for event in self.events}))
        self.assertEqual(2, len({event.source_port for event in self.events}))
        self.assertTrue(all(event.source_ip == "127.0.0.1" for event in self.events))

    async def test_pipelined_requests_keep_transaction_and_session_context(self) -> None:
        def operation() -> tuple[bytes, bytes]:
            first = struct.pack(">HHHBBHH", 0x1234, 0, 6, UNIT_ID, 3, area_base("holding_register"), 1)
            second = struct.pack(">HHHBBHH", 0x1235, 0, 6, UNIT_ID, 3, area_base("holding_register"), 1)
            with socket.create_connection(("127.0.0.1", self.port), timeout=1) as client:
                client.sendall(first + second)
                return _recv_modbus_frame(client), _recv_modbus_frame(client)

        first_response, second_response = await asyncio.to_thread(operation)
        self.assertEqual(0x1234, int.from_bytes(first_response[:2], "big"))
        self.assertEqual(0x1235, int.from_bytes(second_response[:2], "big"))
        self.assertEqual([0x1234, 0x1235], [event.transaction_id for event in self.events])
        self.assertEqual(1, len({event.session_id for event in self.events}))

    async def test_write_changes_process_then_read_back(self) -> None:
        def writes(client: ModbusTcpClient):
            return (
                client.write_register(addr("control_mode"), 0, device_id=UNIT_ID),
                client.write_coil(addr("pump_command"), True, device_id=UNIT_ID),
                client.write_register(
                    addr("pump_speed_setpoint"), 8000, device_id=UNIT_ID
                ),
            )

        responses = await self._run_client(writes)
        for response in responses:
            self.assertFalse(response.isError(), response)
        self.assertEqual(3, len(self.events))
        self.assertEqual(["write", "write", "write"], [event.operation for event in self.events])
        self.model.tick()
        self.model.tick()
        before = self.model.snapshot_raw()["tank_level_pv"]
        for _ in range(20):
            self.model.tick()

        def reads(client: ModbusTcpClient):
            return (
                client.read_discrete_inputs(
                    addr("pump_feedback"), count=1, device_id=UNIT_ID
                ),
                client.read_input_registers(
                    area_base("input_register"), count=5, device_id=UNIT_ID
                ),
            )

        feedback, process = await self._run_client(reads)
        self.assertFalse(feedback.isError(), feedback)
        self.assertFalse(process.isError(), process)
        self.assertTrue(feedback.bits[0])
        self.assertLess(process.registers[index_of("tank_level_pv")], before)
        self.assertGreater(
            process.registers[index_of("outlet_flow_pv")],
            process.registers[index_of("inlet_flow_pv")],
        )
        read_events = [event for event in self.events if event.operation == "read"]
        self.assertEqual(feedback.bits[0], read_events[0].response_values["pump_feedback"])
        self.assertEqual(
            process.registers[index_of("tank_level_pv")],
            read_events[1].response_values["tank_level_pv"],
        )
        write_events = [event for event in self.events if event.operation == "write"]
        self.assertEqual(3, len(write_events))
        self.assertEqual(
            {"pump_speed_setpoint": self.register_map.require_key("pump_speed_setpoint").default},
            write_events[-1].before,
        )
        self.assertEqual(
            {"pump_speed_setpoint": 8000},
            write_events[-1].after,
        )

    async def test_read_only_and_undefined_writes_are_rejected(self) -> None:
        def operation(client: ModbusTcpClient):
            return (
                client.write_register(
                    addr("high_alarm_limit"), 7000, device_id=UNIT_ID
                ),
                # Deliberately past the end of the block, wherever it now sits.
                client.write_register(
                    area_base("holding_register") + 50, 1234, device_id=UNIT_ID
                ),
                client.write_register(
                    addr("pump_speed_setpoint"), 0, device_id=UNIT_ID
                ),
            )

        read_only, undefined, invalid_value = await self._run_client(operation)
        self.assertTrue(read_only.isError())
        self.assertTrue(undefined.isError())
        self.assertTrue(invalid_value.isError())
        self.assertEqual(
            self.register_map.require_key("high_alarm_limit").default,
            self.model.snapshot_raw()["high_alarm_limit"],
        )
        self.assertEqual(
            self.register_map.require_key("pump_speed_setpoint").default,
            self.model.snapshot_raw()["pump_speed_setpoint"],
        )

    async def test_wrong_unit_id_has_no_valid_response(self) -> None:
        with self.assertRaises(ModbusIOException):
            await self._run_client(
                lambda client: client.read_holding_registers(
                    area_base("holding_register"), count=1, device_id=2
                )
            )


class MalformedAndUndefinedRequestsAreAnsweredTests(ProtocolBlackBoxTests):
    """Two ways a device can give itself away by being unlike real equipment.

    Both were live in this edition. A truncated FC43 raised inside the decoder
    and the exception escaped into the transport, so the socket simply died --
    and a controller that hangs up on a short frame is the loudest tell there
    is. A single-coil write of 0x1234 was accepted as "on", because the value
    becomes a bool before anything can object, while the protocol defines two
    values and no others.
    """

    async def _raw(self, pdu: bytes, transaction_id: int = 0x2A) -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            writer.write(
                struct.pack(">HHHB", transaction_id, 0, len(pdu) + 1, UNIT_ID) + pdu
            )
            await writer.drain()
            return await asyncio.wait_for(reader.read(256), timeout=2)
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_a_truncated_request_is_answered_not_dropped(self) -> None:
        for label, pdu in (
            ("identification, no object id", struct.pack(">BBB", 43, 14, 1)),
            ("identification, no read code", struct.pack(">BB", 43, 14)),
            ("identification, bare", struct.pack(">B", 43)),
            ("read, no quantity", struct.pack(">BH", 3, area_base("holding_register"))),
        ):
            with self.subTest(label=label):
                reply = await self._raw(pdu)
                self.assertTrue(reply, "the connection was closed instead of answered")
                self.assertTrue(reply[7] & 0x80, "expected an exception response")
                self.assertEqual(pdu[0], reply[7] & 0x7F, "function code not echoed")
                self.assertEqual(
                    0x2A,
                    int.from_bytes(reply[0:2], "big"),
                    "transaction id not echoed; answering 0 is its own tell",
                )

    async def test_the_device_survives_a_malformed_frame(self) -> None:
        await self._raw(struct.pack(">BBB", 43, 14, 1))
        reply = await self._raw(
            struct.pack(">BHH", 4, area_base("input_register"), 5)
        )
        self.assertTrue(reply)
        self.assertFalse(reply[7] & 0x80, "the device stopped answering afterwards")

    async def test_only_the_two_defined_coil_values_are_accepted(self) -> None:
        coil = addr("pump_command")
        for value in (0xFF00, 0x0000):
            with self.subTest(value=hex(value)):
                reply = await self._raw(struct.pack(">BHH", 5, coil, value))
                self.assertFalse(reply[7] & 0x80, f"{value:#06x} is defined")
        for value in (0x0001, 0x1234, 0xFFFF, 0x00FF):
            with self.subTest(value=hex(value)):
                reply = await self._raw(struct.pack(">BHH", 5, coil, value))
                self.assertTrue(reply[7] & 0x80, f"{value:#06x} is not a coil value")
                self.assertEqual(5, reply[7] & 0x7F)
                self.assertEqual(
                    0x2A, int.from_bytes(reply[0:2], "big"), "transaction id not echoed"
                )

    async def test_a_refused_coil_write_does_not_move_the_process(self) -> None:
        """Refusing has to mean refusing, not refusing out loud after writing."""
        before = self.model.snapshot_raw()["pump_command"]
        await self._raw(struct.pack(">BHH", 5, addr("pump_command"), 0x1234))
        self.assertEqual(before, self.model.snapshot_raw()["pump_command"])


class ConnectionBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        model = WetWellProcess()
        adapter = ProcessProtocolAdapter(model)
        self.port = _free_loopback_port()
        self.server = ContextAwareModbusTcpServer(
            adapter.build_context(),
            address=("127.0.0.1", self.port),
            identity=adapter.identity,
            ignore_missing_devices=True,
            max_active_connections=2,
            idle_timeout_seconds=0.15,
            incomplete_request_timeout_seconds=0.06,
        )
        await self.server.serve_forever(background=True)

    async def asyncTearDown(self) -> None:
        await self.server.shutdown()

    async def _valid_read(self, transaction_id: int) -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(struct.pack(">HHHBBHH", transaction_id, 0, 6, UNIT_ID, 3,
                                 area_base("holding_register"), 1))
        await writer.drain()
        response = await asyncio.wait_for(reader.readexactly(11), timeout=0.5)
        writer.close()
        await writer.wait_closed()
        return response

    async def test_incomplete_request_has_absolute_deadline(self) -> None:
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(b"\x00")
        await writer.drain()
        await asyncio.sleep(0.035)
        writer.write(b"\x01")
        await writer.drain()
        self.assertEqual(b"", await asyncio.wait_for(reader.read(1), timeout=0.15))
        writer.close()
        await writer.wait_closed()
        response = await self._valid_read(410)
        self.assertEqual(410, int.from_bytes(response[:2], "big"))

    async def test_connection_limit_recovers_after_idle_timeout(self) -> None:
        first = await asyncio.open_connection("127.0.0.1", self.port)
        second = await asyncio.open_connection("127.0.0.1", self.port)
        third_reader, third_writer = await asyncio.open_connection(
            "127.0.0.1", self.port
        )
        self.assertEqual(
            b"", await asyncio.wait_for(third_reader.read(1), timeout=0.15)
        )
        third_writer.close()
        await third_writer.wait_closed()
        await asyncio.sleep(0.17)
        for reader, writer in (first, second):
            self.assertEqual(b"", await asyncio.wait_for(reader.read(1), timeout=0.1))
            writer.close()
            await writer.wait_closed()
        response = await self._valid_read(411)
        self.assertEqual(411, int.from_bytes(response[:2], "big"))

    async def test_connection_boundaries_must_be_positive(self) -> None:
        model = WetWellProcess()
        adapter = ProcessProtocolAdapter(model)
        with self.assertRaises(ValueError):
            ContextAwareModbusTcpServer(
                adapter.build_context(),
                address=("127.0.0.1", 0),
                max_active_connections=0,
            )


if __name__ == "__main__":
    unittest.main()
