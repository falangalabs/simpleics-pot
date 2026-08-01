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
from simpleics_pot.runtime import parse_args  # noqa: E402
from simpleics_pot.server import ContextAwareModbusTcpServer  # noqa: E402


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
                client.read_input_registers(0, count=5, device_id=1),
                client.read_holding_registers(0, count=7, device_id=1),
                client.read_coils(0, count=3, device_id=1),
                client.read_discrete_inputs(0, count=6, device_id=1),
            )

        responses = await self._run_client(operation)
        for response in responses:
            self.assertFalse(response.isError(), response)
        self.assertEqual(5200, responses[0].registers[0])
        self.assertEqual(5500, responses[1].registers[0])
        self.assertEqual([False, True, False], responses[2].bits[:3])
        self.assertEqual([False, True, False, False, False, True], responses[3].bits[:6])
        self.assertEqual("1.2.0", self.events[0].schema_version)
        self.assertEqual(5200, self.events[0].response_values["tank_level_pv"])
        self.assertEqual(5500, self.events[1].response_values["level_setpoint"])
        self.assertEqual(False, self.events[2].response_values["pump_command"])
        self.assertEqual(False, self.events[3].response_values["pump_feedback"])

    async def test_reports_consistent_synthetic_device_identity(self) -> None:
        response = await self._run_client(
            lambda client: client.read_device_information(device_id=1)
        )
        self.assertFalse(response.isError(), response)
        self.assertEqual(b"Rivergate Automation Labs", response.information[0])
        self.assertEqual(b"RGL-120", response.information[1])
        self.assertEqual(b"2.4.1", response.information[2])

    async def test_event_contains_tcp_peer_transaction_and_session(self) -> None:
        def operation(client: ModbusTcpClient):
            first = client.read_holding_registers(0, count=1, device_id=1)
            second = client.read_input_registers(0, count=1, device_id=1)
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
        self.assertEqual({"level_setpoint": 5500}, first_event.response_values)
        self.assertEqual({"tank_level_pv": 5200}, second_event.response_values)

    async def test_separate_tcp_clients_receive_separate_sessions(self) -> None:
        def operation(client: ModbusTcpClient):
            return client.read_holding_registers(0, count=1, device_id=1)

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
            first = struct.pack(">HHHBBHH", 0x1234, 0, 6, 1, 3, 0, 1)
            second = struct.pack(">HHHBBHH", 0x1235, 0, 6, 1, 3, 0, 1)
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
                client.write_register(4, 0, device_id=1),
                client.write_coil(0, True, device_id=1),
                client.write_register(5, 8000, device_id=1),
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
                client.read_discrete_inputs(0, count=1, device_id=1),
                client.read_input_registers(0, count=4, device_id=1),
            )

        feedback, process = await self._run_client(reads)
        self.assertFalse(feedback.isError(), feedback)
        self.assertFalse(process.isError(), process)
        self.assertTrue(feedback.bits[0])
        self.assertLess(process.registers[0], before)
        self.assertGreater(process.registers[2], process.registers[1])
        read_events = [event for event in self.events if event.operation == "read"]
        self.assertEqual(feedback.bits[0], read_events[0].response_values["pump_feedback"])
        self.assertEqual(process.registers[0], read_events[1].response_values["tank_level_pv"])
        write_events = [event for event in self.events if event.operation == "write"]
        self.assertEqual(3, len(write_events))
        self.assertEqual(
            {"pump_speed_setpoint": 7500},
            write_events[-1].before,
        )
        self.assertEqual(
            {"pump_speed_setpoint": 8000},
            write_events[-1].after,
        )

    async def test_read_only_and_undefined_writes_are_rejected(self) -> None:
        def operation(client: ModbusTcpClient):
            return (
                client.write_register(1, 7000, device_id=1),
                client.write_register(9, 1234, device_id=1),
                client.write_register(5, 0, device_id=1),
            )

        read_only, undefined, invalid_value = await self._run_client(operation)
        self.assertTrue(read_only.isError())
        self.assertTrue(undefined.isError())
        self.assertTrue(invalid_value.isError())
        self.assertEqual(8500, self.model.snapshot_raw()["high_alarm_limit"])
        self.assertEqual(7500, self.model.snapshot_raw()["pump_speed_setpoint"])

    async def test_wrong_unit_id_has_no_valid_response(self) -> None:
        with self.assertRaises(ModbusIOException):
            await self._run_client(
                lambda client: client.read_holding_registers(0, count=1, device_id=2)
            )


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
        writer.write(struct.pack(">HHHBBHH", transaction_id, 0, 6, 1, 3, 0, 1))
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
