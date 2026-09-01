"""PyModbus TCP server integration with request-scoped transport metadata."""

from __future__ import annotations

import asyncio
import logging
import traceback
import uuid
from collections import deque

from pymodbus.constants import ExcCodes
from pymodbus.exceptions import ModbusIOException, NoSuchIdException
from pymodbus.pdu import ExceptionResponse, ModbusPDU
from pymodbus.server import ModbusTcpServer
from pymodbus.server.requesthandler import ServerRequestHandler
from pymodbus.transaction import TransactionManager

from .transport_context import RequestTransportContext, bind_transport_context


MAX_PENDING_REQUEST_BYTES = 1024
MAX_PENDING_REQUESTS = 32
DEFAULT_MAX_ACTIVE_CONNECTIONS = 128
DEFAULT_IDLE_TIMEOUT_SECONDS = 120.0
DEFAULT_INCOMPLETE_REQUEST_TIMEOUT_SECONDS = 5.0
SECURITY_LOG = logging.getLogger("simpleics_pot.security")


class ContextAwareRequestHandler(ServerRequestHandler):
    """Capture the TCP peer and bind it while PyModbus executes a request.

    PyModbus 3.13 exposes the transaction ID on the decoded PDU but does not
    pass the connection peer to datastore callbacks. The dependency is pinned,
    and black-box tests guard this deliberately small internal integration.
    """

    def __init__(self, owner, trace_packet, trace_pdu, trace_connect):
        super().__init__(owner, trace_packet, trace_pdu, trace_connect)
        self.session_id = str(uuid.uuid4())
        self.source_ip: str | None = None
        self.source_port: int | None = None
        self._pending_requests: deque[tuple[ModbusPDU, tuple | None]] = deque()
        self._drain_task: asyncio.Task[None] | None = None
        self._idle_timer: asyncio.TimerHandle | None = None
        self._incomplete_timer: asyncio.TimerHandle | None = None
        self._registered = False

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        peer = transport.get_extra_info("peername")
        if isinstance(peer, tuple) and len(peer) >= 2:
            self.source_ip = str(peer[0])
            try:
                self.source_port = int(peer[1])
            except (TypeError, ValueError):
                self.source_port = None
        if not self.server.register_connection(self):
            SECURITY_LOG.warning(
                "rejecting Modbus TCP connection active_limit=%d",
                self.server.max_active_connections,
            )
            transport.close()
            return
        self._registered = True
        super().connection_made(transport)
        self._arm_idle_timer()

    def connection_lost(self, exc: Exception | None) -> None:
        self._cancel_timers()
        self._unregister()
        super().connection_lost(exc)

    def close(self, reconnect: bool = False) -> None:
        self._cancel_timers()
        self._unregister()
        super().close(reconnect=reconnect)

    def _unregister(self) -> None:
        if self._registered:
            self.server.unregister_connection(self)
            self._registered = False

    def _cancel_timers(self) -> None:
        for timer in (self._idle_timer, self._incomplete_timer):
            if timer is not None:
                timer.cancel()
        self._idle_timer = None
        self._incomplete_timer = None

    def _arm_idle_timer(self) -> None:
        if self._idle_timer is not None:
            self._idle_timer.cancel()
        self._idle_timer = self.loop.call_later(
            self.server.idle_timeout_seconds,
            self._close_idle_connection,
        )

    def _close_idle_connection(self) -> None:
        SECURITY_LOG.info(
            "closing idle Modbus TCP connection session_id=%s timeout_seconds=%.3f",
            self.session_id,
            self.server.idle_timeout_seconds,
        )
        self.close()

    def _close_incomplete_request(self) -> None:
        SECURITY_LOG.warning(
            "closing incomplete Modbus TCP request session_id=%s timeout_seconds=%.3f",
            self.session_id,
            self.server.incomplete_request_timeout_seconds,
        )
        self.close()

    def data_received(self, data: bytes) -> None:
        pending_size = len(self.recv_buffer) + len(data)
        if pending_size > MAX_PENDING_REQUEST_BYTES:
            SECURITY_LOG.warning(
                "closing oversized Modbus TCP input buffered_bytes=%d session_id=%s",
                pending_size,
                self.session_id,
            )
            self.close()
            return
        super().data_received(data)
        self._arm_idle_timer()
        if self.recv_buffer:
            if self._incomplete_timer is None:
                self._incomplete_timer = self.loop.call_later(
                    self.server.incomplete_request_timeout_seconds,
                    self._close_incomplete_request,
                )
        elif self._incomplete_timer is not None:
            self._incomplete_timer.cancel()
            self._incomplete_timer = None

    def callback_data(self, data: bytes, addr: tuple | None = None) -> int:
        """Decode every complete ADU in one TCP delivery into a bounded queue."""
        total_used = 0
        remaining = data
        while remaining:
            frame = remaining
            try:
                used = TransactionManager.callback_data(self, remaining, addr)
            except ModbusIOException:
                self.server_send(
                    ExceptionResponse(40, exception_code=ExcCodes.ILLEGAL_FUNCTION),
                    0,
                )
                return len(data)
            except Exception as exc:  # pinned dependency boundary
                # A decoder that raises must not take the connection with it.
                # A truncated FC43 did exactly that -- struct.error escaped
                # into data_received and the socket died mid-conversation --
                # and a device that hangs up on a short frame is the loudest
                # tell a honeypot can emit. Real equipment answers. So we
                # answer, echoing the function code the frame claimed.
                SECURITY_LOG.warning(
                    "answering an undecodable request session_id=%s error=%s",
                    self.session_id,
                    exc,
                )
                claimed = (
                    frame[FUNCTION_CODE_OFFSET]
                    if len(frame) > FUNCTION_CODE_OFFSET
                    else 0
                )
                refusal = ExceptionResponse(
                    claimed, exception_code=ExcCodes.ILLEGAL_VALUE
                )
                # The header survived even though the payload did not, so the
                # transaction id is still readable -- and echoing it is what a
                # real device does. Answering every malformed frame with id 0
                # would hand a scanner a second tell to replace the first.
                if len(frame) >= 2:
                    refusal.transaction_id = int.from_bytes(frame[0:2], "big")
                if len(frame) > MBAP_UNIT_OFFSET:
                    refusal.dev_id = frame[MBAP_UNIT_OFFSET]
                self.server_send(refusal, addr)
                return len(data)
            if used <= 0:
                break
            total_used += used
            remaining = remaining[used:]
            pdu = self.last_pdu
            pdu_addr = self.last_addr
            self.last_pdu = None
            self.last_addr = None
            if pdu is None:
                continue
            requested = _requested_coil_value(frame[:used])
            if requested is not None and requested not in (COIL_ON, COIL_OFF):
                refusal = ExceptionResponse(
                    WRITE_SINGLE_COIL, exception_code=ExcCodes.ILLEGAL_VALUE
                )
                refusal.transaction_id = pdu.transaction_id
                refusal.dev_id = pdu.dev_id
                self.server_send(refusal, pdu_addr)
                continue
            if len(self._pending_requests) >= MAX_PENDING_REQUESTS:
                SECURITY_LOG.warning(
                    "closing excessive pipelined Modbus requests session_id=%s limit=%d",
                    self.session_id,
                    MAX_PENDING_REQUESTS,
                )
                self._pending_requests.clear()
                self.close()
                return len(data)
            self._pending_requests.append((pdu, pdu_addr))

        if self._pending_requests and (
            self._drain_task is None or self._drain_task.done()
        ):
            self._drain_task = self.loop.create_task(
                self._drain_requests(),
                name=f"modbus-session-{self.session_id}",
            )
        return total_used

    async def _drain_requests(self) -> None:
        while self._pending_requests:
            pdu, addr = self._pending_requests.popleft()
            await self._execute_request(pdu, addr)

    async def _execute_request(self, pdu: ModbusPDU, addr: tuple | None) -> None:
        context = None
        if self.source_ip is not None and self.source_port is not None:
            context = RequestTransportContext(
                source_ip=self.source_ip,
                source_port=self.source_port,
                transaction_id=int(pdu.transaction_id),
                session_id=self.session_id,
            )

        async def datastore_update() -> ModbusPDU | None:
            try:
                if self.server.broadcast_enable and not pdu.dev_id:
                    for device_id in self.server.context.device_ids():
                        await pdu.datastore_update(self.server.context, device_id)
                    return None
                return await pdu.datastore_update(self.server.context, pdu.dev_id)
            except NoSuchIdException:
                if self.server.ignore_missing_devices:
                    return None
                return ExceptionResponse(
                    pdu.function_code,
                    ExcCodes.GATEWAY_NO_RESPONSE,
                )
            except Exception as exc:  # pinned dependency boundary
                SECURITY_LOG.error(
                    "datastore request failed: %s; %s",
                    exc,
                    traceback.format_exc(),
                )
                return ExceptionResponse(pdu.function_code, ExcCodes.DEVICE_FAILURE)

        if context is None:
            response = await datastore_update()
        else:
            with bind_transport_context(context):
                response = await datastore_update()
        if response is None:
            return
        response.transaction_id = pdu.transaction_id
        response.dev_id = pdu.dev_id
        self.server_send(response, addr)


#: A single-coil write carries only two defined values; everything else is
#: outside the protocol. pymodbus turns the field into a bool before the
#: datastore ever sees it, so 0x1234 arrives as "on" and the device happily
#: agrees -- which no real controller does. The check has to happen on the
#: bytes, so it happens here.
COIL_ON = 0xFF00
COIL_OFF = 0x0000
WRITE_SINGLE_COIL = 5
#: Offsets inside a Modbus TCP frame: seven bytes of MBAP header, then the
#: function code, then the payload.
MBAP_UNIT_OFFSET = 6
FUNCTION_CODE_OFFSET = 7
SINGLE_WRITE_VALUE = slice(10, 12)


def _requested_coil_value(frame: bytes) -> int | None:
    """The raw value a single-coil write asked for, or None if it is not one."""
    if len(frame) < 12 or frame[FUNCTION_CODE_OFFSET] != WRITE_SINGLE_COIL:
        return None
    return int.from_bytes(frame[SINGLE_WRITE_VALUE], "big")


class ContextAwareModbusTcpServer(ModbusTcpServer):
    """Create one context-aware handler for every accepted TCP connection."""

    def __init__(
        self,
        *args,
        max_active_connections: int = DEFAULT_MAX_ACTIVE_CONNECTIONS,
        idle_timeout_seconds: float = DEFAULT_IDLE_TIMEOUT_SECONDS,
        incomplete_request_timeout_seconds: float = DEFAULT_INCOMPLETE_REQUEST_TIMEOUT_SECONDS,
        **kwargs,
    ) -> None:
        if max_active_connections <= 0:
            raise ValueError("max_active_connections must be positive")
        if idle_timeout_seconds <= 0:
            raise ValueError("idle_timeout_seconds must be positive")
        if incomplete_request_timeout_seconds <= 0:
            raise ValueError("incomplete_request_timeout_seconds must be positive")
        self.max_active_connections = max_active_connections
        self.idle_timeout_seconds = idle_timeout_seconds
        self.incomplete_request_timeout_seconds = incomplete_request_timeout_seconds
        self._active_connections: set[ContextAwareRequestHandler] = set()
        super().__init__(*args, **kwargs)

    def register_connection(self, handler: ContextAwareRequestHandler) -> bool:
        if len(self._active_connections) >= self.max_active_connections:
            return False
        self._active_connections.add(handler)
        return True

    def unregister_connection(self, handler: ContextAwareRequestHandler) -> None:
        self._active_connections.discard(handler)

    def callback_new_connection(self) -> ContextAwareRequestHandler:
        return ContextAwareRequestHandler(
            self,
            self.trace_packet,
            self.trace_pdu,
            self.trace_connect,
        )
