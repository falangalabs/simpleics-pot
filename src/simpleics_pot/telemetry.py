"""Versioned, JSON-serializable application telemetry."""

from __future__ import annotations

import json
import threading
import uuid
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from .transport_context import current_transport_context


EVENT_SCHEMA_VERSION = "1.2.0"


@dataclass(frozen=True, slots=True)
class ProtocolEvent:
    schema_version: str
    event_id: str
    observed_at: str
    sensor_sequence: int
    event_type: str
    protocol: str
    unit_id: int
    function_code: int
    operation: str
    area: str | None
    address: int
    count: int
    register_keys: tuple[str, ...]
    requested_values: tuple[int | bool, ...] | None
    response_values: dict[str, int | bool] | None
    result: str
    exception_code: int | None
    before: dict[str, int | bool] | None
    after: dict[str, int | bool] | None
    source_ip: str | None
    source_port: int | None
    transaction_id: int | None
    session_id: str | None
    transport_context: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)


EventSink = Callable[[ProtocolEvent], None]


class EventFactory:
    """Create ordered events; transport identity is deliberately explicit."""

    def __init__(self) -> None:
        self._sequence = 0
        self._lock = threading.Lock()

    def create(
        self,
        *,
        unit_id: int,
        function_code: int,
        operation: str,
        area: str | None,
        address: int,
        count: int,
        register_keys: Sequence[str] = (),
        requested_values: Sequence[int | bool] | None = None,
        response_values: dict[str, int | bool] | None = None,
        result: str = "ok",
        exception_code: int | None = None,
        before: dict[str, int | bool] | None = None,
        after: dict[str, int | bool] | None = None,
    ) -> ProtocolEvent:
        with self._lock:
            self._sequence += 1
            sequence = self._sequence
        transport = current_transport_context()
        return ProtocolEvent(
            schema_version=EVENT_SCHEMA_VERSION,
            event_id=str(uuid.uuid4()),
            observed_at=datetime.now(UTC).isoformat(timespec="milliseconds"),
            sensor_sequence=sequence,
            event_type="modbus_transaction",
            protocol="modbus_tcp",
            unit_id=unit_id,
            function_code=function_code,
            operation=operation,
            area=area,
            address=address,
            count=count,
            register_keys=tuple(register_keys),
            requested_values=None if requested_values is None else tuple(requested_values),
            response_values=None if response_values is None else dict(response_values),
            result=result,
            exception_code=exception_code,
            before=before,
            after=after,
            source_ip=None if transport is None else transport.source_ip,
            source_port=None if transport is None else transport.source_port,
            transaction_id=None if transport is None else transport.transaction_id,
            session_id=None if transport is None else transport.session_id,
            transport_context=(
                "unavailable_in_protocol_adapter"
                if transport is None
                else "pymodbus_request_handler"
            ),
        )
