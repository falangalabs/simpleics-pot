"""Request-scoped transport identity for protocol telemetry."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RequestTransportContext:
    """Trusted metadata captured by the TCP request handler."""

    source_ip: str
    source_port: int
    transaction_id: int
    session_id: str


_CURRENT_CONTEXT: ContextVar[RequestTransportContext | None] = ContextVar(
    "simpleics_request_transport_context",
    default=None,
)


def current_transport_context() -> RequestTransportContext | None:
    """Return metadata for the request executing in the current async task."""
    return _CURRENT_CONTEXT.get()


@contextmanager
def bind_transport_context(
    context: RequestTransportContext,
) -> Iterator[None]:
    """Bind metadata for one datastore operation and reliably remove it."""
    token = _CURRENT_CONTEXT.set(context)
    try:
        yield
    finally:
        _CURRENT_CONTEXT.reset(token)
