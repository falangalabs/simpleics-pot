"""Safe-by-default local runtime for SimpleICS Pot."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import logging
from collections.abc import Sequence

from .model import WetWellProcess
from .protocol import ProcessProtocolAdapter
from .server import ContextAwareModbusTcpServer
from .telemetry import ProtocolEvent


LOG = logging.getLogger("simpleics_pot")
EVENT_LOG = logging.getLogger("simpleics_pot.event")
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 1502
MAX_PYMODBUS_LOG_CHARS = 1024


class BoundedLibraryLogFilter(logging.Filter):
    """Prevent malformed wire data from amplifying PyModbus log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not record.name.startswith("pymodbus"):
            return True
        message = record.getMessage()
        if len(message) > MAX_PYMODBUS_LOG_CHARS:
            record.msg = message[:MAX_PYMODBUS_LOG_CHARS] + "...[truncated]"
            record.args = ()
        return True


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    for handler in logging.getLogger().handlers:
        handler.addFilter(BoundedLibraryLogFilter())


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local SimpleICS Modbus server")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="Required acknowledgement before binding outside loopback",
    )
    parser.add_argument("--log-level", default="INFO", choices=("DEBUG", "INFO", "WARNING"))
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if not _is_loopback(args.host) and not args.allow_non_loopback:
        parser.error("non-loopback bind requires --allow-non-loopback")
    return args


async def _process_loop(model: WetWellProcess, interval: float = 1.0) -> None:
    loop = asyncio.get_running_loop()
    next_tick = loop.time() + interval
    while True:
        await asyncio.sleep(max(0.0, next_tick - loop.time()))
        model.tick(interval)
        next_tick += interval


async def run_server(host: str, port: int) -> None:
    model = WetWellProcess()
    adapter = ProcessProtocolAdapter(model, event_sink=_log_event)
    server = ContextAwareModbusTcpServer(
        adapter.build_context(),
        address=(host, port),
        identity=adapter.identity,
        ignore_missing_devices=True,
    )
    process_task = asyncio.create_task(_process_loop(model), name="process-model")
    LOG.info("starting synthetic Modbus device on %s:%d unit_id=%d", host, port, model.register_map.unit_id)
    try:
        await server.serve_forever()
    finally:
        process_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await process_task
        await server.shutdown()


def _log_event(event: ProtocolEvent) -> None:
    """Emit one JSON event; deployment log rotation provides the bounded spool."""
    EVENT_LOG.info(event.to_json())


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    configure_logging(args.log_level)
    try:
        asyncio.run(run_server(args.host, args.port))
    except KeyboardInterrupt:
        LOG.info("server stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
