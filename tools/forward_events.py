#!/usr/bin/env python3
"""Forward honeypot events from a log stream to syslog.

Run it beside the pot, never inside it:

    docker compose logs -f --no-log-prefix | \\
        python3 tools/forward_events.py --host 10.0.0.5 --port 514

WHY IT IS A SEPARATE PROCESS. The decoy holds no outbound client and no
destination credential, and that is a security property rather than an
omission: a honeypot that can dial out is a honeypot that can be turned into
somebody's pivot. Everything that reaches the network from the pot's own
process is a Modbus reply to whoever asked. This tool reads what the pot has
already printed, so compromising the decoy gains an attacker nothing here --
there is nothing in it to take.

WHY SYSLOG. It is the one transport every collector already speaks, and it
needs no key, token or account. That also means it is unauthenticated and, over
UDP, unencrypted and lossy. On a link you control to a collector you control,
that is the usual and reasonable trade. Across anything else, send it over TCP
into a local relay and let the relay do the transport security -- do not put
credentials in here later to solve that; put a relay in front instead.

IT MUST NEVER SLOW THE POT DOWN. A honeypot that stalls when its collector is
unreachable is a honeypot that answers Modbus differently on a bad network day,
and timing is exactly what a careful visitor measures. So the socket is
non-blocking, a full buffer drops the event, and the drop is counted and
reported rather than retried.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import signal
import socket
import sys
import time
from dataclasses import dataclass, field

#: An event reaches stdout as a log record, so the JSON object is preceded by
#: the timestamp, level and logger name. Both shapes are accepted: the prefixed
#: line, and the bare object for anyone piping the JSON straight in.
EVENT_LINE = re.compile(r"^(?:.*?simpleics_pot\.event\s+)?(\{.*\})\s*$")

#: RFC 5424 wants a priority of facility * 8 + severity. local0/informational
#: is the ordinary choice for application events and is what collectors expect
#: to filter on.
DEFAULT_FACILITY = 16
DEFAULT_SEVERITY = 6

#: A line longer than this is not an event we produced; it is either a mangled
#: stream or somebody feeding the tool something else. Bounded so a single
#: enormous line cannot become the whole run's memory.
MAX_LINE_BYTES = 64 * 1024
#: Syslog datagrams above this are commonly truncated in transit, and a
#: truncated JSON object is worse than a dropped one -- the collector stores
#: something that will not parse and nobody notices for a month.
MAX_DATAGRAM_BYTES = 8 * 1024


@dataclass
class Counters:
    forwarded: int = 0
    dropped_unreachable: int = 0
    dropped_oversized: int = 0
    dropped_rate_limited: int = 0
    ignored_non_event: int = 0
    started: float = field(default_factory=time.monotonic)

    def summary(self) -> str:
        return json.dumps(
            {
                "forwarded": self.forwarded,
                "dropped_unreachable": self.dropped_unreachable,
                "dropped_oversized": self.dropped_oversized,
                "dropped_rate_limited": self.dropped_rate_limited,
                "ignored_non_event": self.ignored_non_event,
            },
            sort_keys=True,
        )


def parse_event(line: str) -> dict | None:
    """Pull the event object out of one line, or None if there is not one.

    Anything else on the stream -- startup banners, library warnings, a blank
    line -- is not an error. The pot logs those too, and a forwarder that died
    on the first one would be useless.
    """
    match = EVENT_LINE.match(line.strip())
    if match is None:
        return None
    try:
        event = json.loads(match.group(1))
    except ValueError:
        return None
    if not isinstance(event, dict) or event.get("event_type") != "modbus_transaction":
        return None
    return event


def format_syslog(event: dict, hostname: str, app_name: str, facility: int) -> bytes:
    """One RFC 5424 line, structured data left empty and the event as the message."""
    priority = facility * 8 + DEFAULT_SEVERITY
    timestamp = str(event.get("observed_at") or "-")
    # The event id makes a natural message id: collectors dedupe on it, and it
    # is already unique per event.
    message_id = str(event.get("event_id") or "-")[:32] or "-"
    payload = json.dumps(event, separators=(",", ":"), sort_keys=True)
    header = f"<{priority}>1 {timestamp} {hostname} {app_name} - {message_id} - "
    return (header + payload).encode("utf-8", errors="replace")


class Forwarder:
    def __init__(
        self,
        host: str,
        port: int,
        protocol: str,
        hostname: str,
        app_name: str,
        facility: int,
        events_per_second: float,
        counters: Counters,
        stream=None,
    ) -> None:
        self.address = (host, port)
        self.protocol = protocol
        self.hostname = hostname
        self.app_name = app_name
        self.facility = facility
        self.counters = counters
        self.stream = stream
        # A token bucket, not a minimum gap between sends. The first version
        # enforced a gap and dropped two of the first three events a real pot
        # produced, because Modbus traffic arrives in bursts -- a scanner sends
        # twenty requests as fast as it can, and those are the twenty most
        # worth keeping. The bucket lets a burst through and only bites on a
        # sustained flood, which is what the limit is actually for.
        self._rate = float(events_per_second)
        self._capacity = max(1.0, self._rate) if self._rate > 0 else 0.0
        self._tokens = self._capacity
        self._refilled = time.monotonic()
        self._socket: socket.socket | None = None

    def _take_token(self, now: float) -> bool:
        if self._rate <= 0:
            return True
        self._tokens = min(
            self._capacity, self._tokens + (now - self._refilled) * self._rate
        )
        self._refilled = now
        if self._tokens < 1.0:
            return False
        self._tokens -= 1.0
        return True

    def _connect(self) -> socket.socket:
        if self._socket is not None:
            return self._socket
        if self.protocol == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(self.address)
        sock.setblocking(False)
        self._socket = sock
        return sock

    def send(self, event: dict) -> bool:
        now = time.monotonic()
        if not self._take_token(now):
            # Dropped rather than queued. A queue would grow without bound
            # exactly when the pot is busiest, which is when it matters that
            # the pot is not competing with this process for memory.
            self.counters.dropped_rate_limited += 1
            return False
        datagram = format_syslog(event, self.hostname, self.app_name, self.facility)
        if len(datagram) > MAX_DATAGRAM_BYTES:
            self.counters.dropped_oversized += 1
            return False
        if self.stream is not None:
            self.stream.write(datagram.decode("utf-8", errors="replace") + "\n")
            self.counters.forwarded += 1
            return True
        try:
            sock = self._connect()
            if self.protocol == "udp":
                sock.sendto(datagram, self.address)
            else:
                sock.sendall(datagram + b"\n")
        except (OSError, BlockingIOError):
            # Never retried and never blocking: the collector being down is
            # the collector's problem, and the pot must not answer Modbus any
            # differently because of it.
            self.counters.dropped_unreachable += 1
            self._reset()
            return False
        self.counters.forwarded += 1
        return True

    def _reset(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
        self._socket = None


def _destination(value: str) -> str:
    """Refuse a destination that is obviously not one.

    There is no default host on purpose. A forwarder with a built-in
    destination is a forwarder that sends somebody else's honeypot traffic
    somewhere nobody chose.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if not value or len(value) > 253:
            raise argparse.ArgumentTypeError("destination host is not usable")
        return value
    if address.is_multicast or address.is_unspecified:
        raise argparse.ArgumentTypeError("destination host is not a single collector")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", type=_destination, help="collector address")
    parser.add_argument("--port", type=int, default=514)
    parser.add_argument("--protocol", choices=("udp", "tcp"), default="udp")
    parser.add_argument("--hostname", default=socket.gethostname())
    parser.add_argument("--app-name", default="simpleics-pot")
    parser.add_argument("--facility", type=int, default=DEFAULT_FACILITY)
    parser.add_argument(
        "--max-events-per-second",
        type=float,
        default=200.0,
        help="sustained ceiling; bursts up to one second's worth pass, 0 disables",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the syslog lines instead of sending them",
    )
    parser.add_argument(
        "--summary-seconds",
        type=float,
        default=60.0,
        help="how often to report counters on stderr; 0 disables",
    )
    return parser


def run(arguments: argparse.Namespace, source, output=None, error=None) -> int:
    output = output if output is not None else sys.stdout
    error = error if error is not None else sys.stderr
    counters = Counters()
    forwarder = Forwarder(
        host=arguments.host or "",
        port=arguments.port,
        protocol=arguments.protocol,
        hostname=arguments.hostname,
        app_name=arguments.app_name,
        facility=arguments.facility,
        events_per_second=arguments.max_events_per_second,
        counters=counters,
        stream=output if arguments.dry_run else None,
    )
    last_summary = time.monotonic()
    for raw in source:
        if len(raw) > MAX_LINE_BYTES:
            counters.ignored_non_event += 1
            continue
        event = parse_event(raw)
        if event is None:
            counters.ignored_non_event += 1
        else:
            forwarder.send(event)
        if arguments.summary_seconds:
            now = time.monotonic()
            if now - last_summary >= arguments.summary_seconds:
                print(counters.summary(), file=error, flush=True)
                last_summary = now
    print(counters.summary(), file=error, flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if not arguments.dry_run and not arguments.host:
        build_parser().error("--host is required unless --dry-run is given")
    # A closed pipe is how this ends normally -- the pot stopped, or the reader
    # in front of it did. Exiting quietly beats a traceback in an operator's log.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL) if hasattr(signal, "SIGPIPE") else None
    try:
        return run(arguments, sys.stdin)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
