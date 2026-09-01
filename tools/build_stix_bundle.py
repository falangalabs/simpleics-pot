#!/usr/bin/env python3
"""Package honeypot events into a STIX 2.1 bundle for someone to collect.

    docker compose logs --no-log-prefix | \\
        python3 tools/build_stix_bundle.py --output-dir /var/lib/simpleics-drop

The pot writes a file and stops there. How the file leaves the host -- rsync,
scp, a pull from a collector, a USB stick -- is yours to build, and that is
deliberate: the decoy has no outbound client and no destination credential, so
a visitor who owns the container still finds nothing in it that reaches your
network. Sending is a job for something that is not the honeypot.

WHAT THE BUNDLE SAYS, AND WHAT IT DOES NOT. This edition observes; it does not
judge. Each source that spoke Modbus becomes an `observed-data` with when it
was first and last seen and how many events it produced, plus an `indicator`
carrying its address and the function codes it used. There is no verdict,
score or threat classification, because nothing here computed one and a label
invented at packaging time would be a guess wearing a standard's clothes.

NON-GLOBAL SOURCES ARE LEFT OUT BY DEFAULT. Your own testing, your colleague
on the LAN and the container's own bridge all speak to the pot, and none of
them is intelligence about anybody. Publishing them is how a honeypot ends up
distributing a map of the people who run it. Pass --include-non-global if you
are packaging a lab exercise and know that is what you want.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import uuid

#: Same shape the pot prints: a log record whose tail is the event object. The
#: bare object is accepted too, for anyone piping JSON straight in.
EVENT_LINE = re.compile(r"^(?:.*?simpleics_pot\.event\s+)?(\{.*\})\s*$")

#: STIX 2.1 names this namespace for deterministic SCO identifiers, so the same
#: address always yields the same id and a consumer can merge two bundles
#: without deciding whether it has seen the address before.
STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

#: Bounds, because the input is a log stream fed by whoever is on the network.
MAX_LINE_BYTES = 64 * 1024
MAX_SOURCES = 10_000
MAX_EVENTS = 5_000_000


def parse_event(line: str) -> dict | None:
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


def _stix_time(value: str | None) -> str | None:
    """RFC 3339 with milliseconds and a Z, which is what STIX 2.1 requires."""
    if not value:
        return None
    try:
        moment = dt.datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.timezone.utc)
    return (
        moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    )


def _sco_id(kind: str, contributing: dict) -> str:
    """A STIX 2.1 cyber-observable id: UUIDv5 over the defining properties."""
    canonical = json.dumps(contributing, sort_keys=True, separators=(",", ":"))
    return f"{kind}--{uuid.uuid5(STIX_NAMESPACE, canonical)}"


def _sdo_id(kind: str, seed: str) -> str:
    """Derived rather than random, so re-packaging the same window is stable.

    A fresh uuid4 per run would make every re-run look like new intelligence to
    a consumer that dedupes on id, which is most of them.
    """
    return f"{kind}--{uuid.uuid5(STIX_NAMESPACE, f'{kind}:{seed}')}"


#: MITRE ATT&CK for ICS technique IDs, keyed by the Modbus function code that
#: was REQUESTED. Public taxonomy, applied to the request as it arrived.
#:
#: Read carefully, because the distinction is the whole point: this says "a
#: request of this kind corresponds to this technique". It does NOT say the
#: sender achieved anything, intended anything, or is any particular sort of
#: actor. A device that answers an identification request with an exception has
#: still been asked, and the asking is what is being labelled.
#:
#: Only unambiguous codes are here, and that is a deliberate choice to under-
#: claim:
#:
#:   * writes (5, 6, 15, 16) -- a command message aimed at process state. On a
#:     decoy there is no master entitled to send one, so the request is
#:     unauthorised by construction rather than by judgement.
#:   * identification reads (17, 43) -- asking the device to say what it is,
#:     which is discovery in any deployment.
#:
#: Ordinary reads (1-4) are deliberately NOT mapped. A read is what a real SCADA
#: client does all day; calling it a technique would put a label on the most
#: common and least informative thing this device sees. Diagnostics (8) is not
#: mapped either: only some of its subfunctions are disruptive, this edition
#: does not record which one was asked for, and mapping the whole code would be
#: guessing at intent.
ATTACK_ICS_BY_FUNCTION_CODE = {
    5: "T0855",
    6: "T0855",
    15: "T0855",
    16: "T0855",
    17: "T0846",
    43: "T0846",
}


def attack_ics_techniques(function_codes) -> list[str]:
    """Technique ids for the codes seen, sorted and deduplicated.

    An unmapped code contributes nothing rather than a fallback: silence is the
    honest output for a request this table has no confident reading of.
    """
    return sorted(
        {
            ATTACK_ICS_BY_FUNCTION_CODE[code]
            for code in function_codes
            if code in ATTACK_ICS_BY_FUNCTION_CODE
        }
    )


class Source:
    __slots__ = ("value", "first", "last", "count", "function_codes", "wrote")

    def __init__(self, value: str) -> None:
        self.value = value
        self.first: str | None = None
        self.last: str | None = None
        self.count = 0
        self.function_codes: set[int] = set()
        self.wrote = False

    def observe(self, event: dict) -> None:
        self.count += 1
        moment = _stix_time(event.get("observed_at"))
        if moment:
            self.first = moment if self.first is None else min(self.first, moment)
            self.last = moment if self.last is None else max(self.last, moment)
        code = event.get("function_code")
        if isinstance(code, int):
            self.function_codes.add(code)
        if event.get("operation") == "write":
            self.wrote = True


def collect(lines, include_non_global: bool = False) -> dict[str, Source]:
    sources: dict[str, Source] = {}
    seen_events = 0
    for raw in lines:
        if len(raw) > MAX_LINE_BYTES:
            continue
        event = parse_event(raw)
        if event is None:
            continue
        seen_events += 1
        if seen_events > MAX_EVENTS:
            raise RuntimeError("event stream exceeded the packaging bound")
        value = event.get("source_ip")
        if not isinstance(value, str):
            continue
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if not include_non_global and not address.is_global:
            continue
        key = address.compressed
        if key not in sources:
            if len(sources) >= MAX_SOURCES:
                raise RuntimeError("source count exceeded the packaging bound")
            sources[key] = Source(key)
        sources[key].observe(event)
    return sources


def build_bundle(sources: dict[str, Source], sensor_name: str, now: str) -> dict:
    identity_id = _sdo_id("identity", sensor_name)
    objects: list[dict] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": sensor_name,
            "identity_class": "system",
            "description": "SimpleICS Pot sensor; observations only, no assessment.",
        }
    ]
    for value in sorted(sources):
        source = sources[value]
        kind = "ipv4-addr" if ":" not in value else "ipv6-addr"
        observable_id = _sco_id(kind, {"value": value})
        first = source.first or now
        last = source.last or first
        codes = ",".join(str(code) for code in sorted(source.function_codes))
        objects.append(
            {"type": kind, "spec_version": "2.1", "id": observable_id, "value": value}
        )
        objects.append(
            {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": _sdo_id("observed-data", f"{value}|{first}|{last}"),
                "created_by_ref": identity_id,
                "created": now,
                "modified": now,
                "first_observed": first,
                "last_observed": last,
                "number_observed": min(source.count, 999_999_999),
                "object_refs": [observable_id],
            }
        )
        labels = ["modbus-interaction"]
        if source.wrote:
            # Factual, not a verdict: this source sent a write request. What it
            # means is the consumer's call, not the packager's.
            labels.append("attempted-write")
        # Same rule, one level up: a technique id is a taxonomy entry for the
        # REQUEST, so a consumer can group this across sensors and vendors
        # without every one of them inventing its own vocabulary. Ids only, no
        # technique names -- a name is prose, and prose in a bundle starts
        # reading as a conclusion.
        for technique in attack_ics_techniques(source.function_codes):
            labels.append(f"attack-pattern-ics:{technique}")
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": _sdo_id("indicator", f"{value}|{first}"),
                "created_by_ref": identity_id,
                "created": now,
                "modified": now,
                "name": f"Modbus source {value}",
                "description": (
                    f"Observed {source.count} Modbus transactions; "
                    f"function codes seen: {codes or 'none'}."
                ),
                "indicator_types": ["anomalous-activity"],
                "pattern": f"[{kind}:value = '{value}']",
                "pattern_type": "stix",
                "valid_from": first,
                "labels": labels,
            }
        )
    return {
        "type": "bundle",
        "id": _sdo_id("bundle", f"{sensor_name}|{now}"),
        "objects": objects,
    }


def write_bundle(bundle: dict, output_dir: Path, now: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = now.replace(":", "").replace("-", "").replace(".", "")
    path = output_dir / f"simpleics-pot-{stamp}.stix.json"
    # Written whole and then moved, so a collector that arrives mid-write never
    # picks up half a bundle.
    temporary = path.with_suffix(".partial")
    temporary.write_text(
        json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, path)
    path.chmod(0o644)
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--output-dir", type=Path, help="where to drop the bundle; omit for stdout"
    )
    parser.add_argument("--sensor-name", default="simpleics-pot")
    parser.add_argument(
        "--include-non-global",
        action="store_true",
        help=(
            "also package private, loopback and reserved sources -- note that "
            "the documentation ranges (203.0.113.x, 198.51.100.x, 192.0.2.x) "
            "count as reserved, so a test run using one produces an empty "
            "bundle without this"
        ),
    )
    parser.add_argument("--input", type=Path, help="read this file instead of stdin")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    if arguments.input:
        with arguments.input.open(encoding="utf-8", errors="replace") as handle:
            sources = collect(handle, arguments.include_non_global)
    else:
        sources = collect(sys.stdin, arguments.include_non_global)
    bundle = build_bundle(sources, arguments.sensor_name, now)
    if arguments.output_dir:
        path = write_bundle(bundle, arguments.output_dir, now)
        print(
            json.dumps(
                {"bundle": str(path), "sources": len(sources), "objects": len(bundle["objects"])},
                sort_keys=True,
            )
        )
    else:
        print(json.dumps(bundle, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
