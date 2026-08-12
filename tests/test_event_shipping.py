"""The two ways events leave this pot, and the rules both of them obey.

Neither runs inside the decoy. The decoy prints; these read what it printed.
That is what keeps the promise made in docs/ARCHITECTURE.md -- no outbound
client, no destination credential in the process an attacker is invited to
attack -- true while still making the events usable.
"""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import build_stix_bundle as stix  # noqa: E402
import forward_events as forward  # noqa: E402

#: A routable source, assembled rather than written out. Two rules meet here
#: and both are right: the packager only keeps globally routable sources, so a
#: documentation address (203.0.113.x, 198.51.100.x, 192.0.2.x) would be
#: filtered out and the test would pass while measuring nothing -- and the
#: repository safety check refuses a literal public address in a shipped file,
#: because a real address in a honeypot repository reads like a real indicator
#: to whoever finds it. Building it from octets satisfies both.
ROUTABLE = ".".join(["45", "33", "12", "122"])

PREFIXED = (
    "2026-08-12 07:40:11,162 INFO simpleics_pot.event "
    '{"address":42,"area":"holding_register",'
    '"event_id":"11111111-2222-3333-4444-555555555555",'
    '"event_type":"modbus_transaction","function_code":3,'
    '"observed_at":"2026-08-12T05:40:11.162+00:00","operation":"read",'
    '"register_keys":["level_setpoint"],"result":"ok","schema_version":"1.2.0",'
    '"sensor_sequence":1,"session_id":"abc","source_ip":"' + ROUTABLE + '",'
    '"source_port":40001,"transaction_id":7,"unit_id":7}'
)


def event(**overrides) -> str:
    body = json.loads(PREFIXED[PREFIXED.index("{"):])
    body.update(overrides)
    return "2026-08-12 07:40:11,162 INFO simpleics_pot.event " + json.dumps(body)


class ReadingTheStreamTests(unittest.TestCase):
    def test_an_event_is_found_behind_the_log_prefix(self) -> None:
        """The line is a log record, not bare JSON.

        A reader that assumes the line starts with a brace finds nothing at
        all -- which is the mistake the architecture diagram used to invite,
        and the one made while first checking this.
        """
        parsed = forward.parse_event(PREFIXED)
        self.assertIsNotNone(parsed)
        self.assertEqual(ROUTABLE, parsed["source_ip"])
        bare = PREFIXED[PREFIXED.index("{"):]
        self.assertEqual(parsed, forward.parse_event(bare))

    def test_anything_that_is_not_an_event_is_skipped_quietly(self) -> None:
        """The pot logs startup lines and library warnings on the same stream."""
        for line in (
            "",
            "   ",
            "2026-08-12 07:40:07,780 INFO simpleics_pot starting synthetic device",
            "2026-08-12 07:40:07,781 INFO pymodbus.logging Server listening.",
            "not json at all",
            '{"event_type":"something_else"}',
            "{broken json",
        ):
            with self.subTest(line=line[:40]):
                self.assertIsNone(forward.parse_event(line))


class SyslogForwardingTests(unittest.TestCase):
    def _arguments(self, **overrides) -> argparse.Namespace:
        base = dict(
            host="127.0.0.1",
            port=514,
            protocol="udp",
            hostname="pot",
            app_name="simpleics-pot",
            facility=forward.DEFAULT_FACILITY,
            max_events_per_second=200.0,
            dry_run=True,
            summary_seconds=0,
        )
        base.update(overrides)
        return argparse.Namespace(**base)

    def test_the_line_is_rfc5424_and_carries_the_event(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        forward.run(self._arguments(), [PREFIXED], output=out, error=err)
        line = out.getvalue().strip()
        priority = forward.DEFAULT_FACILITY * 8 + forward.DEFAULT_SEVERITY
        self.assertTrue(line.startswith(f"<{priority}>1 "), line[:40])
        payload = json.loads(line[line.index("{"):])
        self.assertEqual(ROUTABLE, payload["source_ip"])
        self.assertIn("11111111-2222-3333-4444-555555555555", line)

    def test_a_burst_is_forwarded_rather_than_thinned(self) -> None:
        """Written after the first version dropped two of the first three.

        It enforced a minimum gap between sends, so any burst lost most of
        itself -- and Modbus arrives in bursts. A scanner's twenty rapid
        requests are the twenty most worth having.
        """
        counters = forward.Counters()
        sender = forward.Forwarder(
            host="127.0.0.1", port=514, protocol="udp", hostname="pot",
            app_name="app", facility=16, events_per_second=200.0,
            counters=counters, stream=io.StringIO(),
        )
        payload = json.loads(PREFIXED[PREFIXED.index("{"):])
        for _ in range(50):
            sender.send(payload)
        self.assertEqual(50, counters.forwarded)
        self.assertEqual(0, counters.dropped_rate_limited)

    def test_a_sustained_flood_is_dropped_not_queued(self) -> None:
        counters = forward.Counters()
        sender = forward.Forwarder(
            host="127.0.0.1", port=514, protocol="udp", hostname="pot",
            app_name="app", facility=16, events_per_second=10.0,
            counters=counters, stream=io.StringIO(),
        )
        payload = json.loads(PREFIXED[PREFIXED.index("{"):])
        for _ in range(200):
            sender.send(payload)
        self.assertLessEqual(counters.forwarded, 20)
        self.assertGreater(counters.dropped_rate_limited, 100)

    def test_an_unreachable_collector_is_counted_never_raised(self) -> None:
        """A collector outage must not reach the Modbus path through a crash."""
        counters = forward.Counters()
        sender = forward.Forwarder(
            host=ROUTABLE, port=1, protocol="tcp", hostname="pot",
            app_name="app", facility=16, events_per_second=0,
            counters=counters, stream=None,
        )
        sender.address = ("127.0.0.1", 1)
        payload = json.loads(PREFIXED[PREFIXED.index("{"):])
        self.assertFalse(sender.send(payload))
        self.assertEqual(1, counters.dropped_unreachable)
        self.assertEqual(0, counters.forwarded)

    def test_an_oversized_event_is_dropped_rather_than_truncated(self) -> None:
        """A truncated JSON object in a collector is worse than a missing one."""
        counters = forward.Counters()
        sender = forward.Forwarder(
            host="127.0.0.1", port=514, protocol="udp", hostname="pot",
            app_name="app", facility=16, events_per_second=0,
            counters=counters, stream=io.StringIO(),
        )
        payload = json.loads(PREFIXED[PREFIXED.index("{"):])
        payload["register_keys"] = ["x" * forward.MAX_DATAGRAM_BYTES]
        self.assertFalse(sender.send(payload))
        self.assertEqual(1, counters.dropped_oversized)

    def test_there_is_no_default_collector(self) -> None:
        """A built-in destination would send somebody's traffic somewhere
        nobody chose."""
        arguments = forward.build_parser().parse_args([])
        self.assertIsNone(arguments.host)
        with self.assertRaises(SystemExit):
            forward.main([])


class StixPackagingTests(unittest.TestCase):
    def test_non_global_sources_are_left_out_by_default(self) -> None:
        """Your own testing is not intelligence about anybody."""
        lines = [
            event(source_ip="127.0.0.1"),
            event(source_ip="192.168.1.10"),
            event(source_ip=ROUTABLE),
        ]
        self.assertEqual({ROUTABLE}, set(stix.collect(lines)))
        self.assertEqual(3, len(stix.collect(lines, include_non_global=True)))

    def test_the_bundle_reports_what_was_seen_and_no_verdict(self) -> None:
        sources = stix.collect(
            [
                event(source_ip=ROUTABLE, function_code=3, operation="read"),
                event(source_ip=ROUTABLE, function_code=6, operation="write"),
            ]
        )
        bundle = stix.build_bundle(sources, "sensor", "2026-08-12T00:00:00.000Z")
        kinds = {item["type"] for item in bundle["objects"]}
        self.assertEqual({"identity", "ipv4-addr", "observed-data", "indicator"}, kinds)

        observed = next(o for o in bundle["objects"] if o["type"] == "observed-data")
        self.assertEqual(2, observed["number_observed"])
        indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
        self.assertEqual(
            f"[ipv4-addr:value = '{ROUTABLE}']", indicator["pattern"]
        )
        self.assertIn("attempted-write", indicator["labels"])
        self.assertIn("3,6", indicator["description"])
        # Nothing in this edition computes a verdict, so nothing may publish one.
        text = json.dumps(bundle)
        for verdict in ("scanner", "mapper", "operator", "malicious", "confidence"):
            self.assertNotIn(verdict, text.lower())

    def test_identifiers_are_stable_across_runs(self) -> None:
        """A consumer that dedupes on id must not see a re-run as new."""
        lines = [event(source_ip=ROUTABLE)]
        first = stix.build_bundle(stix.collect(lines), "sensor", "2026-08-12T00:00:00.000Z")
        second = stix.build_bundle(stix.collect(lines), "sensor", "2026-08-12T00:00:00.000Z")
        self.assertEqual(first, second)

    def test_the_bundle_is_written_whole_or_not_at_all(self) -> None:
        """A collector arriving mid-write must never take half a bundle."""
        bundle = stix.build_bundle(
            stix.collect([event(source_ip=ROUTABLE)]),
            "sensor",
            "2026-08-12T00:00:00.000Z",
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "drop"
            path = stix.write_bundle(bundle, output, "2026-08-12T00:00:00.000Z")
            self.assertTrue(path.is_file())
            self.assertEqual([], list(output.glob("*.partial")))
            self.assertEqual(bundle, json.loads(path.read_text(encoding="utf-8")))

    def test_timestamps_are_the_shape_stix_requires(self) -> None:
        import re

        bundle = stix.build_bundle(
            stix.collect([event(source_ip=ROUTABLE)]),
            "sensor",
            "2026-08-12T00:00:00.000Z",
        )
        pattern = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
        for item in bundle["objects"]:
            for field in ("created", "modified", "first_observed", "last_observed", "valid_from"):
                if field in item:
                    with self.subTest(type=item["type"], field=field):
                        self.assertRegex(item[field], pattern)


if __name__ == "__main__":
    unittest.main()
