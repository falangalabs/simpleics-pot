from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from simpleics_pot.telemetry import EVENT_SCHEMA_VERSION, EventFactory  # noqa: E402
from simpleics_pot.transport_context import (  # noqa: E402
    RequestTransportContext,
    bind_transport_context,
)


class EventFactoryTests(unittest.TestCase):
    def test_event_is_versioned_ordered_and_json_serializable(self) -> None:
        factory = EventFactory()
        first = factory.create(
            unit_id=1,
            function_code=3,
            operation="read",
            area="holding_register",
            address=0,
            count=2,
            register_keys=("level_setpoint", "high_alarm_limit"),
        )
        second = factory.create(
            unit_id=1,
            function_code=6,
            operation="write",
            area="holding_register",
            address=0,
            count=1,
            register_keys=("level_setpoint",),
            requested_values=(6000,),
            before={"level_setpoint": 4321},  # arbitrary fixture value: must not
            # coincide with any deployed register default, or the public
            # build refuses to ship the file.
            after={"level_setpoint": 6000},
        )

        self.assertEqual(EVENT_SCHEMA_VERSION, first.schema_version)
        self.assertEqual("1.2.0", first.schema_version)
        self.assertIsNone(first.response_values)
        self.assertEqual(first.sensor_sequence + 1, second.sensor_sequence)
        self.assertEqual(6000, json.loads(second.to_json())["after"]["level_setpoint"])

    def test_missing_transport_identity_is_not_fabricated(self) -> None:
        event = EventFactory().create(
            unit_id=1,
            function_code=4,
            operation="read",
            area="input_register",
            address=0,
            count=1,
        )
        self.assertIsNone(event.source_ip)
        self.assertIsNone(event.source_port)
        self.assertIsNone(event.transaction_id)
        self.assertIsNone(event.session_id)
        self.assertIsNone(event.response_values)
        self.assertEqual("unavailable_in_protocol_adapter", event.transport_context)

    def test_bound_transport_identity_is_copied_then_cleared(self) -> None:
        factory = EventFactory()
        transport = RequestTransportContext(
            source_ip="192.0.2.10",
            source_port=41000,
            transaction_id=4660,
            session_id="5af71150-4dce-4f95-8f29-0d29109da718",
        )
        with bind_transport_context(transport):
            enriched = factory.create(
                unit_id=1,
                function_code=3,
                operation="read",
                area="holding_register",
                address=0,
                count=1,
            )
        cleared = factory.create(
            unit_id=1,
            function_code=3,
            operation="read",
            area="holding_register",
            address=0,
            count=1,
        )

        self.assertEqual("192.0.2.10", enriched.source_ip)
        self.assertEqual(41000, enriched.source_port)
        self.assertEqual(4660, enriched.transaction_id)
        self.assertEqual(transport.session_id, enriched.session_id)
        self.assertEqual("pymodbus_request_handler", enriched.transport_context)
        self.assertIsNone(cleared.source_ip)


if __name__ == "__main__":
    unittest.main()
