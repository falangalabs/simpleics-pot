from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.validate_register_map import load_map, validate_map  # noqa: E402


class RegisterMapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = load_map()

    def test_repository_map_is_valid(self) -> None:
        self.assertEqual([], validate_map(self.document))

    def test_duplicate_address_is_rejected_within_area(self) -> None:
        document = copy.deepcopy(self.document)
        document["registers"][1]["area"] = document["registers"][0]["area"]
        document["registers"][1]["address"] = document["registers"][0]["address"]
        self.assertTrue(any("duplicate address" in item for item in validate_map(document)))

    def test_same_offset_is_allowed_in_different_areas(self) -> None:
        locations = [(item["area"], item["address"]) for item in self.document["registers"]]
        self.assertEqual(len(locations), len(set(locations)))
        offsets = [item["address"] for item in self.document["registers"]]
        self.assertLess(len(set(offsets)), len(offsets))

    def test_writable_register_requires_effect(self) -> None:
        document = copy.deepcopy(self.document)
        writable = next(item for item in document["registers"] if item["writable"])
        writable.pop("write_effect")
        self.assertTrue(any("write_effect" in item for item in validate_map(document)))

    def test_read_only_area_cannot_be_writable(self) -> None:
        document = copy.deepcopy(self.document)
        register = next(item for item in document["registers"] if item["area"] == "input_register")
        register["writable"] = True
        register["write_effect"] = "invalid test effect"
        self.assertTrue(any("read-only area" in item for item in validate_map(document)))

    def test_default_must_be_in_range(self) -> None:
        document = copy.deepcopy(self.document)
        document["registers"][0]["default"] = document["registers"][0]["maximum"] + 1
        self.assertTrue(any("outside minimum/maximum" in item for item in validate_map(document)))

    def test_identity_must_be_synthetic(self) -> None:
        document = copy.deepcopy(self.document)
        document["device"]["synthetic_identity"] = False
        self.assertIn("device.synthetic_identity must be true", validate_map(document))

    def test_process_dynamics_are_required_and_bounded(self) -> None:
        document = copy.deepcopy(self.document)
        document["process"].pop("capacity_liters")
        self.assertIn("process.capacity_liters must be numeric", validate_map(document))

        document = copy.deepcopy(self.document)
        document["process"]["actuator_delay_seconds"] = 0
        self.assertTrue(
            any("process.actuator_delay_seconds" in item for item in validate_map(document))
        )

    def test_protocol_identity_strings_are_required(self) -> None:
        document = copy.deepcopy(self.document)
        document["device"]["vendor_name"] = ""
        self.assertIn(
            "device.vendor_name must be a non-empty string", validate_map(document)
        )

    def test_vendor_url_may_be_omitted_but_never_reserved(self) -> None:
        """Empty means "do not publish object 0x03", as real controllers do."""
        document = copy.deepcopy(self.document)
        document["device"]["vendor_url"] = ""
        self.assertEqual([], validate_map(document))

        for reserved in (
            "https://example.invalid/x",
            "http://millgate.test",
            "https://a.example/b",
            "https://example.com/support",
            "http://sub.example.org",
            "https://localhost",
        ):
            document["device"]["vendor_url"] = reserved
            self.assertTrue(
                any("RFC-reserved" in item for item in validate_map(document)),
                f"{reserved} was accepted",
            )

        # Matched on the host's trailing label, not as a substring: these are
        # ordinary names a real vendor could hold, and rejecting them would
        # push the map towards having no vendor URL for the wrong reason.
        for ordinary in (
            "https://acme.testlab.com/plc",
            "https://example-automation.de",
            "http://millgate-controls.co.uk/support",
            "https://invalidate.io",
        ):
            document["device"]["vendor_url"] = ordinary
            self.assertEqual([], validate_map(document), f"{ordinary} was rejected")

        document["device"]["vendor_url"] = "ftp://millgate.example.com"
        self.assertIn("device.vendor_url must use http or https", validate_map(document))


if __name__ == "__main__":
    unittest.main()
