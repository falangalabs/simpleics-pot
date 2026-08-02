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
        document["device"]["vendor_url"] = ""
        self.assertIn("device.vendor_url must be a non-empty string", validate_map(document))


if __name__ == "__main__":
    unittest.main()
