#!/usr/bin/env python3
"""Validate the dependency-free SimpleICS register map specification."""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MAP = ROOT / "config" / "register_map.v1.json"
ALLOWED_AREAS = {"coil", "discrete_input", "holding_register", "input_register"}
WRITABLE_AREAS = {"coil", "holding_register"}
REQUIRED_FIELDS = {
    "key",
    "area",
    "address",
    "reference",
    "data_type",
    "scale",
    "unit",
    "minimum",
    "maximum",
    "default",
    "writable",
    "description",
}
REQUIRED_DEVICE_STRINGS = {
    "vendor_name",
    "product_code",
    "product_name",
    "model_name",
    "revision",
    "user_application_name",
}
#: MEI-14 object 0x03. Optional on real equipment and commonly absent, so an
#: empty value is valid and means "do not publish the object" — pymodbus drops
#: falsy identity objects. A non-empty value must still be a real scheme, and
#: must never be an RFC 2606/6761 reserved name: those cannot exist on real
#: equipment, so one read of FC43 would prove the device synthetic.
OPTIONAL_DEVICE_STRINGS = {"vendor_url"}
RESERVED_TLDS = ("invalid", "example", "test", "localhost")


def _uses_reserved_name(url: str) -> bool:
    """Whether the URL's host sits under an RFC 2606/6761 reserved name.

    Matched on the host's trailing label, not as a substring: `acme.testlab.com`
    and `example-automation.de` are perfectly ordinary names, and a substring
    rule would reject them while a real vendor URL is exactly what we want here.
    """
    remainder = url.split("://", 1)[-1]
    host = remainder.split("/", 1)[0].split("@")[-1].split(":", 1)[0]
    labels = [label for label in host.casefold().rstrip(".").split(".") if label]
    if not labels:
        return False
    # `example.com`/`example.net`/`example.org` are reserved as whole names,
    # while `.invalid`, `.test` and `.localhost` are reserved as the last label.
    if labels[-1] in RESERVED_TLDS:
        return True
    return len(labels) >= 2 and labels[-2] == "example" and labels[-1] in {
        "com",
        "net",
        "org",
    }
PROCESS_BOUNDS = {
    "tick_seconds": (0.05, 10.0),
    "capacity_liters": (100.0, 1_000_000.0),
    "max_pump_flow_lps": (0.01, 10_000.0),
    "nominal_inlet_flow_lps": (0.0, 10_000.0),
    "auto_hysteresis_raw": (1, 5_000),
    "actuator_delay_seconds": (0.05, 60.0),
}
#: Bounds are declared only for the quantities this edition's plant actually
#: has. Carrying an entry for a key the model never reads would publish the
#: name of a behaviour that exists somewhere else, and the bound and its
#: comment would describe it -- which is how a validator becomes a datasheet
#: for the thing it is not validating.


class MapValidationError(ValueError):
    """Raised when a register map violates an invariant."""


def load_map(path: Path = DEFAULT_MAP) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def validate_map(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    registers = document.get("registers")
    if not isinstance(registers, list) or not registers:
        return ["registers must be a non-empty list"]

    seen_keys: set[str] = set()
    seen_addresses: set[tuple[str, int]] = set()

    device = document.get("device", {})
    if device.get("synthetic_identity") is not True:
        errors.append("device.synthetic_identity must be true")
    if not isinstance(device.get("unit_id"), int) or not 1 <= device["unit_id"] <= 247:
        errors.append("device.unit_id must be an integer between 1 and 247")
    for key in sorted(REQUIRED_DEVICE_STRINGS):
        if not isinstance(device.get(key), str) or not device[key].strip():
            errors.append(f"device.{key} must be a non-empty string")
    for key in sorted(OPTIONAL_DEVICE_STRINGS):
        if not isinstance(device.get(key), str):
            errors.append(f"device.{key} must be a string, empty to omit it")
    vendor_url = device.get("vendor_url")
    if isinstance(vendor_url, str) and vendor_url:
        if not vendor_url.startswith(("https://", "http://")):
            errors.append("device.vendor_url must use http or https")
        if _uses_reserved_name(vendor_url):
            errors.append(
                "device.vendor_url must not use an RFC-reserved name; it would "
                "prove the device synthetic in one read of FC43"
            )

    process = document.get("process", {})
    if not isinstance(process.get("name"), str) or not process["name"].strip():
        errors.append("process.name must be a non-empty string")
    if not isinstance(process.get("deterministic_seed"), int):
        errors.append("process.deterministic_seed must be an integer")
    for key, (minimum, maximum) in PROCESS_BOUNDS.items():
        value = process.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            errors.append(f"process.{key} must be numeric")
        elif not math.isfinite(value) or not minimum <= value <= maximum:
            errors.append(f"process.{key} must be between {minimum} and {maximum}")

    for index, register in enumerate(registers):
        prefix = f"registers[{index}]"
        if not isinstance(register, dict):
            errors.append(f"{prefix} must be an object")
            continue

        missing = REQUIRED_FIELDS - register.keys()
        if missing:
            errors.append(f"{prefix} missing fields: {', '.join(sorted(missing))}")
            continue

        key = register["key"]
        area = register["area"]
        address = register["address"]

        if not isinstance(key, str) or not key:
            errors.append(f"{prefix}.key must be a non-empty string")
        elif key in seen_keys:
            errors.append(f"duplicate key: {key}")
        else:
            seen_keys.add(key)

        if area not in ALLOWED_AREAS:
            errors.append(f"{prefix}.area is unsupported: {area!r}")

        if not isinstance(address, int) or not 0 <= address <= 65535:
            errors.append(f"{prefix}.address must be an integer from 0 to 65535")
        else:
            location = (area, address)
            if location in seen_addresses:
                errors.append(f"duplicate address in {area}: {address}")
            seen_addresses.add(location)

        minimum = register["minimum"]
        maximum = register["maximum"]
        default = register["default"]
        if not all(isinstance(value, (int, float)) for value in (minimum, maximum, default)):
            errors.append(f"{prefix} minimum/maximum/default must be numeric")
        elif minimum > maximum:
            errors.append(f"{prefix} minimum exceeds maximum")
        elif not minimum <= default <= maximum:
            errors.append(f"{prefix} default is outside minimum/maximum")

        writable = register["writable"]
        if not isinstance(writable, bool):
            errors.append(f"{prefix}.writable must be boolean")
        elif writable:
            if area not in WRITABLE_AREAS:
                errors.append(f"{prefix} writable register is in read-only area {area}")
            if not register.get("write_effect"):
                errors.append(f"{prefix} writable register has no write_effect")

        if not isinstance(register["scale"], (int, float)) or register["scale"] <= 0:
            errors.append(f"{prefix}.scale must be a positive number")

    invariants = document.get("invariants")
    if not isinstance(invariants, list) or not invariants:
        errors.append("invariants must be a non-empty list")

    return errors


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT_MAP
    try:
        document = load_map(path)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot load {path}: {exc}", file=sys.stderr)
        return 2

    errors = validate_map(document)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(f"OK: {path} ({len(document['registers'])} registers, map {document['map_version']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
