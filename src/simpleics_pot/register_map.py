"""Typed access to the versioned Modbus register map."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROJECT_REGISTER_MAP = PROJECT_ROOT / "config" / "register_map.v1.json"
PACKAGE_REGISTER_MAP = Path(__file__).resolve().parent / "data" / "register_map.v1.json"
DEFAULT_REGISTER_MAP = (
    PROJECT_REGISTER_MAP if PROJECT_REGISTER_MAP.is_file() else PACKAGE_REGISTER_MAP
)


@dataclass(frozen=True, slots=True)
class RegisterDefinition:
    """A single addressable process value from the register manifest."""

    key: str
    area: str
    address: int
    reference: int
    data_type: str
    scale: float
    unit: str
    minimum: int | float
    maximum: int | float
    default: int | float
    writable: bool
    description: str
    write_effect: str | None = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> RegisterDefinition:
        return cls(
            key=str(value["key"]),
            area=str(value["area"]),
            address=int(value["address"]),
            reference=int(value["reference"]),
            data_type=str(value["data_type"]),
            scale=float(value["scale"]),
            unit=str(value["unit"]),
            minimum=value["minimum"],
            maximum=value["maximum"],
            default=value["default"],
            writable=bool(value["writable"]),
            description=str(value["description"]),
            write_effect=str(value["write_effect"]) if value.get("write_effect") else None,
        )


class RegisterMap:
    """Immutable lookup indexes backed by the checked-in JSON manifest."""

    def __init__(self, document: Mapping[str, Any]):
        definitions = tuple(RegisterDefinition.from_dict(item) for item in document["registers"])
        by_key = {item.key: item for item in definitions}
        by_location = {(item.area, item.address): item for item in definitions}
        if len(by_key) != len(definitions) or len(by_location) != len(definitions):
            raise ValueError("register map contains duplicate keys or locations")

        self.document = MappingProxyType(dict(document))
        self.definitions = definitions
        self.by_key: Mapping[str, RegisterDefinition] = MappingProxyType(by_key)
        self.by_location: Mapping[tuple[str, int], RegisterDefinition] = MappingProxyType(by_location)

    @classmethod
    def load(cls, path: Path = DEFAULT_REGISTER_MAP) -> RegisterMap:
        with path.open(encoding="utf-8") as handle:
            return cls(json.load(handle))

    @property
    def unit_id(self) -> int:
        return int(self.document["device"]["unit_id"])

    @property
    def map_version(self) -> str:
        return str(self.document["map_version"])

    def for_area(self, area: str) -> tuple[RegisterDefinition, ...]:
        return tuple(item for item in self.definitions if item.area == area)

    def require_key(self, key: str) -> RegisterDefinition:
        try:
            return self.by_key[key]
        except KeyError as exc:
            raise KeyError(f"unknown register key: {key}") from exc

    def require_location(self, area: str, address: int) -> RegisterDefinition:
        try:
            return self.by_location[(area, address)]
        except KeyError as exc:
            raise KeyError(f"undefined {area} address: {address}") from exc
