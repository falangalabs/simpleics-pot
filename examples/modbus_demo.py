#!/usr/bin/env python3
"""Harmless read/write/read demonstration for an explicitly authorized target."""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path

from pymodbus.client import ModbusTcpClient


ROOT = Path(__file__).resolve().parents[1]
_MAP = json.loads(
    (ROOT / "config" / "register_map.v1.json").read_text(encoding="utf-8")
)
UNIT_ID = int(_MAP["device"]["unit_id"])


def address_of(key: str) -> int:
    """Where this device keeps a value, asked rather than assumed.

    The map is the persona and the persona is meant to be changed -- that is
    most of the point of running your own. A demonstration that hardcodes 0
    works only for whoever left the block where it started, and this one did
    not: after the published layout moved, the first command in the README
    answered with an exception.
    """
    for register in _MAP["registers"]:
        if register["key"] == key:
            return int(register["address"])
    raise KeyError(f"the register map has no {key}")


def block(area: str) -> tuple[int, int]:
    """First address of an area and how many registers it holds."""
    addresses = [int(r["address"]) for r in _MAP["registers"] if r["area"] == area]
    return min(addresses), len(addresses)


def _is_loopback(host: str) -> bool:
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1502)
    parser.add_argument(
        "--acknowledge-authorized-target",
        action="store_true",
        help="required for a non-loopback target that you own or may test",
    )
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if not _is_loopback(args.host) and not args.acknowledge_authorized_target:
        parser.error("a non-loopback target requires --acknowledge-authorized-target")

    client = ModbusTcpClient(args.host, port=args.port, timeout=2, retries=0)
    try:
        if not client.connect():
            raise RuntimeError("could not connect")
        base, count = block("holding_register")
        initial = client.read_holding_registers(base, count=count, device_id=UNIT_ID)
        if initial.isError():
            raise RuntimeError(f"initial read failed: {initial}")
        speed = address_of("pump_speed_setpoint")
        write = client.write_register(speed, 8000, device_id=UNIT_ID)
        if write.isError():
            raise RuntimeError(f"bounded setpoint write failed: {write}")
        final = client.read_holding_registers(speed, count=1, device_id=UNIT_ID)
        if final.isError():
            raise RuntimeError(f"read-back failed: {final}")
        print(
            {
                "initial_level_setpoint": initial.registers[
                    address_of("level_setpoint") - base
                ],
                "initial_pump_speed_setpoint": initial.registers[speed - base],
                "read_back_pump_speed_setpoint": final.registers[0],
            }
        )
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
