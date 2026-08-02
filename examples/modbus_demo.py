#!/usr/bin/env python3
"""Harmless read/write/read demonstration for an explicitly authorized target."""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path

from pymodbus.client import ModbusTcpClient


ROOT = Path(__file__).resolve().parents[1]
UNIT_ID = int(
    json.loads((ROOT / "config" / "register_map.v1.json").read_text(encoding="utf-8"))[
        "device"
    ]["unit_id"]
)


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
        initial = client.read_holding_registers(0, count=7, device_id=UNIT_ID)
        if initial.isError():
            raise RuntimeError(f"initial read failed: {initial}")
        write = client.write_register(5, 8000, device_id=UNIT_ID)
        if write.isError():
            raise RuntimeError(f"bounded setpoint write failed: {write}")
        final = client.read_holding_registers(5, count=1, device_id=UNIT_ID)
        if final.isError():
            raise RuntimeError(f"read-back failed: {final}")
        print(
            {
                "initial_level_setpoint": initial.registers[0],
                "initial_pump_speed_setpoint": initial.registers[5],
                "read_back_pump_speed_setpoint": final.registers[0],
            }
        )
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
