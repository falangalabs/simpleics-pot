#!/usr/bin/env python3
"""Reject common secret artifacts and live-deployment identifiers."""

from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IGNORED_PARTS = {".git", ".venv", "__pycache__", "build", "dist"}
FORBIDDEN_SUFFIXES = {".age", ".key", ".p12", ".pfx", ".pcap", ".pcapng"}
FORBIDDEN_BASENAMES = {".env", "authorized_keys", "credentials", "id_ed25519", "id_rsa"}
EMAIL_PATTERN = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
IPV4_PATTERN = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
PRIVATE_KEY_MARKERS = tuple(
    "-----BEGIN " + kind + " PRIVATE KEY-----"
    for kind in ("", "OPENSSH", "RSA", "EC")
)
ACTION_USES_PATTERN = re.compile(r"(?m)^\s*-?\s*uses:\s*([^\s#]+)")
FULL_COMMIT_REF = re.compile(r"^[^@\s]+@[0-9a-fA-F]{40}$")


def _is_allowed_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    return address.is_loopback or address.is_unspecified or address.is_private


def check_repository(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in IGNORED_PARTS for part in relative.parts):
            continue
        if path.is_dir():
            continue
        if path.is_symlink() or not path.is_file():
            errors.append(f"unsafe filesystem entry: {relative}")
            continue
        if path.name.casefold() in FORBIDDEN_BASENAMES:
            errors.append(f"forbidden basename: {relative}")
        if path.suffix.casefold() in FORBIDDEN_SUFFIXES:
            errors.append(f"forbidden artifact type: {relative}")
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append(f"unexpected non-text artifact: {relative}")
            continue
        if EMAIL_PATTERN.search(text):
            errors.append(f"email address found: {relative}")
        if any(marker in text for marker in PRIVATE_KEY_MARKERS):
            errors.append(f"private-key marker found: {relative}")
        for match in IPV4_PATTERN.finditer(text):
            value = match.group(0)
            if not _is_allowed_address(value):
                errors.append(f"public IPv4 address found in {relative}")
                break
        if relative.parts[:2] == (".github", "workflows"):
            if "pull_request_target:" in text:
                errors.append(f"unsafe privileged workflow trigger: {relative}")
            for match in ACTION_USES_PATTERN.finditer(text):
                reference = match.group(1)
                if reference.startswith("./"):
                    continue
                if not FULL_COMMIT_REF.fullmatch(reference):
                    errors.append(f"GitHub Action is not pinned to a full commit: {relative}")
                    break
    return errors


def main() -> int:
    errors = check_repository()
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("OK: repository contains no forbidden secret artifacts or public IPv4 addresses")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
