#!/usr/bin/env python3
"""Read-only marker scan across the user-provided WannaCry container layers."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from extract_r1831_bundle import find_resource, read_outer_pe, u32


MARKERS = (
    b"WANACRY!",
    b"t.wnry",
    b"u.wnry",
    b"taskdl.exe",
    b"taskse.exe",
    b"PK\x03\x04",
    b"PK\x05\x06",
)


def offsets(data: bytes, marker: bytes, limit: int = 100) -> list[int]:
    found: list[int] = []
    cursor = 0
    while len(found) < limit:
        offset = data.find(marker, cursor)
        if offset < 0:
            break
        found.append(offset)
        cursor = offset + 1
    return found


def describe(name: str, data: bytes) -> dict[str, object]:
    return {
        "name": name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "markers": {
            marker.decode("ascii", errors="backslashreplace"): offsets(data, marker)
            for marker in MARKERS
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source_zip", type=Path)
    parser.add_argument("--password", default="infected")
    args = parser.parse_args()

    _, outer = read_outer_pe(args.source_zip, args.password.encode())
    packed = find_resource(outer, "W", 101)
    intermediate_size = u32(packed, 0)
    intermediate = packed[4 : 4 + intermediate_size]
    r1831 = find_resource(intermediate, "R", 1831)
    print(
        json.dumps(
            [
                describe("outer", outer),
                describe("W/101 intermediate", intermediate),
                describe("R/1831", r1831),
            ],
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
