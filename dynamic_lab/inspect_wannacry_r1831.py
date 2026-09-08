#!/usr/bin/env python3
"""Read-only structural inspection for an extracted WannaCry R/1831 payload."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import struct
from pathlib import Path

import pefile


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    total = len(data)
    return -sum(
        (count / total) * math.log2(count / total)
        for count in counts
        if count
    )


def scan_local_headers(data: bytes) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    cursor = 0
    while True:
        offset = data.find(b"PK\x03\x04", cursor)
        if offset < 0:
            break
        cursor = offset + 4
        if offset + 30 > len(data):
            continue
        (
            version,
            flags,
            method,
            mod_time,
            mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            name_length,
            extra_length,
        ) = struct.unpack_from("<HHHHHIIIHH", data, offset + 4)
        name_start = offset + 30
        name_end = name_start + name_length
        data_start = name_end + extra_length
        if name_end > len(data) or data_start > len(data):
            name = "<out-of-range>"
        else:
            name = data[name_start:name_end].decode("utf-8", errors="replace")
        results.append(
            {
                "offset": offset,
                "version": version,
                "flags": flags,
                "method": method,
                "crc32": f"{crc32:08x}",
                "compressed_size": compressed_size,
                "uncompressed_size": uncompressed_size,
                "name_length": name_length,
                "extra_length": extra_length,
                "data_start": data_start,
                "data_end": data_start + compressed_size,
                "name": name,
                "plausible": (
                    version <= 100
                    and method in {0, 8, 9, 12, 14, 98}
                    and name_length <= 1024
                    and data_start + compressed_size <= len(data)
                ),
            }
        )
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("payload", type=Path)
    args = parser.parse_args()

    data = args.payload.read_bytes()
    pe = pefile.PE(data=data, fast_load=False)
    sections = []
    for section in pe.sections:
        raw_start = section.PointerToRawData
        raw_end = raw_start + section.SizeOfRawData
        content = data[raw_start:raw_end]
        sections.append(
            {
                "name": section.Name.rstrip(b"\0").decode("ascii", errors="replace"),
                "virtual_address": section.VirtualAddress,
                "virtual_size": section.Misc_VirtualSize,
                "raw_start": raw_start,
                "raw_size": section.SizeOfRawData,
                "raw_end": raw_end,
                "entropy": round(entropy(content), 4),
            }
        )
    headers = scan_local_headers(data)
    report = {
        "path": str(args.payload.resolve()),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "entry_rva": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        "image_base": pe.OPTIONAL_HEADER.ImageBase,
        "size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,
        "sections": sections,
        "overlay_offset": pe.get_overlay_data_start_offset(),
        "whole_file_entropy": round(entropy(data), 4),
        "markers": {
            "XIA": [index for index in range(len(data)) if data.startswith(b"XIA", index)][:20],
            "WANACRY": [index for index in range(len(data)) if data.startswith(b"WANACRY", index)][:20],
            "WNcry_password": [
                index
                for index in range(len(data))
                if data.startswith(b"WNcry@2ol7", index)
            ][:20],
            "RSA2": [index for index in range(len(data)) if data.startswith(b"RSA2", index)][:20],
            "zip_eocd": [
                index
                for index in range(len(data))
                if data.startswith(b"PK\x05\x06", index)
            ][:20],
        },
        "zip_local_headers_total": len(headers),
        "zip_local_headers_plausible": sum(bool(item["plausible"]) for item in headers),
        "zip_local_headers": headers,
        "pe_warnings": pe.get_warnings(),
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
