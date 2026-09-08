#!/usr/bin/env python3
"""Inspect one password-protected ZIP member entirely in memory.

The member is never written to disk and is never executed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import re
import subprocess
from pathlib import Path
from typing import Any

import pefile


ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")
KEYWORDS = re.compile(
    r"(?i)"
    r"(encrypt|decrypt|ransom|bitcoin|wallet|recover|restore|locked|"
    r"\.wncry|\.lock|readme|shadow|vssadmin|wbadmin|bcdedit|wevtutil|"
    r"powershell|cmd\.exe|schtasks|currentversion\\run|createservice|"
    r"crypt(?:encrypt|decrypt|gen|import|export|acquire)|bcrypt|"
    r"aes|chacha|rsa|public key|private key|nonce|"
    r"http://|https://|\.onion|socket|wininet|winhttp|internetopen|"
    r"virtualbox|vmware|sandbox|debugger|isdebuggerpresent|"
    r"process32|createprocess|writeprocessmemory|virtualalloc|"
    r"documents|desktop|appdata|programdata|"
    r"\.(?:docx?|xlsx?|pptx?|pdf|txt|jpg|png|zip|sql|db|py|js)\b)"
)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    return round(
        -sum(
            (count / length) * math.log2(count / length)
            for count in counts
            if count
        ),
        4,
    )


def strings(data: bytes) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for match in ASCII_RE.finditer(data):
        found.append((match.start(), match.group().decode("ascii", errors="replace")))
    for match in UTF16_RE.finditer(data):
        found.append(
            (match.start(), match.group().decode("utf-16le", errors="replace"))
        )
    return sorted(found)


def resource_inventory(pe: pefile.PE) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return result
    for type_entry in root.entries:
        type_value = (
            str(type_entry.name)
            if type_entry.name is not None
            else int(type_entry.struct.Id)
        )
        for name_entry in getattr(type_entry.directory, "entries", []):
            name_value = (
                str(name_entry.name)
                if name_entry.name is not None
                else int(name_entry.struct.Id)
            )
            for language_entry in getattr(name_entry.directory, "entries", []):
                data_entry = language_entry.data.struct
                result.append(
                    {
                        "type": type_value,
                        "name": name_value,
                        "language": int(language_entry.struct.Id),
                        "rva": int(data_entry.OffsetToData),
                        "size": int(data_entry.Size),
                    }
                )
    return result[:1000]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--password", default="infected")
    args = parser.parse_args()

    completed = subprocess.run(
        ["7z", "x", "-so", f"-p{args.password}", str(args.archive)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    data = completed.stdout
    if data[:2] != b"MZ":
        raise ValueError("The decrypted member is not a PE file")

    pe = pefile.PE(data=data, fast_load=False)
    imports: list[dict[str, Any]] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        imports.append(
            {
                "dll": entry.dll.decode("ascii", errors="replace"),
                "symbols": [
                    (
                        symbol.name.decode("ascii", errors="replace")
                        if symbol.name
                        else f"ordinal:{symbol.ordinal}"
                    )
                    for symbol in entry.imports
                ],
            }
        )
    exports = [
        {
            "name": (
                symbol.name.decode("ascii", errors="replace")
                if symbol.name
                else None
            ),
            "ordinal": int(symbol.ordinal),
            "address": int(symbol.address),
        }
        for symbol in getattr(
            getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []
        )
    ]
    string_rows = strings(data)
    suspicious = [
        {"offset": offset, "text": value[:1000]}
        for offset, value in string_rows
        if KEYWORDS.search(value)
    ][:1000]
    sections = []
    for section in pe.sections:
        content = section.get_data()
        sections.append(
            {
                "name": section.Name.rstrip(b"\0").decode("ascii", errors="replace"),
                "rva": int(section.VirtualAddress),
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_offset": int(section.PointerToRawData),
                "raw_size": int(section.SizeOfRawData),
                "entropy": entropy(content),
                "characteristics": f"0x{int(section.Characteristics):08x}",
            }
        )
    directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    clr_rva = int(directories[14].VirtualAddress) if len(directories) > 14 else 0
    timestamp = int(pe.FILE_HEADER.TimeDateStamp)
    report = {
        "safety": {
            "archive_member_written_to_disk": False,
            "sample_executed": False,
            "operation": "7-Zip stdout to in-memory PE parsing",
        },
        "archive": {
            "path": str(args.archive.resolve()),
            "size": args.archive.stat().st_size,
            "sha256": hashlib.sha256(args.archive.read_bytes()).hexdigest(),
        },
        "member": {
            "size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "entropy": entropy(data),
        },
        "pe": {
            "machine": f"0x{int(pe.FILE_HEADER.Machine):04x}",
            "format": (
                "PE32+" if int(pe.OPTIONAL_HEADER.Magic) == 0x20B else "PE32"
            ),
            "subsystem": int(pe.OPTIONAL_HEADER.Subsystem),
            "image_base": int(pe.OPTIONAL_HEADER.ImageBase),
            "entry_rva": int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_size": int(pe.OPTIONAL_HEADER.SizeOfImage),
            "header_size": int(pe.OPTIONAL_HEADER.SizeOfHeaders),
            "compile_timestamp": timestamp,
            "compile_time_utc": (
                dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc).isoformat()
                if 0 < timestamp < 0x80000000
                else None
            ),
            "imphash": pe.get_imphash(),
            "is_dotnet": bool(clr_rva),
            "pyinstaller_marker": b"MEI\x0c\x0b\x0a\x0b\x0e" in data,
            "upx_markers": data.count(b"UPX"),
            "overlay_offset": pe.get_overlay_data_start_offset(),
            "sections": sections,
            "imports": imports,
            "exports": exports,
            "resources": resource_inventory(pe),
            "warnings": pe.get_warnings(),
        },
        "string_counts": {
            "total": len(string_rows),
            "suspicious": len(suspicious),
        },
        "suspicious_strings": suspicious,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
