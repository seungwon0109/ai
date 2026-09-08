#!/usr/bin/env python3
"""Extract only WannaCry resource R/1831 into a short-lived CAPE ZIP.

The outer PE and the intermediate worm/dropper PE are kept in memory and are
never written to disk. The output archive contains only the known ransomware
payload plus harmless canary files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path


EXPECTED_OUTER_SHA256 = (
    "9487edf9b75f4c15e3ba6ccbae23588ee3dc9c4983417f1b469278af17fc3847"
)
EXPECTED_R1831_SHA256 = (
    "e08c3337c4395d59de15866abcf9c017581b7fa1cb13cfb2cfc5d77e1d8bbbc1"
)


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


@dataclass(frozen=True)
class Section:
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int


class PortableExecutable:
    def __init__(self, data: bytes) -> None:
        self.data = data
        if data[:2] != b"MZ":
            raise ValueError("Input is not a PE file")
        pe_offset = u32(data, 0x3C)
        if data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise ValueError("PE signature is missing")

        coff = pe_offset + 4
        section_count = u16(data, coff + 2)
        optional_size = u16(data, coff + 16)
        optional = coff + 20
        magic = u16(data, optional)
        if magic == 0x10B:
            data_directory = optional + 96
        elif magic == 0x20B:
            data_directory = optional + 112
        else:
            raise ValueError(f"Unsupported optional-header magic: 0x{magic:04x}")

        self.resource_rva = u32(data, data_directory + (2 * 8))
        self.resource_size = u32(data, data_directory + (2 * 8) + 4)

        section_table = optional + optional_size
        sections: list[Section] = []
        for index in range(section_count):
            entry = section_table + (index * 40)
            sections.append(
                Section(
                    virtual_address=u32(data, entry + 12),
                    virtual_size=u32(data, entry + 8),
                    raw_offset=u32(data, entry + 20),
                    raw_size=u32(data, entry + 16),
                )
            )
        self.sections = sections

    def rva_to_offset(self, rva: int) -> int:
        for section in self.sections:
            span = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + span:
                return section.raw_offset + (rva - section.virtual_address)
        if rva < len(self.data):
            return rva
        raise ValueError(f"RVA is outside mapped sections: 0x{rva:x}")

    def resources(self) -> list[tuple[tuple[str | int, ...], bytes]]:
        if not self.resource_rva:
            return []
        base = self.rva_to_offset(self.resource_rva)
        results: list[tuple[tuple[str | int, ...], bytes]] = []

        def read_name(value: int) -> str | int:
            if not value & 0x80000000:
                return value
            name_offset = base + (value & 0x7FFFFFFF)
            length = u16(self.data, name_offset)
            start = name_offset + 2
            end = start + (length * 2)
            return self.data[start:end].decode("utf-16le", errors="replace")

        def walk(directory_relative: int, path: tuple[str | int, ...]) -> None:
            directory = base + directory_relative
            named_count = u16(self.data, directory + 12)
            id_count = u16(self.data, directory + 14)
            for index in range(named_count + id_count):
                entry = directory + 16 + (index * 8)
                component = read_name(u32(self.data, entry))
                target = u32(self.data, entry + 4)
                next_path = path + (component,)
                if target & 0x80000000:
                    walk(target & 0x7FFFFFFF, next_path)
                    continue
                data_entry = base + target
                data_rva = u32(self.data, data_entry)
                size = u32(self.data, data_entry + 4)
                file_offset = self.rva_to_offset(data_rva)
                results.append(
                    (next_path, self.data[file_offset : file_offset + size])
                )

        walk(0, ())
        return results


def find_resource(
    pe_data: bytes,
    resource_type: str,
    resource_id: int,
) -> bytes:
    resources = PortableExecutable(pe_data).resources()
    for path, content in resources:
        if len(path) >= 2 and path[0] == resource_type and path[1] == resource_id:
            return content
    inventory = [list(path) for path, _ in resources]
    raise ValueError(
        f"Resource {resource_type}/{resource_id} was not found; "
        f"inventory={inventory}"
    )


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_outer_pe(archive_path: Path, password: bytes) -> tuple[str, bytes]:
    with zipfile.ZipFile(archive_path) as archive:
        files = [info for info in archive.infolist() if not info.is_dir()]
        if len(files) != 1:
            raise ValueError(
                f"Expected one file in source ZIP, found {len(files)}"
            )
        info = files[0]
        try:
            return info.filename, archive.read(info, pwd=password)
        except NotImplementedError:
            # Stream the unsupported ZIP member into memory with 7-Zip.
            # The outer PE is never extracted to the filesystem.
            result = subprocess.run(
                [
                    "7z",
                    "x",
                    "-so",
                    f"-p{password.decode('utf-8')}",
                    str(archive_path),
                    info.filename,
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return info.filename, result.stdout


def make_bundle(output_path: Path, payload: bytes) -> dict[str, object]:
    marker = b"CAPE-ISOLATED-CANARY-20260731\n"
    canaries = {
        "case_notes.txt": marker + b"Controlled ransomware behavior canary.\n",
        "budget.xlsx": marker + b"Quarter,Revenue\nQ1,1000\n",
        "report.docx": marker + b"Controlled laboratory document.\n",
        "presentation.pptx": marker + b"Controlled presentation.\n",
        "manual.pdf": b"%PDF-1.4\n% " + marker + b"%%EOF\n",
        "photo.jpg": b"\xff\xd8\xff\xe0CAPE\xff\xd9",
        "database.sqlite": marker + b"SQLite canary placeholder.\n",
        "source_code.py": b"# " + marker + b"print('controlled canary')\n",
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        output_path,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        archive.writestr("tasksche.exe", payload)
        for name, content in canaries.items():
            archive.writestr(name, content)
    os.chmod(output_path, 0o600)
    return {
        "bundle_path": str(output_path),
        "bundle_sha256": sha256(output_path.read_bytes()),
        "bundle_size": output_path.stat().st_size,
        "executed_member": "tasksche.exe",
        "canary_members": sorted(canaries),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source_zip", type=Path)
    parser.add_argument("output_zip", type=Path)
    parser.add_argument("--password", default="infected")
    args = parser.parse_args()

    source_zip_hash = sha256(args.source_zip.read_bytes())
    member_name, outer = read_outer_pe(
        args.source_zip,
        args.password.encode("utf-8"),
    )
    outer_hash = sha256(outer)
    if outer_hash != EXPECTED_OUTER_SHA256:
        raise ValueError(
            f"Unexpected outer PE SHA256: {outer_hash}; "
            f"expected {EXPECTED_OUTER_SHA256}"
        )

    packed_resource = find_resource(outer, "W", 101)
    if len(packed_resource) < 4:
        raise ValueError("W/101 resource is too short")
    intermediate_size = u32(packed_resource, 0)
    intermediate = packed_resource[4 : 4 + intermediate_size]
    if len(intermediate) != intermediate_size or intermediate[:2] != b"MZ":
        raise ValueError("W/101 did not contain the expected intermediate PE")

    payload = find_resource(intermediate, "R", 1831)
    payload_hash = sha256(payload)
    if payload_hash != EXPECTED_R1831_SHA256:
        raise ValueError(
            f"Unexpected R/1831 SHA256: {payload_hash}; "
            f"expected {EXPECTED_R1831_SHA256}"
        )

    metadata = {
        "source_zip": str(args.source_zip),
        "source_zip_sha256": source_zip_hash,
        "outer_member": member_name,
        "outer_pe_sha256": outer_hash,
        "intermediate_pe_sha256": sha256(intermediate),
        "intermediate_pe_size": len(intermediate),
        "r1831_sha256": payload_hash,
        "r1831_size": len(payload),
        "safety": {
            "outer_written_to_disk": False,
            "intermediate_written_to_disk": False,
            "outer_executed": False,
            "intermediate_executed": False,
            "only_r1831_scheduled_for_execution": True,
        },
    }
    metadata.update(make_bundle(args.output_zip, payload))
    print(json.dumps(metadata, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

