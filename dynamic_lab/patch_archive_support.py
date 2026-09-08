#!/usr/bin/env python3
"""Install password-protected ZIP support into the local analysis pipeline."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if new in text:
        return
    if old not in text:
        raise RuntimeError(f"Patch marker not found in {path}: {old[:80]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")


def patch_main() -> None:
    path = ROOT / "main.py"
    replace_once(
        path,
        '    parser.add_argument("--cape-package")\n',
        '    parser.add_argument("--cape-package")\n'
        '    parser.add_argument("--archive-password")\n'
        '    parser.add_argument("--archive-member")\n',
    )
    replace_once(
        path,
        '    if args.capa_path:\n'
        '        pipeline.extend(["--capa-path", str(args.capa_path.resolve())])\n',
        '    if args.archive_password:\n'
        '        pipeline.extend(["--archive-password", args.archive_password])\n'
        '    if args.archive_member:\n'
        '        pipeline.extend(["--archive-member", args.archive_member])\n\n'
        '    if args.capa_path:\n'
        '        pipeline.extend(["--capa-path", str(args.capa_path.resolve())])\n',
    )
    replace_once(
        path,
        '            pipeline[0] = "CAPE_DEMO.py"\n'
        '            print(f"[CAPE] ?숈쟻 遺꾩꽍 ?쒖꽦?? package={package}")\n',
        '            cape_options = []\n'
        '            if package == "zip" and args.archive_password:\n'
        '                cape_options.append(f"password={args.archive_password}")\n'
        '            if package == "zip" and args.archive_member:\n'
        '                cape_options.append(f"file={args.archive_member}")\n'
        '            if cape_options:\n'
        '                pipeline.extend(["--cape-options", ",".join(cape_options)])\n'
        '            pipeline[0] = "CAPE_DEMO.py"\n'
        '            print(f"[CAPE] ?숈쟻 遺꾩꽍 ?쒖꽦?? package={package}")\n',
    )


def patch_cape_entry() -> None:
    path = ROOT / "cape_entry.py"
    replace_once(
        path,
        '    tags: str | None\n',
        '    tags: str | None\n'
        '    options: str | None\n',
    )
    replace_once(
        path,
        '    parser.add_argument("--cape-tags")\n',
        '    parser.add_argument("--cape-tags")\n'
        '    parser.add_argument("--cape-options")\n',
    )
    replace_once(
        path,
        '        tags=values.cape_tags,\n'
        '    ), remaining\n',
        '        tags=values.cape_tags,\n'
        '        options=values.cape_options,\n'
        '    ), remaining\n',
    )
    replace_once(
        path,
        '                    tags=options.tags,\n'
        '                )\n',
        '                    tags=options.tags,\n'
        '                    options=options.options,\n'
        '                )\n',
    )


ZIP_ANALYZER = r'''def pe_details_bytes(data: bytes) -> dict[str, Any]:
    try:
        import pefile  # type: ignore
    except ImportError:
        return {"available": False, "note": "python -m pip install pefile"}
    try:
        pe = pefile.PE(data=data, fast_load=False)
        imports = [{
            "dll": entry.dll.decode(errors="replace"),
            "symbols": [
                symbol.name.decode(errors="replace")
                if symbol.name else f"ordinal:{symbol.ordinal}"
                for symbol in entry.imports
            ],
        } for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])]
        directories = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", [])
        clr_rva = int(directories[14].VirtualAddress) if len(directories) > 14 else 0
        return {
            "available": True,
            "imphash": pe.get_imphash(),
            "is_dotnet": bool(clr_rva),
            "imports": imports,
        }
    except Exception as exc:
        return {"available": True, "error": str(exc)}


def _archive_member_bytes(
    path: Path,
    member: str,
    password: str,
    *,
    maximum: int,
) -> bytes:
    seven_zip = shutil.which("7z.exe") or shutil.which("7z")
    if not seven_zip:
        raise RuntimeError("7z executable was not found for streamed ZIP inspection")
    process = subprocess.run(
        [seven_zip, "x", "-so", "-bd", "-y", f"-p{password}", "--", str(path), member],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=180,
        check=False,
    )
    if process.returncode:
        detail = process.stderr.decode("utf-8", errors="replace")[-2000:]
        raise RuntimeError(f"7z stream extraction failed: {detail}")
    if len(process.stdout) > maximum:
        raise RuntimeError(f"archive member exceeds limit: {len(process.stdout)} > {maximum}")
    return process.stdout


def analyze_zip(
    path: Path,
    *,
    password: str | None = None,
    selected_member: str | None = None,
    maximum_member_bytes: int = 512 * 1024 * 1024,
    max_strings: int = 1000,
) -> dict[str, Any]:
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            members = [{
                "name": info.filename,
                "size": info.file_size,
                "compressed_size": info.compress_size,
                "encrypted": bool(info.flag_bits & 1),
            } for info in infos[:5000]]
            result: dict[str, Any] = {
                "member_count": len(infos),
                "members": members,
                "disk_extraction": False,
            }
            if not password:
                result["note"] = "목록만 확인했으며 --archive-password가 없어 내부 분석은 생략했습니다."
                return result
            names = [info.filename for info in infos if not info.is_dir()]
            member = selected_member
            if member and member not in names:
                raise RuntimeError(f"archive member was not found: {member}")
            if not member:
                preferred = (
                    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".py", ".js", ".jse"
                )
                member = next(
                    (name for name in names if Path(name).suffix.casefold() in preferred),
                    names[0] if names else None,
                )
            if not member:
                raise RuntimeError("archive has no file member")
            info = archive.getinfo(member)
            if info.file_size > maximum_member_bytes:
                raise RuntimeError(
                    f"archive member exceeds limit: {info.file_size} > {maximum_member_bytes}"
                )
        inner = _archive_member_bytes(
            path,
            member,
            password,
            maximum=maximum_member_bytes,
        )
        inner_path = Path(member)
        inner_text, inner_encoding = decode_text(inner)
        inner_detected = identify(inner_path, inner, inner_text)
        inner_headers = pe_headers(inner)
        inner_details = (
            pe_details_bytes(inner) if inner_headers.get("is_pe")
            else {"applicable": False}
        )
        inner_strings = strings_from(inner, max_strings)
        inner_script = None
        if inner_text is not None and inner_detected["detected_type"] in {
            "python_source", "batch_script", "powershell_script", "javascript", "text",
        }:
            inner_script = analyze_script(inner_text, inner_detected["detected_type"])
        result["selected_member"] = {
            "name": member,
            "size": len(inner),
            "hashes": {
                name: hashlib.new(name, inner).hexdigest()
                for name in ("md5", "sha1", "sha256")
            },
            "format_detection": inner_detected,
            "encoding": inner_encoding,
            "entropy": entropy(inner),
            "pe_headers": inner_headers,
            "pefile": inner_details,
            "strings": inner_strings,
            "script_analysis": inner_script,
            "findings": build_findings(
                inner_strings,
                inner_details,
                inner_text,
                inner_script,
            ),
        }
        return result
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        return {"error": str(exc), "disk_extraction": False}


'''


def patch_demo_core() -> None:
    path = ROOT / "demo_core.py"
    replace_once(path, "import re\n", "import re\nimport shutil\n")
    text = path.read_text(encoding="utf-8")
    if "def pe_details_bytes(data: bytes)" not in text:
        start = text.index("def analyze_zip(path: Path)")
        end = text.index("\ndef build_findings(", start)
        text = text[:start] + ZIP_ANALYZER + text[end + 1:]
        path.write_text(text, encoding="utf-8", newline="\n")
    replace_once(
        path,
        '    parser.add_argument("--max-file-size-mb", type=int, default=512)\n',
        '    parser.add_argument("--max-file-size-mb", type=int, default=512)\n'
        '    parser.add_argument("--archive-password")\n'
        '    parser.add_argument("--archive-member")\n',
    )
    replace_once(
        path,
        "        archive = analyze_zip(sample)\n",
        "        archive = analyze_zip(\n"
        "            sample,\n"
        "            password=args.archive_password,\n"
        "            selected_member=args.archive_member,\n"
        "            maximum_member_bytes=args.max_file_size_mb * 1024 * 1024,\n"
        "            max_strings=args.max_strings,\n"
        "        )\n",
    )


def patch_ai_entry() -> None:
    path = ROOT / "ai_entry.py"
    replace_once(
        path,
        '        "script_analysis": selected_script,\n',
        '        "script_analysis": selected_script,\n'
        '        "archive_analysis": static.get("archive_analysis"),\n',
    )


def main() -> int:
    patch_main()
    patch_cape_entry()
    patch_demo_core()
    patch_ai_entry()
    print("archive support installed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
