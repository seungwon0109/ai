"""Run archive decryption and static analysis inside the CAPE Linux filesystem."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import demo_core


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--password", required=True)
    parser.add_argument("--member")
    parser.add_argument("--maximum-member-bytes", type=int, default=512 * 1024 * 1024)
    parser.add_argument("--max-strings", type=int, default=1000)
    parser.add_argument("--capa-timeout", type=int, default=240)
    return parser.parse_args()


def capa_analysis(target: Path, timeout: int) -> dict[str, Any]:
    capa = Path("/home/cape/CAPEv2/.venv/bin/capa")
    if not capa.is_file():
        return {"skipped": True, "reason": "CAPE WSL capa executable was not found"}
    try:
        process = subprocess.run(
            [
                str(capa),
                "-r", "/home/cape/CAPEv2/data/capa-rules",
                "-s", "/home/cape/CAPEv2/data/flare-signatures",
                "-j", str(target),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            env={**os.environ, "HOME": "/home/cape"},
        )
    except subprocess.TimeoutExpired:
        return {"error": f"capa timed out after {timeout}s"}
    if process.returncode:
        return {
            "error": process.stderr[-4000:] or process.stdout[-4000:],
            "return_code": process.returncode,
        }
    try:
        value = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        return {"error": f"capa JSON error: {exc}"}
    return value if isinstance(value, dict) else {"error": "capa returned non-object JSON"}


def ghidra_analysis(target: Path, workspace: Path, timeout: int = 900) -> dict[str, Any]:
    ghidra_home = Path(__file__).resolve().parents[1] / "tools" / "ghidra_12.1.2_PUBLIC_20260605" / "ghidra_12.1.2_PUBLIC"
    headless = ghidra_home / "support" / "analyzeHeadless"
    exporter = Path(__file__).resolve().parent / "ghidra_scripts" / "ExportAnalysis.java"
    if not headless.is_file():
        return {"skipped": True, "reason": f"Ghidra Headless not found: {headless}"}
    if not exporter.is_file():
        return {"skipped": True, "reason": f"Ghidra export script not found: {exporter}"}
    if not shutil.which("java"):
        return {"skipped": True, "reason": "Java is not installed in WSL"}

    project_dir = workspace / "ghidra-project"
    script_dir = workspace / "ghidra-scripts"
    output = workspace / "ghidra-analysis.json"
    home = workspace / "ghidra-home"
    project_dir.mkdir()
    script_dir.mkdir()
    home.mkdir()
    shutil.copy2(exporter, script_dir / exporter.name)
    command = [
        str(headless), str(project_dir), "isolated_static",
        "-import", str(target),
        "-scriptPath", str(script_dir),
        "-postScript", "ExportAnalysis.java", str(output), "1200", "120",
        "-analysisTimeoutPerFile", str(timeout),
        "-deleteProject",
    ]
    started = time.monotonic()
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout + 120,
            check=False,
            env={**os.environ, "HOME": str(home), "JAVA_HOME": "/usr/lib/jvm/java-21-openjdk-amd64"},
        )
    except subprocess.TimeoutExpired:
        return {"error": f"Ghidra timed out after {timeout + 120}s"}
    elapsed = round(time.monotonic() - started, 3)
    if process.returncode or not output.is_file():
        return {
            "error": "Ghidra Headless analysis failed",
            "return_code": process.returncode,
            "elapsed_seconds": elapsed,
            "stdout_tail": process.stdout[-4000:],
            "stderr_tail": process.stderr[-4000:],
        }
    try:
        value = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"error": f"Ghidra JSON error: {exc}", "elapsed_seconds": elapsed}
    value["elapsed_seconds"] = elapsed
    value["provider"] = "ghidra-headless-wsl"
    value["sample_executed"] = False
    return value


def main() -> int:
    args = arguments()
    os.umask(0o077)
    input_temporary = None
    archive_path = args.archive
    if str(args.archive) == "-":
        input_temporary = tempfile.TemporaryDirectory(prefix="malware-static-input-")
        archive_path = Path(input_temporary.name) / "encrypted-input.zip"
        with archive_path.open("wb") as output:
            shutil.copyfileobj(sys.stdin.buffer, output, length=1024 * 1024)
    result = demo_core.analyze_zip(
        archive_path,
        password=args.password,
        selected_member=args.member,
        maximum_member_bytes=args.maximum_member_bytes,
        max_strings=args.max_strings,
    )
    result["isolation"] = {
        "provider": "wsl",
        "distro": "Ubuntu-24.04",
        "decrypted_on_windows_host": False,
        "sample_executed": False,
        "temporary_plaintext_location": "WSL ext4 only",
        "cleanup_requested": True,
    }
    selected = result.get("selected_member")
    if not isinstance(selected, dict) or result.get("error"):
        if input_temporary is not None:
            input_temporary.cleanup()
            result["isolation"]["encrypted_staging_cleanup_completed"] = not Path(input_temporary.name).exists()
        print(json.dumps(result, ensure_ascii=False))
        return 0

    member = str(selected.get("name") or "")
    suffix = Path(member).suffix[:16]
    with tempfile.TemporaryDirectory(prefix="malware-static-") as temporary:
        raw = demo_core._archive_member_bytes(
            archive_path,
            member,
            args.password,
            maximum=args.maximum_member_bytes,
        )
        digest = hashlib.sha256(raw).hexdigest()
        target = Path(temporary) / f"{digest}{suffix}"
        target.write_bytes(raw)
        result["isolated_capa"] = capa_analysis(target, args.capa_timeout)
        result["isolated_ghidra"] = ghidra_analysis(target, Path(temporary))
        del raw

    result["isolation"]["cleanup_completed"] = not Path(temporary).exists()
    if input_temporary is not None:
        input_temporary.cleanup()
        result["isolation"]["encrypted_staging_cleanup_completed"] = not Path(input_temporary.name).exists()
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
