"""Host-side launcher for password-protected archive analysis inside WSL.

The encrypted archive remains on the Windows filesystem. Decrypted member bytes
exist only in the selected WSL distribution and are never returned to Windows.
Only structured JSON evidence is returned.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


class IsolatedStaticError(RuntimeError):
    pass


def _wsl_path(path: Path, distro: str, timeout: int) -> str:
    process = subprocess.run(
        ["wsl.exe", "-d", distro, "--", "wslpath", "-a", str(path.resolve())],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    if process.returncode or not process.stdout.strip():
        raise IsolatedStaticError(
            f"Unable to map Windows path into WSL: {(process.stderr or process.stdout)[-1000:]}"
        )
    return process.stdout.strip()


def analyze_zip_in_wsl(
    archive: Path,
    *,
    password: str,
    selected_member: str | None,
    maximum_member_bytes: int,
    max_strings: int,
    distro: str = "Ubuntu-24.04",
    timeout: int = 420,
) -> dict[str, Any]:
    if os.name != "nt":
        raise IsolatedStaticError("The WSL launcher is only available on Windows hosts")
    if not shutil.which("wsl.exe"):
        raise IsolatedStaticError("wsl.exe was not found")

    worker = Path(__file__).resolve().with_name("isolated_static_worker.py")
    worker_wsl = _wsl_path(worker, distro, 30)
    command = [
        "wsl.exe", "-d", distro, "--",
        "env", "MALWARE_STATIC_WORKER=1",
        "/home/cape/CAPEv2/.venv/bin/python",
        worker_wsl,
        "-",
        "--password", password,
        "--maximum-member-bytes", str(maximum_member_bytes),
        "--max-strings", str(max_strings),
    ]
    if selected_member:
        command.extend(["--member", selected_member])

    try:
        with archive.open("rb") as encrypted_stream:
            process = subprocess.run(
                command,
                stdin=encrypted_stream,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
    except subprocess.TimeoutExpired as exc:
        raise IsolatedStaticError(f"WSL static analysis timed out after {timeout}s") from exc
    if process.returncode:
        raise IsolatedStaticError(
            f"WSL static worker failed ({process.returncode}): {process.stderr[-3000:]}"
        )
    try:
        value = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise IsolatedStaticError(
            f"WSL static worker returned invalid JSON: {process.stdout[-2000:]}"
        ) from exc
    if not isinstance(value, dict):
        raise IsolatedStaticError("WSL static worker returned a non-object result")
    return value

