#!/usr/bin/env python3
"""Submit one password-protected ZIP to the isolated CAPE VM.

This client deliberately forces route=none and a named analysis machine.
It is intended for defensive analysis of samples explicitly supplied by
the workspace owner.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import secrets
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


BASE_URL = "http://127.0.0.1:8000/apiv2"
TOKEN_PATH = Path("/home/cape/.cape_api_token")


def api_request(
    path: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    content_type: str | None = None,
) -> dict[str, Any]:
    token = TOKEN_PATH.read_text(encoding="ascii").strip()
    headers = {
        "Accept": "application/json",
        "Authorization": f"Token {token}",
    }
    if content_type:
        headers["Content-Type"] = content_type
    request = urllib.request.Request(
        f"{BASE_URL}/{path.lstrip('/')}",
        data=body,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read(2000).decode("utf-8", errors="replace")
        raise RuntimeError(
            f"CAPE API {method} {path} failed: HTTP {exc.code}: {detail}"
        ) from exc
    if not isinstance(payload, dict):
        raise RuntimeError("CAPE returned non-object JSON")
    return payload


def multipart_body(fields: dict[str, str], sample: Path) -> tuple[bytes, str]:
    boundary = f"----cape-protected-zip-{secrets.token_hex(16)}"
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.extend(
            [
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                value.encode(),
                b"\r\n",
            ]
        )
    mime = mimetypes.guess_type(sample.name)[0] or "application/octet-stream"
    chunks.extend(
        [
            f"--{boundary}\r\n".encode(),
            (
                f'Content-Disposition: form-data; name="file"; '
                f'filename="{sample.name}"\r\n'
            ).encode(),
            f"Content-Type: {mime}\r\n\r\n".encode(),
            sample.read_bytes(),
            b"\r\n",
            f"--{boundary}--\r\n".encode(),
        ]
    )
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def find_task_id(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, list):
        for item in value:
            try:
                return find_task_id(item)
            except ValueError:
                continue
    if isinstance(value, dict):
        for key in ("task_id", "task_ids", "data"):
            if key in value:
                try:
                    return find_task_id(value[key])
                except ValueError:
                    continue
    raise ValueError(f"Task ID was not present in CAPE response: {value}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("zip_path", type=Path)
    parser.add_argument("--member", required=True)
    parser.add_argument("--password", default="infected")
    parser.add_argument("--machine", default="CAPE-Win11")
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()

    sample = args.zip_path.resolve()
    if not sample.is_file():
        raise FileNotFoundError(sample)
    if not 30 <= args.timeout <= 600:
        raise ValueError("timeout must be between 30 and 600 seconds")

    fields = {
        "package": "zip",
        "machine": args.machine,
        "platform": "windows",
        "options": f"password={args.password},file={args.member}",
        "route": "none",
        "timeout": str(args.timeout),
        "enforce_timeout": "1",
    }
    body, content_type = multipart_body(fields, sample)
    response = api_request(
        "tasks/create/file/",
        method="POST",
        body=body,
        content_type=content_type,
    )
    print(
        json.dumps(
            {
                "task_id": find_task_id(response),
                "sample": str(sample),
                "machine": args.machine,
                "package": "zip",
                "route": "none",
                "timeout": args.timeout,
                "response": response,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
