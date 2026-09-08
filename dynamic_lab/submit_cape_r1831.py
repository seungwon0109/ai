#!/usr/bin/env python3
"""Minimal stdlib CAPE client for the isolated R/1831 analysis task."""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
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
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read(2000).decode("utf-8", errors="replace")
        raise RuntimeError(
            f"CAPE API {method} {path} failed: HTTP {exc.code}: {detail}"
        ) from exc
    if not isinstance(payload, dict):
        raise RuntimeError("CAPE returned non-object JSON")
    return payload


def multipart_body(
    fields: dict[str, str],
    file_field: str,
    file_path: Path,
) -> tuple[bytes, str]:
    boundary = f"----cape-r1831-{secrets.token_hex(16)}"
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.extend(
            [
                f"--{boundary}\r\n".encode(),
                (
                    f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                ).encode(),
                value.encode(),
                b"\r\n",
            ]
        )
    content_type = (
        mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
    )
    chunks.extend(
        [
            f"--{boundary}\r\n".encode(),
            (
                f'Content-Disposition: form-data; name="{file_field}"; '
                f'filename="{file_path.name}"\r\n'
            ).encode(),
            f"Content-Type: {content_type}\r\n\r\n".encode(),
            file_path.read_bytes(),
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
                pass
    if isinstance(value, dict):
        for key in ("task_id", "task_ids", "data"):
            if key in value:
                try:
                    return find_task_id(value[key])
                except ValueError:
                    pass
    raise ValueError(f"Task ID was not present in CAPE response: {value}")


def task_status(payload: dict[str, Any]) -> str:
    task = payload.get("task", payload.get("data", payload))
    if isinstance(task, dict) and isinstance(task.get("status"), str):
        return task["status"]
    raise ValueError(f"Task status was not present in CAPE response: {payload}")


def submit(bundle: Path) -> dict[str, Any]:
    fields = {
        "package": "zip",
        "machine": "CAPE-Win11",
        "platform": "windows",
        "options": "file=tasksche.exe",
        "route": "none",
        "timeout": "240",
        "enforce_timeout": "1",
    }
    body, content_type = multipart_body(fields, "file", bundle)
    response = api_request(
        "tasks/create/file/",
        method="POST",
        body=body,
        content_type=content_type,
    )
    return {"task_id": find_task_id(response), "response": response}


def get_status(task_id: int) -> dict[str, Any]:
    response = api_request(f"tasks/view/{task_id}/")
    return {
        "task_id": task_id,
        "status": task_status(response),
        "response": response,
    }


def get_report(task_id: int, output: Path) -> dict[str, Any]:
    errors: list[str] = []
    for endpoint in (
        f"tasks/get/report/{task_id}/",
        f"tasks/report/{task_id}/",
    ):
        try:
            report = api_request(endpoint)
        except RuntimeError as exc:
            errors.append(str(exc))
            continue
        if isinstance(report.get("target"), dict):
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(report, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            return {
                "task_id": task_id,
                "report_path": str(output),
                "report_size": output.stat().st_size,
            }
        errors.append(f"{endpoint}: response was not a completed CAPE report")
    raise RuntimeError("; ".join(errors))


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    submit_parser = subparsers.add_parser("submit")
    submit_parser.add_argument("bundle", type=Path)

    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("task_id", type=int)

    report_parser = subparsers.add_parser("report")
    report_parser.add_argument("task_id", type=int)
    report_parser.add_argument("output", type=Path)

    args = parser.parse_args()
    if args.command == "submit":
        result = submit(args.bundle)
    elif args.command == "status":
        result = get_status(args.task_id)
    else:
        result = get_report(args.task_id, args.output)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
