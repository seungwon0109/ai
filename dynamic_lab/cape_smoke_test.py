from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from cape_client import CapeClient, normalize_cape_report  # noqa: E402


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_api_token(wsl_distro: str) -> str:
    token = os.environ.get("CAPE_API_TOKEN", "").strip()
    if token:
        return token

    token_path = Path("/home/cape/.cape_api_token")
    if token_path.is_file():
        return token_path.read_text(encoding="utf-8").strip()

    if sys.platform == "win32":
        result = subprocess.run(
            [
                "wsl.exe",
                "-d",
                wsl_distro,
                "--",
                "cat",
                "/home/cape/.cape_api_token",
            ],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        token = result.stdout.strip()
        if token:
            return token

    raise RuntimeError("CAPE API token could not be loaded.")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("sample", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--analysis-timeout", type=int, default=45)
    parser.add_argument("--wait-timeout", type=int, default=600)
    parser.add_argument("--task-id", type=int)
    parser.add_argument("--wsl-distro", default="Ubuntu-24.04")
    args = parser.parse_args()

    sample = args.sample.resolve()
    if not sample.is_file():
        raise SystemExit(f"Sample was not found: {sample}")

    token = load_api_token(args.wsl_distro)
    expected_sha256 = sha256_file(sample)

    with CapeClient("http://127.0.0.1:8000/apiv2", token) as cape:
        if args.task_id is None:
            task_id = cape.submit_file(
                sample,
                analysis_timeout=args.analysis_timeout,
                package="exe",
                machine="CAPE-Win11",
            )
            print(f"SMOKE_TASK_ID={task_id}", flush=True)
        else:
            task_id = args.task_id
            print(f"RESUME_TASK_ID={task_id}", flush=True)
        status = cape.wait_for_report(
            task_id,
            wait_timeout=args.wait_timeout,
            poll_interval=8,
        )
        print(f"SMOKE_STATUS={status}", flush=True)
        report = cape.get_report(task_id)

    summary = normalize_cape_report(
        report,
        task_id=task_id,
        expected_sha256=expected_sha256,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    raw_path = args.output_dir / f"whoami_task_{task_id}.cape.json"
    summary_path = args.output_dir / f"whoami_task_{task_id}.summary.json"
    raw_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"RAW_REPORT={raw_path}")
    print(f"SUMMARY_REPORT={summary_path}")
    print(f"PROCESS_COUNT={len(summary.get('behavior', {}).get('processes', []))}")
    print(f"SIGNATURE_COUNT={len(summary.get('signatures', []))}")
    print(f"PCAP_AVAILABLE={bool(report.get('network', {}).get('pcap_sha256'))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
