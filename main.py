from __future__ import annotations

from dotenv import load_dotenv
import argparse
import base64
import configparser
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx


PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env", override=False)

DEFAULT_CAPE_URL = "http://127.0.0.1:8000/apiv2"
DEFAULT_CAPE_MACHINE = "CAPE-Win11"
DEFAULT_LOCAL_URL = "http://127.0.0.1:11434/v1"
DEFAULT_LOCAL_MODEL = "malware-qwen:9b"
DEFAULT_OPENAI_URL = "https://api.openai.com/v1"
DEFAULT_OPENAI_MODEL = "gpt-5.6-luna"

CAPE_PACKAGES = {
    ".exe": "exe",
    ".dll": "dll",
    ".bat": "batch",
    ".cmd": "batch",
    ".ps1": "ps1",
    ".py": "python",
    ".js": "js",
    ".zip": "zip",
}


def is_pe_file(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return stream.read(2) == b"MZ"
    except OSError:
        return False


def cape_package_for(path: Path) -> str | None:
    suffix = path.suffix.casefold()
    if is_pe_file(path):
        return "dll" if suffix == ".dll" else "exe"
    return CAPE_PACKAGES.get(suffix)


def find_capa() -> Path | None:
    candidates = [
        os.getenv("CAPA_PATH"),
        str(PROJECT_ROOT / "tools" / "capa" / "capa.exe"),
        str(PROJECT_ROOT / "tools" / "capa.exe"),
        shutil.which("capa"),
        shutil.which("capa.exe"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).expanduser().is_file():
            return Path(candidate).expanduser().resolve()
    return None


def load_cape_token(distro: str) -> str | None:
    token = os.getenv("CAPE_API_TOKEN", "").strip()
    if token:
        return token

    linux_path = Path("/home/cape/.cape_api_token")
    if linux_path.is_file():
        return linux_path.read_text(encoding="utf-8").strip() or None

    if os.name == "nt" and shutil.which("wsl.exe"):
        try:
            result = subprocess.run(
                [
                    "wsl.exe",
                    "-d",
                    distro,
                    "--",
                    "cat",
                    "/home/cape/.cape_api_token",
                ],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return result.stdout.strip() or None
    return None


def cape_probe(url: str, token: str | None, timeout: float = 5.0) -> tuple[bool, str]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Token {token}"
    try:
        response = httpx.get(
            f"{url.rstrip('/')}/machines/list/",
            headers=headers,
            timeout=timeout,
            follow_redirects=True,
        )
    except httpx.HTTPError as exc:
        return False, str(exc)
    if response.status_code == 200:
        return True, "ready"
    if response.status_code in {401, 403}:
        return False, f"authentication failed (HTTP {response.status_code})"
    return False, f"HTTP {response.status_code}: {response.text[:200]}"


def start_wsl_keepalive(distro: str) -> subprocess.Popen[bytes] | None:
    if os.name != "nt" or not shutil.which("wsl.exe"):
        return None
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.Popen(
        ["wsl.exe", "-d", distro, "-u", "root", "--", "sleep", "infinity"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creation_flags,
    )


def stop_wsl_keepalive(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def start_cape_lab() -> None:
    script = PROJECT_ROOT / "dynamic_lab" / "Start-CapeLab.ps1"
    if os.name != "nt" or not script.is_file():
        raise RuntimeError(f"CAPE startup script was not found: {script}")
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
        ],
        cwd=PROJECT_ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout)[-2000:]
        raise RuntimeError(
            "CAPE 자동 시작에 실패했습니다. 관리자 권한 VSCode인지 확인하세요.\n"
            + detail
        )


def validate_cape_safety_audit(
    value: dict[str, Any], expected_snapshot: str | None = None
) -> list[str]:
    failures: list[str] = []
    if value.get("vm_name") != DEFAULT_CAPE_MACHINE:
        failures.append("unexpected VM name")
    if value.get("switch_name") != "CAPE-Lab":
        failures.append("VM is not attached to CAPE-Lab")
    if str(value.get("switch_type")).casefold() != "internal":
        failures.append("CAPE-Lab is not an Internal Hyper-V switch")
    if int(value.get("matching_nat_count") or 0) != 0:
        failures.append("a NAT exposes the CAPE subnet")
    if str(value.get("ipv4_forwarding") or "").casefold() not in {"disabled", "false"}:
        failures.append("IPv4 forwarding is enabled on CAPE-Lab")
    checkpoints = value.get("checkpoints") or []
    if isinstance(checkpoints, dict):
        checkpoints = [checkpoints]
    checkpoint_names = {
        str(item.get("Name")) for item in checkpoints if isinstance(item, dict) and item.get("Name")
    }
    if expected_snapshot:
        if expected_snapshot not in checkpoint_names:
            failures.append(f"configured checkpoint is missing: {expected_snapshot}")
    elif not any(name.startswith("Ready") for name in checkpoint_names):
        failures.append("Ready checkpoint is missing")
    return failures


def _cape_hyperv_config(distro: str) -> configparser.ConfigParser:
    process = subprocess.run(
        ["wsl.exe", "-d", distro, "--", "cat", "/home/cape/CAPEv2/conf/hyperv.conf"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        check=False,
    )
    if process.returncode:
        raise RuntimeError("Unable to read CAPE Hyper-V configuration")
    config = configparser.ConfigParser()
    config.read_string(process.stdout)
    return config


def _remote_cape_audit(distro: str) -> tuple[dict[str, Any], str]:
    config = _cape_hyperv_config(distro)
    host = config.get("hyperv", "host")
    username = config.get("hyperv", "username")
    key = config.get("hyperv", "ssh_key")
    machine_section = config.get("hyperv", "machines").split(",")[0].strip()
    snapshot = config.get(machine_section, "snapshot")
    script = r'''$ErrorActionPreference = "Stop"
$vm = Get-VM -Name "CAPE-Win11"
$adapter = Get-VMNetworkAdapter -VMName "CAPE-Win11"
$interface = Get-NetIPInterface -InterfaceAlias "vEthernet (CAPE-Lab)" -AddressFamily IPv4 | Select-Object -First 1
$natCount = @(Get-NetNat -ErrorAction SilentlyContinue | Where-Object { $_.InternalIPInterfaceAddressPrefix -like "192.168.56.*" }).Count
$labSwitch = Get-VMSwitch -Name "CAPE-Lab"
$checkpoints = @(Get-VMSnapshot -VMName "CAPE-Win11" | Select-Object Name,CreationTime)
[ordered]@{
  vm_name=$vm.Name
  vm_state=$vm.State.ToString()
  vm_status=$vm.Status
  switch_name=$adapter.SwitchName
  switch_type=$labSwitch.SwitchType.ToString()
  vm_addresses=@($adapter.IPAddresses)
  ipv4_forwarding=$interface.Forwarding.ToString()
  matching_nat_count=$natCount
  checkpoints=$checkpoints
} | ConvertTo-Json -Depth 6 -Compress
'''
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    remote = f"powershell.exe -NoProfile -EncodedCommand {encoded}"
    process = subprocess.run(
        [
            "wsl.exe", "-d", distro, "--", "sudo", "-u", "cape",
            "ssh", "-i", key,
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=yes",
            f"{username}@{host}", remote,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )
    if process.returncode:
        raise RuntimeError("CAPE SSH safety audit failed: " + (process.stderr or process.stdout)[-1200:])
    try:
        value = json.loads(process.stdout.strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError("CAPE SSH safety audit returned invalid JSON") from exc
    return value, snapshot


def audit_cape_safety(distro: str = "Ubuntu-24.04") -> dict[str, Any]:
    script = PROJECT_ROOT / "dynamic_lab" / "Audit-CapeHostSafety.ps1"
    if not script.is_file():
        raise RuntimeError(f"CAPE safety audit script was not found: {script}")
    process = subprocess.run(
        [
            "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", str(script),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )
    expected_snapshot = None
    if process.returncode == 0:
        try:
            value = json.loads(process.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("CAPE safety audit returned invalid JSON") from exc
        provider = "local-admin"
    else:
        value, expected_snapshot = _remote_cape_audit(distro)
        provider = "cape-hyperv-ssh"
    failures = validate_cape_safety_audit(value, expected_snapshot)
    if failures:
        raise RuntimeError("CAPE safety audit failed: " + "; ".join(failures))
    print(
        f"[CAPE safety] provider={provider}; Internal switch, no NAT/forwarding, "
        f"checkpoint={expected_snapshot or 'Ready*'} verified"
    )
    return value

def ensure_cape_ready(
    url: str,
    token: str | None,
    *,
    auto_start: bool,
) -> None:
    ready, detail = cape_probe(url, token)
    if ready:
        return
    if "authentication failed" in detail:
        raise RuntimeError(f"CAPE API {detail}")
    if not auto_start:
        raise RuntimeError(f"CAPE API에 연결할 수 없습니다: {detail}")

    print("[준비] CAPE 서비스가 응답하지 않아 안전한 분석 랩을 시작합니다.")
    start_cape_lab()
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        ready, detail = cape_probe(url, token)
        if ready:
            return
        time.sleep(2)
    raise RuntimeError(f"CAPE API 준비 시간 초과: {detail}")


def ollama_model_available(base_url: str, model: str) -> tuple[bool, str]:
    parsed = urlsplit(base_url)
    if not parsed.scheme or not parsed.netloc:
        return False, "잘못된 로컬 AI URL"
    tags_url = f"{parsed.scheme}://{parsed.netloc}/api/tags"
    try:
        response = httpx.get(tags_url, timeout=5.0)
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        return False, str(exc)
    names = {
        item.get("name")
        for item in payload.get("models", [])
        if isinstance(item, dict)
    }
    return model in names, ", ".join(sorted(value for value in names if value))


def is_openai_api(base_url: str) -> bool:
    try:
        parsed = urlsplit(base_url)
    except ValueError:
        return False
    return (parsed.hostname or "").casefold() == "api.openai.com"


def default_ai_settings() -> tuple[str, str, str | None]:
    """Prefer Luna when OPENAI_API_KEY is configured, even if an old Ollama .env remains."""
    openai_key = str(os.getenv("OPENAI_API_KEY") or "").strip() or None
    if openai_key:
        return DEFAULT_OPENAI_URL, DEFAULT_OPENAI_MODEL, openai_key
    return (
        os.getenv("LOCAL_AI_BASE_URL") or DEFAULT_LOCAL_URL,
        os.getenv("LOCAL_AI_MODEL") or DEFAULT_LOCAL_MODEL,
        str(os.getenv("LOCAL_AI_API_KEY") or "").strip() or None,
    )

def ghidra_available() -> tuple[bool, str]:
    try:
        import ghidra_mcp_core
    except Exception as exc:
        return False, str(exc)
    if not ghidra_mcp_core.HEADLESS.is_file():
        return False, f"analyzeHeadless 없음: {ghidra_mcp_core.HEADLESS}"
    return True, str(ghidra_mcp_core.HEADLESS)


def latest_evidence(output_dir: Path) -> Path | None:
    candidates = sorted(
        output_dir.glob("*.evidence.json"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def print_result_summary(output_dir: Path) -> None:
    evidence_path = latest_evidence(output_dir)
    if not evidence_path:
        return
    try:
        evidence: dict[str, Any] = json.loads(
            evidence_path.read_text(encoding="utf-8")
        )
    except (OSError, ValueError):
        return
    dynamic = evidence.get("dynamic_analysis")
    processes = []
    if isinstance(dynamic, dict):
        behavior = dynamic.get("behavior")
        if isinstance(behavior, dict) and isinstance(behavior.get("processes"), list):
            processes = behavior["processes"]
    print("")
    print("[완료 요약]")
    print(f"- 증거 JSON: {evidence_path}")
    print(f"- 최종 보고서: {evidence_path.with_suffix('').with_suffix('.report.md')}")
    if isinstance(dynamic, dict):
        print(f"- CAPE 상태: {dynamic.get('status', 'unknown')}")
        print(f"- CAPE 작업 ID: {dynamic.get('task_id', '-')}")
        print(f"- 관찰 프로세스: {len(processes)}개")



_WEB_JOBS: dict[str, dict[str, Any]] = {}
_WEB_JOBS_LOCK = threading.Lock()
_WEB_ACTIVE_JOB: str | None = None


def _zip_requires_password(path: Path) -> bool:
    if path.suffix.casefold() != ".zip":
        return False
    try:
        with zipfile.ZipFile(path) as archive:
            return any(bool(info.flag_bits & 0x1) for info in archive.infolist())
    except (OSError, zipfile.BadZipFile):
        return False


def _web_job_summary(evidence: dict[str, Any]) -> dict[str, Any]:
    from src.reporting.human_report import (
        build_analysis_details,
        build_attack_candidate_table,
        build_external_cross_validation,
        build_report_data,
        external_intelligence_summary,
    )

    local_ai = evidence.get("local_ai") or {}
    report = local_ai.get("user_report") or ((local_ai.get("pass_3") or {}).get("user_report"))
    if not isinstance(report, dict) or not report.get("plain_summary"):
        report = build_report_data(evidence)
    external = external_intelligence_summary(evidence)
    details = build_analysis_details(evidence)
    cross = evidence.get("cross_validation")
    if not isinstance(cross, dict):
        cross = build_external_cross_validation(evidence)

    dynamic = evidence.get("dynamic_analysis") or {}
    if not isinstance(dynamic, dict):
        dynamic = {}
    behavior = dynamic.get("behavior") or {}
    if not isinstance(behavior, dict):
        behavior = {}
    processes = behavior.get("processes") or []
    if not isinstance(processes, list):
        processes = []
    dropped = dynamic.get("dropped_files") or []
    if not isinstance(dropped, list):
        dropped = []
    signatures = dynamic.get("signatures") or []
    if not isinstance(signatures, list):
        signatures = []

    return {
        "sample": evidence.get("sample") or {},
        "details": details,
        "local": {
            "summary": report.get("plain_summary"),
            "analysis_narrative": (report.get("analysis_narrative") or [])[:10],
            "risk_rationale": (report.get("risk_rationale") or [])[:15],
            "local_conclusion": report.get("local_conclusion"),
            "execution_command_lines": (report.get("execution_command_lines") or [])[:5],
            "family": report.get("family") or {},
            "classification": report.get("classification"),
            "risk_level": report.get("risk_level"),
            "behaviors": (report.get("behaviors") or [])[:12],
            "execution_flow": (report.get("execution_flow") or [])[:15],
            "user_impact": (report.get("user_impact") or [])[:15],
            "iocs": (report.get("iocs") or [])[:30],
            "unknowns": (report.get("unknowns") or [])[:20],
            "dynamic": {
                "status": dynamic.get("status") or "not_run",
                "task_id": dynamic.get("task_id"),
                "process_count": len(processes),
                "dropped_file_count": len(dropped),
                "signature_count": len(signatures),
                "error": dynamic.get("error"),
            },
        },
        "virustotal": external,
        "cross_validation": cross,
        "attack_candidates": build_attack_candidate_table(evidence),
        "behavior_flow": [
            {"step": index + 1, "title": item.get("title"), "status": item.get("status")}
            for index, item in enumerate((report.get("behaviors") or [])[:10])
            if isinstance(item, dict) and item.get("title")
        ],
        "final_assessment": report.get("final_assessment") or {},
    }


def _web_child_command(args: argparse.Namespace, sample: Path, output: Path, archive_member: str | None) -> list[str]:
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        str(sample),
        "--output-dir", str(output),
        "--cape-url", str(args.cape_url),
        "--cape-machine", str(args.cape_machine),
        "--cape-analysis-timeout", str(args.cape_analysis_timeout),
        "--cape-wait-timeout", str(args.cape_wait_timeout),
        "--wsl-distro", str(args.wsl_distro),
        "--local-base-url", str(args.local_base_url),
        "--local-model", str(args.local_model),
        "--vt-timeout", str(args.vt_timeout),
        "--vt-max-related", str(args.vt_max_related),
        "--vt-min-interval", str(args.vt_min_interval),
        "--max-file-size-mb", str(args.max_file_size_mb),
        "--ai-timeout", str(args.ai_timeout),
        "--max-domain-reviews", str(args.max_domain_reviews),
        "--local-report-timeout", str(args.local_report_timeout),
        "--local-report-attempts", str(args.local_report_attempts),
    ]
    if args.static_only:
        command.append("--static-only")
    if args.skip_ghidra:
        command.append("--skip-ghidra")
    if args.no_start_cape:
        command.append("--no-start-cape")
    if args.no_local_ai:
        command.append("--no-local-ai")
    if args.skip_capa:
        command.append("--skip-capa")
    elif args.capa_path:
        command.extend(["--capa-path", str(args.capa_path)])
    if args.no_vt:
        command.append("--no-vt")
    if args.vt_refresh:
        command.append("--vt-refresh")
    if archive_member:
        command.extend(["--archive-member", archive_member])
    if args.use_cloud:
        command.append("--use-cloud")
        if args.cloud_base_url:
            command.extend(["--cloud-base-url", str(args.cloud_base_url)])
        if args.cloud_model:
            command.extend(["--cloud-model", str(args.cloud_model)])
    return command


def _web_run_job(
    job_id: str,
    args: argparse.Namespace,
    sample: Path,
    output: Path,
    password: str,
    archive_member: str | None,
) -> None:
    global _WEB_ACTIVE_JOB
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    if password:
        env["MALWARE_ARCHIVE_PASSWORD"] = password
    else:
        env.pop("MALWARE_ARCHIVE_PASSWORD", None)
    if args.vt_api_key:
        env["VIRUSTOTAL_API_KEY"] = str(args.vt_api_key)
    if args.cape_token:
        env["CAPE_API_TOKEN"] = str(args.cape_token)
    if args.cloud_api_key:
        env["CLOUD_AI_API_KEY"] = str(args.cloud_api_key)
    if args.local_api_key:
        env["LOCAL_AI_API_KEY"] = str(args.local_api_key)

    command = _web_child_command(args, sample, output, archive_member)
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    with _WEB_JOBS_LOCK:
        job = _WEB_JOBS[job_id]
        job.update({
            "status": "running",
            "stage": "분석 준비",
            "progress": 3,
            "cape": {
                "analysis_timeout": int(args.cape_analysis_timeout),
                "wait_timeout": int(args.cape_wait_timeout),
                "status": "대기",
                "task_id": None,
                "started_at": None,
                "elapsed": 0,
            },
        })

    try:
        process = subprocess.Popen(
            command,
            cwd=PROJECT_ROOT,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=creation_flags,
        )
        assert process.stdout is not None
        for raw in process.stdout:
            line = raw.rstrip()
            if not line:
                continue
            with _WEB_JOBS_LOCK:
                logs = _WEB_JOBS[job_id].setdefault("logs", [])
                logs.append(line)
                if len(logs) > 160:
                    del logs[:-160]
                match = re.search(r"\[(\d)/8\]\s*(.+)", line)
                if match:
                    step = int(match.group(1))
                    _WEB_JOBS[job_id]["progress"] = min(95, 5 + step * 11)
                    _WEB_JOBS[job_id]["stage"] = match.group(2).strip()
                elif line.startswith("[CAPE] 시작:"):
                    cape = _WEB_JOBS[job_id].setdefault("cape", {})
                    cape["status"] = "실행 중"
                    cape["started_at"] = time.time()
                    cape["elapsed"] = 0
                    _WEB_JOBS[job_id]["progress"] = max(int(_WEB_JOBS[job_id].get("progress") or 0), 55)
                    _WEB_JOBS[job_id]["stage"] = "CAPE 동적 분석"
                elif line.startswith("[CAPE] task_id="):
                    cape = _WEB_JOBS[job_id].setdefault("cape", {})
                    task_match = re.search(r"task_id=(\d+)", line)
                    if task_match:
                        cape["task_id"] = int(task_match.group(1))
                    cape["status"] = "분석 중"
                    _WEB_JOBS[job_id]["stage"] = "CAPE 동적 분석"
                elif line.startswith("[CAPE] 상태="):
                    cape = _WEB_JOBS[job_id].setdefault("cape", {})
                    status_match = re.search(r"상태=([^·]+)", line)
                    elapsed_match = re.search(r"경과=(\d+)초", line)
                    if status_match:
                        cape["status"] = status_match.group(1).strip()
                    if elapsed_match:
                        cape["elapsed"] = int(elapsed_match.group(1))
                    _WEB_JOBS[job_id]["stage"] = "CAPE 동적 분석"
                elif line.startswith("[CAPE] 분석 완료:"):
                    cape = _WEB_JOBS[job_id].setdefault("cape", {})
                    cape["status"] = "완료"
                    if cape.get("started_at"):
                        cape["elapsed"] = int(max(0, time.time() - float(cape["started_at"])))
                    _WEB_JOBS[job_id]["stage"] = "CAPE 분석 완료"
                elif line.startswith("[CAPE] 분석 결과를 사용할 수 없음:"):
                    cape = _WEB_JOBS[job_id].setdefault("cape", {})
                    cape["status"] = "실패/시간초과"
                    if cape.get("started_at"):
                        cape["elapsed"] = int(max(0, time.time() - float(cape["started_at"])))
                elif line.startswith("[VirusTotal]"):
                    _WEB_JOBS[job_id]["progress"] = max(int(_WEB_JOBS[job_id].get("progress") or 0), 90)
                    _WEB_JOBS[job_id]["stage"] = "VirusTotal 독립 비교"
        code = process.wait()
        if code != 0:
            with _WEB_JOBS_LOCK:
                _WEB_JOBS[job_id].update({"status": "failed", "stage": "분석 실패", "progress": 100, "return_code": code})
            return

        evidence_path = latest_evidence(output)
        if not evidence_path:
            with _WEB_JOBS_LOCK:
                _WEB_JOBS[job_id].update({"status": "failed", "stage": "결과 파일 없음", "progress": 100})
            return
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        report_path = evidence_path.with_suffix("").with_suffix(".report.md")
        report_text = report_path.read_text(encoding="utf-8", errors="replace") if report_path.is_file() else ""
        with _WEB_JOBS_LOCK:
            _WEB_JOBS[job_id].update({
                "status": "completed",
                "stage": "분석 완료",
                "progress": 100,
                "result": _web_job_summary(evidence),
                "report": report_text,
                "evidence_path": str(evidence_path),
                "report_path": str(report_path),
            })
    except Exception as exc:
        with _WEB_JOBS_LOCK:
            _WEB_JOBS[job_id].update({"status": "failed", "stage": "예외 발생", "progress": 100, "error": str(exc)})
    finally:
        # Password-protected samples are not retained by the upload UI after analysis.
        try:
            sample.unlink(missing_ok=True)
        except OSError:
            pass
        with _WEB_JOBS_LOCK:
            if _WEB_ACTIVE_JOB == job_id:
                _WEB_ACTIVE_JOB = None


WEB_HTML = r'''<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Malware Analysis</title>
<style>
:root{font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;color:#172033;background:#f4f7fb}
*{box-sizing:border-box}body{margin:0}.wrap{max-width:1180px;margin:0 auto;padding:34px 20px 70px}
h1{margin:0;font-size:30px}.sub{color:#667085;margin:8px 0 24px}.card{background:white;border:1px solid #e4e9f2;border-radius:18px;box-shadow:0 8px 28px rgba(30,41,59,.06)}
.drop{padding:34px;border:2px dashed #b9c4d6;text-align:center;cursor:pointer;transition:.2s}.drop.drag{border-color:#2563eb;background:#eff6ff}.drop strong{display:block;font-size:20px;margin-bottom:7px}.muted{color:#7b8798;font-size:13px}
.controls{display:grid;grid-template-columns:1fr 1fr auto;gap:12px;margin-top:14px}.controls input,.controls button{height:46px;border-radius:11px;border:1px solid #d7deea;padding:0 14px;font-size:14px}.controls button{border:0;background:#172033;color:white;font-weight:700;padding:0 24px;cursor:pointer}.controls button:disabled{opacity:.45;cursor:not-allowed}
.status{margin-top:18px;padding:18px 20px;display:none}.bar{height:8px;background:#e8edf5;border-radius:999px;overflow:hidden;margin:12px 0}.bar>div{height:100%;width:0;background:#2563eb;transition:.4s}.stage{font-weight:700}.cape-meta{margin-top:6px;color:#667085;font-size:13px}.logs{white-space:pre-wrap;max-height:145px;overflow:auto;background:#0f172a;color:#d6e2f0;padding:12px;border-radius:10px;font:12px/1.55 Consolas,monospace}
.card{min-width:0}.results{display:none;margin-top:20px}.grid{display:grid;grid-template-columns:minmax(0,1fr);gap:18px}.pane{padding:22px}.eyebrow{font-size:12px;font-weight:800;letter-spacing:.09em;color:#667085;text-transform:uppercase}.title{font-size:20px;font-weight:800;margin:7px 0 14px}.metric{display:flex;gap:8px;flex-wrap:wrap}.pill{background:#eef2f7;border-radius:999px;padding:7px 10px;font-size:12px;font-weight:700}.summary{line-height:1.7;color:#39465b;overflow-wrap:anywhere}.behaviors{margin:12px 0 0;padding-left:18px;color:#39465b}.behaviors li{margin:5px 0;overflow-wrap:anywhere}.compare,.final,.cape-overview{padding:22px;margin-top:18px}table{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px;table-layout:fixed}th,td{text-align:left;padding:10px;border-bottom:1px solid #edf0f5;vertical-align:top;overflow-wrap:anywhere;word-break:break-word}th{color:#667085}.match{font-weight:800}.priority-table th:nth-child(1){width:17%}.priority-table th:last-child{width:22%}.attack-table th:nth-child(1){width:11%}.attack-table th:nth-child(2){width:24%}.final{border-left:5px solid #2563eb}.final h2{margin:0 0 12px}.final ul{margin:8px 0}.detail-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:18px;margin-top:18px}.detail-grid .card{padding:22px}.wide{grid-column:1/-1}.compact-table td,.compact-table th{padding:8px;font-size:12px}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-all}.subhead{margin:20px 0 8px;font-size:15px}.error{color:#b42318;font-weight:700}.file{margin-top:10px;font-weight:700;overflow-wrap:anywhere}.report-actions{display:flex;justify-content:flex-end;margin:0 0 4px}.download{display:none;border:0;border-radius:11px;background:#2563eb;color:#fff;font-weight:800;padding:12px 18px;cursor:pointer}.cape-overview{border-left:5px solid #10b981}.cape-alert{display:none;margin-top:12px;padding:11px 13px;border-radius:10px;background:#fff4e5;color:#9a4d00;font-size:13px;white-space:pre-wrap;overflow-wrap:anywhere}@media(max-width:800px){.detail-grid{grid-template-columns:1fr}.wide{grid-column:auto}.attack-table{font-size:11px}.attack-table th,.attack-table td{padding:7px 5px}}
@media(max-width:780px){.grid,.controls{grid-template-columns:1fr}.controls button{width:100%}}
</style></head>
<body><div class="wrap">
<h1>악성코드 자동 분석</h1><div class="sub">파일을 업로드하면 자체 분석을 먼저 완료한 뒤 VirusTotal 해시 결과와 독립 비교하고, 마지막 AI가 두 결과를 종합합니다.</div>
<div id="drop" class="card drop"><strong>파일을 드래그하거나 클릭하세요</strong><span class="muted">EXE · DLL · BAT · CMD · PS1 · PY · JS · ZIP</span><div id="fileName" class="file"></div><input id="file" type="file" hidden></div>
<div class="controls"><input id="password" type="password" autocomplete="off" placeholder="암호화 ZIP 비밀번호 (필요한 경우)"><input id="member" type="text" placeholder="ZIP 내부 실행 파일명 (선택)"><button id="start" disabled>분석 시작</button></div>
<div id="status" class="card status"><div id="stage" class="stage">대기 중</div><div id="capeMeta" class="cape-meta"></div><div class="bar"><div id="bar"></div></div><div id="error" class="error"></div><div id="logs" class="logs"></div></div>
<div id="results" class="results"><div class="report-actions"><button id="downloadPdf" class="download" type="button">최종 보고서 PDF 다운로드</button></div>
<section class="card cape-overview"><div class="eyebrow">CAPE Dynamic Summary</div><div class="title">CAPE 실행 요약</div><div id="capeTopMetrics" class="metric"></div><div id="capeTopAlert" class="cape-alert"></div></section>
<section class="card compare"><div class="eyebrow">Cross Validation</div><div class="title">자체 분석 ↔ VirusTotal 비교</div><table class="priority-table"><thead><tr><th>행위</th><th>자체 분석</th><th>VirusTotal</th><th>판정</th></tr></thead><tbody id="compareBody"></tbody></table></section>
<section class="card compare"><div class="eyebrow">MITRE ATT&CK Candidates</div><div class="title">ATT&CK 후보 비교</div><p class="muted">로컬 증거와 VirusTotal 외부 매핑에서 파생된 후보이며 공격 성공이나 전체 공격 경로를 확정하지 않습니다.</p><table class="attack-table"><thead><tr><th>Technique</th><th>이름</th><th>Local</th><th>VT</th><th>판정</th><th>신뢰도</th></tr></thead><tbody id="attackBody"></tbody></table></section>
<div class="grid"><section class="card pane"><div class="eyebrow">Local Analysis</div><div class="title">자체 AI 분석</div><div id="localMetrics" class="metric"></div><p id="localSummary" class="summary"></p><h3 class="subhead">자체 분석 상세 해석</h3><div id="localNarrative" class="summary"></div><h3 class="subhead">위험도 산정 근거</h3><ul id="localRiskRationale" class="behaviors"></ul><h3 class="subhead">핵심 증거</h3><ul id="localBehaviors" class="behaviors"></ul></section><section class="card pane"><div class="eyebrow">External Intelligence</div><div class="title">VirusTotal</div><div id="vtMetrics" class="metric"></div><p id="vtSummary" class="summary"></p><ul id="vtTags" class="behaviors"></ul><h3 class="subhead">외부 행위 핵심</h3><ul id="vtBehaviors" class="behaviors"></ul><h3 class="subhead">주요 위협명·실행 근거</h3><ul id="vtEvidence" class="behaviors"></ul></section></div><section class="card final"><div class="eyebrow">Final AI</div><h2>AI 최종 종합판정</h2><div id="finalConfidence" class="metric"></div><p id="finalSummary" class="summary"></p><div id="finalOverall" class="pill"></div><h3>종합 해석</h3><div id="finalExecutive" class="summary"></div><h3>로컬·외부 증거 종합</h3><ul id="finalSynthesis"></ul><h3>가능성이 높은 행위 체인</h3><ol id="finalBehaviorChain"></ol><h3>위험도 해석</h3><ul id="finalRiskInterpretation"></ul><h3>분석가 최종 결론</h3><p id="finalAnalystConclusion" class="summary"></p><h3>VT 근거를 반영한 핵심 분석</h3><ul id="finalExternalEvidence"></ul><h3>일치한 핵심</h3><ul id="agreements"></ul><h3>차이와 해석</h3><ul id="differences"></ul><h3>패밀리 해석</h3><p id="familyNote" class="summary"></p><h3>한계</h3><ul id="limitations"></ul></section>
<section class="card compare"><div class="eyebrow">Analysis Target</div><div class="title">분석 대상 상세 식별</div><table class="compact-table"><tbody id="sampleBody"></tbody></table></section>
<div class="detail-grid">
<section class="card"><div class="eyebrow">Static Analysis</div><div class="title">상세 정적 분석</div><div id="staticMetrics" class="metric"></div><h3 class="subhead">Import 요약</h3><table class="compact-table"><thead><tr><th>모듈</th><th>심볼 수</th><th>주요 심볼</th></tr></thead><tbody id="importBody"></tbody></table><h3 class="subhead">정적 후보 기능</h3><ul id="findingList" class="behaviors"></ul></section>
<section class="card"><div class="eyebrow">PE Sections</div><div class="title">PE 섹션 구조</div><table class="compact-table"><thead><tr><th>섹션</th><th>Virtual</th><th>Raw</th><th>Entropy</th></tr></thead><tbody id="sectionBody"></tbody></table></section>
<section class="card"><div class="eyebrow">Evidence Coverage</div><div class="title">증거 및 AI 처리 현황</div><div id="evidenceMetrics" class="metric"></div><table class="compact-table"><thead><tr><th>AI 단계</th><th>상태</th><th>세부</th></tr></thead><tbody id="aiStageBody"></tbody></table></section>
<section class="card"><div class="eyebrow">Indicators</div><div class="title">주요 IOC</div><table class="compact-table"><thead><tr><th>유형</th><th>값</th></tr></thead><tbody id="iocBody"></tbody></table><h3 class="subhead">사용자 영향</h3><ul id="impactList" class="behaviors"></ul></section>
<section class="card"><div class="eyebrow">Unknowns</div><div class="title">확인하지 못한 내용</div><ul id="unknownList" class="behaviors"></ul></section>
<section class="card wide"><div class="eyebrow">Response Guidance</div><div class="title">대응 권고</div><ol id="recommendationList" class="behaviors"></ol></section>
</div>
<section class="card compare"><div class="eyebrow">Estimated Behavior Flow</div><div class="title">추정 행위 흐름</div><p class="muted">관찰·추론된 행위를 이해하기 쉽게 정리한 흐름이며, 이벤트 타임스탬프로 확정한 실제 실행 순서는 아닙니다.</p><ol id="behaviorFlow" class="behaviors"></ol></section></div>
</div><script>
const $=id=>document.getElementById(id);let selected=null,timer=null,currentJobId=null;
const drop=$('drop'),input=$('file'),start=$('start');drop.onclick=()=>input.click();input.onchange=()=>pick(input.files[0]);
['dragenter','dragover'].forEach(e=>drop.addEventListener(e,x=>{x.preventDefault();drop.classList.add('drag')}));['dragleave','drop'].forEach(e=>drop.addEventListener(e,x=>{x.preventDefault();drop.classList.remove('drag')}));drop.addEventListener('drop',e=>pick(e.dataTransfer.files[0]));
function pick(f){selected=f||null;$('fileName').textContent=selected?`${selected.name} · ${(selected.size/1024/1024).toFixed(2)} MB`:'';start.disabled=!selected}
function pill(text){const s=document.createElement('span');s.className='pill';s.textContent=text;return s}function li(list,text){const e=document.createElement('li');e.textContent=text;list.appendChild(e)}function clear(el){while(el.firstChild)el.removeChild(el.firstChild)}
start.onclick=async()=>{if(!selected)return;start.disabled=true;currentJobId=null;$('downloadPdf').style.display='none';$('status').style.display='block';$('results').style.display='none';$('error').textContent='';$('logs').textContent='';$('stage').textContent='업로드 중';$('bar').style.width='2%';const fd=new FormData();fd.append('file',selected);fd.append('password',$('password').value);fd.append('archive_member',$('member').value);let r=await fetch('/api/analyze',{method:'POST',body:fd});let j=await r.json();if(!r.ok){if(j.password_required){$('error').textContent='암호화된 ZIP입니다. 비밀번호를 입력한 뒤 다시 분석 시작을 누르세요.'}else $('error').textContent=j.error||'요청 실패';start.disabled=false;return}poll(j.job_id)};
function poll(id){if(timer)clearInterval(timer);timer=setInterval(async()=>{let r=await fetch('/api/status/'+id),j=await r.json();$('stage').textContent=j.stage||j.status;$('bar').style.width=(j.progress||0)+'%';const c=j.cape||{};$('capeMeta').textContent=c.status&&c.status!=='대기'?`CAPE · ${c.status} · Task ${c.task_id??'-'} · 경과 ${c.elapsed??0}초 · 실행 ${c.analysis_timeout??100}초 / 대기 ${c.wait_timeout??300}초`:'';$('logs').textContent=(j.logs||[]).slice(-30).join('\n');$('logs').scrollTop=$('logs').scrollHeight;if(j.status==='completed'){clearInterval(timer);currentJobId=id;$('downloadPdf').style.display='inline-flex';render(j.result);start.disabled=false}else if(j.status==='failed'){clearInterval(timer);$('error').textContent=j.error||`분석 실패 (code ${j.return_code??'-'})`;start.disabled=false}},1200)}
$('downloadPdf').onclick=()=>{if(currentJobId)window.location.assign('/api/report/'+encodeURIComponent(currentJobId)+'.pdf')};
function addRow(body,values){const tr=document.createElement('tr');values.forEach(v=>{const td=document.createElement('td');td.textContent=(v===null||v===undefined||v==='')?'-':String(v);tr.appendChild(td)});body.appendChild(tr)}
function bytes(v){const n=Number(v||0);if(!n)return '-';return n>=1048576?(n/1048576).toFixed(2)+' MB':n>=1024?(n/1024).toFixed(2)+' KB':n+' bytes'}
function fillList(id,items,empty,format=x=>String(x)){const el=$(id);clear(el);(items||[]).forEach(x=>li(el,format(x)));if(!(items||[]).length)li(el,empty)}
function render(r){
  $('results').style.display='block';
  const L=r.local||{},V=r.virustotal||{},C=r.cross_validation||{},F=r.final_assessment||{};
  const X=r.details||{},S=X.sample||{},ST=X.static||{},DY=X.dynamic||{},M=X.evidence_metrics||{};
  const D=L.dynamic||{};

  clear($('localMetrics'));
  $('localMetrics').append(pill('위험도 '+(L.risk_level||'미확인')),pill('패밀리 '+((L.family||{}).name||'미확인')),pill('CAPE '+(D.status||'not_run')));
  if(D.task_id!==null&&D.task_id!==undefined)$('localMetrics').append(pill('Task '+D.task_id));
  $('localMetrics').append(pill('프로세스 '+(D.process_count||0)),pill('Dropped '+(D.dropped_file_count||0)),pill('시그니처 '+(D.signature_count||0)));
  $('localSummary').textContent=L.summary||'';
  const localNarrative=$('localNarrative');clear(localNarrative);
  (L.analysis_narrative||[]).forEach(value=>{const p=document.createElement('p');p.textContent=value;p.className='summary';localNarrative.appendChild(p)});
  if(!(L.analysis_narrative||[]).length)localNarrative.textContent='상세 자체 분석이 생성되지 않았습니다.';
  fillList('localRiskRationale',L.risk_rationale||[],'위험도 근거가 생성되지 않았습니다.');
  fillList('localBehaviors',(L.behaviors||[]).slice(0,12),'핵심 행위 요약 없음',x=>`${x.title} · ${x.status} · ${x.description||''}`);

  clear($('vtMetrics'));
  if(V.found){const s=V.stats||{};$('vtMetrics').append(pill('악성 '+(s.malicious||0)),pill('의심 '+(s.suspicious||0)),pill('정상 '+(s.harmless||0)),pill('미탐 '+(s.undetected||0)),pill('후보 '+(V.family_candidate||'미확인')));$('vtSummary').textContent=`Behaviour ${V.behaviour_status||'미확인'} · MITRE ${V.mitre_status||'미확인'} · SHA-256 해시 조회만 사용`;}
  else{$('vtMetrics').append(pill('VT '+(V.status||'not_available')));$('vtSummary').textContent=V.status==='completed'?'VT NOT FOUND는 정상 판정이 아닙니다.':'VirusTotal 결과를 사용할 수 없습니다.'}
  fillList('vtTags',(V.tags||[]).slice(0,20),'VT 태그 없음');
  const BF=V.behavior_features||{},BD=V.behavior_detail||{};
  const behaviorLabels={file_write:'파일 쓰기',file_delete:'파일 삭제',process_create:'프로세스 생성',process_injection:'프로세스 인젝션',service_create:'서비스 생성',registry_modification:'레지스트리 변경',network_communication:'네트워크 통신',cryptographic_activity:'암호화 관련 동작',file_encryption:'파일 암호화'};
  const observed=Object.entries(behaviorLabels).filter(([k])=>BF[k]&&BF[k].observed).map(([k,label])=>{const x=BF[k]||{};return `${label} · ${x.count||0}건${(x.examples||[]).length?' · '+x.examples.slice(0,2).join('; '):''}`});
  fillList('vtBehaviors',observed,'VT 외부 샌드박스에서 요약된 관찰 행위 없음');
  const vtEvidence=[];
  (V.threat_names||[]).slice(0,8).forEach(x=>vtEvidence.push(`위협명 ${x.name} · ${x.count||0}개 엔진`));
  (V.engine_detections||[]).slice(0,12).forEach(x=>vtEvidence.push(`${x.engine} · ${x.category} · ${x.result||'탐지명 없음'}`));
  if((BD.verdict_labels||[]).length||(BD.verdicts||[]).length)vtEvidence.push(`샌드박스 판정 ${[...(BD.verdict_labels||[]),...(BD.verdicts||[])].join(', ')} · 신뢰도 ${BD.verdict_confidence??'미확인'}`);
  (BD.domains||[]).slice(0,5).forEach(x=>vtEvidence.push(`메모리 도메인 · ${x}`));
  (BD.command_executions||[]).slice(0,3).forEach(x=>vtEvidence.push(`실행 명령 · ${x}`));
  fillList('vtEvidence',vtEvidence,'추가 위협명·실행 근거 없음');

  const sampleBody=$('sampleBody');clear(sampleBody);
  [['외부 파일명',S.name],['외부 파일 크기',bytes(S.size)],['외부 SHA-256',S.sha256],['외부 형식',S.detected_type],['내부 파일명',S.inner_name],['내부 파일 크기',bytes(S.inner_size)],['내부 SHA-256',S.inner_sha256],['내부 형식',S.inner_type]].forEach(x=>addRow(sampleBody,x));

  clear($('staticMetrics'));
  $('staticMetrics').append(pill((ST.format||'형식 미확인')+' / '+(ST.machine||'machine 미확인')),pill('DLL '+(ST.is_dll?'예':'아니요')),pill('Entropy '+(ST.entropy??'-')),pill('Import '+(ST.import_module_count||0)+'개 / '+(ST.import_symbol_count||0)+' symbols'),pill('capa '+(ST.capa_rule_count||0)+' rules'),pill('Ghidra '+(ST.ghidra_provider||'미사용')));
  const importBody=$('importBody');clear(importBody);(ST.imports||[]).forEach(x=>addRow(importBody,[x.module,x.symbol_count,(x.symbols||[]).join(', ')]));if(!(ST.imports||[]).length)addRow(importBody,['확인된 Import 없음',0,'-']);
  fillList('findingList',ST.findings||[],'정적 후보 기능 없음',x=>`${x.category} · ${x.status} · ${(x.matched||[]).join(', ')||'세부 문자열 없음'}${x.evidence_id?' · '+x.evidence_id:''}`);
  const sectionBody=$('sectionBody');clear(sectionBody);(ST.sections||[]).forEach(x=>addRow(sectionBody,[x.name,x.virtual_size,x.raw_size,x.entropy]));if(!(ST.sections||[]).length)addRow(sectionBody,['섹션 정보 없음','-','-','-']);

  clear($('capeTopMetrics'));
  $('capeTopMetrics').append(pill('상태 '+(DY.status||'not_run')),pill('Task '+(DY.task_id??'-')),pill('Package '+(DY.package||'-')),pill('실행 '+(DY.duration??'-')+'초'),pill('해시 '+(DY.sample_hash_verified?'일치':'미확인')),pill('프로세스 '+(DY.process_count||0)),pill('시그니처 '+(DY.signature_count||0)),pill('Dropped '+(DY.dropped_count||0)));
  const capeAlert=$('capeTopAlert'),capeNotes=[];if(DY.timed_out)capeNotes.push('주의: 설정된 실행 시간이 만료되어 일부 행위가 관찰되지 않았을 수 있습니다.');(DY.errors||[]).forEach(x=>capeNotes.push('분석 오류: '+x));capeAlert.textContent=capeNotes.join('\n');capeAlert.style.display=capeNotes.length?'block':'none';

  clear($('evidenceMetrics'));
  $('evidenceMetrics').append(pill('Claims '+(M.claims||0)),pill('Events '+(M.events||0)),pill('Relations '+(M.relations||0)),pill('ATT&CK '+(M.attack_candidates||0)),pill('AI refs '+(M.validated_references||0)),pill('검증 '+(M.validation_status||'not_run')));
  const aiStageBody=$('aiStageBody');clear(aiStageBody);(X.ai_stages||[]).forEach(x=>addRow(aiStageBody,[x.stage,x.status,x.detail]));

  const iocBody=$('iocBody');clear(iocBody);(L.iocs||[]).forEach(x=>addRow(iocBody,[x.type||'IOC',x.value||'-']));if(!(L.iocs||[]).length)addRow(iocBody,['IOC','보고 가능한 값 없음']);
  fillList('impactList',L.user_impact||[],'사용자 영향 미확인');
  fillList('unknownList',L.unknowns||[],'추가 미확인 항목 없음');
  fillList('recommendationList',X.recommendations||[],'추가 대응 권고 없음');

  fillList('behaviorFlow',r.behavior_flow||[],'동작 순서를 복원하지 못했습니다.',x=>`${x.step}. ${x.title} · ${x.status}`);
  const attackBody=$('attackBody');clear(attackBody);(r.attack_candidates||[]).forEach(x=>addRow(attackBody,[x.technique_id,x.name||'-',x.local,x.virustotal,x.result,x.confidence]));
  const compareBody=$('compareBody');clear(compareBody);(C.items||[]).forEach(x=>{const tr=document.createElement('tr');[x.label,x.local,x.virustotal,x.result].forEach((v,i)=>{const td=document.createElement('td');td.textContent=v||'-';if(i===3)td.className='match';tr.appendChild(td)});compareBody.appendChild(tr)});

  clear($('finalConfidence'));$('finalConfidence').append(pill('신뢰도 '+(F.confidence||'미확인')),pill(F.generated_by||'AI'));
  $('finalSummary').textContent=F.summary||'최종 AI 종합판정이 생성되지 않았습니다.';
  $('finalOverall').textContent=F.overall_verdict||'추가 검증 필요';
  const finalExecutive=$('finalExecutive');clear(finalExecutive);
  (F.executive_assessment||[]).forEach(value=>{const p=document.createElement('p');p.textContent=value;p.className='summary';finalExecutive.appendChild(p)});
  if(!(F.executive_assessment||[]).length)finalExecutive.textContent='종합 해석이 생성되지 않았습니다.';
  fillList('finalSynthesis',F.evidence_synthesis||[],'종합할 추가 증거 없음');
  fillList('finalBehaviorChain',F.likely_behavior_chain||[],'행위 체인을 구성하지 못했습니다.');
  fillList('finalRiskInterpretation',F.risk_interpretation||[],'추가 위험도 해석 없음');
  $('finalAnalystConclusion').textContent=F.analyst_conclusion||'분석가 최종 결론이 생성되지 않았습니다.';
  fillList('finalExternalEvidence',F.external_evidence_points||[],'VT 핵심 근거 해석 없음');
  fillList('agreements',F.agreement_points||[],'명확한 일치 항목 없음');
  fillList('differences',F.difference_points||[],'별도 차이 설명 없음');
  $('familyNote').textContent=F.family_interpretation||'패밀리 해석 없음';
  fillList('limitations',F.limitations||[],'추가 한계 설명 없음');
  window.scrollTo({top:$('results').offsetTop-20,behavior:'smooth'});
}
</script></body></html>'''


def run_web_server(args: argparse.Namespace) -> int:
    try:
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import FileResponse, HTMLResponse, JSONResponse
        from starlette.routing import Route
        import uvicorn
    except ImportError as exc:
        print("[오류] 웹 UI 의존성이 없습니다. requirements.txt를 설치하세요.", file=sys.stderr)
        print(str(exc), file=sys.stderr)
        return 2

    async def index(_: Request) -> HTMLResponse:
        return HTMLResponse(WEB_HTML)

    async def analyze(request: Request) -> JSONResponse:
        global _WEB_ACTIVE_JOB
        with _WEB_JOBS_LOCK:
            if _WEB_ACTIVE_JOB and (_WEB_JOBS.get(_WEB_ACTIVE_JOB) or {}).get("status") in {"queued", "running"}:
                return JSONResponse({"error": "현재 다른 분석이 진행 중입니다."}, status_code=409)

        form = await request.form()
        upload = form.get("file")
        if upload is None or not getattr(upload, "filename", None):
            return JSONResponse({"error": "분석할 파일이 없습니다."}, status_code=400)
        safe_name = Path(str(upload.filename)).name
        if not safe_name or safe_name in {".", ".."}:
            return JSONResponse({"error": "올바르지 않은 파일명입니다."}, status_code=400)

        vault = PROJECT_ROOT / "malware-vault"
        vault.mkdir(parents=True, exist_ok=True)
        sample = vault / safe_name
        max_bytes = int(args.max_file_size_mb) * 1024 * 1024
        written = 0
        try:
            with sample.open("wb") as stream:
                while True:
                    chunk = await upload.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > max_bytes:
                        raise ValueError("파일 크기 제한 초과")
                    stream.write(chunk)
        except Exception as exc:
            sample.unlink(missing_ok=True)
            return JSONResponse({"error": str(exc)}, status_code=413 if "크기" in str(exc) else 400)

        password = str(form.get("password") or "")
        if _zip_requires_password(sample) and not password:
            sample.unlink(missing_ok=True)
            return JSONResponse({"error": "암호화 ZIP 비밀번호가 필요합니다.", "password_required": True}, status_code=422)
        archive_member = str(form.get("archive_member") or "").strip() or None

        job_id = uuid.uuid4().hex
        output = PROJECT_ROOT / "analysis-results" / "runs" / f"{datetime.now():%Y%m%d_%H%M%S}_{sample.stem}"
        output.mkdir(parents=True, exist_ok=True)
        with _WEB_JOBS_LOCK:
            _WEB_ACTIVE_JOB = job_id
            _WEB_JOBS[job_id] = {
                "job_id": job_id,
                "status": "queued",
                "stage": "분석 대기",
                "progress": 1,
                "logs": [],
            }
        thread = threading.Thread(
            target=_web_run_job,
            args=(job_id, args, sample, output, password, archive_member),
            daemon=True,
        )
        thread.start()
        return JSONResponse({"job_id": job_id})

    async def status(request: Request) -> JSONResponse:
        job_id = request.path_params["job_id"]
        with _WEB_JOBS_LOCK:
            job = _WEB_JOBS.get(job_id)
            if not job:
                return JSONResponse({"error": "분석 작업을 찾을 수 없습니다."}, status_code=404)
            payload = json.loads(json.dumps(job, ensure_ascii=False, default=str))
        cape = payload.get("cape")
        if isinstance(cape, dict) and cape.get("started_at") and cape.get("status") not in {"완료", "실패/시간초과"}:
            try:
                cape["elapsed"] = int(max(0, time.time() - float(cape["started_at"])))
            except (TypeError, ValueError):
                pass
        return JSONResponse(payload)

    async def pdf_report(request: Request):
        job_id = request.path_params["job_id"]
        with _WEB_JOBS_LOCK:
            job = _WEB_JOBS.get(job_id)
            if not job:
                return JSONResponse({"error": "분석 작업을 찾을 수 없습니다."}, status_code=404)
            if job.get("status") != "completed" or not isinstance(job.get("result"), dict):
                return JSONResponse({"error": "분석이 완료된 뒤 PDF를 받을 수 있습니다."}, status_code=409)
            existing_pdf = job.get("pdf_path")
            result = json.loads(json.dumps(job["result"], ensure_ascii=False, default=str))
        try:
            if existing_pdf and Path(existing_pdf).is_file():
                pdf_path = Path(existing_pdf)
            else:
                from src.reporting.pdf_report import render_analysis_pdf

                details = result.get("details") or {}
                sample_info = details.get("sample") or result.get("sample") or {}
                dynamic_info = details.get("dynamic") or {}
                safe_stem = re.sub(r"[^0-9A-Za-z._-]+", "_", Path(str(sample_info.get("name") or "sample")).stem).strip("._") or "sample"
                task_label = dynamic_info.get("task_id")
                prefix = f"Task-{task_label}" if task_label is not None else "Static"
                pdf_path = PROJECT_ROOT / "output" / "pdf" / f"{prefix}-{safe_stem}-malware-analysis-report.pdf"
                render_analysis_pdf(result, pdf_path)
                with _WEB_JOBS_LOCK:
                    if job_id in _WEB_JOBS:
                        _WEB_JOBS[job_id]["pdf_path"] = str(pdf_path)
            return FileResponse(
                str(pdf_path),
                media_type="application/pdf",
                filename=pdf_path.name,
            )
        except Exception as exc:
            return JSONResponse({"error": f"PDF 생성 실패: {exc}"}, status_code=500)

    app = Starlette(routes=[
        Route("/", index, methods=["GET"]),
        Route("/api/analyze", analyze, methods=["POST"]),
        Route("/api/status/{job_id}", status, methods=["GET"]),
        Route("/api/report/{job_id}.pdf", pdf_report, methods=["GET"]),
    ])
    print(f"[웹] http://{args.web_host}:{args.web_port}")
    print("[안전] 웹 UI는 기본적으로 localhost에만 바인딩됩니다.")
    uvicorn.run(app, host=args.web_host, port=args.web_port, log_level="warning")
    return 0

def arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="파일 1개 정적 분석 + Ghidra + CAPE 동적 분석 + AI 통합 보고서"
    )
    parser.add_argument("sample", type=Path, nargs="?")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--static-only", action="store_true")
    parser.add_argument("--skip-ghidra", action="store_true")
    parser.add_argument("--no-start-cape", action="store_true")
    parser.add_argument("--cape-url", default=os.getenv("CAPE_API_URL") or DEFAULT_CAPE_URL)
    parser.add_argument("--cape-token", default=os.getenv("CAPE_API_TOKEN"))
    parser.add_argument("--cape-machine", default=DEFAULT_CAPE_MACHINE)
    parser.add_argument("--cape-package")
    parser.add_argument("--archive-password", default=os.getenv("MALWARE_ARCHIVE_PASSWORD"))
    parser.add_argument("--archive-member")
    parser.add_argument("--cape-analysis-timeout", type=int, default=100)
    parser.add_argument("--cape-wait-timeout", type=int, default=300)
    parser.add_argument("--wsl-distro", default="Ubuntu-24.04")
    parser.add_argument("--no-local-ai", action="store_true")
    default_ai_url, default_ai_model, default_ai_key = default_ai_settings()
    parser.add_argument("--local-base-url", default=default_ai_url)
    parser.add_argument("--local-model", default=default_ai_model)
    parser.add_argument("--local-api-key", default=default_ai_key)
    parser.add_argument("--use-cloud", action="store_true")
    parser.add_argument("--cloud-base-url", default=os.getenv("CLOUD_AI_BASE_URL"))
    parser.add_argument("--cloud-api-key", default=os.getenv("CLOUD_AI_API_KEY"))
    parser.add_argument("--cloud-model", default=os.getenv("CLOUD_AI_MODEL"))
    parser.add_argument("--capa-path", type=Path)
    parser.add_argument("--skip-capa", action="store_true")
    parser.add_argument("--no-vt", action="store_true", help="VirusTotal 해시 조회 비활성화")
    parser.add_argument("--vt-api-key", default=os.getenv("VIRUSTOTAL_API_KEY"))
    parser.add_argument("--vt-timeout", type=int, default=20)
    parser.add_argument("--vt-max-related", type=int, default=1)
    parser.add_argument("--vt-min-interval", type=float, default=float(os.getenv("VT_MIN_INTERVAL_SECONDS", "16")))
    parser.add_argument("--vt-refresh", action="store_true")
    parser.add_argument("--max-file-size-mb", type=int, default=512)
    parser.add_argument("--ai-timeout", type=int, default=120)
    parser.add_argument("--max-domain-reviews", type=int, default=4)
    parser.add_argument("--local-report-timeout", type=int, default=180)
    parser.add_argument("--local-report-attempts", type=int, default=1)
    parser.add_argument("--web", action="store_true", help="로컬 웹 업로드 UI 실행")
    parser.add_argument("--web-host", default="127.0.0.1")
    parser.add_argument("--web-port", type=int, default=8765)
    return parser.parse_args(argv)


def build_pipeline_argv(args: argparse.Namespace, sample: Path, output: Path) -> list[str]:
    pipeline = [
        "DEMO.py",
        str(sample),
        "--output-dir",
        str(output),
        "--max-file-size-mb",
        str(args.max_file_size_mb),
        "--max-mcp-calls-per-pass",
        "2",
        "--ai-timeout",
        str(args.ai_timeout),
        "--max-domain-reviews",
        str(args.max_domain_reviews),
        "--local-report-timeout",
        str(args.local_report_timeout),
        "--local-report-attempts",
        str(args.local_report_attempts),
    ]

    if args.archive_password:
        pipeline.extend(["--archive-password", args.archive_password])
        if sample.suffix.casefold() == ".zip":
            pipeline.extend(["--isolated-static-wsl", args.wsl_distro])
            print(f"[isolated static] decrypt and run capa only inside {args.wsl_distro}")
    if args.archive_member:
        pipeline.extend(["--archive-member", args.archive_member])

    if args.no_local_ai:
        # DEMO.py parses its own arguments and otherwise falls back to the
        # LOCAL_AI_* values loaded from .env. Merely omitting explicit local
        # AI settings therefore does not disable the downstream AI stages.
        pipeline.append("--no-local-ai")

    capa_path = None if args.skip_capa else (args.capa_path or find_capa())
    if capa_path:
        pipeline.extend(["--capa-path", str(capa_path.resolve())])
        print(f"[capa] 활성화: {capa_path}")
    elif not args.skip_capa:
        print("[경고] capa를 찾지 못해 해당 단계만 건너뜁니다. CAPA_PATH 또는 --capa-path를 설정하세요.")

    if not args.no_local_ai:
        if is_openai_api(args.local_base_url):
            if not args.local_api_key:
                print("[경고] OPENAI_API_KEY가 없어 AI 단계를 비활성화하고 규칙 기반 분석으로 계속합니다.")
            else:
                pipeline.extend([
                    "--local-base-url", args.local_base_url,
                    "--local-api-key", args.local_api_key,
                    "--local-model", args.local_model,
                    "--local-context-chars", "80000",
                ])
                print(f"[AI] OpenAI {args.local_model}")
        else:
            available, models = ollama_model_available(args.local_base_url, args.local_model)
            if available:
                pipeline.extend([
                    "--local-base-url", args.local_base_url,
                    "--local-api-key", args.local_api_key or "ollama",
                    "--local-model", args.local_model,
                    "--local-context-chars", "80000",
                ])
                print(f"[로컬 AI] {args.local_model}")
            else:
                print(f"[경고] 로컬 AI를 사용할 수 없어 규칙 기반 분석으로 계속합니다: {models}")

    if args.no_vt:
        pipeline.append("--no-vt")
    else:
        if args.vt_api_key:
            pipeline.extend(["--vt-api-key", args.vt_api_key])
        pipeline.extend(["--vt-timeout", str(args.vt_timeout)])
        pipeline.extend(["--vt-max-related", str(args.vt_max_related)])
        pipeline.extend(["--vt-min-interval", str(args.vt_min_interval)])
        if args.vt_refresh:
            pipeline.append("--vt-refresh")

    if args.use_cloud:
        if not args.cloud_base_url or not args.cloud_model:
            raise RuntimeError(
                "--use-cloud 사용 시 CLOUD_AI_BASE_URL과 CLOUD_AI_MODEL이 필요합니다."
            )
        pipeline.extend(
            [
                "--cloud-base-url",
                args.cloud_base_url,
                "--cloud-model",
                args.cloud_model,
            ]
        )
        if args.cloud_api_key:
            pipeline.extend(["--cloud-api-key", args.cloud_api_key])
    else:
        pipeline.append("--no-cloud")

    if is_pe_file(sample) and not args.skip_ghidra:
        available, detail = ghidra_available()
        if available:
            pipeline.extend(
                [
                    "--mcp-command",
                    sys.executable,
                    "--mcp-arg",
                    str(PROJECT_ROOT / "GHIDRA_MCP_SERVER.py"),
                    "--mcp-plan",
                    str(PROJECT_ROOT / "config" / "mcp_plan.json"),
                ]
            )
            print(f"[Ghidra] 활성화: {detail}")
        else:
            print(f"[경고] Ghidra를 사용할 수 없어 건너뜁니다: {detail}")

    if not args.static_only:
        token = args.cape_token or load_cape_token(args.wsl_distro)
        if not token:
            raise RuntimeError(
                "CAPE API 토큰을 불러오지 못했습니다. CAPE_API_TOKEN을 설정하세요."
            )
        package = args.cape_package or cape_package_for(sample)
        if not package:
            print(
                f"[경고] {sample.suffix or '확장자 없음'} 형식은 CAPE 자동 실행을 "
                "지원하지 않아 정적 분석만 수행합니다."
            )
        else:
            audit_cape_safety(args.wsl_distro)
            ensure_cape_ready(
                args.cape_url,
                token,
                auto_start=not args.no_start_cape,
            )
            pipeline.extend(
                [
                    "--cape-url",
                    args.cape_url,
                    "--cape-token",
                    token,
                    "--cape-machine",
                    args.cape_machine,
                    "--cape-package",
                    package,
                    "--cape-analysis-timeout",
                    str(args.cape_analysis_timeout),
                    "--cape-wait-timeout",
                    str(args.cape_wait_timeout),
                ]
            )
            cape_options = []
            if package == "zip" and args.archive_password:
                cape_options.append(f"password={args.archive_password}")
            if package == "zip" and args.archive_member:
                cape_options.append(f"file={args.archive_member}")
            if cape_options:
                pipeline.extend(["--cape-options", ",".join(cape_options)])
            pipeline[0] = "CAPE_DEMO.py"
            print(f"[CAPE] 동적 분석 활성화: package={package}")

    return pipeline


def main(argv: list[str] | None = None) -> int:
    args = arguments(argv)
    if args.web:
        return run_web_server(args)
    if args.sample is None:
        print("[오류] 분석할 파일을 지정하거나 --web을 사용하세요.", file=sys.stderr)
        return 2
    sample = args.sample.expanduser().resolve()
    if not sample.is_file():
        print(f"[오류] 파일을 찾을 수 없습니다: {sample}", file=sys.stderr)
        return 2

    output = (
        args.output_dir.expanduser().resolve()
        if args.output_dir
        else PROJECT_ROOT
        / "analysis-results"
        / "runs"
        / f"{datetime.now():%Y%m%d_%H%M%S}_{sample.stem}"
    )
    output.mkdir(parents=True, exist_ok=True)

    print(f"[입력] {sample}")
    print("[안전] 호스트에서는 샘플을 실행하지 않습니다.")
    keepalive = start_wsl_keepalive(args.wsl_distro) if not args.static_only else None
    try:
        try:
            pipeline_argv = build_pipeline_argv(args, sample, output)
        except RuntimeError as exc:
            print(f"[오류] {exc}", file=sys.stderr)
            return 2

        previous_argv = sys.argv
        sys.argv = pipeline_argv
        if pipeline_argv[0] == "CAPE_DEMO.py":
            import CAPE_DEMO

            result = CAPE_DEMO.main()
        else:
            import DEMO

            result = DEMO.main()
    finally:
        if "previous_argv" in locals():
            sys.argv = previous_argv
        stop_wsl_keepalive(keepalive)
    if result == 0:
        print_result_summary(output)
    return result


if __name__ == "__main__":
    raise SystemExit(main())