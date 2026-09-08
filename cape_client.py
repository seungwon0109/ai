#!/usr/bin/env python3
"""Small, defensive CAPE v2 REST client and report normalizer."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import httpx


TERMINAL_SUCCESS = {"reported", "completed"}
TERMINAL_FAILURE = {
    "failed_analysis",
    "failed_processing",
    "failed_reporting",
    "recovered",
}


class CapeError(RuntimeError):
    """Raised when CAPE submission, polling, or report retrieval fails."""


def _limited(value: Any, limit: int) -> list[Any]:
    return value[:limit] if isinstance(value, list) else []


def _task_id(payload: dict[str, Any]) -> int:
    candidates: list[Any] = [
        payload.get("task_id"),
        payload.get("task_ids"),
        payload.get("data"),
    ]
    for candidate in candidates:
        if isinstance(candidate, int):
            return candidate
        if isinstance(candidate, list) and candidate:
            try:
                return int(candidate[0])
            except (TypeError, ValueError):
                pass
        if isinstance(candidate, dict):
            try:
                return _task_id(candidate)
            except CapeError:
                pass
    raise CapeError(f"CAPE response did not contain a task ID: {payload}")


def _task_status(payload: dict[str, Any]) -> str:
    task = payload.get("task", payload.get("data", payload))
    if isinstance(task, dict):
        value = task.get("status")
        if isinstance(value, str) and value:
            return value.casefold()
    raise CapeError(f"CAPE task response did not contain a status: {payload}")

def _retry_after_seconds(response: httpx.Response, fallback: float) -> float:
    value = response.headers.get("Retry-After", "")
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        seconds = fallback
    return max(0.2, seconds)


def _network_summary(network: Any) -> dict[str, list[Any]]:
    source = network if isinstance(network, dict) else {}
    return {
        "hosts": _limited(source.get("hosts"), 100),
        "domains": _limited(source.get("domains"), 100),
        "dns": _limited(source.get("dns"), 100),
        "http": _limited(source.get("http"), 100),
        "tcp": _limited(source.get("tcp"), 100),
        "udp": _limited(source.get("udp"), 100),
        "smtp": _limited(source.get("smtp"), 50),
    }


def _integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip(), 0)
        except ValueError:
            return None
    return None


def _signature_pids(value: Any, *, limit: int = 100) -> list[int]:
    """Extract explicit actor PIDs without guessing from free-form prose."""
    output: list[int] = []

    def walk(current: Any) -> None:
        if len(output) >= limit:
            return
        if isinstance(current, dict):
            for key, child in current.items():
                if str(key).casefold() in {"pid", "process_id", "processid"}:
                    pid = _integer(child)
                    if pid is not None and pid >= 0 and pid not in output:
                        output.append(pid)
                else:
                    walk(child)
        elif isinstance(current, list):
            for child in current:
                walk(child)

    walk(value)
    return output


def _signature_summary(signatures: Any) -> tuple[list[dict[str, Any]], list[str]]:
    output: list[dict[str, Any]] = []
    techniques: set[str] = set()
    for item in _limited(signatures, 150):
        if not isinstance(item, dict):
            continue
        ttps = item.get("ttps", [])
        if isinstance(ttps, list):
            for value in ttps:
                if isinstance(value, str):
                    techniques.add(value)
                elif isinstance(value, dict):
                    technique = value.get("ttp") or value.get("id")
                    if isinstance(technique, str):
                        techniques.add(technique)
        data = _limited(item.get("data"), 100)
        marks = _limited(item.get("marks"), 100)
        output.append({
            "name": item.get("name"),
            "description": item.get("description"),
            "severity": item.get("severity"),
            "confidence": item.get("confidence"),
            "ttps": ttps[:30] if isinstance(ttps, list) else [],
            # CAPE signatures commonly place the originating PID and call ID in
            # data rather than marks.  Dropping data destroys actor provenance.
            "data": data,
            "marks": marks,
            "actor_pids": _signature_pids([data, marks]),
        })
    return output, sorted(techniques)


CAUSAL_APIS = {
    "createprocessa", "createprocessw", "createprocessinternalw",
    "shellexecutea", "shellexecutew", "winexec",
    "ntopenprocess", "openprocess", "ntwritevirtualmemory",
    "writeprocessmemory", "virtualallocex", "ntallocatevirtualmemory",
    "createremotethread", "createremotethreadex", "ntcreatethreadex",
    "ntresumethread", "resumethread", "queueuserapc", "ntqueueapcthread",
    "createfilea", "createfilew", "ntcreatefile", "ntwritefile",
    "writefile", "movefilea", "movefilew", "copyfilea", "copyfilew",
    "regsetvalueexa", "regsetvalueexw", "ntsetvaluekey",
    "createservicea", "createservicew", "changeserviceconfiga",
    "changeserviceconfigw", "startservicea", "startservicew",
    "schtasks", "iwbemservices_execmethod", "iwbemservices_putinstance",
    "internetconnecta", "internetconnectw", "httpopenrequesta",
    "httpopenrequestw", "httpsendrequesta", "httpsendrequestw",
    "winhttpsendrequest", "connect", "wsaconnect", "dnsquery_a", "dnsquery_w",
}


def _arguments(value: Any) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for item in value if isinstance(value, list) else []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        raw = item.get("value")
        output[name] = raw
        pretty = item.get("pretty_value")
        if pretty not in (None, ""):
            output[f"{name}__pretty"] = pretty
    return output


def _causal_calls(process: dict[str, Any], *, limit: int = 1500) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    actor_pid = _integer(process.get("process_id"))
    for call in process.get("calls") if isinstance(process.get("calls"), list) else []:
        if not isinstance(call, dict):
            continue
        api = str(call.get("api") or "")
        if api.casefold() not in CAUSAL_APIS:
            continue
        output.append({
            "actor_pid": actor_pid,
            "call_id": call.get("id"),
            "timestamp": call.get("timestamp"),
            "api": api,
            "status": call.get("status"),
            "return_value": call.get("return_value"),
            "arguments": _arguments(call.get("arguments")),
        })
        if len(output) >= limit:
            break
    return output


def _process_summary(behavior: Any) -> dict[str, Any]:
    source = behavior if isinstance(behavior, dict) else {}
    processes = []
    causal_calls: list[dict[str, Any]] = []
    for item in _limited(source.get("processes"), 150):
        if not isinstance(item, dict):
            continue
        processes.append({
            "process_id": item.get("process_id"),
            "parent_id": item.get("parent_id"),
            "process_name": item.get("process_name"),
            "module_path": item.get("module_path"),
            "command_line": item.get("command_line"),
            "first_seen": item.get("first_seen"),
        })
        if len(causal_calls) < 5000:
            causal_calls.extend(_causal_calls(item, limit=1500)[: 5000 - len(causal_calls)])
    summary = source.get("summary")
    return {
        "processes": processes,
        "process_tree": _limited(source.get("processtree"), 50),
        "summary": summary if isinstance(summary, dict) else {},
        "causal_calls": causal_calls,
        "causal_calls_truncated": len(causal_calls) >= 5000,
    }


def _analysis_failures(report: dict[str, Any]) -> list[str]:
    """Extract terminal analyzer failures that CAPE may only expose in debug.log."""
    failures: list[str] = []
    raw_errors = report.get("errors")
    if isinstance(raw_errors, list):
        failures.extend(str(item) for item in raw_errors if item)
    elif raw_errors:
        failures.append(str(raw_errors))

    debug = report.get("debug") if isinstance(report.get("debug"), dict) else {}
    debug_log = str(debug.get("log") or "")
    fatal_markers = (
        "ERROR_BAD_EXE_FORMAT",
        "Unable to execute the initial process, analysis aborted",
        "You probably submitted the job with wrong package",
        "CuckooPackageError: Unable to execute the initial process",
    )
    for line in debug_log.splitlines():
        if any(marker.casefold() in line.casefold() for marker in fatal_markers):
            failures.append(line.strip())

    return list(dict.fromkeys(failures))[:100]


def normalize_cape_report(
    report: dict[str, Any],
    *,
    task_id: int,
    expected_sha256: str,
) -> dict[str, Any]:
    """Reduce a large CAPE report to bounded evidence suitable for an AI prompt."""
    info = report.get("info") if isinstance(report.get("info"), dict) else {}
    target = report.get("target") if isinstance(report.get("target"), dict) else {}
    target_file = target.get("file") if isinstance(target.get("file"), dict) else {}
    observed_sha256 = target_file.get("sha256")
    signatures, techniques = _signature_summary(report.get("signatures"))
    analysis_errors = _analysis_failures(report)
    dropped = []
    for item in _limited(report.get("dropped"), 100):
        if isinstance(item, dict):
            guest_paths = _limited(item.get("guest_paths"), 20)
            dropped.append({
                "name": item.get("name"),
                "path": item.get("path"),
                "guest_paths": guest_paths,
                "pid": item.get("pid"),
                "size": item.get("size"),
                "type": item.get("type"),
                "sha256": item.get("sha256"),
                "runtime_staging": any("\\_mei" in str(path).casefold() for path in guest_paths),
            })
    cape_payloads = report.get("CAPE")
    if not isinstance(cape_payloads, list):
        cape_payloads = report.get("cape") if isinstance(report.get("cape"), list) else []
    return {
        "provider": "cape",
        "status": "failed" if analysis_errors else "completed",
        "task_id": task_id,
        "sample_name": target_file.get("name"),
        "sample_sha256": observed_sha256,
        "sample_sha256_verified": (
            isinstance(observed_sha256, str)
            and observed_sha256.casefold() == expected_sha256.casefold()
        ),
        "score": report.get("malscore", info.get("score")),
        "category": info.get("category"),
        "package": info.get("package"),
        "duration": info.get("duration"),
        "analysis_timed_out": bool(info.get("timeout")),
        "machine": info.get("machine"),
        "signatures": signatures,
        "mitre_techniques": techniques,
        "behavior": _process_summary(report.get("behavior")),
        "network": _network_summary(report.get("network")),
        "dropped_files": dropped,
        "extracted_payloads": _limited(cape_payloads, 100),
        "malware_config": report.get("cape_config") or report.get("malware_config") or {},
        "suricata": report.get("suricata") if isinstance(report.get("suricata"), dict) else {},
        "analysis_errors": analysis_errors,
        "error": analysis_errors[0] if analysis_errors else None,
    }


class CapeClient:
    """Synchronous CAPE client used by the local orchestration pipeline."""

    def __init__(
        self,
        base_url: str,
        token: str | None = None,
        *,
        request_timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Token {token}"
        self.client = httpx.Client(
            base_url=self.base_url + "/",
            headers=headers,
            timeout=request_timeout,
            follow_redirects=True,
        )

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> "CapeClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @staticmethod
    def _json(response: httpx.Response, operation: str) -> dict[str, Any]:
        try:
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise CapeError(
                f"CAPE {operation} failed: {exc}; response={response.text[:1000]}"
            ) from exc
        if not isinstance(payload, dict):
            raise CapeError(f"CAPE {operation} returned non-object JSON")
        return payload

    def submit_file(
        self,
        sample: Path,
        *,
        analysis_timeout: int,
        package: str | None = None,
        machine: str | None = None,
        tags: str | None = None,
        options: str | None = None,
    ) -> int:
        data = {"timeout": str(analysis_timeout), "platform": "windows"}
        for key, value in (
            ("package", package),
            ("machine", machine),
            ("tags", tags),
            ("options", options),
        ):
            if value:
                data[key] = value
        try:
            with sample.open("rb") as stream:
                response = self.client.post(
                    "tasks/create/file/",
                    data=data,
                    files={"file": (sample.name, stream, "application/octet-stream")},
                )
        except (OSError, httpx.HTTPError) as exc:
            raise CapeError(f"CAPE submission failed: {exc}") from exc
        return _task_id(self._json(response, "submission"))

    def wait_for_report(
        self,
        task_id: int,
        *,
        wait_timeout: int,
        poll_interval: float,
    ) -> str:
        started = time.monotonic()
        deadline = started + wait_timeout
        last_status = "unknown"
        last_logged_status: str | None = None
        last_logged_at = -15.0
        while time.monotonic() < deadline:
            try:
                response = self.client.get(f"tasks/view/{task_id}/")
            except httpx.HTTPError as exc:
                last_status = f"connection_error: {exc}"
                delay = max(0.2, poll_interval)
                if time.monotonic() + delay >= deadline:
                    break
                time.sleep(delay)
                continue
            if response.status_code == 429:
                delay = _retry_after_seconds(response, poll_interval)
                if time.monotonic() + delay >= deadline:
                    last_status = "rate_limited"
                    break
                time.sleep(delay)
                continue
            last_status = _task_status(self._json(response, "status request"))
            elapsed = int(time.monotonic() - started)
            if last_status != last_logged_status or elapsed - last_logged_at >= 15:
                print(
                    f"[CAPE] 상태={last_status} · 경과={elapsed}초 / 대기한도={wait_timeout}초",
                    flush=True,
                )
                last_logged_status = last_status
                last_logged_at = float(elapsed)
            if last_status in TERMINAL_SUCCESS:
                return last_status
            if last_status in TERMINAL_FAILURE or last_status.startswith("failed"):
                raise CapeError(f"CAPE task {task_id} ended with status {last_status}")
            time.sleep(max(0.2, poll_interval))
        raise CapeError(
            f"CAPE task {task_id} did not finish within {wait_timeout}s "
            f"(last status: {last_status})"
        )

    def get_report(
        self,
        task_id: int,
        *,
        wait_timeout: int = 300,
        poll_interval: float = 5.0,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + wait_timeout
        errors = []
        for endpoint in (
            f"tasks/get/report/{task_id}/",
            f"tasks/report/{task_id}/",
        ):
            while time.monotonic() < deadline:
                try:
                    response = self.client.get(endpoint)
                    if response.status_code == 429:
                        time.sleep(_retry_after_seconds(response, poll_interval))
                        continue
                    if response.status_code == 404:
                        errors.append(f"{endpoint}: 404")
                        break
                    payload = self._json(response, "report request")
                    if payload.get("error") is True:
                        message = str(
                            payload.get("error_value")
                            or payload.get("message")
                            or "unknown CAPE application error"
                        )
                        if "still being analyzed" in message.casefold():
                            time.sleep(max(0.2, poll_interval))
                            continue
                        errors.append(f"{endpoint}: {message}")
                        break
                    if not isinstance(payload.get("target"), dict):
                        errors.append(f"{endpoint}: response was not a CAPE report")
                        break
                    return payload
                except httpx.HTTPError as exc:
                    errors.append(str(exc))
                    delay = max(0.2, poll_interval)
                    if time.monotonic() + delay >= deadline:
                        break
                    time.sleep(delay)
                    continue
                except CapeError as exc:
                    errors.append(str(exc))
                    break
            else:
                errors.append(f"{endpoint}: report did not become available")
        raise CapeError("CAPE report was unavailable: " + "; ".join(errors))

    def analyze(
        self,
        sample: Path,
        *,
        expected_sha256: str,
        analysis_timeout: int,
        wait_timeout: int,
        poll_interval: float,
        package: str | None = None,
        machine: str | None = None,
        tags: str | None = None,
        options: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        print(
            f"[CAPE] 시작: 실행={analysis_timeout}초 · 전체대기={wait_timeout}초",
            flush=True,
        )
        task_id = self.submit_file(
            sample,
            analysis_timeout=analysis_timeout,
            package=package,
            machine=machine,
            tags=tags,
            options=options,
        )
        print(f"[CAPE] task_id={task_id} 제출 완료", flush=True)
        wait_started = time.monotonic()
        self.wait_for_report(
            task_id,
            wait_timeout=wait_timeout,
            poll_interval=poll_interval,
        )
        waited = time.monotonic() - wait_started
        remaining = max(1, int(wait_timeout - waited))
        print(
            f"[CAPE] 작업 종료 확인 · 보고서 수집 남은 대기={remaining}초",
            flush=True,
        )
        report = self.get_report(
            task_id,
            wait_timeout=remaining,
            poll_interval=poll_interval,
        )
        return normalize_cape_report(
            report,
            task_id=task_id,
            expected_sha256=expected_sha256,
        ), report
