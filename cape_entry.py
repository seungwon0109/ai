#!/usr/bin/env python3
"""Install CAPE collection into the existing analysis pipeline without forking it."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import ai_entry
import demo_core as core
from cape_client import CapeClient, CapeError
from src.common_evidence import build_common_evidence
from src.common_evidence.attribution import build_causal_attribution


@dataclass(frozen=True)
class CapeOptions:
    url: str
    token: str | None
    analysis_timeout: int
    wait_timeout: int
    poll_interval: float
    package: str | None
    machine: str | None
    tags: str | None
    options: str | None


def parse_cape_options(argv: list[str]) -> tuple[CapeOptions, list[str]]:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--cape-url", required=True)
    parser.add_argument("--cape-token")
    parser.add_argument("--cape-analysis-timeout", type=int, default=100)
    parser.add_argument("--cape-wait-timeout", type=int, default=300)
    parser.add_argument("--cape-poll-interval", type=float, default=5.0)
    parser.add_argument("--cape-package")
    parser.add_argument("--cape-machine")
    parser.add_argument("--cape-tags")
    parser.add_argument("--cape-options")
    values, remaining = parser.parse_known_args(argv)
    if values.cape_analysis_timeout < 1 or values.cape_wait_timeout < 1:
        parser.error("CAPE timeouts must be positive")
    if values.cape_poll_interval <= 0:
        parser.error("--cape-poll-interval must be positive")
    return CapeOptions(
        url=values.cape_url,
        token=values.cape_token,
        analysis_timeout=values.cape_analysis_timeout,
        wait_timeout=values.cape_wait_timeout,
        poll_interval=values.cape_poll_interval,
        package=values.cape_package,
        machine=values.cape_machine,
        tags=values.cape_tags,
        options=values.cape_options,
    ), remaining


def _save_raw_report(
    report: dict[str, Any],
    evidence: dict[str, Any],
    args: argparse.Namespace,
) -> Path:
    output = args.output_dir.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    sample = evidence["sample"]
    stem = f"{Path(sample['name']).stem}_{sample['hashes']['sha256'][:12]}"
    path = output / f"{stem}.cape.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _hash_occurrences(value: Any, expected: str, path: str = "$", limit: int = 40) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []

    def walk(current: Any, current_path: str, inherited_pid: Any = None) -> None:
        if len(found) >= limit:
            return
        if isinstance(current, dict):
            current_pid = current.get("process_id") or current.get("pid") or inherited_pid
            for key, child in current.items():
                child_path = f"{current_path}.{key}"
                if isinstance(child, str) and expected.casefold() in child.casefold():
                    found.append({
                        "json_path": child_path,
                        "object_name": current.get("name") or current.get("process_name") or current.get("path"),
                        "process_id": current_pid,
                        "matched_value": child[:500],
                    })
                else:
                    walk(child, child_path, current_pid)
        elif isinstance(current, list):
            for index, child in enumerate(current):
                walk(child, f"{current_path}[{index}]", inherited_pid)

    walk(value, path)
    return found


def _archive_hash_correlation(
    evidence: dict[str, Any], summary: dict[str, Any], report: dict[str, Any]
) -> dict[str, Any] | None:
    archive = ((evidence.get("static_analysis") or {}).get("archive_analysis") or {})
    selected = archive.get("selected_member") if isinstance(archive, dict) else None
    if not isinstance(selected, dict):
        return None
    inner_sha256 = ((selected.get("hashes") or {}).get("sha256"))
    if not isinstance(inner_sha256, str):
        return None
    occurrences = _hash_occurrences(report, inner_sha256)
    expected_name = str(selected.get("name") or "").casefold()
    processes = ((summary.get("behavior") or {}).get("processes") or [])
    occurrence_pids = {
        str(item.get("process_id"))
        for item in occurrences
        if isinstance(item, dict) and item.get("process_id") not in (None, "")
    }
    matching_processes = [
        item for item in processes
        if isinstance(item, dict)
        and (
            str(item.get("process_id") or "") in occurrence_pids
            or str(item.get("process_name") or "").casefold() == Path(expected_name).name.casefold()
        )
    ]
    return {
        "outer_zip_sha256": ((evidence.get("sample") or {}).get("hashes") or {}).get("sha256"),
        "outer_zip_verified": summary.get("sample_sha256_verified"),
        "inner_member_name": selected.get("name"),
        "inner_exe_sha256": inner_sha256,
        "inner_hash_observed_in_cape_report": bool(occurrences),
        "inner_hash_occurrences": occurrences,
        "inner_process_name_observed": bool(matching_processes),
        "matching_processes": matching_processes[:20],
        "interpretation": "Outer ZIP and inner EXE are different files; both hashes are retained and correlated.",
    }



def _with_cape_option(options: str | None, key: str, value: str) -> str:
    prefix = key.casefold() + "="
    parts = [part.strip() for part in str(options or "").split(",") if part.strip()]
    parts = [part for part in parts if not part.casefold().startswith(prefix)]
    parts.append(f"{key}={value}")
    return ",".join(parts)

def install(options: CapeOptions) -> None:
    """Patch evidence selection and collection before the first local-AI pass."""
    original_local_pass = core.local_pass
    original_cloud_packet = core.cloud_packet
    original_selected = ai_entry.selected_local_evidence

    def selected_with_cape(evidence: dict[str, Any]) -> dict[str, Any]:
        selected = original_selected(evidence)
        selected["dynamic_analysis"] = evidence.get("dynamic_analysis")
        return selected

    def collect_once(evidence: dict[str, Any], args: argparse.Namespace) -> None:
        if "dynamic_analysis" in evidence:
            return
        safety = evidence.setdefault("safety", {})
        safety.update({
            "sample_executed_on_host": False,
            "sandbox_execution_requested": True,
            "sandbox_execution_status": "pending",
        })
        sample = Path(evidence["sample"]["path"]).resolve()
        try:
            effective_options = options.options
            if str(options.package or "").casefold() == "zip":
                selected = ((((evidence.get("static_analysis") or {}).get("archive_analysis") or {}).get("selected_member") or {}))
                selected_name = str(selected.get("name") or "").strip() if isinstance(selected, dict) else ""
                if selected_name:
                    effective_options = _with_cape_option(effective_options, "file", selected_name)
            with CapeClient(options.url, options.token) as cape:
                summary, raw_report = cape.analyze(
                    sample,
                    expected_sha256=evidence["sample"]["hashes"]["sha256"],
                    analysis_timeout=options.analysis_timeout,
                    wait_timeout=options.wait_timeout,
                    poll_interval=options.poll_interval,
                    package=options.package,
                    machine=options.machine,
                    tags=options.tags,
                    options=effective_options,
                )
            raw_path = _save_raw_report(raw_report, evidence, args)
            summary["raw_report_path"] = str(raw_path)
            correlation = _archive_hash_correlation(evidence, summary, raw_report)
            if correlation is not None:
                summary["archive_hash_correlation"] = correlation
            summary["attribution"] = build_causal_attribution(summary)
            evidence["dynamic_analysis"] = summary
            evidence["common_evidence"] = build_common_evidence(evidence)
            if summary.get("status") == "completed":
                safety["sandbox_execution_status"] = "completed"
                print(f"[CAPE] 분석 완료: task_id={summary['task_id']}")
            else:
                safety["sandbox_execution_status"] = "failed_or_timed_out"
                print(
                    f"[CAPE] 실행 실패: task_id={summary['task_id']} · "
                    f"{summary.get('error') or '분석기 오류'}"
                )
        except CapeError as exc:
            evidence["dynamic_analysis"] = {
                "provider": "cape",
                "status": "unavailable",
                "error": str(exc),
            }
            evidence["common_evidence"] = build_common_evidence(evidence)
            safety["sandbox_execution_status"] = "failed_or_timed_out"
            print(f"[CAPE] 분석 결과를 사용할 수 없음: {exc}")

    def local_pass_with_cape(
        number: int,
        evidence: dict[str, Any],
        prior: dict[str, Any] | None,
        tools: list[dict[str, Any]],
        args: argparse.Namespace,
    ) -> dict[str, Any]:
        collect_once(evidence, args)
        return original_local_pass(number, evidence, prior, tools, args)

    def cloud_packet_with_cape(evidence: dict[str, Any]) -> dict[str, Any]:
        packet = original_cloud_packet(evidence)
        dynamic = evidence.get("dynamic_analysis")
        packet["dynamic_analysis"] = dynamic
        rules = packet.setdefault("rules", {})
        rules["static_only"] = not (
            isinstance(dynamic, dict) and dynamic.get("status") == "completed"
        )
        rules["sandbox_observation_is_time_bounded"] = True
        return packet

    ai_entry.selected_local_evidence = selected_with_cape
    core.local_pass = local_pass_with_cape
    core.cloud_packet = cloud_packet_with_cape
