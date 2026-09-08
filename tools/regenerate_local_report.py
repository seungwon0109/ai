#!/usr/bin/env python3
"""Regenerate only the Qwen-authored report from previously collected evidence."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import ai_entry
import demo_core
from src.common_evidence import build_common_evidence, validate_ai_results


def main() -> int:
    parser = argparse.ArgumentParser(description="기존 증거로 로컬 Qwen 사용자 보고서만 재생성")
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--model", default=os.getenv("LOCAL_AI_MODEL") or "malware-qwen:9b")
    parser.add_argument("--base-url", default=os.getenv("LOCAL_AI_BASE_URL") or "http://127.0.0.1:11434")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--context-chars", type=int, default=40000)
    args = parser.parse_args()

    source = args.evidence.expanduser().resolve()
    evidence = json.loads(source.read_text(encoding="utf-8"))
    evidence["common_evidence"] = evidence.get("common_evidence") or build_common_evidence(evidence)
    runtime_args = SimpleNamespace(
        local_base_url=args.base_url,
        local_api_key="local",
        local_model=args.model,
        local_context_chars=args.context_chars,
        ai_timeout=args.timeout,
    )
    local_ai = evidence.setdefault("local_ai", {})
    local_ai["user_report"] = ai_entry.qwen_user_report(evidence, runtime_args)
    evidence["ai_validation"] = validate_ai_results(
        evidence,
        evidence["common_evidence"],
        ROOT / "config" / "attack_techniques.json",
    )

    stem = source.name.removesuffix(".evidence.json")
    report_path = source.with_name(stem + ".local-ai-report.md")
    evidence_path = source.with_name(stem + ".local-ai-report.evidence.json")
    evidence_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    report_path.write_text(demo_core.fallback_report(evidence), encoding="utf-8")
    print(f"로컬 AI: {args.model}")
    print(f"검증: {evidence['ai_validation']['status']}")
    print(f"보고서: {report_path}")
    print(f"증거: {evidence_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
