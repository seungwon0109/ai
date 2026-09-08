from __future__ import annotations

import hashlib
import json
from typing import Any

from .evidence_digest import build_analysis_digest


def _render(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _preview(value: Any, limit: int = 700) -> Any:
    rendered = _render(value)
    if len(rendered) <= limit:
        return value
    return {"truncated": True, "preview": rendered[:limit]}




def _compact_event(item: dict[str, Any]) -> dict[str, Any]:
    attrs = item.get("attributes") if isinstance(item.get("attributes"), dict) else {}
    keep = {}
    for key in (
        "attribution", "included_in_conclusion", "api", "status", "normalized_from",
        "value", "command_line", "module_path", "reason",
    ):
        if key in attrs:
            keep[key] = _preview(attrs.get(key), 420)
    if "arguments" in attrs:
        keep["arguments"] = _preview(attrs.get("arguments"), 520)
    if "record" in attrs:
        keep["record"] = _preview(attrs.get("record"), 520)
    return {
        "event_id": item.get("event_id"),
        "event_type": item.get("event_type"),
        "timestamp": item.get("timestamp"),
        "actor_entity_id": item.get("actor_entity_id"),
        "target_entity_id": item.get("target_entity_id"),
        "artifact_ids": list(item.get("artifact_ids") or [])[:4],
        "attributes": keep,
    }




def _diverse_events(items: list[dict[str, Any]], limit: int = 20, per_type: int = 4) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for item in items:
        event_type = str(item.get("event_type") or "UNKNOWN")
        if counts.get(event_type, 0) >= per_type:
            continue
        output.append(item)
        counts[event_type] = counts.get(event_type, 0) + 1
        if len(output) >= limit:
            break
    if len(output) < limit:
        seen = {str(item.get("event_id")) for item in output}
        for item in items:
            if str(item.get("event_id")) in seen:
                continue
            output.append(item)
            if len(output) >= limit:
                break
    return output


class ContextBuilder:
    """Build evidence-bound JSON under a strict character budget."""

    LEVEL_ORDER = {"CONFIRMED": 0, "OBSERVED": 1, "INFERRED": 2, "UNRESOLVED": 3}
    EVENT_ORDER = {
        "PROCESS_CREATE": 0, "REMOTE_PROCESS_MUTATION": 1, "FILE_WRITE": 2,
        "FILE_DELETE": 3, "REGISTRY_SET": 4, "SERVICE_CREATE": 5,
        "DNS_QUERY": 6, "NETWORK_CONNECT": 7, "HTTP_REQUEST": 8,
        "PROCESS_START": 20,
    }

    def __init__(self, budget_chars: int = 8_000) -> None:
        self.budget_chars = max(8_000, min(int(budget_chars), 120_000))

    def _fits(self, root: dict[str, Any]) -> bool:
        return len(_render(root)) <= self.budget_chars

    def _append_until(self, target: list[Any], candidates: list[Any], root: dict[str, Any]) -> None:
        for candidate in candidates:
            target.append(candidate)
            if not self._fits(root):
                target.pop()
                break

    def build(
        self, evidence: dict[str, Any], prior: dict[str, Any] | None,
        tools: list[dict[str, Any]], state: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        common = evidence.get("common_evidence") or {}
        static = evidence.get("static_analysis") or {}
        context: dict[str, Any] = {
            "goal": "Identify the program role and verify important behavior using only cited evidence.",
            "sample": evidence.get("sample"),
            "format_detection": evidence.get("format_detection"),
            "packer_assessment": static.get("packer_assessment"),
            "analysis_digest": build_analysis_digest(evidence),
            "run_state": {
                "run_id": state.get("run_id"), "current_step": state.get("current_step"),
                "remaining_steps": max(0, int(state.get("max_steps", 3)) - int(state.get("current_step", 0))),
                "remaining_total_tool_calls": max(0, int(state.get("max_total_tool_calls", 6)) - int(state.get("total_tool_calls", 0))),
                "open_questions": (state.get("open_questions") or [])[:5],
            },
            "confirmed_events": [], "claims": [], "evidence_records": [],
            "attack_candidates": [], "latest_tool_results": [],
            "background_events": [],
            "previous_step": _preview(prior or {}, 1_200), "allowed_tools": [],
        }

        events = [item for item in common.get("events", []) if isinstance(item, dict)]
        conclusion_events = sorted(
            [item for item in events if bool((item.get("attributes") or {}).get("included_in_conclusion"))],
            key=lambda item: self.EVENT_ORDER.get(str(item.get("event_type")), 99),
        )
        background_events = sorted(
            [item for item in events if not bool((item.get("attributes") or {}).get("included_in_conclusion"))],
            key=lambda item: self.EVENT_ORDER.get(str(item.get("event_type")), 99),
        )[:40]
        self._append_until(
            context["confirmed_events"],
            [_compact_event(item) for item in _diverse_events(conclusion_events, 20, 4)],
            context,
        )

        claims = sorted(
            [item for item in common.get("claims", []) if isinstance(item, dict)],
            key=lambda item: self.LEVEL_ORDER.get(str(item.get("level")), 99),
        )[:80]
        artifact_map = {
            str(item.get("artifact_id")): item
            for item in common.get("artifacts", []) if isinstance(item, dict) and item.get("artifact_id")
        }
        added_artifacts: set[str] = set()
        for claim in claims[:30]:
            before_claims = len(context["claims"])
            before_records = len(context["evidence_records"])
            valid_artifact_ids = [
                str(artifact_id)
                for artifact_id in (claim.get("artifact_ids") or [])
                if str(artifact_id) in artifact_map
            ]
            compact_claim = dict(claim)
            compact_claim["artifact_ids"] = valid_artifact_ids
            context["claims"].append(compact_claim)
            for artifact_id in valid_artifact_ids:
                if artifact_id in added_artifacts:
                    continue
                item = artifact_map[artifact_id]
                context["evidence_records"].append({
                    "artifact_id": item.get("artifact_id"),
                    "artifact_type": item.get("artifact_type"),
                    "locator": item.get("locator"),
                    "value": _preview(item.get("value"), 900),
                })
                added_artifacts.add(artifact_id)
            if not self._fits(context):
                del context["claims"][before_claims:]
                for removed in context["evidence_records"][before_records:]:
                    added_artifacts.discard(str(removed.get("artifact_id")))
                del context["evidence_records"][before_records:]
                break

        mappings = [item for item in common.get("attack_mappings", []) if isinstance(item, dict)][:50]
        self._append_until(context["attack_candidates"], mappings[:20], context)

        calls: list[dict[str, Any]] = []
        for phase in reversed(evidence.get("tool_results", [])):
            if not isinstance(phase, dict):
                continue
            for call in reversed(phase.get("calls") or []):
                if isinstance(call, dict):
                    calls.append({
                        "phase": phase.get("phase"), "tool": call.get("tool"),
                        "arguments": call.get("arguments"),
                        "result": _preview(call.get("result"), 1_500), "error": call.get("error"),
                    })
        self._append_until(context["latest_tool_results"], calls[:8], context)

        self._append_until(context["background_events"], background_events[:12], context)

        tool_summaries = [{
            "name": item.get("name"), "description": str(item.get("description") or "")[:240],
            "input_schema": _preview(item.get("input_schema"), 500),
        } for item in tools if isinstance(item, dict) and item.get("name")]
        self._append_until(context["allowed_tools"], tool_summaries[:20], context)

        rendered = _render(context)
        stats = {
            "chars": len(rendered), "sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
            "event_count": len(context["confirmed_events"]), "claim_count": len(context["claims"]),
            "artifact_count": len(context["evidence_records"]),
            "tool_result_count": len(context["latest_tool_results"]),
            "allowed_tool_count": len(context["allowed_tools"]),
        }
        return context, stats

