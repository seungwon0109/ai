from __future__ import annotations

import json
from typing import Any, Callable

from .context_builder import ContextBuilder
from .state import RunState


DECISIONS = {
    "CONTINUE",
    "FINISH",
    "NEEDS_DYNAMIC",
    "NEEDS_SPECIAL_ANALYZER",
    "INCONCLUSIVE",
}


def _list_of_strings(value: Any, limit: int = 10) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value[:limit]]


def _valid_stage(number: int, value: dict[str, Any]) -> bool:
    if number in {1, 2}:
        return isinstance(value.get("hypotheses"), list) and isinstance(value.get("tool_requests", []), list)
    return all(isinstance(value.get(key), list) for key in ("confirmed_facts", "inferences", "unresolved"))


def _normalize_stage(number: int, value: dict[str, Any]) -> dict[str, Any]:
    """Fill omitted empty arrays so a small local model is not rejected for harmless omissions."""
    for key in (
        "hypotheses",
        "tool_requests",
        "confirmed_facts",
        "inferences",
        "rejected_hypotheses",
        "unresolved",
        "recommended_special_reviews",
    ):
        value.setdefault(key, [])
    return value


def _guard_evidence_references(value: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    """Remove fabricated IDs and prevent static-only claims from being labelled CONFIRMED."""
    common = evidence.get("common_evidence") or {}
    valid_ids = {
        str(item.get("evidence_id"))
        for item in ((evidence.get("static_analysis") or {}).get("findings") or [])
        if isinstance(item, dict) and item.get("evidence_id")
    }
    for key, id_key in (("artifacts", "artifact_id"), ("events", "event_id"), ("claims", "claim_id")):
        valid_ids.update(
            str(item.get(id_key))
            for item in common.get(key, [])
            if isinstance(item, dict) and item.get(id_key)
        )
    confirmed_artifacts = {
        str(artifact_id)
        for claim in common.get("claims", [])
        if isinstance(claim, dict) and claim.get("level") == "CONFIRMED"
        for artifact_id in claim.get("artifact_ids", [])
    }
    attributable_events = {
        str(item.get("event_id"))
        for item in common.get("events", [])
        if isinstance(item, dict)
        and item.get("event_id")
        and bool((item.get("attributes") or {}).get("included_in_conclusion"))
    }

    for key in ("hypotheses", "inferences", "confirmed_facts", "rejected_hypotheses"):
        items = value.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("evidence_ids"), list):
                continue
            item["evidence_ids"] = [str(ref) for ref in item["evidence_ids"] if str(ref) in valid_ids]
            if item.get("status") in {"supported", "partial"} and not item["evidence_ids"]:
                item["status"] = "unverified"

    report = value.get("user_report")
    if isinstance(report, dict):
        for item in report.get("behaviors") or []:
            if not isinstance(item, dict):
                continue
            ids = item.get("evidence_ids")
            if isinstance(ids, list):
                item["evidence_ids"] = [str(ref) for ref in ids if str(ref) in valid_ids]
            else:
                item["evidence_ids"] = []
            if item.get("status") == "CONFIRMED" and not any(
                str(ref) in attributable_events or str(ref) in confirmed_artifacts
                for ref in item["evidence_ids"]
            ):
                item["status"] = "OBSERVED"

    retained_confirmed: list[Any] = []
    downgraded: list[dict[str, Any]] = []
    for item in value.get("confirmed_facts", []):
        if not isinstance(item, dict):
            retained_confirmed.append(item)
            continue
        ids = item.get("evidence_ids") or []
        has_dynamic_support = any(str(ref) in attributable_events or str(ref) in confirmed_artifacts for ref in ids)
        if has_dynamic_support:
            item["level"] = "CONFIRMED"
            retained_confirmed.append(item)
        else:
            downgraded.append({**item, "level": "INFERRED"})
    value["confirmed_facts"] = retained_confirmed
    value["inferences"] = list(value.get("inferences") or []) + downgraded
    return value


def _tool_requests(
    value: Any,
    *,
    allowed: set[str],
    sample_path: str,
    state: RunState,
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    remaining = max(0, state.max_total_tool_calls - state.total_tool_calls)
    limit = min(state.max_tool_calls_per_step, remaining)
    output: list[dict[str, Any]] = []
    for item in value:
        if len(output) >= limit or not isinstance(item, dict):
            break
        tool = item.get("tool")
        arguments = item.get("arguments")
        if tool not in allowed or not isinstance(arguments, dict):
            continue
        arguments = dict(arguments)
        if "sample_path" in arguments:
            arguments["sample_path"] = sample_path
        if not state.register_tool_request(str(tool), arguments):
            continue
        output.append({
            "tool": tool,
            "arguments": arguments,
            "reason": str(item.get("reason") or "Evidence gap verification")[:400],
        })
    return output


def run_qwen_agent_step(
    number: int,
    evidence: dict[str, Any],
    prior: dict[str, Any] | None,
    tools: list[dict[str, Any]],
    args: Any,
    *,
    chat_fn: Callable[..., dict[str, Any]],
    parse_fn: Callable[[str], dict[str, Any]],
    fallback_fn: Callable[[int, dict[str, Any], dict[str, Any] | None], dict[str, Any]],
) -> dict[str, Any]:
    model = str(args.local_model or "malware-qwen:9b")
    state = RunState.load(evidence, model)
    state.max_steps = 3
    state.max_tool_calls_per_step = 2
    state.max_total_tool_calls = 6
    state.begin_step(number, evidence)

    context, stats = ContextBuilder(args.local_context_chars).build(
        evidence,
        prior,
        tools,
        state.to_dict(),
    )
    schema = {
        "stage": "triage|investigation|critical_review",
        "decision": "CONTINUE|FINISH|NEEDS_DYNAMIC|NEEDS_SPECIAL_ANALYZER|INCONCLUSIVE",
        "likely_file_role": "string",
        "hypotheses": [{
            "hypothesis_id": "H-001",
            "claim": "string",
            "status": "unverified|supported|refuted|partial",
            "evidence_ids": ["existing evidence ID only"],
            "missing_evidence": ["string"],
        }],
        "tool_requests": [{
            "tool": "exact allowed tool name",
            "arguments": {},
            "reason": "string",
        }],
        "confirmed_facts": [{"claim": "string", "level": "CONFIRMED", "evidence_ids": ["EVT/ART ID"]}],
        "inferences": [{"claim": "string", "level": "INFERRED", "evidence_ids": ["ART/E ID"]}],
        "rejected_hypotheses": [],
        "unresolved": [],
        "recommended_special_reviews": [],
    }
    task = {
        1: "Create a small set of testable hypotheses and request only the most important missing code evidence.",
        2: "Compare new tool evidence with prior hypotheses. Support, refute, or narrow them and request only indispensable evidence.",
        3: "Perform a critical final review. Separate confirmed facts, inferences, rejected hypotheses, and unresolved questions. Do not request tools.",
    }[number]
    system = (
        "You are a defensive malware-analysis controller running on Qwen3.5 9B. "
        "Use only supplied evidence IDs. Never invent hashes, functions, addresses, events, or ATT&CK IDs. "
        "OBSERVED means a literal/static artifact exists, INFERRED requires code-flow support, and CONFIRMED requires a sandbox event. "
        "Select tools only from allowed_tools, use no more than two, and return exactly one JSON object. "
        "Keep hypotheses, facts, inferences, unresolved items, and reviews to at most five entries each. "
        "Keep every claim concise. Do not output hidden reasoning or chain-of-thought."
    )
    user = (
        task
        + "\nOutput schema:\n"
        + json.dumps(schema, ensure_ascii=False, separators=(",", ":"))
        + "\nCurrent bounded context:\n"
        + json.dumps(context, ensure_ascii=False, separators=(",", ":"))
    )
    response = chat_fn(
        args.local_base_url,
        args.local_api_key or "local",
        model,
        system,
        user,
        args.ai_timeout,
    )
    parsed: dict[str, Any]
    response_valid = False
    if response.get("ok"):
        parsed = parse_fn(str(response.get("content") or ""))
        if not parsed.get("parse_error"):
            parsed = _normalize_stage(number, parsed)
            parsed = _guard_evidence_references(parsed, evidence)
        response_valid = not parsed.get("parse_error") and _valid_stage(number, parsed)
    else:
        parsed = {"model_error": response.get("error")}

    if not response_valid:
        raw_response = str(response.get("content") or "")[:4000]
        fallback = fallback_fn(number, evidence, prior)
        parsed = {
            **fallback,
            "decision": "INCONCLUSIVE" if number == 3 else "CONTINUE",
            "model_error": parsed.get("model_error") or "Qwen response failed schema validation",
            "raw_response": raw_response,
            "fallback_used": True,
        }

    decision = str(parsed.get("decision") or ("FINISH" if number == 3 else "CONTINUE")).upper()
    if decision not in DECISIONS:
        decision = "INCONCLUSIVE" if number == 3 else "CONTINUE"
    if number == 3 and decision == "CONTINUE":
        decision = "FINISH"
    if number > 1 and state.no_new_evidence_steps > 0 and decision == "CONTINUE":
        decision = "FINISH" if number == 2 else "INCONCLUSIVE"

    allowed = {str(item.get("name")) for item in tools if isinstance(item, dict) and item.get("name")}
    requests = []
    if number < 3 and decision == "CONTINUE":
        requests = _tool_requests(
            parsed.get("tool_requests"),
            allowed=allowed,
            sample_path=str((evidence.get("sample") or {}).get("path") or ""),
            state=state,
        )
    parsed["tool_requests"] = requests
    parsed["decision"] = decision
    parsed["_model"] = model
    parsed["_agent_control"] = {
        "run_id": state.run_id,
        "step": number,
        "context_chars": stats["chars"],
        "context_sha256": stats["sha256"],
        "tool_request_limit": state.max_tool_calls_per_step,
        "response_schema_valid": response_valid,
        "provider": response.get("provider"),
        "thinking_disabled": response.get("thinking_disabled", False),
    }

    unresolved = _list_of_strings(parsed.get("unresolved"))
    if not unresolved:
        unresolved = [
            str(item)
            for hypothesis in parsed.get("hypotheses", [])
            if isinstance(hypothesis, dict)
            for item in hypothesis.get("missing_evidence", [])[:3]
        ][:10]
    state.finish_step(
        number=number,
        decision=decision,
        response_valid=response_valid,
        context_chars=stats["chars"],
        context_hash=stats["sha256"],
        requested_tools=requests,
        unresolved=unresolved,
    )
    evidence["agent_run"] = state.to_dict()
    return parsed
