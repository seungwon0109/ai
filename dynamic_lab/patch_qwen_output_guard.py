from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "src" / "agent_runtime" / "controller.py"


def replace_once(text: str, old: str, new: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise RuntimeError(f"Patch marker not found: {old[:100]!r}")
    return text.replace(old, new, 1)


text = PATH.read_text(encoding="utf-8")
marker = '''def _valid_stage(number: int, value: dict[str, Any]) -> bool:
    if number in {1, 2}:
        return isinstance(value.get("hypotheses"), list) and isinstance(value.get("tool_requests", []), list)
    return all(isinstance(value.get(key), list) for key in ("confirmed_facts", "inferences", "unresolved"))


'''
replacement = marker + '''def _normalize_stage(number: int, value: dict[str, Any]) -> dict[str, Any]:
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

    retained_confirmed: list[Any] = []
    downgraded: list[dict[str, Any]] = []
    for item in value.get("confirmed_facts", []):
        if not isinstance(item, dict):
            retained_confirmed.append(item)
            continue
        ids = item.get("evidence_ids") or []
        has_dynamic_support = any(str(ref).startswith("EVT-") or str(ref) in confirmed_artifacts for ref in ids)
        if has_dynamic_support:
            item["level"] = "CONFIRMED"
            retained_confirmed.append(item)
        else:
            downgraded.append({**item, "level": "INFERRED"})
    value["confirmed_facts"] = retained_confirmed
    value["inferences"] = list(value.get("inferences") or []) + downgraded
    return value


'''
text = replace_once(text, marker, replacement)

old = '''    if response.get("ok"):
        parsed = parse_fn(str(response.get("content") or ""))
        response_valid = not parsed.get("parse_error") and _valid_stage(number, parsed)
    else:
'''
new = '''    if response.get("ok"):
        parsed = parse_fn(str(response.get("content") or ""))
        if not parsed.get("parse_error"):
            parsed = _normalize_stage(number, parsed)
            parsed = _guard_evidence_references(parsed, evidence)
        response_valid = not parsed.get("parse_error") and _valid_stage(number, parsed)
    else:
'''
text = replace_once(text, old, new)
PATH.write_text(text, encoding="utf-8")
print("Patched Qwen output normalization and evidence-reference guard.")
