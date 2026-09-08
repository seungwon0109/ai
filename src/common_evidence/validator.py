from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterator

ATTACK_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.I)
FUNCTION_TOKEN_RE = re.compile(r"\b(?:FUN_[0-9A-Fa-f]+|sub_[0-9A-Fa-f]+)\b")


def _walk(value: Any, path: str = "$") -> Iterator[tuple[str, Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, f"{path}[{index}]")


def _attack_catalog(path: Path | None) -> set[str] | None:
    if not path or not path.is_file():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, dict):
        value = value.get("techniques") or value.get("ids") or []
    return {str(item).upper() for item in value if isinstance(item, str)}


def validate_ai_results(
    evidence: dict[str, Any],
    common: dict[str, Any],
    attack_catalog_path: Path | None = None,
) -> dict[str, Any]:
    valid_evidence_ids = {
        str(item.get("evidence_id"))
        for item in ((evidence.get("static_analysis") or {}).get("findings") or [])
        if isinstance(item, dict) and item.get("evidence_id")
    }
    for key in ("artifacts", "events", "claims"):
        id_key = {"artifacts": "artifact_id", "events": "event_id", "claims": "claim_id"}[key]
        valid_evidence_ids.update(
            str(item.get(id_key)) for item in common.get(key, [])
            if isinstance(item, dict) and item.get(id_key)
        )

    known_functions: set[str] = set()
    function_sources = [evidence.get("tool_results") or [], common.get("artifacts") or []]
    for _, value in _walk(function_sources):
        if isinstance(value, dict):
            for key in ("name", "function", "entry", "address"):
                candidate = value.get(key)
                if isinstance(candidate, str):
                    known_functions.add(candidate.casefold())

    catalog = _attack_catalog(attack_catalog_path)
    attributable_events = {
        str(item.get("event_id"))
        for item in common.get("events", [])
        if isinstance(item, dict)
        and item.get("event_id")
        and bool((item.get("attributes") or {}).get("included_in_conclusion"))
    }
    issues: list[dict[str, Any]] = []
    validated_attack_mappings = 0
    for index, mapping in enumerate(common.get("attack_mappings") or []):
        if not isinstance(mapping, dict):
            continue
        technique_id = str(mapping.get("technique_id") or "").upper()
        if not ATTACK_ID_RE.fullmatch(technique_id):
            mapping["catalog_validation"] = "invalid_format"
            issues.append({"severity": "error", "code": "INVALID_ATTACK_ID", "path": f"$.common_evidence.attack_mappings[{index}]", "value": technique_id})
        elif catalog is None:
            mapping["catalog_validation"] = "catalog_unavailable"
        elif technique_id in catalog:
            mapping["catalog_validation"] = "verified"
            validated_attack_mappings += 1
        else:
            mapping["catalog_validation"] = "not_found"
            issues.append({"severity": "error", "code": "UNKNOWN_ATTACK_ID", "path": f"$.common_evidence.attack_mappings[{index}]", "value": technique_id})
    checked_references = 0
    ai = evidence.get("local_ai") or {}
    analysis_payload = {
        "local_ai": ai,
        "domain_analysis": evidence.get("domain_analysis") or {},
    }
    for path, value in _walk(analysis_payload, "$.analysis"):
        if isinstance(value, dict) and isinstance(value.get("evidence_ids"), list):
            ids = [str(item) for item in value["evidence_ids"]]
            if value.get("status") in {"supported", "partial"} and not ids:
                issues.append({"severity": "error", "code": "MISSING_EVIDENCE", "path": path})
            known_ids = []
            for evidence_id in ids:
                checked_references += 1
                if evidence_id not in valid_evidence_ids:
                    issues.append({"severity": "error", "code": "UNKNOWN_EVIDENCE_ID", "path": path, "value": evidence_id})
                else:
                    known_ids.append(evidence_id)
            if "confirmed_facts" in path and known_ids:
                confirmed_artifacts = {
                    artifact_id
                    for claim in common.get("claims", [])
                    if isinstance(claim, dict) and claim.get("level") == "CONFIRMED"
                    for artifact_id in claim.get("artifact_ids", [])
                }
                if not any(item in attributable_events or item in confirmed_artifacts for item in known_ids):
                    issues.append({"severity": "error", "code": "STATIC_ONLY_CONFIRMED_CLAIM", "path": path, "evidence_ids": known_ids})
        if isinstance(value, str):
            for function in FUNCTION_TOKEN_RE.findall(value):
                if function.casefold() not in known_functions:
                    issues.append({"severity": "error", "code": "UNKNOWN_FUNCTION", "path": path, "value": function})
            for token in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", value, re.I):
                technique_id = token.upper()
                if not ATTACK_ID_RE.fullmatch(technique_id):
                    issues.append({"severity": "error", "code": "INVALID_ATTACK_ID", "path": path, "value": technique_id})
                elif catalog is not None and technique_id not in catalog:
                    issues.append({"severity": "error", "code": "UNKNOWN_ATTACK_ID", "path": path, "value": technique_id})

    dynamic = evidence.get("dynamic_analysis") or {}
    if dynamic.get("status") == "completed":
        network_events = [
            item for item in common.get("events", [])
            if isinstance(item, dict)
            and item.get("event_type") in {"DNS_QUERY", "NETWORK_CONNECT", "HTTP_REQUEST"}
            and bool((item.get("attributes") or {}).get("included_in_conclusion"))
        ]
        confirmed_text = json.dumps((ai.get("pass_3") or {}).get("confirmed_facts", []), ensure_ascii=False).casefold()
        if not network_events and any(term in confirmed_text for term in ("network", "http", "dns", "c2", "connect")):
            issues.append({"severity": "warning", "code": "DYNAMIC_NETWORK_NOT_OBSERVED", "path": "$.local_ai.pass_3.confirmed_facts"})

    user_report = ai.get("user_report") or ((ai.get("pass_3") or {}).get("user_report")) or {}
    report_control = user_report.get("_report_control") if isinstance(user_report, dict) else {}
    if isinstance(report_control, dict) and report_control.get("fallback_used"):
        issues.append({
            "severity": "warning",
            "code": "MODEL_SCHEMA_INVALID_FALLBACK_USED",
            "path": "$.local_ai.user_report._report_control",
        })

    errors = sum(item["severity"] == "error" for item in issues)
    warnings = sum(item["severity"] == "warning" for item in issues)
    return {
        "status": "passed" if errors == 0 else "rejected",
        "checked_evidence_references": checked_references,
        "valid_evidence_id_count": len(valid_evidence_ids),
        "attack_catalog": "loaded" if catalog is not None else "not_configured",
        "verified_attack_mapping_count": validated_attack_mappings,
        "error_count": errors,
        "warning_count": warnings,
        "validation_scope": [
            "evidence_id_integrity",
            "attack_catalog_integrity",
            "known_function_integrity",
            "causal_actor_attribution",
            "model_fallback_state",
        ],
        "semantic_gate": ((evidence.get("domain_analysis") or {}).get("control") or {}).get("validator", "not_run"),
        "issues": issues[:500],
    }
