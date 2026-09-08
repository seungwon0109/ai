"""Deterministic, evidence-bounded malware reporting.

Every sentence is selected from the current evidence bundle. A known-family
name may only be returned by an exact hash lookup.
"""

from __future__ import annotations

import json
import re
from pathlib import PureWindowsPath
from typing import Any, Iterable


KNOWN_FAMILY_HASHES: dict[str, dict[str, str]] = {
    "386fbb57ba83864ee57a9e8a271c6dc215dc20bb1521ee85ad414f0dc67babdc": {
        "family": "TokyoCore",
        "classification": "랜섬웨어 및 정보수집 기능이 보고된 악성코드",
    },
}



ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
STATIC_ATTACK_NAMES = {
    "T1059.003": "Windows Command Shell",
    "T1106": "Native API",
    "T1129": "Shared Modules",
    "T1543.003": "Windows Service",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1622": "Debugger Evasion",
}



def _virustotal(evidence: dict[str, Any]) -> dict[str, Any]:
    value = ((evidence.get("external_intelligence") or {}).get("virustotal") or {})
    return value if isinstance(value, dict) else {}


def _local_mitre_ids(evidence: dict[str, Any]) -> set[str]:
    output: set[str] = set()
    for item in _common(evidence).get("attack_mappings") or []:
        if not isinstance(item, dict):
            continue
        value = str(item.get("technique_id") or item.get("id") or "").upper()
        if ATTACK_ID_RE.fullmatch(value):
            output.add(value)
    dynamic = _dynamic(evidence)
    rendered = json.dumps(dynamic.get("mitre_techniques") or [], ensure_ascii=False, default=str)
    output.update(match.upper() for match in ATTACK_ID_RE.findall(rendered))
    return output


def external_intelligence_summary(evidence: dict[str, Any]) -> dict[str, Any]:
    vt = _virustotal(evidence)
    if not vt:
        return {"status": "not_available"}
    stats = vt.get("last_analysis_stats") if isinstance(vt.get("last_analysis_stats"), dict) else {}
    vt_ids = {
        str(item.get("technique_id") or "").upper()
        for item in vt.get("mitre_techniques") or []
        if isinstance(item, dict) and ATTACK_ID_RE.fullmatch(str(item.get("technique_id") or "").upper())
    }
    local_ids = _local_mitre_ids(evidence)
    primary = vt.get("primary") if isinstance(vt.get("primary"), dict) else {}
    behaviour = primary.get("behaviour_summary") if isinstance(primary.get("behaviour_summary"), dict) else {}
    behaviour_data = behaviour.get("data") if isinstance(behaviour.get("data"), dict) else {}
    related = [item for item in vt.get("related_files") or [] if isinstance(item, dict)]

    def bounded_list(key: str, limit: int) -> list[Any]:
        values = behaviour_data.get(key)
        return list(values[:limit]) if isinstance(values, list) else []

    threat_names = [item for item in primary.get("threat_names") or [] if isinstance(item, dict)]
    mitre_names = {
        str(item.get("technique_id") or "").upper(): str(item.get("name") or "")
        for item in vt.get("mitre_techniques") or [] if isinstance(item, dict)
    }
    detailed_mitre: list[dict[str, Any]] = []
    seen_mitre: set[tuple[str, str]] = set()
    for item in bounded_list("mitre_attack_techniques", 40):
        if not isinstance(item, dict):
            continue
        technique_id = str(item.get("id") or "").upper()
        description = str(item.get("signature_description") or "")
        identity = (technique_id, description)
        if technique_id and identity not in seen_mitre:
            seen_mitre.add(identity)
            detailed_mitre.append({
                "technique_id": technique_id,
                "name": mitre_names.get(technique_id, ""),
                "severity": item.get("severity"),
                "description": description,
            })

    signatures = []
    for item in bounded_list("signature_matches", 20):
        if isinstance(item, dict):
            signatures.append({
                "name": item.get("name"),
                "description": item.get("description"),
                "format": item.get("format"),
                "match_data": (item.get("match_data") or [])[:5] if isinstance(item.get("match_data"), list) else [],
            })

    return {
        "status": vt.get("status"),
        "lookup_hash": vt.get("lookup_hash"),
        "found": bool(vt.get("found")),
        "stats": {
            "malicious": int(stats.get("malicious") or 0),
            "suspicious": int(stats.get("suspicious") or 0),
            "harmless": int(stats.get("harmless") or 0),
            "undetected": int(stats.get("undetected") or 0),
            "timeout": int(stats.get("timeout") or 0),
            "failure": int(stats.get("failure") or 0),
            "type_unsupported": int(stats.get("type-unsupported") or 0),
        },
        "family_candidate": vt.get("family_candidate"),
        "threat_names": threat_names[:15],
        "engine_detections": [item for item in primary.get("engine_detections") or [] if isinstance(item, dict)][:60],
        "tags": (vt.get("tags") or [])[:20],
        "meaningful_name": primary.get("meaningful_name"),
        "known_names": (primary.get("known_names") or [])[:15],
        "type_description": primary.get("type_description"),
        "reputation": primary.get("reputation"),
        "first_submission_time": primary.get("first_submission_time"),
        "last_analysis_time": primary.get("last_analysis_time"),
        "analysis_link": vt.get("analysis_link"),
        "behaviour_status": behaviour.get("status"),
        "mitre_status": primary.get("mitre_status"),
        "behavior_features": primary.get("behavior_features") or {},
        "behavior_detail": {
            "verdicts": bounded_list("verdicts", 10),
            "verdict_labels": bounded_list("verdict_labels", 10),
            "verdict_confidence": behaviour_data.get("verdict_confidence"),
            "command_executions": bounded_list("command_executions", 15),
            "processes_created": bounded_list("processes_created", 20),
            "files_written": bounded_list("files_written", 20),
            "files_opened": bounded_list("files_opened", 20),
            "registry_keys_opened": bounded_list("registry_keys_opened", 20),
            "ip_traffic": bounded_list("ip_traffic", 20),
            "domains": bounded_list("memory_pattern_domains", 20),
            "urls": bounded_list("memory_pattern_urls", 20),
            "modules_loaded": bounded_list("modules_loaded", 20),
            "mbc": bounded_list("mbc", 20),
            "signatures": signatures,
            "mitre": detailed_mitre,
            "counts": {key: len(value) for key, value in behaviour_data.items() if isinstance(value, list)},
        },
        "mitre_match": sorted(local_ids & vt_ids),
        "local_only_mitre": sorted(local_ids - vt_ids),
        "vt_only_mitre": sorted(vt_ids - local_ids),
        "related_file_count": len(related),
        "related_files": related[:10],
        "privacy_mode": vt.get("privacy_mode"),
        "file_upload_performed": bool(vt.get("file_upload_performed")),
    }


DOMAIN_TITLES = {
    "identity": "파일 식별",
    "execution": "프로세스 실행",
    "persistence_privilege": "지속성·권한",
    "encryption_recovery": "암호화·복구",
    "collection_injection": "정보수집·프로세스 조작",
    "network": "네트워크",
    "impact_defense_evasion": "영향·분석 회피",
}


def _archive_member(evidence: dict[str, Any]) -> dict[str, Any]:
    value = (((evidence.get("static_analysis") or {}).get("archive_analysis") or {}).get("selected_member") or {})
    return value if isinstance(value, dict) else {}


def _dynamic(evidence: dict[str, Any]) -> dict[str, Any]:
    value = evidence.get("dynamic_analysis") or {}
    return value if isinstance(value, dict) else {}


def _dynamic_completed(evidence: dict[str, Any]) -> bool:
    return str(_dynamic(evidence).get("status") or "").casefold() == "completed"


def _common(evidence: dict[str, Any]) -> dict[str, Any]:
    value = evidence.get("common_evidence") or {}
    return value if isinstance(value, dict) else {}


def _inner_sha256(evidence: dict[str, Any]) -> str | None:
    value = (_archive_member(evidence).get("hashes") or {}).get("sha256")
    if not value:
        value = (_dynamic(evidence).get("archive_hash_correlation") or {}).get("inner_sha256")
    return str(value).casefold() if value else None


def family_assessment(evidence: dict[str, Any]) -> dict[str, Any]:
    """Confirm a family only from local exact-hash evidence; keep VT as an external candidate."""
    inner_hash = _inner_sha256(evidence)
    known = KNOWN_FAMILY_HASHES.get(inner_hash or "")
    vt_candidate = str(_virustotal(evidence).get("family_candidate") or "").strip() or None
    if known:
        basis = [f"내부 실행 파일 SHA-256 정확 일치: {inner_hash}"]
        return {
            "family": known["family"],
            "confidence": "confirmed_hash_match",
            "basis": basis,
            "classification": known["classification"],
            "external_candidate": vt_candidate,
        }
    basis = ["현재 샘플의 정확한 해시 일치 또는 고유 패밀리 표식이 없음"]
    return {
        "family": "미확인",
        "confidence": "insufficient_evidence",
        "basis": basis,
        "classification": "행위 기반 분류만 가능",
        "external_candidate": vt_candidate,
    }


def _signature_records(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    ids_by_index: dict[int, str] = {}
    for artifact in _common(evidence).get("artifacts") or []:
        if not isinstance(artifact, dict) or artifact.get("artifact_type") != "CAPE_SIGNATURE":
            continue
        locator = artifact.get("locator") or {}
        path = str(locator.get("json_path") or "")
        try:
            index = int(path.rsplit("[", 1)[1].rstrip("]"))
        except (IndexError, ValueError):
            continue
        if artifact.get("artifact_id"):
            ids_by_index[index] = str(artifact["artifact_id"])
    output: list[dict[str, Any]] = []
    for index, item in enumerate(_dynamic(evidence).get("signatures") or []):
        if not isinstance(item, dict):
            continue
        record = dict(item)
        record["evidence_id"] = ids_by_index.get(index)
        output.append(record)
    return output


def _conclusion_signatures(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        item for item in _signature_records(evidence)
        if bool((item.get("attribution") or {}).get("included_in_conclusion"))
    ]


def _signature_names(evidence: dict[str, Any]) -> set[str]:
    return {str(item.get("name") or "").casefold() for item in _conclusion_signatures(evidence)}


def _event_records(evidence: dict[str, Any], *types: str) -> list[dict[str, Any]]:
    wanted = {value.upper() for value in types}
    return [
        item for item in _common(evidence).get("events") or []
        if isinstance(item, dict) and str(item.get("event_type") or "").upper() in wanted
    ]


def _dropped(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in _dynamic(evidence).get("dropped_files") or [] if isinstance(item, dict)]


def _dropped_names(evidence: dict[str, Any]) -> set[str]:
    output: set[str] = set()
    attributed_pids = {
        item.get("process_id")
        for item in (_dynamic(evidence).get("attribution") or {}).get("processes") or []
        if isinstance(item, dict) and item.get("included_in_conclusion")
    }
    for item in _dropped(evidence):
        if item.get("runtime_staging") or item.get("pid") not in attributed_pids:
            continue
        values = item.get("name") if isinstance(item.get("name"), list) else [item.get("name")]
        for value in values:
            if value:
                output.add(str(value).casefold())
                output.add(PureWindowsPath(str(value)).name.casefold())
    return output


def _static_capability_records(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for artifact in _common(evidence).get("artifacts") or []:
        if not isinstance(artifact, dict) or artifact.get("artifact_type") != "CAPA_RULE_MATCH":
            continue
        locator = artifact.get("locator") or {}
        value = artifact.get("value") if isinstance(artifact.get("value"), dict) else {}
        meta = value.get("meta") if isinstance(value.get("meta"), dict) else {}
        path = str(locator.get("json_path") or "")
        match = re.search(r"capa\.rules\[(.+)\]$", path)
        rule_name = str(meta.get("name") or "")
        if not rule_name and match:
            rule_name = match.group(1).strip().strip("'\"")
        trusted_fields = {
            "rule_name": rule_name,
            "namespace": meta.get("namespace"),
            "mbc": meta.get("mbc"),
            "attack": meta.get("attack"),
        }
        output.append({
            "evidence_id": str(artifact.get("artifact_id") or ""),
            "name": rule_name or path,
            "trusted_text": json.dumps(trusted_fields, ensure_ascii=False, default=str).casefold(),
            "attack_ids": [match.upper() for match in ATTACK_ID_RE.findall(json.dumps(meta.get("attack") or [], ensure_ascii=False, default=str))],
        })
    return output

def _strings(evidence: dict[str, Any]) -> list[str]:
    values = _archive_member(evidence).get("strings")
    if not isinstance(values, list):
        values = (evidence.get("static_analysis") or {}).get("strings") or []
    return [str(value) for value in values if isinstance(value, str)]


def _network_observed(evidence: dict[str, Any]) -> bool:
    return any(
        bool((item.get("attributes") or {}).get("included_in_conclusion"))
        for item in _event_records(evidence, "DNS_QUERY", "NETWORK_CONNECT", "HTTP_REQUEST")
    )


def _direct_encryption(evidence: dict[str, Any]) -> bool:
    return any(
        marker in name
        for name in _signature_names(evidence)
        for marker in ("encrypts_files", "file_encryption", "ransomware_files", "encrypted_files")
    )


def _static_crypto(evidence: dict[str, Any]) -> tuple[bool, list[str], list[str]]:
    ids: list[str] = []
    labels: list[str] = []
    crypto_tokens = ("encrypt", "cipher", "rc4", "aes", "chacha", "cryptographic", "bcryptencrypt", "cryptencrypt")
    for item in _static_capability_records(evidence):
        text = str(item.get("trusted_text") or "")
        if any(token in text for token in crypto_tokens):
            if item["evidence_id"]:
                ids.append(item["evidence_id"])
            labels.append(str(item.get("name") or "crypto capability"))
    for finding in _archive_member(evidence).get("findings") or []:
        if not isinstance(finding, dict) or str(finding.get("category") or "") != "crypto_or_file_encryption":
            continue
        matched = [str(value) for value in finding.get("matched") or [] if str(value).strip()]
        if finding.get("evidence_id"):
            ids.append(str(finding["evidence_id"]))
        labels.append("내부 PE 암호화 후보: " + ", ".join(matched[:8]))
    return bool(labels), list(dict.fromkeys(ids))[:8], list(dict.fromkeys(labels))[:8]

def _static_file_encryption(evidence: dict[str, Any]) -> tuple[bool, list[str], list[str]]:
    """Infer file encryption only from trusted capa metadata/rule names."""
    ids: list[str] = []
    labels: list[str] = []
    explicit_markers = (
        "encrypt file", "encrypts file", "file encryption", "encrypt files",
        "encrypted file", "data encrypted for impact", "ransomware",
    )
    for item in _static_capability_records(evidence):
        text = str(item.get("trusted_text") or "")
        explicit = any(marker in text for marker in explicit_markers) or "T1486" in set(item.get("attack_ids") or [])
        if not explicit:
            continue
        if item["evidence_id"]:
            ids.append(item["evidence_id"])
        labels.append(str(item.get("name") or "file encryption capability"))
    return bool(labels), list(dict.fromkeys(ids))[:8], list(dict.fromkeys(labels))[:8]


FEATURE_LABELS = {
    "file_write": "파일 쓰기",
    "file_delete": "파일 삭제",
    "process_create": "프로세스 생성",
    "process_injection": "프로세스 인젝션",
    "service_create": "서비스 생성",
    "registry_modification": "레지스트리 변경",
    "network_communication": "네트워크 통신",
    "cryptographic_activity": "암호화 관련 동작",
    "file_encryption": "파일 암호화",
}


def _local_event_feature(evidence: dict[str, Any], *event_types: str) -> tuple[bool, list[str]]:
    ids = [
        str(item.get("event_id"))
        for item in _event_records(evidence, *event_types)
        if item.get("event_id") and bool((item.get("attributes") or {}).get("included_in_conclusion"))
    ]
    return bool(ids), ids[:8]


def _static_behavior_candidate(evidence: dict[str, Any], capability: str) -> tuple[bool, list[str]]:
    capa_tokens = {
        "file_write": ("write file", "writes file"),
        "process_create": ("create process",),
    }
    ids: list[str] = []
    for item in _static_capability_records(evidence):
        text = str(item.get("trusted_text") or "")
        if any(token in text for token in capa_tokens.get(capability, ())):
            if item.get("evidence_id"):
                ids.append(str(item["evidence_id"]))
    finding_rules = {
        "process_create": ("process_execution", ("createprocess", "cmd.exe")),
        "service_create": ("persistence", ("createservice", "startservice")),
        "registry_modification": ("persistence", ("regsetvalue", "startup")),
        "network_communication": ("url", ("http://", "https://")),
    }
    category, tokens = finding_rules.get(capability, ("", ()))
    for finding in _archive_member(evidence).get("findings") or []:
        if not isinstance(finding, dict) or str(finding.get("category") or "") != category:
            continue
        matched = " ".join(str(value).casefold() for value in finding.get("matched") or [])
        if any(token in matched for token in tokens):
            if finding.get("evidence_id"):
                ids.append(str(finding["evidence_id"]))
    return bool(ids), list(dict.fromkeys(ids))[:8]


def _local_behavior_features(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    dynamic_completed = _dynamic_completed(evidence)
    event_map = {
        "file_write": ("FILE_WRITE",),
        "file_delete": ("FILE_DELETE",),
        "process_create": ("PROCESS_CREATE",),
        "service_create": ("SERVICE_CREATE",),
        "registry_modification": ("REGISTRY_SET", "REGISTRY_DELETE"),
        "network_communication": ("DNS_QUERY", "NETWORK_CONNECT", "HTTP_REQUEST"),
    }
    for key, event_types in event_map.items():
        if not dynamic_completed:
            inferred, ids = _static_behavior_candidate(evidence, key)
            output[key] = {
                "status": "inferred" if inferred else "unavailable",
                "evidence_ids": ids,
            }
            continue
        observed, ids = _local_event_feature(evidence, *event_types)
        if observed:
            output[key] = {"status": "observed", "evidence_ids": ids}
        else:
            inferred, static_ids = _static_behavior_candidate(evidence, key)
            output[key] = {
                "status": "inferred" if inferred else "not_observed",
                "evidence_ids": static_ids,
            }

    injection_ids = [
        str(item.get("evidence_id"))
        for item in _conclusion_signatures(evidence)
        if item.get("evidence_id")
        and any(token in str(item.get("name") or "").casefold() for token in ("inject", "suspended_process", "resumethread"))
    ]
    mutation_observed, mutation_ids = _local_event_feature(evidence, "REMOTE_PROCESS_MUTATION")
    injection_ids.extend(mutation_ids)
    output["process_injection"] = {
        "status": (
            "observed" if dynamic_completed and (injection_ids or mutation_observed)
            else "not_observed" if dynamic_completed
            else "unavailable"
        ),
        "evidence_ids": list(dict.fromkeys(injection_ids))[:8],
    }

    direct_encryption = _direct_encryption(evidence) if dynamic_completed else False
    static_crypto, static_ids, _ = _static_crypto(evidence)
    static_file_encryption, file_crypto_ids, _ = _static_file_encryption(evidence)
    output["cryptographic_activity"] = {
        "status": (
            "observed" if direct_encryption
            else "inferred" if static_crypto
            else "not_observed" if dynamic_completed
            else "unavailable"
        ),
        "evidence_ids": static_ids[:8],
    }
    output["file_encryption"] = {
        "status": (
            "observed" if direct_encryption
            else "inferred" if static_file_encryption
            else "not_observed" if dynamic_completed
            else "unavailable"
        ),
        "evidence_ids": file_crypto_ids[:8],
    }
    return output


def _comparison_result(local_status: str, vt_status: str) -> str:
    if local_status == "unavailable":
        if vt_status in {"observed", "reported"}:
            return "VT_ONLY_LOCAL_UNAVAILABLE"
        return "LOCAL_UNAVAILABLE" if vt_status == "not_observed" else "BOTH_UNAVAILABLE"
    if vt_status == "unavailable":
        return "VT_UNAVAILABLE"
    if local_status == "observed" and vt_status == "observed":
        return "MATCH"
    if vt_status == "reported":
        if local_status in {"observed", "inferred"}:
            return "EXTERNAL_SUPPORT"
        if local_status == "not_observed":
            return "VT_REPORTED_ONLY"
    if local_status == "inferred" and vt_status == "observed":
        return "VT_SUPPORTS_LOCAL_INFERENCE"
    if local_status == "observed" and vt_status == "not_observed":
        return "LOCAL_ONLY"
    if local_status == "inferred" and vt_status == "not_observed":
        return "LOCAL_INFERENCE_ONLY"
    if local_status == "not_observed" and vt_status == "observed":
        return "VT_ONLY"
    if local_status == "not_observed" and vt_status == "not_observed":
        return "BOTH_NOT_OBSERVED"
    return "PARTIAL"

def build_external_cross_validation(evidence: dict[str, Any]) -> dict[str, Any]:
    """Compare frozen local evidence with VT without upgrading reported MITRE to observed behavior."""
    external = external_intelligence_summary(evidence)
    local_features = _local_behavior_features(evidence)
    vt_features = external.get("behavior_features") if isinstance(external.get("behavior_features"), dict) else {}
    behaviour_available = external.get("behaviour_status") == "available"
    mitre_available = external.get("mitre_status") == "available"

    items: list[dict[str, Any]] = []
    for key, label in FEATURE_LABELS.items():
        local = local_features.get(key) or {"status": "not_observed", "evidence_ids": []}
        vt_item = vt_features.get(key) if isinstance(vt_features.get(key), dict) else {}
        if behaviour_available and bool(vt_item.get("observed")):
            vt_status = "observed"
        elif key == "file_encryption" and mitre_available and bool(vt_item.get("reported")):
            vt_status = "reported"
        elif behaviour_available:
            vt_status = "not_observed"
        else:
            vt_status = "unavailable"
        items.append({
            "capability": key, "label": label,
            "local": local.get("status", "not_observed"), "virustotal": vt_status,
            "result": _comparison_result(str(local.get("status") or "not_observed"), vt_status),
            "local_evidence_ids": local.get("evidence_ids") or [],
            "vt_examples": (vt_item.get("examples") or [])[:5],
            "vt_count": int(vt_item.get("count") or 0),
        })

    counts: dict[str, int] = {}
    for item in items:
        counts[item["result"]] = counts.get(item["result"], 0) + 1
    return {
        "source_boundary": "local_results_frozen_before_external_comparison",
        "local_result_rewritten_by_vt": False,
        "virustotal_status": external.get("status"),
        "behaviour_status": external.get("behaviour_status"),
        "mitre_status": external.get("mitre_status"),
        "items": items, "result_counts": counts,
        "mitre": {
            "match": external.get("mitre_match") or [],
            "local_only": external.get("local_only_mitre") or [],
            "vt_only": external.get("vt_only_mitre") or [],
        },
    }

def build_attack_candidate_table(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    """Build an evidence-derived ATT&CK candidate comparison table."""
    grouped: dict[str, dict[str, Any]] = {}
    for item in _common(evidence).get("attack_mappings") or []:
        if not isinstance(item, dict):
            continue
        technique = str(item.get("technique_id") or "").upper()
        if not ATTACK_ID_RE.fullmatch(technique):
            continue
        row = grouped.setdefault(technique, {"technique_id": technique, "local_sources": set(), "local": None})
        source = str(item.get("source") or "unknown").casefold()
        row["local_sources"].add(source)
        if source == "cape":
            row["local"] = "DYNAMIC_OBSERVED"
        elif row.get("local") != "DYNAMIC_OBSERVED":
            row["local"] = "STATIC_INFERRED"

    vt = _virustotal(evidence)
    primary = vt.get("primary") if isinstance(vt.get("primary"), dict) else {}
    vt_available = str(primary.get("mitre_status") or "") == "available"
    vt_rows = {
        str(item.get("technique_id") or "").upper(): item
        for item in vt.get("mitre_techniques") or []
        if isinstance(item, dict) and ATTACK_ID_RE.fullmatch(str(item.get("technique_id") or "").upper())
    }
    for technique, item in vt_rows.items():
        grouped.setdefault(technique, {"technique_id": technique, "local_sources": set(), "local": None})["vt_name"] = item.get("name")

    rows: list[dict[str, Any]] = []
    for technique in sorted(grouped):
        row = grouped[technique]
        local = row.get("local") or "NOT_MAPPED"
        vt_status = "REPORTED" if technique in vt_rows else ("NOT_REPORTED" if vt_available else "UNAVAILABLE")
        if local == "DYNAMIC_OBSERVED" and vt_status == "REPORTED":
            verdict, confidence = "CORROBORATED", "높음"
        elif local == "STATIC_INFERRED" and vt_status == "REPORTED":
            verdict, confidence = "EXTERNAL_SUPPORT", "중간"
        elif local == "DYNAMIC_OBSERVED":
            verdict, confidence = "LOCAL_OBSERVED_ONLY", "중간"
        elif local == "STATIC_INFERRED":
            verdict, confidence = "LOCAL_INFERRED_ONLY", "중간"
        else:
            verdict, confidence = "VT_ONLY", "외부 근거"
        rows.append({
            "technique_id": technique, "name": row.get("vt_name") or STATIC_ATTACK_NAMES.get(technique, ""),
            "local": local, "local_sources": sorted(row.get("local_sources") or []),
            "virustotal": vt_status, "result": verdict, "confidence": confidence,
        })
    return rows[:80]


def _valid_evidence_ids(evidence: dict[str, Any]) -> set[str]:
    output = {
        str(item.get("evidence_id"))
        for item in ((evidence.get("static_analysis") or {}).get("findings") or [])
        if isinstance(item, dict) and item.get("evidence_id")
    }
    for key, id_key in (("artifacts", "artifact_id"), ("events", "event_id"), ("claims", "claim_id")):
        output.update(
            str(item.get(id_key)) for item in _common(evidence).get(key) or []
            if isinstance(item, dict) and item.get(id_key)
        )
    return output


def _claim_behaviors(evidence: dict[str, Any], claims: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    valid_ids = _valid_evidence_ids(evidence)
    status_rank = {"UNRESOLVED": 0, "INFERRED": 1, "OBSERVED": 2, "CONFIRMED": 3}
    grouped: dict[str, dict[str, Any]] = {}
    for claim in claims:
        if not isinstance(claim, dict):
            continue
        text = str(claim.get("claim") or claim.get("statement") or "").strip()
        ids = [str(value) for value in claim.get("evidence_ids") or [] if str(value) in valid_ids]
        if not text or not ids:
            continue
        status = str(claim.get("status") or "OBSERVED").upper()
        if status not in status_rank:
            status = "OBSERVED"
        title = DOMAIN_TITLES.get(str(claim.get("domain") or ""), "검증된 행위")
        current = grouped.get(title)
        if current is None:
            grouped[title] = {
                "title": title,
                "status": status,
                "description_parts": [text],
                "evidence_ids": list(dict.fromkeys(ids))[:8],
            }
            continue
        if status_rank[status] > status_rank[str(current.get("status") or "UNRESOLVED")]:
            current["status"] = status
        if text not in current["description_parts"]:
            current["description_parts"].append(text)
        current["evidence_ids"] = list(dict.fromkeys([*current["evidence_ids"], *ids]))[:8]

    output: list[dict[str, Any]] = []
    for item in grouped.values():
        parts = item.pop("description_parts")
        item["description"] = " / ".join(parts[:3])
        output.append(item)
        if len(output) >= 12:
            break
    return output


def _deterministic_behaviors(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    signature_groups = (
        ("분석 환경 확인", ("antivm", "antidebug", "antisandbox"), "샌드박스에서 분석 환경 또는 디버깅 환경을 확인하는 행위가 관찰되었습니다."),
        ("프로세스 인젝션·조작", ("creates_suspended_process", "resumethread_remote_process", "injection"), "중지 상태 프로세스 생성 또는 다른 프로세스 스레드 재개 정황이 관찰되었습니다."),
        ("쿠키 파일 접근", ("infostealer_cookies",), "쿠키가 포함된 파일에 접근한 행위가 관찰되었습니다. 외부 전송 여부는 별도 증거가 필요합니다."),
        ("드라이브·볼륨 탐색", ("mountpoint", "volume_discovery"), "연결된 드라이브와 볼륨 정보를 조회한 행위가 관찰되었습니다."),
        ("시스템 정보 확인", ("hardware_id", "recon_fingerprint"), "하드웨어 또는 시스템 식별 정보를 조회한 행위가 관찰되었습니다."),
        ("권한 상태 확인", ("privilege_elevation_check", "per_file_acl_token_check"), "토큰 또는 파일 접근 권한을 확인한 행위가 관찰되었습니다. 권한 상승 성공을 의미하지는 않습니다."),
    )
    records = _conclusion_signatures(evidence)
    for title, tokens, description in signature_groups:
        matched = [
            item for item in records
            if any(token in str(item.get("name") or "").casefold() for token in tokens)
        ]
        ids = [
            str(item.get("evidence_id")) for item in matched if item.get("evidence_id")
        ]
        if matched:
            output.append({"title": title, "status": "OBSERVED", "description": description, "evidence_ids": ids[:8]})

    for event_type, title, description in (
        ("PROCESS_START", "프로세스 시작", "샌드박스 실행 중 프로세스 시작 이벤트가 기록되었습니다. PID와 PPID는 별도 프로세스 표에서 확인해야 합니다."),
        ("SERVICE_CREATE", "서비스 생성", "샌드박스 실행 중 서비스 생성 이벤트가 기록되었습니다."),
        ("FILE_DELETE", "파일 삭제", "샌드박스 실행 중 파일 삭제 이벤트가 기록되었습니다."),
        ("HTTP_REQUEST", "HTTP 통신", "샌드박스 실행 중 HTTP 요청 이벤트가 기록되었습니다."),
        ("DNS_QUERY", "DNS 질의", "샌드박스 실행 중 DNS 질의 이벤트가 기록되었습니다."),
    ):
        ids = [
            str(item.get("event_id")) for item in _event_records(evidence, event_type)
            if item.get("event_id")
            and bool((item.get("attributes") or {}).get("included_in_conclusion"))
        ]
        if ids:
            output.append({"title": title, "status": "CONFIRMED", "description": description, "evidence_ids": ids[:8]})

    static_crypto, crypto_ids, labels = _static_crypto(evidence)
    if static_crypto:
        output.append({
            "title": "암호화 기능(정적)",
            "status": "INFERRED",
            "description": f"정적 분석에서 암호화 관련 기능이 탐지되었습니다: {', '.join(labels[:3])}. 실제 파일 암호화 실행을 의미하지는 않습니다.",
            "evidence_ids": crypto_ids,
        })
    return output[:12]


def _iocs(evidence: dict[str, Any]) -> list[dict[str, str]]:
    output: list[dict[str, str]] = []
    sample = evidence.get("sample") or {}
    outer = (sample.get("hashes") or {}).get("sha256")
    if outer:
        output.append({"type": "입력 SHA-256", "value": str(outer)})
    inner = _inner_sha256(evidence)
    if inner and inner != str(outer or "").casefold():
        output.append({"type": "내부 파일 SHA-256", "value": inner})
    network = _dynamic(evidence).get("network") or {}
    for key, label in (("domains", "도메인"), ("hosts", "호스트"), ("dns", "DNS"), ("http", "HTTP")):
        for item in network.get(key) or []:
            rendered = json.dumps(item, ensure_ascii=False, default=str) if isinstance(item, (dict, list)) else str(item)
            record = {"type": label, "value": rendered[:500]}
            if rendered and record not in output:
                output.append(record)
            if len(output) >= 20:
                return output
    return output


def _build_local_narrative(
    evidence: dict[str, Any],
    *,
    behaviors: list[dict[str, Any]],
    risk: str,
    classification: str,
    network_observed: bool,
    direct_encryption: bool,
    static_crypto: bool,
) -> dict[str, Any]:
    member = _archive_member(evidence)
    dynamic = _dynamic(evidence)
    attribution = dynamic.get("attribution") if isinstance(dynamic.get("attribution"), dict) else {}
    processes = [
        item for item in attribution.get("processes") or []
        if isinstance(item, dict) and item.get("included_in_conclusion")
    ]
    signatures = _conclusion_signatures(evidence)
    process_names = [
        f"{item.get('process_name') or '프로세스'}(PID {item.get('process_id')}, {item.get('level')})"
        for item in processes
    ]
    signature_names = [str(item.get("name") or "") for item in signatures if item.get("name")]
    findings = [item for item in member.get("findings") or [] if isinstance(item, dict)]
    finding_text = [
        f"{item.get('category')}: {', '.join(map(str, (item.get('matched') or [])[:6]))}"
        for item in findings[:8]
    ]
    pe = member.get("pe_headers") if isinstance(member.get("pe_headers"), dict) else {}
    pefile = member.get("pefile") if isinstance(member.get("pefile"), dict) else {}
    capa_rules = (evidence.get("capa") or {}).get("rules")
    capa_count = len(capa_rules) if isinstance(capa_rules, dict) else 0
    try:
        is_dll = bool(int(str(pe.get("characteristics") or "0"), 0) & 0x2000)
    except ValueError:
        is_dll = False
    command_lines = []
    for item in ((dynamic.get("behavior") or {}).get("process_tree") or []):
        if not isinstance(item, dict):
            continue
        command = ((item.get("environ") or {}).get("CommandLine")) if isinstance(item.get("environ"), dict) else None
        if command:
            command_lines.append(str(command))

    identity = (
        f"입력 ZIP에서 선택된 내부 파일 '{member.get('name') or '미확인'}'은 "
        f"{pe.get('format') or 'PE'} / machine {pe.get('machine') or '미확인'} 형식이며 "
        f"{'DLL 플래그가 설정된 64비트 PE' if is_dll else 'PE 실행 파일'}로 식별되었습니다. "
        f"Import는 {len(pefile.get('imports') or [])}개 모듈, "
        f"{sum(len(item.get('symbols') or []) for item in pefile.get('imports') or [] if isinstance(item, dict))}개 심볼이고 "
        f"capa 규칙 {capa_count}개가 일치했습니다."
    )
    execution = (
        f"CAPE Task {dynamic.get('task_id') or '-'}는 상태 '{dynamic.get('status') or '미확인'}'로 종료됐습니다. "
        f"샘플 귀속 프로세스는 {', '.join(process_names) if process_names else '확정되지 않았습니다'}."
    )
    if command_lines:
        execution += f" 확인된 실행 명령은 '{command_lines[0]}'입니다."
    if dynamic.get("analysis_timed_out"):
        execution += " 설정된 분석 시간이 만료되어 종료됐으므로 장기 지연 행위나 후속 단계는 관찰 범위 밖일 수 있습니다."

    static_paragraph = (
        "정적 분석은 다음 기능 후보를 확인했습니다: "
        + ("; ".join(finding_text) if finding_text else "명시적 기능 후보 없음")
        + ". 이 항목들은 코드·문자열·Import에 존재한다는 의미이며 실제 호출 성공을 뜻하지 않습니다."
    )
    dynamic_paragraph = (
        f"샘플에 귀속된 CAPE 시그니처는 {', '.join(signature_names) if signature_names else '없습니다'}. "
        f"동적 네트워크 통신은 {'관찰됐습니다' if network_observed else '관찰되지 않았고'}, "
        f"실제 사용자 파일 암호화는 {'관찰됐습니다' if direct_encryption else '관찰되지 않았습니다'}. "
        f"Dropped 파일은 {len(dynamic.get('dropped_files') or [])}개입니다."
    )
    interpretation = (
        f"로컬 증거만으로는 이 파일을 '{classification}'으로 분류하며 위험도는 '{risk}'입니다. "
        "이 평가는 제한된 샌드박스 실행에서 직접 귀속된 행위만 반영한 로컬 판정입니다. "
        "미관찰 항목은 기능 부재나 안전을 의미하지 않으며, 외부 평판은 이 단계의 판정에 사용하지 않았습니다."
    )

    positive = []
    if processes:
        positive.append(f"내부 DLL이 rundll32 계열 프로세스에 직접 귀속됨: {', '.join(process_names)}")
    if signature_names:
        positive.append(f"샘플 귀속 동적 시그니처 {len(signature_names)}개: {', '.join(signature_names)}")
    if static_crypto:
        positive.append("정적 분석에서 암호화 관련 API·문자열 후보가 확인됨")
    if findings:
        positive.append(f"실행·지속성·분석 회피 등을 포함한 정적 후보 {len(findings)}개가 기록됨")
    negative = [
        "로컬 실행에서 외부 네트워크 이벤트가 관찰되지 않음" if not network_observed else "로컬 실행에서 네트워크 이벤트가 관찰됨",
        "사용자 파일 암호화 완료와 랜섬노트 생성은 확인되지 않음" if not direct_encryption else "파일 암호화 관련 동적 증거가 확인됨",
    ]
    if dynamic.get("analysis_timed_out"):
        negative.append("분석 시간 만료로 지연 실행·후속 페이로드 단계의 관찰이 제한됨")

    return {
        "analysis_narrative": [identity, execution, static_paragraph, dynamic_paragraph, interpretation],
        "risk_rationale": [*positive, *negative],
        "local_conclusion": interpretation,
        "execution_command_lines": command_lines[:5],
        "dynamic_status": dynamic.get("status"),
        "analysis_timed_out": bool(dynamic.get("analysis_timed_out")),
        "attributed_process_count": len(processes),
        "attributed_signature_count": len(signatures),
    }


def build_report_data(
    evidence: dict[str, Any],
    *,
    verified_claims: Iterable[dict[str, Any]] | None = None,
    unresolved: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Create the report schema from current evidence only."""
    family = family_assessment(evidence)
    dynamic = _dynamic(evidence)
    signatures = _conclusion_signatures(evidence)
    direct_encryption = _direct_encryption(evidence)
    static_crypto, _, crypto_labels = _static_crypto(evidence)
    network_observed = _network_observed(evidence)
    dropped_names = _dropped_names(evidence)

    if verified_claims is None:
        domain_analysis = evidence.get("domain_analysis") or {}
        control = domain_analysis.get("control") or {}
        trusted = control.get("validator") == "deterministic_semantic_gate_v3"
        claims = list(domain_analysis.get("verified_claims") or []) if trusted else []
    else:
        claims = list(verified_claims)
    behaviors = _claim_behaviors(evidence, claims)
    existing_titles = {item["title"] for item in behaviors}
    for item in _deterministic_behaviors(evidence):
        if item["title"] not in existing_titles:
            behaviors.append(item)
            existing_titles.add(item["title"])
        if len(behaviors) >= 12:
            break

    severity_three = sum(int(item.get("severity") or 0) >= 3 for item in signatures)
    attributed_deletes = [
        item for item in _event_records(evidence, "FILE_DELETE")
        if bool((item.get("attributes") or {}).get("included_in_conclusion"))
    ]
    injection_observed, _ = _local_event_feature(evidence, "REMOTE_PROCESS_MUTATION")
    service_observed, _ = _local_event_feature(evidence, "SERVICE_CREATE")
    risk_score = 0
    risk_score += 5 if direct_encryption else 0
    risk_score += 4 if injection_observed else 0
    risk_score += 3 if service_observed else 0
    risk_score += 2 if network_observed else 0
    if len(attributed_deletes) >= 20:
        risk_score += 4
    elif len(attributed_deletes) >= 5:
        risk_score += 2
    elif attributed_deletes:
        risk_score += 1
    risk_score += 3 if severity_three >= 2 else (1 if severity_three == 1 else 0)
    risk_score += 2 if len(signatures) >= 5 else (1 if signatures else 0)
    risk_score += 1 if static_crypto else 0
    dynamic_status = str(dynamic.get("status") or "").casefold()
    if risk_score >= 7:
        risk = "매우 높음"
    elif risk_score >= 4:
        risk = "높음"
    elif risk_score >= 2:
        risk = "중간"
    elif dynamic_status != "completed":
        risk = "판정 불가"
    else:
        risk = "낮음"

    if family["confidence"] == "confirmed_hash_match":
        classification = family["classification"]
    elif direct_encryption:
        classification = "파일 암호화 행위가 동적으로 관찰된 악성 의심 프로그램"
    elif len(signatures) >= 2:
        classification = "분석 회피·권한 확인 행위가 관찰된 다기능 의심 DLL"
    elif len(signatures) == 1:
        classification = "의심 행위가 관찰된 미분류 프로그램"
    elif static_crypto:
        classification = "암호화 관련 정적 기능을 포함한 미분류 프로그램"
    else:
        classification = "현재 증거만으로 역할 미확인"

    if direct_encryption:
        encryption_status = "확인됨: 샌드박스에서 파일 암호화 관련 동적 시그니처가 관찰됨"
    elif static_crypto:
        encryption_status = "코드에 존재: 정적 기능은 탐지됐지만 실제 사용자 파일 암호화는 미확인"
    else:
        encryption_status = "미확인: 현재 증거에서 파일 암호화 기능 또는 실행을 확인하지 못함"

    crypto_text = " ".join(crypto_labels).casefold()
    if "rc4" in crypto_text:
        method = "정적 분석에서 RC4 관련 기능이 탐지됨. 실행 여부와 파일 암호화 사용 여부는 미확인"
    elif static_crypto:
        method = "정적 분석에서 암호화 관련 기능이 탐지됐으나 정확한 알고리즘과 실행 경로는 미확인"
    else:
        method = "미확인"

    key_names = sorted(name for name in dropped_names if "key" in name and len(name) <= 120)
    key_handling = (
        "동적 분석에서 다음 키 후보 파일명이 관찰됨: " + ", ".join(key_names[:5]) + ". 실제 암호화 키인지는 미확인"
        if key_names else "미확인: 키 생성·저장·전송 증거 없음"
    )
    all_strings = "\n".join(_strings(evidence)).casefold()
    ransom_message = (
        "코드 문자열에서 랜섬 요구 또는 복호화 안내 문구가 발견됨. 실제 화면 표시 여부는 미확인"
        if any(token in all_strings for token in ("your files have been encrypted", "ransom", "decrypt key"))
        else "미확인: 랜섬노트 또는 안내 화면 증거 없음"
    )

    observed_titles = ", ".join(dict.fromkeys(item["title"] for item in behaviors[:4]))
    if not observed_titles:
        observed_titles = (
            "뚜렷한 악성 행위 없음"
            if dynamic_status == "completed"
            else "동적 분석 실패로 실행 행위 판정 불가"
        )
    if dynamic.get("status") == "completed":
        network_sentence = "외부 네트워크 기록이 관찰되었습니다." if network_observed else "외부 네트워크 통신은 이번 CAPE 실행에서 관찰되지 않았습니다."
        encryption_sentence = " 실제 파일 암호화 행위가 관찰되었습니다." if direct_encryption else " 실제 사용자 파일 암호화 완료는 이번 CAPE 실행에서 확인되지 않았습니다."
    else:
        network_sentence = "CAPE 동적 분석 결과를 사용할 수 없어 외부 네트워크 통신 여부를 판단할 수 없습니다."
        encryption_sentence = " 실제 사용자 파일 암호화 완료 여부도 동적으로 판단할 수 없습니다."
    summary = (
        f"현재 샘플에서는 {observed_titles} 관련 증거가 확인되었습니다. 위험도는 {risk}으로 평가합니다. "
        + network_sentence
        + encryption_sentence
    )

    unknown_values = [str(item) for item in (unresolved or []) if str(item).strip()]
    if not direct_encryption:
        unknown_values.append("실제 사용자 파일 암호화 수행 여부")
    if dynamic.get("status") != "completed":
        unknown_values.append("CAPE 동적 분석 결과가 없어 실제 실행 행위 검증이 제한됨")
    elif not network_observed:
        unknown_values.append("외부 C2 통신 또는 정보 유출 여부")
    if family["family"] == "미확인":
        unknown_values.append("정확한 악성코드 패밀리")

    narrative = _build_local_narrative(
        evidence,
        behaviors=behaviors,
        risk=risk,
        classification=classification,
        network_observed=network_observed,
        direct_encryption=direct_encryption,
        static_crypto=static_crypto,
    )
    return {
        "plain_summary": summary,
        **narrative,
        "family": {
            "name": family["family"],
            "confidence": "높음" if family["confidence"] == "confirmed_hash_match" else "낮음",
            "basis": family["basis"],
        },
        "classification": classification,
        "risk_level": risk,
        "encryption": {
            "status": encryption_status,
            "method": method,
            "key_handling": key_handling,
            "target_files": "미확인: 실제 암호화 대상 파일 목록이 입증되지 않음",
            "renamed_extension": "미확인: 암호화 후 파일명 또는 확장자 변경 이벤트가 입증되지 않음",
            "ransom_message": ransom_message,
            "wallpaper_change": "미확인: 바탕화면 변경 이벤트가 입증되지 않음",
            "decryption_outlook": "판정 불가: 실제 암호화 파일과 키의 관계가 입증되지 않음",
        },
        "behaviors": behaviors[:12],
        "execution_flow": [item["description"] for item in behaviors if item["status"] in {"CONFIRMED", "OBSERVED", "INFERRED"}][:12],
        "user_impact": [
            "관찰된 기능이 실제 환경에서 악용될 경우 정보 노출 또는 시스템 변경 위험이 있음",
            "실제 파일 암호화 완료는 확인되지 않았으므로 데이터 손실 여부는 추가 검증 필요",
        ],
        "iocs": _iocs(evidence),
        "external_intelligence": external_intelligence_summary(evidence),
        "cross_validation": evidence.get("cross_validation") or build_external_cross_validation(evidence),
        "unknowns": list(dict.fromkeys(unknown_values))[:20],
    }


def build_analysis_details(evidence: dict[str, Any]) -> dict[str, Any]:
    """Build a verbose, bounded analyst view from current-sample evidence only."""
    sample = evidence.get("sample") or {}
    static = evidence.get("static_analysis") or {}
    archive = static.get("archive_analysis") or {}
    member = archive.get("selected_member") or {}
    headers = member.get("pe_headers") or static.get("pe_headers") or {}
    pefile = member.get("pefile") or static.get("pefile") or {}
    dynamic = _dynamic(evidence)
    behavior = dynamic.get("behavior") or {}
    network = dynamic.get("network") or {}
    common = _common(evidence)
    external = external_intelligence_summary(evidence)

    import_rows: list[dict[str, Any]] = []
    import_symbol_count = 0
    for item in pefile.get("imports") or []:
        if not isinstance(item, dict):
            continue
        symbols = [str(value) for value in item.get("symbols") or [] if value]
        import_symbol_count += len(symbols)
        import_rows.append({
            "module": str(item.get("dll") or "미확인"),
            "symbol_count": len(symbols),
            "symbols": symbols[:20],
        })

    sections = [
        {
            "name": str(item.get("name") or "미확인"),
            "virtual_size": item.get("virtual_size"),
            "raw_size": item.get("raw_size"),
            "entropy": item.get("entropy"),
        }
        for item in headers.get("sections") or []
        if isinstance(item, dict)
    ][:20]

    findings: list[dict[str, Any]] = []
    for item in [*(static.get("findings") or []), *(member.get("findings") or [])]:
        if not isinstance(item, dict):
            continue
        findings.append({
            "category": str(item.get("category") or "미분류"),
            "status": str(item.get("status") or "candidate_only"),
            "matched": [str(value) for value in item.get("matched") or []][:20],
            "evidence_id": item.get("evidence_id"),
            "caution": item.get("caution"),
        })

    capa = archive.get("isolated_capa") or evidence.get("capa") or {}
    capa_rules = capa.get("rules") if isinstance(capa, dict) else None
    capa_rule_count = len(capa_rules) if isinstance(capa_rules, (dict, list)) else 0
    ghidra = archive.get("isolated_ghidra") or {}
    ghidra_program = ghidra.get("program") if isinstance(ghidra.get("program"), dict) else {}

    processes = [item for item in behavior.get("processes") or [] if isinstance(item, dict)]
    dropped = [item for item in dynamic.get("dropped_files") or [] if isinstance(item, dict)]
    signatures = [item for item in dynamic.get("signatures") or [] if isinstance(item, dict)]
    errors = [str(item) for item in dynamic.get("analysis_errors") or [] if item]

    ai_stages: list[dict[str, Any]] = []
    local_ai = evidence.get("local_ai") or {}
    for number in (1, 2, 3):
        stage = local_ai.get(f"pass_{number}") or {}
        if stage.get("model_error"):
            status = "fallback"
            detail = str(stage.get("model_error"))
        elif stage:
            status = "completed"
            detail = str(stage.get("_model") or "structured result")
        else:
            status = "not_run"
            detail = "결과 없음"
        ai_stages.append({"stage": f"local_pass_{number}", "status": status, "detail": detail})
    final = local_ai.get("user_report") or {}
    ai_stages.append({
        "stage": "final_synthesis",
        "status": "completed" if (final.get("final_assessment") or {}).get("summary") else "not_run",
        "detail": str((final.get("final_assessment") or {}).get("generated_by") or "결과 없음"),
    })

    dynamic_status = str(dynamic.get("status") or "not_run")
    malicious = int((external.get("stats") or {}).get("malicious") or 0)
    recommendations = [
        "원본 파일과 생성된 증거 JSON의 SHA-256을 보존하고 분석본과 업무용 복사본을 분리하십시오.",
        "해시·경로·시간 정보를 기준으로 EDR, 프록시, DNS, 방화벽 로그에서 동일 지표를 검색하십시오.",
    ]
    if dynamic_status != "completed":
        recommendations.append(
            "CAPE 동적 분석이 완료되지 않았으므로 실행 패키지·아키텍처·필수 인자를 보정해 다시 분석하고, 현재의 미관찰 항목을 정상으로 해석하지 마십시오."
        )
    if external.get("found") and malicious:
        recommendations.append(
            f"VirusTotal에서 악성 판정 {malicious}건이 보고되었으므로 파일을 격리하고 내부 파일 해시의 조직 내 존재 여부를 우선 확인하십시오."
        )
    if findings:
        recommendations.append(
            "정적 후보 기능은 실제 호출 경로와 인자까지 Ghidra에서 확인한 뒤 실행 행위로 승격하십시오."
        )
    if any(network.get(key) for key in ("domains", "dns", "http", "tcp", "udp")):
        recommendations.append("관찰된 네트워크 지표를 차단 후보로 검토하고 접속 전후의 호스트 행위를 함께 조사하십시오.")
    recommendations.append("재분석 전까지 해당 파일을 업무 단말에서 실행하지 말고 격리된 샌드박스에서만 취급하십시오.")

    characteristics = str(headers.get("characteristics") or "")
    try:
        is_dll = bool(int(characteristics, 16) & 0x2000)
    except ValueError:
        is_dll = False

    return {
        "sample": {
            "name": sample.get("name"),
            "size": sample.get("size"),
            "sha256": (sample.get("hashes") or {}).get("sha256"),
            "detected_type": (evidence.get("format_detection") or {}).get("detected_type"),
            "inner_name": member.get("name"),
            "inner_size": member.get("size"),
            "inner_sha256": (member.get("hashes") or {}).get("sha256"),
            "inner_type": (member.get("format_detection") or {}).get("detected_type"),
        },
        "static": {
            "format": headers.get("format"),
            "machine": headers.get("machine"),
            "entry_point": headers.get("entry_point_rva"),
            "image_base": headers.get("image_base"),
            "characteristics": characteristics or None,
            "is_dll": is_dll,
            "entropy": member.get("entropy", static.get("entropy")),
            "imphash": pefile.get("imphash"),
            "import_module_count": len(import_rows),
            "import_symbol_count": import_symbol_count,
            "imports": import_rows[:30],
            "sections": sections,
            "findings": findings[:30],
            "capa_rule_count": capa_rule_count,
            "ghidra_provider": ghidra.get("provider"),
            "ghidra_format": ghidra_program.get("executable_format"),
            "ghidra_language": ghidra_program.get("language_id"),
            "ghidra_compiler": ghidra_program.get("compiler"),
        },
        "dynamic": {
            "status": dynamic_status,
            "task_id": dynamic.get("task_id"),
            "package": dynamic.get("package"),
            "duration": dynamic.get("duration"),
            "timed_out": bool(dynamic.get("analysis_timed_out")),
            "sample_hash_verified": dynamic.get("sample_sha256_verified"),
            "process_count": len(processes),
            "signature_count": len(signatures),
            "dropped_count": len(dropped),
            "network_counts": {
                key: len(network.get(key) or [])
                for key in ("hosts", "domains", "dns", "http", "tcp", "udp", "smtp")
            },
            "errors": errors[:20],
        },
        "evidence_metrics": {
            "claims": len(common.get("claims") or []),
            "events": len(common.get("events") or []),
            "relations": len(common.get("relations") or []),
            "attack_candidates": len(common.get("attack_candidates") or []),
            "validated_references": int((evidence.get("ai_validation") or {}).get("checked_evidence_references") or 0),
            "validation_status": (evidence.get("ai_validation") or {}).get("status") or "not_run",
        },
        "ai_stages": ai_stages,
        "recommendations": recommendations[:10],
    }

def _drop_line(item: dict[str, Any]) -> str:
    names = item.get("name")
    name = ", ".join(str(value) for value in names) if isinstance(names, list) else str(names or "이름 미확인")
    note = " — 런타임 임시 추출물" if item.get("runtime_staging") else ""
    return f"`{name}` ({item.get('size', '?')} bytes, SHA-256 `{item.get('sha256', '-')}`){note}"


def render_human_report(evidence: dict[str, Any]) -> str:
    """Render the deterministic evidence-only fallback report."""
    data = build_report_data(evidence)
    sample = evidence.get("sample") or {}
    detected = evidence.get("format_detection") or {}
    dynamic = _dynamic(evidence)
    member = _archive_member(evidence)
    processes = [item for item in ((dynamic.get("behavior") or {}).get("processes") or []) if isinstance(item, dict)]
    process_attrs = {
        item.get("process_id"): item
        for item in (dynamic.get("attribution") or {}).get("processes") or []
        if isinstance(item, dict)
    }
    network = dynamic.get("network") or {}

    lines = [
        "# 사용자용 악성코드 분석 보고서", "", "## 1. 결론부터", "",
        f"- **추정 패밀리:** `{data['family']['name']}`",
        f"- **패밀리 신뢰도:** `{data['family']['confidence']}`",
        f"- **악성코드 성격:** {data['classification']}",
        f"- **위험도:** `{data['risk_level']}`",
        "- **보고서 모드:** `결정론적 evidence-only fallback`", "", data["plain_summary"], "", "판정 근거:",
    ]
    lines.extend(f"- {item}" for item in data["family"]["basis"])

    enc = data["encryption"]
    lines += [
        "", "## 2. 사용자의 파일에 무슨 일이 생기는가", "", "| 확인 항목 | 현재 판정 |", "|---|---|",
        f"| 암호화 실행 여부 | {enc['status']} |", f"| 암호화 방식 | {enc['method']} |",
        f"| 키 생성·보관 | {enc['key_handling']} |", f"| 암호화 대상 파일 | {enc['target_files']} |",
        f"| 암호화 후 파일명/확장자 | {enc['renamed_extension']} |", f"| 랜섬 안내 화면 | {enc['ransom_message']} |",
        f"| 바탕화면 변경 | {enc['wallpaper_change']} |", f"| 복호화 가능성 | {enc['decryption_outlook']} |",
        "", "## 3. 확인된 기능과 행위", "",
    ]
    for item in data["behaviors"]:
        refs = ", ".join(f"`{value}`" for value in item.get("evidence_ids") or [])
        lines.append(f"- **{item['title']} — {item['status']}:** {item['description']}" + (f" 근거: {refs}" if refs else ""))
    if not data["behaviors"]:
        lines.append("- 현재 증거에서 보고 가능한 핵심 행위를 확인하지 못했습니다.")

    lines += ["", "### 프로세스 관찰 및 귀속", "", "| 프로세스 | PID | PPID | 귀속 | 결론 사용 |", "|---|---:|---:|---|---|"]
    for process in processes[:30]:
        proc_attr = process_attrs.get(process.get("process_id")) or {}
        lines.append(
            f"| `{process.get('process_name', '-')}` | `{process.get('process_id', '-')}` | "
            f"`{process.get('parent_id', '-')}` | `{proc_attr.get('level', 'UNRELATED')}` | "
            f"{'예' if proc_attr.get('included_in_conclusion') else '아니요'} |"
        )
    if not processes:
        lines.append("| 관찰 기록 없음 | - | - | - | - |")
    lines += [
        "", "> 프로세스 귀속은 제출 파일 일치, PPID 계보, 명시적 프로세스 생성, 원격 프로세스 조작, 기록한 실행 파일의 후속 실행을 근거로 합니다. 단순 시간 순서나 같은 이름만으로 귀속하지 않습니다.",
        "", "## 4. 생성·드롭된 파일", "",
    ]
    lines.extend(f"- {_drop_line(item)}" for item in _dropped(evidence))
    if not _dropped(evidence):
        lines.append("- 동적 분석에서 수집된 드롭 파일이 없습니다.")

    external = data.get("external_intelligence") or {}
    lines += ["", "## 외부 위협 인텔리전스 교차검증", ""]
    if external.get("status") in {"completed", "found", "not_found"}:
        if external.get("found"):
            stats = external.get("stats") or {}
            lines += [
                f"- VirusTotal 조회 SHA-256: `{external.get('lookup_hash', '-')}`",
                f"- 탐지 통계: 악성 `{stats.get('malicious', 0)}` / 의심 `{stats.get('suspicious', 0)}` / 정상 `{stats.get('harmless', 0)}` / 미탐 `{stats.get('undetected', 0)}`",
                f"- 외부 패밀리 후보: `{external.get('family_candidate') or '미확인'}`",
                f"- VirusTotal 분석 링크: {external.get('analysis_link') or '미확인'}",
                f"- 로컬 ↔ VT MITRE 일치: `{', '.join(external.get('mitre_match') or []) or '없음'}`",
                f"- 로컬에서만 확인: `{', '.join(external.get('local_only_mitre') or []) or '없음'}`",
                f"- VT에서만 확인: `{', '.join(external.get('vt_only_mitre') or []) or '없음'}`",
                f"- 관련 파일 추가 조회: `{external.get('related_file_count', 0)}`개",
                "- 판정 규칙: VirusTotal은 외부 위협 인텔리전스이며 로컬 관찰 증거와 분리합니다.",
            ]
        else:
            lines += [
                "- VirusTotal에 기존 자료가 없습니다. 이는 정상 판정이 아니라 `VT NOT FOUND`입니다.",
                "- 파일 업로드는 수행하지 않았으며 SHA-256 조회만 사용했습니다.",
            ]
    elif external.get("status") == "not_configured":
        lines.append("- VirusTotal API 키가 설정되지 않아 외부 평판 조회를 수행하지 않았습니다.")
    elif external.get("status") == "disabled":
        lines.append("- VirusTotal 조회가 비활성화되었습니다.")
    else:
        lines.append(f"- VirusTotal 조회 상태: `{external.get('status', 'not_available')}`")

    cross = data.get("cross_validation") or {}
    items = [item for item in cross.get("items") or [] if isinstance(item, dict)]
    if items:
        lines += [
            "",
            "### 자체 분석 ↔ VirusTotal 행위 비교",
            "",
            "| 행위 | 자체 분석 | VirusTotal | 비교 결과 |",
            "|---|---|---|---|",
        ]
        for item in items:
            lines.append(
                f"| {item.get('label', item.get('capability', '-'))} | "
                f"`{item.get('local', '-')}` | `{item.get('virustotal', '-')}` | `{item.get('result', '-')}` |"
            )
        lines += [
            "",
            "> `VT_ONLY`는 로컬 분석 결과를 덮어쓰지 않습니다. 분석 환경·실행 조건·시점 차이를 설명하기 위한 외부 비교 결과입니다.",
        ]

    related = external.get("related_files") or []
    if related:
        lines += ["", "### VirusTotal 관련 파일 조회", "", "| 역할 | 파일 | 상태 | 악성 | 의심 | 패밀리 후보 |", "|---|---|---|---:|---:|---|"]
        for item in related[:10]:
            stats = item.get("last_analysis_stats") if isinstance(item.get("last_analysis_stats"), dict) else {}
            lines.append(
                f"| `{item.get('role', '-')}` | `{item.get('source_name') or item.get('lookup_hash', '-')}` | "
                f"`{item.get('status', '-')}` | {int(stats.get('malicious') or 0)} | {int(stats.get('suspicious') or 0)} | "
                f"`{item.get('family_candidate') or '미확인'}` |"
            )

    lines += ["", "## 5. 확인하지 못한 내용", ""]
    lines.extend(f"- {item}" for item in data["unknowns"])
    lines += [
        "", "## 6. 분석 범위와 해시", "", f"- 입력 파일: `{sample.get('name', '-')}`",
        f"- 입력 파일 SHA-256: `{(sample.get('hashes') or {}).get('sha256', '-')}`",
        f"- 내부 실행 파일: `{member.get('name', '-')}`", f"- 내부 EXE SHA-256: `{_inner_sha256(evidence) or '-'}`",
        f"- 형식: `{detected.get('detected_type', '-')}` / 내부 `{(member.get('format_detection') or {}).get('detected_type', '-')}`",
        f"- CAPE 상태/작업 ID/실행 시간: `{dynamic.get('status', 'unavailable')}` / `{dynamic.get('task_id', '-')}` / `{dynamic.get('duration', '-')}초`",
        f"- 관찰 프로세스: `{len(processes)}`개",
        f"- DNS/HTTP/TCP/UDP 기록: `{len(network.get('dns', []))}` / `{len(network.get('http', []))}` / `{len(network.get('tcp', []))}` / `{len(network.get('udp', []))}`",
        "", "## 7. 증거 수준 읽는 법", "", "- **CONFIRMED:** 격리 VM에서 샘플과 인과 연결된 직접 이벤트로 확인했습니다.",
        "- **OBSERVED:** 관찰됐지만 행위 주체 또는 결과까지 확정하지 않습니다.",
        "- **INFERRED:** 정적 기능 또는 둘 이상의 증거를 조합한 제한적 추론입니다.",
        "- **미확인:** 현재 증거에 없으며 다른 샘플의 정보를 가져오지 않습니다.",
        "", "## 분석 처리 요약", "", f"- CAPE 전체 시그니처 수: {len(_signature_records(evidence))}개",
        f"- 샘플 귀속 시그니처 수: {len(_conclusion_signatures(evidence))}개",
        f"- 분석 제한시간 도달 여부: {'예' if dynamic.get('analysis_timed_out') else '아니요'}",
        f"- 드롭 파일: {len(_dropped(evidence))}개", f"- 관찰 프로세스: `{len(processes)}`개",
        "- 전체 영문 시그니처와 AI 원문은 증거 JSON에만 보존됩니다.", "",
    ]
    return "\n".join(lines)
