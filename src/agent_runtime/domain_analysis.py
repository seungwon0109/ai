"""Question-scoped local-model reviews with deterministic semantic checks."""

from __future__ import annotations

import json
from pathlib import PureWindowsPath
from typing import Any, Callable


# The highest-risk, easiest-to-verify domains run first when calls are limited.
DOMAINS: dict[str, dict[str, Any]] = {
    "execution": {"question": "실행 후 프로세스와 직접 자식 프로세스가 어떻게 동작했는가?", "terms": ("process", "parent", "child", "pid", "command", "프로세스", "실행", "자식")},
    "network": {"question": "DNS, TCP, HTTP, C2 또는 외부 전송은 실제 관찰됐는가?", "terms": ("network", "dns", "http", "tcp", "udp", "connect", "c2", "통신", "전송")},
    "encryption_recovery": {"question": "파일 암호화와 키 처리 및 복구 가능성은 어디까지 입증됐는가?", "terms": ("encrypt", "decrypt", "crypto", "rc4", "key", "nonce", "cipher", "암호", "복호")},
    "impact_defense_evasion": {"question": "복구 방해, 분석 회피, 파일 삭제가 실제로 관찰됐는가?", "terms": ("shadow", "antivm", "sandbox", "debug", "delete", "impact", "복구", "삭제", "회피")},
    "persistence_privilege": {"question": "서비스 생성, 예약 작업, 자동 실행, 권한 변경이 실제로 있었는가?", "terms": ("service", "schtasks", "startup", "registry", "token", "privilege", "서비스", "지속", "권한")},
    "collection_injection": {"question": "정보 수집, 키로깅, 웹캠 또는 프로세스 조작이 관찰됐는가?", "terms": ("keylog", "webcam", "credential", "cookie", "inject", "정보", "웹캠", "인젝션")},
    "identity": {"question": "현재 파일은 어떤 종류이며 알려진 패밀리와 정확히 일치하는가?", "terms": ("family", "malware", "hash", "sha256", "파일", "패밀리")},
}

STATIC_ARTIFACT_TYPES = {
    "CAPA_RULE_MATCH", "ARCHIVE_MEMBER_STATIC_FINDING", "GHIDRA_FINDING",
    "GHIDRA_STRING", "PE_IMPORT", "STATIC_STRING",
}
DYNAMIC_EVENT_TYPES = {
    "PROCESS_START", "PROCESS_COMMAND", "FILE_WRITE", "FILE_DELETE", "FILE_RENAME",
    "REGISTRY_SET", "REGISTRY_DELETE", "SERVICE_CREATE", "SERVICE_START",
    "SCHEDULED_TASK_CREATE", "DNS_QUERY", "NETWORK_CONNECT", "HTTP_REQUEST",
}
EXECUTION_WORDS = (
    "실행했다", "수행했다", "삭제했다", "생성했다", "변경했다", "암호화했다",
    "전송했다", "수집했다", "등록했다", "시작했다", "완료했다", "성공했다",
    "executed", "deleted", "created", "encrypted", "sent", "connected",
)


def _text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str).casefold()


def _artifact_kind(item: dict[str, Any]) -> str:
    artifact_type = str(item.get("artifact_type") or "").upper()
    if artifact_type in STATIC_ARTIFACT_TYPES or artifact_type.startswith("GHIDRA"):
        return "static"
    if artifact_type == "CAPE_PROCESS":
        return "dynamic_process"
    if artifact_type == "CAPE_SIGNATURE":
        level = str((((item.get("value") or {}).get("attribution") or {}).get("level") or "POSSIBLE"))
        if level in {"DIRECT", "CHILD", "CAUSAL"}:
            return "dynamic_signature"
        return "background_signature" if level == "UNRELATED" else "unattributed_signature"
    if artifact_type.startswith("CAPE_"):
        return "dynamic_artifact"
    return "artifact"


def build_evidence_catalog(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index current-sample records and retain their evidence strength."""
    catalog: dict[str, dict[str, Any]] = {}
    for item in ((evidence.get("static_analysis") or {}).get("findings") or []):
        if isinstance(item, dict) and item.get("evidence_id"):
            catalog[str(item["evidence_id"])] = {"source": "static", "kind": "static", "record": item}
    common = evidence.get("common_evidence") or {}
    for item in common.get("artifacts") or []:
        if isinstance(item, dict) and item.get("artifact_id"):
            catalog[str(item["artifact_id"])] = {"source": "artifact", "kind": _artifact_kind(item), "record": item}
    for item in common.get("events") or []:
        if isinstance(item, dict) and item.get("event_id"):
            catalog[str(item["event_id"])] = {"source": "event", "kind": "dynamic_event", "record": item}
    for item in common.get("claims") or []:
        if isinstance(item, dict) and item.get("claim_id"):
            level = str(item.get("level") or "").upper()
            catalog[str(item["claim_id"])] = {
                "source": "claim", "kind": "dynamic_claim" if level == "CONFIRMED" else "derived_claim", "record": item,
            }
    return catalog


def _process_context(evidence: dict[str, Any]) -> dict[str, Any]:
    processes = [
        item for item in (((evidence.get("dynamic_analysis") or {}).get("behavior") or {}).get("processes") or [])
        if isinstance(item, dict) and item.get("process_id") is not None
    ]
    by_pid = {int(item["process_id"]): item for item in processes if str(item.get("process_id", "")).isdigit()}
    children: dict[int, list[int]] = {}
    for pid, item in by_pid.items():
        parent = item.get("parent_id")
        if str(parent).isdigit():
            children.setdefault(int(parent), []).append(pid)

    sample_names: set[str] = set()
    sample = evidence.get("sample") or {}
    member = ((((evidence.get("static_analysis") or {}).get("archive_analysis") or {}).get("selected_member") or {}))
    for value in (sample.get("name"), member.get("name")):
        if value:
            sample_names.add(PureWindowsPath(str(value)).name.casefold())
    attrs = {
        item.get("process_id"): item
        for item in ((evidence.get("dynamic_analysis") or {}).get("attribution") or {}).get("processes") or []
        if isinstance(item, dict)
    }
    sample_pids = [pid for pid in by_pid if (attrs.get(pid) or {}).get("included_in_conclusion")]
    rows = [
        {
            "pid": pid,
            "ppid": item.get("parent_id"),
            "name": item.get("process_name"),
            "direct_children": children.get(pid, []),
            "is_sample_process": pid in sample_pids,
            "attribution": (attrs.get(pid) or {}).get("level", "UNRELATED"),
        }
        for pid, item in sorted(by_pid.items())
    ]
    return {"sample_process_pids": sample_pids, "processes": rows}


def _observed_flags(evidence: dict[str, Any]) -> dict[str, Any]:
    dynamic = evidence.get("dynamic_analysis") or {}
    common = evidence.get("common_evidence") or {}
    attributed_events = [
        item for item in common.get("events") or []
        if isinstance(item, dict) and bool((item.get("attributes") or {}).get("included_in_conclusion"))
    ]
    event_types = {
        str(item.get("event_type") or "").upper()
        for item in attributed_events
    }
    signatures = {
        str(item.get("name") or "").casefold()
        for item in dynamic.get("signatures") or []
        if isinstance(item, dict) and bool((item.get("attribution") or {}).get("included_in_conclusion"))
    }
    return {
        "network_observed": bool(event_types & {"DNS_QUERY", "NETWORK_CONNECT", "HTTP_REQUEST"}),
        "service_create_observed": "SERVICE_CREATE" in event_types,
        "scheduled_task_create_observed": "SCHEDULED_TASK_CREATE" in event_types,
        "file_delete_observed": "FILE_DELETE" in event_types,
        "file_encryption_observed": any(any(token in name for token in ("encrypts_files", "file_encryption", "ransomware_files", "encrypted_files")) for name in signatures),
        "keylogging_observed": any("infostealer_keylog" in name or "keylogging" in name for name in signatures),
        "webcam_observed": any("webcam" in name or "camera_capture" in name for name in signatures),
        "event_types": sorted(event_types & DYNAMIC_EVENT_TYPES),
    }


def retrieve_domain_evidence(evidence: dict[str, Any], domain: str, limit: int = 36) -> dict[str, Any]:
    """Retrieve only records relevant to one question, preserving exact IDs."""
    spec = DOMAINS[domain]
    catalog = build_evidence_catalog(evidence)
    scored: list[tuple[int, str, dict[str, Any]]] = []
    for evidence_id, wrapped in catalog.items():
        rendered = _text(wrapped["record"])
        score = sum(1 for term in spec["terms"] if term.casefold() in rendered)
        if score:
            scored.append((score, evidence_id, wrapped))
    scored.sort(key=lambda row: (-row[0], row[1]))
    records = [
        {"evidence_id": eid, "source": wrapped["source"], "kind": wrapped["kind"], "record": wrapped["record"]}
        for _, eid, wrapped in scored[:limit]
    ]
    context = {
        "domain": domain,
        "question": spec["question"],
        "sample": evidence.get("sample"),
        "family_intelligence": evidence.get("family_intelligence"),
        "observed_flags": _observed_flags(evidence),
        "evidence_records": records,
    }
    if domain == "execution":
        context["process_graph"] = _process_context(evidence)
    return context


def _direct_process_relation(raw: dict[str, Any], evidence: dict[str, Any]) -> bool:
    subject = raw.get("subject_pid")
    target = raw.get("object_pid")
    if not (str(subject).isdigit() and str(target).isdigit()):
        return False
    for item in _process_context(evidence)["processes"]:
        if item["pid"] == int(target):
            if str(item.get("ppid")) == str(int(subject)):
                return True
    return any(
        isinstance(edge, dict)
        and str(edge.get("source_pid")) == str(int(subject))
        and str(edge.get("target_pid")) == str(int(target))
        and edge.get("type") in {"PROCESS_CREATE_CALL", "REMOTE_PROCESS_MUTATION", "WROTE_EXECUTED_IMAGE"}
        for edge in ((evidence.get("dynamic_analysis") or {}).get("attribution") or {}).get("edges") or []
    )


def verify_domain_review(review: dict[str, Any], evidence: dict[str, Any], domain: str) -> dict[str, Any]:
    """Reject unsupported semantics, not merely unknown evidence IDs."""
    catalog = build_evidence_catalog(evidence)
    terms = DOMAINS[domain]["terms"]
    flags = _observed_flags(evidence)
    verified: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []

    for raw in review.get("claims") or []:
        if not isinstance(raw, dict):
            continue
        claim = str(raw.get("claim") or "").strip()
        ids = [str(value) for value in raw.get("evidence_ids") or [] if str(value) in catalog]
        records = [catalog[value] for value in ids]
        evidence_text = " ".join(_text(item["record"]) for item in records)
        lowered = claim.casefold()
        kinds = {item["kind"] for item in records}
        only_static = bool(kinds) and kinds <= {"static", "derived_claim"}
        has_excluded_dynamic = bool(kinds & {"background_signature", "unattributed_signature"})
        reason = ""

        if not claim or not ids:
            reason = "유효한 주장 또는 현재 샘플의 증거 ID가 없음"
        elif not any(term.casefold() in evidence_text for term in terms):
            reason = "인용 증거가 해당 분석 분야와 의미상 연결되지 않음"
        elif only_static and any(word in lowered for word in EXECUTION_WORDS):
            reason = "정적 기능을 실제 실행 사실로 표현함"
        elif has_excluded_dynamic and not (kinds & {"dynamic_signature", "dynamic_event", "dynamic_claim"}):
            reason = "시그니처 행위 주체가 샘플 인과 그래프에 귀속되지 않음"
        elif domain == "network" and not flags["network_observed"] and any(word in lowered for word in ("전송", "통신", "연결", "송수신", "connect", "sent")) and "미확인" not in lowered:
            reason = "동적 네트워크 기록이 0건인데 통신을 주장함"
        elif domain == "encryption_recovery" and not flags["file_encryption_observed"] and any(word in lowered for word in ("암호화했다", "암호화 완료", "파일을 암호화", "encrypted files")):
            reason = "실제 파일 암호화 이벤트가 없음"
        elif domain == "persistence_privilege" and not flags["service_create_observed"] and any(word in lowered for word in ("서비스를 생성", "서비스 생성", "서비스 등록")):
            reason = "서비스 생성 이벤트가 없음"
        elif domain == "persistence_privilege" and not flags["scheduled_task_create_observed"] and any(word in lowered for word in ("예약 작업 생성", "예약 작업 등록")):
            reason = "예약 작업 생성 이벤트가 없음"
        elif domain == "impact_defense_evasion" and not flags["file_delete_observed"] and any(word in lowered for word in ("파일을 삭제", "디렉터리를 삭제", "삭제했다")):
            reason = "실제 파일 삭제 이벤트가 없음"
        elif domain == "collection_injection" and "키로" in lowered and not flags["keylogging_observed"]:
            reason = "키보드 배열 조회와 키 입력 수집을 구분하지 않음"
        elif domain == "collection_injection" and "웹캠" in lowered and not flags["webcam_observed"]:
            reason = "웹캠 접근 또는 이미지 생성 이벤트가 없음"
        elif domain == "execution" and any(word in lowered for word in ("자식", "생성", "통해", "spawn", "child")) and not _direct_process_relation(raw, evidence):
            reason = "subject_pid/object_pid로 직접 PPID 관계가 입증되지 않음"

        if reason:
            rejected.append({"claim": claim, "evidence_ids": ids, "reason": reason})
            continue

        status = str(raw.get("status") or "OBSERVED").upper()
        has_event = "dynamic_event" in kinds and any(
            item["kind"] == "dynamic_event"
            and bool(((item["record"].get("attributes") or {}).get("included_in_conclusion")))
            for item in records
        )
        if status == "CONFIRMED" and not has_event:
            status = "OBSERVED"
        if only_static and status != "UNRESOLVED":
            status = "INFERRED"
        if status not in {"CONFIRMED", "OBSERVED", "INFERRED", "UNRESOLVED"}:
            status = "OBSERVED"
        verified.append({
            "domain": domain,
            "claim": claim,
            "status": status,
            "confidence": str(raw.get("confidence") or "중간"),
            "evidence_ids": ids[:8],
        })

    return {
        "domain": domain,
        "assessment": str(review.get("assessment") or ""),
        "verified_claims": verified[:8],
        "rejected_claims": rejected[:8],
        "unresolved": [str(value) for value in review.get("unresolved") or []][:8],
    }


def run_domain_reviews(
    evidence: dict[str, Any],
    args: Any,
    *,
    chat_fn: Callable[..., dict[str, Any]],
    parse_fn: Callable[[str], dict[str, Any]],
) -> dict[str, Any]:
    """Run a bounded number of reviews and verify every retained claim."""
    model = str(getattr(args, "local_model", None) or "malware-qwen:9b")
    limit = max(0, min(int(getattr(args, "max_domain_reviews", 4)), len(DOMAINS)))
    per_call_timeout = max(1, min(int(getattr(args, "ai_timeout", 120)), int(getattr(args, "local_report_timeout", 180))))
    output: dict[str, Any] = {"model": model, "reviews": {}, "verified_claims": [], "rejected_claims": []}
    schema = {
        "assessment": "해당 분야의 짧은 한국어 판단",
        "claims": [{
            "claim": "한 가지 사실", "status": "CONFIRMED|OBSERVED|INFERRED|UNRESOLVED",
            "confidence": "높음|중간|낮음", "evidence_ids": ["기존 ID"],
            "subject_pid": "프로세스 관계일 때 필수 정수", "object_pid": "프로세스 관계일 때 필수 정수",
        }],
        "unresolved": ["증거로 답할 수 없는 질문"],
    }
    system = (
        "당신은 방어 목적 악성코드 분석가다. 현재 제공된 한 샘플과 한 분야만 분석하라. "
        "정적 capa/Ghidra 결과는 기능 보유일 뿐 실행 사실이 아니다. CAPE 시그니처도 성공 결과를 자동으로 의미하지 않는다. "
        "프로세스 인과관계는 제공된 attribution/edge 또는 직접 PPID 연결로만 주장하고 시간 순서를 인과관계로 사용하지 마라. "
        "서비스 시작은 서비스 생성이나 지속성 확보가 아니다. 키보드 배열 조회는 키로깅이 아니다. "
        "각 주장은 현재 제공된 evidence_id를 인용하고, 증거가 없으면 unresolved에 기록하라. JSON 객체 하나만 출력하라."
    )

    calls = 0
    domains = list(DOMAINS)
    for index, domain in enumerate(domains):
        context = retrieve_domain_evidence(evidence, domain)
        if index >= limit:
            output["reviews"][domain] = {
                "domain": domain,
                "assessment": "모델 호출 제한으로 결정론적 보고서에서 처리",
                "verified_claims": [], "rejected_claims": [], "unresolved": [context["question"]],
            }
            continue
        user = (
            "질문: " + context["question"]
            + "\n출력 구조:\n" + json.dumps(schema, ensure_ascii=False, separators=(",", ":"))
            + "\n선별 증거:\n" + json.dumps(context, ensure_ascii=False, separators=(",", ":"))
        )
        response = chat_fn(
            getattr(args, "local_base_url", None), getattr(args, "local_api_key", None) or "local",
            model, system, user, per_call_timeout,
        )
        calls += 1
        parsed = parse_fn(str(response.get("content") or "")) if response.get("ok") else {}
        if not isinstance(parsed, dict) or not isinstance(parsed.get("claims"), list):
            parsed = {"assessment": "로컬 모델 응답 검증 실패", "claims": [], "unresolved": [context["question"]]}
        checked = verify_domain_review(parsed, evidence, domain)
        output["reviews"][domain] = checked
        output["verified_claims"].extend(checked["verified_claims"])
        output["rejected_claims"].extend(checked["rejected_claims"])

    output["control"] = {
        "domain_count": len(DOMAINS),
        "model_call_count": calls,
        "model_call_limit": limit,
        "verified_claim_count": len(output["verified_claims"]),
        "rejected_claim_count": len(output["rejected_claims"]),
        "timeout_seconds_per_call": per_call_timeout,
        "stopped_reason": "call_limit" if limit < len(DOMAINS) else "completed",
        "author": "local_ai",
        "validator": "deterministic_semantic_gate_v3",
    }
    return output
