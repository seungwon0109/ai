"""Final local-Qwen synthesis after independent local analysis and VT comparison."""

from __future__ import annotations

import json
from typing import Any, Callable

from .domain_analysis import run_domain_reviews
from ..reporting.human_report import (
    build_external_cross_validation,
    build_report_data,
    external_intelligence_summary,
)


def _schema() -> dict[str, Any]:
    return {
        "summary": "자체 분석과 VirusTotal 비교를 종합한 한국어 결론",
        "agreement_points": ["양쪽에서 일치한 핵심"],
        "difference_points": ["LOCAL_ONLY/VT_ONLY 차이와 가능한 이유. 가능성으로만 표현"],
        "family_interpretation": "로컬 패밀리 판정과 VT 외부 후보를 구분한 설명",
        "confidence": "높음|중간|낮음",
        "limitations": ["현재 분석에서 확정할 수 없는 한계"],
    }


def _valid(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    required = {
        "summary", "agreement_points", "difference_points",
        "family_interpretation", "confidence", "limitations",
    }
    if not required.issubset(value):
        return False
    if not isinstance(value.get("summary"), str) or not value["summary"].strip():
        return False
    if not isinstance(value.get("family_interpretation"), str):
        return False
    if str(value.get("confidence")) not in {"높음", "중간", "낮음"}:
        return False
    return all(isinstance(value.get(key), list) for key in ("agreement_points", "difference_points", "limitations"))


def _valid_ids(evidence: dict[str, Any]) -> tuple[set[str], set[str]]:
    common = evidence.get("common_evidence") or {}
    valid: set[str] = {
        str(item.get("evidence_id"))
        for item in ((evidence.get("static_analysis") or {}).get("findings") or [])
        if isinstance(item, dict) and item.get("evidence_id")
    }
    dynamic: set[str] = set()
    for key, id_key in (("artifacts", "artifact_id"), ("events", "event_id"), ("claims", "claim_id")):
        for item in common.get(key) or []:
            if isinstance(item, dict) and item.get(id_key):
                value = str(item[id_key])
                valid.add(value)
                if key == "events" or (key == "artifacts" and item.get("source_id")):
                    dynamic.add(value)
    return valid, dynamic


def _guard(value: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    """Return only deterministic current-sample report data.

    Kept as a separate guard because tests and other callers use it directly.
    Free-form model facts are never allowed to replace local evidence findings.
    """
    domain_analysis = evidence.get("domain_analysis") or {}
    verified = domain_analysis.get("verified_claims") or []
    unresolved = [
        str(item)
        for review in (domain_analysis.get("reviews") or {}).values()
        if isinstance(review, dict)
        for item in review.get("unresolved") or []
    ]
    return build_report_data(evidence, verified_claims=verified, unresolved=unresolved)


def _bounded_strings(values: Any, limit: int = 8) -> list[str]:
    if not isinstance(values, list):
        return []
    return [str(value)[:700] for value in values[:limit] if str(value).strip()]


def _cross_labels(cross: dict[str, Any], *results: str) -> list[str]:
    wanted = set(results)
    return [
        str(item.get("label"))
        for item in cross.get("items") or []
        if isinstance(item, dict) and item.get("result") in wanted and item.get("label")
    ]


def _external_behavior_labels(external: dict[str, Any]) -> list[str]:
    labels = {
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
    features = external.get("behavior_features") if isinstance(external.get("behavior_features"), dict) else {}
    return [
        label for key, label in labels.items()
        if isinstance(features.get(key), dict) and bool(features[key].get("observed"))
    ]


def _external_evidence_points(external: dict[str, Any]) -> list[str]:
    detail = external.get("behavior_detail") if isinstance(external.get("behavior_detail"), dict) else {}
    points: list[str] = []
    observed = _external_behavior_labels(external)
    if observed:
        points.append(f"VirusTotal 외부 샌드박스 관찰: {', '.join(observed)}")
    verdicts = [str(item) for item in detail.get("verdicts") or [] if str(item).strip()]
    labels = [str(item) for item in detail.get("verdict_labels") or [] if str(item).strip()]
    confidence = detail.get("verdict_confidence")
    if verdicts or labels:
        suffix = f" (샌드박스 신뢰도 {confidence})" if confidence is not None else ""
        points.append(f"외부 샌드박스 판정: {', '.join([*labels, *verdicts])}{suffix}")
    domains = [str(item) for item in detail.get("domains") or [] if str(item).strip()]
    if domains:
        points.append(f"메모리 패턴 도메인: {', '.join(domains[:3])}")
    commands = [str(item) for item in detail.get("command_executions") or [] if str(item).strip()]
    if commands:
        points.append(f"외부 실행 명령: {commands[0]}")
    return points[:6]


def _canonical_family_interpretation(local_report: dict[str, Any], external: dict[str, Any]) -> str:
    local_family = str(((local_report.get("family") or {}).get("name") or "미확인"))
    candidate = str(external.get("family_candidate") or "").strip()
    status = str(external.get("status") or "not_available")
    local_text = f"자체 분석의 패밀리 판정은 '{local_family}'입니다."
    if external.get("found") and candidate:
        return (
            f"{local_text} VirusTotal의 '{candidate}'는 외부 패밀리 후보이며 "
            "자체 패밀리 확정 근거로 사용하지 않습니다."
        )
    if status == "not_configured":
        return f"{local_text} VirusTotal이 설정되지 않아 외부 패밀리 후보와 비교하지 못했습니다."
    if status in {"completed", "not_found"} and not external.get("found"):
        return f"{local_text} VirusTotal에 기존 파일 정보가 없어 외부 패밀리 후보도 확인되지 않았습니다."
    return f"{local_text} 외부 패밀리 정보는 현재 사용할 수 없습니다."


def _deterministic_final_summary(
    local_report: dict[str, Any],
    external: dict[str, Any],
    cross: dict[str, Any],
) -> str:
    risk = str(local_report.get("risk_level") or "미확인")
    classification = str(local_report.get("classification") or "역할 미확인")
    local_family = str(((local_report.get("family") or {}).get("name") or "미확인"))
    if external.get("found"):
        stats = external.get("stats") or {}
        candidate = str(external.get("family_candidate") or "미확인")
        threat_names = [
            f"{item.get('name')}({int(item.get('count') or 0)})"
            for item in external.get("threat_names") or [] if isinstance(item, dict) and item.get("name")
        ]
        matches = len(_cross_labels(cross, "MATCH"))
        supported = len(_cross_labels(cross, "VT_SUPPORTS_LOCAL_INFERENCE", "EXTERNAL_SUPPORT"))
        local_unavailable = len(_cross_labels(cross, "VT_ONLY_LOCAL_UNAVAILABLE"))
        observed = _external_behavior_labels(external)
        dynamic_status = str(local_report.get("dynamic_status") or "미확인")
        if dynamic_status == "completed" and local_report.get("analysis_timed_out"):
            dynamic_context = "로컬 CAPE는 완료됐지만 설정된 분석 시간이 만료되어 후속 행위 관찰이 제한됐습니다."
        elif dynamic_status == "completed":
            dynamic_context = "로컬 CAPE는 완료됐으며 샘플에 직접 귀속된 행위와 미관찰 항목을 분리했습니다."
        else:
            dynamic_context = "로컬 동적 분석 결과가 불완전해 실행 행위 일부를 검증하지 못했습니다."
        summary = (
            f"자체 분석은 위험도 '{risk}', 분류 '{classification}', 패밀리 '{local_family}'으로 결론냈습니다. "
            f"{dynamic_context} "
            f"VirusTotal 해시 평판에서는 악성 {int(stats.get('malicious') or 0)}개 엔진이 탐지했고 "
            f"외부 패밀리 후보는 '{candidate}'입니다. "
        )
        if threat_names:
            summary += f"외부 엔진의 주요 위협명 집계는 {', '.join(threat_names[:5])}입니다. "
        if observed:
            summary += f"VirusTotal 외부 샌드박스에서는 다음 행위가 관찰됐습니다: {', '.join(observed)}. "
        summary += (
            f"로컬과 VT의 직접 일치는 {matches}건, 로컬 정적 추론을 VT가 보강한 항목은 {supported}건이며, "
            f"로컬 실행 증거 부재로 VT 관찰만 남은 항목은 {local_unavailable}건입니다. "
            "따라서 로컬 미관찰을 정상 근거로 해석해서는 안 되며, VT 내용은 강한 외부 근거이지만 자체 동적 관찰과는 구분해야 합니다."
        )
        return summary
    status = str(external.get("status") or "not_available")
    if status == "not_configured":
        return f"자체 분석 결과는 위험도 {risk}, 분류 '{classification}', 패밀리 '{local_family}'입니다. VirusTotal API가 설정되지 않아 외부 교차검증은 수행하지 못했습니다."
    if status in {"completed", "not_found"}:
        return f"자체 분석 결과는 위험도 {risk}, 분류 '{classification}', 패밀리 '{local_family}'입니다. VirusTotal에서 해당 SHA-256의 기존 분석 정보가 확인되지 않아 외부 행위 비교는 수행하지 못했습니다. 이는 정상 판정을 의미하지 않습니다."
    return f"자체 분석 결과는 위험도 {risk}, 분류 '{classification}', 패밀리 '{local_family}'입니다. VirusTotal 상태가 '{status}'여서 외부 교차검증 결과를 사용할 수 없습니다."


def _build_comprehensive_final_sections(
    local_report: dict[str, Any],
    external: dict[str, Any],
    cross: dict[str, Any],
) -> dict[str, Any]:
    stats = external.get("stats") if isinstance(external.get("stats"), dict) else {}
    malicious = int(stats.get("malicious") or 0)
    candidate = str(external.get("family_candidate") or "미확인")
    local_risk = str(local_report.get("risk_level") or "미확인")
    classification = str(local_report.get("classification") or "역할 미확인")
    detail = external.get("behavior_detail") if isinstance(external.get("behavior_detail"), dict) else {}
    observed = _external_behavior_labels(external)
    supported = _cross_labels(cross, "MATCH", "VT_SUPPORTS_LOCAL_INFERENCE", "EXTERNAL_SUPPORT")
    local_only = _cross_labels(cross, "LOCAL_ONLY", "LOCAL_INFERENCE_ONLY")
    vt_only = _cross_labels(cross, "VT_ONLY", "VT_ONLY_LOCAL_UNAVAILABLE", "VT_REPORTED_ONLY")
    threat_names = [
        f"{item.get('name')}({int(item.get('count') or 0)})"
        for item in external.get("threat_names") or []
        if isinstance(item, dict) and item.get("name")
    ]
    commands = [str(item) for item in detail.get("command_executions") or [] if str(item).strip()]
    domains = [str(item) for item in detail.get("domains") or [] if str(item).strip()]
    vt_mitre = [str(item) for item in external.get("vt_only_mitre") or [] if str(item).strip()]
    local_narrative = [str(item) for item in local_report.get("analysis_narrative") or [] if str(item).strip()]

    if malicious >= 30:
        overall = "악성 가능성 매우 높음 · 즉시 격리 권고"
        priority = "매우 높음"
    elif malicious >= 10:
        overall = "악성 가능성 높음 · 격리 우선"
        priority = "높음"
    else:
        overall = f"추가 검증 필요 · 로컬 위험도 {local_risk}"
        priority = local_risk

    executive = [
        (
            f"로컬 자체 분석은 외부 평판을 보지 않은 상태에서 위험도 '{local_risk}', "
            f"분류 '{classification}'로 평가했습니다. 이 값은 제한된 CAPE 실행에서 샘플에 직접 귀속된 행위만 반영하므로 "
            "파일의 최종 안전성 판정과 동일하지 않습니다."
        ),
        (
            f"동일 내부 SHA-256에 대한 VirusTotal 조회에서는 {malicious}개 엔진이 악성으로 분류했고, "
            f"주요 위협명은 {', '.join(threat_names[:5]) or '미확인'}, 외부 패밀리 후보는 '{candidate}'입니다. "
            f"외부 샌드박스가 보고한 핵심 행위는 {', '.join(observed) or '요약 정보 없음'}입니다."
        ),
        (
            f"두 결과를 합치면 종합 대응 우선순위는 '{priority}'입니다. "
            "로컬에서 랜섬웨어의 전체 암호화 단계가 재현되지 않았더라도, 정확한 해시에 대한 다수 엔진 탐지와 "
            "외부 행위 보고를 무시해 낮은 위험으로 처리해서는 안 됩니다."
        ),
    ]

    synthesis = []
    if local_narrative:
        synthesis.append(f"로컬 실행 해석: {local_narrative[1] if len(local_narrative) > 1 else local_narrative[0]}")
    if supported:
        synthesis.append(f"로컬 근거와 VT가 같은 방향을 가리킨 행위: {', '.join(supported)}")
    if vt_only:
        synthesis.append(f"VT에서만 동적으로 보고된 행위: {', '.join(vt_only)}")
    if local_only:
        synthesis.append(f"로컬 정적 후보만 있고 VT 행위 요약에는 없는 항목: {', '.join(local_only)}")
    if domains:
        synthesis.append(f"정적·외부 분석에서 주목할 도메인: {', '.join(domains[:5])}")
    if commands:
        synthesis.append(f"VT 외부 실행 명령 예시: {commands[0]}")
    if vt_mitre:
        synthesis.append(f"VT에서 추가 보고된 ATT&CK 기법: {', '.join(vt_mitre[:12])}")

    chain = [
        "입력 ZIP에서 64비트 DLL 성격의 내부 PE가 선택되고 rundll32를 통한 로딩 대상으로 처리됩니다.",
        "로컬 정적 분석에서 프로세스 실행, 서비스·레지스트리 기반 지속성, 암호화, 디버거 확인 기능 후보가 확인됩니다.",
    ]
    if any("rundll32" in value.casefold() for value in commands) or local_report.get("execution_command_lines"):
        chain.append("rundll32가 DLL 엔트리포인트를 호출하는 실행 경로가 로컬 또는 VT 증거에서 확인됩니다.")
    chain.append(
        "분석 환경 확인과 권한 상태 점검을 거친 뒤 후속 기능을 실행할 가능성이 있으나, "
        "각 단계의 성공 여부는 샌드박스별로 다르게 관찰됐습니다."
    )
    if "프로세스 생성" in observed:
        chain.append("VT 외부 샌드박스에서는 추가 프로세스 생성이 관찰됐으며 로컬 정적 CreateProcess 후보와 같은 방향입니다.")
    if "네트워크 통신" in observed or domains:
        chain.append("VT 외부 환경에서는 네트워크 통신이 보고됐고 kill-switch로 알려진 형태의 도메인 문자열이 확인되지만, 로컬 CAPE에서는 통신이 재현되지 않았습니다.")
    chain.append("파일 암호화·랜섬노트·복구 방해의 실제 완료는 이번 로컬 실행에서 확인되지 않았으므로 해당 단계는 확정하지 않습니다.")

    risk_points = [
        f"정확한 내부 SHA-256에 대해 VT 악성 탐지 {malicious}건과 '{candidate}' 후보가 존재해 외부 평판 위험은 높습니다.",
        f"로컬 위험도 '{local_risk}'이라는 평가는 시간 제한·실행 조건·네트워크 환경의 영향을 받는 관찰 기반 값이며 종합 위험도를 낮추는 근거가 아닙니다.",
        "VT의 행위는 외부 샌드박스 관찰이므로 로컬 실행 사실로 바꾸지 않지만, 대응 우선순위를 정하는 독립 근거로 사용합니다.",
        "로컬 미관찰과 VT 관찰의 차이는 기능 부재가 아니라 실행 경로, 분석 시간, 환경 탐지 또는 네트워크 조건 차이로 설명될 수 있습니다.",
    ]

    conclusion = (
        f"이 파일은 로컬 실행만으로 전체 악성 행위를 재현하지 못했지만, 정확한 해시 기준 {malicious}개 악성 탐지, "
        f"'{candidate}' 패밀리 후보, VT의 {', '.join(observed) or '행위'} 보고를 종합하면 "
        "업무 환경에서 실행을 허용할 수 없는 고위험 샘플로 취급하는 것이 타당합니다. "
        "다만 실제 파일 암호화 완료와 피해 범위는 이번 로컬 증거로 확정하지 않습니다."
    )

    return {
        "overall_verdict": overall,
        "executive_assessment": executive,
        "evidence_synthesis": synthesis[:12],
        "likely_behavior_chain": chain[:10],
        "risk_interpretation": risk_points,
        "analyst_conclusion": conclusion,
    }


def _fallback_final_assessment(
    local_report: dict[str, Any],
    external: dict[str, Any],
    cross: dict[str, Any],
) -> dict[str, Any]:
    matches = _cross_labels(cross, "MATCH")
    supported = _cross_labels(cross, "VT_SUPPORTS_LOCAL_INFERENCE", "EXTERNAL_SUPPORT")
    vt_only_unavailable = _cross_labels(cross, "VT_ONLY_LOCAL_UNAVAILABLE")
    differences = [
        f"{item.get('label')}: 로컬 동적 증거는 확보하지 못했지만 VT 외부 샌드박스에서는 관찰됨"
        for item in cross.get("items") or []
        if isinstance(item, dict) and item.get("result") == "VT_ONLY_LOCAL_UNAVAILABLE"
    ]
    differences.extend(
        f"{item.get('label')}: {item.get('result')}"
        for item in cross.get("items") or []
        if isinstance(item, dict)
        and item.get("result") in {"LOCAL_ONLY", "VT_ONLY", "LOCAL_INFERENCE_ONLY", "VT_REPORTED_ONLY"}
    )
    external_available = bool(external.get("found"))
    agreement_points = [*matches, *[f"{label}: 로컬 정적 추론과 VT 외부 행위가 같은 방향" for label in supported]]
    local_iocs = [
        str(item.get("value") or "").casefold()
        for item in local_report.get("iocs") or [] if isinstance(item, dict)
    ]
    domains = [
        str(item).casefold()
        for item in ((external.get("behavior_detail") or {}).get("domains") or [])
    ]
    if any(domain and any(domain in ioc for ioc in local_iocs) for domain in domains):
        agreement_points.append("로컬 정적 분석의 URL·도메인과 VT 메모리 패턴 도메인이 일치")
    limitations = ["VirusTotal 결과는 로컬 관찰 사실을 덮어쓰지 않습니다."]
    if external_available:
        dynamic_status = str(local_report.get("dynamic_status") or "")
        if dynamic_status == "completed" and local_report.get("analysis_timed_out"):
            limitations.append("로컬 CAPE 작업은 완료됐지만 분석 시간 만료로 지연 실행 또는 후속 단계가 관찰되지 않았을 수 있습니다.")
        elif dynamic_status == "completed":
            limitations.append("로컬 CAPE 작업은 완료됐지만 단일 실행 환경에서 모든 조건부 행위를 재현했다고 볼 수 없습니다.")
        else:
            limitations.append("로컬 CAPE 결과가 불완전해 VT 외부 샌드박스 행위를 동일 환경에서 재현·검증하지 못했습니다.")
        limitations.append("샌드박스 환경·실행 조건·분석 시점 차이로 행위 관찰 결과가 달라질 수 있습니다.")
    else:
        limitations.append("외부 행위 정보가 없어 자체 분석과 VirusTotal의 행위 단위 일치 여부를 평가할 수 없습니다.")
    if vt_only_unavailable:
        limitations.append(f"VT에서만 관찰된 {len(vt_only_unavailable)}개 행위는 로컬 부재가 아니라 로컬 검증 불가 상태입니다.")
    return {
        "summary": _deterministic_final_summary(local_report, external, cross),
        **_build_comprehensive_final_sections(local_report, external, cross),
        "agreement_points": agreement_points[:10],
        "difference_points": differences[:10] if external_available else [],
        "external_evidence_points": _external_evidence_points(external),
        "family_interpretation": _canonical_family_interpretation(local_report, external),
        "confidence": "중간" if external_available else "낮음",
        "limitations": limitations,
        "generated_by": "deterministic_guard",
    }


def generate_qwen_user_report(
    evidence: dict[str, Any],
    args: Any,
    *,
    chat_fn: Callable[..., dict[str, Any]],
    parse_fn: Callable[[str], dict[str, Any]],
) -> dict[str, Any]:
    """Freeze local findings, compare them with VT, then ask AI only for synthesis."""
    model = str(args.local_model or "gpt-5.6-luna")

    frozen = evidence.get("local_analysis_frozen")
    domain_analysis = evidence.get("domain_analysis")
    if isinstance(frozen, dict) and isinstance(domain_analysis, dict):
        local_report = dict(frozen)
    else:
        # Backward-compatible fallback for direct callers/tests. Production path
        # freezes this before VirusTotal is fetched.
        domain_analysis = run_domain_reviews(evidence, args, chat_fn=chat_fn, parse_fn=parse_fn)
        evidence["domain_analysis"] = domain_analysis
        unresolved = [
            str(item)
            for review in (domain_analysis.get("reviews") or {}).values()
            if isinstance(review, dict)
            for item in review.get("unresolved") or []
        ]
        local_report = build_report_data(
            evidence,
            verified_claims=domain_analysis.get("verified_claims") or [],
            unresolved=unresolved,
        )
    cross = evidence.get("cross_validation")
    if not isinstance(cross, dict):
        cross = build_external_cross_validation(evidence)
        evidence["cross_validation"] = cross
    external = external_intelligence_summary(evidence)

    context = {
        "local_analysis_frozen": {
            "plain_summary": local_report.get("plain_summary"),
            "family": local_report.get("family"),
            "classification": local_report.get("classification"),
            "risk_level": local_report.get("risk_level"),
            "behaviors": local_report.get("behaviors") or [],
            "unknowns": local_report.get("unknowns") or [],
        },
        "virustotal_external_only": external,
        "deterministic_cross_validation": cross,
    }
    rendered_context = json.dumps(context, ensure_ascii=False, separators=(",", ":"), default=str)
    system = (
        "당신은 방어 목적 악성코드 분석의 최종 비교 설명자다. 반드시 한국어 JSON 객체 하나만 출력하라. "
        "local_analysis_frozen은 VirusTotal을 보기 전에 확정된 자체 분석 결과이며 절대로 수정하거나 덮어쓰지 마라. "
        "VirusTotal은 외부 위협 인텔리전스일 뿐 로컬 관찰 사실이 아니다. VT NOT FOUND를 정상으로 해석하지 마라. "
        "VT 패밀리 후보를 자체 패밀리 확정으로 바꾸지 마라. MATCH/LOCAL_ONLY/VT_ONLY/EXTERNAL_SUPPORT/VT_REPORTED_ONLY 판정은 deterministic_cross_validation을 그대로 따라라. "
        "not_observed를 관찰됨으로 바꾸지 말고, unavailable을 미관찰로 바꾸지 마라. 정적 INFERRED를 동적 OBSERVED처럼 서술하지 마라. "
        "차이가 나는 이유를 설명할 때는 샌드박스 네트워크, C2 활성 여부, 실행 조건, 분석 시점 등의 가능성으로만 표현하고 사실처럼 단정하지 마라. "
        "VirusTotal이 not_configured/not_found/unavailable이면 새로운 변종, 미등록 악성코드, 패밀리 가능성 등을 추측하지 마라. "
        "새로운 행위, IOC, 패밀리, 공격기법을 추가하지 마라. 숨은 사고 과정은 출력하지 마라."
    )
    user = (
        "아래 자체 분석과 VirusTotal 비교 결과를 사용자에게 설명할 최종 종합판정을 작성하라.\n"
        "출력 구조:\n" + json.dumps(_schema(), ensure_ascii=False, separators=(",", ":"))
        + "\n비교 문맥:\n" + rendered_context
    )
    external_comparable = bool(external.get("found"))
    timeout = max(1, min(int(getattr(args, "ai_timeout", 120)), int(getattr(args, "local_report_timeout", 180))))
    response = chat_fn(args.local_base_url, args.local_api_key or "local", model, system, user, timeout)
    raw = str(response.get("content") or "")
    parsed = parse_fn(raw) if response.get("ok") else {}
    schema_valid = _valid(parsed)

    result = local_report
    # VT가 실제로 조회되지 않았거나 파일 정보가 없으면 AI가 빈 외부 정보를 추측으로 채우지 못하게
    # 최종 문장을 결정론적 가드가 직접 생성한다.
    if schema_valid and external_comparable:
        assessment = _fallback_final_assessment(local_report, external, cross)
        assessment["confidence"] = str(parsed.get("confidence") or assessment.get("confidence") or "중간")
        assessment["limitations"] = list(dict.fromkeys([
            *_bounded_strings(parsed.get("limitations")),
            *(assessment.get("limitations") or []),
        ]))[:10]
        assessment["generated_by"] = model
        result["final_assessment"] = assessment
    else:
        result["final_assessment"] = _fallback_final_assessment(local_report, external, cross)
    result["_model"] = model
    result["_report_control"] = {
        "attempts": 1,
        "attempt_limit": 1,
        "context_chars": len(rendered_context),
        "schema_valid": schema_valid,
        "fallback_used": (not schema_valid) or (not external_comparable),
        "stopped_reason": "completed" if (schema_valid and external_comparable) else ("external_unavailable" if not external_comparable else "schema_invalid"),
        "evidence_bound_version": 4,
        "local_analysis_frozen_before_vt": True,
        "vt_used_only_for_final_comparison": True,
    }
    if not schema_valid:
        result["model_error"] = "최종 비교 AI 응답이 스키마 검증을 통과하지 못해 결정론적 비교 설명을 사용했습니다."
    return result
