"""Last-resort semantic downgrades for local-model report candidates."""

from __future__ import annotations

from typing import Any


def _network_observed(evidence: dict[str, Any]) -> bool:
    return any(
        isinstance(item, dict)
        and item.get("event_type") in {"DNS_QUERY", "NETWORK_CONNECT", "HTTP_REQUEST"}
        and bool((item.get("attributes") or {}).get("included_in_conclusion"))
        for item in (evidence.get("common_evidence") or {}).get("events") or []
    )


def _direct_encryption(evidence: dict[str, Any]) -> bool:
    names = {
        str(item.get("name") or "").casefold()
        for item in (evidence.get("dynamic_analysis") or {}).get("signatures") or []
        if isinstance(item, dict) and bool((item.get("attribution") or {}).get("included_in_conclusion"))
    }
    return any(
        marker in name
        for name in names
        for marker in ("encrypts_files", "file_encryption", "ransomware_files", "encrypted_files")
    )


def _dropped_names(evidence: dict[str, Any]) -> set[str]:
    output: set[str] = set()
    for item in (evidence.get("dynamic_analysis") or {}).get("dropped_files") or []:
        if not isinstance(item, dict):
            continue
        values = item.get("name") if isinstance(item.get("name"), list) else [item.get("name")]
        output.update(str(value).casefold() for value in values if value)
    return output


def _replace_language(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace("解压", "압축 해제").replace("细节", "세부 사항")
    if isinstance(value, list):
        return [_replace_language(item) for item in value]
    if isinstance(value, dict):
        return {key: _replace_language(item) for key, item in value.items()}
    return value


def guard_report_semantics(value: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    """Downgrade unsupported outcomes without adding any new sample facts."""
    value = _replace_language(value)
    direct_encryption = _direct_encryption(evidence)
    network_observed = _network_observed(evidence)
    dropped_names = _dropped_names(evidence)

    encryption = value.setdefault("encryption", {})
    if not direct_encryption:
        encryption["status"] = "정적 암호화 기능이 존재할 수 있으나 실제 사용자 파일의 원문→암호문 변환은 미확인"
        encryption["target_files"] = "미확인: 실제 암호화 대상 파일 이벤트 없음"
        encryption["renamed_extension"] = "미확인: 파일명 또는 확장자 변경 이벤트 없음"
        encryption["wallpaper_change"] = "미확인: 바탕화면 변경 이벤트 없음"
    if ".keyfile" in dropped_names:
        encryption["key_handling"] = "동적 분석에서 .keyfile 이름의 파일이 관찰됐지만 실제 암호화 키인지는 미확인"
        encryption["decryption_outlook"] = "조건부 가능: 키 후보 파일과 암호화 파일의 관계를 추가 검증해야 함"
    elif not direct_encryption:
        encryption["key_handling"] = "미확인: 키 생성·저장·전송 증거 없음"
        encryption["decryption_outlook"] = "판정 불가: 실제 암호화 파일과 키 관계가 입증되지 않음"

    summary = str(value.get("plain_summary") or "").strip()
    if not direct_encryption and "실제 사용자 파일 암호화 완료" not in summary:
        summary += " 이번 동적 관찰에서는 실제 사용자 파일 암호화 완료가 확인되지 않았습니다."
    if not network_observed and "외부 네트워크" not in summary:
        summary += " 외부 네트워크 송수신도 관찰되지 않았습니다."
    value["plain_summary"] = summary.strip()

    for behavior in value.get("behaviors") or []:
        if not isinstance(behavior, dict):
            continue
        title = str(behavior.get("title") or "").casefold()
        if any(token in title for token in ("암호화", "랜섬")) and not direct_encryption:
            if str(behavior.get("status") or "").upper() in {"CONFIRMED", "OBSERVED"}:
                behavior["status"] = "INFERRED"
            behavior["description"] = "정적 기능 또는 후보는 존재할 수 있으나 실제 사용자 파일 암호화 완료는 미확인입니다."
        if any(token in title for token in ("외부", "c&c", "c2", "통신", "전송")) and not network_observed:
            if str(behavior.get("status") or "").upper() in {"CONFIRMED", "OBSERVED"}:
                behavior["status"] = "UNRESOLVED"
            behavior["description"] = "네트워크 관련 코드 후보와 실제 외부 송수신을 구분해야 하며, 이번 실행에서는 귀속 가능한 통신이 관찰되지 않았습니다."

    if not direct_encryption:
        impacts = [
            str(item) for item in value.get("user_impact") or []
            if not any(token in str(item) for token in ("영구적 손실", "복호화 불가", "복구 불가능", "접근 불가"))
        ]
        impacts.insert(0, "파일 암호화 기능에 따른 데이터 손실 위험은 있으나 실제 완료 여부는 미확인")
        value["user_impact"] = list(dict.fromkeys(impacts))
    return value
