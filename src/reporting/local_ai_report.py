"""Render the validated, structured report authored by the local Qwen model."""

from __future__ import annotations

from typing import Any, Callable

from .human_report import build_analysis_details, external_intelligence_summary


def _text(value: Any, default: str = "미확인") -> str:
    value = str(value or "").strip()
    return value if value else default


def _list(value: Any, limit: int = 20) -> list[Any]:
    return value[:limit] if isinstance(value, list) else []


def has_local_ai_report(evidence: dict[str, Any]) -> bool:
    local_ai = evidence.get("local_ai") or {}
    report = local_ai.get("user_report") or ((local_ai.get("pass_3") or {}).get("user_report"))
    control = report.get("_report_control") if isinstance(report, dict) else None
    return (
        isinstance(report, dict)
        and bool(report.get("plain_summary"))
        and isinstance(control, dict)
        and control.get("evidence_bound_version") in {3, 4}
    )


def render_local_ai_report(
    evidence: dict[str, Any],
    *,
    fallback: Callable[[dict[str, Any]], str],
) -> str:
    """Use Qwen-authored fields; fall back only when generation/validation failed."""
    validation = evidence.get("ai_validation") or {}
    local_ai = evidence.get("local_ai") or {}
    final_stage = (local_ai.get("pass_3") or {})
    report = local_ai.get("user_report") or final_stage.get("user_report")
    if not has_local_ai_report(evidence):
        return fallback(evidence)
    if validation.get("status") == "rejected":
        return fallback(evidence)

    family = report.get("family") or {}
    encryption = report.get("encryption") or {}
    sample = evidence.get("sample") or {}
    dynamic = evidence.get("dynamic_analysis") or {}
    member = (((evidence.get("static_analysis") or {}).get("archive_analysis") or {}).get("selected_member") or {})
    model = report.get("_model") or final_stage.get("_model") or local_ai.get("model") or "로컬 모델"
    details = build_analysis_details(evidence)

    lines = [
        "# 악성코드 사용자 분석 보고서",
        "",
        f"- **보고서 작성:** 로컬 AI `{model}` 제안 + 결정론적 evidence-bound renderer v4",
        "- **근거 수집:** 정적 분석 · capa · Ghidra · CAPE",
        "- **작성 원칙:** 모델 자유서술을 직접 사용하지 않고 검증된 현재 샘플 증거만 렌더링",
        "",
        "## 1. 결론",
        "",
        f"- **악성코드/패밀리:** `{_text(family.get('name'))}`",
        f"- **패밀리 신뢰도:** `{_text(family.get('confidence'))}`",
        f"- **분류:** {_text(report.get('classification'))}",
        f"- **위험도:** `{_text(report.get('risk_level'))}`",
        "",
        _text(report.get("plain_summary")),
        "",
        "### 패밀리 판정 근거",
        "",
    ]
    narrative = _list(report.get("analysis_narrative"), 10)
    if narrative:
        lines[-2:-2] = [
            "### 자체 분석 상세 해석",
            "",
            *[_text(item) for item in narrative],
            "",
            "### 위험도 산정 근거",
            "",
            *[f"- {_text(item)}" for item in _list(report.get("risk_rationale"), 15)],
            "",
        ]
    basis = _list(family.get("basis"), 10)
    lines.extend(f"- {_text(item)}" for item in basis)
    if not basis:
        lines.append("- 미확인")

    fields = [
        ("암호화 실행 여부", "status"),
        ("암호화 방식·API", "method"),
        ("키 생성·보관", "key_handling"),
        ("암호화 대상 파일", "target_files"),
        ("암호화 후 파일명·확장자", "renamed_extension"),
        ("랜섬노트·안내 화면", "ransom_message"),
        ("바탕화면 변경", "wallpaper_change"),
        ("복호화 가능성", "decryption_outlook"),
    ]
    lines += [
        "",
        "## 2. 파일 암호화와 복구 가능성",
        "",
        "| 확인 항목 | 분석 결과 |",
        "|---|---|",
    ]
    lines.extend(f"| {label} | {_text(encryption.get(key))} |" for label, key in fields)

    lines += ["", "## 3. 핵심 악성 기능", ""]
    behaviors = _list(report.get("behaviors"), 16)
    for item in behaviors:
        if not isinstance(item, dict):
            continue
        title = _text(item.get("title"), "행위")
        status = _text(item.get("status"))
        description = _text(item.get("description"))
        ids = ", ".join(f"`{value}`" for value in _list(item.get("evidence_ids"), 8))
        suffix = f" 근거: {ids}" if ids else ""
        lines.append(f"- **{title} — {status}:** {description}{suffix}")
    if not behaviors:
        lines.append("- 핵심 악성 기능을 요약할 수 없습니다.")

    lines += ["", "## 4. 예상 동작 순서", ""]
    flow = _list(report.get("execution_flow"), 15)
    lines.extend(f"{index}. {_text(item)}" for index, item in enumerate(flow, 1))
    if not flow:
        lines.append("1. 동작 순서를 복원하지 못했습니다.")

    lines += ["", "## 5. 사용자에게 미치는 영향", ""]
    impacts = _list(report.get("user_impact"), 15)
    lines.extend(f"- {_text(item)}" for item in impacts)
    if not impacts:
        lines.append("- 사용자 영향이 미확인입니다.")

    lines += ["", "## 6. 주요 IOC와 생성 파일", ""]
    iocs = _list(report.get("iocs"), 20)
    for item in iocs:
        if isinstance(item, dict):
            kind = _text(item.get("type"), "IOC")
            value = _text(item.get("value"))
            lines.append(f"- **{kind}:** {value}")
        else:
            lines.append(f"- {_text(item)}")
    if not iocs:
        lines.append("- 보고 가능한 IOC가 없습니다.")

    external = external_intelligence_summary(evidence)
    cross = report.get("cross_validation") or evidence.get("cross_validation") or {}
    lines += ["", "## 7. 자체 분석 ↔ VirusTotal 독립 비교", ""]
    if external.get("status") in {"completed", "found", "not_found"}:
        if external.get("found"):
            stats = external.get("stats") or {}
            lines += [
                "### VirusTotal 외부 정보",
                "",
                f"- 조회 SHA-256: `{external.get('lookup_hash', '-')}`",
                f"- 탐지 통계: 악성 `{stats.get('malicious', 0)}` / 의심 `{stats.get('suspicious', 0)}` / 정상 `{stats.get('harmless', 0)}` / 미탐 `{stats.get('undetected', 0)}`",
                f"- 외부 패밀리 후보: `{external.get('family_candidate') or '미확인'}`",
                f"- Behaviour 조회 상태: `{external.get('behaviour_status') or '미확인'}`",
                f"- MITRE 조회 상태: `{external.get('mitre_status') or '미확인'}`",
                f"- 분석 링크: {external.get('analysis_link') or '미확인'}",
                "- VirusTotal 정보는 자체 분석 결과를 생성하거나 수정하는 데 사용하지 않았습니다.",
            ]

            threat_names = [
                f"{_text(item.get('name'))} ({int(item.get('count') or 0)})"
                for item in external.get("threat_names") or [] if isinstance(item, dict)
            ]
            engines = [item for item in external.get("engine_detections") or [] if isinstance(item, dict)]
            if engines:
                lines += ["", "#### VT 엔진별 탐지명", "", "| 엔진 | 분류 | 탐지명 | 버전 / 업데이트 |", "|---|---|---|---|"]
                for item in engines[:40]:
                    version = " / ".join(
                        _text(value, "-") for value in (item.get("engine_version"), item.get("engine_update"))
                    )
                    result_name = _text(item.get("result"), "-").replace("|", "\\|")
                    lines.append(
                        f"| {_text(item.get('engine'), '-')} | {_text(item.get('category'), '-')} | "
                        f"{result_name} | {version} |"
                    )
            detail = external.get("behavior_detail") if isinstance(external.get("behavior_detail"), dict) else {}
            features = external.get("behavior_features") if isinstance(external.get("behavior_features"), dict) else {}
            lines += [
                "",
                "#### VT 파일 평판 상세",
                "",
                f"- 대표 파일명: `{_text(external.get('meaningful_name'), '미확인')}`",
                f"- 알려진 파일명: {', '.join(f'`{_text(item)}`' for item in (external.get('known_names') or [])[:10]) or '없음'}",
                f"- 파일 형식: `{_text(external.get('type_description'), '미확인')}` / 평판 점수: `{_text(external.get('reputation'), '미확인')}`",
                f"- 최초 제출: `{_text(external.get('first_submission_time'), '미확인')}`",
                f"- 최근 분석: `{_text(external.get('last_analysis_time'), '미확인')}`",
                f"- 주요 위협명 집계: {', '.join(threat_names) or '미확인'}",
                f"- 기타 엔진 상태: 시간초과 `{stats.get('timeout', 0)}` / 실패 `{stats.get('failure', 0)}` / 형식 미지원 `{stats.get('type_unsupported', 0)}`",
                "",
                "#### VT 외부 샌드박스 행위",
                "",
                "| 행위 | 관찰 | 건수 | 예시 |",
                "|---|---|---:|---|",
            ]
            feature_labels = {
                "file_write": "파일 쓰기", "file_delete": "파일 삭제",
                "process_create": "프로세스 생성", "process_injection": "프로세스 인젝션",
                "service_create": "서비스 생성", "registry_modification": "레지스트리 변경",
                "network_communication": "네트워크 통신",
                "cryptographic_activity": "암호화 관련 동작", "file_encryption": "파일 암호화",
            }
            for key, label in feature_labels.items():
                item = features.get(key) if isinstance(features.get(key), dict) else {}
                examples = "; ".join(_text(value).replace("|", "\\|") for value in (item.get("examples") or [])[:3])
                lines.append(f"| {label} | `{'예' if item.get('observed') else '아니요'}` | {int(item.get('count') or 0)} | {examples or '-'} |")
            verdicts = [*(_list(detail.get("verdict_labels"), 5)), *(_list(detail.get("verdicts"), 5))]
            lines += [
                "",
                f"- 외부 샌드박스 판정: `{', '.join(_text(item) for item in verdicts) or '미확인'}`",
                f"- 외부 판정 신뢰도: `{_text(detail.get('verdict_confidence'), '미확인')}`",
                f"- 메모리 패턴 도메인: {', '.join(f'`{_text(item)}`' for item in _list(detail.get('domains'), 10)) or '없음'}",
                f"- 메모리 패턴 URL: {', '.join(f'`{_text(item)}`' for item in _list(detail.get('urls'), 10)) or '없음'}",
                "",
                "#### VT에서 보고된 실행 명령",
                "",
            ]
            commands = _list(detail.get("command_executions"), 10)
            lines.extend(f"- `{_text(item)}`" for item in commands)
            if not commands:
                lines.append("- 없음")
            signatures = [item for item in detail.get("signatures") or [] if isinstance(item, dict)]
            if signatures:
                lines += ["", "#### VT 행위·정적 시그니처", "", "| 시그니처 | 분류 | 주요 매치 |", "|---|---|---|"]
                for item in signatures[:15]:
                    match_data = "; ".join(_text(value).replace("|", "\\|") for value in (item.get("match_data") or [])[:3])
                    lines.append(f"| {_text(item.get('name'), '-')} | {_text(item.get('description'), '-')} | {match_data or '-'} |")
        else:
            lines += [
                "- VirusTotal에 기존 자료가 없습니다. `VT NOT FOUND`는 정상 판정이 아닙니다.",
                "- 샘플 파일은 VirusTotal에 업로드하지 않고 SHA-256 조회만 수행했습니다.",
            ]
    elif external.get("status") == "not_configured":
        lines.append("- VirusTotal API 키가 설정되지 않아 외부 평판 조회를 수행하지 않았습니다.")
    elif external.get("status") == "disabled":
        lines.append("- VirusTotal 조회가 비활성화되었습니다.")
    else:
        lines.append(f"- VirusTotal 조회 상태: `{external.get('status', 'not_available')}`")

    items = [item for item in cross.get("items") or [] if isinstance(item, dict)]
    if items:
        lines += [
            "",
            "### 행위 단위 교차검증",
            "",
            "| 행위 | 자체 분석 | VirusTotal | 판정 |",
            "|---|---|---|---|",
        ]
        for item in items:
            lines.append(
                f"| {_text(item.get('label'), _text(item.get('capability'), '-'))} | "
                f"`{_text(item.get('local'), '-')}` | `{_text(item.get('virustotal'), '-')}` | `{_text(item.get('result'), '-')}` |"
            )
        lines += [
            "",
            "> `VT_ONLY` 또는 `LOCAL_ONLY`는 어느 한쪽을 정답으로 덮어쓰는 의미가 아닙니다. 서로 다른 분석 환경에서 관찰 범위가 달랐음을 표시합니다.",
        ]

    related = external.get("related_files") or []
    if related:
        lines += ["", "### 관련 파일 VirusTotal 조회", "", "| 역할 | 파일 | 상태 | 악성 | 의심 | 패밀리 후보 |", "|---|---|---|---:|---:|---|"]
        for item in related[:10]:
            stats = item.get("last_analysis_stats") if isinstance(item.get("last_analysis_stats"), dict) else {}
            lines.append(
                f"| `{_text(item.get('role'), '-')}` | `{_text(item.get('source_name') or item.get('lookup_hash'), '-')}` | "
                f"`{_text(item.get('status'), '-')}` | {int(stats.get('malicious') or 0)} | {int(stats.get('suspicious') or 0)} | "
                f"`{_text(item.get('family_candidate'), '미확인')}` |"
            )

    final_assessment = report.get("final_assessment") or {}
    lines += ["", "## 8. AI 최종 종합판정", ""]
    if isinstance(final_assessment, dict) and final_assessment.get("summary"):
        lines += [
            f"- **종합 신뢰도:** `{_text(final_assessment.get('confidence'), '낮음')}`",
            f"- **작성:** `{_text(final_assessment.get('generated_by'), model)}`",
            "",
            _text(final_assessment.get("summary")),
            "",
            "### 일치한 핵심",
            "",
        ]
        executive = _list(final_assessment.get("executive_assessment"), 10)
        synthesis = _list(final_assessment.get("evidence_synthesis"), 15)
        behavior_chain = _list(final_assessment.get("likely_behavior_chain"), 15)
        risk_interpretation = _list(final_assessment.get("risk_interpretation"), 10)
        comprehensive = []
        if executive or synthesis or behavior_chain or risk_interpretation:
            comprehensive = [
                "### 종합 결론",
                "",
                f"**{_text(final_assessment.get('overall_verdict'), '추가 검증 필요')}**",
                "",
                *[_text(item) for item in executive],
                "",
                "### 로컬·외부 증거 종합",
                "",
                *[f"- {_text(item)}" for item in synthesis],
                "",
                "### 가능성이 높은 행위 체인",
                "",
                *[f"{index}. {_text(item)}" for index, item in enumerate(behavior_chain, 1)],
                "",
                "### 위험도 해석",
                "",
                *[f"- {_text(item)}" for item in risk_interpretation],
                "",
                "### 분석가 최종 결론",
                "",
                _text(final_assessment.get("analyst_conclusion")),
                "",
            ]
            lines[-2:-2] = comprehensive
        external_points = _list(final_assessment.get("external_evidence_points"), 10)
        if external_points:
            lines[-2:-2] = [
                "### VT 근거를 반영한 핵심 분석",
                "",
                *(f"- {_text(item)}" for item in external_points),
                "",
            ]
        agreements = _list(final_assessment.get("agreement_points"), 10)
        lines.extend(f"- {_text(item)}" for item in agreements)
        if not agreements:
            lines.append("- 명확한 일치 항목 없음")
        lines += ["", "### 차이와 해석", ""]
        differences = _list(final_assessment.get("difference_points"), 10)
        lines.extend(f"- {_text(item)}" for item in differences)
        if not differences:
            lines.append("- 별도 차이 설명 없음")
        lines += [
            "",
            "### 패밀리 해석",
            "",
            f"- {_text(final_assessment.get('family_interpretation'))}",
            "",
            "### 한계",
            "",
        ]
        limitations = _list(final_assessment.get("limitations"), 10)
        lines.extend(f"- {_text(item)}" for item in limitations)
    else:
        lines.append("- 최종 비교 AI 결과가 생성되지 않았습니다.")

    lines += ["", "## 9. 확인하지 못한 내용", ""]
    unknowns = _list(report.get("unknowns"), 20)
    lines.extend(f"- {_text(item)}" for item in unknowns)
    if not unknowns:
        lines.append("- 없음")

    lines += [
        "",
        "## 10. 분석 범위",
        "",
        f"- 입력 파일: `{_text(sample.get('name'), '-')}`",
        f"- 입력 파일 SHA-256: `{_text((sample.get('hashes') or {}).get('sha256'), '-')}`",
        f"- 내부 실행 파일: `{_text(member.get('name'), '-')}`",
        f"- 내부 EXE SHA-256: `{_text((member.get('hashes') or {}).get('sha256'), '-')}`",
        f"- CAPE 작업 ID: `{_text(dynamic.get('task_id'), '-')}`",
        f"- CAPE 실행 시간: `{_text(dynamic.get('duration'), '-')}초`",
        f"- AI 증거 검증: `{_text(validation.get('status'), 'not_run')}`",
        "",
        "원시 CAPE 시그니처, 전체 프로세스 목록, Ghidra 출력과 AI JSON은 본문에 반복하지 않고 증거 JSON에 보존됩니다.",
        "",
    ]
    sample_detail = details.get("sample") or {}
    static_detail = details.get("static") or {}
    dynamic_detail = details.get("dynamic") or {}
    metrics = details.get("evidence_metrics") or {}

    lines += [
        "",
        "## 11. 분석 대상 상세 식별",
        "",
        "| 항목 | 값 |",
        "|---|---|",
        f"| 외부 파일명 | `{_text(sample_detail.get('name'), '-')}` |",
        f"| 외부 파일 크기 | `{_text(sample_detail.get('size'), '-')} bytes` |",
        f"| 외부 SHA-256 | `{_text(sample_detail.get('sha256'), '-')}` |",
        f"| 외부 형식 | `{_text(sample_detail.get('detected_type'), '-')}` |",
        f"| 내부 파일명 | `{_text(sample_detail.get('inner_name'), '-')}` |",
        f"| 내부 파일 크기 | `{_text(sample_detail.get('inner_size'), '-')} bytes` |",
        f"| 내부 SHA-256 | `{_text(sample_detail.get('inner_sha256'), '-')}` |",
        f"| 내부 형식 | `{_text(sample_detail.get('inner_type'), '-')}` |",
        "",
        "## 12. 상세 정적 분석",
        "",
        "| 항목 | 값 |",
        "|---|---|",
        f"| PE 형식 / Machine | `{_text(static_detail.get('format'), '-')}` / `{_text(static_detail.get('machine'), '-')}` |",
        f"| DLL 플래그 | `{'예' if static_detail.get('is_dll') else '아니요'}` |",
        f"| Entry point / Image base | `{_text(static_detail.get('entry_point'), '-')}` / `{_text(static_detail.get('image_base'), '-')}` |",
        f"| Characteristics | `{_text(static_detail.get('characteristics'), '-')}` |",
        f"| 엔트로피 / imphash | `{_text(static_detail.get('entropy'), '-')}` / `{_text(static_detail.get('imphash'), '-')}` |",
        f"| Import 모듈 / 심볼 | `{static_detail.get('import_module_count', 0)}` / `{static_detail.get('import_symbol_count', 0)}` |",
        f"| capa 규칙 | `{static_detail.get('capa_rule_count', 0)}`개 |",
        f"| Ghidra | `{_text(static_detail.get('ghidra_provider'), '-')}` · `{_text(static_detail.get('ghidra_language'), '-')}` · `{_text(static_detail.get('ghidra_compiler'), '-')}` |",
        "",
        "### Import 요약",
        "",
        "| 모듈 | 심볼 수 | 주요 심볼 |",
        "|---|---:|---|",
    ]
    for item in _list(static_detail.get("imports"), 30):
        symbols = ", ".join(_list(item.get("symbols"), 20))
        lines.append(f"| `{_text(item.get('module'), '-')}` | {int(item.get('symbol_count') or 0)} | `{symbols or '-'}` |")
    if not static_detail.get("imports"):
        lines.append("| 확인된 Import 없음 | 0 | - |")

    lines += ["", "### PE 섹션", "", "| 섹션 | Virtual size | Raw size | Entropy |", "|---|---:|---:|---:|"]
    for item in _list(static_detail.get("sections"), 20):
        lines.append(
            f"| `{_text(item.get('name'), '-')}` | {_text(item.get('virtual_size'), '-')} | "
            f"{_text(item.get('raw_size'), '-')} | {_text(item.get('entropy'), '-')} |"
        )
    if not static_detail.get("sections"):
        lines.append("| 섹션 정보 없음 | - | - | - |")

    lines += ["", "### 정적 후보 기능", ""]
    for item in _list(static_detail.get("findings"), 30):
        matched = ", ".join(_list(item.get("matched"), 20)) or "세부 문자열 없음"
        lines.append(
            f"- **{_text(item.get('category'), '미분류')} — {_text(item.get('status'), 'candidate_only')}:** "
            f"`{matched}`" + (f" · 근거 `{item.get('evidence_id')}`" if item.get("evidence_id") else "")
        )
    if not static_detail.get("findings"):
        lines.append("- 보고 가능한 정적 후보 기능이 없습니다.")

    counts = dynamic_detail.get("network_counts") or {}
    lines += [
        "",
        "## 13. 동적 분석 진단",
        "",
        "| 항목 | 값 |",
        "|---|---|",
        f"| 상태 / Task | `{_text(dynamic_detail.get('status'), 'not_run')}` / `{_text(dynamic_detail.get('task_id'), '-')}` |",
        f"| 패키지 / 실행 시간 | `{_text(dynamic_detail.get('package'), '-')}` / `{_text(dynamic_detail.get('duration'), '-')}초` |",
        f"| 제출 해시 검증 | `{'일치' if dynamic_detail.get('sample_hash_verified') else '미확인 또는 불일치'}` |",
        f"| 프로세스 / 시그니처 / 드롭 파일 | `{dynamic_detail.get('process_count', 0)}` / `{dynamic_detail.get('signature_count', 0)}` / `{dynamic_detail.get('dropped_count', 0)}` |",
        f"| Hosts / Domains / DNS | `{counts.get('hosts', 0)}` / `{counts.get('domains', 0)}` / `{counts.get('dns', 0)}` |",
        f"| HTTP / TCP / UDP / SMTP | `{counts.get('http', 0)}` / `{counts.get('tcp', 0)}` / `{counts.get('udp', 0)}` / `{counts.get('smtp', 0)}` |",
        "",
        "### 분석 오류",
        "",
    ]
    errors = _list(dynamic_detail.get("errors"), 20)
    lines.extend(f"- `{_text(item)}`" for item in errors)
    if not errors:
        lines.append("- 보고된 치명적 분석 오류가 없습니다.")

    lines += [
        "",
        "## 14. 증거 인벤토리와 AI 처리 상태",
        "",
        "| 증거 종류 | 수량/상태 |",
        "|---|---|",
        f"| Claims | `{metrics.get('claims', 0)}` |",
        f"| Events | `{metrics.get('events', 0)}` |",
        f"| Relations | `{metrics.get('relations', 0)}` |",
        f"| ATT&CK 후보 | `{metrics.get('attack_candidates', 0)}` |",
        f"| 검증된 AI 참조 | `{metrics.get('validated_references', 0)}` |",
        f"| AI 검증 상태 | `{_text(metrics.get('validation_status'), 'not_run')}` |",
        "",
        "### AI 단계별 상태",
        "",
        "| 단계 | 상태 | 세부 정보 |",
        "|---|---|---|",
    ]
    for item in details.get("ai_stages") or []:
        lines.append(f"| `{_text(item.get('stage'), '-')}` | `{_text(item.get('status'), '-')}` | {_text(item.get('detail'), '-')} |")

    lines += ["", "## 15. 대응 권고", ""]
    recommendations = _list(details.get("recommendations"), 10)
    lines.extend(f"{index}. {_text(item)}" for index, item in enumerate(recommendations, 1))
    if not recommendations:
        lines.append("1. 추가 대응 권고가 없습니다.")
    lines += [
        "",
        "> 권고사항은 현재 증거에 따른 방어 목적 우선순위이며, 운영 환경 변경 전 담당자의 검토가 필요합니다.",
        "",
    ]
    return "\n".join(lines)
