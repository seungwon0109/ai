from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    LongTable,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


_FONT_REGULAR = "MalgunGothic"
_FONT_BOLD = "MalgunGothicBold"


def _register_fonts() -> tuple[str, str]:
    regular = Path(r"C:\Windows\Fonts\malgun.ttf")
    bold = Path(r"C:\Windows\Fonts\malgunbd.ttf")
    if regular.is_file() and bold.is_file():
        if _FONT_REGULAR not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(_FONT_REGULAR, str(regular)))
        if _FONT_BOLD not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(_FONT_BOLD, str(bold)))
        return _FONT_REGULAR, _FONT_BOLD
    return "Helvetica", "Helvetica-Bold"


def _text(value: Any) -> str:
    if value is None or value == "":
        return "-"
    if isinstance(value, bool):
        return "예" if value else "아니요"
    return str(value)


def _paragraph(value: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(_text(value)).replace("\n", "<br/>"), style)


def _styles() -> dict[str, ParagraphStyle]:
    regular, bold = _register_fonts()
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle", parent=base["Title"], fontName=bold, fontSize=24,
            leading=31, textColor=colors.HexColor("#172033"), alignment=TA_LEFT,
            spaceAfter=7 * mm, wordWrap="CJK",
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle", parent=base["BodyText"], fontName=regular, fontSize=9,
            leading=14, textColor=colors.HexColor("#667085"), spaceAfter=6 * mm,
            wordWrap="CJK",
        ),
        "h1": ParagraphStyle(
            "SectionHeading", parent=base["Heading1"], fontName=bold, fontSize=16,
            leading=22, textColor=colors.HexColor("#172033"), spaceBefore=7 * mm,
            spaceAfter=3 * mm, keepWithNext=True, wordWrap="CJK",
        ),
        "h2": ParagraphStyle(
            "SubHeading", parent=base["Heading2"], fontName=bold, fontSize=11.5,
            leading=17, textColor=colors.HexColor("#25324A"), spaceBefore=4 * mm,
            spaceAfter=2 * mm, keepWithNext=True, wordWrap="CJK",
        ),
        "body": ParagraphStyle(
            "BodyCJK", parent=base["BodyText"], fontName=regular, fontSize=8.7,
            leading=14, textColor=colors.HexColor("#39465B"), spaceAfter=2.2 * mm,
            wordWrap="CJK",
        ),
        "small": ParagraphStyle(
            "SmallCJK", parent=base["BodyText"], fontName=regular, fontSize=7.2,
            leading=10.5, textColor=colors.HexColor("#475467"), wordWrap="CJK",
        ),
        "table_header": ParagraphStyle(
            "TableHeader", parent=base["BodyText"], fontName=bold, fontSize=7.2,
            leading=10, textColor=colors.white, alignment=TA_LEFT, wordWrap="CJK",
        ),
        "table": ParagraphStyle(
            "TableCell", parent=base["BodyText"], fontName=regular, fontSize=7.1,
            leading=10, textColor=colors.HexColor("#27364D"), wordWrap="CJK",
        ),
        "metric": ParagraphStyle(
            "Metric", parent=base["BodyText"], fontName=bold, fontSize=8,
            leading=11, textColor=colors.HexColor("#172033"), alignment=TA_CENTER,
            wordWrap="CJK",
        ),
        "footer": ParagraphStyle(
            "Footer", parent=base["BodyText"], fontName=regular, fontSize=7,
            textColor=colors.HexColor("#7B8798"), alignment=TA_CENTER,
        ),
    }


def _table(
    rows: list[list[Any]],
    styles: dict[str, ParagraphStyle],
    widths: list[float] | None = None,
    header: bool = True,
    font_size: float = 7.1,
) -> LongTable:
    available = landscape(A4)[0] - 30 * mm
    if widths:
        col_widths = [available * value for value in widths]
    else:
        count = max(1, len(rows[0]) if rows else 1)
        col_widths = [available / count] * count
    converted: list[list[Paragraph]] = []
    for row_index, row in enumerate(rows):
        style = styles["table_header"] if header and row_index == 0 else styles["table"]
        converted.append([_paragraph(value, style) for value in row])
    table = LongTable(converted, colWidths=col_widths, repeatRows=1 if header else 0, hAlign="LEFT")
    commands: list[tuple[Any, ...]] = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#DCE3ED")),
        ("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1), [colors.white, colors.HexColor("#F7F9FC")]),
    ]
    if header:
        commands.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#26364D")))
    table.setStyle(TableStyle(commands))
    return table


def _section(story: list[Any], title: str, styles: dict[str, ParagraphStyle]) -> None:
    story.append(Paragraph(escape(title), styles["h1"]))


def _subsection(story: list[Any], title: str, styles: dict[str, ParagraphStyle]) -> None:
    story.append(Paragraph(escape(title), styles["h2"]))


def _paragraphs(story: list[Any], values: list[Any] | None, styles: dict[str, ParagraphStyle], empty: str) -> None:
    usable = [value for value in (values or []) if value not in (None, "")]
    if not usable:
        story.append(_paragraph(empty, styles["body"]))
        return
    for value in usable:
        story.append(_paragraph(value, styles["body"]))


def _bullets(story: list[Any], values: list[Any] | None, styles: dict[str, ParagraphStyle], empty: str) -> None:
    usable = [value for value in (values or []) if value not in (None, "")]
    if not usable:
        usable = [empty]
    for value in usable:
        row = Table(
            [[_paragraph("•", styles["body"]), _paragraph(value, styles["body"])]],
            colWidths=[5 * mm, landscape(A4)[0] - 35 * mm],
        )
        row.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 2),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))
        story.append(row)


def _metric_table(values: list[tuple[str, Any]], styles: dict[str, ParagraphStyle]) -> Table:
    available = landscape(A4)[0] - 30 * mm
    cells = [_paragraph(f"{label}\n{_text(value)}", styles["metric"]) for label, value in values]
    table = Table([cells], colWidths=[available / len(cells)] * len(cells), hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EEF2F7")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#DCE3ED")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.white),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return table


def _on_page(canvas: Any, doc: BaseDocTemplate, styles: dict[str, ParagraphStyle], sample_name: str) -> None:
    canvas.saveState()
    width, _ = landscape(A4)
    canvas.setStrokeColor(colors.HexColor("#DCE3ED"))
    canvas.line(15 * mm, 12 * mm, width - 15 * mm, 12 * mm)
    footer = _paragraph(f"{sample_name}  |  악성코드 자동 분석  |  {doc.page}", styles["footer"])
    footer.wrapOn(canvas, width - 30 * mm, 8 * mm)
    footer.drawOn(canvas, 15 * mm, 5.5 * mm)
    canvas.restoreState()


def render_analysis_pdf(result: dict[str, Any], output_path: Path) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    styles = _styles()
    details = result.get("details") or {}
    sample = details.get("sample") or result.get("sample") or {}
    static = details.get("static") or {}
    dynamic = details.get("dynamic") or {}
    local = result.get("local") or {}
    vt = result.get("virustotal") or {}
    cross = result.get("cross_validation") or {}
    final = result.get("final_assessment") or {}
    sample_name = _text(sample.get("name") or sample.get("inner_name") or "분석 샘플")

    page_width, page_height = landscape(A4)
    doc = BaseDocTemplate(
        str(output_path), pagesize=landscape(A4), leftMargin=15 * mm, rightMargin=15 * mm,
        topMargin=15 * mm, bottomMargin=18 * mm, title="악성코드 자동 분석 최종 보고서",
        author="Malware Analysis Pipeline",
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="report")
    doc.addPageTemplates([
        PageTemplate(
            id="main", frames=[frame],
            onPage=lambda canvas, current_doc: _on_page(canvas, current_doc, styles, sample_name),
        )
    ])

    story: list[Any] = [
        Paragraph("악성코드 자동 분석 최종 보고서", styles["title"]),
        Paragraph(
            escape(f"분석 대상: {sample_name}  |  생성: {datetime.now():%Y-%m-%d %H:%M:%S}  |  로컬 분석과 VirusTotal은 독립 근거로 구분"),
            styles["subtitle"],
        ),
    ]

    _section(story, "1. CAPE 실행 요약", styles)
    story.append(_metric_table([
        ("상태", dynamic.get("status") or "not_run"),
        ("Task", dynamic.get("task_id")),
        ("Package", dynamic.get("package")),
        ("실행", f"{_text(dynamic.get('duration'))}초"),
        ("해시", "일치" if dynamic.get("sample_hash_verified") else "미확인"),
        ("프로세스", dynamic.get("process_count") or 0),
        ("시그니처", dynamic.get("signature_count") or 0),
        ("Dropped", dynamic.get("dropped_count") or 0),
    ], styles))
    warnings: list[str] = []
    if dynamic.get("timed_out"):
        warnings.append("설정된 실행 시간이 만료되어 일부 행위가 관찰되지 않았을 수 있습니다.")
    warnings.extend(_text(item) for item in (dynamic.get("errors") or []))
    if warnings:
        _subsection(story, "실행 주의사항", styles)
        _bullets(story, warnings, styles, "별도 주의사항 없음")

    _section(story, "2. 자체 분석 ↔ VirusTotal 비교", styles)
    compare_rows = [["행위", "자체 분석", "VirusTotal", "판정"]]
    for item in cross.get("items") or []:
        compare_rows.append([item.get("label"), item.get("local"), item.get("virustotal"), item.get("result")])
    if len(compare_rows) == 1:
        compare_rows.append(["비교 항목 없음", "-", "-", "UNAVAILABLE"])
    story.append(_table(compare_rows, styles, [0.18, 0.27, 0.27, 0.28]))

    _section(story, "3. MITRE ATT&CK 후보 비교", styles)
    story.append(_paragraph("로컬 증거와 VirusTotal 외부 매핑에서 파생된 후보입니다. 공격 성공 또는 전체 공격 경로 확정을 의미하지 않습니다.", styles["body"]))
    attack_rows = [["Technique", "이름", "Local", "VT", "판정", "신뢰도"]]
    for item in result.get("attack_candidates") or []:
        attack_rows.append([
            item.get("technique_id"), item.get("name"), item.get("local"),
            item.get("virustotal"), item.get("result"), item.get("confidence"),
        ])
    if len(attack_rows) == 1:
        attack_rows.append(["-", "후보 없음", "NOT_MAPPED", "UNAVAILABLE", "UNAVAILABLE", "-"])
    story.append(_table(attack_rows, styles, [0.10, 0.22, 0.16, 0.14, 0.22, 0.16]))
    story.append(PageBreak())

    _section(story, "4. 자체 AI 분석", styles)
    story.append(_metric_table([
        ("위험도", local.get("risk_level") or "미확인"),
        ("분류", local.get("classification") or "미확인"),
        ("패밀리", (local.get("family") or {}).get("name") or "미확인"),
        ("CAPE", (local.get("dynamic") or {}).get("status") or "not_run"),
    ], styles))
    story.append(_paragraph(local.get("summary") or "자체 분석 요약이 생성되지 않았습니다.", styles["body"]))
    _subsection(story, "자체 분석 상세 해석", styles)
    _paragraphs(story, local.get("analysis_narrative"), styles, "상세 자체 분석이 생성되지 않았습니다.")
    _subsection(story, "위험도 산정 근거", styles)
    _bullets(story, local.get("risk_rationale"), styles, "위험도 근거가 생성되지 않았습니다.")
    _subsection(story, "핵심 행위 및 증거", styles)
    local_behaviors = []
    for item in local.get("behaviors") or []:
        if isinstance(item, dict):
            local_behaviors.append(f"{_text(item.get('title'))} | {_text(item.get('status'))} | {_text(item.get('description'))}")
        else:
            local_behaviors.append(_text(item))
    _bullets(story, local_behaviors, styles, "핵심 행위 요약 없음")

    _section(story, "5. VirusTotal 외부 위협 인텔리전스", styles)
    stats = vt.get("stats") or {}
    story.append(_metric_table([
        ("악성", stats.get("malicious") or 0),
        ("의심", stats.get("suspicious") or 0),
        ("정상", stats.get("harmless") or 0),
        ("미탐", stats.get("undetected") or 0),
        ("패밀리 후보", vt.get("family_candidate") or "미확인"),
    ], styles))
    story.append(_paragraph(
        f"Behaviour {_text(vt.get('behaviour_status'))} | MITRE {_text(vt.get('mitre_status'))} | SHA-256 해시 조회만 사용",
        styles["body"],
    ))
    _subsection(story, "태그", styles)
    _bullets(story, vt.get("tags"), styles, "VT 태그 없음")
    features = vt.get("behavior_features") or {}
    labels = {
        "file_write": "파일 쓰기", "file_delete": "파일 삭제", "process_create": "프로세스 생성",
        "process_injection": "프로세스 인젝션", "service_create": "서비스 생성",
        "registry_modification": "레지스트리 변경", "network_communication": "네트워크 통신",
        "cryptographic_activity": "암호화 관련 동작", "file_encryption": "파일 암호화",
    }
    observed = []
    for key, label in labels.items():
        value = features.get(key) or {}
        if value.get("observed"):
            examples = "; ".join(_text(x) for x in (value.get("examples") or [])[:4])
            observed.append(f"{label} | {value.get('count') or 0}건" + (f" | {examples}" if examples else ""))
    _subsection(story, "외부 샌드박스 관찰 행위", styles)
    _bullets(story, observed, styles, "VT 외부 샌드박스에서 요약된 관찰 행위 없음")
    external_evidence = []
    for item in (vt.get("threat_names") or [])[:15]:
        external_evidence.append(f"위협명 {_text(item.get('name'))} | {item.get('count') or 0}개 엔진")
    for item in (vt.get("engine_detections") or [])[:25]:
        external_evidence.append(f"{_text(item.get('engine'))} | {_text(item.get('category'))} | {_text(item.get('result'))}")
    behavior_detail = vt.get("behavior_detail") or {}
    if behavior_detail.get("verdict_labels") or behavior_detail.get("verdicts"):
        verdicts = [*_text_list(behavior_detail.get("verdict_labels")), *_text_list(behavior_detail.get("verdicts"))]
        external_evidence.append(f"샌드박스 판정 {', '.join(verdicts)} | 신뢰도 {_text(behavior_detail.get('verdict_confidence'))}")
    external_evidence.extend(f"메모리 도메인 | {_text(value)}" for value in (behavior_detail.get("domains") or [])[:10])
    external_evidence.extend(f"실행 명령 | {_text(value)}" for value in (behavior_detail.get("command_executions") or [])[:8])
    _subsection(story, "주요 위협명·엔진·실행 근거", styles)
    _bullets(story, external_evidence, styles, "추가 위협명·실행 근거 없음")

    _section(story, "6. AI 최종 종합판정", styles)
    story.append(_metric_table([
        ("종합판정", final.get("overall_verdict") or "추가 검증 필요"),
        ("신뢰도", final.get("confidence") or "미확인"),
        ("생성 모델", final.get("generated_by") or "AI"),
    ], styles))
    story.append(_paragraph(final.get("summary") or "최종 AI 종합판정이 생성되지 않았습니다.", styles["body"]))
    _subsection(story, "종합 해석", styles)
    _paragraphs(story, final.get("executive_assessment"), styles, "종합 해석이 생성되지 않았습니다.")
    for heading, key, empty in [
        ("로컬·외부 증거 종합", "evidence_synthesis", "종합할 추가 증거 없음"),
        ("가능성이 높은 행위 체인", "likely_behavior_chain", "행위 체인을 구성하지 못했습니다."),
        ("위험도 해석", "risk_interpretation", "추가 위험도 해석 없음"),
        ("VT 근거를 반영한 핵심 분석", "external_evidence_points", "VT 핵심 근거 해석 없음"),
        ("일치한 핵심", "agreement_points", "명확한 일치 항목 없음"),
        ("차이와 해석", "difference_points", "별도 차이 설명 없음"),
        ("한계", "limitations", "추가 한계 설명 없음"),
    ]:
        _subsection(story, heading, styles)
        _bullets(story, final.get(key), styles, empty)
    _subsection(story, "패밀리 해석", styles)
    story.append(_paragraph(final.get("family_interpretation") or "패밀리 해석 없음", styles["body"]))
    _subsection(story, "분석가 최종 결론", styles)
    story.append(_paragraph(final.get("analyst_conclusion") or "분석가 최종 결론이 생성되지 않았습니다.", styles["body"]))

    _section(story, "7. 분석 대상 상세 식별", styles)
    sample_rows = [["항목", "값"]]
    for label, key in [
        ("외부 파일명", "name"), ("외부 파일 크기", "size"), ("외부 SHA-256", "sha256"),
        ("외부 형식", "detected_type"), ("내부 파일명", "inner_name"), ("내부 파일 크기", "inner_size"),
        ("내부 SHA-256", "inner_sha256"), ("내부 형식", "inner_type"),
    ]:
        sample_rows.append([label, sample.get(key)])
    story.append(_table(sample_rows, styles, [0.20, 0.80]))

    _section(story, "8. 상세 정적 분석", styles)
    story.append(_metric_table([
        ("형식", f"{_text(static.get('format'))} / {_text(static.get('machine'))}"),
        ("DLL", "예" if static.get("is_dll") else "아니요"),
        ("Entropy", static.get("entropy")),
        ("Import", f"{static.get('import_module_count') or 0}개 / {static.get('import_symbol_count') or 0} symbols"),
        ("capa", f"{static.get('capa_rule_count') or 0} rules"),
        ("Ghidra", static.get("ghidra_provider") or "미사용"),
    ], styles))
    _subsection(story, "Import 요약", styles)
    import_rows = [["모듈", "심볼 수", "주요 심볼"]]
    for item in static.get("imports") or []:
        import_rows.append([item.get("module"), item.get("symbol_count"), ", ".join(_text(x) for x in (item.get("symbols") or []))])
    if len(import_rows) == 1:
        import_rows.append(["확인된 Import 없음", 0, "-"])
    story.append(_table(import_rows, styles, [0.18, 0.10, 0.72]))
    _subsection(story, "정적 후보 기능", styles)
    findings = []
    for item in static.get("findings") or []:
        findings.append(
            f"{_text(item.get('category'))} | {_text(item.get('status'))} | "
            f"{', '.join(_text(x) for x in (item.get('matched') or [])) or '세부 문자열 없음'} | {_text(item.get('evidence_id'))}"
        )
    _bullets(story, findings, styles, "정적 후보 기능 없음")
    _subsection(story, "PE 섹션 구조", styles)
    section_rows = [["섹션", "Virtual", "Raw", "Entropy"]]
    for item in static.get("sections") or []:
        section_rows.append([item.get("name"), item.get("virtual_size"), item.get("raw_size"), item.get("entropy")])
    if len(section_rows) == 1:
        section_rows.append(["섹션 정보 없음", "-", "-", "-"])
    story.append(_table(section_rows, styles, [0.28, 0.24, 0.24, 0.24]))

    _section(story, "9. 증거·IOC·대응", styles)
    metrics = details.get("evidence_metrics") or {}
    story.append(_metric_table([
        ("Claims", metrics.get("claims") or 0), ("Events", metrics.get("events") or 0),
        ("Relations", metrics.get("relations") or 0), ("ATT&CK", metrics.get("attack_candidates") or 0),
        ("AI refs", metrics.get("validated_references") or 0), ("검증", metrics.get("validation_status") or "not_run"),
    ], styles))
    _subsection(story, "AI 처리 단계", styles)
    ai_rows = [["AI 단계", "상태", "세부"]]
    for item in details.get("ai_stages") or []:
        ai_rows.append([item.get("stage"), item.get("status"), item.get("detail")])
    story.append(_table(ai_rows, styles, [0.25, 0.18, 0.57]))
    _subsection(story, "주요 IOC", styles)
    ioc_rows = [["유형", "값"]]
    for item in local.get("iocs") or []:
        ioc_rows.append([item.get("type") or "IOC", item.get("value")])
    if len(ioc_rows) == 1:
        ioc_rows.append(["IOC", "보고 가능한 값 없음"])
    story.append(_table(ioc_rows, styles, [0.20, 0.80]))
    for heading, values, empty in [
        ("사용자 영향", local.get("user_impact"), "사용자 영향 미확인"),
        ("확인하지 못한 내용", local.get("unknowns"), "추가 미확인 항목 없음"),
        ("대응 권고", details.get("recommendations"), "추가 대응 권고 없음"),
    ]:
        _subsection(story, heading, styles)
        _bullets(story, values, styles, empty)
    _subsection(story, "추정 행위 흐름", styles)
    flow = [
        f"{item.get('step')}. {_text(item.get('title'))} | {_text(item.get('status'))}"
        for item in (result.get("behavior_flow") or [])
    ]
    _bullets(story, flow, styles, "동작 순서를 복원하지 못했습니다.")

    doc.build(story)
    return output_path


def _text_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return [_text(value) for value in values if value not in (None, "")]
