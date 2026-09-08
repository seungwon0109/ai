from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if new in text:
        return
    if text.count(old) != 1:
        raise RuntimeError(f"Patch marker mismatch in {path}: {old[:100]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    adapters = ROOT / "src" / "common_evidence" / "adapters.py"
    replace_once(
        adapters,
        '        builder.relation("CONTAINS", sample_entity, inner_entity)\n    return sample_entity',
        '''        builder.relation("CONTAINS", sample_entity, inner_entity)\n        for index, finding in enumerate(selected.get("findings") or []):\n            if not isinstance(finding, dict):\n                continue\n            artifact_id = builder.artifact(\n                source_id,\n                "ARCHIVE_MEMBER_STATIC_FINDING",\n                {"json_path": f"static_analysis.archive_analysis.selected_member.findings[{index}]"},\n                finding,\n            )\n            category = str(finding.get("category") or "unknown")\n            matched = finding.get("matched") or []\n            builder.claim(\n                f"Static indicators in archive member associated with {category} were observed: {', '.join(map(str, matched[:12]))}",\n                "OBSERVED",\n                "candidate",\n                0.45,\n                [artifact_id],\n                entities=[inner_entity],\n                category=category,\n            )\n    return sample_entity''',
    )

    ai_entry = ROOT / "ai_entry.py"
    text = ai_entry.read_text(encoding="utf-8")
    line = '        "common_evidence": compact_common_evidence(evidence.get("common_evidence")),\n'
    if text.count(line) == 1:
        text = text.replace(line, "", 1)
        marker = '        "analysis_route": evidence["analysis_route"],\n'
        if text.count(marker) != 1:
            raise RuntimeError("analysis_route marker mismatch in ai_entry.py")
        text = text.replace(marker, marker + line, 1)
        ai_entry.write_text(text, encoding="utf-8")

    print("Common evidence v2 patch applied.")


if __name__ == "__main__":
    main()
