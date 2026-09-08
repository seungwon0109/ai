from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if new in text:
        return
    if text.count(old) != 1:
        raise RuntimeError(f"Patch marker mismatch in {path}: {old[:120]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    validator = ROOT / "src" / "common_evidence" / "validator.py"
    replace_once(
        validator,
        '    known_functions: set[str] = set()\n    for _, value in _walk(evidence.get("tool_results") or []):',
        '    known_functions: set[str] = set()\n    function_sources = [evidence.get("tool_results") or [], common.get("artifacts") or []]\n    for _, value in _walk(function_sources):',
    )
    replace_once(
        validator,
        '    catalog = _attack_catalog(attack_catalog_path)\n    issues: list[dict[str, Any]] = []',
        '''    catalog = _attack_catalog(attack_catalog_path)\n    issues: list[dict[str, Any]] = []\n    validated_attack_mappings = 0\n    for index, mapping in enumerate(common.get("attack_mappings") or []):\n        if not isinstance(mapping, dict):\n            continue\n        technique_id = str(mapping.get("technique_id") or "").upper()\n        if not ATTACK_ID_RE.fullmatch(technique_id):\n            mapping["catalog_validation"] = "invalid_format"\n            issues.append({"severity": "error", "code": "INVALID_ATTACK_ID", "path": f"$.common_evidence.attack_mappings[{index}]", "value": technique_id})\n        elif catalog is None:\n            mapping["catalog_validation"] = "catalog_unavailable"\n        elif technique_id in catalog:\n            mapping["catalog_validation"] = "verified"\n            validated_attack_mappings += 1\n        else:\n            mapping["catalog_validation"] = "not_found"\n            issues.append({"severity": "error", "code": "UNKNOWN_ATTACK_ID", "path": f"$.common_evidence.attack_mappings[{index}]", "value": technique_id})''',
    )
    replace_once(
        validator,
        '            for evidence_id in ids:\n                checked_references += 1\n                if evidence_id not in valid_evidence_ids:\n                    issues.append({"severity": "error", "code": "UNKNOWN_EVIDENCE_ID", "path": path, "value": evidence_id})',
        '''            known_ids = []\n            for evidence_id in ids:\n                checked_references += 1\n                if evidence_id not in valid_evidence_ids:\n                    issues.append({"severity": "error", "code": "UNKNOWN_EVIDENCE_ID", "path": path, "value": evidence_id})\n                else:\n                    known_ids.append(evidence_id)\n            if "confirmed_facts" in path and known_ids:\n                confirmed_artifacts = {\n                    artifact_id\n                    for claim in common.get("claims", [])\n                    if isinstance(claim, dict) and claim.get("level") == "CONFIRMED"\n                    for artifact_id in claim.get("artifact_ids", [])\n                }\n                if not any(item.startswith("EVT-") or item in confirmed_artifacts for item in known_ids):\n                    issues.append({"severity": "error", "code": "STATIC_ONLY_CONFIRMED_CLAIM", "path": path, "evidence_ids": known_ids})''',
    )
    replace_once(
        validator,
        '        "attack_catalog": "loaded" if catalog is not None else "not_configured",\n',
        '        "attack_catalog": "loaded" if catalog is not None else "not_configured",\n        "verified_attack_mapping_count": validated_attack_mappings,\n',
    )

    ai_entry = ROOT / "ai_entry.py"
    replace_once(
        ai_entry,
        '        "confirmed_facts": [],\n        "inferences": [],',
        '''        "confirmed_facts": [{\n            "claim": "string",\n            "level": "CONFIRMED",\n            "evidence_ids": ["EVT-... or ART-..."],\n        }],\n        "inferences": [{\n            "claim": "string",\n            "level": "INFERRED",\n            "evidence_ids": ["ART-... or E-..."],\n        }],''',
    )
    print("Common evidence v3 patch applied.")


if __name__ == "__main__":
    main()
