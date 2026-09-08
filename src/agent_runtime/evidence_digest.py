"""Build a cross-tool digest for the local report-writing pass."""

from __future__ import annotations

from typing import Any


KEY_TERMS = (
    "encrypt", "decrypt", "ransom", "key", "nonce", "bcrypt", "crypt",
    "vssadmin", "bcdedit", "shadow", "wallpaper", "desktop", "documents",
    "pictures", "downloads", "extension", "inject", "discord", "browser",
    "webcam", "password", "cookie", "token", "startup", "schtasks",
    "service", "powershell", "http", "https", "tokyocore", "fsociety",
)


def _selected_member(evidence: dict[str, Any]) -> dict[str, Any]:
    return (
        ((evidence.get("static_analysis") or {}).get("archive_analysis") or {})
        .get("selected_member")
        or {}
    )


def _relevant_strings(values: Any, limit: int = 100) -> list[str]:
    if not isinstance(values, list):
        return []
    output: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        lowered = value.lower()
        if any(term in lowered for term in KEY_TERMS):
            output.append(value[:500])
            if len(output) >= limit:
                break
    return output


def _relevant_imports(member: dict[str, Any], limit: int = 120) -> list[str]:
    output: list[str] = []
    pefile = member.get("pefile") or {}
    for library in pefile.get("imports") or []:
        if not isinstance(library, dict):
            continue
        dll = str(library.get("dll") or "")
        for symbol in library.get("symbols") or []:
            value = f"{dll}!{symbol}"
            if any(term in value.lower() for term in KEY_TERMS) or any(
                marker in value.lower()
                for marker in ("createprocess", "writeprocess", "virtualalloc", "setwindowshook", "regsetvalue")
            ):
                output.append(value)
                if len(output) >= limit:
                    return output
    return output




def _external_intelligence(evidence: dict[str, Any]) -> dict[str, Any] | None:
    vt = ((evidence.get("external_intelligence") or {}).get("virustotal"))
    if not isinstance(vt, dict):
        return None
    primary = vt.get("primary") if isinstance(vt.get("primary"), dict) else {}
    return {
        "virustotal": {
            "status": vt.get("status"),
            "lookup_hash": vt.get("lookup_hash"),
            "found": vt.get("found"),
            "last_analysis_stats": vt.get("last_analysis_stats") or {},
            "family_candidate": vt.get("family_candidate"),
            "tags": (vt.get("tags") or [])[:30],
            "mitre_techniques": (vt.get("mitre_techniques") or [])[:50],
            "known_names": (primary.get("known_names") or [])[:20],
            "type_description": primary.get("type_description"),
            "behaviour_status": (primary.get("behaviour_summary") or {}).get("status") if isinstance(primary.get("behaviour_summary"), dict) else None,
            "source_boundary": "external_intelligence_not_local_observation",
        }
    }

def build_analysis_digest(evidence: dict[str, Any]) -> dict[str, Any]:
    """Preserve every analysis category while bounding repetitive raw records."""
    static = evidence.get("static_analysis") or {}
    archive = static.get("archive_analysis") or {}
    member = _selected_member(evidence)
    dynamic = evidence.get("dynamic_analysis") or {}
    common = evidence.get("common_evidence") or {}

    signature_records = []
    for artifact in common.get("artifacts") or []:
        if not isinstance(artifact, dict) or artifact.get("artifact_type") != "CAPE_SIGNATURE":
            continue
        value = artifact.get("value") or {}
        attr = value.get("attribution") or {}
        signature_records.append({
            "evidence_id": artifact.get("artifact_id"),
            "name": value.get("name"),
            "severity": value.get("severity"),
            "confidence": value.get("confidence"),
            "attribution": attr.get("level", "POSSIBLE"),
            "actor_pids": attr.get("actor_pids") or [],
            "included_in_conclusion": bool(attr.get("included_in_conclusion")),
        })

    process_records = []
    for process in ((dynamic.get("behavior") or {}).get("processes") or [])[:100]:
        if isinstance(process, dict):
            process_records.append({
                "name": process.get("process_name"),
                "pid": process.get("process_id"),
                "parent_id": process.get("parent_id"),
                "command_line": str(process.get("command_line") or "")[:700],
                "attribution": next((
                    item.get("level")
                    for item in (dynamic.get("attribution") or {}).get("processes") or []
                    if isinstance(item, dict) and item.get("process_id") == process.get("process_id")
                ), "UNRELATED"),
            })

    dropped_records = []
    for item in (dynamic.get("dropped_files") or [])[:100]:
        if isinstance(item, dict):
            dropped_records.append({
                "name": item.get("name"),
                "size": item.get("size"),
                "type": item.get("type"),
                "sha256": item.get("sha256"),
            })

    isolated_capa = archive.get("isolated_capa") or {}
    capa_rules = isolated_capa.get("rules") or []
    if isinstance(capa_rules, dict):
        capa_rules = list(capa_rules.keys())

    ghidra = archive.get("isolated_ghidra") or {}
    return {
        "sample": evidence.get("sample"),
        "inner_member": {
            "name": member.get("name"),
            "size": member.get("size"),
            "hashes": member.get("hashes"),
            "format": member.get("format_detection"),
        },
        "static": {
            "findings": static.get("findings") or member.get("findings") or [],
            "relevant_imports": _relevant_imports(member),
            "relevant_strings": _relevant_strings(member.get("strings") or static.get("strings")),
            "packer": static.get("packer_assessment"),
        },
        "capa": {
            "matched_rule_count": len(capa_rules) if isinstance(capa_rules, list) else 0,
            "rules": capa_rules[:120] if isinstance(capa_rules, list) else [],
        },
        "ghidra": {
            "summary": ghidra.get("summary"),
            "program": ghidra.get("program"),
            "provider": ghidra.get("provider"),
        },
        "dynamic": {
            "status": dynamic.get("status"),
            "task_id": dynamic.get("task_id"),
            "duration": dynamic.get("duration"),
            "signatures": signature_records[:100],
            "processes": process_records,
            "dropped_files": dropped_records,
            "network": dynamic.get("network"),
            "malware_config": dynamic.get("malware_config"),
            "analysis_errors": dynamic.get("analysis_errors"),
            "attribution": dynamic.get("attribution"),
        },
        "coverage": {
            "artifact_count": len(common.get("artifacts") or []),
            "event_count": len(common.get("events") or []),
            "claim_count": len(common.get("claims") or []),
            "relation_count": len(common.get("relations") or []),
            "attack_mapping_count": len(common.get("attack_mappings") or []),
        },
    }
