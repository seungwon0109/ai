from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if new in text:
        return
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"Expected one integration marker in {path.name}, found {count}: {old[:80]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def patch_demo_core() -> None:
    path = ROOT / "demo_core.py"
    replace_once(
        path,
        "from typing import Any\n\n\nASCII_RE",
        "from typing import Any\n\nfrom src.common_evidence import build_common_evidence, validate_ai_results\n\n\nASCII_RE",
    )
    replace_once(
        path,
        '        "tool_results": evidence["tool_results"],\n        "local_analysis": evidence["local_ai"],',
        '        "tool_results": evidence["tool_results"],\n        "common_evidence": evidence.get("common_evidence"),\n        "ai_validation": evidence.get("ai_validation"),\n        "local_analysis": evidence["local_ai"],',
    )
    replace_once(
        path,
        '    evidence["mcp_tool_catalog"] = catalog\n    evidence["tool_results"] = tool_results\n\n    print("[5/8]',
        '    evidence["mcp_tool_catalog"] = catalog\n    evidence["tool_results"] = tool_results\n    evidence["common_evidence"] = build_common_evidence(evidence)\n\n    print("[5/8]',
    )
    replace_once(
        path,
        '    evidence["local_ai"] = {\n        "configured": bool(args.local_base_url and args.local_model),\n        "pass_1": pass_1,\n        "pass_2": pass_2,\n        "pass_3": pass_3,\n    }\n    packet = cloud_packet(evidence)',
        '    evidence["local_ai"] = {\n        "configured": bool(args.local_base_url and args.local_model),\n        "pass_1": pass_1,\n        "pass_2": pass_2,\n        "pass_3": pass_3,\n    }\n    evidence["common_evidence"] = build_common_evidence(evidence)\n    evidence["ai_validation"] = validate_ai_results(\n        evidence,\n        evidence["common_evidence"],\n        Path(__file__).resolve().parent / "config" / "attack_techniques.json",\n    )\n    packet = cloud_packet(evidence)',
    )
    replace_once(
        path,
        '    evidence_path = output / f"{stem}.evidence.json"\n    packet_path = output / f"{stem}.cloud-packet.json"',
        '    evidence_path = output / f"{stem}.evidence.json"\n    common_path = output / f"{stem}.common-evidence.json"\n    packet_path = output / f"{stem}.cloud-packet.json"',
    )
    replace_once(
        path,
        '    evidence_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")\n    packet_path.write_text',
        '    evidence_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")\n    common_path.write_text(\n        json.dumps(evidence["common_evidence"], ensure_ascii=False, indent=2),\n        encoding="utf-8",\n    )\n    packet_path.write_text',
    )
    replace_once(
        path,
        '    print(f"利앷굅: {evidence_path}")\n',
        '    print(f"利앷굅: {evidence_path}")\n    print(f"Common evidence: {common_path}")\n',
    )


def patch_ai_entry() -> None:
    path = ROOT / "ai_entry.py"
    replace_once(
        path,
        "import demo_core as core\n",
        "import demo_core as core\nfrom src.common_evidence import compact_common_evidence\n",
    )
    replace_once(
        path,
        '        "tool_results": evidence.get("tool_results", []),\n        "safety": evidence["safety"],',
        '        "tool_results": evidence.get("tool_results", []),\n        "common_evidence": compact_common_evidence(evidence.get("common_evidence")),\n        "safety": evidence["safety"],',
    )


def patch_cape_entry() -> None:
    path = ROOT / "cape_entry.py"
    replace_once(
        path,
        "from cape_client import CapeClient, CapeError\n",
        "from cape_client import CapeClient, CapeError\nfrom src.common_evidence import build_common_evidence\n",
    )
    replace_once(
        path,
        '            evidence["dynamic_analysis"] = summary\n            safety["sandbox_execution_status"] = "completed"',
        '            evidence["dynamic_analysis"] = summary\n            evidence["common_evidence"] = build_common_evidence(evidence)\n            safety["sandbox_execution_status"] = "completed"',
    )
    replace_once(
        path,
        '            safety["sandbox_execution_status"] = "failed_or_timed_out"',
        '            evidence["common_evidence"] = build_common_evidence(evidence)\n            safety["sandbox_execution_status"] = "failed_or_timed_out"',
    )


def patch_main() -> None:
    path = ROOT / "main.py"
    replace_once(
        path,
        "def load_cape_token(distro: str) -> str | None:\n",
        '''def find_capa() -> Path | None:\n    candidates = [\n        os.getenv("CAPA_PATH"),\n        str(PROJECT_ROOT / "tools" / "capa" / "capa.exe"),\n        str(PROJECT_ROOT / "tools" / "capa.exe"),\n        shutil.which("capa"),\n        shutil.which("capa.exe"),\n    ]\n    for candidate in candidates:\n        if candidate and Path(candidate).expanduser().is_file():\n            return Path(candidate).expanduser().resolve()\n    return None\n\n\ndef load_cape_token(distro: str) -> str | None:\n''',
    )
    replace_once(
        path,
        '    parser.add_argument("--capa-path", type=Path)\n',
        '    parser.add_argument("--capa-path", type=Path)\n    parser.add_argument("--skip-capa", action="store_true")\n',
    )
    replace_once(
        path,
        '    if args.capa_path:\n        pipeline.extend(["--capa-path", str(args.capa_path.resolve())])\n',
        '    capa_path = None if args.skip_capa else (args.capa_path or find_capa())\n    if capa_path:\n        pipeline.extend(["--capa-path", str(capa_path.resolve())])\n        print(f"[capa] 활성화: {capa_path}")\n    elif not args.skip_capa:\n        print("[경고] capa를 찾지 못해 해당 단계만 건너뜁니다. CAPA_PATH 또는 --capa-path를 설정하세요.")\n',
    )


def main() -> None:
    patch_demo_core()
    patch_ai_entry()
    patch_cape_entry()
    patch_main()
    print("Common evidence integration applied.")


if __name__ == "__main__":
    main()
