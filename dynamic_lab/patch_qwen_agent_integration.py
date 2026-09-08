from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if new in text:
        return
    if text.count(old) != 1:
        raise RuntimeError(f"Patch marker mismatch in {path.name}: {old[:140]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def patch_ai_entry() -> None:
    path = ROOT / "ai_entry.py"
    replace_once(
        path,
        "from src.common_evidence import compact_common_evidence\n",
        "from src.common_evidence import compact_common_evidence\nfrom src.agent_runtime import run_qwen_agent_step\n",
    )
    replace_once(
        path,
        '''        "temperature": 0.1,\n        "max_tokens": 2048,\n        "options": {"num_ctx": 8192, "num_predict": 1200},\n''',
        '''        "temperature": 0.1,\n        "top_p": 0.9,\n        "presence_penalty": 0.0,\n        "max_tokens": 1200,\n        "options": {\n            "num_ctx": 8192,\n            "num_predict": 1200,\n            "temperature": 0.1,\n            "top_k": 20,\n            "top_p": 0.9,\n            "presence_penalty": 0.0,\n        },\n''',
    )
    replace_once(
        path,
        '    json_requested = "諛섎뱶??JSON 媛앹껜" in system\n',
        '    json_requested = "JSON" in system.upper()\n',
    )
    replace_once(
        path,
        '''# demo_core???꾩뿭 ?몄텧湲곕? 媛쒖꽑??援ы쁽?쇰줈 援먯껜?쒕떎.\ncore.chat = reliable_chat\ncore.local_pass = reliable_local_pass\n''',
        '''def qwen_agent_local_pass(\n    number: int,\n    evidence: dict[str, Any],\n    prior: dict[str, Any] | None,\n    tools: list[dict[str, Any]],\n    args: Any,\n) -> dict[str, Any]:\n    if not (args.local_base_url and args.local_model):\n        return core.deterministic_pass(number, evidence, prior)\n    return run_qwen_agent_step(\n        number,\n        evidence,\n        prior,\n        tools,\n        args,\n        chat_fn=reliable_chat,\n        parse_fn=core.json_response,\n        fallback_fn=core.deterministic_pass,\n    )\n\n\n# Install the Qwen3.5 9B bounded controller into the shared pipeline.\ncore.chat = reliable_chat\ncore.local_pass = qwen_agent_local_pass\n''',
    )


def patch_demo_core() -> None:
    path = ROOT / "demo_core.py"
    replace_once(
        path,
        '    parser.add_argument("--max-mcp-calls-per-pass", type=int, default=6)\n',
        '    parser.add_argument("--max-mcp-calls-per-pass", type=int, default=2)\n',
    )
    replace_once(
        path,
        '    parser.add_argument("--local-context-chars", type=int, default=120000)\n',
        '    parser.add_argument("--local-context-chars", type=int, default=8000)\n',
    )
    replace_once(
        path,
        '        "ai_validation": evidence.get("ai_validation"),\n        "local_analysis": evidence["local_ai"],',
        '        "ai_validation": evidence.get("ai_validation"),\n        "agent_run": evidence.get("agent_run"),\n        "local_analysis": evidence["local_ai"],',
    )
    replace_once(
        path,
        '    common_path = output / f"{stem}.common-evidence.json"\n    packet_path = output / f"{stem}.cloud-packet.json"',
        '    common_path = output / f"{stem}.common-evidence.json"\n    agent_path = output / f"{stem}.agent-run.json"\n    packet_path = output / f"{stem}.cloud-packet.json"',
    )
    replace_once(
        path,
        '''    common_path.write_text(\n        json.dumps(evidence["common_evidence"], ensure_ascii=False, indent=2),\n        encoding="utf-8",\n    )\n    packet_path.write_text''',
        '''    common_path.write_text(\n        json.dumps(evidence["common_evidence"], ensure_ascii=False, indent=2),\n        encoding="utf-8",\n    )\n    agent_path.write_text(\n        json.dumps(evidence.get("agent_run", {"status": "LOCAL_AI_DISABLED"}), ensure_ascii=False, indent=2),\n        encoding="utf-8",\n    )\n    packet_path.write_text''',
    )
    replace_once(
        path,
        '    print(f"공통 증거: {common_path}")\n',
        '    print(f"공통 증거: {common_path}")\n    print(f"Agent run: {agent_path}")\n',
    )


def patch_main() -> None:
    path = ROOT / "main.py"
    replace_once(
        path,
        '''        "--max-file-size-mb",\n        str(args.max_file_size_mb),\n    ]\n''',
        '''        "--max-file-size-mb",\n        str(args.max_file_size_mb),\n        "--max-mcp-calls-per-pass",\n        "2",\n    ]\n''',
    )


def main() -> None:
    patch_ai_entry()
    patch_demo_core()
    patch_main()
    print("Qwen3.5 9B agent integration applied.")


if __name__ == "__main__":
    main()
