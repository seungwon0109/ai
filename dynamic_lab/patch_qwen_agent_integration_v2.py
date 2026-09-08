from __future__ import annotations

import re

import patch_qwen_agent_integration as v1


def patch_ai_entry_remaining() -> None:
    path = v1.ROOT / "ai_entry.py"
    text = path.read_text(encoding="utf-8")
    replacement = '    json_requested = "JSON" in system.upper()\n'
    if replacement not in text:
        text, count = re.subn(
            r'^    json_requested = .*?\n',
            replacement,
            text,
            count=1,
            flags=re.MULTILINE,
        )
        if count != 1:
            raise RuntimeError("json_requested marker mismatch")

    old = "core.chat = reliable_chat\ncore.local_pass = reliable_local_pass\n"
    new = '''def qwen_agent_local_pass(\n    number: int,\n    evidence: dict[str, Any],\n    prior: dict[str, Any] | None,\n    tools: list[dict[str, Any]],\n    args: Any,\n) -> dict[str, Any]:\n    if not (args.local_base_url and args.local_model):\n        return core.deterministic_pass(number, evidence, prior)\n    return run_qwen_agent_step(\n        number,\n        evidence,\n        prior,\n        tools,\n        args,\n        chat_fn=reliable_chat,\n        parse_fn=core.json_response,\n        fallback_fn=core.deterministic_pass,\n    )\n\n\n# Install the Qwen3.5 9B bounded controller into the shared pipeline.\ncore.chat = reliable_chat\ncore.local_pass = qwen_agent_local_pass\n'''
    if new not in text:
        if text.count(old) != 1:
            raise RuntimeError("local_pass assignment marker mismatch")
        text = text.replace(old, new, 1)
    path.write_text(text, encoding="utf-8")


def main() -> None:
    patch_ai_entry_remaining()
    v1.patch_demo_core()
    v1.patch_main()
    print("Qwen3.5 9B agent integration completed.")


if __name__ == "__main__":
    main()
