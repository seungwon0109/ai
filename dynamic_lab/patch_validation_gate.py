from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "demo_core.py"


def main() -> None:
    text = PATH.read_text(encoding="utf-8")
    old = '''def cloud_judge(packet: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:\n    if args.no_cloud or not (args.cloud_base_url and args.cloud_model):\n'''
    new = '''def cloud_judge(packet: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:\n    validation = packet.get("ai_validation")\n    if isinstance(validation, dict) and validation.get("status") == "rejected":\n        return {\n            "skipped": True,\n            "reason": "AI evidence validation rejected one or more claims",\n            "validation": validation,\n        }\n    if args.no_cloud or not (args.cloud_base_url and args.cloud_model):\n'''
    if new not in text:
        if text.count(old) != 1:
            raise RuntimeError("cloud_judge marker mismatch")
        text = text.replace(old, new, 1)

    if "## AI evidence validation" not in text:
        start = text.index("    tool_results = evidence.get(\"tool_results\")")
        marker = "\n    lines += [\n"
        insertion_at = text.index(marker, start)
        block = '''\n    validation = evidence.get("ai_validation") or {}\n    lines += [\n        "",\n        "## AI evidence validation",\n        "",\n        f"- Status: `{validation.get('status', 'not_run')}`",\n        f"- Errors: `{validation.get('error_count', 0)}`",\n        f"- Warnings: `{validation.get('warning_count', 0)}`",\n        f"- ATT&CK catalog: `{validation.get('attack_catalog', 'not_configured')}`",\n    ]\n'''
        text = text[:insertion_at] + block + text[insertion_at:]

    PATH.write_text(text, encoding="utf-8")
    print("AI validation gate applied.")


if __name__ == "__main__":
    main()
