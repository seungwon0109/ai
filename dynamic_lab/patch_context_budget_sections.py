from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "src" / "agent_runtime" / "context_builder.py"


def main() -> None:
    text = PATH.read_text(encoding="utf-8")
    replacements = {
        '        self._append_until(context["confirmed_events"], events, context)\n':
            '        self._append_until(context["confirmed_events"], events[:30], context)\n',
        '        self._append_until(context["claims"], claims, context)\n':
            '        self._append_until(context["claims"], claims[:20], context)\n',
        '        self._append_until(context["evidence_records"], artifacts, context)\n':
            '        self._append_until(context["evidence_records"], artifacts[:20], context)\n',
        '        self._append_until(context["attack_candidates"], mappings, context)\n':
            '        self._append_until(context["attack_candidates"], mappings[:15], context)\n',
    }
    for old, new in replacements.items():
        if new in text:
            continue
        if text.count(old) != 1:
            raise RuntimeError(f"Context budget marker mismatch: {old!r}")
        text = text.replace(old, new, 1)
    PATH.write_text(text, encoding="utf-8")
    print("Context section budgets applied.")


if __name__ == "__main__":
    main()
