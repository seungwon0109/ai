from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if new in text:
        return
    if text.count(old) != 1:
        raise RuntimeError(f"Patch marker mismatch in {path}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    replace_once(
        ROOT / "main.py",
        '        / "results"\n        / "runs"\n',
        '        / "analysis-results"\n        / "runs"\n',
    )
    replace_once(
        ROOT / "docs" / "VSCODE_RUN.md",
        'under `results/runs/<run>`:',
        'under `analysis-results/runs/<run>`:',
    )
    print("Standard output path patch applied.")


if __name__ == "__main__":
    main()
