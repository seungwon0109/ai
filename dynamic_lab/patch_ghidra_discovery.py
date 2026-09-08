from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "ghidra_mcp_core.py"


def main() -> None:
    text = PATH.read_text(encoding="utf-8")
    old = '''PROJECT_DIR = Path(__file__).resolve().parent\nDEFAULT_GHIDRA_HOME = Path(\n    r"C:\\Users\\Arast\\Downloads\\ghidra_12.1.2_PUBLIC_20260605"\n    r"\\ghidra_12.1.2_PUBLIC"\n)\nGHIDRA_HOME = Path(os.getenv("GHIDRA_HOME", str(DEFAULT_GHIDRA_HOME))).resolve()\n'''
    new = '''PROJECT_DIR = Path(__file__).resolve().parent\n\n\ndef _default_ghidra_home() -> Path:\n    candidates = [\n        PROJECT_DIR.parent / "tools" / "ghidra_12.1.2_PUBLIC_20260605" / "ghidra_12.1.2_PUBLIC",\n        Path(r"C:\\Users\\Arast\\Downloads\\ghidra_12.1.2_PUBLIC_20260605\\ghidra_12.1.2_PUBLIC"),\n    ]\n    for candidate in candidates:\n        if (candidate / "support" / "analyzeHeadless.bat").is_file():\n            return candidate.resolve()\n    return candidates[0].resolve()\n\n\nDEFAULT_GHIDRA_HOME = _default_ghidra_home()\nGHIDRA_HOME = Path(os.getenv("GHIDRA_HOME", str(DEFAULT_GHIDRA_HOME))).resolve()\n'''
    if new in text:
        print("Ghidra discovery already applied.")
        return
    if text.count(old) != 1:
        raise RuntimeError("Ghidra path marker mismatch")
    PATH.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"Ghidra discovery applied: {new.splitlines()[0]}")


if __name__ == "__main__":
    main()
