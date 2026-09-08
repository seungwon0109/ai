from pathlib import Path

path = Path(__file__).resolve().parents[1] / "demo_core.py"
text = path.read_text(encoding="utf-8")
if 'archive_ghidra = archive.get("isolated_ghidra")' not in text:
    start = text.index('    print("[4/8]')
    catalog_pos = text.index('    catalog, tool_results = [], []\n', start)
    catalog_end = catalog_pos + len('    catalog, tool_results = [], []\n')
    replacement = '''    print("[4/8] optional Ghidra evidence")
    catalog, tool_results = [], []
    archive_ghidra = archive.get("isolated_ghidra") if isinstance(archive, dict) else None
    if isinstance(archive_ghidra, dict):
        tool_results.append({
            "phase": "isolated_static",
            "calls": [{
                "tool": "analyze_binary",
                "arguments": {"sample": (archive.get("selected_member") or {}).get("name")},
                "result": archive_ghidra,
            }],
        })
'''
    text = text[:start] + replacement + text[catalog_end:]
    path.write_text(text, encoding="utf-8")
print("Completed WSL Ghidra evidence integration.")
