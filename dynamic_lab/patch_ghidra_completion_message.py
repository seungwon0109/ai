from pathlib import Path

path = Path(__file__).resolve().parents[1] / "demo_core.py"
text = path.read_text(encoding="utf-8")
old = '''    if not args.mcp_command:
        print("[?덈궡] Ghidra MCP 誘몄뿰寃?)
'''
new = '''    archive_ghidra = (
        ((evidence.get("static_analysis") or {}).get("archive_analysis") or {}).get("isolated_ghidra")
    )
    if isinstance(archive_ghidra, dict) and archive_ghidra.get("provider") == "ghidra-headless-wsl":
        print("[Ghidra] WSL Headless archive-member analysis completed")
    elif not args.mcp_command:
        print("[notice] Ghidra MCP was not connected")
'''
if new not in text:
    if old not in text:
        start = text.index("    if not args.mcp_command:\n", text.index("    print(f\"", text.index("packet_path.write_text")))
        end = text.index("    return 0\n", start)
        text = text[:start] + new + text[end:]
    else:
        text = text.replace(old, new, 1)
    path.write_text(text, encoding="utf-8")
print("Fixed completion message for WSL Ghidra analysis.")
