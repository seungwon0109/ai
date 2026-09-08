from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
worker = ROOT / "isolated_static_worker.py"
text = worker.read_text(encoding="utf-8")
text = text.replace("import tempfile\n", "import tempfile\nimport time\n")

marker = '''def main() -> int:
'''
addition = '''def ghidra_analysis(target: Path, workspace: Path, timeout: int = 900) -> dict[str, Any]:
    ghidra_home = Path(__file__).resolve().parents[1] / "tools" / "ghidra_12.1.2_PUBLIC_20260605" / "ghidra_12.1.2_PUBLIC"
    headless = ghidra_home / "support" / "analyzeHeadless"
    exporter = Path(__file__).resolve().parent / "ghidra_scripts" / "ExportAnalysis.java"
    if not headless.is_file():
        return {"skipped": True, "reason": f"Ghidra Headless not found: {headless}"}
    if not exporter.is_file():
        return {"skipped": True, "reason": f"Ghidra export script not found: {exporter}"}
    if not shutil.which("java"):
        return {"skipped": True, "reason": "Java is not installed in WSL"}

    project_dir = workspace / "ghidra-project"
    script_dir = workspace / "ghidra-scripts"
    output = workspace / "ghidra-analysis.json"
    home = workspace / "ghidra-home"
    project_dir.mkdir()
    script_dir.mkdir()
    home.mkdir()
    shutil.copy2(exporter, script_dir / exporter.name)
    command = [
        str(headless), str(project_dir), "isolated_static",
        "-import", str(target),
        "-scriptPath", str(script_dir),
        "-postScript", "ExportAnalysis.java", str(output), "1200", "120",
        "-analysisTimeoutPerFile", str(timeout),
        "-deleteProject",
    ]
    started = time.monotonic()
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout + 120,
            check=False,
            env={**os.environ, "HOME": str(home), "JAVA_HOME": "/usr/lib/jvm/java-21-openjdk-amd64"},
        )
    except subprocess.TimeoutExpired:
        return {"error": f"Ghidra timed out after {timeout + 120}s"}
    elapsed = round(time.monotonic() - started, 3)
    if process.returncode or not output.is_file():
        return {
            "error": "Ghidra Headless analysis failed",
            "return_code": process.returncode,
            "elapsed_seconds": elapsed,
            "stdout_tail": process.stdout[-4000:],
            "stderr_tail": process.stderr[-4000:],
        }
    try:
        value = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"error": f"Ghidra JSON error: {exc}", "elapsed_seconds": elapsed}
    value["elapsed_seconds"] = elapsed
    value["provider"] = "ghidra-headless-wsl"
    value["sample_executed"] = False
    return value


'''
if addition not in text:
    if marker not in text:
        raise RuntimeError("worker main marker not found")
    text = text.replace(marker, addition + marker, 1)

old = '''        result["isolated_capa"] = capa_analysis(target, args.capa_timeout)
        del raw
'''
new = '''        result["isolated_capa"] = capa_analysis(target, args.capa_timeout)
        result["isolated_ghidra"] = ghidra_analysis(target, Path(temporary))
        del raw
'''
if new not in text:
    if old not in text:
        raise RuntimeError("capa call marker not found")
    text = text.replace(old, new, 1)

old_skip = '''    result["isolated_ghidra"] = {
        "skipped": True,
        "reason": "Ghidra and Java are not installed in the CAPE WSL static environment",
    }
'''
text = text.replace(old_skip, "")
worker.write_text(text, encoding="utf-8")

demo = ROOT / "demo_core.py"
text = demo.read_text(encoding="utf-8")
old = '''    print("[4/8] ?좏깮??Ghidra MCP 珥덇린 遺꾩꽍")
    catalog, tool_results = [], []
'''
new = '''    print("[4/8] optional Ghidra evidence")
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
if new not in text:
    if old not in text:
        raise RuntimeError("Ghidra phase marker not found")
    text = text.replace(old, new, 1)
demo.write_text(text, encoding="utf-8")

print("Enabled Ghidra Headless inside WSL isolated ZIP analysis.")
