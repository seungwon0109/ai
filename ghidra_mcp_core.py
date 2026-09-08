#!/usr/bin/env python3
"""Ghidra headless static-analysis MCP server.

The submitted binary is imported and analyzed by Ghidra; it is never executed.
Results are cached as JSON so each stdio MCP process can answer follow-up calls.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP


PROJECT_DIR = Path(__file__).resolve().parent


def _default_ghidra_home() -> Path:
    candidates = [
        PROJECT_DIR.parent / "tools" / "ghidra_12.1.2_PUBLIC_20260605" / "ghidra_12.1.2_PUBLIC",
        Path(r"C:\Users\Arast\Downloads\ghidra_12.1.2_PUBLIC_20260605\ghidra_12.1.2_PUBLIC"),
    ]
    for candidate in candidates:
        if (candidate / "support" / "analyzeHeadless.bat").is_file():
            return candidate.resolve()
    return candidates[0].resolve()


DEFAULT_GHIDRA_HOME = _default_ghidra_home()
GHIDRA_HOME = Path(os.getenv("GHIDRA_HOME", str(DEFAULT_GHIDRA_HOME))).resolve()
HEADLESS = GHIDRA_HOME / "support" / (
    "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
)
SCRIPT_DIR = PROJECT_DIR / "ghidra_scripts"
CACHE_DIR = PROJECT_DIR / "cache" / "ghidra_cache"
GHIDRA_PROJECT_DIR = PROJECT_DIR / "cache" / "ghidra_projects"

mcp = FastMCP(
    "ghidra-static-analysis",
    instructions=(
        "Defensive static analysis only. The sample is imported into Ghidra and "
        "never executed. Call analyze_binary first, then use focused evidence tools."
    ),
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _sample(path_text: str) -> Path:
    path = Path(path_text).expanduser().resolve()
    if not path.is_file():
        raise ValueError(f"Sample not found: {path}")
    if path.stat().st_size > 1024 * 1024 * 1024:
        raise ValueError("Sample exceeds the 1 GiB static-analysis limit")
    return path


def _cache_path(sample: Path) -> Path:
    return CACHE_DIR / f"{_sha256(sample)}.ghidra.json"


def _load(sample_path: str) -> dict[str, Any]:
    sample = _sample(sample_path)
    cache = _cache_path(sample)
    if not cache.is_file():
        raise ValueError("No cached Ghidra result. Call analyze_binary first.")
    return json.loads(cache.read_text(encoding="utf-8"))


def _headless_command(arguments: list[str]) -> list[str]:
    if os.name != "nt":
        return [str(HEADLESS), *arguments]
    comspec = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
    command_line = subprocess.list2cmdline([str(HEADLESS), *arguments])
    return [comspec, "/d", "/s", "/c", command_line]


def _function_index(data: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    by_entry: dict[str, Any] = {}
    by_name: dict[str, Any] = {}
    for function in data.get("functions", []):
        entry = str(function.get("entry", "")).casefold()
        name = str(function.get("name", "")).casefold()
        if entry:
            by_entry[entry] = function
        if name and name not in by_name:
            by_name[name] = function
    return by_entry, by_name


def _find_function(data: dict[str, Any], query: str) -> dict[str, Any]:
    wanted = query.strip().casefold()
    by_entry, by_name = _function_index(data)
    if wanted in by_entry:
        return by_entry[wanted]
    if wanted in by_name:
        return by_name[wanted]
    matches = [
        function for function in data.get("functions", [])
        if wanted in str(function.get("name", "")).casefold()
    ]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise ValueError(f"Function not found: {query}")
    raise ValueError(
        "Ambiguous function query: "
        + ", ".join(str(item.get("name")) for item in matches[:10])
    )


@mcp.tool()
def analyze_binary(
    sample_path: str,
    max_functions: int = 1200,
    max_decompile: int = 120,
    timeout_seconds: int = 900,
    force: bool = False,
) -> dict[str, Any]:
    """Import a PE/binary into Ghidra, run auto-analysis, and cache JSON evidence."""
    sample = _sample(sample_path)
    if not HEADLESS.is_file():
        raise ValueError(f"Ghidra analyzeHeadless not found: {HEADLESS}")
    exporter = SCRIPT_DIR / "ExportAnalysis.java"
    if not exporter.is_file():
        raise ValueError(f"Ghidra export script not found: {exporter}")

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    GHIDRA_PROJECT_DIR.mkdir(parents=True, exist_ok=True)
    cache = _cache_path(sample)
    if cache.is_file() and not force:
        data = json.loads(cache.read_text(encoding="utf-8"))
        return {
            "status": "cached",
            "sample": data.get("program"),
            "summary": data.get("summary"),
            "cache_path": str(cache),
        }

    max_functions = max(1, min(int(max_functions), 10_000))
    max_decompile = max(0, min(int(max_decompile), 2_000))
    timeout_seconds = max(60, min(int(timeout_seconds), 3_600))
    sha = _sha256(sample)
    project_name = f"mcp_{sha[:12]}_{int(time.time())}"
    arguments = [
        str(GHIDRA_PROJECT_DIR),
        project_name,
        "-import",
        str(sample),
        "-scriptPath",
        str(SCRIPT_DIR),
        "-postScript",
        "ExportAnalysis.java",
        str(cache),
        str(max_functions),
        str(max_decompile),
        "-analysisTimeoutPerFile",
        str(timeout_seconds),
        "-deleteProject",
    ]
    started = time.monotonic()
    process = subprocess.run(
        _headless_command(arguments),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds + 120,
        check=False,
        env=os.environ.copy(),
    )
    elapsed = round(time.monotonic() - started, 3)
    if process.returncode != 0 or not cache.is_file():
        raise RuntimeError(json.dumps({
            "message": "Ghidra headless analysis failed",
            "return_code": process.returncode,
            "stdout_tail": process.stdout[-6000:],
            "stderr_tail": process.stderr[-6000:],
        }, ensure_ascii=False))
    data = json.loads(cache.read_text(encoding="utf-8"))
    return {
        "status": "analyzed",
        "elapsed_seconds": elapsed,
        "sample": data.get("program"),
        "summary": data.get("summary"),
        "cache_path": str(cache),
        "headless_stdout_tail": process.stdout[-2000:],
    }


@mcp.tool()
def list_functions(
    sample_path: str,
    query: str = "",
    limit: int = 100,
) -> dict[str, Any]:
    """List Ghidra functions, optionally filtering by name/address substring."""
    data = _load(sample_path)
    wanted = query.casefold().strip()
    functions = [
        {
            "name": item.get("name"),
            "entry": item.get("entry"),
            "size": item.get("size"),
            "external": item.get("external"),
            "thunk": item.get("thunk"),
        }
        for item in data.get("functions", [])
        if not wanted
        or wanted in str(item.get("name", "")).casefold()
        or wanted in str(item.get("entry", "")).casefold()
    ]
    return {"count": len(functions), "functions": functions[:max(1, min(limit, 500))]}


@mcp.tool()
def get_function_details(sample_path: str, function: str) -> dict[str, Any]:
    """Return one function's address, signature, callers, callees, and decompilation."""
    return _find_function(_load(sample_path), function)


@mcp.tool()
def get_callers(sample_path: str, function: str) -> dict[str, Any]:
    """Return functions that call the selected function."""
    selected = _find_function(_load(sample_path), function)
    return {
        "function": selected.get("name"),
        "entry": selected.get("entry"),
        "callers": selected.get("callers", []),
    }


@mcp.tool()
def get_callees(sample_path: str, function: str) -> dict[str, Any]:
    """Return functions called by the selected function."""
    selected = _find_function(_load(sample_path), function)
    return {
        "function": selected.get("name"),
        "entry": selected.get("entry"),
        "callees": selected.get("callees", []),
    }


@mcp.tool()
def trace_call_path(
    sample_path: str,
    source_function: str,
    target_function: str,
    max_depth: int = 12,
) -> dict[str, Any]:
    """Find a bounded static call path between two Ghidra functions."""
    data = _load(sample_path)
    source = _find_function(data, source_function)
    target = _find_function(data, target_function)
    target_entry = str(target.get("entry", "")).casefold()
    by_entry, _ = _function_index(data)
    start = str(source.get("entry", "")).casefold()
    queue: deque[tuple[str, list[str]]] = deque([(start, [start])])
    visited = {start}
    max_depth = max(1, min(int(max_depth), 50))
    while queue:
        current, path = queue.popleft()
        if current == target_entry:
            return {
                "found": True,
                "path": [
                    {
                        "entry": entry,
                        "name": by_entry.get(entry, {}).get("name"),
                    }
                    for entry in path
                ],
            }
        if len(path) > max_depth:
            continue
        for callee in by_entry.get(current, {}).get("callees", []):
            next_entry = str(callee.get("entry", "")).casefold()
            if next_entry and next_entry not in visited:
                visited.add(next_entry)
                queue.append((next_entry, [*path, next_entry]))
    return {"found": False, "source": source.get("entry"), "target": target.get("entry")}


@mcp.tool()
def search_evidence(
    sample_path: str,
    query: str,
    limit: int = 100,
) -> dict[str, Any]:
    """Search function names, pseudocode, callees, and defined strings."""
    data = _load(sample_path)
    wanted = query.casefold().strip()
    if not wanted:
        raise ValueError("query must not be empty")
    matches: list[dict[str, Any]] = []
    for item in data.get("strings", []):
        if wanted in str(item.get("value", "")).casefold():
            matches.append({"type": "string", **item})
    for function in data.get("functions", []):
        searchable = "\n".join([
            str(function.get("name", "")),
            str(function.get("signature", "")),
            str(function.get("decompiled", "")),
            json.dumps(function.get("callees", []), ensure_ascii=False),
        ]).casefold()
        if wanted in searchable:
            matches.append({
                "type": "function",
                "name": function.get("name"),
                "entry": function.get("entry"),
                "signature": function.get("signature"),
                "decompiled": function.get("decompiled"),
            })
    limit = max(1, min(int(limit), 500))
    return {"query": query, "count": len(matches), "matches": matches[:limit]}


@mcp.tool()
def analysis_status(sample_path: str) -> dict[str, Any]:
    """Check whether a cached Ghidra analysis exists for this exact SHA-256."""
    sample = _sample(sample_path)
    cache = _cache_path(sample)
    return {
        "sample_path": str(sample),
        "sha256": _sha256(sample),
        "cached": cache.is_file(),
        "cache_path": str(cache),
        "ghidra_home": str(GHIDRA_HOME),
        "headless_exists": HEADLESS.is_file(),
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
