#!/usr/bin/env python3
"""Windows entry point for the Ghidra static-analysis MCP server."""

from __future__ import annotations

import ghidra_mcp_core as core


def direct_headless_command(arguments: list[str]) -> list[str]:
    # subprocess on Windows safely launches .bat files and quotes list arguments.
    return [str(core.HEADLESS), *arguments]


core._headless_command = direct_headless_command


if __name__ == "__main__":
    core.mcp.run(transport="stdio")
