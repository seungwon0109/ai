from pathlib import Path

path = Path(__file__).resolve().parents[1] / "docs" / "ISOLATED_ZIP_ANALYSIS.md"
text = path.read_text(encoding="utf-8")
text = text.replace(
    "4. PE metadata, strings, imports, findings, and CAPE's capa rules are collected.\n",
    "4. PE metadata, strings, imports, CAPE's capa rules, and Ghidra Headless decompilation are collected.\n",
)
old = '''## Current limitation

The CAPE WSL environment has capa and its rules/signatures, but not Java or
Ghidra. ZIP-member Ghidra analysis therefore remains disabled until a Linux JDK
and Ghidra Headless are installed inside the isolated static environment.
'''
new = '''## Ghidra and hash correlation

OpenJDK 21 is installed in the CAPE WSL environment. The existing Ghidra 12.1.2
distribution is used through its Linux `analyzeHeadless` launcher. Its project,
decrypted sample, and decompiler output files are created only in WSL temporary
storage and deleted after structured JSON is collected.

The encrypted outer ZIP and decrypted inner executable intentionally have
different SHA-256 values. Both are retained as separate entities linked by a
`CONTAINS` relation. CAPE then verifies the outer upload hash and separately
correlates the inner hash with report objects and observed process names.
'''
if old not in text:
    raise RuntimeError("documentation limitation marker not found")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
print("Updated isolated ZIP documentation for WSL Ghidra and dual-hash correlation.")
