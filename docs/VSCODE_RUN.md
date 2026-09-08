# VSCode execution

Open `D:\my life\악성코드 분석` as the VSCode folder and select this interpreter:

`D:\my life\악성코드 분석\.venv\Scripts\python.exe`

In a PowerShell terminal:

```powershell
cd "D:\my life\악성코드 분석"
Set-ExecutionPolicy Bypass -Scope Process -Force
.\.venv\Scripts\Activate.ps1
python -m unittest discover -v
```

## Static analysis only

```powershell
python main.py ".\samples\sample.exe" --static-only
```

For a direct PE file this runs PE parsing, capa when available, Ghidra MCP, and
the local AI passes. It does not run CAPE.

## Static and dynamic analysis

```powershell
python main.py ".\samples\sample.exe"
```

This uses the same static pipeline and submits the original sample to the CAPE
Windows analysis VM. CAPE is collected before the first local-AI pass.

## Password-protected ZIP

```powershell
python main.py ".\samples\sample.zip" --archive-password infected
```

Select a specific archive member when needed:

```powershell
python main.py ".\samples\sample.zip" `
  --archive-password infected `
  --archive-member "sample.exe"
```

Cloud AI is disabled by default. Add `--use-cloud` only when intentionally
configured. Add `--no-local-ai` to test only the deterministic analyzers.

Each run creates these important files under `analysis-results/runs/<run>`:

- `*.evidence.json`: complete raw and normalized evidence
- `*.common-evidence.json`: EvidenceSource, ArtifactRecord, Entity, Event,
  Relation, Claim, and ATTACKMapping objects
- `*.cape.json`: raw CAPE report when dynamic analysis is enabled
- `*.report.md`: final report

The `ai_validation` object inside `*.evidence.json` records rejected evidence
IDs, unknown function names, ATT&CK validation results, and static/dynamic
conflicts detected by the validator.
