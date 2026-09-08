# Qwen3.5 9B agent runtime

The default local model is `malware-qwen:9b` (Qwen3.5 9B through Ollama).

## Runtime flow

1. Detect the input type and choose the analyzer route.
2. Collect static evidence with the built-in parser, capa, and Ghidra MCP.
3. Build a bounded evidence context (maximum 8,000 characters).
4. Run three local-agent stages: triage, investigation, and critical review.
5. Permit at most two tool requests per stage and six per run.
6. Reject duplicate tool requests and force every request to the current sample.
7. Normalize CAPE output into common events when dynamic analysis is enabled.
8. Validate evidence IDs, confidence levels, function names, and ATT&CK mappings.
9. Write the evidence graph, agent trace, cloud packet, and report.

Local Ollama requests use `/api/chat` with `think: false`. This prevents the
Qwen reasoning channel from consuming the response budget before the required
JSON object is emitted. The response budget is 2,048 tokens; local context is
8,192 tokens and the evidence packet itself is capped at 8,000 characters.

## Evidence levels

- `OBSERVED`: literal static artifact or API/string/capa observation.
- `INFERRED`: code-flow or correlated evidence supports the claim.
- `CONFIRMED`: a CAPE event or another confirmed dynamic artifact supports it.

The output guard removes unknown evidence IDs. A static-only claim labelled
`CONFIRMED` by the model is automatically downgraded to `INFERRED`.

## VS Code commands

Run these in the project terminal after activating `.venv`.

```powershell
# Static analysis only: parser + capa + Ghidra MCP + Qwen agent
python main.py ".\malware-vault\sample.exe" --static-only

# Full analysis: static path + isolated CAPE dynamic path + Qwen agent
python main.py ".\malware-vault\sample.exe"

# Password-protected archive
python main.py ".\malware-vault\sample.zip" --archive-password infected
```

Do not manually extract or execute a real sample on the host. Full analysis is
allowed only when the isolated CAPE guest is ready and the host pipeline reports
that CAPE is available.

## Important outputs

- `*.evidence.json`: complete evidence and analyzer output.
- `*.common-evidence.json`: normalized entities, events, relations, and claims.
- `*.agent-run.json`: bounded-agent decisions, context hashes, and tool trace.
- `*.cloud-packet.json`: compact validated packet for an optional cloud judge.
- `*.report.md`: final readable report.
