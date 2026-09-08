# AI Malware Analysis PoC

This proof of concept combines host-safe static analysis, Ghidra evidence, and
CAPE execution inside the isolated Windows analysis VM. A local AI model reviews
the combined evidence three times. Cloud AI is optional and reserved for the
final report.

## Run

```powershell
python .\main.py ".\samples\sample.exe"
```

`main.py` automatically loads the local CAPE token from WSL, selects the CAPE
package from the file type, enables Ghidra for PE files, and uses
`malware-qwen:9b` when it is available in Ollama. Each run creates the raw CAPE
report, combined evidence, an AI packet, and a final report under
`results\runs\timestamp_sample`. Cloud AI is disabled by default.

```powershell
# Host-safe static analysis only
python .\main.py ".\samples\sample.exe" --static-only

# Skip Ghidra but keep CAPE dynamic analysis
python .\main.py ".\samples\sample.exe" --skip-ghidra

# Only after cloud endpoint, model, and API key settings have been configured
python .\main.py ".\samples\sample.exe" --use-cloud
```

Never double-click or manually execute a suspicious sample. `main.py` reads it
for static analysis on the host and submits it to the isolated CAPE guest for
execution.

## Layout

| Path | Purpose |
| --- | --- |
| `main.py` | One-command static, Ghidra, CAPE, and AI orchestrator |
| `DEMO.py`, `demo_core.py`, `ai_entry.py` | Core pipeline and three local-AI evidence reviews |
| `CAPE_DEMO.py`, `cape_entry.py`, `cape_client.py` | CAPE collection and bounded dynamic-evidence integration |
| `src/common_evidence/attribution.py` | Causal process/signature attribution without deleting background telemetry |
| `GHIDRA_MCP_SERVER.py`, `ghidra_mcp_core.py`, `ghidra_scripts` | Ghidra static-analysis MCP server and export script |
| `config` | Run configuration, including the initial MCP plan |
| `samples` | User-provided suspicious files; never execute directly |
| `results` | Evidence JSON, AI packets, and reports for real samples |
| `cache` | Reusable Ghidra cache and Ghidra project files |
| `archive/smoke_tests` | Historic development-test outputs; unused during analysis |
| `.venv` | Project-only Python dependencies |

Keep private material such as `private.pem` out of Git and shared folders.
# Evidence-bound 보고서 안전장치 v5

최종 보고서는 로컬·클라우드 모델의 자유서술을 그대로 저장하지 않습니다.

- CAPE의 모든 프로세스·시그니처는 보존하고 `DIRECT`, `CHILD`, `CAUSAL`, `POSSIBLE`, `UNRELATED`로 귀속합니다.
- 제출 파일 일치, PPID 계보, 명시적 프로세스 생성, 원격 핸들 조작, 기록한 실행 파일의 후속 실행만 인과 근거로 사용합니다.
- 단순 시간 순서, 프로세스 이름 유사성, `OpenProcess` 조회만으로 인과관계나 인젝션을 주장하지 않습니다.
- `0xffffffff`/`-1` 같은 자기 프로세스 pseudo-handle은 원격 인젝션에서 제외합니다.
- `DIRECT`/`CHILD`/`CAUSAL` 증거만 샘플의 확정 결론에 사용할 수 있습니다.
- capa·Ghidra 정적 기능은 실제 실행 행위로 승격하지 않습니다.
- 서비스 시작과 서비스 생성, 키보드 배열 조회와 키로깅을 구분합니다.
- 네트워크·파일 삭제·암호화 완료는 대응하는 동적 이벤트가 있어야 확정합니다.
- 모델 JSON이 잘못되면 재시도 루프 없이 1회에서 종료하고 evidence-only 보고서를 생성합니다.
- 최종 Markdown은 항상 현재 샘플의 검증된 구조화 증거로 다시 렌더링합니다.
- CAPE 시그니처의 `data`와 actor PID를 버리지 않으며, 주체가 없는 시그니처는 `POSSIBLE`로만 유지합니다.
- 기존 결과의 구형 AI 보고서는 `evidence_bound_version=3`이 아니면 재사용하지 않습니다.
