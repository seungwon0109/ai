# v5 causal-attribution 변경 요약

## 해결한 오판

- CAPE 시그니처의 `data`에 있는 actor PID와 call ID를 정규화 결과에 보존합니다.
- 샘플 PID 계보와 무관한 `svchost.exe`, `backgroundTaskHost.exe` 등의 행위를 샘플 결론에서 제외합니다.
- actor PID가 없는 시그니처는 삭제하지 않고 `POSSIBLE`로 보존하되 확정 결론에는 쓰지 않습니다.
- 정적 capa/Ghidra 기능은 `INFERRED`이며 실행 사실이 아닙니다.
- `0xffffffff`, `-1` 같은 self pseudo-handle 호출은 원격 인젝션으로 판정하지 않습니다.

## 인과 귀속 단계

| 단계 | 의미 | 확정 결론 사용 |
|---|---|---|
| `DIRECT` | 제출 파일과 직접 일치한 루트 프로세스 | 예 |
| `CHILD` | 귀속 프로세스의 PPID 자손 | 예 |
| `CAUSAL` | 명시적 생성·원격 조작·파일 기록→실행으로 연결 | 예 |
| `POSSIBLE` | 관찰됐지만 주체 또는 인과관계가 부족 | 아니요 |
| `UNRELATED` | 샘플 인과 그래프 밖의 백그라운드 행위 | 아니요 |

모든 원본 텔레메트리는 증거 JSON에 남습니다. 분류는 삭제 필터가 아니라 보고서 결론 사용 정책입니다.

## 검증

- 단위·회귀 테스트 42개
- 직접/자식/무관 프로세스 분리
- self-handle 인젝션 오판 방지
- 성공한 원격 핸들 체인 귀속
- PPID가 끊긴 파일 기록→실행 귀속
- 실제 CAPE task 27에서 PID 1052/892의 시그니처 제외 확인

