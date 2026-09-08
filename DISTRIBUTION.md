# Causal-attribution v5 전체 소스 교체본

이 ZIP에는 실행에 필요한 Python 전체 소스, 설정, 문서, 테스트가 들어 있습니다.
용량이 큰 `.venv`, `tools/capa/capa.exe`, 샘플, 기존 분석 결과는 포함하지 않았습니다.

기존 프로젝트 폴더에 같은 경로로 덮어쓰거나 별도 폴더에서 사용할 수 있습니다.

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -p "test_*.py"
python .\main.py ".\samples\분석대상.zip" --archive-password "infected"
```

기존 `tools/capa/capa.exe`, `samples`, CAPE 설정은 그대로 유지하면 됩니다.

## 핵심 변경

- 전체 CAPE 텔레메트리 보존 + 5단계 인과 귀속
- 시그니처 actor PID/data 보존 및 무관한 Windows 백그라운드 행위 제외
- PPID가 끊겨도 명시적 프로세스 생성·원격 조작·파일 기록→실행 엣지로 인과관계 복구
- self pseudo-handle을 원격 인젝션으로 오판하지 않음
- capa/Ghidra 정적 기능을 실행 사실로 승격하는 주장 거부
- 서비스 시작과 서비스 생성, 키보드 배열 조회와 키로깅 분리
- 네트워크·삭제·암호화 완료에 동적 증거 요구
- 도메인 모델 호출 제한 적용
- 최종 보고서 모델 호출 1회 제한 및 즉시 결정론적 fallback
- 과거 샘플 고정 서술 제거
- 최종 Markdown을 evidence-bound 구조화 데이터에서만 생성
