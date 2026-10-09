# P0 결정 기록

2026-09-27 · 구현 계약 확정과 검증 완료는 서로 다르다.

| 항목 | 현재 결정 | 상태/남은 증거 |
|---|---|---|
| 구현 언어 | proxy backend는 Rust/Tokio; manager 기존 stack 유지 | 확정. dependency/MSRV 선택은 D-01에서 별도 검증 |
| D-01 | 자동 SDK upgrade 금지. 지원 revision allowlist와 원문 보존 중계 필요 | 미확정: SDK/MSRV·실제 client wire probe. 버전 문자열 parse 성공은 지원 증거가 아님 |
| D-02 | client/proxy/upstream/manager identity 분리. 기존 fleet read token으로 관리 불가 | 부분 결정: bootstrap은 명시적 --config, 인증 방식과 manager 권한 mapping은 미확정 |
| D-03 | host event와 별도 proxy ledger; 원자적 수집·event-ID dedup | 부분 결정: 완전한 API/DTO, retention/tombstone, lifecycle semantic validation 필요 |
| D-04 | 첫 production 검증 대상 Ubuntu 24.04 LTS x86_64, macOS arm64 개발 | 검증 계획으로 채택. validation.md의 limits/benchmark 목표는 초기 시험 기준이며 성능 보장 아님 |
| D-05 | daemon HOME baseline 파일 공유 금지; proxy 소유 scope별 snapshot | 부분 결정: metadata registry/API와 versioned fingerprint 계약 필요 |
| D-06/07 | 승인 흐름·step-up/OAuth | 계획대로 P3 이전 확정 |

D-04의 수치는 [검증 계획](validation.md)을 단일 참조로 사용한다. 프로토콜별
세션/요청 차이에 따라 D-01 결정 시 적용 항목을 조정하고 변경 근거를 기록한다.
이 문서의 부분 결정만으로 production 경로 구현 gate를 통과했다고 해석하지 않는다.

## 다음 실행 단위

1. T-01 결과 기반으로 SDK 의존 여부와 Rust 최소 버전의 실제 빌드 대안을 비교한다.
2. fixture revision과 지원 대상 revision을 일치시키고 실제 client 1종의 안전한 HTTP 왕복을 측정한다.
3. T-02에서 등록·인증·route config·inventory·heartbeat·조회 DTO까지 완성한다.
4. 독립 계약 리뷰로 D-01–05를 닫은 뒤 P1 crate/서비스 구현을 시작한다.

임시 fixture나 schema 테스트는 위 실제 client 및 production 검증을 대신하지 않는다.
