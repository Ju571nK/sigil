# 구현 작업과 검증 계획

2026-09-27 · P0 조사·계약 후보·검증 fixture 작업 진행 중. 실제 배정과 증거는 [execution.md](execution.md)에 기록한다. P1 production 구현은 미착수다.

## 작업 흐름

요구사항 ID → 계약/결정 → 테스트 시나리오 → 구현 → 검증 증거 → 단계 완료 기록.
각 PR은 연결된 PX/AC ID, 계약 변경, 테스트, 알려진 제한을 포함한다.
manager 코드는 기존 manager 저장소에서 별도 PR로 작성하되 같은 계약 버전을 연결한다.
서버 소비자/API를 먼저 배포하고 proxy producer와 manager를 순차 활성화한다.

## P0 — 계약과 호환성 확정

| 작업 | 산출물 | 의존 |
|---|---|---|
| T-00 | server 인증·이벤트·정책·spool과 manager API/RBAC 조사, 재사용/신규 경계 확정 | 없음 |
| T-01 | 실제 client/server 버전별 protocol·capability·인증 probe; D-01/02 해결 | 없음 |
| T-02 | OpenAPI/JSON Schema, 예제 이벤트, 오류/버전 처리, 설정 경로·우선순위; D-03/05 해결 | T-00/01 |
| T-03 | fixture MCP, 장애 주입 절차, OS·limits·성능 목표; D-04 해결 | T-01 |

완료 조건: D-01–05와 P1 지원 표가 문서화되고 fixture가 재현 가능하다.
벤더 설정·권한·hook·MCP·무인 실행·OS 동작은 제품별 날짜가 있는 조사로 남긴다.
이번 준비 문서의 Codex 버전 확인만으로 호환성을 인정하지 않는다.

## P1 — 관찰 MVP

| 작업 | 구현 범위 | 요구사항 | 검증 |
|---|---|---|---|
| T-10 | crate/CLI/config/서비스 lifecycle, health와 limits | 001,013,016 | AC-07/12/14 |
| T-11 | core DTO와 server 등록·설정·권한·이벤트 저장/조회 | 007–012,016 | AC-04/05/06/13 |
| T-12 | HTTP relay, protocol adapter, principal 격리, 목적지 보호 | 002–004,008/009,014/015 | AC-01/03/04/07/08/15 |
| T-13 | inventory, 완전한 snapshot과 drift, 호출 lifecycle, privacy | 005–007,010 | AC-02/03/04/05 |
| T-14 | durable spool·재전송·중복 제거·복구 | 011,013,016 | AC-06/12 |
| T-15 | manager proxy/upstream 목록·상세·호출 검색·설정 화면 | 012,016 | AC-01/05/06/12/13 |
| T-16 | 설치·운영·복구 문서, E2E와 측정 결과, 출시 | 001–016 | P1 전체 (AC-14/15 포함) |

순서: T-10/11 계약 기반 → T-12 → T-13/14 → T-15 통합 → T-16.
화면은 T-11 fixture 계약으로 개발할 수 있지만 실제 데이터 E2E 없이 완료 처리하지 않는다.

## P2 — 정책 통제

- [ ] T-20: invocation 정책 모델·주체 grant·위임·폐기 계약 (PX-017–020).
- [ ] T-21: observe/enforce, 정책 버전/만료, 호출 시 검사, 감사 (AC-09/10/12).
- [ ] T-22: manager 정책·위임 관리, deployment별 우회 경계 표시, 회귀 검증.

의존: P1 완료. 승인 기능 미지원 상태의 require_approval은 전달하지 않고
unsupported/approval-unavailable로 기록한다. allow로 대체하지 않는다.
기존 assess API가 호출 정책을 충분히 표현한다고 가정하지 말고 별도 범위를 검증한다.

## P3 — 인간 승인과 확장

- [ ] T-30: D-06/07 확정, 승인 지문·상태 전이·RBAC·step-up 계약.
- [ ] T-31: server 승인 저장, proxy 원자적 소비·재검증, manager 승인함 (PX-021–023, AC-11/13).
- [ ] T-32: 사용자별 OAuth upstream 지원과 token 수명/폐기 시험.
- [ ] T-33: proxy 호스트 stdio supervisor, 실행 허용목록·환경 최소화·종료/격리 시험.

T-32/33은 별도 출시 단위이며 인간 승인 기능 완료와 혼동하지 않는다.
원격 PC bridge, HA/공유 세션 저장, 도구 통합 서버, 선택적 원문 캡처는 별도 후속 스펙이다.

## 검증 방법

- 계약: event/API schema golden fixture, old/new consumer 호환성, unknown field/variant 처리.
- 프로토콜: JSON/SSE, pagination, 알림, request ID, capability, 버전별 취소/세션,
  불명확한 전송 결과, 서버 요청 또는 신버전 대체 흐름을 실제 지원 범위대로 검증.
- 격리: 두 principal과 두 upstream의 같은 request/session 식별자를 사용해 교차 노출 시험.
- 보안: canary 비밀, 인증/인가, SSRF IPv4/IPv6/DNS/redirect, Origin, 비신뢰 metadata 렌더링.
- 복구: 강제 종료, 중복 이벤트, 중앙 단절, 디스크 한도, 설정 충돌·만료.
- 승인: 동시 승인 소비, 인자 교체, 정책/정의 drift, 만료, 재시작, 전달 직전 장애.
- 성능: 정해진 payload·동시성·긴 SSE 연결로 proxy 추가 p50/p95/p99 지연,
  메모리 상한·CPU·spool 증가량 측정. 직접 연결 기준과 비교.
- 제품 검증: 실제 client → proxy → 시험 MCP → server → manager에서 한 호출의 ID를 추적.
  버전/OS/날짜/설정/명령/결과를 기록하고 토큰·원문 비밀은 첨부하지 않는다.

## 완료 기록 템플릿

| 단계/작업 | PX/AC | PR·커밋 | 실행 환경·버전 | 검증 증거 | 제한·미해결 | 상태 |
|---|---|---|---|---|---|---|
| 준비 문서 | 전체 설계 | `97db268` | sigil 24eddb2 기준 | 문서 연결·요구사항 점검 | D-01–07 | 커밋 |
| P0 2026-10-10 회차 | PX-002–016, AC-01–08 계약·probe | 이 회차 커밋 | sigil cdd1d1d, macOS arm64, Claude Code 2.1.296, codex-cli 0.162.0, rustc 1.78–1.89 | T-01 probe + 독립 리뷰, contract v0.3 checker 53/271, fixture 14 tests | D-02, D-03·D-05 잔여, M2 사용자 결정, Linux 미검증 | P0 진행 |
