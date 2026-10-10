# Sigil Proxy 작업 상태

갱신: 2026-10-10 · Claude Code orchestrator 세션 (기준 커밋 `cdd1d1d`)

## 현재 상태

- P0 부분 진행. Production proxy 및 manager 구현은 미착수.
- 사용자 창구: 이 대화의 orchestrator.
- 2026-10-10 회차 종료. 실행 중 작업자 없음(spec-auditor, review-lead, coding-lead, contract-coder 모두 완료).
  위임 실적: coding-lead만 하위 모델 사용(sonnet: raw relay, haiku: MSRV 빌드). 나머지 lead는 작업 규모가 작아 직접 수행.
- 회차 결과: D-01 구조 결정 + 후속 결정, D-03 ingest 하위 계약 동결, contract v0.3(checker PASS 53/271, orchestrator 재실행 확인),
  T-01 probe 증거(독립 리뷰 통과), 기존 workspace MSRV 불일치 #240 등록.
- P1 production 코드(`crates/`)와 공유 계약(`contracts/`)은 D-01–05 종료 전 배정하지 않는다.
- 문서/fixture 통과를 P0 완료로 해석하지 않는다.

## 2026-10-10 배정

| 작업 | 역할/인스턴스 | 목표 | Spec | 소유 파일 |
|---|---|---|---|---|
| P0-spec-audit | spec-auditor (읽기 전용) | 추적성·P0 종료 조건·배정 적합성·선행 가능한 P1 작업 점검 | 전체 PX/AC, D-01–05 | 없음 (orchestrator에 보고) |
| P0-targeted-rereview | review-lead (reviewer) | R1–R3 수정·lifecycle·fixture 독립 재리뷰 | PX-003/006/007/010/011/015, AC-03/05/06, D-02/03 | `review-p0-followup.md` |
| T-01 resume | coding-lead (coder, probe 한정) | SDK vs raw relay, MSRV 빌드, 실제 client HTTP 왕복 | PX-003/004/008/015, AC-07, D-01/02 | `scripts/proxy-p0/probes/**`, `docs/research/sigil-proxy-t01-probe-2026-10-10.md` |

## 작업 보드

| 작업 | 상태 | 산출물/증거 | 남은 조건 |
|---|---|---|---|
| T-00 | done: source survey | [저장소 조사](../../research/sigil-proxy-repository-survey-2026-09-27.md) | 실기 결과를 뜻하지 않음 |
| T-01 | done: evidence (2026-10-10 coding-lead), review pending | [T-01 probe](../../research/sigil-proxy-t01-probe-2026-10-10.md): rmcp 0.16 typed 경로는 unknown field 유실·version allowlist 없음; raw hyper relay 10/10 byte 동일; Claude Code 2.1.296·codex 0.162.0 실제 HTTP 왕복(macOS loopback) | 독립 리뷰(T-01-review), -32022 반응·Linux 미검증. 기존 workspace는 선언 MSRV 1.78에서 빌드 불가(측정, 최저 1.88) → #240 |
| T-02 | draft, review fixes applied | [계약](contracts/README.md), schema 정상24/거부60 통과 | 독립 재리뷰, 인증/API/ledger 계약 확정 |
| T-03 | done: fixture preparation | [검증 계획](validation.md), smoke + 14 self-tests 통과 | T-01 revision 정합성, 실제 proxy benchmark/E2E |
| P0-review | done: needs_changes | [초기 리뷰](review-p0.md), R1–R3 | 후속 수정 독립 검토 |
| T-02-fix | done: coder report + tests | contracts/만 수정, coordinator checker 재실행 통과 | 독립 승인 아님 |
| P0-targeted-rereview | done: needs_changes (2026-10-10 review-lead) | [재리뷰](review-p0-followup.md): R1–R3 해결, 신규 major N1–N4·N9(metadata registry offline 모순), minor N5–N8. checker 24/60, smoke, 14 tests 통과 (승인 아님) | contract owner가 N1–N4·N9 수정 → 표적 독립 재확인. D-02는 N3, D-05는 N9 결정 전 종료 불가. N4·revision 고정은 D-01 결과와 함께 처리 |

## 결정과 다음 작업

[결정 기록](decisions.md)에 언어·배포·저장 경계와 미해결 항목을 기록했다.
D-04의 시험 환경·초기 한도는 시험 기준으로 채택했으며 성능 보장이 아니다.

1. 사용자 결정: 첫 production 대상 OS(D-04), #240 MSRV 방향. (M2는 2026-10-10 A로 확정: 2025-11-25만 지원, codex 제한 명시)
2. D-02 계약: 인증 mapping, manager 권한(proxy.read/manage), CSRF/Origin, M3 header 정책, 런타임 route 거절 응답 반영.
   manager 변경은 sigil-manager에 이슈로 요청한다.
3. D-03 잔여(retention, projection/query DTO, semantic validation, aggregate 계약)와 D-05 잔여(registry DTO, key rotation, drift 이벤트).
4. 추적성 보완: PX-001(기본 비활성) 시나리오, PX-004 capability/support 표 산출물, fixture N5/N6.
5. D-01–05 인수 조건 확인 후 P1 crate와 서비스 구현으로 넘어간다.

## 실행 이력

| 역할/작업 | Task | Dispatch | 결과/정리 |
|---|---|---|---|
| T-00 | task_8effdc8ddb34 | ctx_7cca1b7a0087 | succeeded, released |
| T-01 | task_8a942cd9d0a2 | ctx_3e7856e537a5 | session restore failure, stopped |
| T-01 retry | task_8a942cd9d0a2 | ctx_64bc0eeaa75a | session restore failure, stopped |
| T-03 | task_8ef4195c1ee4 | ctx_913145acde55 | tests written, session restore failure, stopped |
| T-03 retry | task_8ef4195c1ee4 | ctx_d26b47a10bb9 | docs completed, succeeded/released |
| review | task_e8c5761b056a | ctx_ae5cff21b3e8 | findings delivered, succeeded/released |
| fixes | task_3fd3cf9f0136 | ctx_6f6279a00c6f | fixes delivered, succeeded/released |
| re-review | task_019b8018bdcc | ctx_ced4fae98e2a | observed shell parse failure, stopped |
| re-review retry | task_019b8018bdcc | ctx_4876e7ff14cd | session restore failure, stopped |
| spec-audit | 2026-10-10 | spec-auditor | needs_changes 보고 (D-01 MSRV 모순, 추적성·stale 문서, 배정 보정), completed |
| re-review (resume) | 2026-10-10 | review-lead | needs_changes 보고, completed. 기존 체크포인트를 덮어썼다가 정정 지시 후 원문을 맨 위로 복원 |
| T-01 (resume) | 2026-10-10 | coding-lead | completed; 하위 위임 sonnet(raw relay)·haiku(MSRV 빌드). toolchain 1.78/1.85/1.88/1.89.0 추가 설치 |
| T-01-review | 2026-10-10 | review-lead | needs_changes 보고 (B1 blocker, M1–M4, m1–m8), completed. 핵심 측정 3종 재현 일치 |
| T-01-fix | 2026-10-10 | coding-lead | completed: B1/M1–M4/m1–m8 반영, compare.py·server_probe.py 재실행 통과, client 재실행 없음 |
| T-02-fix-2 re-check | 2026-10-10 | review-lead | completed: N1–N4·N7–N9 계약 범위 해결(주장 전부 재현), 신규 major M1(state loss)·M2(batch/registry liveness)·M3(cancel 순서), minor m1–m6. D-03/D-05 종료 불가 권고 |
| D-01 후속 결정안 + T-01 정정본 리뷰 | 2026-10-10 | review-lead | completed: B1·m5 승인(m5 근거 정정), M3 보완 후 승인, M4 수정(dispatch 안 함), M2는 codex 2025-06-18 결과 명시 필요, tasks는 route 단위 거절 권고. T-01 정정 전부 반영 확인. R1은 keyed ref에서도 유지 |
| T-02-fix-3 (M1–M3, m1–m5) | 2026-10-10 | contract-coder (소유: contracts/**) | completed: contract v0.3, checker PASS 43/196 (+dedup 10, batch 4, registry 4, ref 5), -O/-OO·no-format exit 2. 중간 정정 2–5 미반영 |
| T-02-fix-3b (tasks route 거절, upstream_version_unsupported, modern 요청 감사, key_id 고유성) | 2026-10-10 | contract-coder | completed: checker PASS 48/234, -O·no-format exit 2 |
| v0.3 + fix-3b 표적 재확인 | 2026-10-10 | review-lead | completed: M1·M2a·M2b·M3·m1–m5 해결, 신규 major N10(params.task 거절이 2025-11-25 tasks 규칙 위반), minor N11–N14. D-03/D-05 종료 불가 |
| T-02-fix-4 (N10–N14, task handle route 표시, entry hash 검사) | 2026-10-10 | contract-coder | completed: checker PASS 53/271 (+model 35), -O·no-format exit 2 |
| T-02-fix-4 최종 재확인 | 2026-10-10 | review-lead | completed: 신규 finding 없음, D-03 ingest 하위 계약 동결 권고 |
| T-02-fix-2 (N1–N4·N7–N9) | 2026-10-10 | contract-coder (소유: contracts/**, design.md:47) | completed: schema 후보 v0.2, checker PASS 40/169 (+dedup 7, ref 5), format 미설치 시 exit 2 |

복구 중 파일을 덮거나 작업을 성공으로 재분류하지 않았다. P0 산출물은 `97db268`로
main에 커밋·push되었다. 외부 배포·manager 변경·사용자 MCP 설정 변경은 하지 않았다.
