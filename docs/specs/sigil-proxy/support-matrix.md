# Sigil Proxy P1 capability / 지원 표

2026-10-10 · PX-004 산출물 · AC-15의 시험 기준.
이 표는 "광고하거나 조용히 버리지 않는다"는 PX-004의 공개 표다. 구현 전이므로 **decided는 계약·결정 수준이며
proxy 구현 시험을 거친 것이 아니다.** 결정되지 않은 항목은 undecided로 남기며 추정하지 않는다.
undecided 행이 남아 있으면 AC-15와 P1 완료 정의를 통과할 수 없다.

## 라벨

| 라벨 | 의미 |
|---|---|
| measured | 실제 client 또는 fixture로 측정한 사실. 측정 대상(fixture/proxy)을 함께 적는다. 현재 proxy 경유 측정은 없다 |
| documented | 공식 문서·명세 열람. 측정하지 않았다 |
| decided | [decisions.md](decisions.md)·[contracts](contracts/README.md)에서 확정한 P1 동작. 구현·시험 전 |
| unverified | 시험하지 않았다 |
| undecided | 문서가 결정하지 않았다. P1 완료 전 결정 필요 |

근거: [T-01 probe](../../research/sigil-proxy-t01-probe-2026-10-10.md) (§4, §4b),
[decisions.md](decisions.md) D-01 후속 결정, [contracts/README.md](contracts/README.md) "Protocol revision, tasks and cancellation".

## 1. 프로토콜 revision 허용 목록

| Revision / 입력 | P1 처리 | 라벨 | 근거 |
|---|---|---|---|
| 2025-11-25 (Streamable HTTP) | **지원(유일)** | decided | D-01, M2 |
| 2025-06-18 — (a) client `initialize`가 제시 | 그대로 upstream에 전달하고 upstream 응답 revision으로 판단한다. 2025-11-25면 정상, 2025-06-18이면 (c) | decided | decisions.md "2025-06-18 downstream 입력" (a). codex-cli의 제시는 measured |
| 2025-06-18 — (b) initialize 이후 `MCP-Protocol-Version`이 협상된 2025-11-25와 다름 | 400 거절. modern 요청으로 분류하지 않는다. 감사 reason 상수는 [OPEN](reason 생략) | decided | 같은 행 (b). contracts/README.md "P1 method 범위와 route 거절 응답"에 반영 |
| 2025-06-18 — (c) upstream이 2025-06-18로 응답 | 미지원. route unsupported, 런타임이면 M2 거절(아래 마지막 행). 2025-06-18 추가는 fixture·계약 상수·scope key·독립 리뷰를 갖춘 별도 작업 | decided | D-01 M2, D-05 |
| 2026-07-28 modern 요청 (`server/discover`, `_meta`의 `io.modelcontextprotocol/protocolVersion`, 허용 목록 밖 `MCP-Protocol-Version`) | 인증 후 upstream에 전달하지 않고 HTTP 400 + empty body. `-32022`/`-32020`/`-32601`을 내보내지 않는다 | decided | D-01 B1. Claude Code가 fixture의 empty-body 400 뒤 `initialize` 2025-11-25로 대체함은 measured(proxy 경유 아님) |
| initialize 이후 `MCP-Protocol-Version` 누락 | 400 거절(의도적 엄격성). rmcp 0.16 client는 P1 미지원. 감사는 protocol_error/not_sent, reason 상수 [OPEN](contracts/README.md "P1 method 범위와 route 거절 응답"에 반영) | decided | m5. Claude·codex는 이후 모든 요청에 헤더 전송(measured) |
| upstream initialize 응답 revision이 허용 목록 밖 | route unsupported 표시. 런타임이면 downstream에 전달하지 않고 upstream session DELETE, initialize id에 고정 `-32603` (계약 미반영, decisions.md "런타임 route 거절 응답" 행이 근거) | decided | M2, "런타임 route 거절 응답" |

## 2. 기능별 처리

| 기능 | P1 처리 | 라벨 | 근거 / 비고 |
|---|---|---|---|
| `initialize`, `notifications/initialized` | 중계(initialize 응답만 한도 안에서 buffer 후 판단, 재작성 없음) | decided | D-01, N12. 두 client의 handshake는 fixture에서 measured |
| `tools/list` (pagination) | 중계·관찰, 완전한 snapshot만 baseline | decided | PX-005. fixture 2페이지는 measured(proxy 아님) |
| `tools/call` | 중계·관찰·자동 재실행 없음 | decided | PX-006/015. Claude의 재시도 없음은 measured(fixture) |
| `tools/call`의 `params.task` | 그대로 전달, 일반 결과로 감사 | decided | N10, 2025-11-25 tasks 규칙(documented) |
| `tasks/*` 요청 | 전달하지 않고 `-32601 Method not found`, protocol_error/not_sent | decided | N10 |
| upstream `capabilities.tasks` | capability를 제거·중계하지 않고 route unsupported(런타임이면 `upstream_capability_unsupported`) | decided | decisions.md "tasks capability". 실제 upstream의 tasks 채택 현황은 unverified |
| upstream이 보낸 task handle | 그대로 중계, protocol_error/sent로 기록, route degraded/unsupported 표시 | decided | N10 (ii) |
| 취소 (`notifications/cancelled`) | dispatch 전이면 미전달·`cancelled_before_dispatch`; dispatch 후면 전달 + cancel_requested, 무응답은 `cancel_no_response` | decided | M4. Claude가 타임아웃 시 전송함은 measured(fixture), codex는 unverified |
| POST 응답의 SSE 스트림 | 원문 byte 보존 중계 | decided | D-01 relay-first. JSON/SSE 왕복은 fixture에서 measured |
| GET SSE 스트림(서버 → client 알림 채널) | 인증 후 고정 405, upstream 미접속. POST 응답 스트림 재개 없음. GET으로만 오는 unsolicited 알림은 전달되지 않는다. contracts/README.md "P1 method 범위와 route 거절 응답"에 반영 | decided (사용자 결정) | [decisions.md "P1 기능 범위"](decisions.md). 두 client가 405를 허용함은 measured(fixture). 장기 스트림·재개는 해당 없음 |
| `*.listChanged` capability | 광고를 그대로 두고 문서화된 기능 저하로 취급한다. 요청 단위 POST 스트림으로 오는 알림만 전달된다 | decided (추론 근거; P1 실측 필요) | [decisions.md "P1 기능 범위"](decisions.md) |
| resources/subscribe, unsubscribe | 전달하지 않고 고정 `-32601`, protocol_error/not_sent(method `unknown`). upstream이 `resources.subscribe=true`를 광고하면 route unsupported(`upstream_capability_unsupported`). contracts/README.md "P1 method 범위와 route 거절 응답"에 반영 | decided (사용자 결정) | [decisions.md "P1 기능 범위"](decisions.md) |
| resources list/read/templates/list, prompts list/get | 그대로 중계. 감사는 method `unknown`, tool 없음, 원문 method 미기록. 세분화 method 값은 P2 | decided | [decisions.md "P1 기능 범위"](decisions.md) |
| 서버 → client 요청 (sampling, elicitation, roots) | POST 응답 스트림 안에서 bytes 그대로 중계. client의 JSON-RPC 응답(method 없음)을 malformed로 분류하지 않는다. 이벤트 없음, **관찰 사각지대**. contracts/README.md "P1 method 범위와 route 거절 응답"에 반영 | decided | [decisions.md "P1 기능 범위"](decisions.md). 두 client의 `elicitation` 선언은 measured. 실제 중계 시험은 not_run |
| 그 밖의 알림(progress, list_changed 등) | 그대로 중계, 이벤트 없음. progress는 최대 시간 제한(PX-013)을 연장하지 않는다 | decided | [decisions.md "P1 기능 범위"](decisions.md). `notifications/cancelled`는 위 취소 행 |
| JSON-RPC batch 배열 | 최상위 배열을 감지해 전달하지 않고 malformed 경로로 거절(2025-11-25 단일 메시지 규칙). method `unknown`, protocol_error/not_sent. contracts/README.md "P1 method 범위와 route 거절 응답"에 반영 | decided | [decisions.md "P1 기능 범위"](decisions.md). rmcp typed path의 415는 measured이며 proxy 응답과 무관 |
| 세션 종료 DELETE | 인증 후 같은 principal·route의 session만 처리(아니면 동일한 404). 묶인 upstream session에 DELETE 1회 전달(재시도 없음). upstream 2xx/404면 proxy session 무효화 후 이후 요청 404, 405·오류면 상태 그대로 전달하고 session 유지. 이벤트 없음. contracts/README.md "P1 method 범위와 route 거절 응답"에 반영 | decided | [decisions.md "P1 기능 범위"](decisions.md), M3. codex는 종료 시 DELETE, Claude는 관찰되지 않음(measured) |
| 인증: 정적 bearer | 지원. 모든 listener에서 필수, 요청마다 검사 | decided | N3, M3. Claude `headers`·codex `bearer_token_env_var`가 모든 요청에 전송함은 measured |
| 인증: 사용자별 OAuth, `WWW-Authenticate` discovery | P1 범위 밖. 상세 설계는 미결 | decided (범위만: spec PX-024) | 근거는 spec PX-024(P3)와 D-06/07(P3 전 확정 예정, 미결). 두 client의 동작은 documented, not measured |
| 요청 크기·응답·동시성 한도 | [validation.md](validation.md) "D-04 권고" 제안값을 P1 초기 기본값으로 사용 | decided (2026-10-10 사용자 결정) | 성능 보장 아님. 측정 후 조정한다(unverified) |

## 3. 클라이언트별 상태

| Client | 상태 | 라벨 | 제한 |
|---|---|---|---|
| Claude Code 2.1.296 (macOS arm64) | initialize·tools/list(페이지)·tools/call·타임아웃 취소를 fixture 대상으로 측정. static bearer 전송, 재시도 없음 | measured | proxy 경유 아님; 1회 실행; OAuth·headless 권한 기본값(`--allowedTools` 없이)은 unverified; modern 요청 400 뒤 fallback이 실제 proxy에서도 같은지는 P1 검증 항목 |
| codex-cli 0.162.0 (macOS arm64) | handshake와 `tools/list`만 관찰. initialize에서 **2025-06-18**을 제시하고 fixture의 2025-11-25 응답을 허용 | measured (handshake only) | **P1 제한(M2, 사용자 결정):** 2025-06-18도 지원하는 upstream은 2025-06-18로 답하고 proxy가 이를 거절하므로 이 조합은 P1에서 동작하지 않는다. 취소·tool call·재시도는 인증 run이 없어 unverified |
| rmcp 0.16 client | 이후 요청에 `MCP-Protocol-Version`을 보내지 않으므로 P1 미지원 | decided (m5) | 헤더 미전송은 measured |
| 그 외 client | 호환 주장 없음 | unverified | |

## 4. OS별 상태

| OS | 상태 | 라벨 | 제한 |
|---|---|---|---|
| Rocky Linux 9 (SELinux enforcing, rpm) | **production 첫 검증 대상** | decided (D-04, 2026-10-10 사용자 결정) | proxy 시험 전. 아키텍처별(aarch64 실기 VM, x86_64) baseline을 분리해 기록한다. T-01 probe는 Linux에서 실행하지 않았다(unverified) |
| macOS arm64 | 개발·probe 환경. production 대상 아님 | measured (probe·fixture) | 지원 보장 아님 |
| Windows 서비스 | 별도 검증 전 미지원 표시 | decided (contract 후보 문구 + D-04) | [contracts/README.md](contracts/README.md) "Bootstrap 구성 후보". D-04의 첫 대상은 Rocky 9이며 Windows 시험 기록은 없다(unverified) |
| 그 밖의 OS | P1 미지원 | decided (D-04: P1 production 대상은 Rocky Linux 9, macOS는 개발 환경) | 시험 기록 없음. 추가하려면 별도 호환성·실기 검증 |

## 5. AC-15 시험 기준 (행별 oracle)

"upstream 호출 수"는 시험 fixture의 호출 카운터(oracle)이며 제품 감사 API가 아니다.

| 입력 | 기대 결과 |
|---|---|
| modern 요청, 인증됨 | HTTP 400, 빈 body, upstream 호출 수 0. 감사: method·protocol_version `unknown`인 start + protocol_error/not_sent/`modern_request_unsupported`. 원문 method·`_meta`·헤더 값 미기록 |
| modern 요청, 미인증 | 401. B1 처리·invocation 이벤트 없음. upstream 호출 수 0 |
| Claude Code가 400 뒤 `initialize` 2025-11-25로 대체 | 기대 결과이며 정상 세션이 수립된다(실제 proxy 경유 확인은 P1 검증 항목) |
| client `initialize` 2025-06-18 제시, upstream이 2025-11-25로 응답 | initialize가 upstream에 그대로 전달(호출 수 1), 응답 bytes 재작성 없이 중계, 세션 수립 |
| client `initialize` 2025-06-18 제시, upstream이 2025-06-18로 응답 | downstream에 전달하지 않음, initialize id에 고정 `-32603`(HTTP 200), upstream session DELETE, protocol_error/sent/`upstream_version_unsupported` |
| initialize 이후 헤더가 협상값과 다름 또는 누락 | HTTP 400, upstream 호출 수 0. 감사 reason 상수는 [OPEN](정해지기 전에는 reason 값을 시험하지 않는다) |
| upstream `capabilities.tasks` (등록·health) | route unsupported 표시, 신규 세션 거절 |
| upstream `capabilities.tasks` (런타임) | downstream 세션 미수립, initialize id에 고정 `-32603`, upstream DELETE, protocol_error/sent/`upstream_capability_unsupported` |
| `tasks/*` 요청 | `-32601 Method not found`, upstream 호출 수 0, protocol_error/not_sent/`task_augmentation_unsupported` |
| `tools/call`의 `params.task` | byte 보존 전달, 일반 outcome으로 감사 |
| GET SSE (인증됨) | 405, upstream 호출 수 0. 미인증은 401 |
| `resources/subscribe`·`unsubscribe` | `-32601`, upstream 호출 수 0, protocol_error/not_sent. upstream이 `resources.subscribe=true` 광고 시 route unsupported |
| resources list/read, prompts list/get | upstream 호출 수 1, 응답 중계, method `unknown`으로 감사 |
| JSON-RPC batch 배열 | 미전달(upstream 호출 수 0), malformed 경로 거절, protocol_error/not_sent. 정확한 client 응답 형태는 [OPEN] |
| 서버 → client 요청과 client 응답 | bytes 그대로 중계, client 응답이 malformed로 거절되지 않음. 이벤트 없음 |
| 세션 DELETE | 같은 principal·route면 upstream DELETE 1회. 다른 principal·존재하지 않는 session은 동일한 404 |
| undecided 행 | 시험 불가. 결정 후 행을 갱신해야 AC-15를 통과한다 |
