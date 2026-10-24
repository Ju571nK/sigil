# P0 결정 기록

2026-09-27 · 갱신 2026-10-10 · 구현 계약 확정과 검증 완료는 서로 다르다.

| 항목 | 현재 결정 | 상태/남은 증거 |
|---|---|---|
| 구현 언어 | proxy backend는 Rust/Tokio; manager 기존 stack 유지 | 확정. dependency/MSRV 선택은 D-01에서 별도 검증 |
| D-01 | **2026-10-10 구조 결정:** relay-first. 원문 bytes를 그대로 중계하고 관찰·정책용으로만 사본을 parse한다. 전달 경로에 SDK typed message를 쓰지 않는다(rmcp 0.16.0 측정: unknown field 유실, version allowlist 없음, version header 미전송, cancel 지연). P1 지원 revision은 잠정 2025-11-25(legacy) 하나. proxy는 rmcp에 의존하지 않으므로 proxy 때문에 MSRV를 바꾸지 않는다 | 부분 결정. 근거: [T-01 probe](../../research/sigil-proxy-t01-probe-2026-10-10.md) + 독립 리뷰(T-01-review). 미결: 프록시 경유 B1 재측정(P1 검증), codex 인증 run. 나머지(B1·M2·M3·M4·m5)는 아래 "D-01 후속 결정"에서 확정. 기존 workspace MSRV 불일치는 별건 #240. **P0 종료(2026-10-11)**: 잔여는 아래 "P0 종료" 절 |
| D-02 | client/proxy/upstream/manager identity 분리. 기존 fleet read token으로 관리 불가. **2026-10-10 사용자 결정(추천안 전부 채택):** 아래 "D-02 결정" 절 | 계약 결정(control-plane.md). 구현·실기 검증은 P1. sigil-manager 변경 요청은 issue로만 |
| D-03 | host event와 별도 proxy ledger; 원자적 수집·event-ID dedup. **2026-10-10: ingest 하위 계약 동결**(schema v0.3 envelope·payload, 전체 event dedup, epoch, 422/403/409/424 batch error items; 2026-10-10 개정: identity 불일치·미등록 proxy는 선검사 404 `proxy_unknown`, integrity gap 보고, startup 규칙). 계약 수준·fixture/model 증거만이며 ledger 구현 시험은 P1 | 부분 결정. 남은 항목: retention·dedup tombstone 기간(최대 offline 재시도 기간 대비), invocation projection/query DTO(out-of-order·start-only 규칙), cross-event semantic validation 규칙·시험, 인증 실패·unmatched cancel aggregate 계약, 관리·등록·config·heartbeat DTO. **P0 종료(2026-10-11)**: 잔여는 아래 "P0 종료" 절 |
| D-04 | **2026-10-10 사용자 결정:** 첫 production 검증 대상은 Rocky Linux 9(RHEL 계열, SELinux enforcing, rpm 배포). 아키텍처별 결과는 별도 baseline으로 기록한다(현재 실기 VM은 aarch64). macOS arm64는 개발 환경 | 대상 OS 확정. validation.md의 limits/benchmark 목표는 초기 시험 기준이며 성능 보장 아님. Ubuntu 24.04 x86_64 권고안은 대체됨 |
| D-05 | daemon HOME baseline 파일 공유 금지; proxy 소유 scope별 snapshot. **2026-10-10:** metadata_ref는 proxy가 per-proxy 키로 로컬 발급(HMAC, UUIDv8), scope key·fingerprint `sigil-tooldef-fp-v1`·offline 해석·sync 순서·retryable 424·registry 동일성(불변 필드)·local entry hash 검사 계약화 | 부분 결정. 남은 항목: registry entry DTO·schema, key rotation 운영과 이력 연결, re-baseline marker projection, inventory/drift event 계약. M2 사용자 결정(2025-06-18 추가 시 scope key의 protocol_version 값 증가). **P0 종료(2026-10-11)**: 잔여는 아래 "P0 종료" 절 |
| D-06/07 | 승인 흐름·step-up/OAuth | 계획대로 P3 이전 확정 |

## D-02 결정 (2026-10-10, 사용자 결정: 추천안 전부 채택)

근거: [control-plane.md](contracts/control-plane.md) §9, 독립 리뷰(r-w3-review) 승인. 계약 수준 결정이며 구현·실기 검증은 P1이다.

| # | 항목 | 결정 |
|---|---|---|
| 1 | proxy identity | A1a: proxy 전용 CA를 client bundle에 추가하고 server registry에 `proxy_id`를 SAN·DER blake3 fingerprint와 묶는다. 관리 caller cert class는 host CA + verifier 파일의 fingerprint 목록(최소안). proxy CA는 관리 cert에 쓰지 않는다. TLS terminator 뒤 loopback 구성은 proxy·관리 route를 제공하지 않는다 |
| 2 | 관리 자격증명 | B1′: server verifier 파일의 관리 bearer, scope `config`/`identity`, `requested_by`는 asserted로 기록(B4). 검사 순서: 관리 cert class(404) → bearer(401) → scope(403) |
| 3 | manager 범위 | M0: P1에서 manager는 proxy 기능 읽기 전용. 관리 조작은 operator CLI. viewer/operator mapping·CSRF R1–R13은 M1 채택 시에만 |
| 4 | downstream token 생성 | proxy-host CLI가 생성하고 server에는 verifier만 제출 |
| 5 | server 미도달 상태 재시작 | fail closed: 새 config fetch 전까지 forwarding하지 않는다 |
| 6 | disable→re-enable 후 event | 수용하고 제시한 cert fingerprint를 태그한다 |
| 7 | upstream 401/403 감사 | `unknown`/`sent`, reason 없음(schema 상수 추가 없음) |
| 8 | credential_ref origin 바인딩 | proxy 로컬 bootstrap의 `upstream_origins`에 묶는다. 원격 config는 넓힐 수 없고 불일치는 적용 전체 실패(`apply_failed`) |
| — | identity 불일치 응답 | 404 `proxy_unknown`을 채택한다(미등록과 구별 불가, 422>403>409>424보다 먼저 평가). D-03 ingest의 identity 403을 대체한다 |
| — | O-1 미전송 event 만료 | A: R 경과 후 미전송 event를 변경 없이 quarantine으로 옮기고 `spool_expired` gap을 보고한다. 조용한 삭제 없음 |
| — | D-04 한도 | validation.md "D-04 권고" 제안값을 P1 초기 기본값으로 채택한다. 성능 보장이 아니며 측정 후 조정한다 |

## D-01 후속 결정 (2026-10-10, 독립 리뷰 반영)

T-01 리뷰(B1, M2–M4, m5) 후속 결정. 독립 리뷰(review-lead, 2026-10-10) 결과를 반영했다.
상태: **확정** = 리뷰 승인, **잠정** = 사용자 판단 또는 추가 증거 필요.

| 항목 | 결정 | 상태·근거 |
|---|---|---|
| B1 modern 요청 | 인증을 먼저 검사한다(미인증은 401). `server/discover`, `io.modelcontextprotocol/protocolVersion` `_meta`, allowlist 밖 `MCP-Protocol-Version` 헤더는 upstream에 전달하지 않고 HTTP 400 + empty body로 답한다. legacy-only 동안 -32022/-32020/-32601을 내보내지 않는다. 감사: method·protocol_version `unknown` start + protocol_error/not_sent/`modern_request_unsupported` completion, 원문 method 미기록 | 확정. 2026-07-28 streamable-http Backward Compatibility, T-01 측정. 실제 proxy 경유 Claude 재측정은 P1 검증 |
| M2 upstream version | route 등록·health 확인에서 upstream initialize revision이 allowlist 밖이면 route를 unsupported로 표시한다. 런타임에는 initialize 응답(SSE 포함)을 한도 안에서 buffer해 판단하고, allowlist 밖이면 downstream에 전달하지 않고 upstream session을 DELETE하며 protocol_error/sent/`upstream_version_unsupported`로 기록한다. bytes는 재작성하지 않는다 | **확정(2026-10-10, 사용자 결정 A).** P1 allowlist는 2025-11-25 하나다. 알려진 제한: codex-cli 0.162.0은 initialize에서 2025-06-18을 제시하므로(측정), 2025-06-18도 지원하는 upstream은 2025-06-18로 답하고 proxy가 이를 거절한다. 이 조합은 P1에서 동작하지 않으며 P1 capability/support 표에 명시한다. 2025-06-18 추가는 버전별 fixture·계약 상수·scope key 값과 독립 리뷰를 갖춘 별도 작업이다 |
| M3 header 정책 | 요청 방향: downstream `Authorization`, `Cookie`, proxy 인증 헤더 제거, upstream 자격증명은 route에서 주입, `Origin`은 PX-014로 검사하고 미전달. 응답 방향: upstream `WWW-Authenticate`, `Set-Cookie` 제거, upstream 401/403은 고정 proxy 오류로 변환. `Forwarded`/`X-Forwarded-*`/`User-Agent` 정책 명시. proxy가 downstream session id를 발급해 (principal, route, upstream session)에 **1:1**로 묶고, `Last-Event-ID` 재개는 묶인 session 안에서만 허용. 항목별 거부 테스트 | 확정(D-02 계약에 포함). PX-008/009/014, AC-04/08 |
| M4 cancel 순서 | dispatch 전 관찰한 `notifications/cancelled`는 해당 요청을 **dispatch하지 않음**을 뜻한다. unknown/not_sent/`cancelled_before_dispatch`로 기록하고 client에 응답하지 않는다. 아직 도착하지 않은 id의 cancel 보류는 짧은 한도 후 폐기(PX-013). dispatch 후 cancel은 전달 + cancel_requested, 무응답이면 cancel_no_response | 확정. PX-006/013/015, 2025-11-25 cancellation |
| tasks capability | upstream initialize 결과에 `capabilities.tasks`가 있으면 route를 unsupported로 표시한다. 런타임에 나타나면 M2와 같이 종료하고 `upstream_capability_unsupported`로 기록한다. capability 제거(bytes 재작성)와 광고 그대로 중계는 하지 않는다. `params.task`가 붙은 tools/call은 2025-11-25 tasks 규칙(capability 미선언 수신자는 task metadata를 무시하고 정상 처리)에 따라 그대로 전달한다. `tasks/*`는 -32601. 지원 route에서 task handle이 오면 그대로 중계·기록하고 route를 degraded/unsupported로 표시 | 확정. PX-004(미지원 기능 광고 금지), D-01 relay-first. P1 capability 표에 표시. 실제 upstream의 tasks 채택 현황은 P1 전 조사 |
| 2025-06-18 downstream 입력 | (a) client `initialize`가 2025-06-18을 제시하면 그대로 upstream에 전달하고 upstream 응답 revision으로 판단한다(2025-11-25면 정상, 2025-06-18이면 M2 거절). (b) initialize 이후 `MCP-Protocol-Version` 헤더가 협상된 revision(2025-11-25)과 다르면 400으로 거절한다. 2025-06-18 같은 legacy 값은 modern 요청으로 분류하지 않으며, 감사 reason 상수는 [OPEN](contracts/README.md v0.4에 반영됨) | 확정(2026-10-10, M2·relay-first 적용). W4 리뷰 F1 |
| 런타임 route 거절 응답 | upstream_capability_unsupported·upstream_version_unsupported·upstream_initialize_unreadable 모두 initialize id에 고정 JSON-RPC 오류 하나로 답한다(HTTP 200 application/json, -32603, 고정 메시지, data 없음, echo 없음). 구체 reason은 감사·route health에만 둔다. `supported` data가 붙은 -32602는 쓰지 않는다 | 확정(T-02-fix-4 재확인 권고). contracts/README.md v0.4에 반영됨 |
| 취소 전 dispatch의 HTTP 종료 | 열린 POST에 200 text/event-stream을 이벤트 없이 닫는다(contract v0.3). P1에서 Claude·Codex가 이를 재시도하는지 측정하고, 재시도하면 HTTP 응답 없이 연결을 닫는 방식으로 바꾼다(PX-015) | 확정(P1 검증 항목) |
| m5 버전 헤더 누락 | initialize 이후 `MCP-Protocol-Version` 헤더가 없는 요청은 400으로 거절한다. 스펙 요구가 아니라 의도적 엄격성 선택이다(2025-11-25는 client에 헤더 전송을 요구하지만 서버는 initialize 협상 값으로 version을 알 수 있다). 결과: rmcp 0.16 client는 P1 미지원 | 확정. 측정한 Claude 2.1.296·codex 0.162.0은 initialize 이후 모든 요청에 헤더를 보냈다 |
| 이벤트 의미 검증 위치 (flag, not reject) | 한 이벤트와 registry·소유권 상태만으로 판정되는 검사(owner, ref 존재, ref scope; ledger-and-query L5 SV-1..SV-5)는 ingest에서 거절한다. 같은 invocation의 두 이벤트를 비교하는 검사(C-1..C-3, 중복)는 거절하지 않고 projection에서 flag한다(`completion_without_start`, `integrity_conflict`). flag된 invocation은 `outcome=null`이고 보고값은 `reported_*`로만 남으며 `outcome` 필터에 걸리지 않는다 | 확정(2026-10-10, W2 리뷰 F1·F11). 거절하면 결과가 도착 순서에 따라 달라진다. README R2/R3의 "제한"을 위치별로 나눈 것이다 |
| metadata_ref 키 | per-proxy 키 K는 state_dir 비밀 취급 규칙을 따르고 백업·지원 번들에서 제외한다. 새 K는 재사용하지 않는 새 key_id를 받는다. state_dir 손실 = 새 epoch + 새 K/key_id + 서버 감사 공백 | 확정. R1 유지(K 없이 이름·정의에서 ref 계산 불가) |

D-04의 수치는 [검증 계획](validation.md)을 단일 참조로 사용한다. 프로토콜별
세션/요청 차이에 따라 D-01 결정 시 적용 항목을 조정하고 변경 근거를 기록한다.
P0 종료와 잔여 항목은 아래 "P0 종료" 절을 따른다. 계약 종료는 구현·실기 검증 완료가 아니다.

## P1 기능 범위 (2026-10-10, W5 조사 + 사용자 결정)

근거: MCP 2025-11-25 transports·resources·prompts·client features·changelog(2026-10-10 조회), T-01 측정, W5 조사.
원칙: capability 필드는 제거하지 않는다(relay-first). proxy가 능동적으로 거절하는 capability를 upstream이 광고하면 route를 unsupported로 표시하고, 그 밖의 기능 저하는 문서로 밝힌다.

| 기능 | P1 처리 | 감사 | 상태 |
|---|---|---|---|
| GET SSE 스트림 | 인증 후 고정 405, upstream 미접속. POST 응답 스트림 재개 없음(결과 불명은 PX-015대로). GET으로만 오는 unsolicited 알림은 전달되지 않음 | invocation 아님(집계만) | 확정(사용자 결정) |
| `*.listChanged` capability | 광고를 그대로 두고 문서화된 기능 저하로 취급(요청 단위 POST 스트림으로 오는 알림만 전달) | — | 확정(추론 근거, P1 실측 필요) |
| resources/subscribe·unsubscribe | 전달하지 않고 고정 -32601. upstream이 `resources.subscribe=true`를 광고하면 route unsupported(`upstream_capability_unsupported`) | method `unknown`, protocol_error/not_sent | 확정(사용자 결정) |
| resources list·read·templates/list, prompts list·get | 그대로 중계 | method `unknown` start/completion, tool 없음, 원문 method 미기록 | 확정. 세분화 method 값은 P2(schema 변경·리뷰 필요) |
| 서버→client 요청(sampling, elicitation, roots) | POST 응답 스트림 안에서 bytes 그대로 중계. client→server JSON-RPC 응답(method 없음)을 malformed로 분류하지 않는다. M4 cancel 표는 client가 시작한 id만 다룬다 | 이벤트 없음. 관찰 사각지대로 문서화(P2 고려) | 확정 |
| 그 밖의 알림(progress, list_changed 등) | 그대로 중계. `notifications/cancelled`는 M4. progress가 최대 시간 제한(PX-013)을 연장하지 않는다 | 이벤트 없음 | 확정 |
| JSON-RPC batch 배열 | 2025-11-25에서 제거된 형식. parse 사본에서 최상위 배열을 감지해 전달하지 않고 malformed 경로로 거절 | method `unknown`, protocol_error/not_sent | 확정 |
| 세션 DELETE | 인증 후 같은 principal·route의 session만 처리(아니면 동일한 404). 묶인 upstream session에 DELETE를 1회 전달(재시도 없음). upstream 2xx/404면 proxy session 무효화 후 이후 요청 404, 405·오류면 상태를 그대로 전달하고 session 유지 | 이벤트 없음(집계만) | 확정 |

계약 반영(Traffic·오류 표의 405, -32601 subscribe, batch 거절, DELETE 규칙, method 없는 응답 처리)은 contracts/README.md v0.4에 반영됨.

## P0 종료 (2026-10-11, 사용자 결정)

plan.md P0 완료 조건(D-01–05와 P1 지원 표 문서화, fixture 재현)을 계약 수준에서 충족했다고 보고 P0를 종료한다.
근거: P0 종료 점검(spec-auditor, 2026-10-11), support-matrix undecided 0행, fixture 14 tests 재실행 통과(2026-10-11),
checker PASS(2026-10-10 orchestrator 재실행). 계약 종료는 구현·실기 검증 완료가 아니다.
남은 [OPEN]은 아래 담당 P1 작업 안에서 확정하고, 실측 항목은 P1 인수 증거로 남긴다.

| 잔여 항목 | 구분 | 담당 |
|---|---|---|
| 프록시 경유 B1 재측정, 400 뒤 Claude 대체 동작 | 실측 | T-12 / T-16 |
| codex 인증 run·cancel·tool call, Linux probe | 실측 | T-12 / T-16 |
| listChanged 기능 저하, cancel 후 HTTP 종료에 대한 client 재시도 | 실측 | T-12 |
| 헤더 누락·legacy 값 400의 감사 reason 상수, batch 거절 client 응답 형태, -32603 고정 메시지 | 세부 | T-12 |
| proxy SAN 정확한 형태, CA 키 위치, lifecycle 경로 이름, disabled/retired HTTP status, `proxy_unknown` 메시지 문구 | 세부 | T-11 (S1/S2) |
| 새 고정 오류 코드 확정(`invocation_owner_conflict`, `semantic_invalid`, `invalid_cursor`, `invalid_filter`), SV-1/SV-3/SV-5, gap 목록·status·inventory endpoint 이름 | 세부 | T-11 (S3–S5) |
| 비밀·origin 변경 적용 방식(reload/restart), rate limit, TTL 수치 | 세부 | T-10 / T-11 |
| registry O-2–O-6, R6 scoped content 조회와 `proxy.metadata` 권한 | 세부 | T-13 / T-15 |
| `POST /v1/proxy-events` 본문 형태: 후보 `{events:[…]}`(1–100개), 응답 `{accepted_event_ids, duplicate_event_ids}`. `sigil-proxy-api`(#244)가 이 후보를 쓴다 | 세부 | T-11 (S4) |
| ledger SQLite 트랜잭션·재시작 내구성·성능 | 실측 | T-11 (S4) / T-16 |
| 성능 목표(validation.md), x86_64 baseline, SELinux enforcing 실행 | 실측 | T-16 |

추가 결정(2026-10-11):
- 운영자 CLI: 등록·비활성·재활성·폐기·config 변경·proxy 인증서 서명은 `sigil-server proxy …` 하위 명령(T-11),
  downstream 토큰 생성과 verifier 출력은 `sigil-proxy` CLI(T-10)가 맡는다.
- 패키징: rpm·systemd unit은 T-10(설치만, 자동 활성화 없음, 별도 state_dir). 전용 SELinux 도메인 `sigil_proxy_t`는
  Rocky 9 enforcing 실기 검증 단계에서 작성하며 그 전에는 unconfined로 실행한다.
- 서버 측 관리·수신 API는 계약대로 sigil-server 안 `proxy/` 모듈에 격리하고 설정이 없으면 비활성이다. proxy는 별도 프로세스다.
- downstream·관리 토큰 verifier 규칙(2026-10-11, T-10 리뷰): verifier = wire로 보내는 ASCII bearer 문자열("Bearer " 뒤 값)의
  SHA-256 소문자 hex. 상수 시간 비교. 구현은 `sigil-proxy-api`의 단일 함수를 proxy·server가 함께 쓴다.
- `upstream_origins` 정규화: 기본 포트(http 80, https 443)는 제거해 비교한다. `http://`는 loopback host에만 허용한다.
- 인증서는 공개 자료로 취급한다(일반 파일·symlink 금지). 개인 키와 비밀 파일만 소유자 전용(0600 상당)이다. 파일은 O_NOFOLLOW로 열고 열린 fd로 검사한다.
- downstream 리스너의 client 인증: bootstrap에는 principal이 없으므로 리스너는 바인드하되, 적용된 config에 verifier가 1개 이상 생기기 전에는 모든 요청을
  전달하지 않고 401로 거절한다. "client 인증 없음 = 시작 실패"는 non-loopback인데 TLS가 없는 경우처럼 bootstrap만으로 판정되는 경우에 적용한다(T-12).
- state_dir의 `binding.json`이 손상되면 새 epoch로 덮지 않고 시작을 거부한다(손상 ≠ 손실). 운영자가 명시적으로 지운 뒤에만 새 epoch이며, 기존 spool은 삭제하지 않고 격리한다.
- bootstrap 후보 키 추가: `tls_cert_file`·`tls_key_file`(non-loopback 리스너 TLS, 함께 설정). 기본 listen은 `127.0.0.1:8480`(후보).
- host route 교차 거절 응답(2026-10-11, T-11 S1 리뷰): proxy 인증서·판정 불가 인증서·mTLS 신원 없는 요청이 host route에 오면
  `{"error":"host_unknown"}`(404)로 답하고 `host_id`를 되돌려주지 않는다. 본문을 parse하기 전에 거절하므로 기존 host route의
  미등록 응답(`host_id` 포함)과 본문이 다르다. 값 미echo를 우선한 의도적 차이다(control-plane §1.2 "미등록 principal과 같은 답"의 예외).
- 서버 proxy 등록 목록 파일: 중복 proxy_id·중복 fingerprint·group/world 쓰기 권한·symlink는 부팅 오류. 파일이 없으면 `registry_init: true`일 때만 빈 목록으로 시작한다.
  client CA 묶음에 proxy CA 외 CA가 없으면 부팅을 거부한다(host 전체 거절 방지).
- 관리 lifecycle 경로(2026-10-11, T-11 S2, orchestrator 결정·후보 이름): `POST /v1/proxies`(등록, identity),
  `POST /v1/proxies/{id}/fingerprints`(다음 fingerprint 등록, identity), `POST /v1/proxies/{id}/disable`(config),
  `POST /v1/proxies/{id}/enable`·`/retire`(identity), `POST /v1/proxies/{id}/csr`(인증서 서명, identity, S2b), `GET /v1/proxy-management-audit`(proxy.read).
  인증된 proxy 신원에 대한 `disabled`·`retired` 답의 HTTP status는 403으로 정한다(신원은 확인됐고 상태가 거절 사유이므로; 미등록·불일치는 계속 404).
- 관리 구현 세부(2026-10-11, #251 보안 리뷰): scope는 정확히 일치해야 한다(identity ⊉ config, 긴급 disable에는 config 토큰이 따로 필요).
  감사 조회 `GET /v1/proxy-management-audit`만 관리 caller cert를 받는다(CLI가 mTLS 전용이므로; 다른 host·read route는 계속 거절).
  fingerprint 승격은 감사가 기록될 때만 일어나며, 감사 장애 중에는 이전 fingerprint가 계속 유효하다(회전 지연, 안전 방향 예외).
  감사 파일 마지막 줄이 줄바꿈만 빠진 유효 기록이면 유지하고, 검증할 수 없는 조각만 `.torn.<epoch>`로 옮긴다. 다른 손상은 부팅 거부.
  verifier 파일 재적재가 실패하면 모든 관리 자격증명을 끈다(fail closed).
- 운영자 CLI(`sigil-server proxy …`)는 실행 중인 서버의 관리 API를 mTLS(관리 caller cert)+bearer로 호출하는 client다. 등록 목록 파일을 직접 쓰지 않는다
  (감사 선기록·동시성 유지). bearer는 소유자 전용 파일에서 읽고 CLI 인자로 받지 않는다.
- proxy 패키징(2026-10-11, #253 리뷰): proxy는 전용 system 사용자·그룹 `sigil-proxy`(전용 sysusers 파일)로 실행해 다른 sigil 데몬이 upstream 자격증명을 읽지 못하게 한다.
  proxy 패키지는 빌드하되 relay(T-12)가 생기기 전까지 릴리스에 공개하지 않는다(`release.yml`의 `rm -f pkgs/sigil-proxy*`).
- 착수 순서: PR0 `sigil-proxy-api` DTO crate(#244) → T-10 `sigil-proxy` 골격(#245)과 T-11 S1 신원·등록(#246) 병렬.
- T-11 S4 범위(2026-10-14, 사용자 결정·추천안 채택): S4는 `POST /v1/proxy-events` 수신과 ledger 저장(중복·tombstone·epoch/sequence gap·보존 정리·저장 한도),
  그리고 최소 metadata 업로드 저장소(`POST /v1/proxy-metadata`, SV-2–4 검증용)를 포함한다. projection과 조회 API는 S5.
  SV-5는 route 변경 중 직전 revision과 현재 revision의 credential scope id를 모두 받는다. ledger는 기존 상태 파일 옆 별도 SQLite 파일에 두고,
  기존 status·config 저장소의 DB 이전은 나중 단계로 미룬다. status 보고의 `last_assigned_sequence`로 만드는 tail gap은 S5 후속으로 미룬다.
  저장 한도 수치는 설정값이며 기본값은 보수적인 시험값이다(D-04 초기값). proxy 쪽 invocation 이벤트 생성은 T-13/T-14이며 S4의 proxy 갈래는 전송 client와 gap queue까지만 한다.
- 오류 code(2026-10-14, S4): 현재 고정 message 문구를 확정한다. 413은 `payload_too_large`, 429는 `rate_limited`, 503은 `storage_limit`(저장 한도)·`storage_unavailable`(일시 저장 실패).
  parse 오류 분류는 serde message 문자열 검사가 아니라 입력이 위조할 수 없는 typed 신호로 한다(#271).
- T-11 S5 범위(2026-10-17, 사용자 결정·추천안 채택): projection은 ledger 안의 저장 테이블로 두고 이벤트 저장과 같은 트랜잭션에서
  해당 invocation의 이벤트 집합으로 다시 계산한다(순수 함수, 도착 순서·재전송 무관). ledger 스키마는 v2로 올리고 v1에서 기존 이벤트로 projection을 다시 만든다.
  보존 정리는 invocation 단위로 지운다. 모순된 이벤트는 거절하지 않고 projection flag로 표시한다(L2).
  조회 API(`GET /v1/proxies`, `/v1/proxies/{id}`, `/v1/proxy-invocations`, `/v1/proxy-invocations/{id}`)는 기존 read API와 같은 read bearer + host mTLS를 쓴다.
  P1의 `proxy.read` 범위는 read bearer 하나가 모든 proxy를 보는 모델이며, 범위 검사는 handler의 한 함수로 모아 나중에 token별 범위로 바꿀 수 있게 한다.
  범위 밖과 없는 대상은 같은 404 `proxy_unknown`이다. gap 목록은 `/v1/proxies/{id}`의 `audit_gaps`(최대 50)와 총수만 두고 별도 endpoint는 두지 않는다.
  status 보고의 `last_assigned_sequence`가 ledger 최고 sequence보다 크면 보고 한 번으로 `tail=true` sequence_gap을 만들고, 이벤트가 도착하면 닫되 기록은 남긴다.
  수락된 ingest도 `last_seen`을 갱신한다. `spool.as_of`·`status_as_of` 이름과 message 문구는 기본안으로 구현하고 리뷰에서 확정한다.
  registry 409의 `metadata_ref`와 metadata 보존은 S5 밖이다(#279).
- T-13/T-14 범위(2026-10-20, 사용자 결정·추천안 채택): 호출 lifecycle과 inventory 수집은 MCP 해석이 필요하므로 T-12b를 둘로 나눠
  T-12b1(요청·응답 분류, `Observation` seam, cancel, protocol version·batch·`tasks/*` 거절)을 T-13보다 먼저 한다. session·DELETE·GET 405는 T-12b2.
  spool은 SQLite WAL(`synchronous=FULL`)이며 fsync 뒤에만 local ack한다. T-12b1 전에는 해석 없는 임시 이벤트를 만들지 않는다.
  spool이 차면 P1은 차단만 한다(`allow-with-gap`은 미룸). inventory는 status 보고와 분리된 `POST /v1/proxy-inventory`로 보낸다(O-4).
  도구 이름 조회(R6)는 P1에서 ref만 두고 T-15에서 다시 본다. test 전용 feature 이름은 crate별 기존 이름을 유지한다(proxy `test-util`, server `test-support`).
  기본값: 재시작 뒤 완료가 없는 호출은 start만 남는다. key 회전 시 이전 K는 즉시 폐기한다(O-2). scope를 넘는 link는 만들지 않는다(O-6).
- T-13a/T-13b 후속 결정(2026-10-21, 사용자 결정·추천안 채택):
  status 보고의 tail gap은 `last_assigned_sequence − spool.unsent_events`를 기준으로 판정한다. spool에 남아 아직 보내지 않은 이벤트는 gap이 아니다(spool은 epoch 하나에만 묶인다).
  inventory chain 순서는 proxy 시계(`observed_at`)로 정하고, server 수신 시각보다 300초 넘게 미래인 보고는 422 `semantic_invalid`로 거절한다.
  status `registry` 블록에 선택 필드 `quarantined_entries`·`poisoned_entries`·`discarded_reports`를 둔다. status DTO는 모르는 필드를 거절하므로 server를 proxy보다 먼저 올린다.
  canonical JSON은 2^53을 넘는 정수도 RFC 8785대로 double로 반올림한다.
  orchestrator 결정: inventory body 한도는 4 MiB(P1 초기 시험값)이며 parse 전에 413 `payload_too_large`로 막는다. `pending_previous` 대기는 proxy당 256개이며 넘으면 503 `storage_limit`이다.

## T-13d/T-12b2 구현 세부 확정 (2026-10-24, orchestrator)

기존 결정의 실행 세부 선택은 [구현 계약](t13d-t12b2.md)에 기록한다.
공식 명세 대조와 독립 계약 리뷰를 거쳐 session 누락 400, initialize의 임의 session header 400
(조회 전 동일 응답), stateless upstream용 proxy session과 local DELETE 204, upstream POST404 무효화,
`Internal error` 고정 문구, unsupported binding의 신규 initialize 미전달을 고정했다.
2025-11-25 지원·B1 선처리·원문 보존·감사 vocabulary·제품 호환성 gate는 유지한다.
M2/m3 등록·health-check 판정은 여전히 미완료 P1 요구사항이며 이번 runtime 범위 완료로
전체 P1 종료나 실기 검증을 선언하지 않는다. 구현과 회귀 테스트·독립 코드 리뷰는 execution.md에서 추적한다.
