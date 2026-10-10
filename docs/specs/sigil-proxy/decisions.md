# P0 결정 기록

2026-09-27 · 갱신 2026-10-10 · 구현 계약 확정과 검증 완료는 서로 다르다.

| 항목 | 현재 결정 | 상태/남은 증거 |
|---|---|---|
| 구현 언어 | proxy backend는 Rust/Tokio; manager 기존 stack 유지 | 확정. dependency/MSRV 선택은 D-01에서 별도 검증 |
| D-01 | **2026-10-10 구조 결정:** relay-first. 원문 bytes를 그대로 중계하고 관찰·정책용으로만 사본을 parse한다. 전달 경로에 SDK typed message를 쓰지 않는다(rmcp 0.16.0 측정: unknown field 유실, version allowlist 없음, version header 미전송, cancel 지연). P1 지원 revision은 잠정 2025-11-25(legacy) 하나. proxy는 rmcp에 의존하지 않으므로 proxy 때문에 MSRV를 바꾸지 않는다 | 부분 결정. 근거: [T-01 probe](../../research/sigil-proxy-t01-probe-2026-10-10.md) + 독립 리뷰(T-01-review). 미결: modern 요청 응답(B1: empty-body 400, 프록시 경유 재측정), upstream version allowlist 밖 응답 처리(M2), header 정책(M3→D-02), spool-before-forward의 cancel 순서(M4), MCP-Protocol-Version 누락 정책(m5), codex 인증 run(M2는 A로 확정). 기존 workspace MSRV 불일치는 별건 #240 |
| D-02 | client/proxy/upstream/manager identity 분리. 기존 fleet read token으로 관리 불가 | 부분 결정: bootstrap은 명시적 --config, 인증 방식과 manager 권한 mapping은 미확정 |
| D-03 | host event와 별도 proxy ledger; 원자적 수집·event-ID dedup. **2026-10-10: ingest 하위 계약 동결**(schema v0.3 envelope·payload, 전체 event dedup, epoch, 422/403/409/424 batch error items, integrity gap 보고, startup 규칙). 계약 수준·fixture/model 증거만이며 ledger 구현 시험은 P1 | 부분 결정. 남은 항목: retention·dedup tombstone 기간(최대 offline 재시도 기간 대비), invocation projection/query DTO(out-of-order·start-only 규칙), cross-event semantic validation 규칙·시험, 인증 실패·unmatched cancel aggregate 계약, 관리·등록·config·heartbeat DTO |
| D-04 | **2026-10-10 사용자 결정:** 첫 production 검증 대상은 Rocky Linux 9(RHEL 계열, SELinux enforcing, rpm 배포). 아키텍처별 결과는 별도 baseline으로 기록한다(현재 실기 VM은 aarch64). macOS arm64는 개발 환경 | 대상 OS 확정. validation.md의 limits/benchmark 목표는 초기 시험 기준이며 성능 보장 아님. Ubuntu 24.04 x86_64 권고안은 대체됨 |
| D-05 | daemon HOME baseline 파일 공유 금지; proxy 소유 scope별 snapshot. **2026-10-10:** metadata_ref는 proxy가 per-proxy 키로 로컬 발급(HMAC, UUIDv8), scope key·fingerprint `sigil-tooldef-fp-v1`·offline 해석·sync 순서·retryable 424·registry 동일성(불변 필드)·local entry hash 검사 계약화 | 부분 결정. 남은 항목: registry entry DTO·schema, key rotation 운영과 이력 연결, re-baseline marker projection, inventory/drift event 계약. M2 사용자 결정(2025-06-18 추가 시 scope key의 protocol_version 값 증가) |
| D-06/07 | 승인 흐름·step-up/OAuth | 계획대로 P3 이전 확정 |

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
| 런타임 route 거절 응답 | upstream_capability_unsupported·upstream_version_unsupported·upstream_initialize_unreadable 모두 initialize id에 고정 JSON-RPC 오류 하나로 답한다(HTTP 200 application/json, -32603, 고정 메시지, data 없음, echo 없음). 구체 reason은 감사·route health에만 둔다. `supported` data가 붙은 -32602는 쓰지 않는다 | 확정(T-02-fix-4 재확인 권고). 계약 반영은 다음 계약 작업 |
| 취소 전 dispatch의 HTTP 종료 | 열린 POST에 200 text/event-stream을 이벤트 없이 닫는다(contract v0.3). P1에서 Claude·Codex가 이를 재시도하는지 측정하고, 재시도하면 HTTP 응답 없이 연결을 닫는 방식으로 바꾼다(PX-015) | 확정(P1 검증 항목) |
| m5 버전 헤더 누락 | initialize 이후 `MCP-Protocol-Version` 헤더가 없는 요청은 400으로 거절한다. 스펙 요구가 아니라 의도적 엄격성 선택이다(2025-11-25는 client에 헤더 전송을 요구하지만 서버는 initialize 협상 값으로 version을 알 수 있다). 결과: rmcp 0.16 client는 P1 미지원 | 확정. 측정한 Claude 2.1.296·codex 0.162.0은 initialize 이후 모든 요청에 헤더를 보냈다 |
| metadata_ref 키 | per-proxy 키 K는 state_dir 비밀 취급 규칙을 따르고 백업·지원 번들에서 제외한다. 새 K는 재사용하지 않는 새 key_id를 받는다. state_dir 손실 = 새 epoch + 새 K/key_id + 서버 감사 공백 | 확정. R1 유지(K 없이 이름·정의에서 ref 계산 불가) |

D-04의 수치는 [검증 계획](validation.md)을 단일 참조로 사용한다. 프로토콜별
세션/요청 차이에 따라 D-01 결정 시 적용 항목을 조정하고 변경 근거를 기록한다.
이 문서의 부분 결정만으로 production 경로 구현 gate를 통과했다고 해석하지 않는다.

## 다음 실행 단위

1. T-01 결과 기반으로 SDK 의존 여부와 Rust 최소 버전의 실제 빌드 대안을 비교한다.
2. fixture revision과 지원 대상 revision을 일치시키고 실제 client 1종의 안전한 HTTP 왕복을 측정한다.
3. T-02에서 등록·인증·route config·inventory·heartbeat·조회 DTO까지 완성한다.
4. 독립 계약 리뷰로 D-01–05를 닫은 뒤 P1 crate/서비스 구현을 시작한다.

임시 fixture나 schema 테스트는 위 실제 client 및 production 검증을 대신하지 않는다.
