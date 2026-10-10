# P1 계약 후보 v0.3

2026-09-27 작성, 2026-10-10 T-02-fix-2·T-02-fix-3 반영. P0 리뷰와 실기 검증 전에는 구현 고정 계약이 아니다.
D 항목은 이 문서로 닫히지 않는다.

## 구현 기술과 서비스 경계

Rust/Tokio를 사용한다. 기존 workspace Rust MSRV와 lockfile 호환성을 검증하며
SDK 편의를 위해 자동으로 MSRV를 올리지 않는다. sigil-server와 별도 바이너리다.
관리 API는 sigil-server, 관리 화면은 기존 sigil-manager가 담당한다.

기존 `AssessInput`은 command/McpServer만 표현한다. 호출 정책은 별도 타입으로 만들며
기존 verdict의 allow/warn/deny를 승인된 호출로 변환하지 않는다.
기존 host Event 스키마는 유지하고 proxy audit stream과 storage/index를 분리한다.

## Bootstrap 구성 후보

초기 지원 배포 OS 후보: Linux 서비스, macOS 로컬 개발. Windows 서비스는 별도 검증 전 미지원 표시.
실행 시 `--config PATH`를 요구한다. 자동 발견/환경 override는 v0.1에 없다.
서비스 패키지는 `/etc/sigil/proxy.yaml`, state는 `/var/lib/sigil-proxy`를 명시한다.
macOS 개발은 임시 디렉터리의 절대 경로를 사용한다. 비밀값 CLI 인자는 제공하지 않는다.

로컬 bootstrap: proxy_id, listen, control_plane_url, state_dir,
client_cert_file, client_key_file, ca_file, limits. 상대 파일 경로는 설정 파일 디렉터리 기준이다.
민감 파일은 소유자 읽기만 허용하며 symlink/소유권 검사는 플랫폼별로 검증한다.
기본 listen은 loopback이다. 모든 listener(loopback 포함)는 client 인증 설정이 없으면 시작 실패한다.
인증되지 않은 요청은 upstream에 전달하지 않는다(PX-008, observe 모드 포함). 외부 bind는 TLS도 필요하다.
미인증·인증 실패 요청은 invocation 이벤트가 아니며 actor를 만들지 않는다. 그 집계 기록은 후속 계약이다.

원격 route/auth 설정은 중앙 버전 단위로 검증 후 원자 적용한다. 로컬 bootstrap과 병합하지 않는다.
현재 버전과 낮은 버전은 새 적용으로 인정하지 않는다. 만료 시 새 호출을 전달하지 않는다.
인증 실패·폐기 갱신 지연의 최대 허용 시간을 config TTL로 명시하며 즉시 폐기를 주장하지 않는다.

## 감사 이벤트 초안

[JSON Schema](proxy-event.schema.json)와 [예제](invocation-started.example.json)는
P1 invocation started/completed와 nonterminal cancel_requested 관찰만 정의한다. inventory/heartbeat/config 감사는
후속 계약 항목이며 이 schema로 임의 payload를 전달하지 않는다.

- sequence는 `(proxy_id, epoch_id)`별 단조 증가, event_id는 UUID이며 재전송 시 동일하다.
  epoch_id는 첫 시작과 로컬 상태 복구 불가 시마다 새로 만드는 random UUID다(M1 절 참고).
  동일 invocation의 start/cancel/completion은 각각 다른 event_id와 sequence를 갖는다.
- 동일 event_id의 **전체 제출 event**(모든 envelope 필드 + payload)가 canonical하게 같을 때만 중복이다.
  sequence·occurred_at·event_type·schema_version·payload 중 하나라도 다르면 409 충돌이다(N2 절 참고).
- 시작/완료 이벤트의 proxy 소유권과 invocation 결합을 저장 계층이 검사한다. schema 검사만으로 인증하지 않는다.
- occurred_at은 proxy 시각이다. 중앙 received_at은 저장 계층이 별도 부여한다.
- 중앙은 `(proxy_id,event_id)` unique로 중복 제거하고 `(proxy_id,epoch_id,sequence)`도 unique로 검사한다. sequence는 공백 진단용이며
  높은 sequence 수신만으로 낮은 미수신 이벤트를 버리지 않는다.
- 원문 arguments/results/error/session/token은 불허한다. 고정 code만 기록한다.
- actor의 모든 필드는 proxy가 인증한 credential을 적용된 중앙 route/credential 설정에서 찾은 결과다.
  clientInfo·임의 헤더·`_meta`·human 플래그에서 가져오지 않는다(N3 절 참고).
- upstream_id/route_revision은 호출 시작 당시 값으로 고정한다.
- producer는 정확한 schema를 지킨다. 새 버전은 consumer 지원 확인 후 보낸다.
  알 수 없는 schema_version/event_type은 수집에서 명시적으로 거절하고 producer가 spool을 유지한다.
- 완료 이벤트가 먼저 수신되거나 시작만 남은 상태를 index가 표현할 수 있어야 한다.

## P1 API 후보와 권한

| Method/path | 계약 | 권한 |
|---|---|---|
| GET /v1/proxies | cursor, limit 기본 100/최대 500; items,next_cursor | proxy.read |
| GET /v1/proxies/{id} | 상태·desired/applied revision·last_seen | proxy.read 범위 검사 |
| GET /v1/proxy-invocations | cursor와 proxy/upstream/actor/outcome/time 필터 | proxy.read 범위 검사 |
| GET /v1/proxy-invocations/{id} | started/decision/completed projection | proxy.read 범위 검사 |
| PUT /v1/proxies/{id}/config | expected_revision, 새 설정; 충돌 409 | proxy.manage |
| GET /v1/proxies/{id}/config | 해당 proxy에 대한 설정과 expires_at | proxy identity와 path ID 일치 |
| POST /v1/proxy-events | events 배열, 최대 100개/1 MiB; 전부 검증 후 원자 수락 | 등록 proxy mTLS identity |

수집 성공은 durable 저장 뒤 `accepted_event_ids`와 `duplicate_event_ids`를 반환한다.
부분 성공을 만들지 않는다. 요청 전체 유효성 실패는 422, identity mismatch는 403,
크기 초과 413, backpressure 429, 일시 저장 실패 503이다. envelope 전체 raw body를 오류에 넣지 않는다.
관리 충돌은 409; 인증 누락/오류 401, 권한 부족 403, 미존재 404.
오류 구조는 `{error:{code,message,items?,pending_metadata_refs?}}`; message는 안전한 고정 텍스트다.
수집 오류의 `items`는 `{index, event_id?, code}` 목록이다. 422는 검증 전 값을 신뢰할 수 없으므로
`index`만 쓰고, 409/424는 검증된 `event_id`와 고정 code(`conflict`, `sequence_conflict`,
`metadata_ref_pending`)를 쓴다. 424는 검증된 metadata_ref UUID 목록 `pending_metadata_refs`를 추가한다.
그 외 필드 값은 오류에 넣지 않는다. 여러 조건이 겹치면 422 > 403 > 409 > 424 순으로 하나만 반환한다.
cursor는 필터·정렬과 결합하고 안정적인 tie-breaker를 포함한다.

위 API는 기존 read bearer를 관리/수집 credential로 인정하지 않는다.
관리 인증 mapping과 manager의 viewer/operator 연결은 T-00 조사 뒤 고정한다.
사용자에게 새 SSO/멀티테넌트 기능을 요구하지 않는 단일 설치 범위다.

## Traffic와 내구성

upstream 전송 전 요청 크기를 검사하고 정책 판단에 필요한 메시지를 파싱한다.
응답은 고정 상한 buffer로 streaming한다. audit는 bounded queue + 전용 writer로 보낸다.
기존 spool append는 동기 fsync이므로 Tokio I/O task에서 직접 실행하지 않는다.
기본 모드에서는 started의 **LOCAL spool durable commit ACK**를 기다린 후 upstream에 전달한다.
이 ACK는 중앙 POST /v1/proxy-events의 durable acceptance와 다른 경계다.
유효한 로컬 설정과 spool 여유가 있으면 중앙 단절 중에도 중계하며, 중앙 ACK를 전송 선행 조건으로 삼지 않는다.
이에 따른 디스크 지연도 benchmark에 포함하며 '감사 무비용'을 주장하지 않는다.
completion 저장 실패는 이미 수행된 동작을 되돌리지 못한다. degraded/audit-gap으로 표시한다.

**취소 순서(M3).** proxy는 인증 주체의 같은 session 안에서 `(session, requestId)`로 취소를 대응시킨다.
- 요청 X의 dispatch 시작(요청 bytes를 upstream에 쓰기 시작한 시점) 전에 X에 대한 `notifications/cancelled`를
  관찰하면 X를 dispatch하지 않는다. 취소도 upstream에 전달하지 않는다(hold-and-forward 없음).
  X의 completion은 `unknown`/`not_sent`, reason `cancelled_before_dispatch`이다. 2025-11-25 취소 규칙대로
  X에 대한 JSON-RPC 응답은 보내지 않는다.
  HTTP 수준(N13): X의 열린 POST에는 `200`, `Content-Type: text/event-stream`을 보내고 event 없이(event id·`retry`
  없음) 스트림을 종료한다. 근거는 2025-11-25 Streamable HTTP 규칙이다. 요청 POST에는 SSE나 JSON 객체 하나로만
  답할 수 있고, `application/json`은 응답 객체를 요구하므로 취소 규칙("응답하지 않는다")과 충돌한다. SSE의
  "결국 응답을 포함한다"는 SHOULD이므로 취소된 요청에서는 생략할 수 있다. event id가 없으므로 client가
  `Last-Event-ID`로 재개할 대상도 없다. 실제 client 동작은 미검증이다.
- requestId 대응은 정확한 JSON 값 일치다. 타입과 값이 모두 같아야 하므로 문자열 `"4"`와 숫자 `4`는 다르고,
  정수 `4`와 `4.0`도 일치하지 않는다.
- 아직 도착하지 않은 requestId에 대한 취소의 보류·조회는 bounded다(PX-013): 짧은 창(수치는 D-04) 안에
  요청이 오지 않으면 버리고 집계 카운터만 남긴다. 창 안에 요청이 오면 위 규칙대로 dispatch하지 않는다.
- dispatch 후의 취소는 즉시 upstream에 전달하고 `cancel_requested`를 기록한다. 응답이 없으면
  `cancel_no_response`로 끝낸다(N4 절).
- 요청이 dispatch 없이 끝나면(거절·malformed 등) 취소를 전달하지 않고 그 completion을 유지한다.
- 대응 요청이 있으면 모든 경우 `invocation.cancel_requested`를 기록한다. 대응 요청이 없거나 창이 지난
  취소는 전달하지 않고 집계 카운터만 남긴다(후속 집계 계약, m6 참고).

spool directory는 process lock을 가져 한 writer만 사용한다. 디스크 한도 초과 시 새 호출 차단.
client 재전송을 자동 dedup한다고 주장하지 않는다. MCP request ID만으로 도구 부작용 idempotency를
보장할 수 없으므로 각 전달은 별도 invocation이며 proxy 자체 재실행은 금지한다.

## 미고정 계약 목록

T-00/01/03 결과에 따라 인증과 protocol 지원, 관리 DTO, inventory 저장/조회,
heartbeat, configuration TTL, 부하 수치, route별 credential 배포 계약을 채운다.
이 목록이 남아 있는 동안 P0 완료나 P1 production 경로 준비 완료라고 표시하지 않는다.

## T-00 반영: 저장과 baseline 경계

[저장소 조사](../../../research/sigil-proxy-repository-survey-2026-09-27.md)에 따라
P1은 단일 server 인스턴스의 별도 SQLite proxy ledger를 후보로 둔다. insert/dedup/ACK를
하나의 transaction durability 경계로 묶고 조회는 receipt 날짜에 의존하지 않는다.
기존 host high-water dedup을 재사용하지 않는다. event 보존과 dedup tombstone 수명은
최대 offline spool 재전송 기간과 함께 고정해야 하며 아직 미정이다.

기존 daemon baseline 파일은 HOME에 결합되어 있어 공유하지 않는다. 순수 hash/comparison
알고리즘만 검토하고 proxy 전용 immutable first baseline과 latest complete snapshot을 분리한다.
키는 upstream/credential scope/protocol/observation source 및 필요한 proxy visibility를 포함한다.

manager의 기존 fleet 조회는 계속 read-only다. proxy 관리 기능만 새 관리 계약을 사용한다.
manager 작업 시 기존 지침과 UI 스펙에 이 범위의 예외를 명시하며 viewer/operator mapping과
CSRF/Origin 검증을 추가한다. 기존 로그인 session 모두를 관리자/승인자로 취급하지 않는다.

## 계약 검사 실행

저장소 밖 격리 venv에 [requirements-check.txt](requirements-check.txt)의 정확한 pin을 설치하고 실행한다.
`rfc3339-validator`가 없으면 jsonschema가 `date-time`을 조용히 건너뛰므로, 검사기는
`date-time`/`uuid` format 검사가 비활성일 때 exit 2로 실패한다(N1). `python -O`에서도 exit 2다(m1).
검사 범위: schema 자체, positive/rejected case, JSON token 수준 정수 거절, lifecycle fixture ID,
dedup 규칙 reference model, metadata_ref 유도 reference model. 모델은 fixture이며 실제 ledger/registry가 아니다.
API 인증·저장·전달, producer 정규화, registry 동기화/권한, 실제 client 호환성을 검증한 것이 아니다.

```text
python3 -m venv <scratch>/venv
<scratch>/venv/bin/pip install -r docs/specs/sigil-proxy/contracts/requirements-check.txt
<scratch>/venv/bin/python -I -B docs/specs/sigil-proxy/contracts/check_schema.py
PASS: schema, 53 positive cases, 271 rejected cases, 4 JSON-token integer rejections, 10 dedup-model cases, 4 batch-error-model cases, 4 registry-model cases, 12 integrity/requestId/startup-model cases, 5 ref-derivation-model cases (jsonschema 4.26.0, rfc3339-validator 0.1.4, date-time and uuid format checking active)
```

## R1–R3 scoped revision — 2026-09-27

Links: PX-006/009/010/011/012/015; AC-01/03/05/06/07. These are contract
and fixture fixes, not production implementation, independent review approval,
or P0 completion. The open authentication, API DTO and protocol decisions above
remain open, including metadata lookup endpoint/permission wiring.

### Fixed audit vocabulary and provenance (R1)

`method` is exactly one of `initialize`, `ping`, `tools/list`, `tools/call`,
`unknown`. The producer emits a constant only after an exact parser match;
missing, malformed, extension, or otherwise unlisted values become literal
`unknown`, including on rejected calls. Do not echo, truncate, hash or attach
an unknown original value in another event field or validation error.

`protocol_version` is exactly `2025-11-25` or `unknown`. Emit the revision only
from validated negotiated protocol context mapped to this audit vocabulary;
otherwise emit literal `unknown`. An `initialize` start is always `unknown`
(schema-enforced): the revision is negotiated only in the response. Never copy a proposed revision or an HTTP
header directly. A recognized method does not establish a negotiated version.
These intentionally narrow audit constants are **not** a protocol/capability
support matrix or forwarding authorization; revisions/methods outside this
vocabulary stay unknown in audit until an explicit contract update. The runtime
support/rejection gate remains a separate P0 decision.

Scoped official-document check on 2026-09-27:
[2025-11-25 lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)
documents negotiation, and
[tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
documents `tools/list` and `tools/call`. This check supports the pinned vocabulary
only; it does not select the current/latest release for deployment. The existing
[compatibility research](../../../research/sigil-proxy-compatibility-2026-09-27.md)
records newer-revision discovery and local versions separately; its gates remain.
No installed proxy adapter or real-client behavior was verified in this patch.
Configuration precedence, approval modes, hooks, unattended operation and
platform behavior are unchanged and unverified here.

### Tool identity and controlled metadata lookup (R1/R2)

Every `tools/call` start requires a closed `tool` object. Other method constants,
including `unknown`, prohibit it. `tool_name` is forbidden.

*Superseded in part by T-02-fix-2 (N9); see "D-05 metadata registry" below.*

- Identified calls use `{"status":"identified","metadata_ref":"<UUIDv8>"}`.
  The proxy derives the reference locally with a proxy-held secret key, so it is
  never the raw name, an unkeyed name hash/encoding, an arbitrary request field,
  or a client/upstream-provided identifier.
- The reference binds the scope key and the definition fingerprint from the last
  complete inventory (not `route_revision`). The producer resolves the parsed tool
  name locally against that inventory before emitting the reference. An inventory
  name is untrusted content even when received from a registered upstream;
  observing it grants no approval.
- A parsed name without a reference is forwarded in P1 observe mode and recorded
  as `{"status":"metadata_unavailable","reason":...}`. Its completion may be any
  outcome allowed by the matrix.
- A call whose tool name cannot be parsed is rejected before dispatch and recorded as
  `{"status":"unavailable","reason":"malformed"}`. The former `unresolved`
  reason is withdrawn. Do not invent a reference or silently omit `tool`. A
  malformed start cannot later claim dispatch or success: its correlated
  completion must have `not_sent` and `protocol_error` or `denied`.
- Ordinary audit spool/log/API/UI retains only the reference. Raw tool names,
  descriptions and schemas belong only in the separately access-controlled
  metadata store under its own content/secret handling and retention policy.
  No automatic join/expansion into invocation lists, errors or ordinary logs.
  Displaying a name requires an explicit scoped metadata lookup, authenticated
  caller permission for that upstream/credential scope and metadata access,
  with access audited and content treated as untrusted. Possession of a UUID or
  ordinary audit-read permission is insufficient; never fall back to raw text.
  Missing/deleted metadata displays a fixed unavailable label plus the reference.

Producer and ingestion **semantic validation** must check reference allocation
and immutable scope binding against authenticated proxy ownership and the start's
upstream/route/actor visibility, then preserve the binding across the invocation.
JSON Schema can validate UUID shape but cannot establish provenance, permissions,
or cross-event consistency; a secret encoded as a UUID is not made safe by format
validation. Unknown or out-of-scope references must not be durably accepted;
failed validation must use fixed errors without echoing submitted values.
Registry synchronization, offline resolution and retention are specified
in the D-05 section below. The registry entry DTO and endpoint are still candidates.

### Lifecycle observations and fixture integrity (R3 and related)

`invocation.cancel_requested` has only `invocation_id` in its payload. It is a
nonterminal observation that the proxy saw a cancellation request: not proof of
forwarding, receipt, stopped execution or rollback. It must neither finalize an
invocation nor prevent a subsequent success, tool/protocol error, timeout or
unknown completion. An observation arriving after completion must not replace
the completed projection. Raw cancellation reason and protocol request ID are
excluded. This follows the race considerations in the pinned
[cancellation specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation);
it is not a claim that cancellation relay is implemented or hardware-verified.

The candidate outcome/delivery matrix enforced by the schema is:

| Outcome | Allowed delivery_state | Allowed `reason` (optional) |
|---|---|---|
| success, tool_error | sent | none |
| denied | not_sent | none |
| protocol_error | not_sent, sent, unknown | `task_augmentation_unsupported` (not_sent = `tasks/*` refusal; sent = task handle from a non-compliant upstream); `upstream_capability_unsupported`, `upstream_version_unsupported`, `upstream_initialize_unreadable` (sent only); `modern_request_unsupported` (not_sent only) |
| timeout | not_sent, sent, unknown | none |
| unknown | not_sent, sent, unknown | `cancel_no_response` (sent, unknown only); `cancelled_before_dispatch` (not_sent only) |

`delivery_state` concerns request dispatch toward upstream, not response delivery
to the client. `sent` does not prove execution or side effects; `not_sent` means
no dispatch occurred, and `unknown` means dispatch cannot be established.
Success/tool_error requires an observed upstream result, hence `sent`.
`unknown/not_sent` is only an unknown local final result with established absence
of dispatch, never an insinuation of possible upstream execution. Cross-event
validation additionally restricts unavailable-tool starts as described above.
`denied` describes a pre-dispatch rejection and does not enable P2 policy behavior.

`duration_ms` measures monotonic elapsed time from request acceptance to the
proxy's terminal observation, including local queue/spool wait. `response_bytes`
counts upstream response body bytes read for this invocation (after HTTP transfer
framing, before decompression if present; SSE framing included), including partial
reads; it does not count locally generated errors or claim downstream receipt.
Shared-stream attribution, numeric limits and recovery/projection rules still
need the P0 transport/ledger decisions; do not guess counts for shared traffic.

The checker has separate event IDs and increasing sequences for start,
cancellation and completion while preserving invocation/proxy IDs. Its dedup
reference model covers an unchanged retransmission and same-ID conflicts that
differ only in sequence, only in occurred_at, or only in a payload field, plus a
reused sequence with a new event ID. All are schema-valid; a future ledger must
reject the conflicts. Fixture
assertions are not evidence of 409 handling, canonical comparison, transactional
ACK, restart durability, out-of-order ingestion or retention behavior.

Canary negatives cover method/version and raw tool-name paths on identified,
metadata_unavailable and malformed starts, closed tool metadata objects and cancellation data.
Positive cases cover every fixed vocabulary constant, explicit unavailable tools,
non-tool methods and all allowed outcome/delivery combinations. Real producer
normalization, registry provenance/authorization and end-to-end canary absence in
spool/server/manager still require implementation and independent verification.


## T-02-fix-2 contract rules — 2026-10-10

Links: PX-003/006/007/008/010/011/015; AC-03/04/05/06; D-02/D-03/D-05. These rules
answer the [2026-10-10 re-review](../review-p0-followup.md) N1–N4, N7–N9 at
contract scope. They are not an implementation, a hardware verification, or
the closure of any D item.

### Timestamps and integers (N1, N7)

- `occurred_at` is UTC RFC 3339 with uppercase `T`/`Z` and 0–9 fractional digits.
  The schema enforces the shape with a pattern and calendar validity with
  `format: date-time`. Ingestion must parse it as RFC 3339 itself, whatever
  the JSON Schema format support.
- Leap seconds (m2): the wire never carries second `60`. The producer either uses a
  smeared clock or clamps a leap second to `23:59:59.999999999Z`. Ordering comes
  from `(epoch_id, sequence)`, never from `occurred_at`, so clamping cannot reorder events.
- UUID fields are lowercase hyphenated text. Patterns end with the lookahead `(?![\s\S])`
  instead of `$`, because Python `re` lets `$` match before a trailing newline.
- `sequence`, `route_revision`, `duration_ms` and `response_bytes` are bounded to
  `2^63−1` (SQLite/i64). Integer fields must be JSON integer tokens. `1.0`, `1e0`
  and booleans are rejected. A standard JSON Schema validator treats `1.0` as an
  integer, so producers and ingestion need a strict integer layer. The checker
  shows both behaviours.

### Dedup equality (N2)

- The equality domain is the full submitted event: every envelope field
  (`schema_version`, `event_id`, `proxy_id`, `sequence`, `occurred_at`,
  `event_type`) and the full payload. The ledger compares the parsed,
  schema-valid event structurally. Key order is ignored, integers must match
  exactly, and strings must match code point for code point with no Unicode or
  timestamp normalisation. For example, `08:00:00Z` and `08:00:00.0Z` count
  as a conflict. Server-assigned `received_at` is not part of the submission. The
  producer retransmits the spooled bytes unchanged.
- An equal event under the same `(proxy_id,event_id)` is a duplicate and is ACKed again.
  A difference in any field is a 409 conflict, and a 409 is never ACKed as a duplicate.
- The same `(proxy_id,epoch_id,sequence)` with a different `event_id` is also a 409
  conflict (`sequence_conflict`). The same sequence in a different epoch is not a
  conflict (see M1 below).
- Candidate producer handling of a 409: move the conflicting event, unchanged, to a
  local quarantine.
  Report integrity/audit-gap status, then resubmit the rest of the batch. The 409 body
  names each conflicting item by index and `event_id` (M2a). Never re-ID or rewrite
  the event to get it accepted. The only exception is the registry-conflict rewrite
  of never-accepted events in the D-05 table (M2b).

### Actor provenance and authentication (N3)

- PX-008: client authentication is required on every listener, loopback included,
  and in observe mode. The proxy forwards nothing unauthenticated. Every
  invocation event therefore has an authenticated actor. There is no `none`,
  `unknown` or `unauthenticated` authentication method.
- `actor_id`, `actor_kind`, `credential_owner_id` and `evidence_source` all come
  from the server-issued route/credential configuration. The proxy matches the
  authenticated credential against the applied revision. No value comes from
  client input.
  - `actor_kind` is the kind declared in the credential registration, or `unknown`
    when none is declared. `human` is not representable. Any future human kind
    stays behind D-07.
  - `credential_owner_id` is the permission owner of the credential. It is not
    evidence of who executed the call, and manager must not label it as the actor.
    If it is absent, the owner is unknown.
  - `evidence_source` (restored from design.md ActorContext) is the closed enum
    `proxy_credential_mapping`. New sources such as P2 delegation need a contract
    update.
- Self-asserted client values are not identity. Examples are clientInfo, `human` flags,
  and the per-call `_meta` `claudecode/toolUseId` observed from Claude Code in the
  [T-01 probe](../../../research/sigil-proxy-t01-probe-2026-10-10.md). This schema carries
  none of them. A future field for such values must be a separate, closed and explicitly
  unverified object, and needs PX-010 review first. It can never feed `actor`.
- The concrete client authentication mechanism (static bearer measured for both
  probed clients; mTLS candidate) and its mapping DTO remain D-02.

### Protocol revision, tasks and cancellation (N4)

P1 supports protocol revision `2025-11-25` only (D-01 direction from T-01; D-01
is not closed by this). `protocol_version` remains a closed enum. A new revision
is added as a new constant after its own review and is never matched by a pattern.

- **Task augmentation in P1 (N10).** Supported routes never declare `tasks` (route-level
  refusal below). The 2025-11-25 tasks rule (Task Support and Handling 1) says a receiver
  that does not declare the task capability MUST process the request normally and ignore
  task metadata. So a `tools/call` carrying `params.task` is **forwarded byte-preserved**,
  `task` field included, and audited by its normal outcome. The proxy does not refuse it.
- Any `tasks/*` request (audited as method `unknown`) is not forwarded. It gets the fixed
  `-32601` error below and completes as `protocol_error`/`not_sent` with reason
  `task_augmentation_unsupported`. That is now the only use of that reason with `not_sent`.
- **Task handle from a non-compliant upstream (N10 ii).** On a supported route, a task handle
  can only come from an upstream that breaks the rule above. The response is relayed
  unchanged (relay-first, never rewritten) and audited `protocol_error`/`sent`/
  `task_augmentation_unsupported`, never `success`. On the first occurrence the route is
  marked unsupported (degraded) by the same mechanism as `upstream_capability_unsupported`,
  so new sessions and the next health check are refused. The client's follow-up `tasks/*`
  gets `-32601`.
- **Upstream `tasks` capability: route-level refusal (T-02-fix-3 correction 2).** The
  proxy never strips the capability and never relays it.
  - At registration or health check, an upstream `initialize` result containing
    `capabilities.tasks` marks the route unsupported.
  - If one appears at runtime, the attempt ends the same way as an unsupported
    upstream version. No downstream session is established. The proxy sends DELETE
    for the upstream session. The `initialize` invocation completes as
    `protocol_error`/`sent` with reason `upstream_capability_unsupported`.
  - This follows PX-004's first clause: a feature the proxy does not support is never
    advertised. Review-lead withdrew the earlier "relay unchanged" view.
  - The task-handle rule above stays as defense in depth.
  - Supporting tasks later needs its own non-terminal state, recorded until the task
    result is observed.
- **Upstream version outside the allowlist (correction 3).** If the upstream
  `initialize` answer carries a revision outside the allowlist (`2025-11-25`), the
  attempt ends as above, with reason `upstream_version_unsupported` and
  `protocol_error`/`sent`. To decide this, the proxy buffers the `initialize` response,
  bounded by the response limit, including when it arrives as SSE. This is a narrow
  exception to streaming, and the response is never rewritten.
- **Buffer end (N12).** Buffering ends at the first complete JSON-RPC response whose `id`
  exactly equals the `initialize` id (JSON value equality), or when the bound or timeout
  (values: D-04) is reached.
  - Supported answer: the proxy relays the held bytes in order (including any SSE events
    that came before the response), then streams the rest unchanged.
  - Bound or timeout exceeded before a complete matching response: nothing is relayed,
    no downstream session is established, and the proxy sends DELETE for any upstream
    session. The `initialize` invocation completes as `protocol_error`/`sent` with reason
    `upstream_initialize_unreadable`. It is not `timeout`, because the proxy received
    bytes and refused them for being unreadable within its bound. It is not the version
    reason either, because the answer's version is not known.
- **Intercepted modern requests (D-01 B1, decisions.md "D-01 후속 결정", correction 4).**
  Authentication is checked first. An unauthenticated request gets 401 and no B1
  handling. An authenticated request counts as modern-era if any of these holds:
  method `server/discover`; request `_meta` contains `io.modelcontextprotocol/protocolVersion`;
  an `MCP-Protocol-Version` header outside the allowlist.
  - Such a request is not forwarded. The client gets HTTP 400 with an empty body.
  - Audit: a start with `method` and `protocol_version` both literal `unknown` and no
    `tool`, then a completion `protocol_error`/`not_sent` with reason
    `modern_request_unsupported`.
  - The raw method, `_meta` value and header value are echoed nowhere.
- **Client-visible errors for pre-dispatch refusals (m4).** These are standard
  JSON-RPC 2.0 codes from the legacy era. The modern-era codes `-32020`/`-32022`
  are never used. Each error has a fixed `message`, no `data`, and echoes nothing
  from the request apart from the JSON-RPC `id`.

  | Refusal | `code` | `message` | Why |
  |---|---|---|---|
  | `tools/call` with an unparseable tool name (`unavailable/malformed`) | `-32602` | `Invalid params` | The request is well formed but its params are not. |
  | any `tasks/*` request | `-32601` | `Method not found` | The method is not available through the proxy. |
  | cancelled before dispatch | none | none | 2025-11-25 cancellation: no response is sent for a cancelled request. |
- **Cancellation with no response.** After `invocation.cancel_requested` for a
  dispatched invocation, the proxy waits for a response for a bounded grace period
  (value: D-04). If a response arrives, its actual outcome is recorded. If none
  arrives, the completion is `unknown` with reason `cancel_no_response` and delivery
  `sent` or `unknown`. A cancellation before dispatch is `cancelled_before_dispatch`
  (see Traffic section, M3). It is never `timeout`, even if the proxy deadline elapses
  later. `timeout` is reserved for the proxy-enforced deadline when no
  cancellation was observed. Neither outcome claims that execution stopped.
  This follows the documented 2025-11-25 cancellation semantics. Real-client behaviour
  is unverified, except that T-01 measured Claude Code sending `notifications/cancelled`.

### D-05 metadata registry (N9)

This makes forwarding independent of central resolution, so relay continues offline as in
design.md:22. Recorded for D-05; not closed.

| Item | Rule |
|---|---|
| Allocation authority | The proxy allocates `metadata_ref` locally under its authenticated identity, when it observes a **complete** inventory. Calls only perform a local lookup. The server adopts entries later and never mints or rewrites them. |
| Scope key | `(proxy_id, upstream_id, credential_scope_id, protocol_version, observation_source="proxy_live")`. The server assigns `credential_scope_id` to the upstream endpoint + upstream credential + visibility binding, and it changes when any of those change. `route_revision` is excluded: other route edits (limits, timeouts) do not change what the upstream exposes, and each invocation already records its own `route_revision`, so including it would re-mint refs for unchanged tools. |
| Fingerprint | `sigil-tooldef-fp-v1` = HMAC-SHA-256(K, `"sigil-tooldef-fp-v1\0"` ‖ RFC 8785 JCS(full tool object)). The tool object includes name, title, description, input/output schema, annotations, icons, execution, `_meta` and unknown fields, so any change counts. Volatility rule (m5): the canon version carries a fixed list of tool-level `_meta` keys excluded as volatile. The v1 list is **empty**, because no volatile key has been measured. Adding a key creates a new canon version (`-v2`), which re-mints refs and records a re-baseline marker, not drift. An excluded key's changes are invisible to drift, and that trade-off is recorded with the evidence for each key. K is a per-proxy 256-bit key with a `key_id`, kept owner-only in `state_dir`, never transmitted. The keyed fingerprint goes only to the access-controlled metadata store. Drift is computed only between equal `(canon version, key_id)`. A change of either produces a re-baseline marker, never drift. A tool object that cannot be canonicalised makes the inventory incomplete. |
| Reference | `metadata_ref` = first 16 bytes of HMAC-SHA-256(K, `"sigil-metadata-ref-v1\0"` ‖ JCS(scope key + canon version + key_id + fingerprint)), formatted as an RFC 9562 version-8 UUID (schema-enforced). It is deterministic, so a restart or a re-list maps the same definition to the same ref. Without K it is not guessable from a tool name. `check_schema.py` models this derivation with a fixture key; the example ref is that model's output. |
| Inventory source (m5) | P1 uses only client-driven `tools/list` traffic that the proxy observes. The proxy never issues its own listing, because that would use the upstream credential outside any client request and blur visibility scope. An inventory is complete when one authenticated session, in one scope, follows a chain that starts without a cursor, through successful pages, to a page without `nextCursor`. A proxy-initiated listing needs a separate contract. |
| Offline resolution | The lookup uses only the last *complete* paginated inventory of the scope, held in local state. An incomplete or failed listing never removes or replaces entries (PX-005). A tool name absent from that inventory is forwarded (P1 observe mode does not block) and recorded as `metadata_unavailable` with reason `not_in_inventory`. If no complete inventory exists, the reason is `no_complete_inventory`. If a name is listed more than once, the reason is `ambiguous_in_inventory`. An unparseable name is `unavailable/malformed` and is rejected before dispatch. |
| Sync ordering | The proxy durably records each registry entry locally before any start that references it. It uploads the entries (candidate endpoint `POST /v1/proxy-metadata`, mTLS proxy identity, access-controlled store) before, or atomically with, the event batches that reference them. Registry ingest is idempotent per `(proxy_id, metadata_ref)`. Equality covers the immutable fields only: `proxy_id`, `metadata_ref`, the scope key fields, `canon`, `key_id`, `fingerprint`. The stored definition is bound through the fingerprint. Volatile fields such as `observed_at` and upload metadata are excluded. A difference in an immutable field is a 409 (M2b). |
| Registry 409 (M2b) | The producer quarantines the entry unchanged and records an integrity audit gap. It then rewrites only the `tool` field of each dependent start that was never centrally accepted to `{"status":"metadata_unavailable","reason":"registry_conflict"}`, keeping every other field. This is the only permitted spool rewrite, and the original bytes are kept in quarantine for at least the event retention period (N11). The producer reports the integrity gap centrally (N11): `kind=registry_conflict`, the conflicting `metadata_ref`, the `key_id`, and the affected `event_id`s, with no field values. This report travels on the gap/heartbeat channel, whose DTO is still open. Before sending any event, the producer recomputes the hash of the local registry entry's immutable fields and compares it with the hash recorded when the upload was ACKed. A mismatch is treated as a registry conflict and goes down this same path (N11 iii). A 424 accepts nothing, so only never-accepted events are rewritten. If a rewritten event still conflicts, it is quarantined as an event conflict. Dependent events therefore stop waiting on 424. |
| Not-yet-synced refs | An event batch that references a ref not yet registered for that proxy is rejected as a whole with retryable **424 `metadata_ref_pending`** (not 422). The error names the waiting items (index, `event_id`) and lists the validated pending refs, and echoes no other value (M2a). The producer uploads the pending entries from local state and retries with backoff, and health reports a stalled sync. A ref registered to another scope or proxy is a permanent 422/403. A ref with no local entry is a producer integrity fault: the event is quarantined with audit-gap status and never resubmitted with an invented ref. |
| Retention | A registry entry is kept, centrally and locally, at least as long as every event that references it and the dedup tombstones of those events. Locally, it is kept until those events and the entry itself have been centrally ACKed. If content is deleted (for example on a privacy request), the scope-bound stub stays so that ingestion still recognises the ref. Deleted content displays the fixed unavailable label. |

Still open for D-05: the full registry entry DTO and JSON Schema, key rotation operations,
the projection of re-baseline markers, and the inventory/drift event contract.

## Changes in T-02-fix-2

| N-id | Change |
|---|---|
| N1 | Added exact pins in `requirements-check.txt` (`jsonschema==4.26.0`, `rfc3339-validator==0.1.4`, plus transitive pins). `check_schema.py` exits 2 when `date-time`/`uuid` checking is missing or ineffective. Added an `occurred_at` UTC shape pattern. New negatives include `canary-secret`, `not-a-date`, a trailing newline, an offset, lowercase, an epoch number and calendar-invalid dates; the calendar cases are shown to need format checking. Added the ingestion RFC 3339 parse rule. |
| N2 | Dedup equality now covers the full submitted envelope plus payload. A reused sequence is a conflict. Added a 409 quarantine candidate. Added dedup reference-model cases that differ only in sequence, only in occurred_at (including the same instant written differently) or only in a payload field, plus a new ID on an old sequence. |
| N3 | Authentication is required on all listeners, loopback included. Restored `evidence_source`, which is required. Stated the provenance of `actor_kind` and `credential_owner_id`. Client-asserted values (`_meta`/toolUseId, clientInfo, human) are not representable. New negatives cover auth `none`/`unknown`/`unauthenticated`, the human flag, `_meta`, a client tool-use ID and a missing or raw `evidence_source`. |
| N4 | Pinned P1 to `2025-11-25` with a closed enum. Task augmentation is rejected as `protocol_error` + `task_augmentation_unsupported` and is never `success`. A cancellation with no response becomes `unknown` + `cancel_no_response` and is never `timeout`. Added an optional closed completion `reason` with an outcome/delivery matrix, plus negatives for `2026-07-28`, `2025-06-18` and `tasks/get` as version/method values. |
| N7 | Integers are bounded to `2^63−1` through `$defs`. The strict integer layer rejects `1.0`/`1e0`/`1E0`/`1.00` at the JSON-token level and rejects booleans. Added max/max+1/`2^70`/float negatives. |
| N8 | `design.md:47` now uses the tool/metadata_ref wording. An `initialize` start requires `protocol_version=unknown` (schema plus negative). |
| N9 | Added the D-05 registry table: local keyed deterministic refs, a scope key without `route_revision`, the fingerprint v1 canon, offline `metadata_unavailable` forwarding, sync ordering, retryable 424 and retention. `unresolved` is withdrawn. The schema requires version-8 refs, and the example ref is the derivation model output. |

## T-02-fix-3 contract rules — 2026-10-10

Links: PX-006/008/011/015; AC-03/06; D-03/D-05. These rules address the v0.2 re-check
items M1–M3 and m1–m6. Nothing here closes a D item or claims an implementation.

### Producer epoch (M1)

- `epoch_id` is a required envelope field, a random lowercase UUID. The proxy generates and
  durably stores a new epoch on first start, and whenever its local state (spool,
  sequence counter, registry key) cannot be recovered. A new epoch starts its sequence again.
- Sequence uniqueness and `sequence_conflict` use `(proxy_id, epoch_id, sequence)`.
  Event dedup stays `(proxy_id, event_id)` over the full event, so the same `event_id`
  arriving under another epoch is a conflict.
- When the server sees a new epoch for a `proxy_id` that already has one, it records an
  explicit audit gap (`producer_epoch_change`, previous and new epoch). Events still
  arriving for an older epoch are accepted normally. Starts from a lost epoch that have
  no completion stay start-only and are never shown as success.
- A `state_dir` loss is the same event as an unrecoverable state. The proxy creates a new
  `epoch_id` and a new K with a new `key_id`, and the server records the audit gap. Refs
  re-mint under the new `key_id` (D-05 table).
- `key_id` is unique per K and never reused. P1 derives it from K: `"kid-"` + the first
  24 hex digits of SHA-256(`"sigil-key-id-v1\0"` ‖ K). K is always a fresh random
  256-bit key. K falls under the `state_dir` secret-handling rules: owner-only
  permissions, never transmitted or logged, and excluded from backups and support bundles.

### Follow-up (m6, tracked only)

Authentication failures, and cancellations that match no request, are not invocation
events. Their aggregate contract (bounded counters by route and fixed reason code,
with no raw headers, tokens or IDs) is a tracked follow-up and is not defined here.

## Changes in T-02-fix-3

| Item | Change |
|---|---|
| M1 | Required envelope `epoch_id` (schema v0.3; example updated). The sequence domain is `(proxy_id, epoch_id, sequence)`, and the server records a `producer_epoch_change` audit gap. Cases: missing, raw, empty, uppercase, integer and newline epoch rejected; another epoch accepted. Model: same sequence in a new epoch accepted with a gap recorded; a reused sequence in the same epoch gives `sequence_conflict`; the same `event_id` under another epoch gives a conflict. |
| M2a | The error body gains `items` (`index`, validated `event_id`, fixed code) and, for 424, `pending_metadata_refs`. 422 items carry the index only, and precedence is 422 > 403 > 409 > 424. A batch model checks 409, 424, 422 (index only, no canary in the body) and 200 accepted+duplicate. |
| M2b | Registry equality covers immutable fields only, and `observed_at` is excluded. On a registry 409 the producer quarantines the entry, records a gap, and rewrites the never-accepted dependent starts to `metadata_unavailable/registry_conflict` (new reason). Model: volatile-only difference is a duplicate, fingerprint difference is a conflict, and the rewritten dependent is accepted. |
| M3 | (Revised by correction 1.) The Traffic section defines cancel ordering. A cancel observed before dispatch stops the dispatch: the completion is `unknown/not_sent/cancelled_before_dispatch`, nothing goes to the client, and nothing is held and forwarded. A cancel whose request has not arrived yet is held for a bounded window (D-04), then dropped. A cancel after dispatch is forwarded. New completion reason `cancelled_before_dispatch`, valid only with `unknown/not_sent`. `cancel_no_response` is now `sent`/`unknown` only. The full outcome × delivery × reason matrix is covered by cases. |
| m1 | `check_schema.py` exits 2 under `python -O`. |
| m2 | Leap-second producer rule (smeared clock or clamp to `:59.999999999`). Second `60` is rejected and the clamped value accepted. |
| m3 | (Revised by correction 2.) An upstream `tasks` capability makes the route unsupported, at registration, health check or runtime. At runtime there is no downstream session, the proxy sends DELETE upstream, and the completion is `protocol_error/sent/upstream_capability_unsupported`. Nothing is stripped or relayed. The per-call refusal is kept as defense in depth. The "remove the capability" text is gone. |
| m4 | (Revised by T-02-fix-4 N10.) Fixed refusal errors: malformed gets `-32602 Invalid params`; `tasks/*` gets `-32601 Method not found`; `params.task` is no longer refused but forwarded; cancelled before dispatch gets no JSON-RPC response (HTTP shape in N13); `-32020`/`-32022` are never used. An upstream task handle is relayed unchanged, audited `protocol_error/sent`, and marks the route unsupported. |
| m5 | Inventory source is client-driven `tools/list` observation only, with the completeness rule stated. The fingerprint canon version carries a volatile `_meta` exclusion list (empty in v1). Changing that list is a new version and a re-baseline, not drift. |
| m6 | Tracked follow-up note only (auth-failure and unmatched-cancel aggregate contract). |

### T-02-fix-3 corrections (D-01 follow-up review)

| Correction | Change |
|---|---|
| 1 Cancel before dispatch | No hold-and-forward. The request is not dispatched and completes as `unknown/not_sent/cancelled_before_dispatch`, with nothing sent to the client. A cancel for a not-yet-arrived id is held for a bounded window (PX-013, value in D-04), then discarded and counted. A cancel after dispatch is unchanged. |
| 2 `tasks` capability | Route-level refusal and the new reason `upstream_capability_unsupported` (`protocol_error/sent` only). Matrix cases cover every outcome × delivery combination. |
| 3 Upstream version | New reason `upstream_version_unsupported` (`protocol_error/sent` only). The `initialize` response is buffered, bounded, including when it arrives as SSE, and is never rewritten. |
| 4 B1 audit | (Extended in fix-3b.) Authentication is checked first (401). A modern request (`server/discover`, the `protocolVersion` `_meta`, or a header outside the allowlist) is not forwarded and gets HTTP 400 with an empty body. The start has method and version both `unknown`; the completion is `protocol_error/not_sent/modern_request_unsupported` (new constant, not_sent only). Positive cases, plus negatives for a raw method, a raw version, a raw `_meta` and the reason with `sent`. |
| 5 key_id | `key_id` is derived from K, so it is never reused. A `state_dir` loss means a new epoch, a new K/`key_id` and an audit gap. K is excluded from backups and support bundles. The checker fixture now uses derived key IDs, and the example ref was re-derived. |
| 2 (fix-3b note) | Review-lead's withdrawal is recorded: relaying `capabilities.tasks` unchanged would break PX-004's first clause. The open question about a single-call task handle is resolved: it is unreachable through a supported route, and its `protocol_error/sent` audit stays as a defensive rule. |

## Changes in T-02-fix-4

| Item | Change |
|---|---|
| N10 | `tools/call` with `params.task` is forwarded byte-preserved, task included, and audited by its normal outcome, per the 2025-11-25 tasks rule "Task Support and Handling 1". The per-call `-32601` refusal and its error-table row are removed, and the m4 row is revised. `tasks/*` keeps `-32601` + `protocol_error/not_sent/task_augmentation_unsupported`. Cases: a task-augmented call with a normal outcome; `tasks/*` refusal; the full matrix. |
| N10 (ii) | A task handle is relayed unchanged and audited `protocol_error/sent/task_augmentation_unsupported`. On the first occurrence the route is marked unsupported (new sessions and the next health check refused), and follow-up `tasks/*` gets `-32601`. Both delivery states of the reason remain in use, so the matrix is unchanged. |
| N11 | Central integrity-gap report (`registry_conflict`, ref, `key_id`, affected `event_id`s, no values). Quarantined originals are kept for at least the event retention period. Before each send, the local entry hash is compared with the hash recorded at upload, and a mismatch takes the registry-conflict path. Model cases: hash match, tampered entry, and a gap report that carries no field values. |
| N12 | Buffering ends at the first complete response whose id equals the `initialize` id, or at the bound/timeout. Held bytes are relayed and then the rest streams. New reason `upstream_initialize_unreadable` (`protocol_error/sent` only) for an exceeded bound or timeout. |
| N13 | `cancelled_before_dispatch` at the HTTP level: `200 text/event-stream`, terminated with no event, no event id and no `retry`, justified against the 2025-11-25 Streamable HTTP rules. requestId matching uses exact JSON value equality. Model cases: `"4"`≠`4`, `4`≠`4.0`, `true`≠`1`, and `4`=`4`/`"4"`=`"4"`. |
| M1 gap | Startup model: if K is absent while the spool is present, a new epoch is created. The same holds for a missing epoch or spool; a fully present state keeps the epoch. |
