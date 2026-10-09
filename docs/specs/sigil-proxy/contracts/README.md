# P1 계약 후보 v0.1

2026-09-27 · T-02 진행 중. P0 리뷰와 실기 검증 전에는 구현 고정 계약이 아니다.

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
기본 listen은 loopback이다. 외부 bind는 TLS 설정과 인증이 없으면 시작 실패한다.

원격 route/auth 설정은 중앙 버전 단위로 검증 후 원자 적용한다. 로컬 bootstrap과 병합하지 않는다.
현재 버전과 낮은 버전은 새 적용으로 인정하지 않는다. 만료 시 새 호출을 전달하지 않는다.
인증 실패·폐기 갱신 지연의 최대 허용 시간을 config TTL로 명시하며 즉시 폐기를 주장하지 않는다.

## 감사 이벤트 초안

[JSON Schema](proxy-event.schema.json)와 [예제](invocation-started.example.json)는
P1 invocation started/completed와 nonterminal cancel_requested 관찰만 정의한다. inventory/heartbeat/config 감사는
후속 계약 항목이며 이 schema로 임의 payload를 전달하지 않는다.

- sequence는 proxy별 단조 증가, event_id는 UUID이며 재전송 시 동일하다.
  동일 invocation의 start/cancel/completion은 각각 다른 event_id와 sequence를 갖는다.
- 동일 event_id의 동일 canonical payload 재전송만 중복으로 인정한다. 다른 payload는 409 충돌이다.
- 시작/완료 이벤트의 proxy 소유권과 invocation 결합을 저장 계층이 검사한다. schema 검사만으로 인증하지 않는다.
- occurred_at은 proxy 시각이다. 중앙 received_at은 저장 계층이 별도 부여한다.
- 중앙은 `(proxy_id,event_id)` unique로 중복 제거한다. sequence는 공백 진단용이며
  높은 sequence 수신만으로 낮은 미수신 이벤트를 버리지 않는다.
- 원문 arguments/results/error/session/token은 불허한다. 고정 code만 기록한다.
- actor_id는 인증 서버 매핑에서 나온다. clientInfo나 임의 헤더에서 가져오지 않는다.
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
오류 구조는 `{error:{code,message}}`; message는 안전한 고정 텍스트다.
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

`jsonschema==4.26.0`이 설치된 격리 Python 환경에서
`python docs/specs/sigil-proxy/contracts/check_schema.py`를 실행한다.
현재 검사는 schema 자체, positive 24개, rejected 60개 및 lifecycle fixture ID를 검사한다.
동일 재전송/충돌 재사용 fixture도 구분하지만 실제 ledger에 수집하지 않는다.
API 인증·저장·전달, producer 정규화, metadata provenance/권한, 실제 client 호환성을 검증한 것이 아니다.

```text
/tmp/sigil-proxy-schema-check-20260927/bin/python docs/specs/sigil-proxy/contracts/check_schema.py
PASS: schema, 24 positive cases, 60 rejected cases; lifecycle IDs, unchanged retransmission and conflicting-reuse fixture assertions
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
otherwise emit literal `unknown`. Never copy a proposed revision or an HTTP
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

- Valid calls use `{"status":"identified","metadata_ref":"<UUID>"}`.
  The reference is an independently generated opaque random UUID allocated by
  the controlled metadata registry, never the raw name, a name hash/encoding,
  an arbitrary request field, or a client/upstream-provided identifier.
- The registry binds an immutable entry to the registered upstream, route
  revision, credential/visibility scope and observed tool metadata revision.
  The producer resolves the parsed tool name against that scoped entry before
  emitting the reference. An inventory name is untrusted content even when
  received from a registered upstream; observing it grants no approval.
- If no valid tool can be identified, emit only
  `{"status":"unavailable","reason":"malformed"}` or reason `unresolved`.
  These are explicit pre-dispatch rejected-call representations, not successful
  call substitutes. Do not invent a reference or silently omit `tool`. An
  unavailable start cannot later claim dispatch or success: its correlated
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
Ordering/availability of registry synchronization, its scoped DTOs and offline
reference resolution must be frozen before implementation. They must not silently
turn a central metadata lookup into a pre-dispatch online dependency.

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

| Outcome | Allowed delivery_state |
|---|---|
| success, tool_error | sent |
| denied | not_sent |
| protocol_error, timeout, unknown | not_sent, sent, unknown |

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
cancellation and completion while preserving invocation/proxy IDs. It also
constructs an unchanged retransmission and a same-ID/different-payload conflict.
Both are schema-valid; the latter must be rejected by a future ledger. Fixture
assertions are not evidence of 409 handling, canonical comparison, transactional
ACK, restart durability, out-of-order ingestion or retention behavior.

Canary negatives cover method/version and raw tool-name paths on identified and
malformed/unresolved starts, closed tool metadata objects and cancellation data.
Positive cases cover every fixed vocabulary constant, explicit unavailable tools,
non-tool methods and all allowed outcome/delivery combinations. Real producer
normalization, registry provenance/authorization and end-to-end canary absence in
spool/server/manager still require implementation and independent verification.

