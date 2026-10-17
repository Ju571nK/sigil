//! `POST /v1/proxy-events` (T-11 S4 slice B2): event ingest.
//!
//! Spec: ledger-and-query.md L5 (SV-1..SV-8), contracts README (ingest answers,
//! N2/M1/M2a, error table), control-plane.md 1.2. PX-005/010/011, AC-05/06.
//!
//! Answer order, first match wins (the identity layer runs before this handler
//! and before any body byte is read):
//!
//! | Step | Condition | Answer |
//! |---|---|---|
//! | guard | no/unknown/mismatched identity | 404 `proxy_unknown` |
//! | guard | disabled / retired | 403 `disabled` / `retired` |
//! | slot | all ingest slots busy | 429 `rate_limited` (body unread) |
//! | body | more than 1 MiB | 413 `payload_too_large` |
//! | identity-in-body | any event `proxy_id` != mTLS identity | 404 `proxy_unknown` |
//! | parse | schema/syntax/semantic, or too many events | 422 (index of the first bad event when known) / 413 for a count or size bound |
//! | SV-3/4/5 | ref owned by another proxy, scope or protocol mismatch, scope not assigned | 422 `semantic_invalid`, index only |
//! | 409 | `conflict`, `sequence_conflict`, `invocation_owner_conflict` | 409 with `{index, event_id, code}` |
//! | SV-2 | a start names a ref nobody registered | 424 `metadata_ref_pending` + `pending_metadata_refs` |
//! | store | cap reached / store failed | 503 `storage_limit` / `storage_unavailable` |
//! | commit | everything stored | 200 `{accepted_event_ids, duplicate_event_ids}` |
//!
//! The body `proxy_id` mismatch is a 404 and not a 422 because the contract
//! says an identity mismatch is byte-identical to an unknown proxy and is
//! evaluated before body validation (ledger L5 preamble, README ingest text,
//! decisions.md "D-02 결정"); it is also what `status.rs` does. Like there,
//! it is read from the raw body BEFORE the typed parse, so a malformed event
//! next to a foreign `proxy_id` still answers 404.
//!
//! Precedence 422 > 409 > 424 with all-or-nothing storage: a batch that has
//! both a conflict and a pending ref answers 409 (the ledger's dry run
//! `check_batch` finds the conflict without storing anything), and nothing is
//! stored for any non-200 answer. 200 is sent only after the ledger commit.
//!
//! Errors carry fixed text and indexes/validated ids only; no request value is
//! echoed. Denials are logged at most once a minute per reason with a count.

use super::guard::{proxy_unknown, VerifiedProxy};
use super::metadata::RefLookup;
use super::ProxyContext;
use axum::body::{Body, Bytes};
use axum::extract::{Extension, State};
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use parking_lot::Mutex;
use sigil_proxy_api::event::{ProtocolVersion, Tool};
use sigil_proxy_api::registry::RegistryProtocolVersion;
use sigil_proxy_api::{
    parse_event_batch, ApiError, ErrorCategory, ErrorCode, ErrorItem, EventPayload, IngestResponse,
    MetadataRef,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::TryAcquireError;

pub const INGEST_PATH: &str = "/v1/proxy-events";
/// Request body cap (README: 1 MiB).
pub const MAX_INGEST_BODY: usize = sigil_proxy_api::parse::MAX_EVENT_BATCH_BYTES;

const LOG_WINDOW: Duration = Duration::from_secs(60);

/// Rate-limited warning log: the first denial of a reason logs at once, later
/// ones are counted and reported with the next line after the window.
#[derive(Default)]
pub struct DenyLog {
    seen: Mutex<HashMap<&'static str, (Instant, u32)>>,
}

impl DenyLog {
    pub fn note(&self, route: &'static str, reason: &'static str) {
        let mut g = self.seen.lock();
        match g.get_mut(reason) {
            None => {
                g.insert(reason, (Instant::now(), 0));
                tracing::warn!(route, reason, "proxy request refused");
            }
            Some((t, suppressed)) if t.elapsed() >= LOG_WINDOW => {
                tracing::warn!(
                    route,
                    reason,
                    suppressed = *suppressed,
                    "proxy request refused (further refusals in the last minute counted)"
                );
                *t = Instant::now();
                *suppressed = 0;
            }
            Some((_, suppressed)) => *suppressed += 1,
        }
    }
}

pub(super) fn api_response(status: StatusCode, e: ApiError) -> Response {
    (
        status,
        Json(serde_json::to_value(e).unwrap_or(serde_json::Value::Null)),
    )
        .into_response()
}

pub(super) fn fixed(code: ErrorCode) -> Response {
    let status = StatusCode::from_u16(code.http_status().unwrap_or(500))
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    api_response(status, ApiError::from_code(code))
}

pub(super) fn index_u32(i: usize) -> u32 {
    u32::try_from(i).unwrap_or(u32::MAX)
}

/// 422 with index-only items (never a value).
pub(super) fn semantic_422(mut indexes: Vec<usize>) -> Response {
    indexes.sort_unstable();
    indexes.dedup();
    let items = indexes
        .into_iter()
        .map(|i| ErrorItem {
            index: index_u32(i),
            event_id: None,
            gap_id: None,
            code: ErrorCode::SemanticInvalid,
        })
        .collect();
    api_response(
        StatusCode::UNPROCESSABLE_ENTITY,
        ApiError::from_code(ErrorCode::SemanticInvalid).with_items(items),
    )
}

/// Reads the whole body up to `limit`. `None` = over the limit (or unreadable).
pub(super) async fn read_capped(body: Body, limit: usize) -> Option<Bytes> {
    axum::body::to_bytes(body, limit).await.ok()
}

/// `true` when some event names a different proxy than the caller. Reads only
/// string `proxy_id` values, element by element, so a malformed neighbour does
/// not hide a foreign id. A body without this shape falls through to the typed
/// parse (which re-checks identity on the parsed events).
fn foreign_proxy_id_in_body(body: &[u8], peer_id: &str) -> bool {
    let Ok(serde_json::Value::Object(doc)) = serde_json::from_slice::<serde_json::Value>(body)
    else {
        return false;
    };
    doc.get("events")
        .and_then(|e| e.as_array())
        .is_some_and(|evs| evs.iter().any(|e| differs(e.get("proxy_id"), peer_id)))
}

/// A string `proxy_id` that is not the caller's.
pub(super) fn differs(v: Option<&serde_json::Value>, peer_id: &str) -> bool {
    matches!(v, Some(serde_json::Value::String(s)) if s != peer_id)
}

fn storage_error(e: &super::ledger::LedgerError) -> Response {
    use super::ledger::LedgerError;
    match e {
        LedgerError::StorageLimit => fixed(ErrorCode::StorageLimit),
        // ProxyMismatch cannot happen after the identity check; fail closed.
        LedgerError::ProxyMismatch => proxy_unknown(),
        _ => fixed(ErrorCode::StorageUnavailable),
    }
}

fn conflict_response(items: &[super::ledger::ConflictItem]) -> Response {
    let items = items
        .iter()
        .map(|c| ErrorItem {
            index: index_u32(c.index),
            event_id: Some(c.event_id.clone()),
            gap_id: None,
            code: c.kind.error_code(),
        })
        .collect();
    api_response(
        StatusCode::CONFLICT,
        ApiError::from_code(ErrorCode::Conflict).with_items(items),
    )
}

/// Blocking body of the handler: validate against the registry, then store.
pub fn handle(ctx: &ProxyContext, peer_id: &str, body: &[u8]) -> Response {
    if foreign_proxy_id_in_body(body, peer_id) {
        ctx.ingest_log.note("events", "identity_mismatch");
        return proxy_unknown();
    }
    let batch = match parse_event_batch(body) {
        Ok(b) => b,
        Err(e) => {
            if e.category() == ErrorCategory::Limit {
                ctx.ingest_log.note("events", "payload_too_large");
                return fixed(ErrorCode::PayloadTooLarge);
            }
            ctx.ingest_log.note("events", "invalid");
            // Only the position of the first bad event is attributable.
            let err = ApiError::from_code(ErrorCode::SemanticInvalid);
            return api_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                match e.index() {
                    Some(i) => err.with_items(vec![ErrorItem {
                        index: index_u32(i),
                        event_id: None,
                        gap_id: None,
                        code: ErrorCode::SemanticInvalid,
                    }]),
                    None => err,
                },
            );
        }
    };
    let events = batch.events;
    if events.iter().any(|e| e.proxy_id.as_str() != peer_id) {
        ctx.ingest_log.note("events", "identity_mismatch");
        return proxy_unknown();
    }

    // An event already stored byte-equal is a duplicate: it is not re-judged
    // against the registry or the (since changed) route scopes, so an
    // ack-lost retransmission after route edits is still a duplicate.
    let stored_equal = match ctx.ledger.existing_equal(peer_id, &events) {
        Ok(v) => v,
        Err(e) => return storage_error(&e),
    };

    // SV-2..SV-5 over every start that names a ref.
    let mut invalid: Vec<usize> = Vec::new();
    let mut pending: Vec<(usize, MetadataRef)> = Vec::new();
    {
        let wanted: Vec<(usize, &MetadataRef)> = events
            .iter()
            .enumerate()
            .filter(|(i, _)| !stored_equal[*i])
            .filter_map(|(i, e)| match &e.payload {
                EventPayload::Started(s) => match &s.tool {
                    Some(Tool::Identified(t)) => Some((i, &t.metadata_ref)),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        if !wanted.is_empty() {
            let refs: Vec<&str> = wanted.iter().map(|(_, r)| r.as_str()).collect();
            let found = match ctx.metadata.lookup(peer_id, &refs) {
                Ok(f) => f,
                Err(_) => return fixed(ErrorCode::StorageUnavailable),
            };
            for ((index, mref), lookup) in wanted.into_iter().zip(found) {
                let EventPayload::Started(start) = &events[index].payload else {
                    continue;
                };
                match lookup {
                    RefLookup::Unknown => pending.push((index, mref.clone())),
                    // SV-3: registered, but only under another proxy.
                    RefLookup::OtherProxy => invalid.push(index),
                    RefLookup::Own(info) => {
                        // SV-4: upstream, protocol and observation source.
                        let protocol_ok = match start.protocol_version {
                            ProtocolVersion::Unknown => true,
                            ProtocolVersion::V2025_11_25 => {
                                info.protocol_version
                                    == super::metadata::enum_text(
                                        &RegistryProtocolVersion::V2025_11_25,
                                    )
                            }
                        };
                        if info.upstream_id != start.upstream_id.as_str()
                            || !protocol_ok
                            || info.observation_source != "proxy_live"
                        {
                            invalid.push(index);
                            continue;
                        }
                        // SV-5: the entry's scope is one the server assigned for
                        // this upstream in the current or the previous revision.
                        if !ctx.store.scope_assigned(
                            peer_id,
                            &info.upstream_id,
                            &info.credential_scope_id,
                        ) {
                            invalid.push(index);
                        }
                    }
                }
            }
        }
    }
    if !invalid.is_empty() {
        ctx.ingest_log.note("events", "semantic_invalid");
        return semantic_422(invalid);
    }

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if !pending.is_empty() {
        // 409 outranks 424: look for conflicts without storing anything.
        match ctx.ledger.check_batch(peer_id, &events, now) {
            Err(super::ledger::LedgerError::Conflicts(items)) => {
                ctx.ingest_log.note("events", "conflict");
                return conflict_response(&items);
            }
            Err(e) => return storage_error(&e),
            Ok(()) => {}
        }
        ctx.ingest_log.note("events", "metadata_ref_pending");
        let items = pending
            .iter()
            .map(|(i, _)| ErrorItem {
                index: index_u32(*i),
                event_id: Some(events[*i].event_id.clone()),
                gap_id: None,
                code: ErrorCode::MetadataRefPending,
            })
            .collect();
        let mut refs: Vec<MetadataRef> = Vec::new();
        for (_, r) in pending {
            if !refs.contains(&r) {
                refs.push(r);
            }
        }
        return api_response(
            StatusCode::from_u16(424).unwrap_or(StatusCode::FAILED_DEPENDENCY),
            ApiError::from_code(ErrorCode::MetadataRefPending)
                .with_items(items)
                .with_pending_metadata_refs(refs),
        );
    }

    match ctx.ledger.insert_batch(peer_id, &events, now) {
        Ok(out) => {
            touch_last_seen(ctx, peer_id);
            Json(
                serde_json::to_value(IngestResponse {
                    accepted_event_ids: out.accepted,
                    duplicate_event_ids: out.duplicate,
                })
                .unwrap_or(serde_json::Value::Null),
            )
            .into_response()
        }
        Err(super::ledger::LedgerError::Conflicts(items)) => {
            ctx.ingest_log.note("events", "conflict");
            conflict_response(&items)
        }
        Err(e) => {
            ctx.ingest_log.note("events", "storage");
            storage_error(&e)
        }
    }
}

/// `last_seen` after an accepted batch (rate-bounded by the store). The batch
/// is already committed in the ledger, so a failed state write must not turn
/// the answer into an error: it is logged without values and the next accepted
/// batch or status report refreshes it.
fn touch_last_seen(ctx: &ProxyContext, peer_id: &str) {
    if let Err(e) = ctx.store.touch_last_seen(peer_id) {
        tracing::warn!(error = %e, "proxy last_seen update failed (ingest)");
    }
}

/// One ingest/upload slot: a global permit plus a per-proxy count, both
/// released on drop (also when the request is cancelled mid-read).
pub(super) struct Slot {
    _permit: tokio::sync::OwnedSemaphorePermit,
    ctx: Arc<ProxyContext>,
    id: String,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut g = self.ctx.ingest_per_proxy.lock();
        if let Some(n) = g.get_mut(&self.id) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                g.remove(&self.id);
            }
        }
    }
}

/// Take a slot for `proxy_id`, or the 429 to send. One identity may hold at
/// most `ingest_per_proxy_cap` slots (max(1, N/4)), so it cannot starve the
/// others; the global semaphore bounds the total.
pub(super) fn acquire_slot(
    ctx: &Arc<ProxyContext>,
    proxy_id: &str,
    route: &'static str,
) -> Result<Slot, Box<Response>> {
    let busy = |reason: &'static str| {
        ctx.ingest_log.note(route, reason);
        fixed(ErrorCode::RateLimited)
    };
    let mut g = ctx.ingest_per_proxy.lock();
    if g.get(proxy_id).copied().unwrap_or(0) >= ctx.ingest_per_proxy_cap {
        return Err(Box::new(busy("rate_limited_proxy")));
    }
    let permit = match ctx.ingest_slots.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(TryAcquireError::NoPermits) => return Err(Box::new(busy("rate_limited"))),
        Err(TryAcquireError::Closed) => return Err(Box::new(fixed(ErrorCode::StorageUnavailable))),
    };
    *g.entry(proxy_id.to_string()).or_insert(0) += 1;
    Ok(Slot {
        _permit: permit,
        ctx: ctx.clone(),
        id: proxy_id.to_string(),
    })
}

/// Read the capped body within the body timeout (a trickling client must not
/// hold a slot). There is no 408 error code in the contract, so a timeout is
/// answered 429 `rate_limited`: the request was not processed, nothing was
/// stored, and the producer's reaction (back off, retry) is the right one.
pub(super) async fn read_body(
    ctx: &ProxyContext,
    body: Body,
    limit: usize,
    route: &'static str,
) -> Result<Bytes, Box<Response>> {
    match tokio::time::timeout(ctx.ingest_body_timeout, read_capped(body, limit)).await {
        Ok(Some(b)) => Ok(b),
        Ok(None) => {
            ctx.ingest_log.note(route, "payload_too_large");
            Err(Box::new(fixed(ErrorCode::PayloadTooLarge)))
        }
        Err(_) => {
            ctx.ingest_log.note(route, "body_timeout");
            Err(Box::new(fixed(ErrorCode::RateLimited)))
        }
    }
}

/// Handler: take an ingest slot, read the capped body (with timeout), run
/// [`handle`] on the blocking pool while holding the slot.
pub async fn post_events(
    State(ctx): State<Arc<ProxyContext>>,
    Extension(id): Extension<VerifiedProxy>,
    req: Request<Body>,
) -> Response {
    let slot = match acquire_slot(&ctx, &id.proxy_id, "events") {
        Ok(s) => s,
        Err(r) => return *r,
    };
    let body = match read_body(&ctx, req.into_body(), MAX_INGEST_BODY, "events").await {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let r = tokio::task::spawn_blocking(move || {
        let r = handle(&ctx, &id.proxy_id, &body);
        drop(slot);
        r
    })
    .await;
    r.unwrap_or_else(|_| fixed(ErrorCode::StorageUnavailable))
}
