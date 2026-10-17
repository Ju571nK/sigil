//! `POST /v1/proxy-status` (ledger L6b): state snapshot, gap upsert, ACK.
//!
//! Identity is the mTLS peer (the guard has verified it); a body `proxy_id`
//! must equal it, else 404 `proxy_unknown`, evaluated before anything else in
//! the body. Disabled and retired proxies are answered 403 by the guard.
//!
//! The pure part ([`apply`]) decides snapshot, gap and counter outcomes against
//! the stored entry. A gap conflict applies nothing from the report (409,
//! including `last_seen`). A gap that merely does not FIT (count or byte cap)
//! is refused on its own (503 with an item for it): the snapshot, `last_seen`,
//! the counters and the gaps that fit are still stored, and a refused gap is
//! simply not acknowledged, so the proxy resends it.
//!
//! Gap retention (ledger L1): a stored gap is dropped once its `detected_at` is
//! older than E (`event_retention_seconds` of the stored config, the default
//! when there is none). An open `central_outage` is never pruned.
//!
//! Counters (ledger L6): the server keeps the maximum per
//! `(epoch, kind, upstream_id, reason)`; on an epoch change the previous epoch
//! is folded into `previous_epoch_totals` (a total per kind, bounded).

use super::guard::VerifiedProxy;
use super::store::{
    EpochTotals, ProxyEntry, MAX_COUNTER_KEYS, MAX_EPOCHS_SEEN, MAX_GAPS_BYTES_PER_PROXY,
    MAX_GAPS_PER_PROXY,
};
use super::ProxyContext;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use sigil_proxy_api::canonical::canonical_json;
use sigil_proxy_api::{
    parse_status, ApiError, ErrorCode, ErrorItem, GapReport, ProxyStatus, StatusResponse,
    Timestamp, Uuid,
};
use std::sync::Arc;
use time::OffsetDateTime;

pub const STATUS_PATH: &str = "/v1/proxy-status";
/// Request body cap. 100 gaps of 100 event ids and the counter lists fit well
/// below it.
pub const MAX_STATUS_BODY: usize = 1024 * 1024;
const FALLBACK_RETENTION_SECONDS: i64 = sigil_proxy_api::config::DEFAULT_EVENT_RETENTION_SECONDS;

fn gap_id(g: &GapReport) -> &Uuid {
    match g {
        GapReport::RegistryConflict(x) => &x.gap_id,
        GapReport::EventQuarantined(x) => &x.gap_id,
        GapReport::LocalRecordFailed(x) => &x.gap_id,
        GapReport::SpoolExpired(x) => &x.gap_id,
        GapReport::UnrecordedCalls(x) => &x.gap_id,
        GapReport::CentralOutage(x) => &x.gap_id,
    }
}

fn detected_at(g: &GapReport) -> &Timestamp {
    match g {
        GapReport::RegistryConflict(x) => &x.detected_at,
        GapReport::EventQuarantined(x) => &x.detected_at,
        GapReport::LocalRecordFailed(x) => &x.detected_at,
        GapReport::SpoolExpired(x) => &x.detected_at,
        GapReport::UnrecordedCalls(x) => &x.detected_at,
        GapReport::CentralOutage(x) => &x.detected_at,
    }
}

fn parse_ts(t: &Timestamp) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(t.as_str(), &time::format_description::well_known::Rfc3339).ok()
}

fn push_unique(list: &mut Vec<Uuid>, id: &Uuid) {
    if !list.contains(id) {
        list.push(id.clone());
    }
}

fn canon(g: &GapReport) -> Vec<u8> {
    canonical_json(&serde_json::to_value(g).unwrap_or(serde_json::Value::Null))
}

fn gap_bytes(g: &GapReport) -> usize {
    serde_json::to_vec(g).map_or(usize::MAX / 4, |v| v.len())
}

/// What a gap upsert does.
#[derive(Debug, PartialEq, Eq)]
enum GapOutcome {
    Store,
    Duplicate,
    /// `central_outage.ended_at` null to a value, nothing else different.
    CloseOutage,
    Conflict,
}

fn classify_gap(existing: Option<&GapReport>, incoming: &GapReport) -> GapOutcome {
    let Some(old) = existing else {
        return GapOutcome::Store;
    };
    if canon(old) == canon(incoming) {
        return GapOutcome::Duplicate;
    }
    if let (GapReport::CentralOutage(o), GapReport::CentralOutage(n)) = (old, incoming) {
        let same_but_end =
            o.gap_id == n.gap_id && o.detected_at == n.detected_at && o.started_at == n.started_at;
        if same_but_end && o.ended_at.is_none() {
            // The outage may only end at or after its start (an end before the
            // start is a conflict, as is an end that cannot be compared).
            let ends_after_start = match (
                n.ended_at.as_ref().and_then(parse_ts),
                parse_ts(&n.started_at),
            ) {
                (Some(end), Some(start)) => end >= start,
                _ => false,
            };
            if ends_after_start {
                return GapOutcome::CloseOutage;
            }
        }
    }
    GapOutcome::Conflict
}

fn prunable(g: &GapReport, now: OffsetDateTime, retention_secs: i64) -> bool {
    if let GapReport::CentralOutage(o) = g {
        if o.ended_at.is_none() {
            return false;
        }
    }
    parse_ts(detected_at(g)).is_some_and(|t| t + time::Duration::seconds(retention_secs) < now)
}

#[derive(Debug, PartialEq)]
pub enum ApplyError {
    /// 409 `conflict`, with one item per conflicting gap.
    Conflicts(Vec<ErrorItem>),
}

/// Result of an accepted report.
#[derive(Debug)]
pub struct Applied {
    pub entry: ProxyEntry,
    pub response: StatusResponse,
    /// Gaps that did not fit (count or byte cap): answered 503 with these items.
    pub refused: Vec<ErrorItem>,
}

fn counter_key(kind: char, upstream: Option<&sigil_proxy_api::Id>, reason: &str) -> String {
    format!(
        "{kind}\u{1f}{}\u{1f}{reason}",
        upstream.map_or("", |u| u.as_str())
    )
}

fn reason_text<T: serde::Serialize>(r: &T) -> String {
    serde_json::to_value(r)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn merge_counters(entry: &mut ProxyEntry, st: &ProxyStatus, state_applied: bool) {
    let mut dropped = 0usize;
    let epoch = st.epoch_id.as_str().to_string();
    match entry.counters_epoch.clone() {
        None => entry.counters_epoch = Some(epoch),
        Some(cur) if cur == epoch => {}
        Some(cur) if state_applied => {
            // New epoch: keep only a total of the previous one.
            let sum = |kind: char| {
                entry
                    .counter_max
                    .iter()
                    .filter(|(k, _)| k.starts_with(kind))
                    .fold(0i64, |a, (_, v)| a.saturating_add(*v))
            };
            entry.previous_epoch_totals.push(EpochTotals {
                epoch_id: cur,
                auth_failures: sum('a'),
                unmatched_cancels: sum('c'),
            });
            while entry.previous_epoch_totals.len() > MAX_EPOCHS_SEEN {
                entry.previous_epoch_totals.remove(0);
            }
            entry.counter_max.clear();
            entry.counters_epoch = Some(epoch);
        }
        // A replay of an older epoch: its totals were folded already.
        Some(_) => return,
    }
    let items = st
        .counters
        .auth_failures
        .iter()
        .map(|c| {
            (
                counter_key('a', c.upstream_id.as_ref(), &reason_text(&c.reason)),
                c.count.get(),
            )
        })
        .chain(st.counters.unmatched_cancels.iter().map(|c| {
            (
                counter_key('c', c.upstream_id.as_ref(), &reason_text(&c.reason)),
                c.count.get(),
            )
        }));
    for (k, v) in items {
        if let Some(slot) = entry.counter_max.get_mut(&k) {
            *slot = (*slot).max(v);
        } else if entry.counter_max.len() < MAX_COUNTER_KEYS {
            entry.counter_max.insert(k, v);
        } else {
            dropped += 1;
        }
    }
    if dropped > 0 {
        // Counters are aggregates, so a dropped key is a lost count, not a lost
        // event; it is reported rather than silent.
        tracing::warn!(
            dropped,
            limit = MAX_COUNTER_KEYS,
            "proxy status counter keys beyond the per-proxy limit were dropped"
        );
    }
}

/// Applies a validated report to the stored entry. Pure: returns the new entry,
/// the response and the refused gaps, or the reason nothing may be stored.
/// `retention_secs` is E.
pub fn apply(
    cur: &ProxyEntry,
    mut st: ProxyStatus,
    now: OffsetDateTime,
    retention_secs: i64,
) -> Result<Applied, ApplyError> {
    let mut next = cur.clone();
    let now_text = now
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();

    next.gaps.retain(|g| !prunable(g, now, retention_secs));
    let mut bytes: usize = next.gaps.iter().map(gap_bytes).sum();

    // Gaps first: they are independent of the snapshot (a stale epoch or a
    // lower sequence never drops a gap).
    let gaps = std::mem::take(&mut st.gaps);
    let mut conflicts = Vec::new();
    let mut refused = Vec::new();
    let (mut ack, mut dup): (Vec<Uuid>, Vec<Uuid>) = (Vec::new(), Vec::new());
    let item = |index: usize, id: &Uuid, code: ErrorCode| ErrorItem {
        index: u32::try_from(index).unwrap_or(u32::MAX),
        event_id: None,
        gap_id: Some(id.clone()),
        code,
    };
    for (index, incoming) in gaps.into_iter().enumerate() {
        let id = gap_id(&incoming).clone();
        let pos = next.gaps.iter().position(|g| gap_id(g) == &id);
        match classify_gap(pos.map(|i| &next.gaps[i]), &incoming) {
            GapOutcome::Store => {
                let size = gap_bytes(&incoming);
                if next.gaps.len() >= MAX_GAPS_PER_PROXY
                    || bytes.saturating_add(size) > MAX_GAPS_BYTES_PER_PROXY
                {
                    refused.push(item(index, &id, ErrorCode::StorageLimit));
                    continue;
                }
                bytes += size;
                next.gaps.push(incoming);
                push_unique(&mut ack, &id);
            }
            GapOutcome::CloseOutage => {
                if let Some(i) = pos {
                    bytes = bytes - gap_bytes(&next.gaps[i]) + gap_bytes(&incoming);
                    next.gaps[i] = incoming;
                }
                push_unique(&mut ack, &id);
            }
            GapOutcome::Duplicate => {
                if !ack.contains(&id) {
                    push_unique(&mut dup, &id);
                }
            }
            GapOutcome::Conflict => conflicts.push(item(index, &id, ErrorCode::Conflict)),
        }
    }
    if !conflicts.is_empty() {
        return Err(ApplyError::Conflicts(conflicts));
    }

    // Snapshot: new epoch (never applied before) or a higher sequence in the
    // current one.
    let epoch = st.epoch_id.as_str().to_string();
    let state_applied = match &cur.status {
        None => !cur.epochs_seen.contains(&epoch),
        Some(prev) if prev.epoch_id == st.epoch_id => {
            st.status_sequence.get() > prev.status_sequence.get()
        }
        Some(_) => !cur.epochs_seen.contains(&epoch),
    };
    merge_counters(&mut next, &st, state_applied);
    if state_applied {
        if cur
            .status
            .as_ref()
            .is_none_or(|p| p.epoch_id != st.epoch_id)
        {
            next.epochs_seen.retain(|e| e != &epoch);
            next.epochs_seen.push(epoch);
            // 64 epochs is far more than a proxy's restarts within one
            // retention window; it only has to tell a replayed old epoch from
            // a new one, and an epoch that fell off is treated as new.
            while next.epochs_seen.len() > MAX_EPOCHS_SEEN {
                next.epochs_seen.remove(0);
            }
        }
        next.status = Some(st);
    }
    next.last_seen = Some(now_text);
    Ok(Applied {
        entry: next,
        response: StatusResponse {
            state_applied,
            acknowledged_gap_ids: ack,
            duplicate_gap_ids: dup,
        },
        refused,
    })
}

#[derive(Deserialize)]
struct Peek {
    proxy_id: Option<serde_json::Value>,
}

fn json_error(status: StatusCode, e: ApiError) -> Response {
    (
        status,
        Json(serde_json::to_value(e).unwrap_or(serde_json::Value::Null)),
    )
        .into_response()
}

fn fixed(code: ErrorCode, status: StatusCode) -> Response {
    json_error(status, ApiError::from_code(code))
}

/// The report handler's work, in a blocking context (the store fsyncs).
pub fn handle(ctx: &ProxyContext, peer_id: &str, body: &[u8]) -> Response {
    // Identity before anything else in the body (ledger L6b): a body proxy_id
    // that is a string and differs from the peer's is the same 404 as an
    // unknown proxy, whatever else is wrong with the body.
    if let Ok(Peek {
        proxy_id: Some(serde_json::Value::String(bid)),
    }) = serde_json::from_slice::<Peek>(body)
    {
        if bid != peer_id {
            return super::guard::proxy_unknown();
        }
    }
    let st = match parse_status(body) {
        Ok(s) => s,
        Err(e) => {
            // The index of a bad gap is attributable; nothing else is.
            let mut err = ApiError::from_code(ErrorCode::SemanticInvalid);
            if let Some(i) = e.index() {
                err = err.with_items(vec![ErrorItem {
                    index: u32::try_from(i).unwrap_or(u32::MAX),
                    event_id: None,
                    gap_id: None,
                    code: ErrorCode::SemanticInvalid,
                }]);
            }
            return json_error(StatusCode::UNPROCESSABLE_ENTITY, err);
        }
    };
    if st.proxy_id.as_str() != peer_id {
        return super::guard::proxy_unknown();
    }
    let (report_epoch, last_assigned) = (
        st.epoch_id.as_str().to_string(),
        st.last_assigned_sequence.get(),
    );
    let txn = ctx.store.begin();
    let cur = txn.entry(peer_id);
    let retention = cur.config.as_ref().map_or(FALLBACK_RETENTION_SECONDS, |c| {
        c.config.event_retention_seconds
    });
    match apply(&cur, st, OffsetDateTime::now_utc(), retention) {
        Err(ApplyError::Conflicts(items)) => json_error(
            StatusCode::CONFLICT,
            ApiError::from_code(ErrorCode::Conflict).with_items(items),
        ),
        Ok(Applied {
            entry,
            response,
            refused,
        }) => {
            // A failed write means nothing was acknowledged: the proxy keeps
            // its gaps and retries, so this is a retryable 503, not a 500.
            // (`commit` consumes the txn, so the store lock is free below.)
            if let Err(e) = txn.commit(peer_id, entry) {
                tracing::error!(error = %e, "proxy state persist failed (status report)");
                return fixed(
                    ErrorCode::StorageUnavailable,
                    StatusCode::SERVICE_UNAVAILABLE,
                );
            }
            // Only after the status commit, so a ledger failure cannot lose or
            // corrupt the status update, and only for a report that was applied
            // as current (a stale one never opens a tail gap).
            if response.state_applied {
                note_tail(ctx, peer_id, &report_epoch, last_assigned);
            }
            if refused.is_empty() {
                Json(serde_json::to_value(response).unwrap_or(serde_json::Value::Null))
                    .into_response()
            } else {
                json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    ApiError::from_code(ErrorCode::StorageLimit).with_items(refused),
                )
            }
        }
    }
}

/// F13/AC-06: tell the ledger the highest sequence the proxy assigned in the
/// report's epoch, so a tail it never sent shows as a `tail=true` gap. The
/// ledger itself ignores an epoch that is known but not the proxy's latest.
/// The report is already stored, so a ledger error (including `StorageLimit`,
/// the open-gap cap) never fails it: logged without values, the next report
/// retries (the next higher-sequence report; a same-sequence retransmission is
/// not applied and so does not retry).
fn note_tail(ctx: &ProxyContext, peer_id: &str, epoch: &str, last_assigned: i64) {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if let Err(e) = ctx
        .ledger
        .note_last_assigned(peer_id, epoch, last_assigned, now)
    {
        tracing::warn!(error = %e, "proxy tail gap not recorded (status report)");
    }
}

pub async fn post_status(
    State(ctx): State<Arc<ProxyContext>>,
    Extension(id): Extension<VerifiedProxy>,
    body: Bytes,
) -> Response {
    tokio::task::spawn_blocking(move || handle(&ctx, &id.proxy_id, &body))
        .await
        .unwrap_or_else(|_| {
            fixed(
                ErrorCode::parse("internal"),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const E1: &str = "00000000-0000-4000-8000-0000000000e1";
    const E2: &str = "00000000-0000-4000-8000-0000000000e2";
    const NOW: &str = "2026-10-11T01:00:00Z";
    const E_SECS: i64 = 7_776_000;

    fn at(s: &str) -> OffsetDateTime {
        OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).unwrap()
    }

    /// `apply` with E = 90 days; the refused list must be empty.
    fn run(
        cur: &ProxyEntry,
        st: ProxyStatus,
        now: &str,
    ) -> Result<(ProxyEntry, StatusResponse), ApplyError> {
        let a = apply(cur, st, at(now), E_SECS)?;
        assert!(a.refused.is_empty());
        Ok((a.entry, a.response))
    }

    fn uid(n: u32) -> String {
        format!("00000000-0000-4000-8000-{n:012x}")
    }

    fn outage(n: u32, ended: Value) -> Value {
        json!({"kind": "central_outage", "gap_id": uid(n),
            "detected_at": "2026-10-11T00:00:00Z", "started_at": "2026-10-11T00:00:00Z",
            "ended_at": ended})
    }

    fn quarantine(n: u32, code: &str) -> Value {
        json!({"kind": "event_quarantined", "gap_id": uid(n),
            "detected_at": "2026-10-11T00:00:00Z", "event_ids": [uid(900)], "code": code})
    }

    fn report(epoch: &str, seq: i64, gaps: Vec<Value>) -> ProxyStatus {
        let v = json!({
            "schema_version": 1, "report_id": uid(1000 + seq as u32), "proxy_id": "px-1",
            "epoch_id": epoch, "status_sequence": seq, "sent_at": "2026-10-11T00:00:00Z",
            "config": {"state": "none", "applied_revision": null,
                "observed_desired_revision": null, "expires_at": null},
            "spool": {"state": "ok", "depth_events": 0, "unsent_events": 0, "bytes": 0,
                "capacity_bytes": 1000, "oldest_unsent_age_seconds": null,
                "quarantined_events": 0},
            "registry": {"pending_entries": 0, "sync_stalled": false},
            "central": {"last_ingest_ack_at": null, "consecutive_failures": 0},
            "routes": [], "counters": {"auth_failures": [], "unmatched_cancels": []},
            "gaps": gaps, "last_assigned_sequence": 0,
        });
        parse_status(&serde_json::to_vec(&v).unwrap()).unwrap()
    }

    fn ids(v: &[Uuid]) -> Vec<String> {
        v.iter().map(|u| u.as_str().to_string()).collect()
    }

    #[test]
    fn snapshot_rules() {
        let cur = ProxyEntry::default();
        let (e1, r) = run(&cur, report(E1, 5, vec![]), NOW).unwrap();
        assert!(r.state_applied);
        assert_eq!(e1.last_seen.as_deref(), Some(NOW));
        // lower and equal sequence: not applied, last_seen still moves
        let (e2, r) = run(&e1, report(E1, 4, vec![]), "2026-10-11T02:00:00Z").unwrap();
        assert!(!r.state_applied);
        assert_eq!(e2.status.as_ref().unwrap().status_sequence.get(), 5);
        assert_eq!(e2.last_seen.as_deref(), Some("2026-10-11T02:00:00Z"));
        assert!(
            !run(&e1, report(E1, 5, vec![]), NOW)
                .unwrap()
                .1
                .state_applied
        );
        // higher: applied
        let (e3, r) = run(&e2, report(E1, 6, vec![]), NOW).unwrap();
        assert!(r.state_applied);
        // new epoch resets the sequence
        let (e4, r) = run(&e3, report(E2, 1, vec![]), NOW).unwrap();
        assert!(r.state_applied);
        assert_eq!(e4.status.as_ref().unwrap().epoch_id.as_str(), E2);
        // a replay of the old epoch is not new
        let (e5, r) = run(&e4, report(E1, 99, vec![]), NOW).unwrap();
        assert!(!r.state_applied);
        assert_eq!(e5.status.as_ref().unwrap().epoch_id.as_str(), E2);
        // the stored snapshot never carries gaps
        assert!(e4.status.unwrap().gaps.is_empty());
    }

    #[test]
    fn gap_upsert_is_idempotent_and_acked() {
        let g = vec![quarantine(1, "conflict"), outage(2, Value::Null)];
        let (e1, r) = run(&ProxyEntry::default(), report(E1, 1, g.clone()), NOW).unwrap();
        assert_eq!(ids(&r.acknowledged_gap_ids), vec![uid(1), uid(2)]);
        assert!(r.duplicate_gap_ids.is_empty());
        assert_eq!(e1.gaps.len(), 2);
        // resend: duplicates, nothing new stored
        let (e2, r) = run(&e1, report(E1, 2, g.clone()), NOW).unwrap();
        assert!(r.acknowledged_gap_ids.is_empty());
        assert_eq!(ids(&r.duplicate_gap_ids), vec![uid(1), uid(2)]);
        assert_eq!(e2.gaps, e1.gaps);
        // a stale epoch never drops a gap
        let (e3, r) = run(&e2, report(E1, 1, vec![quarantine(3, "conflict")]), NOW).unwrap();
        assert!(!r.state_applied);
        assert_eq!(ids(&r.acknowledged_gap_ids), vec![uid(3)]);
        assert_eq!(e3.gaps.len(), 3);
    }

    #[test]
    fn outage_may_only_close() {
        let open = vec![outage(2, Value::Null)];
        let (e1, _) = run(&ProxyEntry::default(), report(E1, 1, open), NOW).unwrap();
        // null -> value: updated and acked
        let closed = vec![outage(2, json!("2026-10-11T00:30:00Z"))];
        let (e2, r) = run(&e1, report(E1, 2, closed.clone()), NOW).unwrap();
        assert_eq!(ids(&r.acknowledged_gap_ids), vec![uid(2)]);
        match &e2.gaps[0] {
            GapReport::CentralOutage(o) => assert!(o.ended_at.is_some()),
            _ => panic!("kind changed"),
        }
        // resending the closed one is a duplicate
        let (_, r) = run(&e2, report(E1, 3, closed), NOW).unwrap();
        assert_eq!(ids(&r.duplicate_gap_ids), vec![uid(2)]);
        // closed -> another value, closed -> null: conflict
        for v in [json!("2026-10-11T00:31:00Z"), Value::Null] {
            let err = run(&e2, report(E1, 4, vec![outage(2, v)]), NOW).unwrap_err();
            let ApplyError::Conflicts(items) = err;
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].index, 0);
            assert_eq!(items[0].gap_id.as_ref().unwrap().as_str(), uid(2));
            assert_eq!(items[0].code, ErrorCode::Conflict);
        }
        // an open outage with a different start is not a close
        let mut other = outage(2, json!("2026-10-11T00:30:00Z"));
        other["started_at"] = json!("2026-10-11T00:00:01Z");
        assert!(run(&e1, report(E1, 2, vec![other]), NOW).is_err());
    }

    #[test]
    fn any_other_difference_conflicts_and_applies_nothing() {
        let (e1, _) = run(
            &ProxyEntry::default(),
            report(E1, 1, vec![quarantine(1, "conflict")]),
            NOW,
        )
        .unwrap();
        // same id, different content; a good new gap rides along at index 1
        let err = run(
            &e1,
            report(
                E1,
                2,
                vec![quarantine(1, "semantic_invalid"), quarantine(9, "conflict")],
            ),
            "2026-10-11T02:00:00Z",
        )
        .unwrap_err();
        let ApplyError::Conflicts(items) = err;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].index, 0);
        // same id, different kind
        let err = run(&e1, report(E1, 2, vec![outage(1, Value::Null)]), NOW).unwrap_err();
        assert!(matches!(err, ApplyError::Conflicts(_)));
        // two conflicts are both listed with their indexes
        let (e2, _) = run(&e1, report(E1, 2, vec![quarantine(2, "conflict")]), NOW).unwrap();
        let err = run(
            &e2,
            report(
                E1,
                3,
                vec![
                    quarantine(1, "sequence_conflict"),
                    quarantine(2, "semantic_invalid"),
                ],
            ),
            NOW,
        )
        .unwrap_err();
        let ApplyError::Conflicts(items) = err;
        assert_eq!(
            items.iter().map(|i| i.index).collect::<Vec<_>>(),
            vec![0, 1]
        );
    }

    #[test]
    fn same_gap_twice_in_one_report() {
        let g = quarantine(1, "conflict");
        let (e, r) = run(
            &ProxyEntry::default(),
            report(E1, 1, vec![g.clone(), g.clone()]),
            NOW,
        )
        .unwrap();
        assert_eq!(e.gaps.len(), 1);
        assert_eq!(ids(&r.acknowledged_gap_ids), vec![uid(1)]);
        assert!(r.duplicate_gap_ids.is_empty(), "no id in both lists");
        r.validate_lists();
        let bad = run(
            &ProxyEntry::default(),
            report(E1, 1, vec![g, quarantine(1, "semantic_invalid")]),
            NOW,
        );
        assert!(matches!(bad, Err(ApplyError::Conflicts(_))));
    }

    #[test]
    fn full_gap_store_refuses_only_the_new_gaps_and_still_applies_the_snapshot() {
        let mut cur = ProxyEntry::default();
        for n in 0..MAX_GAPS_PER_PROXY as u32 {
            cur.gaps
                .push(serde_json::from_value(quarantine(10_000 + n, "conflict")).unwrap());
        }
        let a = apply(
            &cur,
            report(
                E1,
                1,
                vec![quarantine(1, "conflict"), quarantine(10_000, "conflict")],
            ),
            at(NOW),
            E_SECS,
        )
        .unwrap();
        // the new gap is refused with its own item, the known one is a duplicate
        assert_eq!(a.refused.len(), 1);
        assert_eq!(a.refused[0].index, 0);
        assert_eq!(a.refused[0].gap_id.as_ref().unwrap().as_str(), uid(1));
        assert_eq!(a.refused[0].code, ErrorCode::StorageLimit);
        assert!(a.response.acknowledged_gap_ids.is_empty());
        assert_eq!(ids(&a.response.duplicate_gap_ids), vec![uid(10_000)]);
        assert_eq!(a.entry.gaps.len(), MAX_GAPS_PER_PROXY);
        // snapshot and last_seen still applied
        assert!(a.response.state_applied);
        assert_eq!(a.entry.last_seen.as_deref(), Some(NOW));
    }

    #[test]
    fn gap_bytes_are_capped_too() {
        let big = |n: u32| {
            let ids: Vec<String> = (0..100).map(|i| uid(100_000 + n * 100 + i)).collect();
            serde_json::json!({"kind": "event_quarantined", "gap_id": uid(20_000 + n),
                "detected_at": "2026-10-11T00:00:00Z", "event_ids": ids, "code": "conflict"})
        };
        let mut cur = ProxyEntry::default();
        let mut n = 0;
        let mut bytes = 0;
        while bytes + 5000 < MAX_GAPS_BYTES_PER_PROXY {
            let g: GapReport = serde_json::from_value(big(n)).unwrap();
            bytes += gap_bytes(&g);
            cur.gaps.push(g);
            n += 1;
        }
        assert!(
            cur.gaps.len() < MAX_GAPS_PER_PROXY,
            "bytes bind before count"
        );
        let a = apply(
            &cur,
            report(E1, 1, vec![big(n), big(n + 1), big(n + 2)]),
            at(NOW),
            E_SECS,
        )
        .unwrap();
        assert!(!a.refused.is_empty());
        assert!(a.entry.gaps.iter().map(gap_bytes).sum::<usize>() <= MAX_GAPS_BYTES_PER_PROXY);
        assert!(a.response.state_applied);
    }

    #[test]
    fn closed_and_point_gaps_older_than_e_are_pruned_open_outages_are_not() {
        let mut cur = ProxyEntry::default();
        for g in [
            quarantine(1, "conflict"),
            outage(2, "2026-10-11T00:30:00Z".into()),
            outage(3, Value::Null),
        ] {
            cur.gaps.push(serde_json::from_value(g).unwrap());
        }
        // just inside E: all kept
        let inside = "2027-01-08T00:00:00Z"; // 89 days after detected_at
        let a = apply(&cur, report(E1, 1, vec![]), at(inside), E_SECS).unwrap();
        assert_eq!(a.entry.gaps.len(), 3);
        // past E: the quarantine and the closed outage go, the open outage stays
        let past = "2027-01-11T00:00:00Z"; // 92 days
        let a = apply(&cur, report(E1, 1, vec![]), at(past), E_SECS).unwrap();
        assert_eq!(a.entry.gaps.len(), 1);
        match &a.entry.gaps[0] {
            GapReport::CentralOutage(o) => assert!(o.ended_at.is_none()),
            _ => panic!(),
        }
    }

    #[test]
    fn outage_end_before_start_is_a_conflict() {
        let (e1, _) = run(
            &ProxyEntry::default(),
            report(E1, 1, vec![outage(2, Value::Null)]),
            NOW,
        )
        .unwrap();
        let err = run(
            &e1,
            report(E1, 2, vec![outage(2, "2026-10-10T23:59:59Z".into())]),
            NOW,
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::Conflicts(_)));
        // equal to the start is allowed
        assert!(run(
            &e1,
            report(E1, 2, vec![outage(2, "2026-10-11T00:00:00Z".into())]),
            NOW
        )
        .is_ok());
    }

    fn counters_report(epoch: &str, seq: i64, auth: i64, cancels: i64) -> ProxyStatus {
        let mut st = report(epoch, seq, vec![]);
        st.counters = serde_json::from_value(serde_json::json!({
            "auth_failures": [
                {"upstream_id": "up-1", "reason": "credential_invalid", "count": auth},
                {"upstream_id": null, "reason": "origin_rejected", "count": 1}],
            "unmatched_cancels": [
                {"upstream_id": "up-1", "reason": "window_expired", "count": cancels}],
        }))
        .unwrap();
        st
    }

    #[test]
    fn counters_keep_the_maximum_and_fold_into_previous_epoch_totals() {
        let (e1, _) = run(&ProxyEntry::default(), counters_report(E1, 1, 5, 2), NOW).unwrap();
        // a later report with LOWER counts (reordered/lost heartbeat) loses nothing
        let (e2, _) = run(&e1, counters_report(E1, 2, 3, 1), NOW).unwrap();
        // even a stale-sequence report merges by max
        let (e3, _) = run(&e2, counters_report(E1, 1, 9, 2), NOW).unwrap();
        assert_eq!(e3.counter_max.values().copied().max(), Some(9));
        let sum = |e: &ProxyEntry, k: char| -> i64 {
            e.counter_max
                .iter()
                .filter(|(n, _)| n.starts_with(k))
                .map(|(_, v)| *v)
                .sum()
        };
        assert_eq!((sum(&e3, 'a'), sum(&e3, 'c')), (10, 2)); // 9 + 1, and 2
        assert!(e3.previous_epoch_totals.is_empty());
        // epoch change: previous totals are kept, the new epoch starts fresh
        let (e4, r) = run(&e3, counters_report(E2, 1, 4, 0), NOW).unwrap();
        assert!(r.state_applied);
        assert_eq!(
            e4.previous_epoch_totals,
            vec![EpochTotals {
                epoch_id: E1.into(),
                auth_failures: 10,
                unmatched_cancels: 2
            }]
        );
        assert_eq!((sum(&e4, 'a'), sum(&e4, 'c')), (5, 0));
        assert_eq!(e4.counters_epoch.as_deref(), Some(E2));
        // a replay of the old epoch changes neither
        let (e5, r) = run(&e4, counters_report(E1, 50, 999, 999), NOW).unwrap();
        assert!(!r.state_applied);
        assert_eq!(e5.counter_max, e4.counter_max);
        assert_eq!(e5.previous_epoch_totals, e4.previous_epoch_totals);
        // bounded
        let mut cur = e5;
        for i in 0..(MAX_EPOCHS_SEEN as u32 + 5) {
            let ep = format!("00000000-0000-4000-8000-{:012x}", 0xf000 + i);
            cur = run(&cur, counters_report(&ep, 1, 1, 1), NOW).unwrap().0;
        }
        assert_eq!(cur.previous_epoch_totals.len(), MAX_EPOCHS_SEEN);
    }

    trait Lists {
        fn validate_lists(&self);
    }
    impl Lists for StatusResponse {
        fn validate_lists(&self) {
            assert!(sigil_proxy_api::Validate::validate(self).is_ok());
        }
    }
}
