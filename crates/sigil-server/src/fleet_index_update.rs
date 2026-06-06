//! Per-evidence-variant update mapping. Spec §3.3 table. Pure function so it
//! can be exercised by unit tests without spinning up a FleetIndex.

use crate::fleet_index::HostSummary;
use sigil_core::event::{AiGuardBucket, Event, Evidence, Severity};

/// True if this evidence matches `/v1/meta.alerts_definition_default` (issue #21):
/// AiGuardRiskAssessed in {high, critical} + the additional alert kinds.
/// MUST stay in sync with the JSON in `routes/meta.rs::get_meta`.
fn is_alert_evidence(ev: &Evidence) -> bool {
    matches!(
        ev,
        Evidence::AiGuardRiskAssessed {
            bucket: AiGuardBucket::High | AiGuardBucket::Critical,
            ..
        } | Evidence::PolicySignatureInvalid { .. }
            | Evidence::TlsFailure { .. }
            | Evidence::HostIdFingerprintDrift { .. }
            | Evidence::AgentDying { .. }
            | Evidence::SenderLagCritical { .. }
    )
}

/// Apply one event to a HostSummary. Caller (FleetIndex in Task 5 / boot_rebuild
/// in Task 6) holds the write lock and the `host_id`-keyed entry.
pub fn apply_event(host: &mut HostSummary, event: &Event) {
    // Identity bookkeeping — every variant updates these.
    host.agent_version = event.agent_version.clone();
    if host.last_seen_ts.map_or(true, |t| event.ts > t) {
        host.last_seen_ts = Some(event.ts);
    }
    let cur_hour = event.ts.unix_timestamp() / 3600;
    host.counts_24h.advance_to(cur_hour);
    let slot = host.counts_24h.slot_for(cur_hour);

    // Generic severity bucket (info/warn) is incremented for every event;
    // specific-evidence buckets get additional increments below where applicable.
    if let Some(s) = slot {
        match event.severity {
            Severity::Info => host.counts_24h.info[s] = host.counts_24h.info[s].saturating_add(1),
            Severity::Warn => host.counts_24h.warn[s] = host.counts_24h.warn[s].saturating_add(1),
        }
        if is_alert_evidence(&event.evidence) {
            host.counts_24h.alerts[s] = host.counts_24h.alerts[s].saturating_add(1);
        }
    }

    // Variant-specific updates.
    match &event.evidence {
        Evidence::HostMetaSnapshot { snapshot, .. } => {
            host.latest_host_meta = Some(snapshot.clone());
        }
        Evidence::AiGuardRiskAssessed {
            tool,
            scope,
            score,
            bucket,
            reasons,
            is_reattestation,
            ..
        } => {
            host.current_risk.insert(
                *tool,
                crate::fleet_index::RiskEntry {
                    score: *score,
                    bucket: *bucket,
                    assessed_ts: event.ts,
                    is_reattestation: *is_reattestation,
                    scope: scope.clone(),
                    reasons: reasons.clone(),
                },
            );
        }
        Evidence::Heartbeat {
            hash_p99_ms,
            jsonl_above_soft_floor,
            last_applied_policy_version,
            policy_expired_active,
            ..
        } => {
            host.agent_health.last_heartbeat_ts = Some(event.ts);
            host.agent_health.hash_p99_ms_latest = Some(*hash_p99_ms);
            host.agent_health.jsonl_above_soft_floor_latest = Some(*jsonl_above_soft_floor);
            // Heartbeat carries the agent's current policy view as a sticky
            // backup signal. PolicyReloaded / PolicyExpiredActive are the
            // discrete authoritative sources, but the heartbeat snapshot is
            // useful after agent restart when no fresh discrete event fires.
            if *last_applied_policy_version > host.policy_state.last_applied_policy_version {
                host.policy_state.last_applied_policy_version = *last_applied_policy_version;
            }
            host.policy_state.policy_expired_active = *policy_expired_active;
        }
        Evidence::PolicyReloaded { policy_version } => {
            host.policy_state.last_applied_policy_version = *policy_version;
            host.policy_state.last_policy_reload_ts = Some(event.ts);
            host.policy_state.policy_expired_active = false;
        }
        Evidence::PolicyExpiredActive { .. } => {
            host.policy_state.policy_expired_active = true;
        }
        Evidence::PolicySignatureInvalid { .. } => {
            if let Some(s) = slot {
                host.counts_24h.sig_failures[s] = host.counts_24h.sig_failures[s].saturating_add(1);
            }
        }
        Evidence::SenderLagCritical { .. } => {
            if let Some(s) = slot {
                host.counts_24h.sender_lag_critical[s] =
                    host.counts_24h.sender_lag_critical[s].saturating_add(1);
            }
        }
        Evidence::WatcherDegraded { .. } => {
            if let Some(s) = slot {
                host.counts_24h.watcher_degraded[s] =
                    host.counts_24h.watcher_degraded[s].saturating_add(1);
            }
        }
        Evidence::ChannelStall { .. } => {
            if let Some(s) = slot {
                host.counts_24h.channel_stalls[s] =
                    host.counts_24h.channel_stalls[s].saturating_add(1);
            }
        }
        // All other variants: identity + severity-bucket increment above is the
        // entire update. Listed explicitly so future variant additions raise
        // a non-exhaustive match warning until decided where to map them.
        Evidence::FileChange { .. }
        | Evidence::PermissionMissing { .. }
        | Evidence::AgentDying { .. }
        | Evidence::RateLimitExceeded { .. }
        | Evidence::HostIdFingerprintDrift { .. }
        | Evidence::AgentJsonlForceGc { .. }
        | Evidence::SenderSkippedSegment { .. }
        | Evidence::HostIdConflict { .. }
        | Evidence::AgentTooOld { .. }
        | Evidence::CertExpired { .. }
        | Evidence::TlsFailure { .. }
        | Evidence::EventUnprocessableLocal { .. }
        | Evidence::ServerProtocolViolation { .. }
        | Evidence::RulePackBundleApplied { .. } => { /* identity + severity only */ }
        Evidence::HookInvocation(_)
        | Evidence::HookDecision(_)
        | Evidence::HookConfigDrift(_)
        | Evidence::PossibleHookActivitySilent(_)
        | Evidence::Unknown => {
            // Hook observe/decision/drift events are not indexed into the fleet rollup
            // (slice 1); the severity-bucket increment above already counts them.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::event::{
        AgentDyingReason, AiGuardBucket, AiGuardScope, AiTool, Event, Evidence, HostMetaSnapshot,
        PolicySignatureInvalidReason, Severity, SourceKind, Subject, SCHEMA_VERSION,
    };
    use std::collections::BTreeMap;
    use time::macros::datetime;
    use uuid::Uuid;

    /// Drift guard (issue #52): every kind in `/v1/meta.alerts_definition_default`
    /// must be recognized by `is_alert_evidence`, and a sampling of non-alert warns
    /// must not be. Reads the live meta definition so changing one side without the
    /// other fails here.
    #[test]
    fn is_alert_evidence_matches_meta_alerts_definition() {
        use crate::routes::meta::alerts_definition_default;

        fn ai_guard(bucket: AiGuardBucket) -> Evidence {
            Evidence::AiGuardRiskAssessed {
                tool: AiTool::ClaudeCode,
                scope: AiGuardScope::UserGlobal,
                score: 5.0,
                bucket,
                reasons: vec![],
                is_reattestation: false,
                rule_pack_id: None,
                tool_label: None,
            }
        }

        let def = alerts_definition_default();

        for k in def["additional_kinds"].as_array().unwrap() {
            let kind = k.as_str().unwrap();
            let ev = match kind {
                "policy_signature_invalid" => Evidence::PolicySignatureInvalid {
                    reason: PolicySignatureInvalidReason::SignatureInvalid,
                    signing_pubkey_id: "k".into(),
                    policy_version_in_envelope: 1,
                    last_applied_policy_version: 0,
                },
                "tls_failure" => Evidence::TlsFailure { reason: "x".into() },
                "host_id_fingerprint_drift" => Evidence::HostIdFingerprintDrift {
                    prev_fingerprint: "a".into(),
                    new_fingerprint: "b".into(),
                },
                "agent_dying" => Evidence::AgentDying {
                    reason: AgentDyingReason::Panic,
                    detail: "d".into(),
                    task: None,
                },
                "sender_lag_critical" => Evidence::SenderLagCritical {
                    lag_events: 1,
                    lag_bytes: 1,
                    oldest_unsent_age_s: 1,
                },
                other => panic!(
                    "meta additional_kinds lists `{other}` but this test has no Evidence \
                     mapping — add it AND ensure is_alert_evidence covers it"
                ),
            };
            assert!(
                is_alert_evidence(&ev),
                "`{kind}` is in alerts_definition_default but is_alert_evidence returned false"
            );
        }

        for b in def["ai_guard_buckets"].as_array().unwrap() {
            let bucket = match b.as_str().unwrap() {
                "high" => AiGuardBucket::High,
                "critical" => AiGuardBucket::Critical,
                other => panic!("unexpected ai_guard_bucket `{other}` in meta"),
            };
            assert!(
                is_alert_evidence(&ai_guard(bucket)),
                "AiGuard {b} should be an alert"
            );
        }
        // Low/Medium AI Guard and a non-listed warn must NOT count as alerts.
        assert!(!is_alert_evidence(&ai_guard(AiGuardBucket::Low)));
        assert!(!is_alert_evidence(&ai_guard(AiGuardBucket::Medium)));
        assert!(!is_alert_evidence(&Evidence::WatcherDegraded {
            from: "fsevents".into(),
            to: "poll".into(),
            reason: "r".into(),
        }));
    }

    fn ev(evidence: Evidence, sev: Severity, ts: time::OffsetDateTime) -> Event {
        Event {
            schema_version: SCHEMA_VERSION,
            event_id: Uuid::now_v7(),
            ts,
            host_id: "h".into(),
            agent_version: "0.5.0".into(),
            severity: sev,
            source: SourceKind::Agent,
            subject: Subject::Self_,
            evidence,
            target_id: None,
        }
    }

    fn heartbeat(
        hash_p99_ms: u32,
        jsonl_above_soft_floor: bool,
        last_applied_policy_version: i64,
        policy_expired_active: bool,
    ) -> Evidence {
        Evidence::Heartbeat {
            uptime_s: 60,
            is_final: false,
            channel_stall_events_total: 0,
            events_emitted_total: 100,
            events_by_kind: BTreeMap::new(),
            hash_p50_ms: 1,
            hash_p99_ms,
            watcher_backend: "fsevents".into(),
            state_db_size_bytes: 4096,
            last_log_rotation_ts: None,
            last_applied_policy_version,
            policy_expired_active,
            jsonl_above_soft_floor,
        }
    }

    #[test]
    fn host_meta_snapshot_populates_latest_meta() {
        let mut h = HostSummary::new("h".into());
        let snap = HostMetaSnapshot {
            hostname: Some("alice".into()),
            os_name: None,
            os_version: None,
            kernel_version: None,
            architecture: None,
            interfaces: vec![],
            default_gateway_v4: None,
            default_gateway_v6: None,
            dns_servers: vec![],
        };
        let e = ev(
            Evidence::HostMetaSnapshot {
                snapshot: snap.clone(),
                is_reattestation: false,
            },
            Severity::Info,
            datetime!(2026-05-17 12:00 UTC),
        );
        apply_event(&mut h, &e);
        assert_eq!(
            h.latest_host_meta.as_ref().unwrap().hostname.as_deref(),
            Some("alice")
        );
    }

    #[test]
    fn ai_guard_risk_inserts_per_tool_latest() {
        let mut h = HostSummary::new("h".into());
        let e = ev(
            Evidence::AiGuardRiskAssessed {
                tool: AiTool::ClaudeCode,
                scope: AiGuardScope::UserGlobal,
                score: 7.2,
                bucket: AiGuardBucket::Critical,
                reasons: vec![],
                is_reattestation: false,
                rule_pack_id: None,
                tool_label: None,
            },
            Severity::Warn,
            datetime!(2026-05-17 12:00 UTC),
        );
        apply_event(&mut h, &e);
        let entry = h.current_risk.get(&AiTool::ClaudeCode).unwrap();
        assert_eq!(entry.score, 7.2);
        assert_eq!(entry.bucket, AiGuardBucket::Critical);
    }

    #[test]
    fn policy_reloaded_updates_version_and_clears_expired() {
        let mut h = HostSummary::new("h".into());
        h.policy_state.policy_expired_active = true;
        let e = ev(
            Evidence::PolicyReloaded { policy_version: 17 },
            Severity::Info,
            datetime!(2026-05-17 12:00 UTC),
        );
        apply_event(&mut h, &e);
        assert_eq!(h.policy_state.last_applied_policy_version, 17);
        assert!(!h.policy_state.policy_expired_active);
        assert_eq!(
            h.policy_state.last_policy_reload_ts,
            Some(datetime!(2026-05-17 12:00 UTC))
        );
    }

    #[test]
    fn policy_expired_active_sets_flag() {
        let mut h = HostSummary::new("h".into());
        let e = ev(
            Evidence::PolicyExpiredActive {
                policy_version: 17,
                valid_until: datetime!(2026-05-10 0:00 UTC),
            },
            Severity::Warn,
            datetime!(2026-05-17 12:00 UTC),
        );
        apply_event(&mut h, &e);
        assert!(h.policy_state.policy_expired_active);
    }

    #[test]
    fn policy_signature_invalid_increments_counter() {
        let mut h = HostSummary::new("h".into());
        let e = ev(
            Evidence::PolicySignatureInvalid {
                reason: PolicySignatureInvalidReason::SignatureInvalid,
                signing_pubkey_id: "k1".into(),
                policy_version_in_envelope: 17,
                last_applied_policy_version: 16,
            },
            Severity::Warn,
            datetime!(2026-05-17 12:00 UTC),
        );
        apply_event(&mut h, &e);
        assert_eq!(h.counts_24h.sum_sig_failures(), 1);
    }

    #[test]
    fn heartbeat_updates_health_block_and_policy_backup() {
        let mut h = HostSummary::new("h".into());
        let e = ev(
            heartbeat(12, false, 17, false),
            Severity::Info,
            datetime!(2026-05-17 12:00 UTC),
        );
        apply_event(&mut h, &e);
        assert_eq!(h.agent_health.hash_p99_ms_latest, Some(12));
        assert_eq!(h.agent_health.jsonl_above_soft_floor_latest, Some(false));
        assert_eq!(
            h.agent_health.last_heartbeat_ts,
            Some(datetime!(2026-05-17 12:00 UTC))
        );
        // Heartbeat's policy-version backup signal also populated the index.
        assert_eq!(h.policy_state.last_applied_policy_version, 17);
        assert!(!h.policy_state.policy_expired_active);
    }

    #[test]
    fn identity_fields_track_latest() {
        let mut h = HostSummary::new("h".into());
        let t1 = datetime!(2026-05-17 12:00 UTC);
        let t2 = datetime!(2026-05-17 13:00 UTC);
        apply_event(
            &mut h,
            &ev(heartbeat(1, false, 0, false), Severity::Info, t1),
        );
        apply_event(
            &mut h,
            &ev(heartbeat(1, false, 0, false), Severity::Info, t2),
        );
        assert_eq!(h.last_seen_ts, Some(t2));
    }

    #[test]
    fn old_event_skipped_for_counts_but_keeps_identity() {
        let mut h = HostSummary::new("h".into());
        let recent = datetime!(2026-05-17 12:00 UTC);
        let ancient = datetime!(2026-05-15 12:00 UTC); // 2 days old (out of 24h window)
        apply_event(
            &mut h,
            &ev(heartbeat(1, false, 0, false), Severity::Info, recent),
        );
        apply_event(
            &mut h,
            &ev(heartbeat(1, false, 0, false), Severity::Info, ancient),
        );
        // Recent counted, ancient skipped.
        assert_eq!(h.counts_24h.sum_info(), 1);
        // last_seen_ts stays at recent (we used max()).
        assert_eq!(h.last_seen_ts, Some(recent));
    }

    #[test]
    fn alerts_bucket_counts_only_alert_definition_events() {
        let mut h = HostSummary::new("h".into());
        let t = datetime!(2026-05-17 12:00 UTC);
        apply_event(
            &mut h,
            &ev(
                Evidence::AiGuardRiskAssessed {
                    tool: AiTool::ClaudeCode,
                    scope: AiGuardScope::UserGlobal,
                    score: 8.0,
                    bucket: AiGuardBucket::High,
                    reasons: vec![],
                    is_reattestation: false,
                    rule_pack_id: None,
                    tool_label: None,
                },
                Severity::Warn,
                t,
            ),
        );
        apply_event(
            &mut h,
            &ev(
                Evidence::TlsFailure {
                    reason: "ca".into(),
                },
                Severity::Warn,
                t,
            ),
        );
        apply_event(
            &mut h,
            &ev(
                Evidence::SenderLagCritical {
                    lag_events: 1,
                    lag_bytes: 1,
                    oldest_unsent_age_s: 1,
                },
                Severity::Warn,
                t,
            ),
        );
        apply_event(
            &mut h,
            &ev(
                Evidence::PolicySignatureInvalid {
                    reason: PolicySignatureInvalidReason::SignatureInvalid,
                    signing_pubkey_id: "k1".into(),
                    policy_version_in_envelope: 17,
                    last_applied_policy_version: 16,
                },
                Severity::Warn,
                t,
            ),
        );
        apply_event(
            &mut h,
            &ev(
                Evidence::WatcherDegraded {
                    from: "fsevents".into(),
                    to: "poll".into(),
                    reason: "x".into(),
                },
                Severity::Warn,
                t,
            ),
        );
        assert_eq!(
            h.counts_24h.sum_alerts(),
            4,
            "AiGuard High + TlsFailure + SenderLagCritical + PolicySignatureInvalid"
        );
        assert_eq!(h.counts_24h.sum_warn(), 5, "all five are warn-severity");
    }

    #[test]
    fn ai_guard_low_medium_are_not_alerts() {
        let mut h = HostSummary::new("h".into());
        let t = datetime!(2026-05-17 12:00 UTC);
        apply_event(
            &mut h,
            &ev(
                Evidence::AiGuardRiskAssessed {
                    tool: AiTool::ClaudeCode,
                    scope: AiGuardScope::UserGlobal,
                    score: 2.0,
                    bucket: AiGuardBucket::Medium,
                    reasons: vec![],
                    is_reattestation: false,
                    rule_pack_id: None,
                    tool_label: None,
                },
                Severity::Warn,
                t,
            ),
        );
        assert_eq!(h.counts_24h.sum_alerts(), 0);
        assert_eq!(h.counts_24h.sum_warn(), 1);
    }
}
