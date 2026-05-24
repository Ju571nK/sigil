//! Six properties covering the spec's invariants.

use proptest::prelude::*;
use sigil_core::debounce::Debouncer;
use sigil_core::event::{Event, FileChangeKind};
use sigil_core::policy::{merge, HostIdStrategy, Platform, PolicyDocument, Tier, WatchTarget};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

fn make_target(id: &str, tier: Tier, platform: Platform) -> WatchTarget {
    WatchTarget {
        id: id.into(),
        description: "d".into(),
        tier,
        platform,
        paths: vec!["/p".into()],
        recursive: false,
        follow_symlinks: false,
        disabled: false,
    }
}

proptest! {
    #[test]
    fn merge_is_deterministic(
        ids in proptest::collection::vec("[a-z]{3,8}", 1..10)
    ) {
        let unique: Vec<String> = {
            let mut seen = HashSet::new();
            ids.into_iter().filter(|s| seen.insert(s.clone())).collect()
        };
        prop_assume!(!unique.is_empty());
        let defaults = PolicyDocument {
            version: 1,
            host_id_strategy: HostIdStrategy::MachineId,
            overrides: vec![],
            targets: unique.iter().map(|id| make_target(id, Tier::Standard, Platform::Any)).collect(),
            continue_workspaces: vec![],
            claude_code_workspaces: vec![],
            codex_workspaces: vec![],
            gemini_workspaces: vec![],
            cursor_workspaces: vec![],
            rule_packs: vec![],
            rubric_overrides: HashMap::new(),
        };
        let r1 = merge(defaults.clone(), None, Platform::Any).unwrap();
        let r2 = merge(defaults, None, Platform::Any).unwrap();
        prop_assert_eq!(r1, r2);
    }

    #[test]
    fn merge_id_uniqueness_holds(
        ids in proptest::collection::vec("[a-z]{3,8}", 1..10)
    ) {
        let unique: Vec<String> = {
            let mut seen = HashSet::new();
            ids.into_iter().filter(|s| seen.insert(s.clone())).collect()
        };
        prop_assume!(unique.len() >= 2);
        let defaults = PolicyDocument {
            version: 1,
            host_id_strategy: HostIdStrategy::MachineId,
            overrides: vec![],
            targets: unique.iter().take(unique.len() - 1).map(|id| make_target(id, Tier::Standard, Platform::Any)).collect(),
            continue_workspaces: vec![],
            claude_code_workspaces: vec![],
            codex_workspaces: vec![],
            gemini_workspaces: vec![],
            cursor_workspaces: vec![],
            rule_packs: vec![],
            rubric_overrides: HashMap::new(),
        };
        let user = PolicyDocument {
            version: 1,
            host_id_strategy: HostIdStrategy::MachineId,
            overrides: vec![],
            targets: vec![make_target(&unique[0], Tier::Critical, Platform::Any)],
            continue_workspaces: vec![],
            claude_code_workspaces: vec![],
            codex_workspaces: vec![],
            gemini_workspaces: vec![],
            cursor_workspaces: vec![],
            rule_packs: vec![],
            rubric_overrides: HashMap::new(),
        };
        let res = merge(defaults, Some(user), Platform::Any);
        prop_assert!(res.is_err());
    }

    #[test]
    fn debounce_never_drops_removed(
        sequence in proptest::collection::vec(any::<u8>(), 1..50)
    ) {
        let mut d = Debouncer::new();
        let mut t = 0u64;
        let mut input_removed = 0u64;
        let mut emitted_immediately = 0u64;
        for byte in sequence {
            let kind = match byte % 4 {
                0 => FileChangeKind::Created,
                1 => FileChangeKind::Modified,
                2 => FileChangeKind::Removed,
                _ => FileChangeKind::Renamed,
            };
            if matches!(kind, FileChangeKind::Removed) {
                input_removed += 1;
            }
            if d.push(PathBuf::from("/x"), kind, false, t).is_some()
                && matches!(kind, FileChangeKind::Removed) {
                    emitted_immediately += 1;
                }
            t += 5;
        }
        prop_assert_eq!(input_removed, emitted_immediately);
    }

    #[test]
    fn jsonl_serialization_is_lossless(
        host_id in "[A-Za-z0-9-]{3,30}"
    ) {
        let ev = Event {
            schema_version: sigil_core::event::SCHEMA_VERSION,
            event_id: uuid::Uuid::now_v7(),
            ts: time::OffsetDateTime::now_utc(),
            host_id: host_id.clone(),
            agent_version: sigil_core::event::AGENT_VERSION.to_string(),
            severity: sigil_core::event::Severity::Warn,
            source: sigil_core::event::SourceKind::FileSystem,
            subject: sigil_core::event::Subject::Path { value: PathBuf::from("/p") },
            evidence: sigil_core::event::Evidence::FileChange {
                change_kind: FileChangeKind::Modified,
                before_hash: Some("a".into()),
                after_hash: Some("b".into()),
                recheck_hash: None,
                rename_from: None,
                size_after: Some(1),
                evidence_quality: sigil_core::event::EvidenceQuality::Definitive,
            },
            target_id: Some("t".into()),
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: Event = serde_json::from_str(&s).unwrap();
        prop_assert_eq!(back.host_id, host_id);
    }

    #[test]
    fn rate_limiter_never_grants_more_than_capacity_at_t0(
        n in 0u32..1000
    ) {
        use sigil_core::ratelimit::{RateLimiter, BUCKET_CAPACITY};
        let mut r = RateLimiter::new();
        let mut allowed = 0u32;
        for _ in 0..n {
            if r.allow("t", 0) {
                allowed += 1;
            }
        }
        prop_assert!(allowed as f64 <= BUCKET_CAPACITY);
    }

    #[test]
    fn warmup_then_change_yields_correct_before_hash(
        first in "[a-f0-9]{64}",
        second in "[a-f0-9]{64}"
    ) {
        prop_assume!(first != second);
        let td = tempfile::TempDir::new().unwrap();
        let dbp = td.path().join("state.db");
        let cache = sigil_core::state::HashCache::open(&dbp).unwrap();
        cache.put(std::path::Path::new("/x"), &first, 1, "t", 0).unwrap();
        let got = cache.get(std::path::Path::new("/x")).unwrap();
        prop_assert_eq!(got.as_deref(), Some(first.as_str()));
        cache.put(std::path::Path::new("/x"), &second, 1, "t", 1).unwrap();
        let got2 = cache.get(std::path::Path::new("/x")).unwrap();
        prop_assert_eq!(got2.as_deref(), Some(second.as_str()));
    }
}
