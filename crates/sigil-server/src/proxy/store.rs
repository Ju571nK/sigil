//! Durable per-proxy state: the latest config, the latest status snapshot, the
//! gap records and `last_seen` (control-plane §6, ledger L6/L6b).
//!
//! Storage: one JSON file, owner-only (0600), loaded into memory at boot and
//! rewritten atomically (tmp in the same dir, fsync, rename, dir fsync) on every
//! mutation. Mutations are persist-first-then-swap: a failed write leaves
//! memory unchanged. The file holds verifiers (config), so a group/world
//! accessible or symlinked file is a boot error.
// OPEN: moves to the S4 ledger DB. A whole-file rewrite per status report is an
// interim cost that is fine for a handful of proxies and not for a fleet.

use anyhow::{bail, Context, Result};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use sigil_proxy_api::{GapReport, ProxyConfig, ProxyStatus};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Gap records kept per proxy. A new gap that would exceed the count or the byte
/// cap is refused (503, see `status`) rather than dropping a stored gap.
pub const MAX_GAPS_PER_PROXY: usize = 10_000;
/// Serialized size of the gap records of one proxy.
pub const MAX_GAPS_BYTES_PER_PROXY: usize = 8 * 1024 * 1024;
/// Epoch ids and per-epoch counter totals remembered per proxy (a replayed old
/// epoch is told from a new one by this list; an epoch that fell off counts as
/// new).
pub const MAX_EPOCHS_SEEN: usize = 64;
/// Distinct `(kind, upstream_id, reason)` counter keys kept for the current
/// epoch (routes x reasons stays far below it).
pub const MAX_COUNTER_KEYS: usize = 4096;
/// Format version of the state file.
pub const FILE_VERSION: u8 = 1;

/// Counter totals of a finished epoch (ledger L6 `previous_epoch_totals`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochTotals {
    pub epoch_id: String,
    pub auth_failures: i64,
    pub unmatched_cancels: i64,
}

/// The accepted config of a proxy.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StoredConfig {
    /// As accepted at PUT, with the PUT-time stamps. A fetch restamps it.
    pub config: ProxyConfig,
    pub config_hash: String,
    pub updated_at: String,
}

/// One route's `(upstream_id, credential_scope_id)` binding. Kept for the
/// previous revision so ledger SV-5 can accept the scope a proxy is still
/// minting under until it applies the new revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopePair {
    pub upstream_id: String,
    pub credential_scope_id: String,
}

fn scopes_of(c: &ProxyConfig) -> Vec<ScopePair> {
    c.routes
        .iter()
        .map(|r| ScopePair {
            upstream_id: r.upstream_id.as_str().to_string(),
            credential_scope_id: r.credential_scope_id.as_str().to_string(),
        })
        .collect()
}

/// An accepted ingest refreshes `last_seen` only when the stored value is at
/// least this old, so ingest is not a heartbeat writer (every write fsyncs the
/// whole state file). It must stay well below any sensible `stale_after`.
pub const LAST_SEEN_MIN_INTERVAL_SECS: i64 = 30;

/// Everything stored for one `proxy_id`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ProxyEntry {
    #[serde(default)]
    pub config: Option<StoredConfig>,
    /// Latest applied snapshot. Its `gaps` are always empty here; gap records
    /// live in `gaps`, keyed by gap id.
    #[serde(default)]
    pub status: Option<ProxyStatus>,
    /// Server time of the last accepted status report (heartbeat source).
    #[serde(default)]
    pub last_seen: Option<String>,
    /// Epochs a snapshot was applied for, oldest first (bounded).
    #[serde(default)]
    pub epochs_seen: Vec<String>,
    #[serde(default)]
    pub gaps: Vec<GapReport>,
    /// Epoch the `counter_max` values belong to.
    #[serde(default)]
    pub counters_epoch: Option<String>,
    /// Maximum seen per `(kind, upstream_id, reason)` in `counters_epoch`; key is
    /// `a|c`, upstream id (empty = none), reason, separated by U+001F.
    #[serde(default)]
    pub counter_max: BTreeMap<String, i64>,
    /// Totals of earlier epochs, oldest first (bounded).
    #[serde(default)]
    pub previous_epoch_totals: Vec<EpochTotals>,
    /// Route bindings of the revision BEFORE the stored config (SV-5). Set by
    /// [`StoreTxn::commit`] whenever the stored config's revision changes; empty
    /// before the first revision change. Only the immediately previous revision
    /// is kept (decisions.md "T-11 S4 범위").
    #[serde(default)]
    pub previous_scopes: Vec<ScopePair>,
}

impl ProxyEntry {
    pub fn revision(&self) -> u64 {
        self.config
            .as_ref()
            .map_or(0, |c| c.config.revision.get() as u64)
    }
}

#[derive(Default, Serialize, Deserialize)]
struct FileFormat {
    #[serde(default)]
    v: u8,
    #[serde(default)]
    proxies: BTreeMap<String, ProxyEntry>,
}

pub struct ProxyStore {
    path: PathBuf,
    inner: RwLock<BTreeMap<String, ProxyEntry>>,
    /// Serializes writers (read-modify-persist). The map lock is taken only for
    /// the final swap, so readers never wait on an fsync.
    writer: Mutex<()>,
}

impl ProxyStore {
    /// Load the store (boot). A missing file starts empty with a warning: it is
    /// also the state of every server that predates S3, and losing the file
    /// resets revisions to 0, which a proxy reports as `stale_revision`. A
    /// symlink, a non-regular file, a group/world accessible file, unparsable
    /// JSON or an inconsistent entry is refused.
    pub fn open(path: &Path) -> Result<Self> {
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => Some(m),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e).context("stat proxy state"),
        };
        let mut map = BTreeMap::new();
        match meta {
            None => {
                tracing::warn!(
                    path = %path.display(),
                    "proxy state file does not exist; starting empty (every proxy sees config_unavailable until a config is PUT)"
                );
            }
            Some(meta) => {
                if meta.file_type().is_symlink() {
                    bail!("proxy state must not be a symlink");
                }
                if !meta.is_file() {
                    bail!("proxy state is not a regular file");
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if meta.permissions().mode() & 0o077 != 0 {
                        bail!("proxy state must be owner-only (it holds verifiers)");
                    }
                }
                let b = std::fs::read(path).context("read proxy state")?;
                let f: FileFormat = serde_json::from_slice(&b).context("parse proxy state JSON")?;
                if f.v != FILE_VERSION {
                    bail!("proxy state has an unknown format version");
                }
                for (id, e) in &f.proxies {
                    if let Some(c) = &e.config {
                        if c.config.proxy_id.as_str() != id {
                            bail!("proxy state: config proxy_id does not match its key");
                        }
                        sigil_proxy_api::Validate::validate(&c.config)
                            .map_err(|_| anyhow::anyhow!("proxy state: invalid stored config"))?;
                        if c.config.config_hash().as_str() != c.config_hash {
                            bail!("proxy state: stored config_hash does not match the config");
                        }
                    }
                    if let Some(s) = &e.status {
                        if s.proxy_id.as_str() != id {
                            bail!("proxy state: status proxy_id does not match its key");
                        }
                    }
                }
                map = f.proxies;
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            inner: RwLock::new(map),
            writer: Mutex::new(()),
        })
    }

    /// The stored config of `proxy_id` only.
    pub fn config(&self, proxy_id: &str) -> Option<StoredConfig> {
        self.inner
            .read()
            .get(proxy_id)
            .and_then(|e| e.config.clone())
    }

    /// Whole entry (clones the gap list).
    pub fn entry(&self, proxy_id: &str) -> Option<ProxyEntry> {
        self.inner.read().get(proxy_id).cloned()
    }

    /// `(proxy_id, stored config)` for every proxy that has one.
    pub fn configs(&self) -> Vec<(String, StoredConfig)> {
        self.inner
            .read()
            .iter()
            .filter_map(|(k, e)| e.config.clone().map(|c| (k.clone(), c)))
            .collect()
    }

    /// SV-5 / registry R2: is `credential_scope_id` one the server assigned to
    /// `(proxy_id, upstream_id)` in the current revision's route set or in the
    /// previous revision's? `false` when the proxy has no config.
    pub fn scope_assigned(
        &self,
        proxy_id: &str,
        upstream_id: &str,
        credential_scope_id: &str,
    ) -> bool {
        let g = self.inner.read();
        let Some(e) = g.get(proxy_id) else {
            return false;
        };
        let hit = |p: &ScopePair| {
            p.upstream_id == upstream_id && p.credential_scope_id == credential_scope_id
        };
        e.config
            .as_ref()
            .is_some_and(|c| scopes_of(&c.config).iter().any(hit))
            || e.previous_scopes.iter().any(hit)
    }

    pub fn last_seen(&self, proxy_id: &str) -> Option<String> {
        self.inner
            .read()
            .get(proxy_id)
            .and_then(|e| e.last_seen.clone())
    }

    /// Record the current time as the proxy's `last_seen` after an accepted
    /// ingest, unless the stored value is already within
    /// [`LAST_SEEN_MIN_INTERVAL_SECS`] of now. The clock is read AFTER the
    /// writer lock is held and the check runs against the current entry, so a
    /// newer status-report value is never replaced with an older one. A stored
    /// value more than the interval in the future (clock stepped back) or one
    /// that does not parse is replaced. Returns whether a write happened.
    pub fn touch_last_seen(&self, proxy_id: &str) -> Result<bool> {
        self.touch_last_seen_with(proxy_id, time::OffsetDateTime::now_utc)
    }

    fn touch_last_seen_with(
        &self,
        proxy_id: &str,
        clock: impl FnOnce() -> time::OffsetDateTime,
    ) -> Result<bool> {
        let rfc3339 = &time::format_description::well_known::Rfc3339;
        let txn = self.begin();
        let now = clock();
        let mut entry = txn.entry(proxy_id);
        let window = time::Duration::seconds(LAST_SEEN_MIN_INTERVAL_SECS);
        let fresh = entry
            .last_seen
            .as_deref()
            .and_then(|t| time::OffsetDateTime::parse(t, rfc3339).ok())
            .is_some_and(|seen| seen > now - window && seen <= now + window);
        if fresh {
            return Ok(false);
        }
        entry.last_seen = Some(now.format(rfc3339)?);
        txn.commit(proxy_id, entry)?;
        Ok(true)
    }

    /// Start a write transaction (takes the writer mutex).
    pub fn begin(&self) -> StoreTxn<'_> {
        StoreTxn {
            store: self,
            _writer: self.writer.lock(),
        }
    }
}

/// Write transaction (see [`ProxyStore::begin`]).
pub struct StoreTxn<'a> {
    store: &'a ProxyStore,
    _writer: parking_lot::MutexGuard<'a, ()>,
}

impl StoreTxn<'_> {
    /// Current entry, or an empty one.
    pub fn entry(&self, proxy_id: &str) -> ProxyEntry {
        self.store.entry(proxy_id).unwrap_or_default()
    }

    /// Persist `entry` for `proxy_id`, then swap it into memory. On error
    /// nothing changed in memory.
    pub fn commit(self, proxy_id: &str, mut entry: ProxyEntry) -> Result<()> {
        {
            let guard = self.store.inner.read();
            // SV-5 history: when the config revision changes, the outgoing
            // config's bindings become `previous_scopes`. Done here, under the
            // writer lock, so every writer (config PUT, status) stays correct.
            let outgoing = match (
                guard.get(proxy_id).and_then(|e| e.config.as_ref()),
                entry.config.as_ref(),
            ) {
                (Some(old), Some(new))
                    if old.config.revision.get() != new.config.revision.get() =>
                {
                    Some(scopes_of(&old.config))
                }
                _ => None,
            };
            if let Some(prev) = outgoing {
                entry.previous_scopes = prev;
            }
            let mut view: BTreeMap<&str, &ProxyEntry> =
                guard.iter().map(|(k, v)| (k.as_str(), v)).collect();
            view.insert(proxy_id, &entry);
            #[derive(Serialize)]
            struct Out<'a> {
                v: u8,
                proxies: &'a BTreeMap<&'a str, &'a ProxyEntry>,
            }
            let bytes = serde_json::to_vec(&Out {
                v: 1,
                proxies: &view,
            })?;
            write_atomic(&self.store.path, &bytes)?;
        }
        self.store.inner.write().insert(proxy_id.to_string(), entry);
        Ok(())
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    // NamedTempFile is created 0600 on unix.
    let mut tmp = tempfile::Builder::new()
        .prefix(".proxy-state-")
        .tempfile_in(dir)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    if let Ok(f) = std::fs::File::open(dir) {
        let _ = f.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sigil_proxy_api::parse_config;

    #[test]
    fn touch_last_seen_never_regresses_a_newer_value() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProxyStore::open(&dir.path().join("p.json")).unwrap();
        let t0 = time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let fmt = |t: time::OffsetDateTime| {
            t.format(&time::format_description::well_known::Rfc3339)
                .unwrap()
        };
        let secs = time::Duration::seconds;
        let set = |v: String| {
            let txn = store.begin();
            let mut e = txn.entry("px");
            e.last_seen = Some(v);
            txn.commit("px", e).unwrap();
        };
        // Written a moment after our clock read (a status report racing us).
        set(fmt(t0 + secs(5)));
        assert!(!store.touch_last_seen_with("px", || t0).unwrap());
        assert_eq!(store.last_seen("px"), Some(fmt(t0 + secs(5))));
        // Far in the future (clock stepped back): replaced.
        set(fmt(t0 + secs(3600)));
        assert!(store.touch_last_seen_with("px", || t0).unwrap());
        assert_eq!(store.last_seen("px"), Some(fmt(t0)));
        // Old: replaced; fresh: kept.
        set(fmt(t0 - secs(LAST_SEEN_MIN_INTERVAL_SECS + 1)));
        assert!(store.touch_last_seen_with("px", || t0).unwrap());
        assert!(!store.touch_last_seen_with("px", || t0).unwrap());
    }

    pub(crate) fn sample_config(id: &str, revision: u64) -> ProxyConfig {
        parse_config(
            serde_json::to_vec(&json!({
                "schema_version": 1, "mode": "observe",
                "proxy_id": id, "revision": revision,
                "issued_at": "2026-10-11T00:00:00Z", "expires_at": "2026-10-11T00:05:00Z",
                "ttl_seconds": 300,
                "max_offline_retry_age_seconds": 2592000, "event_retention_seconds": 7776000,
                "allowed_origins": [],
                "routes": [{"route_id": "r1", "upstream_id": "up1",
                    "upstream_url": "https://a.example/mcp",
                    "upstream_protocol": "2025-11-25", "credential_ref": "gh",
                    "credential_scope_id": "cs-00000000000000000000000000000001"}],
                "principals": [{"principal_id": "p", "routes": ["r1"], "verifiers": [
                    {"key_id": "k1", "verifier": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}]}],
            }))
            .unwrap()
            .as_slice(),
        )
        .unwrap()
    }

    fn entry_with(id: &str, rev: u64) -> ProxyEntry {
        let c = sample_config(id, rev);
        ProxyEntry {
            config: Some(StoredConfig {
                config_hash: c.config_hash().as_str().to_string(),
                config: c,
                updated_at: "2026-10-11T00:00:00Z".into(),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn unknown_or_missing_format_version_refuses_boot() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("proxy-state.json");
        let s = ProxyStore::open(&p).unwrap();
        s.begin().commit("a", entry_with("a", 1)).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.starts_with("{\"v\":1,"), "compact JSON with a version");
        assert!(!text.contains('\n'), "compact");
        for bad in ["\"v\":2", "\"v\":0", "\"v\":255"] {
            std::fs::write(&p, text.replacen("\"v\":1", bad, 1)).unwrap();
            assert!(ProxyStore::open(&p).is_err(), "{bad}");
        }
        std::fs::write(&p, text.replacen("\"v\":1,", "", 1)).unwrap();
        assert!(ProxyStore::open(&p).is_err(), "missing version");
        std::fs::write(&p, &text).unwrap();
        assert!(ProxyStore::open(&p).is_ok());
    }

    #[test]
    fn persists_reloads_and_isolates_proxies() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sub/proxy-state.json");
        let s = ProxyStore::open(&p).unwrap();
        assert!(s.config("a").is_none());
        s.begin().commit("a", entry_with("a", 1)).unwrap();
        s.begin().commit("b", entry_with("b", 7)).unwrap();
        let r = ProxyStore::open(&p).unwrap();
        assert_eq!(r.config("a").unwrap().config.revision.get(), 1);
        assert_eq!(r.config("b").unwrap().config.revision.get(), 7);
        assert!(r.config("c").is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(m & 0o777, 0o600, "owner-only");
        }
    }

    /// SV-5 history: a revision change keeps the outgoing route bindings, a
    /// write at the same revision (status report) leaves them alone, and only
    /// the immediately previous revision is remembered.
    #[test]
    fn revision_change_records_the_previous_route_scopes() {
        use sigil_proxy_api::Id;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("proxy-state.json");
        let s = ProxyStore::open(&p).unwrap();
        let scope = |n: u32| Id::new(format!("cs-{n:032x}")).unwrap();
        let rev = |r: u64, sc: u32| {
            let mut e = entry_with("a", r);
            let c = e.config.as_mut().unwrap();
            c.config.routes[0].credential_scope_id = scope(sc);
            c.config_hash = c.config.config_hash().as_str().to_string();
            e
        };
        assert!(
            !s.scope_assigned("a", "up1", scope(1).as_str()),
            "no config"
        );
        s.begin().commit("a", rev(1, 1)).unwrap();
        assert!(s.scope_assigned("a", "up1", scope(1).as_str()));
        assert!(
            !s.scope_assigned("a", "up2", scope(1).as_str()),
            "upstream matters"
        );
        assert!(
            !s.scope_assigned("b", "up1", scope(1).as_str()),
            "proxy matters"
        );
        assert!(s.entry("a").unwrap().previous_scopes.is_empty());

        s.begin().commit("a", rev(2, 2)).unwrap();
        assert!(s.scope_assigned("a", "up1", scope(1).as_str()), "previous");
        assert!(s.scope_assigned("a", "up1", scope(2).as_str()), "current");

        // Same revision: history untouched.
        let mut same = s.entry("a").unwrap();
        same.last_seen = Some("2026-10-11T00:00:00Z".into());
        s.begin().commit("a", same).unwrap();
        assert!(s.scope_assigned("a", "up1", scope(1).as_str()));

        s.begin().commit("a", rev(3, 3)).unwrap();
        assert!(!s.scope_assigned("a", "up1", scope(1).as_str()), "two back");
        assert!(s.scope_assigned("a", "up1", scope(2).as_str()));
        assert!(s.scope_assigned("a", "up1", scope(3).as_str()));

        // Survives a reload.
        let r = ProxyStore::open(&p).unwrap();
        assert!(r.scope_assigned("a", "up1", scope(2).as_str()));
        assert!(!r.scope_assigned("a", "up1", scope(1).as_str()));
    }

    #[test]
    fn failed_write_leaves_memory_unchanged() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("proxy-state.json");
        let s = ProxyStore::open(&p).unwrap();
        s.begin().commit("a", entry_with("a", 1)).unwrap();
        // Replace the target by a non-empty directory: the rename fails.
        std::fs::remove_file(&p).unwrap();
        std::fs::create_dir(&p).unwrap();
        std::fs::write(p.join("x"), b"x").unwrap();
        assert!(s.begin().commit("a", entry_with("a", 2)).is_err());
        assert_eq!(s.config("a").unwrap().config.revision.get(), 1);
    }

    #[test]
    fn broken_files_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("proxy-state.json");
        std::fs::write(&p, b"{not json").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(ProxyStore::open(&p).is_err());

        // key/proxy_id mismatch and a tampered hash
        let s = ProxyStore::open(&d.path().join("ok.json")).unwrap();
        s.begin().commit("a", entry_with("a", 1)).unwrap();
        let text = std::fs::read_to_string(d.path().join("ok.json")).unwrap();
        let swapped = text.replacen("\"a\":{", "\"zz\":{", 1);
        let q = d.path().join("swapped.json");
        std::fs::write(&q, swapped).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&q, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(ProxyStore::open(&q).is_err());
        let h = sample_config("a", 1).config_hash().as_str().to_string();
        let tampered = text.replace(&h, &"0".repeat(64));
        let t = d.path().join("tampered.json");
        std::fs::write(&t, tampered).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&t, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(ProxyStore::open(&t).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn accessible_or_symlinked_file_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("proxy-state.json");
        ProxyStore::open(&p)
            .unwrap()
            .begin()
            .commit("a", entry_with("a", 1))
            .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(ProxyStore::open(&p).is_err());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(ProxyStore::open(&p).is_ok());
        let l = d.path().join("link.json");
        std::os::unix::fs::symlink(&p, &l).unwrap();
        assert!(ProxyStore::open(&l).is_err());
    }
}
