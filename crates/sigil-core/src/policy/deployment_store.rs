//! Durable paired deployment storage (#230). Not wired into legacy writers.
//!
//! SQLite FULL-synchronous transactions commit both artifact BLOBs, the signed
//! manifest, and the replay checkpoint together. A commit is not an apply ack.
//! Provisioning must quiesce legacy writers before copying their watermarks.

use super::deployment::{
    verify_manifest, DeploymentError, ReplayState, SignedDeploymentManifest,
    VerificationDisposition, VerifiedManifest, MAX_ARTIFACT_BYTES, MAX_MANIFEST_BYTES,
};
use super::{Keystore, PolicyDocument};
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use std::path::Path;
use time::OffsetDateTime;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("deployment storage: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("deployment storage I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Verify(#[from] DeploymentError),
    #[error("invalid or incomplete deployment store")]
    InvalidState,
    #[error("deployment policy preparation failed: {0}")]
    Preparation(String),
}

/// Raw committed bytes, never evidence that a runtime generation is active.
struct StoredDeployment {
    signed: SignedDeploymentManifest,
    policy: Vec<u8>,
    rule_packs: Vec<u8>,
}

pub struct DeploymentStore {
    conn: Connection,
    host_id: String,
}

struct Snapshot {
    replay: ReplayState,
    deployment: Option<StoredDeployment>,
}

impl DeploymentStore {
    /// Explicit provisioning only. Refuses to overwrite even an empty file.
    /// Do not call on a missing store after enrollment: loss requires recovery.
    pub fn initialize(
        path: &Path,
        host_id: &str,
        policy_version: i64,
        rule_packs_version: i64,
    ) -> Result<Self, StoreError> {
        if host_id.is_empty()
            || host_id.len() > 256
            || host_id.trim() != host_id
            || host_id.chars().any(char::is_control)
            || policy_version < 0
            || rule_packs_version < 0
        {
            return Err(StoreError::InvalidState);
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)?.sync_all()?;
        let mut conn = connect(path)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "CREATE TABLE deployment_state (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                store_version INTEGER NOT NULL CHECK(store_version = 1),
                host_id TEXT NOT NULL,
                legacy_policy INTEGER NOT NULL,
                legacy_packs INTEGER NOT NULL,
                targeted INTEGER NOT NULL CHECK(targeted IN (0, 1)),
                sequence INTEGER,
                digest TEXT,
                manifest BLOB,
                policy BLOB,
                packs BLOB,
                CHECK ((targeted = 0 AND sequence IS NULL AND digest IS NULL
                    AND manifest IS NULL AND policy IS NULL AND packs IS NULL)
                    OR (targeted = 1 AND sequence IS NOT NULL AND digest IS NOT NULL
                    AND manifest IS NOT NULL AND policy IS NOT NULL AND packs IS NOT NULL))
            );",
        )?;
        tx.execute(
            "INSERT INTO deployment_state
             (id, store_version, host_id, legacy_policy, legacy_packs, targeted)
             VALUES (1, 1, ?1, ?2, ?3, 0)",
            params![host_id, policy_version, rule_packs_version],
        )?;
        tx.commit()?;
        #[cfg(unix)]
        std::fs::File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()?;
        Ok(Self {
            conn,
            host_id: host_id.into(),
        })
    }

    /// Never creates or repairs a missing/corrupt enrolled store.
    pub fn open_existing(path: &Path, enrolled_host_id: &str) -> Result<Self, StoreError> {
        let conn = connect(path)?;
        read_snapshot(&conn, enrolled_host_id)?;
        Ok(Self {
            conn,
            host_id: enrolled_host_id.into(),
        })
    }

    /// Verify and compile before committing. All failures leave the old row.
    /// The clock is sampled again after preparation, immediately before commit.
    /// A caller publishing in-memory state must serialize readers with this call.
    pub fn commit<T>(
        &mut self,
        signed: &SignedDeploymentManifest,
        policy: &[u8],
        rule_packs: &[u8],
        keystore: &Keystore,
        clock: impl Fn() -> OffsetDateTime,
        prepare: impl FnOnce(&VerifiedManifest, PolicyDocument, PolicyDocument) -> Result<T, String>,
    ) -> Result<T, StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let snapshot = read_snapshot(&tx, &self.host_id)?;
        let verified = verify_manifest(keystore, signed, &self.host_id, clock(), &snapshot.replay)?;
        let (policy_doc, packs_doc) = verified.verify_artifacts(policy, rule_packs)?;
        let prepared =
            prepare(&verified, policy_doc, packs_doc).map_err(StoreError::Preparation)?;
        // Compilation may take time; do not commit after key/manifest expiry.
        verify_manifest(keystore, signed, &self.host_id, clock(), &snapshot.replay)?;
        if verified.disposition() == VerificationDisposition::Retry {
            let old = snapshot.deployment.ok_or(StoreError::InvalidState)?;
            if old.policy != policy || old.rule_packs != rule_packs {
                return Err(StoreError::InvalidState);
            }
        } else {
            let manifest = serde_json::to_vec(signed).map_err(|_| StoreError::InvalidState)?;
            if manifest.len() > MAX_MANIFEST_BYTES {
                return Err(StoreError::InvalidState);
            }
            tx.execute(
                "UPDATE deployment_state SET targeted = 1, sequence = ?1, digest = ?2,
                 manifest = ?3, policy = ?4, packs = ?5 WHERE id = 1",
                params![
                    signed.manifest.sequence,
                    verified.digest(),
                    manifest,
                    policy,
                    rule_packs
                ],
            )?;
        }
        #[cfg(test)]
        tests::crash_point("before_commit");
        tx.commit()?;
        #[cfg(test)]
        tests::crash_point("after_commit");
        Ok(prepared)
    }

    /// Reverify and recompile the complete generation at restart. Expired or
    /// corrupt state is an error, never silently interpreted as legacy mode.
    pub fn recover<T>(
        &self,
        keystore: &Keystore,
        now: OffsetDateTime,
        prepare: impl FnOnce(&VerifiedManifest, PolicyDocument, PolicyDocument) -> Result<T, String>,
    ) -> Result<Option<T>, StoreError> {
        let snapshot = read_snapshot(&self.conn, &self.host_id)?;
        let Some(stored) = snapshot.deployment else {
            return Ok(None);
        };
        let verified = verify_manifest(
            keystore,
            &stored.signed,
            &self.host_id,
            now,
            &snapshot.replay,
        )?;
        let (policy, packs) = verified.verify_artifacts(&stored.policy, &stored.rule_packs)?;
        prepare(&verified, policy, packs)
            .map(Some)
            .map_err(StoreError::Preparation)
    }
}

#[cfg(test)]
mod tests;

fn connect(path: &Path) -> Result<Connection, StoreError> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "fullfsync", true)?;
    Ok(conn)
}

fn read_snapshot(conn: &Connection, host_id: &str) -> Result<Snapshot, StoreError> {
    let snapshot = conn.query_row(
        "SELECT host_id, legacy_policy, legacy_packs, targeted, sequence, digest,
         manifest, policy, packs FROM deployment_state WHERE id = 1 AND store_version = 1
         AND (manifest IS NULL OR length(manifest) <= ?1)
         AND (policy IS NULL OR length(policy) <= ?2)
         AND (packs IS NULL OR length(packs) <= ?2)",
        params![MAX_MANIFEST_BYTES, MAX_ARTIFACT_BYTES],
        |row| {
            let host: String = row.get(0)?;
            let legacy_policy: i64 = row.get(1)?;
            let legacy_packs: i64 = row.get(2)?;
            let targeted: i64 = row.get(3)?;
            let sequence: Option<i64> = row.get(4)?;
            let digest: Option<String> = row.get(5)?;
            let manifest: Option<Vec<u8>> = row.get(6)?;
            let policy: Option<Vec<u8>> = row.get(7)?;
            let packs: Option<Vec<u8>> = row.get(8)?;
            Ok((
                host,
                legacy_policy,
                legacy_packs,
                targeted,
                sequence,
                digest,
                manifest,
                policy,
                packs,
            ))
        },
    )?;
    let (host, legacy_policy, legacy_packs, targeted, sequence, digest, manifest, policy, packs) =
        snapshot;
    if host != host_id || legacy_policy < 0 || legacy_packs < 0 {
        return Err(StoreError::InvalidState);
    }
    match (targeted, sequence, digest, manifest, policy, packs) {
        (0, None, None, None, None, None) => Ok(Snapshot {
            replay: ReplayState::Legacy {
                policy_version: legacy_policy,
                rule_packs_version: legacy_packs,
            },
            deployment: None,
        }),
        (1, Some(sequence), Some(digest), Some(manifest), Some(policy), Some(rule_packs)) => {
            let signed = SignedDeploymentManifest::from_json(&manifest)
                .map_err(|_| StoreError::InvalidState)?;
            if signed.manifest.target_host_id != host
                || signed.manifest.sequence != sequence
                || signed
                    .manifest
                    .digest()
                    .map_err(|_| StoreError::InvalidState)?
                    != digest
                || sequence <= legacy_policy.max(legacy_packs)
            {
                return Err(StoreError::InvalidState);
            }
            Ok(Snapshot {
                replay: ReplayState::Targeted {
                    host_id: host,
                    sequence,
                    manifest_digest: digest,
                },
                deployment: Some(StoredDeployment {
                    signed,
                    policy,
                    rule_packs,
                }),
            })
        }
        _ => Err(StoreError::InvalidState),
    }
}
