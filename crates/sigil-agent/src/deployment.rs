//! Targeted deployment preparation and durable generation coordinator (#230).
//!
//! This is not connected to daemon IPC, watchers, or fleet acknowledgements yet.
//! Consumers must read one generation, not copy its parts into independent live
//! locks. Storage commit alone must never be reported as `applied`.

use crate::ai_guard::rubric::Rubric;
use crate::ai_guard::rule_pack::{pack_is_loadable, parser::RulePackParser, selector::Selector};
use crate::hook_deny::DenyEvaluator;
use parking_lot::Mutex;
use sigil_core::policy::deployment::{
    DeploymentManifest, SignedDeploymentManifest, VerifiedManifest,
};
use sigil_core::policy::deployment_store::{DeploymentStore, StoreError};
use sigil_core::policy::{self, EffectivePolicy, HostIdStrategy, Keystore, PolicyDocument};
use std::collections::HashSet;
use std::sync::Arc;
use time::OffsetDateTime;

pub struct PreparedDeployment {
    pub manifest: DeploymentManifest,
    pub manifest_digest: String,
    pub effective: EffectivePolicy,
    pub rubric: Rubric,
    pub evaluator: DenyEvaluator,
    /// Validated templates, not yet bound to discovered project directories.
    pub rule_packs: Vec<RulePackParser>,
}

struct CoordinatorState {
    store: DeploymentStore,
    current: Option<Arc<PreparedDeployment>>,
    recovery_required: bool,
}

pub struct DeploymentCoordinator {
    state: Mutex<CoordinatorState>,
    keystore: Arc<Keystore>,
    identity_strategy: HostIdStrategy,
}

#[derive(Debug, thiserror::Error)]
pub enum CoordinatorError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("committed deployment is expired")]
    Expired,
    #[error("deployment recovery required before serving a generation")]
    RecoveryRequired,
}

impl DeploymentCoordinator {
    /// One coordinator per runtime. Reload the complete durable generation.
    pub fn open(
        store: DeploymentStore,
        keystore: Arc<Keystore>,
        identity_strategy: HostIdStrategy,
        now: OffsetDateTime,
    ) -> Result<Self, CoordinatorError> {
        let current = store.recover(&keystore, now, |verified, policy, packs| {
            prepare(verified, policy, packs, &identity_strategy).map(Arc::new)
        })?;
        Ok(Self {
            state: Mutex::new(CoordinatorState {
                store,
                current,
                recovery_required: false,
            }),
            keystore,
            identity_strategy,
        })
    }

    /// Obtain a coherent committed snapshot. Not a watcher/daemon apply status.
    pub fn snapshot(
        &self,
        now: OffsetDateTime,
    ) -> Result<Option<Arc<PreparedDeployment>>, CoordinatorError> {
        let state = self.state.lock();
        if state.recovery_required {
            return Err(CoordinatorError::RecoveryRequired);
        }
        if let Some(current) = &state.current {
            if now.unix_timestamp() >= current.manifest.valid_until {
                return Err(CoordinatorError::Expired);
            }
        }
        Ok(state.current.clone())
    }

    /// Compile all components, commit once, then publish one Arc under the same
    /// lock. Failed preparation never changes either disk or the current Arc.
    pub fn commit(
        &self,
        signed: &SignedDeploymentManifest,
        policy: &[u8],
        packs: &[u8],
        clock: impl Fn() -> OffsetDateTime,
    ) -> Result<Arc<PreparedDeployment>, CoordinatorError> {
        let mut state = self.state.lock();
        if state.recovery_required {
            return Err(CoordinatorError::RecoveryRequired);
        }
        let result = state.store.commit(
            signed,
            policy,
            packs,
            &self.keystore,
            clock,
            |verified, policy, packs| {
                prepare(verified, policy, packs, &self.identity_strategy).map(Arc::new)
            },
        );
        match result {
            Ok(prepared) => {
                state.current = Some(prepared.clone());
                Ok(prepared)
            }
            Err(error) => {
                // A storage error can leave commit outcome uncertain. Do not
                // present an old in-memory snapshot as the durable generation.
                if matches!(
                    error,
                    StoreError::Sql(_) | StoreError::Io(_) | StoreError::InvalidState
                ) {
                    state.recovery_required = true;
                }
                Err(error.into())
            }
        }
    }
}

fn prepare(
    verified: &VerifiedManifest,
    policy_doc: PolicyDocument,
    packs_doc: PolicyDocument,
    identity_strategy: &HostIdStrategy,
) -> Result<PreparedDeployment, String> {
    if &policy_doc.host_id_strategy != identity_strategy {
        return Err("targeted policy cannot change enrolled identity strategy".into());
    }
    // Validate each input before folding; an override must not hide a bad rule.
    validate_document(&policy_doc)?;
    validate_document(&packs_doc)?;
    let effective = policy::merge(
        policy::defaults().map_err(|e| e.to_string())?,
        Some(policy_doc),
        Some(packs_doc),
        policy::current_platform(),
    )
    .map_err(|e| e.to_string())?;
    for target in &effective.targets {
        for path in &target.paths {
            policy::glob::CompiledGlob::new(path).map_err(|e| e.to_string())?;
        }
    }
    if effective
        .rubric_overrides
        .values()
        .any(|v| !v.is_finite() || *v < 0.0)
    {
        return Err("rubric weights must be finite and nonnegative".into());
    }
    let rubric = Rubric::defaults().with_overrides(&effective.rubric_overrides);
    if !rubric.unknown_override_keys.is_empty() {
        return Err("unknown rubric override key".into());
    }
    policy::validate_deny_rule_ids(&effective.hook_deny_rules).map_err(|e| e.to_string())?;
    let evaluator = DenyEvaluator::new(&effective.hook_deny_rules).map_err(|e| e.to_string())?;
    let mut rule_packs = Vec::new();
    for pack in &effective.rule_packs {
        // Foreign-platform defaults remain in the effective document but do
        // not become live parsers, matching the current daemon's pack filter.
        if pack
            .platforms
            .as_ref()
            .is_some_and(|p| !p.is_empty() && !p.contains(&policy::current_platform()))
        {
            continue;
        }
        validate_pack(pack)?;
        rule_packs.push(RulePackParser::new(pack.clone()).map_err(|e| e.to_string())?);
    }
    Ok(PreparedDeployment {
        manifest: verified.manifest().clone(),
        manifest_digest: verified.digest().into(),
        effective,
        rubric,
        evaluator,
        rule_packs,
    })
}

fn validate_document(doc: &PolicyDocument) -> Result<(), String> {
    DenyEvaluator::new(&doc.hook_deny_rules).map_err(|e| e.to_string())?;
    let mut ids = HashSet::new();
    for pack in &doc.rule_packs {
        if !ids.insert(&pack.id) {
            return Err(format!("duplicate rule pack ID: {}", pack.id));
        }
        validate_pack(pack)?;
    }
    Ok(())
}

fn validate_pack(pack: &policy::RulePack) -> Result<(), String> {
    let mut structural = pack.clone();
    structural.platforms = None;
    if !pack_is_loadable(&structural) {
        return Err(format!("unsupported rule pack: {}", pack.id));
    }
    let mut ids = HashSet::new();
    for rule in &pack.rules {
        if !ids.insert(&rule.id) {
            return Err(format!("duplicate rule ID: {}", rule.id));
        }
        Selector::parse(&rule.selector).map_err(|e| e.to_string())?;
        for condition in &rule.when {
            Selector::parse(&condition.selector).map_err(|e| e.to_string())?;
        }
    }
    RulePackParser::new(pack.clone()).map_err(|e| e.to_string())?;
    Ok(())
}
