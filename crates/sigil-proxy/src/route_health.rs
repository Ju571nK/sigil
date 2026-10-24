//! Runtime route health (T-12b2; README N4, M2; status `routes[]`).
//!
//! The relay marks a route when its upstream answers in a way the proxy does not
//! support:
//!
//! | event | state | reason |
//! |---|---|---|
//! | `initialize` answered with a revision outside the allowlist | `unsupported` | `upstream_version_unsupported` |
//! | `initialize` answered with `tasks` or `resources.subscribe = true` | `unsupported` | `upstream_capability_unsupported` |
//! | `initialize` answer unreadable within the bound or timeout | `unsupported` | `upstream_initialize_unreadable` |
//! | a `tools/call` answered with a task handle (N10 ii) | `degraded` | `task_augmentation_unsupported` |
//!
//! A mark belongs to the route's [`Binding`] (upstream endpoint, credential and
//! scope), not to a config revision: a revision that changes only limits keeps
//! it, a repoint of the route to another endpoint or credential drops it. Marks
//! live in memory only, so a restart clears them. `unsupported` outranks
//! `degraded` and the first reason of a state is kept.
//!
//! A mark made under a binding the route no longer has (a late answer after a
//! repoint) is ignored. While a route's current binding is marked, a new
//! `initialize` on it is refused locally before the upstream (t13d-t12b2.md);
//! the marks also feed the status report.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sigil_proxy_api::status::{RouteReason, RouteState};

use crate::route::{Binding, TableHandle};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mark {
    pub state: RouteState,
    pub reason: RouteReason,
}

struct Entry {
    upstream_id: String,
    binding: Arc<Binding>,
    mark: Mark,
}

/// Shared between the relay (writer) and the status report (reader).
#[derive(Clone)]
pub struct RouteHealth {
    table: TableHandle,
    inner: Arc<Mutex<HashMap<String, Entry>>>,
}

impl std::fmt::Debug for RouteHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteHealth").finish_non_exhaustive()
    }
}

impl RouteHealth {
    /// `table` is the relay's table holder: a mark counts only while the route
    /// still has the binding it was made under.
    pub fn new(table: TableHandle) -> RouteHealth {
        RouteHealth {
            table,
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Record `mark` for route `route_id` under `binding`. A route without a
    /// scope (no applied config) has no upstream id to report and is skipped.
    pub fn mark(&self, route_id: &str, binding: &Arc<Binding>, upstream_id: &str, mark: Mark) {
        let mut g = self.lock();
        if !self.is_current(route_id, binding) {
            return;
        }
        match g.get_mut(route_id) {
            Some(e) if e.binding == *binding => {
                // unsupported outranks degraded; the first reason of a state stays
                if e.mark.state == RouteState::Degraded && mark.state == RouteState::Unsupported {
                    e.mark = mark;
                }
            }
            _ => {
                g.insert(
                    route_id.to_string(),
                    Entry {
                        upstream_id: upstream_id.to_string(),
                        binding: binding.clone(),
                        mark,
                    },
                );
            }
        }
    }

    fn is_current(&self, route_id: &str, binding: &Arc<Binding>) -> bool {
        self.table
            .last()
            .as_ref()
            .and_then(|t| t.route(route_id))
            .is_some_and(|r| **r.binding() == **binding)
    }

    /// Whether route `route_id` is marked `unsupported` under `binding`, which
    /// must still be the route's current binding. `degraded` does not count.
    pub fn is_unsupported(&self, route_id: &str, binding: &Arc<Binding>) -> bool {
        let g = self.lock();
        self.is_current(route_id, binding)
            && g.get(route_id)
                .is_some_and(|e| *e.binding == **binding && e.mark.state == RouteState::Unsupported)
    }

    /// The marks still current, by upstream id. Marks of a route that is gone
    /// or now has another binding are dropped. When several routes share an
    /// upstream, `unsupported` wins.
    pub fn current(&self) -> HashMap<String, Mark> {
        let mut g = self.lock();
        let table = self.table.last();
        g.retain(|route_id, e| {
            table
                .as_ref()
                .and_then(|t| t.route(route_id))
                .is_some_and(|r| **r.binding() == *e.binding)
        });
        let mut out: HashMap<String, Mark> = HashMap::new();
        for e in g.values() {
            let slot = out.entry(e.upstream_id.clone()).or_insert(e.mark);
            if slot.state == RouteState::Degraded && e.mark.state == RouteState::Unsupported {
                *slot = e.mark;
            }
        }
        out
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::bootstrap::Credential;
    use crate::limits::Limits;
    use crate::route::{PrincipalSpec, RouteScope, RouteSpec, RouteTable};
    use sigil_proxy_api::Id;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    fn table(dir: &std::path::Path, url: &str, cs: &str) -> RouteTable {
        let p = dir.join("secret");
        std::fs::write(&p, "S").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let creds = BTreeMap::from([(
            "ref1".to_string(),
            Credential {
                secret_file: p,
                upstream_origins: vec![
                    "http://127.0.0.1:9".to_string(),
                    "http://127.0.0.1:10".to_string(),
                ],
            },
        )]);
        RouteTable::build(
            &[RouteSpec {
                route_id: Id::new("a").unwrap(),
                upstream_url: url.into(),
                credential_ref: "ref1".into(),
                principals: vec![PrincipalSpec::new(
                    Id::new("p").unwrap(),
                    vec![sigil_proxy_api::verifier_for("t").into()],
                )],
                allowed_origins: vec![],
                allow_private_destination: false,
                limits: Default::default(),
                scope: Some(RouteScope {
                    upstream_id: "up-1".into(),
                    credential_scope_id: cs.into(),
                }),
            }],
            &creds,
            &Limits::default(),
        )
        .unwrap()
    }

    const VERSION: Mark = Mark {
        state: RouteState::Unsupported,
        reason: RouteReason::UpstreamVersionUnsupported,
    };
    const TASK: Mark = Mark {
        state: RouteState::Degraded,
        reason: RouteReason::TaskAugmentationUnsupported,
    };

    #[test]
    fn marks_follow_the_binding_not_the_revision() {
        let d = tempfile::tempdir().unwrap();
        let h = TableHandle::new();
        h.set(Some(table(d.path(), "http://127.0.0.1:9/mcp", "cs-1")));
        let rh = RouteHealth::new(h.clone());
        let b = h.current().unwrap().route("a").unwrap().binding().clone();
        rh.mark("a", &b, "up-1", TASK);
        assert_eq!(rh.current()["up-1"], TASK);
        // unsupported outranks degraded, and stays over a later degraded mark
        rh.mark("a", &b, "up-1", VERSION);
        rh.mark("a", &b, "up-1", TASK);
        assert_eq!(rh.current()["up-1"], VERSION);
        // a rebuilt table with the same binding (new revision) keeps the mark
        h.set(Some(
            table(d.path(), "http://127.0.0.1:9/mcp", "cs-1")
                .with_revision(sigil_proxy_api::PositiveI64::new(2).unwrap()),
        ));
        assert_eq!(rh.current()["up-1"], VERSION);
        // a repoint to another endpoint drops it
        h.set(Some(table(d.path(), "http://127.0.0.1:10/mcp", "cs-1")));
        assert!(rh.current().is_empty());
        // and so does a credential scope change
        h.set(Some(table(d.path(), "http://127.0.0.1:9/mcp", "cs-1")));
        let b = h.current().unwrap().route("a").unwrap().binding().clone();
        rh.mark("a", &b, "up-1", TASK);
        h.set(Some(table(d.path(), "http://127.0.0.1:9/mcp", "cs-2")));
        assert!(rh.current().is_empty());
        // a removed route drops it too
        h.set(None);
        assert!(rh.current().is_empty());
    }

    #[test]
    fn a_late_mark_under_an_old_binding_is_ignored() {
        let d = tempfile::tempdir().unwrap();
        let h = TableHandle::new();
        h.set(Some(table(d.path(), "http://127.0.0.1:9/mcp", "cs-1")));
        let rh = RouteHealth::new(h.clone());
        let old = h.current().unwrap().route("a").unwrap().binding().clone();
        // repoint, then a task handle answered under the old binding arrives
        h.set(Some(table(d.path(), "http://127.0.0.1:10/mcp", "cs-1")));
        let new = h.current().unwrap().route("a").unwrap().binding().clone();
        rh.mark("a", &new, "up-1", TASK);
        rh.mark("a", &old, "up-1", VERSION);
        assert_eq!(rh.current()["up-1"], TASK);
        // degraded never refuses an initialize
        assert!(!rh.is_unsupported("a", &new));
        rh.mark("a", &new, "up-1", VERSION);
        assert!(rh.is_unsupported("a", &new));
        assert!(!rh.is_unsupported("a", &old));
        // with no mark on the new binding the old one never shows up
        let rh = RouteHealth::new(h.clone());
        rh.mark("a", &old, "up-1", VERSION);
        assert!(rh.current().is_empty());
        assert!(!rh.is_unsupported("a", &new));
    }
}
