//! Route table (T-12 slice A). Maps `route_id` to a fixed upstream, its
//! credential binding, the principals allowed on it and the downstream
//! `Origin` allowlist (PX-002, PX-008, PX-009, PX-014).
//!
//! The remote config fetch/apply is a later slice. It will call exactly one
//! constructor, [`RouteTable::build`], and install the result with
//! [`TableHandle::set`]. Nothing here reads the network.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use http::HeaderValue;
use sigil_proxy_api::Id;
use thiserror::Error;
use tokio::sync::Semaphore;

use sigil_proxy_api::config::ActorKind as ConfigActorKind;
use sigil_proxy_api::event::{Actor, ActorKind, AuthenticationMethod, EvidenceSource};

use crate::bootstrap::{normalize_origin, split_host_port, Credential};
use crate::limits::{Limits, RemoteLimits};

/// One principal as the later config slice will describe it. The token itself
/// never appears here, only SHA-256 verifiers (control-plane.md §5.2).
#[derive(Debug, Clone)]
pub struct PrincipalSpec {
    pub principal_id: Id,
    /// Lowercase-hex SHA-256 verifiers (at most two for overlap).
    pub verifiers: Vec<VerifierSpec>,
    /// Declared kind from the server-issued credential mapping (README N3).
    /// `None`: none declared, audited as `unknown`.
    pub actor_kind: Option<ConfigActorKind>,
    /// Permission owner from the same mapping. Not evidence of the executor.
    pub credential_owner_id: Option<Id>,
}

impl PrincipalSpec {
    /// A principal with no declared kind or owner.
    pub fn new(principal_id: Id, verifiers: Vec<VerifierSpec>) -> PrincipalSpec {
        PrincipalSpec {
            principal_id,
            verifiers,
            actor_kind: None,
            credential_owner_id: None,
        }
    }
}

/// One verifier with its optional expiry (control-plane.md §5.2). `not_after` is
/// enforced per verifier at authenticate time, so during a rotation the old
/// verifier stops working on its own while the new one keeps working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierSpec {
    /// Lowercase-hex SHA-256 of the token.
    pub verifier: String,
    /// Unix seconds. The verifier is usable only while `now < not_after`
    /// (fail-closed reading: the instant itself is already expired).
    pub not_after: Option<i64>,
}

impl From<String> for VerifierSpec {
    fn from(verifier: String) -> Self {
        VerifierSpec {
            verifier,
            not_after: None,
        }
    }
}

impl From<&str> for VerifierSpec {
    fn from(verifier: &str) -> Self {
        verifier.to_string().into()
    }
}

#[derive(Debug, Clone)]
pub struct RouteSpec {
    pub route_id: Id,
    pub upstream_url: String,
    pub credential_ref: String,
    pub principals: Vec<PrincipalSpec>,
    /// Downstream `Origin` allowlist (control-plane.md §5.3). Normalized with
    /// [`normalize_origin`] at build.
    pub allowed_origins: Vec<String>,
    /// Explicit management flag for private destinations (control-plane.md
    /// §6.1 "private destinations need an explicit management flag").
    // OPEN: the DTO field name for this flag is not defined by the contract.
    pub allow_private_destination: bool,
    /// Remote per-route limits; they can only lower the local ones.
    pub limits: RemoteLimits,
    /// The applied config's `(upstream_id, credential_scope_id)` of this route.
    /// `None` outside a config sync (tests, local tables): such calls feed no
    /// inventory.
    pub scope: Option<RouteScope>,
}

/// The inventory scope of a route, fixed in the route table it was built into
/// (T-13c). A call carries the scope of the table that routed it, so a later
/// config that repoints the route never re-scopes a call already in flight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteScope {
    pub upstream_id: String,
    pub credential_scope_id: String,
}

/// What a proxy session is bound to besides its principal and route (T-12b2):
/// the upstream endpoint, the upstream credential and the server's scope of
/// both. A session created under one binding is never used under another, so a
/// repointed route can never carry an old upstream session id to a new endpoint
/// or credential. A change of anything else (limits, revision) keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    scope: Option<RouteScope>,
    /// `scheme://host:port/path` of the upstream.
    endpoint: String,
    credential_ref: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RouteError {
    #[error("route {route}: invalid upstream_url: {reason}")]
    UpstreamUrl { route: String, reason: String },
    #[error("route {route}: unknown credential_ref {reference}")]
    UnknownCredential { route: String, reference: String },
    #[error("route {route}: upstream origin is not bound to credential_ref {reference}")]
    CredentialOrigin { route: String, reference: String },
    #[error("credential_ref {reference}: cannot read the secret: {reason}")]
    Secret { reference: String, reason: String },
    #[error("route {route}: invalid allowed_origins entry: {reason}")]
    AllowedOrigin { route: String, reason: String },
    #[error("route {route}: verifier must be 64 lowercase hex characters")]
    Verifier { route: String },
    #[error("duplicate route_id {0}")]
    DuplicateRoute(String),
}

/// The fixed upstream of a route. Requests can never change it (AC-08).
#[derive(Debug, Clone)]
pub struct Upstream {
    pub https: bool,
    /// Lowercase host without IPv6 brackets.
    pub host: String,
    pub port: u16,
    /// Absolute path sent upstream. No query: the request's query is dropped.
    pub path: String,
    /// Set when the host is an IP literal (an "explicitly configured" address).
    pub host_literal: Option<IpAddr>,
    /// Value for the upstream `Host` header.
    pub host_header: String,
}

pub struct Principal {
    pub id: Id,
    /// The audit actor of this principal, from the applied credential mapping
    /// only (README N3); never from client input.
    pub actor: Actor,
    verifiers: Vec<VerifierSpec>,
    /// Shared by every route that names the same principal id.
    pub(crate) sem: Arc<Semaphore>,
    sem_cap: usize,
}

impl std::fmt::Debug for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Principal")
            .field("id", &self.id)
            .field("verifiers", &self.verifiers.len())
            .finish()
    }
}

pub struct Route {
    pub id: Id,
    pub upstream: Upstream,
    /// `Bearer <secret>`, marked sensitive so a Debug print shows nothing.
    pub(crate) upstream_authorization: HeaderValue,
    principals: Vec<Principal>,
    pub(crate) allowed_origins: Vec<String>,
    pub(crate) allow_private: bool,
    pub(crate) sem: Arc<Semaphore>,
    sem_cap: usize,
    /// Effective limits of this route: `min(local, remote)` per field.
    pub(crate) limits: Limits,
    pub(crate) scope: Option<Arc<RouteScope>>,
    pub(crate) binding: Arc<Binding>,
}

impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route")
            .field("id", &self.id)
            .field("upstream", &self.upstream)
            .field("principals", &self.principals)
            .field("allowed_origins", &self.allowed_origins)
            .finish_non_exhaustive()
    }
}

impl Route {
    /// Verify a bearer token against every verifier of every principal of this
    /// route (PX-008, AC-04). The work does not depend on which verifier
    /// matches or on whether any does: no early exit.
    pub fn authenticate(&self, token: &str) -> Option<&Principal> {
        self.authenticate_at(token, unix_now())
    }

    /// [`Route::authenticate`] with an explicit clock (unix seconds). A verifier
    /// whose `not_after` has been reached never matches; the hash work is done
    /// for it anyway so expiry is not a timing signal.
    pub fn authenticate_at(&self, token: &str, now: i64) -> Option<&Principal> {
        let mut matched = 0u8;
        let mut idx = 0usize;
        for (i, p) in self.principals.iter().enumerate() {
            for v in &p.verifiers {
                let live = v.not_after.is_none_or(|t| now < t) as u8;
                let ok = sigil_proxy_api::verify(token, &v.verifier) as u8 & live;
                // Keep the first match without a secret-dependent branch.
                let take = ok & (1 ^ matched);
                let mask = 0usize.wrapping_sub(take as usize);
                idx = (idx & !mask) | (i & mask);
                matched |= ok;
            }
        }
        if matched == 1 {
            self.principals.get(idx)
        } else {
            None
        }
    }

    /// Effective per-route limits.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn origin_allowed(&self, normalized_origin: &str) -> bool {
        self.allowed_origins.iter().any(|o| o == normalized_origin)
    }

    /// The session binding of this route (T-12b2).
    pub fn binding(&self) -> &Arc<Binding> {
        &self.binding
    }

    /// The inventory scope of this route, if it came from an applied config.
    pub fn scope(&self) -> Option<&Arc<RouteScope>> {
        self.scope.as_ref()
    }
}

#[derive(Debug)]
pub struct RouteTable {
    routes: HashMap<String, Route>,
    has_verifier: bool,
    /// The applied config revision this table was built from (`route_revision`
    /// of every call it routes). `None` outside a config sync: such calls cannot
    /// be audited.
    revision: Option<sigil_proxy_api::PositiveI64>,
}

impl RouteTable {
    /// The single constructor the config-apply slice will call. Validates the
    /// whole input and fails as a whole (no partial table, control-plane.md
    /// §6.2 "Atomic apply"). Reads each referenced secret through the
    /// owner-only reader; secrets are never logged or put in errors.
    pub fn build(
        specs: &[RouteSpec],
        credentials: &BTreeMap<String, Credential>,
        limits: &Limits,
    ) -> Result<RouteTable, RouteError> {
        Self::build_carrying(specs, credentials, limits, None)
    }

    /// [`RouteTable::build`], reusing the admission semaphores of `prev` for every
    /// route and principal that keeps its id and its limit. Without this, an apply
    /// (including a same-revision rebuild) would give each route a fresh set of
    /// permits while calls admitted under the old table still hold theirs, so a
    /// route could briefly run up to twice `max_calls_per_route`.
    pub fn build_carrying(
        specs: &[RouteSpec],
        credentials: &BTreeMap<String, Credential>,
        limits: &Limits,
        prev: Option<&RouteTable>,
    ) -> Result<RouteTable, RouteError> {
        let route_cap = limits.max_calls_per_route as usize;
        let principal_cap = limits.max_calls_per_principal as usize;
        let mut secrets: HashMap<&str, Vec<u8>> = HashMap::new();
        let mut principal_sems: HashMap<String, Arc<Semaphore>> = HashMap::new();
        let mut routes = HashMap::new();
        let mut has_verifier = false;

        for spec in specs {
            let rid = spec.route_id.as_str().to_string();
            if routes.contains_key(&rid) {
                return Err(RouteError::DuplicateRoute(rid));
            }
            let (upstream, origin) =
                parse_upstream(&spec.upstream_url).map_err(|reason| RouteError::UpstreamUrl {
                    route: rid.clone(),
                    reason,
                })?;
            let cred = credentials.get(&spec.credential_ref).ok_or_else(|| {
                RouteError::UnknownCredential {
                    route: rid.clone(),
                    reference: spec.credential_ref.clone(),
                }
            })?;
            // N-1: the ref may only be sent to its bound origins.
            if !cred.upstream_origins.contains(&origin) {
                return Err(RouteError::CredentialOrigin {
                    route: rid,
                    reference: spec.credential_ref.clone(),
                });
            }
            if !secrets.contains_key(spec.credential_ref.as_str()) {
                let raw = crate::fsutil::read_private_file(&cred.secret_file).map_err(|e| {
                    RouteError::Secret {
                        reference: spec.credential_ref.clone(),
                        reason: e.kind().to_string(),
                    }
                })?;
                secrets.insert(spec.credential_ref.as_str(), raw);
            }
            let upstream_authorization = bearer_value(&secrets[spec.credential_ref.as_str()])
                .ok_or_else(|| RouteError::Secret {
                    reference: spec.credential_ref.clone(),
                    reason: "secret is empty or not a valid header value".into(),
                })?;

            let mut allowed_origins = Vec::new();
            for o in &spec.allowed_origins {
                let n = normalize_origin(o).map_err(|reason| RouteError::AllowedOrigin {
                    route: rid.clone(),
                    reason,
                })?;
                if !allowed_origins.contains(&n) {
                    allowed_origins.push(n);
                }
            }

            let mut principals = Vec::new();
            for p in &spec.principals {
                for v in &p.verifiers {
                    let v = &v.verifier;
                    if v.len() != 64 || !v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                        return Err(RouteError::Verifier { route: rid.clone() });
                    }
                }
                if !p.verifiers.is_empty() {
                    has_verifier = true;
                }
                let sem = principal_sems
                    .entry(p.principal_id.as_str().to_string())
                    .or_insert_with(|| {
                        prev.and_then(|t| t.principal_sem(p.principal_id.as_str(), principal_cap))
                            .unwrap_or_else(|| Arc::new(Semaphore::new(principal_cap)))
                    })
                    .clone();
                principals.push(Principal {
                    id: p.principal_id.clone(),
                    actor: Actor {
                        actor_id: p.principal_id.clone(),
                        actor_kind: match p.actor_kind {
                            Some(ConfigActorKind::NonHuman) => ActorKind::NonHuman,
                            Some(ConfigActorKind::Unknown) | None => ActorKind::Unknown,
                        },
                        authentication_method: AuthenticationMethod::Bearer,
                        evidence_source: EvidenceSource::ProxyCredentialMapping,
                        credential_owner_id: p.credential_owner_id.clone(),
                    },
                    verifiers: p.verifiers.clone(),
                    sem,
                    sem_cap: principal_cap,
                });
            }

            let binding = Arc::new(Binding {
                scope: spec.scope.clone(),
                endpoint: format!(
                    "{}://{}:{}{}",
                    if upstream.https { "https" } else { "http" },
                    upstream.host,
                    upstream.port,
                    upstream.path
                ),
                credential_ref: spec.credential_ref.clone(),
            });
            routes.insert(
                rid,
                Route {
                    id: spec.route_id.clone(),
                    upstream,
                    upstream_authorization,
                    principals,
                    allowed_origins,
                    allow_private: spec.allow_private_destination,
                    sem: prev
                        .and_then(|t| t.routes.get(spec.route_id.as_str()))
                        .filter(|r| r.sem_cap == route_cap)
                        .map_or_else(|| Arc::new(Semaphore::new(route_cap)), |r| r.sem.clone()),
                    sem_cap: route_cap,
                    limits: limits.lowered_by(&spec.limits),
                    scope: spec.scope.clone().map(Arc::new),
                    binding,
                },
            );
        }
        Ok(RouteTable {
            routes,
            has_verifier,
            revision: None,
        })
    }

    /// Record the applied config revision this table serves (the config sync).
    pub fn with_revision(mut self, revision: sigil_proxy_api::PositiveI64) -> RouteTable {
        self.revision = Some(revision);
        self
    }

    pub fn revision(&self) -> Option<sigil_proxy_api::PositiveI64> {
        self.revision
    }

    /// The semaphore of principal `id` in this table, if its capacity is `cap`.
    fn principal_sem(&self, id: &str, cap: usize) -> Option<Arc<Semaphore>> {
        self.routes
            .values()
            .flat_map(|r| r.principals.iter())
            .find(|p| p.id.as_str() == id && p.sem_cap == cap)
            .map(|p| p.sem.clone())
    }

    pub fn route(&self, id: &str) -> Option<&Route> {
        self.routes.get(id)
    }

    /// True when at least one principal has a verifier. Until then the
    /// listener answers 401 to everything (decisions.md "P0 종료", T-12).
    pub fn has_verifier(&self) -> bool {
        self.has_verifier
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn bearer_value(secret: &[u8]) -> Option<HeaderValue> {
    let s = std::str::from_utf8(secret).ok()?.trim();
    if s.is_empty() {
        return None;
    }
    let mut v = HeaderValue::from_str(&format!("Bearer {s}")).ok()?;
    v.set_sensitive(true);
    Some(v)
}

/// Parse `scheme://host[:port][/path]` with no userinfo, query or fragment.
/// Returns the upstream and its normalized origin (via [`normalize_origin`], so
/// a plain-http origin must be a loopback host).
fn parse_upstream(url: &str) -> Result<(Upstream, String), String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or("must be scheme://host[:port]/path")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err("scheme must be http or https".into());
    }
    if rest.contains(['?', '#', '@']) {
        return Err("userinfo, query and fragment are not allowed".into());
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if path
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'\\')
    {
        return Err("invalid character in path".into());
    }
    path.parse::<http::uri::PathAndQuery>()
        .map_err(|_| "invalid path".to_string())?;
    let origin = normalize_origin(&format!("{scheme}://{authority}"))?;
    let (host, port) = split_host_port(authority)?;
    let https = scheme == "https";
    let port = port.unwrap_or(if https { 443 } else { 80 });
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(&host)
        .to_string();
    let host_literal = bare.parse::<IpAddr>().ok();
    let default_port = if https { 443 } else { 80 };
    let host_header = if port == default_port {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    Ok((
        Upstream {
            https,
            host: bare,
            port,
            path: path.to_string(),
            host_literal,
            host_header,
        },
        origin,
    ))
}

/// Holder for the applied table. The config slice swaps it atomically; `None`
/// means no config has been applied, and every request is answered 401.
///
/// The table carries its own expiry deadline (a monotonic instant), checked on
/// every [`TableHandle::current`]. Expiry therefore does not depend on any
/// background task: if the sync task dies, the last table still stops serving at
/// its deadline (fail closed, control-plane.md §6.3).
#[derive(Clone, Default)]
pub struct TableHandle(Arc<RwLock<Slot>>);

#[derive(Default)]
struct Slot {
    table: Option<Arc<RouteTable>>,
    /// `None`: no expiry (tests and callers that manage expiry themselves).
    deadline: Option<tokio::time::Instant>,
}

impl TableHandle {
    pub fn new() -> Self {
        Self::default()
    }
    /// Install (or remove) a table without an expiry deadline.
    pub fn set(&self, table: Option<RouteTable>) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = Slot {
            table: table.map(Arc::new),
            deadline: None,
        };
    }
    /// Install a table that stops being returned by [`TableHandle::current`] at
    /// `deadline`.
    pub fn set_with_deadline(&self, table: RouteTable, deadline: tokio::time::Instant) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = Slot {
            table: Some(Arc::new(table)),
            deadline: Some(deadline),
        };
    }
    /// Move the deadline of the installed table (a TTL refresh). No-op when no
    /// table is installed.
    pub fn extend_deadline(&self, deadline: tokio::time::Instant) {
        let mut g = self.0.write().unwrap_or_else(|e| e.into_inner());
        if g.table.is_some() {
            g.deadline = Some(deadline);
        }
    }
    /// The table to serve with, or `None` when there is none or its deadline has
    /// been reached.
    pub fn current(&self) -> Option<Arc<RouteTable>> {
        let g = self.0.read().unwrap_or_else(|e| e.into_inner());
        if g.deadline.is_some_and(|d| tokio::time::Instant::now() >= d) {
            return None;
        }
        g.table.clone()
    }
    /// The installed table regardless of its deadline. Only for carrying
    /// admission state over to the next table; never for serving.
    pub(crate) fn last(&self) -> Option<Arc<RouteTable>> {
        self.0
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .table
            .clone()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn cred(dir: &std::path::Path, mode: u32, origins: &[&str]) -> BTreeMap<String, Credential> {
        let p = dir.join("secret");
        std::fs::write(&p, "UPSTREAM-SECRET-VALUE\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        BTreeMap::from([(
            "ref1".to_string(),
            Credential {
                secret_file: p,
                upstream_origins: origins.iter().map(|s| s.to_string()).collect(),
            },
        )])
    }

    fn spec(url: &str) -> RouteSpec {
        RouteSpec {
            route_id: Id::new("a").unwrap(),
            upstream_url: url.into(),
            credential_ref: "ref1".into(),
            principals: vec![PrincipalSpec::new(
                Id::new("p1").unwrap(),
                vec![sigil_proxy_api::verifier_for("tok-1").into()],
            )],
            allowed_origins: vec![],
            allow_private_destination: false,
            limits: RemoteLimits::default(),
            scope: None,
        }
    }

    fn build(url: &str, origins: &[&str]) -> Result<RouteTable, RouteError> {
        let d = tempfile::tempdir().unwrap();
        RouteTable::build(
            &[spec(url)],
            &cred(d.path(), 0o600, origins),
            &Limits::default(),
        )
    }

    /// AC-08 / PX-014: the credential only goes to its bound origin.
    #[test]
    fn credential_origin_binding() {
        assert!(build("https://api.example.com/mcp", &["https://api.example.com"]).is_ok());
        // default port is normalized away on both sides
        assert!(build(
            "https://api.example.com:443/mcp",
            &["https://api.example.com"]
        )
        .is_ok());
        let e = build("https://evil.example.com/mcp", &["https://api.example.com"]).unwrap_err();
        assert!(matches!(e, RouteError::CredentialOrigin { .. }), "{e}");
        let e = build(
            "https://api.example.com:8443/mcp",
            &["https://api.example.com"],
        )
        .unwrap_err();
        assert!(matches!(e, RouteError::CredentialOrigin { .. }), "{e}");
    }

    /// AC-08: http only for loopback hosts, no userinfo/query/fragment.
    #[test]
    fn upstream_url_rules() {
        assert!(build("http://127.0.0.1:9000/mcp", &["http://127.0.0.1:9000"]).is_ok());
        assert!(build("http://localhost:9000/mcp", &["http://localhost:9000"]).is_ok());
        for bad in [
            "http://10.0.0.5:9000/mcp",
            "http://api.example.com/mcp",
            "https://u:p@api.example.com/mcp",
            "https://api.example.com/mcp?key=v",
            "https://api.example.com/mcp#f",
            "ftp://api.example.com/mcp",
            "api.example.com/mcp",
        ] {
            let e = build(bad, &["https://api.example.com"]).unwrap_err();
            assert!(matches!(e, RouteError::UpstreamUrl { .. }), "{bad}: {e}");
        }
    }

    /// PX-009: unknown ref, group-readable secret and bad verifier fail the build;
    /// no error text carries the secret.
    #[test]
    fn build_failures_do_not_leak_the_secret() {
        let d = tempfile::tempdir().unwrap();
        let c = cred(d.path(), 0o644, &["https://api.example.com"]);
        let e = RouteTable::build(&[spec("https://api.example.com/m")], &c, &Limits::default())
            .unwrap_err();
        assert!(matches!(e, RouteError::Secret { .. }));
        assert!(!format!("{e} {e:?}").contains("UPSTREAM-SECRET"));

        let d = tempfile::tempdir().unwrap();
        let c = cred(d.path(), 0o600, &["https://api.example.com"]);
        let mut s = spec("https://api.example.com/m");
        s.credential_ref = "missing".into();
        assert!(matches!(
            RouteTable::build(&[s], &c, &Limits::default()).unwrap_err(),
            RouteError::UnknownCredential { .. }
        ));
        let mut s = spec("https://api.example.com/m");
        s.principals[0].verifiers = vec!["ABC".into()];
        assert!(matches!(
            RouteTable::build(&[s], &c, &Limits::default()).unwrap_err(),
            RouteError::Verifier { .. }
        ));
        let t = RouteTable::build(&[spec("https://api.example.com/m")], &c, &Limits::default())
            .unwrap();
        assert!(!format!("{t:?}").contains("UPSTREAM-SECRET"));
    }

    #[test]
    fn allowed_origins_are_normalized() {
        let d = tempfile::tempdir().unwrap();
        let c = cred(d.path(), 0o600, &["https://api.example.com"]);
        let mut s = spec("https://api.example.com/m");
        s.allowed_origins = vec![
            "HTTPS://App.Example.com:443".into(),
            "http://localhost:80".into(),
        ];
        let t = RouteTable::build(&[s], &c, &Limits::default()).unwrap();
        let r = t.route("a").unwrap();
        assert!(r.origin_allowed("https://app.example.com"));
        assert!(r.origin_allowed("http://localhost"));
        assert!(!r.origin_allowed("https://other.example.com"));
        let mut s = spec("https://api.example.com/m");
        s.allowed_origins = vec!["http://app.example.com".into()];
        assert!(matches!(
            RouteTable::build(&[s], &c, &Limits::default()).unwrap_err(),
            RouteError::AllowedOrigin { .. }
        ));
    }

    /// AC-04: a token verifies only on its own route; a route without
    /// principals authenticates nobody.
    #[test]
    fn authenticate_is_per_route() {
        let t = build("https://api.example.com/m", &["https://api.example.com"]).unwrap();
        let r = t.route("a").unwrap();
        assert_eq!(r.authenticate("tok-1").unwrap().id.as_str(), "p1");
        assert!(r.authenticate("tok-2").is_none());
        assert!(r.authenticate("").is_none());
        assert!(t.has_verifier());
    }

    /// #260: `not_after` is enforced per verifier, so a two-verifier overlap
    /// works: the old one stops at its deadline, the new one keeps working.
    #[test]
    fn not_after_is_enforced_per_verifier() {
        let d = tempfile::tempdir().unwrap();
        let c = cred(d.path(), 0o600, &["https://api.example.com"]);
        let mut s = spec("https://api.example.com/m");
        s.principals[0].verifiers = vec![
            VerifierSpec {
                verifier: sigil_proxy_api::verifier_for("old"),
                not_after: Some(1_000),
            },
            VerifierSpec {
                verifier: sigil_proxy_api::verifier_for("new"),
                not_after: None,
            },
        ];
        let t = RouteTable::build(&[s], &c, &Limits::default()).unwrap();
        let r = t.route("a").unwrap();
        // overlap: both work
        assert!(r.authenticate_at("old", 999).is_some());
        assert!(r.authenticate_at("new", 999).is_some());
        // at the deadline the old one is already expired; the new one stays
        assert!(r.authenticate_at("old", 1_000).is_none());
        assert!(r.authenticate_at("old", 5_000).is_none());
        assert!(r.authenticate_at("new", 5_000).is_some());
        // real clock: a deadline in the past rejects, a far one accepts
        let mut s = spec("https://api.example.com/m");
        s.principals[0].verifiers = vec![
            VerifierSpec {
                verifier: sigil_proxy_api::verifier_for("gone"),
                not_after: Some(1),
            },
            VerifierSpec {
                verifier: sigil_proxy_api::verifier_for("live"),
                not_after: Some(i64::MAX),
            },
        ];
        let t = RouteTable::build(&[s], &c, &Limits::default()).unwrap();
        let r = t.route("a").unwrap();
        assert!(r.authenticate("gone").is_none());
        assert!(r.authenticate("live").is_some());
    }

    /// #260: remote route limits only lower the local ones.
    #[test]
    fn route_limits_are_min_of_local_and_remote() {
        let d = tempfile::tempdir().unwrap();
        let c = cred(d.path(), 0o600, &["https://api.example.com"]);
        let local = Limits {
            max_request_body_bytes: 1000,
            call_timeout_secs: 60,
            ..Limits::default()
        };
        let mut s = spec("https://api.example.com/m");
        s.limits = RemoteLimits {
            max_request_bytes: Some(50),
            max_response_bytes: None,
            request_timeout_seconds: Some(600),
        };
        let t = RouteTable::build(&[s], &c, &local).unwrap();
        let l = t.route("a").unwrap().limits();
        assert_eq!(l.max_request_body_bytes, 50);
        assert_eq!(l.call_timeout_secs, 60);
        assert_eq!(l.max_json_response_bytes, local.max_json_response_bytes);
    }

    /// Expiry does not depend on a background task: `current()` itself stops
    /// returning the table at its deadline.
    #[test]
    fn current_returns_none_after_the_deadline_without_any_task() {
        let t = RouteTable::build(&[], &BTreeMap::new(), &Limits::default()).unwrap();
        let h = TableHandle::new();
        let d = tokio::time::Instant::now() + std::time::Duration::from_millis(60);
        h.set_with_deadline(t, d);
        assert!(h.current().is_some());
        std::thread::sleep(std::time::Duration::from_millis(120));
        assert!(h.current().is_none(), "served past its deadline");
        // the slot still holds it for admission carry-over, never for serving
        assert!(h.last().is_some());
        // extending a held table does not resurrect an expired view unless the
        // deadline moves past now
        h.extend_deadline(tokio::time::Instant::now() + std::time::Duration::from_secs(60));
        assert!(h.current().is_some());
        // no table: extend is a no-op
        let e = TableHandle::new();
        e.extend_deadline(tokio::time::Instant::now() + std::time::Duration::from_secs(60));
        assert!(e.current().is_none());
    }

    /// A rebuild keeps the permits of unchanged routes and principals, so an
    /// apply cannot double the admission limits.
    #[test]
    fn rebuild_carries_semaphores_over() {
        let d = tempfile::tempdir().unwrap();
        let c = cred(d.path(), 0o600, &["https://api.example.com"]);
        let local = Limits::default();
        let a = RouteTable::build(&[spec("https://api.example.com/m")], &c, &local).unwrap();
        let b =
            RouteTable::build_carrying(&[spec("https://api.example.com/m")], &c, &local, Some(&a))
                .unwrap();
        let (ra, rb) = (a.route("a").unwrap(), b.route("a").unwrap());
        assert!(Arc::ptr_eq(&ra.sem, &rb.sem), "route semaphore not carried");
        assert!(
            Arc::ptr_eq(&ra.principals[0].sem, &rb.principals[0].sem),
            "principal semaphore not carried"
        );
        // a held permit is visible through the new table
        let _held = ra.sem.clone().try_acquire_owned().unwrap();
        assert_eq!(
            rb.sem.available_permits(),
            local.max_calls_per_route as usize - 1
        );
        // a changed limit gets a fresh semaphore
        let lower = Limits {
            max_calls_per_route: 2,
            max_calls_per_principal: 2,
            ..Limits::default()
        };
        let n =
            RouteTable::build_carrying(&[spec("https://api.example.com/m")], &c, &lower, Some(&a))
                .unwrap();
        let rn = n.route("a").unwrap();
        assert!(!Arc::ptr_eq(&ra.sem, &rn.sem));
        assert!(!Arc::ptr_eq(&ra.principals[0].sem, &rn.principals[0].sem));
        assert_eq!(rn.sem.available_permits(), 2);
        // a different route id gets a fresh one
        let mut other = spec("https://api.example.com/m");
        other.route_id = Id::new("b").unwrap();
        let o = RouteTable::build_carrying(&[other], &c, &local, Some(&a)).unwrap();
        assert!(!Arc::ptr_eq(&ra.sem, &o.route("b").unwrap().sem));
    }
}
