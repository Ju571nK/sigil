//! #184 — `POST /v1/enroll` (B-mint). Signs a host CSR into a per-host mTLS
//! CLIENT cert using the operator's intermediate CA, gated by a single-use,
//! TTL, per-host enrollment token.
//!
//! Auth: NO read-bearer layer — the enroll token in the body is the credential;
//! mTLS still gates at the TLS layer (PMS-mediated). Feature off ⇒ 404.
//!
//! COMMIT ORDER (codex-hardened, prevents double-mint):
//!   lock mint Mutex
//!   → validate (UUID host_id, CSR size/PEM, CSR CN == host_id)
//!   → RESERVE the token (durably stamp used_at + write) BEFORE signing
//!   → sign (openssl, fixed profile, random serial, post-sign inspection)
//!   → allowlist add (atomic file)
//!   → audit append (signed, fsync, FAIL-CLOSED)
//!   → 200 with cert.
//! Any failure AFTER reserve ⇒ 500 and NO cert (token is spent; operator
//! re-issues). The token is never signed against twice.
//!
//! External error generalization: every token failure (expired/used/mismatch/
//! not-found) returns a single `403 {"error":{"code":"enrollment_denied"}}`.
//! The specific reason is logged + audited internally. 404 (off) and 400
//! (malformed) stay distinct.

use crate::app::SharedState;
use crate::enroll::audit;
use crate::enroll::sign::{self, SignError};
use crate::enroll::tokens::{RedeemErr, TokenStore};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize)]
pub struct EnrollReq {
    pub token: String,
    pub host_id: String,
    pub csr_pem: String,
}

pub async fn post_enroll(State(st): State<SharedState>, Json(req): Json<EnrollReq>) -> Response {
    // Feature off ⇒ 404 (indistinguishable from "route absent").
    let Some(en) = st.enroll.as_ref() else {
        return err(
            StatusCode::NOT_FOUND,
            "enroll_not_configured",
            "enrollment is not enabled",
        );
    };

    // Input validation (distinct 400, before touching any token).
    if uuid::Uuid::parse_str(&req.host_id).is_err() {
        return err(StatusCode::BAD_REQUEST, "bad_request", "host_id must be a UUID");
    }
    if req.token.is_empty() {
        return err(StatusCode::BAD_REQUEST, "bad_request", "missing token");
    }
    if req.csr_pem.len() > sign::MAX_CSR_BYTES {
        return err(StatusCode::BAD_REQUEST, "bad_request", "csr too large");
    }

    let now = time::OffsetDateTime::now_utc();
    let ts = now
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let csr_fp = audit::fingerprint(req.csr_pem.as_bytes());

    // Serialize the entire mint critical section across requests.
    let _mint = match en.mint.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(), // poisoned: proceed (no shared mutable state held)
    };

    // 1. CSR sanity: parse + verify the CSR, extract CN, require CN == host_id.
    let cn = match sign::csr_cn(&en.openssl_path, &req.csr_pem) {
        Ok(c) => c,
        Err(SignError::BadCsr(_)) => {
            return err(StatusCode::BAD_REQUEST, "bad_request", "invalid csr");
        }
        Err(e) => {
            tracing::error!(error = %e, "enroll: csr parse failed");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "sign_failed", "csr inspect failed");
        }
    };
    if cn != req.host_id {
        // CN mismatch is a token-scope denial → generic enrollment_denied.
        record_denied(&st, en, &req.host_id, "cn_mismatch", &csr_fp, &ts);
        return enrollment_denied();
    }

    // 2. Pre-check the token (cheap, gives the specific internal reason).
    if let Err(e) = TokenStore::check(&en.tokens_path, &req.token, &req.host_id, now) {
        let reason = denial_reason(&e);
        record_denied(&st, en, &req.host_id, reason, &csr_fp, &ts);
        // I/O errors are a server fault (500); everything else is a denial.
        if let RedeemErr::Io(msg) = &e {
            tracing::error!(error = %msg, "enroll: token store read failed");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "sign_failed", "token store error");
        }
        return enrollment_denied();
    }

    // 3. RESERVE the token (durable used_at stamp) BEFORE signing. After this
    //    point the token is spent; any failure ⇒ 500 + no cert (safe re-issue).
    if let Err(e) = TokenStore::mark_used(&en.tokens_path, &req.token, &req.host_id, now) {
        let reason = denial_reason(&e);
        record_denied(&st, en, &req.host_id, reason, &csr_fp, &ts);
        if matches!(e, RedeemErr::Io(_)) {
            tracing::error!(error = %e, "enroll: token reserve write failed");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "sign_failed", "token reserve failed");
        }
        // Lost a race (used/expired since check): still a denial.
        return enrollment_denied();
    }

    // 4. Sign.
    let cert = match sign::sign_csr(
        &en.openssl_path,
        &en.ca_cert_path,
        &en.ca_key_path,
        &req.csr_pem,
        &req.host_id,
        en.cert_days,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, host_id = %req.host_id, "enroll: signing failed (token already spent)");
            record_denied(&st, en, &req.host_id, "sign_failed", &csr_fp, &ts);
            return err(StatusCode::INTERNAL_SERVER_ERROR, "sign_failed", "signing failed");
        }
    };
    let cert_fp = audit::fingerprint(cert.as_bytes());
    let (serial, not_after) = sign::issued_meta(&en.openssl_path, &cert);

    // 5. Allowlist add (atomic file). Required — failure ⇒ 500, no cert.
    if let Some(p) = st.allowlist_path.as_ref() {
        if let Err(e) = crate::allowlist::add_host_atomic(p, &req.host_id) {
            tracing::error!(error = %e, "enroll: allowlist add failed (token already spent)");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "sign_failed", "allowlist update failed");
        }
    }

    // 6. Audit append — FAIL-CLOSED. No key ⇒ cannot audit ⇒ 500, no cert.
    let Some(key) = st.audit_key.as_ref() else {
        tracing::error!("enroll: no audit key; refusing to issue without an audit trail");
        return err(StatusCode::INTERNAL_SERVER_ERROR, "sign_failed", "audit unavailable");
    };
    if let Err(e) = audit::append(
        &en.audit_path,
        key,
        &req.host_id,
        "issued",
        "ok",
        &csr_fp,
        &cert_fp,
        &serial,
        &not_after,
        &ts,
    ) {
        tracing::error!(error = %e, "enroll: audit append failed (token already spent)");
        return err(StatusCode::INTERNAL_SERVER_ERROR, "sign_failed", "audit append failed");
    }

    let chain = std::fs::read_to_string(&en.ca_cert_path).unwrap_or_default();
    tracing::info!(host_id = %req.host_id, serial = %serial, "enroll: issued client cert");
    (
        StatusCode::OK,
        Json(json!({
            "client_cert_pem": cert,
            "ca_chain_pem": chain,
            "host_id": req.host_id,
            "not_after": not_after,
            "serial": serial,
        })),
    )
        .into_response()
}

fn denial_reason(e: &RedeemErr) -> &'static str {
    match e {
        RedeemErr::NotFound => "token_not_found",
        RedeemErr::Expired => "token_expired",
        RedeemErr::Used => "token_used",
        RedeemErr::HostMismatch => "host_mismatch",
        RedeemErr::Io(_) => "token_store_io",
    }
}

/// Append a fail-closed-but-best-effort denial audit line. A denial that can't
/// be audited is logged (we still return the denial; we are not issuing a cert).
fn record_denied(
    st: &SharedState,
    en: &crate::enroll::EnrollState,
    host_id: &str,
    reason: &str,
    csr_fp: &str,
    ts: &str,
) {
    let Some(key) = st.audit_key.as_ref() else {
        tracing::warn!(host_id, reason, "enroll: denied (no audit key to record)");
        return;
    };
    if let Err(e) = audit::append(
        &en.audit_path,
        key,
        host_id,
        "denied",
        reason,
        csr_fp,
        "",
        "",
        "",
        ts,
    ) {
        tracing::error!(error = %e, host_id, reason, "enroll: failed to audit denial");
    }
}

fn enrollment_denied() -> Response {
    // Single generic response for ALL token failures (no state leak).
    err(StatusCode::FORBIDDEN, "enrollment_denied", "enrollment denied")
}

fn err(code: StatusCode, body_code: &str, message: &str) -> Response {
    (
        code,
        Json(json!({"error": {"code": body_code, "message": message}})),
    )
        .into_response()
}
