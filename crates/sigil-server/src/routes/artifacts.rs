//! #182 — read-only signed-artifact serving. Lets an air-gapped PMS pull the
//! agent release files (tarballs/zips, `.deb`/`.rpm`, `SHA256SUMS`,
//! `build-manifest.json`) from the sigil-server it already runs, instead of
//! GitHub Releases. The files are operator-populated and already signed +
//! checksummed; the server only serves them read-only, gated by the read-API
//! bearer token. `artifacts_dir` unset ⇒ every artifact route 404s.

use crate::app::SharedState;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// `GET /v1/artifacts` — JSON index of the available artifact filenames.
pub async fn get_artifacts_index(State(state): State<SharedState>) -> Response {
    let Some(dir) = state.artifacts_dir.as_ref() else {
        return not_configured();
    };
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            tracing::error!(error = ?e, dir = %dir.display(), "read artifacts dir failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": {"code": "artifacts_read_failed", "message": "could not list artifacts"}})),
            )
                .into_response();
        }
    };
    let mut names: Vec<String> = rd
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| is_safe_name(n))
        .collect();
    names.sort();
    (StatusCode::OK, Json(json!({ "artifacts": names }))).into_response()
}

/// `GET /v1/artifacts/:filename` — stream one artifact file.
pub async fn get_artifact_by_name(
    State(state): State<SharedState>,
    Path(name): Path<String>,
) -> Response {
    let Some(dir) = state.artifacts_dir.as_ref() else {
        return not_configured();
    };
    if !is_safe_name(&name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": {"code": "bad_filename", "message": "filename must match ^[A-Za-z0-9._-]+$"}})),
        )
            .into_response();
    }
    // is_safe_name already excludes path separators and `..`; the
    // canonical-containment check below is belt-and-suspenders (e.g. a symlink
    // inside the dir pointing out).
    let canonical = match std::fs::canonicalize(dir.join(&name)) {
        Ok(p) => p,
        Err(_) => return artifact_not_found(&name),
    };
    let dir_canonical = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.clone());
    if !canonical.starts_with(&dir_canonical) || !canonical.is_file() {
        return artifact_not_found(&name);
    }
    let file = match tokio::fs::File::open(&canonical).await {
        Ok(f) => f,
        Err(_) => return artifact_not_found(&name),
    };
    let len = file.metadata().await.ok().map(|m| m.len());
    let body = Body::from_stream(tokio_util::io::ReaderStream::new(file));

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    // `name` is is_safe_name-validated ([A-Za-z0-9._-]), so it cannot inject a
    // header; the parse is infallible for that charset but handled defensively.
    if let Ok(v) = format!("attachment; filename=\"{name}\"").parse() {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    if let Some(len) = len {
        if let Ok(v) = len.to_string().parse() {
            headers.insert(header::CONTENT_LENGTH, v);
        }
    }
    (StatusCode::OK, headers, body).into_response()
}

/// Accept only a bare filename: no path separators, no `..`, ASCII
/// `[A-Za-z0-9._-]`. Covers every real release artifact name
/// (`sigil-<ver>-<target>.tar.gz`/`.zip`, `*.deb`, `*.rpm`, `SHA256SUMS`,
/// `build-manifest.json`) and rejects traversal.
fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": {"code": "artifacts_not_configured", "message": "artifact serving is not enabled"}})),
    )
        .into_response()
}

fn artifact_not_found(name: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": {"code": "artifact_not_found", "message": format!("no artifact named {name}")}})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::is_safe_name;

    #[test]
    fn accepts_real_artifact_names() {
        for n in [
            "sigil-0.6.2-aarch64-unknown-linux-musl.tar.gz",
            "sigil-0.6.2-aarch64-pc-windows-msvc.zip",
            "sigil_0.6.2-1_arm64.deb",
            "sigil-0.6.2-1.aarch64.rpm",
            "SHA256SUMS",
            "build-manifest.json",
        ] {
            assert!(is_safe_name(n), "should accept {n}");
        }
    }

    #[test]
    fn rejects_traversal_and_separators() {
        for n in [
            "",
            ".",
            "..",
            "../etc/passwd",
            "a/b",
            "a\\b",
            "foo/../bar",
            "a b",
            "name\0",
        ] {
            assert!(!is_safe_name(n), "should reject {n:?}");
        }
    }
}
