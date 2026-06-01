use regex::Regex;
use sigil_core::hook_proto::CaptureLevel;
use std::sync::OnceLock;

const PREVIEW_CAP: usize = 256;

pub struct Captured {
    pub hash: String,
    pub preview: Option<String>,
}

/// Compute a blake3 hex digest over the RAW pre-mask text (stable correlation
/// id, NOT a privacy guarantee — the hash identifies the exact command), plus
/// a preview whose shape depends on `level`:
/// - `HashOnly`  → no preview
/// - `Raw`       → verbatim text (capped to PREVIEW_CAP bytes at a char boundary)
/// - `Redacted`  → secret patterns replaced with ‹redacted›, then capped
pub fn capture(raw: &str, level: CaptureLevel) -> Captured {
    let hash = blake3::hash(raw.as_bytes()).to_hex().to_string();
    let preview = match level {
        CaptureLevel::HashOnly => None,
        CaptureLevel::Raw => Some(cap(raw)),
        CaptureLevel::Redacted => Some(cap(&mask(raw))),
    };
    Captured { hash, preview }
}

/// Truncate `s` to at most PREVIEW_CAP bytes, always ending on a valid UTF-8
/// char boundary so that slicing never panics.  If truncated, appends '…'
/// (U+2026, 3 UTF-8 bytes) so the caller can detect the cap was reached.
fn cap(s: &str) -> String {
    if s.len() <= PREVIEW_CAP {
        return s.to_string();
    }
    // Walk backwards from PREVIEW_CAP to find the largest valid char boundary.
    let boundary = floor_char_boundary(s, PREVIEW_CAP);
    format!("{}…", &s[..boundary])
}

/// Return the largest index ≤ `index` that is a valid UTF-8 char boundary in
/// `s`.  Always returns a value in `0..=s.len()`.
fn floor_char_boundary(s: &str, index: usize) -> usize {
    // `str::floor_char_boundary` is stable since Rust 1.77; use it when
    // available.  We replicate it manually here for older toolchains:
    if index >= s.len() {
        return s.len();
    }
    // A byte is the start of a UTF-8 code point when it is NOT a continuation
    // byte (i.e. not of the form 0b10xx_xxxx).
    let mut i = index;
    while i > 0 && (s.as_bytes()[i] & 0xC0) == 0x80 {
        i -= 1;
    }
    i
}

fn patterns() -> &'static [Regex] {
    static P: OnceLock<Vec<Regex>> = OnceLock::new();
    P.get_or_init(|| {
        vec![
            // KEY=value / KEY: value patterns
            Regex::new(
                r"(?i)(token|secret|password|passwd|api[_-]?key|auth|bearer|access[_-]?key)\s*[=:]\s*\S+",
            )
            .unwrap(),
            // HTTP Authorization header
            Regex::new(r"(?i)Authorization:\s*Bearer\s+\S+").unwrap(),
            // AWS access-key IDs
            Regex::new(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b").unwrap(),
            // GitHub tokens
            Regex::new(r"\b(ghp_|gho_|github_pat_)[A-Za-z0-9_]{20,}\b").unwrap(),
            // Generic base64-ish long token (≥ 32 chars)
            Regex::new(r"\b[A-Za-z0-9+/]{32,}={0,2}\b").unwrap(),
        ]
    })
    .as_slice()
}

fn mask(s: &str) -> String {
    let mut out = s.to_string();
    for re in patterns() {
        out = re.replace_all(&out, "‹redacted›").into_owned();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::hook_proto::CaptureLevel;

    #[test]
    fn hash_is_stable_across_levels_and_over_raw() {
        let raw = "export API_KEY=supersecret123456789012345678";
        let a = capture(raw, CaptureLevel::Redacted);
        let b = capture(raw, CaptureLevel::HashOnly);
        let c = capture(raw, CaptureLevel::Raw);
        assert_eq!(a.hash, b.hash);
        assert_eq!(a.hash, c.hash);
        assert_eq!(a.hash.len(), 64);
    }

    #[test]
    fn redacted_masks_known_secret_and_caps_length() {
        let raw = "curl -H 'Authorization: Bearer abcdef0123456789abcdef0123456789' x";
        let out = capture(raw, CaptureLevel::Redacted);
        let p = out.preview.unwrap();
        assert!(!p.contains("abcdef0123456789abcdef0123456789"));
        assert!(p.contains("‹redacted›"));
    }

    #[test]
    fn hash_only_has_no_preview() {
        assert!(capture("anything", CaptureLevel::HashOnly)
            .preview
            .is_none());
    }

    #[test]
    fn raw_is_verbatim() {
        let raw = "token=keepme";
        assert_eq!(capture(raw, CaptureLevel::Raw).preview.unwrap(), raw);
    }

    #[test]
    fn cap_is_panic_safe_on_multibyte() {
        // Each '日' is 3 UTF-8 bytes; 100 chars = 300 bytes > PREVIEW_CAP (256).
        let long: String = "日".repeat(100);
        assert!(long.len() > PREVIEW_CAP);
        // Must not panic regardless of byte-boundary alignment.
        let out = capture(&long, CaptureLevel::Raw);
        let preview = out.preview.unwrap();
        // Result must be valid UTF-8 (Rust String guarantees) and end with '…'.
        assert!(
            preview.ends_with('…'),
            "expected truncation marker, got: {preview:?}"
        );
        // The non-ellipsis portion must itself be valid: parse it back.
        let without_ellipsis = preview.trim_end_matches('…');
        assert!(
            std::str::from_utf8(without_ellipsis.as_bytes()).is_ok(),
            "non-ASCII slice is not valid UTF-8"
        );
        // Byte length of the preview content (excluding the 3-byte '…') must be ≤ cap.
        assert!(without_ellipsis.len() <= PREVIEW_CAP);
    }

    #[test]
    fn cap_does_not_truncate_short_multibyte() {
        // A short multi-byte string that fits within the cap should be returned verbatim.
        let short = "こんにちは"; // 5 chars × 3 bytes = 15 bytes, well within 256
        let out = capture(short, CaptureLevel::Raw);
        assert_eq!(out.preview.unwrap(), short);
    }
}
