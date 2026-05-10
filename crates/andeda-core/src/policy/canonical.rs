//! Minimal canonical-JSON serializer — RFC 8785 (JCS) subset.
//!
//! Used to produce the byte sequence the policy signing key signs (and
//! agents verify against). The full JCS spec covers many edge cases; this
//! implementation handles the subset that ANDEDA's `SignedEnvelope` exercises:
//!
//! - Object keys sorted lexicographically (UTF-16 code units).
//! - No insignificant whitespace.
//! - String escapes per RFC 8259 §7 with the JCS rule that only `\"`,
//!   `\\`, `\b`, `\f`, `\n`, `\r`, `\t` and `\u00XX` for control chars
//!   are produced.
//! - Numbers serialized as the shortest IEEE-754-roundtrippable form.
//!   For `SignedEnvelope` all numeric fields are integers, so we only
//!   need to handle `i64`.
//! - No NaN, Infinity, or trailing zeros after `.`.
//!
//! Anything outside that subset (floats, arrays of nested objects beyond
//! one level, etc.) returns an error in the `NonIntegerNumeric` variant.

use serde::Serialize;

/// Serialize `value` as canonical JSON bytes (RFC 8785 subset).
pub fn to_canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let v: serde_json::Value = serde_json::to_value(value)?;
    let mut out = Vec::new();
    write_value(&v, &mut out)?;
    Ok(out)
}

/// Errors produced during canonical serialization.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalError {
    /// Underlying serde_json error.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// Numeric value not representable as i64 (the subset this canonicalizer supports).
    #[error("non-integer numeric value not supported: {0}")]
    NonIntegerNumeric(serde_json::Number),
}

fn write_value(v: &serde_json::Value, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    use serde_json::Value::*;
    match v {
        Null => out.extend_from_slice(b"null"),
        Bool(true) => out.extend_from_slice(b"true"),
        Bool(false) => out.extend_from_slice(b"false"),
        Number(n) => {
            if let Some(i) = n.as_i64() {
                out.extend_from_slice(i.to_string().as_bytes());
            } else if let Some(u) = n.as_u64() {
                out.extend_from_slice(u.to_string().as_bytes());
            } else {
                return Err(CanonicalError::NonIntegerNumeric(n.clone()));
            }
        }
        String(s) => write_string(s, out),
        Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Object(map) => {
            // Collect keys + sort by UTF-16 code unit ordering.
            let mut keys: Vec<&str> = map.keys().map(|s| s.as_str()).collect();
            keys.sort_by(|a, b| {
                let av: Vec<u16> = a.encode_utf16().collect();
                let bv: Vec<u16> = b.encode_utf16().collect();
                av.cmp(&bv)
            });
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                write_value(map.get(*k).unwrap(), out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0C}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Doc {
        b: i64,
        a: i64,
        nested: Inner,
    }
    #[derive(Serialize)]
    struct Inner {
        z: String,
        a: i64,
    }

    #[test]
    fn keys_sorted_lexicographically() {
        let d = Doc {
            b: 2,
            a: 1,
            nested: Inner {
                z: "zz".into(),
                a: 5,
            },
        };
        let bytes = to_canonical_bytes(&d).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert_eq!(s, r#"{"a":1,"b":2,"nested":{"a":5,"z":"zz"}}"#);
    }

    #[test]
    fn no_insignificant_whitespace() {
        let d = Doc {
            b: 2,
            a: 1,
            nested: Inner {
                z: "x".into(),
                a: 0,
            },
        };
        let s = String::from_utf8(to_canonical_bytes(&d).unwrap()).unwrap();
        assert!(!s.contains(' '));
        assert!(!s.contains('\n'));
        assert!(!s.contains('\t'));
    }

    #[test]
    fn string_escapes_control_chars() {
        #[derive(Serialize)]
        struct S {
            v: String,
        }
        let s = S {
            v: "tab\there\nnewline\u{01}ctrl".into(),
        };
        let bytes = to_canonical_bytes(&s).unwrap();
        let out = String::from_utf8(bytes).unwrap();
        assert!(out.contains("\\t"));
        assert!(out.contains("\\n"));
        assert!(out.contains("\\u0001"));
    }

    #[test]
    fn integers_serialize_without_decimal_point() {
        #[derive(Serialize)]
        struct N {
            n: i64,
        }
        let s = String::from_utf8(to_canonical_bytes(&N { n: 42 }).unwrap()).unwrap();
        assert_eq!(s, r#"{"n":42}"#);
    }

    #[test]
    fn float_value_returns_error() {
        let v = serde_json::json!({ "n": 1.5 });
        assert!(to_canonical_bytes(&v).is_err());
    }

    #[test]
    fn signed_envelope_canonicalizes_deterministically() {
        use crate::policy::signed_envelope::SignedEnvelope;
        use time::macros::datetime;
        let e = SignedEnvelope {
            policy_version: 7,
            policy_bytes_b64: "AAA=".into(),
            valid_until: datetime!(2026-06-15 0:00 UTC),
            issued_at: datetime!(2026-05-15 8:00 UTC),
        };
        let a = to_canonical_bytes(&e).unwrap();
        let b = to_canonical_bytes(&e).unwrap();
        assert_eq!(a, b);
        let s = String::from_utf8(a).unwrap();
        assert!(s.starts_with(r#"{"issued_at":"#));
        assert!(s.contains(r#""policy_bytes_b64":"AAA=""#));
        assert!(s.contains(r#""policy_version":7"#));
    }
}
