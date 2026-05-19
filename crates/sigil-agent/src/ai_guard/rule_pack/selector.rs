//! Phase 3b.7 — JSONPath subset for rule pack DSL. Strictly Tier 1:
//! top-level key, nested key, object wildcard `*`, array wildcard `[*]`.
//! Rejects recursive descent `..`, filter expressions `[?(...)]`,
//! bracketed string keys `['foo']`, array indices/slices.

use crate::ai_guard::parser::AssessError;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedValue {
    /// "Key" of the match: literal segment for direct path; child name for
    /// object wildcard; `[i]` for array wildcard.
    pub key: String,
    /// Stringified value at the match position.
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Key(String),
    ObjectWildcard,
    ArrayWildcard,
}

#[derive(Debug, Clone)]
pub struct Selector {
    segments: Vec<Segment>,
}

#[derive(Debug, Error)]
pub enum SelectorError {
    #[error("selector must start with '$'")]
    MustStartWithDollar,
    #[error("recursive descent '..' is not supported")]
    RecursiveDescent,
    #[error("filter expression '[?...]' is not supported")]
    FilterExpression,
    #[error("bracketed string keys like ['foo'] are not supported; use .foo")]
    BracketedStringKey,
    #[error("only '[*]' bracket form is supported (no indices, slices)")]
    OnlyArrayWildcard,
    #[error("empty segment after '.'")]
    EmptySegment,
    #[error("unexpected character: {0}")]
    UnexpectedChar(char),
}

impl Selector {
    pub fn parse(s: &str) -> Result<Self, SelectorError> {
        if !s.starts_with('$') {
            return Err(SelectorError::MustStartWithDollar);
        }
        if s.contains("..") {
            return Err(SelectorError::RecursiveDescent);
        }
        if s.contains("[?") {
            return Err(SelectorError::FilterExpression);
        }
        if s.contains("['") {
            return Err(SelectorError::BracketedStringKey);
        }
        let mut segments = Vec::new();
        let mut rest = &s[1..]; // skip '$'
        while !rest.is_empty() {
            if let Some(after_dot) = rest.strip_prefix('.') {
                let end = after_dot.find(['.', '[']).unwrap_or(after_dot.len());
                let segment_str = &after_dot[..end];
                if segment_str.is_empty() {
                    return Err(SelectorError::EmptySegment);
                }
                if segment_str == "*" {
                    segments.push(Segment::ObjectWildcard);
                } else {
                    segments.push(Segment::Key(segment_str.to_string()));
                }
                rest = &after_dot[end..];
            } else if let Some(after_bracket) = rest.strip_prefix("[*]") {
                segments.push(Segment::ArrayWildcard);
                rest = after_bracket;
            } else if rest.starts_with('[') {
                return Err(SelectorError::OnlyArrayWildcard);
            } else {
                return Err(SelectorError::UnexpectedChar(rest.chars().next().unwrap()));
            }
        }
        Ok(Selector { segments })
    }
}

pub fn eval_json(
    text: &str,
    selector_str: &str,
    path: &Path,
) -> Result<Vec<MatchedValue>, AssessError> {
    let value: serde_json::Value = serde_json::from_str(text).map_err(|e| AssessError::Parse {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    let selector = Selector::parse(selector_str).map_err(|e| AssessError::Parse {
        path: path.to_path_buf(),
        message: format!("selector parse: {e}"),
    })?;
    Ok(walk_json(&value, &selector.segments, ""))
}

pub fn eval_toml(
    text: &str,
    selector_str: &str,
    path: &Path,
) -> Result<Vec<MatchedValue>, AssessError> {
    let value: toml::Value = toml::from_str(text).map_err(|e| AssessError::Parse {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    let selector = Selector::parse(selector_str).map_err(|e| AssessError::Parse {
        path: path.to_path_buf(),
        message: format!("selector parse: {e}"),
    })?;
    Ok(walk_toml(&value, &selector.segments, ""))
}

fn walk_json(
    value: &serde_json::Value,
    segments: &[Segment],
    current_key: &str,
) -> Vec<MatchedValue> {
    if segments.is_empty() {
        return vec![MatchedValue {
            key: current_key.to_string(),
            value: stringify_json(value),
        }];
    }
    let (first, rest) = segments.split_first().unwrap();
    let mut out = Vec::new();
    match first {
        Segment::Key(k) => {
            if let Some(child) = value.as_object().and_then(|o| o.get(k)) {
                out.extend(walk_json(child, rest, k));
            }
        }
        Segment::ObjectWildcard => {
            if let Some(obj) = value.as_object() {
                for (child_key, child_val) in obj {
                    // Key is pinned to the wildcard child name; override any
                    // deeper key that walk_json would otherwise surface.
                    let matches = walk_json(child_val, rest, child_key);
                    out.extend(matches.into_iter().map(|mut m| {
                        m.key = child_key.clone();
                        m
                    }));
                }
            }
        }
        Segment::ArrayWildcard => {
            if let Some(arr) = value.as_array() {
                for (i, elem) in arr.iter().enumerate() {
                    let idx_key = format!("[{i}]");
                    // Key is pinned to the index string.
                    let matches = walk_json(elem, rest, &idx_key);
                    out.extend(matches.into_iter().map(|mut m| {
                        m.key = idx_key.clone();
                        m
                    }));
                }
            }
        }
    }
    out
}

fn stringify_json(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "null".to_string(),
        _ => serde_json::to_string(v).unwrap_or_default(),
    }
}

fn walk_toml(value: &toml::Value, segments: &[Segment], current_key: &str) -> Vec<MatchedValue> {
    if segments.is_empty() {
        return vec![MatchedValue {
            key: current_key.to_string(),
            value: stringify_toml(value),
        }];
    }
    let (first, rest) = segments.split_first().unwrap();
    let mut out = Vec::new();
    match first {
        Segment::Key(k) => {
            if let Some(child) = value.as_table().and_then(|t| t.get(k)) {
                out.extend(walk_toml(child, rest, k));
            }
        }
        Segment::ObjectWildcard => {
            if let Some(tbl) = value.as_table() {
                for (child_key, child_val) in tbl {
                    // Key is pinned to the wildcard child name.
                    let matches = walk_toml(child_val, rest, child_key);
                    out.extend(matches.into_iter().map(|mut m| {
                        m.key = child_key.clone();
                        m
                    }));
                }
            }
        }
        Segment::ArrayWildcard => {
            if let Some(arr) = value.as_array() {
                for (i, elem) in arr.iter().enumerate() {
                    let idx_key = format!("[{i}]");
                    // Key is pinned to the index string.
                    let matches = walk_toml(elem, rest, &idx_key);
                    out.extend(matches.into_iter().map(|mut m| {
                        m.key = idx_key.clone();
                        m
                    }));
                }
            }
        }
    }
    out
}

fn stringify_toml(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        toml::Value::Integer(n) => n.to_string(),
        toml::Value::Float(n) => n.to_string(),
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Datetime(d) => d.to_string(),
        _ => toml::to_string(v).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p() -> PathBuf {
        PathBuf::from("/tmp/test")
    }

    #[test]
    fn selector_parse_top_level_key() {
        let s = Selector::parse("$.foo").unwrap();
        assert_eq!(s.segments, vec![Segment::Key("foo".into())]);
    }

    #[test]
    fn selector_parse_nested_key() {
        let s = Selector::parse("$.foo.bar").unwrap();
        assert_eq!(
            s.segments,
            vec![Segment::Key("foo".into()), Segment::Key("bar".into())]
        );
    }

    #[test]
    fn selector_parse_object_wildcard() {
        let s = Selector::parse("$.foo.*").unwrap();
        assert_eq!(
            s.segments,
            vec![Segment::Key("foo".into()), Segment::ObjectWildcard]
        );
    }

    #[test]
    fn selector_parse_object_wildcard_then_key() {
        let s = Selector::parse("$.foo.*.bar").unwrap();
        assert_eq!(
            s.segments,
            vec![
                Segment::Key("foo".into()),
                Segment::ObjectWildcard,
                Segment::Key("bar".into()),
            ]
        );
    }

    #[test]
    fn selector_parse_array_wildcard() {
        let s = Selector::parse("$.foo[*]").unwrap();
        assert_eq!(
            s.segments,
            vec![Segment::Key("foo".into()), Segment::ArrayWildcard]
        );
    }

    #[test]
    fn selector_rejects_recursive_descent() {
        assert!(matches!(
            Selector::parse("$..foo"),
            Err(SelectorError::RecursiveDescent)
        ));
    }

    #[test]
    fn selector_rejects_filter_expression() {
        assert!(matches!(
            Selector::parse("$.foo[?(@.x > 5)]"),
            Err(SelectorError::FilterExpression)
        ));
    }

    #[test]
    fn selector_rejects_bracketed_string_key() {
        assert!(matches!(
            Selector::parse("$['foo']"),
            Err(SelectorError::BracketedStringKey)
        ));
    }

    #[test]
    fn selector_rejects_array_index() {
        assert!(matches!(
            Selector::parse("$.foo[0]"),
            Err(SelectorError::OnlyArrayWildcard)
        ));
    }

    #[test]
    fn eval_json_top_level_string() {
        let m = eval_json(r#"{"foo": "bar"}"#, "$.foo", &p()).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].key, "foo");
        assert_eq!(m[0].value, "bar");
    }

    #[test]
    fn eval_json_object_wildcard_url_field() {
        let m = eval_json(
            r#"{"mcpServers": {"a": {"url": "https://a"}, "b": {"command": "/bin/x"}}}"#,
            "$.mcpServers.*.url",
            &p(),
        )
        .unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].key, "a");
        assert_eq!(m[0].value, "https://a");
    }

    #[test]
    fn eval_json_missing_path_returns_empty() {
        let m = eval_json(r#"{"foo": 1}"#, "$.bar", &p()).unwrap();
        assert!(m.is_empty());
    }

    #[test]
    fn eval_json_array_wildcard() {
        let m = eval_json(r#"{"xs": [1, 2, 3]}"#, "$.xs[*]", &p()).unwrap();
        assert_eq!(m.len(), 3);
        assert_eq!(m[0].key, "[0]");
        assert_eq!(m[0].value, "1");
        assert_eq!(m[2].key, "[2]");
        assert_eq!(m[2].value, "3");
    }

    #[test]
    fn eval_json_corrupt_returns_parse_error() {
        let err = eval_json("{ not json", "$.foo", &p()).unwrap_err();
        assert!(matches!(err, AssessError::Parse { .. }));
    }

    #[test]
    fn eval_toml_top_level_string() {
        let m = eval_toml(
            r#"sandbox_mode = "danger-full-access""#,
            "$.sandbox_mode",
            &p(),
        )
        .unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].value, "danger-full-access");
    }

    #[test]
    fn eval_toml_array_of_tables_wildcard() {
        let m = eval_toml(
            "[[hooks.PreToolUse]]\nmatcher = \"Bash\"\n[[hooks.PreToolUse]]\nmatcher = \".*\"\n",
            "$.hooks.PreToolUse[*].matcher",
            &p(),
        )
        .unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].value, "Bash");
        assert_eq!(m[1].value, ".*");
    }
}
