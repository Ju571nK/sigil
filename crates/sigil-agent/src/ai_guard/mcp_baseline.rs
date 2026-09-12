//! Immutable, first-observed MCP metadata baseline. Only the daemon writes it.
//! No raw prompts/schemas are stored; fingerprints and property paths suffice.

use super::parser::AssessError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sigil_core::event::AiGuardReason;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::Path;

const MAX_BASELINE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOOLS: usize = 8000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ToolFingerprint {
    pub server: String,
    pub tool: String,
    surface_hash: String,
    required: BTreeSet<String>,
    sensitive: BTreeSet<String>,
    writes: bool,
}

pub(crate) type Snapshot = BTreeMap<String, Vec<ToolFingerprint>>;

fn canonical(v: &Value) -> String {
    match v {
        Value::Object(obj) => {
            let sorted: BTreeMap<_, _> = obj.iter().collect();
            format!(
                "{{{}}}",
                sorted
                    .into_iter()
                    .map(|(k, v)| format!(
                        "{}:{}",
                        serde_json::to_string(k).expect("key"),
                        canonical(v)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
        Value::Array(arr) => format!(
            "[{}]",
            arr.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        _ => v.to_string(),
    }
}

fn properties(
    v: &Value,
    prefix: &str,
    depth: usize,
    required: &mut BTreeSet<String>,
    sensitive: &mut BTreeSet<String>,
    writes: &mut bool,
) {
    if depth > 32 {
        return;
    }
    if let Some(obj) = v.as_object() {
        if let Some(arr) = obj.get("required").and_then(Value::as_array) {
            for name in arr.iter().filter_map(Value::as_str).take(2000) {
                required.insert(format!(
                    "{prefix}/{}",
                    name.replace('~', "~0").replace('/', "~1")
                ));
            }
        }
        if let Some(props) = obj.get("properties").and_then(Value::as_object) {
            for name in props.keys() {
                let lower = name.to_ascii_lowercase();
                let write = ["command", "shell", "script", "write", "delete", "execute"]
                    .iter()
                    .any(|word| lower.contains(word));
                *writes |= write;
                if write
                    || ["path", "url", "uri", "filename", "destination"]
                        .iter()
                        .any(|word| lower.contains(word))
                {
                    sensitive.insert(format!(
                        "{prefix}/properties/{}",
                        name.replace('~', "~0").replace('/', "~1")
                    ));
                }
            }
        }
        for (key, value) in obj {
            properties(
                value,
                &format!("{prefix}/{}", key.replace('~', "~0").replace('/', "~1")),
                depth + 1,
                required,
                sensitive,
                writes,
            );
        }
    } else if let Some(arr) = v.as_array() {
        for (i, value) in arr.iter().enumerate() {
            properties(
                value,
                &format!("{prefix}/{i}"),
                depth + 1,
                required,
                sensitive,
                writes,
            );
        }
    }
}

impl ToolFingerprint {
    pub(crate) fn new(server: &str, tool: &str, metadata: &Value, schema: &Value) -> Self {
        let mut result = Self {
            server: server.into(),
            tool: tool.into(),
            surface_hash: blake3::hash(canonical(metadata).as_bytes())
                .to_hex()
                .to_string(),
            required: BTreeSet::new(),
            sensitive: BTreeSet::new(),
            writes: false,
        };
        properties(
            schema,
            "",
            0,
            &mut result.required,
            &mut result.sensitive,
            &mut result.writes,
        );
        result
    }

    pub(crate) fn read_only_contradiction(&self, read_only: bool) -> Option<AiGuardReason> {
        (read_only && self.writes).then(|| AiGuardReason::McpReadOnlyHintContradiction {
            server: self.server.clone(),
            tool: self.tool.clone(),
        })
    }
}

#[derive(Serialize, Deserialize)]
struct Baseline {
    version: u32,
    home_hash: String,
    tools: Snapshot,
}

fn parse_error(path: &Path, message: impl ToString) -> AssessError {
    AssessError::Parse {
        path: path.into(),
        message: message.to_string(),
    }
}

/// Compare against a frozen snapshot. Changed/new tools never auto-approve
/// themselves on the next scan. Missing/broken caches must not call this.
pub(crate) fn assess(
    dir: &Path,
    home: &Path,
    current: &Snapshot,
) -> Result<Vec<AiGuardReason>, AssessError> {
    if current.values().map(Vec::len).sum::<usize>() > MAX_TOOLS {
        return Err(parse_error(dir, "MCP snapshot exceeds tool cap"));
    }
    let mut servers: BTreeMap<&str, Snapshot> = BTreeMap::new();
    for (key, variants) in current {
        for tool in variants {
            servers
                .entry(&tool.server)
                .or_default()
                .entry(key.clone())
                .or_default()
                .push(tool.clone());
        }
    }
    let mut out = Vec::new();
    for (server, snapshot) in servers {
        out.extend(assess_server(&server_path(dir, server), home, &snapshot)?);
    }
    Ok(out)
}

fn server_path(dir: &Path, server: &str) -> std::path::PathBuf {
    dir.join(format!("{}.json", blake3::hash(server.as_bytes()).to_hex()))
}

fn assess_server(
    path: &Path,
    home: &Path,
    current: &Snapshot,
) -> Result<Vec<AiGuardReason>, AssessError> {
    let io_error = |source| AssessError::Io {
        path: path.into(),
        source,
    };
    if current.values().map(Vec::len).sum::<usize>() > MAX_TOOLS {
        return Err(parse_error(path, "MCP snapshot exceeds tool cap"));
    }
    let home = home.canonicalize().map_err(io_error)?;
    let home_hash = blake3::hash(home.to_string_lossy().as_bytes())
        .to_hex()
        .to_string();
    let baseline = match std::fs::File::open(path) {
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take(MAX_BASELINE_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(io_error)?;
            if bytes.len() as u64 > MAX_BASELINE_BYTES {
                return Err(parse_error(path, "MCP baseline exceeds size cap"));
            }
            let baseline: Baseline =
                serde_json::from_slice(&bytes).map_err(|e| parse_error(path, e))?;
            if baseline.version != 1 || baseline.home_hash != home_hash {
                return Err(parse_error(
                    path,
                    "unsupported MCP baseline version or HOME mismatch",
                ));
            }
            baseline
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if current.is_empty() {
                return Ok(Vec::new());
            }
            let baseline = Baseline {
                version: 1,
                home_hash,
                tools: current.clone(),
            };
            let bytes = serde_json::to_vec(&baseline).map_err(|e| parse_error(path, e))?;
            if bytes.len() as u64 > MAX_BASELINE_BYTES {
                return Err(parse_error(path, "MCP baseline exceeds size cap"));
            }
            let parent = path
                .parent()
                .ok_or_else(|| parse_error(path, "baseline needs parent directory"))?;
            std::fs::create_dir_all(parent).map_err(io_error)?;
            let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(io_error)?;
            tmp.write_all(&bytes).map_err(io_error)?;
            tmp.as_file().sync_all().map_err(io_error)?;
            // A concurrent first writer must not be overwritten.
            tmp.persist_noclobber(path).map_err(|e| io_error(e.error))?;
            return Ok(Vec::new());
        }
        Err(e) => return Err(io_error(e)),
    };
    let known_servers: BTreeSet<_> = baseline
        .tools
        .values()
        .flatten()
        .map(|t| &t.server)
        .collect();
    let mut out = Vec::new();
    for (key, variants) in current {
        for tool in variants {
            let Some(old) = baseline.tools.get(key) else {
                if known_servers.contains(&tool.server) {
                    out.push(AiGuardReason::McpUnapprovedNewTool {
                        server: tool.server.clone(),
                        tool: tool.tool.clone(),
                        current_hash: tool.surface_hash.clone(),
                    });
                }
                continue;
            };
            if old.iter().any(|o| o.surface_hash == tool.surface_hash) {
                continue;
            }
            out.push(AiGuardReason::McpToolSurfaceDrift {
                server: tool.server.clone(),
                tool: tool.tool.clone(),
                baseline_hash: {
                    let mut hashes: Vec<_> = old.iter().map(|o| o.surface_hash.as_str()).collect();
                    hashes.sort_unstable();
                    blake3::hash(hashes.join(",").as_bytes())
                        .to_hex()
                        .to_string()
                },
                current_hash: tool.surface_hash.clone(),
            });
            if old.iter().all(|o| {
                !tool.sensitive.is_subset(&o.sensitive) || !o.required.is_subset(&tool.required)
            }) {
                out.push(AiGuardReason::McpSchemaPrivilegeExpansion {
                    server: tool.server.clone(),
                    tool: tool.tool.clone(),
                });
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn snapshot(description: &str, schema: Value) -> Snapshot {
        BTreeMap::from([(
            "server/tool".into(),
            vec![ToolFingerprint::new(
                "server",
                "tool",
                &json!({"description":description,"inputSchema":schema}),
                &schema,
            )],
        )])
    }

    #[test]
    fn immutable_baseline_survives_reopen_and_detects_all_drift_classes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        let base = snapshot(
            "read",
            json!({"properties":{"path":{}},"required":["path"]}),
        );
        assert!(assess(&path, dir.path(), &base).unwrap().is_empty());
        let file = server_path(&path, "server");
        let bytes = std::fs::read(&file).unwrap();
        let mut changed = snapshot("updated", json!({"properties":{"path":{},"command":{}}}));
        changed.insert(
            "server/new".into(),
            vec![ToolFingerprint::new(
                "server",
                "new",
                &json!({}),
                &json!({}),
            )],
        );
        for _ in 0..2 {
            let reasons = assess(&path, dir.path(), &changed).unwrap();
            assert_eq!(reasons.len(), 3);
            assert!(reasons
                .iter()
                .any(|r| matches!(r, AiGuardReason::McpToolSurfaceDrift { .. })));
            assert!(reasons
                .iter()
                .any(|r| matches!(r, AiGuardReason::McpSchemaPrivilegeExpansion { .. })));
            assert!(reasons
                .iter()
                .any(|r| matches!(r, AiGuardReason::McpUnapprovedNewTool { .. })));
        }
        assert_eq!(std::fs::read(&file).unwrap(), bytes);
        assert!(assess(&path, dir.path(), &base).unwrap().is_empty());
        std::fs::write(&file, "bad").unwrap();
        assert!(assess(&path, dir.path(), &base).is_err());
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "bad");
    }

    #[test]
    fn object_order_is_stable_and_path_alone_does_not_prove_writes() {
        let a: Value = serde_json::from_str(r#"{"b":1,"a":{"d":2,"c":3}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":{"c":3,"d":2},"b":1}"#).unwrap();
        assert_eq!(canonical(&a), canonical(&b));
        let tool = ToolFingerprint::new("s", "t", &a, &json!({"properties":{"path":{}}}));
        assert!(tool.read_only_contradiction(true).is_none());
        let tool = ToolFingerprint::new("s", "t", &a, &json!({"properties":{"shell_command":{}}}));
        assert!(tool.read_only_contradiction(false).is_none());
        assert!(tool.read_only_contradiction(true).is_some());
    }

    #[test]
    fn empty_cache_does_not_create_baseline_and_home_is_bound() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        assert!(assess(&path, dir.path(), &Snapshot::new())
            .unwrap()
            .is_empty());
        assert!(!path.exists());
        let base = snapshot("x", json!({}));
        assess(&path, dir.path(), &base).unwrap();
        let other = tempfile::tempdir().unwrap();
        assert!(assess(&path, other.path(), &base).is_err());
    }

    #[test]
    fn server_added_after_boot_gets_its_own_immutable_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baselines");
        let base = snapshot("x", json!({}));
        assess(&path, dir.path(), &base).unwrap();
        let mut expanded = base;
        expanded.insert(
            "later/tool".into(),
            vec![ToolFingerprint::new(
                "later",
                "tool",
                &json!("original"),
                &json!({}),
            )],
        );
        assert!(assess(&path, dir.path(), &expanded).unwrap().is_empty());
        expanded.get_mut("later/tool").unwrap()[0] =
            ToolFingerprint::new("later", "tool", &json!("updated"), &json!({}));
        assert!(assess(&path, dir.path(), &expanded).unwrap().iter().any(
            |r| matches!(r, AiGuardReason::McpToolSurfaceDrift { server, .. } if server == "later")
        ));
    }
}
