// Consumed by install/uninstall subcommands. Registers/deregisters the
// sigil-hook entry in each agent's config WITHOUT clobbering unrelated hooks.
//
// Agents differ in config path AND format (web-verified 2026-06):
//   - Claude Code / Codex: nested `hooks.PreToolUse[]` with
//     `{matcher, hooks:[{type:"command", command}]}`.
//       Claude Code: ~/.claude/settings.json
//       Codex:       ~/.codex/hooks.json   (also needs hooks enabled in
//                    ~/.codex/config.toml — surfaced as a note)
//   - Cursor: ~/.cursor/hooks.json with `version:1` + per-event arrays
//     (`beforeShellExecution`, `beforeMCPExecution`) of `{command}`.
//
// Antigravity is deliberately absent here: on-hardware verification (real `agy`
// 1.0.4) proved its hooks are NOT read from any settings.json — they load only
// from an imported plugin bundle. That install path lives in
// `install_antigravity.rs` (a directory bundle handed to `agy plugin install`).

use serde_json::{json, Value};
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookFormat {
    /// `root.hooks.PreToolUse[]` — Claude Code, Codex.
    NestedPreToolUse,
    /// `root.version` + `root.hooks.{beforeShellExecution,beforeMCPExecution}[]`.
    Cursor,
}

pub(crate) fn agent_format(agent: &str) -> Option<HookFormat> {
    match agent {
        "claude-code" | "codex" => Some(HookFormat::NestedPreToolUse),
        "cursor" => Some(HookFormat::Cursor),
        _ => None,
    }
}

pub(crate) const CURSOR_EVENTS: [&str; 2] = ["beforeShellExecution", "beforeMCPExecution"];

fn command_string(exe: &str, agent: &str, capture: &str) -> String {
    format!("{exe} {agent} --capture {capture}")
}

fn command_string_enforce(exe: &str, agent: &str, capture: &str, on_failure: &str) -> String {
    // Registrations dedupe by binary path: installing enforce over an existing observe
    // registration (same exe) REPLACES it — operators upgrading observe→enforce get the
    // observe entry overwritten, not a second entry.
    format!("{exe} {agent} --enforce --on-failure {on_failure} --capture {capture}")
}

/// First whitespace token of a command string (= the binary path).
pub(crate) fn first_token(cmd: &str) -> &str {
    cmd.split_whitespace().next().unwrap_or("")
}

// --- Claude-style entry helpers ---

fn claude_entry(cmd: &str) -> Value {
    json!({ "matcher": "*", "hooks": [{ "type": "command", "command": cmd }] })
}

/// The command of a Claude-style entry's first inner hook, if any.
pub(crate) fn claude_entry_cmd(entry: &Value) -> Option<&str> {
    entry
        .get("hooks")
        .and_then(|h| h.as_array())
        .and_then(|hooks| hooks.first())
        .and_then(|h| h.get("command"))
        .and_then(|c| c.as_str())
}

pub(crate) fn claude_entry_is_ours(entry: &Value, exe: &str) -> bool {
    entry
        .get("hooks")
        .and_then(|h| h.as_array())
        .map(|hooks| {
            hooks.iter().any(|h| {
                h.get("command")
                    .and_then(|c| c.as_str())
                    .map(|c| first_token(c) == exe)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// Get-or-create the nested `hooks.PreToolUse` array.
fn pretooluse_array_mut(root: &mut Value) -> &mut Vec<Value> {
    if !root.is_object() {
        *root = json!({});
    }
    if !root["hooks"].is_object() {
        root["hooks"] = json!({});
    }
    let h = &mut root["hooks"];
    if !h["PreToolUse"].is_array() {
        h["PreToolUse"] = json!([]);
    }
    h["PreToolUse"].as_array_mut().unwrap()
}

fn merge_claude(arr: &mut Vec<Value>, exe: &str, cmd: &str) -> bool {
    match arr.iter().position(|e| claude_entry_is_ours(e, exe)) {
        Some(i) => {
            if claude_entry_cmd(&arr[i]) == Some(cmd) {
                false
            } else {
                arr[i] = claude_entry(cmd);
                true
            }
        }
        None => {
            arr.push(claude_entry(cmd));
            true
        }
    }
}

// --- Cursor helpers ---

pub(crate) fn cursor_entry_is_ours(entry: &Value, exe: &str) -> bool {
    entry
        .get("command")
        .and_then(|c| c.as_str())
        .map(|c| first_token(c) == exe)
        .unwrap_or(false)
}

/// The `command` string of a Cursor settings entry, if present.
pub(crate) fn cursor_entry_command(entry: &Value) -> Option<&str> {
    entry.get("command").and_then(|c| c.as_str())
}

/// Effective `failClosed` of a Cursor entry — absent means false (Cursor default).
pub(crate) fn cursor_entry_fail_closed(entry: &Value) -> bool {
    entry
        .get("failClosed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// The settings entry object for our hook on a Cursor event. Observe = bare
/// command; enforce-closed additionally carries `failClosed:true`, coupling our
/// `--on-failure closed` to Cursor's own fail-closed so a hook process that
/// crashes / times out / returns invalid JSON blocks the tool call instead of
/// failing open.
fn cursor_observe_entry(cmd: &str) -> Value {
    cursor_enforce_entry(cmd, "open")
}

fn cursor_enforce_entry(cmd: &str, on_failure: &str) -> Value {
    if on_failure == "closed" {
        json!({ "command": cmd, "failClosed": true })
    } else {
        json!({ "command": cmd })
    }
}

/// Upsert our prebuilt entry on BOTH Cursor gate events, keyed by exe first-token.
/// Replaces the whole entry object on change (so a stale `failClosed` from a prior
/// closed install is dropped on a later open install). Returns true if changed.
fn upsert_cursor_entry(root: &mut Value, exe: &str, entry: &Value) -> bool {
    if !root.is_object() {
        *root = json!({});
    }
    let mut changed = false;
    if root["version"].is_null() {
        root["version"] = json!(1);
        changed = true;
    }
    if !root["hooks"].is_object() {
        root["hooks"] = json!({});
    }
    for ev in CURSOR_EVENTS {
        let arr = {
            let h = &mut root["hooks"];
            if !h[ev].is_array() {
                h[ev] = json!([]);
            }
            h[ev].as_array_mut().unwrap()
        };
        match arr.iter().position(|e| cursor_entry_is_ours(e, exe)) {
            Some(i) => {
                if &arr[i] != entry {
                    arr[i] = entry.clone();
                    changed = true;
                }
            }
            None => {
                arr.push(entry.clone());
                changed = true;
            }
        }
    }
    changed
}

fn merge_cursor(root: &mut Value, exe: &str, cmd: &str) -> bool {
    upsert_cursor_entry(root, exe, &cursor_observe_entry(cmd))
}

fn merge_cursor_enforce(root: &mut Value, exe: &str, cmd: &str, on_failure: &str) -> bool {
    upsert_cursor_entry(root, exe, &cursor_enforce_entry(cmd, on_failure))
}

// ---------------------------------------------------------------------------
// Public API (dispatched by agent format)
// ---------------------------------------------------------------------------

/// Shared body for `render_block` / `render_block_enforce`: builds the
/// human-pasteable settings fragment + undo hint for a prebuilt command string.
/// `cursor_entry` is the pre-built Cursor entry object (observe or enforce with
/// optional `failClosed`) — used only for the Cursor format arm.
fn render_block_inner(cmd: &str, agent: &str, cursor_entry: &Value) -> String {
    let Some(fmt) = agent_format(agent) else {
        return format!("// unsupported agent '{agent}'\n");
    };
    let path = settings_path(agent)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<settings>".into());
    let fragment = match fmt {
        HookFormat::NestedPreToolUse => json!({ "hooks": { "PreToolUse": [claude_entry(cmd)] } }),
        HookFormat::Cursor => json!({
            "version": 1,
            "hooks": {
                "beforeShellExecution": [cursor_entry],
                "beforeMCPExecution": [cursor_entry],
            }
        }),
    };
    let pretty = serde_json::to_string_pretty(&fragment).unwrap_or_default();
    let note = if agent == "codex" {
        "// note: Codex also requires hooks enabled in ~/.codex/config.toml.\n"
    } else {
        ""
    };
    format!(
        "// Merge this into {path}:\n\
         {pretty}\n\
         {note}// remove with: sigil-hook uninstall --agent {agent} --write\n"
    )
}

/// Human-pasteable block showing the settings fragment + undo hint.
pub fn render_block(exe: &str, agent: &str, capture: &str) -> String {
    let cmd = command_string(exe, agent, capture);
    render_block_inner(&cmd, agent, &cursor_observe_entry(&cmd))
}

/// Idempotently ensure the sigil-hook entry is present. Returns `true` if the
/// document was modified.
pub fn merge_into(root: &mut Value, exe: &str, agent: &str, capture: &str) -> bool {
    let cmd = command_string(exe, agent, capture);
    match agent_format(agent) {
        Some(HookFormat::NestedPreToolUse) => merge_claude(pretooluse_array_mut(root), exe, &cmd),
        Some(HookFormat::Cursor) => merge_cursor(root, exe, &cmd),
        None => false,
    }
}

/// Like `render_block`, but the registered command runs the Stage 2 enforce
/// (deny-decision) path with the given on_failure mode.
pub fn render_block_enforce(exe: &str, agent: &str, capture: &str, on_failure: &str) -> String {
    let cmd = command_string_enforce(exe, agent, capture, on_failure);
    render_block_inner(&cmd, agent, &cursor_enforce_entry(&cmd, on_failure))
}

/// Merge an enforce-mode registration into the settings JSON.
/// For claude-code / codex (NestedPreToolUse): merges with the enforce command string.
/// For Cursor: upserts both gate-event entries; adds `failClosed:true` when
/// `on_failure == "closed"` to couple Cursor's own fail-closed behaviour to ours.
/// Returns `true` if the document was modified, `false` if already up-to-date.
pub fn merge_into_enforce(
    root: &mut Value,
    exe: &str,
    agent: &str,
    capture: &str,
    on_failure: &str,
) -> bool {
    let cmd = command_string_enforce(exe, agent, capture, on_failure);
    match agent_format(agent) {
        Some(HookFormat::NestedPreToolUse) => merge_claude(pretooluse_array_mut(root), exe, &cmd),
        Some(HookFormat::Cursor) => merge_cursor_enforce(root, exe, &cmd, on_failure),
        None => false,
    }
}

/// Remove every sigil-hook entry for `exe`. Returns `true` if anything was
/// removed. Leaves unrelated hooks untouched.
pub fn remove_from(root: &mut Value, exe: &str, agent: &str) -> bool {
    match agent_format(agent) {
        Some(HookFormat::NestedPreToolUse) => match root["hooks"]["PreToolUse"].as_array_mut() {
            Some(a) => {
                let before = a.len();
                a.retain(|e| !claude_entry_is_ours(e, exe));
                a.len() < before
            }
            None => false,
        },
        Some(HookFormat::Cursor) => {
            let mut removed = false;
            for ev in CURSOR_EVENTS {
                if let Some(a) = root["hooks"][ev].as_array_mut() {
                    let before = a.len();
                    a.retain(|e| !cursor_entry_is_ours(e, exe));
                    removed |= a.len() < before;
                }
            }
            removed
        }
        None => false,
    }
}

/// Count sigil-hook entries for `exe` (across all relevant arrays).
pub fn count_sigil_entries(root: &Value, exe: &str, agent: &str) -> usize {
    match agent_format(agent) {
        Some(HookFormat::NestedPreToolUse) => root["hooks"]["PreToolUse"]
            .as_array()
            .map(|a| a.iter().filter(|e| claude_entry_is_ours(e, exe)).count())
            .unwrap_or(0),
        Some(HookFormat::Cursor) => CURSOR_EVENTS
            .iter()
            .map(|ev| {
                root["hooks"][*ev]
                    .as_array()
                    .map(|a| a.iter().filter(|e| cursor_entry_is_ours(e, exe)).count())
                    .unwrap_or(0)
            })
            .sum(),
        None => 0,
    }
}

/// The user's home directory, cross-platform: `HOME` (Unix) or `USERPROFILE`
/// (Windows, where `HOME` is usually unset).
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var_os("USERPROFILE").filter(|s| !s.is_empty()))
        .map(PathBuf::from)
}

/// `$XDG_STATE_HOME/sigil` or `<home>/.local/state/sigil`.
pub fn state_dir() -> PathBuf {
    if let Ok(base) = std::env::var("XDG_STATE_HOME") {
        PathBuf::from(base).join("sigil")
    } else {
        home_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join(".local/state/sigil")
    }
}

/// Per-agent baseline path, only for agents with a known hook format (so a raw
/// `--agent` string can never be interpolated into a traversal path).
pub(crate) fn baseline_path_in(dir: &std::path::Path, agent: &str) -> Option<PathBuf> {
    agent_format(agent)?; // validate: known slug only
    Some(dir.join(format!("hook-registration-{agent}.json")))
}

pub(crate) fn baseline_path(agent: &str) -> Option<PathBuf> {
    baseline_path_in(&state_dir(), agent)
}

/// Map agent name → absolute path to its hook config file.
pub fn settings_path(agent: &str) -> Option<PathBuf> {
    let home = home_dir()?;
    let p = match agent {
        "claude-code" => home.join(".claude/settings.json"),
        "codex" => home.join(".codex/hooks.json"),
        "cursor" => home.join(".cursor/hooks.json"),
        _ => return None,
    };
    Some(p)
}

/// Write `state_dir()/hook-registration.json` + append to the discovery index.
#[allow(clippy::too_many_arguments)]
pub fn write_baseline(
    agent: &str,
    settings_path: &std::path::Path,
    exe: &str,
    agent_arg: &str,
    capture: &str,
    matcher: &str,
    enforce: bool,
    on_failure: &str,
) -> io::Result<()> {
    write_baseline_in(
        &state_dir(),
        agent,
        settings_path,
        exe,
        agent_arg,
        capture,
        matcher,
        enforce,
        on_failure,
    )
}

/// Directory-injectable core of [`write_baseline`]: writes
/// `dir/hook-registration-<agent>.json` + appends to `dir/hook-index.json`. Kept
/// separate so tests can supply a temp dir without touching the process-global
/// `XDG_STATE_HOME` env var (which would race other tests).
#[allow(clippy::too_many_arguments)]
fn write_baseline_in(
    dir: &std::path::Path,
    agent: &str,
    settings_path: &std::path::Path,
    exe: &str,
    agent_arg: &str,
    capture: &str,
    matcher: &str,
    enforce: bool,
    on_failure: &str,
) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;

    let cmd = if enforce {
        command_string_enforce(exe, agent_arg, capture, on_failure)
    } else {
        command_string(exe, agent_arg, capture)
    };
    let block_hash = blake3::hash(cmd.as_bytes()).to_hex().to_string();
    let written_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let settings_path_str = settings_path.to_string_lossy().to_string();

    let fail_closed: Option<bool> = (agent_format(agent) == Some(HookFormat::Cursor))
        .then(|| enforce && on_failure == "closed");

    let baseline = json!({
        "agent": agent,
        "settings_path": settings_path_str,
        "command": cmd,
        "capture": capture,
        "matcher": matcher,
        "block_hash": block_hash,
        "fail_closed": fail_closed,        // null for claude/codex; bool for cursor
        "written_at_unix": written_at_unix,
    });

    let reg_path = baseline_path_in(dir, agent)
        .ok_or_else(|| io::Error::other(format!("unknown agent for baseline: {agent}")))?;
    let pretty = serde_json::to_string_pretty(&baseline).map_err(io::Error::other)?;
    std::fs::write(&reg_path, pretty.as_bytes())?;

    let index_path = dir.join("hook-index.json");
    let mut entries: Vec<String> = if index_path.exists() {
        let raw = std::fs::read(&index_path)?;
        serde_json::from_slice::<Vec<String>>(&raw).unwrap_or_default()
    } else {
        Vec::new()
    };
    if !entries.contains(&settings_path_str) {
        entries.push(settings_path_str);
        let json = serde_json::to_string_pretty(&entries).map_err(io::Error::other)?;
        std::fs::write(&index_path, json.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_block_enforce_carries_flags() {
        let s = render_block_enforce("/abs/sigil-hook", "claude-code", "redacted", "open");
        assert!(s.contains(
            "/abs/sigil-hook claude-code --enforce --on-failure open --capture redacted"
        ));
        assert!(s.contains("PreToolUse"));
    }

    #[test]
    fn render_block_enforce_codex_carries_flags() {
        let s = render_block_enforce("/abs/sigil-hook", "codex", "redacted", "open");
        assert!(s.contains("/abs/sigil-hook codex --enforce --on-failure open --capture redacted"));
        assert!(s.contains("PreToolUse"));
    }

    // --- Claude Code (nested) ---
    #[test]
    fn render_block_has_abs_path_and_capture() {
        let s = render_block("/abs/sigil-hook", "claude-code", "redacted");
        assert!(s.contains("/abs/sigil-hook claude-code --capture redacted"));
        assert!(s.contains("PreToolUse"));
    }
    #[test]
    fn nested_merge_empty_idempotent_update() {
        let mut v = json!({});
        assert!(merge_into(
            &mut v,
            "/abs/sigil-hook",
            "claude-code",
            "redacted"
        ));
        assert!(!merge_into(
            &mut v,
            "/abs/sigil-hook",
            "claude-code",
            "redacted"
        ));
        assert_eq!(count_sigil_entries(&v, "/abs/sigil-hook", "claude-code"), 1);
        // capture change updates in place
        assert!(merge_into(&mut v, "/abs/sigil-hook", "claude-code", "raw"));
        assert_eq!(count_sigil_entries(&v, "/abs/sigil-hook", "claude-code"), 1);
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("--capture raw") && !s.contains("--capture redacted"));
    }
    #[test]
    fn nested_remove_preserves_foreign() {
        let mut v = json!({"hooks":{"PreToolUse":[
            {"matcher":"*","hooks":[{"type":"command","command":"/other/tool run"}]}
        ]}});
        merge_into(&mut v, "/abs/sigil-hook", "claude-code", "redacted");
        assert!(remove_from(&mut v, "/abs/sigil-hook", "claude-code"));
        assert_eq!(count_sigil_entries(&v, "/abs/sigil-hook", "claude-code"), 0);
        assert!(serde_json::to_string(&v)
            .unwrap()
            .contains("/other/tool run"));
    }

    // --- Codex (nested, ~/.codex/hooks.json) ---
    #[test]
    fn codex_uses_nested_and_notes_config_toml() {
        let s = render_block("/abs/sigil-hook", "codex", "redacted");
        assert!(s.contains("/abs/sigil-hook codex --capture redacted"));
        // Path-separator-agnostic: PathBuf renders `\` on Windows.
        assert!(s.contains("codex") && s.contains("hooks.json"));
        assert!(s.contains("config.toml"));
        let mut v = json!({});
        assert!(merge_into(&mut v, "/abs/sigil-hook", "codex", "redacted"));
        assert_eq!(count_sigil_entries(&v, "/abs/sigil-hook", "codex"), 1);
        assert!(v["hooks"]["PreToolUse"].is_array());
    }

    // Antigravity is NOT a settings-merge agent — it installs as an `agy`
    // plugin bundle (see install_antigravity.rs). The JSON-merge path must
    // treat it as unsupported so it can never write a settings.json hook that
    // `agy` silently ignores.
    #[test]
    fn antigravity_not_in_settings_merge_path() {
        assert!(settings_path("antigravity").is_none());
        assert!(!merge_into(
            &mut json!({}),
            "/abs/sigil-hook",
            "antigravity",
            "redacted"
        ));
        assert_eq!(
            count_sigil_entries(&json!({}), "/abs/sigil-hook", "antigravity"),
            0
        );
    }

    // --- Cursor (version + two event arrays) ---
    #[test]
    fn cursor_registers_both_events_with_version() {
        let mut v = json!({});
        assert!(merge_into(&mut v, "/abs/sigil-hook", "cursor", "redacted"));
        assert_eq!(v["version"], json!(1));
        assert!(v["hooks"]["beforeShellExecution"].is_array());
        assert!(v["hooks"]["beforeMCPExecution"].is_array());
        // one entry per event = 2 total
        assert_eq!(count_sigil_entries(&v, "/abs/sigil-hook", "cursor"), 2);
        assert!(!merge_into(&mut v, "/abs/sigil-hook", "cursor", "redacted"));
        let s = render_block("/abs/sigil-hook", "cursor", "redacted");
        assert!(s.contains("beforeShellExecution") && s.contains("beforeMCPExecution"));
    }
    #[test]
    fn cursor_remove_preserves_foreign() {
        let mut v = json!({"version":1,"hooks":{"beforeShellExecution":[
            {"command":"/other/guard.sh"}
        ]}});
        merge_into(&mut v, "/abs/sigil-hook", "cursor", "redacted");
        assert!(remove_from(&mut v, "/abs/sigil-hook", "cursor"));
        assert_eq!(count_sigil_entries(&v, "/abs/sigil-hook", "cursor"), 0);
        assert!(serde_json::to_string(&v)
            .unwrap()
            .contains("/other/guard.sh"));
    }

    #[test]
    fn unsupported_agent_paths() {
        assert!(settings_path("nope").is_none());
        assert_eq!(count_sigil_entries(&json!({}), "/x", "nope"), 0);
    }

    // --- Cursor enforce ---

    #[test]
    fn cursor_enforce_registers_both_events_with_failclosed() {
        let mut v = json!({});
        assert!(merge_into_enforce(
            &mut v,
            "/abs/sigil-hook",
            "cursor",
            "redacted",
            "closed"
        ));
        for ev in CURSOR_EVENTS {
            let arr = v["hooks"][ev].as_array().unwrap();
            assert_eq!(arr.len(), 1, "{ev} has exactly one entry");
            assert_eq!(arr[0]["failClosed"], json!(true));
            let cmd = arr[0]["command"].as_str().unwrap();
            assert!(cmd.contains("--enforce"), "got: {cmd}");
            assert!(cmd.contains("--on-failure closed"), "got: {cmd}");
        }
        // idempotent
        assert!(!merge_into_enforce(
            &mut v,
            "/abs/sigil-hook",
            "cursor",
            "redacted",
            "closed"
        ));
        assert_eq!(count_sigil_entries(&v, "/abs/sigil-hook", "cursor"), 2);
    }

    #[test]
    fn cursor_enforce_open_has_no_failclosed() {
        let mut v = json!({});
        merge_into_enforce(&mut v, "/abs/sigil-hook", "cursor", "redacted", "open");
        let arr = v["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert!(arr[0].get("failClosed").is_none());
    }

    #[test]
    fn cursor_closed_to_open_strips_failclosed() {
        let mut v = json!({});
        merge_into_enforce(&mut v, "/abs/sigil-hook", "cursor", "redacted", "closed");
        assert!(merge_into_enforce(
            &mut v,
            "/abs/sigil-hook",
            "cursor",
            "redacted",
            "open"
        ));
        let arr = v["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert!(
            arr[0].get("failClosed").is_none(),
            "stale failClosed must be removed"
        );
        assert_eq!(
            arr[0].as_object().unwrap().len(),
            1,
            "entry is exactly {{command}}"
        );
    }

    #[test]
    fn cursor_observe_to_enforce_replaces_in_place() {
        let mut v = json!({});
        merge_into(&mut v, "/abs/sigil-hook", "cursor", "redacted");
        assert!(merge_into_enforce(
            &mut v,
            "/abs/sigil-hook",
            "cursor",
            "redacted",
            "open"
        ));
        // replaced, not stacked: still one per event (2 total)
        assert_eq!(count_sigil_entries(&v, "/abs/sigil-hook", "cursor"), 2);
        let arr = v["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert!(arr[0]["command"].as_str().unwrap().contains("--enforce"));
    }

    #[test]
    fn cursor_entry_accessors() {
        let e = json!({ "command": "/x/sigil-hook cursor --enforce", "failClosed": true });
        assert_eq!(
            cursor_entry_command(&e),
            Some("/x/sigil-hook cursor --enforce")
        );
        assert!(cursor_entry_fail_closed(&e));
        let no_fc = json!({ "command": "/x/sigil-hook cursor" });
        assert!(!cursor_entry_fail_closed(&no_fc)); // absent = false (Cursor default)
        assert_eq!(cursor_entry_command(&json!({})), None); // command absent → None
        assert!(!cursor_entry_fail_closed(&json!({ "failClosed": "yes" }))); // non-bool → false
    }

    #[test]
    fn cursor_enforce_to_observe_strips_enforce() {
        let mut v = json!({});
        merge_into_enforce(&mut v, "/abs/sigil-hook", "cursor", "redacted", "closed");
        assert!(merge_into(&mut v, "/abs/sigil-hook", "cursor", "redacted"));
        let arr = v["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        let entry = arr[0].as_object().unwrap();
        assert_eq!(entry.len(), 1, "downgrade leaves exactly {{command}}");
        assert!(!entry["command"].as_str().unwrap().contains("--enforce"));
        assert!(
            entry.get("failClosed").is_none(),
            "stale failClosed stripped on downgrade"
        );
    }

    #[test]
    fn cursor_enforce_preview_closed_shows_failclosed() {
        let s = render_block_enforce("/abs/sigil-hook", "cursor", "redacted", "closed");
        assert!(
            s.contains("\"failClosed\": true"),
            "closed preview must show failClosed:\n{s}"
        );
        let open = render_block_enforce("/abs/sigil-hook", "cursor", "redacted", "open");
        assert!(
            !open.contains("failClosed"),
            "open preview must NOT show failClosed:\n{open}"
        );
    }

    // --- write_baseline records the actual installed command ---

    /// Helper: call the directory-injectable `write_baseline_in` with `dir` and
    /// return the parsed JSON from `dir/hook-registration.json`. Race-free: no
    /// process-global env var (`XDG_STATE_HOME`) is touched, so these tests are
    /// safe to run in parallel with any other state_dir()-dependent test.
    fn baseline_json_in(
        dir: &std::path::Path,
        enforce: bool,
        on_failure: &str,
    ) -> serde_json::Value {
        let settings = dir.join("settings.json");
        write_baseline_in(
            dir,
            "claude-code",
            &settings,
            "/usr/bin/sigil-hook",
            "claude-code",
            "redacted",
            "*",
            enforce,
            on_failure,
        )
        .unwrap();
        let raw = std::fs::read(baseline_path_in(dir, "claude-code").unwrap()).unwrap();
        serde_json::from_slice(&raw).unwrap()
    }

    /// `command_string_enforce` produces the right flag sequence (pure, race-free).
    #[test]
    fn command_string_enforce_contains_enforce_flags() {
        let cmd = command_string_enforce("/usr/bin/sigil-hook", "claude-code", "redacted", "open");
        assert!(
            cmd.contains("--enforce --on-failure open"),
            "command_string_enforce must include enforce flags, got: {cmd}"
        );
        assert!(
            cmd.contains("--capture redacted"),
            "command_string_enforce must include --capture, got: {cmd}"
        );
    }

    /// write_baseline(enforce=true) records the enforce command and a matching hash.
    #[test]
    fn write_baseline_records_enforce_command_when_enforce() {
        let tmp = tempfile::tempdir().unwrap();
        let v = baseline_json_in(tmp.path(), true, "open");
        let cmd = v["command"].as_str().unwrap();
        assert!(
            cmd.contains("--enforce --on-failure open"),
            "baseline must record the enforce command, got: {cmd}"
        );
        let expected_hash = blake3::hash(cmd.as_bytes()).to_hex().to_string();
        assert_eq!(
            v["block_hash"].as_str().unwrap(),
            expected_hash,
            "block_hash must be blake3 of the enforce command"
        );
    }

    /// write_baseline(enforce=false) records the observe command (regression guard).
    #[test]
    fn write_baseline_records_observe_command_when_not_enforce() {
        let tmp = tempfile::tempdir().unwrap();
        let v = baseline_json_in(tmp.path(), false, "open");
        let cmd = v["command"].as_str().unwrap();
        assert!(
            !cmd.contains("--enforce"),
            "non-enforce baseline must NOT contain --enforce, got: {cmd}"
        );
        assert!(
            cmd.contains("--capture redacted"),
            "non-enforce baseline must contain --capture, got: {cmd}"
        );
    }

    #[test]
    fn baseline_path_is_per_agent_and_validated() {
        let dir = std::path::Path::new("/state");
        assert_eq!(
            baseline_path_in(dir, "cursor").unwrap(),
            dir.join("hook-registration-cursor.json")
        );
        assert!(baseline_path_in(dir, "../evil").is_none()); // unknown slug → no path
    }

    #[test]
    fn write_baseline_per_agent_no_clobber_and_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        // claude (observe) then cursor (enforce closed) → two distinct files
        write_baseline_in(
            dir.path(),
            "claude-code",
            std::path::Path::new("/h/.claude/settings.json"),
            "/x/sigil-hook",
            "claude-code",
            "redacted",
            "*",
            false,
            "open",
        )
        .unwrap();
        write_baseline_in(
            dir.path(),
            "cursor",
            std::path::Path::new("/h/.cursor/hooks.json"),
            "/x/sigil-hook",
            "cursor",
            "redacted",
            "*",
            true,
            "closed",
        )
        .unwrap();

        let claude: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("hook-registration-claude-code.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(claude["agent"], "claude-code");
        assert!(claude["matcher"].is_string());
        assert!(claude["fail_closed"].is_null()); // claude → no fail_closed

        let cursor: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("hook-registration-cursor.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(cursor["agent"], "cursor");
        assert_eq!(cursor["fail_closed"], serde_json::json!(true)); // enforce + closed
        assert!(cursor["matcher"].is_string()); // matcher kept for wire continuity
    }
}
