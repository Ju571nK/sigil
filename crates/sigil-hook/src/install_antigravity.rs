// Antigravity (Google `agy` CLI) install. Antigravity loads hooks from an
// imported plugin bundle (`agy plugin install <dir>`), NOT settings.json.
//
// VERSION CAVEAT (#112): agy 1.0.4 accepted and loaded this `hooks/hooks.json`
// bundle (`agy plugin validate` reported "hooks: 1 processed"), but agy
// 1.0.7/1.0.8 do NOT fire `agy plugin install` PreToolUse command-hooks —
// `agy plugin validate` reports "hooks: skipped (not found)", `plugin list`
// shows components: null, and an always-deny probe hook fired 0 times on
// hardware. So on current agy this registration is a no-op. `sigil-hook install
// --agent antigravity` therefore does NOT install by default (see
// cmd_install_antigravity); this module's bundle path is reached only under
// `--force` (experimental / for a future agy that restores command-hooks).
//
// Canonical bundle layout (as accepted by agy 1.0.4; `hooks/` subdir required —
// root-level hooks.json, inline `hooks` in plugin.json, and hooks.toml were all
// reported "hooks: not found"):
//
//   <dir>/plugin.json        {name, version, description, license, keywords}
//   <dir>/hooks/hooks.json   {PreToolUse:[{matcher, hooks:[{type, command}]}]}
//
// `agy plugin install` copies the bundle into ~/.gemini/config/plugins/<name>/;
// `agy plugin uninstall <name>` reverses it.

use serde_json::{json, Value};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Plugin name `agy` registers it under (also the bundle directory name and the
/// `agy plugin uninstall` argument).
pub const PLUGIN_NAME: &str = "sigil-hook";

/// The `antigravity` runtime entrypoint the registered hook invokes.
fn command_string(exe: &str, capture: &str) -> String {
    format!("{exe} antigravity --capture {capture}")
}

/// `<state_dir>/antigravity-plugin/sigil-hook` — the bundle source we
/// materialize before handing it to `agy plugin install`. Sigil-owned and
/// stable so re-install/uninstall can find it.
pub fn staging_dir() -> PathBuf {
    crate::install::state_dir()
        .join("antigravity-plugin")
        .join(PLUGIN_NAME)
}

/// `<dir>/plugin.json` contents.
pub fn plugin_json() -> Value {
    json!({
        "name": PLUGIN_NAME,
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Sigil runtime observer (NOTE: current agy may not invoke this command-hook — sigil #112).",
        "license": "Apache-2.0",
        "keywords": ["sigil", "security", "observability", "antigravity"],
    })
}

/// `<dir>/hooks/hooks.json` contents (bare top-level `PreToolUse`, the only
/// shape `agy plugin validate` accepts inside a plugin's `hooks/` directory).
pub fn hooks_json(exe: &str, capture: &str) -> Value {
    json!({
        "PreToolUse": [{
            "matcher": "*",
            "hooks": [{ "type": "command", "command": command_string(exe, capture) }],
        }],
    })
}

/// Materialize the plugin bundle (`plugin.json` + `hooks/hooks.json`) into
/// `dir`, creating it (and the `hooks/` subdir) if absent.
pub fn write_bundle(dir: &Path, exe: &str, capture: &str) -> io::Result<()> {
    let hooks_dir = dir.join("hooks");
    std::fs::create_dir_all(&hooks_dir)?;
    let pj = serde_json::to_string_pretty(&plugin_json()).map_err(io::Error::other)?;
    std::fs::write(dir.join("plugin.json"), pj.as_bytes())?;
    let hj = serde_json::to_string_pretty(&hooks_json(exe, capture)).map_err(io::Error::other)?;
    std::fs::write(hooks_dir.join("hooks.json"), hj.as_bytes())?;
    Ok(())
}

/// The `agy` program to invoke: the documented install location
/// (`<home>/.local/bin/agy`) if present, else bare `agy` (resolved via PATH).
fn agy_program() -> PathBuf {
    if let Some(home) = crate::install::home_dir() {
        let p = home.join(".local/bin/agy");
        if p.exists() {
            return p;
        }
    }
    PathBuf::from("agy")
}

/// Register the bundle with `agy plugin install <dir>`.
pub fn run_install(dir: &Path) -> io::Result<Output> {
    Command::new(agy_program())
        .args(["plugin", "install"])
        .arg(dir)
        .output()
}

/// Deregister with `agy plugin uninstall <PLUGIN_NAME>`.
pub fn run_uninstall() -> io::Result<Output> {
    Command::new(agy_program())
        .args(["plugin", "uninstall", PLUGIN_NAME])
        .output()
}

/// Human-readable preview of what `--write` would do (the bundle contents and
/// the `agy` command), mirroring `install::render_block` for the merge agents.
pub fn render_block(exe: &str, capture: &str) -> String {
    let dir = staging_dir();
    let dir_s = dir.display();
    let pj = serde_json::to_string_pretty(&plugin_json()).unwrap_or_default();
    let hj = serde_json::to_string_pretty(&hooks_json(exe, capture)).unwrap_or_default();
    format!(
        "// Antigravity registers hooks via an imported plugin, not a settings file.\n\
         // NOTE: current agy (>=1.0.7) does NOT fire this command-hook (sigil #112);\n\
         // `install --agent antigravity` is a no-op unless you pass --force.\n\
         // Under --force, --write writes this bundle to\n\
         //   {dir_s}\n\
         // then runs: agy plugin install {dir_s}\n\
         //\n\
         // {dir_s}/plugin.json:\n\
         {pj}\n\
         // {dir_s}/hooks/hooks.json:\n\
         {hj}\n\
         // remove with: sigil-hook uninstall --agent antigravity --write\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_json_names_the_plugin_and_carries_version() {
        let v = plugin_json();
        assert_eq!(v["name"], json!(PLUGIN_NAME));
        assert_eq!(v["version"], json!(env!("CARGO_PKG_VERSION")));
        assert!(v["description"].as_str().unwrap().contains("Sigil"));
    }

    #[test]
    fn hooks_json_is_bare_pretooluse_with_command() {
        let v = hooks_json("/abs/sigil-hook", "redacted");
        // Top-level PreToolUse (NOT under a `hooks` wrapper) — the shape agy
        // accepts inside a plugin's hooks/hooks.json.
        let arr = v["PreToolUse"].as_array().expect("PreToolUse array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["matcher"], json!("*"));
        let cmd = arr[0]["hooks"][0]["command"].as_str().unwrap();
        assert_eq!(cmd, "/abs/sigil-hook antigravity --capture redacted");
        assert_eq!(arr[0]["hooks"][0]["type"], json!("command"));
        // No nested `hooks.PreToolUse` — that would be the settings.json shape.
        assert!(v["hooks"].is_null());
    }

    #[test]
    fn hooks_json_threads_capture_level() {
        let v = hooks_json("/x/sigil-hook", "raw");
        let cmd = v["PreToolUse"][0]["hooks"][0]["command"].as_str().unwrap();
        assert!(cmd.ends_with("--capture raw"));
    }

    #[test]
    fn write_bundle_creates_canonical_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("sigil-hook");
        write_bundle(&dir, "/abs/sigil-hook", "redacted").unwrap();

        // plugin.json round-trips.
        let pj: Value =
            serde_json::from_slice(&std::fs::read(dir.join("plugin.json")).unwrap()).unwrap();
        assert_eq!(pj["name"], json!(PLUGIN_NAME));

        // hooks live at hooks/hooks.json (the required subdirectory), not root.
        assert!(!dir.join("hooks.json").exists());
        let hj: Value =
            serde_json::from_slice(&std::fs::read(dir.join("hooks/hooks.json")).unwrap()).unwrap();
        assert_eq!(hj, hooks_json("/abs/sigil-hook", "redacted"));
    }

    #[test]
    fn staging_dir_ends_with_plugin_name() {
        assert!(staging_dir().ends_with(PLUGIN_NAME));
    }

    #[test]
    fn render_block_shows_agy_command_and_both_files() {
        let s = render_block("/abs/sigil-hook", "redacted");
        assert!(s.contains("agy plugin install"));
        assert!(s.contains("plugin.json"));
        assert!(s.contains("hooks/hooks.json"));
        assert!(s.contains("/abs/sigil-hook antigravity --capture redacted"));
    }
}
