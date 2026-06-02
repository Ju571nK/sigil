mod adapters;
mod emit;
mod install;
mod install_antigravity;
mod redact;

use sigil_core::hook_proto::*;
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand, ValueEnum};

const INSTALL_AGENT_DEFAULT: &str = "claude-code";

const MAX_STDIN: usize = 1024 * 1024;

fn run_hook(agent: &str, capture: CaptureLevel) -> ! {
    // Spec §7: a panic on the hot path must never print to stderr and must
    // still exit 0 so the agent's tool call is never blocked.
    std::panic::set_hook(Box::new(|_| std::process::exit(0)));
    emit::arm_watchdog(Duration::from_millis(200));
    let adapter = match adapters::for_agent(agent) {
        Some(a) => a,
        None => std::process::exit(0),
    };

    let mut buf = Vec::new();
    let _ = std::io::stdin()
        .take(MAX_STDIN as u64 + 1)
        .read_to_end(&mut buf);
    let oversized = buf.len() > MAX_STDIN;
    let payload: serde_json::Value =
        serde_json::from_slice(&buf).unwrap_or(serde_json::Value::Null);

    let mut inv = match adapter.normalize(&payload, capture) {
        Ok(i) => i,
        Err(status) => minimal_unparsed(adapter.agent(), capture, status),
    };
    if oversized {
        inv.capture_status = CaptureStatus::Oversized;
    }

    let env = HookEnvelope {
        protocol_version: HOOK_PROTOCOL_VERSION,
        msg_type: HookMsgType::HookInvocation,
        request_id: uuid::Uuid::now_v7(),
        sent_at_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
        payload: inv,
    };
    if let Ok(line) = serde_json::to_string(&env) {
        let _ = emit::send_envelope(&hook_socket_path(), &line, Duration::from_millis(150));
    }
    std::process::exit(0);
}

fn minimal_unparsed(
    agent: sigil_core::event::AiTool,
    level: CaptureLevel,
    status: CaptureStatus,
) -> HookInvocation {
    HookInvocation {
        agent,
        agent_session_id: None,
        tool_use_id: None,
        action: HookAction::Other {
            label: "unparsed".into(),
            detail_hash: String::new(),
            detail_preview: None,
        },
        capture_level: level,
        capture_status: status,
        cwd: None,
    }
}

/// Resolve the agent's hook socket. In the root-daemon deployment the agent
/// (root) binds the SYSTEM socket `/var/run/sigil/hook.sock`, but a hook spawned
/// by the agent runs as the *developer's* user — resolving by the hook's own uid
/// would point at a per-user runtime path the daemon never binds (verified on
/// Rocky 9). So: prefer the system socket when it exists (root-daemon), else fall
/// back to the per-user path (non-root/local agent on the same uid).
/// `SIGIL_HOOK_SOCKET` overrides both.
#[cfg(unix)]
fn hook_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("SIGIL_HOOK_SOCKET") {
        return PathBuf::from(p);
    }
    let system = PathBuf::from("/var/run/sigil/hook.sock");
    if system.exists() {
        return system;
    }
    let uid = unsafe { libc::geteuid() };
    let xdg = std::env::var("XDG_RUNTIME_DIR").ok();
    let tmp = std::env::var("TMPDIR").ok();
    sigil_core::control_proto::resolve_control_socket(uid == 0, xdg, tmp, uid)
        .with_file_name("hook.sock")
}

/// Non-unix: only the `SIGIL_HOOK_SOCKET` override (the emit is a no-op stub on
/// Windows — see `emit::send_envelope`), so the value is effectively unused.
#[cfg(not(unix))]
fn hook_socket_path() -> PathBuf {
    std::env::var("SIGIL_HOOK_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_default()
}

#[derive(Parser)]
#[command(
    name = "sigil-hook",
    about = "Runtime observer at the AI agent tool boundary"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Claude Code PreToolUse entrypoint: read stdin, emit, exit 0.
    #[command(name = "claude-code")]
    ClaudeCode {
        #[arg(long, value_enum, default_value_t = CaptureArg::Redacted)]
        capture: CaptureArg,
    },

    /// Codex CLI PreToolUse entrypoint: read stdin, emit, exit 0.
    Codex {
        #[arg(long, value_enum, default_value_t = CaptureArg::Redacted)]
        capture: CaptureArg,
    },

    /// Cursor before{Shell,MCP}Execution entrypoint: read stdin, emit, exit 0.
    Cursor {
        #[arg(long, value_enum, default_value_t = CaptureArg::Redacted)]
        capture: CaptureArg,
    },

    /// Antigravity PreToolUse entrypoint: read stdin, emit, exit 0.
    Antigravity {
        #[arg(long, value_enum, default_value_t = CaptureArg::Redacted)]
        capture: CaptureArg,
    },

    /// Print (or write) the sigil-hook registration for an agent.
    ///
    /// claude-code | codex | cursor merge into a settings JSON file; antigravity
    /// is registered as an `agy` plugin bundle (`agy plugin install`).
    Install {
        /// Agent to register with: claude-code | codex | cursor | antigravity.
        #[arg(long, default_value = INSTALL_AGENT_DEFAULT)]
        agent: String,
        /// Apply the change to the settings file (default: print only).
        #[arg(long)]
        write: bool,
        /// Capture level for the registered hook command.
        #[arg(long, value_enum, default_value_t = CaptureArg::Redacted)]
        capture: CaptureArg,
    },

    /// Remove the sigil-hook registration from an agent's settings.
    Uninstall {
        /// Agent to deregister from.
        #[arg(long, default_value = INSTALL_AGENT_DEFAULT)]
        agent: String,
        /// Apply the change to the settings file (default: print what would be removed).
        #[arg(long)]
        write: bool,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum CaptureArg {
    Redacted,
    Raw,
    HashOnly,
}

impl From<CaptureArg> for CaptureLevel {
    fn from(a: CaptureArg) -> Self {
        match a {
            CaptureArg::Redacted => CaptureLevel::Redacted,
            CaptureArg::Raw => CaptureLevel::Raw,
            CaptureArg::HashOnly => CaptureLevel::HashOnly,
        }
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::ClaudeCode { capture } => run_hook("claude-code", capture.into()),
        Cmd::Codex { capture } => run_hook("codex", capture.into()),
        Cmd::Cursor { capture } => run_hook("cursor", capture.into()),
        Cmd::Antigravity { capture } => run_hook("antigravity", capture.into()),
        Cmd::Install {
            agent,
            write,
            capture,
        } => cmd_install(&agent, write, capture),
        Cmd::Uninstall { agent, write } => cmd_uninstall(&agent, write),
    }
}

fn exe_path() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "sigil-hook".to_string())
}

fn cmd_install(agent: &str, write: bool, capture: CaptureArg) {
    let capture_str = match capture {
        CaptureArg::Redacted => "redacted",
        CaptureArg::Raw => "raw",
        CaptureArg::HashOnly => "hash-only",
    };
    let exe = exe_path();

    // Antigravity is not a settings-merge agent: it installs as an `agy` plugin
    // bundle. Route it through the dedicated path.
    if agent == "antigravity" {
        return cmd_install_antigravity(&exe, write, capture_str);
    }

    if !write {
        print!("{}", install::render_block(&exe, agent, capture_str));
        return;
    }

    // Resolve the settings path for this agent.
    let sp = match install::settings_path(agent) {
        Some(p) => p,
        None => {
            eprintln!("error: unsupported agent '{agent}'");
            std::process::exit(1);
        }
    };

    // Read existing settings or start from an empty object.
    let mut root: serde_json::Value = if sp.exists() {
        let raw = match std::fs::read(&sp) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error reading {}: {e}", sp.display());
                std::process::exit(1);
            }
        };
        serde_json::from_slice(&raw).unwrap_or(serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    let changed = install::merge_into(&mut root, &exe, agent, capture_str);

    // Write back atomically: write to a temp file beside the target, then rename.
    let pretty = serde_json::to_string_pretty(&root).unwrap_or_default();
    if let Some(parent) = sp.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("error creating {}: {e}", parent.display());
            std::process::exit(1);
        }
    }

    // Atomic write: temp file + rename.
    let tmp_path = sp.with_extension("json.sigil-tmp");
    if let Err(e) = std::fs::write(&tmp_path, pretty.as_bytes()) {
        eprintln!("error writing temp file {}: {e}", tmp_path.display());
        std::process::exit(1);
    }
    if let Err(e) = std::fs::rename(&tmp_path, &sp) {
        eprintln!("error renaming to {}: {e}", sp.display());
        let _ = std::fs::remove_file(&tmp_path);
        std::process::exit(1);
    }

    // Write baseline / update discovery index.
    if let Err(e) = install::write_baseline(agent, &sp, &exe, agent, capture_str, "*") {
        eprintln!("warning: could not write baseline: {e}");
    }

    if changed {
        eprintln!("sigil-hook: installed for {agent} in {}", sp.display());
    } else {
        eprintln!("sigil-hook: already installed for {agent} (no change)");
    }
}

fn cmd_uninstall(agent: &str, write: bool) {
    let exe = exe_path();

    if agent == "antigravity" {
        return cmd_uninstall_antigravity(write);
    }

    let sp = match install::settings_path(agent) {
        Some(p) => p,
        None => {
            eprintln!("error: unsupported agent '{agent}'");
            std::process::exit(1);
        }
    };

    if !sp.exists() {
        eprintln!(
            "sigil-hook: settings file not found at {} — nothing to remove",
            sp.display()
        );
        return;
    }

    let raw = match std::fs::read(&sp) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error reading {}: {e}", sp.display());
            std::process::exit(1);
        }
    };
    let mut root: serde_json::Value = serde_json::from_slice(&raw).unwrap_or(serde_json::json!({}));

    let count = install::count_sigil_entries(&root, &exe, agent);
    if count == 0 {
        eprintln!(
            "sigil-hook: no entries found for {} in {}",
            exe,
            sp.display()
        );
        return;
    }

    if !write {
        eprintln!(
            "sigil-hook: would remove {count} entry/entries for {exe} from {} (pass --write to apply)",
            sp.display()
        );
        return;
    }

    install::remove_from(&mut root, &exe, agent);

    let pretty = serde_json::to_string_pretty(&root).unwrap_or_default();
    let tmp_path = sp.with_extension("json.sigil-tmp");
    if let Err(e) = std::fs::write(&tmp_path, pretty.as_bytes()) {
        eprintln!("error writing temp file {}: {e}", tmp_path.display());
        std::process::exit(1);
    }
    if let Err(e) = std::fs::rename(&tmp_path, &sp) {
        eprintln!("error renaming to {}: {e}", sp.display());
        let _ = std::fs::remove_file(&tmp_path);
        std::process::exit(1);
    }

    eprintln!(
        "sigil-hook: removed {count} entry/entries for {agent} from {}",
        sp.display()
    );
}

/// Antigravity install: materialize the plugin bundle, then register it with
/// `agy plugin install`. Without `--write`, print the bundle + command preview.
fn cmd_install_antigravity(exe: &str, write: bool, capture: &str) {
    if !write {
        print!("{}", install_antigravity::render_block(exe, capture));
        return;
    }

    let dir = install_antigravity::staging_dir();
    if let Err(e) = install_antigravity::write_bundle(&dir, exe, capture) {
        eprintln!(
            "error writing Antigravity plugin bundle to {}: {e}",
            dir.display()
        );
        std::process::exit(1);
    }

    match install_antigravity::run_install(&dir) {
        Ok(out) if out.status.success() => {
            eprintln!(
                "sigil-hook: installed Antigravity plugin via agy (bundle: {})",
                dir.display()
            );
        }
        Ok(out) => {
            // `agy` ran but rejected the install — surface its diagnostics and
            // the manual command so the user can finish registration.
            eprintln!(
                "sigil-hook: wrote bundle to {} but `agy plugin install` failed:\n{}",
                dir.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
            eprintln!("run manually: agy plugin install {}", dir.display());
            std::process::exit(1);
        }
        Err(e) => {
            // `agy` not found / not runnable: the bundle is written, so the user
            // can register it once `agy` is installed. Not an error exit.
            eprintln!(
                "sigil-hook: wrote Antigravity plugin bundle to {} (could not run agy: {e})",
                dir.display()
            );
            eprintln!("register it with: agy plugin install {}", dir.display());
        }
    }
}

/// Antigravity uninstall: deregister via `agy plugin uninstall` and remove the
/// staged bundle. Without `--write`, print what would happen.
fn cmd_uninstall_antigravity(write: bool) {
    let dir = install_antigravity::staging_dir();
    if !write {
        eprintln!(
            "sigil-hook: would run `agy plugin uninstall {}` and remove {} (pass --write to apply)",
            install_antigravity::PLUGIN_NAME,
            dir.display()
        );
        return;
    }

    match install_antigravity::run_uninstall() {
        Ok(out) if out.status.success() => {
            eprintln!("sigil-hook: removed Antigravity plugin via agy");
        }
        Ok(out) => {
            eprintln!(
                "sigil-hook: `agy plugin uninstall` returned non-zero:\n{}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Err(e) => {
            eprintln!(
                "sigil-hook: could not run agy ({e}); remove manually: agy plugin uninstall {}",
                install_antigravity::PLUGIN_NAME
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
