mod adapters;
mod decide;
mod emit;
mod install;
mod install_antigravity;
mod install_grok;
mod redact;
mod verify;

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

/// Resolve the decide socket for the enforce path. Mirrors `hook_socket_path`
/// but targets `hook-decide.sock` (the Stage 2 synchronous channel).
/// `SIGIL_HOOK_DECIDE_SOCKET` overrides everything.
#[cfg(unix)]
fn hook_decide_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("SIGIL_HOOK_DECIDE_SOCKET") {
        return PathBuf::from(p);
    }
    let system = PathBuf::from("/var/run/sigil/hook-decide.sock");
    if system.exists() {
        return system;
    }
    let uid = unsafe { libc::geteuid() };
    let xdg = std::env::var("XDG_RUNTIME_DIR").ok();
    let tmp = std::env::var("TMPDIR").ok();
    sigil_core::control_proto::resolve_control_socket(uid == 0, xdg, tmp, uid)
        .with_file_name("hook-decide.sock")
}

#[cfg(not(unix))]
fn hook_decide_socket_path() -> PathBuf {
    std::env::var("SIGIL_HOOK_DECIDE_SOCKET")
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
    /// Claude Code PreToolUse entrypoint: observe (emit, exit 0), or --enforce (deny-decision path).
    #[command(name = "claude-code")]
    ClaudeCode {
        #[arg(long, value_enum, default_value_t = CaptureArg::Redacted)]
        capture: CaptureArg,
        /// Stage 2: run the synchronous deny-decision path instead of observe.
        #[arg(long)]
        enforce: bool,
        /// Behavior when no verdict is obtainable. Default open (fail-open).
        #[arg(long, value_enum, default_value_t = OnFailureArg::Open)]
        on_failure: OnFailureArg,
    },

    /// Codex CLI PreToolUse entrypoint: observe (emit, exit 0), or --enforce (deny-decision path).
    Codex {
        #[arg(long, value_enum, default_value_t = CaptureArg::Redacted)]
        capture: CaptureArg,
        /// Stage 2: run the synchronous deny-decision path instead of observe.
        #[arg(long)]
        enforce: bool,
        /// Behavior when no verdict is obtainable. Default open (fail-open).
        #[arg(long, value_enum, default_value_t = OnFailureArg::Open)]
        on_failure: OnFailureArg,
    },

    /// Cursor before{Shell,MCP}Execution entrypoint: observe (emit, exit 0), or --enforce (deny-decision path).
    Cursor {
        #[arg(long, value_enum, default_value_t = CaptureArg::Redacted)]
        capture: CaptureArg,
        /// Stage 2: run the synchronous deny-decision path instead of observe.
        #[arg(long)]
        enforce: bool,
        /// Behavior when no verdict is obtainable. Default open (fail-open).
        #[arg(long, value_enum, default_value_t = OnFailureArg::Open)]
        on_failure: OnFailureArg,
    },

    /// Antigravity PreToolUse entrypoint: read stdin, emit, exit 0.
    Antigravity {
        #[arg(long, value_enum, default_value_t = CaptureArg::Redacted)]
        capture: CaptureArg,
    },

    /// Grok Build PreToolUse entrypoint: observe (emit, exit 0), or --enforce (deny-decision path).
    Grok {
        #[arg(long, value_enum, default_value_t = CaptureArg::Redacted)]
        capture: CaptureArg,
        /// Stage 2: run the synchronous deny-decision path instead of observe.
        #[arg(long)]
        enforce: bool,
        /// Behavior when no verdict is obtainable. Default open (fail-open).
        #[arg(long, value_enum, default_value_t = OnFailureArg::Open)]
        on_failure: OnFailureArg,
    },

    /// Print (or write) the sigil-hook registration for an agent.
    ///
    /// claude-code | codex | cursor merge into a settings JSON file; antigravity
    /// is registered as an `agy` plugin bundle (`agy plugin install`); grok
    /// writes a dedicated ~/.grok/hooks/sigil-hook.json file.
    Install {
        /// Agent to register with: claude-code | codex | cursor | antigravity | grok.
        #[arg(long, default_value = INSTALL_AGENT_DEFAULT)]
        agent: String,
        /// Apply the change to the settings file (default: print only).
        #[arg(long)]
        write: bool,
        /// Capture level for the registered hook command.
        #[arg(long, value_enum, default_value_t = CaptureArg::Redacted)]
        capture: CaptureArg,
        /// Register the Stage 2 enforce (deny-decision) hook instead of observe.
        #[arg(long)]
        enforce: bool,
        /// Fail mode baked into the enforce command. Default open.
        #[arg(long, value_enum, default_value_t = OnFailureArg::Open)]
        on_failure: OnFailureArg,
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

    /// tamper-evidence: compare the live hook registration against the install baseline.
    Verify {
        /// Agent whose registration to verify (slice 1: claude-code).
        #[arg(long, default_value = INSTALL_AGENT_DEFAULT)]
        agent: String,
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

/// Behavior when no verdict is obtainable from the decide daemon.
#[derive(Copy, Clone, ValueEnum)]
enum OnFailureArg {
    Open,
    Closed,
}

/// Maximum elapsed time waiting for a verdict before falling back to on_failure.
const DECISION_DEADLINE: Duration = Duration::from_millis(250);

/// Per-agent enforce entrypoint. Panic-safe; never hangs past the watchdog.
/// On Deny → emit the agent's deny output; on a deliberate Allow → emit the
/// agent's allow output (empty for agents where silence==allow). A
/// panic/watchdog exits silently (empty stdout), which Cursor's failClosed
/// converts to a block in closed mode.
/// No verdict (daemon down / timeout / malformed) → apply on_failure.
fn run_enforce(agent: &str, capture: CaptureLevel, on_failure: OnFailureArg) -> ! {
    std::panic::set_hook(Box::new(|_| std::process::exit(0)));
    emit::arm_watchdog(Duration::from_millis(800)); // > decision deadline, < agent UX budget
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

    let req = HookDecisionRequest {
        protocol_version: HOOK_PROTOCOL_VERSION,
        request_id: uuid::Uuid::now_v7(),
        sent_at_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
        invocation: inv,
        deadline_ms: DECISION_DEADLINE.as_millis() as u32,
    };

    match decide::request_verdict(&hook_decide_socket_path(), &req, DECISION_DEADLINE) {
        Some(v) => match (v.decision, v.enforcement_mode) {
            // Only block when the daemon explicitly says Deny AND is in Enforce mode.
            // A Deny down-shifted to Observe (spec §4) must not block the tool call.
            (Decision::Deny { rule_id, reason }, EnforcementMode::Enforce) => {
                emit_deny(&*adapter, &rule_id, &reason);
            }
            // Allow, or a Deny down-shifted to Observe → do not block.
            _ => emit_allow(&*adapter),
        },
        None => match on_failure {
            OnFailureArg::Open => emit_allow(&*adapter),
            OnFailureArg::Closed => {
                emit_deny(
                    &*adapter,
                    "fail_closed",
                    "decision unavailable; on_failure=closed",
                );
            }
        },
    }
}

/// Emit the adapter's explicit allow output (if any) and exit 0. Used on every
/// DELIBERATE-allow branch so the only empty-stdout exit is a panic/watchdog
/// failure — which Cursor's failClosed converts to a block in closed mode.
fn emit_allow(adapter: &dyn adapters::HookAdapter) -> ! {
    if let Some(s) = adapter.allow_output() {
        println!("{s}");
    }
    std::process::exit(0);
}

/// Print the adapter's deny output (if any) and exit with its code.
fn emit_deny(adapter: &dyn adapters::HookAdapter, rule_id: &str, reason: &str) -> ! {
    let out = adapter.deny_output(rule_id, reason);
    if let Some(s) = out.stdout {
        // println! appends a trailing newline; the agent reads the deny response as a line.
        println!("{s}");
    }
    std::process::exit(out.exit_code);
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::ClaudeCode {
            capture,
            enforce,
            on_failure,
        } => {
            if enforce {
                run_enforce("claude-code", capture.into(), on_failure)
            } else {
                run_hook("claude-code", capture.into())
            }
        }
        Cmd::Codex {
            capture,
            enforce,
            on_failure,
        } => {
            if enforce {
                run_enforce("codex", capture.into(), on_failure)
            } else {
                run_hook("codex", capture.into())
            }
        }
        Cmd::Cursor {
            capture,
            enforce,
            on_failure,
        } => {
            if enforce {
                run_enforce("cursor", capture.into(), on_failure)
            } else {
                run_hook("cursor", capture.into())
            }
        }
        Cmd::Antigravity { capture } => run_hook("antigravity", capture.into()),
        Cmd::Grok {
            capture,
            enforce,
            on_failure,
        } => {
            if enforce {
                run_enforce("grok", capture.into(), on_failure)
            } else {
                run_hook("grok", capture.into())
            }
        }
        Cmd::Install {
            agent,
            write,
            capture,
            enforce,
            on_failure,
        } => cmd_install(&agent, write, capture, enforce, on_failure),
        Cmd::Uninstall { agent, write } => cmd_uninstall(&agent, write),
        Cmd::Verify { agent } => std::process::exit(cmd_verify(&agent)),
    }
}

fn exe_path() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "sigil-hook".to_string())
}

fn cmd_install(
    agent: &str,
    write: bool,
    capture: CaptureArg,
    enforce: bool,
    on_failure: OnFailureArg,
) {
    let capture_str = match capture {
        CaptureArg::Redacted => "redacted",
        CaptureArg::Raw => "raw",
        CaptureArg::HashOnly => "hash-only",
    };
    let on_failure_str = match on_failure {
        OnFailureArg::Open => "open",
        OnFailureArg::Closed => "closed",
    };
    let exe = exe_path();

    // Antigravity is not a settings-merge agent: it installs as an `agy` plugin
    // bundle. Route it through the dedicated path.
    if agent == "antigravity" {
        return cmd_install_antigravity(&exe, write, capture_str);
    }

    // Grok is not a settings-merge agent: it writes a dedicated
    // ~/.grok/hooks/sigil-hook.json file. Route before settings_path.
    if agent == "grok" {
        return cmd_install_grok(&exe, write, capture_str, enforce, on_failure_str);
    }

    if !write {
        if enforce {
            print!(
                "{}",
                install::render_block_enforce(&exe, agent, capture_str, on_failure_str)
            );
        } else {
            print!("{}", install::render_block(&exe, agent, capture_str));
        }
        return;
    }

    // Enforce-mode --write is supported for the NestedPreToolUse agents
    // (claude-code, codex), for cursor (beforeShellExecution/beforeMCPExecution),
    // and for grok (native ~/.grok/hooks). Guard any other agent so we never
    // write a misleading settings file. (antigravity routes to its own plugin
    // path above; grok routes to cmd_install_grok above — so by here the only
    // enforce-capable agents reaching the generic path are claude-code/codex/cursor.)
    if enforce && !matches!(agent, "claude-code" | "codex" | "grok" | "cursor") {
        eprintln!(
            "error: enforce-mode install is only supported for claude-code/codex/grok/cursor in this slice (agent '{agent}' not registered)"
        );
        std::process::exit(1);
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

    let changed = if enforce {
        install::merge_into_enforce(&mut root, &exe, agent, capture_str, on_failure_str)
    } else {
        install::merge_into(&mut root, &exe, agent, capture_str)
    };

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

    // Write baseline / update discovery index. Only for agents whose `verify`
    // path is implemented (claude-code/codex). Cursor's settings use
    // beforeShellExecution/beforeMCPExecution, which slice-1 verify can't check,
    // and the baseline is a single global file — a cursor baseline would both
    // false-positive `verify` and clobber the claude one (spec D6). (grok and
    // antigravity never reach here; they return to their own install fns above.)
    if matches!(agent, "claude-code" | "codex") {
        if let Err(e) = install::write_baseline(
            agent,
            &sp,
            &exe,
            agent,
            capture_str,
            "*",
            enforce,
            on_failure_str,
        ) {
            eprintln!("warning: could not write baseline: {e}");
        }
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

    if agent == "grok" {
        return cmd_uninstall_grok(write);
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

/// Grok install: write ~/.grok/hooks/sigil-hook.json (Grok's always-trusted
/// native hook dir). Without `--write`, print the JSON + target path.
fn cmd_install_grok(exe: &str, write: bool, capture: &str, enforce: bool, on_failure: &str) {
    let v = install_grok::hook_json(exe, capture, enforce, on_failure);
    let Some(path) = install_grok::hook_file() else {
        eprintln!("cannot resolve home dir");
        std::process::exit(1);
    };
    if !write {
        println!(
            "// Write this to {}:\n{}",
            path.display(),
            serde_json::to_string_pretty(&v).unwrap()
        );
        return;
    }
    match install_grok::write_file_at(&path, &v) {
        Ok(()) => println!("installed grok hook → {}", path.display()),
        Err(e) => {
            eprintln!("write failed: {e}");
            std::process::exit(1);
        }
    }
}

/// Grok uninstall: remove ~/.grok/hooks/sigil-hook.json.
/// Without `--write`, print what would be removed.
fn cmd_uninstall_grok(write: bool) {
    let Some(path) = install_grok::hook_file() else {
        eprintln!("cannot resolve home dir");
        std::process::exit(1);
    };
    if !write {
        println!("// Would remove {}", path.display());
        return;
    }
    match install_grok::remove_file_at(&path) {
        Ok(()) => println!("removed {}", path.display()),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
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

fn drift_exit_code(kind: DriftKind) -> i32 {
    use sigil_core::hook_proto::DriftKind::*;
    match kind {
        BaselineAbsent => 3,
        EntryMissing | CommandDrift | MatcherDrift | FailModeDrift => 2,
    }
}

fn cmd_verify(_agent: &str) -> i32 {
    use sigil_core::event::AiTool;

    let Some(report) = verify::check() else {
        println!("[OK]    hook registration matches baseline");
        return 0;
    };

    match report.kind {
        DriftKind::BaselineAbsent => println!(
            "[DRIFT] baseline not found at {} (baseline_absent)",
            report.settings_path
        ),
        DriftKind::EntryMissing => println!(
            "[DRIFT] no sigil hook entry in {} (entry_missing)",
            report.settings_path
        ),
        DriftKind::CommandDrift => println!(
            "[DRIFT] hook command changed in {} — binary repoint / flag flip (command_drift)",
            report.settings_path
        ),
        DriftKind::MatcherDrift => println!(
            "[DRIFT] matcher changed: {:?} -> {:?} (matcher_drift)",
            report.expected_matcher.as_deref().unwrap_or("?"),
            report.observed_matcher.as_deref().unwrap_or("?"),
        ),
        DriftKind::FailModeDrift => println!(
            "[DRIFT] hook fail-mode (failClosed) changed in {} (fail_mode_drift)",
            report.settings_path
        ),
    }

    // Best-effort emit over hook.sock (agent-down -> still printed + exits).
    let env = HookDriftEnvelope {
        protocol_version: HOOK_PROTOCOL_VERSION,
        msg_type: HookMsgType::DriftReport,
        request_id: uuid::Uuid::now_v7(),
        sent_at_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
        payload: HookConfigDriftReport {
            agent: AiTool::ClaudeCode, // slice 1
            drift_kind: report.kind,
            settings_path: report.settings_path.clone(),
            expected_command_hash: report.expected_command_hash.clone(),
            observed_command_hash: report.observed_command_hash.clone(),
            expected_matcher: report.expected_matcher.clone(),
            observed_matcher: report.observed_matcher.clone(),
        },
    };
    if let Ok(line) = serde_json::to_string(&env) {
        let _ = emit::send_envelope(&hook_socket_path(), &line, Duration::from_millis(150));
    }
    drift_exit_code(report.kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drift_exit_codes() {
        use sigil_core::hook_proto::DriftKind::*;
        assert_eq!(drift_exit_code(BaselineAbsent), 3);
        assert_eq!(drift_exit_code(EntryMissing), 2);
        assert_eq!(drift_exit_code(CommandDrift), 2);
        assert_eq!(drift_exit_code(MatcherDrift), 2);
        assert_eq!(drift_exit_code(FailModeDrift), 2);
    }
}
