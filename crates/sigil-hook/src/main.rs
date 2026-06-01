mod adapters;
mod emit;
mod redact;

use sigil_core::hook_proto::*;
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand, ValueEnum};

const MAX_STDIN: usize = 1024 * 1024;

fn run_hook(agent: &str, capture: CaptureLevel) -> ! {
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

/// Same directory the agent's control socket resolves to, but named hook.sock.
fn hook_socket_path() -> PathBuf {
    let uid = unsafe { libc::geteuid() };
    let xdg = std::env::var("XDG_RUNTIME_DIR").ok();
    let tmp = std::env::var("TMPDIR").ok();
    sigil_core::control_proto::resolve_control_socket(uid == 0, xdg, tmp, uid)
        .with_file_name("hook.sock")
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
    }
}
