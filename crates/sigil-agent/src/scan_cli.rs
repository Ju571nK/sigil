//! `sigil scan` — one-shot, daemon-free personal posture scan (#174).
//!
//! Reads each built-in AI-agent guard surface once — the user-global configs
//! under `$HOME` (`~/.claude`, `~/.codex`, `~/.cursor`, …) plus the current
//! directory if it is a project — scores the findings with the default rubric,
//! and prints a headline + per-tool table (or JSON). No daemon, no state.db, no
//! policy required. Always exits 0 (informational; this is "show me my score",
//! not a gate).

use crate::ai_guard::parser::AiGuardParser;
use crate::ai_guard::{rubric, tool_cli_label, user_global_parsers};
use sigil_core::event::{AiGuardBucket, AiGuardReason, AiGuardScope, AiTool};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Arguments for `sigil scan`. The `*_override` fields are test seams; the
/// binary always passes `None` (resolve `$HOME` / current dir).
pub struct ScanArgs {
    /// Emit the full report as pretty JSON instead of the human table.
    pub json: bool,
    /// Override the home dir. `None` → `$HOME` / `%USERPROFILE%`.
    pub home_override: Option<PathBuf>,
    /// Override the project dir. `None` → `current_dir()`.
    pub cwd_override: Option<PathBuf>,
}

/// One assessed (tool, scope) — a configured tool, even if it scored clean.
struct Row {
    tool: AiTool,
    scope: AiGuardScope,
    score: f32,
    bucket: AiGuardBucket,
    reasons: Vec<AiGuardReason>,
}

struct Report {
    rows: Vec<Row>,
    /// Tools whose config files are absent (not installed / not used).
    not_configured: Vec<AiTool>,
    /// (tool, scope, message) for parsers whose config failed to read/parse.
    errors: Vec<(AiTool, AiGuardScope, String)>,
}

/// CLI entry. Resolves home + cwd, builds the report, prints it, returns 0.
pub fn run(args: ScanArgs) -> i32 {
    let home = match args.home_override.or_else(default_home) {
        Some(h) => h,
        None => {
            eprintln!("sigil scan: could not resolve home dir (set $HOME or %USERPROFILE%)");
            return 0;
        }
    };
    let cwd = args.cwd_override.or_else(|| std::env::current_dir().ok());

    if args.json {
        let v = report_json(&build_report(&home, cwd.as_deref()));
        println!(
            "{}",
            serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".into())
        );
    } else {
        print!("{}", render_human(&build_report(&home, cwd.as_deref())));
    }
    0
}

/// Test seam — assemble the JSON report for a given home + optional project dir
/// without going through `current_dir()` or printing. Used by integration tests.
pub fn report_json_for(home: &Path, cwd: Option<&Path>) -> serde_json::Value {
    report_json(&build_report(home, cwd))
}

/// Test seam — the human-rendered report as a string.
pub fn render_human_for(home: &Path, cwd: Option<&Path>) -> String {
    render_human(&build_report(home, cwd))
}

fn default_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var_os("USERPROFILE").filter(|s| !s.is_empty()))
        .map(PathBuf::from)
}

fn build_report(home: &Path, cwd: Option<&Path>) -> Report {
    let mut parsers = user_global_parsers();
    if let Some(dir) = cwd {
        parsers.extend(project_parsers_for_dir(dir));
    }

    let mut rows = Vec::new();
    let mut not_configured = Vec::new();
    let mut errors = Vec::new();

    for p in &parsers {
        let configured = p.watched_paths(home).iter().any(|path| path.exists());
        match p.assess(home) {
            Ok(reasons) => {
                if reasons.is_empty() && !configured {
                    // Tool not installed / not used — summarize in the footer.
                    not_configured.push(p.tool());
                } else {
                    let score = rubric::score(&reasons);
                    rows.push(Row {
                        tool: p.tool(),
                        scope: p.scope(),
                        score,
                        bucket: rubric::bucket(score),
                        reasons,
                    });
                }
            }
            Err(e) => errors.push((p.tool(), p.scope(), e.to_string())),
        }
    }

    // Worst (highest score) first; ties broken by stable tool label.
    rows.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| tool_cli_label(a.tool).cmp(tool_cli_label(b.tool)))
    });
    not_configured.sort_by_key(|t| tool_cli_label(*t));
    not_configured.dedup();

    Report {
        rows,
        not_configured,
        errors,
    }
}

/// Build the project parsers for `dir` if (and only if) `dir` itself carries a
/// tool's project markers. Mirrors the per-repo discovery markers used by the
/// daemon (`workspace_discovery`), but applied to `dir` directly rather than to
/// its subdirectories.
fn project_parsers_for_dir(dir: &Path) -> Vec<Arc<dyn AiGuardParser>> {
    use crate::ai_guard::{
        AntigravityProjectParser, ClaudeCodeProjectParser, CodexProjectParser,
        ContinueDevProjectParser, CursorProjectParser, GeminiProjectParser,
    };
    let mut out: Vec<Arc<dyn AiGuardParser>> = Vec::new();
    let has = |rel: &str| dir.join(rel).exists();
    let root = || dir.to_path_buf();

    // Claude Code: .claude/settings.json | .mcp.json | CLAUDE.md | AGENTS.md
    if has(".claude/settings.json") || has(".mcp.json") || has("CLAUDE.md") || has("AGENTS.md") {
        out.push(Arc::new(ClaudeCodeProjectParser { repo_root: root() }));
    }
    // Codex: .codex/config.toml | AGENTS.md
    if has(".codex/config.toml") || has("AGENTS.md") {
        out.push(Arc::new(CodexProjectParser { repo_root: root() }));
    }
    // Cursor: .cursor/mcp.json | .cursorrules | .cursor/rules/ (directory)
    if has(".cursor/mcp.json") || has(".cursorrules") || dir.join(".cursor").join("rules").is_dir()
    {
        out.push(Arc::new(CursorProjectParser { repo_root: root() }));
    }
    // Continue.dev: .continue/config.json
    if has(".continue/config.json") {
        out.push(Arc::new(ContinueDevProjectParser { repo_root: root() }));
    }
    // Gemini: .gemini/settings.json
    if has(".gemini/settings.json") {
        out.push(Arc::new(GeminiProjectParser { repo_root: root() }));
    }
    // Antigravity: .antigravity/settings.json
    if has(".antigravity/settings.json") {
        out.push(Arc::new(AntigravityProjectParser { repo_root: root() }));
    }
    out
}

// ---- rendering -------------------------------------------------------------

fn scope_str(scope: &AiGuardScope) -> String {
    match scope {
        AiGuardScope::UserGlobal => "user-global".to_string(),
        AiGuardScope::Project { path } => format!("project:{}", path.display()),
        AiGuardScope::Application { app } => format!("application:{app}"),
    }
}

fn bucket_wire(b: AiGuardBucket) -> &'static str {
    match b {
        AiGuardBucket::Low => "low",
        AiGuardBucket::Medium => "medium",
        AiGuardBucket::High => "high",
        AiGuardBucket::Critical => "critical",
    }
}

/// Round to one decimal, returning `f64` so JSON serializes as a clean "5.8"
/// rather than the f32 round-trip artifact "5.800000190734863".
fn round1(x: f32) -> f64 {
    (x as f64 * 10.0).round() / 10.0
}

/// Distinct reason kinds (the serde `kind` tag) for a row, in first-seen order.
fn reason_kinds(reasons: &[AiGuardReason]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for r in reasons {
        let kind = serde_json::to_value(r)
            .ok()
            .and_then(|v| v.get("kind").and_then(|k| k.as_str()).map(str::to_string))
            .unwrap_or_else(|| "unknown".to_string());
        if !seen.contains(&kind) {
            seen.push(kind);
        }
    }
    seen
}

/// Short "top findings" cell: up to two distinct kinds, then "(+N more)".
fn reasons_summary(reasons: &[AiGuardReason]) -> String {
    if reasons.is_empty() {
        return "(clean)".to_string();
    }
    let kinds = reason_kinds(reasons);
    let shown = kinds.iter().take(2).cloned().collect::<Vec<_>>().join(", ");
    let extra = kinds.len().saturating_sub(2);
    if extra > 0 {
        format!("{shown} (+{extra} more)")
    } else {
        shown
    }
}

/// (bucket, score, tools_assessed, findings) — the headline. The bucket/score
/// come from the single worst scope (max score), not a sum across tools.
fn headline(report: &Report) -> (AiGuardBucket, f32, usize, usize) {
    let worst = report
        .rows
        .iter()
        .fold((AiGuardBucket::Low, 0.0_f32), |acc, r| {
            if r.score > acc.1 {
                (r.bucket, r.score)
            } else {
                acc
            }
        });
    let findings = report.rows.iter().map(|r| r.reasons.len()).sum();
    (worst.0, worst.1, report.rows.len(), findings)
}

fn render_human(report: &Report) -> String {
    use std::fmt::Write;
    let (hb, hs, tools, findings) = headline(report);
    let mut out = String::new();

    let _ = writeln!(
        out,
        "Sigil scan — {} ({:.1})",
        bucket_wire(hb).to_uppercase(),
        round1(hs)
    );
    let _ = writeln!(out, "{tools} tools assessed · {findings} findings\n");

    if !report.rows.is_empty() {
        // Column widths sized to content for clean alignment.
        let tcol = report
            .rows
            .iter()
            .map(|r| tool_cli_label(r.tool).len())
            .chain(std::iter::once("TOOL".len()))
            .max()
            .unwrap_or(4);
        let scol = report
            .rows
            .iter()
            .map(|r| scope_str(&r.scope).len())
            .chain(std::iter::once("SCOPE".len()))
            .max()
            .unwrap_or(5);
        let _ = writeln!(
            out,
            "{:<tcol$}  {:<scol$}  {:>5}  {:<8}  TOP FINDINGS",
            "TOOL", "SCOPE", "SCORE", "BUCKET"
        );
        for r in &report.rows {
            let _ = writeln!(
                out,
                "{:<tcol$}  {:<scol$}  {:>5.1}  {:<8}  {}",
                tool_cli_label(r.tool),
                scope_str(&r.scope),
                round1(r.score),
                bucket_wire(r.bucket),
                reasons_summary(&r.reasons),
            );
        }
        out.push('\n');
    } else {
        let _ = writeln!(out, "No configured AI agents found to assess.\n");
    }

    if !report.not_configured.is_empty() {
        let names = report
            .not_configured
            .iter()
            .map(|t| tool_cli_label(*t))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            out,
            "{} tools not configured: {names}",
            report.not_configured.len()
        );
    }
    for (tool, scope, msg) in &report.errors {
        let _ = writeln!(
            out,
            "⚠ could not read {} ({}): {msg}",
            tool_cli_label(*tool),
            scope_str(scope)
        );
    }

    if !report.rows.is_empty() {
        let _ = writeln!(out, "\nRun `sigil scan --json` for full detail.");
    }
    out
}

fn report_json(report: &Report) -> serde_json::Value {
    use serde_json::json;
    let (hb, hs, tools, findings) = headline(report);
    json!({
        "headline": {
            "bucket": bucket_wire(hb),
            "score": round1(hs),
            "tools_assessed": tools,
            "findings": findings,
        },
        "results": report.rows.iter().map(|r| json!({
            "tool": tool_cli_label(r.tool),
            "scope": scope_str(&r.scope),
            "score": round1(r.score),
            "bucket": bucket_wire(r.bucket),
            "reasons": r.reasons,
        })).collect::<Vec<_>>(),
        "not_configured": report.not_configured.iter()
            .map(|t| tool_cli_label(*t)).collect::<Vec<_>>(),
        "errors": report.errors.iter().map(|(t, s, m)| json!({
            "tool": tool_cli_label(*t),
            "scope": scope_str(s),
            "error": m,
        })).collect::<Vec<_>>(),
    })
}
