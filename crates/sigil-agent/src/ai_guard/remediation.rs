//! #188-followup A — one-line, advisory remediation hints per AI-Guard reason.
//! Turns a `sigil scan` score into action: each finding maps to a short "how to
//! reduce it" line. Advisory only — Sigil measures, it does not block or
//! auto-edit, so hints suggest, never act.
//!
//! `hint_for_reason` matches the `AiGuardReason` variant directly (not its wire
//! `kind` string), so the exhaustive match makes a new reason variant fail to
//! compile here until it has a hint — the same drift guard `rubric::kind_key`
//! and `tool_cli_label` use. Hints are general per variant (one line), so a
//! finding's distinguishing fields don't change the guidance.

use sigil_core::event::AiGuardReason;

/// Advisory one-liner for a finding. Always non-empty.
pub fn hint_for_reason(reason: &AiGuardReason) -> &'static str {
    use AiGuardReason::*;
    match reason {
        DestructiveInInlineCommand { .. } => {
            "A hook runs a destructive shell command inline — review and remove it."
        }
        DestructiveInHookScript { .. } => {
            "A hook script contains a destructive pattern — review the referenced script."
        }
        SandboxDisabled => {
            "The sandbox is disabled — restore a non-bypass sandbox mode in the tool's config."
        }
        NoSandbox { .. } => {
            "The agent runs with no sandbox boundary — enable the tool's sandbox or limit what it can run."
        }
        PermissionsAllowBroad { .. } => {
            "A wildcard allow rule grants broad tool access — narrow it to specific commands."
        }
        ExternalScriptUnscanned { .. } => {
            "A hook calls an external script Sigil can't read — review it, or keep hook scripts in the convention dir."
        }
        BroadMatcher { .. } => {
            "A broad hook matcher catches most or all tool calls — scope it to specific tools."
        }
        PermissionsDenyEmpty => {
            "The deny list is empty — add deny rules so permissions actually block something."
        }
        McpServerRemote { .. } => {
            "A remote MCP server is configured — confirm you trust the endpoint and what it can see."
        }
        McpServerLocalCommand { .. } => {
            "An MCP server auto-launches a local command — review or remove it, or run it sandboxed."
        }
        TrustedMcpServer { .. } => {
            "An MCP server is marked trusted (skips per-tool confirmation) — remove the trust flag unless required."
        }
        AutoApprovalEnabled { .. } => {
            "Auto-approval is on — turn it off so tool calls require confirmation."
        }
        McpServerSuspiciousLauncher { .. } => {
            "An MCP server uses a suspicious launcher (shell exec or a transient/writable path) — pin it to a trusted binary."
        }
        ProjectMcpAutoEnabled { .. } => {
            "Project MCP servers auto-launch on folder-trust — disable project-MCP autorun."
        }
        InstructionFileDirective { .. } => {
            "An instruction file contains a flagged directive (fetch-pipe, destructive, obfuscated, or an override marker) — review it for prompt injection."
        }
        UnattendedScheduledTask { .. } => {
            "An unattended scheduled task runs Claude Code on a recurring basis — review its prompt and permissions, or remove it if unexpected."
        }
        McpToolInstructionOverride { .. } => {
            "An MCP tool's description contains instructions aimed at your agent — treat the server as untrusted; remove it or pin a reviewed version."
        }
        McpToolHiddenText { .. } => {
            "An MCP tool's advertised text contains hidden or deceptive Unicode (zero-width, bidi, or homoglyphs) — inspect the raw metadata and remove the server unless you trust it."
        }
        McpToolNameShadow { .. } => {
            "The same MCP tool name is offered by multiple servers — a server may be shadowing a trusted tool; disambiguate or remove the untrusted one."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints_are_nonempty_and_specific() {
        // A representative sample across the field-bearing and unit variants;
        // the exhaustive match in hint_for_reason guarantees the rest compile.
        let samples = [
            AiGuardReason::SandboxDisabled,
            AiGuardReason::PermissionsDenyEmpty,
            AiGuardReason::AutoApprovalEnabled {
                mode: "auto_edit".into(),
            },
        ];
        for r in &samples {
            assert!(!hint_for_reason(r).is_empty());
        }
    }
}
