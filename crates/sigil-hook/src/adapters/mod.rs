// Consumed by later tasks (hook dispatch). Unused items are expected until then.
#![allow(dead_code)]

use sigil_core::event::AiTool;
use sigil_core::hook_proto::{CaptureLevel, CaptureStatus, HookInvocation};
pub mod claude_code;

/// One impl per agent. Turns a vendor stdin payload into a normalized
/// HookInvocation. (Shape mirrors ai_guard/parser, but is a distinct trait —
/// that one assesses on-disk config, this one normalizes runtime stdin.)
pub trait HookAdapter {
    fn agent(&self) -> AiTool;
    fn normalize(
        &self,
        payload: &serde_json::Value,
        level: CaptureLevel,
    ) -> Result<HookInvocation, CaptureStatus>;
}

pub fn for_agent(name: &str) -> Option<Box<dyn HookAdapter>> {
    match name {
        "claude-code" => Some(Box::new(claude_code::ClaudeCode)),
        _ => None,
    }
}
