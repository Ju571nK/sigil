## Imported Claude Cowork project instructions

## GitHub Issue Triage

- Conserve tokens when inspecting GitHub issues: request only the fields and number of results needed for the task, then summarize rather than reproducing full issue bodies.
- A lower-cost model may be used for routine issue discovery, classification, and status summaries. Use a stronger model when implementation planning, security analysis, or conflicting requirements require deeper reasoning.

## Generative AI Compatibility Gate

- Before implementing any issue tied to a generative AI product, verify that product's current behavior using official documentation, release notes, and the locally installed version when available.
- Record changes to configuration paths and precedence, permission or approval modes, hook events and payloads, MCP/tool behavior, unattended modes, and platform-specific behavior before changing code.
- Distinguish documented behavior from hardware-verified behavior. Do not remove compatibility gates or enable enforcement from documentation alone when the repository records conflicting measurements.
- Use a lower-cost model for broad changelog discovery and classification, then use a stronger model to validate security implications, resolve contradictions, and define implementation scope.
- Keep research scoped per product and date-stamped so later issue work can reuse it without repeating full discovery.

## Sigil Proxy Agent Workflow

For Sigil Proxy work, read [the specification entry point](docs/specs/sigil-proxy/README.md),
[agent roles and operating rules](docs/specs/sigil-proxy/agents/README.md), and
[current execution status](docs/specs/sigil-proxy/execution.md) before starting.

- The primary assistant is the orchestrator and the user's single reporting interface.
- Delegate scoped research, coding, independent review, and verification as the authorized task requires.
- Role definitions are not running agents; start workers only for concrete tasks and respect runtime limits.
- Assign one writer per file; link assignments and results to requirement and acceptance IDs.
- Preserve compatibility gates and distinguish implementation, review, and hardware verification.
- Maintain execution status and report integrated results to the user.
- Read sigil-manager's own repository instructions before assigning work there.
