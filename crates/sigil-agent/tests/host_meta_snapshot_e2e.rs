//! Phase 3b.4-pre e2e: boot the agent under a tempdir HOME and assert that
//! a host_meta_snapshot event with reasonable fields appears in events_dir
//! within a few seconds. Tests the full collect → emit → JSONL pipeline.

#![cfg(all(unix, feature = "operator-cli"))]

mod common;
use common::TestAgentBuilder;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_emits_host_meta_snapshot_on_boot() {
    let agent = TestAgentBuilder::new()
        .policy("version: 1\nhost_id_strategy: machine_id\ntargets: []\n")
        .start()
        .await;

    let ev = agent
        .wait_for_event(
            |v| v["evidence"]["kind"] == "host_meta_snapshot",
            Duration::from_secs(10),
        )
        .await
        .expect("expected a HostMetaSnapshot event within 10s");

    // Architecture is the most deterministic field — it matches the test
    // process's own ARCH constant exactly.
    let arch = ev["evidence"]["snapshot"]["architecture"]
        .as_str()
        .expect("architecture must be present as a string");
    assert_eq!(arch, std::env::consts::ARCH, "architecture mismatch");

    // Boot scan is NOT a re-attestation (no prior state).
    let is_re = ev["evidence"]["is_reattestation"]
        .as_bool()
        .expect("is_reattestation must be bool");
    assert!(!is_re, "boot event must not be re-attestation");

    // hostname is Some on every Unix CI image (real OS hostname call works).
    assert!(
        ev["evidence"]["snapshot"]["hostname"].is_string(),
        "hostname must be present, got {ev}"
    );

    // os_name should be Some on macOS + Linux runners.
    assert!(
        ev["evidence"]["snapshot"]["os_name"].is_string(),
        "os_name must be present, got {ev}"
    );

    // interfaces: CI runners have at least one non-loopback NIC.
    let ifaces = ev["evidence"]["snapshot"]["interfaces"]
        .as_array()
        .expect("interfaces must be an array");
    assert!(!ifaces.is_empty(), "expected at least one non-loopback interface");

    agent.join.abort();
}
