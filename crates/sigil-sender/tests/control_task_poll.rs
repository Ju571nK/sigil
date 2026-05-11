mod common;

use sigil_core::policy::signed_envelope::{SignedEnvelope, SignedPolicyResponse};
use sigil_sender::control_task::{poll_policy, PollOutcome};
use time::macros::datetime;

fn sample_response(etag: &str) -> SignedPolicyResponse {
    SignedPolicyResponse {
        etag: etag.into(),
        signed_envelope: SignedEnvelope {
            policy_version: 1,
            policy_bytes_b64: "AAA=".into(),
            valid_until: datetime!(2030-01-01 0:00 UTC),
            issued_at: datetime!(2026-01-01 0:00 UTC),
        },
        signature: "sig".into(),
        signing_pubkey_id: "k1".into(),
        applied_at: datetime!(2026-01-01 0:00 UTC),
    }
}

#[tokio::test]
async fn no_etag_returns_new_policy() {
    let (addr, state) = common::spawn_mock().await;
    {
        let mut s = state.lock().await;
        s.policy_etag = "fresh".into();
        s.policy_response = Some(sample_response("fresh"));
    }
    let client = reqwest::Client::new();
    match poll_policy(&client, &format!("http://{addr}"), "h", None).await {
        PollOutcome::NewPolicy { etag, .. } => assert_eq!(etag, "fresh"),
        other => panic!("expected NewPolicy, got {other:?}"),
    }
}

#[tokio::test]
async fn matching_etag_returns_unmodified() {
    let (addr, state) = common::spawn_mock().await;
    {
        let mut s = state.lock().await;
        s.policy_etag = "abc".into();
    }
    let client = reqwest::Client::new();
    match poll_policy(&client, &format!("http://{addr}"), "h", Some("abc")).await {
        PollOutcome::Unmodified => {}
        other => panic!("expected Unmodified, got {other:?}"),
    }
}

#[tokio::test]
async fn loop_fires_once_then_shuts_down() {
    let (addr, state) = common::spawn_mock().await;
    {
        let mut s = state.lock().await;
        s.policy_etag = "v1".into();
        s.policy_response = Some(sample_response("v1"));
    }
    let client = reqwest::Client::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_c = cancel.clone();
    let handle = tokio::spawn(async move {
        sigil_sender::control_task::run(sigil_sender::control_task::ControlLoopCtx {
            client,
            server_base_url: format!("http://{addr}"),
            host_id: "h".into(),
            poll_interval: std::time::Duration::from_millis(20),
            shutdown: cancel_c,
            outcomes: tx,
        })
        .await;
    });

    let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        outcome,
        sigil_sender::control_task::PollOutcome::NewPolicy { .. }
    ));
    cancel.cancel();
    handle.await.unwrap();
}
