mod common;

use andeda_core::policy::signed_envelope::{SignedEnvelope, SignedPolicyResponse};
use andeda_sender::control_task::{poll_policy, PollOutcome};
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
