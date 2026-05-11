#![cfg(unix)]
mod common;

use sigil_core::policy::signed_envelope::{SignedEnvelope, SignedPolicyResponse};
use sigil_sender::control_task::{ControlLoopCtx, PollOutcome};
use serde_json::json;
use time::macros::datetime;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

fn sample_policy(etag: &str) -> SignedPolicyResponse {
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
async fn control_loop_emits_new_policy_then_ipc_handoff_succeeds() {
    let (addr, mock_state) = common::spawn_mock().await;
    {
        let mut s = mock_state.lock().await;
        s.policy_etag = "v1".into();
        s.policy_response = Some(sample_policy("v1"));
    }
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let listener = UnixListener::bind(&socket).unwrap();

    // Fake agent: accept one connection, ACK with applied_policy_version=1.
    let agent = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (rd, mut wr) = stream.into_split();
        let mut buf = String::new();
        BufReader::new(rd).read_line(&mut buf).await.unwrap();
        let resp = json!({
            "ok": true,
            "stats": null,
            "apply_policy": {"outcome": "accepted", "applied_policy_version": 1},
            "policy_status": null,
            "error": null,
        });
        let mut resp_bytes = serde_json::to_vec(&resp).unwrap();
        resp_bytes.push(b'\n');
        wr.write_all(&resp_bytes).await.unwrap();
        wr.shutdown().await.unwrap();
    });

    let (tx, mut rx) = tokio::sync::mpsc::channel::<PollOutcome>(4);
    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_c = cancel.clone();
    let client = reqwest::Client::new();
    let server_base = format!("http://{addr}");
    let ctl = tokio::spawn(async move {
        sigil_sender::control_task::run(ControlLoopCtx {
            client,
            server_base_url: server_base,
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
    let response = match outcome {
        PollOutcome::NewPolicy { response, .. } => response,
        other => panic!("expected NewPolicy, got {other:?}"),
    };
    let agent_resp = sigil_sender::agent_ipc::apply_policy(&socket, &response)
        .await
        .unwrap();
    assert!(agent_resp.ok);
    cancel.cancel();
    let _ = tokio::join!(ctl, agent);
}
