#![cfg(unix)]

use andeda_core::policy::signed_envelope::{SignedEnvelope, SignedPolicyResponse};
use andeda_sender::agent_ipc::{apply_policy, ApplyPolicyResult};
use serde_json::json;
use time::macros::datetime;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

#[tokio::test]
async fn apply_policy_round_trips_against_fake_agent() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let socket_for_client = socket.clone();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (rd, mut wr) = stream.into_split();
        let mut buf = String::new();
        BufReader::new(rd).read_line(&mut buf).await.unwrap();
        let req: serde_json::Value = serde_json::from_str(buf.trim()).unwrap();
        assert_eq!(req["cmd"], "apply_policy");
        let resp = json!({
            "ok": true,
            "stats": null,
            "apply_policy": {"outcome": "accepted", "applied_policy_version": 7},
            "policy_status": null,
            "error": null,
        });
        let mut resp_bytes = serde_json::to_vec(&resp).unwrap();
        resp_bytes.push(b'\n');
        wr.write_all(&resp_bytes).await.unwrap();
        wr.shutdown().await.unwrap();
    });

    let response = SignedPolicyResponse {
        etag: "e".into(),
        signed_envelope: SignedEnvelope {
            policy_version: 7,
            policy_bytes_b64: "AAA=".into(),
            valid_until: datetime!(2030-01-01 0:00 UTC),
            issued_at: datetime!(2026-01-01 0:00 UTC),
        },
        signature: "sig".into(),
        signing_pubkey_id: "k1".into(),
        applied_at: datetime!(2026-01-01 0:00 UTC),
    };
    let agent_resp = apply_policy(&socket_for_client, &response).await.unwrap();
    assert!(agent_resp.ok);
    match agent_resp.apply_policy.unwrap() {
        ApplyPolicyResult::Accepted { applied_policy_version } => {
            assert_eq!(applied_policy_version, 7);
        }
        other => panic!("expected Accepted, got {other:?}"),
    }
    server.await.unwrap();
}
