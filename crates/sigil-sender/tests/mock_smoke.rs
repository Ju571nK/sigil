mod common;

use andeda_sender::wire::{Envelope, EventEntry, EventsRequest};
use time::macros::datetime;
use uuid::Uuid;

#[tokio::test]
async fn mock_accepts_a_batch_and_records_it() {
    let (addr, state) = common::spawn_mock().await;
    let client = reqwest::Client::new();
    let req = EventsRequest {
        envelope: Envelope {
            schema_version: 1,
            batch_id: Uuid::nil(),
            host_id: "h".into(),
            agent_version: "0.2.0".into(),
            sender_version: "0.2.0".into(),
            sent_at: datetime!(2026-05-15 8:30:00 UTC),
        },
        events: vec![EventEntry {
            event_id: Uuid::nil(),
            sequence: 1,
            payload: serde_json::json!({}),
        }],
    };
    let resp = client
        .post(format!("http://{addr}/v1/events"))
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let recorded = state.lock().await;
    assert_eq!(recorded.received_batches.len(), 1);
}

#[tokio::test]
async fn mock_returns_304_on_matching_etag() {
    let (addr, state) = common::spawn_mock().await;
    {
        let mut s = state.lock().await;
        s.policy_etag = "abc".into();
    }
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/v1/policy"))
        .header("if-none-match", "abc")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 304);
}

#[tokio::test]
async fn mock_returns_200_with_etag_when_no_match() {
    let (addr, state) = common::spawn_mock().await;
    {
        let mut s = state.lock().await;
        s.policy_etag = "fresh".into();
    }
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/v1/policy"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("etag").unwrap(), "fresh");
}
