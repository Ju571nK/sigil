mod common;

use andeda_sender::data_task::{send_one_batch, BatchOutcome, BatchSendCtx};
use andeda_sender::wire::EventEntry;
use uuid::Uuid;

#[tokio::test]
async fn batch_with_events_returns_accepted_with_high_water() {
    let (addr, _state) = common::spawn_mock().await;
    let client = reqwest::Client::new();
    let ev1 = EventEntry { event_id: Uuid::from_u128(1), sequence: 1, payload: serde_json::json!({}) };
    let ev2 = EventEntry { event_id: Uuid::from_u128(2), sequence: 2, payload: serde_json::json!({}) };
    let ctx = BatchSendCtx {
        client: &client,
        server_base_url: &format!("http://{addr}"),
        host_id: "h",
        agent_version: "0.2.0",
        sender_version: "0.2.0",
        events: vec![ev1.clone(), ev2.clone()],
    };
    match send_one_batch(ctx).await {
        BatchOutcome::Accepted(r) => {
            assert_eq!(r.high_water_event_id, ev2.event_id);
            assert_eq!(r.accepted.len(), 2);
        }
        other => panic!("expected Accepted, got {other:?}"),
    }
}

#[tokio::test]
async fn batch_against_503_mock_returns_server_busy() {
    let (addr, state) = common::spawn_mock().await;
    {
        let mut s = state.lock().await;
        s.next_status = 503;
    }
    let client = reqwest::Client::new();
    let ev = EventEntry { event_id: Uuid::from_u128(1), sequence: 1, payload: serde_json::json!({}) };
    let ctx = BatchSendCtx {
        client: &client,
        server_base_url: &format!("http://{addr}"),
        host_id: "h",
        agent_version: "0.2.0",
        sender_version: "0.2.0",
        events: vec![ev],
    };
    match send_one_batch(ctx).await {
        BatchOutcome::ServerBusy { status: 503, .. } => {}
        other => panic!("expected ServerBusy(503), got {other:?}"),
    }
}

#[tokio::test]
async fn batch_against_409_mock_returns_permanent_reject() {
    let (addr, state) = common::spawn_mock().await;
    {
        let mut s = state.lock().await;
        s.next_status = 409;
    }
    let client = reqwest::Client::new();
    let ev = EventEntry { event_id: Uuid::from_u128(1), sequence: 1, payload: serde_json::json!({}) };
    let ctx = BatchSendCtx {
        client: &client,
        server_base_url: &format!("http://{addr}"),
        host_id: "h",
        agent_version: "0.2.0",
        sender_version: "0.2.0",
        events: vec![ev],
    };
    match send_one_batch(ctx).await {
        BatchOutcome::PermanentReject { status: 409, .. } => {}
        other => panic!("expected PermanentReject(409), got {other:?}"),
    }
}
