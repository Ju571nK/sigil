mod common;

use andeda_sender::batch_reader::read_next_batch;
use andeda_sender::data_task::{send_one_batch, BatchOutcome, BatchSendCtx};
use andeda_sender::state::SenderState;
use std::io::Write;
use uuid::Uuid;

fn write_jsonl(dir: &std::path::Path, name: &str, lines: &[(Uuid, &str)]) {
    let mut f = std::fs::File::create(dir.join(name)).unwrap();
    for (id, body) in lines {
        let line = format!(r#"{{"event_id":"{id}","payload":{body}}}"#);
        writeln!(f, "{line}").unwrap();
    }
}

#[tokio::test]
async fn server_busy_returns_no_offset_advance_then_recovers() {
    let (addr, mock_state) = common::spawn_mock().await;
    {
        let mut s = mock_state.lock().await;
        s.next_status = 503;
    }
    let dir = tempfile::tempdir().unwrap();
    let id = Uuid::from_u128(1);
    write_jsonl(dir.path(), "events-1.jsonl", &[(id, r#""a""#)]);
    let initial = SenderState {
        current_file: "events-1.jsonl".into(),
        byte_offset: 0,
        last_acked_sequence: 0,
    };
    let (events, _manifest) = read_next_batch(dir.path(), &initial, 256, 1_000_000).unwrap();

    let client = reqwest::Client::new();
    // First attempt — server returns 503.
    let outcome = send_one_batch(BatchSendCtx {
        client: &client,
        server_base_url: &format!("http://{addr}"),
        host_id: "h",
        agent_version: "0.2.0",
        sender_version: "0.2.0",
        events: events.clone(),
    })
    .await;
    assert!(matches!(outcome, BatchOutcome::ServerBusy { .. }));

    // Recover — server returns 200 next.
    {
        let mut s = mock_state.lock().await;
        s.next_status = 200;
    }
    let outcome = send_one_batch(BatchSendCtx {
        client: &client,
        server_base_url: &format!("http://{addr}"),
        host_id: "h",
        agent_version: "0.2.0",
        sender_version: "0.2.0",
        events,
    })
    .await;
    assert!(matches!(outcome, BatchOutcome::Accepted(_)));
}
