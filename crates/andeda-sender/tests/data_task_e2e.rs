mod common;

use andeda_sender::batch_reader::read_next_batch;
use andeda_sender::data_task::{apply_ack, send_one_batch, BatchOutcome, BatchSendCtx};
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
async fn read_send_ack_advances_state_to_high_water() {
    let (addr, _state) = common::spawn_mock().await;
    let dir = tempfile::tempdir().unwrap();
    let id_a = Uuid::from_u128(1);
    let id_b = Uuid::from_u128(2);
    write_jsonl(
        dir.path(),
        "events-1.jsonl",
        &[(id_a, r#""a""#), (id_b, r#""b""#)],
    );

    let initial = SenderState {
        current_file: "events-1.jsonl".into(),
        byte_offset: 0,
        last_acked_sequence: 0,
    };
    let (events, manifest) = read_next_batch(dir.path(), &initial, 256, 1_000_000).unwrap();
    assert_eq!(events.len(), 2);

    let client = reqwest::Client::new();
    let outcome = send_one_batch(BatchSendCtx {
        client: &client,
        server_base_url: &format!("http://{addr}"),
        host_id: "h",
        agent_version: "0.2.0",
        sender_version: "0.2.0",
        events: events.clone(),
    })
    .await;
    let accepted = match outcome {
        BatchOutcome::Accepted(a) => a,
        other => panic!("expected Accepted, got {other:?}"),
    };
    let next = apply_ack(&manifest, accepted.high_water_event_id).unwrap();
    assert_eq!(next.last_acked_sequence, 2);
    // byte_offset should equal end of last event line in jsonl.
    let bytes_on_disk = std::fs::metadata(dir.path().join("events-1.jsonl"))
        .unwrap()
        .len();
    assert_eq!(next.byte_offset, bytes_on_disk);
}
