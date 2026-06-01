//! Integration test: hook.sock listener — peer-cred stamp, event queuing.
//! Step 1 of TDD for Task 7 (sigil-hook Stage 1 #64).

#[cfg(unix)]
mod unix_only {
    use sigil_agent::hook_listener;
    use sigil_agent::state_task::CommittableEvent;
    use sigil_core::event::{Evidence, SourceKind};
    use sigil_core::hook_proto::{
        CaptureLevel, CaptureStatus, HookAction, HookEnvelope, HookInvocation, HookMsgType,
        HOOK_PROTOCOL_VERSION,
    };
    use std::path::PathBuf;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hook_listener_stamps_peer_uid_and_action_kind() {
        // 1. Create a temp dir + socket path.
        let dir = tempfile::tempdir().unwrap();
        let sock_path: PathBuf = dir.path().join("hook.sock");

        // 2. Channel — capacity 16 is plenty for one event.
        let (tx, mut rx) = mpsc::channel::<CommittableEvent>(16);

        // 3. Start the hook listener in a background task.
        let sock_path_clone = sock_path.clone();
        let _listener_task = tokio::spawn(async move {
            hook_listener::serve(sock_path_clone, tx, "host-1".to_string())
                .await
                .expect("hook listener should not exit early");
        });

        // 4. Wait for the socket file to appear (max 2 s).
        timeout(Duration::from_secs(2), async {
            loop {
                if sock_path.exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("hook.sock should appear within 2 s");

        // 5. Connect a UnixStream client and write one HookEnvelope JSON line.
        let mut client = UnixStream::connect(&sock_path)
            .await
            .expect("should connect to hook.sock");

        let envelope = HookEnvelope {
            protocol_version: HOOK_PROTOCOL_VERSION,
            msg_type: HookMsgType::HookInvocation,
            request_id: uuid::Uuid::now_v7(),
            sent_at_unix_ms: 1_700_000_000_000,
            payload: HookInvocation {
                agent: sigil_core::event::AiTool::ClaudeCode,
                agent_session_id: Some("sess-42".into()),
                tool_use_id: Some("tu-1".into()),
                action: HookAction::Bash {
                    command_hash: "ab".repeat(32),
                    command_preview: Some("git status".into()),
                },
                capture_level: CaptureLevel::Redacted,
                capture_status: CaptureStatus::Ok,
                cwd: None,
            },
        };

        let mut line = serde_json::to_string(&envelope).expect("serialize envelope");
        line.push('\n');
        client
            .write_all(line.as_bytes())
            .await
            .expect("write envelope to socket");
        // Flush / close write side so the listener sees EOF after the line.
        client.shutdown().await.ok();

        // 6. Assert one CommittableEvent arrives on rx within 2 s.
        let committable = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("CommittableEvent should arrive within 2 s")
            .expect("channel must not close");

        let ev = &committable.event;
        assert_eq!(ev.source, SourceKind::AgentHook, "source must be AgentHook");

        // The listener stamps peer_uid from the kernel (SO_PEERCRED).
        // In a test, both ends run as the same user, so peer_uid == getuid().
        let expected_uid = unsafe { libc::getuid() };

        match &ev.evidence {
            Evidence::HookInvocation(h) => {
                assert_eq!(h.peer_uid, expected_uid, "peer_uid must match process uid");
                assert_eq!(h.action_kind, "bash", "action_kind must be 'bash'");
            }
            other => panic!("expected HookInvocation evidence, got: {other:?}"),
        }
    }
}
