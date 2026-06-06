//! Integration test: hook.sock listener — peer-cred stamp, event queuing.
//! Step 1 of TDD for Task 7 (sigil-hook Stage 1 #64).

#[cfg(unix)]
mod unix_only {
    use sigil_agent::hook_listener;
    use sigil_agent::state_task::CommittableEvent;
    use sigil_core::event::{Evidence, Severity, SourceKind, Subject};
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
            hook_listener::serve(
                sock_path_clone,
                tx,
                "host-1".to_string(),
                sigil_agent::hook_silence::new_map(),
            )
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
        assert_eq!(ev.severity, Severity::Info, "severity must be Info");
        assert_eq!(ev.subject, Subject::Self_, "subject must be Self_");
        assert_eq!(ev.host_id, "host-1", "host_id must be the configured value");

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

    /// Helper: build a valid Bash envelope as a newline-terminated JSON line.
    fn bash_envelope_line(preview: &str) -> String {
        let envelope = HookEnvelope {
            protocol_version: HOOK_PROTOCOL_VERSION,
            msg_type: HookMsgType::HookInvocation,
            request_id: uuid::Uuid::now_v7(),
            sent_at_unix_ms: 1_700_000_000_000,
            payload: HookInvocation {
                agent: sigil_core::event::AiTool::ClaudeCode,
                agent_session_id: None,
                tool_use_id: None,
                action: HookAction::Bash {
                    command_hash: "ab".repeat(32),
                    command_preview: Some(preview.to_string()),
                },
                capture_level: CaptureLevel::Redacted,
                capture_status: CaptureStatus::Ok,
                cwd: None,
            },
        };
        let mut line = serde_json::to_string(&envelope).expect("serialize envelope");
        line.push('\n');
        line
    }

    /// Overload: open more than MAX_INFLIGHT (32) connections that connect but
    /// never send a line. Each holds a semaphore permit, saturating the bound.
    /// The accept loop must NOT block — a fresh connection that DOES send a line
    /// is dropped-before-read on overload, yet the listener keeps accepting and,
    /// once the lingering connections close (freeing permits), a valid emit
    /// flows through. Deterministic via timeouts; the core assertion is that the
    /// listener never deadlocks under saturation.
    ///
    /// NOTE on non-determinism: the assertion that exactly 32 permits become
    /// saturated depends on async scheduling — some of the 36 lingering connects
    /// may be dropped-before-read by the overload guard rather than consuming a
    /// permit. The REAL invariant being tested is "the accept loop never
    /// deadlocks under connection saturation", not exact permit accounting.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn hook_listener_survives_connection_overload() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path: PathBuf = dir.path().join("hook.sock");

        let (tx, mut rx) = mpsc::channel::<CommittableEvent>(64);

        let sock_path_clone = sock_path.clone();
        let _listener_task = tokio::spawn(async move {
            hook_listener::serve(
                sock_path_clone,
                tx,
                "host-overload".to_string(),
                sigil_agent::hook_silence::new_map(),
            )
            .await
            .expect("hook listener should not exit early");
        });

        // Wait for the socket to appear.
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

        // Open MAX_INFLIGHT + 4 = 36 connections that connect but never send.
        // Each successful accept that wins a permit holds it open (its task is
        // parked in read_line waiting for bytes that never come). The rest are
        // dropped-before-read by the overload guard. Either way, the accept loop
        // must keep running.
        const LINGER: usize = 36;
        let mut lingering: Vec<UnixStream> = Vec::with_capacity(LINGER);
        for _ in 0..LINGER {
            // Connect must not hang — bound it.
            let s = timeout(Duration::from_secs(2), UnixStream::connect(&sock_path))
                .await
                .expect("connect must not hang under overload")
                .expect("connect should succeed");
            lingering.push(s);
        }

        // Prove the listener is STILL accepting new connections under saturation:
        // a brand-new connect must complete quickly (the accept loop is alive).
        let probe = timeout(Duration::from_secs(2), UnixStream::connect(&sock_path))
            .await
            .expect("listener must keep accepting connections under overload")
            .expect("probe connect should succeed");
        drop(probe);

        // Now release the lingering connections, freeing their permits.
        lingering.clear();
        // Give the listener a moment to drain dropped tasks / free permits.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // A valid emit after the pressure subsides must flow through — proving
        // the listener recovered rather than wedged.
        let mut client = timeout(Duration::from_secs(2), UnixStream::connect(&sock_path))
            .await
            .expect("post-overload connect must not hang")
            .expect("post-overload connect should succeed");
        client
            .write_all(bash_envelope_line("recovered").as_bytes())
            .await
            .expect("write envelope after overload");
        client.shutdown().await.ok();

        let committable = timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a valid emit must arrive after overload subsides")
            .expect("channel must not close");
        assert_eq!(committable.event.source, SourceKind::AgentHook);
        match &committable.event.evidence {
            Evidence::HookInvocation(h) => assert_eq!(h.action_kind, "bash"),
            other => panic!("expected HookInvocation, got {other:?}"),
        }
    }
}
