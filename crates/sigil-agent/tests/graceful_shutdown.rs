#![cfg(unix)]

#[allow(unused_imports)]
mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_until(mut ready: impl FnMut() -> bool, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !ready() {
        assert!(Instant::now() < deadline, "test deadline exceeded");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn shutdown_case(signal: i32, deliver: bool, late: bool, poll: bool, stall: bool) {
    // Short paths also fit macOS's sockaddr_un limit.
    let dir = tempfile::Builder::new()
        .prefix("sg-stop-")
        .tempdir_in("/tmp")
        .unwrap();
    let root = dir.path().join("late/cache");
    let file = root.join("snapshot.json");
    if !late {
        std::fs::create_dir_all(&root).unwrap();
    }
    let mut policy = common::policy_for_paths(&[root.join("*").to_str().unwrap()], "standard")
        .replace("recursive: false", "recursive: true");
    // Do not poll the developer's home or system trees in a subprocess test.
    policy.push_str("overrides:\n");
    for target in sigil_core::policy::defaults().unwrap().targets {
        policy.push_str(&format!("  - id: {}\n    disabled: true\n", target.id));
    }
    let policy_path = dir.path().join("policy.yaml");
    std::fs::write(&policy_path, policy).unwrap();
    let socket = dir.path().join("control.sock");
    let events = dir.path().join("events");
    let db = dir.path().join("state.db");
    let log = dir.path().join("daemon.log");
    let binary =
        std::env::var_os("SIGIL_TEST_BIN").unwrap_or_else(|| env!("CARGO_BIN_EXE_sigil").into());
    let mut command = Command::new(binary);
    command
        .arg("run")
        .arg("--policy")
        .arg(&policy_path)
        .arg("--state-db")
        .arg(&db)
        .arg("--events-dir")
        .arg(&events)
        .arg("--control-socket")
        .arg(&socket)
        .arg("--keystore")
        .arg(dir.path().join("keystore.json"))
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).unwrap());
    if poll {
        command.arg("--poll");
    }
    let mut daemon = Daemon(command.spawn().unwrap());
    wait_until(
        || {
            assert!(
                daemon.0.try_wait().unwrap().is_none(),
                "daemon exited during startup"
            );
            if !socket.exists() {
                return false;
            }
            let Ok(mut stream) = UnixStream::connect(&socket) else {
                return false;
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            stream.write_all(b"{\"cmd\":\"stats\"}\n").unwrap();
            let mut response = String::new();
            BufReader::new(stream).read_line(&mut response).is_ok() && !response.is_empty()
        },
        Duration::from_secs(30),
    );
    let _stalled_client = stall.then(|| UnixStream::connect(&socket).unwrap());
    // The listeners can bind just before the supervisor registers its signals.
    std::thread::sleep(Duration::from_millis(300));
    let expected = if deliver {
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&file, b"shutdown snapshot").unwrap();
        let expected = dunce::canonicalize(&file).unwrap();
        wait_until(
            || {
                read_events(&events).iter().any(|event| {
                    event["evidence"]["kind"] == "file_change"
                        && event["subject"]["value"]
                            .as_str()
                            .is_some_and(|p| Path::new(p) == expected)
                })
            },
            Duration::from_secs(35),
        );
        Some(expected)
    } else {
        None
    };
    assert_eq!(unsafe { libc::kill(daemon.0.id() as i32, signal) }, 0);
    wait_until(
        || daemon.0.try_wait().unwrap().is_some(),
        Duration::from_secs(12),
    );
    assert!(
        daemon.0.wait().unwrap().success() != stall,
        "{}",
        std::fs::read_to_string(&log).unwrap()
    );
    for name in ["control.sock", "hook.sock", "hook-decide.sock"] {
        assert!(
            !dir.path().join(name).exists(),
            "leftover IPC socket: {name}"
        );
    }
    assert!(!read_events(&events).is_empty());
    if let Some(expected) = expected {
        let cache = sigil_core::state::HashCache::open(&db).unwrap();
        assert!(
            cache.get(&expected).unwrap().is_some(),
            "baseline not committed"
        );
    }
}

fn read_events(dir: &Path) -> Vec<serde_json::Value> {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "jsonl"))
        .flat_map(|entry| {
            std::fs::read_to_string(entry.path())
                .unwrap()
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn sigint_idle_daemon() {
    shutdown_case(libc::SIGINT, false, false, false, false);
}

#[test]
fn sigterm_with_missing_roots() {
    shutdown_case(libc::SIGTERM, false, true, true, false);
}

#[test]
fn sigint_after_file_delivery() {
    shutdown_case(libc::SIGINT, true, false, false, false);
}

#[test]
fn sigterm_after_late_root_catchup() {
    shutdown_case(libc::SIGTERM, true, true, true, false);
}

#[test]
fn sigterm_with_stalled_ipc_client_reports_failure_and_cleans_up() {
    shutdown_case(libc::SIGTERM, false, false, false, true);
}
