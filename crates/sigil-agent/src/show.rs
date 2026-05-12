//! `sigil show ...` — print effective config, expanded paths, or live stats.

use crate::cli::ShowWhat;
use crate::platform::ActivePlatform;
use sigil_core::policy::expand::{expand_per_user, EnvLookup};
use sigil_core::policy::{current_platform, defaults, merge};
use sigil_core::stats::StatsSnapshot;
use std::io::{self, Write};
use std::path::PathBuf;

pub fn run(what: ShowWhat, policy_override: Option<PathBuf>) -> anyhow::Result<i32> {
    // `stats` talks to the running daemon over the control socket; it doesn't
    // touch the policy file, so handle it before the merge below.
    if let ShowWhat::Stats = what {
        return show_stats();
    }

    let user_doc = match policy_override.as_ref() {
        Some(p) => Some(sigil_core::policy::parse(&std::fs::read_to_string(p)?)?),
        None => None,
    };
    let effective = merge(defaults()?, user_doc, current_platform())?;

    match what {
        ShowWhat::Config => {
            println!("{}", serde_yaml::to_string(&effective.targets)?);
        }
        ShowWhat::Paths => {
            let plat = ActivePlatform::new();
            let users = sigil_core::policy::expand::UserEnumerator::list(&plat);
            let env = EnvLookup;
            for t in &effective.targets {
                println!("# {} ({:?})", t.id, t.tier);
                for path_template in &t.paths {
                    for r in expand_per_user(path_template, &users, &env) {
                        match r {
                            Ok(p) => println!("  {}", p.display()),
                            Err(e) => println!("  ! expand error: {e}"),
                        }
                    }
                }
            }
        }
        ShowWhat::Stats => unreachable!("handled above"),
    }
    Ok(0)
}

/// Connect to the running daemon's control socket, ask for `{"cmd":"stats"}`,
/// and print the snapshot. Returns exit code 1 (without erroring) if the
/// daemon can't be reached — the common case being "it isn't running".
fn show_stats() -> anyhow::Result<i32> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    #[cfg(unix)]
    let (target, result) = {
        let socket = crate::control::default_control_socket();
        let r = rt.block_on(query_stats(&socket));
        (socket.display().to_string(), r)
    };
    #[cfg(windows)]
    let (target, result) = {
        let pipe = crate::control::default_control_pipe_name();
        let r = rt.block_on(query_stats(&pipe));
        (pipe.clone(), r)
    };

    match result {
        Ok(snap) => {
            write_stats(&mut io::stdout().lock(), &snap)?;
            Ok(0)
        }
        Err(e) => {
            eprintln!("sigil show stats: cannot reach the sigil daemon at {target}: {e}");
            eprintln!("Is `sigil run` running?");
            Ok(1)
        }
    }
}

fn write_stats(w: &mut impl Write, s: &StatsSnapshot) -> io::Result<()> {
    writeln!(w, "events emitted total : {}", s.events_emitted_total)?;
    writeln!(w, "channel stalls       : {}", s.channel_stall_events_total)?;
    writeln!(
        w,
        "hash latency p50/p99 : {} ms / {} ms",
        s.hash_p50_ms, s.hash_p99_ms
    )?;
    if s.events_by_kind.is_empty() {
        writeln!(w, "events by kind       : (none yet)")?;
    } else {
        writeln!(w, "events by kind       :")?;
        for (kind, count) in &s.events_by_kind {
            writeln!(w, "  {kind:<24} {count}")?;
        }
    }
    Ok(())
}

#[cfg(unix)]
async fn query_stats(socket: &std::path::Path) -> anyhow::Result<StatsSnapshot> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;
    let stream = UnixStream::connect(socket).await?;
    let (rd, mut wr) = stream.into_split();
    wr.write_all(stats_request_line().as_bytes()).await?;
    wr.shutdown().await.ok();
    let mut line = String::new();
    BufReader::new(rd).read_line(&mut line).await?;
    parse_stats_reply(&line)
}

#[cfg(windows)]
async fn query_stats(pipe_name: &str) -> anyhow::Result<StatsSnapshot> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ClientOptions;
    let mut client = ClientOptions::new().open(pipe_name)?;
    client.write_all(stats_request_line().as_bytes()).await?;
    client.flush().await?;
    let mut line = String::new();
    BufReader::new(&mut client).read_line(&mut line).await?;
    parse_stats_reply(&line)
}

fn stats_request_line() -> String {
    // `{"cmd":"stats"}` — the wire form of `control::Request::Stats`.
    let mut s = serde_json::to_string(&crate::control::Request::Stats)
        .expect("Request::Stats always serializes");
    s.push('\n');
    s
}

fn parse_stats_reply(line: &str) -> anyhow::Result<StatsSnapshot> {
    let resp: crate::control::Response = serde_json::from_str(line.trim())?;
    if let Some(stats) = resp.stats {
        Ok(stats)
    } else {
        anyhow::bail!(
            "daemon returned no stats{}",
            resp.error.map(|e| format!(": {e}")).unwrap_or_default()
        )
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn write_stats_renders_counts_and_kinds() {
        let mut by_kind = BTreeMap::new();
        by_kind.insert("file_change".to_string(), 12u64);
        by_kind.insert("heartbeat".to_string(), 3u64);
        let snap = StatsSnapshot {
            events_emitted_total: 15,
            channel_stall_events_total: 0,
            events_by_kind: by_kind,
            hash_p50_ms: 2,
            hash_p99_ms: 9,
        };
        let mut buf = Vec::new();
        write_stats(&mut buf, &snap).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("events emitted total : 15"));
        assert!(out.contains("hash latency p50/p99 : 2 ms / 9 ms"));
        assert!(out.contains("file_change"));
        assert!(out.contains("heartbeat"));
        assert!(out.contains(" 12"));
    }

    #[test]
    fn write_stats_handles_empty_kinds() {
        let snap = StatsSnapshot {
            events_emitted_total: 0,
            channel_stall_events_total: 0,
            events_by_kind: BTreeMap::new(),
            hash_p50_ms: 0,
            hash_p99_ms: 0,
        };
        let mut buf = Vec::new();
        write_stats(&mut buf, &snap).unwrap();
        assert!(String::from_utf8(buf).unwrap().contains("(none yet)"));
    }

    #[tokio::test]
    async fn query_stats_round_trips_against_a_canned_server() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();

        // A one-shot server: read the request line, assert it's the stats cmd,
        // reply with a canned Response.
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (rd, mut wr) = stream.into_split();
            let mut line = String::new();
            BufReader::new(rd).read_line(&mut line).await.unwrap();
            assert_eq!(line.trim(), r#"{"cmd":"stats"}"#);
            let resp = crate::control::Response {
                ok: true,
                stats: Some(StatsSnapshot {
                    events_emitted_total: 7,
                    channel_stall_events_total: 1,
                    events_by_kind: BTreeMap::new(),
                    hash_p50_ms: 0,
                    hash_p99_ms: 0,
                }),
                apply_policy: None,
                policy_status: None,
                error: None,
            };
            let mut bytes = serde_json::to_vec(&resp).unwrap();
            bytes.push(b'\n');
            wr.write_all(&bytes).await.unwrap();
        });

        let snap = query_stats(&socket).await.unwrap();
        assert_eq!(snap.events_emitted_total, 7);
        assert_eq!(snap.channel_stall_events_total, 1);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn query_stats_errors_when_socket_absent() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("nope.sock");
        assert!(query_stats(&socket).await.is_err());
    }
}
