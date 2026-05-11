//! JSON-Lines sink with lazy rotation (size + UTC date roll).

use super::{EventSink, SinkError};
use crate::event::Event;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use time::macros::format_description;
use time::OffsetDateTime;

pub const ROTATE_BYTES: u64 = 100 * 1024 * 1024;

pub struct JsonlSink {
    dir: PathBuf,
    current_path: PathBuf,
    writer: BufWriter<File>,
    bytes_written: u64,
    current_date: OffsetDateTime, // UTC
    current_seq: u32,
}

impl JsonlSink {
    pub fn open(dir: &Path, now: OffsetDateTime) -> Result<Self, SinkError> {
        std::fs::create_dir_all(dir)?;
        let (current_path, file, bytes) = open_for_date(dir, now, 0)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            current_path,
            writer: BufWriter::with_capacity(8 * 1024, file),
            bytes_written: bytes,
            current_date: now,
            current_seq: 0,
        })
    }

    pub fn current_file(&self) -> &Path {
        &self.current_path
    }

    fn rotate_to_new_date(&mut self, now: OffsetDateTime) -> Result<(), SinkError> {
        self.flush_durable()?;
        let (path, file, bytes) = open_for_date(&self.dir, now, 0)?;
        self.current_path = path;
        self.writer = BufWriter::with_capacity(8 * 1024, file);
        self.bytes_written = bytes;
        self.current_date = now;
        self.current_seq = 0;
        Ok(())
    }

    fn rotate_to_next_seq(&mut self) -> Result<(), SinkError> {
        self.flush_durable()?;
        let next_seq = self.current_seq + 1;
        let (path, file, bytes) = open_for_date(&self.dir, self.current_date, next_seq)?;
        self.current_path = path;
        self.writer = BufWriter::with_capacity(8 * 1024, file);
        self.bytes_written = bytes;
        self.current_seq = next_seq;
        Ok(())
    }

    fn maybe_rotate(&mut self, now: OffsetDateTime) -> Result<(), SinkError> {
        if now.date() != self.current_date.date() {
            self.rotate_to_new_date(now)?;
        } else if self.bytes_written >= ROTATE_BYTES {
            self.rotate_to_next_seq()?;
        }
        Ok(())
    }
}

fn open_for_date(
    dir: &Path,
    now: OffsetDateTime,
    seq: u32,
) -> Result<(PathBuf, File, u64), SinkError> {
    let date_fmt = format_description!("[year]-[month]-[day]");
    let date_str = now.format(date_fmt).expect("date format infallible");
    let name = if seq == 0 {
        format!("events-{date_str}.jsonl")
    } else {
        format!("events-{date_str}-{seq:03}.jsonl")
    };
    let path = dir.join(name);
    let file = OpenOptions::new().create(true).append(true).open(&path)?;
    let bytes = file.metadata()?.len();
    Ok((path, file, bytes))
}

impl EventSink for JsonlSink {
    fn write(&mut self, event: &Event) -> Result<(), SinkError> {
        self.maybe_rotate(event.ts)?;
        let line = serde_json::to_vec(event)?;
        self.writer.write_all(&line)?;
        self.writer.write_all(b"\n")?;
        self.bytes_written += line.len() as u64 + 1;
        // Memory → OS cache; periodic fsync handled by caller.
        self.writer.flush()?;
        Ok(())
    }

    fn flush_durable(&mut self) -> Result<(), SinkError> {
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), SinkError> {
        self.flush_durable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use time::macros::datetime;

    fn sample_event(ts: OffsetDateTime) -> Event {
        Event::new_file_change(
            ts,
            "host-1",
            PathBuf::from("/x"),
            Evidence::FileChange {
                change_kind: FileChangeKind::Modified,
                before_hash: Some("a".into()),
                after_hash: Some("b".into()),
                recheck_hash: None,
                rename_from: None,
                size_after: Some(1),
                evidence_quality: EvidenceQuality::Definitive,
            },
            Some("t".into()),
        )
    }

    #[test]
    fn writes_one_line_per_event() {
        let td = TempDir::new().unwrap();
        let mut sink = JsonlSink::open(td.path(), datetime!(2026-05-08 10:00 UTC)).unwrap();
        sink.write(&sample_event(datetime!(2026-05-08 10:00:01 UTC)))
            .unwrap();
        sink.write(&sample_event(datetime!(2026-05-08 10:00:02 UTC)))
            .unwrap();
        sink.flush_durable().unwrap();
        let contents = fs::read_to_string(sink.current_file()).unwrap();
        assert_eq!(contents.lines().count(), 2);
    }

    #[test]
    fn rotates_at_utc_date_change() {
        let td = TempDir::new().unwrap();
        let mut sink = JsonlSink::open(td.path(), datetime!(2026-05-08 23:59:59 UTC)).unwrap();
        sink.write(&sample_event(datetime!(2026-05-08 23:59:59 UTC)))
            .unwrap();
        let day1_path = sink.current_file().to_path_buf();
        sink.write(&sample_event(datetime!(2026-05-09 00:00:00 UTC)))
            .unwrap();
        let day2_path = sink.current_file().to_path_buf();
        assert_ne!(day1_path, day2_path);
        assert!(day1_path.to_string_lossy().contains("2026-05-08"));
        assert!(day2_path.to_string_lossy().contains("2026-05-09"));
    }

    #[test]
    fn rotates_at_size_threshold() {
        let td = TempDir::new().unwrap();
        let mut sink = JsonlSink::open(td.path(), datetime!(2026-05-08 10:00 UTC)).unwrap();
        // Force-rotate by manually setting bytes_written near the limit.
        sink.bytes_written = ROTATE_BYTES;
        sink.write(&sample_event(datetime!(2026-05-08 10:00:01 UTC)))
            .unwrap();
        let p = sink.current_file();
        assert!(
            p.to_string_lossy().contains("-001."),
            "expected rotated file, got {}",
            p.display()
        );
    }

    #[test]
    fn lazy_rotation_after_simulated_sleep_jump() {
        // Date jumps by 2 days between writes — first post-sleep write must rotate
        // (lazy: no wall-clock timer involved).
        let td = TempDir::new().unwrap();
        let mut sink = JsonlSink::open(td.path(), datetime!(2026-05-08 22:00 UTC)).unwrap();
        sink.write(&sample_event(datetime!(2026-05-08 22:00:01 UTC)))
            .unwrap();
        sink.write(&sample_event(datetime!(2026-05-10 09:00:00 UTC)))
            .unwrap();
        assert!(sink.current_file().to_string_lossy().contains("2026-05-10"));
    }

    #[test]
    fn shutdown_is_durable() {
        let td = TempDir::new().unwrap();
        let mut sink = JsonlSink::open(td.path(), datetime!(2026-05-08 10:00 UTC)).unwrap();
        sink.write(&sample_event(datetime!(2026-05-08 10:00:01 UTC)))
            .unwrap();
        sink.shutdown().unwrap();
    }
}
