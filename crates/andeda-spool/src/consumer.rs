//! Spool consumer — tail-follow + checkpoint advance.

use crate::checkpoint::Checkpoint;
use crate::DurableOffset;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use thiserror::Error;

/// One record yielded by `Consumer::next_with_timeout`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    /// The raw JSONL line bytes (without the trailing `\n`).
    pub bytes: Vec<u8>,
    /// Durable position *after* this record. Pass to `Checkpoint::advance`
    /// once downstream durability is confirmed.
    pub offset: DurableOffset,
}

/// Errors produced by the consumer.
#[derive(Debug, Error)]
pub enum ConsumerError {
    /// I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Truncated / malformed line found at the given absolute byte position.
    /// The consumer skips past the bad bytes and surfaces them so callers can
    /// emit spec-§3.10 `spool_corruption` events.
    #[error("corruption at segment={segment} offset={byte_offset}: {bytes_skipped} bytes skipped")]
    Corruption {
        /// Segment basename.
        segment: String,
        /// Byte offset where corruption began.
        byte_offset: u64,
        /// Number of bytes skipped to reach the next `\n` (or EOF).
        bytes_skipped: u64,
    },
}

/// Consumer (reader) for a single spool. Driven synchronously by
/// `next_with_timeout`; production callers wrap this in a tokio task that
/// polls on a tight interval.
///
/// **Threading:** Single-reader, like `Producer`. `&mut self` enforces it.
pub struct Consumer {
    spool_dir: PathBuf,
    prefix: String,
    cur_segment: u64,
    cur_offset: u64,
    cur_file: Option<File>,
}

impl Consumer {
    /// Open a consumer that resumes from the checkpoint's last position. If
    /// the checkpoint is empty, starts at segment 0 offset 0.
    pub fn open<P: AsRef<Path>>(
        spool_dir: P,
        prefix: &str,
        cp: &mut Checkpoint,
    ) -> Result<Self, ConsumerError> {
        let (cur_segment, cur_offset) = match cp.position() {
            Some(p) => (parse_segment_n(&p.segment, prefix), p.byte_offset),
            None => (0u64, 0u64),
        };
        let mut c = Self {
            spool_dir: spool_dir.as_ref().to_path_buf(),
            prefix: prefix.to_string(),
            cur_segment,
            cur_offset,
            cur_file: None,
        };
        c.open_current_if_exists()?;
        Ok(c)
    }

    /// Block (busy-poll with 25 ms sleeps) for up to `timeout` waiting for
    /// the next record. Returns `Ok(None)` on timeout. The library deliberately
    /// avoids `notify` here so it can be exercised in deterministic tests; the
    /// agent wraps this in a `tokio::task::spawn_blocking` with a 25 ms cycle
    /// and supplements with `notify` for low-latency wake-up in production
    /// (Plan B layering).
    pub fn next_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<Record>, ConsumerError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(rec) = self.try_read_one()? {
                return Ok(Some(rec));
            }
            // Maybe the producer rolled to a new segment.
            if self.try_advance_segment()? {
                continue;
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn try_read_one(&mut self) -> Result<Option<Record>, ConsumerError> {
        let file = match &mut self.cur_file {
            Some(f) => f,
            None => return Ok(None),
        };
        let len = file.metadata()?.len();
        if self.cur_offset >= len {
            return Ok(None);
        }
        file.seek(SeekFrom::Start(self.cur_offset))?;
        let mut reader = BufReader::new(file);
        let mut buf: Vec<u8> = Vec::new();
        let n = reader.read_until(b'\n', &mut buf)?;
        if n == 0 {
            return Ok(None);
        }
        if buf.last() != Some(&b'\n') {
            // Trailing partial line — producer may be mid-write or this is
            // truncation. Skip past it and surface as corruption so callers
            // can advance and continue.
            let bytes_skipped = n as u64;
            let segment = segment_basename(&self.prefix, self.cur_segment);
            let start_offset = self.cur_offset;
            self.cur_offset += bytes_skipped;
            return Err(ConsumerError::Corruption {
                segment,
                byte_offset: start_offset,
                bytes_skipped,
            });
        }
        // Strip the trailing \n.
        let mut bytes = buf;
        bytes.pop();
        self.cur_offset += n as u64;
        Ok(Some(Record {
            bytes,
            offset: DurableOffset {
                segment: segment_basename(&self.prefix, self.cur_segment),
                byte_offset: self.cur_offset,
            },
        }))
    }

    fn try_advance_segment(&mut self) -> Result<bool, ConsumerError> {
        // If a higher-numbered segment exists, advance.
        let next_n = self.cur_segment + 1;
        let next_path = self.spool_dir.join(segment_basename(&self.prefix, next_n));
        if next_path.exists() {
            self.cur_segment = next_n;
            self.cur_offset = 0;
            self.open_current_if_exists()?;
            return Ok(true);
        }
        Ok(false)
    }

    fn open_current_if_exists(&mut self) -> Result<(), ConsumerError> {
        let path = self
            .spool_dir
            .join(segment_basename(&self.prefix, self.cur_segment));
        match File::open(&path) {
            Ok(f) => {
                self.cur_file = Some(f);
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.cur_file = None;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
}

fn segment_basename(prefix: &str, n: u64) -> String {
    format!("{prefix}-{n}.jsonl")
}

fn parse_segment_n(basename: &str, prefix: &str) -> u64 {
    basename
        .strip_prefix(&format!("{prefix}-"))
        .and_then(|s| s.strip_suffix(".jsonl"))
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}
