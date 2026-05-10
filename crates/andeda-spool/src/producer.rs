//! Spool producer — append + fsync + return durable offset.

use crate::DurableOffset;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::PathBuf;
use thiserror::Error;

/// Configuration for a single producer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProducerConfig {
    /// Directory containing segment files.
    pub spool_dir: PathBuf,
    /// File name pattern; segment N is `<prefix>-<N>.jsonl`.
    pub prefix: String,
    /// Roll to a new segment when the current one exceeds this many bytes.
    pub max_segment_bytes: u64,
}

/// Errors produced by the producer.
#[derive(Debug, Error)]
pub enum ProducerError {
    /// I/O failure (read, write, fsync, rename).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The line passed to `append_line` contained a `\n` byte.
    #[error("line contains embedded newline")]
    EmbeddedNewline,
}

/// Producer (writer) for a single spool.
pub struct Producer {
    cfg: ProducerConfig,
    current_segment_n: u64,
    current_file: File,
    current_size: u64,
}

impl Producer {
    /// Open or create the producer. Scans the spool directory for existing
    /// segments, picks the one with the highest sequence number, and
    /// truncates any incomplete trailing line back to the last `\n`.
    pub fn open(cfg: ProducerConfig) -> Result<Self, ProducerError> {
        std::fs::create_dir_all(&cfg.spool_dir)?;

        let segment_n = scan_highest_segment(&cfg)?.unwrap_or(0);
        let path = segment_path(&cfg, segment_n);

        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&path)?;

        // Truncation recovery: find the last `\n` and truncate beyond it.
        let size = file.metadata()?.len();
        let good_size = last_newline_offset(&mut file, size)?;
        if good_size != size {
            file.set_len(good_size)?;
            file.sync_all()?;
            tracing::warn!(
                segment = %path.display(),
                lost_bytes = size - good_size,
                "truncated incomplete trailing line on open"
            );
        }
        file.seek(SeekFrom::End(0))?;

        Ok(Self {
            cfg,
            current_segment_n: segment_n,
            current_file: file,
            current_size: good_size,
        })
    }

    /// Append a JSONL line and fsync. The line MUST NOT contain `\n` (the
    /// producer adds the trailing newline). Returns the durable byte offset
    /// after the append.
    pub fn append_line(&mut self, line: &[u8]) -> Result<DurableOffset, ProducerError> {
        if line.contains(&b'\n') {
            return Err(ProducerError::EmbeddedNewline);
        }
        // Roll to a new segment if this write would push us past the cap.
        let needed = line.len() as u64 + 1;
        if self.current_size > 0 && self.current_size + needed > self.cfg.max_segment_bytes {
            self.roll()?;
        }
        self.current_file.write_all(line)?;
        self.current_file.write_all(b"\n")?;
        self.current_file.sync_all()?;
        self.current_size += needed;
        Ok(DurableOffset {
            segment: segment_basename(&self.cfg, self.current_segment_n),
            byte_offset: self.current_size,
        })
    }

    fn roll(&mut self) -> Result<(), ProducerError> {
        self.current_segment_n += 1;
        let path = segment_path(&self.cfg, self.current_segment_n);
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        self.current_file = file;
        self.current_size = 0;
        Ok(())
    }
}

fn segment_basename(cfg: &ProducerConfig, n: u64) -> String {
    format!("{}-{}.jsonl", cfg.prefix, n)
}

fn segment_path(cfg: &ProducerConfig, n: u64) -> PathBuf {
    cfg.spool_dir.join(segment_basename(cfg, n))
}

fn scan_highest_segment(cfg: &ProducerConfig) -> std::io::Result<Option<u64>> {
    let mut best: Option<u64> = None;
    for entry in std::fs::read_dir(&cfg.spool_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        let stripped = match name
            .strip_prefix(&format!("{}-", cfg.prefix))
            .and_then(|s| s.strip_suffix(".jsonl"))
        {
            Some(s) => s,
            None => continue,
        };
        if let Ok(n) = stripped.parse::<u64>() {
            best = Some(best.map_or(n, |b| b.max(n)));
        }
    }
    Ok(best)
}

fn last_newline_offset(file: &mut File, size: u64) -> std::io::Result<u64> {
    if size == 0 {
        return Ok(0);
    }
    file.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::new(file);
    let mut last_good: u64 = 0;
    let mut cursor: u64 = 0;
    let mut buf = String::new();
    loop {
        buf.clear();
        let n = reader.read_line(&mut buf)?;
        if n == 0 {
            break;
        }
        cursor += n as u64;
        if buf.ends_with('\n') {
            last_good = cursor;
        }
    }
    Ok(last_good)
}
