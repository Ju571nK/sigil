//! Atomic checkpoint write (tmp + fsync + rename), single fsync barrier.

use crate::DurableOffset;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors produced by checkpoint operations.
#[derive(Debug, Error)]
pub enum CheckpointError {
    /// I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization / deserialization failure.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OnDisk {
    segment: String,
    byte_offset: u64,
}

/// Persistent checkpoint state for one consumer.
pub struct Checkpoint {
    path: PathBuf,
    state: Option<DurableOffset>,
}

impl Checkpoint {
    /// Open (or create-on-first-write) the checkpoint at the given path.
    /// A nonexistent path is treated as an empty checkpoint (`position()`
    /// returns `None`); calling `advance` will then create the file.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, CheckpointError> {
        let path = path.as_ref().to_path_buf();
        let state = match fs::read(&path) {
            Ok(bytes) => {
                let on_disk: OnDisk = serde_json::from_slice(&bytes)?;
                Some(DurableOffset {
                    segment: on_disk.segment,
                    byte_offset: on_disk.byte_offset,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        Ok(Self { path, state })
    }

    /// Last persisted position, or `None` if no `advance` has ever succeeded.
    pub fn position(&self) -> Option<DurableOffset> {
        self.state.clone()
    }

    /// Atomically write the new position: write to `<path>.tmp`, fsync, rename
    /// over `<path>`. A single fsync barrier per advance.
    pub fn advance(&mut self, offset: DurableOffset) -> Result<(), CheckpointError> {
        let on_disk = OnDisk {
            segment: offset.segment.clone(),
            byte_offset: offset.byte_offset,
        };
        let bytes = serde_json::to_vec(&on_disk)?;
        let tmp = tmp_path(&self.path);
        {
            let mut f: File = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        // Best-effort fsync of the parent dir to make the rename durable.
        if let Some(parent) = self.path.parent() {
            if let Ok(d) = File::open(parent) {
                let _ = d.sync_all();
            }
        }
        self.state = Some(offset);
        Ok(())
    }
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}
