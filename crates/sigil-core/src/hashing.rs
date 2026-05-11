//! Streaming blake3 hashing with a 10 MB size cap.

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;
use thiserror::Error;

pub const MAX_HASH_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum HashError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

/// Result of hashing a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashOutcome {
    /// The hash succeeded; payload is the hex blake3 + size.
    Hashed { hex: String, size: u64 },
    /// File is larger than `MAX_HASH_BYTES`; size known but hash skipped.
    TooLarge { size: u64 },
    /// File disappeared before/while hashing — caller emits Incomplete.
    NotFound,
}

/// Hash a path, returning an outcome variant. Streams 64 KB at a time so
/// memory use stays bounded regardless of file size.
pub fn hash_path(path: &Path) -> Result<HashOutcome, HashError> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(HashOutcome::NotFound),
        Err(e) => return Err(e.into()),
    };
    let metadata = file.metadata()?;
    let size = metadata.len();
    if size > MAX_HASH_BYTES {
        return Ok(HashOutcome::TooLarge { size });
    }
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(HashOutcome::Hashed {
        hex: hasher.finalize().to_hex().to_string(),
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn empty_file_has_known_blake3() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("empty");
        File::create(&p).unwrap();
        let out = hash_path(&p).unwrap();
        match out {
            HashOutcome::Hashed { hex, size } => {
                assert_eq!(size, 0);
                assert_eq!(
                    hex,
                    "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
                );
            }
            _ => panic!("expected Hashed"),
        }
    }

    #[test]
    fn hashes_one_megabyte() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("1mb");
        let mut f = File::create(&p).unwrap();
        f.write_all(&vec![0x42u8; 1024 * 1024]).unwrap();
        let out = hash_path(&p).unwrap();
        match out {
            HashOutcome::Hashed { size, .. } => assert_eq!(size, 1024 * 1024),
            _ => panic!(),
        }
    }

    #[test]
    fn ten_megs_plus_one_returns_too_large() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("big");
        let mut f = File::create(&p).unwrap();
        f.write_all(&vec![0u8; (MAX_HASH_BYTES + 1) as usize])
            .unwrap();
        let out = hash_path(&p).unwrap();
        assert!(matches!(out, HashOutcome::TooLarge { .. }));
    }

    #[test]
    fn missing_file_returns_not_found() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("ghost");
        let out = hash_path(&p).unwrap();
        assert_eq!(out, HashOutcome::NotFound);
    }
}
