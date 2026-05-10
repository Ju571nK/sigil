//! Hash baseline persistence backed by SQLite.

use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
}

pub struct HashCache {
    conn: Connection,
}

impl HashCache {
    pub fn open(db_path: &Path) -> Result<Self, StateError> {
        let conn = Connection::open(db_path)?;
        // Spec section 1.4 PRAGMAs.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        conn.pragma_update(None, "mmap_size", 0i64)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS baseline (
                path TEXT PRIMARY KEY,
                hash_hex TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                target_id TEXT NOT NULL,
                updated_at_ms INTEGER NOT NULL
            )",
            [],
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS host_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                host_id TEXT,
                hw_fingerprint TEXT,
                last_applied_policy_version INTEGER NOT NULL DEFAULT 0
            )",
            [],
        )?;
        // Ensure singleton row 1 exists. Idempotent.
        conn.execute(
            "INSERT OR IGNORE INTO host_meta (id, host_id, hw_fingerprint, last_applied_policy_version)
             VALUES (1, NULL, NULL, 0)",
            [],
        )?;
        Ok(Self { conn })
    }

    pub fn put(
        &self,
        path: &Path,
        hash_hex: &str,
        size: u64,
        target_id: &str,
        now_ms: u64,
    ) -> Result<(), StateError> {
        let path_str = path.to_string_lossy();
        self.conn.execute(
            "INSERT OR REPLACE INTO baseline (path, hash_hex, size_bytes, target_id, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![path_str, hash_hex, size as i64, target_id, now_ms as i64],
        )?;
        Ok(())
    }

    pub fn get(&self, path: &Path) -> Result<Option<String>, StateError> {
        let path_str = path.to_string_lossy();
        Ok(self
            .conn
            .query_row(
                "SELECT hash_hex FROM baseline WHERE path = ?1",
                params![path_str],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn delete(&self, path: &Path) -> Result<(), StateError> {
        let path_str = path.to_string_lossy();
        self.conn
            .execute("DELETE FROM baseline WHERE path = ?1", params![path_str])?;
        Ok(())
    }

    pub fn size_on_disk(&self, db_path: &Path) -> u64 {
        std::fs::metadata(db_path).map(|m| m.len()).unwrap_or(0)
    }

    pub fn count(&self) -> Result<u64, StateError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM baseline", [], |row| row.get(0))?;
        Ok(n as u64)
    }

    pub fn all_paths(&self) -> Result<Vec<PathBuf>, StateError> {
        let mut stmt = self
            .conn
            .prepare("SELECT path FROM baseline ORDER BY path")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(PathBuf::from(r?));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn open_in(td: &TempDir) -> (HashCache, PathBuf) {
        let dbp = td.path().join("state.db");
        (HashCache::open(&dbp).unwrap(), dbp)
    }

    #[test]
    fn put_and_get_roundtrip() {
        let td = TempDir::new().unwrap();
        let (c, _) = open_in(&td);
        c.put(Path::new("/x"), "abc", 10, "t1", 0).unwrap();
        assert_eq!(c.get(Path::new("/x")).unwrap().as_deref(), Some("abc"));
    }

    #[test]
    fn missing_returns_none() {
        let td = TempDir::new().unwrap();
        let (c, _) = open_in(&td);
        assert!(c.get(Path::new("/nope")).unwrap().is_none());
    }

    #[test]
    fn replace_updates_existing() {
        let td = TempDir::new().unwrap();
        let (c, _) = open_in(&td);
        c.put(Path::new("/x"), "old", 10, "t1", 0).unwrap();
        c.put(Path::new("/x"), "new", 20, "t1", 1).unwrap();
        assert_eq!(c.get(Path::new("/x")).unwrap().as_deref(), Some("new"));
    }

    #[test]
    fn data_persists_across_open() {
        let td = TempDir::new().unwrap();
        let dbp = td.path().join("state.db");
        {
            let c = HashCache::open(&dbp).unwrap();
            c.put(Path::new("/x"), "abc", 10, "t1", 0).unwrap();
        }
        let c2 = HashCache::open(&dbp).unwrap();
        assert_eq!(c2.get(Path::new("/x")).unwrap().as_deref(), Some("abc"));
    }

    #[test]
    fn delete_removes_entry() {
        let td = TempDir::new().unwrap();
        let (c, _) = open_in(&td);
        c.put(Path::new("/x"), "abc", 10, "t1", 0).unwrap();
        c.delete(Path::new("/x")).unwrap();
        assert!(c.get(Path::new("/x")).unwrap().is_none());
    }

    #[test]
    fn count_reflects_inserts() {
        let td = TempDir::new().unwrap();
        let (c, _) = open_in(&td);
        c.put(Path::new("/a"), "1", 0, "t", 0).unwrap();
        c.put(Path::new("/b"), "2", 0, "t", 0).unwrap();
        assert_eq!(c.count().unwrap(), 2);
    }

    #[test]
    fn lookup_p99_under_one_ms_for_50k_entries() {
        // Skip in debug builds; SQLite without optimization can be slow.
        if cfg!(debug_assertions) {
            eprintln!("skipping lookup perf test in debug build");
            return;
        }
        let td = TempDir::new().unwrap();
        let (c, _) = open_in(&td);
        for i in 0..50_000u32 {
            c.put(Path::new(&format!("/p/{i}")), "h", 0, "t", 0)
                .unwrap();
        }
        let mut samples = Vec::with_capacity(1000);
        for i in 0..1000u32 {
            let t0 = std::time::Instant::now();
            let _ = c
                .get(Path::new(&format!("/p/{}", i * 47 % 50_000)))
                .unwrap();
            samples.push(t0.elapsed().as_micros() as u64);
        }
        samples.sort_unstable();
        let p99 = samples[(samples.len() as f64 * 0.99) as usize];
        assert!(p99 < 1000, "p99 lookup latency {p99}us > 1ms");
    }
}

#[cfg(test)]
mod host_meta_tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn host_meta_table_created_on_open() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("state.db");
        let cache = HashCache::open(&db).unwrap();

        // Direct SQL to confirm the table exists with expected columns.
        let cols: Vec<String> = cache
            .conn
            .prepare("PRAGMA table_info(host_meta)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(cols.contains(&"id".to_string()));
        assert!(cols.contains(&"host_id".to_string()));
        assert!(cols.contains(&"hw_fingerprint".to_string()));
        assert!(cols.contains(&"last_applied_policy_version".to_string()));
    }

    #[test]
    fn host_meta_singleton_row_initialized_to_empty() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("state.db");
        let cache = HashCache::open(&db).unwrap();
        let row: (i64, Option<String>, Option<String>, i64) = cache
            .conn
            .query_row(
                "SELECT id, host_id, hw_fingerprint, last_applied_policy_version
                 FROM host_meta WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(row.0, 1);
        assert_eq!(row.1, None);
        assert_eq!(row.2, None);
        assert_eq!(row.3, 0);
    }
}
