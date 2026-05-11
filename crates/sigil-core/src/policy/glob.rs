//! Glob compilation wrapping `globset`.

use globset::{Glob, GlobMatcher};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GlobError {
    #[error("invalid glob pattern: {0}")]
    Invalid(#[from] globset::Error),
}

#[derive(Debug)]
pub struct CompiledGlob(GlobMatcher);

impl CompiledGlob {
    pub fn new(pattern: &str) -> Result<Self, GlobError> {
        let glob = Glob::new(pattern)?;
        Ok(Self(glob.compile_matcher()))
    }

    pub fn is_match(&self, path: &Path) -> bool {
        self.0.is_match(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn matches_star_glob() {
        let g = CompiledGlob::new("/Applications/*.app/Contents/Info.plist").unwrap();
        assert!(g.is_match(Path::new("/Applications/Cursor.app/Contents/Info.plist")));
        assert!(!g.is_match(Path::new("/tmp/Cursor.app/Contents/Info.plist")));
    }

    #[test]
    fn matches_question_mark_and_charclass() {
        let g = CompiledGlob::new("/tmp/file?.[ab]").unwrap();
        assert!(g.is_match(&PathBuf::from("/tmp/file1.a")));
        assert!(g.is_match(&PathBuf::from("/tmp/fileX.b")));
        assert!(!g.is_match(&PathBuf::from("/tmp/file12.a")));
    }

    #[test]
    fn literal_path_matches_exactly() {
        let g = CompiledGlob::new("/Users/alice/.claude.json").unwrap();
        assert!(g.is_match(Path::new("/Users/alice/.claude.json")));
        assert!(!g.is_match(Path::new("/Users/alice/.claude.jsonx")));
    }
}
