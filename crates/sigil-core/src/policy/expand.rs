//! Path token expansion: `~`, `$VAR`, `%VAR%`, `%ProgramFiles(x86)%`.

use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExpandError {
    #[error("undefined variable: {0}")]
    UndefinedVar(String),
    #[error("home directory unavailable")]
    HomeUnavailable,
    #[error("malformed token at position {0}")]
    Malformed(usize),
}

/// Lookup function used to resolve variables. Production callers pass `std::env::var`.
/// Tests pass mock closures.
pub trait VarLookup {
    fn lookup(&self, name: &str) -> Option<String>;
    fn home(&self) -> Option<PathBuf>;
}

pub struct EnvLookup;

impl VarLookup for EnvLookup {
    fn lookup(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
    fn home(&self) -> Option<PathBuf> {
        // We avoid the `dirs` crate here to keep sigil-core dep-free of OS APIs.
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

/// Expand path tokens in `input`. Single-user (uses caller's lookup).
pub fn expand(input: &str, vars: &impl VarLookup) -> Result<PathBuf, ExpandError> {
    let mut out = String::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'~' if i == 0 && (bytes.len() == 1 || bytes[1] == b'/' || bytes[1] == b'\\') => {
                let home = vars.home().ok_or(ExpandError::HomeUnavailable)?;
                out.push_str(home.to_str().ok_or(ExpandError::Malformed(i))?);
                i += 1;
            }
            b'$' if i + 1 < bytes.len() => {
                // $VAR — name terminates on non [A-Za-z0-9_]
                let start = i + 1;
                let mut end = start;
                while end < bytes.len()
                    && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_')
                {
                    end += 1;
                }
                if end == start {
                    return Err(ExpandError::Malformed(i));
                }
                let name = &input[start..end];
                let value = vars
                    .lookup(name)
                    .ok_or_else(|| ExpandError::UndefinedVar(name.to_string()))?;
                out.push_str(&value);
                i = end;
            }
            b'%' => {
                // %VAR% — name terminates at next %; allowed inner chars include parens
                let start = i + 1;
                let mut end = start;
                while end < bytes.len() && bytes[end] != b'%' {
                    end += 1;
                }
                if end == bytes.len() {
                    return Err(ExpandError::Malformed(i));
                }
                let name = &input[start..end];
                let value = vars
                    .lookup(name)
                    .ok_or_else(|| ExpandError::UndefinedVar(name.to_string()))?;
                out.push_str(&value);
                i = end + 1;
            }
            other => {
                out.push(other as char);
                i += 1;
            }
        }
    }
    Ok(PathBuf::from(out))
}

/// One human user discovered on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserContext {
    pub name: String,
    pub home: PathBuf,
    pub uid_or_sid: String,
}

/// Trait for runtime user enumeration. The agent crate implements this per OS.
pub trait UserEnumerator {
    fn list(&self) -> Vec<UserContext>;
}

/// Expand a path template once per user. Tokens `~` and `%USERPROFILE%` are
/// resolved per user; system tokens (`$HOME` is treated as system) use `vars`.
pub fn expand_per_user(
    template: &str,
    users: &[UserContext],
    vars: &impl VarLookup,
) -> Vec<Result<PathBuf, ExpandError>> {
    // If the template has no user-scoped token, expand once with system vars only.
    let user_scoped = template.contains('~') || template.contains("%USERPROFILE%");
    if !user_scoped {
        return vec![expand(template, vars)];
    }
    users
        .iter()
        .map(|u| {
            // Build a per-user lookup that overrides ~ and %USERPROFILE%.
            let per_user = PerUserLookup {
                user_home: u.home.clone(),
                inner: vars,
            };
            expand(template, &per_user)
        })
        .collect()
}

struct PerUserLookup<'a, V: VarLookup> {
    user_home: PathBuf,
    inner: &'a V,
}

impl<'a, V: VarLookup> VarLookup for PerUserLookup<'a, V> {
    fn lookup(&self, name: &str) -> Option<String> {
        if name == "USERPROFILE" || name == "HOME" {
            self.user_home.to_str().map(|s| s.to_string())
        } else {
            self.inner.lookup(name)
        }
    }
    fn home(&self) -> Option<PathBuf> {
        Some(self.user_home.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Mock {
        vars: HashMap<&'static str, &'static str>,
        home: Option<&'static str>,
    }
    impl VarLookup for Mock {
        fn lookup(&self, name: &str) -> Option<String> {
            self.vars.get(name).map(|s| s.to_string())
        }
        fn home(&self) -> Option<PathBuf> {
            self.home.map(PathBuf::from)
        }
    }

    fn mock(home: Option<&'static str>, vars: &[(&'static str, &'static str)]) -> Mock {
        Mock {
            home,
            vars: vars.iter().copied().collect(),
        }
    }

    #[test]
    fn expands_tilde_at_start() {
        let m = mock(Some("/Users/alice"), &[]);
        assert_eq!(
            expand("~/.claude.json", &m).unwrap(),
            PathBuf::from("/Users/alice/.claude.json")
        );
    }

    #[test]
    fn expands_dollar_var() {
        let m = mock(None, &[("HOME", "/Users/alice")]);
        assert_eq!(
            expand("$HOME/.config", &m).unwrap(),
            PathBuf::from("/Users/alice/.config")
        );
    }

    #[test]
    fn expands_percent_var() {
        let m = mock(None, &[("APPDATA", r"C:\Users\alice\AppData\Roaming")]);
        assert_eq!(
            expand(r"%APPDATA%\Cursor", &m).unwrap(),
            PathBuf::from(r"C:\Users\alice\AppData\Roaming\Cursor")
        );
    }

    #[test]
    fn expands_program_files_x86_with_parens() {
        let m = mock(None, &[("ProgramFiles(x86)", r"C:\Program Files (x86)")]);
        assert_eq!(
            expand(r"%ProgramFiles(x86)%\OldApp", &m).unwrap(),
            PathBuf::from(r"C:\Program Files (x86)\OldApp")
        );
    }

    #[test]
    fn errors_on_undefined_var() {
        let m = mock(None, &[]);
        assert_eq!(
            expand("$NOPE/foo", &m).unwrap_err(),
            ExpandError::UndefinedVar("NOPE".into())
        );
    }

    #[test]
    fn errors_on_unterminated_percent() {
        let m = mock(None, &[]);
        assert_eq!(
            expand("%APPDATA", &m).unwrap_err(),
            ExpandError::Malformed(0)
        );
    }

    fn users() -> Vec<UserContext> {
        vec![
            UserContext {
                name: "alice".into(),
                home: PathBuf::from("/Users/alice"),
                uid_or_sid: "501".into(),
            },
            UserContext {
                name: "bob".into(),
                home: PathBuf::from("/Users/bob"),
                uid_or_sid: "502".into(),
            },
        ]
    }

    #[test]
    fn expands_tilde_per_user() {
        let m = mock(Some("/var/root"), &[]);
        let out = expand_per_user("~/.claude.json", &users(), &m);
        assert_eq!(out.len(), 2);
        assert_eq!(
            out[0].as_ref().unwrap(),
            &PathBuf::from("/Users/alice/.claude.json")
        );
        assert_eq!(
            out[1].as_ref().unwrap(),
            &PathBuf::from("/Users/bob/.claude.json")
        );
    }

    #[test]
    fn expands_userprofile_per_user() {
        let m = mock(None, &[]);
        let out = expand_per_user(r"%USERPROFILE%\Cursor", &users(), &m);
        assert_eq!(out.len(), 2);
        assert!(out[0].as_ref().unwrap().to_string_lossy().contains("alice"));
        assert!(out[1].as_ref().unwrap().to_string_lossy().contains("bob"));
    }

    #[test]
    fn system_path_expands_once() {
        let m = mock(None, &[("PROGRAMFILES", r"C:\Program Files")]);
        let out = expand_per_user(r"%PROGRAMFILES%\App", &users(), &m);
        assert_eq!(out.len(), 1);
    }
}
