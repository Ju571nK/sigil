use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub base_url: String,
    pub token: String,
    pub mtls: Option<MtlsPaths>,
}

#[derive(Debug, Clone)]
pub struct MtlsPaths {
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
    pub ca_cert: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required env var {0}")]
    Missing(&'static str),
    #[error("incomplete mTLS config: set all of SIGIL_CLIENT_CERT, SIGIL_CLIENT_KEY, SIGIL_CA_CERT, or none")]
    PartialMtls,
}

impl Config {
    pub fn from_map(map: &HashMap<String, String>) -> Result<Self, ConfigError> {
        let base_url = map
            .get("SIGIL_SERVER_BASE_URL")
            .cloned()
            .ok_or(ConfigError::Missing("SIGIL_SERVER_BASE_URL"))?;
        let token = map
            .get("SIGIL_SERVER_READ_TOKEN")
            .cloned()
            .ok_or(ConfigError::Missing("SIGIL_SERVER_READ_TOKEN"))?;
        let mtls = match (
            map.get("SIGIL_CLIENT_CERT"),
            map.get("SIGIL_CLIENT_KEY"),
            map.get("SIGIL_CA_CERT"),
        ) {
            (Some(c), Some(k), Some(a)) => Some(MtlsPaths {
                client_cert: PathBuf::from(c),
                client_key: PathBuf::from(k),
                ca_cert: PathBuf::from(a),
            }),
            (None, None, None) => None,
            _ => return Err(ConfigError::PartialMtls),
        };
        Ok(Config {
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            mtls,
        })
    }
}

/// Operating mode, selected from the environment. `SIGIL_SERVER_BASE_URL`
/// present -> [`Mode::Fleet`] (the existing read-API client config); absent ->
/// [`Mode::Local`], which talks to a local sigil-agent over its control socket.
#[derive(Debug, Clone)]
pub enum Mode {
    Fleet(Config),
    Local(LocalConfig),
}

/// Local-mode config: the path to the local agent's control socket.
#[derive(Debug, Clone)]
pub struct LocalConfig {
    pub socket: PathBuf,
}

impl Mode {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_map(&std::env::vars().collect())
    }

    pub fn from_map(map: &HashMap<String, String>) -> Result<Self, ConfigError> {
        if map.contains_key("SIGIL_SERVER_BASE_URL") {
            Ok(Mode::Fleet(Config::from_map(map)?))
        } else {
            let socket = map
                .get("SIGIL_AGENT_CONTROL_SOCKET")
                .map(PathBuf::from)
                .unwrap_or_else(default_control_socket);
            Ok(Mode::Local(LocalConfig { socket }))
        }
    }
}

/// Default agent control-socket path, mirroring sigil-agent's
/// `default_control_socket()`: as root, the system path `/var/run/sigil`;
/// else `$XDG_RUNTIME_DIR/sigil`; else `$TMPDIR`/`/tmp/sigil-<uid>`. The pure
/// branch logic is shared via `sigil_core::control_proto::resolve_control_socket`;
/// this wrapper supplies the euid/root/XDG/TMPDIR inputs. Override with
/// `SIGIL_AGENT_CONTROL_SOCKET`.
fn default_control_socket() -> PathBuf {
    sigil_core::control_proto::resolve_control_socket(
        is_root(),
        std::env::var("XDG_RUNTIME_DIR")
            .ok()
            .filter(|s| !s.is_empty()),
        std::env::var("TMPDIR").ok().filter(|s| !s.is_empty()),
        current_uid(),
    )
}

/// True when the process effective uid is 0 (root). Non-Unix: always false.
#[cfg(unix)]
fn is_root() -> bool {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}
#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

/// Process real uid — namespaces the fallback socket dir in shared `/tmp`.
/// Non-Unix: 0 (unused; Windows uses the named pipe).
#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: `getuid` has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}
#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn missing_base_url_errs() {
        let m = map(&[("SIGIL_SERVER_READ_TOKEN", "t")]);
        assert!(matches!(
            Config::from_map(&m),
            Err(ConfigError::Missing("SIGIL_SERVER_BASE_URL"))
        ));
    }

    #[test]
    fn missing_token_errs() {
        let m = map(&[("SIGIL_SERVER_BASE_URL", "http://x")]);
        assert!(matches!(
            Config::from_map(&m),
            Err(ConfigError::Missing("SIGIL_SERVER_READ_TOKEN"))
        ));
    }

    #[test]
    fn bearer_only_ok_and_trailing_slash_trimmed() {
        let m = map(&[
            ("SIGIL_SERVER_BASE_URL", "http://127.0.0.1:9090/"),
            ("SIGIL_SERVER_READ_TOKEN", "tok"),
        ]);
        let c = Config::from_map(&m).unwrap();
        assert_eq!(c.base_url, "http://127.0.0.1:9090");
        assert_eq!(c.token, "tok");
        assert!(c.mtls.is_none());
    }

    #[test]
    fn full_mtls_parsed() {
        let m = map(&[
            ("SIGIL_SERVER_BASE_URL", "https://h:8443"),
            ("SIGIL_SERVER_READ_TOKEN", "tok"),
            ("SIGIL_CLIENT_CERT", "/p/c.crt"),
            ("SIGIL_CLIENT_KEY", "/p/c.key"),
            ("SIGIL_CA_CERT", "/p/ca.crt"),
        ]);
        let c = Config::from_map(&m).unwrap();
        let mtls = c.mtls.unwrap();
        assert_eq!(mtls.client_cert.to_str().unwrap(), "/p/c.crt");
        assert_eq!(mtls.client_key.to_str().unwrap(), "/p/c.key");
        assert_eq!(mtls.ca_cert.to_str().unwrap(), "/p/ca.crt");
    }

    #[test]
    fn partial_mtls_errs() {
        let m = map(&[
            ("SIGIL_SERVER_BASE_URL", "https://h:8443"),
            ("SIGIL_SERVER_READ_TOKEN", "tok"),
            ("SIGIL_CLIENT_CERT", "/p/c.crt"),
        ]);
        assert!(matches!(
            Config::from_map(&m),
            Err(ConfigError::PartialMtls)
        ));
    }

    #[test]
    fn server_url_present_selects_fleet() {
        let m = map(&[
            ("SIGIL_SERVER_BASE_URL", "http://h:8443"),
            ("SIGIL_SERVER_READ_TOKEN", "t"),
        ]);
        assert!(matches!(Mode::from_map(&m).unwrap(), Mode::Fleet(_)));
    }

    #[test]
    fn no_server_url_selects_local() {
        let m = map(&[]);
        assert!(matches!(Mode::from_map(&m).unwrap(), Mode::Local(_)));
    }

    #[test]
    fn explicit_socket_env_honored() {
        let m = map(&[("SIGIL_AGENT_CONTROL_SOCKET", "/tmp/x/control.sock")]);
        match Mode::from_map(&m).unwrap() {
            Mode::Local(c) => assert_eq!(c.socket.to_str().unwrap(), "/tmp/x/control.sock"),
            _ => panic!("expected local"),
        }
    }
}
