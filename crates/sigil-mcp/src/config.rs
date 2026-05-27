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
    pub fn from_env() -> Result<Self, ConfigError> {
        let map: HashMap<String, String> = std::env::vars().collect();
        Self::from_map(&map)
    }

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
}
