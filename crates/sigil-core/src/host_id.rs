//! HostIdStrategy resolution.
//!
//! Strategy parsing/validation lives here; OS-specific resolution lives in
//! `sigil-agent::platform::*`. This crate provides a trait that the agent
//! implements per OS.

use crate::policy::HostIdStrategy;

pub trait HostIdResolver {
    fn machine_id(&self) -> Option<String>;
    fn hostname(&self) -> Option<String>;
    fn fresh_uuid(&self) -> String;
}

/// Resolve a `HostIdStrategy` to a concrete host_id string. Falls back through
/// `MachineId → Hostname → fresh_uuid` if upstream returns None.
pub fn resolve(strategy: &HostIdStrategy, resolver: &impl HostIdResolver) -> String {
    match strategy {
        HostIdStrategy::Static(v) => v.clone(),
        HostIdStrategy::MachineId => resolver
            .machine_id()
            .or_else(|| resolver.hostname())
            .unwrap_or_else(|| resolver.fresh_uuid()),
        HostIdStrategy::Hostname => resolver
            .hostname()
            .or_else(|| resolver.machine_id())
            .unwrap_or_else(|| resolver.fresh_uuid()),
        HostIdStrategy::Uuid => resolver.fresh_uuid(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Mock {
        m: Option<&'static str>,
        h: Option<&'static str>,
        u: &'static str,
    }
    impl HostIdResolver for Mock {
        fn machine_id(&self) -> Option<String> {
            self.m.map(String::from)
        }
        fn hostname(&self) -> Option<String> {
            self.h.map(String::from)
        }
        fn fresh_uuid(&self) -> String {
            self.u.into()
        }
    }

    #[test]
    fn static_returns_literal() {
        let r = Mock {
            m: None,
            h: None,
            u: "u",
        };
        let id = resolve(&HostIdStrategy::Static("fixed".into()), &r);
        assert_eq!(id, "fixed");
    }

    #[test]
    fn machine_id_falls_back_to_hostname() {
        let r = Mock {
            m: None,
            h: Some("host"),
            u: "u",
        };
        assert_eq!(resolve(&HostIdStrategy::MachineId, &r), "host");
    }

    #[test]
    fn machine_id_falls_back_to_uuid_if_no_hostname() {
        let r = Mock {
            m: None,
            h: None,
            u: "uuid-123",
        };
        assert_eq!(resolve(&HostIdStrategy::MachineId, &r), "uuid-123");
    }

    #[test]
    fn hostname_strategy_prefers_hostname() {
        let r = Mock {
            m: Some("m"),
            h: Some("h"),
            u: "u",
        };
        assert_eq!(resolve(&HostIdStrategy::Hostname, &r), "h");
    }

    #[test]
    fn uuid_strategy_always_uuid() {
        let r = Mock {
            m: Some("m"),
            h: Some("h"),
            u: "u",
        };
        assert_eq!(resolve(&HostIdStrategy::Uuid, &r), "u");
    }
}
