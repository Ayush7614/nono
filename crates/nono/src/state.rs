//! Sandbox state persistence
//!
//! This module provides serialization of capability state for diagnostic purposes.

use crate::capability::{
    AccessMode, CapabilitySet, FsCapability, IpcMode, NetworkMode, ProcessInfoMode, SignalMode,
    SocketScope, UnixSocketCapability, UnixSocketMode,
};
use crate::resource::ResourceLimits;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_signal_default(m: &SignalMode) -> bool {
    *m == SignalMode::Isolated
}

fn is_process_info_default(m: &ProcessInfoMode) -> bool {
    *m == ProcessInfoMode::Isolated
}

fn is_ipc_default(m: &IpcMode) -> bool {
    *m == IpcMode::SharedMemoryOnly
}

/// Serializable representation of sandbox state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxState {
    /// Filesystem capabilities
    pub fs: Vec<FsCapState>,
    /// AF_UNIX socket capabilities (may be absent in states persisted
    /// by older nono builds; `#[serde(default)]` preserves backward compat).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unix_sockets: Vec<UnixSocketCapState>,
    /// Whether network is blocked (legacy field for backward compat).
    /// New states also set `network_mode`; old states lacking `network_mode`
    /// fall back to this boolean.
    pub net_blocked: bool,
    /// Precise network mode. Present in states written by new builds;
    /// absent in legacy states (where `net_blocked` is used instead).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_mode: Option<NetworkMode>,
    /// Whether implicit macOS DNS resolver grants are disabled.
    /// Older states retain their original DNS-enabled behavior.
    #[serde(default)]
    pub dns_blocked: bool,
    /// Per-port TCP connect allowlist (Linux Landlock V4+).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tcp_connect_ports: Vec<u16>,
    /// Per-port TCP bind allowlist (Linux Landlock V4+).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tcp_bind_ports: Vec<u16>,
    /// Bidirectional localhost IPC ports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub localhost_ports: Vec<u16>,
    /// Bidirectional localhost IPC port ranges (inclusive).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub localhost_port_ranges: Vec<(u16, u16)>,
    /// Signal isolation mode.
    #[serde(default, skip_serializing_if = "is_signal_default")]
    pub signal_mode: SignalMode,
    /// Process inspection mode.
    #[serde(default, skip_serializing_if = "is_process_info_default")]
    pub process_info_mode: ProcessInfoMode,
    /// IPC mode.
    #[serde(default, skip_serializing_if = "is_ipc_default")]
    pub ipc_mode: IpcMode,
    /// Whether sandbox extensions are enabled.
    #[serde(default, skip_serializing_if = "is_false")]
    pub extensions_enabled: bool,
    /// Whether macOS Seatbelt denial logging is enabled.
    #[serde(default, skip_serializing_if = "is_false")]
    pub seatbelt_debug_deny: bool,
    /// Commands explicitly allowed (overrides blocklists).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_commands: Vec<String>,
    /// Commands explicitly blocked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_commands: Vec<String>,
    /// Raw platform-specific Seatbelt rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub platform_rules: Vec<String>,
    /// Resource ceilings (memory and max processes). Absent in states from older
    /// nono builds; `#[serde(default)]` keeps those loadable. Plain numbers, so
    /// unlike paths they need no re-validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_limits: Option<ResourceLimits>,
}

/// Serializable representation of a filesystem capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsCapState {
    /// Original path as specified
    pub original: PathBuf,
    /// Resolved canonical path
    pub resolved: PathBuf,
    /// Access mode
    pub access: String,
    /// Whether this is a file (vs directory)
    pub is_file: bool,
}

/// Serializable representation of a [`UnixSocketCapability`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnixSocketCapState {
    /// Original path as specified
    pub original: PathBuf,
    /// Resolved canonical path
    pub resolved: PathBuf,
    /// Path matching scope for this socket grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<SocketScope>,
    /// Legacy state field from before `SocketScope`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_directory: Option<bool>,
    /// Mode string: "connect" or "connect+bind"
    pub mode: String,
}

impl SandboxState {
    /// Create state from a capability set
    #[must_use]
    pub fn from_caps(caps: &CapabilitySet) -> Self {
        Self {
            fs: caps
                .fs_capabilities()
                .iter()
                .map(|cap| FsCapState {
                    original: cap.original.clone(),
                    resolved: cap.resolved.clone(),
                    access: cap.access.to_string(),
                    is_file: cap.is_file,
                })
                .collect(),
            unix_sockets: caps
                .unix_socket_capabilities()
                .iter()
                .map(|cap| UnixSocketCapState {
                    original: cap.original.clone(),
                    resolved: cap.resolved.clone(),
                    scope: Some(cap.scope),
                    is_directory: None,
                    mode: cap.mode.to_string(),
                })
                .collect(),
            net_blocked: caps.is_network_blocked(),
            network_mode: Some(caps.network_mode().clone()),
            dns_blocked: !caps.dns_enabled(),
            tcp_connect_ports: caps.tcp_connect_ports().to_vec(),
            tcp_bind_ports: caps.tcp_bind_ports().to_vec(),
            localhost_ports: caps.localhost_ports().to_vec(),
            localhost_port_ranges: caps.localhost_port_ranges().to_vec(),
            signal_mode: caps.signal_mode(),
            process_info_mode: caps.process_info_mode(),
            ipc_mode: caps.ipc_mode(),
            extensions_enabled: caps.extensions_enabled(),
            seatbelt_debug_deny: caps.seatbelt_debug_deny(),
            allowed_commands: caps.allowed_commands().to_vec(),
            blocked_commands: caps.blocked_commands().to_vec(),
            platform_rules: caps.platform_rules().to_vec(),
            resource_limits: caps.resource_limits().copied(),
        }
    }

    /// Convert state back to a capability set
    ///
    /// Paths are re-validated through the standard constructors (`new_dir`/`new_file`)
    /// which canonicalize paths and verify existence. This prevents crafted JSON from
    /// injecting arbitrary paths that bypass validation.
    ///
    /// Returns an error if any path no longer exists or fails validation.
    pub fn to_caps(&self) -> crate::error::Result<CapabilitySet> {
        let mut caps = CapabilitySet::new();

        for fs_cap in &self.fs {
            let access = match fs_cap.access.as_str() {
                "read" => AccessMode::Read,
                "write" => AccessMode::Write,
                "read+write" => AccessMode::ReadWrite,
                other => {
                    return Err(crate::error::NonoError::ConfigParse(format!(
                        "invalid access mode in sandbox state: {other}"
                    )));
                }
            };

            // Re-validate through the standard constructors to ensure
            // path canonicalization and existence checks are applied.
            let cap = if fs_cap.is_file {
                FsCapability::new_file(&fs_cap.original, access)?
            } else {
                FsCapability::new_dir(&fs_cap.original, access)?
            };
            caps.add_fs(cap);
        }

        for sock in &self.unix_sockets {
            let mode = match sock.mode.as_str() {
                "connect" => UnixSocketMode::Connect,
                "connect+bind" => UnixSocketMode::ConnectBind,
                other => {
                    return Err(crate::error::NonoError::ConfigParse(format!(
                        "invalid unix socket mode in sandbox state: {other}"
                    )));
                }
            };

            // Reconstruct from the caller-supplied `original` so the
            // stored alias survives the roundtrip (macOS Seatbelt uses
            // it for dual-path emission when original != resolved).
            // Then validate that canonicalisation produced the same
            // `resolved` as was serialized. The check rejects two
            // failure modes with one test:
            //
            // - Filesystem drift between save and reload (symlink moved,
            //   ConnectBind pending path now exists, etc.).
            // - Crafted JSON smuggling: attacker sets an evil `original`
            //   and legit `resolved`; the reconstructed cap's actual
            //   resolved won't match the crafted one, so we reject.
            let scope = sock.scope.unwrap_or_else(|| {
                if sock.is_directory.unwrap_or(false) {
                    SocketScope::DirChildren
                } else {
                    SocketScope::File
                }
            });

            let cap = match scope {
                SocketScope::File => UnixSocketCapability::new_file(&sock.original, mode)?,
                SocketScope::DirChildren => UnixSocketCapability::new_dir(&sock.original, mode)?,
                SocketScope::DirSubtree => {
                    UnixSocketCapability::new_dir_subtree(&sock.original, mode)?
                }
            };
            if cap.resolved != sock.resolved {
                return Err(crate::error::NonoError::ConfigParse(format!(
                    "unix socket grant canonical path drifted at state reload: \
                     serialized resolved={}, actual resolved={}",
                    sock.resolved.display(),
                    cap.resolved.display(),
                )));
            }
            caps.add_unix_socket(cap);
        }

        // Prefer precise network_mode when present; fall back to legacy
        // net_blocked boolean for states written by older builds.
        if let Some(mode) = &self.network_mode {
            caps.set_network_mode_mut(mode.clone());
        } else {
            caps.set_network_blocked(self.net_blocked);
        }
        if self.dns_blocked {
            caps = caps.block_dns();
        }

        for port in &self.tcp_connect_ports {
            caps.add_tcp_connect_port(*port);
        }
        for port in &self.tcp_bind_ports {
            caps.add_tcp_bind_port(*port);
        }
        for port in &self.localhost_ports {
            caps.add_localhost_port(*port);
        }
        for (start, end) in &self.localhost_port_ranges {
            caps.add_localhost_port_range(*start, *end)?;
        }

        caps.set_signal_mode_mut(self.signal_mode);
        caps.set_process_info_mode_mut(self.process_info_mode);
        caps.set_ipc_mode_mut(self.ipc_mode);

        if self.extensions_enabled {
            caps = caps.enable_extensions();
        }
        if self.seatbelt_debug_deny {
            caps.set_seatbelt_debug_deny(true);
        }

        for cmd in &self.allowed_commands {
            caps.add_allowed_command(cmd.clone());
        }
        for cmd in &self.blocked_commands {
            caps.add_blocked_command(cmd.clone());
        }
        for rule in &self.platform_rules {
            caps.add_platform_rule(rule.clone())?;
        }

        if let Some(limits) = self.resource_limits {
            caps = caps.with_resource_limits(limits);
        }

        Ok(caps)
    }

    /// Serialize state to JSON
    pub fn to_json(&self) -> crate::error::Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| {
            crate::error::NonoError::ConfigParse(format!("Failed to serialize sandbox state: {e}"))
        })
    }

    /// Deserialize state from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_blocking_roundtrip() -> crate::error::Result<()> {
        for caps in [
            CapabilitySet::new(),
            CapabilitySet::new().block_network(),
            CapabilitySet::new().proxy_only(8080),
        ] {
            for block_dns in [false, true] {
                let caps = if block_dns {
                    caps.clone().block_dns()
                } else {
                    caps.clone()
                };
                let json = SandboxState::from_caps(&caps).to_json()?;
                let restored = SandboxState::from_json(&json)
                    .map_err(|e| crate::error::NonoError::ConfigParse(e.to_string()))?
                    .to_caps()?;
                assert_eq!(restored.dns_enabled(), caps.dns_enabled());
            }
        }
        Ok(())
    }

    #[test]
    fn test_legacy_state_keeps_dns_enabled() -> crate::error::Result<()> {
        for net_blocked in [false, true] {
            let json = format!(r#"{{ "fs": [], "net_blocked": {net_blocked} }}"#);
            let restored = SandboxState::from_json(&json)
                .map_err(|e| crate::error::NonoError::ConfigParse(e.to_string()))?
                .to_caps()?;
            assert!(restored.dns_enabled());
            assert_eq!(restored.is_network_blocked(), net_blocked);
        }
        Ok(())
    }

    #[test]
    fn test_state_roundtrip() {
        let caps = CapabilitySet::new().block_network();
        let state = SandboxState::from_caps(&caps);

        assert!(state.net_blocked);
        assert!(state.fs.is_empty());

        let json = state.to_json().expect("serialize state");
        let restored = SandboxState::from_json(&json).expect("deserialize state");
        assert!(restored.net_blocked);
    }

    #[test]
    fn test_resource_limits_roundtrip() {
        use crate::resource::ResourceLimits;

        let caps = CapabilitySet::new().with_resource_limits(ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024),
            max_processes: None,
        });
        let state = SandboxState::from_caps(&caps);
        assert_eq!(
            state.resource_limits.and_then(|l| l.memory_bytes),
            Some(512 * 1024 * 1024)
        );

        let json = state.to_json().expect("serialize state");
        let restored = SandboxState::from_json(&json).expect("deserialize state");
        let limits = restored.resource_limits.expect("limits survive roundtrip");
        assert_eq!(limits.memory_bytes, Some(512 * 1024 * 1024));

        // And back into a CapabilitySet.
        let caps2 = restored.to_caps().expect("to_caps");
        assert_eq!(caps2.resource_limits(), caps.resource_limits());
    }

    #[test]
    fn test_resource_limits_absent_in_legacy_state() {
        // A state JSON written before resource limits existed must still load.
        let json = r#"{ "fs": [], "net_blocked": false }"#;
        let state = SandboxState::from_json(json).expect("legacy state");
        assert!(state.resource_limits.is_none());
    }

    // ---- On-disk shape & backward-compat ----

    #[test]
    fn state_without_limits_omits_resource_limits_key() {
        let caps = CapabilitySet::new().block_network();
        let state = SandboxState::from_caps(&caps);
        assert!(state.resource_limits.is_none());

        // skip_serializing_if on the field: no limits => the key is absent in JSON,
        // which is exactly what a legacy reader expects to NOT find.
        let json = state.to_json().expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().expect("object");
        assert!(
            !obj.contains_key("resource_limits"),
            "with no limits the resource_limits key must be omitted, got {obj:?}"
        );
    }

    #[test]
    fn state_with_limits_serializes_inner_value() {
        use crate::resource::ResourceLimits;

        let caps = CapabilitySet::new()
            .block_network()
            .with_resource_limits(ResourceLimits {
                memory_bytes: Some(256 * 1024 * 1024),
                max_processes: None,
            });
        let state = SandboxState::from_caps(&caps);

        // The serialized state must nest memory_bytes at resource_limits.memory_bytes
        // (the roundtrip test checks the value survives; this pins the JSON shape).
        let json = state.to_json().expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let inner = v
            .get("resource_limits")
            .and_then(|r| r.get("memory_bytes"))
            .and_then(serde_json::Value::as_u64);
        assert_eq!(inner, Some(256 * 1024 * 1024));
    }

    #[test]
    fn legacy_state_defaults_resource_limits_and_unix_sockets() {
        // An older state JSON (predating these fields) has neither
        // resource_limits nor unix_sockets.
        // #[serde(default)] on both must fill them in (None / empty) without error
        // — the backward-compat guarantee for on-disk states from older builds.
        let json = r#"{ "fs": [], "net_blocked": true }"#;
        let state = SandboxState::from_json(json).expect("legacy state loads");
        assert!(state.resource_limits.is_none(), "absent field -> None");
        assert!(state.unix_sockets.is_empty(), "absent field -> empty vec");
        assert!(state.net_blocked);

        // Explicit null is equivalent to absent for the Option field.
        let json_null = r#"{ "fs": [], "net_blocked": false, "resource_limits": null }"#;
        let state_null = SandboxState::from_json(json_null).expect("null limits load");
        assert!(state_null.resource_limits.is_none());
    }

    #[test]
    fn test_to_caps_rejects_nonexistent_path() {
        let json = r#"{
            "fs": [{
                "original": "/nonexistent/crafted/path",
                "resolved": "/nonexistent/crafted/path",
                "access": "read+write",
                "is_file": false
            }],
            "net_blocked": false
        }"#;
        let state = SandboxState::from_json(json).unwrap();
        assert!(
            state.to_caps().is_err(),
            "to_caps must reject nonexistent paths"
        );
    }

    #[test]
    fn test_to_caps_rejects_invalid_access_mode() {
        let json = r#"{
            "fs": [{
                "original": "/tmp",
                "resolved": "/tmp",
                "access": "root-access",
                "is_file": false
            }],
            "net_blocked": false
        }"#;
        let state = SandboxState::from_json(json).unwrap();
        assert!(
            state.to_caps().is_err(),
            "to_caps must reject invalid access modes"
        );
    }

    #[test]
    fn test_unix_socket_state_roundtrip_preserves_original_and_resolved() {
        use tempfile::tempdir;
        let dir = tempdir().expect("tempdir");
        let sock = dir.path().join("a.sock");
        std::os::unix::net::UnixListener::bind(&sock).expect("create socket");

        let caps = CapabilitySet::new()
            .allow_unix_socket(&sock, UnixSocketMode::Connect)
            .expect("grant");
        let state = SandboxState::from_caps(&caps);
        let restored = state.to_caps().expect("to_caps");

        let round = restored.unix_socket_capabilities();
        assert_eq!(round.len(), 1);
        let before = &caps.unix_socket_capabilities()[0];
        let after = &round[0];
        assert_eq!(after.resolved, before.resolved);
        assert_eq!(after.original, before.original);
        assert_eq!(after.mode, before.mode);
        assert_eq!(after.scope, before.scope);
    }

    #[test]
    fn test_unix_socket_state_legacy_is_directory_maps_to_dir_children() {
        use tempfile::tempdir;
        let dir = tempdir().expect("tempdir");
        let json = format!(
            r#"{{
            "fs": [],
            "unix_sockets": [{{
                "original": "{}",
                "resolved": "{}",
                "is_directory": true,
                "mode": "connect"
            }}],
            "net_blocked": false
        }}"#,
            dir.path().display(),
            dir.path().canonicalize().expect("canonicalize").display()
        );
        let state = SandboxState::from_json(&json).expect("state json");
        let caps = state.to_caps().expect("to_caps");
        let sockets = caps.unix_socket_capabilities();
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].scope, SocketScope::DirChildren);
    }

    #[test]
    fn test_unix_socket_state_rejects_invalid_mode() {
        let json = r#"{
            "fs": [],
            "unix_sockets": [{
                "original": "/tmp",
                "resolved": "/tmp",
                "is_directory": true,
                "mode": "bind-only"
            }],
            "net_blocked": false
        }"#;
        let state = SandboxState::from_json(json).unwrap();
        assert!(
            state.to_caps().is_err(),
            "to_caps must reject unknown unix socket modes"
        );
    }

    #[test]
    fn test_network_mode_proxy_only_roundtrip() -> crate::error::Result<()> {
        let caps = CapabilitySet::new().proxy_only(8080);
        let state = SandboxState::from_caps(&caps);
        assert_eq!(
            state.network_mode,
            Some(crate::capability::NetworkMode::ProxyOnly {
                port: 8080,
                bind_ports: Vec::new()
            })
        );
        // net_blocked stays true for backward compat
        assert!(state.net_blocked);
        let json = state.to_json()?;
        let restored = SandboxState::from_json(&json)
            .map_err(|e| crate::error::NonoError::ConfigParse(e.to_string()))?
            .to_caps()?;
        assert_eq!(restored.network_mode(), caps.network_mode());
        assert_eq!(restored.is_network_blocked(), caps.is_network_blocked());
        Ok(())
    }

    #[test]
    fn test_network_mode_proxy_only_with_bind_ports_roundtrip() -> crate::error::Result<()> {
        let caps = CapabilitySet::new().proxy_only_with_bind(9090, vec![3000, 3001]);
        let state = SandboxState::from_caps(&caps);
        let json = state.to_json()?;
        let restored = SandboxState::from_json(&json)
            .map_err(|e| crate::error::NonoError::ConfigParse(e.to_string()))?
            .to_caps()?;
        assert_eq!(restored.network_mode(), caps.network_mode());
        Ok(())
    }

    #[test]
    fn test_network_mode_blocked_and_allow_all_roundtrip() -> crate::error::Result<()> {
        for caps in [CapabilitySet::new().block_network(), CapabilitySet::new()] {
            let state = SandboxState::from_caps(&caps);
            let json = state.to_json()?;
            let restored = SandboxState::from_json(&json)
                .map_err(|e| crate::error::NonoError::ConfigParse(e.to_string()))?
                .to_caps()?;
            assert_eq!(restored.network_mode(), caps.network_mode());
        }
        Ok(())
    }

    #[test]
    fn test_legacy_proxy_only_collapse_fixed() -> crate::error::Result<()> {
        // Legacy JSON has net_blocked=true but no network_mode (old writer).
        // It must still deserialize and fallback to Blocked (not ProxyOnly),
        // but new writer must not collapse ProxyOnly to Blocked.
        let legacy_json = r#"{ "fs": [], "net_blocked": true }"#;
        let legacy = SandboxState::from_json(legacy_json)
            .map_err(|e| crate::error::NonoError::ConfigParse(e.to_string()))?
            .to_caps()?;
        // Legacy with only net_blocked=true becomes Blocked (cannot infer ProxyOnly)
        assert_eq!(
            legacy.network_mode(),
            &crate::capability::NetworkMode::Blocked
        );

        // New writer preserves ProxyOnly distinctly
        let caps = CapabilitySet::new().proxy_only(7070);
        let state = SandboxState::from_caps(&caps);
        let json = state.to_json()?;
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            v.get("network_mode").is_some(),
            "new state must include network_mode"
        );
        let restored = SandboxState::from_json(&json)
            .map_err(|e| crate::error::NonoError::ConfigParse(e.to_string()))?
            .to_caps()?;
        assert_eq!(
            restored.network_mode(),
            &crate::capability::NetworkMode::ProxyOnly {
                port: 7070,
                bind_ports: vec![]
            }
        );
        Ok(())
    }

    #[test]
    fn test_localhost_and_tcp_ports_roundtrip() -> crate::error::Result<()> {
        let caps = CapabilitySet::new()
            .allow_localhost_port(3000)
            .allow_localhost_port(3001)
            .allow_tcp_connect(443)
            .allow_tcp_bind(8080);
        let caps = caps.allow_localhost_port_range(4000, 4005).expect("range");
        let state = SandboxState::from_caps(&caps);
        assert_eq!(state.localhost_ports, vec![3000, 3001]);
        assert_eq!(state.tcp_connect_ports, vec![443]);
        assert_eq!(state.tcp_bind_ports, vec![8080]);
        assert_eq!(state.localhost_port_ranges, vec![(4000, 4005)]);
        let json = state.to_json()?;
        let restored = SandboxState::from_json(&json)
            .map_err(|e| crate::error::NonoError::ConfigParse(e.to_string()))?
            .to_caps()?;
        assert_eq!(restored.localhost_ports(), caps.localhost_ports());
        assert_eq!(restored.tcp_connect_ports(), caps.tcp_connect_ports());
        assert_eq!(restored.tcp_bind_ports(), caps.tcp_bind_ports());
        assert_eq!(
            restored.localhost_port_ranges(),
            caps.localhost_port_ranges()
        );
        Ok(())
    }

    #[test]
    fn test_signal_and_ipc_modes_roundtrip() -> crate::error::Result<()> {
        let caps = CapabilitySet::new()
            .set_signal_mode(crate::capability::SignalMode::AllowAll)
            .set_process_info_mode(crate::capability::ProcessInfoMode::AllowAll)
            .set_ipc_mode(crate::capability::IpcMode::Full);
        let state = SandboxState::from_caps(&caps);
        let json = state.to_json()?;
        let restored = SandboxState::from_json(&json)
            .map_err(|e| crate::error::NonoError::ConfigParse(e.to_string()))?
            .to_caps()?;
        assert_eq!(restored.signal_mode(), caps.signal_mode());
        assert_eq!(restored.process_info_mode(), caps.process_info_mode());
        assert_eq!(restored.ipc_mode(), caps.ipc_mode());
        Ok(())
    }

    #[test]
    fn test_commands_and_platform_rules_roundtrip() -> crate::error::Result<()> {
        let caps = CapabilitySet::new()
            .allow_command("cargo")
            .block_command("curl")
            .platform_rule("(allow file-read* (subpath \"/tmp\"))".to_string())
            .expect("platform rule");
        // need to set enable_extensions
        let caps = caps.enable_extensions();
        let mut caps = caps;
        caps.set_seatbelt_debug_deny(true);
        let state = SandboxState::from_caps(&caps);
        assert_eq!(state.allowed_commands, vec!["cargo"]);
        assert_eq!(state.blocked_commands, vec!["curl"]);
        assert_eq!(
            state.platform_rules,
            vec!["(allow file-read* (subpath \"/tmp\"))"]
        );
        assert!(state.extensions_enabled);
        assert!(state.seatbelt_debug_deny);
        let json = state.to_json()?;
        let restored = SandboxState::from_json(&json)
            .map_err(|e| crate::error::NonoError::ConfigParse(e.to_string()))?
            .to_caps()?;
        assert_eq!(restored.allowed_commands(), caps.allowed_commands());
        assert_eq!(restored.blocked_commands(), caps.blocked_commands());
        assert_eq!(restored.platform_rules(), caps.platform_rules());
        assert_eq!(restored.extensions_enabled(), caps.extensions_enabled());
        assert_eq!(restored.seatbelt_debug_deny(), caps.seatbelt_debug_deny());
        Ok(())
    }

    #[test]
    fn test_legacy_state_without_new_fields_still_loads() -> crate::error::Result<()> {
        let json = r#"{ "fs": [], "net_blocked": false }"#;
        let state = SandboxState::from_json(json)
            .map_err(|e| crate::error::NonoError::ConfigParse(e.to_string()))?;
        assert!(state.network_mode.is_none());
        assert!(state.tcp_connect_ports.is_empty());
        assert!(state.localhost_ports.is_empty());
        assert_eq!(state.signal_mode, crate::capability::SignalMode::Isolated);
        let caps = state.to_caps()?;
        assert_eq!(
            caps.network_mode(),
            &crate::capability::NetworkMode::AllowAll
        );
        Ok(())
    }

    #[test]
    fn test_new_state_omits_default_fields_for_backward_compat() -> crate::error::Result<()> {
        let caps = CapabilitySet::new();
        let state = SandboxState::from_caps(&caps);
        let json = state.to_json()?;
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();
        // Empty vec fields and default enums/bools must be omitted
        assert!(
            !obj.contains_key("tcp_connect_ports"),
            "empty tcp_connect_ports should be omitted"
        );
        assert!(
            !obj.contains_key("localhost_ports"),
            "empty localhost_ports should be omitted"
        );
        assert!(
            !obj.contains_key("platform_rules"),
            "empty platform_rules should be omitted"
        );
        assert!(
            !obj.contains_key("allowed_commands"),
            "empty allowed_commands should be omitted"
        );
        // network_mode is Some(AllowAll) -> should be present (since it's precise)
        assert!(
            obj.contains_key("network_mode"),
            "AllowAll should be serialized explicitly"
        );
        Ok(())
    }
}
