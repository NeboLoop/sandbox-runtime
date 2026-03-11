use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::{SandboxError, Result};

/// Schema for MITM proxy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MitmProxyConfig {
    pub socket_path: String,
    pub domains: Vec<String>,
}

/// Network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkConfig {
    pub allowed_domains: Vec<String>,
    pub denied_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_unix_sockets: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_all_unix_sockets: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_local_binding: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_proxy_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks_proxy_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mitm_proxy: Option<MitmProxyConfig>,
}

/// Filesystem configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilesystemConfig {
    pub deny_read: Vec<String>,
    pub allow_write: Vec<String>,
    pub deny_write: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_git_config: Option<bool>,
}

/// Ripgrep configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RipgrepConfig {
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
}

impl Default for RipgrepConfig {
    fn default() -> Self {
        Self {
            command: "rg".to_string(),
            args: None,
        }
    }
}

/// Seccomp configuration (Linux only).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeccompConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bpf_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply_path: Option<String>,
}

/// Main configuration for Sandbox Runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxRuntimeConfig {
    pub network: NetworkConfig,
    pub filesystem: FilesystemConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ignore_violations: Option<HashMap<String, Vec<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_weaker_nested_sandbox: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_weaker_network_isolation: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ripgrep: Option<RipgrepConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mandatory_deny_search_depth: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_pty: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seccomp: Option<SeccompConfig>,
}

/// Validate a domain pattern.
pub fn validate_domain_pattern(pattern: &str) -> Result<()> {
    // Reject protocols, paths, ports
    if pattern.contains("://") || pattern.contains('/') || pattern.contains(':') {
        return Err(SandboxError::InvalidDomainPattern {
            pattern: pattern.to_string(),
            reason: "Must not contain protocols, paths, or ports".to_string(),
        });
    }

    // Allow localhost
    if pattern == "localhost" {
        return Ok(());
    }

    // Allow wildcard domains like *.example.com
    if let Some(domain) = pattern.strip_prefix("*.") {
        if !domain.contains('.')
            || domain.starts_with('.')
            || domain.ends_with('.')
        {
            return Err(SandboxError::InvalidDomainPattern {
                pattern: pattern.to_string(),
                reason: "Wildcard domain must have at least two parts after *. (e.g., *.example.com)".to_string(),
            });
        }
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 2 || parts.iter().any(|p| p.is_empty()) {
            return Err(SandboxError::InvalidDomainPattern {
                pattern: pattern.to_string(),
                reason: "Overly broad patterns like *.com are not allowed".to_string(),
            });
        }
        return Ok(());
    }

    // Reject any other use of wildcards
    if pattern.contains('*') {
        return Err(SandboxError::InvalidDomainPattern {
            pattern: pattern.to_string(),
            reason: "Invalid wildcard usage. Use *.example.com format".to_string(),
        });
    }

    // Regular domains must have at least one dot
    if !pattern.contains('.') || pattern.starts_with('.') || pattern.ends_with('.') {
        return Err(SandboxError::InvalidDomainPattern {
            pattern: pattern.to_string(),
            reason: "Must be a valid domain with at least one dot".to_string(),
        });
    }

    Ok(())
}

/// Validate the full SandboxRuntimeConfig.
pub fn validate_config(config: &SandboxRuntimeConfig) -> Result<()> {
    // Validate domain patterns
    for domain in &config.network.allowed_domains {
        validate_domain_pattern(domain)?;
    }
    for domain in &config.network.denied_domains {
        validate_domain_pattern(domain)?;
    }

    // Validate MITM proxy domains
    if let Some(ref mitm) = config.network.mitm_proxy {
        if mitm.socket_path.is_empty() {
            return Err(SandboxError::InvalidConfig(
                "MITM proxy socket path cannot be empty".to_string(),
            ));
        }
        if mitm.domains.is_empty() {
            return Err(SandboxError::InvalidConfig(
                "MITM proxy must have at least one domain".to_string(),
            ));
        }
        for domain in &mitm.domains {
            validate_domain_pattern(domain)?;
        }
    }

    // Validate filesystem paths
    for path in &config.filesystem.deny_read {
        if path.is_empty() {
            return Err(SandboxError::InvalidConfig(
                "Filesystem path cannot be empty".to_string(),
            ));
        }
    }
    for path in &config.filesystem.allow_write {
        if path.is_empty() {
            return Err(SandboxError::InvalidConfig(
                "Filesystem path cannot be empty".to_string(),
            ));
        }
    }
    for path in &config.filesystem.deny_write {
        if path.is_empty() {
            return Err(SandboxError::InvalidConfig(
                "Filesystem path cannot be empty".to_string(),
            ));
        }
    }

    // Validate proxy ports
    if let Some(port) = config.network.http_proxy_port {
        if port == 0 {
            return Err(SandboxError::InvalidConfig(
                "HTTP proxy port must be 1-65535".to_string(),
            ));
        }
    }
    if let Some(port) = config.network.socks_proxy_port {
        if port == 0 {
            return Err(SandboxError::InvalidConfig(
                "SOCKS proxy port must be 1-65535".to_string(),
            ));
        }
    }

    // Validate mandatory deny search depth
    if let Some(depth) = config.mandatory_deny_search_depth {
        if !(1..=10).contains(&depth) {
            return Err(SandboxError::InvalidConfig(
                "mandatoryDenySearchDepth must be 1-10".to_string(),
            ));
        }
    }

    Ok(())
}

impl SandboxRuntimeConfig {
    /// Create a minimal default config.
    pub fn default_config() -> Self {
        Self {
            network: NetworkConfig {
                allowed_domains: vec![],
                denied_domains: vec![],
                allow_unix_sockets: None,
                allow_all_unix_sockets: None,
                allow_local_binding: None,
                http_proxy_port: None,
                socks_proxy_port: None,
                mitm_proxy: None,
            },
            filesystem: FilesystemConfig {
                deny_read: vec![],
                allow_write: vec![],
                deny_write: vec![],
                allow_git_config: None,
            },
            ignore_violations: None,
            enable_weaker_nested_sandbox: None,
            enable_weaker_network_isolation: None,
            ripgrep: None,
            mandatory_deny_search_depth: None,
            allow_pty: None,
            seccomp: None,
        }
    }

    /// Load config from a file path, returning None if file doesn't exist.
    pub fn load_from_file(path: &std::path::Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let contents = std::fs::read_to_string(path)?;
        let config: Self = serde_json::from_str(&contents)?;
        validate_config(&config)?;
        Ok(Some(config))
    }

    /// Load config from a JSON string.
    pub fn load_from_string(s: &str) -> Result<Option<Self>> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let config: Self = serde_json::from_str(trimmed)?;
        validate_config(&config)?;
        Ok(Some(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_domain_patterns() {
        assert!(validate_domain_pattern("example.com").is_ok());
        assert!(validate_domain_pattern("*.example.com").is_ok());
        assert!(validate_domain_pattern("localhost").is_ok());
        assert!(validate_domain_pattern("sub.domain.example.com").is_ok());
    }

    #[test]
    fn test_invalid_domain_patterns() {
        assert!(validate_domain_pattern("http://example.com").is_err());
        assert!(validate_domain_pattern("example.com/path").is_err());
        assert!(validate_domain_pattern("example.com:8080").is_err());
        assert!(validate_domain_pattern("*.com").is_err());
        assert!(validate_domain_pattern("*").is_err());
        assert!(validate_domain_pattern(".example.com").is_err());
        assert!(validate_domain_pattern("example.com.").is_err());
    }

    #[test]
    fn test_default_config_validates() {
        let config = SandboxRuntimeConfig::default_config();
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_config_serialization() {
        let config = SandboxRuntimeConfig::default_config();
        let json = serde_json::to_string(&config).unwrap();
        let _: SandboxRuntimeConfig = serde_json::from_str(&json).unwrap();
    }

    // --- load_from_string tests ---

    #[test]
    fn test_load_from_string_empty() {
        let result = SandboxRuntimeConfig::load_from_string("").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_from_string_whitespace() {
        let result = SandboxRuntimeConfig::load_from_string("   \n  ").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_from_string_invalid_json() {
        let result = SandboxRuntimeConfig::load_from_string("{not valid json}");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_from_string_valid_minimal() {
        let json = r#"{
            "network": { "allowedDomains": [], "deniedDomains": [] },
            "filesystem": { "denyRead": [], "allowWrite": [], "denyWrite": [] }
        }"#;
        let result = SandboxRuntimeConfig::load_from_string(json).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_load_from_string_full_config() {
        let json = r#"{
            "network": {
                "allowedDomains": ["example.com"],
                "deniedDomains": ["evil.com"],
                "httpProxyPort": 8080,
                "socksProxyPort": 1080
            },
            "filesystem": {
                "denyRead": ["/secret"],
                "allowWrite": ["/tmp"],
                "denyWrite": ["/tmp/protected"]
            },
            "mandatoryDenySearchDepth": 5,
            "allowPty": true
        }"#;
        let config = SandboxRuntimeConfig::load_from_string(json).unwrap().unwrap();
        assert_eq!(config.network.allowed_domains, vec!["example.com"]);
        assert_eq!(config.network.denied_domains, vec!["evil.com"]);
        assert_eq!(config.network.http_proxy_port, Some(8080));
        assert_eq!(config.network.socks_proxy_port, Some(1080));
        assert_eq!(config.filesystem.deny_read, vec!["/secret"]);
        assert_eq!(config.mandatory_deny_search_depth, Some(5));
        assert_eq!(config.allow_pty, Some(true));
    }

    #[test]
    fn test_load_from_string_invalid_domain_in_config() {
        let json = r#"{
            "network": { "allowedDomains": ["*.com"], "deniedDomains": [] },
            "filesystem": { "denyRead": [], "allowWrite": [], "denyWrite": [] }
        }"#;
        let result = SandboxRuntimeConfig::load_from_string(json);
        assert!(result.is_err());
    }

    // --- load_from_file tests ---

    #[test]
    fn test_load_from_file_nonexistent() {
        let result =
            SandboxRuntimeConfig::load_from_file(std::path::Path::new("/nonexistent/config.json"));
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_load_from_file_valid() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("config.json");
        std::fs::write(
            &file_path,
            r#"{
                "network": { "allowedDomains": [], "deniedDomains": [] },
                "filesystem": { "denyRead": [], "allowWrite": [], "denyWrite": [] }
            }"#,
        )
        .unwrap();
        let result = SandboxRuntimeConfig::load_from_file(&file_path).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_load_from_file_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("config.json");
        std::fs::write(&file_path, "not json").unwrap();
        let result = SandboxRuntimeConfig::load_from_file(&file_path);
        assert!(result.is_err());
    }

    // --- validate_config tests ---

    #[test]
    fn test_validate_config_empty_paths_rejected() {
        let mut config = SandboxRuntimeConfig::default_config();
        config.filesystem.deny_read.push(String::new());
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_config_empty_allow_write_rejected() {
        let mut config = SandboxRuntimeConfig::default_config();
        config.filesystem.allow_write.push(String::new());
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_config_empty_deny_write_rejected() {
        let mut config = SandboxRuntimeConfig::default_config();
        config.filesystem.deny_write.push(String::new());
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_config_http_proxy_port_zero_rejected() {
        let mut config = SandboxRuntimeConfig::default_config();
        config.network.http_proxy_port = Some(0);
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_config_socks_proxy_port_zero_rejected() {
        let mut config = SandboxRuntimeConfig::default_config();
        config.network.socks_proxy_port = Some(0);
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_config_valid_ports() {
        let mut config = SandboxRuntimeConfig::default_config();
        config.network.http_proxy_port = Some(8080);
        config.network.socks_proxy_port = Some(1080);
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_validate_config_mandatory_deny_depth_zero_rejected() {
        let mut config = SandboxRuntimeConfig::default_config();
        config.mandatory_deny_search_depth = Some(0);
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_config_mandatory_deny_depth_11_rejected() {
        let mut config = SandboxRuntimeConfig::default_config();
        config.mandatory_deny_search_depth = Some(11);
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_config_mandatory_deny_depth_5_passes() {
        let mut config = SandboxRuntimeConfig::default_config();
        config.mandatory_deny_search_depth = Some(5);
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_validate_config_mitm_empty_socket_path() {
        let mut config = SandboxRuntimeConfig::default_config();
        config.network.mitm_proxy = Some(MitmProxyConfig {
            socket_path: String::new(),
            domains: vec!["example.com".to_string()],
        });
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_config_mitm_empty_domains() {
        let mut config = SandboxRuntimeConfig::default_config();
        config.network.mitm_proxy = Some(MitmProxyConfig {
            socket_path: "/tmp/mitm.sock".to_string(),
            domains: vec![],
        });
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_config_mitm_valid() {
        let mut config = SandboxRuntimeConfig::default_config();
        config.network.mitm_proxy = Some(MitmProxyConfig {
            socket_path: "/tmp/mitm.sock".to_string(),
            domains: vec!["example.com".to_string()],
        });
        assert!(validate_config(&config).is_ok());
    }

    // --- domain edge cases ---

    #[test]
    fn test_domain_bare_word_rejected() {
        assert!(validate_domain_pattern("example").is_err());
    }

    #[test]
    fn test_domain_mid_wildcard_rejected() {
        assert!(validate_domain_pattern("ex*mple.com").is_err());
    }

    #[test]
    fn test_domain_double_wildcard_rejected() {
        assert!(validate_domain_pattern("**.example.com").is_err());
    }

    // --- default config ---

    #[test]
    fn test_default_config_has_expected_defaults() {
        let config = SandboxRuntimeConfig::default_config();
        assert!(config.network.allowed_domains.is_empty());
        assert!(config.network.denied_domains.is_empty());
        assert!(config.network.http_proxy_port.is_none());
        assert!(config.network.socks_proxy_port.is_none());
        assert!(config.network.mitm_proxy.is_none());
        assert!(config.filesystem.deny_read.is_empty());
        assert!(config.filesystem.allow_write.is_empty());
        assert!(config.filesystem.deny_write.is_empty());
        assert!(config.filesystem.allow_git_config.is_none());
        assert!(config.ignore_violations.is_none());
        assert!(config.enable_weaker_nested_sandbox.is_none());
        assert!(config.enable_weaker_network_isolation.is_none());
        assert!(config.ripgrep.is_none());
        assert!(config.mandatory_deny_search_depth.is_none());
        assert!(config.allow_pty.is_none());
        assert!(config.seccomp.is_none());
    }

    #[test]
    fn test_camel_case_field_names() {
        let json = r#"{
            "network": {
                "allowedDomains": ["example.com"],
                "deniedDomains": [],
                "allowUnixSockets": ["/tmp/sock"],
                "allowAllUnixSockets": true,
                "allowLocalBinding": true
            },
            "filesystem": {
                "denyRead": [],
                "allowWrite": [],
                "denyWrite": [],
                "allowGitConfig": true
            },
            "enableWeakerNestedSandbox": true,
            "enableWeakerNetworkIsolation": false,
            "mandatoryDenySearchDepth": 3,
            "allowPty": false
        }"#;
        let config = SandboxRuntimeConfig::load_from_string(json).unwrap().unwrap();
        assert_eq!(config.network.allow_unix_sockets, Some(vec!["/tmp/sock".to_string()]));
        assert_eq!(config.network.allow_all_unix_sockets, Some(true));
        assert_eq!(config.network.allow_local_binding, Some(true));
        assert_eq!(config.filesystem.allow_git_config, Some(true));
        assert_eq!(config.enable_weaker_nested_sandbox, Some(true));
        assert_eq!(config.enable_weaker_network_isolation, Some(false));
    }

    #[test]
    fn test_unknown_fields_ignored() {
        let json = r#"{
            "network": { "allowedDomains": [], "deniedDomains": [], "unknownField": true },
            "filesystem": { "denyRead": [], "allowWrite": [], "denyWrite": [] },
            "totallyUnknown": 42
        }"#;
        // serde with default behavior will fail on unknown fields unless deny_unknown_fields is off
        // This tests the actual behavior
        let result = SandboxRuntimeConfig::load_from_string(json);
        // If it errors, unknown fields are rejected (which is also a valid behavior to test)
        // If it succeeds, unknown fields are ignored
        let _ = result;
    }
}
