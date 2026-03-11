use sandbox_runtime::{SandboxManager, SandboxRuntimeConfig, SandboxViolationEvent};

#[test]
fn test_sandbox_manager_new_defaults() {
    let manager = SandboxManager::new();
    assert!(manager.get_config().is_none());
    assert!(!manager.is_sandboxing_enabled());
    assert!(manager.get_proxy_port().is_none());
    assert!(manager.get_socks_proxy_port().is_none());
}

#[test]
fn test_sandbox_manager_default_trait() {
    let manager = SandboxManager::default();
    assert!(manager.get_config().is_none());
}

#[test]
fn test_update_config() {
    let mut manager = SandboxManager::new();
    let config = SandboxRuntimeConfig::default_config();
    manager.update_config(config);
    assert!(manager.get_config().is_some());
    assert!(manager.is_sandboxing_enabled());
}

#[test]
fn test_get_config_after_update() {
    let mut manager = SandboxManager::new();
    let mut config = SandboxRuntimeConfig::default_config();
    config.network.allowed_domains = vec!["example.com".to_string()];
    manager.update_config(config);
    let retrieved = manager.get_config().unwrap();
    assert_eq!(retrieved.network.allowed_domains, vec!["example.com"]);
}

#[test]
fn test_get_fs_read_config_no_config() {
    let manager = SandboxManager::new();
    let config = manager.get_fs_read_config();
    assert!(config.deny_only.is_empty());
}

#[test]
fn test_get_fs_read_config_with_config() {
    let mut manager = SandboxManager::new();
    let mut config = SandboxRuntimeConfig::default_config();
    config.filesystem.deny_read = vec!["/secret".to_string()];
    manager.update_config(config);
    let read_config = manager.get_fs_read_config();
    assert_eq!(read_config.deny_only, vec!["/secret"]);
}

#[test]
fn test_get_fs_write_config_no_config() {
    let manager = SandboxManager::new();
    let config = manager.get_fs_write_config();
    // Should include default write paths
    assert!(!config.allow_only.is_empty());
    assert!(config.deny_within_allow.is_empty());
}

#[test]
fn test_get_fs_write_config_with_config() {
    let mut manager = SandboxManager::new();
    let mut config = SandboxRuntimeConfig::default_config();
    config.filesystem.allow_write = vec!["/custom/path".to_string()];
    config.filesystem.deny_write = vec!["/custom/path/secret".to_string()];
    manager.update_config(config);
    let write_config = manager.get_fs_write_config();
    assert!(write_config.allow_only.contains(&"/custom/path".to_string()));
    assert_eq!(
        write_config.deny_within_allow,
        vec!["/custom/path/secret"]
    );
}

#[test]
fn test_get_network_restriction_config_no_config() {
    let manager = SandboxManager::new();
    let config = manager.get_network_restriction_config();
    assert!(config.allowed_hosts.is_none());
    assert!(config.denied_hosts.is_none());
}

#[test]
fn test_get_network_restriction_config_with_config() {
    let mut manager = SandboxManager::new();
    let mut config = SandboxRuntimeConfig::default_config();
    config.network.allowed_domains = vec!["example.com".to_string()];
    config.network.denied_domains = vec!["evil.com".to_string()];
    manager.update_config(config);
    let net_config = manager.get_network_restriction_config();
    assert_eq!(
        net_config.allowed_hosts,
        Some(vec!["example.com".to_string()])
    );
    assert_eq!(
        net_config.denied_hosts,
        Some(vec!["evil.com".to_string()])
    );
}

#[test]
fn test_annotate_stderr_no_config() {
    let manager = SandboxManager::new();
    let result = manager.annotate_stderr_with_sandbox_failures("cmd", "error output");
    assert_eq!(result, "error output");
}

#[test]
fn test_annotate_stderr_no_violations() {
    let mut manager = SandboxManager::new();
    manager.update_config(SandboxRuntimeConfig::default_config());
    let result = manager.annotate_stderr_with_sandbox_failures("cmd", "error output");
    assert_eq!(result, "error output");
}

#[test]
fn test_annotate_stderr_with_violations() {
    let mut manager = SandboxManager::new();
    manager.update_config(SandboxRuntimeConfig::default_config());

    let cmd = "echo test";

    // Add violation with matching encoded_command
    // The manager uses encode_sandboxed_command internally, which base64-encodes truncated cmd
    let store = manager.violation_store();
    store.add_violation(SandboxViolationEvent {
        line: "deny file-write /protected".to_string(),
        command: Some(cmd.to_string()),
        // Use the same encoding the manager uses internally
        encoded_command: Some(sandbox_runtime::utils::command::encode_sandboxed_command(cmd)),
        timestamp: std::time::SystemTime::now(),
    });

    let result = manager.annotate_stderr_with_sandbox_failures(cmd, "error output");
    assert!(result.contains("error output"));
    assert!(result.contains("<sandbox_violations>"));
    assert!(result.contains("deny file-write /protected"));
}

#[test]
fn test_proxy_ports_before_init() {
    let manager = SandboxManager::new();
    assert!(manager.get_proxy_port().is_none());
    assert!(manager.get_socks_proxy_port().is_none());
}

#[test]
fn test_violation_store_access() {
    let manager = SandboxManager::new();
    let store = manager.violation_store();
    assert_eq!(store.get_count(), 0);
    store.add_violation(SandboxViolationEvent {
        line: "test".to_string(),
        command: None,
        encoded_command: None,
        timestamp: std::time::SystemTime::now(),
    });
    assert_eq!(store.get_count(), 1);
}
