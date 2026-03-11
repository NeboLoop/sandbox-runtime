use sandbox_runtime::SandboxRuntimeConfig;

#[test]
fn test_load_validate_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("config.json");
    std::fs::write(
        &file_path,
        r#"{
            "network": {
                "allowedDomains": ["example.com", "*.github.com"],
                "deniedDomains": ["evil.com"]
            },
            "filesystem": {
                "denyRead": ["/secret"],
                "allowWrite": ["/tmp/work"],
                "denyWrite": ["/tmp/work/protected"]
            },
            "mandatoryDenySearchDepth": 5
        }"#,
    )
    .unwrap();
    let config = SandboxRuntimeConfig::load_from_file(&file_path)
        .unwrap()
        .unwrap();
    assert_eq!(config.network.allowed_domains.len(), 2);
    assert_eq!(config.network.denied_domains.len(), 1);
    assert_eq!(config.filesystem.deny_read.len(), 1);
    assert_eq!(config.mandatory_deny_search_depth, Some(5));
}

#[test]
fn test_camel_case_field_names_in_file() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("config.json");
    std::fs::write(
        &file_path,
        r#"{
            "network": {
                "allowedDomains": [],
                "deniedDomains": [],
                "httpProxyPort": 9090,
                "socksProxyPort": 1080
            },
            "filesystem": {
                "denyRead": [],
                "allowWrite": [],
                "denyWrite": [],
                "allowGitConfig": true
            },
            "allowPty": true,
            "enableWeakerNestedSandbox": false,
            "enableWeakerNetworkIsolation": true
        }"#,
    )
    .unwrap();

    let config = SandboxRuntimeConfig::load_from_file(&file_path)
        .unwrap()
        .unwrap();
    assert_eq!(config.network.http_proxy_port, Some(9090));
    assert_eq!(config.network.socks_proxy_port, Some(1080));
    assert_eq!(config.filesystem.allow_git_config, Some(true));
    assert_eq!(config.allow_pty, Some(true));
    assert_eq!(config.enable_weaker_nested_sandbox, Some(false));
    assert_eq!(config.enable_weaker_network_isolation, Some(true));
}

#[test]
fn test_config_serialization_preserves_camel_case() {
    let config = SandboxRuntimeConfig::default_config();
    let json = serde_json::to_string_pretty(&config).unwrap();
    // Verify camelCase field names in output
    assert!(json.contains("allowedDomains"));
    assert!(json.contains("deniedDomains"));
    assert!(json.contains("denyRead"));
    assert!(json.contains("allowWrite"));
    assert!(json.contains("denyWrite"));
}

#[test]
fn test_validate_rejects_invalid_config() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("config.json");
    std::fs::write(
        &file_path,
        r#"{
            "network": {
                "allowedDomains": ["*.com"],
                "deniedDomains": []
            },
            "filesystem": {
                "denyRead": [],
                "allowWrite": [],
                "denyWrite": []
            }
        }"#,
    )
    .unwrap();

    let result = SandboxRuntimeConfig::load_from_file(&file_path);
    assert!(result.is_err());
}
