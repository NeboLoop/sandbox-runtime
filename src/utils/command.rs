use base64::{engine::general_purpose::STANDARD, Engine};
use std::path::PathBuf;

use crate::platform::get_platform;
use crate::platform::Platform;

/// Encode a command for sandbox monitoring.
/// Truncates to 100 chars and base64 encodes.
pub fn encode_sandboxed_command(command: &str) -> String {
    let truncated = if command.len() > 100 {
        &command[..100]
    } else {
        command
    };
    STANDARD.encode(truncated.as_bytes())
}

/// Decode a base64-encoded command from sandbox monitoring.
pub fn decode_sandboxed_command(encoded: &str) -> Option<String> {
    STANDARD
        .decode(encoded)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

/// Get recommended system paths that should be writable for commands to work properly.
pub fn get_default_write_paths() -> Vec<String> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"));

    vec![
        "/dev/stdout".to_string(),
        "/dev/stderr".to_string(),
        "/dev/null".to_string(),
        "/dev/tty".to_string(),
        "/dev/dtracehelper".to_string(),
        "/dev/autofs_nowait".to_string(),
        "/tmp/nebo".to_string(),
        "/private/tmp/nebo".to_string(),
        home.join(".npm/_logs").to_string_lossy().to_string(),
        home.join(".nebo/debug").to_string_lossy().to_string(),
    ]
}

/// Generate proxy environment variables for sandboxed processes.
pub fn generate_proxy_env_vars(
    http_proxy_port: Option<u16>,
    socks_proxy_port: Option<u16>,
) -> Vec<String> {
    let tmpdir = std::env::var("NEBO_TMPDIR").unwrap_or_else(|_| "/tmp/nebo".to_string());
    let mut env_vars = vec![
        "SANDBOX_RUNTIME=1".to_string(),
        format!("TMPDIR={tmpdir}"),
    ];

    if http_proxy_port.is_none() && socks_proxy_port.is_none() {
        return env_vars;
    }

    // NO_PROXY addresses
    let no_proxy = [
        "localhost",
        "127.0.0.1",
        "::1",
        "*.local",
        ".local",
        "169.254.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ]
    .join(",");

    env_vars.push(format!("NO_PROXY={no_proxy}"));
    env_vars.push(format!("no_proxy={no_proxy}"));

    if let Some(port) = http_proxy_port {
        env_vars.push(format!("HTTP_PROXY=http://localhost:{port}"));
        env_vars.push(format!("HTTPS_PROXY=http://localhost:{port}"));
        env_vars.push(format!("http_proxy=http://localhost:{port}"));
        env_vars.push(format!("https_proxy=http://localhost:{port}"));
    }

    if let Some(socks_port) = socks_proxy_port {
        env_vars.push(format!("ALL_PROXY=socks5h://localhost:{socks_port}"));
        env_vars.push(format!("all_proxy=socks5h://localhost:{socks_port}"));

        // Git SSH through SOCKS proxy (macOS only)
        if get_platform() == Platform::MacOS {
            env_vars.push(format!(
                "GIT_SSH_COMMAND=ssh -o ProxyCommand='nc -X 5 -x localhost:{socks_port} %h %p'"
            ));
        }

        env_vars.push(format!("FTP_PROXY=socks5h://localhost:{socks_port}"));
        env_vars.push(format!("ftp_proxy=socks5h://localhost:{socks_port}"));
        env_vars.push(format!("RSYNC_PROXY=localhost:{socks_port}"));

        let docker_port = http_proxy_port.unwrap_or(socks_port);
        env_vars.push(format!("DOCKER_HTTP_PROXY=http://localhost:{docker_port}"));
        env_vars.push(format!("DOCKER_HTTPS_PROXY=http://localhost:{docker_port}"));

        if let Some(http_port) = http_proxy_port {
            env_vars.push("CLOUDSDK_PROXY_TYPE=https".to_string());
            env_vars.push("CLOUDSDK_PROXY_ADDRESS=localhost".to_string());
            env_vars.push(format!("CLOUDSDK_PROXY_PORT={http_port}"));
        }

        env_vars.push(format!("GRPC_PROXY=socks5h://localhost:{socks_port}"));
        env_vars.push(format!("grpc_proxy=socks5h://localhost:{socks_port}"));
    }

    env_vars
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_command() {
        let cmd = "echo hello";
        let encoded = encode_sandboxed_command(cmd);
        let decoded = decode_sandboxed_command(&encoded).unwrap();
        assert_eq!(decoded, cmd);
    }

    #[test]
    fn test_encode_truncates() {
        let long_cmd = "x".repeat(200);
        let encoded = encode_sandboxed_command(&long_cmd);
        let decoded = decode_sandboxed_command(&encoded).unwrap();
        assert_eq!(decoded.len(), 100);
    }

    #[test]
    fn test_proxy_env_vars_no_ports() {
        let vars = generate_proxy_env_vars(None, None);
        assert!(vars.iter().any(|v| v.starts_with("SANDBOX_RUNTIME=")));
        assert!(!vars.iter().any(|v| v.starts_with("HTTP_PROXY=")));
    }

    #[test]
    fn test_proxy_env_vars_with_ports() {
        let vars = generate_proxy_env_vars(Some(8080), Some(1080));
        assert!(vars.iter().any(|v| v == "HTTP_PROXY=http://localhost:8080"));
        assert!(vars.iter().any(|v| v == "ALL_PROXY=socks5h://localhost:1080"));
    }
}
