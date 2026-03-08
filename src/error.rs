use thiserror::Error;

#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(String),

    #[error("sandbox dependency not available: {0}")]
    DependencyMissing(String),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("invalid domain pattern: {pattern}. {reason}")]
    InvalidDomainPattern { pattern: String, reason: String },

    #[error("shell not found: {0}")]
    ShellNotFound(String),

    #[error("sandbox initialization failed: {0}")]
    InitializationFailed(String),

    #[error("network bridge failed: {0}")]
    NetworkBridgeFailed(String),

    #[error("proxy server error: {0}")]
    ProxyError(String),

    #[error("seccomp filter error: {0}")]
    SeccompError(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, SandboxError>;
