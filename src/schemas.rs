use std::future::Future;
use std::pin::Pin;

/// Read restriction config using a "deny-only" pattern.
///
/// - `None` = no restrictions (allow all reads)
/// - `Some(FsReadRestrictionConfig { deny_only: vec![] })` = no restrictions
/// - `Some(FsReadRestrictionConfig { deny_only: vec![...] })` = deny reads from these paths
#[derive(Debug, Clone, Default)]
pub struct FsReadRestrictionConfig {
    pub deny_only: Vec<String>,
}

/// Write restriction config using an "allow-only" pattern.
///
/// - `None` = no restrictions (allow all writes)
/// - `Some(FsWriteRestrictionConfig { allow_only: vec![], .. })` = deny ALL writes
/// - `Some(FsWriteRestrictionConfig { allow_only: vec![...], .. })` = allow writes only to these paths
#[derive(Debug, Clone, Default)]
pub struct FsWriteRestrictionConfig {
    pub allow_only: Vec<String>,
    pub deny_within_allow: Vec<String>,
}

/// Network restriction config using an "allow-only" pattern.
///
/// - `None` = maximally restrictive (deny all network)
/// - `Some(NetworkRestrictionConfig { allowed_hosts: Some(vec![]), .. })` = deny all
/// - `Some(NetworkRestrictionConfig { allowed_hosts: Some(vec![...]), .. })` = apply rules
#[derive(Debug, Clone, Default)]
pub struct NetworkRestrictionConfig {
    pub allowed_hosts: Option<Vec<String>>,
    pub denied_hosts: Option<Vec<String>>,
}

/// Host pattern for sandbox ask callbacks.
#[derive(Debug, Clone)]
pub struct NetworkHostPattern {
    pub host: String,
    pub port: Option<u16>,
}

/// Callback type for asking the user about network access.
pub type SandboxAskCallback = Box<
    dyn Fn(NetworkHostPattern) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync,
>;
