use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::config::SandboxRuntimeConfig;
use crate::error::{Result, SandboxError};
use crate::platform::{get_platform, get_wsl_version, Platform};
use crate::proxy::filter::matches_domain_pattern;
use crate::schemas::{
    FsReadRestrictionConfig, FsWriteRestrictionConfig, NetworkHostPattern,
    NetworkRestrictionConfig, SandboxAskCallback,
};
use crate::sandbox::violation::SandboxViolationStore;
use crate::utils::command::get_default_write_paths;
use crate::utils::debug::log_for_debugging;
use crate::utils::glob::{contains_glob_chars, expand_glob_pattern};
use crate::utils::path::remove_trailing_glob_suffix;
use crate::utils::which::which_sync;

/// Async filter function type used by proxy servers.
type FilterFn = Arc<
    dyn Fn(u16, String) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync,
>;

/// Ask callback function signature (without Arc).
type AskCallbackFn =
    dyn Fn(NetworkHostPattern) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync;

/// Shared ask callback wrapped in Arc for use across proxy closures.
type SharedAskCallback = Arc<AskCallbackFn>;

/// The main sandbox manager that orchestrates network and filesystem restrictions.
pub struct SandboxManager {
    config: Option<SandboxRuntimeConfig>,
    http_proxy_port: Option<u16>,
    socks_proxy_port: Option<u16>,
    violation_store: SandboxViolationStore,
    initialized: bool,
    ask_callback: Option<SharedAskCallback>,

    #[cfg(target_os = "linux")]
    linux_bridge: Option<crate::sandbox::linux::LinuxNetworkBridgeContext>,

    #[cfg(target_os = "macos")]
    log_monitor: Option<std::process::Child>,

    http_proxy: Option<crate::proxy::http::HttpProxyServer>,
    socks_proxy: Option<crate::proxy::socks::SocksProxyServer>,
}

impl SandboxManager {
    pub fn new() -> Self {
        Self {
            config: None,
            http_proxy_port: None,
            socks_proxy_port: None,
            violation_store: SandboxViolationStore::new(),
            initialized: false,
            ask_callback: None,
            #[cfg(target_os = "linux")]
            linux_bridge: None,
            #[cfg(target_os = "macos")]
            log_monitor: None,
            http_proxy: None,
            socks_proxy: None,
        }
    }

    /// Check if the current platform is supported.
    pub fn is_supported_platform(&self) -> bool {
        let platform = get_platform();
        if platform == Platform::Linux {
            return get_wsl_version().as_deref() != Some("1");
        }
        platform == Platform::MacOS
    }

    /// Check if sandboxing has been initialized.
    pub fn is_sandboxing_enabled(&self) -> bool {
        self.config.is_some()
    }

    /// Check sandbox dependencies for the current platform.
    pub fn check_dependencies(&self) -> SandboxDependencyCheck {
        if !self.is_supported_platform() {
            return SandboxDependencyCheck {
                errors: vec!["Unsupported platform".to_string()],
                warnings: vec![],
            };
        }

        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Check ripgrep
        let rg_config = self
            .config
            .as_ref()
            .and_then(|c| c.ripgrep.as_ref())
            .cloned()
            .unwrap_or_default();
        if which_sync(&rg_config.command).is_none() {
            errors.push(format!("ripgrep ({}) not found", rg_config.command));
        }

        #[cfg(target_os = "linux")]
        {
            let seccomp = self.config.as_ref().and_then(|c| c.seccomp.clone());
            let linux_deps = crate::sandbox::linux::check_linux_dependencies(&seccomp);
            errors.extend(linux_deps.errors);
            warnings.extend(linux_deps.warnings);
        }

        SandboxDependencyCheck { errors, warnings }
    }

    /// Initialize the sandbox with the given configuration.
    pub async fn initialize(
        &mut self,
        config: SandboxRuntimeConfig,
        ask_callback: Option<SandboxAskCallback>,
        enable_log_monitor: bool,
    ) -> Result<()> {
        if self.initialized {
            return Ok(());
        }

        self.config = Some(config.clone());

        // Store ask callback for use in proxy filters
        let shared_ask: Option<SharedAskCallback> = ask_callback.map(|cb| {
            let cb: SharedAskCallback = Arc::from(cb);
            cb
        });
        self.ask_callback = shared_ask.clone();

        // Check dependencies
        let deps = self.check_dependencies();
        if !deps.errors.is_empty() {
            return Err(SandboxError::DependencyMissing(deps.errors.join(", ")));
        }

        // Start log monitor on macOS
        #[cfg(target_os = "macos")]
        if enable_log_monitor {
            self.log_monitor = crate::sandbox::macos::start_macos_sandbox_log_monitor(
                self.violation_store.clone(),
                config.ignore_violations.clone(),
            );
            log_for_debugging("Started macOS sandbox log monitor", None);
        }

        // Start proxy servers
        let config_ref = Arc::new(std::sync::Mutex::new(config.clone()));

        // Build a filter closure that includes the ask callback
        let make_filter = |config_ref: Arc<std::sync::Mutex<SandboxRuntimeConfig>>,
                           ask_cb: Option<SharedAskCallback>|
         -> FilterFn {
            Arc::new(move |port: u16, host: String| {
                let cfg = config_ref.clone();
                let ask = ask_cb.clone();
                Box::pin(async move {
                    let config = cfg.lock().unwrap().clone();
                    filter_network_request(&config, port, &host, ask.as_deref()).await
                }) as Pin<Box<dyn Future<Output = bool> + Send>>
            })
        };

        // HTTP proxy
        let http_proxy_port = if let Some(port) = config.network.http_proxy_port {
            log_for_debugging(&format!("Using external HTTP proxy on port {port}"), None);
            port
        } else {
            let filter = make_filter(config_ref.clone(), shared_ask.clone());

            let server =
                crate::proxy::http::start_http_proxy_server(filter, None).await?;
            let port = server.port();
            self.http_proxy = Some(server);
            port
        };

        // SOCKS proxy
        let socks_proxy_port = if let Some(port) = config.network.socks_proxy_port {
            log_for_debugging(&format!("Using external SOCKS proxy on port {port}"), None);
            port
        } else {
            let filter = make_filter(config_ref.clone(), shared_ask.clone());

            let server = crate::proxy::socks::start_socks_proxy_server(filter).await?;
            let port = server.port();
            self.socks_proxy = Some(server);
            port
        };

        self.http_proxy_port = Some(http_proxy_port);
        self.socks_proxy_port = Some(socks_proxy_port);

        // Initialize Linux network bridge
        #[cfg(target_os = "linux")]
        {
            self.linux_bridge = Some(
                crate::sandbox::linux::initialize_linux_network_bridge(
                    http_proxy_port,
                    socks_proxy_port,
                )?,
            );
        }

        self.initialized = true;
        log_for_debugging("Network infrastructure initialized", None);
        Ok(())
    }

    /// Wait for network initialization to complete.
    /// Returns true if initialized successfully, false otherwise.
    pub async fn wait_for_network_initialization(&self) -> bool {
        if self.config.is_none() {
            return false;
        }
        self.initialized
    }

    /// Wrap a command with sandbox restrictions.
    /// Optionally accepts a custom config override for per-command settings.
    pub async fn wrap_with_sandbox(
        &self,
        command: &str,
        bin_shell: Option<&str>,
    ) -> Result<String> {
        self.wrap_with_sandbox_opts(command, bin_shell, None).await
    }

    /// Wrap a command with sandbox restrictions, with optional per-command config override.
    pub async fn wrap_with_sandbox_opts(
        &self,
        command: &str,
        bin_shell: Option<&str>,
        custom_config: Option<&SandboxRuntimeConfig>,
    ) -> Result<String> {
        let platform = get_platform();
        let config = self.config.as_ref();

        // Build read config — use custom_config overrides when provided
        let raw_deny_read: Vec<String> = custom_config
            .map(|c| c.filesystem.deny_read.clone())
            .or_else(|| config.map(|c| c.filesystem.deny_read.clone()))
            .unwrap_or_default();

        let mut expanded_deny_read = Vec::new();
        for p in &raw_deny_read {
            let stripped = remove_trailing_glob_suffix(p);
            if platform == Platform::Linux && contains_glob_chars(&stripped) {
                expanded_deny_read.extend(expand_glob_pattern(p));
            } else {
                expanded_deny_read.push(stripped);
            }
        }
        let read_config = FsReadRestrictionConfig {
            deny_only: expanded_deny_read,
        };

        // Build write config
        let strip_write_globs = |paths: &[String]| -> Vec<String> {
            paths
                .iter()
                .map(|p| remove_trailing_glob_suffix(p))
                .filter(|p| {
                    !(platform == Platform::Linux && contains_glob_chars(p))
                })
                .collect()
        };

        let user_allow_write = strip_write_globs(
            &custom_config
                .map(|c| c.filesystem.allow_write.clone())
                .or_else(|| config.map(|c| c.filesystem.allow_write.clone()))
                .unwrap_or_default(),
        );
        let write_config = FsWriteRestrictionConfig {
            allow_only: [get_default_write_paths(), user_allow_write].concat(),
            deny_within_allow: strip_write_globs(
                &custom_config
                    .map(|c| c.filesystem.deny_write.clone())
                    .or_else(|| config.map(|c| c.filesystem.deny_write.clone()))
                    .unwrap_or_default(),
            ),
        };

        let has_network_config = custom_config
            .map(|c| !c.network.allowed_domains.is_empty() || !c.network.denied_domains.is_empty())
            .or_else(|| {
                config.map(|c| {
                    !c.network.allowed_domains.is_empty() || !c.network.denied_domains.is_empty()
                })
            })
            .unwrap_or(false)
            || config.is_some();

        let needs_network_restriction = has_network_config;

        match platform {
            #[cfg(target_os = "macos")]
            Platform::MacOS => {
                let params = crate::sandbox::macos::MacOSSandboxParams {
                    command: command.to_string(),
                    needs_network_restriction,
                    http_proxy_port: if needs_network_restriction {
                        self.http_proxy_port
                    } else {
                        None
                    },
                    socks_proxy_port: if needs_network_restriction {
                        self.socks_proxy_port
                    } else {
                        None
                    },
                    allow_unix_sockets: config.and_then(|c| c.network.allow_unix_sockets.clone()),
                    allow_all_unix_sockets: config
                        .and_then(|c| c.network.allow_all_unix_sockets),
                    allow_local_binding: config.and_then(|c| c.network.allow_local_binding),
                    read_config: Some(read_config),
                    write_config: Some(write_config),
                    ignore_violations: config.and_then(|c| c.ignore_violations.clone()),
                    allow_pty: custom_config
                        .and_then(|c| c.allow_pty)
                        .or_else(|| config.and_then(|c| c.allow_pty)),
                    allow_git_config: config
                        .and_then(|c| c.filesystem.allow_git_config)
                        .unwrap_or(false),
                    enable_weaker_network_isolation: config
                        .and_then(|c| c.enable_weaker_network_isolation)
                        .unwrap_or(false),
                    bin_shell: bin_shell.map(String::from),
                };
                crate::sandbox::macos::wrap_command_with_sandbox_macos(params)
            }

            #[cfg(target_os = "linux")]
            Platform::Linux => {
                let params = crate::sandbox::linux::LinuxSandboxParams {
                    command: command.to_string(),
                    needs_network_restriction,
                    http_socket_path: self
                        .linux_bridge
                        .as_ref()
                        .map(|b| b.http_socket_path.clone()),
                    socks_socket_path: self
                        .linux_bridge
                        .as_ref()
                        .map(|b| b.socks_socket_path.clone()),
                    http_proxy_port: if needs_network_restriction {
                        self.http_proxy_port
                    } else {
                        None
                    },
                    socks_proxy_port: if needs_network_restriction {
                        self.socks_proxy_port
                    } else {
                        None
                    },
                    read_config: Some(read_config),
                    write_config: Some(write_config),
                    enable_weaker_nested_sandbox: config
                        .and_then(|c| c.enable_weaker_nested_sandbox),
                    allow_all_unix_sockets: config
                        .and_then(|c| c.network.allow_all_unix_sockets),
                    bin_shell: bin_shell.map(String::from),
                    ripgrep_config: config
                        .and_then(|c| c.ripgrep.clone())
                        .unwrap_or_default(),
                    mandatory_deny_search_depth: config
                        .and_then(|c| c.mandatory_deny_search_depth)
                        .unwrap_or(3),
                    allow_git_config: config
                        .and_then(|c| c.filesystem.allow_git_config)
                        .unwrap_or(false),
                    seccomp_config: config.and_then(|c| c.seccomp.clone()),
                };
                crate::sandbox::linux::wrap_command_with_sandbox_linux(params)
            }

            _ => Err(SandboxError::UnsupportedPlatform(platform.to_string())),
        }
    }

    /// Get the current configuration.
    pub fn get_config(&self) -> Option<&SandboxRuntimeConfig> {
        self.config.as_ref()
    }

    /// Update the configuration.
    pub fn update_config(&mut self, config: SandboxRuntimeConfig) {
        self.config = Some(config);
        log_for_debugging("Sandbox configuration updated", None);
    }

    /// Get the filesystem read restriction config.
    pub fn get_fs_read_config(&self) -> FsReadRestrictionConfig {
        match &self.config {
            Some(c) => FsReadRestrictionConfig {
                deny_only: c.filesystem.deny_read.clone(),
            },
            None => FsReadRestrictionConfig::default(),
        }
    }

    /// Get the filesystem write restriction config.
    pub fn get_fs_write_config(&self) -> FsWriteRestrictionConfig {
        match &self.config {
            Some(c) => FsWriteRestrictionConfig {
                allow_only: [
                    get_default_write_paths(),
                    c.filesystem.allow_write.clone(),
                ]
                .concat(),
                deny_within_allow: c.filesystem.deny_write.clone(),
            },
            None => FsWriteRestrictionConfig {
                allow_only: get_default_write_paths(),
                deny_within_allow: vec![],
            },
        }
    }

    /// Get network restriction config.
    pub fn get_network_restriction_config(&self) -> NetworkRestrictionConfig {
        match &self.config {
            Some(c) => {
                let allowed = if c.network.allowed_domains.is_empty() {
                    None
                } else {
                    Some(c.network.allowed_domains.clone())
                };
                let denied = if c.network.denied_domains.is_empty() {
                    None
                } else {
                    Some(c.network.denied_domains.clone())
                };
                NetworkRestrictionConfig {
                    allowed_hosts: allowed,
                    denied_hosts: denied,
                }
            }
            None => NetworkRestrictionConfig::default(),
        }
    }

    /// Get the HTTP proxy port.
    pub fn get_proxy_port(&self) -> Option<u16> {
        self.http_proxy_port
    }

    /// Get the SOCKS proxy port.
    pub fn get_socks_proxy_port(&self) -> Option<u16> {
        self.socks_proxy_port
    }

    /// Get the violation store.
    pub fn violation_store(&self) -> &SandboxViolationStore {
        &self.violation_store
    }

    /// Get allowed unix socket paths.
    pub fn get_allow_unix_sockets(&self) -> Option<&Vec<String>> {
        self.config
            .as_ref()
            .and_then(|c| c.network.allow_unix_sockets.as_ref())
    }

    /// Get whether all unix sockets are allowed.
    pub fn get_allow_all_unix_sockets(&self) -> Option<bool> {
        self.config
            .as_ref()
            .and_then(|c| c.network.allow_all_unix_sockets)
    }

    /// Get whether local binding is allowed.
    pub fn get_allow_local_binding(&self) -> Option<bool> {
        self.config
            .as_ref()
            .and_then(|c| c.network.allow_local_binding)
    }

    /// Get ignore violations config.
    pub fn get_ignore_violations(
        &self,
    ) -> Option<&std::collections::HashMap<String, Vec<String>>> {
        self.config
            .as_ref()
            .and_then(|c| c.ignore_violations.as_ref())
    }

    /// Get whether weaker nested sandbox is enabled.
    pub fn get_enable_weaker_nested_sandbox(&self) -> Option<bool> {
        self.config
            .as_ref()
            .and_then(|c| c.enable_weaker_nested_sandbox)
    }

    /// Get whether weaker network isolation is enabled.
    pub fn get_enable_weaker_network_isolation(&self) -> Option<bool> {
        self.config
            .as_ref()
            .and_then(|c| c.enable_weaker_network_isolation)
    }

    /// Get ripgrep configuration.
    pub fn get_ripgrep_config(&self) -> crate::config::RipgrepConfig {
        self.config
            .as_ref()
            .and_then(|c| c.ripgrep.clone())
            .unwrap_or_default()
    }

    /// Get mandatory deny search depth.
    pub fn get_mandatory_deny_search_depth(&self) -> u8 {
        self.config
            .as_ref()
            .and_then(|c| c.mandatory_deny_search_depth)
            .unwrap_or(3)
    }

    /// Get whether git config access is allowed.
    pub fn get_allow_git_config(&self) -> bool {
        self.config
            .as_ref()
            .and_then(|c| c.filesystem.allow_git_config)
            .unwrap_or(false)
    }

    /// Get seccomp configuration.
    pub fn get_seccomp_config(&self) -> Option<&crate::config::SeccompConfig> {
        self.config.as_ref().and_then(|c| c.seccomp.as_ref())
    }

    /// Get Linux HTTP socket path (if bridge is active).
    #[cfg(target_os = "linux")]
    pub fn get_linux_http_socket_path(&self) -> Option<&str> {
        self.linux_bridge
            .as_ref()
            .map(|b| b.http_socket_path.as_str())
    }

    /// Get Linux SOCKS socket path (if bridge is active).
    #[cfg(target_os = "linux")]
    pub fn get_linux_socks_socket_path(&self) -> Option<&str> {
        self.linux_bridge
            .as_ref()
            .map(|b| b.socks_socket_path.as_str())
    }

    /// Get glob patterns from write rules that are not fully supported on Linux.
    /// Returns empty vec on macOS or when sandboxing is disabled.
    pub fn get_linux_glob_pattern_warnings(&self) -> Vec<String> {
        if get_platform() != Platform::Linux {
            return vec![];
        }
        let config = match &self.config {
            Some(c) => c,
            None => return vec![],
        };

        let mut glob_patterns = Vec::new();
        let all_paths = config
            .filesystem
            .allow_write
            .iter()
            .chain(config.filesystem.deny_write.iter());

        for path in all_paths {
            let stripped = remove_trailing_glob_suffix(path);
            if contains_glob_chars(&stripped) {
                glob_patterns.push(path.clone());
            }
        }
        glob_patterns
    }

    /// Cleanup after a sandboxed command completes.
    /// On Linux, removes mount point files created by bwrap for non-existent deny paths.
    /// No-op on macOS.
    pub fn cleanup_after_command(&self) {
        #[cfg(target_os = "linux")]
        crate::sandbox::linux::cleanup_bwrap_mount_points();
    }

    /// Annotate stderr with sandbox violation info.
    pub fn annotate_stderr_with_sandbox_failures(
        &self,
        command: &str,
        stderr: &str,
    ) -> String {
        if self.config.is_none() {
            return stderr.to_string();
        }

        let violations = self.violation_store.get_violations_for_command(command);
        if violations.is_empty() {
            return stderr.to_string();
        }

        let mut annotated = stderr.to_string();
        annotated.push_str("\n<sandbox_violations>\n");
        for violation in &violations {
            annotated.push_str(&violation.line);
            annotated.push('\n');
        }
        annotated.push_str("</sandbox_violations>");
        annotated
    }

    /// Reset the sandbox manager, cleaning up resources.
    pub async fn reset(&mut self) -> Result<()> {
        // Clean up bwrap mount points
        self.cleanup_after_command();

        #[cfg(target_os = "macos")]
        if let Some(mut monitor) = self.log_monitor.take() {
            let _ = monitor.kill();
        }

        #[cfg(target_os = "linux")]
        if let Some(mut bridge) = self.linux_bridge.take() {
            let _ = bridge.http_bridge_process.kill();
            let _ = bridge.socks_bridge_process.kill();
            let _ = std::fs::remove_file(&bridge.http_socket_path);
            let _ = std::fs::remove_file(&bridge.socks_socket_path);
        }

        if let Some(server) = self.http_proxy.take() {
            server.shutdown();
        }
        if let Some(server) = self.socks_proxy.take() {
            server.shutdown();
        }

        self.http_proxy_port = None;
        self.socks_proxy_port = None;
        self.initialized = false;

        Ok(())
    }
}

impl Default for SandboxManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Dependency check result.
pub struct SandboxDependencyCheck {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Filter a network request against the config.
pub(crate) async fn filter_network_request(
    config: &SandboxRuntimeConfig,
    port: u16,
    host: &str,
    ask_callback: Option<&AskCallbackFn>,
) -> bool {
    // Check denied domains first
    for denied in &config.network.denied_domains {
        if matches_domain_pattern(host, denied) {
            log_for_debugging(&format!("Denied by config rule: {host}"), None);
            return false;
        }
    }

    // Check allowed domains
    for allowed in &config.network.allowed_domains {
        if matches_domain_pattern(host, allowed) {
            log_for_debugging(&format!("Allowed by config rule: {host}"), None);
            return true;
        }
    }

    // No matching rules — ask user or deny
    if let Some(callback) = ask_callback {
        log_for_debugging(
            &format!("No matching config rule, asking user: {host}:{port}"),
            None,
        );
        let pattern = NetworkHostPattern {
            host: host.to_string(),
            port: Some(port),
        };
        let user_allowed = callback(pattern).await;
        if user_allowed {
            log_for_debugging(&format!("User allowed: {host}:{port}"), None);
        } else {
            log_for_debugging(&format!("User denied: {host}:{port}"), None);
        }
        user_allowed
    } else {
        log_for_debugging(&format!("No matching config rule, denying: {host}"), None);
        false
    }
}
