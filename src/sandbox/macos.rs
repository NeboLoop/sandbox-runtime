use std::collections::HashMap;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use crate::sandbox::dangerous::{get_dangerous_directories, DANGEROUS_FILES};
use crate::schemas::{FsReadRestrictionConfig, FsWriteRestrictionConfig};
use crate::utils::command::{
    decode_sandboxed_command, encode_sandboxed_command, generate_proxy_env_vars,
};
use crate::utils::debug::log_for_debugging;
use crate::utils::glob::{contains_glob_chars, glob_to_regex};
use crate::utils::path::{get_ancestor_directories, normalize_path_for_sandbox};
use crate::utils::shell::shell_quote_join;
use crate::utils::which::which_sync;

use crate::sandbox::violation::{SandboxViolationEvent, SandboxViolationStore};

/// Parameters for macOS sandbox wrapping.
pub struct MacOSSandboxParams {
    pub command: String,
    pub needs_network_restriction: bool,
    pub http_proxy_port: Option<u16>,
    pub socks_proxy_port: Option<u16>,
    pub allow_unix_sockets: Option<Vec<String>>,
    pub allow_all_unix_sockets: Option<bool>,
    pub allow_local_binding: Option<bool>,
    pub read_config: Option<FsReadRestrictionConfig>,
    pub write_config: Option<FsWriteRestrictionConfig>,
    pub ignore_violations: Option<HashMap<String, Vec<String>>>,
    pub allow_pty: Option<bool>,
    pub allow_git_config: bool,
    pub enable_weaker_network_isolation: bool,
    pub bin_shell: Option<String>,
}

/// Generate a unique session suffix for log monitoring.
fn session_suffix() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let random: String = (0..9)
        .map(|_| {
            let idx = rng.gen_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect();
    format!("_{random}_SBX")
}

thread_local! {
    static SESSION_SUFFIX: String = session_suffix();
}

/// Generate a unique log tag for sandbox monitoring.
fn generate_log_tag(command: &str) -> String {
    let encoded = encode_sandboxed_command(command);
    SESSION_SUFFIX.with(|suffix| format!("CMD64_{encoded}_END_{suffix}"))
}

/// Get mandatory deny patterns as glob patterns (macOS).
pub fn mac_get_mandatory_deny_patterns(allow_git_config: bool) -> Vec<String> {
    let cwd = std::env::current_dir().unwrap_or_default();
    let mut deny_paths = Vec::new();

    // Dangerous files — static paths in CWD + glob patterns for subtree
    for file_name in DANGEROUS_FILES {
        deny_paths.push(
            cwd.join(file_name)
                .to_string_lossy()
                .to_string(),
        );
        deny_paths.push(format!("**/{file_name}"));
    }

    // Dangerous directories
    for dir_name in get_dangerous_directories() {
        deny_paths.push(cwd.join(&dir_name).to_string_lossy().to_string());
        deny_paths.push(format!("**/{dir_name}/**"));
    }

    // Git hooks are always blocked
    deny_paths.push(cwd.join(".git/hooks").to_string_lossy().to_string());
    deny_paths.push("**/.git/hooks/**".to_string());

    // Git config conditionally blocked
    if !allow_git_config {
        deny_paths.push(cwd.join(".git/config").to_string_lossy().to_string());
        deny_paths.push("**/.git/config".to_string());
    }

    deny_paths.sort();
    deny_paths.dedup();
    deny_paths
}

/// Escape path for sandbox profile using JSON-style quoting.
fn escape_path(path_str: &str) -> String {
    serde_json::to_string(path_str).unwrap_or_else(|_| format!("\"{}\"", path_str))
}

/// Get TMPDIR parent if it matches macOS pattern /var/folders/XX/YYY/T/
fn get_tmpdir_parent_if_macos_pattern() -> Vec<String> {
    let tmpdir = match std::env::var("TMPDIR") {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    let re = regex::Regex::new(r"^/(private/)?var/folders/[^/]{2}/[^/]+/T/?$").unwrap();
    if !re.is_match(&tmpdir) {
        return vec![];
    }

    let parent = regex::Regex::new(r"/T/?$")
        .unwrap()
        .replace(&tmpdir, "")
        .to_string();

    if parent.starts_with("/private/var/") {
        vec![parent.clone(), parent.replace("/private", "")]
    } else if parent.starts_with("/var/") {
        vec![parent.clone(), format!("/private{parent}")]
    } else {
        vec![parent]
    }
}

/// Generate deny rules for file movement (file-write-unlink).
fn generate_move_blocking_rules(path_patterns: &[String], log_tag: &str) -> Vec<String> {
    let mut rules = Vec::new();

    for path_pattern in path_patterns {
        let normalized = normalize_path_for_sandbox(path_pattern);

        if contains_glob_chars(&normalized) {
            let regex_pattern = glob_to_regex(&normalized);
            rules.push("(deny file-write-unlink".to_string());
            rules.push(format!("  (regex {})", escape_path(&regex_pattern)));
            rules.push(format!("  (with message \"{log_tag}\"))"));

            // Block ancestor moves for static prefix
            let static_prefix: String = normalized
                .split(&['*', '?', '[', ']'][..])
                .next()
                .unwrap_or("")
                .to_string();

            if !static_prefix.is_empty() && static_prefix != "/" {
                let base_dir = if static_prefix.ends_with('/') {
                    &static_prefix[..static_prefix.len() - 1]
                } else {
                    Path::new(&static_prefix)
                        .parent()
                        .map(|p| p.to_str().unwrap_or(""))
                        .unwrap_or("")
                };

                rules.push("(deny file-write-unlink".to_string());
                rules.push(format!("  (literal {})", escape_path(base_dir)));
                rules.push(format!("  (with message \"{log_tag}\"))"));

                for ancestor in get_ancestor_directories(base_dir) {
                    rules.push("(deny file-write-unlink".to_string());
                    rules.push(format!("  (literal {})", escape_path(&ancestor)));
                    rules.push(format!("  (with message \"{log_tag}\"))"));
                }
            }
        } else {
            rules.push("(deny file-write-unlink".to_string());
            rules.push(format!("  (subpath {})", escape_path(&normalized)));
            rules.push(format!("  (with message \"{log_tag}\"))"));

            for ancestor in get_ancestor_directories(&normalized) {
                rules.push("(deny file-write-unlink".to_string());
                rules.push(format!("  (literal {})", escape_path(&ancestor)));
                rules.push(format!("  (with message \"{log_tag}\"))"));
            }
        }
    }

    rules
}

/// Generate filesystem read rules for sandbox profile.
fn generate_read_rules(config: &Option<FsReadRestrictionConfig>, log_tag: &str) -> Vec<String> {
    let config = match config {
        Some(c) => c,
        None => return vec!["(allow file-read*)".to_string()],
    };

    let mut rules = vec!["(allow file-read*)".to_string()];

    for path_pattern in &config.deny_only {
        let normalized = normalize_path_for_sandbox(path_pattern);

        if contains_glob_chars(&normalized) {
            let regex_pattern = glob_to_regex(&normalized);
            rules.push("(deny file-read*".to_string());
            rules.push(format!("  (regex {})", escape_path(&regex_pattern)));
            rules.push(format!("  (with message \"{log_tag}\"))"));
        } else {
            rules.push("(deny file-read*".to_string());
            rules.push(format!("  (subpath {})", escape_path(&normalized)));
            rules.push(format!("  (with message \"{log_tag}\"))"));
        }
    }

    rules.extend(generate_move_blocking_rules(&config.deny_only, log_tag));
    rules
}

/// Generate filesystem write rules for sandbox profile.
fn generate_write_rules(
    config: &Option<FsWriteRestrictionConfig>,
    log_tag: &str,
    allow_git_config: bool,
) -> Vec<String> {
    let config = match config {
        Some(c) => c,
        None => return vec!["(allow file-write*)".to_string()],
    };

    let mut rules = Vec::new();

    // Auto-allow TMPDIR parent on macOS
    for tmpdir_parent in get_tmpdir_parent_if_macos_pattern() {
        let normalized = normalize_path_for_sandbox(&tmpdir_parent);
        rules.push("(allow file-write*".to_string());
        rules.push(format!("  (subpath {})", escape_path(&normalized)));
        rules.push(format!("  (with message \"{log_tag}\"))"));
    }

    // Allow rules
    for path_pattern in &config.allow_only {
        let normalized = normalize_path_for_sandbox(path_pattern);
        if contains_glob_chars(&normalized) {
            let regex_pattern = glob_to_regex(&normalized);
            rules.push("(allow file-write*".to_string());
            rules.push(format!("  (regex {})", escape_path(&regex_pattern)));
            rules.push(format!("  (with message \"{log_tag}\"))"));
        } else {
            rules.push("(allow file-write*".to_string());
            rules.push(format!("  (subpath {})", escape_path(&normalized)));
            rules.push(format!("  (with message \"{log_tag}\"))"));
        }
    }

    // Deny within allow + mandatory deny
    let mut deny_paths: Vec<String> = config.deny_within_allow.clone();
    deny_paths.extend(mac_get_mandatory_deny_patterns(allow_git_config));

    for path_pattern in &deny_paths {
        let normalized = normalize_path_for_sandbox(path_pattern);
        if contains_glob_chars(&normalized) {
            let regex_pattern = glob_to_regex(&normalized);
            rules.push("(deny file-write*".to_string());
            rules.push(format!("  (regex {})", escape_path(&regex_pattern)));
            rules.push(format!("  (with message \"{log_tag}\"))"));
        } else {
            rules.push("(deny file-write*".to_string());
            rules.push(format!("  (subpath {})", escape_path(&normalized)));
            rules.push(format!("  (with message \"{log_tag}\"))"));
        }
    }

    rules.extend(generate_move_blocking_rules(&deny_paths, log_tag));
    rules
}

/// Generate a complete macOS sandbox profile.
#[allow(clippy::too_many_arguments)]
fn generate_sandbox_profile(
    read_config: &Option<FsReadRestrictionConfig>,
    write_config: &Option<FsWriteRestrictionConfig>,
    http_proxy_port: Option<u16>,
    socks_proxy_port: Option<u16>,
    needs_network_restriction: bool,
    allow_unix_sockets: &Option<Vec<String>>,
    allow_all_unix_sockets: Option<bool>,
    allow_local_binding: Option<bool>,
    allow_pty: Option<bool>,
    allow_git_config: bool,
    enable_weaker_network_isolation: bool,
    log_tag: &str,
) -> String {
    let mut profile = vec![
        "(version 1)".to_string(),
        format!("(deny default (with message \"{log_tag}\"))"),
        String::new(),
        format!("; LogTag: {log_tag}"),
        String::new(),
        "; Essential permissions - based on Chrome sandbox policy".to_string(),
        "; Process permissions".to_string(),
        "(allow process-exec)".to_string(),
        "(allow process-fork)".to_string(),
        "(allow process-info* (target same-sandbox))".to_string(),
        "(allow signal (target same-sandbox))".to_string(),
        "(allow mach-priv-task-port (target same-sandbox))".to_string(),
        String::new(),
        "; User preferences".to_string(),
        "(allow user-preference-read)".to_string(),
        String::new(),
        "; Mach IPC - specific services only (no wildcard)".to_string(),
        "(allow mach-lookup".to_string(),
        "  (global-name \"com.apple.audio.systemsoundserver\")".to_string(),
        "  (global-name \"com.apple.distributed_notifications@Uv3\")".to_string(),
        "  (global-name \"com.apple.FontObjectsServer\")".to_string(),
        "  (global-name \"com.apple.fonts\")".to_string(),
        "  (global-name \"com.apple.logd\")".to_string(),
        "  (global-name \"com.apple.lsd.mapdb\")".to_string(),
        "  (global-name \"com.apple.PowerManagement.control\")".to_string(),
        "  (global-name \"com.apple.system.logger\")".to_string(),
        "  (global-name \"com.apple.system.notification_center\")".to_string(),
        "  (global-name \"com.apple.system.opendirectoryd.libinfo\")".to_string(),
        "  (global-name \"com.apple.system.opendirectoryd.membership\")".to_string(),
        "  (global-name \"com.apple.bsd.dirhelper\")".to_string(),
        "  (global-name \"com.apple.securityd.xpc\")".to_string(),
        "  (global-name \"com.apple.coreservices.launchservicesd\")".to_string(),
        ")".to_string(),
        String::new(),
    ];

    if enable_weaker_network_isolation {
        profile.push("; trustd.agent - needed for Go TLS certificate verification (weaker network isolation)".to_string());
        profile.push("(allow mach-lookup (global-name \"com.apple.trustd.agent\"))".to_string());
    }

    profile.extend([
        String::new(),
        "; POSIX IPC - shared memory".to_string(),
        "(allow ipc-posix-shm)".to_string(),
        String::new(),
        "; POSIX IPC - semaphores for Python multiprocessing".to_string(),
        "(allow ipc-posix-sem)".to_string(),
        String::new(),
        "; IOKit - specific operations only".to_string(),
        "(allow iokit-open".to_string(),
        "  (iokit-registry-entry-class \"IOSurfaceRootUserClient\")".to_string(),
        "  (iokit-registry-entry-class \"RootDomainUserClient\")".to_string(),
        "  (iokit-user-client-class \"IOSurfaceSendRight\")".to_string(),
        ")".to_string(),
        String::new(),
        "; IOKit properties".to_string(),
        "(allow iokit-get-properties)".to_string(),
        String::new(),
        "; Specific safe system-sockets, doesn't allow network access".to_string(),
        "(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))".to_string(),
        String::new(),
        "; sysctl - specific sysctls only".to_string(),
        "(allow sysctl-read".to_string(),
        "  (sysctl-name \"hw.activecpu\")".to_string(),
        "  (sysctl-name \"hw.busfrequency_compat\")".to_string(),
        "  (sysctl-name \"hw.byteorder\")".to_string(),
        "  (sysctl-name \"hw.cacheconfig\")".to_string(),
        "  (sysctl-name \"hw.cachelinesize_compat\")".to_string(),
        "  (sysctl-name \"hw.cpufamily\")".to_string(),
        "  (sysctl-name \"hw.cpufrequency\")".to_string(),
        "  (sysctl-name \"hw.cpufrequency_compat\")".to_string(),
        "  (sysctl-name \"hw.cputype\")".to_string(),
        "  (sysctl-name \"hw.l1dcachesize_compat\")".to_string(),
        "  (sysctl-name \"hw.l1icachesize_compat\")".to_string(),
        "  (sysctl-name \"hw.l2cachesize_compat\")".to_string(),
        "  (sysctl-name \"hw.l3cachesize_compat\")".to_string(),
        "  (sysctl-name \"hw.logicalcpu\")".to_string(),
        "  (sysctl-name \"hw.logicalcpu_max\")".to_string(),
        "  (sysctl-name \"hw.machine\")".to_string(),
        "  (sysctl-name \"hw.memsize\")".to_string(),
        "  (sysctl-name \"hw.ncpu\")".to_string(),
        "  (sysctl-name \"hw.nperflevels\")".to_string(),
        "  (sysctl-name \"hw.packages\")".to_string(),
        "  (sysctl-name \"hw.pagesize_compat\")".to_string(),
        "  (sysctl-name \"hw.pagesize\")".to_string(),
        "  (sysctl-name \"hw.physicalcpu\")".to_string(),
        "  (sysctl-name \"hw.physicalcpu_max\")".to_string(),
        "  (sysctl-name \"hw.tbfrequency_compat\")".to_string(),
        "  (sysctl-name \"hw.vectorunit\")".to_string(),
        "  (sysctl-name \"kern.argmax\")".to_string(),
        "  (sysctl-name \"kern.bootargs\")".to_string(),
        "  (sysctl-name \"kern.hostname\")".to_string(),
        "  (sysctl-name \"kern.maxfiles\")".to_string(),
        "  (sysctl-name \"kern.maxfilesperproc\")".to_string(),
        "  (sysctl-name \"kern.maxproc\")".to_string(),
        "  (sysctl-name \"kern.ngroups\")".to_string(),
        "  (sysctl-name \"kern.osproductversion\")".to_string(),
        "  (sysctl-name \"kern.osrelease\")".to_string(),
        "  (sysctl-name \"kern.ostype\")".to_string(),
        "  (sysctl-name \"kern.osvariant_status\")".to_string(),
        "  (sysctl-name \"kern.osversion\")".to_string(),
        "  (sysctl-name \"kern.secure_kernel\")".to_string(),
        "  (sysctl-name \"kern.tcsm_available\")".to_string(),
        "  (sysctl-name \"kern.tcsm_enable\")".to_string(),
        "  (sysctl-name \"kern.usrstack64\")".to_string(),
        "  (sysctl-name \"kern.version\")".to_string(),
        "  (sysctl-name \"kern.willshutdown\")".to_string(),
        "  (sysctl-name \"machdep.cpu.brand_string\")".to_string(),
        "  (sysctl-name \"machdep.ptrauth_enabled\")".to_string(),
        "  (sysctl-name \"security.mac.lockdown_mode_state\")".to_string(),
        "  (sysctl-name \"sysctl.proc_cputype\")".to_string(),
        "  (sysctl-name \"vm.loadavg\")".to_string(),
        "  (sysctl-name-prefix \"hw.optional.arm\")".to_string(),
        "  (sysctl-name-prefix \"hw.optional.arm.\")".to_string(),
        "  (sysctl-name-prefix \"hw.optional.armv8_\")".to_string(),
        "  (sysctl-name-prefix \"hw.perflevel\")".to_string(),
        "  (sysctl-name-prefix \"kern.proc.all\")".to_string(),
        "  (sysctl-name-prefix \"kern.proc.pgrp.\")".to_string(),
        "  (sysctl-name-prefix \"kern.proc.pid.\")".to_string(),
        "  (sysctl-name-prefix \"machdep.cpu.\")".to_string(),
        "  (sysctl-name-prefix \"net.routetable.\")".to_string(),
        ")".to_string(),
        String::new(),
        "; V8 thread calculations".to_string(),
        "(allow sysctl-write".to_string(),
        "  (sysctl-name \"kern.tcsm_enable\")".to_string(),
        ")".to_string(),
        String::new(),
        "; Distributed notifications".to_string(),
        "(allow distributed-notification-post)".to_string(),
        String::new(),
        "; Specific mach-lookup permissions for security operations".to_string(),
        "(allow mach-lookup (global-name \"com.apple.SecurityServer\"))".to_string(),
        String::new(),
        "; File I/O on device files".to_string(),
        "(allow file-ioctl (literal \"/dev/null\"))".to_string(),
        "(allow file-ioctl (literal \"/dev/zero\"))".to_string(),
        "(allow file-ioctl (literal \"/dev/random\"))".to_string(),
        "(allow file-ioctl (literal \"/dev/urandom\"))".to_string(),
        "(allow file-ioctl (literal \"/dev/dtracehelper\"))".to_string(),
        "(allow file-ioctl (literal \"/dev/tty\"))".to_string(),
        String::new(),
        "(allow file-ioctl file-read-data file-write-data".to_string(),
        "  (require-all".to_string(),
        "    (literal \"/dev/null\")".to_string(),
        "    (vnode-type CHARACTER-DEVICE)".to_string(),
        "  )".to_string(),
        ")".to_string(),
        String::new(),
    ]);

    // Network rules
    profile.push("; Network".to_string());
    if !needs_network_restriction {
        profile.push("(allow network*)".to_string());
    } else {
        if allow_local_binding == Some(true) {
            profile.push("(allow network-bind (local ip \"*:*\"))".to_string());
            profile.push("(allow network-inbound (local ip \"*:*\"))".to_string());
            profile.push("(allow network-outbound (local ip \"*:*\"))".to_string());
        }

        if allow_all_unix_sockets == Some(true) {
            profile.push("(allow system-socket (socket-domain AF_UNIX))".to_string());
            profile.push(
                "(allow network-bind (local unix-socket (path-regex #\"^/\")))".to_string(),
            );
            profile.push(
                "(allow network-outbound (remote unix-socket (path-regex #\"^/\")))".to_string(),
            );
        } else if let Some(ref sockets) = allow_unix_sockets {
            if !sockets.is_empty() {
                profile.push("(allow system-socket (socket-domain AF_UNIX))".to_string());
                for socket_path in sockets {
                    let normalized = normalize_path_for_sandbox(socket_path);
                    profile.push(format!(
                        "(allow network-bind (local unix-socket (subpath {})))",
                        escape_path(&normalized)
                    ));
                    profile.push(format!(
                        "(allow network-outbound (remote unix-socket (subpath {})))",
                        escape_path(&normalized)
                    ));
                }
            }
        }

        if let Some(port) = http_proxy_port {
            profile.push(format!(
                "(allow network-bind (local ip \"localhost:{port}\"))"
            ));
            profile.push(format!(
                "(allow network-inbound (local ip \"localhost:{port}\"))"
            ));
            profile.push(format!(
                "(allow network-outbound (remote ip \"localhost:{port}\"))"
            ));
        }

        if let Some(port) = socks_proxy_port {
            profile.push(format!(
                "(allow network-bind (local ip \"localhost:{port}\"))"
            ));
            profile.push(format!(
                "(allow network-inbound (local ip \"localhost:{port}\"))"
            ));
            profile.push(format!(
                "(allow network-outbound (remote ip \"localhost:{port}\"))"
            ));
        }
    }
    profile.push(String::new());

    // Read rules
    profile.push("; File read".to_string());
    profile.extend(generate_read_rules(read_config, log_tag));
    profile.push(String::new());

    // Write rules
    profile.push("; File write".to_string());
    profile.extend(generate_write_rules(write_config, log_tag, allow_git_config));

    // PTY support
    if allow_pty == Some(true) {
        profile.push(String::new());
        profile.push("; Pseudo-terminal (pty) support".to_string());
        profile.push("(allow pseudo-tty)".to_string());
        profile.push("(allow file-ioctl".to_string());
        profile.push("  (literal \"/dev/ptmx\")".to_string());
        profile.push("  (regex #\"^/dev/ttys\")".to_string());
        profile.push(")".to_string());
        profile.push("(allow file-read* file-write*".to_string());
        profile.push("  (literal \"/dev/ptmx\")".to_string());
        profile.push("  (regex #\"^/dev/ttys\")".to_string());
        profile.push(")".to_string());
    }

    profile.join("\n")
}

/// Wrap a command with macOS sandbox restrictions.
pub fn wrap_command_with_sandbox_macos(params: MacOSSandboxParams) -> crate::error::Result<String> {
    let MacOSSandboxParams {
        command,
        needs_network_restriction,
        http_proxy_port,
        socks_proxy_port,
        allow_unix_sockets,
        allow_all_unix_sockets,
        allow_local_binding,
        read_config,
        write_config,
        allow_pty,
        allow_git_config,
        enable_weaker_network_isolation,
        bin_shell,
        ..
    } = params;

    // Check if we have restrictions to apply
    let has_read_restrictions = read_config
        .as_ref()
        .is_some_and(|c| !c.deny_only.is_empty());
    let has_write_restrictions = write_config.is_some();

    if !needs_network_restriction && !has_read_restrictions && !has_write_restrictions {
        return Ok(command);
    }

    let log_tag = generate_log_tag(&command);

    let profile = generate_sandbox_profile(
        &read_config,
        &write_config,
        http_proxy_port,
        socks_proxy_port,
        needs_network_restriction,
        &allow_unix_sockets,
        allow_all_unix_sockets,
        allow_local_binding,
        allow_pty,
        allow_git_config,
        enable_weaker_network_isolation,
        &log_tag,
    );

    let proxy_env_args = generate_proxy_env_vars(http_proxy_port, socks_proxy_port);

    let shell_name = bin_shell.as_deref().unwrap_or("bash");
    let shell = which_sync(shell_name)
        .ok_or_else(|| crate::error::SandboxError::ShellNotFound(shell_name.to_string()))?;

    // Build args: env VAR=val... sandbox-exec -p <profile> <shell> -c <command>
    let mut args: Vec<&str> = vec!["env"];
    let env_refs: Vec<&str> = proxy_env_args.iter().map(|s| s.as_str()).collect();
    args.extend(&env_refs);
    args.extend(&["sandbox-exec", "-p"]);
    args.push(&profile);
    args.push(&shell);
    args.extend(&["-c"]);
    args.push(&command);

    let wrapped = shell_quote_join(&args);

    log_for_debugging(
        &format!(
            "[Sandbox macOS] Applied restrictions - network: {}, read: {}, write: {}",
            http_proxy_port.is_some() || socks_proxy_port.is_some(),
            if has_read_restrictions {
                "deny"
            } else {
                "none"
            },
            if has_write_restrictions {
                "allow-only"
            } else {
                "none"
            }
        ),
        None,
    );

    Ok(wrapped)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- session_suffix / log_tag tests ---

    #[test]
    fn test_session_suffix_format() {
        let suffix = session_suffix();
        assert!(suffix.starts_with('_'));
        assert!(suffix.ends_with("_SBX"));
        // Total length: _ + 9 chars + _SBX = 14
        assert_eq!(suffix.len(), 14);
    }

    #[test]
    fn test_generate_log_tag_format() {
        let tag = generate_log_tag("echo hello");
        assert!(tag.starts_with("CMD64_"));
        assert!(tag.contains("_END_"));
        assert!(tag.ends_with("_SBX"));
    }

    // --- mandatory deny patterns ---

    #[test]
    fn test_mandatory_deny_patterns_contains_dangerous_files() {
        let patterns = mac_get_mandatory_deny_patterns(false);
        // Should have glob patterns for dangerous files
        assert!(patterns.iter().any(|p| p.contains(".bashrc")));
        assert!(patterns.iter().any(|p| p.contains(".gitconfig")));
        assert!(patterns.iter().any(|p| p.contains(".mcp.json")));
    }

    #[test]
    fn test_mandatory_deny_patterns_git_config_blocked_by_default() {
        let patterns = mac_get_mandatory_deny_patterns(false);
        assert!(patterns.iter().any(|p| p.contains(".git/config")));
    }

    #[test]
    fn test_mandatory_deny_patterns_git_config_allowed_when_toggled() {
        let patterns = mac_get_mandatory_deny_patterns(true);
        // When allow_git_config is true, .git/config should NOT be in deny patterns
        assert!(!patterns.iter().any(|p| p == "**/.git/config"));
    }

    #[test]
    fn test_mandatory_deny_patterns_git_hooks_always_blocked() {
        let patterns_allowed = mac_get_mandatory_deny_patterns(true);
        let patterns_denied = mac_get_mandatory_deny_patterns(false);
        assert!(patterns_allowed.iter().any(|p| p.contains(".git/hooks")));
        assert!(patterns_denied.iter().any(|p| p.contains(".git/hooks")));
    }

    #[test]
    fn test_mandatory_deny_patterns_contains_dangerous_directories() {
        let patterns = mac_get_mandatory_deny_patterns(false);
        assert!(patterns.iter().any(|p| p.contains(".vscode")));
        assert!(patterns.iter().any(|p| p.contains(".idea")));
        assert!(patterns.iter().any(|p| p.contains(".nebo/commands")));
        assert!(patterns.iter().any(|p| p.contains(".nebo/agents")));
    }

    // --- read rules tests ---

    #[test]
    fn test_read_rules_no_config() {
        let rules = generate_read_rules(&None, "TAG");
        assert!(rules.contains(&"(allow file-read*)".to_string()));
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn test_read_rules_with_deny_paths() {
        let config = FsReadRestrictionConfig {
            deny_only: vec!["/secret".to_string()],
        };
        let rules = generate_read_rules(&Some(config), "TAG");
        assert!(rules.iter().any(|r| r.contains("allow file-read*")));
        assert!(rules.iter().any(|r| r.contains("deny file-read*")));
        assert!(rules.iter().any(|r| r.contains("/secret")));
    }

    #[test]
    fn test_read_rules_with_glob_deny() {
        let config = FsReadRestrictionConfig {
            deny_only: vec!["**/.env".to_string()],
        };
        let rules = generate_read_rules(&Some(config), "TAG");
        assert!(rules.iter().any(|r| r.contains("regex")));
    }

    // --- write rules tests ---

    #[test]
    fn test_write_rules_no_config() {
        let rules = generate_write_rules(&None, "TAG", false);
        assert!(rules.contains(&"(allow file-write*)".to_string()));
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn test_write_rules_with_allow_paths() {
        let config = FsWriteRestrictionConfig {
            allow_only: vec!["/tmp/allowed".to_string()],
            deny_within_allow: vec![],
        };
        let rules = generate_write_rules(&Some(config), "TAG", false);
        assert!(rules.iter().any(|r| r.contains("allow file-write*")));
        assert!(rules.iter().any(|r| r.contains("/tmp/allowed") || r.contains("/private/tmp/allowed")));
    }

    #[test]
    fn test_write_rules_mandatory_deny_included() {
        let config = FsWriteRestrictionConfig {
            allow_only: vec!["/tmp".to_string()],
            deny_within_allow: vec![],
        };
        let rules = generate_write_rules(&Some(config), "TAG", false);
        // Mandatory deny patterns should be included
        assert!(rules.iter().any(|r| r.contains("deny file-write*")));
    }

    // --- sandbox profile tests ---

    #[test]
    fn test_sandbox_profile_minimal() {
        let profile = generate_sandbox_profile(
            &None,
            &None,
            None,
            None,
            false,
            &None,
            None,
            None,
            None,
            false,
            false,
            "TEST_TAG",
        );
        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("TEST_TAG"));
        assert!(profile.contains("(allow network*)"));
        assert!(profile.contains("(allow file-read*)"));
        assert!(profile.contains("(allow file-write*)"));
    }

    #[test]
    fn test_sandbox_profile_network_restricted() {
        let profile = generate_sandbox_profile(
            &None,
            &None,
            Some(8080),
            Some(1080),
            true,
            &None,
            None,
            None,
            None,
            false,
            false,
            "TEST_TAG",
        );
        assert!(!profile.contains("(allow network*)"));
        assert!(profile.contains("localhost:8080"));
        assert!(profile.contains("localhost:1080"));
    }

    #[test]
    fn test_sandbox_profile_with_pty() {
        let profile = generate_sandbox_profile(
            &None,
            &None,
            None,
            None,
            false,
            &None,
            None,
            None,
            Some(true),
            false,
            false,
            "TEST_TAG",
        );
        assert!(profile.contains("pseudo-tty"));
        assert!(profile.contains("/dev/ptmx"));
    }

    #[test]
    fn test_sandbox_profile_without_pty() {
        let profile = generate_sandbox_profile(
            &None,
            &None,
            None,
            None,
            false,
            &None,
            None,
            None,
            None,
            false,
            false,
            "TEST_TAG",
        );
        assert!(!profile.contains("pseudo-tty"));
    }

    #[test]
    fn test_sandbox_profile_with_unix_sockets() {
        let sockets = vec!["/tmp/test.sock".to_string()];
        let profile = generate_sandbox_profile(
            &None,
            &None,
            None,
            None,
            true,
            &Some(sockets),
            None,
            None,
            None,
            false,
            false,
            "TEST_TAG",
        );
        assert!(profile.contains("AF_UNIX"));
        assert!(profile.contains("test.sock") || profile.contains("/tmp/test.sock") || profile.contains("/private/tmp/test.sock"));
    }

    #[test]
    fn test_sandbox_profile_with_all_unix_sockets() {
        let profile = generate_sandbox_profile(
            &None,
            &None,
            None,
            None,
            true,
            &None,
            Some(true),
            None,
            None,
            false,
            false,
            "TEST_TAG",
        );
        assert!(profile.contains("AF_UNIX"));
        assert!(profile.contains("path-regex"));
    }

    #[test]
    fn test_sandbox_profile_with_local_binding() {
        let profile = generate_sandbox_profile(
            &None,
            &None,
            None,
            None,
            true,
            &None,
            None,
            Some(true),
            None,
            false,
            false,
            "TEST_TAG",
        );
        assert!(profile.contains("network-bind"));
        assert!(profile.contains("network-inbound"));
    }

    #[test]
    fn test_sandbox_profile_weaker_network_isolation() {
        let profile = generate_sandbox_profile(
            &None,
            &None,
            None,
            None,
            false,
            &None,
            None,
            None,
            None,
            false,
            true,
            "TEST_TAG",
        );
        assert!(profile.contains("trustd.agent"));
    }

    // --- wrap_command tests ---

    #[test]
    fn test_wrap_command_no_restrictions_returns_original() {
        let params = MacOSSandboxParams {
            command: "echo hello".to_string(),
            needs_network_restriction: false,
            http_proxy_port: None,
            socks_proxy_port: None,
            allow_unix_sockets: None,
            allow_all_unix_sockets: None,
            allow_local_binding: None,
            read_config: None,
            write_config: None,
            ignore_violations: None,
            allow_pty: None,
            allow_git_config: false,
            enable_weaker_network_isolation: false,
            bin_shell: None,
        };
        let result = wrap_command_with_sandbox_macos(params).unwrap();
        assert_eq!(result, "echo hello");
    }

    #[test]
    fn test_wrap_command_with_write_restrictions_includes_sandbox_exec() {
        let params = MacOSSandboxParams {
            command: "echo hello".to_string(),
            needs_network_restriction: false,
            http_proxy_port: None,
            socks_proxy_port: None,
            allow_unix_sockets: None,
            allow_all_unix_sockets: None,
            allow_local_binding: None,
            read_config: None,
            write_config: Some(FsWriteRestrictionConfig {
                allow_only: vec!["/tmp".to_string()],
                deny_within_allow: vec![],
            }),
            ignore_violations: None,
            allow_pty: None,
            allow_git_config: false,
            enable_weaker_network_isolation: false,
            bin_shell: None,
        };
        let result = wrap_command_with_sandbox_macos(params).unwrap();
        assert!(result.contains("sandbox-exec"));
        assert!(result.contains("echo hello"));
    }

    #[test]
    fn test_wrap_command_with_network_restriction() {
        let params = MacOSSandboxParams {
            command: "curl example.com".to_string(),
            needs_network_restriction: true,
            http_proxy_port: Some(8080),
            socks_proxy_port: Some(1080),
            allow_unix_sockets: None,
            allow_all_unix_sockets: None,
            allow_local_binding: None,
            read_config: None,
            write_config: Some(FsWriteRestrictionConfig {
                allow_only: vec!["/tmp".to_string()],
                deny_within_allow: vec![],
            }),
            ignore_violations: None,
            allow_pty: None,
            allow_git_config: false,
            enable_weaker_network_isolation: false,
            bin_shell: None,
        };
        let result = wrap_command_with_sandbox_macos(params).unwrap();
        assert!(result.contains("sandbox-exec"));
        assert!(result.contains("SANDBOX_RUNTIME=1"));
    }

    // --- escape_path ---

    #[test]
    fn test_escape_path_basic() {
        let escaped = escape_path("/tmp/test");
        assert_eq!(escaped, "\"/tmp/test\"");
    }

    #[test]
    fn test_escape_path_with_special_chars() {
        let escaped = escape_path("/path with spaces/file");
        assert!(escaped.starts_with('"'));
        assert!(escaped.ends_with('"'));
    }

    // --- move blocking rules ---

    #[test]
    fn test_move_blocking_rules_subpath() {
        let rules = generate_move_blocking_rules(&["/protected".to_string()], "TAG");
        assert!(rules.iter().any(|r| r.contains("file-write-unlink")));
        assert!(rules.iter().any(|r| r.contains("subpath")));
    }

    #[test]
    fn test_move_blocking_rules_glob() {
        let rules = generate_move_blocking_rules(&["**/.secret".to_string()], "TAG");
        assert!(rules.iter().any(|r| r.contains("file-write-unlink")));
        assert!(rules.iter().any(|r| r.contains("regex")));
    }
}

/// Start monitoring macOS system logs for sandbox violations.
/// Returns a handle that kills the monitor process when dropped.
pub fn start_macos_sandbox_log_monitor(
    violation_store: SandboxViolationStore,
    ignore_violations: Option<HashMap<String, Vec<String>>>,
) -> Option<Child> {
    let suffix = SESSION_SUFFIX.with(|s| s.clone());

    let mut child = Command::new("log")
        .args([
            "stream",
            "--predicate",
            &format!("(eventMessage ENDSWITH \"{suffix}\")"),
            "--style",
            "compact",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    // Take ownership of stdout so the thread owns it exclusively
    let stdout = child.stdout.take()?;
    let ignore = ignore_violations.clone();

    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader};

        let reader = BufReader::new(stdout);

        let cmd_regex = regex::Regex::new(r"CMD64_(.+?)_END").unwrap();
        let sandbox_regex = regex::Regex::new(r"Sandbox:\s+(.+)$").unwrap();

        let wildcard_paths: Vec<String> = ignore
            .as_ref()
            .and_then(|ig| ig.get("*"))
            .cloned()
            .unwrap_or_default();

        let command_patterns: Vec<(String, Vec<String>)> = ignore
            .as_ref()
            .map(|ig| {
                ig.iter()
                    .filter(|(k, _)| k.as_str() != "*")
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default();

        for line_result in reader.lines() {
            let line = match line_result {
                Ok(l) => l,
                Err(_) => break,
            };

            if !line.contains("Sandbox:") || !line.contains("deny") {
                continue;
            }

            let violation_details = match sandbox_regex.captures(&line) {
                Some(caps) => caps.get(1).map(|m| m.as_str().to_string()),
                None => continue,
            };

            let violation_details = match violation_details {
                Some(v) => v,
                None => continue,
            };

            // Filter noisy violations
            if violation_details.contains("mDNSResponder")
                || violation_details.contains("mach-lookup com.apple.diagnosticd")
                || violation_details.contains("mach-lookup com.apple.analyticsd")
            {
                continue;
            }

            let mut cmd: Option<String> = None;
            let mut encoded_cmd: Option<String> = None;

            if let Some(caps) = cmd_regex.captures(&line) {
                if let Some(enc) = caps.get(1) {
                    encoded_cmd = Some(enc.as_str().to_string());
                    cmd = decode_sandboxed_command(enc.as_str());
                }
            }

            // Check ignore rules
            if let Some(ref command) = cmd {
                if !wildcard_paths.is_empty()
                    && wildcard_paths
                        .iter()
                        .any(|p| violation_details.contains(p.as_str()))
                {
                    continue;
                }

                let mut should_ignore = false;
                for (pattern, paths) in &command_patterns {
                    if command.contains(pattern.as_str())
                        && paths
                            .iter()
                            .any(|p| violation_details.contains(p.as_str()))
                    {
                        should_ignore = true;
                        break;
                    }
                }
                if should_ignore {
                    continue;
                }
            }

            violation_store.add_violation(SandboxViolationEvent {
                line: violation_details,
                command: cmd,
                encoded_command: encoded_cmd,
                timestamp: std::time::SystemTime::now(),
            });
        }
    });

    Some(child)
}

