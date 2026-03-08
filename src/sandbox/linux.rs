use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use crate::config::RipgrepConfig;
use crate::sandbox::dangerous::{get_dangerous_directories, DANGEROUS_FILES};
use crate::sandbox::seccomp::{
    generate_seccomp_filter, get_apply_seccomp_binary_path, get_pre_generated_bpf_path,
};
use crate::schemas::{FsReadRestrictionConfig, FsWriteRestrictionConfig};
use crate::utils::command::generate_proxy_env_vars;
use crate::utils::debug::log_for_debugging;
use crate::utils::path::{
    is_symlink_outside_boundary, normalize_case_for_comparison, normalize_path_for_sandbox,
};
use crate::utils::ripgrep::rip_grep;
use crate::utils::shell::{shell_quote, shell_quote_join};
use crate::utils::which::which_sync;

const DEFAULT_MANDATORY_DENY_SEARCH_DEPTH: u8 = 3;

/// Global tracking of mount points created by bwrap for non-existent deny paths.
/// When bwrap does --ro-bind /dev/null /nonexistent/path, it creates an empty
/// file on the host as a mount point. These persist after bwrap exits and must
/// be cleaned up explicitly.
static BWRAP_MOUNT_POINTS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Global tracking of generated seccomp filters for cleanup.
static GENERATED_SECCOMP_FILTERS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Linux network bridge context.
pub struct LinuxNetworkBridgeContext {
    pub http_socket_path: String,
    pub socks_socket_path: String,
    pub http_bridge_process: Child,
    pub socks_bridge_process: Child,
    pub http_proxy_port: u16,
    pub socks_proxy_port: u16,
}

/// Parameters for Linux sandbox wrapping.
pub struct LinuxSandboxParams {
    pub command: String,
    pub needs_network_restriction: bool,
    pub http_socket_path: Option<String>,
    pub socks_socket_path: Option<String>,
    pub http_proxy_port: Option<u16>,
    pub socks_proxy_port: Option<u16>,
    pub read_config: Option<FsReadRestrictionConfig>,
    pub write_config: Option<FsWriteRestrictionConfig>,
    pub enable_weaker_nested_sandbox: Option<bool>,
    pub allow_all_unix_sockets: Option<bool>,
    pub bin_shell: Option<String>,
    pub ripgrep_config: RipgrepConfig,
    pub mandatory_deny_search_depth: u8,
    pub allow_git_config: bool,
    pub seccomp_config: Option<crate::config::SeccompConfig>,
}

/// Dependency check result.
pub struct SandboxDependencyCheck {
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

/// Check sandbox dependencies for Linux.
pub fn check_linux_dependencies(
    seccomp_config: &Option<crate::config::SeccompConfig>,
) -> SandboxDependencyCheck {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    if which_sync("bwrap").is_none() {
        errors.push("bubblewrap (bwrap) not installed".to_string());
    }
    if which_sync("socat").is_none() {
        errors.push("socat not installed".to_string());
    }

    let bpf_path = seccomp_config.as_ref().and_then(|c| c.bpf_path.as_deref());
    let apply_path = seccomp_config
        .as_ref()
        .and_then(|c| c.apply_path.as_deref());

    let has_bpf = get_pre_generated_bpf_path(bpf_path).is_some();
    let has_apply = get_apply_seccomp_binary_path(apply_path).is_some();
    if !has_bpf || !has_apply {
        warnings.push("seccomp not available - unix socket access not restricted".to_string());
    }

    SandboxDependencyCheck { warnings, errors }
}

/// Detailed status of Linux sandbox dependencies.
pub struct LinuxDependencyStatus {
    pub has_bwrap: bool,
    pub has_socat: bool,
    pub has_seccomp_bpf: bool,
    pub has_seccomp_apply: bool,
}

/// Get detailed Linux dependency status.
pub fn get_linux_dependency_status(
    seccomp_config: &Option<crate::config::SeccompConfig>,
) -> LinuxDependencyStatus {
    let bpf_path = seccomp_config
        .as_ref()
        .and_then(|c| c.bpf_path.as_deref());
    let apply_path = seccomp_config
        .as_ref()
        .and_then(|c| c.apply_path.as_deref());

    LinuxDependencyStatus {
        has_bwrap: which_sync("bwrap").is_some(),
        has_socat: which_sync("socat").is_some(),
        has_seccomp_bpf: get_pre_generated_bpf_path(bpf_path).is_some(),
        has_seccomp_apply: get_apply_seccomp_binary_path(apply_path).is_some(),
    }
}

/// Clean up mount point files created by bwrap for non-existent deny paths.
///
/// When protecting non-existent deny paths, bwrap creates empty files on the
/// host filesystem as mount points for --ro-bind. These files persist after
/// bwrap exits. This function removes them.
///
/// Safe to call at any time — it only removes files that were tracked during
/// `generate_filesystem_args()` and skips any that no longer exist.
pub fn cleanup_bwrap_mount_points() {
    let mut mount_points = BWRAP_MOUNT_POINTS.lock().unwrap();
    for mount_point in mount_points.iter() {
        match std::fs::metadata(mount_point) {
            Ok(meta) => {
                if meta.is_file() && meta.len() == 0 {
                    let _ = std::fs::remove_file(mount_point);
                    log_for_debugging(
                        &format!(
                            "[Sandbox Linux] Cleaned up bwrap mount point (file): {mount_point}"
                        ),
                        None,
                    );
                } else if meta.is_dir() {
                    if std::fs::read_dir(mount_point)
                        .map(|mut d| d.next().is_none())
                        .unwrap_or(false)
                    {
                        let _ = std::fs::remove_dir(mount_point);
                        log_for_debugging(
                            &format!(
                                "[Sandbox Linux] Cleaned up bwrap mount point (dir): {mount_point}"
                            ),
                            None,
                        );
                    }
                }
            }
            Err(_) => { /* Already removed, ignore */ }
        }
    }
    mount_points.clear();
}

/// Clean up generated seccomp filter files.
pub fn cleanup_seccomp_filters() {
    let mut filters = GENERATED_SECCOMP_FILTERS.lock().unwrap();
    for filter_path in filters.iter() {
        crate::sandbox::seccomp::cleanup_seccomp_filter(filter_path);
    }
    filters.clear();
}

/// Initialize the Linux network bridge for sandbox networking.
pub fn initialize_linux_network_bridge(
    http_proxy_port: u16,
    socks_proxy_port: u16,
) -> crate::error::Result<LinuxNetworkBridgeContext> {
    use rand::Rng;
    let socket_id: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    let tmpdir = std::env::temp_dir();
    let http_socket_path = tmpdir
        .join(format!("nebo-http-{socket_id}.sock"))
        .to_string_lossy()
        .to_string();
    let socks_socket_path = tmpdir
        .join(format!("nebo-socks-{socket_id}.sock"))
        .to_string_lossy()
        .to_string();

    // Start HTTP bridge
    let http_bridge_process = Command::new("socat")
        .args([
            &format!("UNIX-LISTEN:{http_socket_path},fork,reuseaddr"),
            &format!("TCP:localhost:{http_proxy_port},keepalive,keepidle=10,keepintvl=5,keepcnt=3"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| crate::error::SandboxError::NetworkBridgeFailed(format!("HTTP bridge: {e}")))?;

    // Start SOCKS bridge
    let socks_bridge_process = Command::new("socat")
        .args([
            &format!("UNIX-LISTEN:{socks_socket_path},fork,reuseaddr"),
            &format!(
                "TCP:localhost:{socks_proxy_port},keepalive,keepidle=10,keepintvl=5,keepcnt=3"
            ),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            crate::error::SandboxError::NetworkBridgeFailed(format!("SOCKS bridge: {e}"))
        })?;

    // Wait for sockets to be ready
    for i in 0..5 {
        if Path::new(&http_socket_path).exists() && Path::new(&socks_socket_path).exists() {
            log_for_debugging(
                &format!("Linux bridges ready after {} attempts", i + 1),
                None,
            );
            break;
        }
        if i == 4 {
            return Err(crate::error::SandboxError::NetworkBridgeFailed(
                "Failed to create bridge sockets after 5 attempts".to_string(),
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(i as u64 * 100));
    }

    Ok(LinuxNetworkBridgeContext {
        http_socket_path,
        socks_socket_path,
        http_bridge_process,
        socks_bridge_process,
        http_proxy_port,
        socks_proxy_port,
    })
}

/// Check if any component of the path is a file (not a directory).
fn has_file_ancestor(target_path: &str) -> bool {
    let parts: Vec<&str> = target_path.split('/').filter(|s| !s.is_empty()).collect();
    let mut current = String::new();

    for part in &parts {
        current = format!("{}/{}", current, part);
        match std::fs::metadata(&current) {
            Ok(meta) => {
                if meta.is_file() || meta.file_type().is_symlink() {
                    return true;
                }
            }
            Err(_) => break,
        }
    }
    false
}

/// Find the first non-existent path component.
fn find_first_non_existent_component(target_path: &str) -> String {
    let parts: Vec<&str> = target_path.split('/').filter(|s| !s.is_empty()).collect();
    let mut current = String::new();

    for part in &parts {
        let next = format!("{}/{}", current, part);
        if !Path::new(&next).exists() {
            return next;
        }
        current = next;
    }
    target_path.to_string()
}

/// Find symlinks in path within allowed write paths.
fn find_symlink_in_path(target_path: &str, allowed_write_paths: &[String]) -> Option<String> {
    let parts: Vec<&str> = target_path.split('/').filter(|s| !s.is_empty()).collect();
    let mut current = String::new();

    for part in &parts {
        let next = format!("{}/{}", current, part);
        if let Ok(meta) = std::fs::symlink_metadata(&next) {
            if meta.file_type().is_symlink() {
                let is_within = allowed_write_paths
                    .iter()
                    .any(|ap| next.starts_with(&format!("{}/", ap)) || next == *ap);
                if is_within {
                    return Some(next);
                }
            }
        }
        current = next;
    }
    None
}

/// Get mandatory deny paths using ripgrep.
fn linux_get_mandatory_deny_paths(
    ripgrep_config: &RipgrepConfig,
    max_depth: u8,
    allow_git_config: bool,
) -> Vec<String> {
    let cwd = std::env::current_dir()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let dangerous_directories = get_dangerous_directories();

    let mut deny_paths: Vec<String> = Vec::new();

    // Dangerous files in CWD
    for f in DANGEROUS_FILES {
        deny_paths.push(
            PathBuf::from(&cwd)
                .join(f)
                .to_string_lossy()
                .to_string(),
        );
    }

    // Dangerous directories in CWD
    for d in &dangerous_directories {
        deny_paths.push(
            PathBuf::from(&cwd)
                .join(d)
                .to_string_lossy()
                .to_string(),
        );
    }

    // Git hooks and config
    let dot_git = PathBuf::from(&cwd).join(".git");
    let dot_git_is_dir = dot_git
        .metadata()
        .map(|m| m.is_dir())
        .unwrap_or(false);

    if dot_git_is_dir {
        deny_paths.push(
            PathBuf::from(&cwd)
                .join(".git/hooks")
                .to_string_lossy()
                .to_string(),
        );
        if !allow_git_config {
            deny_paths.push(
                PathBuf::from(&cwd)
                    .join(".git/config")
                    .to_string_lossy()
                    .to_string(),
            );
        }
    }

    // Build iglob args for ripgrep
    let mut rg_args: Vec<String> = vec![
        "--files".to_string(),
        "--hidden".to_string(),
        "--max-depth".to_string(),
        max_depth.to_string(),
    ];

    for file_name in DANGEROUS_FILES {
        rg_args.push("--iglob".to_string());
        rg_args.push(file_name.to_string());
    }
    for dir_name in &dangerous_directories {
        rg_args.push("--iglob".to_string());
        rg_args.push(format!("**/{dir_name}/**"));
    }
    rg_args.push("--iglob".to_string());
    rg_args.push("**/.git/hooks/**".to_string());
    if !allow_git_config {
        rg_args.push("--iglob".to_string());
        rg_args.push("**/.git/config".to_string());
    }
    rg_args.push("-g".to_string());
    rg_args.push("!**/node_modules/**".to_string());

    // Run ripgrep
    let rg_arg_refs: Vec<&str> = rg_args.iter().map(|s| s.as_str()).collect();
    let matches = rip_grep(&rg_arg_refs, &cwd, ripgrep_config).unwrap_or_default();

    // Process matches
    let all_dirs: Vec<String> = dangerous_directories
        .iter()
        .chain(std::iter::once(&".git".to_string()))
        .cloned()
        .collect();

    for m in &matches {
        let absolute_path = PathBuf::from(&cwd)
            .join(m)
            .to_string_lossy()
            .to_string();

        let mut found_dir = false;
        for dir_name in &all_dirs {
            let normalized_dir = normalize_case_for_comparison(dir_name);
            let segments: Vec<&str> = absolute_path.split('/').collect();
            if let Some(dir_index) = segments
                .iter()
                .position(|s| normalize_case_for_comparison(s) == normalized_dir)
            {
                if dir_name == ".git" {
                    let git_dir = segments[..dir_index + 1].join("/");
                    if m.contains(".git/hooks") {
                        deny_paths.push(format!("{}/hooks", git_dir));
                    } else if m.contains(".git/config") {
                        deny_paths.push(format!("{}/config", git_dir));
                    }
                } else {
                    deny_paths.push(segments[..dir_index + 1].join("/"));
                }
                found_dir = true;
                break;
            }
        }

        if !found_dir {
            deny_paths.push(absolute_path);
        }
    }

    let unique: HashSet<String> = deny_paths.into_iter().collect();
    unique.into_iter().collect()
}

/// Build the command that runs inside the sandbox.
fn build_sandbox_command(
    http_socket_path: &str,
    socks_socket_path: &str,
    user_command: &str,
    seccomp_filter_path: Option<&str>,
    shell: &str,
    apply_seccomp_path: Option<&str>,
) -> String {
    let socat_commands = vec![
        format!(
            "socat TCP-LISTEN:3128,fork,reuseaddr UNIX-CONNECT:{http_socket_path} >/dev/null 2>&1 &"
        ),
        format!(
            "socat TCP-LISTEN:1080,fork,reuseaddr UNIX-CONNECT:{socks_socket_path} >/dev/null 2>&1 &"
        ),
        "trap \"kill %1 %2 2>/dev/null; exit\" EXIT".to_string(),
    ];

    if let Some(filter_path) = seccomp_filter_path {
        let apply_binary = apply_seccomp_path
            .and_then(|p| get_apply_seccomp_binary_path(Some(p)))
            .or_else(|| get_apply_seccomp_binary_path(None))
            .expect("apply-seccomp binary not found");

        let apply_cmd = shell_quote_join(&[&apply_binary, filter_path, shell, "-c", user_command]);

        let inner_script = socat_commands
            .iter()
            .chain(std::iter::once(&apply_cmd))
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");

        format!("{} -c {}", shell, shell_quote(&inner_script))
    } else {
        let eval_cmd = format!("eval {}", shell_quote(user_command));
        let inner_script = socat_commands
            .iter()
            .chain(std::iter::once(&eval_cmd))
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");

        format!("{} -c {}", shell, shell_quote(&inner_script))
    }
}

/// Generate filesystem bind mount arguments for bwrap.
fn generate_filesystem_args(
    read_config: &Option<FsReadRestrictionConfig>,
    write_config: &Option<FsWriteRestrictionConfig>,
    ripgrep_config: &RipgrepConfig,
    mandatory_deny_search_depth: u8,
    allow_git_config: bool,
) -> Vec<String> {
    let mut args = Vec::new();

    if let Some(wc) = write_config {
        // Write restrictions: read-only root, then allow writes to specific paths
        args.extend(["--ro-bind", "/", "/"].map(String::from));

        let mut allowed_write_paths: Vec<String> = Vec::new();

        for path_pattern in &wc.allow_only {
            let normalized = normalize_path_for_sandbox(path_pattern);

            if normalized.starts_with("/dev/") {
                continue;
            }

            if !Path::new(&normalized).exists() {
                log_for_debugging(
                    &format!("[Sandbox Linux] Skipping non-existent write path: {normalized}"),
                    None,
                );
                continue;
            }

            // Check symlink boundaries
            if let Ok(resolved) = std::fs::canonicalize(&normalized) {
                let resolved_str = resolved.to_string_lossy().to_string();
                let normalized_trimmed = normalized.trim_end_matches('/');
                if resolved_str != normalized_trimmed
                    && is_symlink_outside_boundary(&normalized, &resolved_str)
                {
                    log_for_debugging(
                        &format!("[Sandbox Linux] Skipping symlink write path: {path_pattern} -> {resolved_str}"),
                        None,
                    );
                    continue;
                }
            }

            args.push("--bind".to_string());
            args.push(normalized.clone());
            args.push(normalized.clone());
            allowed_write_paths.push(normalized);
        }

        // Deny paths within allowed
        let mut deny_paths: Vec<String> = wc.deny_within_allow.clone();
        deny_paths.extend(linux_get_mandatory_deny_paths(
            ripgrep_config,
            mandatory_deny_search_depth,
            allow_git_config,
        ));

        for path_pattern in &deny_paths {
            let normalized = normalize_path_for_sandbox(path_pattern);

            if normalized.starts_with("/dev/") {
                continue;
            }

            // Check for symlinks in path
            if let Some(symlink_path) = find_symlink_in_path(&normalized, &allowed_write_paths) {
                args.extend(["--ro-bind", "/dev/null", &symlink_path].map(String::from));
                continue;
            }

            if !Path::new(&normalized).exists() {
                if has_file_ancestor(&normalized) {
                    continue;
                }

                // Find deepest existing ancestor
                let mut ancestor = PathBuf::from(&normalized);
                while ancestor.parent().is_some() {
                    ancestor = ancestor.parent().unwrap().to_path_buf();
                    if ancestor.exists() || ancestor.to_string_lossy() == "/" {
                        break;
                    }
                }
                let ancestor_str = ancestor.to_string_lossy().to_string();

                let ancestor_is_within = allowed_write_paths.iter().any(|ap| {
                    ancestor_str.starts_with(&format!("{}/", ap))
                        || ancestor_str == *ap
                        || normalized.starts_with(&format!("{}/", ap))
                });

                if ancestor_is_within {
                    let first_non_existent = find_first_non_existent_component(&normalized);
                    if first_non_existent != normalized {
                        // Mount empty dir for intermediate component
                        if let Ok(empty_dir) = tempfile::tempdir() {
                            let empty_path = empty_dir.path().to_string_lossy().to_string();
                            args.extend(
                                ["--ro-bind", &empty_path, &first_non_existent].map(String::from),
                            );
                            // Leak the tempdir so it persists
                            std::mem::forget(empty_dir);
                        }
                    } else {
                        args.extend(
                            ["--ro-bind", "/dev/null", &first_non_existent].map(String::from),
                        );
                    }
                    // Track mount point for cleanup
                    if let Ok(mut mp) = BWRAP_MOUNT_POINTS.lock() {
                        mp.push(first_non_existent.clone());
                    }
                }
                continue;
            }

            // Only add deny if within allowed write path
            let is_within = allowed_write_paths.iter().any(|ap| {
                normalized.starts_with(&format!("{}/", ap)) || normalized == *ap
            });

            if is_within {
                args.extend(["--ro-bind", &normalized, &normalized].map(String::from));
            }
        }
    } else {
        // No write restrictions
        args.extend(["--bind", "/", "/"].map(String::from));
    }

    // Handle read restrictions
    let mut read_deny_paths: Vec<String> = read_config
        .as_ref()
        .map(|c| c.deny_only.clone())
        .unwrap_or_default();

    // Hide /etc/ssh/ssh_config.d
    if Path::new("/etc/ssh/ssh_config.d").exists() {
        read_deny_paths.push("/etc/ssh/ssh_config.d".to_string());
    }

    for path_pattern in &read_deny_paths {
        let normalized = normalize_path_for_sandbox(path_pattern);
        if !Path::new(&normalized).exists() {
            continue;
        }

        if std::fs::metadata(&normalized)
            .map(|m| m.is_dir())
            .unwrap_or(false)
        {
            args.extend(["--tmpfs", &normalized].map(String::from));
        } else {
            args.extend(["--ro-bind", "/dev/null", &normalized].map(String::from));
        }
    }

    args
}

/// Wrap a command with sandbox restrictions on Linux.
pub fn wrap_command_with_sandbox_linux(
    params: LinuxSandboxParams,
) -> crate::error::Result<String> {
    let LinuxSandboxParams {
        command,
        needs_network_restriction,
        http_socket_path,
        socks_socket_path,
        http_proxy_port,
        socks_proxy_port,
        read_config,
        write_config,
        enable_weaker_nested_sandbox,
        allow_all_unix_sockets,
        bin_shell,
        ripgrep_config,
        mandatory_deny_search_depth,
        allow_git_config,
        seccomp_config,
    } = params;

    let has_read_restrictions = read_config
        .as_ref()
        .map_or(false, |c| !c.deny_only.is_empty());
    let has_write_restrictions = write_config.is_some();

    if !needs_network_restriction && !has_read_restrictions && !has_write_restrictions {
        return Ok(command);
    }

    let mut bwrap_args: Vec<String> =
        vec!["--new-session".to_string(), "--die-with-parent".to_string()];

    // Seccomp filter
    let mut seccomp_filter_path: Option<String> = None;
    if allow_all_unix_sockets != Some(true) {
        let bpf_path = seccomp_config.as_ref().and_then(|c| c.bpf_path.as_deref());
        seccomp_filter_path = generate_seccomp_filter(bpf_path);
        // Track non-vendor generated filters for cleanup
        if let Some(ref path) = seccomp_filter_path {
            if !path.contains("/vendor/seccomp/") {
                if let Ok(mut filters) = GENERATED_SECCOMP_FILTERS.lock() {
                    filters.push(path.clone());
                }
            }
        }
    }

    // Network restrictions
    if needs_network_restriction {
        bwrap_args.push("--unshare-net".to_string());

        if let (Some(ref http_sock), Some(ref socks_sock)) = (&http_socket_path, &socks_socket_path)
        {
            if !Path::new(http_sock).exists() {
                return Err(crate::error::SandboxError::NetworkBridgeFailed(
                    format!("HTTP bridge socket does not exist: {http_sock}"),
                ));
            }
            if !Path::new(socks_sock).exists() {
                return Err(crate::error::SandboxError::NetworkBridgeFailed(
                    format!("SOCKS bridge socket does not exist: {socks_sock}"),
                ));
            }

            bwrap_args.extend(["--bind", http_sock, http_sock].map(String::from));
            bwrap_args.extend(["--bind", socks_sock, socks_sock].map(String::from));

            // Proxy env vars (internal ports 3128/1080)
            let proxy_env = generate_proxy_env_vars(Some(3128), Some(1080));
            for env_var in &proxy_env {
                if let Some(eq_pos) = env_var.find('=') {
                    let key = &env_var[..eq_pos];
                    let value = &env_var[eq_pos + 1..];
                    bwrap_args.extend(["--setenv", key, value].map(String::from));
                }
            }

            if let Some(port) = http_proxy_port {
                bwrap_args.extend(
                    [
                        "--setenv",
                        "NEBO_HOST_HTTP_PROXY_PORT",
                        &port.to_string(),
                    ]
                    .map(String::from),
                );
            }
            if let Some(port) = socks_proxy_port {
                bwrap_args.extend(
                    [
                        "--setenv",
                        "NEBO_HOST_SOCKS_PROXY_PORT",
                        &port.to_string(),
                    ]
                    .map(String::from),
                );
            }
        }
    }

    // Filesystem restrictions
    let fs_args = generate_filesystem_args(
        &read_config,
        &write_config,
        &ripgrep_config,
        mandatory_deny_search_depth,
        allow_git_config,
    );
    bwrap_args.extend(fs_args);

    // Always bind /dev
    bwrap_args.extend(["--dev", "/dev"].map(String::from));

    // PID namespace isolation
    bwrap_args.push("--unshare-pid".to_string());
    if enable_weaker_nested_sandbox != Some(true) {
        bwrap_args.extend(["--proc", "/proc"].map(String::from));
    }

    // Command
    let shell_name = bin_shell.as_deref().unwrap_or("bash");
    let shell = which_sync(shell_name)
        .ok_or_else(|| crate::error::SandboxError::ShellNotFound(shell_name.to_string()))?;
    bwrap_args.extend(["--", &shell, "-c"].map(String::from));

    if needs_network_restriction {
        if let (Some(ref http_sock), Some(ref socks_sock)) = (&http_socket_path, &socks_socket_path)
        {
            let sandbox_command = build_sandbox_command(
                http_sock,
                socks_sock,
                &command,
                seccomp_filter_path.as_deref(),
                &shell,
                seccomp_config
                    .as_ref()
                    .and_then(|c| c.apply_path.as_deref()),
            );
            bwrap_args.push(sandbox_command);
        } else {
            bwrap_args.push(command);
        }
    } else if let Some(ref filter_path) = seccomp_filter_path {
        let apply_binary = seccomp_config
            .as_ref()
            .and_then(|c| c.apply_path.as_deref())
            .and_then(|p| get_apply_seccomp_binary_path(Some(p)))
            .or_else(|| get_apply_seccomp_binary_path(None));

        if let Some(apply_bin) = apply_binary {
            let cmd = shell_quote_join(&[&apply_bin, filter_path, &shell, "-c", &command]);
            bwrap_args.push(cmd);
        } else {
            bwrap_args.push(command);
        }
    } else {
        bwrap_args.push(command);
    }

    // Build final command
    let mut all_args: Vec<&str> = vec!["bwrap"];
    for arg in &bwrap_args {
        all_args.push(arg);
    }
    let wrapped = shell_quote_join(&all_args);

    log_for_debugging(
        &format!(
            "[Sandbox Linux] Wrapped command with bwrap (network: {}, fs: {}, seccomp: {})",
            needs_network_restriction,
            has_read_restrictions || has_write_restrictions,
            seccomp_filter_path.is_some()
        ),
        None,
    );

    Ok(wrapped)
}
