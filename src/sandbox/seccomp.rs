use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::utils::debug::log_for_debugging;

/// Cached BPF filter path (memoized to avoid repeated filesystem lookups).
static BPF_PATH_CACHE: Mutex<Option<Option<String>>> = Mutex::new(None);

/// Cached apply-seccomp binary path.
static APPLY_SECCOMP_CACHE: Mutex<Option<Option<String>>> = Mutex::new(None);

/// Map Rust target arch to vendor directory architecture names.
fn get_vendor_architecture() -> Option<&'static str> {
    if cfg!(target_arch = "x86_64") {
        Some("x64")
    } else if cfg!(target_arch = "aarch64") {
        Some("arm64")
    } else {
        log_for_debugging(
            &format!(
                "[SeccompFilter] Unsupported architecture: {}. Only x64 and arm64 are supported.",
                std::env::consts::ARCH
            ),
            None,
        );
        None
    }
}

/// Get local paths to check for seccomp files.
fn get_local_seccomp_paths(filename: &str) -> Vec<PathBuf> {
    let arch = match get_vendor_architecture() {
        Some(a) => a,
        None => return vec![],
    };

    let mut paths = Vec::new();

    // Check OUT_DIR from build.rs
    if let Ok(out_dir) = std::env::var("OUT_DIR") {
        paths.push(
            PathBuf::from(&out_dir)
                .join("vendor")
                .join("seccomp")
                .join(arch)
                .join(filename),
        );
    }

    // Check relative to the executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            paths.push(
                exe_dir
                    .join("vendor")
                    .join("seccomp")
                    .join(arch)
                    .join(filename),
            );
            // Also check parent (for cargo target/ layout)
            paths.push(
                exe_dir
                    .join("..")
                    .join("vendor")
                    .join("seccomp")
                    .join(arch)
                    .join(filename),
            );
        }
    }

    // Check CARGO_MANIFEST_DIR
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        paths.push(
            PathBuf::from(&manifest_dir)
                .join("vendor")
                .join("seccomp")
                .join(arch)
                .join(filename),
        );
    }

    paths
}

/// Get the path to a pre-generated BPF filter file.
/// Results are cached after the first lookup (when no explicit path is given).
pub fn get_pre_generated_bpf_path(explicit_path: Option<&str>) -> Option<String> {
    // Check explicit path first (bypass cache)
    if let Some(path) = explicit_path {
        if Path::new(path).exists() {
            log_for_debugging(
                &format!("[SeccompFilter] Using BPF filter from explicit path: {path}"),
                None,
            );
            return Some(path.to_string());
        }
        log_for_debugging(
            &format!("[SeccompFilter] Explicit path provided but file not found: {path}"),
            None,
        );
    }

    // Check cache
    if let Ok(cache) = BPF_PATH_CACHE.lock() {
        if let Some(ref cached) = *cache {
            return cached.clone();
        }
    }

    let result = find_bpf_path();

    // Store in cache
    if let Ok(mut cache) = BPF_PATH_CACHE.lock() {
        *cache = Some(result.clone());
    }

    result
}

fn find_bpf_path() -> Option<String> {
    let arch = get_vendor_architecture()?;

    // Check local paths
    for bpf_path in get_local_seccomp_paths("unix-block.bpf") {
        if bpf_path.exists() {
            let path_str = bpf_path.to_string_lossy().to_string();
            log_for_debugging(
                &format!("[SeccompFilter] Found pre-generated BPF filter: {path_str} ({arch})"),
                None,
            );
            return Some(path_str);
        }
    }

    log_for_debugging(
        &format!("[SeccompFilter] Pre-generated BPF filter not found ({arch})"),
        None,
    );
    None
}

/// Get the path to the apply-seccomp binary.
/// Results are cached after the first lookup (when no explicit path is given).
pub fn get_apply_seccomp_binary_path(explicit_path: Option<&str>) -> Option<String> {
    // Check explicit path first (bypass cache)
    if let Some(path) = explicit_path {
        if Path::new(path).exists() {
            log_for_debugging(
                &format!("[SeccompFilter] Using apply-seccomp binary from explicit path: {path}"),
                None,
            );
            return Some(path.to_string());
        }
        log_for_debugging(
            &format!("[SeccompFilter] Explicit path provided but file not found: {path}"),
            None,
        );
    }

    // Check cache
    if let Ok(cache) = APPLY_SECCOMP_CACHE.lock() {
        if let Some(ref cached) = *cache {
            return cached.clone();
        }
    }

    let result = find_apply_seccomp_binary();

    // Store in cache
    if let Ok(mut cache) = APPLY_SECCOMP_CACHE.lock() {
        *cache = Some(result.clone());
    }

    result
}

fn find_apply_seccomp_binary() -> Option<String> {
    let arch = get_vendor_architecture()?;

    // Check local paths
    for binary_path in get_local_seccomp_paths("apply-seccomp") {
        if binary_path.exists() {
            let path_str = binary_path.to_string_lossy().to_string();
            log_for_debugging(
                &format!("[SeccompFilter] Found apply-seccomp binary: {path_str} ({arch})"),
                None,
            );
            return Some(path_str);
        }
    }

    log_for_debugging(
        &format!("[SeccompFilter] apply-seccomp binary not found ({arch})"),
        None,
    );
    None
}

/// Generate (locate) a seccomp filter path.
pub fn generate_seccomp_filter(explicit_bpf_path: Option<&str>) -> Option<String> {
    let path = get_pre_generated_bpf_path(explicit_bpf_path);
    if path.is_some() {
        log_for_debugging("[SeccompFilter] Using pre-generated BPF filter", None);
    } else {
        log_for_debugging(
            "[SeccompFilter] Pre-generated BPF filter not available for this architecture",
            Some("error"),
        );
    }
    path
}

/// Clean up a seccomp filter file (no-op for pre-generated files).
pub fn cleanup_seccomp_filter(_filter_path: &str) {
    // No-op: pre-generated BPF files are never cleaned up
}
