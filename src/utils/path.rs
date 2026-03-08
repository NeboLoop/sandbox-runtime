use std::path::{Path, PathBuf};

use crate::utils::glob::contains_glob_chars;

/// Normalize case for comparison (prevents case-sensitivity bypasses).
pub fn normalize_case_for_comparison(path_str: &str) -> String {
    path_str.to_lowercase()
}

/// Check if a symlink resolution crosses expected path boundaries.
pub fn is_symlink_outside_boundary(original_path: &str, resolved_path: &str) -> bool {
    let normalized_original = PathBuf::from(original_path)
        .components()
        .collect::<PathBuf>()
        .to_string_lossy()
        .to_string();
    let normalized_resolved = PathBuf::from(resolved_path)
        .components()
        .collect::<PathBuf>()
        .to_string_lossy()
        .to_string();

    // Same path after normalization — OK
    if normalized_resolved == normalized_original {
        return false;
    }

    // Handle macOS /tmp -> /private/tmp canonical resolution
    if (normalized_original == "/tmp" || normalized_original.starts_with("/tmp/"))
        && normalized_resolved == format!("/private{}", normalized_original)
    {
        return false;
    }
    if (normalized_original == "/var" || normalized_original.starts_with("/var/"))
        && normalized_resolved == format!("/private{}", normalized_original)
    {
        return false;
    }
    if (normalized_original == "/private/tmp" || normalized_original.starts_with("/private/tmp/"))
        && normalized_resolved == normalized_original
    {
        return false;
    }
    if (normalized_original == "/private/var" || normalized_original.starts_with("/private/var/"))
        && normalized_resolved == normalized_original
    {
        return false;
    }

    // If resolved path is "/" it's outside expected boundaries
    if normalized_resolved == "/" {
        return true;
    }

    // If resolved path is very short (single component), likely outside boundaries
    let resolved_parts: Vec<&str> = normalized_resolved
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    if resolved_parts.len() <= 1 {
        return true;
    }

    // If original path starts with resolved path, the resolved path is an ancestor
    if normalized_original.starts_with(&format!("{}/", normalized_resolved)) {
        return true;
    }

    // Also check canonical form for macOS
    let canonical_original =
        if normalized_original.starts_with("/tmp/") || normalized_original.starts_with("/var/") {
            format!("/private{}", normalized_original)
        } else {
            normalized_original.clone()
        };

    if canonical_original != normalized_original
        && canonical_original.starts_with(&format!("{}/", normalized_resolved))
    {
        return true;
    }

    // STRICT CHECK: Only allow resolutions within expected path tree
    let resolved_starts_with_original =
        normalized_resolved.starts_with(&format!("{}/", normalized_original));
    let resolved_starts_with_canonical = canonical_original != normalized_original
        && normalized_resolved.starts_with(&format!("{}/", canonical_original));
    let resolved_is_canonical =
        canonical_original != normalized_original && normalized_resolved == canonical_original;
    let resolved_is_same = normalized_resolved == normalized_original;

    if !resolved_is_same
        && !resolved_is_canonical
        && !resolved_starts_with_original
        && !resolved_starts_with_canonical
    {
        return true;
    }

    false
}

/// Normalize a path for use in sandbox configurations.
/// Handles tilde expansion, relative-to-absolute, symlink resolution, glob preservation.
pub fn normalize_path_for_sandbox(path_pattern: &str) -> String {
    let cwd = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("/"));
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"));

    let mut normalized = path_pattern.to_string();

    // Expand ~ to home directory
    if path_pattern == "~" {
        normalized = home.to_string_lossy().to_string();
    } else if let Some(rest) = path_pattern.strip_prefix("~/") {
        normalized = format!("{}/{}", home.display(), rest);
    } else if path_pattern.starts_with("./")
        || path_pattern.starts_with("../")
        || path_pattern == "."
        || path_pattern == ".."
        || !Path::new(path_pattern).is_absolute()
    {
        normalized = cwd.join(path_pattern)
            .components()
            .collect::<PathBuf>()
            .to_string_lossy()
            .to_string();
    }

    // For glob patterns, resolve symlinks for the directory portion only
    if contains_glob_chars(&normalized) {
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

            if let Ok(resolved) = std::fs::canonicalize(base_dir) {
                let resolved_str = resolved.to_string_lossy().to_string();
                if !is_symlink_outside_boundary(base_dir, &resolved_str) {
                    let suffix = &normalized[base_dir.len()..];
                    return format!("{}{}", resolved_str, suffix);
                }
            }
        }
        return normalized;
    }

    // Resolve symlinks to real paths
    if let Ok(resolved) = std::fs::canonicalize(&normalized) {
        let resolved_str = resolved.to_string_lossy().to_string();
        if !is_symlink_outside_boundary(&normalized, &resolved_str) {
            normalized = resolved_str;
        }
    }

    normalized
}

/// Remove trailing /** glob suffix from a path pattern.
pub fn remove_trailing_glob_suffix(path_pattern: &str) -> String {
    let stripped = regex::Regex::new(r"/\*\*$")
        .unwrap()
        .replace(path_pattern, "")
        .to_string();
    if stripped.is_empty() {
        "/".to_string()
    } else {
        stripped
    }
}

/// Get all ancestor directories for a path, up to (but not including) root.
pub fn get_ancestor_directories(path_str: &str) -> Vec<String> {
    let mut ancestors = Vec::new();
    let mut current = Path::new(path_str).parent();

    while let Some(p) = current {
        let p_str = p.to_string_lossy().to_string();
        if p_str == "/" || p_str == "." || p_str.is_empty() {
            break;
        }
        ancestors.push(p_str);
        current = p.parent();
    }

    ancestors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_trailing_glob_suffix() {
        assert_eq!(remove_trailing_glob_suffix("/home/user/**"), "/home/user");
        assert_eq!(remove_trailing_glob_suffix("/home/user"), "/home/user");
        assert_eq!(remove_trailing_glob_suffix("/**"), "/");
    }

    #[test]
    fn test_symlink_boundary_same_path() {
        assert!(!is_symlink_outside_boundary("/foo/bar", "/foo/bar"));
    }

    #[test]
    fn test_symlink_boundary_macos_tmp() {
        assert!(!is_symlink_outside_boundary(
            "/tmp/nebo",
            "/private/tmp/nebo"
        ));
    }

    #[test]
    fn test_symlink_boundary_root() {
        assert!(is_symlink_outside_boundary("/some/path", "/"));
    }

    #[test]
    fn test_symlink_boundary_ancestor() {
        assert!(is_symlink_outside_boundary("/tmp/nebo", "/tmp"));
    }

    #[test]
    fn test_ancestor_directories() {
        let ancestors = get_ancestor_directories("/private/tmp/test/file.txt");
        assert_eq!(
            ancestors,
            vec!["/private/tmp/test", "/private/tmp", "/private"]
        );
    }
}
