use std::path::Path;

use crate::utils::debug::log_for_debugging;
use crate::utils::path::normalize_path_for_sandbox;

/// Check if a path pattern contains glob characters.
pub fn contains_glob_chars(path_pattern: &str) -> bool {
    path_pattern.contains('*')
        || path_pattern.contains('?')
        || path_pattern.contains('[')
        || path_pattern.contains(']')
}

/// Convert a glob pattern to a regular expression string.
///
/// Implements gitignore-style pattern matching:
/// - `*` matches any characters except `/`
/// - `**` matches any characters including `/`
/// - `?` matches any single character except `/`
/// - `[abc]` matches any character in the set
pub fn glob_to_regex(glob_pattern: &str) -> String {
    let mut result = String::from("^");

    // Escape regex special characters (except glob chars * ? [ ])
    // Backslash MUST be first to avoid double-escaping
    let escaped = glob_pattern
        .replace('\\', "\\\\")
        .replace('.', "\\.")
        .replace('^', "\\^")
        .replace('$', "\\$")
        .replace('+', "\\+")
        .replace('{', "\\{")
        .replace('}', "\\}")
        .replace('(', "\\(")
        .replace(')', "\\)")
        .replace('|', "\\|");

    // Handle unclosed brackets — escape them
    let mut working = escaped;
    // Simple heuristic: if there's a [ without a matching ], escape the [
    let mut i = 0;
    let chars: Vec<char> = working.chars().collect();
    let mut fixed = String::new();
    while i < chars.len() {
        if chars[i] == '[' {
            // Look for matching ]
            if let Some(j) = chars[i + 1..].iter().position(|&c| c == ']') {
                // Found matching ], keep the bracket expression
                let bracket_end = i + 1 + j + 1;
                for c in &chars[i..bracket_end] {
                    fixed.push(*c);
                }
                i = bracket_end;
            } else {
                // No matching ], escape the [
                fixed.push_str("\\[");
                i += 1;
            }
        } else {
            fixed.push(chars[i]);
            i += 1;
        }
    }
    working = fixed;

    // Convert glob patterns to regex (order matters — ** before *)
    // Use placeholders first
    working = working.replace("**/", "__GLOBSTAR_SLASH__");
    working = working.replace("**", "__GLOBSTAR__");
    working = working.replace('*', "[^/]*");
    working = working.replace('?', "[^/]");

    // Restore placeholders
    working = working.replace("__GLOBSTAR_SLASH__", "(.*/)?");
    working = working.replace("__GLOBSTAR__", ".*");

    result.push_str(&working);
    result.push('$');
    result
}

/// Expand a glob pattern into concrete file paths (Linux only).
/// Resolves the static directory prefix, lists files recursively,
/// and filters using glob_to_regex().
pub fn expand_glob_pattern(glob_path: &str) -> Vec<String> {
    let normalized_pattern = normalize_path_for_sandbox(glob_path);

    // Extract the static directory prefix before any glob characters
    let static_prefix: String = normalized_pattern
        .split(&['*', '?', '[', ']'][..])
        .next()
        .unwrap_or("")
        .to_string();

    if static_prefix.is_empty() || static_prefix == "/" {
        log_for_debugging(
            &format!("[Sandbox] Glob pattern too broad, skipping: {glob_path}"),
            None,
        );
        return vec![];
    }

    // Get the base directory
    let base_dir = if static_prefix.ends_with('/') {
        &static_prefix[..static_prefix.len() - 1]
    } else {
        Path::new(&static_prefix)
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or("")
    };

    if !Path::new(base_dir).exists() {
        log_for_debugging(
            &format!("[Sandbox] Base directory for glob does not exist: {base_dir}"),
            None,
        );
        return vec![];
    }

    // Build regex from the normalized glob pattern
    let regex_str = glob_to_regex(&normalized_pattern);
    let regex = match regex::Regex::new(&regex_str) {
        Ok(r) => r,
        Err(e) => {
            log_for_debugging(
                &format!("[Sandbox] Invalid glob regex: {e}"),
                Some("error"),
            );
            return vec![];
        }
    };

    // Recursively walk the directory
    let mut results = Vec::new();
    fn walk_dir(dir: &Path, regex: &regex::Regex, results: &mut Vec<String>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let path_str = path.to_string_lossy().to_string();
                if regex.is_match(&path_str) {
                    results.push(path_str.clone());
                }
                if path.is_dir() {
                    walk_dir(&path, regex, results);
                }
            }
        }
    }

    walk_dir(Path::new(base_dir), &regex, &mut results);
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_glob_chars() {
        assert!(contains_glob_chars("*.txt"));
        assert!(contains_glob_chars("file?.txt"));
        assert!(contains_glob_chars("[abc]"));
        assert!(!contains_glob_chars("file.txt"));
        assert!(!contains_glob_chars("/path/to/file"));
    }

    #[test]
    fn test_glob_to_regex_star() {
        let regex = glob_to_regex("*.txt");
        let re = regex::Regex::new(&regex).unwrap();
        assert!(re.is_match("file.txt"));
        assert!(re.is_match("doc.txt"));
        assert!(!re.is_match("dir/file.txt"));
    }

    #[test]
    fn test_glob_to_regex_globstar() {
        let regex = glob_to_regex("**/*.js");
        let re = regex::Regex::new(&regex).unwrap();
        assert!(re.is_match("file.js"));
        assert!(re.is_match("src/file.js"));
        assert!(re.is_match("src/nested/file.js"));
    }

    #[test]
    fn test_glob_to_regex_question() {
        let regex = glob_to_regex("file?.txt");
        let re = regex::Regex::new(&regex).unwrap();
        assert!(re.is_match("file1.txt"));
        assert!(re.is_match("fileA.txt"));
        assert!(!re.is_match("file12.txt"));
    }

    #[test]
    fn test_glob_to_regex_git_subtree() {
        let regex = glob_to_regex(".git/**");
        let re = regex::Regex::new(&regex).unwrap();
        assert!(re.is_match(".git/config"));
        assert!(re.is_match(".git/hooks/pre-commit"));
    }

    #[test]
    fn test_glob_to_regex_bracket_expression() {
        let regex = glob_to_regex("[abc].txt");
        let re = regex::Regex::new(&regex).unwrap();
        assert!(re.is_match("a.txt"));
        assert!(re.is_match("b.txt"));
        assert!(!re.is_match("d.txt"));
    }

    #[test]
    fn test_glob_to_regex_unclosed_bracket() {
        // Unclosed brackets should be escaped, not cause regex error
        let regex = glob_to_regex("file[.txt");
        let re = regex::Regex::new(&regex);
        assert!(re.is_ok());
    }

    #[test]
    fn test_glob_to_regex_double_star_slash() {
        let regex = glob_to_regex("src/**/*.rs");
        let re = regex::Regex::new(&regex).unwrap();
        assert!(re.is_match("src/main.rs"));
        assert!(re.is_match("src/utils/path.rs"));
        assert!(re.is_match("src/deep/nested/file.rs"));
    }

    #[test]
    fn test_glob_to_regex_dots_escaped() {
        let regex = glob_to_regex("file.txt");
        let re = regex::Regex::new(&regex).unwrap();
        assert!(re.is_match("file.txt"));
        assert!(!re.is_match("fileatxt")); // dot should not match arbitrary char
    }

    #[test]
    fn test_expand_glob_pattern_nonexistent_dir() {
        let results = expand_glob_pattern("/nonexistent_dir_xyz_123/**/*.txt");
        assert!(results.is_empty());
    }

    #[test]
    fn test_expand_glob_pattern_real_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "content").unwrap();

        let pattern = format!("{}/*.txt", dir.path().to_string_lossy());
        let results = expand_glob_pattern(&pattern);
        assert!(
            results.iter().any(|r| r.ends_with("test.txt")),
            "Expected test.txt in results: {results:?}"
        );
    }
}
