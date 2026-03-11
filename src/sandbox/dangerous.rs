/// Dangerous files that should be protected from writes.
/// These files can be used for code execution or data exfiltration.
pub const DANGEROUS_FILES: &[&str] = &[
    ".gitconfig",
    ".gitmodules",
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
    ".profile",
    ".ripgreprc",
    ".mcp.json",
];

/// Dangerous directories that should be protected from writes.
const DANGEROUS_DIRECTORIES: &[&str] = &[".git", ".vscode", ".idea"];

/// Get the list of dangerous directories to deny writes to.
/// Excludes `.git` since we need it writable for git operations —
/// instead we block specific paths within `.git` (hooks and config).
pub fn get_dangerous_directories() -> Vec<String> {
    let mut dirs: Vec<String> = DANGEROUS_DIRECTORIES
        .iter()
        .filter(|d| **d != ".git")
        .map(|d| d.to_string())
        .collect();
    dirs.push(".nebo/commands".to_string());
    dirs.push(".nebo/agents".to_string());
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dangerous_files_contains_bashrc() {
        assert!(DANGEROUS_FILES.contains(&".bashrc"));
    }

    #[test]
    fn test_dangerous_files_contains_gitconfig() {
        assert!(DANGEROUS_FILES.contains(&".gitconfig"));
    }

    #[test]
    fn test_dangerous_files_contains_mcp_json() {
        assert!(DANGEROUS_FILES.contains(&".mcp.json"));
    }

    #[test]
    fn test_dangerous_files_contains_shell_profiles() {
        assert!(DANGEROUS_FILES.contains(&".bash_profile"));
        assert!(DANGEROUS_FILES.contains(&".zshrc"));
        assert!(DANGEROUS_FILES.contains(&".zprofile"));
        assert!(DANGEROUS_FILES.contains(&".profile"));
    }

    #[test]
    fn test_dangerous_directories_excludes_git() {
        let dirs = get_dangerous_directories();
        assert!(!dirs.contains(&".git".to_string()));
    }

    #[test]
    fn test_dangerous_directories_includes_vscode() {
        let dirs = get_dangerous_directories();
        assert!(dirs.contains(&".vscode".to_string()));
    }

    #[test]
    fn test_dangerous_directories_includes_idea() {
        let dirs = get_dangerous_directories();
        assert!(dirs.contains(&".idea".to_string()));
    }

    #[test]
    fn test_dangerous_directories_includes_nebo_paths() {
        let dirs = get_dangerous_directories();
        assert!(dirs.contains(&".nebo/commands".to_string()));
        assert!(dirs.contains(&".nebo/agents".to_string()));
    }
}
