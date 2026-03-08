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
