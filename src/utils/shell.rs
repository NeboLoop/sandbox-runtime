/// Quote a string for safe use in a POSIX shell command.
/// Wraps the string in single quotes, escaping internal single quotes.
pub fn shell_quote(s: &str) -> String {
    shell_escape::escape(s.into()).to_string()
}

/// Quote multiple arguments and join with spaces.
pub fn shell_quote_join(args: &[&str]) -> String {
    args.iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_quote_simple() {
        assert_eq!(shell_quote("hello"), "hello");
    }

    #[test]
    fn test_shell_quote_spaces() {
        let quoted = shell_quote("hello world");
        assert!(quoted.contains("hello") && quoted.contains("world"));
    }

    #[test]
    fn test_shell_quote_special_chars() {
        let quoted = shell_quote("it's");
        // Should escape the single quote
        assert!(!quoted.contains("it's") || quoted.starts_with('\''));
    }

    #[test]
    fn test_shell_quote_empty_string() {
        let quoted = shell_quote("");
        // Empty string should be quoted to preserve it as an argument
        assert!(!quoted.is_empty() || quoted == "''");
    }

    #[test]
    fn test_shell_quote_newlines() {
        let quoted = shell_quote("hello\nworld");
        // Newline should be escaped or quoted
        assert!(quoted.len() > "hello\nworld".len() || quoted.contains('\''));
    }

    #[test]
    fn test_shell_quote_backticks() {
        let quoted = shell_quote("echo `whoami`");
        // Backticks should be escaped
        assert!(quoted.contains('\'') || quoted.contains('\\'));
    }

    #[test]
    fn test_shell_quote_semicolons() {
        let quoted = shell_quote("cmd1; cmd2");
        // Semicolons should be escaped
        assert!(quoted.contains('\'') || quoted.contains('\\'));
    }

    #[test]
    fn test_shell_quote_join() {
        let result = shell_quote_join(&["echo", "hello world", "foo"]);
        assert!(result.contains("echo"));
        assert!(result.contains("hello"));
        assert!(result.contains("foo"));
        // Should have spaces between args
        let parts: Vec<&str> = result.split_whitespace().collect();
        assert!(parts.len() >= 3);
    }
}
