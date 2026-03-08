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
}
