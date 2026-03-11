/// Log debug messages when NEBO_DEBUG environment variable is set.
/// Outputs to stderr, matching the TypeScript version's behavior.
pub fn log_for_debugging(message: &str, level: Option<&str>) {
    if std::env::var("NEBO_DEBUG").is_err() {
        return;
    }

    let prefix = "[SandboxDebug]";
    match level.unwrap_or("info") {
        "error" => eprintln!("{prefix} ERROR: {message}"),
        "warn" => eprintln!("{prefix} WARN: {message}"),
        _ => eprintln!("{prefix} {message}"),
    }
}

/// Convenience macro for debug logging.
#[macro_export]
macro_rules! nebo_debug {
    ($msg:expr) => {
        $crate::utils::debug::log_for_debugging($msg, None)
    };
    ($msg:expr, $level:expr) => {
        $crate::utils::debug::log_for_debugging($msg, Some($level))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_panic_without_debug_env() {
        std::env::remove_var("NEBO_DEBUG");
        log_for_debugging("test message", None);
    }

    #[test]
    fn test_no_panic_with_debug_env() {
        std::env::set_var("NEBO_DEBUG", "1");
        log_for_debugging("test message", None);
        std::env::remove_var("NEBO_DEBUG");
    }

    #[test]
    fn test_works_with_error_and_warn_levels() {
        std::env::set_var("NEBO_DEBUG", "1");
        log_for_debugging("error message", Some("error"));
        log_for_debugging("warn message", Some("warn"));
        log_for_debugging("info message", Some("info"));
        std::env::remove_var("NEBO_DEBUG");
    }
}
