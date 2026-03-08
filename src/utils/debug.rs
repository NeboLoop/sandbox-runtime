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
