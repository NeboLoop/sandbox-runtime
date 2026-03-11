use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    MacOS,
    Linux,
    Windows,
    Unknown,
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Platform::MacOS => write!(f, "macos"),
            Platform::Linux => write!(f, "linux"),
            Platform::Windows => write!(f, "windows"),
            Platform::Unknown => write!(f, "unknown"),
        }
    }
}

/// Detect the current platform.
pub fn get_platform() -> Platform {
    if cfg!(target_os = "macos") {
        Platform::MacOS
    } else if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else {
        Platform::Unknown
    }
}

/// Get the WSL version (1 or 2+) if running in WSL.
/// Returns None if not running in WSL.
#[cfg(target_os = "linux")]
pub fn get_wsl_version() -> Option<String> {
    let proc_version = std::fs::read_to_string("/proc/version").ok()?;

    // Check for explicit WSL version markers (e.g., "WSL2", "WSL3", etc.)
    let re = regex::Regex::new(r"(?i)WSL(\d+)").ok()?;
    if let Some(caps) = re.captures(&proc_version) {
        if let Some(ver) = caps.get(1) {
            return Some(ver.as_str().to_string());
        }
    }

    // If no explicit WSL version but contains Microsoft, assume WSL1
    if proc_version.to_lowercase().contains("microsoft") {
        return Some("1".to_string());
    }

    None
}

#[cfg(not(target_os = "linux"))]
pub fn get_wsl_version() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn test_get_platform_macos() {
        assert_eq!(get_platform(), Platform::MacOS);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_get_platform_linux() {
        assert_eq!(get_platform(), Platform::Linux);
    }

    #[test]
    fn test_display_macos() {
        assert_eq!(format!("{}", Platform::MacOS), "macos");
    }

    #[test]
    fn test_display_linux() {
        assert_eq!(format!("{}", Platform::Linux), "linux");
    }

    #[test]
    fn test_display_windows() {
        assert_eq!(format!("{}", Platform::Windows), "windows");
    }

    #[test]
    fn test_display_unknown() {
        assert_eq!(format!("{}", Platform::Unknown), "unknown");
    }

    #[test]
    fn test_partial_eq() {
        assert_eq!(Platform::MacOS, Platform::MacOS);
        assert_ne!(Platform::MacOS, Platform::Linux);
        assert_ne!(Platform::Linux, Platform::Windows);
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_get_wsl_version_returns_none_on_non_linux() {
        assert!(get_wsl_version().is_none());
    }
}
