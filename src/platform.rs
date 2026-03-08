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
