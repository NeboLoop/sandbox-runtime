use std::process::Command;

/// Find the path to an executable, similar to the `which` command.
pub fn which_sync(bin: &str) -> Option<String> {
    let output = Command::new("which")
        .arg(bin)
        .output()
        .ok()?;

    if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if path.is_empty() {
            None
        } else {
            Some(path)
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finds_sh() {
        let result = which_sync("sh");
        assert!(result.is_some());
        assert!(result.unwrap().contains("sh"));
    }

    #[test]
    fn test_finds_bash() {
        let result = which_sync("bash");
        assert!(result.is_some());
        assert!(result.unwrap().contains("bash"));
    }

    #[test]
    fn test_returns_none_for_nonexistent() {
        assert!(which_sync("nonexistent_binary_xyz_123").is_none());
    }

    #[test]
    fn test_returns_none_for_empty_string() {
        assert!(which_sync("").is_none());
    }
}
