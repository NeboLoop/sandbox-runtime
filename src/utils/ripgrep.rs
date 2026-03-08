use std::process::Command;

use crate::config::RipgrepConfig;

/// Run ripgrep with given arguments and return matching lines.
pub fn rip_grep(
    args: &[&str],
    cwd: &str,
    config: &RipgrepConfig,
) -> Result<Vec<String>, String> {
    let mut cmd = Command::new(&config.command);

    // Add prefix args from config (e.g., ["--ripgrep"])
    if let Some(ref prefix_args) = config.args {
        for arg in prefix_args {
            cmd.arg(arg);
        }
    }

    for arg in args {
        cmd.arg(arg);
    }

    cmd.current_dir(cwd);

    let output = cmd.output().map_err(|e| format!("ripgrep failed to start: {e}"))?;

    // Exit code 0 = matches found
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout
            .trim()
            .split('\n')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect())
    }
    // Exit code 1 = no matches (normal)
    else if output.status.code() == Some(1) {
        Ok(vec![])
    }
    // Other exit codes = error
    else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "ripgrep failed with exit code {:?}: {}",
            output.status.code(),
            stderr
        ))
    }
}
