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
