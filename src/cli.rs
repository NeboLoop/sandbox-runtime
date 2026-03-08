#[cfg(feature = "cli")]
use clap::Parser;

#[cfg(feature = "cli")]
#[derive(Parser)]
#[command(name = "nebo", about = "Run commands in a sandbox with network and filesystem restrictions")]
struct Cli {
    /// Command to run in the sandbox
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,

    /// Path to config file (default: ~/.nebo-settings.json)
    #[arg(short, long)]
    settings: Option<String>,

    /// Run command string directly (like sh -c)
    #[arg(short = 'c')]
    command_string: Option<String>,

    /// Read config updates from file descriptor (JSON lines protocol)
    #[arg(long = "control-fd")]
    control_fd: Option<i32>,
}

#[cfg(feature = "cli")]
#[tokio::main]
async fn main() {
    use sandbox_runtime::{SandboxManager, SandboxRuntimeConfig};
    use sandbox_runtime::utils::debug::log_for_debugging;
    use std::process::Command;

    let cli = Cli::parse();

    if cli.debug {
        std::env::set_var("NEBO_DEBUG", "1");
    }

    // Load config
    let config_path = cli.settings.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_default()
            .join(".nebo-settings.json")
            .to_string_lossy()
            .to_string()
    });

    let config = SandboxRuntimeConfig::load_from_file(std::path::Path::new(&config_path))
        .ok()
        .flatten()
        .unwrap_or_else(SandboxRuntimeConfig::default_config);

    // Initialize sandbox
    let mut manager = SandboxManager::new();
    if let Err(e) = manager.initialize(config.clone(), None, false).await {
        eprintln!("Error initializing sandbox: {e}");
        std::process::exit(1);
    }

    // Set up control fd for dynamic config updates via a shared config reference
    // The thread reads JSON lines from the fd and updates the shared config
    let shared_config = std::sync::Arc::new(std::sync::Mutex::new(config));
    if let Some(fd) = cli.control_fd {
        let config_ref = shared_config.clone();

        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            use std::os::unix::io::FromRawFd;

            // Safety: fd is provided by the parent process
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            let reader = BufReader::new(file);

            for line in reader.lines().map_while(Result::ok) {
                if let Ok(Some(new_config)) = SandboxRuntimeConfig::load_from_string(&line) {
                    log_for_debugging(
                        &format!("Config updated from control fd: {line}"),
                        None,
                    );
                    *config_ref.lock().unwrap() = new_config;
                } else if !line.trim().is_empty() {
                    log_for_debugging(
                        &format!("Invalid config on control fd (ignored): {line}"),
                        None,
                    );
                }
            }
        });

        log_for_debugging(
            &format!("Listening for config updates on fd {fd}"),
            None,
        );
    }

    // Determine command
    let command = if let Some(cmd) = cli.command_string {
        cmd
    } else if !cli.command.is_empty() {
        cli.command.join(" ")
    } else {
        eprintln!("Error: No command specified. Use -c <command> or provide command arguments.");
        std::process::exit(1);
    };

    // Apply latest config (may have been updated via control-fd)
    {
        let latest = shared_config.lock().unwrap().clone();
        manager.update_config(latest);
    }

    // Wrap and execute
    let sandboxed = match manager.wrap_with_sandbox(&command, None).await {
        Ok(cmd) => cmd,
        Err(e) => {
            eprintln!("Error wrapping command: {e}");
            std::process::exit(1);
        }
    };

    let mut child = Command::new("sh")
        .arg("-c")
        .arg(&sandboxed)
        .spawn()
        .unwrap_or_else(|e| {
            eprintln!("Failed to execute command: {e}");
            std::process::exit(1);
        });

    // Forward signals to child process
    let child_id = child.id();
    ctrlc::set_handler(move || {
        // Send SIGINT to child process group
        unsafe {
            libc::kill(child_id as i32, libc::SIGINT);
        }
    })
    .ok();

    let status = child.wait().unwrap_or_else(|e| {
        eprintln!("Failed to wait for command: {e}");
        std::process::exit(1);
    });

    // Cleanup bwrap mount points
    manager.cleanup_after_command();

    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(not(feature = "cli"))]
fn main() {
    eprintln!("CLI feature not enabled. Build with: cargo build --features cli");
    std::process::exit(1);
}
