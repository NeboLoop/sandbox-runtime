# sandbox-runtime

OS-level sandboxing for command execution. Uses **macOS Seatbelt** and **Linux bubblewrap + seccomp** to enforce filesystem and network restrictions on spawned processes.

## Features

- **Filesystem restrictions** — deny reads from sensitive paths, allow writes only to specific directories
- **Network restrictions** — allow/deny traffic by domain, with built-in HTTP and SOCKS proxy servers
- **MITM proxy support** — intercept and inspect traffic to specific domains
- **Violation tracking** — monitor and record sandbox violations in real time
- **Dynamic config updates** — update sandbox policy at runtime via a control file descriptor
- **Cross-platform** — macOS (Seatbelt profiles) and Linux (bubblewrap + seccomp BPF)

## Installation

### As a library

Add to your `Cargo.toml`:

```toml
[dependencies]
sandbox-runtime = "0.1"
```

### As a CLI

```sh
cargo build --features cli --release
```

This produces the `nebo` binary.

## Usage

### CLI

```sh
# Run a command in a sandbox
nebo -- ls -la

# Run a command string
nebo -c "echo hello && curl example.com"

# Use a custom settings file
nebo --settings ./my-config.json -c "npm install"

# Enable debug logging
nebo --debug -c "python script.py"

# Accept runtime config updates via file descriptor
nebo --control-fd 3 -c "long-running-process"
```

### Library

```rust
use sandbox_runtime::{SandboxManager, SandboxRuntimeConfig};

let config = SandboxRuntimeConfig::default_config();
let mut manager = SandboxManager::new();
manager.initialize(config, None, false).await?;

let sandboxed_cmd = manager.wrap_with_sandbox("ls -la", None).await?;
// Execute sandboxed_cmd via std::process::Command
```

## Configuration

Settings are loaded from `~/.nebo-settings.json` by default. Example:

```json
{
  "network": {
    "allowedDomains": ["example.com", "*.github.com"],
    "deniedDomains": ["evil.com"],
    "allowLocalBinding": true,
    "httpProxyPort": 8080,
    "socksProxyPort": 1080
  },
  "filesystem": {
    "denyRead": ["/etc/shadow", "/private/var"],
    "allowWrite": ["/tmp", "./build"],
    "denyWrite": ["/usr"]
  }
}
```

## Architecture

```
src/
├── cli.rs          # CLI entry point (nebo binary)
├── config.rs       # Configuration types and loading
├── schemas.rs      # Public restriction config types
├── manager.rs      # SandboxManager — main orchestrator
├── platform.rs     # Platform detection (macOS, Linux, WSL)
├── error.rs        # Error types
├── sandbox/
│   ├── macos.rs    # macOS Seatbelt sandbox profiles
│   ├── linux.rs    # Linux bubblewrap + network bridge
│   ├── seccomp.rs  # seccomp BPF filter generation
│   ├── violation.rs# Violation event tracking
│   └── dangerous.rs# Dangerous command detection
├── proxy/
│   ├── http.rs     # HTTP proxy server
│   ├── socks.rs    # SOCKS5 proxy server
│   └── filter.rs   # Domain pattern matching
└── utils/
    ├── command.rs   # Default write paths, command helpers
    ├── shell.rs     # Shell escaping utilities
    ├── glob.rs      # Glob pattern expansion
    ├── path.rs      # Path manipulation
    ├── which.rs     # Binary lookup
    ├── ripgrep.rs   # Ripgrep integration
    └── debug.rs     # Debug logging
```

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

Copyright 2026 NeboLoop, LLC
