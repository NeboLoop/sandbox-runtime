pub mod config;
pub mod error;
pub mod manager;
pub mod platform;
pub mod proxy;
pub mod sandbox;
pub mod schemas;
pub mod utils;

// Re-export primary types
pub use config::SandboxRuntimeConfig;
pub use error::{Result, SandboxError};
pub use manager::SandboxManager;
pub use platform::{get_platform, get_wsl_version, Platform};
pub use sandbox::violation::{SandboxViolationEvent, SandboxViolationStore};
pub use schemas::{
    FsReadRestrictionConfig, FsWriteRestrictionConfig, NetworkHostPattern,
    NetworkRestrictionConfig, SandboxAskCallback,
};
pub use utils::command::get_default_write_paths;
