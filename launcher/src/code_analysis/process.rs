//! Platform-specific owned processes.
#[cfg(windows)]
#[path = "process_windows.rs"]
mod platform;
#[cfg(unix)]
#[path = "process_posix.rs"]
mod platform;
pub(super) use platform::run_owned;
