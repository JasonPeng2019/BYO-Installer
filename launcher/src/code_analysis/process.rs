//! Platform-specific owned processes.
#[cfg(windows)]
#[path = "process_windows.rs"]
mod platform;
#[cfg(unix)]
#[path = "process_posix.rs"]
mod platform;
pub(super) use platform::run_owned;

// Acceptance observation only. No production process or cleanup rule changes.
#[cfg(test)]
#[macro_export]
macro_rules! final_child_receipt {
    ($kind:expr, $details:expr) => {
        $crate::final_child_receipt!($kind, $details, b"", b"")
    };
    ($kind:expr, $details:expr, $stdout:expr, $stderr:expr) => {{
        if let Some(directory) = std::env::var_os("BYO_FINAL_CHILD_EVIDENCE") {
            use sha2::Digest;
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                .to_string();
            let stem = format!("{}-{}-{:032x}", now, std::process::id(), rand::random::<u128>());
            let stdout = directory.join(format!("{stem}.stdout.log"));
            let stderr = directory.join(format!("{stem}.stderr.log"));
            let out: &[u8] = $stdout;
            let err: &[u8] = $stderr;
            std::fs::write(&stdout, out).unwrap();
            std::fs::write(&stderr, err).unwrap();
            let executable = std::env::current_exe().unwrap();
            let record = serde_json::json!({
                "schema": "fr05-rust-child/v1", "kind": $kind,
                "pid": std::process::id(), "at_unix_nanos": now,
                "executable": executable,
                "executable_sha256": hex::encode(sha2::Sha256::digest(std::fs::read(&executable).unwrap())),
                "details": $details, "stdout": stdout, "stderr": stderr,
                "stdout_sha256": hex::encode(sha2::Sha256::digest(out)),
                "stderr_sha256": hex::encode(sha2::Sha256::digest(err)),
            });
            std::fs::write(directory.join(format!("{stem}.json")), serde_json::to_vec_pretty(&record).unwrap()).unwrap();
        }
    }};
}
