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
            let image = std::fs::metadata(&executable).unwrap();
            let modified = image.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos().to_string();
            // A parent declares an image ephemeral only when its tested cleanup
            // deletes that image before collection. Only then is the actual
            // running image measured here; a changed image keeps no digest.
            let ephemeral = std::env::var_os("BYO_FINAL_CHILD_EPHEMERAL_IMAGE")
                .and_then(|declared| std::fs::canonicalize(declared).ok())
                .is_some_and(|declared| std::fs::canonicalize(&executable).ok() == Some(declared));
            let (image_sha256, hash_method) = if ephemeral {
                let digest = hex::encode(sha2::Sha256::digest(std::fs::read(&executable).unwrap()));
                let after = std::fs::metadata(&executable).unwrap();
                let stable = after.len() == image.len() && after.modified().unwrap() == image.modified().unwrap();
                (stable.then_some(digest), "child-at-receipt-ephemeral-image")
            } else {
                (None, "collector-after-command")
            };
            let record = serde_json::json!({
                "schema": "fr05-rust-child/v1", "kind": $kind,
                "pid": std::process::id(), "at_unix_nanos": now,
                "executable": executable,
                // Hashing the large debug image inside each timed fixture can
                // consume its behavioral deadline. The collector hashes once
                // after the command, checks these image facts, and preserves
                // this raw pending-hash receipt alongside its measured result.
                // A declared ephemeral image is measured above instead.
                "executable_sha256": image_sha256,
                "executable_hash_method": hash_method,
                "executable_bytes": image.len(), "executable_modified_unix_nanos": modified,
                "details": $details, "stdout": stdout, "stderr": stderr,
                "stdout_sha256": hex::encode(sha2::Sha256::digest(out)),
                "stderr_sha256": hex::encode(sha2::Sha256::digest(err)),
            });
            std::fs::write(directory.join(format!("{stem}.json")), serde_json::to_vec_pretty(&record).unwrap()).unwrap();
        }
    }};
}
