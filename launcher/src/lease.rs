use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sysinfo::{Pid, ProcessesToUpdate, System};

use crate::manifest::write_json;
use crate::paths::{ensure_private_directory, ProductPaths};

const MAX_LEASE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLease {
    pub schema: u32,
    pub runtime_version: String,
    pub pid: u32,
    pub process_start_identity: String,
    pub project_id: String,
    pub created_at: String,
}

#[derive(Debug)]
pub struct LeaseStatus {
    pub path: PathBuf,
    pub lease: RuntimeLease,
    pub live: bool,
}

pub struct RuntimeLeaseGuard {
    path: PathBuf,
}

impl RuntimeLeaseGuard {
    #[cfg(test)]
    pub fn acquire(paths: &ProductPaths, runtime_version: &str, project_id: &str) -> Result<Self> {
        let lock = crate::install::InstallLock::acquire(paths)?;
        Self::acquire_locked(paths, runtime_version, project_id, &lock)
    }

    pub fn acquire_locked(
        paths: &ProductPaths,
        runtime_version: &str,
        project_id: &str,
        _lock: &crate::install::InstallLock,
    ) -> Result<Self> {
        let root = paths.leases();
        ensure_private_directory(&root)?;
        let pid = std::process::id();
        let process_start_identity =
            process_start_identity(pid).context("launcher process identity is unavailable")?;
        let lease = RuntimeLease {
            schema: 1,
            runtime_version: runtime_version.to_string(),
            pid,
            process_start_identity,
            project_id: project_id.to_string(),
            created_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        };
        let path = root.join(format!("lease-{pid}-{:032x}.json", rand::random::<u128>()));
        write_json(&path, &lease)?;
        Ok(Self { path })
    }
}

impl Drop for RuntimeLeaseGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn process_start_identity(pid: u32) -> Option<String> {
    let selected = Pid::from_u32(pid);
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::Some(&[selected]), true);
    system
        .process(selected)
        .map(|process| process.start_time().to_string())
}

fn load_lease(path: &Path) -> Result<RuntimeLease> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_LEASE_BYTES
    {
        bail!("lease is not a bounded regular file");
    }
    let lease: RuntimeLease =
        serde_json::from_slice(&std::fs::read(path)?).context("lease JSON is invalid")?;
    if lease.schema != 1
        || lease.runtime_version.is_empty()
        || lease.project_id.is_empty()
        || lease.process_start_identity.is_empty()
    {
        bail!("lease fields are invalid");
    }
    Ok(lease)
}

fn is_atomic_lease_temporary(name: &str) -> bool {
    let Some((lease, nonce)) = name
        .strip_prefix(".lease-")
        .and_then(|value| value.split_once(".json.tmp-"))
    else {
        return false;
    };
    let Some((pid, identity)) = lease.split_once('-') else {
        return false;
    };
    !pid.is_empty()
        && pid.parse::<u32>().is_ok()
        && pid.bytes().all(|value| value.is_ascii_digit())
        && identity.len() == 32
        && identity.bytes().all(|value| value.is_ascii_hexdigit())
        && !nonce.is_empty()
        && nonce.bytes().all(|value| value.is_ascii_digit())
        && nonce.parse::<u64>().is_ok()
}

pub fn inspect(paths: &ProductPaths, remove_stale: bool) -> Result<Vec<LeaseStatus>> {
    let root = paths.leases();
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut statuses = Vec::new();
    for entry in std::fs::read_dir(&root)? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(is_atomic_lease_temporary)
        {
            // A killed atomic writer can leave this exact uncommitted name.
            // Never hide malformed actual lease records or delete live staging.
            continue;
        }
        let lease = load_lease(&path)
            .with_context(|| format!("invalid runtime lease {}", path.display()))?;
        let live = process_start_identity(lease.pid).as_deref()
            == Some(lease.process_start_identity.as_str());
        if !live && remove_stale {
            std::fs::remove_file(&path)?;
        }
        statuses.push(LeaseStatus { path, lease, live });
    }
    statuses.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(statuses)
}

pub fn ensure_project_inactive(paths: &ProductPaths, project_id: &str) -> Result<()> {
    let active: Vec<_> = inspect(paths, true)?
        .into_iter()
        .filter(|status| status.live && status.lease.project_id == project_id)
        .collect();
    if !active.is_empty() {
        bail!("project has an active MCP runtime lease; stop its MCP session before updating");
    }
    Ok(())
}

pub fn ensure_runtime_inactive(paths: &ProductPaths) -> Result<()> {
    if inspect(paths, true)?.iter().any(|status| status.live) {
        bail!("an MCP/runtime lease is active; stop BYO sessions before updating or rolling back");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_temporaries_do_not_hide_malformed_actual_records() {
        let root =
            std::env::temp_dir().join(format!("byo-lease-debris-{:032x}", rand::random::<u128>()));
        let paths = ProductPaths::from_install_dir(&root).unwrap();
        std::fs::create_dir_all(paths.leases()).unwrap();
        let debris = paths
            .leases()
            .join(".lease-123-0123456789abcdef0123456789abcdef.json.tmp-456");
        std::fs::write(&debris, b"unfinished").unwrap();
        let guard = RuntimeLeaseGuard::acquire(&paths, "test", "project").unwrap();
        assert_eq!(inspect(&paths, true).unwrap().len(), 1);
        assert!(debris.is_file());
        let malformed = paths
            .leases()
            .join("lease-123-0123456789abcdef0123456789abcdef.json");
        std::fs::write(&malformed, b"invalid").unwrap();
        assert!(inspect(&paths, false)
            .unwrap_err()
            .to_string()
            .contains("invalid runtime lease"));
        assert!(!is_atomic_lease_temporary(
            ".lease-123-0123456789abcdef0123456789abcdef.json.tmp-wrong"
        ));
        assert!(!is_atomic_lease_temporary(".lease-123-short.json.tmp-456"));
        drop(guard);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn current_process_identity_is_stable() {
        let pid = std::process::id();
        let first = process_start_identity(pid).expect("current process");
        let second = process_start_identity(pid).expect("current process");
        assert_eq!(first, second);
    }

    #[test]
    fn atomic_write_is_available_for_lease_storage() {
        let root =
            std::env::temp_dir().join(format!("byo-lease-test-{:032x}", rand::random::<u128>()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("probe");
        crate::manifest::atomic_write(&path, b"ok").unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"ok");
        std::fs::remove_dir_all(root).unwrap();
    }
}
