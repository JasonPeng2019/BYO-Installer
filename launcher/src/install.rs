use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use fs2::FileExt;
use walkdir::WalkDir;

use crate::manifest::{
    retry_transient_io, sha256_file, verify_runtime, write_json, CurrentRuntime, ReleaseManifest,
};
use crate::paths::{ensure_private_directory, ProductPaths};

pub struct InstallLock {
    file: File,
}

impl InstallLock {
    pub fn acquire(paths: &ProductPaths) -> Result<Self> {
        ensure_private_directory(&paths.state)?;
        let path = paths.state.join("install.lock");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)?;
        file.try_lock_exclusive()
            .context("another BYO installation mutation is active")?;
        Ok(Self { file })
    }
}

impl Drop for InstallLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    for entry in WalkDir::new(source).follow_links(false) {
        let entry = entry?;
        let relative = entry.path().strip_prefix(source)?;
        let target = destination.join(relative);
        if entry.file_type().is_symlink() {
            bail!(
                "bundle contains a forbidden symlink: {}",
                relative.display()
            );
        }
        if entry.file_type().is_dir() {
            retry_transient_io(|| std::fs::create_dir_all(&target))
                .with_context(|| format!("failed to create {}", target.display()))?;
        } else if entry.file_type().is_file() {
            if let Some(parent) = target.parent() {
                retry_transient_io(|| std::fs::create_dir_all(parent))
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            retry_transient_io(|| std::fs::copy(entry.path(), &target))
                .with_context(|| format!("failed to copy runtime file to {}", target.display()))?;
        } else {
            bail!(
                "bundle contains a forbidden special entry: {}",
                relative.display()
            );
        }
    }
    Ok(())
}

fn write_if_changed(path: &Path, payload: &[u8]) -> Result<bool> {
    if std::fs::read(path).ok().as_deref() == Some(payload) {
        return Ok(false);
    }
    crate::manifest::atomic_write(path, payload)?;
    Ok(true)
}

fn portable_relative_path(path: &Path) -> Result<String> {
    let mut components = Vec::new();
    for component in path.components() {
        let std::path::Component::Normal(component) = component else {
            bail!("runtime path contains a non-relative component");
        };
        components.push(
            component
                .to_str()
                .context("runtime path is not valid UTF-8")?,
        );
    }
    if components.is_empty() {
        bail!("runtime path is empty");
    }
    Ok(components.join("/"))
}

fn set_runtime_permissions(runtime: &Path, manifest: &ReleaseManifest) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for file in &manifest.files {
            let mode = if file.executable { 0o700 } else { 0o600 };
            std::fs::set_permissions(
                runtime.join(&file.path),
                std::fs::Permissions::from_mode(mode),
            )?;
        }
        for metadata in ["release-manifest.json", "release-manifest.sig"] {
            let path = runtime.join(metadata);
            if path.is_file() {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        for entry in WalkDir::new(runtime).min_depth(0) {
            let entry = entry?;
            if entry.file_type().is_dir() {
                std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o700))?;
            }
        }
    }
    Ok(())
}

pub fn sidecar_path(runtime: &Path) -> PathBuf {
    runtime.join(if cfg!(windows) {
        "sidecar/byo-mcp-sidecar.exe"
    } else {
        "sidecar/byo-mcp-sidecar"
    })
}

pub fn launcher_path(runtime: &Path) -> PathBuf {
    runtime.join(if cfg!(windows) { "byo.exe" } else { "byo" })
}

pub fn sidecar_self_test(runtime: &Path) -> Result<()> {
    let executable = sidecar_path(runtime);
    let output = Command::new(&executable)
        .arg("self-test")
        .arg("--runtime-root")
        .arg(runtime)
        .arg("--launcher-version")
        .arg(env!("CARGO_PKG_VERSION"))
        .env("BYO_SIDECAR_COMPILED", "1")
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("failed to start {}", executable.display()))?;
    if !output.status.success() {
        bail!(
            "sidecar self-test failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("sidecar self-test output was invalid")?;
    if document["status"] != "passed"
        || document["sidecar_protocol"] != 1
        || document["worker_protocol"] != 1
        || document["workflow_protocol"] != 1
        || document["capsule_schema"] != 1
        || document["project_state_schema"] != 1
        || document["runtime_manifest_verified"] != true
        || document["version"] != env!("CARGO_PKG_VERSION")
    {
        bail!("sidecar self-test returned an incompatible result");
    }
    Ok(())
}

pub fn install_bundle(bundle: &Path, paths: &ProductPaths) -> Result<ReleaseManifest> {
    let _lock = InstallLock::acquire(paths)?;
    install_bundle_locked(bundle, paths)
}

pub(crate) fn install_bundle_locked(
    bundle: &Path,
    paths: &ProductPaths,
) -> Result<ReleaseManifest> {
    let bundle = bundle
        .canonicalize()
        .with_context(|| format!("bundle does not exist: {}", bundle.display()))?;
    let source_manifest = verify_runtime(&bundle)?;
    ensure_private_directory(&paths.data)?;
    ensure_private_directory(&paths.versions())?;
    ensure_private_directory(&paths.staging())?;
    ensure_private_directory(&paths.bin)?;

    let final_runtime = paths.versions().join(&source_manifest.version);
    if final_runtime.exists() {
        let installed = verify_runtime(&final_runtime)?;
        if installed.version != source_manifest.version
            || sha256_file(&final_runtime.join("release-manifest.json"))?
                != sha256_file(&bundle.join("release-manifest.json"))?
        {
            bail!(
                "candidate reuses installed version {} with different contents; publish or install it under a new version (the existing immutable runtime was left unchanged)",
                source_manifest.version
            );
        }
    } else {
        let staging = paths.staging().join(format!(
            "{}-{:016x}",
            source_manifest.version,
            rand::random::<u64>()
        ));
        retry_transient_io(|| std::fs::create_dir(&staging))
            .with_context(|| format!("failed to create staging directory {}", staging.display()))?;
        if let Err(error) = copy_tree(&bundle, &staging)
            .and_then(|_| verify_runtime(&staging).map(|_| ()))
            .and_then(|_| {
                crate::pack::WorkspacePack::load(&staging.join("workflow/workspace.pack"))
                    .map(|_| ())
            })
            .and_then(|_| set_runtime_permissions(&staging, &source_manifest))
            .and_then(|_| sidecar_self_test(&staging))
        {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(error);
        }
        // On Windows the prior version directory may still be in the
        // "delete-pending" state after an uninstall's `remove_dir_all`, and
        // Defender may hold a freshly written sidecar executable open; either
        // makes this rename transiently fail with `ERROR_ACCESS_DENIED`. Retry
        // until the pending deletion finalizes and scans release their handles.
        retry_transient_io(|| std::fs::rename(&staging, &final_runtime)).with_context(|| {
            format!("failed to activate runtime at {}", final_runtime.display())
        })?;
    }

    let manifest_digest = sha256_file(&final_runtime.join("release-manifest.json"))?;
    let current = CurrentRuntime {
        schema: 1,
        version: source_manifest.version.clone(),
        relative_runtime: format!("versions/{}", source_manifest.version),
        manifest_sha256: manifest_digest,
    };
    let launcher = launcher_path(&final_runtime);
    let bytes = std::fs::read(&launcher)?;
    let previous_current = std::fs::read(paths.current()).ok();
    let previous_launcher = std::fs::read(paths.public_launcher()).ok();
    let previous_locator = std::fs::read(paths.install_locator()).ok();
    let switch = (|| -> Result<()> {
        write_if_changed(&paths.public_launcher(), &bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                paths.public_launcher(),
                std::fs::Permissions::from_mode(0o700),
            )?;
        }
        paths.write_install_locator()?;
        write_json(&paths.current(), &current)?;
        let activated = verify_runtime(&final_runtime)?;
        sidecar_self_test(&final_runtime)?;
        crate::pack::WorkspacePack::load(&final_runtime.join("workflow/workspace.pack"))?;
        if sha256_file(&paths.public_launcher())?
            != activated
                .files
                .iter()
                .find(|file| file.kind == "launcher")
                .context("release manifest has no launcher")?
                .sha256
        {
            bail!("public launcher verification failed after activation");
        }
        Ok(())
    })();
    if let Err(error) = switch {
        restore_optional_file(&paths.current(), previous_current.as_deref())?;
        restore_optional_file(&paths.public_launcher(), previous_launcher.as_deref())?;
        restore_optional_file(&paths.install_locator(), previous_locator.as_deref())?;
        return Err(error);
    }
    Ok(source_manifest)
}

fn restore_optional_file(path: &Path, payload: Option<&[u8]>) -> Result<()> {
    if let Some(payload) = payload {
        write_if_changed(path, payload)?;
    } else if path.is_file() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn remove_public_launcher(
    path: &Path,
    _evacuation_root: Option<&Path>,
    _wait_for_pid: Option<u32>,
) -> Result<()> {
    std::fs::remove_file(path)
        .with_context(|| format!("failed to remove public launcher {}", path.display()))
}

#[cfg(windows)]
fn start_windows_launcher_cleanup(tombstone: &Path, wait_for_pid: Option<u32>) -> Result<()> {
    use std::os::windows::process::CommandExt;

    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    let powershell = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .map(|root| {
            root.join("System32")
                .join("WindowsPowerShell")
                .join("v1.0")
                .join("powershell.exe")
        })
        .filter(|candidate| candidate.is_file())
        .unwrap_or_else(|| PathBuf::from("powershell.exe"));
    let mut command = Command::new(powershell);
    // A delete can temporarily report success while the executable image is
    // still mapped, only for the visible path to reappear when that process
    // exits. When this helper is evacuating the current launcher, first poll
    // the exact parent PID. PowerShell exposes the native process object, which
    // avoids `cmd.exe` pipeline and quoting ambiguity. The target itself stays
    // in the environment and is always consumed through `-LiteralPath`.
    let cleanup = r#"$ErrorActionPreference='SilentlyContinue';$parentId=0;if([uint32]::TryParse($env:BYO_UNINSTALL_PID,[ref]$parentId)){$parent=Get-Process -Id $parentId -ErrorAction SilentlyContinue;if(($null -ne $parent) -and (-not $parent.WaitForExit(120000))){exit 1}};for($i=0;$i -lt 120;$i++){Remove-Item -LiteralPath $env:BYO_UNINSTALL_TARGET -Force -ErrorAction SilentlyContinue;if(-not (Test-Path -LiteralPath $env:BYO_UNINSTALL_TARGET)){exit 0};Start-Sleep -Seconds 1};exit 1"#;
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            cleanup,
        ])
        .env("BYO_UNINSTALL_TARGET", tombstone)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
    if let Some(pid) = wait_for_pid {
        command.env("BYO_UNINSTALL_PID", pid.to_string());
    }
    let temporary_directory = std::env::temp_dir();
    if temporary_directory.is_dir() {
        command.current_dir(temporary_directory);
    }
    command
        .spawn()
        .context("failed to start the Windows PowerShell launcher cleanup helper")?;
    Ok(())
}

#[cfg(windows)]
fn mark_windows_launcher_for_posix_deletion(path: &Path) -> Result<()> {
    use std::mem::size_of;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfoEx, SetFileInformationByHandle, DELETE, FILE_DISPOSITION_FLAG_DELETE,
        FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        FILE_DISPOSITION_INFO_EX, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let file = OpenOptions::new()
        .access_mode(DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)
        .with_context(|| {
            format!(
                "failed to open Windows launcher {} for deletion",
                path.display()
            )
        })?;
    let disposition = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    // SAFETY: `file` owns a valid Windows file handle, and `disposition` remains
    // alive and correctly sized for the duration of this synchronous call.
    let result = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            std::ptr::from_ref(&disposition).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if result == 0 {
        let error = std::io::Error::last_os_error();
        drop(file);
        bail!(
            "failed to mark Windows launcher {} for POSIX deletion: {error}",
            path.display()
        );
    }
    drop(file);
    if path.exists() {
        bail!(
            "Windows launcher remained visible after POSIX deletion: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn remove_public_launcher(
    path: &Path,
    evacuation_root: Option<&Path>,
    wait_for_pid: Option<u32>,
) -> Result<()> {
    if let Some(root) = evacuation_root {
        if !path.starts_with(root) {
            bail!("public launcher is not contained by its evacuation root");
        }
        let parent = root
            .parent()
            .context("launcher evacuation root has no parent directory")?;
        let tombstone = parent.join(format!(".byo-uninstall-{:016x}.exe", rand::random::<u64>()));
        retry_transient_io(|| std::fs::rename(path, &tombstone)).with_context(|| {
            format!(
                "failed to move the running public launcher {} outside purge root {}",
                path.display(),
                root.display()
            )
        })?;
        // Do not apply a POSIX delete disposition to the evacuated live image.
        // Windows can make a delete-pending executable temporarily invisible,
        // causing the disposition path to report success without starting the
        // post-exit cleanup that is still required. The raw cmd.exe helper is
        // deterministic here: the tombstone exists before it starts, it waits
        // for this process to release the image, and then it deletes the exact
        // file with bounded retries.
        if let Err(helper_error) = start_windows_launcher_cleanup(&tombstone, wait_for_pid) {
            retry_transient_io(|| std::fs::rename(&tombstone, path)).with_context(|| {
                format!(
                    "Windows cleanup helper failed ({helper_error:#}) and the public launcher could not be restored to {}",
                    path.display()
                )
            })?;
            return Err(helper_error);
        }
        if path.exists() {
            bail!(
                "public launcher remained visible after evacuation: {}",
                path.display()
            );
        }
        return Ok(());
    }

    if let Err(disposition_error) = mark_windows_launcher_for_posix_deletion(path) {
        let parent = path
            .parent()
            .context("public launcher has no parent directory")?;
        let tombstone = parent.join(format!(".byo-uninstall-{:016x}.exe", rand::random::<u64>()));
        std::fs::rename(path, &tombstone).with_context(|| {
            format!(
                "failed to mark public launcher {} for POSIX deletion ({disposition_error}) and failed to rename it for deferred deletion",
                path.display()
            )
        })?;
        if let Err(helper_error) = start_windows_launcher_cleanup(&tombstone, wait_for_pid) {
            retry_transient_io(|| std::fs::rename(&tombstone, path)).with_context(|| {
                format!(
                    "Windows cleanup helper failed ({helper_error:#}) and the public launcher could not be restored to {}",
                    path.display()
                )
            })?;
            return Err(helper_error);
        }
        if path.exists() {
            bail!(
                "public launcher remained visible after deferred deletion: {}",
                path.display()
            );
        }
        return Ok(());
    }
    Ok(())
}

pub fn repair(paths: &ProductPaths, requested: Option<&Path>) -> Result<PathBuf> {
    let _lock = InstallLock::acquire(paths)?;
    let candidate = if let Some(path) = requested {
        path.to_path_buf()
    } else {
        let mut candidates = Vec::new();
        for entry in std::fs::read_dir(paths.versions())? {
            let path = entry?.path();
            if path.is_dir() && verify_runtime(&path).is_ok() {
                candidates.push(path);
            }
        }
        candidates.sort();
        candidates
            .pop()
            .context("no verified BYO runtime is available for repair")?
    };
    let candidate = candidate.canonicalize()?;
    let data = paths.data.canonicalize()?;
    let versions = paths.versions().canonicalize()?;
    if !candidate.starts_with(&versions) {
        bail!("repair candidate must be an installed version directory");
    }
    let release = verify_runtime(&candidate)?;
    sidecar_self_test(&candidate)?;
    let current = CurrentRuntime {
        schema: 1,
        version: release.version.clone(),
        relative_runtime: portable_relative_path(candidate.strip_prefix(&data)?)?,
        manifest_sha256: sha256_file(&candidate.join("release-manifest.json"))?,
    };
    let launcher = std::fs::read(launcher_path(&candidate))?;
    let previous_current = std::fs::read(paths.current()).ok();
    let previous_launcher = std::fs::read(paths.public_launcher()).ok();
    let previous_locator = std::fs::read(paths.install_locator()).ok();
    let switch = (|| -> Result<()> {
        write_if_changed(&paths.public_launcher(), &launcher)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                paths.public_launcher(),
                std::fs::Permissions::from_mode(0o700),
            )?;
        }
        paths.write_install_locator()?;
        write_json(&paths.current(), &current)?;
        verify_runtime(&candidate)?;
        sidecar_self_test(&candidate)?;
        crate::pack::WorkspacePack::load(&candidate.join("workflow/workspace.pack"))?;
        if sha256_file(&paths.public_launcher())?
            != release
                .files
                .iter()
                .find(|file| file.kind == "launcher")
                .context("release manifest has no launcher")?
                .sha256
        {
            bail!("public launcher verification failed after repair activation");
        }
        Ok(())
    })();
    if let Err(error) = switch {
        restore_optional_file(&paths.current(), previous_current.as_deref())?;
        restore_optional_file(&paths.public_launcher(), previous_launcher.as_deref())?;
        restore_optional_file(&paths.install_locator(), previous_locator.as_deref())?;
        return Err(error);
    }
    Ok(candidate)
}

/// Existing directories among `candidates`, dropping any nested under one already
/// kept (on macOS/Windows `state`/`cache` live under `data`). The retained order
/// follows the input order, so parents always precede — and thus absorb — their
/// descendants.
fn non_nested_existing_dirs<'a>(candidates: impl IntoIterator<Item = &'a PathBuf>) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for dir in candidates {
        if dir.is_dir() && !roots.iter().any(|existing| dir.starts_with(existing)) {
            roots.push(dir.clone());
        }
    }
    roots
}

/// The BYO-owned paths a global uninstall removes, in removal order, that
/// currently exist: the public launcher and install locator (files under the
/// shared `bin` dir, which itself is never removed), then the non-nested data
/// roots. This is the exact global product footprint removed after project purge.
pub fn purge_targets(paths: &ProductPaths) -> Vec<PathBuf> {
    let mut targets = Vec::new();
    if paths.public_launcher().is_file() {
        targets.push(paths.public_launcher());
    }
    if paths.install_locator().is_file() {
        targets.push(paths.install_locator());
    }
    targets.extend(non_nested_existing_dirs([
        &paths.data,
        &paths.state,
        &paths.config,
        &paths.cache,
    ]));
    targets
}

#[derive(Debug)]
pub struct GlobalUninstallOutcome {
    pub removed: Vec<PathBuf>,
    pub project_integrations: Vec<PathBuf>,
    pub reverted_path_edits: Vec<String>,
}

fn project_locations(projects: &[PathBuf]) -> String {
    if projects.is_empty() {
        return "  (none registered)".to_string();
    }
    projects
        .iter()
        .map(|project| format!("  {}", project.display()))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn uninstall_global(paths: &ProductPaths) -> Result<GlobalUninstallOutcome> {
    let lock = InstallLock::acquire(paths)?;
    let registered = crate::project::registered_projects(paths)?;
    let registered_paths: Vec<_> = registered
        .iter()
        .map(|project| project.path.clone())
        .collect();
    let active: Vec<_> = crate::lease::inspect(paths, true)?
        .into_iter()
        .filter(|status| status.live)
        .collect();
    if !active.is_empty() {
        bail!(
            "global uninstall refused while {} MCP runtime lease(s) are active\nRegistered project integrations:\n{}",
            active.len(),
            project_locations(&registered_paths)
        );
    }
    let plans = crate::project::plan_registered_project_uninstalls(paths, &registered)?;
    let project_cleanup = crate::project::apply_registered_project_uninstalls(plans, paths)?;
    let reverted_path_edits = crate::path_setup::revert_recorded_edits(paths).with_context(|| {
        format!(
            "project integrations were removed, but recorded PATH cleanup failed\nRemoved project integrations:\n{}",
            project_locations(&project_cleanup.projects)
        )
    })?;

    let removal = (|| -> Result<Vec<PathBuf>> {
        let mut removed = project_cleanup.removed.clone();
        // `--global` is the explicit full-removal request. Remove every BYO-owned
        // root and do not gate on `verify_runtime`: a corrupt runtime must not be
        // able to block a requested wipe. The preview helper returns non-nested,
        // product-scoped targets and never includes the shared bin directory.
        let targets = purge_targets(paths);
        let public_launcher = paths.public_launcher();
        let launcher_evacuation_root = targets
            .iter()
            .find(|target| target.is_dir() && public_launcher.starts_with(target));
        for target in targets.iter().filter(|target| !target.is_dir()) {
            if target == &public_launcher {
                remove_public_launcher(
                    target,
                    launcher_evacuation_root.map(PathBuf::as_path),
                    Some(std::process::id()),
                )?;
            } else {
                std::fs::remove_file(target).with_context(|| {
                    format!("failed to remove global BYO file {}", target.display())
                })?;
            }
            removed.push(target.clone());
        }

        // The install lock itself lives below the state root. Windows refuses to
        // remove a directory containing that open file, so release the lock only
        // after the public launcher and locator are gone and before deleting the
        // product roots. At that point a normal new mutation cannot start through
        // the installed entry point or rediscover the installation through its
        // locator.
        drop(lock);
        for target in targets.into_iter().filter(|target| target.is_dir()) {
            std::fs::remove_dir_all(&target).with_context(|| {
                format!("failed to remove global BYO directory {}", target.display())
            })?;
            removed.push(target);
        }
        Ok(removed)
    })();
    let removed = match removal {
        Ok(removed) => removed,
        Err(error) => {
            bail!(
                "global product removal failed after registered project integrations were removed: {error:#}\nRemoved project integrations:\n{}",
                project_locations(&project_cleanup.projects)
            )
        }
    };
    Ok(GlobalUninstallOutcome {
        removed,
        project_integrations: project_cleanup.projects,
        reverted_path_edits,
    })
}

#[cfg(test)]
mod tests {
    use super::{portable_relative_path, write_if_changed};

    #[cfg(windows)]
    use super::{remove_public_launcher, start_windows_launcher_cleanup};

    fn write_registered_project(
        paths: &crate::paths::ProductPaths,
        project: &std::path::Path,
        project_id: &str,
    ) -> std::path::PathBuf {
        std::fs::create_dir_all(project.join(".agent-workspace")).unwrap();
        std::fs::create_dir_all(project.join(".generated/byo")).unwrap();
        std::fs::create_dir_all(project.join(".firm")).unwrap();
        std::fs::write(project.join(".firm/preserved"), b"user data").unwrap();
        std::fs::write(project.join(".agent-workspace/PLAN.md"), b"user plan").unwrap();
        crate::manifest::write_json(
            &project.join(".agent-workspace/manifest.json"),
            &serde_json::json!({
                "schema": 1,
                "product": "byo",
                "workspace_version": "test",
                "workflow_protocol": 1,
                "minimum_launcher": "0.1.0",
                "maximum_launcher": "0.x",
                "minimum_mcp_protocol": 1,
                "project_id": project_id,
                "mode": "firmware",
                "installed_at": "2026-08-20T00:00:00Z",
                "managed_inventory_sha256": "unused-in-test"
            }),
        )
        .unwrap();
        crate::manifest::write_json(
            &project.join(".generated/byo/projection-manifest.json"),
            &serde_json::json!({
                "schema": 1,
                "managed_files": [],
                "agents_block_sha256": "unused-in-test",
                "codex_server_sha256": "unused-in-test",
                "codex_hooks_sha256": "unused-in-test"
            }),
        )
        .unwrap();
        let project = project.canonicalize().unwrap();
        std::fs::create_dir_all(&paths.state).unwrap();
        let registry_path = paths.state.join("projects.json");
        let mut registry: std::collections::BTreeMap<String, String> = if registry_path.is_file() {
            serde_json::from_slice(&std::fs::read(&registry_path).unwrap()).unwrap()
        } else {
            std::collections::BTreeMap::new()
        };
        registry.insert(project_id.to_string(), project.display().to_string());
        crate::manifest::write_json(&registry_path, &registry).unwrap();
        project
    }

    #[test]
    fn current_runtime_paths_use_portable_separators() {
        let path = std::path::Path::new("versions").join("0.1.0");
        assert_eq!(portable_relative_path(&path).unwrap(), "versions/0.1.0");
        assert!(portable_relative_path(std::path::Path::new("")).is_err());
        assert!(portable_relative_path(std::path::Path::new("../0.1.0")).is_err());
    }

    #[test]
    fn purge_removes_every_byo_owned_root() {
        let root =
            std::env::temp_dir().join(format!("byo-purge-test-{:032x}", rand::random::<u128>()));
        let paths = crate::paths::ProductPaths::from_install_dir(&root).unwrap();
        for dir in [
            &paths.data,
            &paths.state,
            &paths.config,
            &paths.cache,
            &paths.bin,
        ] {
            std::fs::create_dir_all(dir).unwrap();
        }
        // Populate the roots the previous implementation left behind on purge:
        // state/ (registry + would-be leases), staging/, and an empty versions/.
        std::fs::create_dir_all(paths.staging()).unwrap();
        std::fs::create_dir_all(paths.versions().join("0.1.0")).unwrap();
        std::fs::write(paths.state.join("projects.json"), b"{}").unwrap();
        std::fs::write(paths.current(), b"{}").unwrap();
        std::fs::write(paths.public_launcher(), b"launcher").unwrap();
        std::fs::write(paths.install_locator(), b"{}").unwrap();

        super::uninstall_global(&paths).unwrap();

        for leftover in [&paths.data, &paths.state, &paths.config, &paths.cache] {
            assert!(
                !leftover.exists(),
                "purge left {} behind",
                leftover.display()
            );
        }
        assert!(!paths.public_launcher().exists());
        assert!(!paths.install_locator().exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn purge_targets_match_removed_set_and_exclude_bin() {
        let root =
            std::env::temp_dir().join(format!("byo-purge-targets-{:032x}", rand::random::<u128>()));
        let paths = crate::paths::ProductPaths::from_install_dir(&root).unwrap();
        for dir in [
            &paths.data,
            &paths.state,
            &paths.config,
            &paths.cache,
            &paths.bin,
        ] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(paths.public_launcher(), b"launcher").unwrap();
        std::fs::write(paths.install_locator(), b"{}").unwrap();

        let preview = super::purge_targets(&paths);
        assert!(preview.contains(&paths.public_launcher()));
        assert!(preview.contains(&paths.install_locator()));
        for dir in [&paths.data, &paths.state, &paths.config, &paths.cache] {
            assert!(preview.contains(dir), "preview missing {}", dir.display());
        }
        // The shared `bin` directory is never a purge target.
        assert!(!preview.contains(&paths.bin));

        let outcome = super::uninstall_global(&paths).unwrap();
        assert_eq!(outcome.removed, preview);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn global_uninstall_removes_registered_project_integrations_first() {
        let root = std::env::temp_dir().join(format!(
            "byo-global-project-cleanup-{:032x}",
            rand::random::<u128>()
        ));
        let paths = crate::paths::ProductPaths::from_install_dir(&root.join("product")).unwrap();
        let project = write_registered_project(&paths, &root.join("project"), "project-a");

        let outcome = super::uninstall_global(&paths).unwrap();

        assert_eq!(
            outcome.project_integrations.as_slice(),
            std::slice::from_ref(&project)
        );
        assert!(!project.join(".agent-workspace/manifest.json").exists());
        assert!(!project
            .join(".generated/byo/projection-manifest.json")
            .exists());
        assert!(!project.join(".agent-workspace").exists());
        assert!(!project.join(".firm").exists());
        assert!(!paths.state.exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn global_uninstall_deduplicates_stale_registry_aliases_by_project_path() {
        let root = std::env::temp_dir().join(format!(
            "byo-global-project-alias-{:032x}",
            rand::random::<u128>()
        ));
        let paths = crate::paths::ProductPaths::from_install_dir(&root.join("product")).unwrap();
        let project = write_registered_project(&paths, &root.join("project"), "project-current");
        let registry_path = paths.state.join("projects.json");
        let mut registry: std::collections::BTreeMap<String, String> =
            serde_json::from_slice(&std::fs::read(&registry_path).unwrap()).unwrap();
        registry.insert("stale-alias".to_string(), project.display().to_string());
        crate::manifest::write_json(&registry_path, &registry).unwrap();

        let outcome = super::uninstall_global(&paths).unwrap();

        assert_eq!(outcome.project_integrations, vec![project.clone()]);
        assert!(!project.join(".agent-workspace").exists());
        assert!(!project.join(".firm").exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn global_uninstall_preflight_names_every_project_and_changes_nothing() {
        let root = std::env::temp_dir().join(format!(
            "byo-global-project-preflight-{:032x}",
            rand::random::<u128>()
        ));
        let paths = crate::paths::ProductPaths::from_install_dir(&root.join("product")).unwrap();
        let valid = write_registered_project(&paths, &root.join("valid project"), "project-a");
        let missing = root.join("missing project");
        let registry_path = paths.state.join("projects.json");
        let mut registry: std::collections::BTreeMap<String, String> =
            serde_json::from_slice(&std::fs::read(&registry_path).unwrap()).unwrap();
        registry.insert("project-b".to_string(), missing.display().to_string());
        crate::manifest::write_json(&registry_path, &registry).unwrap();
        std::fs::write(paths.state.join("path-edits.json"), b"untouched").unwrap();

        let error = super::uninstall_global(&paths).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(&valid.display().to_string()));
        assert!(message.contains(&missing.display().to_string()));
        assert!(valid.join(".agent-workspace/manifest.json").is_file());
        assert_eq!(
            std::fs::read(paths.state.join("path-edits.json")).unwrap(),
            b"untouched"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn unchanged_launcher_is_not_replaced() {
        let root =
            std::env::temp_dir().join(format!("byo-launcher-test-{:032x}", rand::random::<u128>()));
        std::fs::create_dir_all(&root).unwrap();
        let launcher = root.join("byo.exe");
        std::fs::write(&launcher, b"same").unwrap();
        assert!(!write_if_changed(&launcher, b"same").unwrap());
        assert_eq!(std::fs::read(&launcher).unwrap(), b"same");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_cleanup_helper_deletes_a_regular_file() {
        let container = std::env::temp_dir().join(format!(
            "byo cleanup helper test {:032x}",
            rand::random::<u128>()
        ));
        std::fs::create_dir_all(&container).unwrap();
        let tombstone = container.join(".byo-uninstall-test.exe");
        std::fs::write(&tombstone, b"placeholder").unwrap();
        start_windows_launcher_cleanup(&tombstone, None).unwrap();
        for _ in 0..100 {
            if !tombstone.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(!tombstone.exists());
        std::fs::remove_dir(container).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_cleanup_helper_child_process() {
        let Some(target) = std::env::var_os("BYO_TEST_LIVE_CLEANUP_TARGET") else {
            return;
        };
        start_windows_launcher_cleanup(std::path::Path::new(&target), Some(std::process::id()))
            .unwrap();
        if let Some(ready) = std::env::var_os("BYO_TEST_LIVE_CLEANUP_READY") {
            std::fs::write(ready, b"ready").unwrap();
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_cleanup_helper_deletes_an_exited_executable() {
        let container = std::env::temp_dir().join(format!(
            "byo live cleanup helper test {:032x}",
            rand::random::<u128>()
        ));
        std::fs::create_dir_all(&container).unwrap();
        let tombstone = container.join(".byo-uninstall-live-test.exe");
        std::fs::copy(std::env::current_exe().unwrap(), &tombstone).unwrap();
        let ready = container.join("helper-ready");
        let mut child = std::process::Command::new(&tombstone)
            .args([
                "--exact",
                "install::tests::windows_cleanup_helper_child_process",
            ])
            .env("BYO_TEST_LIVE_CLEANUP_TARGET", &tombstone)
            .env("BYO_TEST_LIVE_CLEANUP_READY", &ready)
            .spawn()
            .unwrap();
        for _ in 0..100 {
            if ready.is_file() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(ready.is_file());
        assert!(child.try_wait().unwrap().is_none());
        assert!(tombstone.is_file());
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(tombstone.is_file());
        let status = child.wait().unwrap();
        assert!(status.success());
        for _ in 0..1300 {
            if !tombstone.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(!tombstone.exists());
        std::fs::remove_file(ready).unwrap();
        std::fs::remove_dir(container).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_public_launcher_evacuation_releases_the_purge_root() {
        let container = std::env::temp_dir().join(format!(
            "byo-uninstall-test-{:032x}",
            rand::random::<u128>()
        ));
        let root = container.join("BYO");
        let launcher = root.join("bin/byo.exe");
        std::fs::create_dir_all(launcher.parent().unwrap()).unwrap();
        std::fs::write(&launcher, b"placeholder").unwrap();
        remove_public_launcher(&launcher, Some(&root), None).unwrap();
        assert!(!launcher.exists());
        std::fs::remove_dir_all(&root).unwrap();
        for _ in 0..100 {
            if std::fs::read_dir(&container).unwrap().next().is_none() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(std::fs::read_dir(&container).unwrap().next().is_none());
        std::fs::remove_dir(container).unwrap();
    }
}
