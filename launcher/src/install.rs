use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use fs2::FileExt;
use walkdir::WalkDir;

use crate::manifest::{sha256_file, verify_runtime, write_json, CurrentRuntime, ReleaseManifest};
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
            std::fs::create_dir_all(&target)?;
        } else if entry.file_type().is_file() {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(entry.path(), &target)?;
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
            bail!("existing immutable version directory does not match the candidate release");
        }
    } else {
        let staging = paths.staging().join(format!(
            "{}-{:016x}",
            source_manifest.version,
            rand::random::<u64>()
        ));
        std::fs::create_dir(&staging)?;
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
        std::fs::rename(&staging, &final_runtime)?;
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
fn remove_public_launcher(path: &Path) -> Result<()> {
    std::fs::remove_file(path)
        .with_context(|| format!("failed to remove public launcher {}", path.display()))
}

#[cfg(windows)]
fn remove_public_launcher(path: &Path) -> Result<()> {
    use std::mem::size_of;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;

    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfoEx, SetFileInformationByHandle, DELETE, FILE_DISPOSITION_FLAG_DELETE,
        FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        FILE_DISPOSITION_INFO_EX, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    let file = OpenOptions::new()
        .access_mode(DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)
        .with_context(|| {
            format!(
                "failed to open public launcher {} for deletion",
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
        let disposition_error = std::io::Error::last_os_error();
        drop(file);
        let parent = path
            .parent()
            .context("public launcher has no parent directory")?;
        let tombstone = parent.join(format!(".byo-uninstall-{:016x}.exe", rand::random::<u64>()));
        let command_shell =
            std::env::var_os("COMSPEC").unwrap_or_else(|| std::ffi::OsString::from("cmd.exe"));
        Command::new(command_shell)
            .args([
                "/D",
                "/Q",
                "/C",
                r#"for /L %I in (1,1,30) do @(del /F /Q "%BYO_UNINSTALL_TARGET%" >NUL 2>NUL && exit /B 0 || ping 127.0.0.1 -n 2 >NUL) & exit /B 1"#,
            ])
            .env("BYO_UNINSTALL_TARGET", &tombstone)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .context("failed to start the Windows launcher cleanup helper")?;
        std::fs::rename(path, &tombstone).with_context(|| {
            format!(
                "failed to mark public launcher {} for POSIX deletion ({disposition_error}) and failed to rename it for deferred deletion",
                path.display()
            )
        })?;
        if path.exists() {
            bail!(
                "public launcher remained visible after deferred deletion: {}",
                path.display()
            );
        }
        return Ok(());
    }
    drop(file);
    if path.exists() {
        bail!(
            "public launcher remained visible after deletion: {}",
            path.display()
        );
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

/// The BYO-owned paths a `--purge-data` wipe removes, in removal order, that
/// currently exist: the public launcher and install locator (files under the
/// shared `bin` dir, which itself is never removed), then the non-nested data
/// roots. This is both the operator preview shown before confirmation and the
/// exact set `uninstall_global(paths, true)` deletes.
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

/// The BYO data roots that survive a non-purge global uninstall — reported as
/// preserved user data in the uninstall receipt.
pub fn remaining_data_roots(paths: &ProductPaths) -> Vec<PathBuf> {
    non_nested_existing_dirs([&paths.data, &paths.state, &paths.config, &paths.cache])
}

pub fn uninstall_global(paths: &ProductPaths, purge: bool) -> Result<Vec<PathBuf>> {
    let _lock = InstallLock::acquire(paths)?;
    let active: Vec<_> = crate::lease::inspect(paths, true)?
        .into_iter()
        .filter(|status| status.live)
        .collect();
    if !active.is_empty() {
        bail!(
            "global uninstall refused while {} MCP runtime lease(s) are active",
            active.len()
        );
    }
    let registry = paths.state.join("projects.json");
    if registry.is_file() {
        let projects: std::collections::BTreeMap<String, String> =
            serde_json::from_slice(&std::fs::read(&registry)?)
                .context("global project registry is invalid")?;
        if !projects.is_empty() {
            bail!(
                "global uninstall refused while {} project(s) remain registered; uninstall their BYO integration first",
                projects.len()
            );
        }
    }
    let mut removed = Vec::new();
    if purge {
        // Destructive path — reached only with `--purge-data --yes`. Remove every
        // BYO-owned root so a purge truly leaves nothing behind, and do NOT gate on
        // `verify_runtime`: a corrupt or half-written runtime must not be able to
        // block a wipe the operator explicitly confirmed. `purge_targets` returns
        // the exact set the `--purge-data` preview shows, already filtered so no
        // entry is nested under another — so each still exists when reached and
        // this never escapes the BYO install footprint (the shared `bin` dir is
        // never included).
        for target in purge_targets(paths) {
            if target.is_dir() {
                std::fs::remove_dir_all(&target)?;
            } else if target == paths.public_launcher() {
                remove_public_launcher(&target)?;
            } else {
                std::fs::remove_file(&target)?;
            }
            removed.push(target);
        }
        return Ok(removed);
    }
    if paths.versions().exists() {
        for entry in std::fs::read_dir(paths.versions())? {
            let candidate = entry?.path();
            if candidate.is_dir() {
                verify_runtime(&candidate).with_context(|| {
                    format!(
                        "refusing to remove unverified runtime directory {}",
                        candidate.display()
                    )
                })?;
                std::fs::remove_dir_all(&candidate)?;
                removed.push(candidate);
            }
        }
    }
    if paths.public_launcher().is_file() {
        remove_public_launcher(&paths.public_launcher())?;
        removed.push(paths.public_launcher());
    }
    if paths.install_locator().is_file() {
        std::fs::remove_file(paths.install_locator())?;
        removed.push(paths.install_locator());
    }
    if paths.current().is_file() {
        std::fs::remove_file(paths.current())?;
        removed.push(paths.current());
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::{portable_relative_path, write_if_changed};

    #[cfg(windows)]
    use super::remove_public_launcher;

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

        super::uninstall_global(&paths, true).unwrap();

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

        // The preview must equal exactly what removal deletes, so the operator
        // confirmation is honest.
        let removed = super::uninstall_global(&paths, true).unwrap();
        assert_eq!(removed, preview);
        std::fs::remove_dir_all(&root).ok();
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
    fn windows_public_launcher_delete_removes_the_visible_path() {
        let root = std::env::temp_dir().join(format!(
            "byo-uninstall-test-{:032x}",
            rand::random::<u128>()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let launcher = root.join("byo.exe");
        std::fs::write(&launcher, b"placeholder").unwrap();
        remove_public_launcher(&launcher).unwrap();
        assert!(!launcher.exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
