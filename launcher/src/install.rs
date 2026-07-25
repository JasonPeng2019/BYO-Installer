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
        return Err(error);
    }
    Ok(candidate)
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
    if paths.current().is_file() {
        std::fs::remove_file(paths.current())?;
        removed.push(paths.current());
    }
    if purge {
        for target in [&paths.cache, &paths.config] {
            if target.is_dir() {
                std::fs::remove_dir_all(target)?;
                removed.push(target.clone());
            }
        }
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
