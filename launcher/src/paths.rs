use std::env;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ProductPaths {
    pub data: PathBuf,
    pub config: PathBuf,
    pub state: PathBuf,
    pub cache: PathBuf,
    pub bin: PathBuf,
}

impl ProductPaths {
    pub fn resolve() -> Result<Self> {
        if let Some(root) = env::var_os("BYO_HOME") {
            let root = absolute(PathBuf::from(root))?;
            return Ok(Self {
                data: root.join("data"),
                config: root.join("config"),
                state: root.join("state"),
                cache: root.join("cache"),
                bin: root.join("bin"),
            });
        }

        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .context("HOME is required to resolve per-user BYO paths")?;
        if !home.is_absolute() {
            bail!("HOME must be absolute");
        }
        #[cfg(target_os = "macos")]
        {
            Ok(Self {
                data: home.join("Library/Application Support/BYO"),
                config: home.join("Library/Preferences/BYO"),
                state: home.join("Library/Application Support/BYO/state"),
                cache: home.join("Library/Caches/BYO"),
                bin: home.join(".local/bin"),
            })
        }
        #[cfg(target_os = "linux")]
        {
            let data = env_path("XDG_DATA_HOME").unwrap_or_else(|| home.join(".local/share"));
            let config = env_path("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));
            let state = env_path("XDG_STATE_HOME").unwrap_or_else(|| home.join(".local/state"));
            let cache = env_path("XDG_CACHE_HOME").unwrap_or_else(|| home.join(".cache"));
            return Ok(Self {
                data: data.join("byo"),
                config: config.join("byo"),
                state: state.join("byo"),
                cache: cache.join("byo"),
                bin: home.join(".local/bin"),
            });
        }
        #[cfg(target_os = "windows")]
        {
            let local = env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .context("LOCALAPPDATA is required")?;
            let roaming = env::var_os("APPDATA")
                .map(PathBuf::from)
                .context("APPDATA is required")?;
            return Ok(Self {
                data: local.join("BYO"),
                config: roaming.join("BYO"),
                state: local.join("BYO/state"),
                cache: local.join("BYO/cache"),
                bin: local.join("BYO/bin"),
            });
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            bail!("unsupported operating system")
        }
    }

    pub fn current(&self) -> PathBuf {
        self.data.join("current.json")
    }

    pub fn versions(&self) -> PathBuf {
        self.data.join("versions")
    }

    pub fn staging(&self) -> PathBuf {
        self.data.join("staging")
    }

    pub fn leases(&self) -> PathBuf {
        self.state.join("leases")
    }

    pub fn public_launcher(&self) -> PathBuf {
        self.bin.join(if cfg!(windows) { "byo.exe" } else { "byo" })
    }
}

fn absolute(path: PathBuf) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(env::current_dir()?.join(path))
    }
}

#[cfg(target_os = "linux")]
fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

pub fn ensure_private_directory(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn is_within(candidate: &Path, parent: &Path) -> bool {
    candidate == parent || candidate.starts_with(parent)
}
