use std::env;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

const INSTALL_LOCATOR_NAME: &str = ".byo-install.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductPaths {
    pub data: PathBuf,
    pub config: PathBuf,
    pub state: PathBuf,
    pub cache: PathBuf,
    pub bin: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallLocator {
    schema: u32,
    product: String,
    paths: ProductPaths,
}

impl ProductPaths {
    pub fn resolve() -> Result<Self> {
        if let Some(root) = env::var_os("BYO_HOME") {
            return Self::from_root(&absolute(PathBuf::from(root))?);
        }

        if let Some(paths) = Self::from_launcher_locator()? {
            return Ok(paths);
        }

        #[cfg(any(target_os = "macos", target_os = "linux"))]
        let home = {
            let home = env::var_os("HOME")
                .map(PathBuf::from)
                .context("HOME is required to resolve per-user BYO paths")?;
            if !home.is_absolute() {
                bail!("HOME must be absolute");
            }
            home
        };
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
            Ok(Self {
                data: data.join("byo"),
                config: config.join("byo"),
                state: state.join("byo"),
                cache: cache.join("byo"),
                bin: home.join(".local/bin"),
            })
        }
        #[cfg(target_os = "windows")]
        {
            let local = env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .context("LOCALAPPDATA is required")?;
            let roaming = env::var_os("APPDATA")
                .map(PathBuf::from)
                .context("APPDATA is required")?;
            Ok(Self {
                data: local.join("BYO"),
                config: roaming.join("BYO"),
                state: local.join("BYO/state"),
                cache: local.join("BYO/cache"),
                bin: local.join("BYO/bin"),
            })
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            bail!("unsupported operating system")
        }
    }

    pub fn from_install_dir(root: &Path) -> Result<Self> {
        if !root.is_absolute() {
            bail!("--install-dir must be an absolute path");
        }
        Self::from_root(root)
    }

    fn from_root(root: &Path) -> Result<Self> {
        if root.parent().is_none() {
            bail!("BYO installation root must not be the filesystem root");
        }
        Ok(Self {
            data: root.join("data"),
            config: root.join("config"),
            state: root.join("state"),
            cache: root.join("cache"),
            bin: root.join("bin"),
        })
    }

    fn from_launcher_locator() -> Result<Option<Self>> {
        let executable = env::current_exe().context("failed to resolve the BYO executable path")?;
        let Some(parent) = executable.parent() else {
            return Ok(None);
        };
        let locator_path = parent.join(INSTALL_LOCATOR_NAME);
        if !locator_path.is_file() {
            return Ok(None);
        }
        let locator: InstallLocator = serde_json::from_slice(
            &std::fs::read(&locator_path)
                .with_context(|| format!("failed to read {}", locator_path.display()))?,
        )
        .with_context(|| {
            format!(
                "invalid BYO installation locator {}",
                locator_path.display()
            )
        })?;
        if locator.schema != 1 || locator.product != "byo" {
            bail!("unsupported BYO installation locator");
        }
        locator.paths.validate_absolute()?;
        let expected = locator
            .paths
            .public_launcher()
            .canonicalize()
            .context("installation locator points to a missing BYO launcher")?;
        if executable.canonicalize()? != expected {
            bail!("installation locator does not describe the running BYO launcher");
        }
        Ok(Some(locator.paths))
    }

    fn validate_absolute(&self) -> Result<()> {
        for (name, path) in [
            ("data", &self.data),
            ("config", &self.config),
            ("state", &self.state),
            ("cache", &self.cache),
            ("bin", &self.bin),
        ] {
            if !path.is_absolute() {
                bail!("installation locator {name} path is not absolute");
            }
        }
        Ok(())
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

    pub fn install_locator(&self) -> PathBuf {
        self.bin.join(INSTALL_LOCATOR_NAME)
    }

    pub fn write_install_locator(&self) -> Result<()> {
        self.validate_absolute()?;
        crate::manifest::write_json(
            &self.install_locator(),
            &InstallLocator {
                schema: 1,
                product: "byo".to_string(),
                paths: self.clone(),
            },
        )
    }

    pub fn verify_install_locator(&self) -> Result<()> {
        let locator: InstallLocator =
            serde_json::from_slice(&std::fs::read(self.install_locator())?)
                .context("BYO installation locator is invalid")?;
        if locator.schema != 1 || locator.product != "byo" || locator.paths != *self {
            bail!("BYO installation locator does not match the active product paths");
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::ProductPaths;

    #[test]
    fn custom_install_root_keeps_every_product_path_under_the_selection() {
        let root = std::env::temp_dir().join("byo custom root");
        let paths = ProductPaths::from_install_dir(&root).unwrap();
        assert_eq!(paths.data, root.join("data"));
        assert_eq!(paths.config, root.join("config"));
        assert_eq!(paths.state, root.join("state"));
        assert_eq!(paths.cache, root.join("cache"));
        assert_eq!(paths.bin, root.join("bin"));
    }

    #[test]
    fn custom_install_root_must_be_absolute_and_bounded() {
        assert!(ProductPaths::from_install_dir(std::path::Path::new("relative")).is_err());
        assert!(ProductPaths::from_install_dir(std::path::Path::new("/")).is_err());
    }

    #[test]
    fn install_locator_round_trips_the_selected_paths() {
        let root =
            std::env::temp_dir().join(format!("byo-locator-{:032x}", rand::random::<u128>()));
        let paths = ProductPaths::from_install_dir(&root).unwrap();
        std::fs::create_dir_all(&paths.bin).unwrap();
        paths.write_install_locator().unwrap();
        paths.verify_install_locator().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
