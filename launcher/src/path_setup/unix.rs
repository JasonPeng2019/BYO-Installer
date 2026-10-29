//! Shell-specific selection/rendering; mutation refuses all non-missing read errors.
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use super::{
    backup_profile, has_valid_block, load_record, read_profile, record_edit, EditKind, PathEdit,
    PathSetupOutcome, BEGIN_MARKER, END_MARKER,
};
use crate::paths::ProductPaths;

#[derive(Clone, Copy)]
enum Syntax {
    Posix,
    Fish,
}

struct Profile {
    path: PathBuf,
    syntax: Syntax,
}

fn choose_profile(
    home: &Path,
    shell: Option<&str>,
    macos: bool,
    zdotdir: Option<&Path>,
    xdg_config: Option<&Path>,
) -> Result<Option<Profile>> {
    let shell = shell
        .and_then(|value| value.rsplit('/').next())
        .unwrap_or("sh");
    let (path, syntax) = match shell {
        "zsh" => (zdotdir.unwrap_or(home).join(".zshrc"), Syntax::Posix),
        "bash" if macos => {
            let mut selected = home.join(".bash_profile");
            for file in [".bash_profile", ".bash_login", ".profile"] {
                let path = home.join(file);
                match std::fs::symlink_metadata(&path) {
                    Ok(_) => {
                        selected = path;
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            (selected, Syntax::Posix)
        }
        "bash" => (home.join(".bashrc"), Syntax::Posix),
        "sh" | "dash" | "ksh" => (home.join(".profile"), Syntax::Posix),
        "fish" => (
            xdg_config
                .map_or_else(|| home.join(".config"), Path::to_path_buf)
                .join("fish/config.fish"),
            Syntax::Fish,
        ),
        _ => return Ok(None),
    };
    Ok(Some(Profile { path, syntax }))
}

fn insert_block(contents: &str, bin: &str, syntax: Syntax) -> Result<Option<String>> {
    if bin.contains(['\0', '\n', '\r']) {
        bail!("BYO bin path contains an unsupported control character; configure PATH manually");
    }
    if has_valid_block(contents)? {
        return Ok(None);
    }
    let command = match syntax {
        Syntax::Posix => {
            let quoted = bin.replace('\'', "'\\''");
            format!("export PATH='{quoted}':\"$PATH\"")
        }
        Syntax::Fish => {
            let quoted = bin.replace('\\', "\\\\").replace('\'', "\\'");
            format!("if not contains -- '{quoted}' $PATH\n    set -gx PATH '{quoted}' $PATH\nend")
        }
    };
    let separator = if contents.is_empty() || contents.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    Ok(Some(format!(
        "{contents}{separator}{BEGIN_MARKER}\n{command}\n{END_MARKER}\n"
    )))
}

fn add_profile(paths: &ProductPaths, profile: Profile, bin: &str) -> Result<PathSetupOutcome> {
    let previous = read_profile(&profile.path)?;
    let Some(updated) = insert_block(previous.as_deref().unwrap_or(""), bin, profile.syntax)?
    else {
        return Ok(PathSetupOutcome::AlreadyPresent);
    };
    load_record(paths)?;
    // Follow a user's profile symlink, preserving the symlink itself on replacement.
    let target = if previous.is_some() {
        profile.path.canonicalize()?
    } else {
        profile.path
    };
    if let Some(bytes) = previous.as_deref() {
        backup_profile(paths, &target, bytes.as_bytes())?;
    }
    crate::manifest::atomic_write(&target, updated.as_bytes())?;
    if let Err(error) = record_edit(
        paths,
        PathEdit {
            kind: EditKind::UnixProfile,
            target: target.display().to_string(),
            bin: bin.to_string(),
        },
    ) {
        let rollback = match previous {
            Some(text) => crate::manifest::atomic_write(&target, text.as_bytes()),
            None => std::fs::remove_file(&target).map_err(anyhow::Error::from),
        };
        rollback
            .with_context(|| format!("PATH record failed ({error:#}); profile rollback failed"))?;
        return Err(error);
    }
    Ok(PathSetupOutcome::Configured {
        target: target.display().to_string(),
    })
}

#[cfg(not(windows))]
pub(super) fn add(paths: &ProductPaths, bin: &str) -> Result<PathSetupOutcome> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is required to modify PATH")?;
    let shell = std::env::var("SHELL").ok();
    let zdotdir = std::env::var_os("ZDOTDIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let xdg = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute());
    let Some(profile) = choose_profile(
        &home,
        shell.as_deref(),
        cfg!(target_os = "macos"),
        zdotdir.as_deref(),
        xdg.as_deref(),
    )?
    else {
        return Ok(PathSetupOutcome::Manual { instructions: format!(
            "Automatic PATH setup does not support {}. Add {} to PATH in that shell's startup configuration. Until then, run {} directly.",
            shell.as_deref().unwrap_or("this shell"), paths.bin.display(), paths.public_launcher().display()) });
    };
    if !profile.path.is_absolute() {
        bail!("shell profile path must be absolute; configure PATH manually");
    }
    add_profile(paths, profile, bin)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (PathBuf, ProductPaths) {
        let root = std::env::temp_dir().join(format!("byo-path-{:032x}", rand::random::<u128>()));
        std::fs::create_dir_all(root.join("home")).unwrap();
        let paths = ProductPaths::from_install_dir(&root.join("product")).unwrap();
        (root, paths)
    }

    #[test]
    fn shell_startup_selection_covers_login_bash_fish_and_zdotdir() {
        let (root, _) = fixture();
        let home = root.join("home");
        assert_eq!(
            choose_profile(&home, Some("/bin/bash"), true, None, None)
                .unwrap()
                .unwrap()
                .path,
            home.join(".bash_profile")
        );
        std::fs::write(home.join(".bash_login"), "existing\n").unwrap();
        assert_eq!(
            choose_profile(&home, Some("/bin/bash"), true, None, None)
                .unwrap()
                .unwrap()
                .path,
            home.join(".bash_login")
        );
        assert_eq!(
            choose_profile(&home, Some("/bin/bash"), false, None, None)
                .unwrap()
                .unwrap()
                .path,
            home.join(".bashrc")
        );
        let custom = root.join("custom");
        assert_eq!(
            choose_profile(&home, Some("/bin/zsh"), false, Some(&custom), None)
                .unwrap()
                .unwrap()
                .path,
            custom.join(".zshrc")
        );
        assert_eq!(
            choose_profile(&home, Some("/bin/fish"), false, None, Some(&custom))
                .unwrap()
                .unwrap()
                .path,
            custom.join("fish/config.fish")
        );
        assert!(choose_profile(&home, Some("/bin/nu"), false, None, None)
            .unwrap()
            .is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unreadable_profile_and_invalid_record_preserve_original_bytes() {
        let (root, paths) = fixture();
        let target = root.join("home/.bashrc");
        let invalid = b"export ORIGINAL=yes\n\xff\n";
        std::fs::write(&target, invalid).unwrap();
        assert!(add_profile(
            &paths,
            Profile {
                path: target.clone(),
                syntax: Syntax::Posix
            },
            "/byo/bin"
        )
        .is_err());
        assert_eq!(std::fs::read(&target).unwrap(), invalid);
        std::fs::write(&target, b"original\n").unwrap();
        std::fs::create_dir_all(&paths.state).unwrap();
        std::fs::write(super::super::record_path(&paths), b"invalid record").unwrap();
        assert!(add_profile(
            &paths,
            Profile {
                path: target.clone(),
                syntax: Syntax::Posix
            },
            "/byo/bin"
        )
        .is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"original\n");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn profile_add_repeat_and_uninstall_preserve_content_and_backup() {
        let (root, paths) = fixture();
        let target = root.join("home/config.fish");
        std::fs::write(&target, "# user's settings\n").unwrap();
        for _ in 0..2 {
            add_profile(
                &paths,
                Profile {
                    path: target.clone(),
                    syntax: Syntax::Fish,
                },
                "/opt/O'Brien/$literal\\bin",
            )
            .unwrap();
        }
        let text = std::fs::read_to_string(&target).unwrap();
        assert_eq!(text.matches(BEGIN_MARKER).count(), 1);
        assert!(text.contains("set -gx PATH '/opt/O\\'Brien/$literal\\\\bin' $PATH"));
        let backups: Vec<_> = std::fs::read_dir(paths.state.join("path-backups"))
            .unwrap()
            .collect();
        assert_eq!(backups.len(), 1);
        assert_eq!(
            std::fs::read(backups[0].as_ref().unwrap().path().join("profile")).unwrap(),
            b"# user's settings\n"
        );
        super::super::revert_recorded_edits(&paths).unwrap();
        assert_eq!(std::fs::read(target).unwrap(), b"# user's settings\n");
        assert!(!super::super::record_path(&paths).exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_profile_on_uninstall_keeps_edit_record() {
        let (root, paths) = fixture();
        let target = root.join("home/.profile");
        add_profile(
            &paths,
            Profile {
                path: target.clone(),
                syntax: Syntax::Posix,
            },
            "/byo/bin",
        )
        .unwrap();
        std::fs::write(&target, b"\xff").unwrap();
        assert!(super::super::revert_recorded_edits(&paths).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"\xff");
        assert!(super::super::record_path(&paths).is_file());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn posix_literal_quoting_and_malformed_markers() {
        let bin = "/opt/O'Brien/$(touch bad)/`bad`";
        let text = insert_block("", bin, Syntax::Posix).unwrap().unwrap();
        assert!(text.contains("PATH='/opt/O'\\''Brien/$(touch bad)/`bad`':\"$PATH\""));
        assert!(insert_block(&text, bin, Syntax::Posix).unwrap().is_none());
        assert!(insert_block(BEGIN_MARKER, bin, Syntax::Posix).is_err());
        assert!(insert_block("", "bad\npath", Syntax::Fish).is_err());
        let original = "# original\n\n\n";
        let inserted = insert_block(original, "/byo/bin", Syntax::Posix)
            .unwrap()
            .unwrap();
        assert_eq!(super::super::remove_block(&inserted).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn profile_symlink_is_preserved_and_uninstall_follows_recorded_target() {
        let (root, paths) = fixture();
        let target = root.join("home/real-profile");
        let link = root.join("home/.zshrc");
        std::fs::write(&target, b"# original\n").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        add_profile(
            &paths,
            Profile {
                path: link.clone(),
                syntax: Syntax::Posix,
            },
            "/byo/bin",
        )
        .unwrap();
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        super::super::revert_recorded_edits(&paths).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"# original\n");
        std::fs::remove_file(&target).unwrap();
        assert!(add_profile(
            &paths,
            Profile {
                path: link.clone(),
                syntax: Syntax::Posix
            },
            "/byo/bin"
        )
        .is_err());
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "qualified native shell job installs bash/zsh/fish/sh before execution"]
    fn generated_profiles_execute_in_real_shell_startup_and_preserve_user_bytes() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        let mut cases = vec!["bash", "zsh", "fish", "sh"];
        if cfg!(target_os = "macos") {
            cases.extend(["bash-login", "bash-profile"]);
        }
        for case in cases {
            let shell = case.split('-').next().unwrap();
            let found = Command::new("/bin/sh")
                .args(["-c", &format!("command -v {shell}")])
                .output()
                .unwrap();
            assert!(
                found.status.success(),
                "required native shell missing: {shell}"
            );
            let executable = String::from_utf8(found.stdout).unwrap();
            let (root, _) = fixture();
            let home = root.join("home");
            let paths = ProductPaths::from_install_dir(&root.join("product ' µ")).unwrap();
            std::fs::create_dir_all(&paths.bin).unwrap();
            let probe = paths.bin.join("byo-startup-probe");
            std::fs::write(
                &probe,
                "#!/bin/sh\nprintf 'actual-generated-profile-startup\\n'\n",
            )
            .unwrap();
            std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755)).unwrap();
            let zdotdir = root.join("custom-zdotdir");
            let xdg = root.join("custom-xdg");
            std::fs::create_dir_all(&zdotdir).unwrap();
            std::fs::create_dir_all(xdg.join("fish")).unwrap();
            if case == "bash-login" {
                std::fs::write(home.join(".bash_login"), "# existing login profile\n").unwrap();
            } else if case == "bash-profile" {
                std::fs::write(home.join(".profile"), "# existing POSIX profile\n").unwrap();
            }
            let profile = choose_profile(
                &home,
                Some(shell),
                cfg!(target_os = "macos"),
                Some(&zdotdir),
                Some(&xdg),
            )
            .unwrap()
            .unwrap();
            let selected = profile.path.clone();
            std::fs::write(&selected, "# unrelated user bytes\n").unwrap();
            let original = std::fs::read(&selected).unwrap();
            add_profile(&paths, profile, paths.bin.to_str().unwrap()).unwrap();
            let generated = std::fs::read(&selected).unwrap();
            assert!(generated.starts_with(&original));
            let mut command = Command::new(executable.trim());
            command
                .env("HOME", &home)
                .env("ZDOTDIR", &zdotdir)
                .env("XDG_CONFIG_HOME", &xdg)
                .env("XDG_DATA_HOME", root.join("xdg-data"))
                .env("XDG_CACHE_HOME", root.join("xdg-cache"))
                .env("SHELL", executable.trim())
                .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                .current_dir(&home)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if shell == "bash" && !cfg!(target_os = "macos") {
                command.args(["--noprofile", "-ic", "byo-startup-probe"]);
            } else if shell == "zsh" || shell == "fish" {
                command.args(["-ic", "byo-startup-probe"]);
            } else {
                command.args(["-lc", "byo-startup-probe"]);
            }
            let mut child = command.spawn().unwrap();
            let deadline = Instant::now() + Duration::from_secs(15);
            while child.try_wait().unwrap().is_none() {
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    let output = child.wait_with_output().unwrap();
                    panic!("native {case} startup timed out: {output:?}");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success(), "{case}: {output:?}");
            assert_eq!(
                output.stdout, b"actual-generated-profile-startup\n",
                "{case}"
            );
            assert_eq!(std::fs::read(&selected).unwrap(), generated);
            super::super::revert_recorded_edits(&paths).unwrap();
            assert_eq!(std::fs::read(&selected).unwrap(), original);
            assert!(!super::super::record_path(&paths).exists());
            println!("native-shell-startup PASS {case} {}", selected.display());
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}
