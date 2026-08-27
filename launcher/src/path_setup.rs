//! PATH setup for the BYO bin directory, recorded so that uninstall can
//! reverse exactly — and only — what BYO itself added.
//!
//! The bootstrap installers run this during every normal installation. Every
//! edit is written to a record in the state directory, and
//! `revert_recorded_edits` undoes precisely those records, so uninstall never
//! guesses at unrelated PATH entries.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::manifest::write_json;
use crate::paths::{ensure_private_directory, ProductPaths};

const BEGIN_MARKER: &str = "# >>> BYO installer >>>";
const END_MARKER: &str = "# <<< BYO installer <<<";
const RECORD_NAME: &str = "path-edits.json";

/// The kind of PATH edit BYO recorded, so reversal can dispatch correctly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum EditKind {
    /// A marked block appended to a POSIX shell profile at `target`.
    UnixProfile,
    /// `bin` appended to the Windows user PATH (`HKCU\Environment\Path`).
    WindowsUserPath,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PathEdit {
    kind: EditKind,
    /// The profile path (Unix) or `HKCU\Environment\Path` (Windows).
    target: String,
    /// The bin directory BYO put on PATH.
    bin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PathEdits {
    schema: u32,
    edits: Vec<PathEdit>,
}

/// The result of a PATH-setup attempt, for a one-line user message.
pub enum PathSetupOutcome {
    AlreadyPresent,
    Configured { target: String },
}

fn record_path(paths: &ProductPaths) -> PathBuf {
    paths.state.join(RECORD_NAME)
}

fn load_record(paths: &ProductPaths) -> Result<Option<PathEdits>> {
    let path = record_path(paths);
    if !path.is_file() {
        return Ok(None);
    }
    let record: PathEdits = serde_json::from_slice(&std::fs::read(&path)?)
        .with_context(|| format!("PATH-edit record {} is invalid", path.display()))?;
    Ok(Some(record))
}

fn save_record(paths: &ProductPaths, record: &PathEdits) -> Result<()> {
    ensure_private_directory(&paths.state)?;
    write_json(&record_path(paths), record)
}

// ---- Pure helpers (unit-tested; no I/O) -----------------------------------

/// The shell profile BYO edits, chosen from the login shell. One file keeps the
/// marked block — and therefore its reversal — unambiguous.
fn choose_unix_profile(home: &Path, shell: Option<&str>) -> PathBuf {
    let leaf = shell
        .and_then(|value| value.rsplit(['/', '\\']).next())
        .unwrap_or("");
    let file = if leaf.contains("zsh") {
        ".zshrc"
    } else if leaf.contains("bash") {
        ".bashrc"
    } else {
        ".profile"
    };
    home.join(file)
}

/// Append the marked export block for `bin`, unless the block is already present.
/// Returns the new file contents, or `None` if BYO already configured this file.
fn insert_block(contents: &str, bin: &str) -> Option<String> {
    if contents.contains(BEGIN_MARKER) {
        return None;
    }
    let mut updated = String::from(contents);
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&format!(
        "{BEGIN_MARKER}\nexport PATH=\"{bin}:$PATH\"\n{END_MARKER}\n"
    ));
    Some(updated)
}

/// Remove a previously inserted marked block. Returns the new contents, or `None`
/// if no BYO block is present (nothing to reverse).
fn remove_block(contents: &str) -> Option<String> {
    let begin = contents.find(BEGIN_MARKER)?;
    let after_end = contents.find(END_MARKER).map(|index| {
        let tail = index + END_MARKER.len();
        // Consume the newline that terminates the end marker, if present.
        if contents[tail..].starts_with('\n') {
            tail + 1
        } else {
            tail
        }
    })?;
    // Drop a single blank separator line immediately before the block, if any,
    // so repeated add/remove cycles don't accumulate blank lines.
    let mut start = begin;
    if contents[..start].ends_with('\n') {
        let trimmed = contents[..start].trim_end_matches('\n');
        if trimmed.len() + 1 < start {
            start = trimmed.len() + 1;
        }
    }
    let mut updated = String::with_capacity(contents.len());
    updated.push_str(&contents[..start]);
    updated.push_str(&contents[after_end..]);
    Some(updated)
}

// ---- Public operations -----------------------------------------------------

/// Put the BYO bin directory on PATH, recording the edit for reversal.
pub fn add_bin_to_path(paths: &ProductPaths) -> Result<PathSetupOutcome> {
    let bin = paths
        .bin
        .to_str()
        .context("BYO bin directory path is not valid UTF-8")?
        .to_string();

    #[cfg(not(windows))]
    {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .context("HOME is required to modify PATH")?;
        let shell = std::env::var("SHELL").ok();
        let profile = choose_unix_profile(&home, shell.as_deref());
        let existing = std::fs::read_to_string(&profile).unwrap_or_default();
        match insert_block(&existing, &bin) {
            None => Ok(PathSetupOutcome::AlreadyPresent),
            Some(updated) => {
                if let Some(parent) = profile.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&profile, updated)
                    .with_context(|| format!("failed to update {}", profile.display()))?;
                record_edit(
                    paths,
                    PathEdit {
                        kind: EditKind::UnixProfile,
                        target: profile.display().to_string(),
                        bin,
                    },
                )?;
                Ok(PathSetupOutcome::Configured {
                    target: profile.display().to_string(),
                })
            }
        }
    }

    #[cfg(windows)]
    {
        let current = windows_user_path()?;
        if windows_path_contains(&current, &bin) {
            // A previous BYO version wrote the registry value without notifying
            // the shell. Repeat the bounded notification even when the value is
            // already present so re-running the installer repairs that state.
            windows_notify_environment_change();
            return Ok(PathSetupOutcome::AlreadyPresent);
        }
        let updated = if current.is_empty() {
            bin.clone()
        } else {
            format!("{current};{bin}")
        };
        windows_set_user_path(&updated)?;
        record_edit(
            paths,
            PathEdit {
                kind: EditKind::WindowsUserPath,
                target: "HKCU\\Environment\\Path".to_string(),
                bin,
            },
        )?;
        Ok(PathSetupOutcome::Configured {
            target: "the Windows user PATH".to_string(),
        })
    }
}

fn record_edit(paths: &ProductPaths, edit: PathEdit) -> Result<()> {
    let mut record = load_record(paths)?.unwrap_or(PathEdits {
        schema: 1,
        edits: Vec::new(),
    });
    if !record.edits.contains(&edit) {
        record.edits.push(edit);
    }
    save_record(paths, &record)
}

/// Reverse exactly the PATH edits BYO recorded, then drop the record. Returns a
/// human-readable list of what was reverted (for the uninstall receipt). Safe to
/// call when nothing was recorded.
pub fn revert_recorded_edits(paths: &ProductPaths) -> Result<Vec<String>> {
    let Some(record) = load_record(paths)? else {
        return Ok(Vec::new());
    };
    let mut reverted = Vec::new();
    for edit in &record.edits {
        match edit.kind {
            EditKind::UnixProfile => {
                let profile = PathBuf::from(&edit.target);
                if let Ok(contents) = std::fs::read_to_string(&profile) {
                    if let Some(updated) = remove_block(&contents) {
                        std::fs::write(&profile, updated).with_context(|| {
                            format!("failed to revert PATH edit in {}", profile.display())
                        })?;
                        reverted.push(edit.target.clone());
                    }
                }
            }
            EditKind::WindowsUserPath => {
                #[cfg(windows)]
                {
                    let current = windows_user_path()?;
                    let updated = windows_path_without(&current, &edit.bin);
                    if updated != current {
                        windows_set_user_path(&updated)?;
                        reverted.push("the Windows user PATH".to_string());
                    }
                }
            }
        }
    }
    let _ = std::fs::remove_file(record_path(paths));
    Ok(reverted)
}

// ---- Windows PATH via `reg` (thin; not exercised on non-Windows hosts) ------

#[cfg(windows)]
fn windows_user_path() -> Result<String> {
    use std::process::Command;
    let output = Command::new("reg")
        .args(["query", "HKCU\\Environment", "/v", "Path"])
        .output()
        .context("failed to query the Windows user PATH")?;
    if !output.status.success() {
        // No Path value yet.
        return Ok(String::new());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if let Some(index) = line.find("REG_") {
            if let Some(rest) = line[index..].split_once("SZ") {
                return Ok(rest.1.trim().to_string());
            }
        }
    }
    Ok(String::new())
}

#[cfg(windows)]
fn windows_set_user_path(value: &str) -> Result<()> {
    use std::process::Command;
    let status = Command::new("reg")
        .args([
            "add",
            "HKCU\\Environment",
            "/v",
            "Path",
            "/t",
            "REG_EXPAND_SZ",
            "/d",
            value,
            "/f",
        ])
        .status()
        .context("failed to update the Windows user PATH")?;
    if !status.success() {
        anyhow::bail!("reg add for the user PATH failed");
    }
    windows_notify_environment_change();
    Ok(())
}

/// Tell Windows shells that the user environment changed. Existing processes
/// retain their own environment block, but Explorer and subsequently launched
/// terminals can rebuild PATH after this broadcast. The notification is best
/// effort: the registry update is already durable, and a hung application must
/// never turn a successful install or uninstall into a failure.
#[cfg(windows)]
fn windows_notify_environment_change() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
    };

    let environment: Vec<u16> = "Environment\0".encode_utf16().collect();
    let mut result = 0usize;
    // SAFETY: `environment` is NUL-terminated and remains alive for the
    // synchronous call. The Windows API does not retain the pointer.
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            environment.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            5_000,
            &mut result,
        );
    }
}

#[cfg(windows)]
fn windows_path_contains(path: &str, entry: &str) -> bool {
    path.split(';')
        .any(|segment| segment.eq_ignore_ascii_case(entry))
}

#[cfg(windows)]
fn windows_path_without(path: &str, entry: &str) -> String {
    path.split(';')
        .filter(|segment| !segment.eq_ignore_ascii_case(entry) && !segment.is_empty())
        .collect::<Vec<_>>()
        .join(";")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_choice_follows_the_login_shell() {
        let home = Path::new("/home/dev");
        assert_eq!(
            choose_unix_profile(home, Some("/bin/zsh")),
            home.join(".zshrc")
        );
        assert_eq!(
            choose_unix_profile(home, Some("/usr/bin/bash")),
            home.join(".bashrc")
        );
        assert_eq!(choose_unix_profile(home, None), home.join(".profile"));
        assert_eq!(
            choose_unix_profile(home, Some("/usr/bin/fish")),
            home.join(".profile")
        );
    }

    #[test]
    fn insert_is_idempotent_and_appends_a_marked_block() {
        let first = insert_block("export EDITOR=vim\n", "/home/dev/.local/bin")
            .expect("first insert applies");
        assert!(first.contains(BEGIN_MARKER));
        assert!(first.contains("export PATH=\"/home/dev/.local/bin:$PATH\""));
        assert!(first.contains(END_MARKER));
        // A second insert over already-configured contents is a no-op.
        assert!(insert_block(&first, "/home/dev/.local/bin").is_none());
    }

    #[test]
    fn insert_then_remove_restores_original_contents() {
        let original = "export EDITOR=vim\n";
        let inserted = insert_block(original, "/opt/byo/bin").expect("insert applies");
        let removed = remove_block(&inserted).expect("remove applies");
        assert_eq!(removed, original);
        // Nothing left to remove.
        assert!(remove_block(&removed).is_none());
    }

    #[test]
    fn remove_on_unmanaged_file_is_a_noop() {
        assert!(remove_block("export PATH=/usr/bin\n").is_none());
    }

    #[cfg(windows)]
    #[test]
    fn windows_path_membership_and_removal_are_case_insensitive() {
        let path = "C:\\Windows;C:\\Users\\dev\\AppData\\Local\\BYO\\bin";
        assert!(windows_path_contains(
            path,
            "c:\\users\\dev\\appdata\\local\\byo\\bin"
        ));
        assert_eq!(
            windows_path_without(path, "C:\\Users\\dev\\AppData\\Local\\BYO\\bin"),
            "C:\\Windows"
        );
    }
}
