//! PATH setup for the BYO bin directory, recorded so that uninstall can
//! reverse exactly — and only — what BYO itself added.
//!
//! The bootstrap installers run this during every normal installation. Every
//! edit is written to a record in the state directory, and
//! `revert_recorded_edits` undoes precisely those records, so uninstall never
//! guesses at unrelated PATH entries.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::manifest::write_json;
use crate::paths::{ensure_private_directory, ProductPaths};

#[cfg(any(not(windows), test))]
mod unix;
#[cfg(windows)]
mod windows_registry;

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
    Configured {
        target: String,
    },
    #[cfg(not(windows))]
    Manual {
        instructions: String,
    },
}

fn record_path(paths: &ProductPaths) -> PathBuf {
    paths.state.join(RECORD_NAME)
}

fn load_record(paths: &ProductPaths) -> Result<Option<PathEdits>> {
    let path = record_path(paths);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()))
        }
    };
    let record: PathEdits = serde_json::from_slice(&bytes)
        .with_context(|| format!("PATH-edit record {} is invalid", path.display()))?;
    if record.schema != 1 {
        anyhow::bail!("unsupported PATH-edit record schema");
    }
    Ok(Some(record))
}

fn save_record(paths: &ProductPaths, record: &PathEdits) -> Result<()> {
    ensure_private_directory(&paths.state)?;
    write_json(&record_path(paths), record)
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
    let mut updated = String::with_capacity(contents.len());
    updated.push_str(&contents[..begin]);
    updated.push_str(&contents[after_end..]);
    Some(updated)
}

fn has_valid_block(contents: &str) -> Result<bool> {
    let begins: Vec<_> = contents.match_indices(BEGIN_MARKER).collect();
    let ends: Vec<_> = contents.match_indices(END_MARKER).collect();
    match (begins.as_slice(), ends.as_slice()) {
        ([], []) => Ok(false),
        ([(begin, _)], [(end, _)]) if begin < end => Ok(true),
        _ => anyhow::bail!(
            "profile contains malformed or duplicate BYO PATH markers; original preserved"
        ),
    }
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
        unix::add(paths, &bin)
    }

    #[cfg(windows)]
    {
        let previous = windows_registry::user_path()?;
        let current = previous.as_ref().map_or("", |value| value.text.as_str());
        if windows_path_contains(current, &bin) {
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
        load_record(paths)?; // Refuse a damaged/unreadable record before mutation.
        let value = windows_registry::PathValue::updated(&previous, updated);
        windows_registry::set_user_path(Some(&value))?;
        if let Err(error) = record_edit(
            paths,
            PathEdit {
                kind: EditKind::WindowsUserPath,
                target: "HKCU\\Environment\\Path".to_string(),
                bin,
            },
        ) {
            windows_registry::set_user_path(previous.as_ref())
                .with_context(|| format!("PATH record failed ({error:#}); PATH rollback failed"))?;
            return Err(error);
        }
        windows_notify_environment_change();
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
                if let Some(contents) = read_profile(&profile)? {
                    has_valid_block(&contents)?;
                    if let Some(updated) = remove_block(&contents) {
                        backup_profile(paths, &profile, contents.as_bytes())?;
                        crate::manifest::atomic_write(&profile, updated.as_bytes())?;
                        reverted.push(edit.target.clone());
                    }
                }
            }
            EditKind::WindowsUserPath => {
                #[cfg(windows)]
                {
                    let previous = windows_registry::user_path()?;
                    let current = previous.as_ref().map_or("", |value| value.text.as_str());
                    let updated = windows_path_without(current, &edit.bin);
                    if updated != current {
                        let value = windows_registry::PathValue::updated(&previous, updated);
                        windows_registry::set_user_path(Some(&value))?;
                        windows_notify_environment_change();
                        reverted.push("the Windows user PATH".to_string());
                    }
                }
            }
        }
    }
    std::fs::remove_file(record_path(paths))?;
    Ok(reverted)
}

fn read_profile(path: &std::path::Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // A dangling profile symlink is not an absent profile.
            match std::fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Ok(_) => anyhow::bail!(
                    "profile {} has a missing link target; configure PATH manually",
                    path.display()
                ),
                Err(error) => Err(error.into()),
            }
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "cannot read {}; original preserved; configure PATH manually",
                path.display()
            )
        }),
    }
}

fn backup_profile(paths: &ProductPaths, profile: &std::path::Path, bytes: &[u8]) -> Result<()> {
    ensure_private_directory(&paths.state)?;
    let root = paths.state.join("path-backups");
    ensure_private_directory(&root)?;
    let backup = root.join(format!("{:032x}", rand::random::<u128>()));
    ensure_private_directory(&backup)?;
    crate::manifest::atomic_write(&backup.join("profile"), bytes)?;
    write_json(&backup.join("target.json"), &profile.display().to_string())
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
        .filter(|segment| !segment.eq_ignore_ascii_case(entry))
        .collect::<Vec<_>>()
        .join(";")
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            windows_path_without(";C:\\BYO;;C:\\Other;", "c:\\byo"),
            ";;C:\\Other;"
        );
    }
}
