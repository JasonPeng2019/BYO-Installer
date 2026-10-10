//! Target rows and native header validation, also testable on a Windows host.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Target {
    Windows,
    MacArm,
    MacIntel,
    Linux,
}
impl Target {
    pub fn parse(platform: &str, architecture: &str) -> Result<Self> {
        match (platform, architecture) {
            ("windows", "x86_64") => Ok(Self::Windows),
            ("macos", "aarch64") => Ok(Self::MacArm),
            ("macos", "x86_64") => Ok(Self::MacIntel),
            ("linux", "x86_64") => Ok(Self::Linux),
            _ => Err(runtime::invalid("Unsupported runtime target")),
        }
    }
    pub fn host() -> Result<Self> {
        Self::parse(
            if cfg!(target_os = "macos") {
                "macos"
            } else {
                std::env::consts::OS
            },
            std::env::consts::ARCH,
        )
    }
    pub fn executable(self, program: &str) -> String {
        let suffix = if self == Self::Windows { ".exe" } else { "" };
        match program {
            "cppcheck" => format!("analysis/cppcheck/cppcheck{suffix}"),
            _ => format!("analysis/clangd/bin/clangd{suffix}"),
        }
    }
    pub fn dependency(self, program: &str, path: &str) -> bool {
        let prefix = if self == Self::Windows {
            if program == "cppcheck" {
                "analysis/cppcheck/".into()
            } else {
                "analysis/clangd/bin/".into()
            }
        } else {
            format!("analysis/{program}/lib/")
        };
        path.strip_prefix(&prefix).is_some_and(|leaf| {
            if leaf.contains('/') {
                return false;
            }
            match self {
                Self::Windows => leaf.ends_with(".dll"),
                Self::MacArm | Self::MacIntel => leaf.ends_with(".dylib"),
                Self::Linux => {
                    leaf.ends_with(".so")
                        || leaf.split_once(".so.").is_some_and(|(name, version)| {
                            !name.is_empty()
                                && version
                                    .split('.')
                                    .all(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                        })
                }
            }
        })
    }
    pub fn validate(self, bytes: &[u8], dependency: bool) -> Result<()> {
        let valid = match self {
            Self::Windows => {
                let offset = bytes
                    .get(60..64)
                    .map(|v| u32::from_le_bytes(v.try_into().unwrap()) as usize)
                    .unwrap_or(usize::MAX);
                let optional_size = bytes
                    .get(offset.saturating_add(20)..offset.saturating_add(22))
                    .map(|v| u16::from_le_bytes(v.try_into().unwrap()) as usize)
                    .unwrap_or(0);
                let characteristics = bytes
                    .get(offset.saturating_add(22)..offset.saturating_add(24))
                    .map(|v| u16::from_le_bytes(v.try_into().unwrap()))
                    .unwrap_or(0);
                bytes.get(..2) == Some(b"MZ")
                    && offset >= 64
                    && optional_size >= 112
                    && offset
                        .checked_add(24)
                        .and_then(|start| start.checked_add(optional_size))
                        .is_some_and(|end| end <= bytes.len())
                    && bytes.get(offset..offset.saturating_add(4)) == Some(b"PE\0\0")
                    && bytes.get(offset.saturating_add(4)..offset.saturating_add(6))
                        == Some(&[0x64, 0x86])
                    && bytes.get(offset.saturating_add(24)..offset.saturating_add(26))
                        == Some(&[0x0b, 0x02])
                    && characteristics & 0x0002 != 0
                    && (characteristics & 0x2000 != 0) == dependency
            }
            Self::MacArm | Self::MacIntel => {
                let cpu: u32 = if self == Self::MacArm {
                    0x0100_000c
                } else {
                    0x0100_0007
                };
                bytes.len() >= 32
                    && bytes[..4] == [0xcf, 0xfa, 0xed, 0xfe]
                    && bytes[4..8] == cpu.to_le_bytes()
                    && u32::from_le_bytes(bytes[12..16].try_into().unwrap())
                        == if dependency { 6 } else { 2 }
            }
            Self::Linux => {
                bytes.len() >= 64
                    && &bytes[..7] == b"\x7fELF\x02\x01\x01"
                    && bytes[18..20] == [62, 0]
                    && bytes[20..24] == [1, 0, 0, 0]
                    && u16::from_le_bytes(bytes[52..54].try_into().unwrap()) == 64
                    && if dependency {
                        bytes[16..18] == [3, 0]
                    } else {
                        [2u16, 3].contains(&u16::from_le_bytes(bytes[16..18].try_into().unwrap()))
                    }
            }
        };
        if valid {
            Ok(())
        } else {
            Err(runtime::invalid(
                "Malformed, incompatible or non-native payload header",
            ))
        }
    }
}

pub(super) fn executable_access(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
        let metadata = fs::metadata(path)?;
        let path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| runtime::invalid("NUL in executable path"))?;
        if metadata.mode() & 0o111 == 0
            || metadata.mode() & 0o6000 != 0
            || unsafe { libc::access(path.as_ptr(), libc::X_OK) } != 0
        {
            return Err(runtime::invalid(
                "Native executable is not executable by this caller",
            ));
        }
    }
    #[cfg(windows)]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn neutral_target_headers_reject_wrong_architecture_type_and_truncation() {
        let mut pe = vec![0; 64 + 24 + 240];
        pe[..2].copy_from_slice(b"MZ");
        pe[60..64].copy_from_slice(&64u32.to_le_bytes());
        pe[64..68].copy_from_slice(b"PE\0\0");
        pe[68..70].copy_from_slice(&[0x64, 0x86]);
        pe[84..86].copy_from_slice(&240u16.to_le_bytes());
        pe[86..88].copy_from_slice(&2u16.to_le_bytes());
        pe[88..90].copy_from_slice(&[0x0b, 0x02]);
        assert!(Target::Windows.validate(&pe, false).is_ok());
        assert!(Target::Windows.validate(&pe[..90], false).is_err());
        assert!(Target::Windows.validate(&pe, true).is_err());
        pe[86..88].copy_from_slice(&0x2002u16.to_le_bytes());
        assert!(Target::Windows.validate(&pe, true).is_ok());
        let mut elf = vec![0; 64];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16] = 3;
        elf[18] = 62;
        elf[20] = 1;
        elf[52] = 64;
        assert!(Target::Linux.validate(&elf, false).is_ok());
        assert!(Target::Linux.validate(&elf, true).is_ok());
        elf[18] = 183;
        assert!(Target::Linux.validate(&elf, false).is_err());
        for target in [Target::MacArm, Target::MacIntel] {
            let mut macho = vec![0; 32];
            macho[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
            macho[4..8].copy_from_slice(
                &(if target == Target::MacArm {
                    0x0100_000cu32
                } else {
                    0x0100_0007u32
                })
                .to_le_bytes(),
            );
            macho[12] = 2;
            assert!(target.validate(&macho, false).is_ok());
            assert!(target.validate(&macho, true).is_err());
            assert!(target.validate(&macho[..31], false).is_err());
            macho[12] = 6;
            assert!(target.validate(&macho, true).is_ok());
        }
        for target in [
            Target::Windows,
            Target::MacArm,
            Target::MacIntel,
            Target::Linux,
        ] {
            assert!(target.validate(b"#!/bin/sh\n", false).is_err());
        }
        assert!(Target::Linux.dependency("cppcheck", "analysis/cppcheck/lib/libx.so.1.2"));
        assert!(!Target::Linux.dependency("cppcheck", "analysis/cppcheck/lib/libx.so.bad"));
        assert!(!Target::MacArm.dependency("clangd", "analysis/clangd/bin/x.dylib"));
    }
}
