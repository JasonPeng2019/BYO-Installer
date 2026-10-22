//! Unicode registry values, with missing values distinct from read failures.
use anyhow::{bail, Context, Result};
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_EXPAND_SZ,
    REG_OPTION_NON_VOLATILE, REG_SZ,
};

const MAX_VALUE_BYTES: u32 = 128 * 1024;

pub(super) struct PathValue {
    pub text: String,
    kind: u32,
}

impl PathValue {
    pub(super) fn updated(previous: &Option<Self>, text: String) -> Self {
        Self {
            text,
            kind: previous.as_ref().map_or(REG_EXPAND_SZ, |value| value.kind),
        }
    }
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: this wrapper exclusively owns the opened registry handle.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

fn wide(text: &str) -> Result<Vec<u16>> {
    if text.contains('\0') {
        bail!("registry string contains NUL");
    }
    Ok(text.encode_utf16().chain(Some(0)).collect())
}

fn open(subkey: &str, write: bool) -> Result<Option<Key>> {
    let subkey = wide(subkey)?;
    let mut handle = std::ptr::null_mut();
    // SAFETY: strings are terminated and output points to a live HKEY slot.
    let status = unsafe {
        if write {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
                std::ptr::null(),
                &mut handle,
                std::ptr::null_mut(),
            )
        } else {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                KEY_QUERY_VALUE,
                &mut handle,
            )
        }
    };
    if !write && status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32).into());
    }
    Ok(Some(Key(handle)))
}

fn read(key: &Key) -> Result<Option<PathValue>> {
    let name = wide("Path")?;
    for _ in 0..4 {
        let mut kind = 0;
        let mut size = 0;
        // SAFETY: first query requests size only; output slots are live.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                std::ptr::null(),
                &mut kind,
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(status as i32).into());
        }
        if size > MAX_VALUE_BYTES || size % 2 != 0 {
            bail!("Windows user PATH has an invalid size");
        }
        let mut data = vec![0u16; (size as usize / 2).max(1)];
        // SAFETY: data is an aligned writable allocation of at least `size` bytes.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                std::ptr::null(),
                &mut kind,
                data.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if status == ERROR_MORE_DATA {
            continue;
        }
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(status as i32).into());
        }
        if !matches!(kind, REG_SZ | REG_EXPAND_SZ) {
            bail!("Windows user PATH is not REG_SZ or REG_EXPAND_SZ; original preserved");
        }
        if size % 2 != 0 || size as usize > data.len() * 2 {
            bail!("Windows user PATH has invalid UTF-16 bytes");
        }
        data.truncate(size as usize / 2);
        if data.last() == Some(&0) {
            data.pop();
        }
        if data.contains(&0) {
            bail!("Windows user PATH contains embedded NUL; original preserved");
        }
        return Ok(Some(PathValue {
            text: String::from_utf16(&data)
                .context("Windows user PATH is invalid UTF-16; original preserved")?,
            kind,
        }));
    }
    bail!("Windows user PATH changed repeatedly while reading; retry PATH setup")
}

fn write(key: &Key, value: Option<&PathValue>) -> Result<()> {
    let name = wide("Path")?;
    let status = if let Some(value) = value {
        if !matches!(value.kind, REG_SZ | REG_EXPAND_SZ) {
            bail!("unsupported PATH registry type");
        }
        let data = wide(&value.text)?;
        let size = u32::try_from(data.len() * 2)?;
        if size > MAX_VALUE_BYTES {
            bail!("Windows user PATH is too large");
        }
        // SAFETY: input buffers are live, terminated UTF-16 strings.
        unsafe {
            RegSetValueExW(
                key.0,
                name.as_ptr(),
                0,
                value.kind,
                data.as_ptr().cast(),
                size,
            )
        }
    } else {
        // SAFETY: the terminated value name is live for the call.
        unsafe { RegDeleteValueW(key.0, name.as_ptr()) }
    };
    if status != ERROR_SUCCESS && !(value.is_none() && status == ERROR_FILE_NOT_FOUND) {
        return Err(std::io::Error::from_raw_os_error(status as i32).into());
    }
    Ok(())
}

pub(super) fn user_path() -> Result<Option<PathValue>> {
    match open("Environment", false)
        .context("failed to open Windows user environment; original PATH preserved")?
    {
        Some(key) => read(&key).context("failed to read Windows user PATH; original preserved"),
        None => Ok(None),
    }
}

pub(super) fn set_user_path(value: Option<&PathValue>) -> Result<()> {
    let key = open("Environment", true)?.context("Windows environment key is missing")?;
    write(&key, value).context("failed to write Windows user PATH")
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Registry::{RegDeleteKeyW, REG_BINARY};

    #[test]
    fn native_unicode_roundtrip_retains_type_and_refuses_bad_reads() {
        // Never query or mutate the developer's real Environment\Path.
        let name = format!("Software\\BYO-Tests\\path-{:032x}", rand::random::<u128>());
        let key = open(&name, true).unwrap().unwrap();
        assert!(read(&key).unwrap().is_none());
        for kind in [REG_SZ, REG_EXPAND_SZ] {
            let original = PathValue {
                text: "C:\\Tëst\\测试\\🙂;%USERPROFILE%\\bin;;".to_string(),
                kind,
            };
            write(&key, Some(&original)).unwrap();
            let result = read(&key).unwrap().unwrap();
            assert_eq!(result.text, original.text);
            assert_eq!(result.kind, kind);
            let updated = PathValue::updated(&Some(result), original.text.clone() + ";C:\\BYO");
            write(&key, Some(&updated)).unwrap();
            let result = read(&key).unwrap().unwrap();
            assert_eq!(result.kind, kind);
            assert_eq!(
                super::super::windows_path_without(&result.text, "C:\\BYO"),
                original.text
            );
        }
        let value_name = wide("Path").unwrap();
        // SAFETY: valid owned test key and bounded live input buffer.
        assert_eq!(
            unsafe {
                RegSetValueExW(
                    key.0,
                    value_name.as_ptr(),
                    0,
                    REG_BINARY,
                    [1u8, 2].as_ptr(),
                    2,
                )
            },
            ERROR_SUCCESS
        );
        assert!(read(&key).is_err());
        let invalid = Key(std::ptr::null_mut());
        assert!(read(&invalid).is_err());
        drop(invalid);
        write(&key, None).unwrap();
        assert!(read(&key).unwrap().is_none());
        drop(key);
        let name = wide(&name).unwrap();
        // SAFETY: deletes only this test's exact randomly named empty key.
        assert_eq!(
            unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, name.as_ptr()) },
            ERROR_SUCCESS
        );
    }
}
