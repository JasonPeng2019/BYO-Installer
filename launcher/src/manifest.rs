use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::error::{categorize, ExitCategory};

const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub schema: u32,
    pub product: String,
    pub version: String,
    pub channel: String,
    pub platform: String,
    pub architecture: String,
    pub launcher_protocol: u32,
    pub sidecar_protocol: u32,
    pub worker_protocol: u32,
    pub workflow_protocol: u32,
    pub capsule_schema: u32,
    pub project_state_schema: u32,
    pub development_unsigned: bool,
    pub source: SourceProvenance,
    pub toolchain: ToolchainProvenance,
    pub files: Vec<ReleaseFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceProvenance {
    pub installer: SourceRevision,
    pub agent_workspace: SourceRevision,
    pub firmware_mcp: SourceRevision,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRevision {
    pub repository: String,
    pub commit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainProvenance {
    pub rustc: String,
    pub cargo: String,
    pub python: String,
    pub nuitka: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseFile {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub kind: String,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentRuntime {
    pub schema: u32,
    pub version: String,
    pub relative_runtime: String,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestSignature {
    schema: u32,
    algorithm: String,
    key_id: String,
    signature: String,
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn sha256_bytes(payload: &[u8]) -> String {
    hex::encode(Sha256::digest(payload))
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("failed to inspect {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > maximum {
        bail!(
            "{} is not a bounded regular file (maximum {} bytes)",
            path.display(),
            maximum
        );
    }
    std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))
}

fn canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => output.extend_from_slice(serde_json::to_string(value)?.as_bytes()),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                canonical_json(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(serde_json::to_string(key)?.as_bytes());
                output.push(b':');
                canonical_json(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

pub fn canonical_manifest_bytes(value: &Value) -> Result<Vec<u8>> {
    if !value.is_object() {
        bail!("release manifest must be a JSON object");
    }
    let mut output = Vec::new();
    canonical_json(value, &mut output)?;
    Ok(output)
}

pub(crate) fn trusted_release_keys() -> Result<Vec<(String, VerifyingKey)>> {
    let encoded = option_env!("BYO_RELEASE_PUBLIC_KEYS").unwrap_or("{}");
    let values: std::collections::BTreeMap<String, String> =
        serde_json::from_str(encoded).context("compiled release public-key map is invalid")?;
    let mut keys = Vec::new();
    for (key_id, encoded_key) in values {
        if key_id.is_empty() || key_id.len() > 128 {
            bail!("compiled release key identifier is invalid");
        }
        let bytes = hex::decode(encoded_key)
            .with_context(|| format!("compiled release key {key_id} is not hexadecimal"))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("compiled release key {key_id} is not 32 bytes"))?;
        let key = VerifyingKey::from_bytes(&bytes)
            .with_context(|| format!("compiled release key {key_id} is invalid"))?;
        if key.is_weak() {
            bail!("compiled release key {key_id} is weak");
        }
        keys.push((key_id, key));
    }
    Ok(keys)
}

pub(crate) fn verify_value_signature(
    value: &Value,
    key_id: &str,
    encoded_signature: &str,
    keys: &[(String, VerifyingKey)],
) -> Result<()> {
    let (_, key) = keys
        .iter()
        .find(|(trusted_id, _)| trusted_id == key_id)
        .context("signature uses an untrusted or revoked key")?;
    let raw_signature = hex::decode(encoded_signature).context("signature is not hexadecimal")?;
    let signature = Signature::from_slice(&raw_signature).context("signature is malformed")?;
    key.verify_strict(&canonical_manifest_bytes(value)?, &signature)
        .context("signature verification failed")
}

fn verify_manifest_signature_with_keys(
    runtime: &Path,
    manifest: &Value,
    keys: &[(String, VerifyingKey)],
) -> Result<()> {
    let path = runtime.join("release-manifest.sig");
    let bytes = read_bounded(&path, MAX_SIGNATURE_BYTES)
        .context("signed release manifest is missing its detached signature")?;
    let envelope: ManifestSignature =
        serde_json::from_slice(&bytes).context("release manifest signature envelope is invalid")?;
    if envelope.schema != 1 || envelope.algorithm != "Ed25519" {
        bail!("release manifest signature algorithm or schema is unsupported");
    }
    verify_value_signature(manifest, &envelope.key_id, &envelope.signature, keys)
        .context("release manifest signature verification failed")
}

fn safe_relative(raw: &str) -> Result<PathBuf> {
    let path = Path::new(raw);
    let first = raw.split('/').next().unwrap_or_default();
    if raw.is_empty() || path.is_absolute() || raw.contains('\\') || first.ends_with(':') {
        bail!("manifest path must be a non-empty relative path: {raw}");
    }
    if path
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        bail!("manifest path contains an unsafe component: {raw}");
    }
    Ok(path.to_path_buf())
}

pub fn load_release_manifest(runtime: &Path) -> Result<ReleaseManifest> {
    let path = runtime.join("release-manifest.json");
    let bytes = read_bounded(&path, MAX_MANIFEST_BYTES)?;
    let value: Value =
        serde_json::from_slice(&bytes).context("release manifest JSON is invalid")?;
    let development_unsigned = value
        .get("development_unsigned")
        .and_then(Value::as_bool)
        .context("release manifest development_unsigned field is invalid")?;
    if development_unsigned {
        if !cfg!(feature = "development") {
            return Err(crate::error::fail(
                ExitCategory::Signature,
                "unsigned development runtime refused by production launcher",
            ));
        }
    } else {
        let keys = categorize(trusted_release_keys(), ExitCategory::Signature)?;
        if keys.is_empty() {
            return Err(crate::error::fail(
                ExitCategory::Signature,
                "production launcher contains no trusted release verification keys",
            ));
        }
        categorize(
            verify_manifest_signature_with_keys(runtime, &value, &keys),
            ExitCategory::Signature,
        )?;
    }
    let manifest: ReleaseManifest =
        serde_json::from_value(value).context("release manifest JSON is invalid")?;
    if manifest.schema != 1
        || manifest.product != "byo"
        || manifest.launcher_protocol != 1
        || manifest.sidecar_protocol != 1
        || manifest.worker_protocol != 1
        || manifest.workflow_protocol != 1
        || manifest.capsule_schema != 1
        || manifest.project_state_schema != 1
    {
        bail!("release manifest declares an unsupported protocol or schema");
    }
    Ok(manifest)
}

pub fn verify_runtime(runtime: &Path) -> Result<ReleaseManifest> {
    let root = runtime
        .canonicalize()
        .with_context(|| format!("runtime does not exist: {}", runtime.display()))?;
    if !root.is_dir() {
        bail!("runtime root is not a directory");
    }
    let manifest = load_release_manifest(&root)?;
    let mut declared = BTreeSet::new();
    let mut declared_casefolded = BTreeSet::new();
    for file in &manifest.files {
        let relative = safe_relative(&file.path)?;
        if !declared.insert(relative.clone()) {
            bail!("duplicate manifest path: {}", file.path);
        }
        if !declared_casefolded.insert(file.path.to_lowercase()) {
            bail!("case-colliding manifest path: {}", file.path);
        }
        let target = root.join(&relative);
        let metadata = std::fs::symlink_metadata(&target)
            .with_context(|| format!("manifest file is missing: {}", file.path))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("manifest entry is not a regular file: {}", file.path);
        }
        if metadata.len() != file.size {
            bail!("manifest size mismatch: {}", file.path);
        }
        if sha256_file(&target)? != file.sha256 {
            bail!("manifest digest mismatch: {}", file.path);
        }
    }

    for entry in WalkDir::new(&root).follow_links(false) {
        let entry = entry?;
        if entry.path() == root || entry.file_type().is_dir() {
            continue;
        }
        if entry.file_type().is_symlink() || !entry.file_type().is_file() {
            bail!(
                "runtime contains a non-regular entry: {}",
                entry.path().display()
            );
        }
        let relative = entry.path().strip_prefix(&root)?.to_path_buf();
        let allowed_metadata = relative == Path::new("release-manifest.json")
            || relative == Path::new("release-manifest.sig");
        if !allowed_metadata && !declared.contains(&relative) {
            bail!(
                "runtime contains an unexpected file: {}",
                relative.display()
            );
        }
    }
    Ok(manifest)
}

pub fn load_current(paths: &crate::paths::ProductPaths) -> Result<(CurrentRuntime, PathBuf)> {
    let bytes = std::fs::read(paths.current()).context("BYO current.json is missing")?;
    let current: CurrentRuntime =
        serde_json::from_slice(&bytes).context("BYO current.json is invalid")?;
    if current.schema != 1 {
        bail!("BYO current.json schema is unsupported");
    }
    let relative = safe_relative(&current.relative_runtime)?;
    let runtime = paths.data.join(relative);
    let runtime = runtime
        .canonicalize()
        .context("selected BYO runtime is missing")?;
    let versions = paths
        .versions()
        .canonicalize()
        .context("BYO versions directory is missing")?;
    if !runtime.starts_with(&versions) {
        bail!("selected runtime escapes the BYO versions directory");
    }
    let manifest_path = runtime.join("release-manifest.json");
    if sha256_file(&manifest_path)? != current.manifest_sha256 {
        bail!("current runtime manifest digest does not match current.json");
    }
    Ok((current, runtime))
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("atomic target has no parent")?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("byo"),
        rand::random::<u64>()
    ));
    {
        let mut file = File::create(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&temporary, path)?;
    Ok(())
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut payload = serde_json::to_vec_pretty(value)?;
    payload.push(b'\n');
    atomic_write(path, &payload)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    #[test]
    fn canonical_json_is_independent_of_object_key_order() {
        let left = serde_json::json!({"z": [3, 2, 1], "a": {"b": true, "a": null}});
        let right = serde_json::json!({"a": {"a": null, "b": true}, "z": [3, 2, 1]});
        assert_eq!(
            canonical_manifest_bytes(&left).unwrap(),
            canonical_manifest_bytes(&right).unwrap()
        );
        assert_eq!(
            canonical_manifest_bytes(&left).unwrap(),
            br#"{"a":{"a":null,"b":true},"z":[3,2,1]}"#
        );
    }

    #[test]
    fn ed25519_verification_accepts_only_the_signed_canonical_value() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let value = serde_json::json!({"schema": 1, "product": "byo"});
        let signature = signing_key.sign(&canonical_manifest_bytes(&value).unwrap());
        let keys = vec![("test-key".to_string(), signing_key.verifying_key())];
        verify_value_signature(
            &value,
            "test-key",
            &hex::encode(signature.to_bytes()),
            &keys,
        )
        .unwrap();
        let modified = serde_json::json!({"schema": 1, "product": "not-byo"});
        assert!(verify_value_signature(
            &modified,
            "test-key",
            &hex::encode(signature.to_bytes()),
            &keys,
        )
        .is_err());
        assert!(verify_value_signature(
            &value,
            "unknown",
            &hex::encode(signature.to_bytes()),
            &keys
        )
        .is_err());
    }

    #[test]
    fn portable_manifest_paths_reject_windows_and_posix_escapes() {
        assert!(safe_relative("sidecar/byo-mcp-sidecar").is_ok());
        assert!(safe_relative("../escape").is_err());
        assert!(safe_relative("/absolute").is_err());
        assert!(safe_relative(r"C:\escape").is_err());
        assert!(safe_relative("C:/escape").is_err());
    }
}
