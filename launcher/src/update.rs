use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cli::UpdateArgs;
use crate::error::{categorize, ExitCategory};
use crate::install;
use crate::manifest::{self, sha256_bytes};
use crate::paths::{ensure_private_directory, ProductPaths};

const MAX_METADATA_BYTES: usize = 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EXTRACTED_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EXTRACTED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveType {
    TarGz,
    Zip,
}

impl ArchiveType {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "tar.gz" => Ok(Self::TarGz),
            "zip" => Ok(Self::Zip),
            _ => bail!("selected update archive type is unsupported"),
        }
    }

    fn expected_for_platform(platform: &str) -> Result<Self> {
        match platform {
            "linux" => Ok(Self::TarGz),
            "macos" | "windows" => Ok(Self::Zip),
            _ => bail!("selected update platform is unsupported"),
        }
    }

    fn extension(self) -> &'static str {
        match self {
            Self::TarGz => "tar.gz",
            Self::Zip => "zip",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedChannelDocument {
    schema: u32,
    signed: Value,
    signatures: Vec<ChannelSignature>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelSignature {
    algorithm: String,
    key_id: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelMetadata {
    schema: u32,
    product: String,
    channel: String,
    sequence: u64,
    generated_at: String,
    expires_at: String,
    releases: Vec<ChannelArtifact>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustedChannelState {
    schema: u32,
    channel: String,
    sequence: u64,
    signed_sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelArtifact {
    version: String,
    platform: String,
    architecture: String,
    url: String,
    archive_type: String,
    archive_sha256: String,
    archive_size: u64,
    manifest_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct UpdateOutcome {
    pub version: String,
    pub channel: String,
    pub platform: String,
    pub architecture: String,
    pub url: String,
    pub dry_run: bool,
}

fn read_metadata(arguments: &UpdateArgs) -> Result<Vec<u8>> {
    if let Some(path) = arguments.metadata_file.as_deref() {
        if !cfg!(feature = "development") {
            bail!("local update metadata is disabled in production launchers");
        }
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("failed to inspect update metadata {}", path.display()))?;
        if !metadata.is_file() || metadata.len() > MAX_METADATA_BYTES as u64 {
            bail!("local update metadata is not a bounded regular file");
        }
        return std::fs::read(path).context("failed to read local update metadata");
    }
    let url = arguments
        .metadata_url
        .as_deref()
        .or(option_env!("BYO_UPDATE_METADATA_URL"))
        .context("no signed update metadata URL is configured")?;
    download(url, MAX_METADATA_BYTES as u64)
}

fn download(url: &str, limit: u64) -> Result<Vec<u8>> {
    if !url.starts_with("https://") {
        bail!("update downloads require an HTTPS URL");
    }
    let configuration = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(120)))
        .https_only(true)
        .build();
    let agent = ureq::Agent::new_with_config(configuration);
    let mut response = agent
        .get(url)
        .call()
        .with_context(|| format!("update download failed for {url}"))?;
    response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .with_context(|| format!("update response exceeded {limit} bytes or could not be read"))
}

fn verify_channel_document(bytes: &[u8]) -> Result<(ChannelMetadata, String)> {
    let keys = categorize(manifest::trusted_release_keys(), ExitCategory::Signature)?;
    if keys.is_empty() {
        return Err(crate::error::fail(
            ExitCategory::Signature,
            "launcher contains no trusted update verification keys",
        ));
    }
    verify_channel_document_with_keys(bytes, &keys, Utc::now())
}

fn verify_channel_document_with_keys(
    bytes: &[u8],
    keys: &[(String, ed25519_dalek::VerifyingKey)],
    now: DateTime<Utc>,
) -> Result<(ChannelMetadata, String)> {
    let document: SignedChannelDocument = categorize(
        serde_json::from_slice(bytes).context("signed channel metadata is invalid"),
        ExitCategory::Signature,
    )?;
    if document.schema != 1 || document.signatures.is_empty() {
        return Err(crate::error::fail(
            ExitCategory::Signature,
            "signed channel metadata has an unsupported schema or no signatures",
        ));
    }
    let mut verified = false;
    let mut diagnostics = Vec::new();
    for signature in &document.signatures {
        if signature.algorithm != "Ed25519" {
            diagnostics.push(format!("{}: unsupported algorithm", signature.key_id));
            continue;
        }
        match manifest::verify_value_signature(
            &document.signed,
            &signature.key_id,
            &signature.signature,
            keys,
        ) {
            Ok(()) => {
                verified = true;
                break;
            }
            Err(error) => diagnostics.push(format!("{}: {error:#}", signature.key_id)),
        }
    }
    if !verified {
        return Err(crate::error::fail(
            ExitCategory::Signature,
            format!(
                "signed channel metadata verification failed: {}",
                diagnostics.join("; ")
            ),
        ));
    }
    let signed_sha256 =
        manifest::sha256_bytes(&manifest::canonical_manifest_bytes(&document.signed)?);
    let metadata: ChannelMetadata = serde_json::from_value(document.signed)
        .context("verified channel metadata payload is invalid")?;
    if metadata.schema != 1
        || metadata.product != "byo"
        || metadata.sequence == 0
        || metadata.generated_at.is_empty()
        || metadata.expires_at.is_empty()
    {
        bail!("verified channel metadata has an unsupported identity");
    }
    let generated_at = DateTime::parse_from_rfc3339(&metadata.generated_at)
        .context("verified channel generated_at is not RFC 3339")?
        .with_timezone(&Utc);
    let expires_at = DateTime::parse_from_rfc3339(&metadata.expires_at)
        .context("verified channel expires_at is not RFC 3339")?
        .with_timezone(&Utc);
    if expires_at <= generated_at || now > expires_at {
        bail!("verified channel metadata is expired or has an invalid validity interval");
    }
    if generated_at > now + chrono::Duration::minutes(10) {
        bail!("verified channel metadata was generated unreasonably far in the future");
    }
    Ok((metadata, signed_sha256))
}

fn validate_channel_name(channel: &str) -> Result<()> {
    if channel.is_empty()
        || channel.len() > 64
        || !channel
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        bail!("update channel name is invalid");
    }
    Ok(())
}

fn accept_channel_sequence(
    paths: &ProductPaths,
    metadata: &ChannelMetadata,
    signed_sha256: &str,
) -> Result<()> {
    validate_channel_name(&metadata.channel)?;
    let root = paths.state.join("channels");
    ensure_private_directory(&root)?;
    let path = root.join(format!("{}.json", metadata.channel));
    if path.exists() {
        let bytes = std::fs::read(&path).context("failed to read trusted channel state")?;
        let prior: TrustedChannelState =
            serde_json::from_slice(&bytes).context("trusted channel state is invalid")?;
        if prior.schema != 1 || prior.channel != metadata.channel {
            bail!("trusted channel state has an unsupported identity");
        }
        if metadata.sequence < prior.sequence {
            bail!(
                "signed channel metadata rollback refused: sequence {} is older than trusted {}",
                metadata.sequence,
                prior.sequence
            );
        }
        if metadata.sequence == prior.sequence && prior.signed_sha256 != signed_sha256 {
            bail!("signed channel metadata equivocation refused at the trusted sequence");
        }
    }
    manifest::write_json(
        &path,
        &TrustedChannelState {
            schema: 1,
            channel: metadata.channel.clone(),
            sequence: metadata.sequence,
            signed_sha256: signed_sha256.to_string(),
        },
    )
}

fn platform_name() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macos",
        "linux" => "linux",
        "windows" => "windows",
        other => other,
    }
}

fn architecture_name() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        other => other,
    }
}

fn select_artifact(metadata: &ChannelMetadata, arguments: &UpdateArgs) -> Result<ChannelArtifact> {
    if metadata.channel != arguments.channel {
        bail!(
            "signed metadata channel {} does not match requested {}",
            metadata.channel,
            arguments.channel
        );
    }
    let mut candidates: Vec<_> = metadata
        .releases
        .iter()
        .filter(|release| {
            release.platform == platform_name()
                && release.architecture == architecture_name()
                && arguments
                    .version
                    .as_ref()
                    .map(|version| version == &release.version)
                    .unwrap_or(true)
        })
        .cloned()
        .collect();
    candidates.sort_by(|left, right| {
        let parsed_left = Version::parse(&left.version);
        let parsed_right = Version::parse(&right.version);
        match (parsed_left, parsed_right) {
            (Ok(left_version), Ok(right_version)) => left_version.cmp(&right_version),
            (Ok(_), Err(_)) => std::cmp::Ordering::Greater,
            (Err(_), Ok(_)) => std::cmp::Ordering::Less,
            (Err(_), Err(_)) => left.version.cmp(&right.version),
        }
    });
    let selected = candidates
        .pop()
        .context("no compatible signed update is available for this platform")?;
    Version::parse(&selected.version).context("selected update version is not semantic")?;
    let archive_type = ArchiveType::parse(&selected.archive_type)?;
    if archive_type != ArchiveType::expected_for_platform(&selected.platform)?
        || selected.archive_size == 0
        || selected.archive_size > MAX_ARCHIVE_BYTES
        || selected.archive_sha256.len() != 64
        || selected.manifest_sha256.len() != 64
        || !selected.url.starts_with("https://")
    {
        bail!("selected update artifact metadata is invalid");
    }
    Ok(selected)
}

fn safe_archive_path(path: &Path) -> Result<()> {
    let rendered = path.to_string_lossy();
    let first = rendered.split('/').next().unwrap_or_default();
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || rendered.contains('\\')
        || first.ends_with(':')
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("update archive contains an unsafe path: {}", path.display());
    }
    Ok(())
}

fn extract_tar_gz(payload: &[u8], destination: &Path) -> Result<()> {
    ensure_private_directory(destination)?;
    let decoder = GzDecoder::new(Cursor::new(payload));
    let mut archive = tar::Archive::new(decoder);
    let mut entries = 0usize;
    let mut extracted_bytes = 0u64;
    let mut normalized_paths = HashSet::new();
    for raw_entry in archive.entries().context("update tar archive is invalid")? {
        let mut entry = raw_entry.context("update tar entry is invalid")?;
        entries += 1;
        if entries > MAX_ARCHIVE_ENTRIES {
            bail!("update archive contains too many entries");
        }
        let path = entry.path()?.into_owned();
        safe_archive_path(&path)?;
        let normalized = path.to_string_lossy().to_ascii_lowercase();
        if !normalized_paths.insert(normalized) {
            bail!(
                "update archive contains a duplicate or case-colliding path: {}",
                path.display()
            );
        }
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            bail!(
                "update archive contains a forbidden non-file entry: {}",
                path.display()
            );
        }
        let entry_size = entry.header().size()?;
        if entry_size > MAX_EXTRACTED_FILE_BYTES {
            bail!("update archive contains an oversized file");
        }
        extracted_bytes = extracted_bytes
            .checked_add(entry_size)
            .context("update archive extracted size overflow")?;
        if extracted_bytes > MAX_EXTRACTED_BYTES {
            bail!("update archive expands beyond the allowed size");
        }
        if !entry.unpack_in(destination)? {
            bail!("update archive entry escaped its extraction directory");
        }
    }
    if entries == 0 {
        bail!("update archive is empty");
    }
    Ok(())
}

fn extract_zip(payload: &[u8], destination: &Path) -> Result<()> {
    ensure_private_directory(destination)?;
    let mut archive =
        zip::ZipArchive::new(Cursor::new(payload)).context("update ZIP archive is invalid")?;
    if archive.is_empty() || archive.len() > MAX_ARCHIVE_ENTRIES {
        bail!("update ZIP archive is empty or contains too many entries");
    }

    let mut extracted_bytes = 0u64;
    let mut normalized_paths = HashSet::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .context("update ZIP entry is invalid or encrypted")?;
        let path = entry
            .enclosed_name()
            .context("update ZIP entry contains an unsafe path")?
            .to_path_buf();
        safe_archive_path(&path)?;
        let normalized = path.to_string_lossy().to_ascii_lowercase();
        if !normalized_paths.insert(normalized) {
            bail!(
                "update archive contains a duplicate or case-colliding path: {}",
                path.display()
            );
        }

        let is_directory = entry.is_dir();
        let mode = entry.unix_mode().unwrap_or(0);
        let file_type = mode & 0o170000;
        if file_type != 0
            && !((is_directory && file_type == 0o040000)
                || (!is_directory && file_type == 0o100000))
        {
            bail!(
                "update ZIP archive contains a forbidden non-file entry: {}",
                path.display()
            );
        }
        let entry_size = entry.size();
        if is_directory && entry_size != 0 {
            bail!("update ZIP directory entry has non-zero content");
        }
        if entry_size > MAX_EXTRACTED_FILE_BYTES {
            bail!("update archive contains an oversized file");
        }
        extracted_bytes = extracted_bytes
            .checked_add(entry_size)
            .context("update archive extracted size overflow")?;
        if extracted_bytes > MAX_EXTRACTED_BYTES {
            bail!("update archive expands beyond the allowed size");
        }

        let output_path = destination.join(&path);
        if is_directory {
            std::fs::create_dir_all(&output_path)?;
            continue;
        }
        let parent = output_path
            .parent()
            .context("update ZIP entry has no parent directory")?;
        std::fs::create_dir_all(parent)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output_path)
            .with_context(|| {
                format!(
                    "failed to create extracted update file {}",
                    output_path.display()
                )
            })?;
        let copied = std::io::copy(
            &mut entry.by_ref().take(entry_size.saturating_add(1)),
            &mut output,
        )?;
        output.flush()?;
        if copied != entry_size {
            bail!("update ZIP entry size does not match its metadata");
        }
        #[cfg(unix)]
        if mode != 0 {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&output_path, std::fs::Permissions::from_mode(mode & 0o777))?;
        }
    }
    Ok(())
}

fn extract_archive(payload: &[u8], destination: &Path, archive_type: ArchiveType) -> Result<()> {
    match archive_type {
        ArchiveType::TarGz => extract_tar_gz(payload, destination),
        ArchiveType::Zip => extract_zip(payload, destination),
    }
}

fn bundle_root(extracted: &Path) -> Result<PathBuf> {
    if extracted.join("release-manifest.json").is_file() {
        return Ok(extracted.to_path_buf());
    }
    let mut children: Vec<_> = std::fs::read_dir(extracted)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.path())
        .collect();
    children.sort();
    if children.len() == 1 && children[0].join("release-manifest.json").is_file() {
        return Ok(children.remove(0));
    }
    bail!("update archive does not contain exactly one BYO bundle")
}

fn remove_abandoned_extractions(downloads: &Path) -> Result<()> {
    if !downloads.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(downloads)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(".extract-") {
            continue;
        }
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("update cache contains an unsafe abandoned extraction entry");
        }
        std::fs::remove_dir_all(entry.path())?;
    }
    Ok(())
}

pub fn perform(arguments: &UpdateArgs, paths: &ProductPaths) -> Result<UpdateOutcome> {
    let _lock = install::InstallLock::acquire(paths)?;
    validate_channel_name(&arguments.channel)?;
    let metadata_bytes = read_metadata(arguments)?;
    let (metadata, signed_sha256) = verify_channel_document(&metadata_bytes)?;
    if metadata.channel != arguments.channel {
        bail!(
            "signed metadata channel {} does not match requested {}",
            metadata.channel,
            arguments.channel
        );
    }
    accept_channel_sequence(paths, &metadata, &signed_sha256)?;
    let artifact = select_artifact(&metadata, arguments)?;
    if let Ok((current, _)) = manifest::load_current(paths) {
        let current_version = Version::parse(&current.version)
            .context("installed runtime version is not semantic")?;
        let selected_version =
            Version::parse(&artifact.version).context("selected update version is not semantic")?;
        if selected_version < current_version {
            bail!(
                "update refuses to downgrade {} to {}; use `byo rollback` for an installed prior runtime",
                current.version,
                artifact.version
            );
        }
    }
    let outcome = UpdateOutcome {
        version: artifact.version.clone(),
        channel: metadata.channel,
        platform: artifact.platform.clone(),
        architecture: artifact.architecture.clone(),
        url: artifact.url.clone(),
        dry_run: arguments.dry_run,
    };
    if arguments.dry_run {
        return Ok(outcome);
    }

    let archive = download(&artifact.url, artifact.archive_size + 1)?;
    if archive.len() as u64 != artifact.archive_size {
        bail!("downloaded update archive size does not match signed metadata");
    }
    if sha256_bytes(&archive) != artifact.archive_sha256 {
        bail!("downloaded update archive digest does not match signed metadata");
    }

    let downloads = paths.cache.join("downloads");
    ensure_private_directory(&downloads)?;
    remove_abandoned_extractions(&downloads)?;
    let archive_type = ArchiveType::parse(&artifact.archive_type)?;
    let archive_path = downloads.join(format!(
        "byo-{}-{}-{}.{}",
        artifact.version,
        artifact.platform,
        artifact.architecture,
        archive_type.extension()
    ));
    manifest::atomic_write(&archive_path, &archive)?;
    let staging = downloads.join(format!(
        ".extract-{}-{:032x}",
        artifact.version,
        rand::random::<u128>()
    ));
    let result = (|| -> Result<()> {
        extract_archive(&archive, &staging, archive_type)?;
        let bundle = bundle_root(&staging)?;
        if manifest::sha256_file(&bundle.join("release-manifest.json"))? != artifact.manifest_sha256
        {
            bail!("extracted release manifest digest does not match signed channel metadata");
        }
        install::install_bundle_locked(&bundle, paths)?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&staging);
    result?;
    Ok(outcome)
}

pub fn rollback(paths: &ProductPaths, requested: Option<&str>) -> Result<PathBuf> {
    let (current, _) = manifest::load_current(paths)?;
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(paths.versions())? {
        let path = entry?.path();
        if !path.is_dir() {
            continue;
        }
        let release = match manifest::verify_runtime(&path) {
            Ok(release) => release,
            Err(_) => continue,
        };
        if release.version == current.version {
            continue;
        }
        if requested
            .map(|version| version != release.version)
            .unwrap_or(false)
        {
            continue;
        }
        let version = Version::parse(&release.version)
            .with_context(|| format!("installed version {} is invalid", release.version))?;
        candidates.push((version, path));
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    let candidate = candidates
        .pop()
        .map(|(_, path)| path)
        .context("no verified prior runtime is available for rollback")?;
    install::repair(paths, Some(&candidate))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use zip::write::SimpleFileOptions;

    use super::*;

    #[test]
    fn archive_paths_reject_traversal_and_absolute_paths() {
        assert!(safe_archive_path(Path::new("bundle/release-manifest.json")).is_ok());
        assert!(safe_archive_path(Path::new("../escape")).is_err());
        assert!(safe_archive_path(Path::new("/absolute")).is_err());
        assert!(safe_archive_path(Path::new(r"C:\escape")).is_err());
        assert!(safe_archive_path(Path::new("C:/escape")).is_err());
    }

    #[test]
    fn selects_highest_semantic_version_for_current_target() {
        let archive_type = ArchiveType::expected_for_platform(platform_name()).unwrap();
        let metadata = ChannelMetadata {
            schema: 1,
            product: "byo".to_string(),
            channel: "stable".to_string(),
            sequence: 1,
            generated_at: "2026-07-24T00:00:00Z".to_string(),
            expires_at: "2026-07-31T00:00:00Z".to_string(),
            releases: ["1.2.0", "1.10.0"]
                .into_iter()
                .map(|version| ChannelArtifact {
                    version: version.to_string(),
                    platform: platform_name().to_string(),
                    architecture: architecture_name().to_string(),
                    url: format!(
                        "https://example.invalid/byo-{version}.{}",
                        archive_type.extension()
                    ),
                    archive_type: archive_type.extension().to_string(),
                    archive_sha256: "0".repeat(64),
                    archive_size: 10,
                    manifest_sha256: "1".repeat(64),
                })
                .collect(),
        };
        let arguments = UpdateArgs {
            version: None,
            channel: "stable".to_string(),
            metadata_url: None,
            metadata_file: None,
            dry_run: true,
        };
        assert_eq!(
            select_artifact(&metadata, &arguments).unwrap().version,
            "1.10.0"
        );
    }

    #[test]
    fn extracts_safe_zip_and_preserves_content() {
        let mut payload = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(Cursor::new(&mut payload));
            let options = SimpleFileOptions::default().unix_permissions(0o100755);
            writer.start_file("bundle/byo", options).unwrap();
            writer.write_all(b"launcher").unwrap();
            writer.finish().unwrap();
        }
        let root = std::env::temp_dir().join(format!(
            "byo-zip-extraction-test-{:032x}",
            rand::random::<u128>()
        ));
        extract_archive(&payload, &root, ArchiveType::Zip).unwrap();
        assert_eq!(std::fs::read(root.join("bundle/byo")).unwrap(), b"launcher");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_unsafe_zip_paths_and_symbolic_links() {
        {
            let mut payload = Vec::new();
            {
                let mut writer = zip::ZipWriter::new(Cursor::new(&mut payload));
                writer
                    .start_file("../escape", SimpleFileOptions::default())
                    .unwrap();
                writer.write_all(b"payload").unwrap();
                writer.finish().unwrap();
            }
            let root = std::env::temp_dir()
                .join(format!("byo-bad-zip-test-{:032x}", rand::random::<u128>()));
            assert!(extract_archive(&payload, &root, ArchiveType::Zip).is_err());
            let _ = std::fs::remove_dir_all(root);
        }
        {
            let mut payload = Vec::new();
            {
                let mut writer = zip::ZipWriter::new(Cursor::new(&mut payload));
                writer
                    .add_symlink("bundle/link", "../escape", SimpleFileOptions::default())
                    .unwrap();
                writer.finish().unwrap();
            }
            let root = std::env::temp_dir()
                .join(format!("byo-link-zip-test-{:032x}", rand::random::<u128>()));
            assert!(extract_archive(&payload, &root, ArchiveType::Zip).is_err());
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[test]
    fn channel_state_rejects_rollback_and_same_sequence_equivocation() {
        let root = std::env::temp_dir().join(format!(
            "byo-channel-state-test-{:032x}",
            rand::random::<u128>()
        ));
        let paths = ProductPaths {
            data: root.join("data"),
            config: root.join("config"),
            state: root.join("state"),
            cache: root.join("cache"),
            bin: root.join("bin"),
        };
        let mut metadata = ChannelMetadata {
            schema: 1,
            product: "byo".to_string(),
            channel: "stable".to_string(),
            sequence: 2,
            generated_at: "2026-07-24T00:00:00Z".to_string(),
            expires_at: "2026-07-31T00:00:00Z".to_string(),
            releases: Vec::new(),
        };
        accept_channel_sequence(&paths, &metadata, &"a".repeat(64)).unwrap();
        accept_channel_sequence(&paths, &metadata, &"a".repeat(64)).unwrap();
        assert!(accept_channel_sequence(&paths, &metadata, &"b".repeat(64)).is_err());
        metadata.sequence = 1;
        assert!(accept_channel_sequence(&paths, &metadata, &"a".repeat(64)).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn channel_names_are_safe_state_file_components() {
        assert!(validate_channel_name("stable").is_ok());
        assert!(validate_channel_name("beta_1").is_ok());
        assert!(validate_channel_name("../stable").is_err());
        assert!(validate_channel_name("stable/channel").is_err());
    }

    #[test]
    fn malformed_signed_metadata_uses_the_signature_exit_category() {
        let error = verify_channel_document(b"{}").unwrap_err();
        assert_eq!(crate::error::exit_code(&error), Some(23));
    }

    #[test]
    fn signed_channel_metadata_verifies_content_and_expiration() {
        let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
        let signed = serde_json::json!({
            "schema": 1,
            "product": "byo",
            "channel": "stable",
            "sequence": 7,
            "generated_at": "2026-07-24T00:00:00Z",
            "expires_at": "2026-07-31T00:00:00Z",
            "releases": []
        });
        let signature = signing_key.sign(&manifest::canonical_manifest_bytes(&signed).unwrap());
        let document = serde_json::json!({
            "schema": 1,
            "signed": signed,
            "signatures": [{
                "algorithm": "Ed25519",
                "key_id": "test",
                "signature": hex::encode(signature.to_bytes())
            }]
        });
        let keys = vec![("test".to_string(), signing_key.verifying_key())];
        let now = DateTime::parse_from_rfc3339("2026-07-25T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let bytes = serde_json::to_vec(&document).unwrap();
        let (metadata, _) = verify_channel_document_with_keys(&bytes, &keys, now).unwrap();
        assert_eq!(metadata.sequence, 7);

        let expired = DateTime::parse_from_rfc3339("2026-08-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(verify_channel_document_with_keys(&bytes, &keys, expired).is_err());

        let mut tampered = document;
        tampered["signed"]["channel"] = Value::String("beta".to_string());
        let error =
            verify_channel_document_with_keys(&serde_json::to_vec(&tampered).unwrap(), &keys, now)
                .unwrap_err();
        assert_eq!(crate::error::exit_code(&error), Some(23));
    }
}
