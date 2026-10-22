use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use toml_edit::{value, Array, DocumentMut, Item, Table};
use walkdir::WalkDir;

use crate::error::{categorize, ExitCategory};
use crate::manifest::{sha256_bytes, sha256_file, write_json, ReleaseManifest};
use crate::pack::{CompiledSkill, WorkspacePack};
use crate::paths::{is_within, ProductPaths};

const BEGIN_MARKER: &str = "<!-- BEGIN BYO MANAGED: agent-bootstrap v1 -->";
const END_MARKER: &str = "<!-- END BYO MANAGED: agent-bootstrap v1 -->";
const INTEGRITY_PATH: &str = ".generated/byo/integrity.json";

// Kept as an ordinary inventoried file so schema 1-3 readers can still read a
// refreshed capsule. Byte hashes remain available to those launchers.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntegrityBaseline {
    schema: u32,
    files: BTreeMap<String, String>,
    codex_server_semantics_sha256: String,
}

fn normalized_text(text: &str) -> String {
    let text = text.replace("\r\n", "\n");
    format!("{}\n", text.trim_end_matches('\n'))
}

// JSON consumers need not agree which duplicate key wins. Reject ambiguity
// before comparing semantics, including in nested permissions/hook objects.
pub(crate) fn parse_project_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    struct Unique(serde_json::Value);
    impl<'de> Deserialize<'de> for Unique {
        fn deserialize<D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> std::result::Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Unique;
                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("JSON without duplicate keys")
                }
                fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Unique, E> {
                    Ok(Unique(serde_json::Value::Null))
                }
                fn visit_bool<E: serde::de::Error>(
                    self,
                    value: bool,
                ) -> std::result::Result<Unique, E> {
                    Ok(Unique(value.into()))
                }
                fn visit_i64<E: serde::de::Error>(
                    self,
                    value: i64,
                ) -> std::result::Result<Unique, E> {
                    Ok(Unique(value.into()))
                }
                fn visit_u64<E: serde::de::Error>(
                    self,
                    value: u64,
                ) -> std::result::Result<Unique, E> {
                    Ok(Unique(value.into()))
                }
                fn visit_f64<E: serde::de::Error>(
                    self,
                    value: f64,
                ) -> std::result::Result<Unique, E> {
                    serde_json::Number::from_f64(value)
                        .map(|number| Unique(number.into()))
                        .ok_or_else(|| E::custom("invalid JSON number"))
                }
                fn visit_str<E: serde::de::Error>(
                    self,
                    value: &str,
                ) -> std::result::Result<Unique, E> {
                    Ok(Unique(value.into()))
                }
                fn visit_string<E: serde::de::Error>(
                    self,
                    value: String,
                ) -> std::result::Result<Unique, E> {
                    Ok(Unique(value.into()))
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut sequence: A,
                ) -> std::result::Result<Unique, A::Error> {
                    let mut values = Vec::new();
                    while let Some(Unique(value)) = sequence.next_element()? {
                        values.push(value);
                    }
                    Ok(Unique(values.into()))
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> std::result::Result<Unique, A::Error> {
                    let mut values = serde_json::Map::new();
                    while let Some((key, Unique(value))) = map.next_entry::<String, Unique>()? {
                        if values.insert(key.clone(), value).is_some() {
                            return Err(serde::de::Error::custom(format!(
                                "duplicate JSON key: {key}"
                            )));
                        }
                    }
                    Ok(Unique(values.into()))
                }
            }
            deserializer.deserialize_any(Visitor)
        }
    }
    let Unique(value) = serde_json::from_slice(bytes)?;
    Ok(serde_json::from_value(value)?)
}

fn parse_project_json_text<T: serde::de::DeserializeOwned>(text: &str) -> Result<T> {
    parse_project_json(text.as_bytes())
}

fn same_owned_text(path: &str, actual: &str, expected: &str) -> Result<bool> {
    if path.ends_with(".json") {
        let actual: serde_json::Value = parse_project_json(actual.as_bytes())?;
        let expected: serde_json::Value = parse_project_json(expected.as_bytes())?;
        Ok(actual == expected)
    } else {
        Ok(normalized_text(actual) == normalized_text(expected))
    }
}

fn toml_semantics(item: &Item) -> Result<serde_json::Value> {
    if let Some(table) = item.as_table_like() {
        let mut entries = BTreeMap::new();
        for (key, value) in table.iter() {
            entries.insert(key, toml_semantics(value)?);
        }
        return Ok(serde_json::to_value(entries)?);
    }
    if let Some(array) = item.as_array_of_tables() {
        return array
            .iter()
            .map(|table| toml_semantics(&Item::Table(table.clone())))
            .collect::<Result<Vec<_>>>()
            .map(serde_json::Value::Array);
    }
    let value = item.as_value().context("BYO TOML value is missing")?;
    Ok(match value {
        toml_edit::Value::String(value) => serde_json::json!(["string", value.value()]),
        toml_edit::Value::Integer(value) => serde_json::json!(["integer", value.value()]),
        toml_edit::Value::Float(value) => serde_json::json!(["float", value.value().to_string()]),
        toml_edit::Value::Boolean(value) => serde_json::json!(["boolean", value.value()]),
        toml_edit::Value::Datetime(value) => {
            serde_json::json!(["datetime", value.value().to_string()])
        }
        toml_edit::Value::Array(values) => serde_json::Value::Array(
            values
                .iter()
                .map(|value| toml_semantics(&Item::Value(value.clone())))
                .collect::<Result<Vec<_>>>()?,
        ),
        toml_edit::Value::InlineTable(table) => {
            let mut entries = BTreeMap::new();
            for (key, value) in table.iter() {
                entries.insert(key, toml_semantics(&Item::Value(value.clone()))?);
            }
            serde_json::to_value(entries)?
        }
    })
}

fn integrity_baseline(
    project: &Path,
    projection: &ProjectionManifest,
) -> Result<Option<IntegrityBaseline>> {
    let Some(record) = projection
        .managed_files
        .iter()
        .find(|file| file.path == INTEGRITY_PATH)
    else {
        return Ok(None);
    };
    let bytes = std::fs::read(safe_project_path(project, INTEGRITY_PATH)?)?;
    let baseline: IntegrityBaseline = parse_project_json(&bytes)?;
    let canonical = serde_json::to_string_pretty(&baseline)? + "\n";
    if sha256_bytes(&bytes) != record.sha256 && sha256_bytes(canonical.as_bytes()) != record.sha256
    {
        bail!("BYO integrity baseline was modified; restore {INTEGRITY_PATH} from the matching private state/project-backups snapshot before running `byo workspace update`");
    }
    if baseline.schema != 1 {
        bail!("unsupported BYO integrity baseline");
    }
    Ok(Some(baseline))
}

fn owned_edit_error(label: &str) -> anyhow::Error {
    anyhow::anyhow!("BYO-owned content changed: {label}. Review and undo the BYO-owned changes, or restore this file from its matching private state/project-backups snapshot (locate state with `byo paths`), then run `byo workspace update`. Keep unrelated user settings and text.")
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleManifest {
    pub schema: u32,
    pub product: String,
    pub workspace_version: String,
    pub workflow_protocol: u32,
    pub minimum_launcher: String,
    pub maximum_launcher: String,
    pub minimum_mcp_protocol: u32,
    pub project_id: String,
    pub mode: String,
    pub installed_at: String,
    pub managed_inventory_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedFile {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionManifest {
    pub schema: u32,
    pub managed_files: Vec<ManagedFile>,
    pub agents_block_sha256: String,
    pub codex_server_sha256: String,
    pub codex_hooks_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claude_block_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claude_server_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claude_hooks_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub created_files: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub created_dirs: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub legacy_cleanup: bool,
}

#[derive(Debug)]
pub struct Runtime {
    pub root: PathBuf,
    pub release: ReleaseManifest,
    pub pack: WorkspacePack,
}

#[derive(Debug, Serialize)]
pub struct InitPreview {
    pub project: String,
    pub workspace: String,
    pub mode: String,
    pub mcp_runtime: String,
    pub managed_files: String,
    pub user_files: String,
    pub firm: String,
    pub full_access: bool,
}

#[derive(Debug, Clone)]
pub struct RegisteredProject {
    pub path: PathBuf,
}

#[derive(Debug)]
struct TextReplacement {
    path: PathBuf,
    contents: String,
}

#[derive(Debug)]
struct ProjectedSkill {
    codex_loader: String,
    claude_loader: String,
    codex_policy: String,
}

#[derive(Clone, Copy)]
enum SkillClient {
    Codex,
    Claude,
}

#[derive(Debug)]
pub(crate) struct ProjectUninstallPlan {
    project: PathBuf,
    purge: bool,
    managed_files: Vec<PathBuf>,
    text_replacements: Vec<TextReplacement>,
    metadata_files: Vec<PathBuf>,
    purge_roots: Vec<PathBuf>,
    cleanup_dirs: Vec<PathBuf>,
    remove_empty_files: BTreeSet<PathBuf>,
}

#[derive(Debug)]
pub struct ProjectUninstallOutcome {
    pub removed: Vec<PathBuf>,
    pub preserved: Vec<PathBuf>,
}

#[derive(Debug)]
pub(crate) struct RegisteredProjectCleanup {
    pub projects: Vec<PathBuf>,
    pub removed: Vec<PathBuf>,
}

pub fn canonical_project(raw: Option<&Path>, paths: &ProductPaths) -> Result<PathBuf> {
    let selected = match raw {
        Some(path) => path.to_path_buf(),
        None => env::current_dir()?,
    };
    let project = selected
        .canonicalize()
        .with_context(|| format!("project does not exist: {}", selected.display()))?;
    if !project.is_dir() {
        bail!("project target is not a directory");
    }
    let anchor = project
        .ancestors()
        .last()
        .context("project path has no filesystem root")?
        .canonicalize()?;
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .and_then(|path| path.canonicalize().ok());
    if project == anchor || home.as_ref() == Some(&project) {
        bail!("project root must not be the filesystem root or user home");
    }
    for product_root in [
        &paths.data,
        &paths.config,
        &paths.state,
        &paths.cache,
        &paths.bin,
    ] {
        if product_root.exists() {
            let canonical = product_root.canonicalize()?;
            if is_within(&project, &canonical) || is_within(&canonical, &project) {
                bail!("project root must not overlap the BYO product installation");
            }
        }
    }
    Ok(project)
}

pub fn active_runtime(paths: &ProductPaths) -> Result<Runtime> {
    let (_, root) = categorize(
        crate::manifest::load_current(paths),
        ExitCategory::RuntimeMissing,
    )?;
    let release = categorize(
        crate::manifest::verify_runtime(&root),
        ExitCategory::RuntimeIntegrity,
    )?;
    let pack = WorkspacePack::load(&root.join("workflow/workspace.pack"))?;
    if release.workflow_protocol != 1 {
        return Err(crate::error::fail(
            ExitCategory::Incompatible,
            "runtime workflow protocol is incompatible",
        ));
    }
    Ok(Runtime {
        root,
        release,
        pack,
    })
}

fn read_capsule(project: &Path) -> Result<Option<CapsuleManifest>> {
    let path = project.join(".agent-workspace/manifest.json");
    if !path.exists() {
        return Ok(None);
    }
    let manifest: CapsuleManifest =
        parse_project_json(&std::fs::read(&path)?).context("capsule manifest is invalid")?;
    if manifest.schema != 1 || manifest.product != "byo" || manifest.workflow_protocol != 1 {
        bail!("capsule manifest has an unsupported schema or protocol");
    }
    Ok(Some(manifest))
}

pub fn project_id(project: &Path) -> Result<String> {
    Ok(read_capsule(project)?
        .context("project capsule is not installed")?
        .project_id)
}

pub fn capsule_mode(project: &Path) -> Result<String> {
    Ok(read_capsule(project)?
        .context("project capsule is not installed")?
        .mode)
}

pub(crate) fn guard_mode(project: &Path) -> Result<String> {
    let capsule = read_capsule(project)?.context("project capsule is not installed")?;
    let mut projection = read_projection(project)?.context("projection manifest is missing")?;
    const MODE: &str = ".generated/byo/active-mode.json";
    if capsule.minimum_mcp_protocol > 1
        || !projection
            .managed_files
            .iter()
            .any(|file| file.path == MODE)
    {
        bail!("guard does not support this capsule/mode protocol");
    }
    projection
        .managed_files
        .retain(|file| file.path == MODE || file.path == INTEGRITY_PATH);
    validate_owned_files(project, &projection)?;
    let mode: serde_json::Value =
        parse_project_json_text(&read_project_text(&safe_project_path(project, MODE)?)?)?;
    if mode["schema"].as_u64() != Some(1)
        || mode["mode"].as_str() != Some(capsule.mode.as_str())
        || mode["full_access"].as_bool().is_none()
        || mode["family"].as_str().is_none()
    {
        bail!("capsule mode does not match its verified policy");
    }
    Ok(capsule.mode)
}

fn read_projection(project: &Path) -> Result<Option<ProjectionManifest>> {
    let path = project.join(".generated/byo/projection-manifest.json");
    if !path.exists() {
        return Ok(None);
    }
    let manifest: ProjectionManifest =
        parse_project_json(&std::fs::read(path)?).context("projection manifest is invalid")?;
    if !matches!(manifest.schema, 1..=3) {
        bail!("projection manifest schema is unsupported");
    }
    Ok(Some(manifest))
}

fn managed_project_path(project: &Path, relative: &str) -> Result<PathBuf> {
    let relative = Path::new(relative);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("managed projection path is not a safe relative path: {relative:?}");
    }
    Ok(project.join(relative))
}

fn safe_project_path(project: &Path, relative: &str) -> Result<PathBuf> {
    let target = managed_project_path(project, relative)?;
    let mut current = project.to_path_buf();
    for component in Path::new(relative).components() {
        let std::path::Component::Normal(component) = component else {
            bail!("managed projection path is not a safe relative path: {relative:?}");
        };
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!(
                    "managed project path traverses a symlink: {}",
                    current.display()
                )
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(target)
}

fn validate_owned_files(project: &Path, projection: &ProjectionManifest) -> Result<()> {
    let baseline = integrity_baseline(project, projection)?;
    for managed in &projection.managed_files {
        let target = safe_project_path(project, &managed.path)?;
        if !target.is_file() || sha256_file(&target)? != managed.sha256 {
            if managed.path == INTEGRITY_PATH && baseline.is_some() {
                continue; // Already checked against the recorded hash above.
            }
            let actual = read_project_text(&target)?;
            let equivalent = if let Some(expected) =
                baseline.as_ref().and_then(|b| b.files.get(&managed.path))
            {
                same_owned_text(&managed.path, &actual, expected)?
            } else if managed.path != INTEGRITY_PATH {
                // Legacy producers wrote LF text with one terminal newline, and
                // sorted, pretty JSON. These candidates never approve new values.
                sha256_bytes(normalized_text(&actual).as_bytes()) == managed.sha256
                    || (managed.path.ends_with(".json")
                        && parse_project_json_text::<serde_json::Value>(&actual)
                            .ok()
                            .and_then(|value| serde_json::to_string_pretty(&value).ok())
                            .is_some_and(|text| {
                                sha256_bytes(format!("{text}\n").as_bytes()) == managed.sha256
                            }))
            } else {
                false
            };
            if !equivalent {
                return Err(owned_edit_error(&managed.path));
            }
        }
    }
    Ok(())
}

fn managed_block(bootstrap: &str) -> String {
    format!("{BEGIN_MARKER}\n{}\n{END_MARKER}", bootstrap.trim())
}

fn replace_managed_block(original: &str, block: &str) -> Result<String> {
    let begins: Vec<_> = original.match_indices(BEGIN_MARKER).collect();
    let ends: Vec<_> = original.match_indices(END_MARKER).collect();
    match (begins.as_slice(), ends.as_slice()) {
        ([], []) => {
            let separator = if original.is_empty() {
                ""
            } else if original.ends_with('\n') {
                "\n"
            } else {
                "\n\n"
            };
            Ok(format!("{original}{separator}{block}\n"))
        }
        ([(begin, _)], [(end, _)]) if begin < end => {
            let after = end + END_MARKER.len();
            Ok(format!(
                "{}{}{}",
                &original[..*begin],
                block,
                &original[after..]
            ))
        }
        _ => bail!("instruction file contains malformed or duplicate BYO managed markers"),
    }
}

fn remove_managed_block(original: &str) -> Result<String> {
    let begins: Vec<_> = original.match_indices(BEGIN_MARKER).collect();
    let ends: Vec<_> = original.match_indices(END_MARKER).collect();
    match (begins.as_slice(), ends.as_slice()) {
        ([], []) => Ok(original.to_string()),
        ([(begin, _)], [(end, _)]) if begin < end => {
            let mut after = end + END_MARKER.len();
            if original[after..].starts_with('\n') {
                after += 1;
            }
            let mut result = format!("{}{}", &original[..*begin], &original[after..]);
            if result.ends_with("\n\n") {
                result.pop();
            }
            Ok(result)
        }
        _ => bail!("instruction file contains malformed or duplicate BYO managed markers"),
    }
}

fn verify_managed_block(original: &str, label: &str, expected_sha256: &str) -> Result<()> {
    let begin = original
        .find(BEGIN_MARKER)
        .ok_or_else(|| owned_edit_error(label).context("BYO managed block is missing"))?;
    let end = original
        .find(END_MARKER)
        .ok_or_else(|| owned_edit_error(label).context("BYO managed block is malformed"))?
        + END_MARKER.len();
    if begin >= end
        || original.matches(BEGIN_MARKER).count() != 1
        || original.matches(END_MARKER).count() != 1
        || (sha256_bytes(&original.as_bytes()[begin..end]) != expected_sha256
            && sha256_bytes(original[begin..end].replace("\r\n", "\n").as_bytes())
                != expected_sha256)
    {
        return Err(owned_edit_error(label));
    }
    Ok(())
}

fn render_codex_config(original: &str, project: &Path) -> Result<(String, String)> {
    let mut document = if original.trim().is_empty() {
        DocumentMut::new()
    } else {
        original
            .parse::<DocumentMut>()
            .context(".codex/config.toml is invalid TOML")?
    };
    let servers = document
        .entry("mcp_servers")
        .or_insert_with(|| Item::Table(Table::new()))
        .as_table_like_mut()
        .context("mcp_servers must be a TOML table")?;
    let byo = servers
        .entry("byo")
        .or_insert_with(|| Item::Table(Table::new()))
        .as_table_like_mut()
        .context("mcp_servers.byo must be a TOML table")?;
    if let Some(command) = byo.get("command").and_then(|item| item.as_str()) {
        if command != "byo" {
            return Err(crate::error::fail(
                ExitCategory::ClientConflict,
                "existing mcp_servers.byo is not owned by BYO",
            ));
        }
    }
    byo.insert("command", value("byo"));
    let mut args = Array::new();
    for argument in [
        "mcp",
        "serve",
        "--project",
        project
            .to_str()
            .context("project path is not valid Unicode for client configuration")?,
    ] {
        args.push(argument);
    }
    byo.insert("args", value(args));
    let server = document["mcp_servers"]["byo"].to_string();
    Ok((document.to_string(), sha256_bytes(server.as_bytes())))
}

fn remove_codex_config(original: &str) -> Result<String> {
    if original.trim().is_empty() {
        return Ok(String::new());
    }
    let mut document = original
        .parse::<DocumentMut>()
        .context(".codex/config.toml is invalid TOML")?;
    if let Some(servers) = document
        .get_mut("mcp_servers")
        .and_then(|item| item.as_table_like_mut())
    {
        servers.remove("byo");
        if servers.is_empty() {
            document.remove("mcp_servers");
        }
    }
    Ok(document.to_string())
}

fn render_claude_mcp(original: &str, project: &Path) -> Result<(String, String)> {
    let mut document: serde_json::Value = if original.trim().is_empty() {
        serde_json::json!({})
    } else {
        parse_project_json_text(original).context(".mcp.json is invalid JSON")?
    };
    let root = document
        .as_object_mut()
        .context(".mcp.json must contain a JSON object")?;
    let servers = root
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .context(".mcp.json mcpServers must be an object")?;
    if let Some(existing) = servers.get("byo") {
        let command = existing
            .as_object()
            .and_then(|server| server.get("command"))
            .and_then(serde_json::Value::as_str);
        if command != Some("byo") {
            return Err(crate::error::fail(
                ExitCategory::ClientConflict,
                "existing mcpServers.byo is not owned by BYO",
            ));
        }
    }
    let server = serde_json::json!({
        "type": "stdio",
        "command": "byo",
        "args": [
            "mcp",
            "serve",
            "--project",
            project
                .to_str()
                .context("project path is not valid Unicode for client configuration")?
        ]
    });
    let server_hash = sha256_bytes(serde_json::to_string(&server)?.as_bytes());
    servers.insert("byo".to_string(), server);
    let mut output = serde_json::to_string_pretty(&document)?;
    output.push('\n');
    Ok((output, server_hash))
}

fn remove_claude_mcp(original: &str) -> Result<String> {
    if original.trim().is_empty() {
        return Ok(String::new());
    }
    let mut document: serde_json::Value =
        parse_project_json_text(original).context(".mcp.json is invalid JSON")?;
    if let Some(servers) = document
        .get_mut("mcpServers")
        .and_then(serde_json::Value::as_object_mut)
    {
        servers.remove("byo");
        if servers.is_empty() {
            document
                .as_object_mut()
                .context(".mcp.json must contain a JSON object")?
                .remove("mcpServers");
        }
    }
    let mut output = serde_json::to_string_pretty(&document)?;
    output.push('\n');
    Ok(output)
}

fn remove_claude_mcp_approval(original: &str, label: &str) -> Result<String> {
    if original.trim().is_empty() {
        return Ok(String::new());
    }
    let mut document: serde_json::Value =
        parse_project_json_text(original).with_context(|| format!("{label} is invalid JSON"))?;
    let root = document
        .as_object_mut()
        .with_context(|| format!("{label} must contain a JSON object"))?;
    for key in ["enabledMcpjsonServers", "disabledMcpjsonServers"] {
        if let Some(servers) = root.get_mut(key).and_then(serde_json::Value::as_array_mut) {
            servers.retain(|server| server.as_str() != Some("byo"));
            if servers.is_empty() {
                root.remove(key);
            }
        }
    }
    let mut output = serde_json::to_string_pretty(&document)?;
    output.push('\n');
    Ok(output)
}

fn byo_hooks() -> serde_json::Value {
    serde_json::json!({
        "SessionStart": [{
            "matcher": "startup|resume|clear|compact",
            "hooks": [{
                "type": "command",
                "command": "byo hook sessionstart-resume",
                "timeout": 30,
                "statusMessage": "Loading BYO resume context"
            }]
        }],
        "PreToolUse": [{
            "matcher": "^Bash$",
            "hooks": [{
                "type": "command",
                "command": "byo hook guard-dangerous",
                "timeout": 30,
                "statusMessage": "Checking BYO command safety"
            }]
        }],
        "PreCompact": [{
            "hooks": [{
                "type": "command",
                "command": "byo hook precompact-handoff",
                "timeout": 30,
                "statusMessage": "Checking BYO compaction boundary"
            }]
        }]
    })
}

fn is_byo_hook(value: &serde_json::Value) -> bool {
    value
        .get("command")
        .and_then(serde_json::Value::as_str)
        .map(|command| command.starts_with("byo hook "))
        .unwrap_or(false)
}

fn remove_byo_hook_entries(document: &mut serde_json::Value) {
    let Some(events) = document
        .get_mut("hooks")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    for entries in events.values_mut() {
        let Some(entries) = entries.as_array_mut() else {
            continue;
        };
        for entry in entries.iter_mut() {
            if let Some(hooks) = entry
                .get_mut("hooks")
                .and_then(serde_json::Value::as_array_mut)
            {
                hooks.retain(|hook| !is_byo_hook(hook));
            }
        }
        entries.retain(|entry| {
            entry
                .get("hooks")
                .and_then(serde_json::Value::as_array)
                .map(|hooks| !hooks.is_empty())
                .unwrap_or(true)
        });
    }
    events.retain(|_, entries| {
        entries
            .as_array()
            .map(|entries| !entries.is_empty())
            .unwrap_or(true)
    });
}

fn render_hook_configuration(original: &str, label: &str) -> Result<(String, String)> {
    let mut document = if original.trim().is_empty() {
        serde_json::json!({})
    } else {
        parse_project_json_text(original).with_context(|| format!("{label} is invalid JSON"))?
    };
    remove_byo_hook_entries(&mut document);
    let root = document
        .as_object_mut()
        .with_context(|| format!("{label} must contain a JSON object"))?;
    let hooks = root
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .with_context(|| format!("{label} hooks must be an object"))?;
    let expected = byo_hooks();
    for (event, entries) in expected
        .as_object()
        .context("internal BYO hook payload is invalid")?
    {
        let target = hooks
            .entry(event.clone())
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut()
            .with_context(|| format!(".codex/hooks.json {event} must be an array"))?;
        for entry in entries
            .as_array()
            .context("internal BYO hook event is invalid")?
        {
            if !target.contains(entry) {
                target.push(entry.clone());
            }
        }
    }
    let mut output = serde_json::to_string_pretty(&document)?;
    output.push('\n');
    Ok((
        output,
        sha256_bytes(serde_json::to_string(&expected)?.as_bytes()),
    ))
}

fn verify_byo_hooks(document: &serde_json::Value, label: &str) -> Result<String> {
    let events = document
        .get("hooks")
        .and_then(serde_json::Value::as_object)
        .with_context(|| format!("{label} hooks object is missing"))?;
    let expected = byo_hooks();
    for (event, expected_entries) in expected
        .as_object()
        .context("internal BYO hook payload is invalid")?
    {
        let actual = events
            .get(event)
            .and_then(serde_json::Value::as_array)
            .with_context(|| format!(".codex/hooks.json {event} is missing"))?;
        for entry in expected_entries
            .as_array()
            .context("internal BYO hook event is invalid")?
        {
            if !actual.contains(entry) {
                bail!("{label} BYO {event} hook was modified");
            }
        }
    }
    Ok(sha256_bytes(serde_json::to_string(&expected)?.as_bytes()))
}

fn remove_hook_configuration(original: &str, label: &str) -> Result<String> {
    if original.trim().is_empty() {
        return Ok(String::new());
    }
    let mut document: serde_json::Value =
        parse_project_json_text(original).with_context(|| format!("{label} is invalid JSON"))?;
    remove_byo_hook_entries(&mut document);
    if document
        .get("hooks")
        .and_then(serde_json::Value::as_object)
        .is_some_and(serde_json::Map::is_empty)
    {
        document
            .as_object_mut()
            .with_context(|| format!("{label} must contain a JSON object"))?
            .remove("hooks");
    }
    let mut output = serde_json::to_string_pretty(&document)?;
    output.push('\n');
    Ok(output)
}

fn atomic_text(path: &Path, text: &str) -> Result<()> {
    if read_optional_bytes(path)?.as_deref() == Some(text.as_bytes()) {
        return Ok(());
    }
    crate::manifest::atomic_write(path, text.as_bytes())
}

fn read_optional_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("cannot read {}; original preserved", path.display())),
    }
}

fn read_project_text(path: &Path) -> Result<String> {
    match read_optional_bytes(path)? {
        None => Ok(String::new()),
        Some(bytes) => String::from_utf8(bytes)
            .with_context(|| format!("{} is not UTF-8; original preserved", path.display())),
    }
}

fn project_registry(paths: &ProductPaths) -> Result<BTreeMap<String, String>> {
    match read_optional_bytes(&paths.state.join("projects.json"))? {
        None => Ok(BTreeMap::new()),
        Some(bytes) => parse_project_json(&bytes).context("project registry is invalid"),
    }
}

fn choose_project_id(
    project: &Path,
    capsule: Option<&CapsuleManifest>,
    registry: &BTreeMap<String, String>,
) -> Result<String> {
    let location = project
        .to_str()
        .context("project path is not valid Unicode")?;
    if let Some(capsule) = capsule {
        if registry
            .get(&capsule.project_id)
            .is_none_or(|path| path == location)
        {
            return Ok(capsule.project_id.clone());
        }
    }
    // A copied capsule must not steal the original path's registration or leases.
    loop {
        let id = format!("{:032x}", rand::random::<u128>());
        if !registry.contains_key(&id) {
            return Ok(id);
        }
    }
}

// Tests exercise the real publication/error path with deterministic I/O barriers.
// Production has no fault switch or externally configurable callback.
#[cfg(test)]
type PublicationBarrier = Box<dyn FnMut(&str, &Path, &ProductPaths) -> Result<()>>;
#[cfg(test)]
std::thread_local! {
    static PUBLICATION_BARRIER: std::cell::RefCell<Option<PublicationBarrier>> = const { std::cell::RefCell::new(None) };
}
fn publication_barrier(_phase: &str, _project: &Path, _paths: &ProductPaths) -> Result<()> {
    #[cfg(test)]
    {
        PUBLICATION_BARRIER.with(|slot| match slot.borrow_mut().as_mut() {
            Some(callback) => callback(_phase, _project, _paths),
            None => Ok(()),
        })
    }
    #[cfg(not(test))]
    {
        Ok(())
    }
}

const PROJECT_BACKUP_RETENTION: usize = 5;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingRefresh {
    schema: u32,
    project: String,
    backup: String,
    targets: Vec<String>,
    existed: Vec<String>,
    expected: BTreeMap<String, Option<String>>,
    registry_aliases: BTreeMap<String, String>,
    #[serde(default)]
    registry_before: Option<String>,
    #[serde(default)]
    legacy_workspace: bool,
}

// Caller holds InstallLock. Recovery is idempotent; never consume the record
// until both the original files and this path's registry aliases are restored.
fn recover_project_refresh(project: &Path, paths: &ProductPaths) -> Result<()> {
    let root = project_backup_root(paths, project)?;
    let pending = root.join("pending.json");
    let Some(bytes) = read_optional_bytes(&pending)? else {
        return Ok(());
    };
    let record: PendingRefresh =
        parse_project_json(&bytes).context("invalid interrupted project refresh record")?;
    if record.schema != 1
        || Path::new(&record.project) != project
        || Path::new(&record.backup).components().count() != 1
        || !matches!(
            Path::new(&record.backup).components().next(),
            Some(std::path::Component::Normal(_))
        )
        || record
            .existed
            .iter()
            .any(|path| !record.targets.contains(path))
        || record
            .registry_aliases
            .values()
            .any(|path| Path::new(path) != project)
    {
        bail!(
            "invalid interrupted project refresh identity; private backup retained at {}",
            root.display()
        );
    }
    let backup = root.join(&record.backup);
    if std::fs::symlink_metadata(&backup)?.file_type().is_symlink()
        || backup.canonicalize()?.parent() != Some(root.canonicalize()?.as_path())
    {
        bail!("interrupted refresh backup escapes private state");
    }
    for relative in &record.targets {
        safe_project_path(project, relative)?;
    }
    for relative in &record.existed {
        safe_project_path(&backup, relative)?;
    }
    for relative in &record.targets {
        if [
            ".agent-workspace/manifest.json",
            ".generated/byo/projection-manifest.json",
        ]
        .contains(&relative.as_str())
        {
            continue; // Transaction-owned metadata has no user-editable region.
        }
        let current = read_optional_bytes(&safe_project_path(project, relative)?)?;
        let original = read_optional_bytes(&safe_project_path(&backup, relative)?)?;
        let planned = record
            .expected
            .get(relative)
            .context("interrupted refresh expected-content record is missing")?;
        if current != original && current.as_ref().map(|bytes| sha256_bytes(bytes)) != *planned {
            bail!("{} changed after an interrupted refresh; preserving it and the private backup at {}. Review/restore this file before retrying `byo workspace update`", relative, backup.display());
        }
    }
    if let Some(capsule) = read_capsule(project).ok().flatten() {
        crate::lease::ensure_project_inactive(paths, &capsule.project_id)?;
    }
    // Also check the original identity if interruption replaced the capsule.
    for id in record.registry_aliases.keys() {
        crate::lease::ensure_project_inactive(paths, id)?;
    }
    let mut registry = project_registry(paths)?;
    for (id, path) in &record.registry_aliases {
        if registry
            .get(id)
            .is_some_and(|registered| registered != path)
        {
            bail!("interrupted refresh registry identity belongs to another path; backup retained");
        }
    }
    let legacy_backup = backup.join("legacy-agent-workspace");
    if record.legacy_workspace && legacy_backup.is_dir() {
        // An archived workspace can contain user files outside the normal
        // transaction targets. Refuse new/edited files before replacing it.
        let live_workspace = safe_project_path(project, ".agent-workspace")?;
        // Rename can finish before mkdir begins. Only definite absence is an
        // unedited transaction state; other reads/types must still refuse.
        let live_directory = match std::fs::symlink_metadata(&live_workspace) {
            Ok(metadata) if metadata.is_dir() => true,
            Ok(_) => {
                bail!("legacy workspace recovery requires a directory; private backup retained")
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(error)
                    .context("cannot inspect live legacy workspace; private backup retained")
            }
        };
        if live_directory {
            for entry in WalkDir::new(&live_workspace).follow_links(false) {
                let entry = entry?;
                if entry.file_type().is_dir() {
                    continue;
                }
                let relative = entry
                    .path()
                    .strip_prefix(project)?
                    .to_string_lossy()
                    .replace('\\', "/");
                if entry.file_type().is_symlink() {
                    bail!("later workspace symlink preserved; backup retained");
                }
                if record.targets.contains(&relative) {
                    continue;
                }
                let original = legacy_backup.join(
                    entry
                        .path()
                        .strip_prefix(project.join(".agent-workspace"))?,
                );
                if read_optional_bytes(&original)? != read_optional_bytes(entry.path())? {
                    bail!(
                        "{} changed after initialization; preserving it and private backup {}",
                        relative,
                        backup.display()
                    );
                }
            }
        }
    }
    let before: BTreeMap<String, String> = record
        .registry_before
        .as_deref()
        .map(parse_project_json_text)
        .transpose()?
        .unwrap_or_default();
    restore_backup(project, &backup, &record.targets, &record.existed)?;
    registry.retain(|_, path| Path::new(path) != project);
    registry.extend(record.registry_aliases);
    let registry_path = paths.state.join("projects.json");
    if registry == before {
        if let Some(text) = record.registry_before {
            crate::manifest::atomic_write(&registry_path, text.as_bytes())?;
        } else if registry_path.is_file() {
            std::fs::remove_file(&registry_path)?;
        }
    } else {
        write_json(&registry_path, &registry)?;
    }
    if record.legacy_workspace && legacy_backup.is_dir() {
        let generated = safe_project_path(project, ".agent-workspace")?;
        if generated.is_dir() {
            std::fs::remove_dir_all(&generated)?;
        }
        std::fs::rename(&legacy_backup, &generated)?;
    }
    std::fs::remove_file(pending)?;
    Ok(())
}

/// Refresh on first use after activation. Lock order is InstallLock, then lease
/// inspection/publication. Runtime activation never changes project files.
pub(crate) fn refresh_project_locked(
    project: &Path,
    paths: &ProductPaths,
    _lock: &crate::install::InstallLock,
) -> Result<()> {
    recover_project_refresh(project, paths)?;
    let capsule =
        read_capsule(project)?.context("project capsule is not installed; run `byo init`")?;
    let runtime = active_runtime(paths)?;
    if capsule.workspace_version == runtime.pack.version() {
        return doctor_project(project, paths);
    }
    let projection = read_projection(project)?.context("projection manifest is missing")?;
    validate_owned_files(project, &projection)?;
    validate_shared_projections(project, &projection)?;
    let active_mode_path = ".generated/byo/active-mode.json";
    if !projection
        .managed_files
        .iter()
        .any(|file| file.path == active_mode_path)
    {
        bail!("legacy capsule has no verified mode policy; run `byo init --mode {}` with any required full-access authorization", capsule.mode);
    }
    let previous: serde_json::Value = parse_project_json_text(&read_project_text(
        &safe_project_path(project, active_mode_path)?,
    )?)?;
    let mode = runtime.pack.mode(&capsule.mode)?;
    if previous["schema"].as_u64() != Some(1)
        || previous["mode"].as_str() != Some(capsule.mode.as_str())
        || previous["family"].as_str() != Some(mode.family.as_str())
        || previous["full_access"].as_bool() != Some(mode.full_access)
        || previous["codex"] != serde_json::to_value(&mode.codex)?
        || capsule.workflow_protocol != runtime.release.workflow_protocol
        || capsule.minimum_mcp_protocol > runtime.release.sidecar_protocol
    {
        bail!("project mode/permissions are incompatible with the active runtime; review `byo modes`, then explicitly run `byo init --mode {}` with --allow-full-access only if intended", capsule.mode);
    }
    init_project_locked(project, &capsule.mode, false, mode.full_access, paths)?;
    Ok(())
}

pub(crate) fn lease_project(
    project: &Path,
    paths: &ProductPaths,
) -> Result<(Runtime, crate::lease::RuntimeLeaseGuard)> {
    let lock = crate::install::InstallLock::acquire(paths)?;
    refresh_project_locked(project, paths, &lock)?;
    let runtime = active_runtime(paths)?;
    let lease = crate::lease::RuntimeLeaseGuard::acquire_locked(
        paths,
        &runtime.release.version,
        &project_id(project)?,
        &lock,
    )?;
    Ok((runtime, lease))
}

fn project_backup_root(paths: &ProductPaths, project: &Path) -> Result<PathBuf> {
    let location = project
        .to_str()
        .context("project path is not valid Unicode")?;
    crate::paths::ensure_private_directory(&paths.state)?;
    let root = paths.state.join("project-backups");
    crate::paths::ensure_private_directory(&root)?;
    let root = root.join(sha256_bytes(location.as_bytes()));
    crate::paths::ensure_private_directory(&root)?;
    Ok(root)
}

fn prune_project_backups(root: &Path) -> Result<()> {
    let mut backups = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        // This namespace is new. Never touch pre-existing .agent-backups history,
        // symlinks, unknown entries or an archived legacy user workspace.
        if !name.is_ascii()
            || name.len() != 33
            || !name.starts_with("20")
            || name.as_bytes()[8] != b'T'
            || &name[15..17] != "Z-"
            || !name[17..].bytes().all(|b| b.is_ascii_hexdigit())
            || !name[..8].bytes().all(|b| b.is_ascii_digit())
            || !name[9..15].bytes().all(|b| b.is_ascii_digit())
            || !entry.file_type()?.is_dir()
            || entry.path().join("legacy-agent-workspace").exists()
        {
            continue;
        }
        backups.push(entry.path());
    }
    backups.sort();
    let remove_count = backups.len().saturating_sub(PROJECT_BACKUP_RETENTION);
    let canonical_root = root.canonicalize()?;
    for backup in backups.into_iter().take(remove_count) {
        let canonical = backup.canonicalize()?;
        if canonical.parent() != Some(canonical_root.as_path()) {
            bail!("project backup escaped its private directory");
        }
        std::fs::remove_dir_all(&canonical)?;
    }
    Ok(())
}

fn copy_backup(project: &Path, backup: &Path, relatives: &[String]) -> Result<Vec<String>> {
    let mut existed = Vec::new();
    for relative in relatives {
        let source = safe_project_path(project, relative)?;
        if let Some(bytes) = read_optional_bytes(&source)? {
            let destination = backup.join(relative);
            if let Some(parent) = destination.parent() {
                crate::paths::ensure_private_directory(parent)?;
            }
            crate::manifest::atomic_write(&destination, &bytes)?;
            std::fs::set_permissions(&destination, std::fs::metadata(&source)?.permissions())?;
            existed.push(relative.clone());
        }
    }
    Ok(existed)
}

fn restore_backup(
    project: &Path,
    backup: &Path,
    relatives: &[String],
    existed: &[String],
) -> Result<()> {
    for relative in relatives {
        let target = project.join(relative);
        if existed.iter().any(|value| value == relative) {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(backup.join(relative), &target)?;
        } else if target.is_file() {
            std::fs::remove_file(target)?;
        }
    }
    Ok(())
}

/// Render the public, metadata-only entry point for a private workflow skill.
///
/// The complete workflow stays in the verified workspace pack until selected.
fn render_skill_loader(skill_id: &str, skill: &CompiledSkill, client: SkillClient) -> String {
    let mut description = skill
        .description
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if skill.disable_model_invocation
        && !description
            .to_ascii_lowercase()
            .contains("do not select or fetch it automatically")
    {
        description.push_str(&format!(
            " Manual-only: use only when the user explicitly invokes ${skill_id}. Do not select or fetch it automatically."
        ));
    }
    let fetch = match client {
        SkillClient::Codex => format!(
            "Run `byo workflow guidance {skill_id}` and follow the returned instructions.\n"
        ),
        SkillClient::Claude => format!("!`byo workflow guidance {skill_id}`\n"),
    };
    format!(
        "---\nname: {skill_id}\ndescription: >-\n  {description}\ndisable-model-invocation: {}\nuser-invocable: {}\nallowed-tools: Bash(byo workflow guidance {skill_id}:*)\n---\n\nLoad the verified private BYO workflow guidance for this skill:\n\n{fetch}",
        skill.disable_model_invocation, skill.user_invocable
    )
}

fn render_codex_skill_policy(skill: &CompiledSkill) -> String {
    format!(
        "policy:\n  allow_implicit_invocation: {}\n",
        !skill.disable_model_invocation
    )
}

fn is_user_invocable(skill: &CompiledSkill) -> bool {
    skill.user_invocable
}

fn reject_unmanaged_loader_collisions(
    project: &Path,
    existing_projection: Option<&ProjectionManifest>,
    desired_loader_paths: &[String],
) -> Result<()> {
    let managed_paths: BTreeSet<&str> = existing_projection
        .into_iter()
        .flat_map(|projection| projection.managed_files.iter())
        .map(|managed| managed.path.as_str())
        .collect();
    for relative in desired_loader_paths {
        let target = safe_project_path(project, relative)?;
        if target.exists() && !managed_paths.contains(relative.as_str()) {
            bail!(
                "user-owned native skill loader conflicts with BYO projection: {relative}; rename or remove it before retrying"
            );
        }
    }
    Ok(())
}

fn remove_obsolete_managed_files(
    project: &Path,
    obsolete_managed_paths: &[String],
    created_dirs: &BTreeSet<String>,
) -> Result<()> {
    let mut parent_dirs = BTreeSet::new();
    for relative in obsolete_managed_paths {
        let target = safe_project_path(project, relative)?;
        if target.is_file() {
            std::fs::remove_file(&target)?;
        }
        let relative_path = Path::new(relative);
        if let Some(parent) = relative_path.parent() {
            parent_dirs.insert(parent.to_string_lossy().replace('\\', "/"));
            if parent.file_name().is_some_and(|name| name == "agents") {
                if let Some(skill_dir) = parent.parent() {
                    parent_dirs.insert(skill_dir.to_string_lossy().replace('\\', "/"));
                }
            }
        }
    }
    let mut parent_dirs: Vec<_> = parent_dirs.into_iter().collect();
    parent_dirs.sort_by_key(|relative| std::cmp::Reverse(Path::new(relative).components().count()));
    for relative in parent_dirs {
        if !created_dirs.contains(&relative) {
            continue;
        }
        let target = safe_project_path(project, &relative)?;
        if target.is_dir() && std::fs::read_dir(&target)?.next().is_none() {
            std::fs::remove_dir(target)?;
        }
    }
    Ok(())
}

fn copy_directory(source: &Path, destination: &Path) -> Result<()> {
    for entry in WalkDir::new(source).follow_links(false) {
        let entry = entry?;
        let relative = entry.path().strip_prefix(source)?;
        let target = destination.join(relative);
        if entry.file_type().is_symlink() {
            bail!(
                "legacy workspace user state contains a forbidden symlink: {}",
                relative.display()
            );
        }
        if entry.file_type().is_dir() {
            std::fs::create_dir_all(target)?;
        } else if entry.file_type().is_file() {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(entry.path(), target)?;
        } else {
            bail!(
                "legacy workspace user state contains a special file: {}",
                relative.display()
            );
        }
    }
    Ok(())
}

pub fn init_project(
    project: &Path,
    mode: &str,
    dry_run: bool,
    allow_full_access: bool,
    paths: &ProductPaths,
) -> Result<InitPreview> {
    // Serialize project/registry publication with global install mutations.
    let _mutation_lock = if dry_run {
        None
    } else {
        Some(crate::install::InstallLock::acquire(paths)?)
    };
    init_project_locked(project, mode, dry_run, allow_full_access, paths)
}

fn init_project_locked(
    project: &Path,
    mode: &str,
    dry_run: bool,
    allow_full_access: bool,
    paths: &ProductPaths,
) -> Result<InitPreview> {
    if !dry_run {
        recover_project_refresh(project, paths)?;
    }
    let runtime = active_runtime(paths)?;
    let mode_policy = runtime.pack.mode(mode)?;
    let workflow_catalog = runtime.pack.workflow_catalog()?;
    let agent_ids: Vec<_> = workflow_catalog.agents.keys().cloned().collect();
    if mode_policy.name != mode {
        bail!("compiled mode policy identity mismatch");
    }
    if mode_policy.full_access && !allow_full_access {
        bail!("{mode} requires --allow-full-access");
    }

    let existing_capsule = read_capsule(project)?;
    let legacy_workspace = project.join(".agent-workspace").exists() && existing_capsule.is_none();
    let existing_projection = read_projection(project)?;
    if let Some(projection) = &existing_projection {
        validate_owned_files(project, projection)?;
        validate_shared_projections(project, projection)?;
    }
    let legacy_cleanup = existing_projection
        .as_ref()
        .is_some_and(|projection| projection.schema < 3 || projection.legacy_cleanup);

    let preview = InitPreview {
        project: project.display().to_string(),
        workspace: format!("install capsule {}", runtime.pack.version()),
        mode: mode.to_string(),
        mcp_runtime: runtime.release.version.clone(),
        managed_files: if legacy_workspace {
            "Codex and Claude projections; archive and migrate legacy workspace".to_string()
        } else {
            "Codex and Claude workspace projections".to_string()
        },
        user_files: "preserved".to_string(),
        firm: "preserved".to_string(),
        full_access: mode_policy.full_access,
    };
    if dry_run {
        return Ok(preview);
    }

    let bootstrap = format!(
        "Use the BYO firmware MCP server for board setup, debugging, deployment,\n\
serial communication, and recovery.\n\n\
Begin each server run with `initialization_handshake`.\n\
Follow the live tool schema and server-provided guidance.\n\
Do not infer hardware authority from project files or prior sessions.\n\n\
Active workflow mode: `{}`.\n\
Load private workflow guidance only when needed with `byo workflow guidance <skill>`.\n\
Allowed skill identifiers: {}.\n\
Load a private specialist only when needed with `byo workflow agent <agent>`.\n\
Available specialist identifiers: {}.\n",
        mode_policy.name,
        mode_policy.skills.join(", "),
        agent_ids.join(", ")
    );
    let plan = runtime.pack.resource("templates/PLAN.template.md")?;
    let handoff = runtime.pack.resource("templates/HANDOFF.template.md")?;
    let skill = format!(
        "---\nname: byo-firmware\ndescription: Use the BYO firmware MCP workflow.\n---\n\n{}\n",
        bootstrap.trim()
    );
    // Each mode-authorized skill that a user may invoke receives a native loader.
    // Manual-only loaders retain their invocation controls, so clients can expose
    // them for explicit use without allowing implicit model selection.
    let mut projected_skill_loaders = BTreeMap::new();
    for skill_id in &mode_policy.skills {
        let entry = workflow_catalog
            .skills
            .get(skill_id)
            .with_context(|| format!("compiled skill metadata is missing: {skill_id}"))?;
        let metadata = entry.metadata(skill_id);
        if is_user_invocable(&metadata) {
            projected_skill_loaders.insert(
                skill_id.clone(),
                ProjectedSkill {
                    codex_loader: render_skill_loader(skill_id, &metadata, SkillClient::Codex),
                    claude_loader: render_skill_loader(skill_id, &metadata, SkillClient::Claude),
                    codex_policy: render_codex_skill_policy(&metadata),
                },
            );
        }
    }
    let desired_loader_paths: Vec<String> = [
        ".agents/skills/byo-firmware/SKILL.md".to_string(),
        ".claude/skills/byo-firmware/SKILL.md".to_string(),
    ]
    .into_iter()
    .chain(projected_skill_loaders.keys().flat_map(|skill_id| {
        [
            format!(".agents/skills/{skill_id}/SKILL.md"),
            format!(".agents/skills/{skill_id}/agents/openai.yaml"),
            format!(".claude/skills/{skill_id}/SKILL.md"),
        ]
    }))
    .collect();
    reject_unmanaged_loader_collisions(
        project,
        existing_projection.as_ref(),
        &desired_loader_paths,
    )?;
    let active_mode = serde_json::to_string_pretty(&serde_json::json!({
        "schema": 1,
        "mode": mode,
        "family": mode_policy.family,
        "full_access": mode_policy.full_access,
        "skills": mode_policy.skills,
        "agents": agent_ids,
        "verify": mode_policy.verify,
        "codex": mode_policy.codex,
        "workflow": mode_policy.workflow,
        "structure": mode_policy.structure
    }))? + "\n";
    let agents_path = safe_project_path(project, "AGENTS.md")?;
    let old_agents = read_project_text(&agents_path)?;
    let block = managed_block(&bootstrap);
    let new_agents = replace_managed_block(&old_agents, &block)?;
    let claude_path = safe_project_path(project, "CLAUDE.md")?;
    let old_claude = read_project_text(&claude_path)?;
    let new_claude = replace_managed_block(&old_claude, &block)?;
    let codex_path = safe_project_path(project, ".codex/config.toml")?;
    let old_codex = read_project_text(&codex_path)?;
    let (new_codex, codex_hash) = render_codex_config(&old_codex, project)?;
    let codex_hooks_path = safe_project_path(project, ".codex/hooks.json")?;
    let old_codex_hooks = read_project_text(&codex_hooks_path)?;
    let (new_codex_hooks, codex_hooks_hash) =
        render_hook_configuration(&old_codex_hooks, ".codex/hooks.json")?;
    let claude_mcp_path = safe_project_path(project, ".mcp.json")?;
    let old_claude_mcp = read_project_text(&claude_mcp_path)?;
    let (new_claude_mcp, claude_server_hash) = render_claude_mcp(&old_claude_mcp, project)?;
    let claude_settings_path = safe_project_path(project, ".claude/settings.json")?;
    let old_claude_settings = read_project_text(&claude_settings_path)?;
    let (new_claude_settings, claude_hooks_hash) =
        render_hook_configuration(&old_claude_settings, ".claude/settings.json")?;

    let mut targets = vec![
        ".agent-workspace/manifest.json".to_string(),
        ".agent-workspace/PLAN.md".to_string(),
        ".agent-workspace/HANDOFF.md".to_string(),
        ".generated/byo/active-mode.json".to_string(),
        ".generated/byo/projection-manifest.json".to_string(),
        ".codex/config.toml".to_string(),
        ".codex/hooks.json".to_string(),
        ".claude/settings.json".to_string(),
        ".mcp.json".to_string(),
        "AGENTS.md".to_string(),
        "CLAUDE.md".to_string(),
    ];
    targets.extend(desired_loader_paths.iter().cloned());
    let desired_managed_paths: BTreeSet<String> = [".generated/byo/active-mode.json".to_string()]
        .into_iter()
        .chain(desired_loader_paths.iter().cloned())
        .chain([INTEGRITY_PATH.to_string()])
        .collect();
    let obsolete_managed_paths: Vec<String> = existing_projection
        .as_ref()
        .map(|projection| {
            projection
                .managed_files
                .iter()
                .map(|managed| managed.path.clone())
                .filter(|path| !desired_managed_paths.contains(path))
                .collect()
        })
        .unwrap_or_default();
    let mut desired_text: BTreeMap<String, String> = [
        ("AGENTS.md", new_agents.as_str()),
        ("CLAUDE.md", new_claude.as_str()),
        (".codex/config.toml", new_codex.as_str()),
        (".codex/hooks.json", new_codex_hooks.as_str()),
        (".mcp.json", new_claude_mcp.as_str()),
        (".claude/settings.json", new_claude_settings.as_str()),
        (".agents/skills/byo-firmware/SKILL.md", skill.as_str()),
        (".claude/skills/byo-firmware/SKILL.md", skill.as_str()),
        (".generated/byo/active-mode.json", active_mode.as_str()),
    ]
    .into_iter()
    .map(|(path, text)| (path.to_string(), text.to_string()))
    .collect();
    for (skill_id, projected) in &projected_skill_loaders {
        desired_text.insert(
            format!(".agents/skills/{skill_id}/SKILL.md"),
            projected.codex_loader.clone(),
        );
        desired_text.insert(
            format!(".agents/skills/{skill_id}/agents/openai.yaml"),
            projected.codex_policy.clone(),
        );
        desired_text.insert(
            format!(".claude/skills/{skill_id}/SKILL.md"),
            projected.claude_loader.clone(),
        );
    }
    let codex_document = new_codex.parse::<DocumentMut>()?;
    let baseline = IntegrityBaseline {
        schema: 1,
        files: desired_text
            .iter()
            .filter(|(path, _)| desired_managed_paths.contains(*path))
            .map(|(path, text)| (path.clone(), text.clone()))
            .collect(),
        codex_server_semantics_sha256: sha256_bytes(&serde_json::to_vec(&toml_semantics(
            &codex_document["mcp_servers"]["byo"],
        )?)?),
    };
    let integrity_text = serde_json::to_string_pretty(&baseline)? + "\n";
    desired_text.insert(INTEGRITY_PATH.to_string(), integrity_text.clone());
    targets.push(INTEGRITY_PATH.to_string());
    let mut changed_text = BTreeSet::new();
    for (relative, text) in &desired_text {
        if read_optional_bytes(&safe_project_path(project, relative)?)?.as_deref()
            != Some(text.as_bytes())
        {
            changed_text.insert(relative.clone());
        }
    }
    let registry_path = paths.state.join("projects.json");
    let previous_registry = read_optional_bytes(&registry_path)?;
    let registry = project_registry(paths)?;
    let selected_project_id = choose_project_id(project, existing_capsule.as_ref(), &registry)?;
    let working_templates_missing = [".agent-workspace/PLAN.md", ".agent-workspace/HANDOFF.md"]
        .iter()
        .any(|relative| !project.join(relative).is_file());
    let current_capsule = existing_capsule.as_ref().is_some_and(|capsule| {
        capsule.workspace_version == runtime.pack.version()
            && capsule.mode == mode
            && capsule.project_id == selected_project_id
    });
    if !legacy_workspace
        && current_capsule
        && existing_projection.is_some()
        && changed_text.is_empty()
        && obsolete_managed_paths.is_empty()
        && !working_templates_missing
        && registry.get(&selected_project_id).map(String::as_str) == project.to_str()
    {
        doctor_project(project, paths)?;
        return Ok(preview);
    }
    crate::lease::ensure_project_inactive(paths, &selected_project_id)?;
    // Save only files this transaction can actually change, including metadata.
    targets.retain(|relative| {
        relative == ".agent-workspace/manifest.json"
            || relative == ".generated/byo/projection-manifest.json"
            || changed_text.contains(relative)
            || ([".agent-workspace/PLAN.md", ".agent-workspace/HANDOFF.md"]
                .contains(&relative.as_str())
                && !project.join(relative).is_file())
    });
    targets.extend(obsolete_managed_paths.iter().cloned());
    targets.sort();
    targets.dedup();
    for target in &targets {
        safe_project_path(project, target)?;
    }
    let directory_targets: BTreeSet<String> = [
        ".agent-workspace".to_string(),
        ".generated".to_string(),
        ".generated/byo".to_string(),
        ".codex".to_string(),
        ".agents".to_string(),
        ".agents/skills".to_string(),
        ".agents/skills/byo-firmware".to_string(),
        ".claude".to_string(),
        ".claude/skills".to_string(),
        ".claude/skills/byo-firmware".to_string(),
    ]
    .into_iter()
    .chain(projected_skill_loaders.keys().flat_map(|skill_id| {
        [
            format!(".agents/skills/{skill_id}"),
            format!(".agents/skills/{skill_id}/agents"),
            format!(".claude/skills/{skill_id}"),
        ]
    }))
    .collect();
    for directory in &directory_targets {
        safe_project_path(project, directory)?;
    }
    let mut created_files: BTreeSet<String> = existing_projection
        .as_ref()
        .map(|projection| projection.created_files.iter().cloned().collect())
        .unwrap_or_default();
    for target in targets
        .iter()
        .map(String::as_str)
        .chain([".agent-workspace/PLAN.md", ".agent-workspace/HANDOFF.md"])
    {
        if !project.join(target).exists() {
            created_files.insert(target.to_string());
        }
    }
    let mut created_dirs: BTreeSet<String> = existing_projection
        .as_ref()
        .map(|projection| projection.created_dirs.iter().cloned().collect())
        .unwrap_or_default();
    for directory in &directory_targets {
        if !project.join(directory).exists() {
            created_dirs.insert(directory.clone());
        }
    }
    let backup_root = project_backup_root(paths, project)?;
    let backup = backup_root.join(format!(
        "{}-{:016x}",
        Utc::now().format("%Y%m%dT%H%M%SZ"),
        rand::random::<u64>()
    ));
    crate::paths::ensure_private_directory(&backup)?;
    let existed = copy_backup(project, &backup, &targets)?;
    let legacy_backup = backup.join("legacy-agent-workspace");
    // Every publication has the same durable, edit-preserving rollback path.
    let pending = backup_root.join("pending.json");
    {
        write_json(
            &pending,
            &PendingRefresh {
                schema: 1,
                project: project.display().to_string(),
                backup: backup
                    .file_name()
                    .context("backup name missing")?
                    .to_string_lossy()
                    .into_owned(),
                targets: targets.clone(),
                existed: existed.clone(),
                expected: targets
                    .iter()
                    .filter(|relative| {
                        ![
                            ".agent-workspace/manifest.json",
                            ".generated/byo/projection-manifest.json",
                        ]
                        .contains(&relative.as_str())
                    })
                    .map(|relative| {
                        let digest = desired_text
                            .get(relative)
                            .map(|text| sha256_bytes(text.as_bytes()))
                            .or_else(|| match relative.as_str() {
                                ".agent-workspace/PLAN.md" => Some(sha256_bytes(&plan)),
                                ".agent-workspace/HANDOFF.md" => Some(sha256_bytes(&handoff)),
                                _ => None,
                            });
                        (relative.clone(), digest)
                    })
                    .collect(),
                registry_before: previous_registry
                    .as_ref()
                    .map(|bytes| String::from_utf8(bytes.clone()))
                    .transpose()?,
                legacy_workspace,
                registry_aliases: registry
                    .iter()
                    .filter(|(_, path)| path.as_str() == project.to_string_lossy())
                    .map(|(id, path)| (id.clone(), path.clone()))
                    .collect(),
            },
        )?;
    }

    let result = (|| -> Result<()> {
        if legacy_workspace {
            std::fs::create_dir_all(&backup)?;
            std::fs::rename(project.join(".agent-workspace"), &legacy_backup)
                .context("failed to archive the legacy full AgentWorkspace")?;
            publication_barrier("legacy-archived", project, paths)?;
        }
        for directory in &directory_targets {
            std::fs::create_dir_all(project.join(directory))?;
        }
        if legacy_workspace {
            for name in ["PLAN.md", "HANDOFF.md"] {
                let source = legacy_backup.join(name);
                let target = project.join(".agent-workspace").join(name);
                if source.is_file() && !target.exists() {
                    std::fs::copy(source, target)?;
                }
            }
            let legacy_specs = legacy_backup.join("specs");
            if legacy_specs.is_dir() {
                copy_directory(&legacy_specs, &project.join(".agent-workspace/specs"))?;
            }
        }
        remove_obsolete_managed_files(project, &obsolete_managed_paths, &created_dirs)?;
        if !project.join(".agent-workspace/PLAN.md").exists() {
            crate::manifest::atomic_write(&project.join(".agent-workspace/PLAN.md"), &plan)?;
        }
        if !project.join(".agent-workspace/HANDOFF.md").exists() {
            crate::manifest::atomic_write(&project.join(".agent-workspace/HANDOFF.md"), &handoff)?;
        }
        atomic_text(
            &project.join(".agents/skills/byo-firmware/SKILL.md"),
            &skill,
        )?;
        atomic_text(
            &project.join(".claude/skills/byo-firmware/SKILL.md"),
            &skill,
        )?;
        for (skill_id, projected_skill) in &projected_skill_loaders {
            atomic_text(
                &project.join(format!(".agents/skills/{skill_id}/SKILL.md")),
                &projected_skill.codex_loader,
            )?;
            atomic_text(
                &project.join(format!(".agents/skills/{skill_id}/agents/openai.yaml")),
                &projected_skill.codex_policy,
            )?;
            atomic_text(
                &project.join(format!(".claude/skills/{skill_id}/SKILL.md")),
                &projected_skill.claude_loader,
            )?;
        }
        atomic_text(
            &project.join(".generated/byo/active-mode.json"),
            &active_mode,
        )?;
        atomic_text(&agents_path, &new_agents)?;
        atomic_text(&claude_path, &new_claude)?;
        atomic_text(&codex_path, &new_codex)?;
        atomic_text(&codex_hooks_path, &new_codex_hooks)?;
        atomic_text(&claude_mcp_path, &new_claude_mcp)?;
        atomic_text(&claude_settings_path, &new_claude_settings)?;
        atomic_text(&project.join(INTEGRITY_PATH), &integrity_text)?;
        publication_barrier("shared-published", project, paths)?;

        let mut managed_files = vec![
            ManagedFile {
                path: ".agents/skills/byo-firmware/SKILL.md".to_string(),
                sha256: sha256_bytes(skill.as_bytes()),
            },
            ManagedFile {
                path: ".generated/byo/active-mode.json".to_string(),
                sha256: sha256_bytes(active_mode.as_bytes()),
            },
            ManagedFile {
                path: ".claude/skills/byo-firmware/SKILL.md".to_string(),
                sha256: sha256_bytes(skill.as_bytes()),
            },
        ];
        managed_files.extend(projected_skill_loaders.iter().flat_map(
            |(skill_id, projected_skill)| {
                let codex_loader_sha256 = sha256_bytes(projected_skill.codex_loader.as_bytes());
                let claude_loader_sha256 = sha256_bytes(projected_skill.claude_loader.as_bytes());
                let codex_policy_sha256 = sha256_bytes(projected_skill.codex_policy.as_bytes());
                [
                    ManagedFile {
                        path: format!(".agents/skills/{skill_id}/SKILL.md"),
                        sha256: codex_loader_sha256,
                    },
                    ManagedFile {
                        path: format!(".agents/skills/{skill_id}/agents/openai.yaml"),
                        sha256: codex_policy_sha256,
                    },
                    ManagedFile {
                        path: format!(".claude/skills/{skill_id}/SKILL.md"),
                        sha256: claude_loader_sha256,
                    },
                ]
            },
        ));
        managed_files.push(ManagedFile {
            path: INTEGRITY_PATH.to_string(),
            sha256: sha256_bytes(integrity_text.as_bytes()),
        });
        managed_files.sort_by(|left, right| left.path.cmp(&right.path));
        let inventory_bytes = serde_json::to_vec(&managed_files)?;
        let projection = ProjectionManifest {
            schema: 3,
            managed_files,
            agents_block_sha256: sha256_bytes(block.as_bytes()),
            codex_server_sha256: codex_hash,
            codex_hooks_sha256: codex_hooks_hash,
            claude_block_sha256: Some(sha256_bytes(block.as_bytes())),
            claude_server_sha256: Some(claude_server_hash),
            claude_hooks_sha256: Some(claude_hooks_hash),
            created_files: created_files.into_iter().collect(),
            created_dirs: created_dirs.into_iter().collect(),
            legacy_cleanup,
        };
        write_json(
            &project.join(".generated/byo/projection-manifest.json"),
            &projection,
        )?;
        let capsule = CapsuleManifest {
            schema: 1,
            product: "byo".to_string(),
            workspace_version: runtime.pack.version().to_string(),
            workflow_protocol: 1,
            minimum_launcher: env!("CARGO_PKG_VERSION").to_string(),
            maximum_launcher: "0.x".to_string(),
            minimum_mcp_protocol: 1,
            project_id: selected_project_id,
            mode: mode.to_string(),
            installed_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            managed_inventory_sha256: sha256_bytes(&inventory_bytes),
        };
        write_json(&project.join(".agent-workspace/manifest.json"), &capsule)?;
        publication_barrier("before-registration", project, paths)?;
        register_project(paths, project, &capsule)?;
        publication_barrier("after-registration", project, paths)?;
        doctor_project(project, paths)?;
        Ok(())
    })();

    if let Err(error) = result {
        if let Err(rollback_error) = recover_project_refresh(project, paths) {
            bail!("{error:#}; rollback preserved later edits and the pending private backup: {rollback_error:#}");
        }
        prune_project_backups(&backup_root)
            .with_context(|| format!("initialization failed ({error:#}); original files restored, but backup retention failed"))?;
        return Err(error);
    }
    if pending.is_file() {
        std::fs::remove_file(&pending)?;
    }
    prune_project_backups(&backup_root)
        .context("project updated, but private backup retention cleanup failed")?;
    Ok(preview)
}

fn register_project(paths: &ProductPaths, project: &Path, capsule: &CapsuleManifest) -> Result<()> {
    std::fs::create_dir_all(&paths.state)?;
    let registry_path = paths.state.join("projects.json");
    let mut registry = project_registry(paths)?;
    let canonical_path = project
        .to_str()
        .context("project path is not valid Unicode")?;
    if registry
        .get(&capsule.project_id)
        .is_some_and(|path| path != canonical_path)
    {
        bail!("project ID belongs to another location; run `byo init` to assign this copy its own identity");
    }
    registry.retain(|_, path| path != canonical_path);
    registry.insert(capsule.project_id.clone(), canonical_path.to_string());
    write_json(&registry_path, &registry)
}

fn validate_shared_projections(project: &Path, projection: &ProjectionManifest) -> Result<()> {
    let agents = std::fs::read_to_string(safe_project_path(project, "AGENTS.md")?)
        .context("AGENTS.md managed projection is missing")?;
    verify_managed_block(
        &agents,
        "AGENTS.md",
        projection.agents_block_sha256.as_str(),
    )?;
    let codex = std::fs::read_to_string(safe_project_path(project, ".codex/config.toml")?)
        .context("Codex MCP configuration is missing")?;
    let document = codex
        .parse::<DocumentMut>()
        .context("Codex MCP configuration is invalid")?;
    let server = document["mcp_servers"]["byo"].to_string();
    let baseline = integrity_baseline(project, projection)?;
    let equivalent = if let Some(baseline) = baseline {
        sha256_bytes(&serde_json::to_vec(&toml_semantics(
            &document["mcp_servers"]["byo"],
        )?)?)
            == baseline.codex_server_semantics_sha256
    } else {
        // The standard legacy entry was emitted command-first, args-second.
        // Canonical reconstruction also tolerates comments, quotes and key order.
        let mut canonical = Table::new();
        if let Some(table) = document["mcp_servers"]["byo"].as_table_like() {
            for key in ["command", "args"] {
                if let Some(item) = table.get(key) {
                    if let Some(text) = item.as_str() {
                        canonical.insert(key, value(text));
                    } else if let Some(arguments) = item.as_array() {
                        let mut array = Array::new();
                        for argument in arguments.iter() {
                            array.push(
                                argument
                                    .as_str()
                                    .context("BYO server arguments must be strings")?,
                            );
                        }
                        canonical.insert(key, value(array));
                    } else {
                        canonical.insert(key, item.clone());
                    }
                }
            }
            for (key, item) in table.iter() {
                if key != "command" && key != "args" {
                    canonical.insert(key, item.clone());
                }
            }
        }
        canonical.fmt();
        sha256_bytes(server.as_bytes()) == projection.codex_server_sha256
            || sha256_bytes(canonical.to_string().as_bytes()) == projection.codex_server_sha256
    };
    if document["mcp_servers"]["byo"]["command"].as_str() != Some("byo") || !equivalent {
        return Err(owned_edit_error(".codex/config.toml [mcp_servers.byo]"));
    }
    let hooks: serde_json::Value = parse_project_json(
        &std::fs::read(safe_project_path(project, ".codex/hooks.json")?)
            .context("Codex hook configuration is missing")?,
    )
    .context("Codex hook configuration is invalid")?;
    if verify_byo_hooks(&hooks, ".codex/hooks.json").map_err(|error| {
        owned_edit_error(".codex/hooks.json BYO hooks").context(format!("{error:#}"))
    })? != projection.codex_hooks_sha256
    {
        return Err(owned_edit_error(".codex/hooks.json BYO hooks"));
    }
    if projection.schema >= 2 {
        let claude_block_hash = projection
            .claude_block_sha256
            .as_deref()
            .context("Claude instruction projection hash is missing")?;
        let claude = std::fs::read_to_string(safe_project_path(project, "CLAUDE.md")?)
            .context("CLAUDE.md managed projection is missing")?;
        verify_managed_block(&claude, "CLAUDE.md", claude_block_hash)?;

        let mcp: serde_json::Value = parse_project_json(
            &std::fs::read(safe_project_path(project, ".mcp.json")?)
                .context("Claude MCP configuration is missing")?,
        )
        .context("Claude MCP configuration is invalid")?;
        let server = mcp
            .get("mcpServers")
            .and_then(|servers| servers.get("byo"))
            .ok_or_else(|| {
                owned_edit_error(".mcp.json mcpServers.byo")
                    .context("Claude BYO MCP server is missing")
            })?;
        if server.get("command").and_then(serde_json::Value::as_str) != Some("byo")
            || sha256_bytes(serde_json::to_string(server)?.as_bytes())
                != projection
                    .claude_server_sha256
                    .as_deref()
                    .context("Claude MCP projection hash is missing")?
        {
            return Err(owned_edit_error(".mcp.json mcpServers.byo"));
        }

        let settings: serde_json::Value = parse_project_json(
            &std::fs::read(safe_project_path(project, ".claude/settings.json")?)
                .context("Claude settings are missing")?,
        )
        .context("Claude settings are invalid")?;
        if verify_byo_hooks(&settings, ".claude/settings.json").map_err(|error| {
            owned_edit_error(".claude/settings.json BYO hooks").context(format!("{error:#}"))
        })? != projection
            .claude_hooks_sha256
            .as_deref()
            .context("Claude hook projection hash is missing")?
        {
            return Err(owned_edit_error(".claude/settings.json BYO hooks"));
        }
    }
    Ok(())
}

pub fn doctor_project(project: &Path, paths: &ProductPaths) -> Result<()> {
    let runtime = active_runtime(paths)?;
    let capsule = read_capsule(project)?.context("project capsule is not installed")?;
    if capsule.workspace_version != runtime.pack.version()
        || capsule.minimum_mcp_protocol > runtime.release.sidecar_protocol
    {
        bail!("project capsule needs refresh for the active runtime; start `byo mcp serve` or run `byo workspace update` (mode and permissions must remain compatible)");
    }
    let projection = read_projection(project)?.context("projection manifest is missing")?;
    validate_owned_files(project, &projection)?;
    if projection
        .managed_files
        .iter()
        .any(|file| file.path == ".generated/byo/active-mode.json")
    {
        let mode: serde_json::Value = parse_project_json_text(&read_project_text(
            &safe_project_path(project, ".generated/byo/active-mode.json")?,
        )?)?;
        let compiled = runtime.pack.mode(&capsule.mode)?;
        if mode["schema"].as_u64() != Some(1)
            || mode["mode"].as_str() != Some(capsule.mode.as_str())
            || mode["family"].as_str() != Some(compiled.family.as_str())
            || mode["full_access"].as_bool() != Some(compiled.full_access)
            || mode["codex"] != serde_json::to_value(&compiled.codex)?
        {
            bail!("capsule mode/permissions differ from the active runtime policy; run `byo init --mode <mode>` with --allow-full-access only if intended");
        }
    }
    validate_shared_projections(project, &projection)?;
    let firm = project.join(".firm");
    if firm.exists() {
        if std::fs::symlink_metadata(&firm)?.file_type().is_symlink() {
            bail!(".firm must not be a symlink");
        }
        let canonical = firm.canonicalize()?;
        if !canonical.starts_with(project) {
            bail!(".firm escapes the project root");
        }
    }
    let registry_path = paths.state.join("projects.json");
    let registry: BTreeMap<String, String> = parse_project_json(
        &std::fs::read(&registry_path).context("global project registry is missing")?,
    )
    .context("global project registry is invalid")?;
    let registered = registry
        .get(&capsule.project_id)
        .context("project is absent from the global registry")?;
    let expected = project
        .to_str()
        .context("project path is not valid Unicode")?;
    if registered != expected {
        bail!("project path does not match the global registry; run `byo init` at the moved path");
    }
    Ok(())
}

pub fn registered_projects(paths: &ProductPaths) -> Result<Vec<RegisteredProject>> {
    let registry = project_registry(paths)?;
    Ok(registry
        .into_values()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|path| RegisteredProject {
            path: PathBuf::from(path),
        })
        .collect())
}

fn plan_project_uninstall(
    project: &Path,
    purge: bool,
    paths: &ProductPaths,
) -> Result<ProjectUninstallPlan> {
    let capsule = read_capsule(project)?.context("project capsule is not installed")?;
    crate::lease::ensure_project_inactive(paths, &capsule.project_id)?;
    let registry_path = paths.state.join("projects.json");
    if registry_path.is_file() {
        parse_project_json::<BTreeMap<String, String>>(&std::fs::read(&registry_path)?)
            .context("global project registry is invalid")?;
    }
    let projection = read_projection(project)?.context("projection manifest is missing")?;
    validate_owned_files(project, &projection)?;
    validate_shared_projections(project, &projection)?;
    let managed_files = projection
        .managed_files
        .iter()
        .map(|managed| safe_project_path(project, &managed.path))
        .collect::<Result<Vec<_>>>()?;
    let mut text_replacements = Vec::new();
    let agents_path = safe_project_path(project, "AGENTS.md")?;
    if agents_path.exists() {
        let original = std::fs::read_to_string(&agents_path)?;
        text_replacements.push(TextReplacement {
            path: agents_path,
            contents: remove_managed_block(&original)?,
        });
    }
    let claude_path = safe_project_path(project, "CLAUDE.md")?;
    if projection.claude_block_sha256.is_some() && claude_path.exists() {
        let original = std::fs::read_to_string(&claude_path)?;
        text_replacements.push(TextReplacement {
            path: claude_path,
            contents: remove_managed_block(&original)?,
        });
    }
    let codex_path = safe_project_path(project, ".codex/config.toml")?;
    if codex_path.exists() {
        let original = std::fs::read_to_string(&codex_path)?;
        text_replacements.push(TextReplacement {
            path: codex_path,
            contents: remove_codex_config(&original)?,
        });
    }
    let hooks_path = safe_project_path(project, ".codex/hooks.json")?;
    if hooks_path.exists() {
        let original = std::fs::read_to_string(&hooks_path)?;
        text_replacements.push(TextReplacement {
            path: hooks_path,
            contents: remove_hook_configuration(&original, ".codex/hooks.json")?,
        });
    }
    let claude_mcp_path = safe_project_path(project, ".mcp.json")?;
    if projection.claude_server_sha256.is_some() && claude_mcp_path.exists() {
        let original = std::fs::read_to_string(&claude_mcp_path)?;
        text_replacements.push(TextReplacement {
            path: claude_mcp_path,
            contents: remove_claude_mcp(&original)?,
        });
    }
    let claude_settings_path = safe_project_path(project, ".claude/settings.json")?;
    if projection.claude_hooks_sha256.is_some() && claude_settings_path.exists() {
        let original = std::fs::read_to_string(&claude_settings_path)?;
        let without_hooks = remove_hook_configuration(&original, ".claude/settings.json")?;
        text_replacements.push(TextReplacement {
            path: claude_settings_path,
            contents: remove_claude_mcp_approval(&without_hooks, ".claude/settings.json")?,
        });
    }
    let claude_local_settings_path = safe_project_path(project, ".claude/settings.local.json")?;
    if claude_local_settings_path.exists() {
        let original = std::fs::read_to_string(&claude_local_settings_path)?;
        text_replacements.push(TextReplacement {
            path: claude_local_settings_path.clone(),
            contents: remove_claude_mcp_approval(&original, ".claude/settings.local.json")?,
        });
    }
    let mut purge_relative_roots: BTreeSet<String> = [
        ".agent-workspace",
        ".agent-backups",
        ".firm",
        ".generated/byo",
        ".agents/skills/byo-firmware",
        ".codex/skills/byo-firmware",
        ".claude/skills/byo-firmware",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    for managed in &projection.managed_files {
        let relative = Path::new(&managed.path);
        let components: Vec<_> = relative.components().collect();
        if components.len() == 4
            && matches!(
                components.as_slice(),
                [
                    std::path::Component::Normal(root),
                    std::path::Component::Normal(skills),
                    std::path::Component::Normal(_),
                    std::path::Component::Normal(file)
                ] if (*root == ".claude" || *root == ".codex" || *root == ".agents")
                    && *skills == "skills"
                    && *file == "SKILL.md"
            )
        {
            purge_relative_roots.insert(
                relative
                    .parent()
                    .context("managed skill path has no parent")?
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    let managed_skill_dirs: BTreeSet<String> = purge_relative_roots
        .iter()
        .filter(|relative| {
            relative.starts_with(".claude/skills/")
                || relative.starts_with(".codex/skills/")
                || relative.starts_with(".agents/skills/")
        })
        .cloned()
        .collect();
    let managed_codex_policy_dirs: BTreeSet<String> = projection
        .managed_files
        .iter()
        .filter_map(|managed| {
            let relative = Path::new(&managed.path);
            let components: Vec<_> = relative.components().collect();
            if components.len() == 5
                && matches!(
                    components.as_slice(),
                    [
                        std::path::Component::Normal(root),
                        std::path::Component::Normal(skills),
                        std::path::Component::Normal(_),
                        std::path::Component::Normal(agents),
                        std::path::Component::Normal(file)
                    ] if (*root == ".codex" || *root == ".agents")
                        && *skills == "skills"
                        && *agents == "agents"
                        && *file == "openai.yaml"
                )
            {
                relative
                    .parent()
                    .map(|parent| parent.to_string_lossy().replace('\\', "/"))
            } else {
                None
            }
        })
        .collect();
    let known_cleanup_dirs: BTreeSet<String> = [
        ".generated/byo",
        ".generated",
        ".agents/skills/byo-firmware",
        ".agents/skills",
        ".agents",
        ".codex/skills/byo-firmware",
        ".codex/skills",
        ".codex",
        ".claude/skills/byo-firmware",
        ".claude/skills",
        ".claude",
        ".agent-workspace",
        ".agent-backups",
    ]
    .into_iter()
    .map(str::to_string)
    .chain(managed_skill_dirs.iter().cloned())
    .chain(managed_codex_policy_dirs.iter().cloned())
    .collect();
    let created_dirs: BTreeSet<_> = projection.created_dirs.iter().cloned().collect();
    let cleanup_dirs = known_cleanup_dirs
        .into_iter()
        .filter(|relative| {
            projection.schema < 3 || projection.legacy_cleanup || created_dirs.contains(relative)
        })
        .map(|relative| safe_project_path(project, &relative))
        .collect::<Result<Vec<_>>>()?;
    let mut remove_empty_files = projection
        .created_files
        .iter()
        .map(|relative| safe_project_path(project, relative))
        .collect::<Result<BTreeSet<_>>>()?;
    if projection.schema < 3 || projection.legacy_cleanup {
        remove_empty_files.extend(
            text_replacements
                .iter()
                .map(|replacement| replacement.path.clone()),
        );
    }
    remove_empty_files.insert(claude_local_settings_path);
    let purge_roots = if purge {
        purge_relative_roots
            .into_iter()
            .map(|relative| {
                let target = safe_project_path(project, &relative)?;
                if target.exists() {
                    let metadata = std::fs::symlink_metadata(&target)?;
                    if metadata.file_type().is_symlink() || !metadata.is_dir() {
                        bail!(
                            "refusing to purge unsafe BYO project root: {}",
                            target.display()
                        );
                    }
                    let canonical = target.canonicalize()?;
                    if !is_within(&canonical, project) {
                        bail!(
                            "refusing to purge BYO project root outside the project: {}",
                            target.display()
                        );
                    }
                }
                Ok(target)
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    Ok(ProjectUninstallPlan {
        project: project.to_path_buf(),
        purge,
        managed_files,
        text_replacements,
        metadata_files: [
            ".generated/byo/projection-manifest.json",
            ".agent-workspace/manifest.json",
        ]
        .into_iter()
        .map(|relative| project.join(relative))
        .collect(),
        purge_roots,
        cleanup_dirs,
        remove_empty_files,
    })
}

pub(crate) fn plan_registered_project_uninstalls(
    paths: &ProductPaths,
    registered: &[RegisteredProject],
) -> Result<Vec<ProjectUninstallPlan>> {
    let mut plans = Vec::new();
    let mut inspections = Vec::new();
    let mut failed = false;
    let mut unique_paths = BTreeSet::new();
    for entry in registered {
        unique_paths.insert(entry.path.clone());
    }
    for registered_path in unique_paths {
        let result = (|| -> Result<Option<ProjectUninstallPlan>> {
            if !registered_path.is_absolute() {
                bail!("registered project path is not absolute");
            }
            match std::fs::symlink_metadata(&registered_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
                Ok(_) => {}
            }
            let project = canonical_project(Some(&registered_path), paths)?;
            if project != registered_path {
                bail!(
                    "registered path now resolves to {}; run `byo init` at the moved path",
                    project.display()
                );
            }
            plan_project_uninstall(&project, true, paths).map(Some)
        })();
        match result {
            Ok(Some(plan)) => {
                inspections.push((registered_path.clone(), None, false));
                plans.push(plan);
            }
            Ok(None) => inspections.push((registered_path.clone(), None, true)),
            Err(error) => {
                failed = true;
                inspections.push((registered_path.clone(), Some(format!("{error:#}")), false));
            }
        }
    }
    if failed {
        let mut message = String::from(
            "global uninstall could not safely remove every registered project integration; no project integrations or PATH edits were changed:\n",
        );
        for (path, error, absent) in inspections {
            match error {
                Some(error) => {
                    message.push_str(&format!("  {}: {error}\n", path.display()));
                }
                None => {
                    message.push_str(&format!(
                        "  {}: {}\n",
                        path.display(),
                        if absent { "already absent" } else { "ready" }
                    ));
                }
            }
        }
        bail!(message.trim_end().to_string());
    }
    Ok(plans)
}

fn text_is_empty_projection(path: &Path, contents: &str) -> bool {
    if contents.trim().is_empty() {
        return true;
    }
    path.extension().and_then(|extension| extension.to_str()) == Some("json")
        && parse_project_json_text::<serde_json::Value>(contents)
            .ok()
            .and_then(|value| value.as_object().cloned())
            .is_some_and(|object| object.is_empty())
}

fn remove_empty_project_dirs(cleanup_dirs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut removed = Vec::new();
    let mut dynamic = cleanup_dirs.to_vec();
    dynamic.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for target in dynamic {
        if target.is_dir() && std::fs::read_dir(&target)?.next().is_none() {
            std::fs::remove_dir(&target)?;
            removed.push(target);
        }
    }
    Ok(removed)
}

fn apply_project_uninstall_plan(
    plan: ProjectUninstallPlan,
    paths: &ProductPaths,
) -> Result<ProjectUninstallOutcome> {
    let mut removed = Vec::new();
    for target in &plan.managed_files {
        if target.is_file() {
            std::fs::remove_file(target)?;
            removed.push(target.clone());
        }
    }
    for replacement in &plan.text_replacements {
        if text_is_empty_projection(&replacement.path, &replacement.contents)
            && plan.remove_empty_files.contains(&replacement.path)
        {
            if replacement.path.is_file() {
                std::fs::remove_file(&replacement.path)?;
                removed.push(replacement.path.clone());
            }
        } else {
            atomic_text(&replacement.path, &replacement.contents)?;
        }
    }
    for target in &plan.metadata_files {
        if target.is_file() {
            std::fs::remove_file(target)?;
            removed.push(target.clone());
        }
    }
    if plan.purge {
        for target in &plan.purge_roots {
            if target.is_dir() {
                std::fs::remove_dir_all(target)?;
                removed.push(target.clone());
            }
        }
    }
    removed.extend(remove_empty_project_dirs(&plan.cleanup_dirs)?);
    let registry_path = paths.state.join("projects.json");
    if registry_path.exists() {
        let mut registry: BTreeMap<String, String> =
            parse_project_json(&std::fs::read(&registry_path)?)
                .context("global project registry is invalid")?;
        let project_path = plan
            .project
            .to_str()
            .context("project path is not valid Unicode")?;
        // Legacy copied capsules may still share this ID. Remove this path's
        // aliases without erasing another location's registration.
        registry.retain(|_, path| path != project_path);
        write_json(&registry_path, &registry)?;
    }
    let preserved = if plan.purge {
        Vec::new()
    } else {
        [
            ".agent-workspace/PLAN.md",
            ".agent-workspace/HANDOFF.md",
            ".agent-workspace/specs",
            ".firm",
            ".agent-backups",
        ]
        .into_iter()
        .map(|relative| plan.project.join(relative))
        .filter(|target| target.exists())
        .collect()
    };
    removed.sort();
    removed.dedup();
    Ok(ProjectUninstallOutcome { removed, preserved })
}

pub(crate) fn apply_registered_project_uninstalls(
    plans: Vec<ProjectUninstallPlan>,
    paths: &ProductPaths,
) -> Result<RegisteredProjectCleanup> {
    let all_projects: Vec<_> = plans.iter().map(|plan| plan.project.clone()).collect();
    let mut cleaned = Vec::new();
    let mut removed = Vec::new();
    for (index, plan) in plans.into_iter().enumerate() {
        let project = plan.project.clone();
        match apply_project_uninstall_plan(plan, paths) {
            Ok(outcome) => {
                removed.extend(outcome.removed);
                cleaned.push(project);
            }
            Err(error) => {
                let mut message = format!(
                    "global uninstall stopped while removing the BYO integration at {}: {error:#}\nRegistered project integration status:\n",
                    project.display()
                );
                for (location_index, location) in all_projects.iter().enumerate() {
                    let status = if location_index < index {
                        "removed"
                    } else if location_index == index {
                        "failed; inspect this project for partial managed-file cleanup"
                    } else {
                        "not attempted"
                    };
                    message.push_str(&format!("  {}: {status}\n", location.display()));
                }
                bail!(message.trim_end().to_string());
            }
        }
    }
    Ok(RegisteredProjectCleanup {
        projects: cleaned,
        removed,
    })
}

pub fn uninstall_project(
    project: &Path,
    paths: &ProductPaths,
    purge: bool,
) -> Result<ProjectUninstallOutcome> {
    let _lock = crate::install::InstallLock::acquire(paths)?;
    recover_project_refresh(project, paths)?;
    let plan = plan_project_uninstall(project, purge, paths)?;
    apply_project_uninstall_plan(plan, paths)
}

#[cfg(test)]
pub(crate) fn test_shared_projections(project: &Path, schema: u32) -> ProjectionManifest {
    let block = managed_block("BYO bootstrap");
    let (codex, codex_hash) = render_codex_config("", project).unwrap();
    let (hooks, hooks_hash) = render_hook_configuration("", ".codex/hooks.json").unwrap();
    let (mcp, mcp_hash) = render_claude_mcp("", project).unwrap();
    let (settings, settings_hash) = render_hook_configuration("", ".claude/settings.json").unwrap();
    for (path, text) in [
        ("AGENTS.md", block.clone() + "\n"),
        ("CLAUDE.md", block.clone() + "\n"),
        (".codex/config.toml", codex),
        (".codex/hooks.json", hooks),
        (".mcp.json", mcp),
        (".claude/settings.json", settings),
    ] {
        if schema < 2 && ["CLAUDE.md", ".mcp.json", ".claude/settings.json"].contains(&path) {
            continue;
        }
        let target = project.join(path);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(target, text).unwrap();
    }
    ProjectionManifest {
        schema,
        managed_files: Vec::new(),
        agents_block_sha256: sha256_bytes(block.as_bytes()),
        codex_server_sha256: codex_hash,
        codex_hooks_sha256: hooks_hash,
        claude_block_sha256: (schema >= 2).then(|| sha256_bytes(block.as_bytes())),
        claude_server_sha256: (schema >= 2).then_some(mcp_hash),
        claude_hooks_sha256: (schema >= 2).then_some(settings_hash),
        created_files: Vec::new(),
        created_dirs: Vec::new(),
        legacy_cleanup: false,
    }
}

#[cfg(test)]
#[path = "b05_lifecycle_tests.rs"]
mod b05_lifecycle_tests;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use super::{
        choose_project_id, is_user_invocable, managed_block, project_backup_root, project_registry,
        prune_project_backups, read_capsule, read_project_text, register_project,
        reject_unmanaged_loader_collisions, remove_claude_mcp, remove_claude_mcp_approval,
        remove_hook_configuration, remove_obsolete_managed_files, render_claude_mcp,
        render_codex_config, render_codex_skill_policy, render_hook_configuration,
        render_skill_loader, uninstall_project, write_json, CapsuleManifest, ManagedFile,
        ProjectionManifest, SkillClient, PROJECT_BACKUP_RETENTION,
    };

    #[test]
    fn project_text_reads_refuse_encoding_and_type_errors_without_mutation() {
        let root =
            std::env::temp_dir().join(format!("byo-project-text-{:032x}", rand::random::<u128>()));
        std::fs::create_dir_all(&root).unwrap();
        for relative in [
            "AGENTS.md",
            "CLAUDE.md",
            ".codex/config.toml",
            ".codex/hooks.json",
            ".mcp.json",
            ".claude/settings.json",
        ] {
            let target = root.join(relative);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            assert_eq!(read_project_text(&target).unwrap(), "");
            std::fs::write(&target, b"original\xff").unwrap();
            assert!(read_project_text(&target).is_err());
            assert_eq!(std::fs::read(&target).unwrap(), b"original\xff");
        }
        assert!(read_project_text(&root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn copied_identity_registration_and_leases_are_independent() {
        let (root, paths, original) = uninstall_fixture();
        let capsule = read_capsule(&original).unwrap().unwrap();
        let copy = root.join("copy");
        std::fs::create_dir_all(&copy).unwrap();
        let copy = copy.canonicalize().unwrap();
        let registry = project_registry(&paths).unwrap();
        let copy_id = choose_project_id(&copy, Some(&capsule), &registry).unwrap();
        assert_ne!(copy_id, capsule.project_id);
        assert!(register_project(&paths, &copy, &capsule).is_err());
        let mut copied_capsule = capsule.clone();
        copied_capsule.project_id = copy_id.clone();
        register_project(&paths, &copy, &copied_capsule).unwrap();
        let registry = project_registry(&paths).unwrap();
        assert_eq!(
            registry.get(&capsule.project_id).unwrap(),
            original.to_str().unwrap()
        );
        assert_eq!(registry.get(&copy_id).unwrap(), copy.to_str().unwrap());
        let lease =
            crate::lease::RuntimeLeaseGuard::acquire(&paths, "test", &capsule.project_id).unwrap();
        assert!(crate::lease::ensure_project_inactive(&paths, &copy_id).is_ok());
        assert!(crate::lease::ensure_project_inactive(&paths, &capsule.project_id).is_err());
        drop(lease);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_shared_id_uninstall_preserves_the_other_registered_location() {
        let (root, paths, original) = uninstall_fixture();
        let capsule = read_capsule(&original).unwrap().unwrap();
        let other = root.join("other");
        std::fs::create_dir_all(&other).unwrap();
        let other = other.canonicalize().unwrap();
        let mut registry = project_registry(&paths).unwrap();
        registry.insert(capsule.project_id.clone(), other.display().to_string());
        write_json(&paths.state.join("projects.json"), &registry).unwrap();
        uninstall_project(&original, &paths, false).unwrap();
        let registry = project_registry(&paths).unwrap();
        assert_eq!(
            registry.get(&capsule.project_id).unwrap(),
            other.to_str().unwrap()
        );
        assert!(!registry
            .values()
            .any(|path| path == original.to_str().unwrap()));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn private_backup_retention_preserves_legacy_and_unknown_history() {
        let (root, paths, project) = uninstall_fixture();
        let backups = project_backup_root(&paths, &project).unwrap();
        assert!(!backups.starts_with(&project));
        for number in 0..8 {
            let backup = backups.join(format!("20260101T00000{number}Z-{number:016x}"));
            std::fs::create_dir(&backup).unwrap();
            std::fs::write(backup.join("secret"), b"secret").unwrap();
        }
        let legacy = backups.join("20250101T000000Z-0000000000000000");
        std::fs::create_dir_all(legacy.join("legacy-agent-workspace")).unwrap();
        std::fs::write(backups.join("user-note"), b"preserve").unwrap();
        prune_project_backups(&backups).unwrap();
        assert_eq!(
            std::fs::read_dir(&backups).unwrap().count(),
            PROJECT_BACKUP_RETENTION + 2
        );
        assert!(legacy.is_dir());
        assert_eq!(
            std::fs::read(project.join(".agent-backups/backup/user")).unwrap(),
            b"backup\n"
        );
        assert!(backups.join("user-note").is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&backups).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    fn uninstall_fixture() -> (PathBuf, crate::paths::ProductPaths, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "byo-project-uninstall-{:032x}",
            rand::random::<u128>()
        ));
        let project = root.join("project");
        let paths = crate::paths::ProductPaths::from_install_dir(&root.join("product")).unwrap();
        for relative in [
            ".agent-workspace/specs",
            ".agent-backups/backup",
            ".firm",
            ".generated/byo",
            ".agents/skills/verify/agents",
            ".claude/skills/verify",
        ] {
            std::fs::create_dir_all(project.join(relative)).unwrap();
        }
        std::fs::write(project.join(".agent-workspace/PLAN.md"), b"plan\n").unwrap();
        std::fs::write(project.join(".agent-workspace/HANDOFF.md"), b"handoff\n").unwrap();
        std::fs::write(project.join(".agent-workspace/specs/user.md"), b"spec\n").unwrap();
        std::fs::write(project.join(".agent-backups/backup/user"), b"backup\n").unwrap();
        std::fs::write(project.join(".firm/user-state"), b"state\n").unwrap();
        std::fs::write(project.join("customer.txt"), b"customer\n").unwrap();
        let loader = b"managed loader\n";
        std::fs::write(project.join(".claude/skills/verify/SKILL.md"), loader).unwrap();
        std::fs::write(project.join(".agents/skills/verify/SKILL.md"), loader).unwrap();
        let policy = b"policy:\n  allow_implicit_invocation: true\n";
        std::fs::write(
            project.join(".agents/skills/verify/agents/openai.yaml"),
            policy,
        )
        .unwrap();
        std::fs::write(
            project.join("AGENTS.md"),
            managed_block("BYO bootstrap") + "\n",
        )
        .unwrap();
        std::fs::write(
            project.join(".claude/settings.local.json"),
            br#"{"enabledMcpjsonServers":["byo","customer"],"unrelated":true}"#,
        )
        .unwrap();
        let shared = super::test_shared_projections(&project, 3);
        let capsule = CapsuleManifest {
            schema: 1,
            product: "byo".to_string(),
            workspace_version: "test".to_string(),
            workflow_protocol: 1,
            minimum_launcher: "0.1.0".to_string(),
            maximum_launcher: "0.x".to_string(),
            minimum_mcp_protocol: 1,
            project_id: "project-current".to_string(),
            mode: "firmware".to_string(),
            installed_at: "2026-08-20T00:00:00Z".to_string(),
            managed_inventory_sha256: "unused".to_string(),
        };
        crate::manifest::write_json(&project.join(".agent-workspace/manifest.json"), &capsule)
            .unwrap();
        crate::manifest::write_json(
            &project.join(".generated/byo/projection-manifest.json"),
            &serde_json::json!({
                "schema": 3,
                "managed_files": [{
                    "path": ".claude/skills/verify/SKILL.md",
                    "sha256": crate::manifest::sha256_bytes(loader)
                }, {
                    "path": ".agents/skills/verify/SKILL.md",
                    "sha256": crate::manifest::sha256_bytes(loader)
                }, {
                    "path": ".agents/skills/verify/agents/openai.yaml",
                    "sha256": crate::manifest::sha256_bytes(policy)
                }],
                "agents_block_sha256": shared.agents_block_sha256,
                "codex_server_sha256": shared.codex_server_sha256,
                "codex_hooks_sha256": shared.codex_hooks_sha256,
                "claude_block_sha256": shared.claude_block_sha256,
                "claude_server_sha256": shared.claude_server_sha256,
                "claude_hooks_sha256": shared.claude_hooks_sha256,
                "created_files": ["AGENTS.md"],
                "created_dirs": [
                    ".agent-workspace",
                    ".generated",
                    ".generated/byo",
                    ".codex",
                    ".agents",
                    ".agents/skills",
                    ".agents/skills/verify",
                    ".agents/skills/verify/agents",
                    ".claude",
                    ".claude/skills",
                    ".claude/skills/verify"
                ]
            }),
        )
        .unwrap();
        let canonical = project.canonicalize().unwrap();
        std::fs::create_dir_all(&paths.state).unwrap();
        crate::manifest::write_json(
            &paths.state.join("projects.json"),
            &BTreeMap::from([
                (
                    "project-current".to_string(),
                    canonical.display().to_string(),
                ),
                ("stale-alias".to_string(), canonical.display().to_string()),
            ]),
        )
        .unwrap();
        (root, paths, canonical)
    }

    #[test]
    fn codex_config_creates_missing_tables() {
        let (rendered, _) =
            render_codex_config("", Path::new("/tmp/example")).expect("config should render");
        assert!(rendered.contains("[mcp_servers.byo]"));
        assert!(rendered.contains("command = \"byo\""));
        assert!(rendered.contains("\"/tmp/example\""));
    }

    #[test]
    fn codex_config_preserves_unrelated_settings() {
        let (rendered, _) = render_codex_config(
            "model_reasoning_summary = \"auto\"\n",
            Path::new("/tmp/example"),
        )
        .expect("config should render");
        assert!(rendered.contains("model_reasoning_summary = \"auto\""));
        assert!(rendered.contains("[mcp_servers.byo]"));
    }

    #[test]
    fn codex_config_refuses_foreign_byo_server() {
        let error = render_codex_config(
            "[mcp_servers.byo]\ncommand = \"foreign\"\n",
            Path::new("/tmp/example"),
        )
        .expect_err("foreign server should be refused");
        assert!(error.to_string().contains("not owned"));
    }

    #[test]
    fn claude_mcp_preserves_unrelated_servers_and_can_be_removed_cleanly() {
        let original = r#"{"mcpServers":{"customer":{"command":"customer-server"}}}"#;
        let (rendered, _) =
            render_claude_mcp(original, Path::new("/tmp/example")).expect("MCP should render");
        let document: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(
            document["mcpServers"]["customer"]["command"],
            "customer-server"
        );
        assert_eq!(document["mcpServers"]["byo"]["type"], "stdio");
        assert_eq!(document["mcpServers"]["byo"]["command"], "byo");
        assert_eq!(document["mcpServers"]["byo"]["args"][3], "/tmp/example");

        let removed: serde_json::Value =
            serde_json::from_str(&remove_claude_mcp(&rendered).unwrap()).unwrap();
        assert!(removed["mcpServers"].get("byo").is_none());
        assert_eq!(
            removed["mcpServers"]["customer"]["command"],
            "customer-server"
        );
    }

    #[test]
    fn claude_mcp_refuses_a_foreign_byo_server() {
        let error = render_claude_mcp(
            r#"{"mcpServers":{"byo":{"command":"foreign"}}}"#,
            Path::new("/tmp/example"),
        )
        .expect_err("foreign server should be refused");
        assert!(error.to_string().contains("not owned"));
    }

    #[test]
    fn native_skill_loader_exposes_metadata_and_fetches_private_body_on_selection() {
        let skill = crate::pack::CompiledSkill {
            resource: "skills-src/firmware/mcp-help/SKILL.md".to_string(),
            description: "Help select the correct MCP tool.".to_string(),
            disable_model_invocation: false,
            user_invocable: true,
        };
        let loader = render_skill_loader("mcp-help", &skill, SkillClient::Codex);
        assert!(loader.contains("name: mcp-help"));
        assert!(loader.contains("description: >-\n  Help select the correct MCP tool."));
        assert!(loader.contains("disable-model-invocation: false"));
        assert!(loader.contains("user-invocable: true"));
        assert!(loader.contains("Run `byo workflow guidance mcp-help`"));
        assert!(!loader.contains("!`byo workflow guidance"));
        let claude_loader = render_skill_loader("mcp-help", &skill, SkillClient::Claude);
        assert!(claude_loader.contains("!`byo workflow guidance mcp-help`"));
        assert!(!loader.contains("skills-src/firmware"));
        assert!(is_user_invocable(&skill));
        let manual_skill = crate::pack::CompiledSkill {
            disable_model_invocation: true,
            ..skill.clone()
        };
        let manual_loader =
            render_skill_loader("bug-fix-complex", &manual_skill, SkillClient::Codex);
        assert!(manual_loader.contains("disable-model-invocation: true"));
        assert!(manual_loader.contains("user-invocable: true"));
        assert!(manual_loader.contains("$bug-fix-complex"));
        assert!(manual_loader.contains("Do not select or fetch it automatically."));
        assert!(is_user_invocable(&manual_skill));
        assert!(!is_user_invocable(&crate::pack::CompiledSkill {
            user_invocable: false,
            ..skill
        }));
    }

    #[test]
    fn codex_skill_policy_preserves_implicit_invocation_metadata() {
        let model_invocable = crate::pack::CompiledSkill {
            resource: "skills-src/firmware/mcp-help/SKILL.md".to_string(),
            description: "Help select the correct MCP tool.".to_string(),
            disable_model_invocation: false,
            user_invocable: true,
        };
        assert_eq!(
            render_codex_skill_policy(&model_invocable),
            "policy:\n  allow_implicit_invocation: true\n"
        );
        assert_eq!(
            render_codex_skill_policy(&crate::pack::CompiledSkill {
                disable_model_invocation: true,
                ..model_invocable
            }),
            "policy:\n  allow_implicit_invocation: false\n"
        );
    }

    #[test]
    fn rejects_unmanaged_loader_collisions_before_mutation() {
        let root = std::env::temp_dir().join(format!(
            "byo-project-loader-collision-{:032x}",
            rand::random::<u128>()
        ));
        let loader_paths = [
            ".agents/skills/bug-fix-complex/SKILL.md",
            ".agents/skills/bug-fix-complex/agents/openai.yaml",
            ".claude/skills/bug-fix-complex/SKILL.md",
        ];
        let neighboring_file = root.join(".agents/skills/bug-fix-complex/notes.md");
        std::fs::create_dir_all(neighboring_file.parent().unwrap()).unwrap();
        std::fs::write(&neighboring_file, b"preserve neighbor\n").unwrap();

        for relative in loader_paths {
            let target = root.join(relative);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(&target, b"user-owned loader\n").unwrap();
            let error = reject_unmanaged_loader_collisions(&root, None, &[relative.to_string()])
                .expect_err("user-owned loader collision should be refused");
            assert!(error.to_string().contains(relative));
            assert_eq!(std::fs::read(&target).unwrap(), b"user-owned loader\n");
            assert!(!root.join(".agent-backups").exists());
            std::fs::remove_file(target).unwrap();
        }

        let managed_path = loader_paths[0].to_string();
        let managed_target = root.join(&managed_path);
        std::fs::write(&managed_target, b"managed loader\n").unwrap();
        let projection = ProjectionManifest {
            schema: 3,
            managed_files: vec![ManagedFile {
                path: managed_path.clone(),
                sha256: crate::manifest::sha256_bytes(b"managed loader\n"),
            }],
            agents_block_sha256: String::new(),
            codex_server_sha256: String::new(),
            codex_hooks_sha256: String::new(),
            claude_block_sha256: None,
            claude_server_sha256: None,
            claude_hooks_sha256: None,
            created_files: Vec::new(),
            created_dirs: Vec::new(),
            legacy_cleanup: false,
        };
        reject_unmanaged_loader_collisions(&root, Some(&projection), &[managed_path])
            .expect("existing BYO-managed loader should be available during update");
        assert_eq!(
            std::fs::read(&neighboring_file).unwrap(),
            b"preserve neighbor\n"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn claude_mcp_approval_cleanup_preserves_other_servers() {
        let removed = remove_claude_mcp_approval(
            r#"{"enabledMcpjsonServers":["byo","customer"],"disabledMcpjsonServers":["byo"],"unrelated":true}"#,
            ".claude/settings.local.json",
        )
        .unwrap();
        let document: serde_json::Value = serde_json::from_str(&removed).unwrap();
        assert_eq!(
            document["enabledMcpjsonServers"],
            serde_json::json!(["customer"])
        );
        assert!(document.get("disabledMcpjsonServers").is_none());
        assert_eq!(document["unrelated"], true);
    }

    #[test]
    fn ordinary_uninstall_removes_integration_and_preserves_working_data() {
        let (root, paths, project) = uninstall_fixture();
        let outcome = uninstall_project(&project, &paths, false).unwrap();
        assert!(!project.join(".claude/skills/verify").exists());
        assert!(!project.join(".agents/skills/verify/agents").exists());
        assert!(!project.join(".agents/skills/verify").exists());
        assert!(!project.join("AGENTS.md").exists());
        assert!(project.join(".agent-workspace/PLAN.md").is_file());
        assert!(project.join(".agent-backups/backup/user").is_file());
        assert!(project.join(".firm/user-state").is_file());
        assert!(project.join("customer.txt").is_file());
        assert!(!outcome.preserved.is_empty());
        let local: serde_json::Value = serde_json::from_slice(
            &std::fs::read(project.join(".claude/settings.local.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            local["enabledMcpjsonServers"],
            serde_json::json!(["customer"])
        );
        let registry: BTreeMap<String, String> =
            serde_json::from_slice(&std::fs::read(paths.state.join("projects.json")).unwrap())
                .unwrap();
        assert!(registry.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn obsolete_loader_cleanup_prunes_owned_nested_codex_policy_dirs() {
        let root = std::env::temp_dir().join(format!(
            "byo-project-obsolete-loader-{:032x}",
            rand::random::<u128>()
        ));
        let skill_dir = ".codex/skills/obsolete";
        let policy_dir = ".codex/skills/obsolete/agents";
        let loader = ".codex/skills/obsolete/SKILL.md";
        let policy = ".codex/skills/obsolete/agents/openai.yaml";
        std::fs::create_dir_all(root.join(policy_dir)).unwrap();
        std::fs::write(root.join(loader), b"managed loader\n").unwrap();
        std::fs::write(root.join(policy), b"policy\n").unwrap();
        let neighboring_dir = root.join(".codex/skills/user-authored");
        std::fs::create_dir_all(&neighboring_dir).unwrap();

        remove_obsolete_managed_files(
            &root,
            &[loader.to_string(), policy.to_string()],
            &std::collections::BTreeSet::from([skill_dir.to_string(), policy_dir.to_string()]),
        )
        .expect("owned nested policy directories should be removed when empty");

        assert!(!root.join(policy_dir).exists());
        assert!(!root.join(skill_dir).exists());
        assert!(neighboring_dir.is_dir());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ordinary_uninstall_keeps_preexisting_shared_files_that_become_empty() {
        let (root, paths, project) = uninstall_fixture();
        let projection_path = project.join(".generated/byo/projection-manifest.json");
        let mut projection: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&projection_path).unwrap()).unwrap();
        projection["created_files"] = serde_json::json!([]);
        crate::manifest::write_json(&projection_path, &projection).unwrap();

        uninstall_project(&project, &paths, false).unwrap();

        assert!(project.join("AGENTS.md").is_file());
        assert!(std::fs::read_to_string(project.join("AGENTS.md"))
            .unwrap()
            .trim()
            .is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_projection_cleanup_prunes_empty_byo_shells_conservatively() {
        let (root, paths, project) = uninstall_fixture();
        let projection_path = project.join(".generated/byo/projection-manifest.json");
        let mut projection: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&projection_path).unwrap()).unwrap();
        projection["schema"] = serde_json::json!(2);
        projection.as_object_mut().unwrap().remove("created_files");
        projection.as_object_mut().unwrap().remove("created_dirs");
        crate::manifest::write_json(&projection_path, &projection).unwrap();

        uninstall_project(&project, &paths, false).unwrap();

        assert!(!project.join("AGENTS.md").exists());
        assert!(!project.join(".claude/skills").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn project_purge_removes_dedicated_byo_roots_only() {
        let (root, paths, project) = uninstall_fixture();
        uninstall_project(&project, &paths, true).unwrap();
        for relative in [
            ".agent-workspace",
            ".agent-backups",
            ".firm",
            ".generated/byo",
        ] {
            assert!(!project.join(relative).exists(), "purge left {relative}");
        }
        assert!(project.join("customer.txt").is_file());
        let local: serde_json::Value = serde_json::from_slice(
            &std::fs::read(project.join(".claude/settings.local.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            local["enabledMcpjsonServers"],
            serde_json::json!(["customer"])
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn project_purge_rejects_symlinked_byo_roots_before_mutation() {
        use std::os::unix::fs::symlink;

        let (root, paths, project) = uninstall_fixture();
        let external = root.join("external-firm");
        std::fs::create_dir(&external).unwrap();
        std::fs::write(external.join("keep"), b"outside\n").unwrap();
        std::fs::remove_dir_all(project.join(".firm")).unwrap();
        symlink(&external, project.join(".firm")).unwrap();

        let error = uninstall_project(&project, &paths, true).unwrap_err();

        assert!(format!("{error:#}").contains("symlink"));
        assert!(project.join(".agent-workspace/manifest.json").is_file());
        assert!(external.join("keep").is_file());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn registration_replaces_stale_aliases_for_the_same_project_path() {
        let (root, paths, project) = uninstall_fixture();
        let capsule: CapsuleManifest = serde_json::from_slice(
            &std::fs::read(project.join(".agent-workspace/manifest.json")).unwrap(),
        )
        .unwrap();
        register_project(&paths, &project, &capsule).unwrap();
        let registry: BTreeMap<String, String> =
            serde_json::from_slice(&std::fs::read(paths.state.join("projects.json")).unwrap())
                .unwrap();
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry.get(&capsule.project_id),
            Some(&project.display().to_string())
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn claude_hooks_preserve_customer_settings_and_uninstall_only_byo_entries() {
        let original = r#"{
            "unrelated": {"preserved": true},
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Write",
                    "hooks": [{"type": "command", "command": "customer-hook"}]
                }]
            }
        }"#;
        let (rendered, _) = render_hook_configuration(original, ".claude/settings.json").unwrap();
        let document: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(document["unrelated"]["preserved"], true);
        assert!(document["hooks"]["PreToolUse"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["matcher"] == "Write"));

        let removed = remove_hook_configuration(&rendered, ".claude/settings.json").unwrap();
        let document: serde_json::Value = serde_json::from_str(&removed).unwrap();
        assert_eq!(document["unrelated"]["preserved"], true);
        assert!(document["hooks"]["PreToolUse"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["matcher"] == "Write"));
        assert!(!removed.contains("\"command\": \"byo hook "));
    }
}
