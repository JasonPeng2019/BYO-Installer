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
pub(crate) struct ProjectUninstallPlan {
    project: PathBuf,
    project_id: String,
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
        serde_json::from_slice(&std::fs::read(&path)?).context("capsule manifest is invalid")?;
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

fn read_projection(project: &Path) -> Result<Option<ProjectionManifest>> {
    let path = project.join(".generated/byo/projection-manifest.json");
    if !path.exists() {
        return Ok(None);
    }
    let manifest: ProjectionManifest =
        serde_json::from_slice(&std::fs::read(path)?).context("projection manifest is invalid")?;
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
    for managed in &projection.managed_files {
        let target = safe_project_path(project, &managed.path)?;
        if !target.is_file() || sha256_file(&target)? != managed.sha256 {
            bail!("vendor-owned projection was modified: {}", managed.path);
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
        .with_context(|| format!("{label} BYO block is missing"))?;
    let end = original
        .find(END_MARKER)
        .with_context(|| format!("{label} BYO block is malformed"))?
        + END_MARKER.len();
    if original[begin..end].matches(BEGIN_MARKER).count() != 1
        || sha256_bytes(&original.as_bytes()[begin..end]) != expected_sha256
    {
        bail!("{label} BYO managed block was modified");
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
        .as_table_mut()
        .context("mcp_servers must be a TOML table")?;
    let byo = servers
        .entry("byo")
        .or_insert_with(|| Item::Table(Table::new()))
        .as_table_mut()
        .context("mcp_servers.byo must be a TOML table")?;
    if let Some(command) = byo.get("command").and_then(|item| item.as_str()) {
        if command != "byo" {
            return Err(crate::error::fail(
                ExitCategory::ClientConflict,
                "existing mcp_servers.byo is not owned by BYO",
            ));
        }
    }
    byo["command"] = value("byo");
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
    byo["args"] = value(args);
    let server = byo.to_string();
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
        .and_then(|item| item.as_table_mut())
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
        serde_json::from_str(original).context(".mcp.json is invalid JSON")?
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
        serde_json::from_str(original).context(".mcp.json is invalid JSON")?;
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
        serde_json::from_str(original).with_context(|| format!("{label} is invalid JSON"))?;
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
        serde_json::from_str(original).with_context(|| format!("{label} is invalid JSON"))?
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
        serde_json::from_str(original).with_context(|| format!("{label} is invalid JSON"))?;
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
    crate::manifest::atomic_write(path, text.as_bytes())
}

fn copy_backup(project: &Path, backup: &Path, relatives: &[String]) -> Result<Vec<String>> {
    let mut existed = Vec::new();
    for relative in relatives {
        let source = project.join(relative);
        if source.is_file() {
            let destination = backup.join(relative);
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&source, destination)?;
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
/// Codex and Claude consume the same native `SKILL.md` contract. The complete
/// workflow stays in the verified workspace pack until the client loads it.
fn render_skill_loader(skill_id: &str, skill: &CompiledSkill) -> String {
    let description = skill
        .description
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "---\nname: {skill_id}\ndescription: >-\n  {description}\ndisable-model-invocation: {}\nuser-invocable: {}\nallowed-tools: Bash(byo workflow guidance {skill_id}:*)\n---\n\nLoad the verified private BYO workflow guidance for this skill:\n\n!`byo workflow guidance {skill_id}`\n",
        skill.disable_model_invocation, skill.user_invocable
    )
}

fn is_model_invocable(skill: &CompiledSkill) -> bool {
    !skill.disable_model_invocation
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
    // Only skills the workspace explicitly permits the model to invoke are
    // advertised as native skills. Manual-only skills remain available through
    // `byo workflow guidance <skill>` after an explicit user request, but their
    // names and descriptions are not injected into either client's catalog.
    let mut visible_skill_loaders = BTreeMap::new();
    for skill_id in &mode_policy.skills {
        let entry = workflow_catalog
            .skills
            .get(skill_id)
            .with_context(|| format!("compiled skill metadata is missing: {skill_id}"))?;
        let metadata = entry.metadata(skill_id);
        if is_model_invocable(&metadata) {
            visible_skill_loaders
                .insert(skill_id.clone(), render_skill_loader(skill_id, &metadata));
        }
    }
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
    let old_agents = std::fs::read_to_string(&agents_path).unwrap_or_default();
    let block = managed_block(&bootstrap);
    let new_agents = replace_managed_block(&old_agents, &block)?;
    let claude_path = safe_project_path(project, "CLAUDE.md")?;
    let old_claude = std::fs::read_to_string(&claude_path).unwrap_or_default();
    let new_claude = replace_managed_block(&old_claude, &block)?;
    let codex_path = safe_project_path(project, ".codex/config.toml")?;
    let old_codex = std::fs::read_to_string(&codex_path).unwrap_or_default();
    let (new_codex, codex_hash) = render_codex_config(&old_codex, project)?;
    let codex_hooks_path = safe_project_path(project, ".codex/hooks.json")?;
    let old_codex_hooks = std::fs::read_to_string(&codex_hooks_path).unwrap_or_default();
    let (new_codex_hooks, codex_hooks_hash) =
        render_hook_configuration(&old_codex_hooks, ".codex/hooks.json")?;
    let claude_mcp_path = safe_project_path(project, ".mcp.json")?;
    let old_claude_mcp = std::fs::read_to_string(&claude_mcp_path).unwrap_or_default();
    let (new_claude_mcp, claude_server_hash) = render_claude_mcp(&old_claude_mcp, project)?;
    let claude_settings_path = safe_project_path(project, ".claude/settings.json")?;
    let old_claude_settings = std::fs::read_to_string(&claude_settings_path).unwrap_or_default();
    let (new_claude_settings, claude_hooks_hash) =
        render_hook_configuration(&old_claude_settings, ".claude/settings.json")?;

    let mut targets = vec![
        ".agent-workspace/manifest.json".to_string(),
        ".generated/byo/active-mode.json".to_string(),
        ".generated/byo/projection-manifest.json".to_string(),
        ".codex/skills/byo-firmware/SKILL.md".to_string(),
        ".claude/skills/byo-firmware/SKILL.md".to_string(),
        ".codex/config.toml".to_string(),
        ".codex/hooks.json".to_string(),
        ".claude/settings.json".to_string(),
        ".mcp.json".to_string(),
        "AGENTS.md".to_string(),
        "CLAUDE.md".to_string(),
    ];
    targets.extend(visible_skill_loaders.keys().flat_map(|skill_id| {
        [
            format!(".codex/skills/{skill_id}/SKILL.md"),
            format!(".claude/skills/{skill_id}/SKILL.md"),
        ]
    }));
    let desired_managed_paths: BTreeSet<String> = [
        ".codex/skills/byo-firmware/SKILL.md".to_string(),
        ".claude/skills/byo-firmware/SKILL.md".to_string(),
        ".generated/byo/active-mode.json".to_string(),
    ]
    .into_iter()
    .chain(visible_skill_loaders.keys().flat_map(|skill_id| {
        [
            format!(".codex/skills/{skill_id}/SKILL.md"),
            format!(".claude/skills/{skill_id}/SKILL.md"),
        ]
    }))
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
        ".codex/skills".to_string(),
        ".codex/skills/byo-firmware".to_string(),
        ".claude".to_string(),
        ".claude/skills".to_string(),
        ".claude/skills/byo-firmware".to_string(),
    ]
    .into_iter()
    .chain(visible_skill_loaders.keys().flat_map(|skill_id| {
        [
            format!(".codex/skills/{skill_id}"),
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
    let backup = project.join(format!(
        ".agent-backups/{}-{:016x}",
        Utc::now().format("%Y%m%dT%H%M%SZ"),
        rand::random::<u64>()
    ));
    let backup_root_existed = project.join(".agent-backups").exists();
    let existed = copy_backup(project, &backup, &targets)?;
    if !backup_root_existed && project.join(".agent-backups").is_dir() {
        created_dirs.insert(".agent-backups".to_string());
    }
    let legacy_backup = backup.join("legacy-agent-workspace");
    let registry_path = paths.state.join("projects.json");
    let previous_registry = std::fs::read(&registry_path).ok();

    let result = (|| -> Result<()> {
        if legacy_workspace {
            std::fs::create_dir_all(&backup)?;
            std::fs::rename(project.join(".agent-workspace"), &legacy_backup)
                .context("failed to archive the legacy full AgentWorkspace")?;
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
        for relative in &obsolete_managed_paths {
            let target = safe_project_path(project, relative)?;
            if target.is_file() {
                std::fs::remove_file(&target)?;
            }
            if let Some(parent) = target.parent() {
                if parent.is_dir() && std::fs::read_dir(parent)?.next().is_none() {
                    std::fs::remove_dir(parent)?;
                }
            }
        }
        if !project.join(".agent-workspace/PLAN.md").exists() {
            crate::manifest::atomic_write(&project.join(".agent-workspace/PLAN.md"), &plan)?;
        }
        if !project.join(".agent-workspace/HANDOFF.md").exists() {
            crate::manifest::atomic_write(&project.join(".agent-workspace/HANDOFF.md"), &handoff)?;
        }
        atomic_text(&project.join(".codex/skills/byo-firmware/SKILL.md"), &skill)?;
        atomic_text(
            &project.join(".claude/skills/byo-firmware/SKILL.md"),
            &skill,
        )?;
        for (skill_id, loader) in &visible_skill_loaders {
            atomic_text(
                &project.join(format!(".codex/skills/{skill_id}/SKILL.md")),
                loader,
            )?;
            atomic_text(
                &project.join(format!(".claude/skills/{skill_id}/SKILL.md")),
                loader,
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

        let mut managed_files = vec![
            ManagedFile {
                path: ".codex/skills/byo-firmware/SKILL.md".to_string(),
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
        managed_files.extend(visible_skill_loaders.iter().flat_map(|(skill_id, loader)| {
            let sha256 = sha256_bytes(loader.as_bytes());
            [
                ManagedFile {
                    path: format!(".codex/skills/{skill_id}/SKILL.md"),
                    sha256: sha256.clone(),
                },
                ManagedFile {
                    path: format!(".claude/skills/{skill_id}/SKILL.md"),
                    sha256,
                },
            ]
        }));
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
            project_id: existing_capsule
                .as_ref()
                .map(|manifest| manifest.project_id.clone())
                .unwrap_or_else(|| format!("{:032x}", rand::random::<u128>())),
            mode: mode.to_string(),
            installed_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            managed_inventory_sha256: sha256_bytes(&inventory_bytes),
        };
        write_json(&project.join(".agent-workspace/manifest.json"), &capsule)?;
        register_project(paths, project, &capsule)?;
        doctor_project(project, paths)?;
        Ok(())
    })();

    if let Err(error) = result {
        let rollback = restore_backup(project, &backup, &targets, &existed);
        if let Err(rollback_error) = rollback {
            bail!("{error:#}; rollback also failed: {rollback_error:#}");
        }
        if let Some(previous) = previous_registry.as_deref() {
            crate::manifest::atomic_write(&registry_path, previous)?;
        } else if registry_path.is_file() {
            std::fs::remove_file(&registry_path)?;
        }
        if legacy_workspace && legacy_backup.is_dir() {
            let generated = project.join(".agent-workspace");
            if generated.is_dir() {
                std::fs::remove_dir_all(&generated)?;
            }
            std::fs::rename(&legacy_backup, &generated)?;
        }
        return Err(error);
    }
    Ok(preview)
}

fn register_project(paths: &ProductPaths, project: &Path, capsule: &CapsuleManifest) -> Result<()> {
    std::fs::create_dir_all(&paths.state)?;
    let registry_path = paths.state.join("projects.json");
    let mut registry: BTreeMap<String, String> = if registry_path.exists() {
        serde_json::from_slice(&std::fs::read(&registry_path)?)
            .context("project registry is invalid")?
    } else {
        BTreeMap::new()
    };
    let canonical_path = project
        .to_str()
        .context("project path is not valid Unicode")?;
    registry.retain(|project_id, path| project_id == &capsule.project_id || path != canonical_path);
    registry.insert(capsule.project_id.clone(), canonical_path.to_string());
    write_json(&registry_path, &registry)
}

pub fn doctor_project(project: &Path, paths: &ProductPaths) -> Result<()> {
    let runtime = active_runtime(paths)?;
    let capsule = read_capsule(project)?.context("project capsule is not installed")?;
    if capsule.workspace_version != runtime.pack.version()
        || capsule.minimum_mcp_protocol > runtime.release.sidecar_protocol
    {
        bail!("project capsule is incompatible with the active runtime");
    }
    let projection = read_projection(project)?.context("projection manifest is missing")?;
    validate_owned_files(project, &projection)?;
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
    if document["mcp_servers"]["byo"]["command"].as_str() != Some("byo")
        || sha256_bytes(server.as_bytes()) != projection.codex_server_sha256
    {
        bail!("Codex BYO MCP configuration was modified");
    }
    let hooks: serde_json::Value = serde_json::from_slice(
        &std::fs::read(safe_project_path(project, ".codex/hooks.json")?)
            .context("Codex hook configuration is missing")?,
    )
    .context("Codex hook configuration is invalid")?;
    if verify_byo_hooks(&hooks, ".codex/hooks.json")? != projection.codex_hooks_sha256 {
        bail!("Codex BYO hook configuration was modified");
    }
    if projection.schema >= 2 {
        let claude_block_hash = projection
            .claude_block_sha256
            .as_deref()
            .context("Claude instruction projection hash is missing")?;
        let claude = std::fs::read_to_string(safe_project_path(project, "CLAUDE.md")?)
            .context("CLAUDE.md managed projection is missing")?;
        verify_managed_block(&claude, "CLAUDE.md", claude_block_hash)?;

        let mcp: serde_json::Value = serde_json::from_slice(
            &std::fs::read(safe_project_path(project, ".mcp.json")?)
                .context("Claude MCP configuration is missing")?,
        )
        .context("Claude MCP configuration is invalid")?;
        let server = mcp
            .get("mcpServers")
            .and_then(|servers| servers.get("byo"))
            .context("Claude BYO MCP server is missing")?;
        if server.get("command").and_then(serde_json::Value::as_str) != Some("byo")
            || sha256_bytes(serde_json::to_string(server)?.as_bytes())
                != projection
                    .claude_server_sha256
                    .as_deref()
                    .context("Claude MCP projection hash is missing")?
        {
            bail!("Claude BYO MCP configuration was modified");
        }

        let settings: serde_json::Value = serde_json::from_slice(
            &std::fs::read(safe_project_path(project, ".claude/settings.json")?)
                .context("Claude settings are missing")?,
        )
        .context("Claude settings are invalid")?;
        if verify_byo_hooks(&settings, ".claude/settings.json")?
            != projection
                .claude_hooks_sha256
                .as_deref()
                .context("Claude hook projection hash is missing")?
        {
            bail!("Claude BYO hook configuration was modified");
        }
    }
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
    let registry: BTreeMap<String, String> = serde_json::from_slice(
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
    let registry_path = paths.state.join("projects.json");
    if !registry_path.is_file() {
        return Ok(Vec::new());
    }
    let registry: BTreeMap<String, String> =
        serde_json::from_slice(&std::fs::read(&registry_path)?)
            .context("global project registry is invalid")?;
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
    let registry_path = paths.state.join("projects.json");
    if registry_path.is_file() {
        serde_json::from_slice::<BTreeMap<String, String>>(&std::fs::read(&registry_path)?)
            .context("global project registry is invalid")?;
    }
    let projection = read_projection(project)?.context("projection manifest is missing")?;
    validate_owned_files(project, &projection)?;
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
                ] if (*root == ".claude" || *root == ".codex")
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
            relative.starts_with(".claude/skills/") || relative.starts_with(".codex/skills/")
        })
        .cloned()
        .collect();
    let known_cleanup_dirs: BTreeSet<String> = [
        ".generated/byo",
        ".generated",
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
    .collect();
    let created_dirs: BTreeSet<_> = projection.created_dirs.iter().cloned().collect();
    let cleanup_dirs = known_cleanup_dirs
        .into_iter()
        .filter(|relative| {
            projection.schema < 3
                || projection.legacy_cleanup
                || created_dirs.contains(relative)
                || managed_skill_dirs.contains(relative)
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
        project_id: capsule.project_id,
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
        let result = (|| -> Result<ProjectUninstallPlan> {
            if !registered_path.is_absolute() {
                bail!("registered project path is not absolute");
            }
            let project = canonical_project(Some(&registered_path), paths)?;
            if project != registered_path {
                bail!(
                    "registered path now resolves to {}; run `byo init` at the moved path",
                    project.display()
                );
            }
            plan_project_uninstall(&project, true, paths)
        })();
        match result {
            Ok(plan) => {
                inspections.push((registered_path.clone(), None));
                plans.push(plan);
            }
            Err(error) => {
                failed = true;
                inspections.push((registered_path.clone(), Some(format!("{error:#}"))));
            }
        }
    }
    if failed {
        let mut message = String::from(
            "global uninstall could not safely remove every registered project integration; no project integrations or PATH edits were changed:\n",
        );
        for (path, error) in inspections {
            match error {
                Some(error) => {
                    message.push_str(&format!("  {}: {error}\n", path.display()));
                }
                None => {
                    message.push_str(&format!("  {}: ready\n", path.display()));
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
        && serde_json::from_str::<serde_json::Value>(contents)
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
            serde_json::from_slice(&std::fs::read(&registry_path)?)
                .context("global project registry is invalid")?;
        let project_path = plan
            .project
            .to_str()
            .context("project path is not valid Unicode")?;
        registry.retain(|project_id, path| project_id != &plan.project_id && path != project_path);
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
    let plan = plan_project_uninstall(project, purge, paths)?;
    apply_project_uninstall_plan(plan, paths)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use super::{
        is_model_invocable, managed_block, register_project, remove_claude_mcp,
        remove_claude_mcp_approval, remove_hook_configuration, render_claude_mcp,
        render_codex_config, render_hook_configuration, render_skill_loader, uninstall_project,
        CapsuleManifest,
    };

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
                }],
                "agents_block_sha256": "unused",
                "codex_server_sha256": "unused",
                "codex_hooks_sha256": "unused",
                "created_files": ["AGENTS.md"],
                "created_dirs": [
                    ".agent-workspace",
                    ".generated",
                    ".generated/byo",
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
    fn native_skill_loader_exposes_metadata_without_private_body() {
        let skill = crate::pack::CompiledSkill {
            resource: "skills-src/firmware/mcp-help/SKILL.md".to_string(),
            description: "Help select the correct MCP tool.".to_string(),
            disable_model_invocation: false,
            user_invocable: true,
        };
        let loader = render_skill_loader("mcp-help", &skill);
        assert!(loader.contains("name: mcp-help"));
        assert!(loader.contains("description: >-"));
        assert!(loader.contains("disable-model-invocation: false"));
        assert!(loader.contains("!`byo workflow guidance mcp-help`"));
        assert!(!loader.contains("skills-src/firmware"));
        assert!(is_model_invocable(&skill));
        assert!(!is_model_invocable(&crate::pack::CompiledSkill {
            disable_model_invocation: true,
            ..skill
        }));
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
