use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use toml_edit::{value, Array, DocumentMut, Item, Table};
use walkdir::WalkDir;

use crate::error::{categorize, ExitCategory};
use crate::manifest::{sha256_bytes, sha256_file, write_json, ReleaseManifest};
use crate::pack::WorkspacePack;
use crate::paths::{is_within, ProductPaths};

const BEGIN_MARKER: &str = "<!-- BEGIN BYO MANAGED: agent-bootstrap v1 -->";
const END_MARKER: &str = "<!-- END BYO MANAGED: agent-bootstrap v1 -->";

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
    if !matches!(manifest.schema, 1 | 2) {
        bail!("projection manifest schema is unsupported");
    }
    Ok(Some(manifest))
}

fn validate_owned_files(project: &Path, projection: &ProjectionManifest) -> Result<()> {
    for managed in &projection.managed_files {
        let target = project.join(&managed.path);
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
    let mut output = serde_json::to_string_pretty(&document)?;
    output.push('\n');
    Ok(output)
}

fn atomic_text(path: &Path, text: &str) -> Result<()> {
    crate::manifest::atomic_write(path, text.as_bytes())
}

fn copy_backup(project: &Path, backup: &Path, relatives: &[&str]) -> Result<Vec<String>> {
    let mut existed = Vec::new();
    for relative in relatives {
        let source = project.join(relative);
        if source.is_file() {
            let destination = backup.join(relative);
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&source, destination)?;
            existed.push((*relative).to_string());
        }
    }
    Ok(existed)
}

fn restore_backup(
    project: &Path,
    backup: &Path,
    relatives: &[&str],
    existed: &[String],
) -> Result<()> {
    for relative in relatives {
        let target = project.join(relative);
        if existed.iter().any(|value| value == relative) {
            std::fs::copy(backup.join(relative), &target)?;
        } else if target.is_file() {
            std::fs::remove_file(target)?;
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
    if let Some(projection) = read_projection(project)? {
        validate_owned_files(project, &projection)?;
    }

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
    let agents_path = project.join("AGENTS.md");
    let old_agents = std::fs::read_to_string(&agents_path).unwrap_or_default();
    let block = managed_block(&bootstrap);
    let new_agents = replace_managed_block(&old_agents, &block)?;
    let claude_path = project.join("CLAUDE.md");
    let old_claude = std::fs::read_to_string(&claude_path).unwrap_or_default();
    let new_claude = replace_managed_block(&old_claude, &block)?;
    let codex_path = project.join(".codex/config.toml");
    let old_codex = std::fs::read_to_string(&codex_path).unwrap_or_default();
    let (new_codex, codex_hash) = render_codex_config(&old_codex, project)?;
    let codex_hooks_path = project.join(".codex/hooks.json");
    let old_codex_hooks = std::fs::read_to_string(&codex_hooks_path).unwrap_or_default();
    let (new_codex_hooks, codex_hooks_hash) =
        render_hook_configuration(&old_codex_hooks, ".codex/hooks.json")?;
    let claude_mcp_path = project.join(".mcp.json");
    let old_claude_mcp = std::fs::read_to_string(&claude_mcp_path).unwrap_or_default();
    let (new_claude_mcp, claude_server_hash) = render_claude_mcp(&old_claude_mcp, project)?;
    let claude_settings_path = project.join(".claude/settings.json");
    let old_claude_settings = std::fs::read_to_string(&claude_settings_path).unwrap_or_default();
    let (new_claude_settings, claude_hooks_hash) =
        render_hook_configuration(&old_claude_settings, ".claude/settings.json")?;

    let targets = [
        ".agent-workspace/manifest.json",
        ".generated/byo/active-mode.json",
        ".generated/byo/projection-manifest.json",
        ".codex/skills/byo-firmware/SKILL.md",
        ".claude/skills/byo-firmware/SKILL.md",
        ".codex/config.toml",
        ".codex/hooks.json",
        ".claude/settings.json",
        ".mcp.json",
        "AGENTS.md",
        "CLAUDE.md",
    ];
    let backup = project.join(format!(
        ".agent-backups/{}-{:016x}",
        Utc::now().format("%Y%m%dT%H%M%SZ"),
        rand::random::<u64>()
    ));
    let existed = copy_backup(project, &backup, &targets)?;
    let legacy_backup = backup.join("legacy-agent-workspace");
    let registry_path = paths.state.join("projects.json");
    let previous_registry = std::fs::read(&registry_path).ok();

    let result = (|| -> Result<()> {
        if legacy_workspace {
            std::fs::create_dir_all(&backup)?;
            std::fs::rename(project.join(".agent-workspace"), &legacy_backup)
                .context("failed to archive the legacy full AgentWorkspace")?;
        }
        for directory in [
            ".agent-workspace",
            ".generated/byo",
            ".codex/skills/byo-firmware",
            ".claude/skills/byo-firmware",
        ] {
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

        let managed_files = vec![
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
        let inventory_bytes = serde_json::to_vec(&managed_files)?;
        let projection = ProjectionManifest {
            schema: 2,
            managed_files,
            agents_block_sha256: sha256_bytes(block.as_bytes()),
            codex_server_sha256: codex_hash,
            codex_hooks_sha256: codex_hooks_hash,
            claude_block_sha256: Some(sha256_bytes(block.as_bytes())),
            claude_server_sha256: Some(claude_server_hash),
            claude_hooks_sha256: Some(claude_hooks_hash),
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
    registry.insert(
        capsule.project_id.clone(),
        project
            .to_str()
            .context("project path is not valid Unicode")?
            .to_string(),
    );
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
    let agents = std::fs::read_to_string(project.join("AGENTS.md"))
        .context("AGENTS.md managed projection is missing")?;
    verify_managed_block(
        &agents,
        "AGENTS.md",
        projection.agents_block_sha256.as_str(),
    )?;
    let codex = std::fs::read_to_string(project.join(".codex/config.toml"))
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
        &std::fs::read(project.join(".codex/hooks.json"))
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
        let claude = std::fs::read_to_string(project.join("CLAUDE.md"))
            .context("CLAUDE.md managed projection is missing")?;
        verify_managed_block(&claude, "CLAUDE.md", claude_block_hash)?;

        let mcp: serde_json::Value = serde_json::from_slice(
            &std::fs::read(project.join(".mcp.json"))
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
            &std::fs::read(project.join(".claude/settings.json"))
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

pub fn uninstall_project(project: &Path, paths: &ProductPaths) -> Result<Vec<String>> {
    let capsule = read_capsule(project)?.context("project capsule is not installed")?;
    let projection = read_projection(project)?.context("projection manifest is missing")?;
    validate_owned_files(project, &projection)?;
    for managed in &projection.managed_files {
        let target = project.join(&managed.path);
        if target.is_file() {
            std::fs::remove_file(target)?;
        }
    }
    let agents_path = project.join("AGENTS.md");
    if agents_path.exists() {
        let original = std::fs::read_to_string(&agents_path)?;
        atomic_text(&agents_path, &remove_managed_block(&original)?)?;
    }
    let claude_path = project.join("CLAUDE.md");
    if projection.claude_block_sha256.is_some() && claude_path.exists() {
        let original = std::fs::read_to_string(&claude_path)?;
        atomic_text(&claude_path, &remove_managed_block(&original)?)?;
    }
    let codex_path = project.join(".codex/config.toml");
    if codex_path.exists() {
        let original = std::fs::read_to_string(&codex_path)?;
        atomic_text(&codex_path, &remove_codex_config(&original)?)?;
    }
    let hooks_path = project.join(".codex/hooks.json");
    if hooks_path.exists() {
        let original = std::fs::read_to_string(&hooks_path)?;
        atomic_text(
            &hooks_path,
            &remove_hook_configuration(&original, ".codex/hooks.json")?,
        )?;
    }
    let claude_mcp_path = project.join(".mcp.json");
    if projection.claude_server_sha256.is_some() && claude_mcp_path.exists() {
        let original = std::fs::read_to_string(&claude_mcp_path)?;
        atomic_text(&claude_mcp_path, &remove_claude_mcp(&original)?)?;
    }
    let claude_settings_path = project.join(".claude/settings.json");
    if projection.claude_hooks_sha256.is_some() && claude_settings_path.exists() {
        let original = std::fs::read_to_string(&claude_settings_path)?;
        atomic_text(
            &claude_settings_path,
            &remove_hook_configuration(&original, ".claude/settings.json")?,
        )?;
    }
    for relative in [
        ".generated/byo/projection-manifest.json",
        ".agent-workspace/manifest.json",
    ] {
        let target = project.join(relative);
        if target.is_file() {
            std::fs::remove_file(target)?;
        }
    }
    let registry_path = paths.state.join("projects.json");
    if registry_path.exists() {
        let mut registry: BTreeMap<String, String> =
            serde_json::from_slice(&std::fs::read(&registry_path)?)?;
        registry.remove(&capsule.project_id);
        write_json(&registry_path, &registry)?;
    }
    Ok([
        ".agent-workspace/PLAN.md",
        ".agent-workspace/HANDOFF.md",
        ".agent-workspace/specs/",
        ".firm/",
        ".agent-backups/",
    ]
    .into_iter()
    .map(str::to_string)
    .collect())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        remove_claude_mcp, remove_hook_configuration, render_claude_mcp, render_codex_config,
        render_hook_configuration,
    };

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
