mod cli;
mod error;
mod install;
mod lease;
mod manifest;
mod pack;
mod path_setup;
mod paths;
mod project;
mod update;
mod workflow;

use std::env;
use std::process::{Command as ProcessCommand, ExitCode, Stdio};

use anyhow::{bail, Context, Result};
use clap::Parser;
use cli::{
    AgentLaunchArgs, Cli, Command, InternalCommand, McpCommand, ProjectArg, WorkflowCommand,
    WorkspaceCommand,
};
use error::{categorize, ExitCategory};
use pack::CompiledMode;
use paths::ProductPaths;
use serde::Serialize;

const SIDECAR_ENVIRONMENT: &[&str] = &[
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "PATH",
    "SystemRoot",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
];

#[derive(Serialize)]
struct Check {
    id: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remedy: Option<String>,
}

fn global_doctor(paths: &ProductPaths) -> Result<Vec<Check>> {
    let (_, runtime) = manifest::load_current(paths)?;
    let release = manifest::verify_runtime(&runtime)?;
    install::sidecar_self_test(&runtime)?;
    let pack = pack::WorkspacePack::load(&runtime.join("workflow/workspace.pack"))?;
    if pack.version().is_empty() {
        bail!("workspace pack version is empty");
    }
    let launcher = paths.public_launcher();
    if !launcher.is_file() {
        bail!("public BYO launcher is missing");
    }
    let declared = release
        .files
        .iter()
        .find(|file| file.kind == "launcher")
        .context("release manifest has no launcher")?;
    if manifest::sha256_file(&launcher)? != declared.sha256 {
        bail!("public BYO launcher does not match the active runtime");
    }
    paths.verify_install_locator()?;
    let leases = lease::inspect(paths, true)?;
    let live_lease_count = leases.iter().filter(|status| status.live).count();
    let stale_lease_count = leases.len() - live_lease_count;
    Ok(vec![
        Check {
            id: "runtime.manifest.integrity".to_string(),
            status: "passed".to_string(),
            code: None,
            remedy: None,
        },
        Check {
            id: "runtime.sidecar.self-test".to_string(),
            status: "passed".to_string(),
            code: None,
            remedy: None,
        },
        Check {
            id: if release.development_unsigned {
                "runtime.signature.development-unsigned"
            } else {
                "runtime.signature"
            }
            .to_string(),
            status: if release.development_unsigned {
                "warning"
            } else {
                "passed"
            }
            .to_string(),
            code: None,
            remedy: if release.development_unsigned {
                Some("Use a signed and notarized production build for distribution.".to_string())
            } else {
                None
            },
        },
        Check {
            id: "runtime.leases".to_string(),
            status: if stale_lease_count == 0 {
                "passed".to_string()
            } else {
                "warning".to_string()
            },
            code: (stale_lease_count != 0).then(|| "STALE_LEASES_REMOVED".to_string()),
            remedy: (stale_lease_count != 0).then(|| {
                format!("{stale_lease_count} stale lease(s) were removed; {live_lease_count} live")
            }),
        },
    ])
}

#[derive(Clone, Copy)]
enum AgentClient {
    Codex,
    Claude,
}

impl AgentClient {
    fn program(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
        }
    }
}

fn has_option(arguments: &[String], long: &str, short: Option<&str>) -> bool {
    arguments.iter().any(|argument| {
        argument == long
            || argument.starts_with(&format!("{long}="))
            || short.is_some_and(|short| argument == short)
    })
}

fn client_arguments(
    client: AgentClient,
    project: &std::path::Path,
    mode: &CompiledMode,
    arguments: &[String],
) -> Vec<String> {
    let mut rendered = Vec::new();
    match client {
        AgentClient::Codex => {
            if !has_option(arguments, "--sandbox", Some("-s")) {
                rendered.extend([
                    "--sandbox".to_string(),
                    mode.codex
                        .sandbox_mode
                        .clone()
                        .unwrap_or_else(|| "workspace-write".to_string()),
                ]);
            }
            if !has_option(arguments, "--cd", Some("-C")) {
                rendered.extend(["--cd".to_string(), project.display().to_string()]);
            }
            if !has_option(arguments, "--ask-for-approval", Some("-a"))
                && !arguments
                    .iter()
                    .any(|argument| argument == "--dangerously-bypass-approvals-and-sandbox")
            {
                rendered.extend([
                    "--ask-for-approval".to_string(),
                    mode.codex.approval_policy.clone(),
                ]);
            }
            match mode.codex.web_search.as_str() {
                "live" if !arguments.iter().any(|argument| argument == "--search") => {
                    rendered.push("--search".to_string());
                }
                "cached" | "off" => {
                    let value = if mode.codex.web_search == "cached" {
                        "\"cached\""
                    } else {
                        "false"
                    };
                    rendered.extend(["--config".to_string(), format!("web_search={value}")]);
                }
                _ => {}
            }
        }
        AgentClient::Claude => {
            if mode.full_access
                && !has_option(arguments, "--permission-mode", None)
                && !arguments
                    .iter()
                    .any(|argument| argument == "--dangerously-skip-permissions")
            {
                rendered.extend([
                    "--permission-mode".to_string(),
                    "bypassPermissions".to_string(),
                ]);
            }
        }
    }
    rendered.extend_from_slice(arguments);
    rendered
}

fn launch_agent(
    client: AgentClient,
    arguments: &AgentLaunchArgs,
    paths: &ProductPaths,
) -> Result<i32> {
    let selected_project = categorize(
        project::canonical_project(arguments.project.as_deref(), paths),
        ExitCategory::ProjectRoot,
    )?;
    categorize(
        project::init_project(
            &selected_project,
            &arguments.mode,
            false,
            arguments.allow_full_access,
            paths,
        ),
        ExitCategory::CapsuleConflict,
    )?;
    let runtime = project::active_runtime(paths)?;
    let mode = runtime.pack.mode(&arguments.mode)?;
    let rendered_arguments =
        client_arguments(client, &selected_project, &mode, &arguments.arguments);
    let mut command = ProcessCommand::new(client.program());
    command
        .args(rendered_arguments)
        .current_dir(&selected_project)
        .env("AGENT_WORKSPACE_MODE", &mode.name)
        .env("AGENT_WORKSPACE_AGENT", client.program())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let status = command.status().map_err(|error| {
        error::fail(
            ExitCategory::ClientLaunch,
            format!(
                "failed to launch {} from {}: {error}",
                client.program(),
                selected_project.display()
            ),
        )
    })?;
    Ok(status
        .code()
        .unwrap_or(ExitCategory::ClientLaunch as i32)
        .clamp(0, 255))
}

fn print_doctor(checks: &[Check], json: bool) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema": 1,
                "status": "passed",
                "checks": checks
            }))?
        );
    } else {
        for check in checks {
            println!("{:<48} {}", check.id, check.status);
        }
    }
    Ok(())
}

/// Run the same global + project checks as `byo doctor` and reduce them to one
/// line for the end of `byo init`.
fn init_health_summary(project: &std::path::Path, paths: &ProductPaths) -> Result<String> {
    let mut checks = global_doctor(paths)?;
    project::doctor_project(project, paths)?;
    checks.push(Check {
        id: "project.capsule".to_string(),
        status: "passed".to_string(),
        code: None,
        remedy: None,
    });
    let warnings = checks
        .iter()
        .filter(|check| check.status == "warning")
        .count();
    let passed = checks
        .iter()
        .filter(|check| check.status == "passed")
        .count();
    Ok(if warnings == 0 {
        format!("Health check: OK ({passed} checks passed)")
    } else {
        format!(
            "Health check: {passed} passed, {warnings} warning(s) — run `byo doctor` for details"
        )
    })
}

fn apply_sidecar_environment(command: &mut ProcessCommand) {
    command.env_clear();
    for name in SIDECAR_ENVIRONMENT {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
    command.env("BYO_SIDECAR_COMPILED", "1");
}

fn serve_mcp(argument: &ProjectArg, paths: &ProductPaths) -> Result<i32> {
    let project = categorize(
        project::canonical_project(argument.project.as_deref(), paths),
        ExitCategory::ProjectRoot,
    )?;
    categorize(
        project::doctor_project(&project, paths),
        ExitCategory::Doctor,
    )?;
    let runtime = project::active_runtime(paths)?;
    let project_id = project::project_id(&project)?;
    let _lease = lease::RuntimeLeaseGuard::acquire(paths, &runtime.release.version, &project_id)?;
    let sidecar = install::sidecar_path(&runtime.root);
    let mut command = ProcessCommand::new(&sidecar);
    command
        .arg("serve")
        .arg("--project-root")
        .arg(&project)
        .arg("--runtime-root")
        .arg(&runtime.root)
        .arg("--launcher-version")
        .arg(env!("CARGO_PKG_VERSION"))
        .arg("--workflow-protocol")
        .arg(runtime.release.workflow_protocol.to_string())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    apply_sidecar_environment(&mut command);
    let status = command
        .status()
        .with_context(|| format!("failed to launch private sidecar {}", sidecar.display()))
        .map_err(|error| {
            error::fail(
                ExitCategory::SidecarLaunch,
                format!("failed to launch private sidecar: {error:#}"),
            )
        })?;
    Ok(if status.success() {
        0
    } else {
        ExitCategory::SidecarLaunch as i32
    })
}

fn run_helper(command: InternalCommand, paths: &ProductPaths) -> Result<i32> {
    let selected_project = categorize(
        project::canonical_project(None, paths),
        ExitCategory::ProjectRoot,
    )?;
    categorize(
        project::doctor_project(&selected_project, paths),
        ExitCategory::Doctor,
    )?;
    let runtime = project::active_runtime(paths)?;
    let sidecar = install::sidecar_path(&runtime.root);
    let (name, arguments) = match command {
        InternalCommand::NativeBuild { arguments } => ("native-build", arguments),
        InternalCommand::CollectArtifacts { arguments } => ("collect-artifacts", arguments),
        InternalCommand::PackRepair { arguments } => ("pack-repair", arguments),
    };
    let mut helper = ProcessCommand::new(sidecar);
    helper
        .arg(name)
        .arg("--project-root")
        .arg(&selected_project)
        .arg("--runtime-root")
        .arg(&runtime.root)
        .arg("--launcher-version")
        .arg(env!("CARGO_PKG_VERSION"))
        .arg("--workflow-protocol")
        .arg(runtime.release.workflow_protocol.to_string())
        .arg("--")
        .args(arguments)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    apply_sidecar_environment(&mut helper);
    let status = helper.status().map_err(|error| {
        error::fail(
            ExitCategory::SidecarLaunch,
            format!("failed to launch sidecar helper: {error}"),
        )
    })?;
    Ok(if status.success() {
        0
    } else {
        ExitCategory::SidecarLaunch as i32
    })
}

fn run() -> Result<i32> {
    let cli = Cli::parse();
    let paths = categorize(
        match &cli.command {
            Command::InstallRuntime(arguments) => arguments
                .install_dir
                .as_deref()
                .map(ProductPaths::from_install_dir)
                .transpose()?
                .map_or_else(ProductPaths::resolve, Ok),
            _ => ProductPaths::resolve(),
        },
        ExitCategory::RuntimeMissing,
    )?;
    match cli.command {
        Command::Paths => {
            println!("{}", serde_json::to_string_pretty(&paths)?);
        }
        Command::Modes => {
            let runtime = project::active_runtime(&paths)?;
            let modes: Vec<_> = runtime
                .pack
                .workflow_catalog()?
                .modes
                .into_iter()
                .map(|mode| {
                    serde_json::json!({
                        "name": mode.name,
                        "family": mode.family,
                        "full_access": mode.full_access,
                        "codex": true,
                        "claude": true
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({ "modes": modes }))?
            );
        }
        Command::Status(argument) => {
            let (_, runtime) =
                categorize(manifest::load_current(&paths), ExitCategory::RuntimeMissing)?;
            let release = categorize(
                manifest::verify_runtime(&runtime),
                ExitCategory::RuntimeIntegrity,
            )?;
            let project_status = argument
                .project
                .as_deref()
                .map(|raw| {
                    let project = categorize(
                        project::canonical_project(Some(raw), &paths),
                        ExitCategory::ProjectRoot,
                    )?;
                    categorize(
                        project::doctor_project(&project, &paths),
                        ExitCategory::Doctor,
                    )?;
                    Ok::<_, anyhow::Error>(project.display().to_string())
                })
                .transpose()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "runtime_version": release.version,
                    "runtime_root": runtime,
                    "project": project_status,
                    "development_unsigned": release.development_unsigned
                }))?
            );
        }
        Command::Init(arguments) => {
            let project = categorize(
                project::canonical_project(arguments.project.as_deref(), &paths),
                ExitCategory::ProjectRoot,
            )?;
            let preview = categorize(
                project::init_project(
                    &project,
                    &arguments.mode,
                    arguments.dry_run,
                    arguments.allow_full_access,
                    &paths,
                ),
                ExitCategory::CapsuleConflict,
            )?;
            println!("{}", serde_json::to_string_pretty(&preview)?);
            if !arguments.dry_run {
                // Fold `byo doctor` into init: report health as one line so the
                // documented flow is just install → `byo init`. Non-fatal — a
                // health problem is surfaced, not a reason to fail the capsule
                // that was just written.
                match init_health_summary(&project, &paths) {
                    Ok(summary) => println!("{summary}"),
                    Err(error) => println!(
                        "Health check: could not complete ({error:#}); run `byo doctor` for details"
                    ),
                }
                if arguments.modify_path {
                    match categorize(path_setup::add_bin_to_path(&paths), ExitCategory::Installer)?
                    {
                        path_setup::PathSetupOutcome::AlreadyPresent => {
                            println!("PATH already includes {}", paths.bin.display());
                        }
                        path_setup::PathSetupOutcome::Configured { target } => {
                            println!(
                                "Added {} to PATH in {target}; open a new shell to use `byo`.",
                                paths.bin.display()
                            );
                        }
                    }
                }
            }
        }
        Command::Doctor(arguments) => {
            let mut checks = categorize(global_doctor(&paths), ExitCategory::Doctor)?;
            if !arguments.global {
                let selected = categorize(
                    project::canonical_project(arguments.project.as_deref(), &paths),
                    ExitCategory::ProjectRoot,
                )?;
                if arguments.project.is_some()
                    || selected.join(".agent-workspace/manifest.json").exists()
                {
                    categorize(
                        project::doctor_project(&selected, &paths),
                        ExitCategory::Doctor,
                    )?;
                    checks.push(Check {
                        id: "project.capsule".to_string(),
                        status: "passed".to_string(),
                        code: None,
                        remedy: None,
                    });
                }
            }
            print_doctor(&checks, arguments.json)?;
        }
        Command::Mode(arguments) => {
            let project = categorize(
                project::canonical_project(arguments.project.as_deref(), &paths),
                ExitCategory::ProjectRoot,
            )?;
            categorize(
                project::init_project(
                    &project,
                    &arguments.mode,
                    false,
                    arguments.allow_full_access,
                    &paths,
                ),
                ExitCategory::CapsuleConflict,
            )?;
            println!(
                "BYO mode set to {} for {}",
                arguments.mode,
                project.display()
            );
        }
        Command::Codex(arguments) => return launch_agent(AgentClient::Codex, &arguments, &paths),
        Command::Claude(arguments) => return launch_agent(AgentClient::Claude, &arguments, &paths),
        Command::Mcp(arguments) => match arguments.command {
            McpCommand::Serve(project) => return serve_mcp(&project, &paths),
        },
        Command::Hook(arguments) => {
            let project = categorize(
                project::canonical_project(arguments.project.as_deref(), &paths),
                ExitCategory::ProjectRoot,
            )?;
            return categorize(
                workflow::run_hook(&project, &arguments.hook_name, &paths),
                ExitCategory::WorkflowPolicy,
            );
        }
        Command::Workflow(arguments) => match arguments.command {
            WorkflowCommand::Guidance(arguments) => {
                let project = categorize(
                    project::canonical_project(arguments.project.as_deref(), &paths),
                    ExitCategory::ProjectRoot,
                )?;
                categorize(
                    workflow::print_guidance(&project, &arguments.id, &paths),
                    ExitCategory::WorkflowPolicy,
                )?;
            }
            WorkflowCommand::Agent(arguments) => {
                let project = categorize(
                    project::canonical_project(arguments.project.as_deref(), &paths),
                    ExitCategory::ProjectRoot,
                )?;
                categorize(
                    workflow::print_agent(&project, &arguments.id, &paths),
                    ExitCategory::WorkflowPolicy,
                )?;
            }
            WorkflowCommand::Tool(arguments) => {
                let project = categorize(
                    project::canonical_project(arguments.project.as_deref(), &paths),
                    ExitCategory::ProjectRoot,
                )?;
                return categorize(
                    workflow::run_tool(&project, &arguments.name, &arguments.arguments, &paths),
                    ExitCategory::WorkflowPolicy,
                );
            }
        },
        Command::Workspace(arguments) => match arguments.command {
            WorkspaceCommand::Update(project_arg) => {
                let project = categorize(
                    project::canonical_project(project_arg.project.as_deref(), &paths),
                    ExitCategory::ProjectRoot,
                )?;
                let capsule: serde_json::Value = serde_json::from_slice(&std::fs::read(
                    project.join(".agent-workspace/manifest.json"),
                )?)?;
                let project_id = capsule["project_id"]
                    .as_str()
                    .context("project capsule has no project_id")?;
                categorize(
                    lease::ensure_project_inactive(&paths, project_id),
                    ExitCategory::CapsuleConflict,
                )?;
                let mode = capsule["mode"].as_str().unwrap_or("firmware");
                if let Some(requested) = project_arg.version.as_deref() {
                    let runtime = project::active_runtime(&paths)?;
                    if runtime.pack.version() != requested {
                        return Err(error::fail(
                            ExitCategory::Incompatible,
                            format!(
                                "requested workspace {requested} is not available; active workspace is {}",
                                runtime.pack.version()
                            ),
                        ));
                    }
                }
                categorize(
                    project::init_project(
                        &project,
                        mode,
                        false,
                        project_arg.allow_full_access,
                        &paths,
                    ),
                    ExitCategory::CapsuleConflict,
                )?;
                println!("BYO workspace updated for {}", project.display());
            }
        },
        Command::Update(arguments) => {
            let previous = manifest::load_current(&paths)
                .ok()
                .map(|(_, runtime)| runtime);
            let outcome = categorize(update::perform(&arguments, &paths), ExitCategory::Update)?;
            if !arguments.dry_run {
                if let Err(doctor_error) = global_doctor(&paths) {
                    if let Some(previous) = previous.as_deref() {
                        if let Err(rollback_error) = install::repair(&paths, Some(previous)) {
                            return Err(error::fail(
                                ExitCategory::UpdateRolledBack,
                                format!(
                                    "updated runtime failed doctor ({doctor_error:#}); rollback also failed: {rollback_error:#}"
                                ),
                            ));
                        }
                    }
                    return Err(error::fail(
                        ExitCategory::UpdateRolledBack,
                        format!(
                            "updated runtime failed doctor and the previous runtime was restored: {doctor_error:#}"
                        ),
                    ));
                }
            }
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        }
        Command::Rollback(arguments) => {
            let selected = categorize(
                update::rollback(&paths, arguments.version.as_deref()),
                ExitCategory::UpdateRolledBack,
            )?;
            categorize(global_doctor(&paths), ExitCategory::Doctor)?;
            println!("BYO runtime rolled back to {}", selected.display());
        }
        Command::Repair(arguments) => {
            let repaired = categorize(
                install::repair(&paths, arguments.runtime.as_deref()),
                ExitCategory::RuntimeIntegrity,
            )?;
            categorize(global_doctor(&paths), ExitCategory::Doctor)?;
            if let Some(raw_project) = arguments.project.as_deref() {
                let project = project::canonical_project(Some(raw_project), &paths)?;
                categorize(
                    project::doctor_project(&project, &paths),
                    ExitCategory::Doctor,
                )?;
            }
            println!("BYO runtime repaired: {}", repaired.display());
        }
        Command::Uninstall(arguments) => {
            let receipt = if arguments.global {
                if arguments.purge_data && !arguments.yes {
                    // Show the operator exactly what a purge would delete, then
                    // refuse until they confirm with --yes. This is the explicit
                    // target preview the refusal message refers to.
                    let targets = install::purge_targets(&paths);
                    eprintln!("--purge-data would permanently remove these BYO roots:");
                    if targets.is_empty() {
                        eprintln!("  (nothing — no BYO installation detected)");
                    } else {
                        for target in &targets {
                            eprintln!("  {}", target.display());
                        }
                    }
                    return Err(error::fail(
                        ExitCategory::Uninstall,
                        "--purge-data requires --yes to confirm the wipe shown above",
                    ));
                }
                // Reverse only the PATH edits BYO itself recorded, before the
                // state directory (which holds the record) is touched.
                let reverted = categorize(
                    path_setup::revert_recorded_edits(&paths),
                    ExitCategory::Uninstall,
                )?;
                let removed = categorize(
                    install::uninstall_global(&paths, arguments.purge_data),
                    ExitCategory::Uninstall,
                )?;
                let preserved = if arguments.purge_data {
                    Vec::new()
                } else {
                    install::remaining_data_roots(&paths)
                };
                UninstallReceipt {
                    scope: "global",
                    purge: arguments.purge_data,
                    note: None,
                    removed,
                    preserved,
                    reverted,
                }
            } else {
                let project = categorize(
                    project::canonical_project(arguments.project.as_deref(), &paths),
                    ExitCategory::ProjectRoot,
                )?;
                let preserved = categorize(
                    project::uninstall_project(&project, &paths),
                    ExitCategory::Uninstall,
                )?
                .into_iter()
                .map(|relative| project.join(relative))
                .collect();
                UninstallReceipt {
                    scope: "project",
                    purge: false,
                    note: Some(
                        "removed BYO-managed integration blocks in place; the listed \
                         paths were preserved"
                            .to_string(),
                    ),
                    removed: Vec::new(),
                    preserved,
                    reverted: Vec::new(),
                }
            };
            receipt.print();
            if let Some(path) = arguments.receipt.as_deref() {
                categorize(receipt.write_json(path), ExitCategory::Uninstall)?;
                println!("Receipt written to {}", path.display());
            }
        }
        Command::InstallRuntime(arguments) => {
            let manifest = categorize(
                install::install_bundle(&arguments.bundle, &paths),
                ExitCategory::Installer,
            )?;
            categorize(global_doctor(&paths), ExitCategory::Doctor)?;
            println!(
                "Installed BYO {} at {}",
                manifest.version,
                paths.public_launcher().display()
            );
            if arguments.modify_path {
                // Route the edit through the same recorded mechanism as
                // `byo init --modify-path`, so `uninstall --global` reverses
                // exactly this entry and nothing else.
                match categorize(path_setup::add_bin_to_path(&paths), ExitCategory::Installer)? {
                    path_setup::PathSetupOutcome::AlreadyPresent => {
                        println!("PATH already includes {}", paths.bin.display());
                    }
                    path_setup::PathSetupOutcome::Configured { target } => {
                        println!(
                            "Added {} to PATH in {target}; open a new shell to use `byo`.",
                            paths.bin.display()
                        );
                    }
                }
            } else if !env::var_os("PATH")
                .map(|value| env::split_paths(&value).any(|entry| entry == paths.bin))
                .unwrap_or(false)
            {
                eprintln!(
                    "PATH note: add {} to PATH in your shell profile, or re-run install with --modify-path.",
                    paths.bin.display()
                );
            }
        }
        Command::Internal(arguments) => return run_helper(arguments.command, &paths),
    }
    Ok(0)
}

/// A record of exactly what an `uninstall` removed and what it preserved. Printed
/// as a human-readable receipt, and — with `--receipt <path>` — also written as
/// JSON for automation and audit.
#[derive(Serialize)]
struct UninstallReceipt {
    scope: &'static str,
    purge: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    removed: Vec<std::path::PathBuf>,
    preserved: Vec<std::path::PathBuf>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    reverted: Vec<String>,
}

impl UninstallReceipt {
    fn print(&self) {
        let mode = if self.purge { " --purge-data" } else { "" };
        println!("BYO uninstall receipt (scope: {}{})", self.scope, mode);
        if let Some(note) = &self.note {
            println!("Note: {note}");
        }
        Self::print_section("Removed", &self.removed);
        Self::print_section("Preserved", &self.preserved);
        if !self.reverted.is_empty() {
            println!("Reverted PATH edits ({}):", self.reverted.len());
            for target in &self.reverted {
                println!("  {target}");
            }
        }
    }

    fn print_section(label: &str, paths: &[std::path::PathBuf]) {
        if paths.is_empty() {
            println!("{label} (0): none");
        } else {
            println!("{label} ({}):", paths.len());
            for path in paths {
                println!("  {}", path.display());
            }
        }
    }

    fn write_json(&self, path: &std::path::Path) -> Result<()> {
        let mut json =
            serde_json::to_vec_pretty(self).context("failed to serialize uninstall receipt")?;
        json.push(b'\n');
        std::fs::write(path, json)
            .with_context(|| format!("failed to write uninstall receipt to {}", path.display()))?;
        Ok(())
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(error) => {
            eprintln!("BYO error: {error:#}");
            ExitCode::from(error::exit_code(&error).unwrap_or(ExitCategory::Internal as u8))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{client_arguments, AgentClient, SIDECAR_ENVIRONMENT};
    use crate::pack::{
        CompiledCodex, CompiledMode, CompiledStructure, CompiledVerify, CompiledWorkflow,
    };

    #[test]
    fn sidecar_environment_preserves_windows_profile_resolution() {
        for required in [
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
            "APPDATA",
            "LOCALAPPDATA",
            "PROGRAMDATA",
        ] {
            assert!(SIDECAR_ENVIRONMENT.contains(&required));
        }
    }

    fn mode(name: &str, full_access: bool) -> CompiledMode {
        CompiledMode {
            name: name.to_string(),
            family: name.trim_end_matches("-full").to_string(),
            extends: Vec::new(),
            full_access,
            skills: Vec::new(),
            instruction_resources: Vec::new(),
            verify: CompiledVerify {
                backend: "software".to_string(),
                required_tools: Vec::new(),
            },
            codex: CompiledCodex {
                permission_profile: "workspace-access".to_string(),
                sandbox_mode: full_access.then(|| "danger-full-access".to_string()),
                approval_policy: if full_access { "never" } else { "on-request" }.to_string(),
                web_search: if name.starts_with("research") {
                    "live"
                } else {
                    "cached"
                }
                .to_string(),
            },
            workflow: CompiledWorkflow {
                one_way_doors: Vec::new(),
                adversarial_triggers: Vec::new(),
            },
            structure: CompiledStructure {
                version: 1,
                default_visibility: "shared".to_string(),
                required_dirs: Vec::new(),
                required_files: Vec::new(),
                forbidden_paths: Vec::new(),
            },
        }
    }

    #[test]
    fn codex_launch_uses_project_and_selected_sandbox_without_overriding_user_flags() {
        let project = Path::new("/tmp/project with spaces");
        assert_eq!(
            client_arguments(AgentClient::Codex, project, &mode("research", false), &[]),
            [
                "--sandbox",
                "workspace-write",
                "--cd",
                "/tmp/project with spaces",
                "--ask-for-approval",
                "on-request",
                "--search"
            ]
        );
        assert_eq!(
            client_arguments(
                AgentClient::Codex,
                project,
                &mode("research-full", true),
                &["--sandbox=read-only".to_string()]
            ),
            [
                "--cd",
                "/tmp/project with spaces",
                "--ask-for-approval",
                "never",
                "--search",
                "--sandbox=read-only"
            ]
        );
    }

    #[test]
    fn claude_full_launch_uses_bypass_only_for_an_explicit_full_mode() {
        assert_eq!(
            client_arguments(
                AgentClient::Claude,
                Path::new("/tmp/project"),
                &mode("research-full", true),
                &[]
            ),
            ["--permission-mode", "bypassPermissions"]
        );
        assert!(client_arguments(
            AgentClient::Claude,
            Path::new("/tmp/project"),
            &mode("research", false),
            &[]
        )
        .is_empty());
    }
}
