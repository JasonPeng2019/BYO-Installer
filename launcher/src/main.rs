mod cli;
mod error;
mod install;
mod lease;
mod manifest;
mod pack;
mod paths;
mod project;
mod update;
mod workflow;

use std::env;
use std::process::{Command as ProcessCommand, ExitCode, Stdio};

use anyhow::{bail, Context, Result};
use clap::Parser;
use cli::{
    Cli, Command, InternalCommand, McpCommand, ProjectArg, WorkflowCommand, WorkspaceCommand,
};
use error::{categorize, ExitCategory};
use paths::ProductPaths;
use serde::Serialize;

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
        .stderr(Stdio::inherit())
        .env_clear();
    for name in [
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
    ] {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
    command.env("BYO_SIDECAR_COMPILED", "1");
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
    helper.env_clear();
    for name in [
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
    ] {
        if let Some(value) = env::var_os(name) {
            helper.env(name, value);
        }
    }
    helper.env("BYO_SIDECAR_COMPILED", "1");
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
    let paths = categorize(ProductPaths::resolve(), ExitCategory::RuntimeMissing)?;
    match cli.command {
        Command::Paths => {
            println!("{}", serde_json::to_string_pretty(&paths)?);
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
                project::init_project(&project, &arguments.mode, arguments.dry_run, false, &paths),
                ExitCategory::CapsuleConflict,
            )?;
            println!("{}", serde_json::to_string_pretty(&preview)?);
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
            if arguments.global {
                if arguments.purge_data && !arguments.yes {
                    return Err(error::fail(
                        ExitCategory::Uninstall,
                        "--purge-data requires --yes and an explicit target preview",
                    ));
                }
                let removed = categorize(
                    install::uninstall_global(&paths, arguments.purge_data),
                    ExitCategory::Uninstall,
                )?;
                for path in removed {
                    println!("Removed {}", path.display());
                }
            } else {
                let project = categorize(
                    project::canonical_project(arguments.project.as_deref(), &paths),
                    ExitCategory::ProjectRoot,
                )?;
                let preserved = categorize(
                    project::uninstall_project(&project, &paths),
                    ExitCategory::Uninstall,
                )?;
                println!("Removed BYO project integration. Preserved:");
                for relative in preserved {
                    println!("  {}", project.join(relative).display());
                }
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
            if !env::var_os("PATH")
                .map(|value| env::split_paths(&value).any(|entry| entry == paths.bin))
                .unwrap_or(false)
            {
                eprintln!(
                    "PATH note: add {} to PATH in your shell profile.",
                    paths.bin.display()
                );
            }
        }
        Command::Internal(arguments) => return run_helper(arguments.command, &paths),
    }
    Ok(0)
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
