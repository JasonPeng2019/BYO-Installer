use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "byo",
    version,
    about = "BYO firmware workspace and MCP runtime"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Paths,
    Modes,
    Status(ProjectArg),
    Init(InitArgs),
    Doctor(DoctorArgs),
    Mode(ModeArgs),
    Codex(AgentLaunchArgs),
    Claude(AgentLaunchArgs),
    Mcp(McpArgs),
    Hook(HookArgs),
    Workflow(WorkflowArgs),
    Workspace(WorkspaceArgs),
    Update(UpdateArgs),
    Rollback(RollbackArgs),
    Repair(RepairArgs),
    Uninstall(UninstallArgs),
    #[command(name = "install-runtime", hide = true)]
    InstallRuntime(InstallRuntimeArgs),
    #[command(hide = true)]
    Internal(InternalArgs),
}

#[derive(Debug, Args)]
pub struct ProjectArg {
    #[arg(long)]
    pub project: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    #[arg(long)]
    pub project: Option<PathBuf>,
    #[arg(long, default_value = "firmware")]
    pub mode: String,
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long)]
    pub yes: bool,
    #[arg(long)]
    pub allow_full_access: bool,
    /// Opt in to putting the BYO bin directory on PATH, recorded so uninstall
    /// can reverse exactly what was added.
    #[arg(long)]
    pub modify_path: bool,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    #[arg(long)]
    pub project: Option<PathBuf>,
    #[arg(long)]
    pub global: bool,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ModeArgs {
    pub mode: String,
    #[arg(long)]
    pub project: Option<PathBuf>,
    #[arg(long)]
    pub allow_full_access: bool,
}

#[derive(Debug, Args)]
pub struct AgentLaunchArgs {
    pub mode: String,
    #[arg(long)]
    pub project: Option<PathBuf>,
    #[arg(long)]
    pub allow_full_access: bool,
    #[arg(last = true, allow_hyphen_values = true)]
    pub arguments: Vec<String>,
}

#[derive(Debug, Args)]
pub struct McpArgs {
    #[command(subcommand)]
    pub command: McpCommand,
}

#[derive(Debug, Subcommand)]
pub enum McpCommand {
    Serve(ProjectArg),
}

#[derive(Debug, Args)]
pub struct WorkspaceArgs {
    #[command(subcommand)]
    pub command: WorkspaceCommand,
}

#[derive(Debug, Subcommand)]
pub enum WorkspaceCommand {
    Update(WorkspaceUpdateArgs),
}

#[derive(Debug, Args)]
pub struct WorkspaceUpdateArgs {
    #[arg(long)]
    pub project: Option<PathBuf>,
    #[arg(long)]
    pub version: Option<String>,
    #[arg(long)]
    pub allow_full_access: bool,
}

#[derive(Debug, Args)]
pub struct HookArgs {
    pub hook_name: String,
    #[arg(long)]
    pub project: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct WorkflowArgs {
    #[command(subcommand)]
    pub command: WorkflowCommand,
}

#[derive(Debug, Subcommand)]
pub enum WorkflowCommand {
    Guidance(WorkflowResourceArgs),
    Agent(WorkflowResourceArgs),
    Tool(WorkflowToolArgs),
}

#[derive(Debug, Args)]
pub struct WorkflowResourceArgs {
    pub id: String,
    #[arg(long)]
    pub project: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct WorkflowToolArgs {
    pub name: String,
    #[arg(long)]
    pub project: Option<PathBuf>,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub arguments: Vec<String>,
}

#[derive(Debug, Args)]
pub struct UpdateArgs {
    #[arg(long)]
    pub version: Option<String>,
    #[arg(long, default_value = "stable")]
    pub channel: String,
    #[arg(long)]
    pub metadata_url: Option<String>,
    #[arg(long, hide = true)]
    pub metadata_file: Option<PathBuf>,
    #[arg(long)]
    pub dry_run: bool,
    /// After the atomic install succeeds, clear BYO's download cache and install
    /// staging so the update feels like a fresh install. This is never a
    /// destructive pre-uninstall: prior versions (kept for `byo rollback`) and
    /// every project's `.firm`/PLAN/HANDOFF data are always preserved.
    #[arg(long)]
    pub clean: bool,
}

#[derive(Debug, Args)]
pub struct RollbackArgs {
    #[arg(long)]
    pub version: Option<String>,
}

#[derive(Debug, Args)]
pub struct RepairArgs {
    #[arg(long)]
    pub project: Option<PathBuf>,
    #[arg(long)]
    pub runtime: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct UninstallArgs {
    #[arg(long, conflicts_with = "global")]
    pub project: Option<PathBuf>,
    /// Remove every registered project integration and all global BYO data.
    #[arg(long, conflicts_with = "purge")]
    pub global: bool,
    /// Remove this project's integration and all project-local BYO data.
    #[arg(long)]
    pub purge: bool,
    /// Also write a machine-readable JSON uninstall receipt to this path.
    #[arg(long)]
    pub receipt: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Cli;

    #[test]
    fn uninstall_exposes_three_non_overlapping_modes() {
        for arguments in [
            vec!["byo", "uninstall"],
            vec!["byo", "uninstall", "--purge"],
            vec!["byo", "uninstall", "--global"],
        ] {
            Cli::try_parse_from(arguments).expect("supported uninstall form should parse");
        }
        for arguments in [
            vec!["byo", "uninstall", "--global", "--purge"],
            vec!["byo", "uninstall", "--global", "--project", "."],
            vec!["byo", "uninstall", "--purge-data"],
            vec!["byo", "uninstall", "--yes"],
        ] {
            assert!(
                Cli::try_parse_from(arguments).is_err(),
                "unsupported uninstall form parsed successfully"
            );
        }
    }
}

#[derive(Debug, Args)]
pub struct InstallRuntimeArgs {
    #[arg(long)]
    pub bundle: PathBuf,
    #[arg(long)]
    pub install_dir: Option<PathBuf>,
    /// Opt in to putting the BYO bin directory on PATH at install time, recorded
    /// so uninstall can reverse exactly what was added. Same mechanism as
    /// `byo init --modify-path`; lets the bootstrap scripts offer PATH setup
    /// directly instead of printing a manual hint.
    #[arg(long)]
    pub modify_path: bool,
}

#[derive(Debug, Args)]
pub struct InternalArgs {
    #[command(subcommand)]
    pub command: InternalCommand,
}

#[derive(Debug, Subcommand)]
pub enum InternalCommand {
    NativeBuild {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        arguments: Vec<String>,
    },
    CollectArtifacts {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        arguments: Vec<String>,
    },
    PackRepair {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        arguments: Vec<String>,
    },
}
