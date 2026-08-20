# Proposal: Claude Skill Projection and Uninstall Contract

Status: Proposed for implementation and review on 2026-08-20.

## Goal and roadmap anchor

Make the installed BYO launcher expose the private Agent Workspace workflows as native Claude Code project skills, and replace the overlapping uninstall flags with the three user-facing modes authorized for the current installer:

1. `byo uninstall` removes the current project's BYO integration while retaining project-owned BYO working data.
2. `byo uninstall --purge` removes the current project's integration and every project-local file or directory created exclusively for BYO.
3. `byo uninstall --global` applies project purge to every registered project, removes the global launcher and all BYO application data, and reverts BYO-owned PATH changes.

This advances the installer roadmap's private-runtime, explicit-lifecycle, reversible-projection, and truthful-cleanup requirements without changing the firmware MCP protocol or hardware behavior.

## Scope

- Preserve useful Agent Workspace skill metadata in the compiled private workspace pack.
- Materialize thin, mode-authorized `.claude/skills/<skill-id>/SKILL.md` loaders during `byo init` so Claude Code can discover, describe, auto-select, and explicitly invoke each skill.
- Keep full private skill bodies in the signed/verified workspace pack and load them on demand through `byo workflow guidance <skill-id>`.
- Implement the three uninstall modes above, including optional `--project <path>` for the two project-scoped modes.
- Remove stale Claude MCP approvals and empty BYO-created configuration shells during project cleanup.
- Track BYO-created projection files/directories for precise cleanup, with a safe fallback for older manifests.
- Deduplicate project registrations by canonical path and remove all aliases for an uninstalled project.
- Update CLI receipts, installed end-to-end coverage, README, installer guide, and top-level plan.

## Non-scope

- Changes to the firmware MCP tool schema, serial transport, hardware safety policy, or handshake response.
- Publishing a release, pushing commits, or changing remote GitHub assets.
- Automatically deleting arbitrary project source files, unrelated Claude/Codex settings, user-authored instructions, or non-empty shared directories.
- Copying the private Agent Workspace skill bodies into plaintext project files.
- Treating the firmware MCP handshake as a Claude skill-registration mechanism; it remains an MCP runtime safety handshake.

## Reconciliation and authority

- The user's explicit 2026-08-20 command contract supersedes the installer guide's earlier `--purge-data` plus `--yes` design.
- The existing in-progress global-uninstall work is retained and extended: global uninstall will purge registered projects rather than refusing while integrations remain.
- The Firmware-CLI build plan does not constrain launcher-only lifecycle or Claude projection behavior.
- Existing project files and unrelated dirty-worktree changes remain authoritative and must not be overwritten or broadly removed.
- Destructive cleanup is limited to canonical, allowlisted BYO roots and exact BYO-owned entries in shared files. Symlinks are never followed for recursive deletion.

## Design

### Compiled skills and Claude projection

The workspace compiler will parse selected frontmatter from each mode-authorized `SKILL.md` and emit a catalog entry containing its private resource path, description, and invocation controls. The launcher will use this catalog to create one thin Claude skill per authorized ID. Each loader contains:

- a stable skill name and source description;
- Claude invocation metadata;
- dynamic context that executes `byo workflow guidance <skill-id>` at invocation time.

The current `byo-firmware` bootstrap remains available for compatibility and MCP safety guidance. The project manifest hashes every loader, so modified projections still fail closed instead of being overwritten silently.

### Projection ownership

The projection manifest will record which managed files and known directories did not exist before initialization and were therefore created by BYO. New initialization and update operations will retain this ownership data across projections. Older manifests receive conservative cleanup: exact BYO files and entries may be removed, while only demonstrably empty known configuration shells/directories are pruned.

### Project uninstall

Ordinary uninstall removes the launcher-managed MCP configuration, hooks, generated bridge files, native skill projections, capsule/projection manifests, and all registrations for the canonical project. It also removes BYO from Claude's local enabled/disabled MCP lists and prunes shared configuration files or known directories only when they become empty and are safe to remove. It preserves BYO working data such as plans, handoffs, specs, `.firm`, and backups.

Project purge performs ordinary uninstall and then recursively removes only the allowlisted dedicated BYO roots (`.agent-workspace`, `.agent-backups`, `.firm`, `.generated/byo`, and remaining BYO-owned skill roots). It never deletes the project root or unrelated content in shared `.claude`, `.codex`, or configuration files.

### Global uninstall

Global uninstall groups registrations by canonical project path, tolerates duplicate/stale registry IDs for the same valid capsule, preflights every unique project, and reports every blocking lease or integrity mismatch before mutation. It then applies project purge to every project and removes all BYO global roots, launcher files, locator data, state/config/cache data, and BYO-owned PATH edits. The command itself is the explicit destructive request; no additional `--yes` flag is required.

### CLI compatibility

`--purge-data` and `--yes` are removed from the uninstall interface. `--global` conflicts with `--purge` and `--project`; `--purge` remains project-scoped and may be combined with `--project <path>`. Receipts distinguish `project`, `project-purge`, and `global` modes and list removed, preserved, and automatically cleaned project integrations.

## Board facts and origin handling

This task changes no board facts, firmware profiles, firmware artifacts, detector origins, provenance records, or hardware-facing behavior. No user-provided board fact is promoted into a durable runtime source.

## Documentation plan

- Keep `InstallerWork/README.md` concise and update installation, initialization, native Claude skills, and the three uninstall forms.
- Update `InstallerWork/install_guide.md` so its CLI contract, lifecycle, cleanup, and acceptance requirements match implementation.
- Update the outer `PLAN.md` status/contract references that describe the installer lifecycle.
- Keep runtime help text and receipts aligned with the same terminology.

## Portability and safety

- Use platform path APIs and existing `PlatformPaths`; no hard-coded home-directory assumptions.
- Treat Windows junctions/reparse points and Unix symlinks as non-recursive cleanup boundaries.
- Canonicalize registered project paths before deduplication and containment checks.
- Use exact allowlists for recursive project deletion and retain unrelated JSON/TOML/Markdown content.
- Keep global deletion scoped to resolved BYO-owned data/config/cache/launcher paths.

## Verification strategy

### Agent-verifiable

- Workspace compiler tests cover metadata parsing, deterministic catalog output, and invalid frontmatter.
- Rust unit/integration tests cover native Claude loader creation and hashing, CLI flag conflicts, stale registry deduplication, Claude MCP approval removal, ordinary uninstall preservation, project purge, global multi-project purge, and unrelated-content preservation.
- Installed end-to-end tests exercise all three command forms and validate receipts and filesystem results.
- Run Python tests, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test`.
- Inspect the generated help and projection files from a temporary packaged workspace.

### Human/operator-verifiable

- In a real Claude Code session, confirm `/skills` lists the authorized BYO skill names and an MCP-related prompt auto-selects the appropriate loader.
- Confirm the first BYO MCP operation still follows the initialization handshake guidance.
- On macOS and Windows, install into disposable projects and visually confirm the three cleanup scopes.

### Hardware-required

None. This change does not affect probes, targets, flashing, reset, memory access, or runtime board behavior.

## Acceptance criteria

- A freshly initialized Claude project has one valid native loader for every mode-authorized packed skill, with useful descriptions and no plaintext private body.
- `byo workflow guidance <skill-id>` remains the source of the full verified workflow content.
- `byo uninstall` succeeds only for a project integration, removes all integration hooks/configuration, removes stale Claude BYO approvals, and preserves retained working data.
- `byo uninstall --purge` removes all dedicated BYO-created project data while preserving unrelated project and agent configuration.
- `byo uninstall --global` purges every unique registered project before removing all global BYO product data and launcher state.
- Duplicate registry IDs for one canonical path do not block global cleanup and are all removed.
- Active leases, modified managed projections, invalid paths, or unsafe recursive targets fail before destructive mutation and identify the affected project(s).
- CLI help and official local documentation expose only the three uninstall forms requested.
- All agent-verifiable checks pass, with any real-Claude checks reported separately as pending operator verification.

## Verification status

- Verified: authority reconciliation; implementation; Rust formatting, lint, and 51 tests; Python compiler/release tests; deterministic pack compilation; packaged macOS Intel build, sidecar self-test, and installed hardware-free E2E.
- Verified: independent review completed CLEAN after one fix iteration.
- Pending: native Linux/Windows/Apple-silicon CI and live Claude skill discovery/selection by an operator.
