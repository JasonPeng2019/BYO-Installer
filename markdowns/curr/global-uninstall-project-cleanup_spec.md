> STATUS: SUPERSEDED 2026-08-20 by `claude-skills-uninstall-contract_spec.md`, which changes global uninstall from integration-only cleanup to full project purge.

# Global uninstall project cleanup

## Goal in plain English

`byo uninstall --global` must safely remove every registered project's BYO-managed integration before removing the shared launcher/runtime. It must preserve project-owned data and identify every registered project path whenever cleanup cannot proceed.

## Scope and non-scope

In scope:

- Enumerate the canonical project paths recorded in `state/projects.json`.
- Refuse before project mutation while an MCP runtime lease is active, with the registered project paths in the diagnostic.
- Preflight all registered projects before removing any project integration.
- Use the existing project-uninstall ownership rules for automatic cleanup.
- Preserve `.firm`, plans, handoffs, specifications, backups, source, and unrelated Codex/Claude configuration.
- Report automatically cleaned project paths in the human and JSON uninstall receipts.
- Keep recorded PATH edits unchanged when project preflight fails.
- Cover ordinary global uninstall and confirmed `--purge-data`.

Out of scope:

- Deleting project-owned retained data.
- Guessing a moved or missing project's new location.
- Bypassing modified vendor-file or malformed managed-file protections.
- Changing active-lease safety or adding a force flag.

## Reconciliation summary

- Firmware build plan: project firmware remains external user data; project paths are runtime data, never fixed product paths.
- Installer design guide §22.1: project uninstall removes only BYO-managed integration and preserves project/user data.
- Installer design guide §22.2 and current code: global uninstall refuses or warns when registered projects remain.
- User decision: supersedes that refusal policy; global uninstall now owns project-integration cleanup.
- Resolution: retain the established project-uninstall preservation and ownership rules, but invoke them automatically from global uninstall after a complete preflight.

## Design

1. Load the registry into typed project entries without following paths implicitly.
2. Resolve and preflight every entry: the recorded path must be absolute, exist as a directory, remain outside BYO product roots, match its capsule project ID, and pass the same ownership checks needed by project uninstall.
3. If any entry fails preflight, fail before project or PATH mutation and include every registry path with either `ready` or its failure reason.
4. If leases are active, fail before cleanup and include every registered project path.
5. If preflight succeeds, remove each integration through the shared project-uninstall implementation, then reverse recorded PATH edits and remove the global runtime/data according to the selected purge mode.
6. Include cleaned project roots in the uninstall receipt. If an unexpected write-time failure occurs, report cleaned, failed, and not-attempted project locations.

## Documentation plan

- Amend `install_guide.md` §22.2 in place.
- Update the concise README uninstall commands and behavior.
- Update installed end-to-end acceptance coverage to leave projects registered before global uninstall.

## Portability

- Use `PathBuf`/`Path`; do not add OS-specific path parsing.
- Accept spaces and Unicode through the existing registry and canonicalization paths.
- Never infer paths from `HOME`, the current directory, or recursive search.
- Do not follow symlinks during managed cleanup or escape registered project roots.

## Verification plan

- Reproduce the old count-only refusal with an isolated `BYO_HOME` (captured before implementation).
- Add Rust regression tests for automatic cleanup and path-rich preflight failure.
- Run Rust format, Clippy, and unit tests.
- Run release-script tests and the installed hardware-free end-to-end test on a locally assembled bundle if available.
- Run the repository validation ladder and review the diff against this spec.

## Acceptance criteria

- A global uninstall with valid registered projects removes their BYO-managed integrations automatically.
- Retained project data survives automatic cleanup.
- An invalid, missing, moved, or modified registered integration stops global removal and names every registered path plus the failing reason.
- A preflight failure leaves project integrations and recorded PATH edits unchanged.
- Active MCP leases still stop global uninstall and the diagnostic names registered project paths.
- Successful receipts identify every project integration removed.
- Existing project-only uninstall behavior remains unchanged.

## Verified

- The current CLI was reproduced returning only `global uninstall refused while 2 project(s) remain registered` for a disposable two-entry registry.
- Current project uninstall already contains the required preservation rules for `.firm`, plans, handoffs, specifications, backups, and unrelated client configuration.
- Rust formatting and Clippy pass with warnings denied.
- All 41 launcher unit tests pass, including automatic project cleanup and all-project path reporting with no preflight mutation.
- Both release-script unit suites pass (11 verification tests and 6 release-build tests), and the installed acceptance test passes against a disposable native macOS Intel bundle.
- The installed acceptance flow verifies one global uninstall removes three registered integrations while retaining project `.firm`, and verifies an active-lease refusal names the registered project.
- The shared Firmware-CLI non-hardware ladder passes: 489 tests, Ruff, and mypy over 72 source files.

## Pending verification

- Native Windows and Linux behavior in CI.
- No hardware verification is required for this filesystem-only change.
