> STATUS: IMPLEMENTED LOCALLY - agent-verifiable checks are clean; native Windows CI and release publication remain pending.

# Clean-host installer portability

## Goal in plain English

Make the offline BYO bootstrap accept a valid downloaded archive without relying on its filename suffix, and make a default Windows install work in a normal PowerShell environment where `HOME` is absent.

Roadmap anchor: `PLAN.md` section 1, one-command install and published release-home work.

## Scope and non-scope

In scope:

- content-based validation of offline ZIP / tar.gz inputs;
- Windows product-path resolution from `LOCALAPPDATA` and `APPDATA` without first requiring `HOME`;
- clean-host regression coverage for both failures;
- installation and sidecar-contract documentation updates.

Out of scope:

- changing the pinned Firmware MCP or AgentWorkspace commits;
- code signing, notarization, or enabling the signed network installer;
- publishing or replacing GitHub release assets without separate authorization;
- hardware validation, because both failures occur before any probe access.

## Reconciliation summary

- Published release: the current macOS Intel archive matches its published SHA-256 and installs successfully when the exact release-note snippet supplies its extracted directory.
- Current bootstrap: `install.sh` decides archive format from the filename suffix before invoking the safe extractor, so a valid ZIP with a renamed or suffixless download produces the reported `.zip format` error.
- Current launcher: `ProductPaths::resolve()` fetches and validates `HOME` before the Windows-only `LOCALAPPDATA` / `APPDATA` branch can run.
- Current acceptance test: Windows removes `HOME`, but also sets `BYO_HOME`, which returns before the defective default-path branch and therefore masks the bug.
- Source locks: remain unchanged; this is launcher/bootstrap work only.

## Design

1. Treat a regular file as an archive candidate and validate its actual contents with the platform extractor instead of rejecting it by filename suffix.
2. Keep all existing bounded extraction, single-root, duplicate-path, traversal, and forbidden-entry checks.
3. Resolve `HOME` only in the macOS/Linux compile-time branches. Resolve Windows defaults only from `LOCALAPPDATA` and `APPDATA`.
4. Extend installed E2E coverage to bootstrap from a suffixless copy of the archive on every target and, on Windows, run the uninstalled launcher with `HOME` and `BYO_HOME` absent.

## Documentation plan

- Replace Windows examples that rely on PowerShell's `$HOME` with `[Environment]::GetFolderPath("UserProfile")` or relative paths after selecting Downloads.
- Document that offline bootstraps identify archives by content and accept renamed downloads.
- Clarify the Windows environment contract in `docs/sidecar-contract.md`.

## Portability

- macOS: `/usr/bin/zipinfo` validates ZIP contents; `ditto` remains the extractor.
- Linux: `tar -tzf` validates gzip-compressed tar contents; bounded extraction remains unchanged.
- Windows: .NET `ZipFile.OpenRead` validates ZIP contents; defaults use native Windows profile variables and do not require `HOME`.

## Verification plan

- Reproduce the suffix false-negative with a valid suffixless macOS ZIP before the edit.
- Run `sh -n install.sh` and Rust format, lint, and unit tests.
- Run installed E2E against the current macOS x86_64 release payload using a suffixless archive.
- Run release-script unit checks.
- Leave Windows runtime verification explicitly pending if no Windows/PowerShell runner is available locally; the updated Windows matrix E2E is the authoritative runtime gate.

## Acceptance criteria

- A valid suffixless macOS ZIP reaches safe extraction and installs.
- A malformed regular file is rejected as an invalid platform archive.
- On Windows, default path resolution succeeds with `LOCALAPPDATA` and `APPDATA` set and both `HOME` and `BYO_HOME` absent.
- Existing custom `BYO_HOME` and installation-locator behavior remains unchanged.
- No Firmware MCP, workflow pack, source lock, or release payload content changes.

## Verified

- Published macOS x86_64 asset SHA-256: `e7d6196c723e2252da00fdc825361154c97cf9e53eb024b3749d9becca555d4d`.
- Exact published macOS x86_64 release-note flow installed and `byo status` reported runtime `0.1.1` on macOS Intel.
- Source inspection reproduced the Windows early-`HOME` dependency and the acceptance-test masking condition.
- Before the fix, the published macOS ZIP copied to a suffixless filename exited 2 with `macOS bundle archives must use the .zip format.`
- After the fix, that same suffixless payload installed successfully and reported runtime `0.1.1`; a non-ZIP regular file was rejected with exit 2.
- Full installed macOS x86_64 acceptance passed against the published archive, including install, init, MCP startup, uninstall/reinstall, custom-location rediscovery, and the suffixless bootstrap input.
- `sh -n install.sh`, `git diff --check`, Rust format, clippy with warnings denied, all 39 launcher tests, and the optimized launcher build passed.
- Ruff check/format passed for the changed E2E script; release verification tests passed 11/11 and release-build tests passed 3/3.

## Pending verification

- Native Windows build-matrix E2E, including PowerShell parsing and the default install with `HOME` / `BYO_HOME` absent.
- Native Linux build-matrix E2E for the suffixless tar.gz input.
- An authorized rebuild and replacement of the currently published pre-fix release assets.
