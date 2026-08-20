> STATUS: COMPLETE - implemented, native CI passed on all four targets, and the repaired preview was published and post-download verified.

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
- publishing or replacing GitHub release assets as part of the original implementation scope (publication was separately authorized and completed afterward);
- hardware validation, because both failures occur before any probe access.

## Reconciliation summary

- Pre-repair published release: the macOS Intel archive matched its published SHA-256 and installed successfully when the exact release-note snippet supplied its extracted directory.
- Before repair, `install.sh` decided archive format from the filename suffix before invoking the safe extractor, so a valid ZIP with a renamed or suffixless download produced the reported `.zip format` error.
- Before repair, `ProductPaths::resolve()` fetched and validated `HOME` before the Windows-only `LOCALAPPDATA` / `APPDATA` branch could run.
- Before the regression update, the Windows acceptance test removed `HOME` but also set `BYO_HOME`, returning before the defective default-path branch and masking the bug.
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
- No Firmware MCP, workflow pack, or source-lock changes; release payload changes are limited to the installer/launcher portability repair.

## Verified

- Pre-repair published macOS x86_64 asset SHA-256: `e7d6196c723e2252da00fdc825361154c97cf9e53eb024b3749d9becca555d4d`.
- Exact published macOS x86_64 release-note flow installed and `byo status` reported runtime `0.1.1` on macOS Intel.
- Source inspection reproduced the Windows early-`HOME` dependency and the acceptance-test masking condition.
- Before the fix, the published macOS ZIP copied to a suffixless filename exited 2 with `macOS bundle archives must use the .zip format.`
- After the fix, that same suffixless payload installed successfully and reported runtime `0.1.1`; a non-ZIP regular file was rejected with exit 2.
- Full installed macOS x86_64 acceptance passed against the published archive, including install, init, MCP startup, uninstall/reinstall, custom-location rediscovery, and the suffixless bootstrap input.
- `sh -n install.sh`, `git diff --check`, Rust format, clippy with warnings denied, all 39 launcher tests, and the optimized launcher build passed.
- Ruff check/format passed for the changed E2E script; release verification tests passed 11/11 and release-build tests passed 3/3.
- Native build-matrix run `32411329430` passed macOS Apple silicon, macOS Intel, Windows x86-64, and Linux x86-64, including packaging, archive verification, and installed E2E on every target.
- The Windows native E2E completed the default install/status/uninstall cycle with both `HOME` and `BYO_HOME` absent; the Linux and both macOS jobs passed the suffixless-archive regression.
- The ten public `v0.1.1-preview` assets were replaced from the exact CI artifacts, downloaded again, and confirmed byte-for-byte identical; all four receipts and archive-integrity checks passed.
- Published bundle SHA-256 values: macOS ARM `108362e267d1c5b3f364ff38892a61f2cb2353fd5112c112726bfccc45b253dd`, macOS Intel `0d3048cfbc2dec85d33ed09eeb79e27e06ac695411ae7d8860912906ce6db838`, Windows `7621a825e4b5b723422348f37a7bc7c438b6cbd99c9f1db8a124cb2668a0f8be`, and Linux `3b0d29badcaca6854304d23aae14b01c41d958c938811d5e65c00fbba3d4a97a`.

## Pending verification

- None for this agent-verifiable repair. Hardware behavior and production signing/notarization remain outside this task.
