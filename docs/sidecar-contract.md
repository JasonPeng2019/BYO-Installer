# BYO sidecar contract (installer ↔ firmware MCP)

This is the versioned interface between the Rust `byo` launcher (this repo,
`JasonPeng2019/BYO-Installer`) and the compiled Python sidecar built from
`JasonPeng2019/BYO-Firmware-MCP` (`pyocd-debug-mcp`). A firmware change that
breaks any clause below must bump the relevant number here **and** in the
firmware source, so the break is visible at review and caught in CI rather than
on a customer's machine.

- **Status:** Accepted / in force for installer `0.1.x`.
- **Last updated:** 2026-08-20.
- **Authoritative version numbers:** the constants in
  `Firmware MCP New/src/pyocd_debug_mcp/sidecar.py`
  (`SIDECAR_PROTOCOL`, `WORKER_PROTOCOL`, `WORKFLOW_PROTOCOL`, `CAPSULE_SCHEMA`,
  `PROJECT_STATE_SCHEMA`). This document mirrors them; on any disagreement the
  firmware source wins and this file must be corrected.
- **Launcher enforcement points:** `launcher/src/install.rs`
  (`sidecar_self_test`) and `launcher/src/manifest.rs` (release-manifest
  `workflow_protocol` check).

## 1. Protocol and schema versions

| Name | Value | Owner | Meaning |
| --- | --- | --- | --- |
| `sidecar_protocol` | `1` | firmware | Launcher ↔ sidecar process/JSON contract (this document). |
| `worker_protocol` | `1` | firmware | Sidecar ↔ provider-worker subprocess contract. |
| `workflow_protocol` | `1` | workspace | Compiled workflow-pack / capsule protocol the sidecar speaks. |
| `capsule_schema` | `1` | workspace | On-disk project capsule schema. |
| `project_state_schema` | `1` | firmware | On-disk `.firm` project-state schema. |

The launcher pins `workflow_protocol == 1` in the release manifest
(`manifest.rs`) and re-checks the full set at runtime via `self-test` (§4).

## 2. Command-line surface

The sidecar executable (`sidecar/byo-mcp-sidecar[.exe]` inside a runtime) must
expose exactly these subcommands. `--version` prints the sidecar version.

### 2.1 `serve` — MCP over stdio (public)

```
serve --project-root <dir> --runtime-root <dir> --launcher-version <str> --workflow-protocol <int>
```

All four arguments are **required**. The launcher spawns it verbatim from
`serve_mcp` (`main.rs`), passing its own `CARGO_PKG_VERSION` as
`--launcher-version` and the release-manifest `workflow_protocol` value. `stdin`,
`stdout`, and `stderr` are inherited from the launcher.

### 2.2 `self-test` — hardware-free packaged checks (public)

```
self-test [--runtime-root <dir>] [--launcher-version <str>]
```

Runs without hardware and prints a single JSON object to stdout (§4).

### 2.3 `provider-worker` and helpers (internal, hidden)

`provider-worker` and the helper verbs `collect-artifacts`, `native-build`,
`pack-repair` are hidden (`argparse.SUPPRESS`). Helpers require the runtime
context (`--project-root`, `--runtime-root`, `--launcher-version`,
`--workflow-protocol`) plus a trailing `REMAINDER`. `provider-worker` accepts the
same context optionally. These are spawned by the sidecar itself, not by an
operator.

## 3. Runtime behaviour clauses

1. **Explicit roots, no ambient authority.** All resolution derives from the
   passed `--project-root` / `--runtime-root`. The sidecar must **not** take a
   root from the current working directory, a current-directory `.env`, or a
   `BYO_MCP_ARTIFACT_ROOT`-style environment variable. Reintroducing any of
   those is a breaking change to `sidecar_protocol`.
2. **Runtime-dir resource resolution.** The runtime contract and bundled data
   are read from `runtime_root` (e.g. `runtime_root/release-manifest.json` via
   `_load_runtime_contract`), never relative to cwd.
3. **Declared data files.** Data the sidecar reads at runtime (e.g.
   `probe_families.json`) must be declared to Nuitka so the standalone build
   bundles it; it must resolve as a package resource, not a source-tree path.
4. **Protocol-clean stdout.** stdout carries only MCP / worker framing. All
   diagnostics go to stderr. A stray print to stdout is a contract violation.
5. **Worker spawn = the compiled multicall binary.** In a packaged build
   (`_is_compiled()` true — `sys.frozen`, `__compiled__`, or
   `BYO_SIDECAR_COMPILED=1`) provider workers are spawned as
   `argv0 provider-worker` (the compiled multicall binary resolved without
   trusting `PATH`). Only in a source checkout may it fall back to
   `sys.executable -m pyocd_debug_mcp.sidecar provider-worker`.
6. **Filtered environment.** The launcher passes only an allowlisted environment
   (`SIDECAR_ENVIRONMENT` in `main.rs`); the sidecar must not depend on
   variables outside it. On Windows that allowlist includes the native profile
   variables (`USERPROFILE`, `HOMEDRIVE`, `HOMEPATH`, `APPDATA`, and
   `LOCALAPPDATA`); neither the launcher nor sidecar may require Unix-style
   `HOME` on a clean Windows host.

## 4. `self-test` output contract

`self-test` must print one JSON object to stdout that the launcher validates in
`sidecar_self_test` (`install.rs`). The launcher fails unless **all** hold:

```json
{
  "status": "passed",
  "sidecar_protocol": 1,
  "worker_protocol": 1,
  "workflow_protocol": 1,
  "capsule_schema": 1,
  "project_state_schema": 1,
  "runtime_manifest_verified": true,
  "version": "<equals the launcher's --launcher-version>"
}
```

`self-test` is the single hardware-free gate that proves a freshly built sidecar
still honours this contract.

## 5. How a firmware change stays safe

- Adding firmware behaviour that keeps every clause above needs **no** version
  bump — the existing `self-test` keeps it green.
- Changing any clause (a new required `serve` argument, a stdout framing change,
  a new required data file, a resolution rule) is **breaking**: bump the owning
  number in `sidecar.py`, update this table, and update the launcher's
  enforcement (`sidecar_self_test` / `manifest.rs`) in the same release.
- The firmware repo should run `self-test` from **outside** any source checkout
  (see PLAN.md §5b) so a cwd/`.env`/data-file regression fails at firmware CI,
  before an installer is ever cut.

## 6. Cutting an installer for a new firmware version

1. Bump `firmware_mcp` (and `agent_workspace` if the workflow changed) in
   `release/source-lock.json` to the new commit; bump the release version.
2. If any number in §1 changed, update this file and the launcher checks.
3. Run a full build (`release/scripts/build_release.py`, not `--reuse-sidecar`)
   then `release/scripts/test_installed_e2e.py`; `self-test` must pass on every
   target.
