# Windows Rust Cppcheck acceptance

This independent suite exercises the public `byo workflow tool verify` command.
It needs no private Rust API or module declaration. Production fixes stay with
the owner. The fake is a native AMD64 program compiled locally with the existing
Rust toolchain; no program or dependency is installed or downloaded.

Prepared on `f1f19752757debfd13b9aabcc78f6352a9f93c0e`, tree
`c9e1ac1ba40df56a083b2f6a6443d2cdd5c15304`. This base has no new Cppcheck
implementation. Successful compilation and fixture identity checks are preparation
evidence. Required Rust behavior, full parity, real ARM, quality, build, release
workflow and installed-product acceptance remain **pending** on a frozen combined
candidate supplied by ROOT.

The 14 original files were recovered only from the immutable snapshot manifest
SHA-256 `222382c5090e0445cc908aa872a14aec3be948e297af48beed95a4d2257c1b3c`.
Every recovery member's SHA-256 and size was verified before copying. The stopped
Claude lane was never accessed. Recovered work was inspected and reworked; its
presence is not an accepted test result.

Accepted server/Python input manifest SHA-256:
`0f8cbf2f43318005e2a9bbc794e5bbab78de06c1dac65703fce869d33a354e92`.
All 15 members match exact raw SHA-256/size and recorded Git blob IDs (LF Git
normalization for CRLF text members). All 38 shared fixture files match the
accepted Python corpus, including committed Git blob bytes. `manifest.json` in
this directory records the independent fixture bytes; `arm-originals.json` records
the 15 protected built ARM inputs. Shared parity fixtures are never edited.

Run from the installer root in native Windows x86_64 PowerShell, using existing
Rust 1.97.1/MSVC and cached locked dependencies. A short task-specific target
directory avoids MSVC's long output-path limitation in deep harness worktrees:

```powershell
$env:CARGO_NET_OFFLINE = 'true'
$env:RUSTUP_AUTO_INSTALL = '0'
$env:CARGO_TARGET_DIR = Join-Path $env:TEMP 'byo-acceptance-target'
# Retain successful and failed labs, complete launcher logs and per-run reports.
$env:BYO_CPPCHECK_ACCEPTANCE_LABS = Join-Path $env:TEMP 'byo-acceptance-evidence'
cargo test --manifest-path launcher/Cargo.toml --locked --offline --test cppcheck_acceptance --no-run
cargo test --manifest-path launcher/Cargo.toml --locked --offline --test cppcheck_acceptance shared_fixture_identity_is_verified_before_parity -- --exact
cargo test --manifest-path launcher/Cargo.toml --locked --offline --test cppcheck_acceptance local_override_receives_target_and_static_step_still_runs_once -- --exact --nocapture
```

The focused RED on this base is exit **101**: the launcher exits **0**, prints
`VERIFY: PASS`, records only `build`, and writes no static `result.json`. Init
and the executable local override succeed first, so this is the missing required
static behavior. The initial default target-directory attempt failed earlier with
MSVC LNK1104; that setup failure is retained separately and is not counted as RED.

After ROOT integrates the owner implementation, run the default suite:

```powershell
cargo test --manifest-path launcher/Cargo.toml --locked --offline --test cppcheck_acceptance -- --nocapture
```

Coverage includes normal/local/failed builds with exactly one static step,
generated headers, closed configuration and runtime schema, version failures,
complete target ABI, ambiguous/malformed/conflicting databases, exact compiler
argv/output and opaque command text, source/directory/header scope, unsupported
assembly coverage, finding/coverage suppressions with file/line/wildcard/BOM,
style opt-in, missing data/notices, all shared XML classifications, mixed-status
precedence, diagnostics/locations, full logs/evidence, finite shared deadline,
owned child/descendant cleanup and no-PATH managed resolution. A same-image peer
must survive timeout cleanup. PID plus creation time controls test cleanup.

Real-program tests are explicitly ignored in the default suite; a default pass
does not satisfy their gate. On the combined candidate set the read-only inputs:

```powershell
$env:BYO_CPPCHECK_PACKAGING_INPUTS = '<context>/cppcheck-windows-packaging-inputs.json'
$env:BYO_CPPCHECK_SOURCE_DIR = '<protected analysis-tools>/cppcheck-windows-static-probe/source'
$env:BYO_ARM_FIXTURE_DIR = '<protected analysis-tools>/built ARM firmware'
cargo test --manifest-path launcher/Cargo.toml --locked --offline --test cppcheck_acceptance real_cppcheck_ -- --ignored --nocapture
```

The manifest is pinned to SHA-256
`e8f71939bafaba468ac299a3995e30ddf05c82365176a2f7c82365f55b57b4d3`;
the Cppcheck 2.22.0 executable to
`bd85657e81f80597c63f4380c2e5f91f6a840e0b12cce159df9812e76bb147cb`.
All 70 cfg/platform/license inputs are checked before copying. The protected
inputs are read/copy only. ARM database relocation is recorded in the private
copy; compiler executables in database argv are never invoked. Build control is
scripted over genuinely built ARM artifacts. The expected analyzer exits for
clean/defect/restored are **0/1/0**; this preparation has not run that gate.

Each retained lab has `invocations/<id>/command.json`, complete stdout/stderr,
launcher executable hash, project input hashes, elapsed time and actual exits.
Reports retain XML, argv, version/analysis logs, result and fake PID/creation
records. Real tests independently sample the private analyzer image and record
observed PID/creation identities and post-exit liveness. Short-lived probes may
escape sampling; inspect the runner's owned-process evidence as well. Missing
process identity/cleanup proof remains a validation gap, never an inferred pass.
Successful labs are removed unless the evidence environment variable is set;
failed labs are always retained. Cleanup never selects processes globally by name.

On the frozen candidate, also run the README's documented Cargo fmt,
`clippy --locked --all-targets -- -D warnings`, `test --locked`, launcher build,
and applicable Windows release/workflow checks with offline cached tools. The
base compilation reports four existing Windows production warnings; this lane
does not modify those files or claim a clean lint gate.

No installed script is prepared here: final packaging/runtime entrypoints are
not available on this base. Fresh installed Windows acceptance must prove both
Cppcheck runners, all five clangd tools, relocated Unicode runtime/project,
no system analysis dependencies, real saved-file queries/diagnostics, exact
process cleanup, update/uninstall and preserved user configuration. Bind that
proof to final archive/runtime hashes. No installed proof, hardware activity,
Linux/macOS/WSL/Docker validation or publication is claimed.
