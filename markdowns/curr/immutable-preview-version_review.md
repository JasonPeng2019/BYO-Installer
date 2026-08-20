# Immutable preview version collision review

Task: Resolve the `0.1.1` immutable-runtime collision without weakening rollback integrity or pulling Proto-1 firmware changes.

## Verdict

CLEAN AND PUBLISHED. The defect is reproduced, the version identity is corrected to `0.1.2`, the real macOS old-to-new transaction and exact reinstall pass, the four-target native matrix is green, and the public release passed independent post-download verification.

## Findings table

| severity | gate | file:line | issue | concrete fix |
|---|---|---|---|---|
| — | — | — | No must-fix findings. | — |

## Spec reconciliation

- The immutable runtime guard remains intact; a reused version with different contents is still refused.
- The new Firmware MCP source commit is based on the previously pinned `f363130` release source and changes only its three package-version fields. No Proto-1 implementation is included.
- Launcher, sidecar, runtime manifest, archive name, README, and source lock agree on `0.1.2`.
- The release builder now defaults to the matching component metadata, and the development matrix derives bundle paths from `launcher/Cargo.toml`; tests reject a stale literal `--version` or bundle field in that workflow.
- Publication moves to a new tag rather than mutating `v0.1.1-preview` again, restoring ADR 0005's release-identity contract.

## Validation matrix

| Check | Result |
|---|---|
| Original `0.1.1` → repaired `0.1.1` isolated repro | PASS — exit 24, distinct manifest digests |
| Real `0.1.1` → locally built `0.1.2` | PASS — both runtimes retained, `0.1.2` active |
| Public `v0.1.1-preview` → public `v0.1.2-preview` on Intel Mac | PASS — both runtimes retained, `0.1.2` active in pointer and status |
| Exact `0.1.2` reinstall | PASS — idempotent |
| Reused `0.1.2` with changed manifest | PASS — refused with actionable diagnostic, exit 24 |
| Full installed macOS Intel acceptance | PASS |
| Compiled sidecar self-test + runtime manifest | PASS — version `0.1.2` |
| Rust format / clippy / unit tests / release build | PASS — 39 tests |
| Release-version / output-verifier tests | PASS — 6 + 11 tests |
| Changed Python lint / format / compile | PASS |
| Workflow YAML parse and shell syntax | PASS |
| Firmware sidecar lock / focused tests / Ruff | PASS — 7 tests |
| Firmware-CLI workflow-core ladder | PASS — 489 pytest tests, Ruff, mypy over 72 files |
| Native macOS ARM / macOS Intel / Windows / Linux | PASS — run `32417292800`, including installed E2E and artifact upload |
| Public `v0.1.2-preview` assets | PASS — ten assets anonymously downloaded and byte-identical to staging; receipts and archive integrity valid |

## Hardware hand-off status

Not required. This defect is confined to release identity and host-side install transactions before probe access.

## What's genuinely good

The repair preserves the invariant that made the failure visible instead of eroding it. It corrects the release identity, makes the failure self-diagnosing, and removes two hardcoded version paths that could silently recreate the publication mistake.

## Verified

- Every local and non-hardware check listed above produced a passing result in this session.
- The full old-to-new transaction used the original published `0.1.1` macOS Intel archive and the newly compiled `0.1.2` archive.
- Native run `32417292800` built and tested exact installer source `ec1d3fbff06095ef2505ff046b0bf9f86636c861` on all four targets.
- The public release body, asset count/names, GitHub asset digests, archive checksums, and all ten downloaded bytes match the reviewed publication set.

## Pending verification

- None for this task.
