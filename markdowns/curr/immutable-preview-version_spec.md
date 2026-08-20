> STATUS: IMPLEMENTED LOCALLY — macOS upgrade and full installed acceptance are green; native four-target CI and publication remain pending.

# Immutable preview version collision

## Goal in plain English

Let a machine with the original `0.1.1` preview install the repaired preview without deleting or overwriting an immutable installed runtime, and prevent the native development matrix from silently retaining a stale hardcoded version during future version bumps.

Roadmap anchor: `PLAN.md` section 1 and ADR 0005's immutable release identity.

## Reproduction and root cause

Installing the pre-repair macOS Intel bundle into an isolated product root succeeds. Installing the repaired bundle into the same root then exits 24 with `existing immutable version directory does not match the candidate release`. The installed and candidate `release-manifest.json` SHA-256 values are respectively `39ed97d267abccf2e41cdb51a4711f631cc713b6315f4e08d585508d3cccf8b3` and `a42cdd663a84617ae9de6ba706b57e746b521381b782490aff5cd3a946d29e7c`.

Both bundles declare version `0.1.1`. The installer correctly keys immutable runtimes by manifest version and refuses to overwrite different bytes at `versions/0.1.1`; the defect was replacing a published preview under the same version/tag, contrary to ADR 0005. The build matrix and release-builder default also hardcode `0.1.1`, making version drift easier to repeat.

## Reconciliation summary

- The authoritative immutable-release policy requires a new version identity; weakening or bypassing the runtime guard is out of scope.
- The user-selected pre–Proto-1 payload remains pinned. The Firmware MCP release source starts at `f36313093f7c2690d53a8b327b404843cbb0bcf6`; only package-version metadata changes for `0.1.2`.
- The latest remote `Deploy/Proto-0.0.1` tip is not used because it contains later merged work and is not the payload pinned by the repaired installer release.
- `v0.1.1-preview` remains historical evidence. The corrected publication target is a new `v0.1.2-preview` release.

## Scope

In scope:

- bump the launcher and pinned sidecar package versions to `0.1.2`;
- update the exact Firmware MCP source lock to the version-only commit;
- derive development-matrix bundle paths and the release-builder default from package metadata instead of a literal release version;
- make the immutable-collision error identify version reuse and the safe next action;
- update current install documentation and publish a new unsigned `v0.1.2-preview` only after native CI passes;
- verify all published assets after downloading them back from GitHub.

Out of scope:

- overwriting or deleting an existing installed runtime;
- pulling any Proto-1 firmware changes;
- signing, notarization, production channel promotion, or hardware behavior changes;
- modifying the historical `v0.1.1-preview` assets again.

## Acceptance criteria

- The old `0.1.1` preview and new candidate have distinct immutable runtime paths.
- Installing `0.1.2` over a root containing `0.1.1` succeeds and activates `0.1.2` while retaining the verified prior version for rollback.
- Reinstalling the exact `0.1.2` bundle is idempotent.
- A different candidate that reuses an installed version is still refused with an actionable diagnostic.
- Launcher, sidecar, manifest, bundle names, and user documentation agree on `0.1.2`.
- The development matrix obtains the version from package metadata and passes all four native targets, including installed E2E.
- A new `v0.1.2-preview` release contains the four archives, matching `.sha256` receipts, and current installer scripts; downloaded public assets match the CI publication set byte-for-byte.

## Verification plan

- Re-run the isolated old-then-new macOS installation and exact-candidate reinstall.
- Run shell syntax, Rust format/clippy/tests/release build, changed Python lint/format/compile, and release-script tests.
- Dispatch and monitor the native build matrix for macOS ARM, macOS Intel, Windows x86-64, and Linux x86-64.
- Verify archive manifests and checksums before upload, then download and compare every published asset.

## Verified

- The original `0.1.1` → repaired `0.1.1` collision reproduces on macOS Intel with exit 24 and the reported diagnostic.
- Source inspection confirms `install_bundle_locked` refuses a manifest mismatch at the existing immutable version path.
- ADR 0005 explicitly says published version assets and tags are never replaced.
- Firmware MCP commit `d3aa7786bc6da050174d9ddf78f9269f6a7832b2` changes only `pyproject.toml`, `src/pyocd_debug_mcp/__init__.py`, and `uv.lock` from the pinned pre–Proto-1 source; its package lock, seven sidecar tests, and Ruff check pass.
- A full macOS Intel bundle build completed, including compiled sidecar self-test and runtime-manifest verification at version `0.1.2`.
- Installing the real `0.1.2` archive over an isolated root containing the original `0.1.1` succeeds, retains both immutable directories, and activates `versions/0.1.2`; reinstalling the exact archive also succeeds.
- A deliberately modified candidate that reuses `0.1.2` is refused with exit 24 and the actionable version-reuse diagnostic.
- The full installed macOS acceptance suite passes against the real `0.1.2` bundle.
- Launcher formatting/clippy, all 39 Rust tests, release-version regression tests, release verification tests, Python lint/format/compile, shell syntax, archive checksum/integrity, and the isolated build-output verifier pass. The local leakage verifier used its documented allowance for the local CPython toolchain path; native CI remains the clean shared-account authority.
- The Firmware-CLI workflow-core ladder also passes: 489 pytest tests, Ruff, and mypy over 72 source files.

## Pending verification

- Native four-target CI.
- New immutable preview publication and post-download verification.
