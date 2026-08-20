> STATUS: HISTORICAL — this clean verdict covers the superseded data-preserving global behavior, not the revised three-mode contract.

# Review for global uninstall project cleanup

Task: Make global uninstall remove registered BYO project integrations automatically and report every project location on failure.

## Verdict

CLEAN

## Findings table

| severity | gate | file:line | issue | concrete fix |
| --- | --- | --- | --- | --- |
| — | — | — | No must-fix findings | — |

## Gate review

- Spec conformance: PASS. Global orchestration preflights and applies shared project cleanup before PATH/runtime removal (`launcher/src/install.rs:511`, `launcher/src/project.rs:1107`).
- Failure diagnostics: PASS. Lease and preflight failures enumerate registered locations, while unexpected apply failures classify removed, failed, and not-attempted projects (`launcher/src/install.rs:518`, `launcher/src/project.rs:1139`, `launcher/src/project.rs:1212`).
- Preservation and ownership: PASS. Automatic cleanup uses the same planned project-uninstall path as explicit project uninstall and retains the established project-data list (`launcher/src/project.rs:1041`, `launcher/src/project.rs:1239`).
- Portability and containment: PASS. Registry paths use `PathBuf`, are required to be absolute/canonical, are checked against product roots, and managed projection paths reject absolute or non-normal components (`launcher/src/project.rs:205`, `launcher/src/project.rs:1116`).
- Documentation sync: PASS. The concise README and authoritative installer guide describe automatic cleanup and path-rich refusal behavior (`README.md:141`, `install_guide.md:2111`).
- Regression coverage: PASS. Rust tests cover successful cleanup and all-path no-mutation preflight failure; installed acceptance covers three projects and active-lease diagnostics (`launcher/src/install.rs:744`, `launcher/src/install.rs:772`, `release/scripts/test_installed_e2e.py:537`).
- Scope: PASS. Active lease safety remains intact; project-owned data is never purged; no force or path-guessing behavior was added.

## Hardware hand-off status

No hardware acceptance criterion applies. Native Windows and Linux CI remain the platform hand-off for this filesystem and launcher change.

## What's genuinely good

The implementation converts project uninstall into a read-first plan and a shared apply path, so global cleanup gains full preflight without creating a second ownership implementation. Receipts and purge previews make the affected locations visible while keeping retained data explicit.

## Verified

- Rust format, Clippy, and 41 unit tests pass.
- Release-script suites pass: 11 and 6 tests.
- Installed macOS Intel acceptance passes with a disposable native bundle.
- Firmware-CLI shared ladder passes: 489 tests, Ruff, and mypy.

## Pending verification

- Native Windows and Linux CI.
- No hardware run is required.
