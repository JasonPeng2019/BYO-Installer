# Cross-repo release triggers (PLAN.md 5d)

## Canonical development validation

Pushes to `chore/Proto-0.04` or `InstallerV1`, and pull requests, run preparation
in `build-matrix.yml`: workflow lint and reusable source/release quality.
`quality.yml` does not also trigger independently for those events. Full
Firmware formatting includes test fixtures, so a test-format failure is found
before native packaging. Rust Clippy and the distinct quality checks remain.

One explicit `workflow_dispatch` with `build_kind=bundle` owns all four native
hosts and the existing installed profiles, lifecycle/update, public MCP,
source/risk and compiled acceptance checks. The old `final_acceptance` input
remains for caller compatibility, but setting it false does not skip required
bundle checks. `build_kind=contracts` runs native source contracts without
claiming installed acceptance. Skipped push build jobs are not passing builds.

For standalone fixture maintenance, dispatch `build_kind=cleanup`. It runs
workflow lint and the affected source fixtures on Linux, Windows and both
macOS architectures, using locked Python dependencies and ordinary pytest.
It checks the changed fixture/helper formatting and lint, and exercises the
small command capture with the source tests. `bundle` remains the default;
`contracts` retains its existing behavior. Cleanup mode does not run Clippy,
Rust, analyzer/bundle builds, installed acceptance, real clients or hardware.
A cleanup PASS verifies those changed test paths, not the product candidate.
Product build failures do not prevent this independent source verification.

Example: `gh workflow run build-matrix.yml --ref chore/Proto-0.04 -f
build_kind=cleanup`. Supply the existing optional exact execution commit/input
digest when binding a frozen candidate. Failure remains a failed Actions job
with its pytest report/streams/inputs uploaded; fix the affected fixture or
setup and dispatch the new exact inputs. Compiled/installed oracle execution
still belongs to the later product verification against genuine artifacts.

The native jobs depend on preparation, then check interpreter/import readiness,
source quality, launcher contracts and retained serious-risk regressions before
analyzer preparation and packaging. The separate FR13 host matrix and copied
`bc01-ci/build-and-native.yml` have been removed. Its useful process controls
are ordinary Firmware pytest modules in the existing native jobs. The redundant
ARM mock-contract workflow is removed; release script unit checks and the real
ARM input producer remain.

`release/source-lock.json` pins the exact Firmware MCP export;
`bc01-ci/CI-INPUTS.json` binds the executed source/helper bytes. Frozen inputs
are verified before and after each native job. Refresh those existing records
for the next frozen candidate; this standalone cleanup leaves historical
exports intact and does not warrant a version bump or public release.

Use one raw artifact upload set and its short job/step summary. Diagnose a
captured failure while unrelated jobs finish on the unchanged candidate;
preserve original failures and partial output. No observer/receipt platform
or duplicate raw archive is needed.

Existing external drivers can check a verified extracted bundle, for example
`python release/scripts/final_public_mcp.py --bundle <bundle> --firmware-source
<source> --evidence <new-directory>`. Such automated execution remains in
Actions. Reuse is valid only when all actual build inputs are unchanged,
including packaged data/tests, dependency/toolchain/profile/recipe and
generated metadata. Record the original build commit and artifact digest
separately from the new test commit. Otherwise rebuild; do not create an
equivalence engine or relabel old assets. This cleanup qualifies no old
artifact for reuse and adds no automatic reuse shortcut.

The Firmware repository runs its own native analysis and package gates on the
canonical Firmware commit. An Installer job checking out that source does not
create checks on the Firmware commit. These workflows publish private Actions
artifacts only; release and channel workflows keep their existing triggers.

The firmware → installer edge is automated so a release tag in
`JasonPeng2019/BYO-Firmware-MCP` bumps this repo's firmware pin and lets the
existing CI validate it. Two pieces cooperate:

| Side | Repo | Workflow | Role |
| --- | --- | --- | --- |
| Sender | `BYO-Firmware-MCP` | `.github/workflows/notify-installer.yml` | On a `v*` tag, POSTs a `firmware-release` `repository_dispatch` to this repo carrying the firmware commit SHA. |
| Receiver | `BYO-Installer` | `.github/workflows/firmware-bump.yml` | Rewrites `release/source-lock.json` `firmware_mcp.commit` and opens a bump PR. `build-matrix.yml` runs preparation and calls reusable quality. A human merges; the explicit bundle dispatch performs native validation. |

The receiver deliberately opens a **PR** instead of building the payload
directly: a release must record the exact pinned commit in
`release/source-lock.json`, and a human should approve the source bump before an
installer is cut. `workflow_dispatch` on `firmware-bump.yml` lets a maintainer
perform the same bump by hand (`commit`, optional `branch`).

## Manual setup you must do once

These are GitHub-account/secret actions the workflows cannot self-provision:

1. **Create a cross-repo dispatch token (for the sender).** In the
   `BYO-Firmware-MCP` repo, add a secret `INSTALLER_DISPATCH_TOKEN` = a
   fine-grained PAT scoped to `JasonPeng2019/BYO-Installer` with
   **Contents: read/write** (repository_dispatch requires write on the target).
   Without it, the sender cannot fire the event.
2. **(Recommended) Create a CI PAT (for the receiver).** In this repo, add a
   secret `BYO_CI_PAT` = a fine-grained PAT with **Contents: write** and
   **Pull requests: write**. The bump PR is opened with this token so it
   triggers downstream `pull_request` CI. If omitted, the workflow falls back to
   the ephemeral `GITHUB_TOKEN`, which opens the PR but — by GitHub design —
   does **not** start further workflows, so you would have to re-run CI on the
   PR by hand.
3. **Confirm branch protection expectations.** The bump PR targets
   `InstallerV1`; require preparation on the PR and the explicit native/installed
   dispatch before product acceptance. The native jobs are deliberately skipped
   on push/PR; do not configure those skips as proof of a passing build. This
   source cleanup does not change GitHub branch protection settings.

## Verifying end to end

- Manually: Actions → **Firmware pin bump** → *Run workflow*, paste a firmware
  commit SHA. Expect a `bot/firmware-pin-<short>` branch and a PR.
- From firmware: push a `v*` tag in `BYO-Firmware-MCP`; the sender fires the
  dispatch and the bump PR appears here within a minute.

## Standalone fixture cleanup

`build-matrix.yml` dispatched with `build_kind=cleanup` runs workflow lint and
the fixture-only matrix on Linux, Windows and both macOS architectures. Native
bundle, source/product quality, Rust, installed and release jobs are excluded.
The two plain `bc01-ci/fixture-cleanup-*.txt` lists name affected tests and changed
Python files; they are scoped cleanup selections, not the product acceptance
suite. Exact committed source is bound before/after. Standard collection, JUnit,
command/exit streams and failed owned inputs are uploaded even on failure.

Neutral Firmware lint/format runs once in reusable quality's Linux source job;
other hosts retain their type/contracts, and native bundle jobs retain their own
host/toolchain type check. A fixture result supplies no installed, real client,
model or hardware acceptance.
