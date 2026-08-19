# Cross-repo release triggers (PLAN.md 5d)

The firmware → installer edge is automated so a release tag in
`JasonPeng2019/BYO-Firmware-MCP` bumps this repo's firmware pin and lets the
existing CI validate it. Two pieces cooperate:

| Side | Repo | Workflow | Role |
| --- | --- | --- | --- |
| Sender | `BYO-Firmware-MCP` | `.github/workflows/notify-installer.yml` | On a `v*` tag, POSTs a `firmware-release` `repository_dispatch` to this repo carrying the firmware commit SHA. |
| Receiver | `BYO-Installer` | `.github/workflows/firmware-bump.yml` | Rewrites `release/source-lock.json` `firmware_mcp.commit` and opens a bump PR. `quality.yml` + `build-matrix.yml` (already `pull_request`-triggered) validate it. A human merges to cut the build. |

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
   `InstallerV1`; ensure required status checks include the `quality` and
   `build` matrix jobs so a firmware bump can't merge red.

## Verifying end to end

- Manually: Actions → **Firmware pin bump** → *Run workflow*, paste a firmware
  commit SHA. Expect a `bot/firmware-pin-<short>` branch and a PR.
- From firmware: push a `v*` tag in `BYO-Firmware-MCP`; the sender fires the
  dispatch and the bump PR appears here within a minute.
