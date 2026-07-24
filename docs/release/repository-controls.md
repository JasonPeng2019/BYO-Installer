# REL-001 repository controls

The release repository is `JasonPeng2019/BYO-Installer`. Its working branch is
`InstallerV1`; `AgentWorkspace/` and `Firmware MCP New/` are deliberately
ignored external inputs pinned by `release/source-lock.json`.

An administrator must complete these one-time controls before the first
production tag:

- enable immutable releases;
- protect the default branch, `InstallerV1`, `channels`, and `v*` tags;
- require pull requests, at least one non-author review, CODEOWNERS review,
  conversation resolution, signed commits where organization policy permits,
  and the `Quality gates` checks;
- prohibit force pushes and branch/tag deletion;
- create `release-production` and `hil-destructive` environments;
- require an independent reviewer on both environments and disallow
  self-approval;
- limit `release-production` to protected `v*` tags;
- allow production secrets only in `release-production`;
- let only the publication workflow write the protected `channels` branch;
- create repository variable `IMMUTABLE_RELEASES_ENABLED=true` only after an
  administrator has verified that control;
- set `BYO_RELEASE_PUBLIC_KEY_PEM` as a public repository/environment variable;
- set `BYO_SOURCE_READ_TOKEN` as a repository secret containing a fine-grained,
  read-only token for `JasonPeng2019/CodexClaudeWorkflow`;
- restrict Actions to selected actions and require full-length SHA pins.

The `channels` orphan branch must initially contain an empty `channels/`
directory or a README. The publication workflow creates immutable
`channels/<name>/<sequence>.json` documents before atomically replacing
`channels/<name>.json`.

Production workflows fail if source checkouts are dirty, external commits do
not match the lock, `GITHUB_SHA` does not identify installer HEAD, the tag is
not `v<package-version>`, or repository immutability has not been
administratively attested.

This document describes desired controls; it is not evidence that GitHub has
applied them. The GA checklist must link to screenshots/API exports of the
actual rules.
