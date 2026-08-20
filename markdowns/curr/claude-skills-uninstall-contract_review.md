# Review: Claude Skill Projection and Uninstall Contract

Reviewed: 2026-08-20
Spec: `markdowns/curr/claude-skills-uninstall-contract_spec.md`
Verdict: CLEAN

## Findings

| Severity | Gate | Finding | Disposition |
| --- | --- | --- | --- |
| — | — | No remaining agent-verifiable must-fix finding | — |

## Resolved during the review loop

| Severity | Gate | Finding | Fix and evidence |
| --- | --- | --- | --- |
| High | Rollback compatibility | Catalog schema 2 initially made the new launcher reject schema-1 packs retained for `byo rollback`. | `CompiledSkillEntry` now accepts legacy resource strings and synthesizes safe manual loader metadata; schema validation accepts catalog versions 1–2. Unit coverage passes. |
| High | Destructive-path containment | Initial purge containment used the `is_within` arguments in reverse and did not reject symlinked intermediate components. | Project paths now validate every existing component with `symlink_metadata`; recursive roots must be real directories whose canonical path remains inside the project. A Unix regression test proves rejection occurs before capsule mutation and external data remains intact. |
| Medium | Ownership migration | A schema-2 project upgraded to schema 3 could lose conservative empty-shell cleanup because historical created-file/created-dir facts were unavailable. | The projection records `legacy_cleanup` across upgrades; legacy projects retain conservative pruning while fresh schema-3 projects use explicit ownership. Tests distinguish a preexisting empty shared file from a legacy BYO shell. |

## Gate review

- Spec conformance: PASS. The CLI exposes ordinary project, project `--purge`, and `--global` modes; old uninstall-specific flags fail parsing (`launcher/src/cli.rs:197`, `launcher/src/main.rs:709`).
- Claude skill discovery: PASS. Compiler catalog entries include source descriptions and invocation controls, while initialization writes thin native loaders that dynamically call `byo workflow guidance <id>` and keeps private bodies in the pack (`release/scripts/compile_workspace.py`, `launcher/src/pack.rs:47`, `launcher/src/project.rs:691`).
- Backward compatibility: PASS. Older schema-1 workflow catalogs remain readable for retained runtime rollback (`launcher/src/pack.rs:62`).
- Cleanup ownership: PASS. Ordinary uninstall removes exact integration content and Claude MCP approvals, removes owned/legacy-empty shells, and preserves working data; project purge deletes only validated dedicated BYO roots (`launcher/src/project.rs:465`, `launcher/src/project.rs:1630`).
- Global behavior: PASS. Global uninstall deduplicates registrations, preflights all unique projects, purges each, reverses recorded PATH edits, and removes all resolved global BYO roots (`launcher/src/project.rs:1442`, `launcher/src/install.rs:503`).
- Failure diagnostics: PASS. Live leases and project preflight failures name the registered paths before project/PATH mutation; partial apply failures identify removed, failed, and unattempted projects.
- Portability and safety: PASS. Relative paths reject prefixes/parent components, Windows-style separators are normalized for managed skill parents, symlinks are not followed, and global paths come from `ProductPaths` rather than `HOME` assumptions.
- Documentation sync: PASS. README, installer guide, CLI help, top-level plan, and CI quality workflow describe the same command and skill-projection contracts.
- Regression coverage: PASS. Rust formatting/clippy and 52 tests pass; Python compile/ruff/release tests pass; the deterministic pack build, compiled sidecar self-test, and installed macOS Intel E2E pass on the final reviewed package.

## Verification boundaries

- Agent-verifiable: PASS.
- Human/operator-verifiable: PENDING — open a real Claude Code session and confirm the projected BYO skills appear in `/skills`, explicit invocation loads the private guidance, and a suitable prompt auto-selects a non-manual skill.
- Hardware-required: NONE — no firmware MCP schema, probe, target, flash, reset, serial, or board-authority behavior changed.
- Platform matrix: PENDING — Linux x86-64, Windows x86-64, and macOS Apple-silicon native CI remain release gates; the final local package run covered macOS Intel.

## Review conclusion

The agent-verifiable surface is clean after one review/fix iteration. The remaining checks are platform/operator validation, not unresolved implementation defects.
