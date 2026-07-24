# BYO V1 GA checklist

Every box requires a stable URL to immutable or protected evidence.

## Source and quality

- [ ] Protected installer tag and commit:
- [ ] AgentWorkspace locked commit:
- [ ] Firmware MCP locked commit:
- [ ] Source-lock and clean-worktree validation:
- [ ] Installer Rust format/Clippy/tests:
- [ ] Firmware Ruff/Pyright/195+ tests:
- [ ] AgentWorkspace lint/type/render/88+ tests:

## Four native targets

- [ ] macOS arm64 build:
- [ ] macOS x86_64 build:
- [ ] Windows x86_64 build:
- [ ] Linux x86_64 glibc 2.28 build:
- [ ] Target-specific SBOMs and private-symbol receipts:
- [ ] Identical version/protocol/schema contract:

## Signing

- [ ] macOS Developer ID identities and `codesign` reports:
- [ ] Notarization logs and `spctl` reports:
- [ ] Windows Artifact Signing identity and SignTool reports:
- [ ] Linux detached signatures:
- [ ] Product manifest signatures:
- [ ] Signing-key ceremony transcript digest:
- [ ] Key-rotation rehearsal:
- [ ] Incident/revocation rehearsal:

## Exact artifact validation

- [ ] Four-target clean-machine matrix:
- [ ] Install/update/rollback/repair/uninstall evidence:
- [ ] Wrong architecture and corrupt artifact fail-closed evidence:
- [ ] Safe HIL on macOS:
- [ ] Safe HIL on Windows:
- [ ] Safe HIL on Linux:
- [ ] Manually approved destructive HIL and successful recovery:

## Publication

- [ ] Build provenance attestations:
- [ ] Immutable draft-then-publish release:
- [ ] Release asset byte-for-byte verification:
- [ ] Signed canary sequence and pointer:
- [ ] Canary update/rollback evidence:
- [ ] Signed beta promotion and evidence:
- [ ] Beta update/rollback evidence:
- [ ] Signed stable promotion and external update:
- [ ] Replay, expiry, equivocation, wrong-target, and corruption tests:
- [ ] Channel expiry monitoring:
- [ ] Repository/environment/ruleset control export:

Release owner:

Independent approver:

GA date:
