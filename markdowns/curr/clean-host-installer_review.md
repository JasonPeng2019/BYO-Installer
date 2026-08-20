# Review for clean-host installer portability

Task: Fix the current macOS archive-format error and the clean-Windows `HOME` failure without changing the Firmware MCP payload.

## Verdict

CLEAN FOR NATIVE CI. The local, agent-verifiable surface is clean. The current public preview remains pre-fix and must not be described as repaired until rebuilt assets pass the native matrix and are explicitly authorized for publication.

## Findings table

| severity | gate | file:line | issue | concrete fix |
| --- | --- | --- | --- | --- |
| — | — | — | No unresolved agent-verifiable finding. | — |

## Spec reconciliation

- Scope stayed within bootstrap scripts, launcher path resolution, regression coverage, and user-facing documentation.
- `release/source-lock.json`, Firmware MCP sources, AgentWorkspace sources, manifests, and published payloads were not changed.
- Content-based recognition still feeds the existing bounded safe extractors; it does not weaken traversal, duplicate, multi-root, entry-count, or forbidden-entry checks.
- Windows defaults now reach the existing native `LOCALAPPDATA` / `APPDATA` branch without a prior Unix `HOME` requirement.
- The Windows E2E no longer relies solely on `BYO_HOME`: it performs a complete default install/status/uninstall cycle with both `HOME` and `BYO_HOME` absent.

## Validation matrix

| Surface | Result |
| --- | --- |
| Reported macOS suffix error, pre-fix reproduction | PASS — exact error reproduced with a valid suffixless published ZIP |
| Focused macOS suffixless install, post-fix | PASS — runtime 0.1.1 installed and reported healthy status |
| Malformed macOS archive rejection | PASS — exit 2 with explicit invalid-ZIP diagnostic |
| Full installed macOS x86_64 E2E | PASS |
| Shell syntax and whitespace | PASS |
| Rust format / clippy / unit tests / release build | PASS — 39 tests |
| Release verification / build-script tests | PASS — 11 + 3 tests |
| Changed Python lint / format / compile | PASS |
| Native Windows PowerShell + runtime | PENDING — no Windows or PowerShell runtime on this host; coverage is wired into the native matrix |
| Native Linux suffixless archive runtime | PENDING — native matrix hand-off |

## Hardware hand-off status

Not required. Both defects occur during bootstrap and product-path resolution before MCP startup or probe access.

## What's genuinely good

The fix addresses the two root causes at their actual boundaries, preserves the existing safe extraction rules, and converts the previously masked Windows clean-host condition into a product-level regression test. Documentation and `PLAN.md` now distinguish the locally fixed source from the still-unrepaired public preview.
