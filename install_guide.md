# BYO Universal Installation, Workspace Partitioning, and Release Guide

> Status: implementation blueprint
>
> Audience: BYO product engineering, security, release engineering, and QA
>
> Platforms: Windows, macOS, and Linux
>
> Product shape: Rust launcher and installer, compiled Python MCP sidecar, and a minimal customer-facing Agent Workspace capsule

## 1. Purpose

This document is the working implementation guide for turning the current BYO Firmware MCP
checkout and the `2nd-Proto` Agent Workspace into a distributable product.

It covers two related deliverables:

1. A universal `byo` command installed on the user's `PATH`. It owns product installation,
   project initialization, Agent Workspace projection, updates, repair, diagnostics, MCP launch,
   and uninstall.
2. A private runtime composed of:
   - a Rust launcher and workspace runtime;
   - a compiled Python MCP sidecar containing the existing firmware MCP implementation; and
   - compiled or embedded Agent Workspace workflow data derived from the private
     `2nd-Proto` source.

The desired customer experience is:

```text
# Install BYO once.
<run the platform installer>

# Initialize any firmware project.
cd <firmware-project>
byo init

# Confirm the installation.
byo doctor
```

The customer should not need Python, `uv`, Rust, Node.js, a source checkout of the MCP server, or
a source checkout of the Agent Workspace.

This guide distinguishes implementation opacity from security:

- Opacity makes casual inspection and reverse engineering more difficult.
- Security protects the customer, host, source tree, credentials, and attached hardware.
- Code signing proves publisher identity and artifact integrity; it does not make local code secret.
- Any instruction ultimately delivered to an agent can be observed by the machine owner.
- Hardware safety must remain enforced locally even if some workflow selection later becomes a
  remote service.

## 2. Source systems and current-state assumptions

### 2.1 Firmware MCP source

The current repository is a Python package named `pyocd-debug-mcp`. Its console entry point is:

```toml
pyocd-debug-mcp = "pyocd_debug_mcp.server:main"
```

The current runtime:

- uses MCP over stdio;
- derives its project root from `BYO_MCP_ARTIFACT_ROOT` or the current working directory;
- loads a current-directory `.env`;
- creates project-owned `.firm` state;
- launches persistent provider workers with:

  ```text
  <sys.executable> -m pyocd_debug_mcp.adapters.provider_worker
  ```

- exposes additional command-line helpers for pack repair, artifact collection, and native builds.

Those behaviors work in a source checkout but require refactoring for a compiled sidecar.

### 2.2 Agent Workspace source

The private Agent Workspace source is the `2nd-Proto` branch of:

<https://github.com/JasonPeng2019/CodexClaudeWorkflow/tree/2nd-Proto>

That branch currently treats `.agent-workspace` as a complete workflow distribution. It includes
setup scripts, hooks, modes, skills, templates, internal Python code, specifications, tests, and
projection logic. Its current customer archive is suitable as a source-based distribution, but it
is too revealing for the intended opaque commercial release.

The release architecture in this guide therefore uses `2nd-Proto` as private build input rather
than copying it verbatim into customer projects.

### 2.3 Required product decision

The product has one public executable:

```text
byo
```

The compiled Python sidecar is private, versioned, not placed on `PATH`, and never referenced
directly in customer MCP configuration.

Do not create separately branded public commands for the installer, workspace manager, and MCP
launcher. One stable command prevents multiple update channels and ownership conflicts.

## 3. Goals and non-goals

### 3.1 Required goals

The finished system must:

- install per user without administrator access for normal operation;
- support Windows, macOS, and Linux;
- place `byo` on the user's `PATH` or provide a precise, reversible PATH setup step;
- require no customer-managed Python environment;
- initialize a project with `byo init`;
- preserve application source and user-authored project configuration;
- install only a minimal, customer-visible Agent Workspace capsule;
- keep internal Agent Workspace implementation out of the project;
- launch the Python sidecar through a stable Rust command;
- survive versioned runtime updates without rewriting MCP configuration;
- detect and repair a moved or missing runtime;
- default to the ordinary `firmware` mode;
- make unrestricted modes separate and explicitly selected;
- use atomic installation and project-update transactions;
- verify every downloaded or embedded release payload;
- sign platform binaries and installers where the platform supports it;
- preserve `.firm` by default during workspace update and uninstall;
- never prompt on MCP stdout;
- fail closed when compatibility, integrity, root identity, or ownership is uncertain; and
- provide clean install, update, rollback, repair, and uninstall tests.

### 3.2 Non-goals

The first release does not need to:

- rewrite the entire firmware MCP server in Rust;
- guarantee that a determined machine owner cannot reverse-engineer local software;
- make Docker a required dependency;
- silently install hardware drivers;
- silently grant client trust or unrestricted agent permissions;
- silently modify shell profiles;
- share one mutable `.agent-workspace` directory between multiple projects;
- support system-wide installation as the default;
- permit the MCP process to auto-update itself while an MCP session is running; or
- delete `.firm` or user-authored plans as part of ordinary uninstall.

### 3.3 Master work order

Use this order to avoid building an installer around source-checkout assumptions:

1. Freeze public protocol, ownership, compatibility, and path decisions.
2. Refactor the Python server so project and runtime roots are explicit constructor inputs.
3. Remove production current-directory `.env` loading and ambient root selection.
4. Turn the Python package into a multicall sidecar with `serve`, `provider-worker`, helper, and
   self-test modes.
5. Prove one target-native Nuitka standalone build and run it without Python or the source tree.
6. Implement the Rust launcher and its verified sidecar launch contract.
7. Classify every `2nd-Proto` file and build the deterministic workspace compiler.
8. Port attach, render, hooks, mode handling, doctor, update, and uninstall behavior to Rust.
9. Implement the project capsule transaction and migrate one old full workspace.
10. Implement versioned global installation, signed manifests, update, runtime leases, repair, and
    rollback.
11. Complete the platform target matrix and clean-machine/HIL testing.
12. Add signing, notarization, installers, SBOMs, attestations, and protected release publication.

Do not begin by writing three unrelated platform scripts. The scripts are thin bootstrap layers
over the same tested Rust installation transaction.

## 4. Terminology

### 4.1 Product runtime

The complete global, per-user installation:

```text
byo executable
private Python sidecar
embedded or signed workflow resource pack
release and compatibility manifests
```

### 4.2 Launcher

The public Rust executable named `byo`.

### 4.3 Sidecar

The compiled, standalone Python firmware MCP executable and its private dynamic libraries and data
files.

### 4.4 Internal workspace

The private `2nd-Proto` source and all workflow implementation details used to build the customer
runtime.

### 4.5 Customer capsule

The minimal project-visible `.agent-workspace` footprint plus the minimal managed projections
needed by supported clients.

### 4.6 Projection

A client-specific file generated into `.codex`, `.claude`, `.agents`, `.generated`, or a root
instruction file.

### 4.7 Vendor-owned file

A file generated entirely by BYO. Customers may inspect it, but update and doctor treat its
contents as product-owned.

### 4.8 User-owned file

A project or task artifact that BYO must not replace merely because the product is updated.

### 4.9 Shared file

A customer file in which BYO owns only a clearly delimited block.

## 5. Final architecture

```text
                         Release pipeline
                                |
             +------------------+------------------+
             |                                     |
             v                                     v
    Private Agent Workspace                 Python MCP source
             |                                     |
      workspace compiler                     Nuitka standalone
             |                                     |
             v                                     v
  compiled workflow resource pack          private sidecar directory
             |                                     |
             +------------------+------------------+
                                |
                         Rust release assembly
                                |
                                v
                     signed BYO product archive
                                |
                        platform installer
                                |
                                v
                     per-user versioned install
                                |
                     stable `byo` command on PATH
                                |
             +------------------+------------------+
             |                                     |
             v                                     v
        `byo init`                         `byo mcp serve`
             |                                     |
   project customer capsule              private Python sidecar
             |                                     |
      managed projections                         stdio
             |                                     |
             +------------------+------------------+
                                |
                         MCP client and agent
```

### 5.1 Boundary rule

The project contains only what a client must read or what a user owns. The global product
installation contains executable implementation. Development specifications, tests, source
scripts, comments, and full workflow documents do not ship in the project capsule.

### 5.2 Single-writer rule

The Rust launcher is the only component allowed to:

- install or update the customer capsule;
- write managed client projections;
- edit shared managed blocks;
- register or remove project MCP configuration;
- migrate capsule versions; and
- uninstall managed project integration.

The Python sidecar owns `.firm` runtime evidence but does not rewrite `.agent-workspace` or client
configuration.

This avoids two independent implementations modifying `.codex`, `.claude`, or `.agents`.

## 6. Threat and opacity model

### 6.1 Observers

Design separately for:

1. The MCP client, which can see initialization metadata, advertised tools, schemas, results,
   errors, and stderr diagnostics surfaced by the host.
2. The coding agent, which can see client-provided context and project files allowed by the client.
3. Another local OS account, which should not read the per-user product installation.
4. The customer who owns the machine, who can inspect their files and processes.
5. A technical competitor willing to reverse-engineer native code.
6. A supply-chain attacker attempting to replace installers, updates, or sidecar files.

### 6.2 Practical opacity targets

The release should:

- prevent the agent from casually browsing internal product source;
- avoid plaintext Python source and full workspace source;
- remove internal specifications, tests, comments, and development scripts;
- compile hooks, renderer logic, mode policy, and workflow transitions;
- expose only a small bootstrap instruction;
- reveal workflow fragments progressively through the MCP server;
- strip native symbols from customer artifacts;
- keep private symbols in controlled release storage; and
- avoid internal module names, source paths, and stack traces in normal customer errors.

### 6.3 What cannot be hidden

The following are necessarily observable:

- the `byo` command;
- the fact that an MCP server is configured;
- public tool names, descriptions, and input schemas;
- tool results and consequential-action disclosures;
- the minimal bootstrap instructions consumed by the agent;
- project mode and workspace version;
- commands placed in client configuration; and
- any instruction text delivered dynamically to the agent.

Do not weaken destructive-operation disclosures to improve opacity. Hide implementation, not
capability or consequence.

### 6.4 Security boundaries

Opacity is never an authorization control. Continue to enforce:

- exact plan binding;
- per-board validation;
- memory-map containment;
- structured permissions;
- fresh one-time approval for destructive recovery;
- process isolation and timeouts;
- project-root containment;
- exact artifact digest verification; and
- fail-closed behavior inside the sidecar.

## 7. Supported target matrix

Build and test each target independently:

| Platform | Architecture | Rust target | Initial release |
|---|---|---|---|
| Windows | x86-64 | `x86_64-pc-windows-msvc` | Required |
| Windows | ARM64 | `aarch64-pc-windows-msvc` | Optional until hardware CI exists |
| macOS | Apple silicon | `aarch64-apple-darwin` | Required |
| macOS | Intel | `x86_64-apple-darwin` | Product decision based on customer demand |
| Linux | x86-64 glibc | `x86_64-unknown-linux-gnu` | Required |
| Linux | ARM64 glibc | `aarch64-unknown-linux-gnu` | Recommended |

Build the Python sidecar on the target operating system and architecture. Do not assume that a
Nuitka output built on one OS can run on another. Native USB, process, and Python dependencies make
target-native testing mandatory.

Prefer separate macOS architecture downloads for the first release. A true universal binary
requires every nested executable and native dependency to contain compatible slices; combining
only the outer Rust launcher is insufficient.

Decide and document minimum supported OS versions before beta. Test against those versions rather
than relying only on current CI images.

## 8. Platform filesystem layout

Use the operating system's per-user data locations. A Rust directory abstraction may be used, but
the resolved path must be logged by `byo paths`.

### 8.1 Global paths

| Purpose | Windows | macOS | Linux |
|---|---|---|---|
| Product data | `%LOCALAPPDATA%\BYO\` | `~/Library/Application Support/BYO/` | `$XDG_DATA_HOME/byo/` or `~/.local/share/byo/` |
| Configuration | `%APPDATA%\BYO\` | `~/Library/Preferences/BYO/` or the selected application-support config directory | `$XDG_CONFIG_HOME/byo/` or `~/.config/byo/` |
| Persistent state/logs | `%LOCALAPPDATA%\BYO\state\` | `~/Library/Application Support/BYO/state/` | `$XDG_STATE_HOME/byo/` or `~/.local/state/byo/` |
| Cache/downloads | `%LOCALAPPDATA%\BYO\cache\` | `~/Library/Caches/BYO/` | `$XDG_CACHE_HOME/byo/` or `~/.cache/byo/` |
| Public command | `%LOCALAPPDATA%\BYO\bin\byo.exe` | `~/.local/bin/byo` | `~/.local/bin/byo` |

The Linux behavior should follow the
[XDG Base Directory Specification](https://specifications.freedesktop.org/basedir/0.8/).

### 8.2 Versioned product layout

```text
<product-data>/
├── current.json
├── versions/
│   ├── 1.4.0/
│   │   ├── byo or byo.exe
│   │   ├── release-manifest.json
│   │   ├── release-manifest.sig
│   │   ├── sidecar/
│   │   │   ├── byo-mcp-sidecar or byo-mcp-sidecar.exe
│   │   │   ├── libraries/
│   │   │   └── resources/
│   │   └── workflow/
│   │       └── workspace.pack
│   └── 1.5.0/
├── staging/
├── downloads/
└── state/
    ├── projects.json
    ├── update-lock
    └── logs/
```

`current.json` is a small atomically replaced record, not an unchecked symlink:

```json
{
  "schema": 1,
  "version": "1.5.0",
  "relative_runtime": "versions/1.5.0",
  "manifest_sha256": "<lowercase-sha256>"
}
```

The public PATH entry may be:

- a stable copy of `byo` that resolves `current.json`; or
- a platform-appropriate shim that invokes the current launcher.

For the simplest trust model, keep a stable signed launcher in the public `bin` directory and make
only private runtime versions switchable.

### 8.3 Permissions

On Unix-like systems:

- product directories: `0700`;
- ordinary private files: `0600`;
- executables: `0700` or `0755` depending on sharing policy;
- no group/world-writable parent directory;
- reject a product root owned by another user.

On Windows:

- use the current user's LocalAppData;
- retain inherited user ACLs only when they exclude unrelated write access;
- reject reparse points in version and staging directories;
- do not place writable runtime DLL directories on the global system `PATH`.

## 9. Recommended source organization

The source may remain in separate private repositories, but the release pipeline should present a
single versioned assembly workspace:

```text
release-source/
├── launcher/
│   ├── Cargo.toml
│   ├── src/
│   └── tests/
├── firmware-mcp/
│   ├── pyproject.toml
│   ├── uv.lock
│   ├── src/pyocd_debug_mcp/
│   └── tests/
├── agent-workspace/
│   ├── internal/
│   ├── modes/
│   ├── skills-src/
│   ├── templates/
│   ├── hooks/
│   ├── tests/
│   └── specs/
├── workspace-compiler/
├── release/
│   ├── manifests/
│   ├── policies/
│   ├── packaging/
│   └── scripts/
└── integration-tests/
```

Every assembled release must record the exact commit of:

- the launcher;
- the firmware MCP;
- the Agent Workspace;
- the workspace compiler; and
- the release tooling.

Do not build a customer release from uncommitted developer state.

## 10. Partitioning the Agent Workspace

### 10.1 Partition objective

The current `2nd-Proto` tree must produce two conceptual outputs:

1. An internal workflow source retained only in private development and build systems.
2. A customer capsule containing the smallest interface supported clients need.

The partition is not a copy-and-delete process performed manually at release time. It must be a
deterministic compiler with an allow-listed output inventory.

### 10.2 File ownership classes

Assign every source artifact one release class:

| Class | Meaning | Customer project |
|---|---|---|
| `compile` | Parsed and converted into Rust data, bytecode, or embedded resources | Not copied as source |
| `embed` | Compressed or encrypted resource read by `byo` | Not copied as plaintext |
| `public-template` | Minimal client-facing template | Rendered into project |
| `user-template` | Initial user-owned task artifact | Created only if absent |
| `developer-only` | Test, spec, CI, source helper, or release tooling | Never shipped |
| `forbidden` | Secret, cache, VCS state, credential, or unexpected output | Release fails |

No file may default to customer-visible merely because it exists.

### 10.3 Suggested mapping for `2nd-Proto`

The exact source inventory should be confirmed against the branch at implementation time, but the
intended mapping is:

| Current area | Release class | Destination |
|---|---|---|
| `internal/` Python implementation | `compile` or `developer-only` | Rust workspace runtime |
| `bin/attach-project` and setup wrappers | `compile` | `byo init` |
| `bin/doctor` | `compile` | `byo doctor` |
| `bin/codex-mode` and launch wrappers | `compile` | `byo mode` and client adapters |
| `hooks/` and hook runner | `compile` | `byo hook` |
| `modes/*.toml` | `compile` | Typed policy tables |
| `skills-src/` | Mostly `compile`/`embed`; one minimal bootstrap may be `public-template` | Workflow pack plus thin client skill |
| `templates/` | `embed` or `user-template` | In-memory render or create-if-absent |
| `.codex/` source policy | `compile` plus minimal `public-template` | Generated `.codex` projection |
| `.github/` | `developer-only` | None |
| `.vscode/` development settings | `developer-only`, unless a deliberate customer integration is approved | None by default |
| `tests/` | `developer-only` | None |
| internal specifications | `developer-only` | None |
| public capability and safety notices | `public-template` or product documentation | Minimal visible documentation |
| generated state | `forbidden` | None |
| VCS metadata | `forbidden` | None |
| credentials, tokens, local DBs, history | `forbidden` | None |

### 10.4 Customer capsule layout

The default capsule should be no larger than necessary:

```text
<project>/
├── .agent-workspace/
│   ├── manifest.json
│   ├── PLAN.md                 # optional user-owned task state
│   ├── HANDOFF.md              # optional user-owned task state
│   └── specs/                  # optional user-authored specifications
├── .generated/
│   └── byo/
│       ├── projection-manifest.json
│       └── active-mode.json
├── .codex/
│   └── <minimal managed projection>
├── .claude/
│   ├── settings.json          # exact BYO hook entries in a shared file
│   └── skills/
│       ├── byo-firmware/      # compatibility/safety bootstrap
│       └── <authorized-id>/   # one thin native Claude loader per packed skill
├── .agents/
│   └── <minimal managed projection>
└── <root instruction file with a small managed block, if required>
```

The presence of user-owned task files does not expose proprietary product implementation.

Each Codex and Claude loader carries a model-invocable packed skill's discovery description and
invocation controls, but not its private body. On selection it dynamically loads verified content
through `byo workflow guidance <skill-id>`. Skills with `disable-model-invocation: true` are not
projected into either client catalog. The MCP `initialization_handshake` remains a runtime safety
handshake; it is not responsible for registering filesystem skills.

### 10.5 Capsule manifest

Example:

```json
{
  "schema": 1,
  "product": "byo",
  "workspace_version": "2.0.0",
  "workflow_protocol": 1,
  "minimum_launcher": "1.4.0",
  "maximum_launcher": "1.x",
  "minimum_mcp_protocol": 1,
  "project_id": "01JABCDEFGHJKMNPQRSTVWXYZ",
  "mode": "firmware",
  "installed_at": "2026-07-23T00:00:00Z",
  "managed_inventory_sha256": "<digest>"
}
```

Do not include:

- installation secrets;
- license-signing keys;
- internal workflow names;
- private repository commit URLs;
- decrypted workflow content; or
- absolute global product paths.

### 10.6 Minimal bootstrap instructions

The visible agent instruction should state only the public contract:

```markdown
Use the BYO firmware MCP server for board setup, debugging, deployment,
serial communication, and recovery.

Begin each server run with `initialization_handshake`.
Follow the live tool schema and server-provided guidance.
Do not infer hardware authority from project files or prior sessions.
```

Avoid copying:

- the complete decision tree;
- all tool sequences;
- hidden recovery logic;
- internal mode-merging behavior;
- release implementation notes; or
- explanations of how safety enforcement is implemented.

### 10.7 Progressive workflow delivery

The runtime should supply only the fragment required for the current state:

```text
agent starts
    -> initialization_handshake
    -> server identifies current state
    -> server exposes or recommends the current valid action
    -> action result carries the next bounded handoff
```

Continue using:

- dynamic tool visibility;
- `tools/list_changed`;
- server-generated plan calls;
- continuation identifiers;
- per-run state; and
- server-owned safety gates.

Do not expose the complete internal workspace through an MCP `resources/list` or prompt catalog.

### 10.8 Workflow resource pack

The workspace compiler should produce:

```text
workspace.pack
├── header
├── version and compatibility record
├── indexed compressed resource records
├── typed mode-policy tables
├── workflow state-machine tables
├── minimal client templates
└── integrity table
```

The pack may be:

- embedded into the Rust binary with `include_bytes!`; or
- shipped as a separately signed, hash-bound file under the versioned runtime.

Embedding simplifies version binding. A separate pack allows independent workflow updates. For the
first release, prefer an embedded pack unless release cadence requires independent updates.

Compression is recommended. Optional encryption may be added after the partition and compiler are
working. Encryption with a key recoverable by the local application is DRM friction, not a
confidentiality guarantee.

### 10.9 Workspace compiler inputs

The compiler must accept:

- a clean `2nd-Proto` source tree;
- an explicit partition policy;
- the target public workflow protocol version;
- the supported client adapter versions;
- a release version; and
- a deterministic build timestamp policy.

It must reject:

- unclassified files;
- symlinks unless explicitly allowed and materialized safely;
- generated state;
- VCS metadata;
- credentials and known secret formats;
- absolute paths;
- source files referenced by no compiled resource;
- duplicate logical resource identifiers;
- conflicting mode definitions; and
- nondeterministic output ordering.

### 10.10 Example partition policy

Illustrative format:

```toml
schema = 1

[[rule]]
pattern = "internal/**"
class = "compile"

[[rule]]
pattern = "hooks/**"
class = "compile"

[[rule]]
pattern = "modes/*.toml"
class = "compile"

[[rule]]
pattern = "skills-src/**"
class = "embed"

[[rule]]
pattern = "templates/PLAN.md"
class = "user-template"

[[rule]]
pattern = "templates/HANDOFF.md"
class = "user-template"

[[rule]]
pattern = "tests/**"
class = "developer-only"

[[rule]]
pattern = "specs/**"
class = "developer-only"

[[rule]]
pattern = ".git/**"
class = "forbidden"

[[rule]]
pattern = "**/.env"
class = "forbidden"
```

Use a last rule that rejects anything unmatched. Never use an implicit `include all`.

### 10.11 Compiler output checks

Run these checks for every build:

1. Build the pack twice and compare hashes.
2. List all source inputs and their assigned classes.
3. List all customer-visible output paths.
4. Assert that no Python, shell, or PowerShell implementation source appears in the capsule.
5. Search the capsule and pack metadata for:
   - private repository paths;
   - developer usernames;
   - absolute build paths;
   - credentials;
   - signing identifiers not intended for customers;
   - internal issue references; and
   - debug-only wording.
6. Extract all embedded public templates in a test harness and validate their syntax.
7. Render every supported client adapter twice and assert idempotence.
8. Verify that the complete private workflow source is not reconstructable from a release inventory
   file accidentally included in the customer package.

### 10.12 User-owned versus vendor-owned capsule content

Suggested ownership:

| Path | Ownership |
|---|---|
| `.agent-workspace/manifest.json` | Vendor |
| `.agent-workspace/PLAN.md` | User after creation |
| `.agent-workspace/HANDOFF.md` | User after creation |
| `.agent-workspace/specs/**` | User unless a specifically public vendor spec is declared |
| `.generated/byo/**` | Vendor/generated |
| BYO-created skill directory | Vendor |
| Existing non-BYO skills | User |
| BYO managed block in root instructions | Shared |
| Existing content outside the block | User |
| `.firm/**` | Project/device evidence; never workspace-update-owned |

### 10.13 Managed block format

Use stable markers:

```text
<!-- BEGIN BYO MANAGED: agent-bootstrap v1 -->
<minimal generated content>
<!-- END BYO MANAGED: agent-bootstrap v1 -->
```

Rules:

- require at most one matching block;
- refuse malformed, nested, or overlapping markers;
- preserve line endings when practical;
- preserve all content outside the block byte-for-byte;
- back up before first modification;
- record the prior file hash and managed block hash;
- never “repair” an ambiguous shared file automatically; and
- remove only the exact managed block on uninstall.

## 11. Rust workspace runtime

### 11.1 Responsibilities

The Rust runtime replaces customer-facing Python Agent Workspace tooling:

- source-root and project-root resolution;
- capsule installation;
- client projection rendering;
- hook execution;
- mode resolution;
- compatibility enforcement;
- doctor checks;
- update migration;
- rollback;
- project registry;
- managed uninstall; and
- internal workflow resource access.

### 11.2 Suggested Rust crate structure

```text
launcher/
├── Cargo.toml
└── src/
    ├── main.rs
    ├── cli.rs
    ├── paths.rs
    ├── manifest.rs
    ├── signatures.rs
    ├── install/
    │   ├── global.rs
    │   ├── transaction.rs
    │   └── archive.rs
    ├── project/
    │   ├── root.rs
    │   ├── capsule.rs
    │   ├── ownership.rs
    │   ├── render.rs
    │   ├── doctor.rs
    │   └── uninstall.rs
    ├── clients/
    │   ├── codex.rs
    │   ├── claude.rs
    │   └── generic.rs
    ├── workflow/
    │   ├── pack.rs
    │   ├── mode.rs
    │   ├── hooks.rs
    │   └── state.rs
    ├── sidecar/
    │   ├── resolve.rs
    │   ├── launch.rs
    │   └── protocol.rs
    ├── update/
    │   ├── metadata.rs
    │   ├── download.rs
    │   └── rollback.rs
    └── commands/
        ├── init.rs
        ├── doctor.rs
        ├── mcp.rs
        ├── repair.rs
        ├── update.rs
        ├── status.rs
        └── uninstall.rs
```

### 11.3 Candidate dependency categories

Select and pin crates only after a security and maintenance review. Likely categories include:

- argument parsing;
- JSON and TOML serialization;
- semantic versions and version requirements;
- platform directory resolution;
- SHA-256;
- Ed25519 signature verification;
- safe ZIP or tar extraction;
- temporary directories;
- filesystem locks;
- atomic file replacement;
- secure credential storage when licensing requires it;
- HTTP with bounded timeouts and TLS;
- structured logging; and
- zeroization for transient licensing secrets.

Do not add a self-update framework without reviewing its signature, rollback, and key-rotation
model.

### 11.4 Production profile

An initial release profile may use:

```toml
[profile.release]
opt-level = "z"
lto = "fat"
codegen-units = 1
panic = "abort"
strip = "symbols"
debug = 0
```

Measure startup and update performance before fixing `opt-level = "z"` permanently. Keep private
symbols from the unstripped build or linker outputs in protected release storage.

### 11.5 Public command contract

Recommended commands:

```text
byo --version
byo paths
byo status [--project <path>]
byo init [--project <path>] [--mode firmware] [--dry-run] [--yes]
byo doctor [--project <path>] [--json]
byo mode <firmware|software> [--project <path>]
byo hook <hook-name> [internal hook arguments]
byo mcp serve [--project <path>]
byo workspace update [--project <path>] [--version <version>]
byo update [--version <version>|--channel <channel>]
byo repair [--project <path>] [--runtime <path>]
byo uninstall [--project <path>]
byo uninstall --purge [--project <path>]
byo uninstall --global
```

The uninstall modes are mutually exclusive. `--global` conflicts with
`--project` and `--purge`; `--purge` remains project-scoped. Do not expose the
superseded `--purge-data` or uninstall-specific `--yes` flags.

Unrestricted modes must use a separate explicit option:

```text
byo mode firmware-full --allow-full-access
```

Do not permit `--yes` alone to enable full access.

### 11.6 Exit codes

Define stable exit categories:

| Code | Meaning |
|---|---|
| `0` | Success |
| `2` | Invalid CLI usage |
| `10` | Project root invalid or ambiguous |
| `11` | Capsule conflict or modified vendor file |
| `12` | Client configuration conflict |
| `20` | Runtime missing |
| `21` | Runtime integrity failure |
| `22` | Runtime/workspace incompatibility |
| `23` | Signature failure |
| `30` | Sidecar launch failure |
| `31` | Doctor failure |
| `40` | Update unavailable or download failure |
| `41` | Update transaction rolled back |
| `50` | License or entitlement failure, if licensing is enabled |

The MCP launch path should keep human diagnostics on stderr and never print a banner to stdout.

## 12. Refactoring the Python MCP for a compiled sidecar

### 12.1 Core requirement

The Python server must become an explicitly configured application rather than an import-time
singleton that derives authority from the ambient working directory.

### 12.2 Add a sidecar command dispatcher

Create a minimal entry module with explicit subcommands:

```text
byo-mcp-sidecar serve --project-root <absolute-path>
byo-mcp-sidecar provider-worker
byo-mcp-sidecar collect-artifacts ...
byo-mcp-sidecar native-build ...
byo-mcp-sidecar pack-repair ...
byo-mcp-sidecar self-test
```

The dispatcher must parse the subcommand before importing modules that create server state.

Conceptual Python structure:

```python
def main() -> int:
    command = parse_minimal_command_line()

    if command.name == "provider-worker":
        return run_provider_worker()

    if command.name == "serve":
        config = validate_serve_config(command)
        app = create_server_application(config)
        return app.run_stdio()

    ...
```

### 12.3 Explicit project root

Replace:

```text
load current-directory .env
read BYO_MCP_ARTIFACT_ROOT
otherwise use cwd
```

with:

```text
validated --project-root supplied by the Rust launcher
```

Requirements:

- absolute after canonicalization;
- must exist and be a directory;
- must not be a filesystem root;
- must not be the user's home directory;
- capsule/project identity must match when a capsule exists;
- the selected path must not change identity during initialization;
- state roots are derived from this value, not from ambient environment; and
- no project `.env` is automatically loaded.

Refactor module-level roots such as pack, session, and artifact roots into an immutable application
configuration object passed to their owners.

### 12.4 Remove production `.env` loading

The current source loads:

```text
<current-working-directory>/.env
<source-checkout>/.env
```

Do not retain this behavior in the production sidecar. A cloned customer project must not be able
to redirect product state or executable selection through an ambient `.env`.

For development only, provide an explicit option such as:

```text
byo-mcp-sidecar serve --development-env <path>
```

Compile that option out of customer builds or require an unmistakable developer build marker.

### 12.5 Provider worker launch

The current worker launch uses:

```text
sys.executable -m pyocd_debug_mcp.adapters.provider_worker
```

That is unsafe to assume in a compiled standalone executable. In a Nuitka build, `sys.executable`
identifies the compiled program, not a customer-facing general Python interpreter.

Change the default worker command to spawn the sidecar executable as a multicall binary:

```text
<absolute-sidecar-path> provider-worker
```

The sidecar executable path must be:

- determined from the running executable, not `PATH`;
- canonicalized before use;
- inside the verified runtime directory;
- bound to the runtime manifest;
- passed as an explicit immutable application setting; and
- tested with spaces and non-ASCII characters in parent directories.

Continue to reserve worker stdout exclusively for the newline-framed worker protocol.

### 12.6 Helper commands

The current native-build command template contains `sys.executable -m ...`. Change customer-facing
guidance to invoke the public Rust launcher:

```text
byo build ...
```

or:

```text
byo internal native-build ...
```

The Rust process may then invoke the private sidecar subcommand by absolute path.

Do not expose the private sidecar location in agent guidance.

### 12.7 Environment policy

The Rust launcher should construct a minimal sidecar environment.

Preserve only required platform variables, for example:

- Windows system variables needed for process and DLL behavior;
- locale and encoding variables where required;
- temporary-directory variables;
- an allow-listed `PATH` if external debug tools are intentionally supported; and
- explicit BYO internal variables that carry no authority beyond validated arguments.

Remove or do not forward by default:

- API tokens;
- cloud credentials;
- client authentication variables;
- unrelated agent variables;
- project `.env` values;
- Python path injection variables;
- dynamic loader injection variables;
- debug/profiling variables; and
- unreviewed executable overrides.

Be careful on macOS and Linux with:

```text
PYTHONPATH
PYTHONHOME
LD_PRELOAD
LD_LIBRARY_PATH
DYLD_INSERT_LIBRARIES
DYLD_LIBRARY_PATH
```

Customer operation should ignore these unless a specifically supported integration requires them.

The native build helper is different: native builds often require project toolchain environment.
Document that boundary and scrub known credentials before inheritance. Log environment variable
names, never secret values.

### 12.8 Stdout and stderr contracts

| Sidecar mode | stdout | stderr |
|---|---|---|
| `serve` | MCP stdio protocol only | diagnostics |
| `provider-worker` | worker framing only | diagnostics |
| helper producing JSON | one documented JSON result | diagnostics |
| self-test | documented test output | diagnostics |

No imported dependency may print to protocol stdout. Retain the current provider-worker strategy
that duplicates the protocol descriptor and redirects ordinary stdout to stderr before importing
native provider code.

### 12.9 Server construction

Refactor from import-time global construction toward:

```python
@dataclass(frozen=True)
class ServerApplicationConfig:
    project_root: Path
    runtime_root: Path
    sidecar_executable: Path
    runs_root: Path
    environment_policy: EnvironmentPolicy
    build_version: str
    protocol_version: int


def create_server_application(config: ServerApplicationConfig) -> ServerApplication:
    ...
```

This makes tests able to instantiate isolated applications and prevents configuration from being
captured before CLI validation.

### 12.10 Sidecar self-test

`byo-mcp-sidecar self-test` should verify without hardware:

- required modules import;
- packaged JSON and schema data are readable;
- stdio modules initialize;
- process marker paths are writable;
- worker subcommand starts and completes its handshake;
- project-root configuration is honored;
- no Python source checkout is required;
- no current-directory `.env` is loaded;
- native libraries load;
- bundled package metadata is readable; and
- the executable version matches the runtime manifest.

## 13. Building the Python sidecar

### 13.1 Packaging choice

Use Nuitka standalone mode for the first production release. Nuitka documents that standalone,
onefile, and app modes can produce executables independent of a customer Python installation:

<https://nuitka.net/user-documentation/user-manual.html>

Prefer standalone over onefile initially because:

- dependencies remain in a stable signed directory;
- startup does not require unpacking an entire runtime for each process;
- provider workers can spawn the same stable executable;
- antivirus behavior is easier to diagnose;
- nested code signing is clearer;
- crash evidence maps to stable files; and
- the Rust installer already provides a single customer-facing command.

“Single public command” does not require “one physical file internally.”

### 13.2 Standardize the build interpreter

Select and pin one supported Python version for release builds. The Agent Workspace currently
targets Python 3.12, while the MCP package permits Python 3.10 or later. Standardizing the release
builder on Python 3.12 is reasonable if every dependency and target passes tests.

Record:

- exact Python distribution and version;
- `uv.lock` hash;
- Nuitka version;
- C compiler version;
- OS image identifier;
- architecture; and
- dependency wheel/source hashes.

### 13.3 Build sequence

Per target:

1. Start from a clean target-native runner.
2. Check out exact source commits.
3. Install the pinned build Python.
4. Perform a locked dependency sync.
5. Run all Python tests.
6. Run lint and type checks.
7. Build the sidecar in Nuitka standalone mode.
8. Review the Nuitka compilation report for missing dynamic imports and data files.
9. Run `self-test` from outside the source checkout.
10. Run MCP initialization and `tools/list` smoke tests.
11. Run provider-worker handshake tests.
12. Run hardware-in-the-loop tests on supported probe families.
13. Scan the output inventory.
14. Strip only after tests establish what symbols and libraries are required.
15. Save private debug artifacts.

### 13.4 Data files

At minimum, ensure package data such as:

```text
src/pyocd_debug_mcp/probe_families.json
```

is included and resolved relative to the compiled runtime rather than the source checkout.

Audit dependencies for:

- pyOCD target and probe data;
- USB backend libraries;
- certificates used for HTTPS;
- serial backend requirements;
- YAML support;
- MCP schema/runtime modules;
- dynamically imported provider modules; and
- platform-specific DLLs or shared objects.

Do not blindly include the entire development environment.

### 13.5 Illustrative build command

Treat this as a starting template, not a final copy-paste command:

```text
uv run --locked python -m nuitka \
  --mode=standalone \
  --output-dir=<target-output> \
  --output-filename=byo-mcp-sidecar \
  --include-data-file=src/pyocd_debug_mcp/probe_families.json=pyocd_debug_mcp/probe_families.json \
  <sidecar-entry-module>
```

Add explicit plugin/package inclusion only after examining Nuitka's report and testing the actual
probe backends. Keep all build options in version-controlled release configuration.

### 13.6 Sidecar output inventory

The release assembly step must permit only:

- the sidecar executable;
- required shared libraries;
- required package data;
- a sidecar metadata file;
- required license notices; and
- optional private-symbol references stored outside the customer archive.

Reject:

- `.py` and `.pyc` files unless an unavoidable dependency has been deliberately approved;
- tests;
- caches;
- build logs;
- compiler intermediate files;
- absolute-path manifests;
- `.env`;
- credentials; and
- developer configuration.

### 13.7 Native dependency testing

Test:

- at least one pyOCD-native debug probe path;
- serial port enumeration;
- a provider worker timeout and forced termination;
- worker restart after failure;
- pack parsing;
- HTTPS pack acquisition if that remains a product feature;
- ELF and HEX parsing;
- Windows Job Object cleanup;
- POSIX process-group cleanup; and
- systems without Python or `uv` installed.

### 13.8 Third-party tools and redistribution

The server can interoperate with probe utilities, USB libraries, vendor CLIs, toolchains, and
CMSIS-Packs. For every external component, classify it as:

- bundled and covered by the product manifest;
- discovered from an existing customer installation;
- downloaded on demand under an approved license;
- unsupported; or
- forbidden from automatic acquisition.

Requirements:

- review redistribution terms before bundling vendor tools or firmware packs;
- do not copy a developer-machine tool into a release merely because a test found it on `PATH`;
- resolve customer-installed tools through an explicit allow-listed adapter;
- validate executable type and expected publisher where the platform permits it;
- never persist a discovered executable as hardware or safety authority;
- keep vendor-tool installation separate from ordinary MCP startup;
- pin downloaded pack bytes by digest;
- record required license notices; and
- test behavior when every optional external tool is absent.

## 14. Rust-to-sidecar launch contract

### 14.1 Launch command

`byo mcp serve` resolves the active verified sidecar and executes:

```text
<sidecar-absolute-path> serve \
  --project-root <canonical-project-root> \
  --runtime-root <canonical-version-root> \
  --launcher-version <version> \
  --workflow-protocol <number>
```

Use a process API with an argument vector. Never construct a shell command string.

### 14.2 Protocol stream

For `byo mcp serve`:

- Rust stdin is inherited or piped directly to sidecar stdin;
- sidecar stdout is passed directly to Rust stdout without modification;
- sidecar stderr is passed through or structured into a separate diagnostic sink;
- Rust prints no status message to stdout;
- Rust does not prompt;
- signals and cancellation are forwarded;
- sidecar exit status is preserved or mapped to a documented launcher code; and
- launcher shutdown waits only within a finite cleanup bound.

### 14.3 Interactive failures

If the runtime is missing during MCP launch:

- print a concise diagnostic to stderr;
- exit nonzero;
- instruct the user to run `byo repair`; and
- never ask for a path on the MCP protocol stream.

Example stderr:

```text
BYO runtime 1.5.0 is missing or failed integrity verification.
Run `byo repair --project "<project>"` from a terminal.
```

### 14.4 Version handshake

The launcher should verify the sidecar manifest before launch. The sidecar should also expose its
compiled version through `self-test` and MCP initialization metadata.

Require agreement on:

- product version or declared compatibility range;
- sidecar protocol version;
- workflow protocol version;
- capsule schema;
- worker protocol version; and
- supported project state schema.

Never infer compatibility solely from filenames.

## 15. Release manifest and signature model

### 15.1 Release manifest

Example:

```json
{
  "schema": 1,
  "product": "byo",
  "version": "1.5.0",
  "channel": "stable",
  "platform": "macos",
  "architecture": "aarch64",
  "minimum_os": "<declared-version>",
  "launcher_protocol": 1,
  "sidecar_protocol": 1,
  "workflow_protocol": 1,
  "capsule_schema": 1,
  "created_at": "2026-07-23T00:00:00Z",
  "source": {
    "launcher_commit": "<commit>",
    "mcp_commit": "<commit>",
    "workspace_commit": "<commit>",
    "release_commit": "<commit>"
  },
  "files": [
    {
      "path": "byo",
      "sha256": "<digest>",
      "size": 123456,
      "kind": "launcher",
      "executable": true
    },
    {
      "path": "sidecar/byo-mcp-sidecar",
      "sha256": "<digest>",
      "size": 234567,
      "kind": "sidecar",
      "executable": true
    },
    {
      "path": "workflow/workspace.pack",
      "sha256": "<digest>",
      "size": 345678,
      "kind": "workflow",
      "executable": false
    }
  ]
}
```

Canonicalize the manifest before signing. Define canonicalization once and test it across
platforms.

### 15.2 Signature strategy

Use two layers:

1. Platform signing:
   - Developer ID and notarization on macOS;
   - Authenticode or Microsoft Artifact Signing on Windows;
   - package-manager or detached signatures on Linux.
2. Product manifest signing:
   - an offline or protected release signing key signs the canonical release manifest;
   - the launcher contains only the public verification key;
   - updates are installed only after signature and hash verification.

The product signing private key must never appear in:

- the launcher source;
- the compiled executable;
- CI logs;
- repository secrets readable by pull-request workflows;
- the Agent Workspace;
- the sidecar; or
- customer licensing material.

### 15.3 Key rotation

Design manifest schema support for:

- key identifiers;
- an active and next public key;
- signed key-rotation metadata;
- revocation metadata;
- minimum accepted release versions where rollback prevention is required; and
- emergency update disablement.

Do not hardcode one irreplaceable verification key with no transition path.

### 15.4 Build attestations

Generate provenance for final archives or the manifest containing their hashes. GitHub documents
artifact attestations as cryptographically signed build provenance and supports attaching SBOM
attestations:

<https://docs.github.com/en/actions/concepts/security/artifact-attestations>

Attestation supplements platform and product signatures; it does not replace them.

## 16. Global installation flow

### 16.1 Bootstrap script responsibilities

The user-facing `install.sh` or `install.ps1` must remain small. It should:

1. Detect supported OS and architecture.
2. Resolve an exact release version rather than executing an unpinned mutable payload.
3. Download the matching platform archive or installer over HTTPS.
4. Verify available platform signature and release checksums.
5. Run the signed Rust install flow.
6. Print the installed path and PATH status.
7. Avoid `sudo` by default.
8. Avoid evaluating downloaded shell text.

The shell script should not contain the full installation implementation.

### 16.2 Bootstrap trust caveat

A checksum downloaded from the same compromised endpoint as an archive does not independently
establish trust. Prefer:

- macOS signature and notarization verification;
- Windows Authenticode verification;
- signed Linux repository metadata or detached signatures;
- a version-pinned installer page;
- product-manifest verification inside an already authenticated launcher; and
- published build attestations.

For Linux script installation, document the exact verification available. Do not claim a detached
signature was checked when the required verifier was absent.

### 16.3 Installation transaction

The Rust installer should:

1. Acquire a global installation lock.
2. Resolve and validate the per-user product root.
3. Reject symlink/reparse redirection of the product root or staging directory.
4. Create a random staging directory under the same filesystem as the final version directory.
5. Extract the archive with strict path validation.
6. Verify the signed manifest.
7. Verify every file's type, size, and digest.
8. Reject unexpected files.
9. Set final permissions.
10. Run launcher and sidecar self-tests from staging.
11. Rename staging to `versions/<version>`.
12. Atomically update `current.json`.
13. Install or update the public PATH command.
14. Run `byo doctor --global`.
15. Retain the prior version for rollback.
16. Release the lock.

If any required step fails before `current.json` changes, remove only the validated staging
directory. If a post-switch check fails, restore the prior `current.json`.

### 16.4 Archive extraction rules

For every entry:

- reject absolute paths;
- reject drive-qualified Windows paths;
- reject `..`;
- reject NULs and invalid platform path forms;
- reject entries escaping the staging root after normalization;
- reject symlinks, hard links, device nodes, FIFOs, and reparse points unless explicitly required;
- reject duplicate normalized paths;
- reject case-colliding paths on case-insensitive platforms;
- enforce a total expanded-size limit;
- enforce a per-file size limit;
- require exact manifest membership;
- create files without following pre-existing links; and
- verify the final canonical path remains under staging.

### 16.5 PATH setup

Do not silently edit shell startup files.

Preferred behavior:

- Windows: offer an explicit user-level PATH update and record the prior value for uninstall.
- macOS/Linux: install to `~/.local/bin` and detect whether it is already on PATH.
- If PATH setup is required, print the exact one-line change and optionally apply it after
  confirmation.
- Never prepend writable runtime library directories to PATH.

`byo doctor --global` must report whether the command resolved by the current shell is the expected
signed launcher.

### 16.6 Hardware drivers and privileged host configuration

Normal product installation remains per user. If a probe requires a driver, udev rule, kernel
extension, or other privileged host configuration:

- detect the missing prerequisite;
- explain the exact device and requirement;
- keep the action outside MCP stdio;
- provide a separate terminal command or vendor-supported installer;
- require an operating-system privilege prompt at the moment it is needed;
- never run a general privileged shell script from project content;
- verify the publisher and source of a vendor installer;
- record what BYO changed so it can provide removal guidance; and
- continue to support nonprivileged probes without forcing the privileged path.

On Linux, do not silently write `/etc/udev/rules.d` from the normal per-user installer. On Windows,
do not silently replace USB drivers. Driver changes can affect unrelated devices and require a
separate product and legal review.

## 17. `byo init` project installation flow

### 17.1 Command behavior

Supported forms:

```text
byo init
byo init --project <path>
byo init --mode firmware
byo init --dry-run
byo init --yes
```

Running `byo` without `init` must not modify the current directory.

### 17.2 Project-root resolution

Resolution order:

1. Explicit `--project`.
2. Current directory.
3. Optional Git-root suggestion.

If a Git root differs from the current directory, display both and require confirmation unless the
target was explicit. Monorepos may intentionally initialize a subdirectory, so do not always force
the outermost Git root.

Reject:

- filesystem root;
- home directory;
- product installation directories;
- a path owned by another user when ownership can be determined;
- non-directory targets;
- target paths that change identity during preflight;
- unsafe symlink/reparse resolution; and
- ambiguous nested capsules unless a documented nesting mode exists.

### 17.3 Preflight inventory

Before writing, inspect:

- existing `.agent-workspace`;
- capsule version and manifest validity;
- `.codex`, `.claude`, `.agents`, and `.generated`;
- existing root instruction files;
- prior BYO managed blocks;
- user-authored skills occupying BYO projection names;
- current project registration;
- global runtime and workflow compatibility;
- write permissions;
- free disk space;
- Git ignore or local exclude policy;
- active BYO processes for the project; and
- whether unrestricted mode was previously selected.

### 17.4 Change preview

Interactive `byo init` should show:

```text
Project:        /absolute/project
Workspace:      install capsule 2.0.0
Mode:           firmware
MCP runtime:    1.5.0
Managed files:  6 create, 1 managed-block edit
User files:     preserved
.firm:          preserved
Full access:    disabled
```

`--dry-run` must generate the same plan without writing.

### 17.5 Project transaction

Use a same-filesystem staging area such as:

```text
<project>/.byo-staging-<random>/
```

or an adjacent safe staging directory when project policy forbids temporary root entries.

Transaction:

1. Acquire a project lock.
2. Revalidate the project identity after locking.
3. Create a backup inventory for files that may change.
4. Render the capsule into staging.
5. Render all client projections into staging.
6. Parse and validate rendered configuration.
7. Compute ownership metadata and hashes.
8. Move vendor-owned directories into final positions.
9. Apply shared managed-block edits atomically.
10. Create user templates only when absent.
11. Write the capsule manifest last within the project content transaction.
12. Register the project in global BYO state.
13. Run project doctor.
14. Commit the backup record as successful.
15. Remove staging.

If doctor fails, restore every modified target from the backup inventory and remove only files
created by this transaction.

### 17.6 Existing full source workspace

When `byo init` encounters the old full `.agent-workspace`:

- detect it through its positive inventory and metadata;
- never overwrite it in place;
- offer a migration plan;
- preserve PLAN, HANDOFF, and user-authored specifications;
- preserve non-overlapping project-authored skills;
- archive the old workspace under `.agent-backups/<timestamp>/` or another explicit backup root;
- install the minimal capsule;
- render new projections;
- run doctor; and
- retain the backup until the user explicitly cleans it.

Do not treat arbitrary files in the old workspace as safe to execute during migration.

### 17.7 Client adapters

Implement each client in a separate versioned adapter. An adapter must:

- know exactly which files it owns;
- preserve unknown user configuration;
- render only supported syntax;
- validate the rendered file with a real parser;
- support idempotent re-render;
- support uninstall;
- report unsupported client versions; and
- never grant trust or unrestricted permissions automatically.

Client configuration should invoke:

```text
byo mcp serve --project <client-appropriate-project-reference>
```

Project reference strategy is client-specific:

- use a workspace variable when the client supports a reliable one;
- use project-relative `.` only when the client guarantees project-root cwd;
- otherwise store an absolute path and make project repair update it after a move.

Do not assume one configuration format works for every MCP client.

### 17.8 Default mode

Default:

```text
firmware
```

Rules:

- ordinary workspace-write or client-equivalent sandbox;
- approvals enabled according to the client policy;
- no implicit full-access mode;
- no automatic trust acceptance;
- no automatic broad network permission; and
- no silent promotion from `firmware` to `firmware-full`.

Full mode requires:

- an explicit mode name;
- `--allow-full-access`;
- a clear disclosure;
- per-project recording;
- a prominent doctor warning; and
- a reversible command to return to safe mode.

## 18. Hooks and internal workflow execution

### 18.1 Hook projection

Visible client hook configuration should call only:

```text
byo hook <stable-hook-id>
```

Do not place Python hook source or shell logic in the project.

### 18.2 Hook input

Define a bounded JSON schema for every hook. Validate:

- maximum input size;
- encoding;
- required fields;
- allowed event names;
- path containment;
- timeout; and
- output size.

Ignore unknown fields only if the versioned schema explicitly allows forward compatibility.
Otherwise reject them.

### 18.3 Hook authority

Hooks must not:

- silently enable full mode;
- create hardware permission;
- rewrite `.firm` authority;
- execute arbitrary shell strings;
- download updates;
- mutate product installation state; or
- read secrets unrelated to their documented purpose.

### 18.4 Workflow state

Prefer:

- in-memory per-session state for authority;
- project-local generated state only for reproducible projection status;
- opaque continuation identifiers;
- explicit protocol versions; and
- deterministic transition tables.

Persisted workflow state must never substitute for live hardware validation or current permission.

## 19. Doctor design

### 19.1 Global doctor

Check:

- public `byo` resolution;
- launcher signature where supported;
- product root ownership and permissions;
- `current.json`;
- runtime manifest signature;
- file hashes and inventory;
- sidecar self-test;
- workflow pack parse and version;
- update lock health;
- stale staging directories;
- private runtime not present on PATH;
- configured update channel; and
- license status without printing secrets.

### 19.2 Project doctor

Check:

- project root identity;
- capsule schema and version;
- launcher, sidecar, workflow, and capsule compatibility;
- managed projection hashes;
- shared managed blocks;
- client config parseability;
- MCP command resolves to expected launcher;
- no old source workspace is active;
- user-owned files remain outside vendor ownership;
- `.firm` containment;
- safe mode versus full mode;
- no repo-local credentials or product runtime;
- render idempotence;
- capsule and global project registry agreement; and
- a sidecar MCP initialization smoke test with no hardware access.

### 19.3 Machine-readable output

`byo doctor --json` should return stable records:

```json
{
  "schema": 1,
  "status": "failed",
  "checks": [
    {
      "id": "runtime.manifest.integrity",
      "status": "passed"
    },
    {
      "id": "project.projection.codex",
      "status": "failed",
      "code": "projection_modified",
      "remedy": "Run `byo repair --project <path>`."
    }
  ]
}
```

Do not include credentials, full environment dumps, or private workflow content.

## 20. Update design

### 20.1 Separate update domains

Treat these versions independently:

- stable launcher;
- private sidecar runtime;
- workflow pack;
- capsule schema/templates; and
- project `.firm` schemas.

A product release may bundle them together, but compatibility metadata must not assume identical
version numbers.

### 20.2 Global update

`byo update`:

1. Acquires global lock.
2. Fetches signed channel metadata.
3. Selects an exact compatible platform artifact.
4. Downloads to cache with bounded size and timeout.
5. Verifies signature and digest.
6. Installs into a new version directory.
7. Runs staged self-tests.
8. Atomically updates `current.json`.
9. Runs global doctor.
10. Rolls back pointer on failure.
11. Keeps at least one known-good prior runtime.
12. Reports projects whose capsules require migration.

Never update the active sidecar directory in place.

### 20.3 Project workspace update

`byo workspace update`:

1. Refuses while a project MCP process is active unless a safe coordinated shutdown exists.
2. Reads capsule and ownership metadata.
3. Detects modified vendor-owned files.
4. Preserves user-owned PLAN, HANDOFF, and specifications.
5. Stages the new capsule and projections.
6. Runs migrations on copied state, not originals.
7. Validates client configuration.
8. Runs doctor against staging.
9. Atomically commits.
10. Rolls back all changed files on failure.

### 20.4 Compatibility policy

Use explicit ranges:

```text
launcher 1.5 supports:
  sidecar protocol 1
  workflow protocol 1..2
  capsule schema 1
```

Rules:

- launcher refuses a newer unknown manifest schema;
- sidecar refuses an unsupported workflow protocol;
- workspace update refuses to install a capsule requiring a newer launcher;
- launcher may offer an update remedy;
- downgrade that would lose state requires explicit confirmation; and
- `.firm` schema downgrade is not automatic.

### 20.5 Rollback

Global rollback switches `current.json` to a previously verified version. Project rollback restores
the exact backup inventory.

Do not roll back:

- hardware effects;
- firmware already flashed;
- user source changes;
- `.firm` evidence created by a valid later server; or
- external client actions.

Document that software rollback cannot reverse physical operations.

### 20.6 Runtime leases and concurrent sessions

A global update may install and select a new version while an existing MCP session is still using
the old version. It must not delete the old runtime until all known sessions release it.

Implement a runtime lease:

```json
{
  "schema": 1,
  "runtime_version": "1.5.0",
  "pid": 12345,
  "process_start_identity": "<platform-specific-identity>",
  "project_id": "<opaque-project-id>",
  "created_at": "<timestamp>"
}
```

Rules:

- create the lease before launching the sidecar;
- bind it to PID plus process-start identity, not PID alone;
- remove it after confirmed sidecar exit;
- let doctor classify stale leases through bounded identity checks;
- never kill a process merely because its PID appears in a stale file;
- garbage-collect a retired runtime only when no live lease references it; and
- retain at least one known-good version even when no lease exists.

Project capsule updates should normally refuse while that project's MCP lease is active. A global
runtime update can stage and switch new sessions without interrupting the old one.

### 20.7 Updating the public launcher

Updating private runtime versions is easier than replacing the public executable itself.

On macOS and Linux, stage a new launcher beside the old one, verify it, then use an atomic rename.
On Windows, a running executable may be locked. Use one of these reviewed patterns:

- a minimal stable bootstrap shim that selects a versioned launcher;
- a signed updater helper launched after the original process exits; or
- a verified pending-replacement record completed at the next invocation.

Requirements:

- never let an unverified helper replace the launcher;
- preserve a known-good launcher;
- verify the replacement after the switch;
- do not delete the currently executing file blindly;
- make interrupted replacement recoverable; and
- include launcher replacement in clean-machine and antivirus tests.

## 21. Repair and moved-install behavior

### 21.1 Missing runtime

`byo repair` should:

1. Inspect `current.json`.
2. Inspect known version directories.
3. Select only directories with valid signed manifests.
4. Offer verified candidates.
5. Optionally accept `--runtime <path>`.
6. Validate the supplied path and signature.
7. Update `current.json` atomically.
8. Run global and project doctor.

Never execute the first similarly named executable found by recursive search.

### 21.2 Public launcher moved

If the user manually moves the public launcher:

- it should discover product data through platform directories, not relative cwd;
- `byo paths` should show the resolved installation;
- if product data is absent, provide install/repair guidance; and
- do not silently adopt an adjacent unverified sidecar.

### 21.3 Project moved

The capsule moves with the project. On first command:

- compare recorded project identity and current canonical path;
- update only path-based client projections that need it;
- retain the stable project ID;
- update the global project registry;
- run doctor; and
- never interpret a move as permission to use a different `.firm`.

## 22. Uninstall design

### 22.1 Project uninstall

Default:

```text
byo uninstall [--project <path>]
```

Remove:

- vendor-owned capsule files;
- generated BYO state;
- vendor-owned client projections;
- exact BYO managed blocks;
- BYO entries in Claude's local MCP approval lists;
- empty BYO-created configuration shells and skill directories; and
- project registration.

Preserve:

- application source;
- user-authored skills;
- user configuration outside managed blocks;
- PLAN and HANDOFF unless the user explicitly requests removal;
- user-authored specifications;
- `.firm`;
- unrelated `.codex`, `.claude`, and `.agents` content; and
- backups unless cleanup was requested.

Report every preserved path.

Project purge is explicit:

```text
byo uninstall --purge [--project <path>]
```

It performs the default project uninstall and then deletes the allowlisted dedicated BYO roots,
including `.agent-workspace`, `.agent-backups`, `.firm`, `.generated/byo`, and BYO-owned skill
directories. It must preserve application source and unrelated content in shared `.claude`,
`.codex`, instruction, JSON, and TOML files. Recursive cleanup must reject symlinks, reparse points,
non-directory replacements, path escapes, and broad roots.

### 22.2 Global uninstall

`byo uninstall --global`:

- enumerates and preflights every registered project before changing project or PATH state;
- refuses before mutation if any registered path is missing, moved, unsafe, malformed, or has a
  modified vendor-owned projection, and reports every registered location with its status;
- deduplicates stale registry aliases that resolve to the same canonical project;
- applies project purge to every valid registered project before removing the shared product;
- preserves only project source and unrelated client configuration, not BYO project data;
- refuses while an MCP runtime lease is active and reports the registered project locations;
- removes the public PATH command only if it matches the recorded installation;
- restores PATH changes only if BYO recorded and still recognizes them;
- removes the complete resolved BYO data, state, configuration, cache, runtime, launcher, and locator
  footprint even when an installed runtime is corrupt;
- never recursively deletes an unresolved environment-variable path; and
- reports every project integration and product path removed in the uninstall receipt.

### 22.3 Purge

The destructive commands are `byo uninstall --purge` for one project and
`byo uninstall --global` for the entire installation. The command flag itself is the explicit
request; no second `--yes` confirmation is required. Both must use exact allowlists, reject broad
or unresolved roots, avoid following symlinks/reparse points, preserve unrelated content, make clear
that board profiles and captured evidence are deleted, and produce an uninstall receipt.

## 23. Security hardening checklist

### 23.1 Filesystem

- Canonicalize only with an explicit policy for non-existing final paths.
- Validate lexical path before filesystem resolution.
- Revalidate after creation.
- Use same-filesystem atomic replacement.
- Reject directory identity changes during transactions.
- Do not traverse symlinks during cleanup.
- Use allow-listed relative paths in archives and manifests.
- Lock global and project mutations.
- Preserve unrelated user content.
- Never recursively delete home, root, workspace root, or an unresolved variable.

### 23.2 Process execution

- Use exact argv.
- Never invoke through a shell for product internals.
- Resolve private executables by verified absolute path.
- Use finite timeouts.
- Own child process groups or Windows Job Objects.
- Close or explicitly assign stdin.
- Keep protocol stdout uncontaminated.
- Validate process identity before stale cleanup.
- Terminate only owned, identity-matching processes.

### 23.3 Environment

- Remove current-directory `.env` loading in production.
- Do not inherit Python path injection.
- Scrub secrets from sidecar and child environments.
- Allow-list executable override variables.
- Do not log values of credential-like variables.
- Separate native build inheritance from MCP server inheritance.
- Do not allow capsule files to configure global runtime paths.

### 23.4 Network

- Normal debug and hardware actions should not require updater network access.
- Keep update download code in the Rust launcher, not the MCP tool surface.
- Separate pack acquisition from ordinary runtime when practical.
- Pin downloaded packs by digest.
- Use bounded redirects, timeouts, sizes, and accepted schemes.
- Never send project source, serial output, or firmware artifacts to an update service.
- Document any licensing traffic separately.
- Treat “offline environment variables” as best effort, not an OS sandbox.

### 23.5 Secrets

- No credentials in project config.
- No credentials in capsule manifest.
- No signing private key in any customer artifact.
- Use OS credential storage for refresh tokens or activation secrets.
- Prefer signed, non-secret entitlement documents for offline feature claims.
- Redact tokens from logs and exception messages.
- Test crash reports and support bundles for secret leakage.

### 23.6 Logging

- stderr only during MCP execution;
- stable event identifiers;
- bounded log size and retention;
- no full environment;
- no secret values;
- no raw private workflow pack;
- project-relative paths where sufficient;
- clear opt-in for verbose diagnostics; and
- user review before creating a support bundle.

### 23.7 Opacity

- No plaintext MCP source in release.
- No full Agent Workspace source in project.
- No development specs or tests.
- Strip Rust and sidecar symbols after testing.
- Remove build paths.
- Use compressed embedded workflow resources.
- Deliver only state-relevant workflow fragments.
- Keep internal error details out of public results.
- Maintain private debug artifacts.

### 23.8 Licensing, if added

Use a signed entitlement:

```json
{
  "schema": 1,
  "customer": "<identifier>",
  "features": ["firmware"],
  "expires_at": "<timestamp-or-null>",
  "maximum_major_version": 1,
  "license_id": "<opaque-id>"
}
```

The launcher verifies it with an embedded public key. The private licensing key remains on the
licensing service or offline signing system.

Machine binding is optional and should be weighed against privacy and hardware-change support.
Never place a symmetric master key in the executable.

## 24. Platform packaging and signing

### 24.1 macOS

Required:

- build on macOS;
- sign every executable and relevant nested native component;
- enable hardened runtime for the distributed command-line executable;
- include secure timestamps;
- use Developer ID;
- package into a notarizable ZIP, PKG, or DMG;
- submit with `notarytool` or the Notary API;
- inspect the notarization log;
- staple the ticket where the container supports it;
- verify with `codesign`, `spctl`, and a clean-machine install; and
- test without a developer checkout or credentials.

Apple's current guidance requires Developer ID signing, hardened runtime, secure timestamps, and
notarization for directly distributed software:

<https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution>

Signing order:

1. Build and strip.
2. Sign nested sidecar executables and native libraries as required.
3. Sign the Rust launcher.
4. Assemble the outer package.
5. Sign the installer package when applicable.
6. Notarize the outer deliverable.
7. Staple.
8. Verify.

Do not modify signed files afterward.

Test USB/debug-probe access under hardened runtime before finalizing entitlements. Add only required
entitlements; do not broadly disable library validation without demonstrating a dependency need.

### 24.2 Windows

Required:

- build with the MSVC target;
- sign `byo.exe`;
- sign the sidecar executable and applicable shipped DLLs;
- timestamp signatures;
- sign the installer/archive format where supported;
- verify signatures after packaging;
- test user-level PATH modification and removal;
- test paths with spaces and non-ASCII characters;
- test antivirus/Defender behavior;
- test Job Object cleanup; and
- test on a clean non-developer machine.

Microsoft documents SignTool and recommends SHA-256 digest and timestamp algorithms:

<https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool>

Microsoft's current SmartScreen guidance explains that publisher and file reputation both matter
and recommends signing every release consistently:

<https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation>

Use Authenticode or Microsoft Artifact Signing according to company and release infrastructure.
Do not assume an EV certificate automatically bypasses SmartScreen.

### 24.3 Linux

Offer at least:

- a versioned `.tar.gz` or `.tar.zst`;
- SHA-256 checksums;
- a detached product signature;
- build provenance;
- documented manual verification;
- per-user script installation; and
- clean uninstall instructions.

Later add:

- signed `.deb`;
- signed `.rpm`;
- package repositories with signed metadata; and
- architecture-specific packages.

Test on the declared minimum glibc baseline. Build on a sufficiently old compatible distribution or
use a controlled manylinux-like policy appropriate for the compiled sidecar. Do not assume a binary
built on the newest runner works on older customer systems.

### 24.4 Release artifact naming

“Universal installer” means a consistent product flow, not one executable that runs on every
kernel and architecture. Publish unambiguous immutable artifacts:

```text
byo-1.5.0-windows-x86_64.zip
byo-1.5.0-windows-aarch64.zip
byo-1.5.0-macos-aarch64.zip
byo-1.5.0-macos-x86_64.zip
byo-1.5.0-linux-x86_64.tar.zst
byo-1.5.0-linux-aarch64.tar.zst
byo-1.5.0-checksums.txt
byo-1.5.0-release-manifests.zip
```

Use the same version in:

- filename;
- signed release manifest;
- launcher version output;
- sidecar self-test;
- update metadata; and
- release page.

Never replace an already published file while retaining its filename and version.

## 25. Release pipeline

### 25.1 Required order

```text
select source commits
    -> verify clean source
    -> locked dependency resolution
    -> source tests and static analysis
    -> compile workspace pack
    -> build Python sidecar
    -> build Rust launcher
    -> assemble unsigned runtime
    -> clean-room functional tests
    -> strip release artifacts
    -> save private symbols
    -> generate manifests and SBOM
    -> sign nested binaries
    -> package
    -> sign/notarize outer deliverables
    -> verify signatures
    -> test exact signed artifacts
    -> generate attestations
    -> publish immutable version
    -> update signed channel metadata
```

Signing occurs after all content-changing operations.

### 25.2 CI jobs

Recommended jobs:

1. `python-quality`
   - locked sync;
   - tests;
   - lint;
   - type checks;
   - generated plan-contract consistency.
2. `workspace-quality`
   - full private workspace tests;
   - source inventory;
   - render idempotence;
   - partition classification.
3. `workspace-compile`
   - deterministic pack;
   - capsule inventory;
   - leakage scan.
4. `rust-quality`
   - format;
   - clippy;
   - tests;
   - dependency audit;
   - unsafe-code review policy.
5. `sidecar-build-<target>`
   - target-native Nuitka build;
   - self-test;
   - worker test.
6. `assemble-<target>`
   - exact manifest;
   - inventory verification;
   - clean install/update/uninstall test.
7. `sign-<target>`
   - protected environment;
   - no pull-request secrets;
   - identity verification.
8. `signed-e2e-<target>`
   - exact downloadable artifact;
   - signature verification;
   - clean host.
9. `attest-and-publish`
   - SBOM;
   - provenance;
   - immutable upload;
   - signed channel metadata.

### 25.3 Protected release conditions

Release only from:

- protected tags;
- reviewed release workflow changes;
- a clean commit;
- successful required jobs;
- target-specific signing environments;
- least-privilege CI permissions; and
- manually approved production publication when appropriate.

Pull-request code must never gain access to production signing or notarization credentials.

### 25.4 SBOM and dependency records

Generate an SBOM covering:

- Rust dependencies;
- Python dependencies;
- bundled native libraries;
- the Python runtime;
- Nuitka;
- packaging tools; and
- installer dependencies.

Store full internal dependency records even if the public SBOM format is decided later. Review
licenses before commercial distribution.

## 26. Test strategy

### 26.1 Unit tests

Rust:

- path normalization;
- archive rejection;
- manifest canonicalization;
- signature verification;
- compatibility range evaluation;
- managed-block parsing;
- ownership merge;
- transaction rollback;
- project-root resolution;
- mode gating;
- current-pointer update;
- project registry;
- redaction.

Python:

- explicit config construction;
- no ambient `.env`;
- sidecar dispatch;
- worker argv;
- stdout isolation;
- project-root containment;
- runtime resource resolution;
- environment policy;
- sidecar version reporting.

Workspace compiler:

- every source classified;
- forbidden files rejected;
- deterministic output;
- template syntax;
- mode merge;
- resource indexing;
- no private path leakage.

### 26.2 Integration tests

- Rust launcher starts source-sidecar development build.
- Rust launcher starts compiled sidecar.
- MCP initialization succeeds.
- Dynamic tools list behaves correctly.
- Provider worker starts, replies, times out, and cleans up.
- Project `.firm` state is created only below selected root.
- Capsule render is idempotent.
- Existing user skill survives init and update.
- Conflicting managed skill is handled according to ownership metadata.
- Modified vendor file produces a conflict, not silent overwrite.
- Shared block preserves surrounding bytes.
- Runtime move invokes repair flow.
- Project move updates only path-dependent projections.
- Old full workspace migrates with user task state preserved.

### 26.3 Clean-machine matrix

For each required target:

1. No Python installed.
2. No `uv` installed.
3. No Rust installed.
4. Product path contains spaces.
5. User name contains non-ASCII characters.
6. Project path contains spaces.
7. Project is not a Git repository.
8. Project is inside a monorepo.
9. Existing `.codex`, `.claude`, and `.agents` content.
10. Read-only project failure.
11. Interrupted install.
12. Interrupted update.
13. Missing runtime after install.
14. Corrupted sidecar file.
15. Modified capsule projection.
16. Offline initialization.
17. Uninstall with preserved `.firm`.
18. Reinstall over preserved project state.

### 26.4 Hardware-in-the-loop

Test representative supported hardware for:

- probe discovery;
- connect and disconnect;
- validation gate;
- bounded memory read;
- guarded write refusal and success paths;
- flash planning;
- application flash;
- serial discovery and exchange;
- cancellation;
- provider timeout;
- process cleanup;
- server restart and required revalidation;
- destructive recovery disclosure without execution; and
- explicitly approved recovery in a controlled sacrificial test environment.

Never run destructive HIL tests on irreplaceable hardware.

### 26.5 Failure injection

Inject:

- power/process termination between staging and pointer switch;
- disk full;
- permission denied;
- antivirus file quarantine;
- signature mismatch;
- manifest file missing;
- directory replaced by symlink;
- runtime library deleted;
- current pointer truncated;
- project moved mid-render;
- client config malformed;
- provider worker protocol contamination;
- stale process marker;
- network timeout;
- update metadata rollback; and
- incompatible capsule/runtime versions.

Every case must end in either the prior known-good installation or a diagnosable fail-closed state.

### 26.6 Opacity tests

Automate:

- no `.py` files in customer artifacts unless approved;
- no `tests/` or internal `specs/`;
- no private repository URL unless deliberately public;
- no source checkout paths;
- no developer user names;
- no `.env`;
- no debug symbols in customer package;
- no full workflow text in capsule;
- minimal skill stays below a declared size/leakage budget;
- public errors contain no stack trace;
- workflow pack cannot be trivially treated as an ordinary source archive; and
- the agent's default project sandbox cannot directly read the global runtime path.

## 27. Implementation phases

### Phase 0: Freeze architecture and protocols

Deliver:

- architecture decision record;
- target matrix;
- version/protocol matrix;
- ownership model;
- project capsule schema;
- release manifest schema;
- public CLI contract;
- threat model;
- supported client list.

Exit criteria:

- no unresolved question about which component writes each path;
- no client config points directly to the Python sidecar;
- safe mode is the documented default; and
- `.firm` ownership is explicitly outside workspace updates.

### Phase 1: Refactor Python configuration

Deliver:

- explicit `ServerApplicationConfig`;
- explicit `--project-root`;
- no production current-directory `.env`;
- no import-time project authority;
- dependency owners receive roots through configuration;
- tests for two isolated project roots in one test process where practical.

Exit criteria:

- server runs from source through explicit config;
- changing cwd does not redirect an initialized server;
- project `.env` cannot change product root;
- existing safety tests pass.

### Phase 2: Create multicall sidecar

Deliver:

- `serve`;
- `provider-worker`;
- helper subcommands;
- self-test;
- executable-self-resolution;
- revised worker argv;
- stdout contracts.

Exit criteria:

- source-mode multicall executable passes;
- provider workers never use `sys.executable -m` in production mode;
- helper guidance no longer exposes a Python interpreter command;
- protocol stdout tests pass.

### Phase 3: Prove Nuitka standalone packaging

Deliver:

- one target first, preferably the primary development OS;
- version-controlled Nuitka configuration;
- compiled sidecar inventory;
- self-test;
- MCP smoke test;
- provider-worker test;
- one HIL probe test;
- no-source clean-machine test.

Exit criteria:

- no Python/`uv` dependency on the clean machine;
- no source checkout dependency;
- no unexpected plaintext source inventory;
- worker isolation still functions.

### Phase 4: Build Rust launcher skeleton

Deliver:

- CLI;
- platform paths;
- manifest verification;
- `byo paths`;
- `byo status`;
- `byo mcp serve`;
- sidecar environment and launch;
- global doctor.

Exit criteria:

- launcher starts compiled sidecar by verified absolute path;
- stdout remains protocol-clean;
- missing runtime points to terminal repair;
- runtime file corruption is detected before execution.

### Phase 5: Build workspace compiler

Deliver:

- source partition policy;
- full classification report;
- deterministic workflow pack;
- minimal capsule templates;
- leakage scan;
- public bootstrap skill;
- internal-versus-customer inventory tests.

Exit criteria:

- full `2nd-Proto` source is not copied to customer output;
- every source input is classified;
- output rebuild is deterministic;
- capsule contains no internal implementation source.

### Phase 6: Port project tooling to Rust

Deliver:

- `byo init`;
- renderer;
- mode resolution;
- hooks;
- doctor;
- managed ownership metadata;
- migration from full workspace;
- project uninstall.

Exit criteria:

- customer initialization needs no Python;
- repeated render is idempotent;
- user-authored content survives;
- failures roll back;
- full mode requires explicit separate authorization.

### Phase 7: Complete target matrix

Deliver:

- all required Rust builds;
- all required sidecar builds;
- platform path handling;
- clean-machine tests;
- HIL results per platform where hardware support differs.

Exit criteria:

- every advertised target passes the same behavioral contract;
- unsupported targets fail at download selection, not after partial install.

### Phase 8: Signing and installers

Deliver:

- macOS Developer ID and notarization;
- Windows signing;
- Linux detached signatures or signed packages;
- bootstrap scripts;
- signed manifest;
- private symbol retention;
- SBOM and provenance.

Exit criteria:

- exact downloadable artifact verifies;
- no post-sign mutation;
- clean-machine installation produces expected publisher identity;
- uninstall reverses recorded PATH changes.

### Phase 9: Updates, repair, and rollback

Deliver:

- signed channel metadata;
- versioned installation;
- `current.json`;
- `byo update`;
- `byo workspace update`;
- repair;
- rollback;
- stale staging cleanup.

Exit criteria:

- interrupted update leaves prior version runnable;
- corrupted candidate never becomes current;
- moved runtime is repaired only after signature verification;
- project update preserves `.firm` and user-owned files.

### Phase 10: Beta hardening

Deliver:

- telemetry decision and privacy review;
- support bundle;
- failure-injection results;
- security review;
- dependency/license review;
- performance measurements;
- installation documentation;
- incident and signing-key rotation runbooks.

Exit criteria:

- release checklist signed off by engineering and security;
- upgrade from beta candidate to next candidate is tested;
- uninstall and reinstall are tested on real customer-like systems.

## 28. Recommended first implementation slice

Do not begin with all installers simultaneously. Build a vertical slice:

1. Refactor explicit project configuration.
2. Add sidecar multicall entry.
3. Compile the sidecar for the primary development platform.
4. Build a small Rust launcher with:
   - `byo paths`;
   - `byo doctor --global`;
   - `byo mcp serve --project`;
   - manifest verification.
5. Create a hand-authored minimal capsule as a prototype.
6. Implement `byo init` for that capsule.
7. Configure one client.
8. Run a complete MCP and HIL session.
9. Move the runtime and test repair.
10. Update the capsule and test rollback.

Only after that vertical slice works should the team generalize the workspace compiler and
platform packaging.

## 29. Definition of done

### 29.1 Product install

- [ ] User downloads one platform-appropriate installer or invokes one minimal script.
- [ ] Normal installation needs no administrator privilege.
- [ ] `byo` resolves from a new terminal.
- [ ] Runtime manifest and platform signatures verify.
- [ ] No customer Python or `uv` is required.
- [ ] Sidecar self-test passes.
- [ ] Prior version can be restored.

### 29.2 Agent Workspace capsule

- [ ] Full `2nd-Proto` source is absent from the project.
- [ ] Capsule contains only declared public and user-owned files.
- [ ] Workflow logic is compiled or embedded.
- [ ] Hooks invoke `byo`, not source scripts.
- [ ] Mode policy is compiled.
- [ ] Bootstrap instruction is minimal.
- [ ] Existing client/project content is preserved.
- [ ] Render is idempotent.
- [ ] Safe mode is default.

### 29.3 MCP sidecar

- [ ] Sidecar is compiled standalone.
- [ ] MCP config references only `byo`.
- [ ] Explicit project root is required.
- [ ] Project `.env` is ignored.
- [ ] Worker launch uses sidecar multicall mode.
- [ ] Stdout is protocol-clean.
- [ ] Runtime resources resolve without source checkout.
- [ ] Current guardrail and HIL suites pass.

### 29.4 Updates and repair

- [ ] Signed update metadata is verified.
- [ ] Update is staged and atomic.
- [ ] Corruption prevents activation.
- [ ] Repair validates candidate runtime signatures.
- [ ] Project move is supported.
- [ ] Capsule migration preserves user state.
- [ ] `.firm` is never removed by ordinary update.

### 29.5 Release

- [ ] Binaries stripped after functional testing.
- [ ] Private symbols retained securely.
- [ ] macOS release signed, notarized, and verified.
- [ ] Windows release signed and verified.
- [ ] Linux checksums and signatures published.
- [ ] SBOM generated.
- [ ] Build provenance generated.
- [ ] Exact signed artifacts pass clean-machine tests.
- [ ] Installer, update, rollback, and uninstall receipts are archived.

## 30. Decisions that must remain explicit

Before GA, record final answers for:

- minimum Windows version;
- minimum macOS version;
- minimum Linux/glibc baseline;
- Intel macOS support duration;
- Windows ARM64 support;
- whether the workflow pack is embedded or independently updatable;
- whether workflow resources are encrypted after compilation;
- licensing model;
- update channels and rollback policy;
- supported MCP clients and exact adapter versions;
- whether `~/.local/bin` is the default on macOS;
- whether automatic update checks are enabled;
- telemetry and crash reporting;
- `.firm` backup policy;
- public SBOM scope;
- support period for capsule and sidecar protocol versions; and
- whether any proprietary workflow selection moves to a remote service.

Do not let these choices emerge accidentally from installer code.

## 31. External references

- Agent Workspace `2nd-Proto` branch:
  <https://github.com/JasonPeng2019/CodexClaudeWorkflow/tree/2nd-Proto>
- Agent Workspace installation source:
  <https://github.com/JasonPeng2019/CodexClaudeWorkflow/blob/2nd-Proto/INSTALL.md>
- Agent Workspace minimal-current specification:
  <https://github.com/JasonPeng2019/CodexClaudeWorkflow/blob/2nd-Proto/specs/SPEC-minimal-current-agent-workspace.md>
- Nuitka deployment manual:
  <https://nuitka.net/user-documentation/user-manual.html>
- Apple notarization:
  <https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution>
- Apple hardened runtime:
  <https://developer.apple.com/documentation/Security/hardened-runtime>
- Microsoft SignTool:
  <https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool>
- Microsoft SmartScreen reputation:
  <https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation>
- XDG Base Directory Specification:
  <https://specifications.freedesktop.org/basedir/0.8/>
- GitHub artifact attestations:
  <https://docs.github.com/en/actions/concepts/security/artifact-attestations>

## 32. Final recommended product shape

The intended release is:

```text
Customer sees:
  byo
  minimal .agent-workspace capsule
  minimal client projections
  public MCP contract
  clear safety disclosures

Customer does not receive as source:
  firmware MCP Python checkout
  full Agent Workspace
  internal workflow specifications
  hooks or render implementation
  mode-merging implementation
  tests and development tooling
  private symbols

Global runtime contains:
  signed and stripped Rust launcher
  compiled Python sidecar
  compiled/compressed workflow resource pack
  signed release manifest
```

This design gives BYO one stable command, preserves the current server's safety architecture,
removes customer runtime dependencies, makes the Agent Workspace substantially harder to inspect,
and keeps installation, update, repair, and uninstall behavior under one transactional owner.
