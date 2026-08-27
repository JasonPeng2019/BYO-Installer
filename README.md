# BYO Installer

BYO installs one verified, versioned firmware workspace and MCP runtime for
Codex and Claude, then projects the required integration into each firmware
project. End users do not need Python, Rust, `uv`, a source checkout, or
administrator access.

The current public build is the unsigned
[`v0.1.3-preview`](https://github.com/buh07/BYO-Releases/releases/tag/v0.1.3-preview).
It supports macOS 12+ on Apple silicon and Intel, Windows 10 22H2/11 on x86-64,
and Linux x86-64 with glibc 2.28+.

## Install

Choose your computer. Each block downloads the native archive, its SHA-256
receipt, and the separate installer from GitHub Releases, verifies the archive,
and performs an offline bundle installation.

### macOS — Apple silicon

```sh
curl -fLO https://github.com/buh07/BYO-Releases/releases/download/v0.1.3-preview/byo-0.1.3-macos-aarch64.zip
curl -fLO https://github.com/buh07/BYO-Releases/releases/download/v0.1.3-preview/byo-0.1.3-macos-aarch64.sha256
curl -fLO https://github.com/buh07/BYO-Releases/releases/download/v0.1.3-preview/install.sh
shasum -a 256 -c byo-0.1.3-macos-aarch64.sha256
xattr -d com.apple.quarantine ./byo-0.1.3-macos-aarch64.zip 2>/dev/null || true
sh ./install.sh --bundle ./byo-0.1.3-macos-aarch64.zip
```

### macOS — Intel

```sh
curl -fLO https://github.com/buh07/BYO-Releases/releases/download/v0.1.3-preview/byo-0.1.3-macos-x86_64.zip
curl -fLO https://github.com/buh07/BYO-Releases/releases/download/v0.1.3-preview/byo-0.1.3-macos-x86_64.sha256
curl -fLO https://github.com/buh07/BYO-Releases/releases/download/v0.1.3-preview/install.sh
shasum -a 256 -c byo-0.1.3-macos-x86_64.sha256
xattr -d com.apple.quarantine ./byo-0.1.3-macos-x86_64.zip 2>/dev/null || true
sh ./install.sh --bundle ./byo-0.1.3-macos-x86_64.zip
```

### Windows — x86-64

Run in PowerShell:

```powershell
Invoke-WebRequest https://github.com/buh07/BYO-Releases/releases/download/v0.1.3-preview/byo-0.1.3-windows-x86_64.zip -OutFile .\byo-0.1.3-windows-x86_64.zip
Invoke-WebRequest https://github.com/buh07/BYO-Releases/releases/download/v0.1.3-preview/byo-0.1.3-windows-x86_64.sha256 -OutFile .\byo-0.1.3-windows-x86_64.sha256
Invoke-WebRequest https://github.com/buh07/BYO-Releases/releases/download/v0.1.3-preview/install.ps1 -OutFile .\install.ps1
$expected = ((Get-Content .\byo-0.1.3-windows-x86_64.sha256 -Raw).Trim() -split '\s+')[0]
$actual = (Get-FileHash .\byo-0.1.3-windows-x86_64.zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected.ToLowerInvariant()) { throw "BYO archive SHA-256 mismatch" }
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Bundle .\byo-0.1.3-windows-x86_64.zip
```

### Linux — x86-64, glibc 2.28+

```sh
curl -fLO https://github.com/buh07/BYO-Releases/releases/download/v0.1.3-preview/byo-0.1.3-linux-x86_64.tar.gz
curl -fLO https://github.com/buh07/BYO-Releases/releases/download/v0.1.3-preview/byo-0.1.3-linux-x86_64.sha256
curl -fLO https://github.com/buh07/BYO-Releases/releases/download/v0.1.3-preview/install.sh
sha256sum -c byo-0.1.3-linux-x86_64.sha256
sh ./install.sh --bundle ./byo-0.1.3-linux-x86_64.tar.gz
```

The checksum command must report `OK`. These preview bundles are not signed or
notarized, so use the offline `--bundle` / `-Bundle` path shown above. Signed
network installation and automatic updates are not available yet.

Installation adds BYO to `PATH` automatically. On macOS/Linux, open a new
terminal after installation. On Windows, the installer refreshes the Windows
environment and makes `byo` available immediately when the installer is run
inline; restart other terminal apps that were already open.

## Initialize a project

Install Codex CLI or Claude Code separately. Then initialize every project that
should use BYO:

```sh
cd /path/to/your/firmware-project
byo init --dry-run
byo init
byo codex firmware
```

The dry run is optional. `byo init` creates the project capsule, registers the
project, configures both clients to launch the MCP server through
`byo mcp serve`, and runs the project health check. It also projects one thin
native skill loader for each model-invocable mode-authorized workflow into both
`.codex/skills` and `.claude/skills`. Each client can discover or invoke those
skills normally; the loader fetches the verified private body from the installed
workspace pack only when selected. Manual-only skills remain private.
Restart an already-open client after initialization. To launch Claude instead,
run `byo claude firmware`.

From another directory:

```sh
byo init --project /path/to/your/firmware-project
```

## Everyday commands

| Command | Purpose |
|---|---|
| `byo status` | Show the active runtime and current project |
| `byo paths` | Show resolved installation paths |
| `byo doctor` / `byo doctor --global` | Check project or product health |
| `byo modes` / `byo mode <name>` | List or select a project mode |
| `byo codex <mode>` / `byo claude <mode>` | Launch a managed client session |
| `byo workspace update` | Reapply managed files in one project |
| `byo update --dry-run` | Resolve a product update without installing it |
| `byo repair` | Verify the active runtime and reconstruct its launcher |
| `byo rollback` | Activate the previous verified runtime |

Available modes are `firmware`, `software`, and `research`, plus `-full`
variants that require `--allow-full-access`. Use full modes only in a trusted or
isolated environment.

`byo workspace update` changes one project's managed projection. `byo update`
changes the shared product runtime and requires a configured signed release
channel; the current unsigned preview has no public update channel.

## Uninstall

Close Codex or Claude sessions before removal.

There are three cleanup modes.

### Remove BYO integration from one project

```sh
cd /path/to/your/firmware-project
byo uninstall
```

Or from anywhere:

```sh
byo uninstall --project /path/to/your/firmware-project
```

This removes BYO-managed client integrations and unregisters the project. It
preserves the shared runtime, `.firm`, plans, handoffs, specifications, backups,
and unrelated client configuration. It also removes BYO from Claude's local MCP
approval lists and deletes empty configuration shells/directories left by the
integration.

### Purge one project

```sh
cd /path/to/your/firmware-project
byo uninstall --purge
```

Or use `byo uninstall --purge --project /path/to/project` from anywhere. This
performs the normal project uninstall and also deletes the dedicated BYO roots
created for that project, including `.agent-workspace`, `.agent-backups`,
`.firm`, `.generated/byo`, and BYO-owned skill directories. It preserves project
source and unrelated Codex/Claude files and settings.

### Uninstall BYO from the computer

```sh
byo uninstall --global
```

This preflights every unique registered project, applies project purge to each
one, then removes the launcher, installed runtimes, global data/state/config/cache
roots, and recorded PATH edits. The `--global` command is the explicit full-wipe
request; it does not take `--purge` or require a second `--yes` flag.

Global removal refuses while an MCP runtime lease is active or when any
registered project cannot be cleaned safely. The error lists every project path
and the failing location before project or PATH mutation. Duplicate stale
registry IDs for the same canonical project are deduplicated automatically.

| Operation | Removes | Preserves |
|---|---|---|
| `byo uninstall` | Current project's integration | Shared runtime and retained project working data |
| `byo uninstall --purge` | Current project's integration and dedicated BYO data | Project source and unrelated agent configuration |
| `byo uninstall --global` | Every registered project's BYO data plus all global BYO content | Unrelated project source and configuration only |

Every uninstall prints a receipt; add `--receipt <path>` to write it as JSON.
Downloaded archives, receipts, and installer scripts are not deleted
automatically.

## Installation model

| Platform | Launcher | Runtime data |
|---|---|---|
| macOS | `$HOME/.local/bin/byo` | `$HOME/Library/Application Support/BYO` |
| Linux | `$HOME/.local/bin/byo` | `${XDG_DATA_HOME:-$HOME/.local/share}/byo` |
| Windows | `$env:LOCALAPPDATA\BYO\bin\byo.exe` | `$env:LOCALAPPDATA\BYO` |

Add `--install-dir <absolute-path>` on macOS/Linux or
`-InstallDir <absolute-path>` on Windows to use a custom root. The root contains
`bin`, `data`, `state`, `config`, and `cache`.

Runtimes are immutable and versioned. Installing `0.1.3` beside `0.1.2`
activates the new runtime without overwriting rollback evidence; different
contents that reuse an installed version are deliberately refused.

## Develop and build

Release assembly requires Rust, Python 3.12, `uv`, a native C toolchain, and
clean AgentWorkspace and Firmware MCP checkouts at the exact commits in
[`release/source-lock.json`](release/source-lock.json).

Run the fast local quality checks:

```sh
cargo fmt --manifest-path launcher/Cargo.toml --check
cargo clippy --manifest-path launcher/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path launcher/Cargo.toml --locked
python3 release/scripts/test_compile_workspace.py
python3 release/scripts/test_verify_build_output.py
python3 release/scripts/test_build_release.py
sh -n install.sh
```

Build the native launcher, compiled sidecar, workspace pack, SBOM, archive, and
private symbols:

```sh
python3 release/scripts/build_release.py
```

The native build matrix is authoritative for the four advertised targets and
runs archive verification plus installed hardware-free end-to-end tests. Do not
publish a development archive as a signed production release.

## Reference

- [Complete architecture and installation design](install_guide.md)
- [Installer ↔ sidecar contract](docs/sidecar-contract.md)
- [Release architecture decisions](docs/decisions/README.md)
- [GA and release operations](docs/release/ga-checklist.md)
- [Hardware-in-the-loop harness](hil/README.md)
