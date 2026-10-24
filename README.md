# BYO Installer

BYO installs one verified, versioned firmware workspace and MCP runtime for
Codex and Claude, then projects the required integration into each firmware
project. End users do not need Python, Rust, `uv`, a source checkout, or
administrator access.

The current public build is the unsigned
[`0.1.8 preview`](https://github.com/JasonPeng2019/BYO-Installer/releases/tag/0.1.8).
It supports macOS 12+ on Apple silicon and Intel, Windows 10 22H2/11 on x86-64,
and Linux x86-64 with glibc 2.28+.

## Install

Choose your computer. Each block downloads the native archive, its SHA-256
receipt, and the separate installer from GitHub Releases, verifies the archive,
and performs an offline bundle installation.

### macOS — Apple silicon

```sh
curl -fLO https://github.com/JasonPeng2019/BYO-Installer/releases/download/0.1.8/byo-0.1.8-macos-aarch64.zip
curl -fLO https://github.com/JasonPeng2019/BYO-Installer/releases/download/0.1.8/byo-0.1.8-macos-aarch64.sha256
curl -fLO https://github.com/JasonPeng2019/BYO-Installer/releases/download/0.1.8/install.sh
shasum -a 256 -c byo-0.1.8-macos-aarch64.sha256
xattr -d com.apple.quarantine ./byo-0.1.8-macos-aarch64.zip 2>/dev/null || true
sh ./install.sh --bundle ./byo-0.1.8-macos-aarch64.zip
```

### macOS — Intel

```sh
curl -fLO https://github.com/JasonPeng2019/BYO-Installer/releases/download/0.1.8/byo-0.1.8-macos-x86_64.zip
curl -fLO https://github.com/JasonPeng2019/BYO-Installer/releases/download/0.1.8/byo-0.1.8-macos-x86_64.sha256
curl -fLO https://github.com/JasonPeng2019/BYO-Installer/releases/download/0.1.8/install.sh
shasum -a 256 -c byo-0.1.8-macos-x86_64.sha256
xattr -d com.apple.quarantine ./byo-0.1.8-macos-x86_64.zip 2>/dev/null || true
sh ./install.sh --bundle ./byo-0.1.8-macos-x86_64.zip
```

### Windows — x86-64

Run in PowerShell:

```powershell
Invoke-WebRequest https://github.com/JasonPeng2019/BYO-Installer/releases/download/0.1.8/byo-0.1.8-windows-x86_64.zip -OutFile .\byo-0.1.8-windows-x86_64.zip
Invoke-WebRequest https://github.com/JasonPeng2019/BYO-Installer/releases/download/0.1.8/byo-0.1.8-windows-x86_64.sha256 -OutFile .\byo-0.1.8-windows-x86_64.sha256
Invoke-WebRequest https://github.com/JasonPeng2019/BYO-Installer/releases/download/0.1.8/install.ps1 -OutFile .\install.ps1
$expected = ((Get-Content .\byo-0.1.8-windows-x86_64.sha256 -Raw).Trim() -split '\s+')[0]
$actual = (Get-FileHash .\byo-0.1.8-windows-x86_64.zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected.ToLowerInvariant()) { throw "BYO archive SHA-256 mismatch" }
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Bundle .\byo-0.1.8-windows-x86_64.zip
```

### Linux — x86-64, glibc 2.28+

```sh
curl -fLO https://github.com/JasonPeng2019/BYO-Installer/releases/download/0.1.8/byo-0.1.8-linux-x86_64.tar.gz
curl -fLO https://github.com/JasonPeng2019/BYO-Installer/releases/download/0.1.8/byo-0.1.8-linux-x86_64.sha256
curl -fLO https://github.com/JasonPeng2019/BYO-Installer/releases/download/0.1.8/install.sh
sha256sum -c byo-0.1.8-linux-x86_64.sha256
sh ./install.sh --bundle ./byo-0.1.8-linux-x86_64.tar.gz
```

The checksum command must report `OK`. These preview bundles are not signed or
notarized, so use the offline `--bundle` / `-Bundle` path shown above. Signed
network installation and automatic updates are not available yet.

Installation configures `PATH` for Windows, bash, zsh and fish. Other shells
receive manual setup instructions and the absolute launcher path. Unix profile
read or encoding errors stop the edit and preserve the original. Originals are
backed up under the private BYO state directory's `path-backups`; uninstall
reverses recorded blocks. Bash on macOS uses its first existing login profile
(or creates `.bash_profile`), zsh honors `ZDOTDIR`, and fish uses
`$XDG_CONFIG_HOME/fish/config.fish` (default `~/.config/fish/config.fish`).
Windows retains Unicode entries and the existing registry string type.
On macOS/Linux, open a new
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

Repeated initialization with unchanged projections keeps capsule timestamps and
does not create another backup. Changed files are backed up in private BYO state
under `project-backups`, outside the project; five ordinary snapshots are kept
per project location. Legacy workspace archives are retained for manual recovery.
Existing project-local `.agent-backups` history is left alone. Unreadable or
invalid-encoding user files stop initialization before replacement. Initialize
a copied project to give it an independent ID, registry entry and runtime leases.

The dry run is optional. `byo init` creates the project capsule, registers the
project, configures both clients to launch the MCP server through
`byo mcp serve`, and runs the project health check. It also projects one thin
native skill loader for each user-invocable mode-authorized workflow into both
`.agents/skills` and `.claude/skills`. The loader fetches the verified private
body from the installed workspace pack only when selected. A manual-only loader
retains `disable-model-invocation: true` and `user-invocable: true`, making it
available for explicit human invocation but not implicit model selection.
Codex receives the equivalent `agents/openai.yaml` policy; Claude uses the
loader frontmatter. If a user-owned skill already occupies a BYO loader path,
initialization refuses the collision without changing it; rename or remove that
skill before retrying.
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

Available modes are `firmware` and `firmware-full`. Selecting `firmware-full`
requires `--allow-full-access`; use it only in a trusted or isolated environment.

`byo workspace update` changes one project's managed projection. `byo update`
changes the shared product runtime and requires a configured signed release
channel; the current unsigned preview has no public update channel.

Updates and rollbacks keep project files on their previous complete projection
until the next `byo mcp serve`, advisory hook, or managed helper use. That use
refreshes the project automatically under the installation lock. Its mode,
full-access grant, PLAN/HANDOFF, `.firm`, user text and other client settings are
preserved. A changed permission policy needs an explicit `byo init --mode <mode>`
decision (and `--allow-full-access` when applicable). Stop active MCP sessions
before activation or a project refresh. A failed or interrupted refresh restores
its private snapshot before retrying. If user text changed after publication,
recovery preserves that text and the pending snapshot, names the file to
review/restore, and requires another retry. `byo doctor` remains a read-only check
and identifies projects awaiting refresh.

Managed text tolerates CRLF and terminal newlines. Owned JSON and Codex TOML
accept equivalent formatting/key order; TOML comments and quoting can change.
Commands, arguments, permissions, modes and skill instructions remain checked.
Duplicate keys refuse. New projects retain a hash-checked semantic baseline in
`.generated/byo/integrity.json`, independent of whether the old runtime is still
installed. Legacy byte-only records accept standard LF/JSON/TOML normalization;
an unusual old TOML layout may need its original owned section restored once.
For a meaningful-edit refusal, review and undo the named BYO-owned change or
restore the file from its matching `state/project-backups` snapshot (`byo paths`
shows state), retaining unrelated user settings, then run `byo workspace update`.
The dangerous-command guard checks its denylist and verified project mode even
when unrelated projections or runtime doctor checks fail; invalid commands and
unverifiable modes block with client exit code 2. Codex hook protocol support
remains unverified.

Update, rollback, repair and direct installation share the same activation
checks and restore the prior pointer, public launcher and locator if the selected
runtime fails its post-activation doctor. They refuse live runtime leases.
Project init, refresh, ordinary uninstall and runtime lease publication share
the installation lock; uninstall also checks the chosen project lease.

When switching runtimes, the selected embedded launcher must support automatic
refresh when existing projects are registered. Activation refuses an older
launcher before changing runtime/project state if that capability is absent. To roll back to a pre-refresh release, first
run `byo uninstall --project <path>` for each registered project, retry rollback,
then run that release's `byo init --project <path> --mode <previous-mode>` with
the prior full-access authorization if needed. Ordinary project uninstall keeps
PLAN/HANDOFF and `.firm`. Initial installs and empty registries need no capability
upgrade. Repairing or reinstalling the exact selected runtime remains supported.
Capable launchers run a read-only internal activation doctor under the parent
lock. An allowed pre-refresh target uses its legacy public doctor; that older
binary does not gain automatic project refresh or new locking behavior.

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

Local lightweight checks:

```sh
cargo fmt --manifest-path launcher/Cargo.toml --check
sh -n install.sh
```

Use GitHub Actions for compilation, test suites and complete native bundles:

```sh
gh workflow run build-matrix.yml --repo JasonPeng2019/BYO-Installer \
  --ref YOUR_TASK_BRANCH -f build_kind=contracts
gh workflow run build-matrix.yml --repo JasonPeng2019/BYO-Installer \
  --ref YOUR_TASK_BRANCH -f build_kind=bundle
```

The native build matrix is authoritative for the four advertised targets and
runs archive verification plus installed hardware-free end-to-end tests. Do not
publish a development archive as a signed production release.

Code-analysis staging supports the existing Windows x86_64, macOS aarch64/x86_64
and Linux x86_64 targets against the source pins and
[`release/analysis-tools.lock.json`](release/analysis-tools.lock.json). Supply its
local archives with `--analysis-input-dir` or `BYO_ANALYSIS_INPUT_DIR`; the builder
rebuilds static Cppcheck and selects the exact clangd resources without downloads.
Linux uses the pinned glibc 2.28 builder and measured GCC runtime inputs. macOS
uses matching native ARM or Intel runners and ships thin native images.
See [native analysis build and test instructions](docs/code-analysis-native-build.md)
for inputs, commands, artifact verification and the two-runner smoke test.
See the [pending analysis release notes](docs/code-analysis-release-notes.md) for
mandatory target-aware Cppcheck configuration, saved-file semantic query scope,
recovery steps and the measured Windows source-path limit. The previous Windows
delivery has its own acceptance record. Native build and runtime results for this
portability candidate must be established by its exact GitHub Actions receipts;
source implementation alone does not establish a passing native build.

## Reference

- [Complete architecture and installation design](install_guide.md)
- [Installer ↔ sidecar contract](docs/sidecar-contract.md)
- [Release architecture decisions](docs/decisions/README.md)
- [GA and release operations](docs/release/ga-checklist.md)
- [Hardware-in-the-loop harness](hil/README.md)
