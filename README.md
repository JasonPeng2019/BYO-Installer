# BYO

BYO installs a compiled firmware workspace and MCP server for Codex and Claude.
Users do not need Python, Rust, `uv`, or a source checkout.

## Quick install

1. Download the archive, its `.sha256` receipt, and the installer for your
   computer. The installer is a separate file; extracting the archive does not
   create `install.sh` or `install.ps1`.

| Computer | Archive | Installer |
|---|---|---|
| Apple silicon Mac | `byo-0.1.1-macos-aarch64.zip` | `install.sh` |
| Intel Mac | `byo-0.1.1-macos-x86_64.zip` | `install.sh` |
| 64-bit Windows | `byo-0.1.1-windows-x86_64.zip` | `install.ps1` |
| 64-bit Linux | `byo-0.1.1-linux-x86_64.tar.gz` | `install.sh` |

2. Check the archive against its `.sha256` receipt.
3. Run the matching installer directly against the archive. These examples
   assume the archive and installer are in your Downloads folder:

On Windows, first resolve the Downloads folder without depending on a `HOME`
environment variable:

```powershell
$Downloads = Join-Path ([Environment]::GetFolderPath("UserProfile")) "Downloads"
```

| Computer | Command |
|---|---|
| Apple silicon Mac | `sh "$HOME/Downloads/install.sh" --bundle "$HOME/Downloads/byo-0.1.1-macos-aarch64.zip"` |
| Intel Mac | `sh "$HOME/Downloads/install.sh" --bundle "$HOME/Downloads/byo-0.1.1-macos-x86_64.zip"` |
| 64-bit Windows | `& (Join-Path $Downloads "install.ps1") -Bundle (Join-Path $Downloads "byo-0.1.1-windows-x86_64.zip")` |
| 64-bit Linux | `sh "$HOME/Downloads/install.sh" --bundle "$HOME/Downloads/byo-0.1.1-linux-x86_64.tar.gz"` |

Before running one of these commands, confirm that both paths exist. For
example, on macOS or Linux:

```sh
test -f "$HOME/Downloads/install.sh"
test -f "$HOME/Downloads/byo-0.1.1-macos-x86_64.zip"
```

On Windows:

```powershell
Test-Path -LiteralPath (Join-Path $Downloads "install.ps1") -PathType Leaf
Test-Path -LiteralPath (Join-Path $Downloads "byo-0.1.1-windows-x86_64.zip") -PathType Leaf
```

Every command should report success before installation. Retype the command if
a pasted line contains a marker such as `<200b>`; that marker represents an
unwanted zero-width character and is not part of any BYO path or option.

The offline bootstraps identify an archive from its contents, so a browser- or
tool-renamed download can still be installed. Keep the published filename until
after checking the `.sha256` receipt, because the receipt names the original
file.

4. Open a terminal in your firmware project and initialize both Codex and
   Claude. `byo init` now runs the health check automatically and prints a
   one-line result, so this is the whole setup:

```sh
byo init
byo codex firmware
# Or launch Claude:
byo claude firmware
```

That is the complete normal setup. If `byo` is not found in a new shell, re-run
`byo init --modify-path` to put its `bin` directory on `PATH` (recorded so
uninstall reverses exactly that), or add it yourself as described below.

## What the installer installs

Each archive contains:

- the native Rust `byo` launcher;
- the compiled Python MCP sidecar;
- the deterministic `2nd-Proto` workflow pack;
- schemas and release metadata; and
- project integrations for both Codex and Claude.

The installer validates the bundle, copies it into an immutable version
directory, creates a public `byo` launcher, records the selected installation
paths, and runs a global health check before succeeding. It requires no
administrator access and does not edit the user's shell profile.

Default locations are:

| Platform | Public launcher | Runtime data |
|---|---|---|
| macOS | `$HOME/.local/bin/byo` | `$HOME/Library/Application Support/BYO` |
| Linux | `$HOME/.local/bin/byo` | `${XDG_DATA_HOME:-$HOME/.local/share}/byo` |
| Windows | `$env:LOCALAPPDATA\BYO\bin\byo.exe` | `$env:LOCALAPPDATA\BYO` |

The compiled MCP executable is stored below the runtime data directory at
`versions/0.1.1/sidecar/byo-mcp-sidecar` on macOS and Linux, or
`versions\0.1.1\sidecar\byo-mcp-sidecar.exe` on Windows. Codex and Claude start
it through `byo mcp serve`; project configuration never points directly at the
private executable.

### Choose a custom installation directory

Add one option to the normal install command:

```sh
# macOS or Linux example
--install-dir "$HOME/Applications/BYO"
```

```powershell
# Windows example
-InstallDir (Join-Path ([Environment]::GetFolderPath("UserProfile")) "Applications\BYO")
```

The selected directory will contain `bin`, `data`, `config`, `state`, and
`cache`. The installer writes a locator beside the public launcher, so `byo`
continues to find a custom installation without requiring `BYO_HOME`.

## Supported computers

| Platform | Minimum | Confirm before downloading |
|---|---|---|
| Apple silicon Mac | macOS 12+ | `uname -m` prints `arm64` |
| Intel Mac | macOS 12+ | `uname -m` prints `x86_64` |
| Windows x86_64 | Windows 10 22H2 or Windows 11 | PowerShell reports OS architecture `X64` |
| Linux x86_64 | glibc 2.28+ | `uname -m` prints `x86_64`; check `ldd --version` |

## Verify the downloads

Verify the archive before extracting or installing it. The receipt contains the
expected SHA-256 and archive filename.

```sh
# Apple silicon Mac
cd "$HOME/Downloads"
shasum -a 256 --check byo-0.1.1-macos-aarch64.sha256

# Intel Mac: use byo-0.1.1-macos-x86_64.sha256 instead
```

```powershell
# Windows
$Downloads = Join-Path ([Environment]::GetFolderPath("UserProfile")) "Downloads"
Set-Location $Downloads
$Expected = ((Get-Content ".\byo-0.1.1-windows-x86_64.sha256").Trim() -split '\s+')[0]
$Actual = (Get-FileHash `
  ".\byo-0.1.1-windows-x86_64.zip" `
  -Algorithm SHA256).Hash
if ($Actual -ne $Expected) {
    throw "BYO archive checksum does not match its receipt"
}
```

```sh
# Linux
cd "$HOME/Downloads"
sha256sum --check byo-0.1.1-linux-x86_64.sha256
```

The command must report a successful match. Do not install an archive if it
does not.

## Detailed installation

The examples below use the default installation location and assume that the
archive, receipt, and installer script are in the user's Downloads folder.
Public signed releases have not been published yet.

### macOS with Apple silicon

Requirements: macOS 12 or newer and an Apple chip. Confirm that `uname -m`
prints `arm64`, then run:

```sh
cd "$HOME/Downloads"
sh "./install.sh" \
  --bundle "./byo-0.1.1-macos-aarch64.zip"
```

To install below `$HOME/Applications/BYO` instead, add
`--install-dir "$HOME/Applications/BYO"` to the final command.

### macOS with an Intel processor

Requirements: macOS 12 or newer and an Intel processor. Confirm that
`uname -m` prints `x86_64`, then run:

```sh
cd "$HOME/Downloads"
sh "./install.sh" \
  --bundle "./byo-0.1.1-macos-x86_64.zip"
```

To install below `$HOME/Applications/BYO` instead, add
`--install-dir "$HOME/Applications/BYO"` to the final command.

### Windows x86_64

Requirements: Windows 10 22H2 or Windows 11 on an x64 computer. Run in
PowerShell:

```powershell
$Downloads = Join-Path ([Environment]::GetFolderPath("UserProfile")) "Downloads"
Set-Location $Downloads
& ".\install.ps1" `
  -Bundle ".\byo-0.1.1-windows-x86_64.zip"
```

To choose a custom install root, add `-InstallDir` with an absolute path, for
example `(Join-Path ([Environment]::GetFolderPath("UserProfile"))
"Applications\BYO")`.

If local policy blocks the unsigned development installer, the user may choose
to allow scripts only in the current PowerShell process:

```powershell
Set-ExecutionPolicy `
  -Scope Process `
  -ExecutionPolicy Bypass
```

### Linux x86_64

Requirements: an x86-64 Linux distribution with glibc 2.28 or newer. Confirm
that `uname -m` prints `x86_64` and inspect the glibc version with
`ldd --version`, then run:

```sh
cd "$HOME/Downloads"
sh "./install.sh" \
  --bundle "./byo-0.1.1-linux-x86_64.tar.gz"
```

To install below `$HOME/Applications/BYO` instead, add
`--install-dir "$HOME/Applications/BYO"` to the final command.

## Put `byo` on `PATH`

By default the installer does **not** modify any shell profile — it prints the
public launcher directory and leaves `PATH` to you. To have installation put the
`byo` bin directory on `PATH` for you, pass the opt-in flag:

```sh
# macOS or Linux
./install.sh --bundle <byo-archive-or-extracted-bundle> --modify-path
```

```powershell
# Windows
./install.ps1 -Bundle <byo-archive-or-extracted-bundle> -ModifyPath
```

This appends a single marked block to the login shell's profile (`.zshrc` /
`.bashrc` / `.profile`) on macOS or Linux, or the `HKCU\Environment\Path` user
variable on Windows, and **records each edit** so that `byo uninstall --global`
reverses exactly what was added and nothing else. Open a new terminal
afterward. (The same edit is available post-install via `byo init
--modify-path`.)

To put `byo` on `PATH` manually instead — open a new terminal after
installation, and if `byo` is still not found, add the launcher directory to
`PATH`.

For the default macOS or Linux installation, update the current shell with:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

For the default Windows installation, update the current PowerShell process
with:

```powershell
$env:Path = "$env:LOCALAPPDATA\BYO\bin;$env:Path"
```

For a custom installation, add its `bin` directory instead—for example,
`$HOME/Applications/BYO/bin` on macOS or Linux, or
`$HOME\Applications\BYO\bin` on Windows. To make the change persistent, add it
to the user's shell profile or Windows user environment settings. The
installer does not modify either unless you pass `--modify-path`
(`-ModifyPath` on Windows).

Confirm the active product paths and runtime:

```sh
byo paths
byo doctor --global
```

## Initialize a project for Codex and Claude

Codex CLI and Claude Code must be installed separately and available on
`PATH`. BYO installs their workspace integrations, not the client programs.

Open a terminal in a project and preview the files BYO will manage:

```sh
cd "$HOME/Projects/example-firmware"
byo init --dry-run
byo init
byo doctor
byo status
```

`byo init` configures both Codex and Claude. It creates the minimal project
capsule and managed client projections while preserving unrelated `AGENTS.md`,
`CLAUDE.md`, `.codex`, `.claude`, and `.mcp.json` content. Both clients start
the compiled MCP server through `byo mcp serve`; they never point directly at
Python or the private sidecar.

Use `--project` to operate on a project other than the current directory:

```sh
byo init --project "$HOME/Projects/example-firmware"
byo doctor --project "$HOME/Projects/example-firmware"
```

## Select and launch a mode

BYO includes six modes:

| Mode | Full access | Intended use |
|---|---:|---|
| `firmware` | No | Guarded firmware development |
| `firmware-full` | Yes | Firmware work with full tool access |
| `software` | No | Guarded software development |
| `software-full` | Yes | Software work with full tool access |
| `research` | No | Guarded investigation and analysis |
| `research-full` | Yes | Research with full tool access |

Initialize directly in a nondefault mode or change an initialized project:

```sh
byo init --mode research
byo mode software
```

List the available modes and launch either client:

```sh
byo modes
byo codex firmware
byo claude firmware
byo codex research
byo claude research
```

Arguments after `--` are passed unchanged to the selected client:

```sh
byo codex research -- --model example-model
byo claude research -- --resume
```

Every `-full` mode requires an explicit acknowledgement:

```sh
byo mode firmware-full --allow-full-access
byo codex research-full --allow-full-access
byo claude research-full --allow-full-access
```

For Claude, a full-mode launch selects `bypassPermissions`. Use full modes only
in an appropriately isolated or trusted environment.

## Maintenance and diagnostics

Useful commands include:

```sh
byo paths
byo status
byo doctor --global --json
byo doctor
byo workspace update
byo repair
byo rollback
```

There are two different update verbs, and they act on different things:

- **`byo update` — update the product runtime.** This upgrades the global `byo`
  install shared by every project. It downloads and activates a
  cryptographically signed runtime from a configured release channel using an
  atomic version switch: the new version installs into its own directory,
  health checks run, and only then does the active pointer flip — so an
  interrupted or failed update always leaves the previous version runnable. Add
  `--dry-run` to resolve the target without installing, or `--clean` to also
  clear BYO's download cache and install staging after a successful switch.
  `--clean` never removes prior versions (kept for `byo rollback`) and never
  touches any project's `.firm`, `PLAN.md`, or `HANDOFF.md` — it is *not* a
  reinstall. The current development artifacts do not yet have a public update
  channel.
- **`byo workspace update` — update one project's workspace.** This refreshes a
  single project's managed Codex and Claude projections from the workflow pack
  in the runtime you *already* have installed. It only rewrites files under that
  project's `.agent-workspace/`; it does not fetch or change the global runtime.

Rule of thumb: `byo update` means "get a newer BYO"; `byo workspace update`
means "re-apply this project's workspace from the BYO I already have".

`byo repair` verifies the active runtime, reconstructs its public launcher if
needed, and reruns health checks. `byo rollback` activates the previous
installed and verified runtime.

### Windows MCP startup failure

Run `byo status` and check `runtime_version` before troubleshooting Codex.
BYO `0.1.0` on Windows did not preserve the Windows profile environment when
starting its compiled MCP sidecar, so the sidecar could close during the
`initialize` handshake even though installation succeeded. Install the
Windows `0.1.1` bundle, then run:

```powershell
$env:Path = "$env:LOCALAPPDATA\BYO\bin;$env:Path"
byo status
byo init
byo doctor
byo codex firmware
```

Do not continue if `byo status` still reports `0.1.0`.

## Uninstall

Remove BYO from a project before removing the product:

```sh
cd "$HOME/Projects/example-firmware"
byo uninstall
byo uninstall --global
```

Project uninstall removes only managed integrations. It preserves `.firm`,
`PLAN.md`, `HANDOFF.md`, specifications, and unrelated client configuration.
Global uninstall refuses to proceed while registered projects or live MCP
leases remain, and preserves your product data and configuration by default.

Every uninstall prints a receipt of exactly what was removed and what was
preserved; add `--receipt <path>` to also write it as JSON for your records.

To remove the global runtime along with its data, cache, and configuration,
first review the exact targets by running the command **without** `--yes`:

```sh
byo uninstall --global --purge-data
```

This prints the precise list of BYO roots that would be deleted and makes no
changes. Re-run with `--yes` to confirm the wipe (board profiles and captured
evidence may be unrecoverable):

```sh
byo uninstall --global --purge-data --yes
```

## Current development artifacts

Version `0.1.1` is built natively for macOS Apple silicon, macOS Intel, Windows
x86_64, and Linux x86_64. Every matrix job uses the same source revisions pinned
in `release/source-lock.json`.

When downloaded from GitHub Actions, each outer workflow artifact contains:

- `install.sh` and `install.ps1`; use the installer for the target computer;
- `dist/`, with the installable archive, `.sha256` receipt, extracted bundle,
  SBOM, and provenance; and
- `symbols/`, with private diagnostic symbols and the Nuitka compilation
  report.

Copy the matching installer plus the archive and receipt from `dist/` to the
example Downloads location used above. The `symbols/` files are not required
for installation.

Each target includes an extracted bundle, archive, checksum receipt, CycloneDX
SBOM, and source provenance. Nuitka reports and native symbols are retained as
private build artifacts. Each native job verifies the archive contract and runs
the installed hardware-free acceptance suite. The Linux job enforces the
declared glibc 2.28 build baseline.

These artifacts are development-unsigned. They are suitable for local
evaluation, but they are not production releases:

- the macOS archive is not Developer ID signed or notarized;
- the Windows executables are not Authenticode signed; and
- the Linux archive has no production detached signature.

Gatekeeper or SmartScreen may therefore display a warning. Do not redistribute
these files as production releases.

## Test in a temporary installation directory

On macOS or Linux, use `--install-dir` to keep a test installation separate
from the normal per-user locations. Point `--bundle` at the archive for the
current platform:

```sh
byo_test_root="$(mktemp -d)"
sh "$HOME/Downloads/install.sh" \
  --bundle "$HOME/Downloads/byo-0.1.1-linux-x86_64.tar.gz" \
  --install-dir "$byo_test_root"
"$byo_test_root/bin/byo" paths
```

On Windows, the equivalent option is
`-InstallDir "$HOME\Applications\BYO-Test"`.

## Build from source

The following commands use `$HOME/Projects/example-byo-installer` as an example
checkout location.

Release assembly requires:

- clean external checkouts at the exact commits in
  the repository's `source-lock.json`;
- the locked Firmware MCP environment, including its `build` dependency group;
- Rust and Cargo;
- Nuitka; and
- a target-native C toolchain.

Build the native launcher and sidecar:

```sh
cd "$HOME/Projects/example-byo-installer"
python3 ./release/scripts/build_release.py
```

Only after a successful full build, launcher- or workflow-only changes may
reuse the compiled sidecar:

```sh
cd "$HOME/Projects/example-byo-installer"
python3 ./release/scripts/build_release.py --reuse-sidecar
```

The build reports the exact output locations. It produces:

- `workspace-classification.json`;
- `workspace.pack`;
- `nuitka-compilation-report.xml`;
- the bundle, archive, checksum, and SBOM; and
- dSYM, PDB, or Linux debug files.

Run the installed hardware-free acceptance suite with:

```sh
cd "$HOME/Projects/example-byo-installer"
python3 ./release/scripts/test_installed_e2e.py \
  --bundle "$HOME/Downloads/byo-0.1.1-linux-x86_64"
```

## Updates and production signatures

Production launchers compile an Ed25519 public-key map into the Rust binary.
Production runtime manifests and channel documents are cryptographically
verified. Channel metadata includes signed sequence and expiration fields, and
the launcher rejects replay or same-sequence equivocation.

`byo update` permits only bounded HTTPS downloads, safe regular-file
extraction, matching signed digests, compatible native targets, and a signed
inner runtime manifest. Activation is versioned and atomic. A failed
post-switch doctor restores the previous verified runtime.

Build a production artifact only inside a protected signing environment:

```sh
export BYO_RELEASE_PUBLIC_KEYS='{"release-key-id":"<32-byte-public-key-hex>"}'
cd "$HOME/Projects/example-byo-installer"
python3 ./release/scripts/build_release.py \
  --production \
  --channel stable \
  --signing-key "$HOME/example-keys/release-private-key.pem" \
  --key-id release-key-id \
  --codesign-identity "Developer ID Application: …"
```

The production build fails closed when release keys or required platform
signing are absent. Windows uses a prepare, sign, and finalize sequence so
Authenticode is applied before the product manifest and deterministic ZIP are
finalized.

After uploading an immutable production archive, publish signed channel
metadata with the repository's `sign_channel.py` tool. The launcher can then
use:

```sh
byo update \
  --channel stable \
  --metadata-url https://releases.example/channel-stable.json
```

For a pinned network bootstrap, `install.sh` requires an exact version, HTTPS
base URL, and expected SHA-256. Linux also requires the release public key and
detached archive signature. `install.ps1` requires valid Authenticode
signatures.

## Stable exit categories

| Code | Category |
|---:|---|
| 0 | Success |
| 2 | Invalid CLI or hook-policy block |
| 10 | Invalid or ambiguous project root |
| 11 | Capsule or managed-file conflict |
| 12 | Client configuration conflict |
| 13 | Compiled workflow policy or tool failure |
| 20 | Runtime missing |
| 21 | Runtime integrity failure |
| 22 | Runtime or workspace incompatibility |
| 23 | Signature or signed-metadata failure |
| 24 | Installation transaction failure |
| 30 | Sidecar launch or nonzero sidecar exit |
| 31 | Doctor failure |
| 32 | Codex or Claude launch failure |
| 40 | Update unavailable or download failure |
| 41 | Update failed and rollback was attempted |
| 42 | Uninstall refusal or failure |
| 50 | Uncategorized internal failure |

## Release operations and remaining external gates

The repository contains the product decision records, operator instructions,
and final release checklist.

The workflows are intentionally not self-certifying. General availability
remains blocked until:

- repository rulesets and protected environments are active;
- Apple and Microsoft publisher identities are enrolled;
- native, clean-machine, and HIL runners are provisioned;
- real fixture identifiers and hashed firmware replace the HIL examples;
- all workflows pass on their actual target hosts; and
- an independent approver completes the GA checklist.
