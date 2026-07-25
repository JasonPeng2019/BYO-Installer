# BYO

BYO installs a compiled firmware workspace and MCP server. You do not need
Python, Rust, `uv`, or a source checkout to use it.

## Install in three steps

1. From your BYO download link, download the archive and installer that match
   your computer:

| Computer | Archive | Installer |
|---|---|---|
| Mac with Apple silicon | `byo-0.1.1-macos-aarch64.zip` | `install.sh` |
| Mac with an Intel processor | `byo-0.1.1-macos-x86_64.zip` | `install.sh` |
| 64-bit Windows | `byo-0.1.1-windows-x86_64.zip` | `install.ps1` |
| 64-bit Linux | `byo-0.1.1-linux-x86_64.tar.gz` | `install.sh` |

2. Extract the downloaded file.
3. Install the extracted folder:

| Computer | Command |
|---|---|
| Mac with Apple silicon | `sh "$HOME/Downloads/install.sh" --bundle "$HOME/Downloads/byo-0.1.1-macos-aarch64"` |
| Mac with an Intel processor | `sh "$HOME/Downloads/install.sh" --bundle "$HOME/Downloads/byo-0.1.1-macos-x86_64"` |
| 64-bit Windows | `& "$HOME\Downloads\install.ps1" -Bundle "$HOME\Downloads\byo-0.1.1-windows-x86_64"` |
| 64-bit Linux | `sh "$HOME/Downloads/install.sh" --bundle "$HOME/Downloads/byo-0.1.1-linux-x86_64"` |

Then open your firmware project and run:

```sh
byo init
byo doctor
byo codex firmware
# or:
byo claude firmware
```

That is all you need for a normal installation. Platform-specific instructions,
verification steps, and development information follow below.

## What BYO installs

BYO includes:

- a Rust command-line launcher;
- a compiled Python MCP sidecar;
- the deterministic `2nd-Proto` workflow pack; and
- small per-project integrations for Codex and Claude.

The installer places BYO in your user account. It does not require administrator
access and does not edit your shell profile automatically.

To choose where BYO and the compiled MCP server are installed, add
`--install-dir "/absolute/example/path"` on macOS or Linux, or
`-InstallDir "C:\example\BYO"` on Windows. The selected directory contains the
complete private runtime and its `bin` directory.

## Detailed installation

The examples below assume that you saved the archive and installer script in
your Downloads folder. Public signed release downloads have not been published
yet.

### macOS with Apple silicon

Requirements: macOS 12 or newer and a Mac with an Apple chip.

Example:

```sh
cd "$HOME/Downloads"
byo_install_dir="$(mktemp -d)"
ditto -x -k \
  byo-0.1.1-macos-aarch64.zip \
  "$byo_install_dir"
sh ./install.sh \
  --bundle "$byo_install_dir/byo-0.1.1-macos-aarch64" \
  --install-dir "$HOME/Applications/BYO"
```

To confirm that your Mac uses Apple silicon, run `uname -m`. The result should
be `arm64`.

### macOS with an Intel processor

Requirements: macOS 12 or newer and an Intel-based Mac.

Example:

```sh
cd "$HOME/Downloads"
byo_install_dir="$(mktemp -d)"
ditto -x -k \
  byo-0.1.1-macos-x86_64.zip \
  "$byo_install_dir"
sh ./install.sh \
  --bundle "$byo_install_dir/byo-0.1.1-macos-x86_64" \
  --install-dir "$HOME/Applications/BYO"
```

Run `uname -m` to confirm that the architecture is `x86_64`.

### Windows x86_64

Requirements: Windows 10 22H2 or Windows 11 on an x64-based computer.

Example:

```powershell
Set-Location "$HOME\Downloads"
$Destination = Join-Path $env:TEMP ("byo-windows-install-" + [guid]::NewGuid())
Expand-Archive `
  -LiteralPath ".\byo-0.1.1-windows-x86_64.zip" `
  -DestinationPath $Destination `
  -Force
.\install.ps1 `
  -Bundle (Join-Path $Destination "byo-0.1.1-windows-x86_64") `
  -InstallDir (Join-Path $HOME "Applications\BYO")
```

### Linux x86_64

Requirements: a 64-bit x86 Linux distribution with glibc 2.28 or newer.

Example:

```sh
cd "$HOME/Downloads"
byo_install_dir="$(mktemp -d)"
tar -xzf \
  byo-0.1.1-linux-x86_64.tar.gz \
  -C "$byo_install_dir"
sh ./install.sh \
  --bundle "$byo_install_dir/byo-0.1.1-linux-x86_64" \
  --install-dir "$HOME/Applications/BYO"
```

Run `uname -m` to confirm that the architecture is `x86_64`. Run
`ldd --version` to see the installed glibc version.

## After installation

The installer prints the BYO executable directory. Open a new terminal after
installation. If `byo` is still not found, add the reported directory to
`PATH`.

The default macOS and Linux location is:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

Initialize a project:

```sh
cd "$HOME/Projects/example-firmware"
byo init
byo doctor --project "$PWD"
byo status --project "$PWD"
```

`byo init` creates only the minimal project capsule and managed client
projections for both Codex and Claude. It preserves unrelated `AGENTS.md`,
`CLAUDE.md`, `.codex`, `.claude`, and `.mcp.json` content. Client
configuration starts the MCP server through `byo mcp serve`; it never points
directly at Python or the private sidecar.

List every installed mode:

```sh
byo modes
```

Launch either client in any mode:

```sh
byo codex firmware
byo claude software
byo codex research
byo claude research
```

Arguments after `--` are passed to the selected client:

```sh
byo codex research -- --model example-model
byo claude research -- --resume
```

The default initialization mode is `firmware`. Every `-full` mode requires
explicit authorization:

```sh
byo mode firmware-full --allow-full-access --project "$PWD"
byo codex research-full --allow-full-access
byo claude research-full --allow-full-access
```

For Claude, a full-mode launch selects `bypassPermissions`; use full modes only
inside an appropriately isolated or trusted environment.

## Common commands

```sh
byo paths
byo modes
byo doctor --global --json
byo workspace update --project "$PWD"
byo repair
byo rollback
byo uninstall --project "$PWD"
byo uninstall --global
```

Project uninstall preserves `.firm`, `PLAN.md`, `HANDOFF.md`, specifications,
and unrelated client configuration. Global uninstall refuses to proceed while
projects or live MCP leases remain.

## Verify the downloads

Download the `.sha256` receipt beside the archive and compare its recorded hash
with a locally calculated SHA-256. For example:

```sh
# macOS
shasum -a 256 "$HOME/Downloads/byo-0.1.1-macos-aarch64.zip"

# Linux
sha256sum "$HOME/Downloads/byo-0.1.1-linux-x86_64.tar.gz"
```

```powershell
# Windows PowerShell
Get-FileHash `
  "$HOME\Downloads\byo-0.1.1-windows-x86_64.zip" `
  -Algorithm SHA256
```

Do not install an archive if its calculated checksum differs from its receipt.

## Current development artifacts

Version `0.1.1` is built natively for macOS Apple silicon, macOS Intel, Windows
x86_64, and Linux x86_64. Every matrix job uses the same source revisions pinned
in `release/source-lock.json`.

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

## Test without changing normal user paths

On macOS or Linux, set an isolated product home before installing:

```sh
export BYO_HOME="$(mktemp -d)"
sh "$HOME/Downloads/install.sh" \
  --bundle "$HOME/Downloads/byo-0.1.1-linux-x86_64"
"$BYO_HOME/bin/byo" paths
```

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
