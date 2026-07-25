# BYO

BYO installs a compiled firmware workspace and MCP server. You do not need
Python, Rust, `uv`, or a source checkout to use it.

## Install in three steps

1. From your BYO download link, download the archive and installer that match
   your computer:

| Computer | Archive | Installer |
|---|---|---|
| Mac with Apple silicon | `byo-0.1.0-macos-aarch64.zip` | `install.sh` |
| 64-bit Windows | `byo-0.1.0-windows-x86_64.zip` | `install.ps1` |
| 64-bit Linux | `byo-0.1.0-linux-x86_64.tar.gz` | `install.sh` |

2. Extract the downloaded file.
3. Install the extracted folder:

| Computer | Command |
|---|---|
| Mac with Apple silicon | `sh "$HOME/Downloads/install.sh" --bundle "$HOME/Downloads/byo-0.1.0-macos-aarch64"` |
| 64-bit Windows | `& "$HOME\Downloads\install.ps1" -Bundle "$HOME\Downloads\byo-0.1.0-windows-x86_64"` |
| 64-bit Linux | `sh "$HOME/Downloads/install.sh" --bundle "$HOME/Downloads/byo-0.1.0-linux-x86_64"` |

Then open your firmware project and run:

```sh
byo init
byo doctor
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
  byo-0.1.0-macos-aarch64.zip \
  "$byo_install_dir"
sh ./install.sh \
  --bundle "$byo_install_dir/byo-0.1.0-macos-aarch64"
```

To confirm that your Mac uses Apple silicon, run `uname -m`. The result should
be `arm64`.

### Windows x86_64

Requirements: Windows 10 22H2 or Windows 11 on an x64-based computer.

Example:

```powershell
Set-Location "$HOME\Downloads"
$Destination = Join-Path $env:TEMP ("byo-windows-install-" + [guid]::NewGuid())
Expand-Archive `
  -LiteralPath ".\byo-0.1.0-windows-x86_64.zip" `
  -DestinationPath $Destination `
  -Force
.\install.ps1 `
  -Bundle (Join-Path $Destination "byo-0.1.0-windows-x86_64")
```

### Linux x86_64

Requirements: a 64-bit x86 Linux distribution with glibc 2.28 or newer.

Example:

```sh
cd "$HOME/Downloads"
byo_install_dir="$(mktemp -d)"
tar -xzf \
  byo-0.1.0-linux-x86_64.tar.gz \
  -C "$byo_install_dir"
sh ./install.sh \
  --bundle "$byo_install_dir/byo-0.1.0-linux-x86_64"
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
projections. Client configuration starts the MCP server through
`byo mcp serve`; it never points directly at Python or the private sidecar.

The default mode is `firmware`. Full access requires an explicit command:

```sh
byo mode firmware-full --allow-full-access --project "$PWD"
```

## Common commands

```sh
byo paths
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

The current archive checksums are:

| Target | SHA-256 |
|---|---|
| macOS Apple silicon | `000f567b0e464f160e7cae2f0d214c80cf29f148dbd6c0f7137331766c539b8b` |
| Windows x86_64 | `37d03be0a571017edcc76d3f6044fc050d0feea4ff17703ba6ea4c7caf65d334` |
| Linux x86_64 | `1e54437880956ab8405cb240d6cd205f538a8dc8002a62ce6a0d41261c49888c` |

macOS:

```sh
shasum -a 256 "$HOME/Downloads/byo-0.1.0-macos-aarch64.zip"
```

Windows PowerShell:

```powershell
Get-FileHash `
  "$HOME\Downloads\byo-0.1.0-windows-x86_64.zip" `
  -Algorithm SHA256
```

Linux:

```sh
sha256sum "$HOME/Downloads/byo-0.1.0-linux-x86_64.tar.gz"
```

Do not install an archive if its calculated checksum differs from the value in
the table.

## Current development artifacts

All three current artifacts are version `0.1.0` and use the same source
revisions:

- Installer: `11175acaa87c0c80db6a661442edd2e23b178fd0`;
- AgentWorkspace: `82ff1ca9f74b93a85d09b0a072b4286f827d2309`; and
- Firmware MCP: `c1a3ed9491113a841c62730b71ce59372b580e34`.

Each target includes an extracted bundle, archive, checksum receipt, and
CycloneDX SBOM. Nuitka reports and native symbols are retained as private build
artifacts.

The macOS and Windows artifacts passed their installed hardware-free suites on
native GitHub-hosted runners. Linux was built and tested in the pinned glibc
2.28 environment; its maximum referenced glibc symbol version is
`GLIBC_2.28`.

These artifacts are development-unsigned. They are suitable for local
evaluation, but they are not production releases:

- the macOS archive is not Developer ID signed or notarized;
- the Windows executables are not Authenticode signed; and
- the Linux archive has no production detached signature.

Gatekeeper or SmartScreen may therefore display a warning. Do not redistribute
these files as production releases.

The V1 decision record also advertises macOS Intel support. An aligned Intel
artifact must complete the same signing and clean-machine gates before V1
publication.

## Test without changing normal user paths

On macOS or Linux, set an isolated product home before installing:

```sh
export BYO_HOME="$(mktemp -d)"
sh "$HOME/Downloads/install.sh" \
  --bundle "$HOME/Downloads/byo-0.1.0-linux-x86_64"
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
  --bundle "$HOME/Downloads/byo-0.1.0-linux-x86_64"
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
