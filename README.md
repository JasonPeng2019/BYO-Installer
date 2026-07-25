# BYO

BYO installs a compiled firmware workspace and MCP server. You do not need
Python, Rust, `uv`, or a source checkout to use it.

## Install in three steps

1. From `release/dist/`, download the file that matches your computer:

| Computer | Download |
|---|---|
| Mac with Apple silicon | `byo-0.1.0-macos-aarch64.zip` |
| 64-bit Windows | `byo-0.1.0-windows-x86_64.zip` |
| 64-bit Linux | `byo-0.1.0-linux-x86_64.tar.gz` |

2. Extract the downloaded file.
3. Install the extracted folder:

| Computer | Command |
|---|---|
| macOS or Linux | `./install.sh --bundle "/path/to/extracted/byo-folder"` |
| Windows PowerShell | `.\install.ps1 -Bundle "C:\path\to\extracted\byo-folder"` |

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

The current files are development builds in `release/dist/`. Public signed
release downloads have not been published yet.

### macOS with Apple silicon

Requirements: macOS 12 or newer and a Mac with an Apple chip.

Run these commands from the installer workspace:

```sh
byo_install_dir="$(mktemp -d /tmp/byo-macos-install.XXXXXXXX)"
ditto -x -k \
  release/dist/byo-0.1.0-macos-aarch64.zip \
  "$byo_install_dir"
./install.sh \
  --bundle "$byo_install_dir/byo-0.1.0-macos-aarch64"
```

To confirm that your Mac uses Apple silicon, run `uname -m`. The result should
be `arm64`.

### Windows x86_64

Requirements: Windows 10 22H2 or Windows 11 on an x64-based computer.

Run these commands in PowerShell from the installer workspace:

```powershell
$Destination = Join-Path $env:TEMP ("byo-windows-install-" + [guid]::NewGuid())
Expand-Archive `
  -LiteralPath ".\release\dist\byo-0.1.0-windows-x86_64.zip" `
  -DestinationPath $Destination `
  -Force
.\install.ps1 `
  -Bundle (Join-Path $Destination "byo-0.1.0-windows-x86_64")
```

### Linux x86_64

Requirements: a 64-bit x86 Linux distribution with glibc 2.28 or newer.

Run these commands from the installer workspace:

```sh
byo_install_dir="$(mktemp -d /tmp/byo-linux-install.XXXXXXXX)"
tar -xzf \
  release/dist/byo-0.1.0-linux-x86_64.tar.gz \
  -C "$byo_install_dir"
./install.sh \
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
cd /absolute/path/to/firmware-project
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
shasum -a 256 release/dist/byo-0.1.0-macos-aarch64.zip
```

Windows PowerShell:

```powershell
Get-FileHash `
  .\release\dist\byo-0.1.0-windows-x86_64.zip `
  -Algorithm SHA256
```

Linux:

```sh
sha256sum release/dist/byo-0.1.0-linux-x86_64.tar.gz
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
CycloneDX SBOM under `release/dist/`. Nuitka reports and native private symbols
are under `release/symbols/`.

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
export BYO_HOME="$(mktemp -d /tmp/byo-home.XXXXXXXX)"
./install.sh --bundle "/path/to/extracted/byo-folder"
"$BYO_HOME/bin/byo" paths
```

## Build from source

Release assembly requires:

- clean external checkouts at the exact commits in
  `release/source-lock.json`;
- the locked Firmware MCP environment, including its `build` dependency group;
- Rust and Cargo;
- Nuitka; and
- a target-native C toolchain.

Build the native launcher and sidecar:

```sh
python3 release/scripts/build_release.py
```

Only after a successful full build, launcher- or workflow-only changes may
reuse the compiled sidecar:

```sh
python3 release/scripts/build_release.py --reuse-sidecar
```

The build writes:

- `release/build/workspace-classification.json`;
- `release/build/workspace.pack`;
- `release/build/nuitka-compilation-report.xml`;
- the bundle, archive, checksum, and SBOM under `release/dist/`; and
- dSYM, PDB, or Linux debug files under `release/symbols/`.

Run the installed hardware-free acceptance suite with:

```sh
python3 release/scripts/test_installed_e2e.py \
  --bundle "/path/to/extracted/byo-folder"
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
python3 release/scripts/build_release.py \
  --production \
  --channel stable \
  --signing-key /protected/path/release-private-key.pem \
  --key-id release-key-id \
  --codesign-identity "Developer ID Application: …"
```

The production build fails closed when release keys or required platform
signing are absent. Windows uses a prepare, sign, and finalize sequence so
Authenticode is applied before the product manifest and deterministic ZIP are
finalized.

After uploading an immutable production archive, publish signed channel
metadata with `release/scripts/sign_channel.py`. The launcher can then use:

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

Product decisions are under `docs/decisions/`. Operator instructions and the
final release checklist are under `docs/release/`.

The workflows are intentionally not self-certifying. General availability
remains blocked until:

- repository rulesets and protected environments are active;
- Apple and Microsoft publisher identities are enrolled;
- native, clean-machine, and HIL runners are provisioned;
- real fixture identifiers and hashed firmware replace the HIL examples;
- all workflows pass on their actual target hosts; and
- an independent approver completes `docs/release/ga-checklist.md`.
