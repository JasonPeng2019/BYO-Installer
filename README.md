# BYO installer implementation

This workspace implements the Rust launcher, compiled Python MCP sidecar,
deterministic `2nd-Proto` workflow pack, and thin platform installers described
by `install_guide.md`.

## Current local development artifact

The target-native local build is version `0.1.0` for macOS x86_64:

- bundle: `release/dist/byo-0.1.0-macos-x86_64/`;
- artifact: `release/dist/byo-0.1.0-macos-x86_64.zip`;
- private symbols and the Nuitka report:
  `release/symbols/byo-0.1.0-macos-x86_64/`;
- pinned AgentWorkspace: `7ece704289bb6fcc2ba3c1983ead118bd7eac52d`;
- pinned Firmware MCP: `2d42e02eb810a2a5cc0b4977107264dadaccaa31`.

This is development-unsigned and is for local evaluation, not redistribution.
The fresh Nuitka 2.8.9 build links the sidecar natively, passes its compiled
self-test, emits a CycloneDX 1.6 SBOM, and contains no Python/source or
development files. Product policy supports macOS 12 and later even when a
compiler reports that the binary itself has an older deployment floor.

## Install and use the current artifact

No Python, Rust, `uv`, or source checkout is required to use the assembled
bundle.

```sh
cd "/Users/benjaminhuh/Documents/GitHub/Embedded CLI/InstallerWork"
./install.sh --bundle release/dist/byo-0.1.0-macos-x86_64
```

The installer deliberately does not edit a shell profile. If `~/.local/bin`
is not already on `PATH`, add it in the new shell:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

Then initialize a firmware project:

```sh
cd /absolute/path/to/firmware-project
byo init
byo doctor --project "$PWD"
byo status --project "$PWD"
```

`byo init` installs only the minimal project capsule and managed client
projections. Codex MCP configuration invokes `byo mcp serve`; it never points
at Python or the private sidecar directly. The default mode is `firmware`.
Full access requires a separate explicit gate:

```sh
byo mode firmware-full --allow-full-access --project "$PWD"
```

Useful lifecycle commands are:

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
and unrelated client configuration. Global uninstall refuses while projects
or live MCP leases remain.

For an isolated test that does not touch normal per-user paths:

```sh
export BYO_HOME="$(mktemp -d /tmp/byo-home.XXXXXXXX)"
./install.sh --bundle release/dist/byo-0.1.0-macos-x86_64
"$BYO_HOME/bin/byo" paths
```

## Build from source

Release assembly requires:

- clean external checkouts at the exact commits in
  `release/source-lock.json`;
- the locked Firmware MCP environment including its `build` dependency group;
- Rust/Cargo;
- Nuitka and a target-native C toolchain.

Run a full build when Python or sidecar inputs changed:

```sh
python3 release/scripts/build_release.py
```

Only after a successful full build, launcher/workflow-only iterations may
reuse the compiled sidecar:

```sh
python3 release/scripts/build_release.py --reuse-sidecar
```

The full build writes:

- `release/build/workspace-classification.json`;
- `release/build/workspace.pack`;
- `release/build/nuitka-compilation-report.xml`;
- the extracted bundle, platform-explicit ZIP or tar.gz, checksum, and SBOM
  under `release/dist/`;
- dSYM/PDB/Linux debug files and the Nuitka report under `release/symbols/`.

Run the installed hardware-free acceptance suite with:

```sh
python3 release/scripts/test_installed_e2e.py \
  --bundle release/dist/byo-0.1.0-macos-x86_64
```

## Updates and signatures

Production launchers compile an Ed25519 public-key map into the Rust binary.
Production runtime manifests and channel documents are cryptographically
verified. Channel metadata has signed sequence and expiry fields; the launcher
persists the highest accepted sequence and rejects replay or same-sequence
equivocation.

`byo update` accepts only HTTPS downloads, bounded response/archive sizes,
safe regular-file extraction, matching signed digests, compatible native
targets, and a signed inner runtime manifest. Activation is versioned and
atomic. A failed post-switch doctor restores the previous verified runtime.
Live sessions hold PID-plus-process-start-identity leases, so updates do not
overwrite their runtime and project updates refuse while that project is live.

Build a production artifact only in a protected signing environment:

```sh
export BYO_RELEASE_PUBLIC_KEYS='{"release-key-id":"<32-byte-public-key-hex>"}'
python3 release/scripts/build_release.py \
  --production \
  --channel stable \
  --signing-key /protected/path/release-private-key.pem \
  --key-id release-key-id \
  --codesign-identity "Developer ID Application: …"
```

The production build fails closed if release keys or required platform signing
are absent. Windows uses a prepare/sign/finalize split so Authenticode is
applied before the signed product manifest and deterministic ZIP are created.

After uploading an immutable production archive, publish signed channel
metadata with `release/scripts/sign_channel.py`. The launcher can then use:

```sh
byo update --channel stable --metadata-url https://releases.example/channel-stable.json
```

For a pinned network bootstrap, `install.sh` requires an exact version, HTTPS
base URL, and expected archive SHA-256. Linux additionally requires the raw
Ed25519 public key and detached archive signature. `install.ps1` requires a
valid Authenticode launcher.

## Stable exit categories

| Code | Category |
|---:|---|
| 0 | success |
| 2 | invalid CLI or hook-policy block |
| 10 | invalid/ambiguous project root |
| 11 | capsule or managed-file conflict |
| 12 | client configuration conflict |
| 13 | compiled workflow policy/tool failure |
| 20 | runtime missing |
| 21 | runtime integrity failure |
| 22 | runtime/workspace incompatibility |
| 23 | signature or signed-metadata failure |
| 24 | installation transaction failure |
| 30 | sidecar launch or nonzero sidecar exit |
| 31 | doctor failure |
| 40 | update unavailable/download failure |
| 41 | update failed and rollback was attempted |
| 42 | uninstall refusal/failure |
| 50 | uncategorized internal failure |

## Release operation and remaining external gates

The decisions are in `docs/decisions/`; protected workflows implement native
builds, platform signing, clean machines, safe/destructive HIL, attestations,
immutable publication, and canary → beta → stable channel promotion. The
operator documents and final checklist are in `docs/release/`.

The workflows are intentionally not self-certifying. GA remains blocked until
the GitHub repository/rulesets/environments exist, Apple and Microsoft
identities are enrolled, the named native/clean/HIL runners are provisioned,
real fixture IDs and hashed firmware replace the HIL examples, all workflow
runs pass on their actual target hosts, and an independent approver completes
`docs/release/ga-checklist.md`.
