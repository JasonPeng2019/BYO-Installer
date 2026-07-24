# BYO installer implementation

This workspace implements the Rust launcher, compiled Python MCP sidecar,
deterministic `2nd-Proto` workflow pack, and thin platform installers described
by `install_guide.md`.

## Current verified development artifact

The locally verified artifact is:

- target: macOS x86_64, macOS 10.15 or newer as reported by Nuitka;
- version: `0.1.0`;
- bundle: `release/dist/byo-0.1.0-macos-x86_64/`;
- archive: `release/dist/byo-0.1.0-macos-x86_64.tar.gz`;
- archive SHA-256:
  `1cc884ccca50bd83be92c96ffc8e9b502cf83bb4bdcb5b13d6c6f86b0c837dc7`;
- manifest SHA-256:
  `a46700034030903d11bd7652adb94d8a37f1d2e17a2bd0eb3b424b4703246b2c`;
- workflow-pack SHA-256:
  `94bd6509dbc7dbaa42673b45111999d488dbe5acb1bbfd4163a592f85ec31820`;
- Agent Workspace source: clean `2nd-Proto` commit `63c8906`;
- Firmware MCP source: clean `Proto-1-WIP` commit `79204cc`.

This is a development-unsigned bundle. It is suitable for local evaluation,
not redistribution. The bundle contains no `.py`, test, specification, hook
script, or Agent Workspace implementation source. It includes a deterministic
CycloneDX 1.6 SBOM at `sbom.cdx.json`.

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

- a clean `AgentWorkspace/` checkout on `2nd-Proto`;
- the locked Firmware MCP virtual environment;
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
- the extracted bundle, deterministic archive, checksum, and SBOM under
  `release/dist/`.

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

The production build fails closed if release keys or required macOS signing
identity are absent. Windows production assembly intentionally requires a
separate protected Authenticode job.

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

## Remaining GA gates

The implementation is not yet a universal signed release:

- required target-native builds and clean-machine tests remain for Windows
  x86_64, macOS Apple silicon, and Linux x86_64; Windows ARM64 and Linux ARM64
  remain optional/recommended targets from the guide;
- macOS signing/notarization, Windows Authenticode, Linux publication
  signatures, protected provenance attestations, and immutable channel hosting
  require release credentials and protected CI;
- no recognized debug probe was attached to this host, so compiled
  hardware-in-the-loop testing still requires an identified supported board,
  probe, firmware fixture, and explicit approval for destructive recovery;
- minimum supported OS/glibc versions, Intel macOS support duration, update
  channels, and other decisions listed in section 30 of `install_guide.md`
  still need product decisions;
- this top-level installer workspace is not itself a Git repository, so a
  production build cannot yet record launcher/compiler/release-tool commit
  identities or produce trustworthy repository provenance.

Do not publish this development bundle as GA until those gates are completed.
