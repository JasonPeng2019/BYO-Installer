# Native analysis build and test

The supported release targets are `windows-x86_64`, `macos-aarch64`,
`macos-x86_64` and `linux-x86_64`. The Python sources are shared. Target-specific
runtime validation, executable formats, process ownership, native analyzer
staging and archive verification implement the platform differences. Both the
Rust firmware runner and the managed Python companion use packaged Cppcheck;
the five MCP semantic tools use packaged clangd.

## Build on GitHub Actions

Use the existing native build matrix on a task branch containing the complete
candidate. `contracts` compiles and tests the Rust launcher and runs release
script contracts on all four native targets. It does not assemble a bundle.
`bundle` additionally builds Cppcheck, the launcher and compiled Python sidecar,
assembles the workspace, analyzer data, SBOM and archive, then validates the
archive and runs installed hardware-free E2E.

```sh
gh workflow run build-matrix.yml --repo JasonPeng2019/BYO-Installer \
  --ref YOUR_TASK_BRANCH -f build_kind=contracts
gh workflow run build-matrix.yml --repo JasonPeng2019/BYO-Installer \
  --ref YOUR_TASK_BRANCH -f build_kind=bundle
gh run list --repo JasonPeng2019/BYO-Installer --branch YOUR_TASK_BRANCH
```

Use `gh run view RUN_ID --log-failed` to diagnose a failed job and
`gh run download RUN_ID` to obtain its artifacts. Preserve the run URL, exact
installer commit, `release/source-lock.json`, target, archive SHA-256 and verifier
receipts when reporting a result. A source contract pass is separate evidence
from a bundle build or an installed test pass.

The matrix uses separate Apple silicon and Intel macOS runners, Windows x86_64,
and a digest-pinned manylinux glibc 2.28 container on a Linux runner. The builder
requires a matching native host; Rosetta and cross compilation do not substitute
for the Intel macOS build. macOS images are thinned to the selected CPU with a
macOS 12 deployment target. Linux ELF dependencies and required GLIBC versions
are checked against the glibc 2.28 baseline.

The private AgentWorkspace checkout requires the existing
`BYO_SOURCE_READ_TOKEN` Actions secret with read access to
`JasonPeng2019/CodexClaudeWorkflow`. Source commits must be reachable on GitHub.
These development workflows produce unsigned artifacts. Release signing and
publication use separate protected workflows and are not part of this test.

## Inputs and native recipe

The exact external source commits are in `release/source-lock.json`; check them
out cleanly as `AgentWorkspace` and `Firmware MCP New` below the installer root.
The exact analyzer sources, archive hashes, recipe and data/resource inventory
are in `release/analysis-tools.lock.json`. Input preparation is separate from
the offline builder:

```sh
python3 release/scripts/acquire_analysis_inputs.py \
  --expected-target TARGET --output /absolute/fresh/analysis-inputs
```

The helper downloads only the selected target's pinned HTTPS archives, verifies
their SHA-256 before publishing each file and refuses to overwrite a mismatched
existing input. It can reuse matching archives. The build receives the prepared
directory through `--analysis-input-dir` or `BYO_ANALYSIS_INPUT_DIR`; it never
downloads analyzer sources itself.

Native build prerequisites are Rust 1.97.1, Python 3.12, `uv`, CMake 3.22 or
newer and a native C/C++ toolchain. macOS also needs Xcode command-line tools and
`lipo`; Linux needs Make, binutils and `patchelf`. The Actions workflow is the
authoritative setup, including pinned build environments and dependencies.

Linux builds require exactly glibc 2.28, the selected GCC compiler's static
`libstdc++.a`, `libgcc.a` and participating `libgcc_eh.a`, and matching GCC notices.
The matrix measures its selected compiler and archives, locates the corresponding
RPM package/source reference and notices, then prepares:

```sh
python3 release/scripts/prepare_gcc_runtime_inputs.py \
  --compiler /absolute/path/to/g++ --notices /matching/gcc/notices \
  --package ACTUAL_COMPILER_PACKAGE --source ACTUAL_SOURCE_REFERENCE \
  --output /absolute/fresh/analysis-inputs/gcc-runtime
```

`gcc-runtime` contains `COPYING3`, `COPYING.RUNTIME` and `provenance.json`.
The builder checks measured compiler/library identities and actual linker-map
participation; supplied labels alone do not establish provenance. The protected
Linux release workflow requires `vars.BYO_GCC_RUNTIME_INPUT_DIR` pointing to
these prepared inputs for its selected compiler.

For a native developer reproducing a build on their own machine, the assembly
command is:

```sh
uv sync --project "Firmware MCP New" --locked --all-groups
uv run --project "Firmware MCP New" python release/scripts/build_release.py \
  --analysis-input-dir /absolute/analysis-inputs \
  --build-dir /absolute/fresh/build --output /absolute/fresh/dist
```

Use a short Windows build path for MSVC/Nuitka. Use fresh build/output paths to
preserve previous evidence. No local build or heavy test is required on the
coordinator's Windows PC; use Actions for those checks.

## Verify an artifact and both runners

The bundle matrix verifies target, archive type, native executable/dependency
closure, data/resources, licenses, modes, namespace, digests and SBOM against the
final delivered bytes. Its archive-only verifier can also be run by a native
tester against a downloaded archive:

```sh
python3 release/scripts/verify_build_output.py analysis-archive \
  --expected-target TARGET --archive /absolute/archive \
  --receipt /absolute/new/archive-receipt.json
```

The preserved `windows-analysis-archive` command is a Windows-only compatibility
alias. Installation consumes the expanded bundle directory through the existing
`byo install-runtime --bundle DIR` protocol. The portable smoke test first binds
that directory to the exact archive, then installs into an isolated home and
exercises both managed Cppcheck runners, all five MCP tools, a fresh saved-file
query and natural EOF cleanup with unrelated-process preservation.

Supply a real native ARM bare-metal GNU toolchain. `ARM_GXX_SHA256` must be the
SHA-256 of the actual supplied `arm-none-eabi-g++` executable. The test compiles
its firmware corpus into real ARM objects and records the toolchain identity;
a host compiler or synthetic ARM object is not a substitute.

```sh
python3 release/scripts/test_code_analysis_portable_smoke.py \
  --expected-target TARGET --archive /absolute/archive \
  --bundle /absolute/expanded-bundle --workspace-source /absolute/AgentWorkspace \
  --arm-gxx /absolute/arm-none-eabi-g++ --arm-gxx-sha256 "$ARM_GXX_SHA256" \
  --evidence /absolute/new/smoke-evidence --artifact-label YOUR_RUN_ID
```

On Windows, use the `.exe` ARM toolchain executable and add
`--rustc C:/absolute/path/to/rustc.exe` to the command. Supply the actual toolchain
compiler rather than the rustup proxy; its bundled `rust-lld` must be available
to link the Windows override fixture. For a rustup installation,
`rustup which rustc` reports that compiler path.

Install the smoke script's
Python test dependency `psutil` in an isolated test environment. Keep its
`report.json`, evidence manifest and captured output even on failure. Exit 0 is
the bounded core smoke pass; exits 1, 2 and 3 distinguish a failed assertion,
setup/unverified evidence and a pending prerequisite. The core smoke does not
replace full update/uninstall, corruption, cancellation/deadline, resource
consumption or minimum-OS testing. macOS 15 runner results alone do not prove
execution on macOS 12.
