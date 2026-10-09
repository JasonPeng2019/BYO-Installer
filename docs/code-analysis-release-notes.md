# Windows code analysis: pending release

These notes describe the accepted configuration and the Windows x86_64 packaging
work in progress. A locally built unsigned archive is a packaging candidate;
acceptance requires checks against its exact final bytes and integrated source.
Required installed Windows tests, clean-host validation, independent testing
and read-only review remain incomplete.
Other platforms are unverified for this change. Existing published releases are
unchanged.

## Migrating firmware verification

Full firmware verification requires target-aware Cppcheck. Continue using
`byo workflow tool verify [path]` in an installed project or `bin/verify [path]`
in an authored Agent Workspace. A local build override still requires static
analysis. Missing programs, configuration, target data, incomplete coverage or
execution failures prevent `VERIFY: PASS`.

Export a truthful `compile_commands.json` for the selected build configuration
using the project's native build system. For a CMake project, configure with
`-DCMAKE_EXPORT_COMPILE_COMMANDS=ON` using its existing compiler/toolchain settings,
then build normally. Analysis does not run a build or invent target flags.

Create project-owned `byo-analysis.json` deliberately:

```json
{
  "schema_version": 1,
  "compilation_database": "build/compile_commands.json",
  "cppcheck": {
    "platform_file": "config/arm32.xml",
    "timeout_seconds": 120,
    "enable_style": false
  },
  "clangd": {
    "query_driver_paths": []
  }
}
```

Relative paths resolve from the project root. Select one build database explicitly
when both root and `build/compile_commands.json` exist. Each entry's own `directory`
governs its compiler arguments. Conflicting commands for one source require a
database for one configuration. The target XML must describe the firmware ABI;
do not select the Windows host platform for an MCU merely to obtain a pass.

Cppcheck's pinned `cfg` library models and platform XML files are packaging inputs.
Their presence does not establish vendor-library or target coverage. The current
project schema has no `libraries` field or arbitrary analyzer-argument override;
do not add either. Custom library-model support requires an explicitly documented
and tested runner setup. Resolve missing include/model or analysis-limit reports
before claiming a full pass. Suppressions, when explicitly configured through
`cppcheck.suppressions_file`, remain project-owned and are never generated to
make verification pass.

Default scope `.` selects all translation units in the chosen build. A source
selects its own unit; a directory selects units underneath it. A header selects
all build units because it has no separate compilation command. An empty
selection is blocked. Warning, performance, portability and error findings fail;
style is opt-in. Information is retained, and known coverage problems block the
run. Full XML, argv, stdout, stderr and result evidence remain under
`.firm/code-analysis/reports/`.

## Semantic queries

The five tools are `get_code_analysis_status`, `find_code_definition`,
`find_code_references`, `get_code_hover` and `get_code_diagnostics`. They require
no board and grant no hardware permissions. Queries use the selected build's
compiler arguments and the files saved on disk; unsaved editor changes are
outside the semantic scope. Positions are one-based Unicode code points, not
UTF-16 offsets. Indexing can be incomplete, and an incomplete response must not
be interpreted as a complete-project answer.

Allow compiler interrogation only by listing exact existing compiler executable
paths in `clangd.query_driver_paths`. No wildcards or command strings are accepted.
These paths allow clangd to execute those compilers to discover system includes.
Preserve existing `.clangd` settings; reconcile conflicting compilation-database
settings explicitly. Tool calls never download or install analyzers.

## Managed runtime and recovery

The accepted layout uses `analysis/runtime.json` for program/data references,
`release-manifest.json.files` as the sole payload size/SHA-256 inventory and
`sbom.cdx.json` for source, notices and dependency relationships. The closed
release manifest schema remains unchanged. Both managed executables resolve
from the verified active runtime with no analyzer PATH fallback. Native doctor
and status reuse the Rust analysis mapping boundary under an active runtime
lease. They expose managed executable/data paths and inventoried byte identities,
and probe both program versions. Installed validation of these reports remains
pending.

| Failure | Recovery |
| --- | --- |
| Missing or ambiguous database | Export the selected build database and set `compilation_database` explicitly. |
| Missing target XML | Supply `cppcheck.platform_file` describing the firmware ABI. |
| Missing generated headers or library coverage | Build the selected configuration; correct include/model setup and rerun. |
| Missing, changed or incompatible runtime data/program/version | Restore or reinstall a complete supported immutable runtime, then relaunch. Do not substitute a PATH executable. |
| Invalid query-driver entry | Set exact compiler executable paths or remove the entry if interrogation is unnecessary. |
| Configuration/database changed during analysis | Save the intended files/configuration and issue a new independent request. |

Project `byo-analysis.json`, `.clangd` and user files must survive workspace update
and uninstall. Final installed preservation checks remain required.

## Measured Windows source-path limit

Pinned Cppcheck 2.22.0 passed a real translation unit whose absolute source path
was **259 UTF-16 code units**, and short Unicode source paths passed. Absolute
source paths of **260, 261 and 317 UTF-16 code units** reported `missingFile`.
Both runners surface this as a nonpass result. This is a measured legacy
source-path limitation; Windows long-path settings and a long database pathname
do not establish support for long source paths.

Move the project to a shorter root, regenerate the compilation database using
the real build system so its source paths identify the relocated files, rebuild
and rerun verification. Do not rewrite a database to claim a build that did not
happen. There is no claimed upstream fix in this packaging work.

## Pinned packaging inputs and pending gates

The portable input selection and proposed build argv are in
[`analysis-tools.lock.json`](../release/analysis-tools.lock.json). Cppcheck is
built from `a436ca35ed1887bee789765122b65ed2d7a7e045`; its source archive SHA-256 is
`68ed9efb7aad635b7f4c121662689b2377d1d745dc9e76227566516a9617f343`, observed from
the official codeload archive, without an independently published checksum.
The MSVC patch normalizes CRLF to LF and trims blank context lines from the
supplied hunk so its checked-in bytes pass whitespace checks. Applying it to the
pinned upstream source produces the same accepted `compileroptions.cmake`
SHA-256. The lock records the verified patch hash and applies it with
`git -c core.autocrlf=false`; both patch assets use Git `-text` attributes.
The UTF-8 manifest is preserved verbatim. The declared
recipe uses Visual Studio 17 2022/x64 Release, static `MultiThreaded`, empty
`FILESDIR`, no core/shared DLL, GUI, tests, Boost or matchcompiler, and an embedded
UTF-8 active-code-page manifest. Actual compiler, linker, SDK and CMake versions
must be recorded when the release builder executes it. Recipe identity alone
does not establish bit-for-bit reproducibility.

The staged native Cppcheck executable exposed a private source root in
`__FILE__` strings. The recipe now retains the default C++ flags and adds
MSVC `/experimental:deterministic` plus `/pathmap` to replace that root with
`C:/cppcheck-src`. An actual MSVC object check verified the mapping; a full
Cppcheck rebuild and final-byte/archive leak check remain required. These build
options do not change the measured legacy translation-unit path-length limit.

The first rebuilt archive passed the compiled 0.1.8 sidecar self-test, but the
final leak gate still found the temporary build/home path in Cppcheck's CodeView
PDB record. The linker recipe also uses
[`/PDBALTPATH:cppcheck.pdb`](https://learn.microsoft.com/en-us/cpp/build/reference/pdbaltpath-use-alternate-pdb-path)
to embed a stable filename while preserving the actual private PDB location.
That failed archive and its gate exits remain evidence; a corrected archive must
repeat the same leak checks without allowances.

The clangd 23.1.0 Windows archive SHA-256 is
`23412a240756a162e7b98a282f36aa2a23a88db5ce16a0cbc4fef7253768c810`, matching the
recorded official asset digest. Selection contains its executable, `LICENSE.TXT`
and exactly 332 resource include leaves: 319 headers and 13 explicitly accepted
extensionless, `.tcc`, `.inc` and module-map resources. Cppcheck selection contains
51 cfg files, 15 platform XML files and four notices. No addons, build output,
PDBs, unselected compiler runtime libraries or arbitrary source are admitted.

Cppcheck source and its static-linked simplecpp, tinyxml2 and picojson notices,
and clangd's license, are recorded. This is not a legal-compliance conclusion.
Before distribution, review corresponding-source and attribution obligations
against the actual rebuilt/linked artifacts and provide the required source and
recipe access. No distribution or publication is authorized by these notes.

Final-byte SBOM/inventory/archive checks, PE32+/AMD64 ordinary and delay-import
closure, a recorded tested Windows OS/build and real isolated installed tests
remain required. The installed gate must use explicit isolated `BYO_HOME`,
relocated runtime/project paths with spaces and Unicode, and no analyzers on
PATH. It must cover genuinely built ARM clean/defect/restore 0/1/0, Python/Rust
parity, configuration/data/version blockers, all five semantic tools and
saved-file freshness, owned-child EOF/idle cleanup, and update/uninstall
preservation. Independent testing and review must bind to the final clean
candidate and exact archive digest. Skipped or failed required Windows gates
remain incomplete; the supported Windows analysis range is not yet established.

## Local Windows build recipe

The existing builder stages analysis before creating the SBOM and sole release
inventory. Supply the two local archives named in the lock through
`--analysis-input-dir` or `BYO_ANALYSIS_INPUT_DIR`. No analyzer download or
installation is performed. Cppcheck is rebuilt from its source archive and exact
patch; clangd is selected from its official pinned archive. Install the build
toolchain separately before running the recipe.

Use a clean, detached `AgentWorkspace` checkout at
`2889c2fdbd77a56f33095ff21f03d78dc1317d03` and `Firmware MCP New` checkout at
`d9a1bc4a1aaf629f1442c83245f4e382a6806beb`. The installer/server version equality
check is intentional. Build with an existing Python environment containing the
server lock's dependencies and Nuitka 2.8.9; the builder compiles the checked-out
server source using that environment.

The Windows builder checks both imported source identity/version and installed
`pyocd-debug-mcp` distribution metadata before compiling. Nuitka can fold a
metadata version from the build interpreter, so pointing `PYTHONPATH` at the
accepted source while retaining older installed metadata is insufficient. Use
an isolated, preprovisioned matching environment without modifying the accepted
checkouts or another development environment. The prior supplied environment
had 0.1.7 metadata and failed the native sidecar's retained self-test against
0.1.8 source; that standalone output is not an accepted product sidecar. The
continuation uses an isolated CPython 3.12.13 Windows x64 environment provisioned
offline from the accepted server lock's build group, with Nuitka 2.8.9 and
matching 0.1.8 distribution metadata. The builder still checks that identity and
runs the compiled sidecar self-test; provisioning alone does not establish a pass.

```powershell
$env:CARGO_NET_OFFLINE = 'true'
$env:CARGO_TARGET_DIR = 'C:/build/byo-cargo'
python release/scripts/build_release.py `
  --build-dir C:/build/byo-release `
  --python C:/build/python-environment/Scripts/python.exe `
  --analysis-input-dir C:/build/pinned-analysis-archives
python release/scripts/verify_build_output.py `
  --dist release/dist --expected-target windows-x86_64 --archive-type zip
```

Choose owned scratch directories and a short path: native MSVC link steps can
fail with `LNK1104` when generated outputs are placed under a deeply nested
checkout. This build-output constraint is separate from Cppcheck's measured
translation-unit source-path limitation. Neither a short build scratch directory
nor a long database-path test establishes long source-path support.

The build scratch `analysis-evidence` directory retains configure/build argv,
exit codes and full logs, actual MSVC/CMake/linker/SDK identity, and analyzer
version probes and PE import evidence. The verifier repeats checks against final
ZIP entries and payload bytes, including exact upstream resources and SBOM
ownership, and records tested System32/API-set module and imported-symbol
resolution. These host observations do not establish clean-machine acceptance
or support for another Windows OS build. No PATH module fallback is accepted.

Windows analysis packaging negatives are wired into the existing build matrix.
The protected clean-test kit includes the Windows verifier modules and locks,
and clean-machine CI has a Windows-only final archive/PE gate. The kit has been
composed locally without publishing. CI must supply the pinned local input
archives. Provisioning that input location and wiring/running the independent
installed test remain integration gates; publication jobs are unchanged. The
independent installed tester's reserved paths remain with that tester.

Nuitka 2.8.9's Windows standalone build uses its bundled `pefile` detector through
`--experimental=force-dependencies-pefile`, as selected by its installed source.
This avoids downloading Dependency Walker. The detector is a build input
selection mechanism; it does not replace the independent checks of all bundled
PE images, ordinary/delay imports and symbols, or installed and clean-host proof.
The first native attempt compiled and linked the server but stopped at the
missing Dependency Walker prompt; no download occurred. That failed standalone
output is not an accepted sidecar and cannot be reused as a successful build.

The native launcher imports `vcruntime140.dll`; its copy belongs beside
`byo.exe`. The sidecar also requires that DLL and `vcruntime140_1.dll`. Their
observed CPython 3.12.13 Windows interpreter bytes, sizes, version 14.44.35211.0,
Nuitka selection provenance and Windows license notice are pinned in the tool
lock and represented in the SBOM and payload inventory. The builder checks the
declared interpreter bytes and report before staging, and never obtains a
redistributable from PATH or assumes that a System32 installation is present.
The preserved CPython Windows binary notice includes Microsoft Distributable
Code conditions. Final distribution review remains required; the notice and
local provenance do not establish compliance or clean-host behavior.
