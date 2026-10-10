# Code analysis portability contract

Contract candidate for ROOT acceptance, 2026-10-10. This module specifies source
implementation; it implements no runtime or builder and establishes no native
macOS/Linux execution, shipping, signing or publication acceptance. The approved
portability extension supersedes only the older Windows-only implementation
boundary. The original Cppcheck/clangd behavior contract remains in force.

## Inputs and observed blockers

The audited source identities are:

| Repository | Accepted commit | Relevant authored sources |
| --- | --- | --- |
| Installer | `7bfc8610889df5c6d2645dea37c943c3b1f3a968` | `launcher/src/code_analysis.rs`, `code_analysis/{config,runtime,process,xml}.rs`, `main.rs`, `workflow.rs`; `release/scripts/{analysis_tools,build_release,verify_build_output}.py`; `schemas/byo-analysis-runtime.schema.json`; `release/{analysis-tools.lock,source-lock}.json`; `.github/workflows/{quality,build-matrix,release,clean-machine}.yml` |
| Firmware server | `ade75ef2fef4af5202c4ff14543f1159b7447330` | `src/pyocd_debug_mcp/code_analysis_manifest.py`, `code_analysis_runtime.py`, `kernel/processes.py`, `adapters/clangd.py`; `docs/code-analysis-runtime-manifest.md` and its schema |
| Workspace | `2889c2fdbd77a56f33095ff21f03d78dc1317d03` | `internal/code_analysis.py`, `internal/agent_workspace.py`, `internal/verify_backend.py` |

There is no installer `launcher/src/code_analysis/manifest.rs`: its mapping
validator is `runtime.rs`. The runtime-manifest document is in the server
repository, not installer `docs/`. Installer `release/source-lock.json` already
pins the two accepted companion commits above. Do not update pins until ROOT
accepts their matched replacements.

Concrete blockers at these identities:

- `main.rs:2`, firmware handling in `workflow.rs:589`, and doctor/status handling
  are gated by Windows. The other firmware branch still makes PATH Cppcheck
  optional and local overrides bypass it.
- `code_analysis.rs::native` rewrites `/` to Windows separators unconditionally.
  `config.rs:6` uses Windows file handles for input identity; `runtime.rs:9`
  uses Windows metadata, restricts mapping/host to Windows and checks only PE.
  Removing the top-level module gate alone cannot compile this module on Unix.
- `xml.rs` depends on Windows XmlLite; `process.rs` depends on Windows jobs,
  suspended creation, HANDLE inheritance and `NUL`.
- Server `_mapping`, `_inventory`, `_windows_executable`, and workspace
  `_validate_runtime` restrict the managed payload to Windows/AMD64. Development
  PATH resolution and POSIX process branches already exist. Workspace POSIX
  cleanup waits only for the leader before claiming group cleanup confirmed.
- `analysis_tools.load_lock/mapping/stage_windows`, the builder's staging and
  post-stage validation, and the archive verifier's complete leaf validation
  are Windows-specific. Non-Windows verification rejects resource `.h` files;
  tar verification currently checks entry types/paths without equivalent payload
  inventory/SBOM verification. Native CI currently supplies no analyzer inputs.

The existing Windows code, artifacts and receipts retain their original
identities. A source-only portability claim does not automatically require a new
Windows compiled distribution. Changed Windows paths do require proportionate
Windows regression checks. Prior artifact acceptance never transfers to rebuilt
or transformed bytes.

## Target and mapping contract

Keep `analysis/runtime.json` mapping schema version **1**, its existing closed
fields, project `byo-analysis.json` version 1 and release-manifest syntax.
Broaden only the supported target union; existing Windows mapping bytes remain
valid. Old Windows-only consumers will reject native mappings, so the installer,
server and workspace validators must be delivered together. No compatibility
fallback or relaxed unknown-field decoding is permitted.

| Target ID | Mapping `platform`, `architecture` | Executable paths | Native format | Baseline / archive |
| --- | --- | --- | --- | --- |
| `windows-x86_64` | `windows`, `x86_64` | `analysis/cppcheck/cppcheck.exe`; `analysis/clangd/bin/clangd.exe` | AMD64 PE32+ | Windows 10 22H2 / Windows 11; ZIP |
| `macos-aarch64` | `macos`, `aarch64` | `analysis/cppcheck/cppcheck`; `analysis/clangd/bin/clangd` | thin Mach-O 64, CPU ARM64 `0x0100000c` | macOS 12+; ZIP |
| `macos-x86_64` | `macos`, `x86_64` | same suffix-free paths | thin Mach-O 64, CPU x86_64 `0x01000007` | macOS 12+; ZIP |
| `linux-x86_64` | `linux`, `x86_64` | same suffix-free paths | ELF64 little endian, machine 62 | glibc 2.28+; tar.gz |

These are the baselines in installer ADRs [0001](decisions/0001-supported-platform-baselines.md)
and [0002](decisions/0002-macos-intel-support.md). Retain the verifier/CI alias
`linux-x86_64-glibc-2.28`, adding `linux-x86_64` as the canonical accepted target
spelling. Neither spelling changes mapping architecture. No Windows ARM64,
Linux ARM64, musl, macOS universal product binary or Rosetta-only build is added.

Normalize Python host OS `Windows/Darwin/Linux` to `windows/macos/linux`, machine
`AMD64/x86_64` to `x86_64`, and `arm64/aarch64` to `aarch64`; Rust uses its native
OS/architecture constants with the same mapping. Require host, release and
analysis mapping to agree with one row. Native build receipts also record the
actual host architecture; a translated x86_64 process on Apple silicon is not
Intel-native build evidence.

Every field stays required: exact integer `schema_version: 1`; exactly two
programs; three-part numeric versions; executable, licenses, dependencies and
`sbom_ref`; Cppcheck `cfg_dir`/`platforms_dir`; clangd `resource_dir`. Reject
duplicate JSON keys, unknown fields, nulls and type coercion (`true`/`1.0` are
not integer-token 1). Preserve mandatory license paths and IDs
`byo-analysis:cppcheck` / `byo-analysis:clangd`.

Data locations are unchanged: `analysis/cppcheck/{cfg,platforms}` and
`analysis/clangd/lib/clang/<version-major>`. Require `cfg/std.cfg`, platform XML
data and `include/stddef.h`; upstream selection completeness is a build gate.
The version major must match `resource_dir`; a version probe cannot substitute
for correct data. clangd always receives the mapped absolute `--resource-dir`.
Cppcheck retains empty `FILESDIR`, adjacent data and an explicit project target
platform XML; host architecture is never the firmware ABI.

Paths retain `/`, exact case-sensitive inventory spelling and the existing
portable subset of Windows-safe names on every target. Reject absolute paths,
drive/UNC paths, backslashes, empty/dot/parent components, reserved names,
trailing dots/spaces and case-fold collisions. Check every ancestor and leaf
without following symlinks/reparse points; resolved paths must remain under the
canonical runtime root. Payloads are regular files. Reject symlinks and hard-link
archive entries rather than silently dereference them. Upstream analyzer ZIPs
inspected here contain no symlinks; do not introduce a link exception.

`release-manifest.json.files` remains the sole runtime digest inventory. Hash
selected payloads, emit matching SBOM components/relationships, then inventory
the SBOM itself. Do not hash an SBOM into itself. `analysis/runtime.json` contains
references, never a duplicate executable/data digest list. Require exact selected
namespace membership, kinds, sizes, hashes, licenses and SBOM ownership. Extra
files, absent references, stale resources and changed directory membership fail.
Mapping/target failures affect both analyzers; selected payload/probe failures
affect the selected analyzer. Preserve expected and observed identities separately.

Dependencies remain explicit arrays: Windows DLLs adjacent to each executable;
POSIX private dependencies under `analysis/<program>/lib/`, regular basename
files (`*.dylib` or `*.so`/`*.so.<numeric-components>`), with all transitive
non-OS dependencies listed. `[]` means no bundled non-OS shared libraries, not
that the analyzer has no native imports. Classify them `analysis-dependency`,
`executable: false`; identify their format/architecture and final bytes too.

Before probes/spawns, Rust and both Python consumers validate the selected
native header, not merely its extension or executable bit: PE signature, AMD64
machine and PE32+ optional header; Mach-O magic/complete header, matching CPU
and executable/dylib file type; ELF class/endian/machine, executable/PIE or
shared-library type as appropriate. Reject malformed/truncated headers, wrong
architecture, scripts, Windows wrappers and fat runtime Mach-O. POSIX analyzers
must have executable permission and be executable by the current caller; this
permission participates in receipt rechecks. Keep Unix inode/device, mode,
size and high-resolution mtime/ctime identities; retain Windows volume/file ID
semantics. Keep project-file identity and input hashing distinct from runtime
payload identity.

The release validator additionally proves native dependency closure: Windows
ordinary/delay imports retain the accepted System32/API-set policy; macOS checks
load commands, install names, every selected Mach-O minimum OS and private
`@loader_path`/`@rpath` resolution; Linux checks interpreter, DT_NEEDED,
RPATH/RUNPATH, imported symbol versions and recursive bundled closure. Allow
only baseline OS libraries or inventoried private libraries. Reject build-host
absolute references, unresolved non-OS imports, empty/relative search components,
cwd lookup and undeclared loader inputs. Managed child environments must remove
inherited library injection/search overrides such as `LD_PRELOAD`,
`LD_LIBRARY_PATH`, `LD_AUDIT` and `DYLD_*`; keep explicit query-driver settings.
Static inspection and an `ldd` listing are not clean baseline execution evidence.

Trust/lifetime is unchanged: launcher `load_current`/runtime verification and
leases select the root; private sidecar/workspace trusted context selects it
explicitly; no cwd/environment inference. Process-local receipts bind manifest,
mapping, SBOM and selected namespace identities before execution, recheck them
on reuse and invalidate probes/sessions after change. No disk trust cache or
automatic repair. Managed failures never use PATH. Explicit unmanaged source
use may use existing development PATH resolution, reporting origin `path`,
the supplied-runtime problem and warning. Hash/probe/spawn/analysis or query
share the existing deadline/cancellation; owned version probes have a maximum
five-second phase within that budget. Status never starts LSP indexing.

For example, a Linux mapping uses the existing Windows example with
`platform: "linux"`, suffix-free executable paths, and actual Linux dependency
and license arrays. Changing only `platform` while retaining `.exe` is invalid;
full firmware verify reports FAIL with `analysis/executable-unavailable`, and
clangd status reports `unavailable` with a restore/select-matching-runtime remedy.

## Runtime behavior and ownership

Both Cppcheck runners preserve the accepted scope/argv/XML/diagnostic corpus,
including target ABI, suppressions coverage protection, style opt-in and full
report retention under `.firm/code-analysis/reports/<unique-run>`. Preserve
`pass`, `findings_failed`, `blocked`, `execution_error` and final verify exit
conventions. Unknown information, coverage limits, missing includes, malformed
XML and unexplained exit status never become clean results. The shared corpus
manifest is `launcher/tests/fixtures/code-analysis/manifest.json`, SHA-256
`f0b33c167ae62673606c03cadf58796a978aeefe78725c9e667585684c77c905`.

All Rust firmware routes use the required static step after build handling:
configured CMake, Makefile, successful/failed/unlaunchable local override, failed
normal build and missing build configuration. Build failure still prevents PASS;
analysis executes once and can report its own evidence. Remove the optional
non-Windows static branch and the local-override bypass. Preserve existing
memory/structure obligations and non-firmware backends. The workspace runner
uses the same behavior without importing server services or hidden Python into
the native launcher.

Use one portable XML engine for Rust: pin `roxmltree = "=0.20.0"` in Cargo and
its lockfile, replacing the private XmlLite implementation while retaining its
`Element` seam. Its documented `Document::parse_with_options` accepts UTF-8
text and has an explicit DTD policy. Set `allow_dtd: false`; no resolver or
entity declarations. Strictly decode UTF-8 (optional BOM) and UTF-16 LE/BE XML
with BOM or XML encoding signature before parsing; reject invalid code units,
unsupported encoding declarations and conflicting encoding evidence. Preserve
numeric/predefined entity decoding, CDATA, XML whitespace, document conformance,
expanded element/attribute names, duplicate-attribute errors and single-root
validation. Namespace-bearing results must not masquerade as unqualified
Cppcheck XML. No lossy decoding, regex XML parser or parser fallback. Run the
Python/Rust corpus plus UTF-16, entity, namespace and malformed cases on Windows
before changing Windows parser acceptance. [Parser API](https://docs.rs/roxmltree/0.20.0/roxmltree/struct.Document.html)

Retain the Windows job/suspended-spawn implementation behind `cfg(windows)`.
Implement POSIX spawn with explicit argv, project cwd, null stdin, separate
retained output streams and a new session/process group; never execute database
shell text. Capture owned PID/start identity and group before observation. On
normal exit, timeout, cancellation, spawn/setup error, service shutdown and EOF,
clean the owned group and observed descendants, reap the leader and confirm no
owned live process remains within the existing cleanup reserve/grace. Leader
exit alone proves neither descendant exit nor group cleanup. Distinguish zombies
from live children and report unconfirmed cleanup honestly. Recheck PID/start
identity before signaling an observed descendant or recovery marker; never kill
an unrelated recycled PID, process name or broad process tree. Do not claim
identity from a cached executable image. Keep retained exact exit proof usable
when an already-exited child's live image is unavailable. A detached descendant
requires its captured exact ownership; lack of identity is a cleanup failure.

Server `kernel.processes` already owns POSIX sessions and start-token markers;
reuse it and correct group/descendant confirmation only where evidence requires.
Workspace `_run_owned` must stop reporting confirmed cleanup solely because its
leader wait succeeded. Rust uses the existing `sysinfo` process observations
plus native session/group signaling; pin a narrowly scoped POSIX syscall crate
in Cargo only if needed. Test startup races, descendants surviving leader exit,
PID reuse, shutdown while idle and bounded cleanup. No broad hardware-process
behavior change is implied.

Keep all five tools available without a board and at every existing tier/profile:
`get_code_analysis_status`, `find_code_definition`, `find_code_references`,
`get_code_hover`, `get_code_diagnostics`. Preserve parameters, position encoding,
JSON block boundaries, saved-file freshness, versioned diagnostics, incompleteness,
index limits, cancellation and EOF lifecycle. No board policy, tier guard,
unlock, probe, hardware access, implicit build, download or file edit is added.
Doctor/global doctor/project doctor and initialization summaries report the same
analysis readiness and identity fields on all four targets:
`runtime.analysis.cppcheck`, `runtime.analysis.clangd`, or the existing
`runtime.analysis` warning with `ANALYSIS_RUNTIME_UNAVAILABLE`. MCP status remains
non-indexing and board-independent; unresolved identities remain null.

## Pinned analyzer inputs and deterministic selection

Retain Cppcheck **2.22.0** and clangd **23.1.0**. The input acquisition step is
separate from local staging/building and from tool calls. Build scripts consume
only supplied local inputs; no download, installation, latest-version resolution,
package-manager analyzer substitution or Windows-default lock selection.

Extend build-only `release/analysis-tools.lock.json` to version 2 with an exact
`targets` map for the four target IDs. Move the existing Windows record into
`targets.windows-x86_64` without changing its inputs/recipe/selection. Each other
record explicitly supplies its platform, architecture, program sources,
selected leaves, transformations and build recipe. `load_lock` must require
an explicit/native-derived supported target; mismatch/missing input is an error.
This is a build-input format change, not a second runtime digest inventory.

| Input | Identity and acquisition |
| --- | --- |
| Cppcheck source, all targets | Commit `a436ca35ed1887bee789765122b65ed2d7a7e045`; local name `cppcheck-2.22.0-a436ca35ed1887bee789765122b65ed2d7a7e045.tar.gz`; SHA-256 `68ed9efb7aad635b7f4c121662689b2377d1d745dc9e76227566516a9617f343`; [official commit archive](https://codeload.github.com/cppcheck-opensource/cppcheck/tar.gz/a436ca35ed1887bee789765122b65ed2d7a7e045). Existing observed-download digest, not an independently published checksum. |
| Windows clangd | Existing `clangd-windows-23.1.0.zip`; SHA-256 `23412a240756a162e7b98a282f36aa2a23a88db5ce16a0cbc4fef7253768c810`; retain accepted Windows selection/recipe. |
| Linux clangd | `clangd-linux-23.1.0.zip`, 117949007 bytes; SHA-256 `e53b1a96196095faedb7642cf64964f7fb9ad4a0c1f00dd2c172a3d9dcbafdfd`; [official asset](https://github.com/clangd/clangd/releases/download/23.1.0/clangd-linux-23.1.0.zip), asset ID `541002329`. |
| Both macOS inputs | `clangd-mac-23.1.0.zip`, 100060151 bytes; SHA-256 `1082e6638223b785ca2daf0939f13afcd0bb95c84ee9a4bbaff4745365159253`; [official asset](https://github.com/clangd/clangd/releases/download/23.1.0/clangd-mac-23.1.0.zip), asset ID `540976785`. Select the native slice before packaging. |

GitHub's [23.1.0 release API](https://api.github.com/repos/clangd/clangd/releases/tags/23.1.0)
reports those native asset digests and LLVM source commit
`ea7d852a70e8bdfaf601d6626a760f9771b2c4b4`. The release itself reports
`immutable: false`; identity is the pinned content digest, not immutability of
the URL/tag. Native ZIP digests were independently matched on this Windows host
against ROOT's supplied files; this is static byte evidence only.

Select Cppcheck's existing **70** locked source leaves unchanged: 66 data leaves
from `cfg/*.cfg` and `platforms/*.xml`, and `COPYING` plus
`externals/{simplecpp,tinyxml2,picojson}/LICENSE`, mapped to the existing four
license paths. Preserve all existing leaf hashes and source-relative names.
The compiled native executable is a measured recipe output, not a predeclared
Windows executable digest. Do not stage addons, source, build caches or binaries
from an unapproved system install.

For native clangd ZIP prefix `clangd_23.1.0/`, select exactly `bin/clangd`,
`LICENSE.TXT`, every regular leaf under `lib/clang/23/include/`, and every leaf
under `lib/clang/23/share/`. Map to the corresponding `analysis/clangd/` paths.
Record each selected input path/size/hash in that target's lock; require exact
set equality. Both native archives have **333 header leaves**. Linux adds five
share files: `asan_ignorelist.txt`, `cfi_ignorelist.txt`, `dfsan_abilist.txt`,
`hwasan_ignorelist.txt`, `msan_ignorelist.txt`; macOS adds the first two.
These are **338 Linux / 335 macOS resource leaves**, distinct from Windows's
332. Do not copy compiler-rt archives, objects or shared runtime libraries from
`lib/clang/23/lib/`; these tools parse/query and do not link user programs.
Native tests must exercise resource-dependent parsing and supported sanitizer
flags. Missing data must be surfaced, never hidden by host headers.

The entire upstream resource tree contains 415 Linux / 409 macOS leaves,
including those excluded compiler runtimes. These totals are not the selected
header inventory. Selection can be reproduced without running an analyzer:
sort upstream names; emit records with keys `path` (prefix removed), `sha256`,
`size`; SHA-256 the UTF-8 JSON list using `sort_keys=True`, separators `(',', ':')`.
Selected resources hash to:

- Linux: `24981bae953d0733809deec24e08f379f37fe302538d8d7e00fcaafc50e60cc7`.
- macOS: `6a7350a53628fd3c0e8253b4a95ba6a986c69c37fabec4baa1d6e5d71afa299b`.

This audit aggregate binds selection evidence, not a runtime digest list.
Both native notice files are 15141 bytes, SHA-256
`8d85c1057d742e597985c7d4e6320b015a9139385cff4cbae06ffc0ebe89afee`.
The Linux executable input is 148913784 bytes, SHA-256
`5a535973dd1274270c8a0d34677fe4758d8c9aaa164aa3701602c957c42dc9e2`.
The macOS universal executable input is 177144960 bytes, SHA-256
`23197c85e1fbe16de89666bb6d1132b36b02213906b09e12d687eda8cc3b6a57`.
Final transformed/signed executable hashes must be measured afresh.

## Native recipes, finalization and prerequisites

Cppcheck native builds use the pinned archive, CMake >=3.22, a native C++11
compiler and Unix Makefiles. Configure Release, CLI on, GUI/tests/core DLL/shared
libraries/Boost/matchcompiler off, bundled tinyxml2 on, `DISABLE_DMAKE=ON`, empty
`FILESDIR`. Build only `cppcheck`, parallelism 4, then stage
`<build>/bin/cppcheck` and locked source data/notices. No Windows MSVC patch or
UTF-8 manifest is applied on POSIX. Preserve compiler-option input identity and
record exact argv/toolchain and output. The upstream
[CMake entry point](https://github.com/cppcheck-opensource/cppcheck/blob/a436ca35ed1887bee789765122b65ed2d7a7e045/CMakeLists.txt)
and [options](https://github.com/cppcheck-opensource/cppcheck/blob/a436ca35ed1887bee789765122b65ed2d7a7e045/cmake/options.cmake)
define these targets/data layout; build-output directories are not an input
selection policy.

Native compiler flags must remap the private extraction/build roots in
`__FILE__` and debug information (GCC/Clang `-ffile-prefix-map` and
`-fdebug-prefix-map` with stable `/cppcheck-src` and `/cppcheck-build` roots).
Record the actual flag values. Include every delivered analyzer in existing
symbol-stripping and private-path leakage checks, not only launcher/sidecar.

```sh
case "$(uname -s):$(uname -m)" in
  Darwin:arm64) set -- -DCMAKE_OSX_DEPLOYMENT_TARGET=12.0 -DCMAKE_OSX_ARCHITECTURES=arm64 ;;
  Darwin:x86_64) set -- -DCMAKE_OSX_DEPLOYMENT_TARGET=12.0 -DCMAKE_OSX_ARCHITECTURES=x86_64 ;;
  Linux:x86_64) set -- '-DCMAKE_EXE_LINKER_FLAGS=-static-libstdc++ -static-libgcc' ;;
  *) exit 2 ;;
esac
cmake -S "$CPPCHECK_SOURCE" -B "$CPPCHECK_BUILD" -G "Unix Makefiles" \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_CLI=ON -DBUILD_GUI=OFF \
  -DBUILD_TESTING=OFF -DBUILD_CORE_DLL=OFF -DBUILD_SHARED_LIBS=OFF \
  -DUSE_BUNDLED_TINYXML2=ON -DUSE_BOOST=Off -DUSE_MATCHCOMPILER=Off \
  -DDISABLE_DMAKE=ON -DFILESDIR:STRING= \
  "-DCMAKE_CXX_FLAGS=-ffile-prefix-map=$CPPCHECK_SOURCE=/cppcheck-src -fdebug-prefix-map=$CPPCHECK_SOURCE=/cppcheck-src -ffile-prefix-map=$CPPCHECK_BUILD=/cppcheck-build -fdebug-prefix-map=$CPPCHECK_BUILD=/cppcheck-build" \
  "$@"
cmake --build "$CPPCHECK_BUILD" --target cppcheck --parallel 4
```

The builder executes equivalent argv directly; `CPPCHECK_SOURCE` is its fresh
verified extraction, and it supplies platform options explicitly rather than
accepting arbitrary runtime flags. On macOS add
`-DCMAKE_OSX_DEPLOYMENT_TARGET=12.0` and
`-DCMAKE_OSX_ARCHITECTURES=arm64` or `x86_64`, matching the actual native host.
Require installed Xcode command-line tools, record `xcrun` compiler/SDK identity
and `sw_vers`. Preserve OS-provided libc++ dependency closure; no Homebrew dylib
may enter accidentally.

On native Linux use a controlled **glibc 2.28** host with a compatible GCC
toolchain, CMake/Make, patchelf and binutils. Add
`'-DCMAKE_EXE_LINKER_FLAGS=-static-libstdc++ -static-libgcc'` as one argv value.
This leaves baseline glibc dynamic and avoids a newer unbundled GLIBCXX runtime.
Record compiler version and hashes of compiler-selected `libstdc++.a`,
`libgcc.a`/other actually linked static runtime inputs; preserve their GCC
GPL/runtime-exception notices as additional Cppcheck license leaves
`analysis/cppcheck/licenses/GCC-COPYING3` and
`analysis/cppcheck/licenses/GCC-COPYING.RUNTIME`. Tester supplies the
matching toolchain notices in `--analysis-input-dir/gcc-runtime/` as `COPYING3`
and `COPYING.RUNTIME`; their measured identity and compiler package/source
reference enter the recipe receipt/SBOM. Do not assume a path or invent those
hashes. Missing static libraries, notices or provenance blocks this recipe.
Verify actual DT_NEEDED/symbol requirements against the baseline after linking.

Linux clangd's inspected ELF dynamic version-needs records reach `GLIBC_2.18`,
with no GLIBCXX version needs. Its OS imports are `libpthread.so.0`, `librt.so.1`,
`libdl.so.2`, `libm.so.6`, `libc.so.6`, `ld-linux-x86-64.so.2`. This supports
choosing the archive as a baseline candidate, not a native compatibility claim.
Its DT_RUNPATH is `$ORIGIN/../lib:$ORIGIN/../lib/x86_64-unknown-linux-gnu:`.
The final empty component permits cwd search. Run native
`patchelf --remove-rpath <staged-clangd>` before final measurement, record input,
tool version/hash, argv and output digest, and validate no RPATH/RUNPATH remains.
No bundled dependency is selected for this inspected archive. Use
`readelf -h -l -d --version-info` on final analyzers and baseline native execution; a newer
host cannot establish glibc 2.28 compatibility.

macOS clangd is a two-slice archive input. Native staging runs
`lipo <input-clangd> -thin arm64 -output <staged-clangd>` or `-thin x86_64`.
Record lipo version/tool identity, original fat input digest, selected CPU and
measured output. The inspected input slices declare minimum OS 11.0 ARM64 /
10.13 Intel, both below the product baseline; they import only system
CoreFoundation, libSystem, libresolv, libedit, libz and libc++. Revalidate final
slice/load commands and run on macOS 12 of the matching architecture. Do not
use lipo under Windows, claim that byte inspection is native execution, or ship
the universal input unchanged as a separate-architecture product.

Stage executable files mode **0755**, data/notices/private libraries **0644**,
directories **0755**, without setuid/setgid bits. Reject input links/special
entries and preserve the final modes through ZIP Unix attributes or tar modes
and update extraction. Installation intentionally normalizes private runtime
permissions to owner-only **0700** executable/directory and **0600** data, as
`install.rs::set_runtime_permissions` already does; preserve that policy and
verify executable access after installation. Existing manifest `executable` stays the
semantic field; do not add an independent mode inventory. Neither an executable
boolean nor a correct hash repairs a lost execute bit.

Each native build retains an external `analysis-evidence` receipt containing
target and actual OS/arch/baseline, installer/server/workspace commits, source
and archive identities/hash basis, selection/lock hash, exact commands and exits,
compiler/CMake/linker/SDK/patchelf/lipo identities, input notices/static libraries,
all byte transformations, native dependency closure, version probes and final
output hashes. Record source recipe output hashes per build; do not pre-pin
fabricated native Cppcheck hashes or reuse Windows executable identities.
SBOM application/file IDs and existing provenance property names stay unchanged;
record static linked third-party/runtime components as well as shipped files.
License/source-distribution review remains a publication gate, not a claim
established by collecting notices.

Order: verify inputs; native build/extract; thin/normalize loader paths; collect
private symbols/strip where appropriate; set modes; platform-sign when separately
authorized; generate final payload inventory/SBOM/manifest; verify final native
closure/probes; form archive; verify archive bytes/modes and installed behavior.
No transformation after measurement without regenerating affected metadata.
Production retains Windows prepare/protected Authenticode/finalize behavior,
macOS codesigning of **all** Mach-O executables/private libraries before
inventory plus exact-ZIP notarization, and existing manifest/archive signatures.
Unsigned development builds remain visibly development-only. This assignment
executes no signing/notarization/publication.

The archive verifier must apply complete manifest/namespace/data/SBOM/native
checks to both macOS ZIPs and Linux tar.gz, including actual archived leaf hashes,
sizes and executable modes; equality with the assembled manifest; only derived
directories; no extra source, caches, reports, links or hidden dependency files.
Allow shipped `.h`/share data only at the **exact target-locked resource paths**,
with matching input bytes/classification, never a global header/source exception.
Retain Windows verifier CLI compatibility; generalize the archive-only gate with
an explicit target so clean-machine verification does not need the builder's
source tree or execute another OS's binaries. Static archive checks are portable;
native probes/signature/installed checks run only on the matching target.

## Native tester commands and independent gates

These commands describe the implementation to be delivered against this
contract; the accepted starting commits still have the blockers listed above.
Do not run them against those commits and call skipped native tests a pass.
Acquire external repository access, clone installer plus `AgentWorkspace/` and
`Firmware MCP New/` at ROOT's integrated/pinned identities. Install native
Rust **1.97.1** with rustfmt/clippy, Python **3.12** (record exact patch/build),
uv and compiler/build tools above. Populate locked Python/Cargo dependencies
before an offline run; `uv sync --locked --all-groups` uses the server `uv.lock`.
No firmware hardware is required. A full installed ARM fixture additionally
requires an actual native ARM cross compiler and generated headers, recorded in
the test receipt; it cannot be substituted by handcrafted database flags.
The ARM mode must require explicit compiler/fixture paths and expected compiler
digest, build the fixture natively with that cross compiler, and retain the
generated database, ABI file and build/header evidence.

Download only the Cppcheck archive and the matching clangd ZIP above into a
private input directory. Hash before using them (macOS `shasum -a 256`, Linux
`sha256sum`); a mismatch stops, without selecting a different version. Transfer
the verified directory to an offline native builder if desired. Build staging
must reuse `--analysis-input-dir` and `--analysis-cmake` for all targets; no new
builder or implicit network fetch is needed. GCC notices live in its input
subdirectory as described above.

After matched implementation and ROOT source-pin integration, on native macOS:

```sh
set -eu
export MACOSX_DEPLOYMENT_TARGET=12.0
ANALYSIS_INPUT_DIR=/absolute/path/to/verified-analysis-inputs
case "$(uname -m)" in
  arm64) TARGET=macos-aarch64 ;;
  x86_64) TARGET=macos-x86_64 ;;
  *) exit 2 ;;
esac
uv sync --project "Firmware MCP New" --locked --all-groups
cargo fmt --manifest-path launcher/Cargo.toml --check
cargo clippy --manifest-path launcher/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path launcher/Cargo.toml --locked
uv run --project "Firmware MCP New" python release/scripts/build_release.py \
  --analysis-input-dir "$ANALYSIS_INPUT_DIR" --analysis-cmake "$(command -v cmake)"
python3 release/scripts/verify_build_output.py --dist release/dist \
  --expected-target "$TARGET" --archive-type zip
VERSION=$(python3 -c 'import tomllib; print(tomllib.load(open("launcher/Cargo.toml", "rb"))["package"]["version"])')
BUNDLE="release/dist/byo-$VERSION-$TARGET"
python3 release/scripts/test_installed_e2e.py --bundle "$BUNDLE"
```

On a provisioned native Linux x86_64/glibc 2.28 builder, use the same quality,
dependency and build commands with these target values (no container or remote
execution is requested here):

```sh
set -eu
test "$(uname -m)" = x86_64
test "$(getconf GNU_LIBC_VERSION)" = 'glibc 2.28'
TARGET=linux-x86_64
ANALYSIS_INPUT_DIR=/absolute/path/to/verified-analysis-inputs
uv sync --project "Firmware MCP New" --locked --all-groups
cargo fmt --manifest-path launcher/Cargo.toml --check
cargo clippy --manifest-path launcher/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path launcher/Cargo.toml --locked
uv run --project "Firmware MCP New" python release/scripts/build_release.py \
  --analysis-input-dir "$ANALYSIS_INPUT_DIR" --analysis-cmake "$(command -v cmake)"
python3 release/scripts/verify_build_output.py --dist release/dist \
  --expected-target "$TARGET" --archive-type tar.gz
VERSION=$(python3 -c 'import tomllib; print(tomllib.load(open("launcher/Cargo.toml", "rb"))["package"]["version"])')
BUNDLE="release/dist/byo-$VERSION-$TARGET"
python3 release/scripts/test_installed_e2e.py --bundle "$BUNDLE"
```

Do not infer offline dependency availability: after explicitly caching the exact
dependencies, add `--offline` to uv sync/run and `--offline --locked` to Cargo.
Run in a fresh task-owned checkout/output directory so no command replaces an
accepted artifact. The existing source builder produces development candidates
without `--production`; production signing is a separate authorized operation.

Independent tester owns a new portable installed-analysis harness
`release/scripts/test_code_analysis_native.py`, retaining the current
Windows-specific accepted harnesses unchanged. Required runnable interface:

```sh
python3 release/scripts/test_code_analysis_native.py \
  --bundle "$BUNDLE" --archive "$BUNDLE.zip" --expected-target "$TARGET" \
  --workspace-source AgentWorkspace --evidence /absolute/path/to/new-evidence
# Linux: use --archive "$BUNDLE.tar.gz" instead.
# Cross-target acceptance adds these explicit options:
# --arm-compiler /absolute/native/arm-none-eabi-gcc \
# --arm-compiler-sha256 <measured-sha256> --arm-fixture-source /absolute/fixture-source
```

The harness is a required implementation/test deliverable, **absent at the
audited baseline**. It must create isolated product home/project fixtures,
install the exact archive through the public launcher, use managed tools with
poisoned analyzer PATH/loader environment, and test both the compiled Rust
workflow route and workspace Python runner against the same project/corpus.
It must call all five tools through the public `byo mcp serve` stdio interface,
parse intact JSON text blocks, test no-board/tier/profile availability and
non-indexing status, and observe exact owned processes through normal shutdown,
EOF, timeout/cancellation and child-survives-leader fixtures. It records failures
and skipped prerequisites, exits nonzero on required skip/failure, and binds its
receipt to harness/source/archive/manifest/final executable identities. Provide
an optional explicit ARM compiler/fixture mode; acceptance of cross-target
firmware requires that mode, not just a host C fixture.

Existing server tests run in the matching server checkout using its locked
environment: `uv run python -m pytest tests/test_code_analysis_*.py` and focused
`tests/test_process_cleanup.py`. First make their target/fixture selection
portable and confirm the tests actually execute; Windows-only decorators are
not native proof. Workspace's tests use pytest, not unittest discovery: in the
workspace checkout install its recorded development dependencies, then run
`python3 -m pytest tests/test_code_analysis.py tests/test_cppcheck_acceptance.py
tests/test_cppcheck_real_program.py` with actual local input prerequisites.
Installer packaging tests remain `python3 release/scripts/test_analysis_tools.py`,
`test_build_release.py`, and `test_verify_build_output.py`; add native-format,
permissions, closed-target and tampered-archive cases, preserving Windows gates.

Independent acceptance must cover:

1. Platform-neutral Python/Rust target/mapping/header/namespace/SBOM parity
   negatives on Windows, labeled **Windows-host platform-neutral fixtures**;
   XML/diagnostic/config/scope parity and existing Windows process regressions.
2. Matching native Cargo compile/lint/tests, actual analyzer source staging,
   version/data probes, dependency/OS-baseline checks and final archive verification
   for each of three native OS/architecture targets; collect commands/exits and
   no required skips. Modern native macOS builds still need macOS 12 clean proof.
3. Installed real Cppcheck defect/clean/blocked cases in both runners, all firmware
   routes, and actual ARM cross-target configuration; real clangd definitions,
   references, hover, saved-file diagnostics/freshness and resource consumption.
4. Managed corruption/missing-data/notice/dependency/wrong-architecture/mode/link
   failures with no PATH fallback, precise health/status, retained reports,
   deadlines and confirmed owned cleanup, plus update/uninstall preservation of
   project configuration and prior runtime leases.

## Ownership, ordering and unresolved evidence

| Sole owner / order | Smallest production file set | Independent test ownership |
| --- | --- | --- |
| 1. ROOT accepts contract | This document only in this module | Fresh contract critique, including target/ABI and selection decisions |
| 2a. Installer Rust owner | `launcher/src/code_analysis.rs`, `code_analysis/{config,runtime,process,xml}.rs`, `main.rs`, `workflow.rs`, `Cargo.toml`, `Cargo.lock` | Tester owns portable fixture additions and focused Rust/native lifecycle tests; preserve accepted corpus identity |
| 2b. Installer packaging owner | `release/scripts/{analysis_tools,build_release,verify_build_output}.py`, `release/analysis-tools.lock.json`, installer mapping schema | Separate tester owns release-script tests and native installed-analysis harness/fixtures |
| 3. Server owner after installer runtime retirement/retarget by ROOT | `code_analysis_manifest.py`, `code_analysis_runtime.py`, `kernel/processes.py` as needed; matching runtime-manifest doc/schema | Server tester owns native mapping/lifecycle/real-clangd/availability regression suites; adapter/service changes only for a demonstrated blocker |
| 4. Workspace owner in its repository | `internal/code_analysis.py`; `internal/agent_workspace.py` only if its existing resolution seam needs correction | Workspace tester owns parity and real Cppcheck/cleanup suites; no server dependency introduced |
| 5. ROOT integration/build instructions/CI | `release/source-lock.json`, `.github/workflows/{quality,build-matrix,release,clean-machine}.yml`, release/runner instructions | Independent integrated-source tests then fresh review; native tester gathers new target evidence |

Keep one writer per path. Rust and packaging can be separate disjoint modules,
but acceptance uses their integrated tip. Source pins/CI belong to final
integration, not an early worker. The single harness is retired before a
repository change; workers need only harness coordination hooks. ROOT owns
acceptance, model/provider deployment and scheduling. Future contracts/review
use Codex gpt-6.1-sol max, implementation xhigh; testing starts Claude
claude-opus-5-5 high every deployment, with Codex high fallback only after ROOT
records that deployment's usage-limit/OAuth error. This document launches none.

No native macOS/Linux program, compile, test, patchelf/lipo transformation,
signing or installed fixture ran in this contract lane. Source inspection,
official API reads, ZIP hashing/enumeration and ELF/Mach-O byte inspection ran
on Windows only. The native Cppcheck outputs, transformed Linux clangd output,
thinned/final macOS clangd outputs and their probes remain unmeasured. GCC
toolchain/static-runtime notice identities are per-build prerequisites, not
missing analyzer source pins. Neither accepted Windows receipts nor synthetic
headers establish these outputs.

ROOT's concrete acceptance decisions are to approve the four-target schema-1
union and build-lock v2 migration; the include/share-only native clangd selection;
Linux RUNPATH removal, macOS thinning and the native Cppcheck recipes; then
allocate disjoint owners and independent tests. All analyzer source/archive
inputs above are obtainable and identity-bound; no version upgrade is needed.
If native baseline execution or supported-resource behavior contradicts these
inputs/recipes, stop the affected acceptance gate and ask ROOT to choose a
compatible same-version source build (LLVM commit above) or an explicit reviewed
scope/baseline change. Do not silently drop Intel, raise glibc/macOS baselines,
choose latest binaries or weaken integrity. A source implementation can be
accepted with accurately labeled Windows checks and executable native routes;
target-native build/installed/baseline acceptance remains unverified until the
matching tester produces identity-bound receipts with actual successful exits.
