# Independent installed analysis tests

Run `python release/scripts/test_code_analysis_installed.py --help` for the full
input and evidence contract. The script uses stdlib Python on native Windows
x86_64. No program or dependency is downloaded. Production code, existing tests,
accepted fixtures, source locks and runtime mappings are not modified.

The `build_control.rs` fixture validates the frozen genuine ARM ELF/map and the
requested target. It does **not** rebuild firmware or substitute for an analyzer.
Cppcheck must match an explicit independent raw candidate digest supplied as
`--cppcheck-sha256`; clangd retains its accepted upstream digest. The static smoke deliberately mutates only a private source copy, then
restores it; the expected actual exits are 0/1/0 for the Python runner and
0/13/0 for the public launcher (its WorkflowPolicy category for a failed verify).

Use a new evidence directory for every invocation:

```powershell
python release/scripts/test_code_analysis_installed.py --archive-only `
  --archive '<actual built pre-packaging ZIP>' --archive-sha256 '<SHA256>' `
  --cppcheck-sha256 '<independently established candidate executable SHA256>' `
  --bundle '<matching expanded bundle>' --evidence '<new initial-RED evidence>'
```

Missing shipped analysis mapping/programs in an **actual** bundle is RED (exit 1).
Missing artifacts are setup failure (exit 2). Successful archive-only preparation
returns 3, with all installed gates still pending. A source directory, synthetic
runtime or fake analyzer cannot establish the initial installed RED or acceptance.

After packaging integration, use the exact final archive/hash/bundle and omit
`--archive-only`. Add explicit immutable inputs:

```powershell
python release/scripts/test_code_analysis_installed.py `
  --archive '<final ZIP>' --archive-sha256 '<SHA256>' --bundle '<expanded bundle>' `
  --cppcheck-sha256 '<independent raw final-candidate executable SHA256>' `
  --cppcheck-inputs '<accepted cppcheck-windows-packaging-inputs.json>' `
  --cppcheck-source '<protected patched Cppcheck source>' `
  --clangd-inputs '<accepted clangd-windows-packaging-input.json>' `
  --clangd-root '<protected clangd_23.1.0>' `
  --arm-fixture '<protected built ARM firmware>' `
  --python-workspace '<clean exact accepted source checkout>' `
  --python-commit '<commit matching the final release workspace provenance>' `
  --rustc '<existing rustc.exe>' --rustc-sha256 '<SHA256>' `
  --availability-inputs '<passive availability fixture manifest>' `
  --availability-sha256 '<SHA256>' --update-bundle '<second immutable version>' `
  --update-manifest-sha256 '<second bundle release-manifest.json SHA256>' `
  --update-cppcheck-sha256 '<independent raw second-build executable SHA256>' `
  --evidence '<new final installed evidence>' --keep-lab
```

MSVC Cppcheck rebuilds can differ in COFF/debug timestamps, PE checksum and
CodeView GUID bytes. Do not edit a test constant or take the expected digest from
the candidate manifest/mapping. Supply a raw digest established beforehand by an
independent reviewed build-byte receipt, or an independent rebuild comparison
that establishes the exact candidate bytes. Historical normalized SHA256
`55a26190972aa1ad73e7bde04bb4d57dbbee118546473c5c2a266912d12cd2a5`
explains previous variation; this script does not implement PE normalization or
use that historical value to admit new bytes. The explicit candidate oracle binds
ZIP/expanded bytes, manifest identity, fixed mapping path/version and both runner
reports. Missing/malformed identity is setup failure (exit 2); wrong executable,
manifest or mapping is RED (exit 1). Updates require a genuinely built distinct
version and a separate explicit executable oracle, not the first build's hash.

Run `--validator-contract-checks` with the archive/hash/bundle/Cppcheck arguments
and a new evidence directory for focused executable contract checks. It validates
real archive inputs and tests private binary/inventory/mapping mutations and
public response values. Success returns 3 with installed gates pending; failures
return 1 or 2. `validator-contract.json` marks this evidence as having no installed
credit. Synthetic second-oracle plumbing is not genuine version-update evidence.

Availability v2 inputs contain existing passive fixture files, for example:

```json
{
  "schema": "installed-analysis-availability/v2",
  "cases": [{
    "state": "setup_lite",
    "profile": "personal",
    "board_id": "existing_board",
    "root": "C:/inputs/passive-board-fixture",
    "files": {".firm/<actual fixture path>": {"sha256": "<64 hex>", "size": 123}}
  }]
}
```

Use an independently hash-bound manifest with actual passive board/profile/policy
artifacts; names and labels cannot substitute for state. The script never seeds
policies through private APIs, injects hardware backends, or calls setup/unlock/
probe tools. It calls **two** public read-only witnesses: `server_health_check`
reports `narrative_logging=enabled` for personal or `not_built` for professional;
`get_capabilities(board_id)` reports `no-setup`, `setup-lite`, `setup-full`, or null
with `policy_status=corrupt`. Revoked/unvalidated is not a tier name. Its public
`setup_incomplete` witness is checked, but it remains pending because that field
alone does not prove attachment revocation. No-board needs an empty board fixture;
other states need real passive files. Observed responses and archive/sidecar
identities are retained even if subsequent semantic queries fail.

`availability_cases` records all twelve pairs separately. Partial inputs run;
missing pairs stay pending. Without inputs, a real fresh no-board server is
exercised for the archive's expected profile. `--installed-profile personal`
(default) describes the shipped personal ZIP. `--installed-profile professional`
requires a **separately compiled professional archive** in a separate invocation;
the public health response must be `not_built`. This option cannot change a
compiled server's profile. Retain separate hash-bound reports for the two builds.
A single personal archive cannot satisfy all twelve pairs; the aggregate gate
stays pending. Source-level tests for both profiles, especially tests using
private seams, remain separate evidence and earn no installed-pair credit.
Named-board cases must inventory that board's actual `.firm/boards/<board_id>`
profile or `.firm/capabilities/<board_id>/current.json` and referenced generations;
unrelated files cannot establish a board fixture. Public capability resolution
may initialize/migrate derived policy state in the private project; original
fixture bytes remain protected and are rechecked.

ROOT confirmed that the cross-runner gate compares the standalone public Python
`bin/verify` source runner with installed Rust `byo workflow tool verify`. Python
runs against the **installed** Cppcheck directory on a private PATH, with source
provenance recorded separately. The capsule contains compiled guidance/modes and
omits Python scripts by design. Source-runner execution is never proof of a
shipped Python entrypoint. Use clean accepted Python commit
`2889c2fdbd77a56f33095ff21f03d78dc1317d03`, matching final release provenance.

Installation uses the native CLI `install-runtime --bundle`, without modifying
the user's registry PATH. It validates ZIP/runtime bytes independently. Testing
the PowerShell bootstrap and normal firmware build is a separate gate owned by
the packaging/release integration lane. Compilation of the build control uses
the existing MSVC environment. Its exact descendants (including a lingering
MSVC helper) are recorded and cleaned by PID plus creation time; that setup
cleanup never earns product process-cleanup credit.
The native installation deadline defaults to 120 seconds. On a busy build host,
an explicitly chosen `--install-timeout-seconds 300` permits a longer test budget;
the invocation records it. A deadline failure remains recorded and earns no pass.

All homes, projects, profiles and cache/temp directories are private children of
a short native temporary root, with spaces and non-ASCII names. Source paths stay
below 260 UTF-16 units, reflecting the pinned Cppcheck limitation. Failed labs
are retained. Successful labs are removed unless `--keep-lab`; logs and reports
are retained in `--evidence` with a SHA256 manifest. MCP requests/replies and full
stderr are retained, along with actual executable argv, exits and process
identities. No cleanup selects processes by image name.

This correction is test preparation at installer base
`f75032a85b21ceeff9e03018263debdbe19d8547`, tree
`cbfae9a0d08609f250813dcab88b8aebfb9e6c78`. Old-archive regression uses only the
preserved `C:/t/byo-final-f75032a-20261009/origin-c7c1a309.zip`, SHA256
`c7c1a309d48af5dff43aa6166941f8af07c3158566767e53b89df1bda36a469e`.
That archive's historical raw Cppcheck digest is available in the independent
run7 evidence. It does not pin a freshly rebuilt final archive. All final
integrated ZIP acceptance and missing availability/update cases remain pending.
Validator plumbing checks and the ARM build control earn no installed credit.
ROOT must run a fresh independent validator against the exact integrated source
and final archive. Linux/macOS/WSL/Docker/hardware checks were not performed.
