# Independent installed analysis tests

Run `python release/scripts/test_code_analysis_installed.py --help` for the full
input and evidence contract. The script uses stdlib Python on native Windows
x86_64. No program or dependency is downloaded. Production code, existing tests,
accepted fixtures, source locks and runtime mappings are not modified.

The `build_control.rs` fixture validates the frozen genuine ARM ELF/map and the
requested target. It does **not** rebuild firmware or substitute for an analyzer.
The installed Cppcheck and clangd executables must match the accepted pinned
hashes. The static smoke deliberately mutates only a private source copy, then
restores it; the expected actual analyzer exits are 0/1/0.

Use a new evidence directory for every invocation:

```powershell
python release/scripts/test_code_analysis_installed.py --archive-only `
  --archive '<actual built pre-packaging ZIP>' --archive-sha256 '<SHA256>' `
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
  --evidence '<new final installed evidence>' --keep-lab
```

Availability inputs need all twelve safety-state/monitoring-profile pairs and
public witnesses identifying both actual state and profile. The help describes
the exact schema. This lane does not seed policies through private APIs, inject a
fake hardware backend, or invoke board setup/unlock/probe tools. Missing public
fixtures remain pending; a fixture label alone cannot credit a safety-tier check.

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

All homes, projects, profiles and cache/temp directories are private children of
a short native temporary root, with spaces and non-ASCII names. Source paths stay
below 260 UTF-16 units, reflecting the pinned Cppcheck limitation. Failed labs
are retained. Successful labs are removed unless `--keep-lab`; logs and reports
are retained in `--evidence` with a SHA256 manifest. MCP requests/replies and full
stderr are retained, along with actual executable argv, exits and process
identities. No cleanup selects processes by image name.

This is a preparation delivery at installer base
`81c4919214c071920aa542c14d9ef072030fd3c4`, tree
`e8a3cda859d01c4fd68a2ed8b00483c4ee26ee90`. No built archive was available here.
The initial attempt is **setup failure**, not product RED. All final installed
gates remain pending, including final ZIP/runtime digests, both runners,
Cppcheck negative controls, all semantic/safety-tier checks, stdio cleanup,
doctor/status/report, relocation, update and both uninstall routes. Script
plumbing checks and the ARM build control carry no installed-product credit.
ROOT must run a fresh independent validator against the exact integrated source
and final archive. Linux/macOS/WSL/Docker/hardware checks were not performed.
