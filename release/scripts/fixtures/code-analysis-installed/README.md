# Installed analysis inputs

`release/scripts/test_installed_analysis.py` owns the installed clangd, Cppcheck,
profile, tier, environment, privacy and distinct-version scenarios. It uses one
shared MCP transport (`installed_support.py`) and standard pytest reports.

Supply `BYO_INSTALLED_BUNDLE`, `BYO_TEST_ARM_GNU_ROOT` (acquired GNU Arm 14.3.1)
and `BYO_TEST_WORKSPACE_SOURCE` (the pinned companion source). Profile and upgrade
checks additionally need genuine `BYO_INSTALLED_PROFESSIONAL_BUNDLE` and
`BYO_INSTALLED_OLD_BUNDLE` inputs. No fixture fabricates a release or upgrades a
manifest in place. Missing inputs are reported as UNRUN skips; they are not PASS.
Run automated checks only in GitHub Actions. The fixture-only cleanup route
never builds a product; it collects installed scenarios and records prerequisites.

`availability/manifest.json` retains the three positive canonical personal tier
states. `availability/generate.py` regenerates them through the actual store API;
its provenance identifies the original snapshot until explicitly regenerated.
The scenarios check passive availability and protected state rather than replaying
a second policy engine or a cartesian matrix of synthetic store corruption.

Failures retain command/status/stdout/stderr, standard traceback and JUnit,
protocol/stderr logs and owned project inputs beneath `BYO_TEST_FAILURES`.
Natural process EOF is asserted before owned cleanup. Physical/model/client
acceptance remains a separate qualified local phase.
