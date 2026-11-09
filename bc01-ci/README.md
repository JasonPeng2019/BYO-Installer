# Build inputs and small command capture

This directory keeps the committed `CI-INPUTS.json`, its
`verify_frozen_sources.py` check, and a small Actions command capture helper.
The separate FR13 observer, nested unittest recorder, source-binding self-tests
and copied build workflow have been removed. There is no optional legacy suite.

The build matrix checks the frozen source/input identity once before and once
after each native job. Historical `FR13_EXECUTION_COMMIT` and
`FR13_INPUT_SHA256` environment names remain compatible input metadata; they
do not launch the deleted FR13 matrix or establish final acceptance.

`build_capture.py --name <step> --cwd <directory> -- <command> <arguments>`
records argv, working directory and RUNNING status before spawning the command.
It writes stdout/stderr directly to files, records the actual exit or setup
error, and propagates failure. The finite Actions job owns the deadline and
process tree. A killed step can leave a RUNNING record and partial streams;
that is incomplete evidence, never PASS. Existing artifact uploads retain it.
No per-command full-tree snapshots or host process-history are required.

The fourteen useful product process-ownership checks formerly mixed into
`test_independent.py` and `test_validator.py`, with their two child fixtures,
now live in Firmware MCP `tests/` as `test_process_callers.py` and
`test_process_release_identity.py`. The existing four-host native regression
step runs them through ordinary pytest, alongside the existing process tests.
No assertion was discarded when removing the recorder.

See [workflow triggers](../.github/workflows/README-triggers.md) for cheap push
preparation and the single explicit native bundle/installed acceptance path.
All automated checks and builds remain Actions-only. Genuine local client,
model and hardware acceptance remains separate and required.

The retained source lock and input index describe the previous exported
candidate. This standalone cleanup does not publish or invent a new export.
The next authorized source owner must adopt these changes and refresh the exact
paired exports/index before gated CI. Do not restore deleted files to satisfy
the historical index, relabel an old artifact, or bump the product version
solely for fixture changes.
