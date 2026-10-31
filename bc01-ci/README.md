# Canonical build inputs

The `chore/Proto-0.04` push runs the committed build matrix, its reusable quality
workflow, and these retained native lifecycle controls. The expected input digest
comes from the current Git commit's `bc01-ci/CI-INPUTS.json` blob. Every product,
workflow, lock and runtime helper in that index is checked before and after the
recorded commands. The source lock and index must name the identical complete
Firmware MCP commit and tree. There is no dispatch-only source replacement.

These controls continue the full02 build owner's actual runtime controls; the
baseline recorder is retained solely for the intentional thread-error negative.
Their historical FR13 labels do not claim independent or final acceptance.
Hardware, model and complete final acceptance remain separate planned scopes.

The build matrix invokes quality once. Its canonical push does not also trigger
a second standalone quality workflow. Dispatch overrides are optional and must
still match the checkout and committed input index. Complete canonical
orchestration and compilation remain Actions-only.

The ordinary Python observer, interpreter, identity and thread-error controls
also support local nonbuilding execution with the real locked dependencies.
Use a private `TEMP`/`TMP` and `FR13_CONTROL_EVIDENCE` directory and the documented
Firmware source import paths. For example, run `python -m unittest
test_observer_controls test_thread_errors test_validator` from this directory
after selecting that environment. Method outcomes, deliberate negatives and
host-specific skips remain separate; a local control is not installed/native
or final independent acceptance. PB01's full01 comparison changes only its old
Actions restriction; the original recorder bytes are retained in PB01 evidence.
