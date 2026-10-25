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
still match the checkout and committed input index. All execution is Actions-only.
