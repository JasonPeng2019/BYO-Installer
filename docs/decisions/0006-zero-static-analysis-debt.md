# ADR 0006: Zero static-analysis debt

- Status: Accepted
- Date: 2026-07-24
- Owners: Engineering

## Decision

InstallerV1 requires:

- `ruff check .`;
- `ruff format --check .`;
- `pyright`; and
- the complete locked test suite

to pass with zero errors before merge or release. Rust formatting, Clippy with
warnings denied, and locked Rust tests are also required.

Broad excludes, repository-wide ignores, and baselining existing errors are not
acceptable substitutes. Narrow platform adapters and truthful typed test fakes
must be used instead.

## Consequences

- The existing formatting changes are committed separately from semantic type
  repairs.
- CI runs from recreated locked environments, never a moved virtual
  environment.
- A dependency import-resolution failure is treated as an environment or lock
  problem and repaired at its source.
