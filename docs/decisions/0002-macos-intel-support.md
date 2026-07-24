# ADR 0002: Retain macOS Intel for V1

- Status: Accepted
- Date: 2026-07-24
- Owners: Product and Release

## Decision

macOS x86_64 remains an advertised V1 target alongside macOS arm64. Separate
downloads are published; V1 will not ship a universal binary.

## Consequences

- Intel and Apple silicon artifacts receive identical source, signing,
  notarization, clean-machine, update, rollback, and uninstall gates.
- Release publication is blocked if either advertised macOS architecture is
  missing required evidence.
- Intel support duration must be revisited before V2.
