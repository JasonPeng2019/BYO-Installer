# ADR 0005: Release hosting

- Status: Accepted
- Date: 2026-07-24
- Owners: Release

## Decision

Release source and artifacts live in a dedicated
`JasonPeng2019/BYO-Installer` GitHub repository. GitHub immutable releases are
enabled before the first public release.

Versioned release artifacts are attached to an immutable GitHub release. Signed
channel history is stored by sequence, while a separately hosted stable pointer
may change only by publishing a newer signed sequence.

## Consequences

- Release drafts receive every artifact before publication.
- Published version assets and tags are never replaced.
- Channel publication uploads immutable history before atomically replacing the
  channel pointer.
- Public update URLs use HTTPS and refer to versioned artifact names.
