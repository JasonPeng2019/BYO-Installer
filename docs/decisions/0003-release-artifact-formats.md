# ADR 0003: Release artifact formats

- Status: Accepted
- Date: 2026-07-24
- Owners: Engineering and Release

## Decision

V1 publishes:

- macOS: notarized `.zip`;
- Windows: `.zip` containing individually Authenticode-signed executables and
  applicable DLLs; and
- Linux: `.tar.gz`, SHA-256 checksum, and detached Ed25519 signature.

The release manifest and signed channel metadata carry the archive type
explicitly. Installers and the Rust updater reject unsupported archive types
before extraction.

## Consequences

- ZIP validation and safe extraction are required in the launcher and bootstrap
  paths.
- Archive paths, duplicates, case collisions, entry types, file counts, and
  expanded sizes must be bounded before installation.
- Changing a published artifact without changing its version is forbidden.
