# ADR 0001: Supported platform baselines

- Status: Accepted
- Date: 2026-07-24
- Owners: Engineering and Release

## Decision

BYO Installer V1 supports:

- macOS 12 or newer;
- Windows 10 22H2 and Windows 11, x86_64; and
- Linux x86_64 with glibc 2.28 or newer.

Target-native build and clean-machine evidence is required for every advertised
target. A build produced on another operating system or architecture is not
acceptable evidence.

## Consequences

- Linux must be built in a controlled glibc 2.28-compatible environment.
- macOS deployment targets must not be lower than the dependencies can support.
- Windows tests must cover both Windows 10 22H2 and the current Windows 11
  release before GA.
- Optional Windows ARM64 and Linux ARM64 artifacts are post-V1 work and must not
  be selected by the V1 installer.
