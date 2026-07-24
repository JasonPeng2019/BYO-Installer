# BYO release architecture decisions

These Architecture Decision Records (ADRs) are production release policy for
BYO Installer V1. A superseding ADR is required to change an accepted decision.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-supported-platform-baselines.md) | Supported platform baselines | Accepted |
| [0002](0002-macos-intel-support.md) | Retain macOS Intel for V1 | Accepted |
| [0003](0003-release-artifact-formats.md) | Target-specific archive formats | Accepted |
| [0004](0004-windows-signing-provider.md) | Microsoft Artifact Signing Public Trust | Accepted |
| [0005](0005-release-hosting.md) | Dedicated GitHub repository and immutable releases | Accepted |
| [0006](0006-zero-static-analysis-debt.md) | Zero Ruff and Pyright debt | Accepted |
| [0007](0007-hil-fixture-and-destructive-policy.md) | HIL fixture and destructive-operation policy | Accepted |

Production release workflows must fail closed when an accepted decision cannot
be enforced.
