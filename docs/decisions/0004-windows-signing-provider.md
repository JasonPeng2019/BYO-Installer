# ADR 0004: Windows signing provider

- Status: Accepted
- Date: 2026-07-24
- Owners: Security and Release

## Decision

BYO V1 uses Microsoft Artifact Signing Public Trust for Windows Authenticode
signatures. GitHub Actions authenticates to Azure through OpenID Connect; no
long-lived Azure client secret is stored in GitHub.

If Public Trust identity validation is unavailable, a superseding ADR may
approve a CA-issued Authenticode certificate whose private key is held by an
HSM-backed signing service. A repository-stored PFX is not an acceptable
fallback.

## Consequences

- Azure subscription, identity validation, certificate profile, and least-
  privilege signer role are release prerequisites.
- The compiled sidecar, launcher, applicable DLLs, and any executable installer
  are signed and RFC 3161 timestamped with SHA-256.
- Pull-request and hardware-test jobs never receive signing authority.
