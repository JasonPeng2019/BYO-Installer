# Signing incident and revocation runbook

Trigger this runbook for suspected credential exposure, unauthorized signing,
unexpected publisher identity, channel equivocation, release-asset mismatch,
or loss of signer control.

1. Stop publication and channel workflows; do not delete immutable evidence.
2. Disable the affected signer identity and remove its production role.
3. Preserve workflow logs, OIDC claims, signing-service audit logs, artifact
   hashes, channel documents, and release attestations.
4. Publish an expired/emergency-disabled channel only through the independent
   incident process; never lower a sequence number or reuse a sequence.
5. Determine the last known-good immutable release and all affected targets.
6. Rotate to the escrowed next key following the rehearsed trust transition.
7. Rebuild from a reviewed protected source tag. Do not re-sign unknown
   binaries.
8. Publish a security advisory and recovery instructions appropriate to the
   impact.
9. Verify clean external install/update/rollback and key-revocation tests.
10. Document root cause, scope, timeline, corrective controls, and new key IDs.

macOS Developer ID or notary compromise must also be reported through Apple
Developer support. Microsoft Artifact Signing identity compromise requires
Azure role removal, federated-credential revocation, audit preservation, and
Microsoft escalation. Never solve an incident by overwriting an existing
release asset or moving its tag.
