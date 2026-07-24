# SIGN-PRODUCT key ceremony

Participants: release security custodian, independent witness, and recovery
custodian. Record names, date, secure location, device serials, firmware
versions, commands, public keys, and transcript hashes in the confidential
ceremony record.

1. Verify HSM/protected signer firmware and administrator workstations from
   known-good media.
2. Generate active and next Ed25519 keys inside the signer. Private keys must
   be non-exportable in production.
3. Assign stable key IDs such as `byo-release-2026-a` and
   `byo-release-2026-b`.
4. Export only public keys. Verify each 32-byte Ed25519 public value on two
   independent displays and record its SHA-256.
5. Configure least-privilege signing identities. Pull-request and HIL
   identities receive no signing permission.
6. Create offline, split-custody recovery material where the signer supports
   it. Store copies in separately controlled locations.
7. Compile both public keys into a test launcher and sign test manifests and
   channels with each key.
8. Rehearse rotation: publish with the active key, update trust to include the
   next key, publish with the next key, then revoke the old key in a test
   channel.
9. Rehearse emergency disable and confirm expired/replayed metadata fails
   closed.
10. Have both custodians sign the transcript and store its digest with the GA
    evidence.

The current scripts accept a protected PEM path for development and CI
integration. GA must replace that boundary with the selected HSM/provider
adapter or a protected non-exportable key mount. A repository secret
containing an exportable production private key is not the intended final
custody model.
