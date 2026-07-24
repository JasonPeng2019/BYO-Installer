# BYO compiled HIL fixtures

The V1 fixture decision is recorded in ADR-0007. The primary fixture is an
nRF52840 DK with onboard J-Link and deterministic UART/LED firmware. The
destructive fixture is a physically labelled, sacrificial STM32 Nucleo with
ST-Link and a pinned CMSIS-Pack.

`run_hil.py` operates only on an already installed, exact signed candidate. It
refuses placeholder identities, changed fixture artifacts, unexpected probes,
unlisted tool calls, and destructive execution without all of:

1. the `destructive` command;
2. a fixture whose `role` is `sacrificial`;
3. `destructive_authorized` set to `true`;
4. only ADR-approved operations;
5. `BYO_HIL_ALLOW_DESTRUCTIVE=1`;
6. approval of the `hil-destructive` GitHub environment.

Permanent readout locks, option-byte/fuse programming, lifecycle transitions,
security provisioning, and irreversible protection are never authorized.

Before enabling either workflow, replace the example records with reviewed
fixture records containing the real board ID, exact probe UID, artifact paths,
SHA-256 hashes, expected UART transcript, and the sequence of MCP calls. Commit
the deterministic fixture firmware source, build recipe, ELF/HEX, and memory
map beside that record. Do not place production signing credentials on a HIL
runner.

The runner must be dedicated, have remotely controlled USB power when
possible, and expose one label for its OS and fixture. A job-level concurrency
key plus the harness lock prevents two jobs from using one board.
