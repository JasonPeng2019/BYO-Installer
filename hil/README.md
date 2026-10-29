# BYO compiled HIL fixtures

The V1 fixture decision is recorded in ADR-0007. The primary fixture is an
nRF52840 DK with onboard J-Link and deterministic UART/LED firmware. The
destructive fixture is a physically labelled, sacrificial STM32 Nucleo with
ST-Link and a pinned CMSIS-Pack.

HIL runs LOCALLY only, on the operator's own bench machine with the boards
attached. There is no GitHub Actions or self-hosted runner route, and
`run_hil.py` refuses to start on an Actions runner. Builds and deterministic
quality gates stay in Actions; the release test kit still carries these files
for local use.

`run_hil.py` operates only on an already installed, exact candidate whose
launcher hash matches. It refuses placeholder identities, changed fixture
artifacts, unexpected probes, unlisted tool calls, and destructive execution
without all of:

1. the `destructive` command;
2. a fixture whose `role` is `sacrificial`;
3. `destructive_authorized` set to `true`;
4. only ADR-approved operations;
5. `BYO_HIL_ALLOW_DESTRUCTIVE=1`;
6. the local operator's explicit, recorded approval for that bench run.

Permanent readout locks, option-byte/fuse programming, lifecycle transitions,
security provisioning, and irreversible protection are never authorized.

Before running either mode, replace the example records with reviewed fixture
records containing the real board ID, exact probe UID, artifact paths, SHA-256
hashes, expected UART transcript, and the sequence of MCP calls. Commit the
deterministic fixture firmware source, build recipe, ELF/HEX, and memory map
beside that record. Do not place production signing credentials on a HIL
machine.

Rediscover each board's actual probe UID and UART before every run. The bench
machine is dedicated to the run, and the harness lock prevents two runs from
using one board. Safe acceptance does not erase, program, unlock, change
protection, reset, halt or resume a target, and does not power-cycle a fixture.
