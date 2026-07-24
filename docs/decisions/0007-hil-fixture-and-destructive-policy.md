# ADR 0007: HIL fixture and destructive-operation policy

- Status: Accepted
- Date: 2026-07-24
- Owners: Firmware, Security, and Release

## Decision

The initial hardware-in-the-loop fixture consists of:

1. an nRF52840 DK with onboard J-Link and deterministic UART/LED fixture
   firmware; and
2. a sacrificial STM32 Nucleo board with onboard ST-Link and a pinned,
   checksummed CMSIS-Pack.

CMSIS-DAP coverage is post-V1 unless it is required by a V1 customer.

The automatic `hil-safe` job may discover, connect, validate, perform bounded
reads, prove guarded-write refusal, execute an allowlisted reversible write,
flash fixture firmware, exchange UART data, cancel work, time out providers,
and verify cleanup.

The `hil-destructive` job is manual and requires all of:

- a protected environment approval for the specific run;
- an allowlisted sacrificial board and probe identifier;
- `BYO_HIL_ALLOW_DESTRUCTIVE=1`;
- a fixture manifest naming the exact permitted operation; and
- successful recovery-disclosure validation before execution.

Permitted destructive operations are limited to recoverable mass erase,
recoverable debug unlock, and reset/reflash of allowlisted sacrificial
fixtures. Permanent fuse programming, irreversible debug lock, permanent read
protection, security-key destruction, and operations on non-sacrificial
hardware are forbidden.

## Consequences

- This ADR is policy authorization, not authorization to operate on an
  unidentified attached device. Each destructive run still requires protected
  approval.
- HIL hosts contain no production signing credentials.
- Fixture source, binary hashes, memory maps, expected UART transcripts, and
  recovery instructions are version controlled.
