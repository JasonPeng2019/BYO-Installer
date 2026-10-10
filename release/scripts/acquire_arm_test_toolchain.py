"""Acquire a pinned native ARM compiler fixture for remote installed smoke tests.

This fixture is separate from shipped analyzer inputs. --expected-target selects
one recorded host archive; --output is an owned fresh extraction directory. The
JSON receipt binds the upstream archive pin and measured compiler bytes. Failed
or existing extraction directories require a fresh output, never implicit removal.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

TARGETS = ("windows-x86_64", "linux-x86_64", "macos-aarch64", "macos-x86_64")
LOCK = Path(__file__).resolve().parents[1] / "arm-test-toolchains.json"


def load_source(target: str) -> dict:
    raise NotImplementedError("ARM test input contract is not implemented yet")


def acquire(target: str, output: Path) -> dict:
    raise NotImplementedError("Pinned ARM fixture acquisition is not implemented yet")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-target", choices=TARGETS, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = acquire(args.expected_target, args.output)
    except (OSError, RuntimeError, ValueError) as error:
        parser.exit(2, f"ARM test input acquisition failed: {error}\n")
    print(json.dumps(receipt, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
