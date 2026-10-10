"""Run native installed analysis smoke with pinned ARM test inputs in CI.

Use after building the bundle/archive on the matching native host. The ARM input
directory and smoke evidence directory must be fresh and caller-owned. The
input receipt is retained beside the smoke evidence; compiler archives are not
part of that evidence or the product. Smoke exit codes propagate unchanged.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import acquire_arm_test_toolchain as arm  # noqa: F401 - source-only acquisition stub
import analysis_tools  # noqa: F401 - source-only host validation stub
import test_code_analysis_portable_smoke as smoke  # noqa: F401 - source-only smoke stub


def run(args: argparse.Namespace) -> int:
    raise NotImplementedError("Native CI input binding is not implemented")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-target", required=True)
    for name in ("bundle", "archive", "workspace-source", "evidence", "arm-input-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--artifact-label", required=True)
    parser.add_argument("--rustc", type=Path)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
