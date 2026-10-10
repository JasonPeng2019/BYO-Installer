"""Run native installed analysis smoke with pinned ARM test inputs in CI.

Use after building the bundle/archive on the matching native host. The ARM input
directory and smoke evidence directory must be fresh and caller-owned. The
input receipt is retained beside the smoke evidence; compiler archives are not
part of that evidence or the product. Smoke exit codes propagate unchanged.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import acquire_arm_test_toolchain as arm
import analysis_tools
import test_code_analysis_portable_smoke as smoke


def run(args: argparse.Namespace) -> int:
    target = analysis_tools.canonical_target(args.expected_target)
    if target != analysis_tools.host_target():
        raise RuntimeError("Installed smoke requires a matching native host")
    if args.evidence.exists() or args.evidence.is_symlink():
        raise RuntimeError("Choose a fresh installed smoke evidence directory")
    if target == "windows-x86_64" and args.rustc is None:
        raise RuntimeError("Windows installed smoke requires the actual rustc path")
    archive = args.archive.resolve(strict=True)
    archive_sha256 = arm.inputs.digest(archive)
    receipt = arm.acquire(target, args.arm_input_dir)
    analysis_tools.write_json(args.evidence.parent / "arm-test-input.json", receipt)
    arguments = [
        "--expected-target",
        target,
        "--bundle",
        str(args.bundle),
        "--archive",
        str(archive),
        "--archive-sha256",
        archive_sha256,
        "--workspace-source",
        str(args.workspace_source),
        "--evidence",
        str(args.evidence),
        "--arm-gxx",
        receipt["compiler"],
        "--arm-gxx-sha256",
        receipt["compiler_sha256"],
        "--artifact-label",
        args.artifact_label,
    ]
    if args.rustc is not None:
        arguments += ["--rustc", str(args.rustc)]
    return smoke.main(arguments)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-target", required=True)
    for name in ("bundle", "archive", "workspace-source", "evidence", "arm-input-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--artifact-label", required=True)
    parser.add_argument("--rustc", type=Path)
    try:
        return run(parser.parse_args(argv))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Installed analysis CI setup failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
