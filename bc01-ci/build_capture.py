"""Capture an unchanged authoritative build command in the Actions workspace."""

from __future__ import annotations

import argparse
import os
import subprocess
import traceback
from pathlib import Path

from ci_common import CLOCK, ROOT, actions_only, compact, source_snapshot, write


def main() -> int:
    actions_only()
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True)
    parser.add_argument("--cwd", type=Path, default=ROOT)
    parser.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    directory = ROOT / "build-runtime" / "evidence" / args.name
    directory.mkdir(parents=True, exist_ok=False)
    argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
    if not argv:
        parser.error("an authoritative command is required after --")
    commit = os.environ.get("FR13_EXECUTION_COMMIT", "")
    input_hash = os.environ.get("FR13_INPUT_SHA256", "")
    before = source_snapshot(commit, input_hash)
    write(directory / "source-before.json", before)
    result = {"argv": argv, "cwd": str(args.cwd), "name": args.name}
    compact("build_command_start", **result, source_reasons=before["reasons"])
    started = CLOCK()
    with (directory / "stdout.log").open("wb") as out:
        with (directory / "stderr.log").open("wb") as err:
            if not before["confirmed"]:
                result.update(outcome="BLOCKED", exit_code=None, reasons=before["reasons"])
            else:
                try:
                    # The workflow owns the finite enclosing deadline and its
                    # process tree. Preserve the full command's own behavior.
                    child = subprocess.run(
                        argv,
                        cwd=args.cwd,
                        stdout=out,
                        stderr=err,
                        stdin=subprocess.DEVNULL,
                        check=False,
                    )
                    result.update(
                        outcome="PASS" if child.returncode == 0 else "FAIL",
                        exit_code=child.returncode,
                    )
                except OSError:
                    result.update(outcome="ERROR", exit_code=None, error=traceback.format_exc())
    after = source_snapshot(commit, input_hash)
    write(directory / "source-after.json", after)
    result.update(elapsed=CLOCK() - started, source_confirmed_after=after["confirmed"])
    write(directory / "command.json", result)
    compact("build_command_complete", **result, source_reasons=after["reasons"])
    for name in ("stdout.log", "stderr.log"):
        lines = (directory / name).read_text(encoding="utf-8", errors="replace").splitlines()
        print(f"{name}: {len(lines)} retained lines; final 40 follow", flush=True)
        for line in lines[-40:]:
            print(line, flush=True)
    return int(result.get("exit_code") != 0 or not after["confirmed"])


if __name__ == "__main__":
    raise SystemExit(main())
