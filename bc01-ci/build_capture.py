"""Capture an unchanged authoritative build command in the Actions workspace."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Build command capture is Actions-only")
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
    result = {
        "argv": argv,
        "cwd": str(args.cwd),
        "name": args.name,
        "outcome": "RUNNING",
        "exit_code": None,
    }
    (directory / "command.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"event": "command-start", **result}), flush=True)
    started = time.monotonic()
    with (directory / "stdout.log").open("wb") as out:
        with (directory / "stderr.log").open("wb") as err:
            try:
                # The Actions job owns the finite deadline and process tree.
                # Write streams from spawn onward so timeout output survives.
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
                result.update(
                    outcome="ERROR", exit_code=None, error=traceback.format_exc()
                )
            finally:
                result["elapsed"] = time.monotonic() - started
                (directory / "command.json").write_text(
                    json.dumps(result, indent=2) + "\n", encoding="utf-8"
                )
    print(json.dumps({"event": "command-complete", **result}), flush=True)
    for name in ("stdout.log", "stderr.log"):
        lines = (
            (directory / name)
            .read_text(encoding="utf-8", errors="replace")
            .splitlines()
        )
        print(f"{name}: {len(lines)} retained lines; final 40 follow", flush=True)
        for line in lines[-40:]:
            print(line, flush=True)
    return result["exit_code"] if result["exit_code"] is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
