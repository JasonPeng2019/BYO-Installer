"""Acquire and execute the pinned test compiler on its native CI build host.

This preflight checks archive extraction and host loader compatibility before a
full product build. It does not establish real ARM program or product acceptance.
Compiler archives remain in the fresh input directory, outside retained evidence.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import acquire_arm_test_toolchain as arm
import analysis_tools


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-target", choices=arm.TARGETS, required=True)
    parser.add_argument("--input-directory", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    target = args.expected_target
    if target != analysis_tools.host_target():
        parser.error("Compiler preflight requires its matching native host")
    if args.evidence.exists() or args.evidence.is_symlink():
        parser.error("Choose a fresh evidence directory")
    args.evidence.mkdir(parents=True)
    result: dict = {"target": target, "confirmed": False}
    try:
        receipt = arm.acquire(target, args.input_directory)
        result["input_receipt"] = receipt
        compiler = Path(receipt["compiler"])
        if arm.inputs.digest(compiler) != receipt["compiler_sha256"]:
            raise RuntimeError("Compiler bytes changed before native execution")
        arguments = [str(compiler), "--version"]
        result.update(arguments=arguments, exit_code=None)
        completed = subprocess.run(arguments, capture_output=True, timeout=30)
        result.update(arguments=arguments, exit_code=completed.returncode)
        (args.evidence / "compiler.stdout").write_bytes(completed.stdout)
        (args.evidence / "compiler.stderr").write_bytes(completed.stderr)
        if completed.returncode:
            raise RuntimeError(
                "Pinned compiler cannot execute on the native build host"
            )
        if arm.inputs.digest(compiler) != receipt["compiler_sha256"]:
            raise RuntimeError("Compiler bytes changed during native execution")
        result["confirmed"] = True
    except subprocess.TimeoutExpired as error:
        (args.evidence / "compiler.stdout").write_bytes(error.output or b"")
        (args.evidence / "compiler.stderr").write_bytes(error.stderr or b"")
        result["error"] = f"{type(error).__name__}: {error}"
        print(result["error"])
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
        print(result["error"])
    finally:
        with (args.evidence / "native-input.json").open(
            "x", encoding="utf-8"
        ) as stream:
            json.dump(result, stream, sort_keys=True, indent=2)
            stream.write("\n")
    return 0 if result["confirmed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
