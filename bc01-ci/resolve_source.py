"""Resolve the scoped checkout from the same exact lock used by release builds."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from ci_common import EVIDENCE, HERE, ROOT, actions_only, git, write


def resolve(index_data: bytes, lock_data: bytes, expected_index_sha256: str) -> dict[str, Any]:
    """Require exact commit equality; matching file trees never replace it."""
    index_sha = hashlib.sha256(index_data).hexdigest()
    if index_sha != expected_index_sha256:
        raise ValueError("Frozen input index SHA256 mismatch before checkout")
    index = json.loads(index_data)
    lock = json.loads(lock_data)
    frozen_lock = index["files"]["release/source-lock.json"]
    actual_lock = {
        "bytes": len(lock_data),
        "sha256": hashlib.sha256(lock_data).hexdigest(),
    }
    if actual_lock != frozen_lock:
        raise ValueError("Source lock bytes differ from the frozen input index")
    firmware = lock["firmware_mcp"]
    commit = firmware["commit"]
    if firmware["repository"] != "JasonPeng2019/BYO-Firmware-MCP":
        raise ValueError("Unexpected firmware repository in source lock")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Firmware checkout requires a full exact commit")
    if commit != index["firmware_export"]["commit"]:
        raise ValueError("Source lock and frozen firmware export commits differ")
    return {
        "firmware": commit,
        "firmware_tree": index["firmware_export"]["tree"],
        "input_sha256": index_sha,
        "source_lock": actual_lock,
        "repository": firmware["repository"],
        "branch": firmware["branch"],
    }


def main() -> int:
    actions_only()
    parser = argparse.ArgumentParser()
    parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()
    record: dict[str, Any] = {"confirmed": False}
    try:
        execution = git(ROOT, "rev-parse", "HEAD")
        record["execution"] = execution
        if execution.get("exit_code") != 0 or execution.get("stdout", "").strip() != os.environ.get(
            "FR13_EXECUTION_COMMIT"
        ):
            raise ValueError("Installer checkout differs from the dispatched execution commit")
        record.update(
            resolve(
                (HERE / "CI-INPUTS.json").read_bytes(),
                (ROOT / "release/source-lock.json").read_bytes(),
                os.environ.get("FR13_INPUT_SHA256", ""),
            )
        )
        record["confirmed"] = True
        with args.github_output.open("a", encoding="utf-8") as output:
            output.write("firmware=" + record["firmware"] + "\n")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        record["error"] = repr(exc)
    write(EVIDENCE / "checkout-resolution.json", record)
    print(json.dumps(record), flush=True)
    return 0 if record["confirmed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
