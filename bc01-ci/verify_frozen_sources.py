"""Actions-only exact frozen bytes for reusable downstream quality jobs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main() -> int:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Actions-only source gate")
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    data = Path(__file__).with_name("CI-INPUTS.json").read_bytes()
    index = json.loads(data)
    reasons = []
    if hashlib.sha256(data).hexdigest() != os.environ["FR13_INPUT_SHA256"]:
        reasons.append("input index does not match dispatch")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root).decode().strip()
    if head != os.environ["FR13_EXECUTION_COMMIT"]:
        reasons.append("installer checkout does not match fixed execution commit")
    firmware = root / "Firmware MCP New"
    if not firmware.is_dir():
        firmware = root / "BYO-Firmware-MCP"
    firmware_head = (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=firmware).decode().strip()
    )
    if firmware_head != index["firmware_export"]["commit"]:
        reasons.append("firmware checkout does not match exact export")
    files = {}
    for relative, expected in index["files"].items():
        path = (
            (firmware / relative.removeprefix("Firmware MCP New/"))
            if relative.startswith("Firmware MCP New/")
            else root / relative
        )
        try:
            content = path.read_bytes()
            files[relative] = {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        except OSError as exc:
            files[relative] = {"error": repr(exc)}
        if files[relative] != expected:
            reasons.append("frozen byte mismatch: " + relative)
    output = root / "release/build/final-acceptance" / ("exact-source-" + args.phase + ".json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            {
                "phase": args.phase,
                "files": files,
                "reasons": reasons,
                "installer_head": head,
                "firmware_head": firmware_head,
                "input_sha256": hashlib.sha256(data).hexdigest(),
                "confirmed": not reasons,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"phase": args.phase, "files": len(files), "reasons": reasons}))
    return int(bool(reasons))


if __name__ == "__main__":
    raise SystemExit(main())
