#!/usr/bin/env python3
"""Serialize three passive tier inputs through the real Firmware store API.

This creates input data only. It does not connect a board or start the server.
Run in Actions with --server, --out and --manifest; both outputs must be new.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    server, output = args.server.resolve(strict=True), args.out.resolve()
    if output.exists() or args.manifest.exists():
        parser.error("outputs must be new")
    sys.path[:0] = [str(server / "src"), str(server)]
    from pyocd_debug_mcp.capabilities.policy import CapabilityPolicyRepository, Tier
    from tests.tiered_acceptance_support import confirmed_lite_policy, known_good_full_policy

    for name in ("no_setup", "setup_lite", "setup_full"):
        (output / name).mkdir(parents=True)
    CapabilityPolicyRepository(output / "no_setup").resolve("raw_board")
    CapabilityPolicyRepository(output / "setup_lite").commit(
        "lite_board", Tier.SETUP_LITE, map_snapshot=confirmed_lite_policy("lite_board"),
        evidence={"source": "confirmed"})
    profile, memory_map = known_good_full_policy()
    CapabilityPolicyRepository(output / "setup_full").commit(
        "legacy_full", Tier.SETUP_FULL, profile_snapshot=profile,
        map_snapshot=memory_map, evidence={"identity": "exact"})
    commit = subprocess.run(["git", "-C", str(server), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True).stdout.strip()
    fixtures = {}
    for state in output.iterdir():
        fixtures[state.name] = {}
        for path in state.rglob("*"):
            if path.is_file():
                data = path.read_bytes()
                fixtures[state.name][path.relative_to(state).as_posix()] = {
                    "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
                    "base64": base64.b64encode(data).decode("ascii")}
    value = {"schema": "installed-analysis-availability/v3",
             "generation_receipt": {"server_commit": commit,
                                    "generator": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
             "fixtures": fixtures,
             "cases": [{"state": state, "variant": None, "profile": "personal",
                        "board_id": board, "fixture": state}
                       for state, board in (("no_setup", "raw_board"), ("setup_lite", "lite_board"),
                                            ("setup_full", "legacy_full"))]}
    args.manifest.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
