#!/usr/bin/env python3
"""Offline generator for passive availability fixture bytes (not run by tests).

Run once with the accepted server checkout's own interpreter:

  <server>/.venv/Scripts/python.exe -I generate.py --server <accepted server root> \
    --out <new short work dir> --manifest <new manifest.json>

It serializes state ONLY through the accepted public persistence classes
(CapabilityPolicyRepository.commit/resolve/mark_setup_incomplete and
AttachmentCache.confirm/revoke) plus the accepted test fixture builders for the
one valid lite/full snapshot. It never starts a server, touches hardware or
probes. The receipt records the server commit/tree and every imported product
module file digest. Every produced file is packed into one hash-bound
installed-analysis-availability/v3 manifest as exact base64 bytes (the deep .firm
paths exceed Windows path limits below long checkouts). The committed manifest
is then frozen; installed tests verify it with independent stdlib checks and
public responses. Case labels here are claims only: the validator derives the
expected public values from the bytes.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    server = args.server.resolve()
    out = args.out.resolve()
    if out.exists() or args.manifest.exists():
        raise SystemExit("work directory and manifest must be NEW")
    sys.path[:0] = [str(server / "src"), str(server)]
    from pyocd_debug_mcp.capabilities.policy import CapabilityPolicyRepository, Tier
    from pyocd_debug_mcp.firmstore.cache import (
        AttachmentCache,
        ProbeIdentity,
        SerialEndpoint,
    )
    from pyocd_debug_mcp.firmstore.store import FirmStore
    from tests.tiered_acceptance_support import (
        confirmed_lite_policy,
        known_good_full_policy,
    )

    def full(root: Path, evidence: dict) -> CapabilityPolicyRepository:
        repository = CapabilityPolicyRepository(root)
        profile, memory_map = known_good_full_policy()
        repository.commit(
            "legacy_full",
            Tier.SETUP_FULL,
            profile_snapshot=profile,
            map_snapshot=memory_map,
            evidence=evidence,
        )
        return repository

    for name in (
        "no_board",
        "no_setup",
        "setup_lite",
        "setup_full",
        "revoked",
        "unvalidated",
        "corrupt_policy",
    ):
        (out / name).mkdir(parents=True)
    CapabilityPolicyRepository(out / "no_setup").resolve("raw_board")
    CapabilityPolicyRepository(out / "setup_lite").commit(
        "lite_board",
        Tier.SETUP_LITE,
        map_snapshot=confirmed_lite_policy("lite_board"),
        evidence={"source": "confirmed"},
    )
    full(out / "setup_full", {"identity": "exact"})
    full(out / "unvalidated", {"source": "passive-unvalidated-fixture"})
    full(out / "revoked", {"identity": "exact"}).mark_setup_incomplete("legacy_full")
    cache = AttachmentCache(FirmStore(out / "revoked"))
    probe = ProbeIdentity("cmsis-dap", "REVOKED-PROBE-0001")
    uart = SerialEndpoint("COM-not-opened", "REVOKED-UART-0001", 4660, 22136)
    cache.confirm("legacy_full", probe, uart, confirmed_at="2026-01-01T00:00:00+00:00")
    if not cache.revoke(
        "legacy_full", probe, uart, revoked_at="2026-02-01T00:00:00+00:00"
    ):
        raise SystemExit("accepted cache did not revoke the confirmed record")
    corrupt = out / "corrupt_policy/.firm/capabilities/corrupt_board"
    corrupt.mkdir(parents=True)
    (corrupt / "current.json").write_bytes(b"not-json\n")

    def git(*argv: str) -> str:
        return subprocess.run(
            ["git", "-C", str(server), *argv],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    imported = sorted(
        {
            Path(module.__file__).resolve()
            for name, module in list(sys.modules.items())
            if name.startswith(("pyocd_debug_mcp", "tests"))
            and getattr(module, "__file__", None)
        }
    )
    receipt = {
        "schema": "availability-fixture-generation/v1",
        "generator": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "server_root": str(server),
        "server_commit": git("rev-parse", "HEAD"),
        "server_tree": git("rev-parse", "HEAD^{tree}"),
        "server_tracked_status": git("status", "--porcelain", "--untracked-files=no"),
        "python": sys.version,
        "imported_files": {
            str(path.relative_to(server)).replace("\\", "/"): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in imported
            if path.is_relative_to(server)
        },
    }
    fixtures = {
        state.name: {
            path.relative_to(state).as_posix(): {
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "size": path.stat().st_size,
                "base64": base64.b64encode(path.read_bytes()).decode("ascii"),
            }
            for path in sorted(state.rglob("*"))
            if path.is_file()
        }
        for state in sorted(out.iterdir())
    }
    claims = (
        ("no_board", None, "absent_board", "no_board"),
        ("no_setup", None, "raw_board", "no_setup"),
        ("setup_lite", None, "lite_board", "setup_lite"),
        ("setup_full", None, "legacy_full", "setup_full"),
        ("revoked_unvalidated", "revoked", "legacy_full", "revoked"),
        ("revoked_unvalidated", "unvalidated", "legacy_full", "unvalidated"),
        ("corrupt_policy", None, "corrupt_board", "corrupt_policy"),
    )
    manifest = {
        "schema": "installed-analysis-availability/v3",
        "generation_receipt": receipt,
        "fixtures": fixtures,
        "cases": [
            {
                "state": state,
                "variant": variant,
                "profile": profile,
                "board_id": board,
                "fixture": fixture,
            }
            for profile in ("personal", "professional")
            for state, variant, board, fixture in claims
        ],
    }
    args.manifest.write_bytes(
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
