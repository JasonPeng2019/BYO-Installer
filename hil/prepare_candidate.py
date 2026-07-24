#!/usr/bin/env python3
"""Extract and install one exact HIL candidate without using a source checkout."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

from clean_candidate import extract_exact, sha256


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    archives = [
        path
        for path in args.candidate.rglob("byo-*")
        if path.is_file() and (path.suffix == ".zip" or path.name.endswith(".tar.gz"))
    ]
    if len(archives) != 1:
        raise RuntimeError(f"expected one exact HIL archive, found {archives}")
    archive = archives[0]
    checksums = list(args.candidate.rglob(f"{archive.name.split('.zip')[0].split('.tar.gz')[0]}.sha256"))
    if len(checksums) != 1 or checksums[0].read_text(encoding="utf-8").split()[0] != sha256(archive):
        raise RuntimeError("HIL candidate does not match its build checksum")

    args.home.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="byo-hil-candidate-") as raw:
        bundle = extract_exact(archive, Path(raw))
        launcher = bundle / ("byo.exe" if os.name == "nt" else "byo")
        environment = {**os.environ, "BYO_HOME": str(args.home)}
        subprocess.run(
            [str(launcher), "install-runtime", "--bundle", str(bundle)],
            env=environment,
            check=True,
        )
    installed = args.home / "bin" / ("byo.exe" if os.name == "nt" else "byo")
    if not installed.is_file():
        raise RuntimeError("exact HIL launcher was not installed")
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(
        json.dumps(
            {
                "schema": 1,
                "archive": archive.name,
                "archive_sha256": sha256(archive),
                "launcher": str(installed),
                "launcher_sha256": hashlib.sha256(installed.read_bytes()).hexdigest(),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
