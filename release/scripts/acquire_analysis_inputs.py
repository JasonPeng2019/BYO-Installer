"""Explicitly acquire hash-pinned analyzer archives before an offline local build."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

import analysis_tools


TARGETS = ("windows-x86_64", "macos-aarch64", "macos-x86_64", "linux-x86_64")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def acquire(target: str, output: Path) -> dict:
    """Reuse matching inputs; atomically publish only verified new downloads."""
    lock = analysis_tools.load_lock(target=target)
    sources = {}
    for name, program in lock["programs"].items():
        source = program["source"]
        archive = analysis_tools.safe_relative(source["archive"])
        address = urllib.parse.urlsplit(source["url"])
        if (
            "/" in archive
            or address.scheme != "https"
            or not address.hostname
            or address.username is not None
            or address.password is not None
            or not re.fullmatch(r"[0-9a-f]{64}", source["sha256"])
        ):
            raise RuntimeError(f"Invalid pinned archive source for {name}")
        if archive in sources and sources[archive] != source:
            raise RuntimeError(f"Conflicting pinned archive sources: {archive}")
        sources[archive] = source
    if output.is_symlink():
        raise RuntimeError(f"Input directory must not be a symlink: {output}")
    output.mkdir(parents=True, exist_ok=True)
    output = output.resolve(strict=True)
    receipts = []
    for archive, source in sources.items():
        destination = output / archive
        if destination.is_symlink():
            raise RuntimeError(f"Input archive must not be a symlink: {destination}")
        if destination.exists():
            if not destination.is_file() or digest(destination) != source["sha256"]:
                raise RuntimeError(
                    f"Existing input differs from its pin: {destination}; "
                    "choose a fresh input directory or replace it explicitly"
                )
        else:
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(
                    prefix=f".{archive}.", suffix=".partial", dir=output, delete=False
                ) as stream:
                    temporary = Path(stream.name)
                    request = urllib.request.Request(
                        source["url"],
                        headers={"User-Agent": "BYO-analysis-input-acquisition"},
                    )
                    with urllib.request.urlopen(request, timeout=60) as response:
                        if urllib.parse.urlsplit(response.geturl()).scheme != "https":
                            raise RuntimeError(
                                f"Insecure archive redirect for {archive}"
                            )
                        for chunk in iter(lambda: response.read(1024 * 1024), b""):
                            stream.write(chunk)
                actual = digest(temporary)
                if actual != source["sha256"]:
                    raise RuntimeError(
                        f"Pinned archive SHA-256 mismatch for {archive}: "
                        f"expected {source['sha256']}, observed {actual}"
                    )
                # This utility has one writer per output directory. Never replace
                # an input created by another invocation during the download.
                if destination.exists() or destination.is_symlink():
                    raise RuntimeError(
                        f"Input appeared while downloading: {destination}"
                    )
                os.link(temporary, destination)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
        receipts.append(
            {
                "archive": archive,
                "url": source["url"],
                "sha256": source["sha256"],
                "size": destination.stat().st_size,
            }
        )
    return {"target": target, "input_dir": str(output), "archives": receipts}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-target", choices=TARGETS, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = acquire(args.expected_target, args.output)
    except (OSError, RuntimeError, ValueError) as error:
        parser.exit(2, f"Analyzer input acquisition failed: {error}\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
