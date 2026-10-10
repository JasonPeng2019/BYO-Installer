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


def _existing_input(destination: Path, expected_sha256: str) -> bool:
    if destination.is_symlink():
        raise RuntimeError(f"Input archive must not be a symlink: {destination}")
    if not destination.exists():
        return False
    if not destination.is_file() or digest(destination) != expected_sha256:
        raise RuntimeError(
            f"Existing input differs from its pin: {destination}; "
            "choose a fresh input directory or replace it explicitly"
        )
    return True


def _source_archive(source: dict) -> str:
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
        raise RuntimeError("Invalid pinned archive source")
    return archive


def acquire_archive(
    source: dict, output: Path, *, user_agent: str = "BYO-analysis-input-acquisition"
) -> dict:
    """Acquire one validated archive without replacing any existing input."""
    archive = _source_archive(source)
    if output.is_symlink():
        raise RuntimeError(f"Input directory must not be a symlink: {output}")
    output.mkdir(parents=True, exist_ok=True)
    output = output.resolve(strict=True)
    destination = output / archive
    if not _existing_input(destination, source["sha256"]):
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                prefix=f".{archive}.", suffix=".partial", dir=output, delete=False
            ) as stream:
                temporary = Path(stream.name)
                request = urllib.request.Request(
                    source["url"], headers={"User-Agent": user_agent}
                )
                with urllib.request.urlopen(request, timeout=60) as response:
                    if urllib.parse.urlsplit(response.geturl()).scheme != "https":
                        raise RuntimeError(f"Insecure archive redirect for {archive}")
                    for chunk in iter(lambda: response.read(1024 * 1024), b""):
                        stream.write(chunk)
            actual = digest(temporary)
            if actual != source["sha256"]:
                raise RuntimeError(
                    f"Pinned archive SHA-256 mismatch for {archive}: "
                    f"expected {source['sha256']}, observed {actual}"
                )
            # One writer per output directory. Publish without replacing an
            # input that appeared while downloading, including a broken link.
            if destination.exists() or destination.is_symlink():
                raise RuntimeError(f"Input appeared while downloading: {destination}")
            os.link(temporary, destination)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    return {
        "archive": archive,
        "url": source["url"],
        "sha256": source["sha256"],
        "size": destination.stat().st_size,
    }


def acquire(target: str, output: Path) -> dict:
    """Reuse matching inputs; atomically publish only verified new downloads."""
    lock = analysis_tools.load_lock(target=target)
    sources = {}
    for program in lock["programs"].values():
        source = program["source"]
        archive = _source_archive(source)
        if archive in sources and sources[archive] != source:
            raise RuntimeError(f"Conflicting pinned archive sources: {archive}")
        sources[archive] = source
    if output.is_symlink():
        raise RuntimeError(f"Input directory must not be a symlink: {output}")
    output.mkdir(parents=True, exist_ok=True)
    output = output.resolve(strict=True)
    # Refuse any invalid existing input before starting acquisition of others.
    for archive, source in sources.items():
        _existing_input(output / archive, source["sha256"])
    # The shared helper rechecks at use time as well: preflight is not a receipt
    # for later bytes. ALL existing slots above are still checked before network.
    receipts = [acquire_archive(source, output) for source in sources.values()]
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
