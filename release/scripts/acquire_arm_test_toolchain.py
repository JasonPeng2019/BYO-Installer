"""Acquire a pinned native ARM compiler fixture for remote installed smoke tests.

This fixture is separate from shipped analyzer inputs. --expected-target selects
one recorded host archive; --output is an owned fresh extraction directory. The
JSON receipt binds the upstream archive pin and measured compiler bytes. Failed
or existing extraction directories require a fresh output, never implicit removal.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

import acquire_analysis_inputs as inputs

TARGETS = ("windows-x86_64", "linux-x86_64", "macos-aarch64", "macos-x86_64")
LOCK = Path(__file__).resolve().parents[1] / "arm-test-toolchains.json"


def load_source(target: str) -> dict:
    if target not in TARGETS:
        raise ValueError(f"Unsupported ARM test input target: {target}")
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    if (
        set(lock) != {"schema_version", "targets"}
        or type(lock["schema_version"]) is not int
        or lock["schema_version"] != 1
        or not isinstance(lock["targets"], dict)
        or set(lock["targets"]) != set(TARGETS)
    ):
        raise ValueError("Invalid four-target ARM test input lock")
    source = lock["targets"][target]
    if (
        not isinstance(source, dict)
        or set(source)
        != {
            "version",
            "archive",
            "url",
            "checksum_url",
            "sha256",
            "directory",
            "compiler",
            "archive_layout",
        }
        or not all(isinstance(value, str) and value for value in source.values())
        or not re.fullmatch(r"[0-9a-f]{64}", source["sha256"])
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.rel[0-9]+", source["version"])
        or source["checksum_url"] != source["url"] + ".sha256asc"
        or source["url"]
        != (
            "https://developer.arm.com/-/media/Files/downloads/gnu/"
            + source["version"]
            + "/binrel/"
            + source["archive"]
        )
        or source["compiler"]
        != ("bin/arm-none-eabi-g++" + (".exe" if target == "windows-x86_64" else ""))
        or source["archive_layout"]
        != ("flat" if target == "windows-x86_64" else "rooted")
    ):
        raise ValueError("Invalid pinned ARM test toolchain source")
    try:
        inputs._source_archive(source)
        if "/" in inputs.analysis_tools.safe_relative(source["directory"]):
            raise ValueError("ARM archive directory must be one component")
    except RuntimeError as error:
        raise ValueError(str(error)) from error
    return source


def _member_name(name: str, directory: str | None) -> None:
    path = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or ":" in name
        or path.is_absolute()
        or ".." in path.parts
        or not path.parts
        or (directory is not None and path.parts[0] != directory)
    ):
        raise RuntimeError(f"Unexpected ARM test archive member: {name!r}")


def _expand(archive: Path, output: Path, source: dict) -> None:
    if archive.suffix == ".zip":
        flat = source["archive_layout"] == "flat"
        destination = output / source["directory"] if flat else output
        with zipfile.ZipFile(archive) as handle:
            seen = set()
            for member in handle.infolist():
                _member_name(member.filename, None if flat else source["directory"])
                key = member.filename.rstrip("/").casefold()
                if key in seen or stat.S_IFMT(member.external_attr >> 16) not in {
                    0,
                    stat.S_IFREG,
                    stat.S_IFDIR,
                }:
                    raise RuntimeError("Duplicate or special ARM ZIP member")
                seen.add(key)
            if flat:
                destination.mkdir()
            handle.extractall(destination)
    else:
        with tarfile.open(archive, "r:xz") as handle:

            def owned_data(member, destination):
                _member_name(member.name, source["directory"])
                return tarfile.data_filter(member, destination)

            # Python 3.12's data filter keeps vendor-internal links within the
            # owned extraction and refuses external links/devices/traversal.
            handle.extractall(output, filter=owned_data)


def acquire(target: str, output: Path) -> dict:
    source = load_source(target)
    if output.is_symlink():
        raise RuntimeError("ARM input output must be an owned directory without links")
    if (output / "toolchain").exists() or (output / "toolchain").is_symlink():
        raise RuntimeError("Choose a fresh ARM toolchain extraction directory")
    output.mkdir(parents=True, exist_ok=True)
    output = output.resolve(strict=True)
    archive = inputs.acquire_archive(source, output, user_agent="curl/8.7.1")
    expanded = output / "toolchain"
    expanded.mkdir()
    _expand(output / source["archive"], expanded, source)
    try:
        compiler = (expanded / source["directory"] / source["compiler"]).resolve(
            strict=True
        )
    except OSError as error:
        raise RuntimeError(
            "Pinned ARM archive has no accessible compiler in its owned root"
        ) from error
    if not compiler.is_relative_to(expanded) or not compiler.is_file():
        raise RuntimeError(
            "Pinned ARM archive has no regular compiler in its owned root"
        )
    if (
        os.name != "nt"
        and target != "windows-x86_64"
        and not os.access(compiler, os.X_OK)
    ):
        raise RuntimeError("Pinned native ARM compiler lacks executable access")
    return {
        "schema": "arm-test-toolchain-input/v1",
        "target": target,
        "version": source["version"],
        "archive_layout": source["archive_layout"],
        "archive": archive,
        "root": str(expanded / source["directory"]),
        "compiler": str(compiler),
        "compiler_sha256": inputs.digest(compiler),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-target", choices=TARGETS, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = acquire(args.expected_target, args.output)
    except (
        OSError,
        RuntimeError,
        ValueError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as error:
        parser.exit(2, f"ARM test input acquisition failed: {error}\n")
    print(json.dumps(receipt, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
