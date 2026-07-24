#!/usr/bin/env python3
"""Fail a native build when its bundle, provenance, or archive contract drifts."""

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
FORBIDDEN_SUFFIXES = {
    ".c",
    ".h",
    ".md",
    ".ps1",
    ".py",
    ".pyc",
    ".pyi",
    ".rs",
    ".sh",
}
MAX_ENTRIES = 20_000


def sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def expected_identity(target: str) -> tuple[str, str]:
    values = {
        "macos-aarch64": ("macos", "aarch64"),
        "macos-x86_64": ("macos", "x86_64"),
        "windows-x86_64": ("windows", "x86_64"),
        "linux-x86_64-glibc-2.28": ("linux", "x86_64"),
    }
    try:
        return values[target]
    except KeyError as exc:
        raise RuntimeError(f"unsupported build target contract: {target}") from exc


def validate_archive_paths(names: list[str], bundle_name: str) -> None:
    if not names or len(names) > MAX_ENTRIES:
        raise RuntimeError("archive is empty or contains too many entries")
    seen: set[str] = set()
    for name in names:
        path = PurePosixPath(name)
        normalized = name.rstrip("/").lower()
        if (
            "\\" in name
            or path.is_absolute()
            or not path.parts
            or path.parts[0] != bundle_name
            or any(part in {"", ".", ".."} for part in path.parts)
            or normalized in seen
        ):
            raise RuntimeError(f"archive contains an unsafe or duplicate path: {name!r}")
        seen.add(normalized)


def validate_archive(archive: Path, archive_type: str, bundle_name: str) -> None:
    if archive_type == "zip":
        if archive.suffix != ".zip":
            raise RuntimeError("ZIP target did not produce a .zip archive")
        with zipfile.ZipFile(archive) as handle:
            members = handle.infolist()
            validate_archive_paths([member.filename for member in members], bundle_name)
            for member in members:
                file_type = (member.external_attr >> 16) & 0o170000
                if file_type not in {0, 0o040000, 0o100000}:
                    raise RuntimeError("ZIP contains a forbidden non-file entry")
    elif archive_type == "tar.gz":
        if not archive.name.endswith(".tar.gz"):
            raise RuntimeError("Linux target did not produce a .tar.gz archive")
        with tarfile.open(archive, "r:gz") as handle:
            members = handle.getmembers()
            validate_archive_paths([member.name for member in members], bundle_name)
            if any(not (member.isfile() or member.isdir()) for member in members):
                raise RuntimeError("tar archive contains a forbidden non-file entry")
    else:
        raise RuntimeError(f"unsupported archive contract: {archive_type}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--expected-target", required=True)
    parser.add_argument("--archive-type", choices=("zip", "tar.gz"), required=True)
    args = parser.parse_args()

    platform, architecture = expected_identity(args.expected_target)
    bundles = sorted(
        path
        for path in args.dist.iterdir()
        if path.is_dir() and path.name.startswith("byo-")
    )
    if len(bundles) != 1:
        raise RuntimeError(f"expected exactly one native bundle, found {bundles}")
    bundle = bundles[0]
    manifest_path = bundle / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("platform") != platform or manifest.get("architecture") != architecture:
        raise RuntimeError("release manifest target does not match the native job")
    if manifest.get("development_unsigned") is not True:
        raise RuntimeError("unprotected build jobs may only produce development candidates")

    lock = json.loads((ROOT / "release/source-lock.json").read_text(encoding="utf-8"))
    source = manifest.get("source", {})
    for manifest_key, lock_key in (
        ("agent_workspace", "agent_workspace"),
        ("firmware_mcp", "firmware_mcp"),
    ):
        if source.get(manifest_key, {}).get("commit") != lock[lock_key]["commit"]:
            raise RuntimeError(f"manifest {manifest_key} commit does not match source lock")
    installer_commit = source.get("installer", {}).get("commit", "")
    if len(installer_commit) != 40:
        raise RuntimeError("manifest does not contain the installer source commit")
    toolchain = manifest.get("toolchain", {})
    if any(not isinstance(toolchain.get(key), str) or not toolchain[key] for key in (
        "rustc",
        "cargo",
        "python",
        "nuitka",
    )):
        raise RuntimeError("manifest does not contain complete toolchain provenance")

    forbidden = [
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file()
        and (
            path.suffix.lower() in FORBIDDEN_SUFFIXES
            or "__pycache__" in path.parts
            or path.name in {"Cargo.toml", "pyproject.toml", "uv.lock"}
        )
    ]
    if forbidden:
        raise RuntimeError(f"bundle leaked source or development files: {forbidden}")

    archives = sorted(
        path
        for path in args.dist.iterdir()
        if path.is_file()
        and (
            path.name == f"{bundle.name}.zip"
            or path.name == f"{bundle.name}.tar.gz"
        )
    )
    if len(archives) != 1:
        raise RuntimeError(f"expected one explicit release archive, found {archives}")
    archive = archives[0]
    validate_archive(archive, args.archive_type, bundle.name)
    checksum = (args.dist / f"{bundle.name}.sha256").read_text(encoding="utf-8").strip()
    if checksum != f"{sha256(archive)}  {archive.name}":
        raise RuntimeError("archive checksum receipt does not match the exact artifact")
    symbol_root = ROOT / "release" / "symbols" / bundle.name
    symbol_inventory = json.loads(
        (symbol_root / "symbols.json").read_text(encoding="utf-8")
    )
    symbol_paths = {
        item.get("path")
        for item in symbol_inventory.get("files", [])
        if isinstance(item, dict)
    }
    if "nuitka-compilation-report.xml" not in symbol_paths:
        raise RuntimeError("private symbol output is missing the Nuitka compilation report")
    expected_symbol_suffix = {
        "macos": ".dSYM/",
        "windows": ".pdb",
        "linux": ".debug",
    }[platform]
    if not any(
        (
            expected_symbol_suffix in str(path)
            if platform == "macos"
            else str(path).endswith(expected_symbol_suffix)
        )
        for path in symbol_paths
    ):
        raise RuntimeError(f"private symbol output is incomplete for {platform}")
    print(
        json.dumps(
            {
                "archive": str(archive),
                "archive_sha256": sha256(archive),
                "manifest_sha256": sha256(manifest_path),
                "target": args.expected_target,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
