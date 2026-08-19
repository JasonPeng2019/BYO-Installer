#!/usr/bin/env python3
"""Verify and test one exact signed candidate on an otherwise clean host."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from xml.etree.ElementTree import Element, ElementTree, SubElement

MAX_ENTRIES = 20_000
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024


def sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def safe_relative(name: str, seen: set[str]) -> Path:
    path = PurePosixPath(name)
    normalized = name.rstrip("/").lower()
    if (
        "\\" in name
        or path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or normalized in seen
    ):
        raise RuntimeError(f"candidate archive contains an unsafe path: {name!r}")
    seen.add(normalized)
    return Path(*path.parts)


def extract_exact(archive: Path, destination: Path) -> Path:
    seen: set[str] = set()
    total = 0
    entries = 0
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as handle:
            for member in handle.infolist():
                entries += 1
                relative = safe_relative(member.filename, seen)
                file_type = (member.external_attr >> 16) & 0o170000
                if file_type not in {0, 0o040000, 0o100000}:
                    raise RuntimeError("candidate ZIP contains a forbidden entry type")
                if member.file_size > MAX_FILE_BYTES:
                    raise RuntimeError("candidate ZIP contains an oversized file")
                total += member.file_size
                target = destination / relative
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with handle.open(member) as source, target.open("xb") as output:
                        shutil.copyfileobj(source, output)
                    if os.name != "nt" and member.external_attr >> 16:
                        target.chmod((member.external_attr >> 16) & 0o777)
                if entries > MAX_ENTRIES or total > MAX_TOTAL_BYTES:
                    raise RuntimeError("candidate ZIP exceeds extraction limits")
    else:
        with tarfile.open(archive, "r:gz") as handle:
            for member in handle:
                entries += 1
                relative = safe_relative(member.name, seen)
                if not (member.isfile() or member.isdir()):
                    raise RuntimeError("candidate tar contains a forbidden entry type")
                if member.size > MAX_FILE_BYTES:
                    raise RuntimeError("candidate tar contains an oversized file")
                total += member.size
                target = destination / relative
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = handle.extractfile(member)
                    if source is None:
                        raise RuntimeError("candidate tar file could not be read")
                    with source, target.open("xb") as output:
                        shutil.copyfileobj(source, output)
                    if os.name != "nt":
                        target.chmod(member.mode & 0o777)
                if entries > MAX_ENTRIES or total > MAX_TOTAL_BYTES:
                    raise RuntimeError("candidate tar exceeds extraction limits")
    roots = [path for path in destination.iterdir() if path.is_dir()]
    if entries == 0 or len(roots) != 1:
        raise RuntimeError("candidate archive does not contain exactly one bundle")
    return roots[0]


def run_checked(argv: list[str]) -> str:
    completed = subprocess.run(
        argv,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"{argv!r} failed:\n{completed.stdout}")
    return completed.stdout


def verify_platform(bundle: Path, archive: Path, public_key: Path | None) -> list[str]:
    evidence: list[str] = []
    if sys.platform == "darwin":
        subprocess.run(
            ["xattr", "-w", "com.apple.quarantine", "0081;BYO", str(bundle)], check=True
        )
        evidence.append(
            run_checked(["codesign", "--verify", "--deep", "--strict", str(bundle)])
        )
        for executable in (
            bundle / "byo",
            bundle / "sidecar/byo-mcp-sidecar",
        ):
            evidence.append(
                run_checked(["spctl", "--assess", "--type", "execute", str(executable)])
            )
    elif os.name == "nt":
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            raise RuntimeError("PowerShell is unavailable")
        script = Path(__file__).with_name("verify_authenticode.ps1")
        evidence.append(
            run_checked(
                [
                    powershell,
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                    str(script),
                    "-Bundle",
                    str(bundle),
                ]
            )
        )
    else:
        libc = run_checked(["getconf", "GNU_LIBC_VERSION"]).strip()
        if libc != "glibc 2.28":
            raise RuntimeError(
                f"clean Linux runner is not the declared baseline: {libc}"
            )
        signature = archive.with_name(f"{archive.name}.sig")
        if public_key is None or not signature.is_file():
            raise RuntimeError(
                "Linux clean test requires the detached signature and public key"
            )
        evidence.append(
            run_checked(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-rawin",
                    "-pubin",
                    "-inkey",
                    str(public_key),
                    "-sigfile",
                    str(signature),
                    "-in",
                    str(archive),
                ]
            )
        )
    return evidence


def write_junit(path: Path, failure: BaseException | None) -> None:
    suite = Element(
        "testsuite",
        name="BYO exact signed clean-machine contract",
        tests="1",
        failures="1" if failure else "0",
    )
    case = SubElement(suite, "testcase", classname="release", name="exact-candidate")
    if failure:
        SubElement(case, "failure", message=str(failure)).text = str(failure)
    path.parent.mkdir(parents=True, exist_ok=True)
    ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--public-key", type=Path)
    args = parser.parse_args()
    failure: BaseException | None = None
    try:
        archives = [
            path
            for path in args.candidate.rglob("byo-*")
            if path.is_file()
            and (path.suffix == ".zip" or path.name.endswith(".tar.gz"))
        ]
        if len(archives) != 1:
            raise RuntimeError(
                f"expected exactly one signed candidate archive, found {archives}"
            )
        archive = archives[0]
        checksum_files = list(
            args.candidate.rglob(
                f"{archive.name.removesuffix('.zip').removesuffix('.tar.gz')}.sha256"
            )
        )
        if len(checksum_files) != 1:
            raise RuntimeError("candidate checksum receipt is missing or ambiguous")
        expected = checksum_files[0].read_text(encoding="utf-8").split()[0]
        if sha256(archive) != expected:
            raise RuntimeError(
                "exact candidate SHA-256 does not match its build receipt"
            )
        with tempfile.TemporaryDirectory(prefix="byo-exact-candidate-") as raw:
            bundle = extract_exact(archive, Path(raw))
            evidence = verify_platform(bundle, archive, args.public_key)
            test = Path(__file__).with_name("test_installed_e2e.py")
            evidence.append(
                run_checked(
                    [
                        sys.executable,
                        str(test),
                        "--bundle",
                        str(bundle),
                        "--archive",
                        str(archive),
                    ]
                )
            )
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "archive": archive.name,
                    "archive_sha256": sha256(archive),
                    "platform": sys.platform,
                    "evidence": evidence,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    except BaseException as exc:
        failure = exc
    write_junit(args.junit, failure)
    if failure:
        raise failure
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
