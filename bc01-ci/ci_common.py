"""Actions-only paths, metadata, and exact source gates for FR13."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import time
from pathlib import Path
from typing import Any

CLOCK = time.monotonic
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIRMWARE = ROOT / "Firmware MCP New"
RUNTIME = ROOT / "fr13-runtime"
EVIDENCE = RUNTIME / "evidence"
VENV = RUNTIME / "venv"
UV_BOOTSTRAP = RUNTIME / "uv-bootstrap"
UV_CACHE = RUNTIME / "uv-cache"
CONTAINER = (
    "quay.io/pypa/manylinux_2_28_x86_64@sha256:"
    "fdb9a9c223b215604dc7b6f7e8fff4b39bfea5fbaa7777a2e5544a60dfa437f8"
)


def actions_only() -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("FR13 execution helpers run only in GitHub Actions")


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, default=str) + "\n", encoding="utf-8")


def compact(kind: str, **values: Any) -> None:
    print(json.dumps({"kind": kind, **values}, default=str), flush=True)


def command(argv: list[str], cwd: Path = ROOT, timeout: int = 30) -> dict[str, Any]:
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return {
            "argv": argv,
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"argv": argv, "exit_code": None, "error": repr(exc)}


def git(directory: Path, *arguments: str) -> dict[str, Any]:
    return command(["git", "-c", f"safe.directory={directory}", "-C", str(directory), *arguments])


def source_snapshot(execution_commit: str, input_sha256: str) -> dict[str, Any]:
    reasons: list[str] = []
    index: dict[str, Any] = {}
    measured: dict[str, Any] = {}
    index_hash = None
    try:
        data = (HERE / "CI-INPUTS.json").read_bytes()
        index_hash = hashlib.sha256(data).hexdigest()
        index = json.loads(data)
        if index_hash != input_sha256:
            reasons.append("input_index_hash_mismatch")
        for name, expected in index["files"].items():
            path = ROOT / name
            try:
                content = path.read_bytes()
                actual = {
                    "bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
                measured[name] = actual
                if actual != expected:
                    reasons.append("source_file_mismatch:" + name)
            except OSError as exc:
                measured[name] = {"error": repr(exc)}
                reasons.append("source_file_unavailable:" + name)
        for directory in (FIRMWARE / "src", FIRMWARE / "tests", HERE):
            for path in directory.rglob("*.py"):
                relative = path.relative_to(ROOT).as_posix()
                if relative not in index["files"]:
                    reasons.append("unexpected_source_file:" + relative)
    except (OSError, KeyError, ValueError, TypeError) as exc:
        reasons.append("input_index_unavailable_or_invalid:" + repr(exc))
    sources = {
        "execution": git(ROOT, "rev-parse", "HEAD"),
        "firmware": git(FIRMWARE, "rev-parse", "HEAD"),
        "firmware_tree": git(FIRMWARE, "rev-parse", "HEAD^{tree}"),
    }
    expected_git = {
        "execution": execution_commit,
        "firmware": index.get("firmware_export", {}).get("commit"),
        "firmware_tree": index.get("firmware_export", {}).get("tree"),
    }
    for name, expected in expected_git.items():
        result = sources[name]
        if (
            not expected
            or result.get("exit_code") != 0
            or result.get("stdout", "").strip() != expected
        ):
            reasons.append("git_binding_unconfirmed:" + name)
    return {
        "input_index_sha256": index_hash,
        "expected_input_sha256": input_sha256,
        "files": measured,
        "git": sources,
        "reasons": sorted(set(reasons)),
        "confirmed": not reasons,
        "validation_only_overlay": index.get("validation_only_overlay"),
        "candidate": index.get("candidate"),
    }


def host_facts(expected: str) -> dict[str, Any]:
    import sys

    system, machine = platform.system(), platform.machine().lower()
    libc = platform.libc_ver()
    facts: dict[str, Any] = {
        "system": system,
        "machine": machine,
        "platform": platform.platform(),
        "python": sys.version,
        "version_info": list(sys.version_info[:3]),
        "executable": sys.executable,
        "prefix": sys.prefix,
        "base_prefix": sys.base_prefix,
        "libc": libc,
        "cwd": str(Path.cwd()),
        "workspace": str(ROOT),
        "evidence_directory": str(EVIDENCE),
        "expected": expected,
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "sha": os.environ.get("GITHUB_SHA"),
        "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF"),
        "runner_os": os.environ.get("RUNNER_OS"),
        "runner_arch": os.environ.get("RUNNER_ARCH"),
        "image_os": os.environ.get("ImageOS"),
        "image_version": os.environ.get("ImageVersion"),
        "native_os_version": platform.mac_ver()[0] if system == "Darwin" else platform.version(),
    }
    matches = {
        "windows-x86_64": system == "Windows" and machine in {"amd64", "x86_64"},
        "macos-aarch64": system == "Darwin" and machine in {"aarch64", "arm64"},
        "macos-x86_64": system == "Darwin" and machine == "x86_64",
        "linux-x86_64-glibc-2.28": system == "Linux" and machine == "x86_64",
    }
    if system == "Windows":
        matches["windows-x86_64"] = matches["windows-x86_64"] and "2022" in facts["platform"]
    if system == "Darwin":
        for target in ("macos-aarch64", "macos-x86_64"):
            matches[target] = matches[target] and platform.mac_ver()[0].split(".")[0] == "15"
    if system == "Linux":
        facts["getconf"] = command(["getconf", "GNU_LIBC_VERSION"])
        facts["required_container"] = CONTAINER
        matches["linux-x86_64-glibc-2.28"] = (
            matches["linux-x86_64-glibc-2.28"]
            and libc == ("glibc", "2.28")
            and facts["getconf"].get("exit_code") == 0
            and facts["getconf"].get("stdout", "").strip() == "glibc 2.28"
        )
    facts["matches_expected"] = matches.get(expected, False)
    return facts
