"""Finite Actions acceptance command accounting in the existing release boundary.

Each command runs once, keeps its own streams/exit, and cannot suppress the
remaining independent commands. The aggregate stays failed. No build/source
provenance logic is replaced here.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]


def record_stages(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    sources = {}
    for name, directory in (
        ("installer", ROOT),
        ("firmware", ROOT / "Firmware MCP New"),
        ("workspace", ROOT / "AgentWorkspace"),
    ):
        result = subprocess.run(
            ["git", "-C", str(directory), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        sources[name] = {
            "exit": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    lock = ROOT / "release/source-lock.json"
    path.write_text(
        json.dumps(
            {
                "github_sha": os.environ.get("GITHUB_SHA"),
                "github_run_id": os.environ.get("GITHUB_RUN_ID"),
                "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
                "github_ref": os.environ.get("GITHUB_REF"),
                "platform": platform.platform(),
                "machine": platform.machine(),
                "python": sys.executable,
                "source_lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
                "source_heads": sources,
                "raw_steps": json.loads(os.environ.get("FINAL_STEP_RESULTS", "{}")),
                "final_acceptance_requested": os.environ.get(
                    "FINAL_ACCEPTANCE_REQUESTED"
                ),
                "rule": "Skipped required stages are BLOCKED/UNRUN according to their recorded dependency outcomes; no absent job is PASS",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def run_finite(command, cwd, out, err, timeout):
    import psutil

    child = subprocess.Popen(command, cwd=cwd, stdout=out, stderr=err)
    owned, observations = {}, []
    try:
        root = psutil.Process(child.pid)
        root_birth = root.create_time()
    except psutil.NoSuchProcess:
        root, root_birth = None, None
        observations.append("root exited before process observation")
    deadline = time.monotonic() + timeout
    timed_out = False
    while child.poll() is None:
        try:
            if (
                root is not None
                and root.is_running()
                and root.create_time() == root_birth
            ):
                for process in root.children(recursive=True):
                    owned[(process.pid, process.create_time())] = process
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            observations.append(type(exc).__name__)
        if time.monotonic() >= deadline:
            timed_out = True
            child.kill()
            break
        try:
            child.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            pass
    child.wait(timeout=15)
    cleanup = []
    for (pid, birth), process in reversed(list(owned.items())):
        try:
            live = (
                process.is_running()
                and process.create_time() == birth
                and process.status() != psutil.STATUS_ZOMBIE
            )
            if live:
                process.kill()
                process.wait(timeout=15)
            cleanup.append(
                {
                    "pid": pid,
                    "creation_time": birth,
                    "survived_command": live,
                    "cleanup": "gone",
                }
            )
        except psutil.NoSuchProcess:
            cleanup.append({"pid": pid, "creation_time": birth, "cleanup": "gone"})
        except (psutil.AccessDenied, psutil.TimeoutExpired) as exc:
            cleanup.append(
                {
                    "pid": pid,
                    "creation_time": birth,
                    "cleanup": "unconfirmed",
                    "error": str(exc),
                }
            )
    return child.returncode, timed_out, cleanup, observations


def commands(group):
    cargo = ["cargo", "+1.97.1"]
    manifest = ["--manifest-path", "launcher/Cargo.toml"]
    if group == "launcher":
        return [
            ("rust-format", [*cargo, "fmt", *manifest, "--check"]),
            (
                "rust-clippy",
                [
                    *cargo,
                    "clippy",
                    *manifest,
                    "--locked",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            ),
            ("rust-inventory", [*cargo, "test", *manifest, "--locked", "--", "--list"]),
            (
                "rust-tests",
                [
                    *cargo,
                    "test",
                    *manifest,
                    "--locked",
                    "--",
                    "--test-threads=1",
                    "--nocapture",
                ],
            ),
        ]
    if group == "release-tests":
        selected = []
        for path in sorted((ROOT / "release/scripts").glob("test_*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8-sig"))
            # Executable installed/compiled smoke clients have explicit bundle
            # prerequisites and are exercised by their existing workflow steps.
            if any(
                isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name.startswith("test")
                for n in ast.walk(tree)
            ):
                selected.append((path.stem, [sys.executable, "-B", str(path)]))
        return selected
    if group == "release-quality":
        return [
            (
                "release-python-syntax",
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "compileall",
                    "-q",
                    "release/scripts",
                    "hil",
                ],
            ),
            (
                "release-ruff",
                [sys.executable, "-B", "-m", "ruff", "check", "release/scripts", "hil"],
            ),
            (
                "release-format",
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "ruff",
                    "format",
                    "--check",
                    "release/scripts",
                    "hil",
                ],
            ),
            ("bootstrap-shell", ["sh", "-n", "install.sh"]),
            (
                "workflow-actionlint",
                [
                    "go",
                    "run",
                    "github.com/rhysd/actionlint/cmd/actionlint@v1.7.12",
                    "-no-color",
                ],
            ),
        ]
    if group == "workspace":
        return [
            (
                "workspace-ruff",
                [
                    "uv",
                    "run",
                    "--no-sync",
                    "--project",
                    "AgentWorkspace",
                    "ruff",
                    "check",
                    "AgentWorkspace",
                ],
            ),
            (
                "workspace-format",
                [
                    "uv",
                    "run",
                    "--no-sync",
                    "--project",
                    "AgentWorkspace",
                    "ruff",
                    "format",
                    "--check",
                    "AgentWorkspace",
                ],
            ),
            ("workspace-type", ["uv", "run", "--no-sync", "basedpyright"]),
            (
                "workspace-pytest",
                [
                    "uv",
                    "run",
                    "--no-sync",
                    "pytest",
                    "--junitxml="
                    + str(ROOT / "release/build/final-acceptance/workspace/pytest.xml"),
                ],
            ),
            (
                "workspace-render",
                [
                    "uv",
                    "run",
                    "--no-sync",
                    "python",
                    "bin/render-all-modes",
                    "--check-idempotent",
                ],
            ),
        ]
    if group == "firmware-quality":
        return [
            ("firmware-ruff", [sys.executable, "-B", "-m", "ruff", "check", "."]),
            (
                "firmware-full-format",
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "ruff",
                    "format",
                    "--check",
                    "src",
                    "tests",
                ],
            ),
            ("firmware-type", [sys.executable, "-B", "-m", "pyright", "src"]),
        ]
    if group == "firmware-contract":
        selected = [
            "src/pyocd_debug_mcp/sidecar.py",
            "src/pyocd_debug_mcp/capabilities/manual_permission_helper.py",
        ]
        tests = [
            "tests/test_sidecar_runtime.py",
            "tests/test_manual_permission_helper_runtime.py",
        ]
        return [
            (
                "firmware-contract-ruff",
                [sys.executable, "-B", "-m", "ruff", "check", "."],
            ),
            (
                "firmware-contract-format",
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "ruff",
                    "format",
                    "--check",
                    *selected,
                    *tests,
                ],
            ),
            (
                "firmware-contract-type",
                [sys.executable, "-B", "-m", "pyright", *selected],
            ),
            (
                "firmware-contract-tests",
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "unittest",
                    "-v",
                    "tests.test_sidecar_runtime",
                    "tests.test_manual_permission_helper_runtime",
                ],
            ),
        ]
    raise ValueError(group)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--group",
        choices=[
            "launcher",
            "release-tests",
            "release-quality",
            "workspace",
            "firmware-quality",
            "firmware-contract",
        ],
    )
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--record-steps", action="store_true")
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Final acceptance execution is Actions-only after ROOT freeze")
    evidence = args.evidence.resolve()
    if args.record_steps:
        record_stages(evidence)
        return 0
    if args.group is None:
        parser.error("--group is required unless --record-steps is selected")
    evidence.mkdir(parents=True, exist_ok=False)
    cwd = ROOT / {
        "workspace": "AgentWorkspace",
        "firmware-quality": "Firmware MCP New",
        "firmware-contract": "Firmware MCP New",
    }.get(args.group, "")
    records = []
    for name, command in commands(args.group):
        # Workspace commands run in the actual locked component checkout.
        if args.group == "workspace" and name in ("workspace-ruff", "workspace-format"):
            command = [
                "uv",
                "run",
                "--no-sync",
                "ruff",
                *(
                    ["check", "."]
                    if name.endswith("ruff")
                    else ["format", "--check", "."]
                ),
            ]
        started = time.monotonic()
        stdout, stderr = (
            evidence / (name + ".stdout.log"),
            evidence / (name + ".stderr.log"),
        )
        with stdout.open("wb") as out, stderr.open("wb") as err:
            cleanup, observation_errors = [], []
            try:
                code, timed_out, cleanup, observation_errors = run_finite(
                    command, cwd, out, err, args.timeout
                )
                state = "TIMEOUT" if timed_out else ("PASS" if code == 0 else "FAIL")
                if any(
                    item.get("survived_command") or item.get("cleanup") != "gone"
                    for item in cleanup
                ):
                    state = "ERROR" if state == "PASS" else state
                reason = None
            except subprocess.TimeoutExpired as exc:
                code, state, reason = None, "TIMEOUT", str(exc)
            except OSError as exc:
                code, state, reason = None, "BLOCKED", str(exc)
                cleanup, observation_errors = [], []
            except Exception as exc:
                code, state, reason = None, "ERROR", repr(exc)
        record = {
            "name": name,
            "argv": command,
            "cwd": str(cwd),
            "exit": code,
            "outcome": state,
            "reason": reason,
            "seconds": time.monotonic() - started,
            "stdout": str(stdout),
            "stderr": str(stderr),
            "stdout_sha256": hashlib.sha256(stdout.read_bytes()).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr.read_bytes()).hexdigest(),
            "captured_descendant_cleanup": cleanup,
            "process_observation_errors": observation_errors,
        }
        records.append(record)
        (evidence / (name + ".json")).write_text(
            json.dumps(record, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps({"name": name, "exit": code, "outcome": state}), flush=True)
    failed = any(record["outcome"] != "PASS" for record in records)
    (evidence / "summary.json").write_text(
        json.dumps(
            {
                "group": args.group,
                "commands": records,
                "outcome": "FAIL" if failed else "PASS",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
