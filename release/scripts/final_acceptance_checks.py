"""Existing CI command groups with ordinary streams and exit codes.

Builds and automated source/release checks remain Actions-only for this campaign.
Each independent command runs once; failure does not suppress later commands.
No process observer, nested-test ledger, or per-command source-tree hashing.
"""

from __future__ import annotations
import argparse
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]


def commands(group):
    cargo = ["cargo", "+1.97.1"]
    contract_config = []
    if os.name == "nt":
        # MSVC link.exe and ring's cl.exe each left a captured live descendant
        # after contract Cargo exit. Use bundled LLD plus the runner's native
        # clang-cl for contract dependencies, keeping all lifecycle judgments.
        contract_config = [
            "--config",
            'build.rustflags=["-C","linker=rust-lld","-C","linker-flavor=lld-link"]',
            "--config",
            'env.CC="clang-cl"',
        ]
    manifest = ["--manifest-path", "launcher/Cargo.toml"]
    if group == "windows-cleanup":
        return [
            (
                "rust-windows-cleanup",
                [
                    *cargo,
                    "test",
                    *contract_config,
                    *manifest,
                    "--locked",
                    "install::tests::windows_",
                    "--",
                    "--test-threads=1",
                    "--nocapture",
                ],
            )
        ]
    if group == "launcher":
        return [
            ("rust-format", [*cargo, "fmt", *manifest, "--check"]),
            (
                "rust-clippy",
                [
                    *cargo,
                    "clippy",
                    # Clippy is an external Cargo subcommand: its forwarded
                    # config must follow the subcommand, not precede it.
                    *contract_config,
                    *manifest,
                    "--locked",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            ),
            (
                "rust-tests",
                [
                    *cargo,
                    "test",
                    *contract_config,
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
    if group == "firmware-lint":
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
        ]
    if group == "firmware-host-type":
        return [("firmware-type", [sys.executable, "-B", "-m", "pyright", "src"])]
    if group == "firmware-quality":
        return commands("firmware-lint") + commands("firmware-host-type")
    if group == "firmware-contract":
        # Neutral lint/format is owned by the Linux quality job. Retain type
        # checks on every host and source contracts through the capture hook.
        return commands("firmware-host-type") + [
            (
                "firmware-contract-tests",
                [
                    sys.executable, "-B", "-m", "pytest", "-o", "addopts=",
                    "--strict-markers", "-m", "not live", "-v",
                    "tests/test_sidecar_runtime.py",
                    "tests/test_manual_permission_helper_runtime.py",
                    "--junitxml=" + str(ROOT / "release/build/final-acceptance/firmware-contract.xml"),
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
            "windows-cleanup",
            "release-tests",
            "release-quality",
            "workspace",
            "firmware-quality",
            "firmware-lint",
            "firmware-host-type",
            "firmware-contract",
        ],
    )
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--record-steps", action="store_true")
    parser.add_argument("--timeout", type=float, default=1800)
    parser.add_argument("--workspace-source", type=Path)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.record_steps:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(
            json.dumps(
                {
                    "source": os.environ.get("GITHUB_SHA"),
                    "steps": json.loads(os.environ.get("FINAL_STEP_RESULTS", "{}")),
                },
                indent=2,
            )
            + "\n"
        )
        return 0
    if args.group is None:
        parser.error("--group is required")
    if (
        args.group in ("launcher", "windows-cleanup")
        and os.environ.get("GITHUB_ACTIONS") != "true"
    ):
        parser.error("compilation is Actions-only")
    args.evidence.mkdir(parents=True, exist_ok=False)
    firmware = ROOT / "Firmware MCP New"
    if not firmware.is_dir():
        firmware = ROOT.parent / "BYO-Firmware-MCP"
    cwd = (
        (args.workspace_source or ROOT / "AgentWorkspace")
        if args.group == "workspace"
        else firmware
        if args.group.startswith("firmware-")
        else ROOT
    )
    # Reuse the product's owned process group and marker, without reconstructing
    # host process histories. Logs are files from spawn onward, including timeout.
    sys.path.insert(0, str(firmware / "src"))
    from pyocd_debug_mcp.kernel.processes import (
        ProcessMarkerStore,
        popen_owned,
        terminate_process_group,
    )

    store = ProcessMarkerStore(args.evidence / "owned")
    records = []
    for name, command in commands(args.group):
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
        record = {
            "name": name,
            "command": command,
            "cwd": str(cwd),
            "phase": "setup",
            "exit_code": None,
        }
        process = marker = None
        with (
            (args.evidence / (name + ".stdout.log")).open("wb") as out,
            (args.evidence / (name + ".stderr.log")).open("wb") as err,
        ):
            try:
                process, marker = popen_owned(
                    command,
                    cwd=cwd,
                    stdout=out,
                    stderr=err,
                    marker_store=store,
                    env={
                        **os.environ,
                        "BYO_FIRMWARE_MCP_SOURCE": str(firmware),
                        "BYO_TEST_FAILURES": os.environ.get(
                            "BYO_TEST_FAILURES", str(args.evidence.resolve() / "failed-inputs")
                        ),
                    },
                )
                record["phase"] = "command"
                record["exit_code"] = process.wait(timeout=args.timeout)
                record["status"] = "PASS" if process.returncode == 0 else "FAIL"
            except subprocess.TimeoutExpired:
                record.update(
                    status="TIMEOUT", phase="timeout", traceback=traceback.format_exc()
                )
            except Exception:
                record.update(status="ERROR", traceback=traceback.format_exc())
            finally:
                if process is not None:
                    try:
                        if terminate_process_group(process):
                            store.remove(marker)
                        else:
                            record["cleanup_error"] = (
                                "owned group termination unconfirmed; marker retained"
                            )
                    except Exception:
                        record["cleanup_error"] = traceback.format_exc()
                record["seconds"] = time.monotonic() - started
        records.append(record)
        (args.evidence / "summary.json").write_text(
            json.dumps(records, indent=2) + "\n"
        )
        print(name, record["status"], flush=True)
    return int(
        not records
        or any(r["status"] != "PASS" or "cleanup_error" in r for r in records)
    )


if __name__ == "__main__":
    raise SystemExit(main())
