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
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]


def source_hashes():
    """Hash the source/lock inputs, excluding generated build and evidence trees."""
    files = []
    for relative in ("launcher/src", "release/scripts", ".github/workflows"):
        files += [path for path in (ROOT / relative).rglob("*")
                  if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"]
    files += [ROOT / name for name in ("launcher/Cargo.toml", "launcher/Cargo.lock",
              "release/source-lock.json", "release/analysis-tools.lock.json",
              "release/arm-test-toolchains.json", "install.sh", "install.ps1")]
    measured = {}
    for path in files:
        try:
            measured[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            measured[path.relative_to(ROOT).as_posix()] = "UNAVAILABLE: " + str(exc)
    return measured


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
    requested = os.environ.get("FINAL_ACCEPTANCE_REQUESTED", "").casefold() == "true"
    required = [
        "official-pack/official-pack-acquisition.json",
        "firmware-source/freeze-inputs.json",
        "firmware-source/native-prerequisites.json",
        "firmware-source/summary.json",
        "launcher/summary.json",
        "release-tests/summary.json",
    ] if requested else []
    gaps = [name for name in required if not (path.parent / name).is_file()]
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
                "required_evidence_gaps": gaps,
                "rule": "Skipped required stages are BLOCKED/UNRUN according to their recorded dependency outcomes; no absent job is PASS",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return int(bool(gaps))


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
    if group == "windows-cleanup":
        return [("rust-windows-cleanup", [*cargo, "test", *manifest, "--locked",
                 "install::tests::windows_", "--", "--test-threads=1", "--nocapture"])]
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


def python_declarations(path):
    tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    classes = {
        node.name: [method.name for method in node.body
                    if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and method.name.startswith("test")]
        for node in tree.body if isinstance(node, ast.ClassDef)
    }
    functions = [node.name for node in tree.body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and node.name.startswith("test")]
    uses_unittest = any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "unittest" and node.func.attr == "main"
        for node in ast.walk(tree)
    )
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "classes": classes, "functions": functions, "unittest_entrypoint": uses_unittest,
            "rule": "AST declarations are not actual loaded or executed tests"}


def rust_ledger(stdout, inventory=False):
    """Retain real libtest outcomes across every cargo test target.

    Outer commands use --show-output so libtest owns uninterrupted result lines;
    captured output sections are kept raw and excluded from the method ledger.
    Child streams have their own observers. Never infer tests from cargo's exit.
    """
    text = stdout.read_text(encoding="utf-8", errors="replace")
    declarations, starts, stops, pending, unmatched = [], [], [], None, []
    suite, active = 0, False
    for number, line in enumerate(text.splitlines(), 1):
        if inventory:
            match = re.fullmatch(r"(.+): (test|benchmark)", line)
            if match:
                declarations.append({"id": match[1], "kind": match[2], "line": number})
            continue
        if re.fullmatch(r"running \d+ tests?", line):
            suite += 1
            active = True
        if line.startswith(("successes:", "failures:", "test result:")):
            active = False
        if not active:
            continue
        match = re.match(r"^test (\S+)(?: - should panic)? \.\.\.\s*(.*)$", line)
        if match:
            if pending is not None:
                unmatched.append({"id": pending, "outcome": "UNRUN; missing terminal output"})
            pending = match[1]
            starts.append({"id": pending, "line": number, "suite": suite})
            token = match[2]
        else:
            token = line.strip()
        outcome = re.fullmatch(r"(ok|FAILED|ignored)(?:, .*)?", token)
        if outcome and pending is not None:
            stops.append({"id": pending, "raw": outcome[1], "line": number, "suite": suite,
                          "outcome": {"ok": "PASS", "FAILED": "FAIL", "ignored": "SKIP"}[outcome[1]]})
            pending = None
    if pending is not None:
        unmatched.append({"id": pending, "outcome": "UNRUN; missing terminal output"})
    gaps = []
    if inventory and not declarations:
        gaps.append("No actual libtest list records")
    if not inventory and not starts:
        gaps.append("No actual libtest execution records")
    if unmatched:
        gaps.append("Incomplete libtest start/stop boundaries; inspect raw streams")
    return {"inventory": declarations, "starts": starts, "stops": stops,
            "unaccounted": unmatched, "evidence_gaps": gaps,
            "scope": "Actual outer libtest text only; ignored/helper declarations are not child-body execution"}


def child_receipts(directory):
    records, errors = [], []
    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            record = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), **data}
            for stream in ("stdout", "stderr"):
                source = Path(data[stream])
                if hashlib.sha256(source.read_bytes()).hexdigest() != data[stream + "_sha256"]:
                    raise RuntimeError("Child stream digest mismatch: " + str(source))
            if data["details"].get("source_streams_present") is False:
                errors.append({"path": str(path), "error": "Actual source child stream was unavailable before retention"})
            if any(data["details"].get("stream_read_errors", [])):
                errors.append({"path": str(path), "error": data["details"]["stream_read_errors"]})
            if data["kind"] in ("command-complete", "owned-command-complete", "owned-descendant-streams"):
                record["libtest"] = rust_ledger(Path(data["stdout"]))
            records.append(record)
        except Exception as exc:
            errors.append({"path": str(path), "error": repr(exc)})
    return {"records": records, "errors": errors,
            "rule": "Dispatch, helper starts/completions and parent-observed exits are distinct; missing child boundaries are never PASS"}


def reconcile_rust_children(outer, children):
    records, gaps, phases = children["records"], [], []
    started = {item["id"] for item in outer["starts"]}
    # These are current exact helper contracts, not historical test totals.
    required = {
        "project::b05_lifecycle_tests::legacy_archive_interruption_recovers_real_journal_in_fresh_process":
            {"archive", "refusal", "recovery-1", "recovery-2"},
        "code_analysis::process::platform::tests::normal_exit_cleans_a_captured_detached_child":
            {"detached-parent"},
        "code_analysis::process::platform::tests::deadline_terminates_owned_child_and_descendant_by_creation_identity":
            {"deadline-parent"},
        "install::tests::windows_cleanup_helper_deletes_an_exited_executable": {"live-cleanup-target"},
    }
    for name, expected in required.items():
        if name not in started:
            continue
        observed = {r["details"].get("phase") for r in records
                    if r["kind"] == "dispatch" and r["details"].get("outer_test") == name}
        for phase in sorted(expected - observed):
            gaps.append(f"Missing actual child dispatch: {name}/{phase}")
    for dispatch in (r for r in records if r["kind"] == "dispatch"):
        detail = dispatch["details"]
        name, phase = detail["child_name"], detail["phase"]
        completions = [r for r in records if r["kind"] in ("command-complete", "owned-command-complete")
                       and r["details"].get("child_name") == name
                       and r["details"].get("phase") == phase]
        starts = [r for r in records if r["kind"] == "helper-start"
                  and r["details"].get("child_name") == name and r["details"].get("phase") == phase]
        if len(completions) != 1 or len(starts) != 1:
            gaps.append(f"Missing/ambiguous actual child boundaries: {name}/{phase}")
        if phase.startswith("recovery-") or phase in ("live-cleanup-target", "detached-parent"):
            ended = [r for r in records if r["kind"] == "helper-complete"
                     and r["details"].get("child_name") == name and r["details"].get("phase") == phase]
            if len(ended) != 1:
                gaps.append(f"Missing actual helper completion: {name}/{phase}")
        phases.append({"child_name": name, "phase": phase,
                       "dispatch": dispatch["path"], "helper_starts": [r["path"] for r in starts],
                       "command_completions": [r["path"] for r in completions],
                       "rule": ("Expected abrupt exit 73; incomplete libtest stop is retained"
                                if phase == "archive" else "Expected nonzero refusal, retained as raw child FAIL"
                                if phase == "refusal" else "Actual completion/ownership observations; no inferred child PASS")})
    for spawn in (r for r in records if r["kind"] == "child-spawned"):
        detail = spawn["details"]
        starts = [r for r in records if r["kind"] == "helper-start"
                  and r["pid"] == detail["child_pid"] and r["details"].get("child_name") == detail["child_name"]]
        if len(starts) != 1:
            gaps.append(f"Spawned child has no unique actual helper start: {detail['child_name']}/{detail['child_pid']}")
    children.update(phases=phases, evidence_gaps=gaps)
    return gaps


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
        return record_stages(evidence)
    if args.group is None:
        parser.error("--group is required unless --record-steps is selected")
    evidence.mkdir(parents=True, exist_ok=False)
    cwd = ROOT / {
        "workspace": "AgentWorkspace",
        "firmware-quality": "Firmware MCP New",
        "firmware-contract": "Firmware MCP New",
    }.get(args.group, "")
    records = []
    before = source_hashes()
    (evidence / "source-before.json").write_text(json.dumps(before, indent=2) + "\n", encoding="utf-8")
    for name, command in commands(args.group):
        declarations = None
        accounting = "command-only; no named method evidence is claimed"
        named = evidence / (name + ".python")
        named_required = False
        if args.group == "release-tests":
            script = (ROOT / command[-1]).resolve()
            declarations = python_declarations(script)
            command = [sys.executable, "-B", str(ROOT / "release/scripts/final_test_ledger.py"),
                       "--script", str(script), "--evidence", str(named)]
            named_required = True
            if declarations["unittest_entrypoint"]:
                accounting = "actual unittest entrypoint/loader/result; AST declarations retained separately"
            else:
                command.append("--command-only")
        if name == "firmware-contract-tests":
            command = [sys.executable, "-B", str(ROOT / "release/scripts/final_test_ledger.py"),
                       "--evidence", str(named), "--unittest-names",
                       "tests.test_sidecar_runtime", "tests.test_manual_permission_helper_runtime"]
            named_required = True
            accounting = "actual selected firmware unittest loader/result"
        if name in ("rust-tests", "rust-windows-cleanup"):
            # Each cargo target has its own libtest process. A common --logfile
            # would be truncated by the next target. Preserve every target's real
            # pretty output instead, with child output retained separately.
            command = [part for part in command if part != "--nocapture"]
            command += ["--show-output", "--format=pretty", "--color=never"]
            accounting = "actual libtest result lines across all targets; captured output and child bodies separately retained"
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
        child_evidence = evidence / (name + ".children")
        child_evidence.mkdir()
        old_child_evidence = os.environ.get("BYO_FINAL_CHILD_EVIDENCE")
        os.environ["BYO_FINAL_CHILD_EVIDENCE"] = str(child_evidence)
        (evidence / (name + ".start.json")).write_text(
            json.dumps({"argv": command, "cwd": str(cwd), "started_monotonic": started,
                        "declarations": declarations, "accounting": accounting}, indent=2) + "\n",
            encoding="utf-8",
        )
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
            finally:
                if old_child_evidence is None:
                    os.environ.pop("BYO_FINAL_CHILD_EVIDENCE", None)
                else:
                    os.environ["BYO_FINAL_CHILD_EVIDENCE"] = old_child_evidence
        named_result, evidence_gaps = None, []
        if named_required:
            if (named / "result.json").is_file():
                try:
                    named_result = json.loads((named / "result.json").read_text(encoding="utf-8"))
                    evidence_gaps.extend(named_result["evidence_gaps"])
                except (OSError, ValueError, KeyError) as exc:
                    evidence_gaps.append("Actual Python ledger is incomplete: " + str(exc))
            else:
                evidence_gaps.append("Required actual Python execution receipt is missing")
        if name in ("rust-inventory", "rust-tests", "rust-windows-cleanup"):
            named_result = rust_ledger(stdout, inventory=name == "rust-inventory")
            evidence_gaps.extend(named_result["evidence_gaps"])
        children = child_receipts(child_evidence)
        if name in ("rust-tests", "rust-windows-cleanup"):
            evidence_gaps.extend(reconcile_rust_children(named_result, children))
        if children["errors"]:
            evidence_gaps.append("Invalid or missing Rust child evidence")
        if evidence_gaps and state == "PASS":
            state = "ERROR"
        after = source_hashes()
        (evidence / (name + ".source-after.json")).write_text(
            json.dumps(after, indent=2) + "\n", encoding="utf-8"
        )
        unchanged = after == before and not any(value.startswith("UNAVAILABLE:") for value in after.values())
        if not unchanged and state == "PASS":
            state = "ERROR"
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
            "declarations": declarations,
            "accounting": accounting,
            "named_results": named_result,
            "children": children,
            "evidence_gaps": evidence_gaps,
            "source_inputs_unchanged": unchanged,
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
