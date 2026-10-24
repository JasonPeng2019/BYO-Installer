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
import math
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
        files += [
            path
            for path in (ROOT / relative).rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix != ".pyc"
        ]
    files += [
        ROOT / name
        for name in (
            "launcher/Cargo.toml",
            "launcher/Cargo.lock",
            "release/source-lock.json",
            "release/analysis-tools.lock.json",
            "release/arm-test-toolchains.json",
            "install.sh",
            "install.ps1",
        )
    ]
    measured = {}
    for path in files:
        try:
            measured[path.relative_to(ROOT).as_posix()] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
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
    required = (
        [
            "official-pack/official-pack-acquisition.json",
            "firmware-source/freeze-inputs.json",
            "firmware-source/native-prerequisites.json",
            "firmware-source/summary.json",
            "launcher/summary.json",
            "release-tests/summary.json",
        ]
        if requested
        else []
    )
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


def command_identity(pid, birth=None):
    """Read OS facts only; never poll/wait/reap/signal or infer a role from a name."""
    import psutil

    facts = {
        "pid": pid,
        "expected_creation_time": birth,
        "at_monotonic": time.monotonic(),
        "observer_pid": os.getpid(),
    }
    try:
        process = psutil.Process(pid)
        actual = process.create_time()
        facts["creation_time"] = actual
        if birth is not None and actual != birth:
            return {
                **facts,
                "identity": "reused",
                "gap": "PID birth changed; no attribution",
            }
        facts["identity"] = "observed" if birth is None else "same_birth"
        for name in ("ppid", "cmdline", "exe", "status"):
            try:
                facts[name] = getattr(process, name)()
            except (OSError, psutil.Error) as exc:
                facts[name] = {"unavailable": type(exc).__name__, "error": str(exc)}
        facts["birth_after_queries"] = psutil.Process(pid).create_time()
        if facts["birth_after_queries"] != actual:
            facts["identity"] = "changed_during_observation"
    except psutil.ZombieProcess as exc:
        facts.update(identity="unavailable", error=type(exc).__name__, detail=str(exc))
    except psutil.NoSuchProcess:
        facts["identity"] = (
            "missing" if "creation_time" not in facts else "gone_during_observation"
        )
    except (OSError, psutil.Error) as exc:
        facts.update(identity="unavailable", error=type(exc).__name__, detail=str(exc))
    return facts


def command_state(facts):
    birth = facts.get("expected_creation_time")
    if type(birth) not in (int, float) or not math.isfinite(birth) or birth <= 0:
        return "unknown"
    if facts.get("identity") == "missing":
        return "gone"
    if (
        facts.get("identity") == "same_birth"
        and facts.get("creation_time") == birth
        and facts.get("birth_after_queries") == birth
    ):
        status = facts.get("status")
        if status in ("zombie", "dead"):
            return "terminal"
        if isinstance(status, str) and status:
            return "live"
    return "unknown"


def captured_identity_state(facts, capture):
    """Retirement of an old witnessed birth is distinct from the current PID owner."""
    state = command_state(facts)
    expected, actual = facts.get("expected_creation_time"), facts.get("creation_time")
    witnessed = any(
        item.get("identity", {}).get("identity") == "same_birth"
        and item["identity"].get("creation_time") == expected
        and item["identity"].get("birth_after_queries") == expected
        for item in (capture["first_capture"], capture.get("last_capture", {}))
    )
    if (
        witnessed
        and facts.get("identity") == "reused"
        and type(expected) in (int, float)
        and math.isfinite(expected)
        and expected > 0
        and type(actual) in (int, float)
        and math.isfinite(actual)
        and actual > 0
        and expected != actual
    ):
        return "retired_exact_identity"
    return state


def terminal_root_race(facts, birth):
    return (
        type(birth) in (int, float)
        and math.isfinite(birth)
        and birth > 0
        and (
            facts.get("identity") == "missing"
            or (
                facts.get("identity") == "gone_during_observation"
                and facts.get("creation_time") == birth
            )
        )
    )


def command_observation_failed(cleanup, observations):
    # Diagnostic image/argv gaps remain raw qualifications. Actual ownership or
    # lifecycle gaps, intervention and survivors still prevent successful proof.
    return any(
        item.get("survived_command")
        or not item.get("natural_terminal")
        or item.get("cleanup") != "gone"
        for item in cleanup
    ) or any(not item.get("terminal_race") for item in observations)


def capture_command_descendants(pid, birth, owned, observations):
    """Contemporaneous tree/parent/argv/image facts, with no cleanup authority."""
    import psutil

    root = command_identity(pid, birth)
    if terminal_root_race(root, birth):
        observations.append(
            {
                "boundary": "during command",
                "root": root,
                "terminal_race": birth is not None,
            }
        )
        return  # The owner's actual wait decides exit; no later PID attribution.
    if birth is None or root.get("identity") != "same_birth":
        observations.append({"boundary": "during command", "root": root})
        return
    try:
        for process in psutil.Process(pid).children(recursive=True):
            try:
                child_birth = process.create_time()
                facts = command_identity(process.pid, child_birth)
                parent_pid = facts.get("ppid")
                parent = (
                    command_identity(parent_pid)
                    if type(parent_pid) is int
                    else {"gap": "Parent PID unavailable during capture"}
                )
                capture = {
                    "identity": facts,
                    "parent_identity": parent,
                    "root_identity": root,
                    "boundary": "during command",
                    "at_monotonic": time.monotonic(),
                    "observer_pid": os.getpid(),
                    "ownership_role": "observed recursive command descendant",
                    "role": "unknown; no exact functional-role receipt",
                    "role_gap": "No role inference from argv, image or a later PID lookup",
                }
                entry = owned.setdefault(
                    (process.pid, child_birth), {"first_capture": capture}
                )
                entry["last_capture"] = capture
                gaps = []
                if facts.get("identity") != "same_birth":
                    gaps.append("Child identity changed or unavailable during capture")
                if parent.get("identity") != "observed":
                    gaps.append("Parent identity unavailable during capture")
                for field in ("ppid", "cmdline", "exe", "status"):
                    if not facts.get(field) or isinstance(facts[field], dict):
                        gaps.append("Child " + field + " unavailable during capture")
                if gaps:
                    entry.setdefault("evidence_gaps", []).extend(gaps)
            except (OSError, psutil.Error) as exc:
                observations.append(
                    {
                        "pid": process.pid,
                        "boundary": "during command",
                        "error": type(exc).__name__,
                        "detail": str(exc),
                    }
                )
        after = command_identity(pid, birth)
        if after.get("identity") != "same_birth":
            observations.append(
                {
                    "boundary": "after tree capture",
                    "root": after,
                    "terminal_race": terminal_root_race(after, birth),
                }
            )
    except (OSError, psutil.Error) as exc:
        after = command_identity(pid, birth)
        observations.append(
            {
                "boundary": "during command",
                "error": type(exc).__name__,
                "detail": str(exc),
                "root_after_error": after,
                "terminal_race": terminal_root_race(after, birth),
            }
        )


def run_finite(command, cwd, out, err, timeout):
    import psutil

    child = subprocess.Popen(command, cwd=cwd, stdout=out, stderr=err)
    owned, observations = {}, []
    root = command_identity(child.pid)
    root_birth = root.get("creation_time")
    if root.get("identity") != "observed":
        observations.append(
            {"gap": "Root identity unavailable at dispatch", "identity": root}
        )
    deadline = time.monotonic() + timeout
    timed_out = False
    timeout_intervention = None
    while child.poll() is None:
        capture_command_descendants(child.pid, root_birth, owned, observations)
        if time.monotonic() >= deadline:
            timed_out = True
            timeout_intervention = {
                "kind": "timeout-command.kill",
                "identity": command_identity(child.pid, root_birth),
                "at_monotonic": time.monotonic(),
            }
            child.kill()
            break
        try:
            child.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            pass
    child.wait(timeout=15)
    command_exited = time.monotonic()
    immediate = {key: command_identity(*key) for key in owned}
    finalization_gaps = {
        key: facts
        for key, facts in immediate.items()
        if command_state(facts) == "unknown"
    }
    finalization_deadline = command_exited + 5.0
    while True:
        final = {key: command_identity(*key) for key in owned}
        for key, facts in final.items():
            if command_state(facts) == "unknown":
                finalization_gaps.setdefault(key, facts)
        if (
            timed_out
            or all(
                captured_identity_state(facts, owned[key])
                in ("gone", "terminal", "retired_exact_identity")
                for key, facts in final.items()
            )
            or time.monotonic() >= finalization_deadline
        ):
            break
        time.sleep(0.05)
    judgment = time.monotonic()
    cleanup = []
    for (pid, birth), capture in reversed(list(owned.items())):
        facts = final[(pid, birth)]
        state = captured_identity_state(facts, capture)
        record = {
            "pid": pid,
            "creation_time": birth,
            **capture,
            "at_command_exit": immediate[(pid, birth)],
            "command_exit_monotonic": command_exited,
            "at_final_boundary": facts,
            "judgment_monotonic": judgment,
            "survived_command": state == "live",
            "final_state": state,
            "retirement_witness": "Previously witnessed old birth retired; replacement PID remains unknown and unsignalled"
            if state == "retired_exact_identity"
            else None,
            "command_exit": child.returncode,
            "timed_out": timed_out,
            "timeout_intervention": timeout_intervention,
            "normal_wait_completed": not timed_out,
            "intervention": None,
            "cleanup": "unconfirmed",
        }
        cleanup.append(record)
        if (pid, birth) in finalization_gaps:
            record.setdefault("evidence_gaps", []).append(
                {
                    "boundary": "passive post-command observation",
                    "identity": finalization_gaps[(pid, birth)],
                }
            )
        if state == "unknown":
            record.setdefault("evidence_gaps", []).append(
                "Unknown/reused/unavailable final identity"
            )
        try:
            if state == "live":
                # The final failed judgment above is immutable. Recheck a fresh
                # birth before the owner's explicit emergency signal.
                before = command_identity(pid, birth)
                process = psutil.Process(pid)
                if command_state(before) != "live" or process.create_time() != birth:
                    record["intervention_gap"] = before
                    continue
                record["intervention"] = {
                    "kind": "post-command-emergency-kill",
                    "at_monotonic": time.monotonic(),
                    "before": before,
                }
                process.kill()
                process.wait(timeout=15)
            if state in ("gone", "terminal", "retired_exact_identity"):
                record["cleanup"] = "gone"
        except psutil.NoSuchProcess:
            pass
        except (OSError, psutil.Error) as exc:
            record["error"] = {"type": type(exc).__name__, "message": str(exc)}
        finally:
            record["after_cleanup"] = command_identity(pid, birth)
            if captured_identity_state(record["after_cleanup"], capture) in (
                "gone",
                "terminal",
                "retired_exact_identity",
            ):
                record["cleanup"] = "gone"
            record["natural_terminal"] = (
                not timed_out
                and state in ("gone", "terminal", "retired_exact_identity")
                and record["intervention"] is None
            )
    return child.returncode, timed_out, cleanup, observations


def commands(group):
    cargo = ["cargo", "+1.97.1"]
    manifest = ["--manifest-path", "launcher/Cargo.toml"]
    if group == "windows-cleanup":
        return [
            (
                "rust-windows-cleanup",
                [
                    *cargo,
                    "test",
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
        node.name: [
            method.name
            for method in node.body
            if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
            and method.name.startswith("test")
        ]
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }
    functions = [
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test")
    ]
    uses_unittest = any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "unittest"
        and node.func.attr == "main"
        for node in ast.walk(tree)
    )
    return {
        "path": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "classes": classes,
        "functions": functions,
        "unittest_entrypoint": uses_unittest,
        "rule": "AST declarations are not actual loaded or executed tests",
    }


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
                unmatched.append(
                    {"id": pending, "outcome": "UNRUN; missing terminal output"}
                )
            pending = match[1]
            starts.append({"id": pending, "line": number, "suite": suite})
            token = match[2]
        else:
            token = line.strip()
        outcome = re.fullmatch(r"(ok|FAILED|ignored)(?:, .*)?", token)
        if outcome and pending is not None:
            stops.append(
                {
                    "id": pending,
                    "raw": outcome[1],
                    "line": number,
                    "suite": suite,
                    "outcome": {"ok": "PASS", "FAILED": "FAIL", "ignored": "SKIP"}[
                        outcome[1]
                    ],
                }
            )
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
    return {
        "inventory": declarations,
        "starts": starts,
        "stops": stops,
        "unaccounted": unmatched,
        "evidence_gaps": gaps,
        "scope": "Actual outer libtest text only; ignored/helper declarations are not child-body execution",
    }


def child_receipts(directory):
    records, errors = [], []
    images = {}
    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            record = {
                "path": str(path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                **data,
            }
            executable = Path(data["executable"]).resolve()
            image = executable.stat()
            image_key = (str(executable), image.st_size, image.st_mtime_ns)
            if data.get("executable_hash_method") == "collector-after-command":
                if (
                    data["executable_bytes"],
                    int(data["executable_modified_unix_nanos"]),
                ) != (image.st_size, image.st_mtime_ns):
                    raise RuntimeError(
                        "Child executable image changed before collection: "
                        + str(executable)
                    )
            if image_key not in images:
                digest = hashlib.sha256()
                with executable.open("rb") as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        digest.update(chunk)
                after = executable.stat()
                if (after.st_size, after.st_mtime_ns) != image_key[1:]:
                    raise RuntimeError("Child executable changed during hashing")
                images[image_key] = digest.hexdigest()
            if data.get("executable_sha256") not in (None, images[image_key]):
                raise RuntimeError("Child executable digest mismatch")
            record["collected_executable_sha256"] = images[image_key]
            record["executable_hash_qualification"] = (
                "Actual image hashed after command; raw child size/mtime and stable hash-time image checked. No synthetic child completion."
            )
            for stream in ("stdout", "stderr"):
                source = Path(data[stream])
                if (
                    hashlib.sha256(source.read_bytes()).hexdigest()
                    != data[stream + "_sha256"]
                ):
                    raise RuntimeError("Child stream digest mismatch: " + str(source))
            if data["details"].get("source_streams_present") is False:
                errors.append(
                    {
                        "path": str(path),
                        "error": "Actual source child stream was unavailable before retention",
                    }
                )
            if any(data["details"].get("stream_read_errors", [])):
                errors.append(
                    {"path": str(path), "error": data["details"]["stream_read_errors"]}
                )
            if data["kind"] in (
                "command-complete",
                "owned-command-complete",
                "owned-descendant-streams",
            ):
                record["libtest"] = rust_ledger(Path(data["stdout"]))
            records.append(record)
        except Exception as exc:
            errors.append({"path": str(path), "error": repr(exc)})
    return {
        "records": records,
        "errors": errors,
        "rule": "Dispatch, helper starts/completions and parent-observed exits are distinct; missing child boundaries are never PASS",
    }


def reconcile_rust_children(outer, children):
    records, gaps, phases = children["records"], [], []
    started = {item["id"] for item in outer["starts"]}
    # These are current exact helper contracts, not historical test totals.
    required = {
        "project::b05_lifecycle_tests::legacy_archive_interruption_recovers_real_journal_in_fresh_process": {
            "archive",
            "refusal",
            "recovery-1",
            "recovery-2",
        },
        "code_analysis::process::platform::tests::normal_exit_cleans_a_captured_detached_child": {
            "detached-parent"
        },
        "code_analysis::process::platform::tests::deadline_terminates_owned_child_and_descendant_by_creation_identity": {
            "deadline-parent"
        },
        "install::tests::windows_cleanup_helper_deletes_an_exited_executable": {
            "live-cleanup-target"
        },
    }
    for name, expected in required.items():
        if name not in started:
            continue
        observed = {
            r["details"].get("phase")
            for r in records
            if r["kind"] == "dispatch" and r["details"].get("outer_test") == name
        }
        for phase in sorted(expected - observed):
            gaps.append(f"Missing actual child dispatch: {name}/{phase}")
    for dispatch in (r for r in records if r["kind"] == "dispatch"):
        detail = dispatch["details"]
        name, phase = detail["child_name"], detail["phase"]
        completions = [
            r
            for r in records
            if r["kind"] in ("command-complete", "owned-command-complete")
            and r["details"].get("child_name") == name
            and r["details"].get("phase") == phase
        ]
        starts = [
            r
            for r in records
            if r["kind"] == "helper-start"
            and r["details"].get("child_name") == name
            and r["details"].get("phase") == phase
        ]
        if len(completions) != 1 or len(starts) != 1:
            gaps.append(f"Missing/ambiguous actual child boundaries: {name}/{phase}")
        if phase.startswith("recovery-") or phase in (
            "live-cleanup-target",
            "detached-parent",
        ):
            ended = [
                r
                for r in records
                if r["kind"] == "helper-complete"
                and r["details"].get("child_name") == name
                and r["details"].get("phase") == phase
            ]
            if len(ended) != 1:
                gaps.append(f"Missing actual helper completion: {name}/{phase}")
        phases.append(
            {
                "child_name": name,
                "phase": phase,
                "dispatch": dispatch["path"],
                "helper_starts": [r["path"] for r in starts],
                "command_completions": [r["path"] for r in completions],
                "rule": (
                    "Expected abrupt exit 73; incomplete libtest stop is retained"
                    if phase == "archive"
                    else "Expected nonzero refusal, retained as raw child FAIL"
                    if phase == "refusal"
                    else "Actual completion/ownership observations; no inferred child PASS"
                ),
            }
        )
    for spawn in (r for r in records if r["kind"] == "child-spawned"):
        detail = spawn["details"]
        starts = [
            r
            for r in records
            if r["kind"] == "helper-start"
            and r["pid"] == detail["child_pid"]
            and r["details"].get("child_name") == detail["child_name"]
        ]
        if len(starts) != 1:
            gaps.append(
                f"Spawned child has no unique actual helper start: {detail['child_name']}/{detail['child_pid']}"
            )
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
    (evidence / "source-before.json").write_text(
        json.dumps(before, indent=2) + "\n", encoding="utf-8"
    )
    for name, command in commands(args.group):
        declarations = None
        accounting = "command-only; no named method evidence is claimed"
        named = evidence / (name + ".python")
        named_required = False
        if args.group == "release-tests":
            script = (ROOT / command[-1]).resolve()
            declarations = python_declarations(script)
            command = [
                sys.executable,
                "-B",
                str(ROOT / "release/scripts/final_test_ledger.py"),
                "--script",
                str(script),
                "--evidence",
                str(named),
            ]
            named_required = True
            if declarations["unittest_entrypoint"]:
                accounting = "actual unittest entrypoint/loader/result; AST declarations retained separately"
            else:
                command.append("--command-only")
        if name == "firmware-contract-tests":
            command = [
                sys.executable,
                "-B",
                str(ROOT / "release/scripts/final_test_ledger.py"),
                "--evidence",
                str(named),
                "--unittest-names",
                "tests.test_sidecar_runtime",
                "tests.test_manual_permission_helper_runtime",
            ]
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
            json.dumps(
                {
                    "argv": command,
                    "cwd": str(cwd),
                    "started_monotonic": started,
                    "declarations": declarations,
                    "accounting": accounting,
                },
                indent=2,
            )
            + "\n",
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
                if command_observation_failed(cleanup, observation_errors):
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
                    named_result = json.loads(
                        (named / "result.json").read_text(encoding="utf-8")
                    )
                    evidence_gaps.extend(named_result["evidence_gaps"])
                except (OSError, ValueError, KeyError) as exc:
                    evidence_gaps.append(
                        "Actual Python ledger is incomplete: " + str(exc)
                    )
            else:
                evidence_gaps.append(
                    "Required actual Python execution receipt is missing"
                )
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
        unchanged = after == before and not any(
            value.startswith("UNAVAILABLE:") for value in after.values()
        )
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
