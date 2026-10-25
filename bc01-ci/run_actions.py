"""Finite Actions-only FR13 validation after explicit interpreter/dependency gates."""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import json
import math
import os
import subprocess
import sys
import traceback
from pathlib import Path
from typing import Any

from ci_common import (
    CLOCK,
    EVIDENCE,
    FIRMWARE,
    HERE,
    VENV,
    actions_only,
    compact,
    host_facts,
    source_snapshot,
    write,
)

MODULES = (
    "tests.test_swd_process_isolation",
    "tests.test_discovery_hook_process",
    "tests.test_process_cleanup",
    "tests.test_process_cleanup_churn",
    "tests.test_code_analysis_posix_ownership",
    "test_independent",
    "test_observer_controls",
    "test_validator",
    "test_source_binding",
    "test_thread_errors",
)
psutil: Any = None


def identity(pid: int, birth=None) -> dict:
    record = {"pid": pid, "expected_birth": birth, "at": CLOCK()}
    if psutil is None:
        return {**record, "identity": "unknown", "gap": "psutil unavailable"}
    try:
        process = psutil.Process(pid)
        actual = process.create_time()
        record["birth"] = actual
        if birth is not None and actual != birth:
            return {
                **record,
                "identity": "reused",
                "gap": "no attribution to new PID owner",
            }
        record["identity"] = "same_birth" if birth is not None else "observed"
        for name in ("ppid", "exe", "cmdline", "status"):
            try:
                record[name] = getattr(process, name)()
            except (psutil.Error, OSError, SystemError) as exc:
                # Darwin's native cmdline query can wrap PermissionError in a
                # SystemError. Diagnostic metadata never substitutes for the
                # independently observed birth and liveness fields.
                record[name] = {"unknown": repr(exc), "cause": repr(exc.__cause__)}
        if psutil.Process(pid).create_time() != actual:
            record["identity"] = "changed_during_observation"
    except psutil.ZombieProcess as exc:
        record.update(identity="unknown", error=repr(exc))
    except psutil.NoSuchProcess:
        record["identity"] = "gone"
    except (psutil.Error, OSError, SystemError) as exc:
        record.update(identity="unknown", error=repr(exc))
    return record


def state(record: dict) -> str:
    if record.get("identity") == "gone":
        return "gone"
    if record.get("identity") not in ("observed", "same_birth"):
        return "unknown"
    if record.get("status") in ("zombie", "dead"):
        return "terminal"
    return "live" if isinstance(record.get("status"), str) else "unknown"


def sample(root_pid, root_birth, owned, events) -> None:
    anchor = identity(root_pid, root_birth)
    if anchor.get("identity") != "same_birth":
        events.write(json.dumps({"kind": "sampling_gap", "root": anchor}) + "\n")
        return
    try:
        # Include previously captured exact descendants after reparenting.
        parents = {(root_pid, root_birth), *owned.keys()}
        for pid, birth in tuple(parents):
            if identity(pid, birth).get("identity") != "same_birth":
                continue
            for child in psutil.Process(pid).children(recursive=True):
                observed = identity(child.pid)
                if observed.get("identity") != "observed":
                    events.write(json.dumps({"kind": "sampling_gap", "child": observed}) + "\n")
                    continue
                key = (child.pid, observed["birth"])
                parent = (
                    identity(observed["ppid"])
                    if isinstance(observed.get("ppid"), int)
                    else {"identity": "unknown"}
                )
                capture = {
                    "kind": "descendant",
                    "child": observed,
                    "parent": parent,
                    "observed_via": {"pid": pid, "birth": birth},
                    "ownership": "observed ancestry; functional role unknown unless joined to fixture receipt",
                    "role_gap": "No functional role inferred from PID/name/image; join exact fixture receipts where available",
                }
                if key not in owned:
                    owned[key] = capture
                    events.write(json.dumps(capture) + "\n")
    except (psutil.Error, OSError) as exc:
        events.write(json.dumps({"kind": "sampling_gap", "error": repr(exc)}) + "\n")


def rescue(record, events) -> None:
    """Emergency containment only, after natural outcome/survivor facts saved."""
    pid, birth = record["pid"], record.get("expected_birth")
    fresh = identity(pid, birth)
    outcome = "no signal; identity unknown/terminal/reused"
    if psutil is not None and birth is not None and state(fresh) == "live":
        process = psutil.Process(pid)
        if process.create_time() == birth:
            process.kill()
            outcome = "emergency exact PID/birth kill"
    events.write(
        json.dumps({"kind": "emergency_cleanup", "before": fresh, "outcome": outcome}) + "\n"
    )


def run_command(directory: Path, argv: list[str], env: dict, timeout: int) -> dict:
    directory.mkdir()
    owned = {}
    started = CLOCK()
    timed_out = False
    observation_errors = []
    # Files prevent inherited PIPE descriptors from concealing natural
    # interpreter exit. No helper/name exemption or preemptive survivor kill.
    with (
        (directory / "stdout.log").open("wb") as out,
        (directory / "stderr.log").open("wb") as err,
    ):
        with (directory / "process-events.jsonl").open(
            "w", encoding="utf-8", buffering=1
        ) as events:
            process = subprocess.Popen(
                argv,
                cwd=FIRMWARE,
                env=env,
                stdout=out,
                stderr=err,
                stdin=subprocess.DEVNULL,
            )
            first = identity(process.pid)
            birth = first.get("birth")
            events.write(
                json.dumps(
                    {
                        "kind": "command_spawn",
                        "identity": first,
                        "role": "exact validation command interpreter",
                    }
                )
                + "\n"
            )
            deadline = started + timeout
            while True:
                # Parent clock is independent of all test-interpreter mocks.
                if psutil is not None and birth is not None:
                    try:
                        sample(process.pid, birth, owned, events)
                    except Exception:
                        # An observer failure must not abandon the real command
                        # before wait/cleanup. Keep its traceback and fail the
                        # observation gate even if the actual command exits 0.
                        error = {
                            "kind": "sampling_error",
                            "traceback": traceback.format_exc(),
                        }
                        observation_errors.append(error)
                        events.write(json.dumps(error) + "\n")
                try:
                    code = process.wait(timeout=min(0.2, max(0.001, deadline - CLOCK())))
                    break
                except subprocess.TimeoutExpired:
                    if CLOCK() < deadline:
                        continue
                    timed_out = True
                    events.write(
                        json.dumps({"kind": "TIMEOUT", "timeout": timeout, "at": CLOCK()}) + "\n"
                    )
                    # Timeout is an abnormal boundary, never natural EOF0.
                    rescue({"pid": process.pid, "expected_birth": birth}, events)
                    try:
                        code = process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        code = None
                    break
            boundary = {
                "kind": "natural_exit" if not timed_out else "abnormal_timeout_exit",
                "exit_code": code,
                "at": CLOCK(),
                "wait_returned": code is not None,
            }
            events.write(json.dumps(boundary) + "\n")
            survivors = []
            for (pid, captured_birth), capture in owned.items():
                final = identity(pid, captured_birth)
                retired = (
                    capture["child"].get("identity") == "observed"
                    and capture["child"].get("birth") == captured_birth
                    and isinstance(captured_birth, (int, float))
                    and math.isfinite(captured_birth)
                    and captured_birth > 0
                    and final.get("identity") == "reused"
                    and isinstance(final.get("birth"), (int, float))
                    and math.isfinite(final["birth"])
                    and final["birth"] > 0
                    and final["birth"] != captured_birth
                )
                row = {
                    "first_capture": capture,
                    "final": final,
                    "state": "retired_exact_identity" if retired else state(final),
                    "retirement_witness": "Fresh different creation time retires the captured old identity; current PID owner remains unknown and unsignalled"
                    if retired
                    else None,
                }
                survivors.append(row)
                events.write(json.dumps({"kind": "post_exit_survivor_judgment", **row}) + "\n")
            # Preserve every survivor/unknown before emergency containment.
            for row in survivors:
                if row["state"] == "live" and psutil is not None:
                    try:
                        rescue(row["final"], events)
                    except (OSError, psutil.Error) as exc:
                        events.write(
                            json.dumps({"kind": "cleanup_error", "error": repr(exc)}) + "\n"
                        )
            unresolved = [r for r in survivors if r["state"] in ("live", "unknown")]
            observation = (
                "GAP"
                if psutil is None or birth is None or unresolved or observation_errors
                else "CAPTURED_IDENTITIES_TERMINAL"
            )
            return {
                "argv": argv,
                "cwd": str(FIRMWARE),
                "timeout": timeout,
                "exit_code": code,
                "timed_out": timed_out,
                "elapsed": CLOCK() - started,
                "raw_outcome": "TIMEOUT" if timed_out else "PASS" if code == 0 else "FAIL",
                "natural_boundary": boundary,
                "survivors": survivors,
                "observation": observation,
                "observation_errors": observation_errors,
                "limits": "Polling is not exhaustive admission proof. Functional role gaps and brief unseen children remain gaps; no name-based exemptions.",
            }


def main() -> int:
    actions_only()
    parser = argparse.ArgumentParser()
    parser.add_argument("--execution-commit", required=True)
    parser.add_argument("--input-sha256", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--prerequisites", type=Path, required=True)
    args = parser.parse_args()
    output = EVIDENCE / "pass"
    output.mkdir(parents=True, exist_ok=False)
    actual_host = host_facts(args.host)
    initial = source_snapshot(args.execution_commit, args.input_sha256)
    write(output / "host.json", actual_host)
    write(output / "source-before.json", initial)
    global_reasons = list(initial["reasons"])
    if not actual_host["matches_expected"]:
        global_reasons.append("actual_host_does_not_match_required_target")
    prerequisites = {}
    expected_prerequisites = EVIDENCE / "prerequisites.json"
    if args.prerequisites.resolve() != expected_prerequisites.resolve():
        global_reasons.append("prerequisites_path_is_outside_controlled_evidence")
    else:
        try:
            prerequisites = json.loads(expected_prerequisites.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            global_reasons.append("prerequisites_unavailable:" + repr(exc))
    if prerequisites.get("schema") != "fr13-prerequisites/v1":
        global_reasons.append("prerequisite_schema_unconfirmed")
    if prerequisites.get("execution_commit") != args.execution_commit:
        global_reasons.append("prerequisite_execution_binding_mismatch")
    if prerequisites.get("input_sha256") != args.input_sha256:
        global_reasons.append("prerequisite_input_binding_mismatch")
    if prerequisites.get("ready") is not True:
        global_reasons.extend(prerequisites.get("reasons", []))
        global_reasons.append("qualified_locked_venv_not_ready")
    if Path(sys.prefix).resolve() != VENV.resolve() or sys.prefix == sys.base_prefix:
        global_reasons.append("coordinator_is_not_in_the_qualified_locked_venv")
    if sys.version_info[:2] != (3, 12):
        global_reasons.append("runtime_interpreter_is_not_Python_3_12")
    if not args.host.startswith("linux-") and sys.version_info[:3] != (3, 12, 10):
        global_reasons.append("native_runtime_patch_does_not_match_qualified_3_12_10")
    packages = prerequisites.get("venv_facts", {}).get("packages", {})
    psutil_error = None
    global psutil
    if not global_reasons:
        try:
            psutil = importlib.import_module("psutil")
        except (ImportError, OSError) as exc:
            psutil_error = repr(exc)
    else:
        psutil_error = "No dependency imports from an unqualified bootstrap interpreter"
    write(output / "prerequisites.json", prerequisites)
    write(
        output / "dependencies.json",
        {
            "role": "qualified locked venv" if not global_reasons else "bootstrap metadata only",
            "executable": sys.executable,
            "prefix": sys.prefix,
            "distributions": sorted(
                (d.metadata.get("Name", ""), d.version) for d in importlib.metadata.distributions()
            ),
            "psutil_import_error": psutil_error,
        },
    )
    compact(
        "validation_preflight",
        host=actual_host,
        blocked_reasons=global_reasons,
        psutil_import_error=psutil_error,
        artifact_directory=str(EVIDENCE),
    )
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    env.update(
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONUNBUFFERED="1",
        PYTHONNOUSERSITE="1",
        PYTHONIOENCODING="utf-8",
        PYOCD_MCP_RUNS_ROOT=str(output / "isolated-runs"),
        BYO_FINAL_CLEANUP_EVIDENCE=str(output / "original-cleanup-receipts"),
        BYO_MANAGED_TEST_EVIDENCE=str(output / "analysis-receipts"),
        FR13_CONTROL_EVIDENCE=str(output / "independent-receipts"),
    )
    commands = []
    for module in MODULES:
        name = module.rsplit(".", 1)[-1]
        commands.append(
            (
                name,
                [
                    sys.executable,
                    "-B",
                    str(HERE / "run_unittest.py"),
                    "--module",
                    module,
                    "--firmware",
                    str(FIRMWARE),
                    "--output",
                    str(output / (name + "-methods")),
                ],
                300,
                "psutil",
            )
        )
    # Include the publication/collection audit scripts as well as the runners.
    helpers = [str(path) for path in sorted(HERE.rglob("*.py"))]
    # Same repository-authoritative product commands; none has a fix/write flag.
    commands.extend(
        [
            (
                "firmware-ruff",
                [sys.executable, "-B", "-m", "ruff", "check", "."],
                300,
                "ruff",
            ),
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
                300,
                "ruff",
            ),
            (
                "firmware-type",
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "pyright",
                    "--pythonpath",
                    sys.executable,
                    "src",
                ],
                600,
                "pyright",
            ),
            (
                "auditor-ruff",
                [sys.executable, "-B", "-m", "ruff", "check", *helpers],
                120,
                "ruff",
            ),
            (
                "auditor-format",
                [sys.executable, "-B", "-m", "ruff", "format", "--check", *helpers],
                120,
                "ruff",
            ),
            (
                "auditor-type",
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "pyright",
                    "--project",
                    str(HERE / "pyrightconfig.json"),
                    "--pythonpath",
                    sys.executable,
                    *helpers,
                ],
                300,
                "pyright",
            ),
        ]
    )
    records = []
    for name, argv, timeout, required in commands:
        before = source_snapshot(args.execution_commit, args.input_sha256)
        write(output / (name + ".source-before.json"), before)
        reasons = sorted(set(global_reasons + before["reasons"]))
        if required == "psutil" and psutil is None:
            reasons.append("required_runtime_psutil_unavailable:" + str(psutil_error))
        elif required != "psutil" and not packages.get(required, {}).get("available"):
            reasons.append("required_quality_tool_unavailable:" + required)
        directory = output / name
        if reasons:
            directory.mkdir()
            (directory / "stdout.log").write_bytes(b"")
            (directory / "stderr.log").write_bytes(b"")
            write(directory / "prerequisite-block.json", {"reasons": reasons})
            record = {
                "name": name,
                "argv": argv,
                "timeout": timeout,
                "raw_outcome": "BLOCKED",
                "exit_code": None,
                "classification": "prerequisite_or_source_gate",
                "reasons": reasons,
                "actual_product_methods_executed": 0,
            }
        else:
            try:
                record = {"name": name, **run_command(directory, argv, env, timeout)}
                if name.startswith("test_"):
                    summary_path = output / (name + "-methods") / "summary.json"
                    if summary_path.is_file():
                        methods = json.loads(summary_path.read_text(encoding="utf-8"))
                        record["method_summary"] = str(summary_path)
                        if record["exit_code"] == 77 and methods.get("status") == "BLOCKED":
                            record.update(
                                raw_outcome="BLOCKED",
                                classification="module_prerequisite",
                                reasons=methods.get("reasons", []),
                            )
                        record["loaded_methods"] = methods.get("loaded")
                        record["testsRun"] = methods.get("testsRun")
                        record["uncaught_thread_errors"] = methods.get("uncaught_thread_errors", [])
                    else:
                        record["method_accounting_gap"] = "No complete method summary retained"
            except BaseException:
                record = {
                    "name": name,
                    "argv": argv,
                    "raw_outcome": "ERROR",
                    "exit_code": None,
                    "traceback": traceback.format_exc(),
                }
        after = source_snapshot(args.execution_commit, args.input_sha256)
        write(output / (name + ".source-after.json"), after)
        global_reasons.extend(after["reasons"])
        record.update(
            source_confirmed_before=before["confirmed"],
            source_confirmed_after=after["confirmed"],
            source_reasons=after["reasons"],
        )
        records.append(record)
        write(output / (name + ".command.json"), record)
        compact(
            "validation_command",
            command=name,
            outcome=record["raw_outcome"],
            exit_code=record.get("exit_code"),
            reasons=record.get("reasons", []),
            source_reasons=after["reasons"][:20],
            source_reason_count=len(after["reasons"]),
        )
    final = source_snapshot(args.execution_commit, args.input_sha256)
    write(output / "source-after.json", final)
    summary = {
        "candidate": final.get("candidate"),
        "execution_commit": args.execution_commit,
        "input_index_sha256": args.input_sha256,
        "host": actual_host,
        "prerequisites": prerequisites,
        "commands": records,
        "source_confirmed": final["confirmed"],
        "source_reasons": final["reasons"],
        "validation_only_overlay": final.get("validation_only_overlay"),
        "runtime_scope": "FR13 only; full final acceptance remains separate/incomplete",
        "observer_scope": "passive parent clock/sampling, natural exit before survivor judgment",
        "raw_outcomes_rewritten": False,
    }
    write(output / "summary.json", summary)
    compact(
        "validation_complete",
        host=actual_host,
        source_reasons=final["reasons"],
        outcomes=[{"name": row["name"], "outcome": row["raw_outcome"]} for row in records],
    )
    return int(
        not final["confirmed"]
        or any(
            row["raw_outcome"] != "PASS"
            or row.get("observation") == "GAP"
            or row.get("method_accounting_gap")
            for row in records
        )
    )


if __name__ == "__main__":
    actions_only()
    try:
        raise SystemExit(main())
    except Exception:
        detail = traceback.format_exc()
        write(
            EVIDENCE / "validation-fatal.json",
            {"outcome": "ERROR", "traceback": detail},
        )
        compact("validation_fatal", error=detail, evidence_directory=str(EVIDENCE))
        raise
