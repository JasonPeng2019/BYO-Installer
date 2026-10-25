"""Qualify an interpreter and fresh locked environment before the finite pass."""

from __future__ import annotations

import argparse
import json
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
    ROOT,
    UV_BOOTSTRAP,
    UV_CACHE,
    VENV,
    actions_only,
    compact,
    host_facts,
    source_snapshot,
    write,
)

PROBE = (HERE / "probe_environment.py").read_text(encoding="utf-8")


def main() -> int:
    actions_only()
    parser = argparse.ArgumentParser()
    parser.add_argument("--execution-commit", required=True)
    parser.add_argument("--input-sha256", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--requested-python", default="")
    parser.add_argument("--python-setup-outcome", required=True)
    args = parser.parse_args()
    setup = EVIDENCE / "setup"
    setup.mkdir(parents=True, exist_ok=False)
    host = host_facts(args.host)
    initial = source_snapshot(args.execution_commit, args.input_sha256)
    write(setup / "host.json", host)
    write(setup / "source-before.json", initial)
    compact(
        "setup_preflight",
        host=host,
        source_reasons=initial["reasons"],
        requested_python=args.requested_python,
        python_setup_outcome=args.python_setup_outcome,
        bootstrap_role="stdlib coordinator; never a feature-test fallback",
    )
    persistent = list(initial["reasons"])
    if not host["matches_expected"]:
        persistent.append("actual_host_does_not_match_required_target")
    records: list[dict[str, Any]] = []

    def run(name, argv, timeout, reasons=(), env=None):
        before = source_snapshot(args.execution_commit, args.input_sha256)
        write(setup / (name + ".source-before.json"), before)
        blocked = sorted(set(persistent + before["reasons"] + list(reasons)))
        result = {"name": name, "argv": argv, "timeout": timeout, "reasons": blocked}
        started = CLOCK()
        stdout, stderr = setup / (name + ".stdout.log"), setup / (name + ".stderr.log")
        with stdout.open("wb") as out, stderr.open("wb") as err:
            if blocked:
                result.update(raw_outcome="BLOCKED", exit_code=None)
            else:
                try:
                    child = subprocess.run(
                        argv,
                        cwd=ROOT,
                        env=env,
                        stdin=subprocess.DEVNULL,
                        stdout=out,
                        stderr=err,
                        timeout=timeout,
                        check=False,
                    )
                    result.update(
                        exit_code=child.returncode,
                        raw_outcome="PASS" if child.returncode == 0 else "FAIL",
                    )
                except subprocess.TimeoutExpired as exc:
                    result.update(raw_outcome="TIMEOUT", exit_code=None, error=repr(exc))
                except OSError as exc:
                    result.update(raw_outcome="ERROR", exit_code=None, error=repr(exc))
        after = source_snapshot(args.execution_commit, args.input_sha256)
        write(setup / (name + ".source-after.json"), after)
        persistent.extend(after["reasons"])
        result.update(
            elapsed=CLOCK() - started,
            source_confirmed=after["confirmed"],
            stdout=str(stdout),
            stderr=str(stderr),
            process_scope="direct wait; pre-venv descendant observation not proven",
        )
        records.append(result)
        write(setup / (name + ".command.json"), result)
        compact("setup_command", **result, source_reasons=after["reasons"])
        return result

    reasons: list[str] = []
    if args.python_setup_outcome not in {"success", "container"}:
        reasons.append("requested_Python_installation_step_failed_or_skipped")
    if not args.requested_python or not Path(args.requested_python).is_file():
        reasons.append("explicit_requested_Python_executable_unavailable")
    chosen = args.requested_python or sys.executable
    interpreter = run("qualified-python", [chosen, "-I", "-c", PROBE], 30, reasons)
    actual: dict[str, Any] = {}
    if interpreter["raw_outcome"] == "PASS":
        try:
            actual = json.loads(Path(interpreter["stdout"]).read_text(encoding="utf-8"))
            expected = [3, 12] if args.host.startswith("linux-") else [3, 12, 10]
            if actual.get("version", [])[: len(expected)] != expected:
                reasons.append("requested_interpreter_version_does_not_match_policy")
            arches = {
                "windows-x86_64": {"amd64", "x86_64"},
                "macos-aarch64": {"aarch64", "arm64"},
                "macos-x86_64": {"x86_64"},
                "linux-x86_64-glibc-2.28": {"x86_64"},
            }
            if actual.get("machine", "").lower() not in arches.get(args.host, set()):
                reasons.append("requested_interpreter_architecture_does_not_match_target")
        except (OSError, ValueError, TypeError) as exc:
            reasons.append("interpreter_probe_invalid:" + repr(exc))
    else:
        reasons.append("qualified_interpreter_probe_did_not_pass")
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    env.update(
        PYTHONNOUSERSITE="1",
        PYTHONDONTWRITEBYTECODE="1",
        UV_PROJECT_ENVIRONMENT=str(VENV),
        UV_CACHE_DIR=str(UV_CACHE),
        UV_PYTHON_DOWNLOADS="never",
        PIP_DISABLE_PIP_VERSION_CHECK="1",
    )
    install = run(
        "uv-install",
        [
            chosen,
            "-I",
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-cache-dir",
            "--target",
            str(UV_BOOTSTRAP),
            "uv==0.11.20",
        ],
        180,
        reasons,
        env,
    )
    if install["raw_outcome"] != "PASS":
        reasons.append("pinned_uv_bootstrap_installation_unavailable")
    uv_env = dict(env, PYTHONPATH=str(UV_BOOTSTRAP))
    uv = [chosen, "-B", "-m", "uv"]
    version = run("uv-version", [*uv, "--version"], 30, reasons, uv_env)
    if version["raw_outcome"] == "PASS":
        value = Path(version["stdout"]).read_text(encoding="utf-8").strip().split()[:2]
        if value != ["uv", "0.11.20"]:
            reasons.append("uv_version_does_not_match_0.11.20")
    else:
        reasons.append("pinned_uv_version_probe_did_not_pass")
    sync = run(
        "locked-sync",
        [
            *uv,
            "sync",
            "--project",
            str(FIRMWARE),
            "--locked",
            "--all-groups",
            "--python",
            chosen,
        ],
        900,
        reasons,
        uv_env,
    )
    if sync["raw_outcome"] != "PASS":
        reasons.append("locked_all_groups_sync_did_not_pass")
    python = VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not python.is_file():
        reasons.append("fresh_locked_virtual_environment_missing")
    probe = run("venv-probe", [str(python), "-I", "-c", PROBE, "venv"], 30, reasons, env)
    facts: dict[str, Any] = {}
    if probe["raw_outcome"] == "PASS":
        try:
            facts = json.loads(Path(probe["stdout"]).read_text(encoding="utf-8"))
            if Path(facts["prefix"]).resolve() != VENV.resolve():
                reasons.append("interpreter_prefix_is_not_the_bound_venv")
            if facts["prefix"] == facts["base_prefix"]:
                reasons.append("interpreter_is_not_a_virtual_environment")
            if facts["version"][:2] != [3, 12] or facts["version"] != actual.get("version"):
                reasons.append("venv_version_differs_from_qualified_Python_3_12")
            config = (VENV / "pyvenv.cfg").read_text(encoding="utf-8").lower()
            if "include-system-site-packages = false" not in config:
                reasons.append("venv_global_dependency_isolation_unconfirmed")
            for name in ("psutil", "ruff", "pyright", "pyocd_debug_mcp"):
                if not facts["packages"].get(name, {}).get("available"):
                    reasons.append("locked_dependency_unavailable:" + name)
            if facts.get("psutil_import", {}).get("ok") is not True:
                reasons.append("locked_psutil_native_import_failed")
            origin = facts["packages"].get("pyocd_debug_mcp", {}).get("path")
            if not origin or not Path(origin).resolve().is_relative_to(FIRMWARE / "src"):
                reasons.append("editable_product_source_is_not_the_fixed_firmware")
        except (OSError, KeyError, ValueError, TypeError) as exc:
            reasons.append("venv_qualification_unavailable:" + repr(exc))
    else:
        reasons.append("venv_probe_did_not_pass")
    final = source_snapshot(args.execution_commit, args.input_sha256)
    reasons.extend(persistent + final["reasons"])
    prerequisites = {
        "schema": "fr13-prerequisites/v1",
        "host": host,
        "execution_commit": args.execution_commit,
        "input_sha256": args.input_sha256,
        "requested_python": args.requested_python,
        "qualified_python": actual,
        "venv_python": str(python),
        "venv_facts": facts,
        "ready": not reasons,
        "reasons": sorted(set(reasons)),
        "commands": records,
        "source_confirmed": final["confirmed"],
        "dependency_policy": "uv0.11.20, locked all-groups, fresh venv, no global fallback",
    }
    write(EVIDENCE / "prerequisites.json", prerequisites)
    compact(
        "prerequisites",
        ready=prerequisites["ready"],
        reasons=prerequisites["reasons"],
        qualified_python=actual,
        venv=facts,
    )
    coordinator = str(python) if prerequisites["ready"] else sys.executable
    driver = [
        coordinator,
        "-B",
        str(HERE / "run_actions.py"),
        "--execution-commit",
        args.execution_commit,
        "--input-sha256",
        args.input_sha256,
        "--host",
        args.host,
        "--prerequisites",
        str(EVIDENCE / "prerequisites.json"),
    ]
    # Independent commands have individual limits; the workflow supplies the
    # enclosing deadline and process-tree cleanup. Never kill only this driver
    # on a shorter outer timeout and strand a still-running test interpreter.
    with (setup / "validation.stdout.log").open("wb") as out:
        with (setup / "validation.stderr.log").open("wb") as err:
            child = subprocess.run(
                driver,
                cwd=ROOT,
                env=env,
                stdout=out,
                stderr=err,
                stdin=subprocess.DEVNULL,
                check=False,
            )
    for line in (setup / "validation.stdout.log").read_text(encoding="utf-8").splitlines():
        print(line, flush=True)
    result = {"argv": driver, "exit_code": child.returncode}
    write(setup / "validation.command.json", result)
    write(
        setup / "source-after.json",
        source_snapshot(args.execution_commit, args.input_sha256),
    )
    compact("setup_complete", driver=result, prerequisites_ready=prerequisites["ready"])
    return int(not prerequisites["ready"] or child.returncode != 0)


if __name__ == "__main__":
    actions_only()
    try:
        raise SystemExit(main())
    except Exception:
        detail = traceback.format_exc()
        write(EVIDENCE / "setup-fatal.json", {"outcome": "ERROR", "traceback": detail})
        compact("setup_fatal", error=detail, evidence_directory=str(EVIDENCE))
        raise
