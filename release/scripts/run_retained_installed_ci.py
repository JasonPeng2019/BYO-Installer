"""Exercise retained Windows analysis drivers on genuine current Actions inputs.

The full original reports remain authoritative, including any PENDING groups.
This adapter gates only the supplied artifact/profile and its actual update
input. run_retained_profiles_ci joins the two genuinely built artifact scopes.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import test_code_analysis_installed as installed


ROOT = Path(__file__).resolve().parents[2]


def reference(path):
    path = Path(path).resolve(strict=True)
    return {
        "path": str(path),
        "sha256": installed.digest(path),
        "size": path.stat().st_size,
    }


def write(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "bundle",
        "archive",
        "firmware-source",
        "workspace-source",
        "arm-receipt",
        "evidence",
        "rustc",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--cppcheck-build-receipt", type=Path)
    parser.add_argument(
        "--installed-profile", choices=("personal", "professional"), default="personal"
    )
    parser.add_argument("--update-bundle", type=Path)
    parser.add_argument("--update-cppcheck-build-receipt", type=Path)
    args = parser.parse_args()
    if bool(args.update_bundle) != bool(args.update_cppcheck_build_receipt):
        parser.error(
            "distinct-version bundle and its actual Cppcheck build receipt are a pair"
        )
    if os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError(
            "Genuine corpus compilation and retained native checks run in Windows Actions"
        )
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    report = {
        "schema": "retained-installed-ci-scope/v1",
        "commands": [],
        "artifact": reference(args.archive),
        "complete_installed_acceptance": False,
        "applicable_ci_outcome": "ERROR",
        "model_requests": 0,
        "hardware_operations": 0,
        "installed_profile": args.installed_profile,
    }
    outcome = 1

    def run(name, command):
        record = {"name": name, "argv": command, "exit": None}
        try:
            with (
                (evidence / f"{name}.stdout").open("xb") as stdout,
                (evidence / f"{name}.stderr").open("xb") as stderr,
            ):
                completed = subprocess.run(
                    command,
                    cwd=ROOT,
                    stdout=stdout,
                    stderr=stderr,
                    stdin=subprocess.DEVNULL,
                    timeout=1800,
                    check=False,
                )
            record.update(
                exit=completed.returncode,
                outcome="PASS" if completed.returncode == 0 else "NONZERO",
            )
        except subprocess.TimeoutExpired as error:
            record.update(outcome="TIMEOUT", error=repr(error))
        except OSError as error:
            record.update(outcome="ERROR", error=repr(error))
        report["commands"].append(record)
        return record["exit"]

    try:
        bundle = args.bundle.resolve(strict=True)
        firmware = args.firmware_source.resolve(strict=True)
        toolchain = installed.read_json(args.arm_receipt)
        cpp_receipt = (
            args.cppcheck_build_receipt
            or ROOT / "release/build/analysis-evidence/cppcheck-build.json"
        )
        cpp = installed.read_json(cpp_receipt)
        source_lock = installed.read_json(ROOT / "release/source-lock.json")
        # Reuse the actual fixed-candidate corpus builder; no template database
        # is published until all real compile and link commands have succeeded.
        sys.path.insert(0, str(firmware / "tests"))
        spec = importlib.util.spec_from_file_location(
            "current_arm_corpus_builder", firmware / "tests/final_acceptance_suite.py"
        )
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        corpus = evidence / "built-arm-corpus"
        facts = {
            "steps": [],
            "source_inputs": {
                str(p.resolve()): installed.file_record(p)
                for p in builder.ARM_CORPUS.rglob("*")
                if p.is_file()
            },
        }
        arm_ready = False
        try:
            builder.build_arm_corpus(Path(toolchain["root"]), corpus, facts)
            arm_ready = True
        except Exception as error:
            facts.update(outcome="ERROR", error=repr(error))
        finally:
            write(evidence / "arm-build.json", facts)
        inputs = {
            "schema": "installed-current-inputs/v1",
            "source_lock": reference(ROOT / "release/source-lock.json"),
            "analysis_lock": reference(ROOT / "release/analysis-tools.lock.json"),
            "cppcheck_build": reference(cpp_receipt),
            "arm_toolchain": reference(args.arm_receipt),
            "arm_build": reference(evidence / "arm-build.json"),
            "arm_corpus": {"root": str(corpus), "files": installed.tree_record(corpus)},
        }
        input_path = evidence / "current-inputs.json"
        write(input_path, inputs)
        manifest_path = bundle / "release-manifest.json"
        manifest = installed.read_json(manifest_path)
        expanded_path = evidence / "expanded-files.json"
        write(
            expanded_path,
            {
                "files": [
                    {
                        "path": p.relative_to(bundle).as_posix(),
                        **installed.file_record(p),
                    }
                    for p in sorted(bundle.rglob("*"))
                    if p.is_file()
                ]
            },
        )
        helper = ROOT / "release/scripts/test_code_analysis_installed.py"
        card_path = evidence / "compiled-inputs.json"
        write(
            card_path,
            {
                "artifact": reference(args.archive),
                "manifest": reference(manifest_path),
                "tester_script": reference(helper),
                "expanded_file_manifest": reference(expanded_path),
                "bundle_root": str(bundle),
                "version": manifest["version"],
                "source": manifest["source"],
                "test_repository_source": {
                    "commit": subprocess.check_output(
                        ["git", "rev-parse", "HEAD"], cwd=ROOT
                    )
                    .decode()
                    .strip()
                },
                "active_required_references": [
                    reference(cpp_receipt),
                    reference(args.arm_receipt),
                    reference(ROOT / "release/source-lock.json"),
                ],
            },
        )
        common = [
            sys.executable,
            "-B",
            str(helper),
            "--archive",
            str(args.archive.resolve()),
            "--archive-sha256",
            installed.digest(args.archive),
            "--bundle",
            str(bundle),
            "--cppcheck-sha256",
            cpp["executable_sha256"],
        ]
        # Execute the retained full personal driver. Its original PENDING gates
        # remain PENDING; no same-version or other-profile credit is invented.
        full_command = [
            *common,
            "--ci-input-record",
            str(input_path),
            "--ci-input-record-sha256",
            installed.digest(input_path),
            "--arm-fixture",
            str(corpus),
            "--python-workspace",
            str(args.workspace_source.resolve()),
            "--python-commit",
            source_lock["agent_workspace"]["commit"],
            "--rustc",
            str(args.rustc.resolve()),
            "--rustc-sha256",
            installed.digest(args.rustc),
            "--availability-inputs",
            str(
                ROOT
                / "release/scripts/fixtures/code-analysis-installed/availability/manifest.json"
            ),
            "--availability-sha256",
            installed.digest(
                ROOT
                / "release/scripts/fixtures/code-analysis-installed/availability/manifest.json"
            ),
            "--evidence",
            str(evidence / "installed"),
            "--installed-profile",
            args.installed_profile,
        ]
        if args.update_bundle:
            other_cpp = installed.read_json(args.update_cppcheck_build_receipt)
            full_command += [
                "--update-bundle",
                str(args.update_bundle.resolve()),
                "--update-manifest-sha256",
                installed.digest(args.update_bundle / "release-manifest.json"),
                "--update-cppcheck-sha256",
                other_cpp["executable_sha256"],
            ]
        full_code = run("installed", full_command) if arm_ready else None
        if not arm_ready:
            report["commands"].append(
                {
                    "name": "installed",
                    "argv": full_command,
                    "outcome": "BLOCKED",
                    "exit": None,
                    "reason": "Genuine selected ARM corpus build failed; see arm-build.json",
                }
            )
        # An independent original compiled driver still runs after any RED/error
        # in the first driver, against the same unmodified artifact inputs.
        compiled_code = (
            run(
                "compiled",
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "release/scripts/test_code_analysis_compiled_smoke.py"),
                    "--receipt",
                    str(card_path),
                    "--receipt-sha256",
                    installed.digest(card_path),
                    "--tester-sha256",
                    installed.digest(helper),
                    "--arm-root",
                    toolchain["root"],
                    "--compiler-sha256",
                    toolchain["compiler_sha256"],
                    "--evidence",
                    str(evidence / "compiled"),
                ],
            )
            if args.installed_profile == "personal"
            else None
        )
        if args.installed_profile == "professional":
            report["commands"].append(
                {
                    "name": "compiled",
                    "outcome": "NOT_APPLICABLE_PROFILE",
                    "reason": "The original 11-contract compiled driver explicitly requires personal narrative health; its unchanged body runs on the personal artifact.",
                }
            )
        full_path, compiled_path = (
            evidence / "installed/report.json",
            evidence / "compiled/report.json",
        )
        full = (
            installed.read_json(full_path)
            if full_path.is_file()
            else {
                "gates": {
                    name: {
                        "status": "UNRUN",
                        "reason": "No terminal driver report; retain actual command/ARM dependency outcome",
                    }
                    for name in installed.GATES
                },
                "availability_cases": {},
                "installed_acceptance": False,
            }
        )
        compiled = installed.read_json(compiled_path) if compiled_path.is_file() else {}
        if full_path.is_file():
            report["original_installed_report"] = reference(full_path)
        if compiled_path.is_file():
            report["original_compiled_report"] = reference(compiled_path)
        report["retained_13_gates"] = full["gates"]
        report["retained_11_contracts"] = compiled.get("compiled_gaps", {})
        report["availability_cases"] = full["availability_cases"]
        allowed_pending = {"mcp-availability", "update-preservation"}
        if args.update_bundle:
            allowed_pending.remove("update-preservation")
        ordinary = all(
            row["status"] == "PASS"
            for name, row in full["gates"].items()
            if name not in allowed_pending
        ) and set(full["gates"]) == set(installed.GATES)
        selected_profile = {
            name: row
            for name, row in full["availability_cases"].items()
            if name.endswith("-" + args.installed_profile)
        }
        compiled_qualified = args.installed_profile == "professional" or (
            compiled_code == 0
            and compiled.get("compiled_milestone") is True
            and len(compiled.get("compiled_gaps", {})) == 11
            and all(value == "PASS" for value in compiled["compiled_gaps"].values())
        )
        qualified = (
            full_code in (0, 3)
            and ordinary
            and len(selected_profile) == 6
            and all(row["status"] == "PASS" for row in selected_profile.values())
            and compiled_qualified
        )
        report["applicable_ci_outcome"] = "PASS" if qualified else "FAIL"
        report["complete_installed_acceptance"] = full.get(
            "installed_acceptance", False
        )
        report["remaining_prerequisites"] = [
            "SAME independent final roles after STOP/admission/newfreeze; current worker evidence is not acceptance",
            "See original opposite-profile PENDING groups and PROFILE-CONTRACT-JOINS.json for actual other-image witnesses",
        ]
        if not args.update_bundle:
            report["remaining_prerequisites"].append(
                "This invocation has no genuine distinct-version second artifact; its update gate remains PENDING"
            )
        outcome = int(not qualified)
    except Exception as error:
        import traceback

        report.update(error=repr(error), traceback=traceback.format_exc())
    finally:
        write(evidence / "report.json", report)
    print(
        json.dumps(
            {
                "applicable_ci_outcome": report["applicable_ci_outcome"],
                "complete_installed_acceptance": report[
                    "complete_installed_acceptance"
                ],
            }
        )
    )
    return outcome


if __name__ == "__main__":
    raise SystemExit(main())
