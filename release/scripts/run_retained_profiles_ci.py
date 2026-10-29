"""Join the retained contracts to actual personal/professional installed bodies.

Both original reports keep their per-invocation pending groups. This finite CI
coordinator runs each eligible artifact once and records the deciding witnesses
for all 13 installed gates, 11 personal compiled contracts and 12 availability
groups. It launches no models, native client or physical targets.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

import test_code_analysis_installed as installed


ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "base-payload",
        "base-analysis",
        "profile-fixture",
        "arm-receipt",
        "evidence",
        "rustc",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError(
            "Retained native compilation/checks are Windows Actions only"
        )
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    report = {
        "schema": "retained-installed-profile-joins/v1",
        "commands": [],
        "artifacts": {},
        "coverage_joins": [],
        "outcome": "ERROR",
        "model_requests": 0,
        "hardware_operations": 0,
        "campaign_acceptance": False,
    }

    def run(label, source, bundle, cpp_receipt, profile, update=None):
        argv = [
            sys.executable,
            "-B",
            str(source / "release/scripts/run_retained_installed_ci.py"),
            "--bundle",
            str(bundle),
            "--archive",
            str(bundle) + ".zip",
            "--firmware-source",
            str(source / "Firmware MCP New"),
            "--workspace-source",
            str(source / "AgentWorkspace"),
            "--arm-receipt",
            str(args.arm_receipt.resolve()),
            "--cppcheck-build-receipt",
            str(cpp_receipt),
            "--installed-profile",
            profile,
            "--rustc",
            str(args.rustc.resolve()),
            "--evidence",
            str(evidence / label),
        ]
        if update is not None:
            argv += [
                "--update-bundle",
                str(update[0]),
                "--update-cppcheck-build-receipt",
                str(update[1]),
            ]
        record = {"label": label, "argv": argv, "exit": None, "outcome": "UNRUN"}
        try:
            with (
                (evidence / f"{label}.stdout").open("xb") as stdout,
                (evidence / f"{label}.stderr").open("xb") as stderr,
            ):
                result = subprocess.run(
                    argv,
                    cwd=source,
                    stdout=stdout,
                    stderr=stderr,
                    stdin=subprocess.DEVNULL,
                    timeout=4200,
                    check=False,
                )
            record.update(
                exit=result.returncode,
                outcome="PASS" if result.returncode == 0 else "NONPASS",
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            record.update(
                outcome="TIMEOUT"
                if isinstance(error, subprocess.TimeoutExpired)
                else "ERROR",
                error=repr(error),
            )
        report["commands"].append(record)
        path = evidence / label / "report.json"
        try:
            return installed.read_json(path) if path.is_file() else {}
        except (OSError, ValueError) as error:
            record["report_error"] = repr(error)
            return {}

    try:
        profile_path = args.profile_fixture / "PROFILE-FIXTURE.json"
        fixture = {}
        professional = None
        try:
            fixture = installed.read_json(profile_path)
            if (
                fixture.get("outcome") != "PASS"
                or fixture["canonical_event_sha"] != os.environ["GITHUB_SHA"]
                or fixture["canonical_sources"]["installer"] != os.environ["GITHUB_SHA"]
            ):
                raise RuntimeError(
                    "Genuine professional fixture build is not qualified"
                )
            source, bundle = Path(fixture["fixture_installer"]), Path(fixture["bundle"])
            if (
                installed.digest(bundle / "release-manifest.json")
                != fixture["manifest_sha256"]
            ):
                raise RuntimeError("Professional fixture image binding changed")
            professional = (
                source,
                bundle,
                source / "release/build/analysis-evidence/cppcheck-build.json",
            )
        except Exception as error:
            report["artifacts"]["professional_input_error"] = repr(error)
        personal_input = None
        try:
            candidates = []
            for path in args.base_payload.rglob("release-manifest.json"):
                manifest = installed.read_json(path)
                if (
                    manifest.get("platform") == "windows"
                    and manifest.get("architecture") == "x86_64"
                    and manifest["source"]["installer"]["commit"]
                    == os.environ["GITHUB_SHA"]
                ):
                    candidates.append(path.parent)
            if len(candidates) != 1:
                raise RuntimeError("No unique exact canonical personal bundle artifact")
            bundle = candidates[0]
            raw_cpp = installed.digest(bundle / "analysis/cppcheck/cppcheck.exe")
            cpp_candidates = [
                p
                for p in args.base_analysis.rglob("cppcheck-build.json")
                if installed.read_json(p).get("executable_sha256") == raw_cpp
            ]
            if len(cpp_candidates) != 1:
                raise RuntimeError(
                    "Personal artifact lacks one exact independent Cppcheck build receipt"
                )
            report["artifacts"]["personal"] = {
                "bundle": str(bundle),
                "manifest_sha256": installed.digest(bundle / "release-manifest.json"),
                "archive_sha256": installed.digest(Path(str(bundle) + ".zip")),
            }
            personal_input = (bundle, cpp_candidates[0])
        except Exception as error:
            report["artifacts"]["personal_input_error"] = repr(error)
        personal = {}
        if personal_input:
            personal = run(
                "personal",
                ROOT,
                *personal_input,
                "personal",
                (professional[1], professional[2]) if professional else None,
            )
        else:
            report["commands"].append(
                {
                    "label": "personal",
                    "outcome": "BLOCKED",
                    "reason": report["artifacts"]["personal_input_error"],
                    "exit": None,
                }
            )
        prof = {}
        if professional:
            report["artifacts"]["professional"] = {
                "bundle": str(professional[1]),
                "manifest_sha256": fixture["manifest_sha256"],
                "fixture_source_receipt": str(profile_path),
                "fixture_source_receipt_sha256": installed.digest(profile_path),
            }
            prof = run("professional", *professional, "professional")
        else:
            report["commands"].append(
                {
                    "label": "professional",
                    "outcome": "BLOCKED",
                    "reason": report["artifacts"]["professional_input_error"],
                    "exit": None,
                }
            )
        for name in installed.GATES:
            if name == "mcp-availability":
                witnesses = [
                    {
                        "artifact": profile,
                        "group": state + "-" + profile,
                        "raw": result.get("availability_cases", {}).get(
                            state + "-" + profile, {"status": "UNRUN"}
                        ),
                    }
                    for profile, result in (
                        ("personal", personal),
                        ("professional", prof),
                    )
                    for state in installed.STATES
                ]
            else:
                # The canonical personal invocation must execute every gate,
                # including the genuine transition to the separately built B.
                witnesses = [
                    {
                        "artifact": "personal",
                        "raw": personal.get("retained_13_gates", {}).get(
                            name, {"status": "UNRUN"}
                        ),
                    }
                ]
            report["coverage_joins"].append(
                {
                    "gate": name,
                    "witnesses": witnesses,
                    "qualified": bool(witnesses)
                    and all(w["raw"]["status"] == "PASS" for w in witnesses),
                }
            )
        compiled = personal.get("retained_11_contracts", {})
        report["compiled_contracts"] = compiled
        report["all_13_installed_gates_qualified"] = len(
            report["coverage_joins"]
        ) == 13 and all(row["qualified"] for row in report["coverage_joins"])
        report["all_11_compiled_contracts_qualified"] = len(compiled) == 11 and all(
            v == "PASS" for v in compiled.values()
        )
        report["outcome"] = (
            "PASS"
            if (
                report["all_13_installed_gates_qualified"]
                and report["all_11_compiled_contracts_qualified"]
                and len(report["commands"]) == 2
                and all(row["outcome"] == "PASS" for row in report["commands"])
            )
            else "FAIL"
        )
        report["scope"] = (
            "Actual native installed contract witnesses across the canonical personal artifact and disclosed genuine professional/version fixture; independent final acceptance remains open. Original pending reports unchanged."
        )
    except Exception as error:
        import traceback

        report.update(error=repr(error), traceback=traceback.format_exc())
    finally:
        (evidence / "PROFILE-CONTRACT-JOINS.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
    print(json.dumps({"outcome": report["outcome"], "campaign_acceptance": False}))
    return int(report["outcome"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
