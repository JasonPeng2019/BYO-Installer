"""Retain real unittest execution while running the release script's own entrypoint.

Only Actions calls this helper. Plain function/script runners stay command-level
in final_acceptance_checks; declarations alone never become executed methods.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import runpy
import sys
import time
import traceback
import unittest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--script", type=Path)
    selection.add_argument("--unittest-names", nargs="+")
    parser.add_argument(
        "--command-only",
        action="store_true",
        help="A standalone script has no promised unittest entrypoint",
    )
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Final named-test execution is Actions-only after ROOT freeze")
    installer = Path(__file__).resolve().parents[2]
    script = args.script.resolve(strict=True) if args.script else None
    if script and script.parent != Path(__file__).resolve().parent:
        raise RuntimeError(
            "Release ledger requires an actual selected release test script"
        )
    source = installer / "Firmware MCP New/tests/final_acceptance_suite.py"
    # The file-loaded driver imports its real test siblings before selection.
    sys.path.insert(0, str(source.parent))
    spec = importlib.util.spec_from_file_location("frozen_firmware_ledger", source)
    ledger = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ledger)
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    suites = []

    class RecordedRunner(unittest.TextTestRunner):
        def run(self, suite):
            directory = evidence / f"suite-{len(suites) + 1}"
            directory.mkdir()
            events = directory / "events.jsonl"
            events.touch()
            loaded = list(ledger.flatten(suite))
            ledger.write(directory / "loaded.json", loaded)
            self.resultclass = lambda *a, **kw: ledger.LedgerResult(
                *a, ledger=events, **kw
            )
            record = {
                "loaded": loaded,
                "started_monotonic": time.monotonic(),
                "result": "UNRUN",
                "directory": str(directory),
            }
            suites.append(record)
            try:
                result = super().run(suite)
                record.update(
                    result="PASS" if result.wasSuccessful() else "FAIL",
                    testsRun=result.testsRun,
                    methods={
                        name: outcome
                        for name, outcome in result.outcomes.items()
                        if name in loaded
                    },
                    fixture_outcomes={
                        name: outcome
                        for name, outcome in result.outcomes.items()
                        if name not in loaded
                    },
                    loaded_without_method_outcome={
                        name: "UNRUN; inspect actual fixture events"
                        for name in loaded
                        if name not in result.outcomes
                    },
                )
                return result
            finally:
                record["completed_monotonic"] = time.monotonic()
                ledger.write(directory / "result.json", record)

    # unittest.main still selects and runs the script's actual __main__ module.
    # Only its result observer changes, in this fresh interpreter.
    unittest.TextTestRunner = RecordedRunner
    unittest.runner.TextTestRunner = RecordedRunner
    import_root = script.parent if script else installer / "Firmware MCP New"
    sys.path.insert(0, str(import_root))
    sys.argv = [str(script)] if script else ["unittest", "-v", *args.unittest_names]
    error, exit_code = None, 0
    ledger.write(
        evidence / "start.json",
        {
            "script": str(script),
            "script_sha256": ledger.digest(script) if script else None,
            "selected_unittest_names": args.unittest_names,
            "ledger_source": str(source),
            "ledger_sha256": ledger.digest(source),
            "at_monotonic": time.monotonic(),
            **ledger.execution_identities(),
        },
    )
    try:
        if script:
            runpy.run_path(str(script), run_name="__main__")
        else:
            unittest.main(module=None)
    except SystemExit as exc:
        exit_code = (
            exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
        )
    except BaseException:
        exit_code, error = 1, traceback.format_exc()
        traceback.print_exc()
    finally:
        imports = []
        for name, module in list(sys.modules.items()):
            raw = getattr(module, "__file__", None)
            if raw:
                path = Path(raw).resolve()
                if path.is_relative_to(import_root) and path.is_file():
                    imports.append(
                        {
                            "module": name,
                            "path": str(path),
                            "sha256": ledger.digest(path),
                        }
                    )
        gaps = (
            ["No actual unittest runner invocation"]
            if not suites and not args.command_only
            else []
        )
        if any(suite["result"] == "UNRUN" for suite in suites):
            gaps.append("A started unittest suite did not produce its final result")
        ledger.write(
            evidence / "result.json",
            {
                "script": str(script),
                "script_sha256": ledger.digest(script) if script else None,
                "selected_unittest_names": args.unittest_names,
                "accounting": "actual unittest suites"
                if suites
                else "command-only; no executed method records claimed",
                "exit": exit_code,
                "error": error,
                "suites": suites,
                "evidence_gaps": gaps,
                "release_imports": imports,
                "at_monotonic": time.monotonic(),
                **ledger.execution_identities(),
            },
        )
    return exit_code or int(
        bool(gaps) or any(suite["result"] != "PASS" for suite in suites)
    )


if __name__ == "__main__":
    raise SystemExit(main())
