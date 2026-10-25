"""Run ordinary unittest fixtures and retain actual methods and subtest events."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import inspect
import json
import os
import platform
import sys
import threading
import time
import traceback
import unittest
from pathlib import Path

CLOCK = time.monotonic


def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test


def main() -> int:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("FR13 tests execute only in GitHub Actions")
    parser = argparse.ArgumentParser()
    parser.add_argument("--module", required=True)
    parser.add_argument("--firmware", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    firmware = args.firmware.resolve()
    here = Path(__file__).parent.resolve()
    sys.path[:0] = [str(firmware), str(firmware / "src"), str(here)]
    try:
        module = importlib.import_module(args.module)
    except Exception as exc:
        missing = getattr(exc, "name", None)
        internal = ("tests", "pyocd_debug_mcp", "test_independent", "native_fixture")
        dependency_gap = (
            isinstance(exc, (ModuleNotFoundError, ImportError))
            and missing is not None
            and missing.split(".", 1)[0] not in internal
        )
        status = "BLOCKED" if dependency_gap else "ERROR"
        reason = (
            "required_module_import_unavailable:" + str(missing)
            if dependency_gap
            else "module_import_error:" + type(exc).__name__
        )
        summary = {
            "module": args.module,
            "status": status,
            "loaded": 0,
            "testsRun": 0,
            "actual_product_methods_executed": 0,
            "reasons": [reason],
            "traceback": traceback.format_exc(),
            "python": sys.version,
            "executable": sys.executable,
            "accounting": "No synthetic loader method counts as an original feature test",
        }
        traceback.print_exc()
        (args.output / "loaded.json").write_text("[]\n", encoding="utf-8")
        (args.output / "summary.json").write_text(
            json.dumps(summary, indent=2) + "\n", encoding="utf-8"
        )
        (args.output / "events.jsonl").write_text(
            json.dumps({"kind": "module_prerequisite", "at": CLOCK(), **summary}) + "\n",
            encoding="utf-8",
        )
        return 77 if dependency_gap else 1
    loaded = list(flatten(unittest.defaultTestLoader.loadTestsFromModule(module)))
    identities = []
    for test in loaded:
        function = getattr(type(test), test._testMethodName, None)
        wrapper = inspect.getsourcefile(function) if function is not None else None
        definition = inspect.unwrap(function) if function is not None else None
        path = inspect.getsourcefile(definition) if definition is not None else None
        identities.append(
            {
                "id": test.id(),
                "path": path,
                "callable_path": wrapper,
                "callable_sha256": hashlib.sha256(Path(wrapper).read_bytes()).hexdigest()
                if wrapper
                else None,
                "unittest_skip": bool(getattr(function, "__unittest_skip__", False)),
                "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest() if path else None,
            }
        )
    (args.output / "loaded.json").write_text(
        json.dumps(identities, indent=2) + "\n", encoding="utf-8"
    )
    events = (args.output / "events.jsonl").open("w", encoding="utf-8", buffering=1)
    outcomes = {}
    starts, stops = set(), set()
    subtests = []
    event_lock = threading.Lock()

    def emit(kind, test=None, **extra):
        with event_lock:
            events.write(
                json.dumps(
                    {
                        "kind": kind,
                        "id": test.id() if test is not None else None,
                        "at": CLOCK(),
                        **extra,
                    },
                    default=str,
                )
                + "\n"
            )

    class Result(unittest.TextTestResult):
        def __init__(self, stream, descriptions, verbosity):
            super().__init__(stream, descriptions, verbosity)

        def startTest(self, test):
            starts.add(test.id())
            emit("start", test)
            super().startTest(test)

        def stopTest(self, test):
            stops.add(test.id())
            emit("stop", test, outcome=outcomes.get(test.id(), "ERROR_MISSING_OUTCOME"))
            super().stopTest(test)

        def addSuccess(self, test):
            outcomes[test.id()] = "PASS"
            emit("outcome", test, outcome="PASS")
            super().addSuccess(test)

        def addError(self, test, err):
            outcomes[test.id()] = "ERROR"
            error_class = err[0]
            emit(
                "outcome",
                test,
                outcome="ERROR",
                error_type=getattr(error_class, "__name__", None),
            )
            super().addError(test, err)

        def addFailure(self, test, err):
            outcomes[test.id()] = "FAIL"
            error_class = err[0]
            emit(
                "outcome",
                test,
                outcome="FAIL",
                error_type=getattr(error_class, "__name__", None),
            )
            super().addFailure(test, err)

        def addSkip(self, test, reason):
            if hasattr(test, "test_case"):
                emit(
                    "subtest",
                    test,
                    outcome="SKIP",
                    parent=getattr(test, "test_case").id(),
                    reason=reason,
                )
                subtests.append({"id": test.id(), "outcome": "SKIP", "reason": reason})
            else:
                outcomes[test.id()] = "SKIP"
                emit("outcome", test, outcome="SKIP", reason=reason)
            super().addSkip(test, reason)

        def addExpectedFailure(self, test, err):
            outcomes[test.id()] = "XFAIL"
            emit("outcome", test, outcome="XFAIL")
            super().addExpectedFailure(test, err)

        def addUnexpectedSuccess(self, test):
            outcomes[test.id()] = "XPASS"
            emit("outcome", test, outcome="XPASS")
            super().addUnexpectedSuccess(test)

        def addSubTest(self, test, subtest, err):
            error_class = err[0] if err else None
            if err is None:
                state = "PASS"
            elif error_class is not None and issubclass(error_class, test.failureException):
                state = "FAIL"
            else:
                state = "ERROR"
            subtests.append({"id": subtest.id(), "parent": test.id(), "outcome": state})
            emit(
                "subtest",
                subtest,
                parent=test.id(),
                outcome=state,
                parameters=str(getattr(subtest, "params")),
                error_type=getattr(error_class, "__name__", None),
            )
            if err is not None:
                prior = outcomes.get(test.id())
                outcomes[test.id()] = "ERROR" if "ERROR" in (prior, state) else "FAIL"
            super().addSubTest(test, subtest, err)

    results = []

    class Runner(unittest.TextTestRunner):
        def _makeResult(self):
            result = super()._makeResult()
            results.append(result)
            return result

    emit("loaded", count=len(loaded))
    runner = Runner(verbosity=2, resultclass=Result, failfast=False, buffer=False)
    fatal = []
    thread_errors = []
    previous_thread_hook = threading.excepthook

    def thread_error(args):
        diagnostic = {
            "outcome": "ERROR",
            "error_type": args.exc_type.__name__,
            "traceback": "".join(
                traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback)
            ),
            "thread_name": args.thread.name if args.thread else None,
            "thread_ident": args.thread.ident if args.thread else None,
            "native_id": args.thread.native_id if args.thread else None,
            "at": CLOCK(),
            "attribution": "command-level uncaught thread error; no method outcome rewritten",
        }
        thread_errors.append(diagnostic)
        emit("uncaught_thread_error", **diagnostic)
        previous_thread_hook(args)

    pending = list(loaded)
    threading.excepthook = thread_error
    try:
        while pending:
            before_count = len(starts)
            try:
                # Retain normal class/module fixtures; never retry a started method.
                runner.run(unittest.TestSuite(pending))
                break
            except BaseException:
                detail = traceback.format_exc()
                fatal.append(detail)
                traceback.print_exc()
                emit("runner_error", traceback=detail)
                pending = [test for test in loaded if test.id() not in starts]
                if len(starts) == before_count:
                    emit(
                        "blocked_remaining",
                        reason="class/module fixture escaped before a new case started",
                        methods=[test.id() for test in pending],
                    )
                    break
    finally:
        threading.excepthook = previous_thread_hook
    imports = []
    for name, imported in sorted(tuple(sys.modules.items())):
        path = getattr(imported, "__file__", None)
        if path and (name.startswith("pyocd_debug_mcp") or name == args.module):
            resolved = Path(path).resolve()
            imports.append(
                {
                    "module": name,
                    "path": str(resolved),
                    "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
                    "inside_firmware": resolved.is_relative_to(firmware),
                }
            )
    imported_outside = [
        row
        for row in imports
        if row["module"].startswith("pyocd_debug_mcp") and not row["inside_firmware"]
    ]
    expected_root = firmware / "tests" if args.module.startswith("tests.") else here
    loaded_outside = [
        row
        for row in identities
        if not row["path"] or not Path(row["path"]).resolve().is_relative_to(expected_root)
    ]
    index = json.loads((here / "CI-INPUTS.json").read_text(encoding="utf-8"))
    declared = set(index["declared_methods_inventory_only"][args.module])
    actual = {row["id"] for row in identities}
    summary = {
        "module": args.module,
        "loaded": len(loaded),
        "testsRun": sum(result.testsRun for result in results),
        "outcomes": outcomes,
        "subtests": subtests,
        "missing_declared": sorted(declared - actual),
        "unexpected_loaded": sorted(actual - declared),
        "missing_start": sorted(actual - starts),
        "missing_stop": sorted(starts - stops),
        "missing_outcome": sorted(stops - outcomes.keys()),
        "imports": imports,
        "wrong_source_imports": imported_outside,
        "wrong_loaded_sources": loaded_outside,
        "dependencies": sorted(
            (d.metadata.get("Name", ""), d.version) for d in importlib.metadata.distributions()
        ),
        "raw_errors": [(test.id(), detail) for result in results for test, detail in result.errors],
        "raw_failures": [
            (test.id(), detail) for result in results for test, detail in result.failures
        ],
        "fatal_error": fatal,
        "uncaught_thread_errors": thread_errors,
        "python": sys.version,
        "executable": sys.executable,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "accounting": "ordinary unittest suite; clock captured before test imports",
    }
    (args.output / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    emit("complete", summary="summary.json")
    events.close()
    bad = (
        fatal
        or thread_errors
        or not loaded
        or not results
        or any(not result.wasSuccessful() for result in results)
        or imported_outside
        or loaded_outside
    )
    for key in (
        "missing_declared",
        "unexpected_loaded",
        "missing_start",
        "missing_stop",
        "missing_outcome",
    ):
        bad = bad or summary[key]
    return int(bool(bad))


if __name__ == "__main__":
    raise SystemExit(main())
