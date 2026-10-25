"""Real baseline/corrected command error controls; original method PASS stays PASS."""

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from thread_error_control import CONTROL_METHOD, HERE, exercise


class ThreadErrorAccounting(unittest.TestCase):
    def setUp(self):
        parent = os.environ.get("FR13_CONTROL_EVIDENCE")
        if parent:
            Path(parent).mkdir(parents=True, exist_ok=True)
        self.directory = Path(tempfile.mkdtemp(prefix="thread-accounting-", dir=parent)).resolve()

    def check_common(self, result):
        self.assertEqual(result["helper_sha256"], result["copied_helper_sha256"])
        summary = result["summary"]
        self.assertEqual(summary["loaded"], 1)
        self.assertEqual(summary["testsRun"], 1)
        self.assertEqual(summary["outcomes"], {CONTROL_METHOD: "PASS"})
        self.assertEqual(summary["raw_errors"], [])
        self.assertEqual(summary["fatal_error"], [])
        for key in (
            "missing_declared",
            "unexpected_loaded",
            "missing_start",
            "missing_stop",
            "missing_outcome",
            "wrong_source_imports",
            "wrong_loaded_sources",
        ):
            self.assertEqual(summary[key], [], key)
        expected_fixture = hashlib.sha256(
            (HERE / "thread_error_fixture.py").read_bytes()
        ).hexdigest()
        self.assertEqual(result["fixture_sha256"], expected_fixture)
        self.assertEqual([row["sha256"] for row in result["loaded"]], [expected_fixture])
        self.assertEqual([row["callable_sha256"] for row in result["loaded"]], [expected_fixture])
        self.assertTrue(result["hook_lifetime"]["previous_handler_restored"])
        starts = [row["id"] for row in result["events"] if row["kind"] == "start"]
        stops = [row["id"] for row in result["events"] if row["kind"] == "stop"]
        self.assertEqual(starts, [CONTROL_METHOD])
        self.assertEqual(stops, [CONTROL_METHOD])

    def test_unexpected_joined_thread_fails_command_without_rewriting_method(self):
        for label, helper, expected in (
            ("baseline", HERE / "inputs/run_unittest.full01.py", 0),
            ("corrected", HERE / "run_unittest.py", 1),
        ):
            with self.subTest(recorder=label):
                result = exercise(
                    helper, HERE.parent / "Firmware MCP New", self.directory / label, True
                )
                self.check_common(result)
                self.assertEqual(result["exit_code"], expected, result)
                self.assertEqual(result["prior_handler"]["message"], "release unlocked lock")
                self.assertIn("RuntimeError: release unlocked lock", result["stderr"])
                errors = result["summary"].get("uncaught_thread_errors", [])
                self.assertEqual(len(errors), 1 if label == "corrected" else 0)
                if errors:
                    self.assertEqual(errors[0]["error_type"], "RuntimeError")
                    self.assertIn("release unlocked lock", errors[0]["traceback"])
                    diagnostic = [
                        r for r in result["events"] if r["kind"] == "uncaught_thread_error"
                    ]
                    self.assertEqual(len(diagnostic), 1)
                    self.assertIsNone(
                        diagnostic[0]["id"], "No passing method owns this thread error"
                    )

    def test_joined_thread_without_error_keeps_both_recorder_commands_successful(self):
        for label, helper in (
            ("baseline", HERE / "inputs/run_unittest.full01.py"),
            ("corrected", HERE / "run_unittest.py"),
        ):
            with self.subTest(recorder=label):
                result = exercise(
                    helper, HERE.parent / "Firmware MCP New", self.directory / label, False
                )
                self.check_common(result)
                self.assertEqual(result["exit_code"], 0, result)
                self.assertEqual(result["summary"].get("uncaught_thread_errors", []), [])
                self.assertNotIn("RuntimeError: release unlocked lock", result["stderr"])


if __name__ == "__main__":
    unittest.main()
