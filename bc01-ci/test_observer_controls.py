"""Directed observer faults with real native commands; Actions execution only."""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import psutil

import run_actions


def native_failure(process):
    try:
        raise PermissionError("directed native metadata denial")
    except PermissionError as cause:
        raise SystemError("native query returned an exception") from cause


class ObserverContracts(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.environ.get("GITHUB_ACTIONS"), "true")
        evidence = Path(
            os.environ.get(
                "FR13_CONTROL_EVIDENCE",
                str(Path(__file__).resolve().parent.parent / "helper-preparation-runtime"),
            )
        )
        self.root = evidence / "observer-controls" / self._testMethodName
        self.root.mkdir(parents=True, exist_ok=False)
        self.previous_psutil = run_actions.psutil
        run_actions.psutil = psutil
        self.addCleanup(setattr, run_actions, "psutil", self.previous_psutil)

    def command(self, source):
        directory = self.root / "command"
        record = run_actions.run_command(
            directory, [sys.executable, "-B", "-c", source], dict(os.environ), 10
        )
        (directory / "control-result.json").write_text(json.dumps(record, indent=2))
        return directory, record

    def test_native_cmdline_error_keeps_exact_birth_and_real_status(self):
        birth = psutil.Process().create_time()
        with patch.object(psutil.Process, "cmdline", native_failure):
            facts = run_actions.identity(os.getpid(), birth)
        (self.root / "facts.json").write_text(json.dumps(facts, indent=2))
        self.assertEqual(facts["identity"], "same_birth")
        self.assertEqual(facts["birth"], birth)
        self.assertEqual(run_actions.state(facts), "live")
        self.assertIn("SystemError", facts["cmdline"]["unknown"])
        self.assertIn("PermissionError", facts["cmdline"]["cause"])

    def test_native_status_error_remains_unknown(self):
        birth = psutil.Process().create_time()
        with patch.object(psutil.Process, "status", native_failure):
            facts = run_actions.identity(os.getpid(), birth)
        (self.root / "facts.json").write_text(json.dumps(facts, indent=2))
        self.assertEqual(run_actions.state(facts), "unknown")
        self.assertIn("SystemError", facts["status"]["unknown"])

    def test_native_cmdline_fault_keeps_real_child_wait_and_streams(self):
        source = (
            "import subprocess,sys; "
            "child=subprocess.Popen([sys.executable,'-B','-c',"
            "'import time; time.sleep(0.8); print(42)']); "
            "raise SystemExit(child.wait(timeout=5))"
        )
        with patch.object(psutil.Process, "cmdline", native_failure):
            directory, record = self.command(source)
        self.assertEqual(record["exit_code"], 0)
        self.assertFalse(record["timed_out"])
        self.assertEqual(record["natural_boundary"]["kind"], "natural_exit")
        self.assertTrue(record["natural_boundary"]["wait_returned"])
        self.assertEqual(record["observation"], "CAPTURED_IDENTITIES_TERMINAL")
        self.assertTrue(record["survivors"])
        self.assertEqual((directory / "stdout.log").read_text().strip(), "42")

    def test_unexpected_sampler_error_keeps_wait_but_fails_observation(self):
        with patch.object(
            run_actions, "sample", side_effect=RuntimeError("directed sampler fault")
        ):
            directory, record = self.command("import time; time.sleep(0.4); print(43)")
        self.assertEqual(record["exit_code"], 0)
        self.assertEqual(record["natural_boundary"]["kind"], "natural_exit")
        self.assertEqual(record["observation"], "GAP")
        self.assertTrue(record["observation_errors"])
        self.assertIn("directed sampler fault", record["observation_errors"][0]["traceback"])
        self.assertEqual((directory / "stdout.log").read_text().strip(), "43")


if __name__ == "__main__":
    unittest.main()
