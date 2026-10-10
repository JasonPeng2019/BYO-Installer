"""Native compiler receipt failure controls; no compiler execution or download."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import check_arm_test_input as ci


class NativeCompilerReceiptContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.compiler = self.root / "compiler-fixture"
        self.compiler.write_bytes(b"receipt fixture; never executed")
        self.receipt = {
            "compiler": str(self.compiler),
            "compiler_sha256": hashlib.sha256(self.compiler.read_bytes()).hexdigest(),
        }
        self.arguments = [str(self.compiler), "--version"]

    def invoke(self, evidence, outcome):
        arguments = [
            "check_arm_test_input.py",
            "--expected-target",
            "linux-x86_64",
            "--input-directory",
            str(self.root / "inputs"),
            "--evidence",
            str(evidence),
        ]
        with (
            mock.patch("sys.argv", arguments),
            mock.patch.object(
                ci.analysis_tools, "host_target", return_value="linux-x86_64"
            ),
            mock.patch.object(ci.arm, "acquire", return_value=self.receipt) as acquire,
            mock.patch.object(ci.subprocess, "run") as execute,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            if isinstance(outcome, BaseException):
                execute.side_effect = outcome
            else:
                execute.return_value = outcome
            code = ci.main()
        acquire.assert_called_once_with("linux-x86_64", self.root / "inputs")
        execute.assert_called_once_with(self.arguments, capture_output=True, timeout=30)
        return code, json.loads((evidence / "native-input.json").read_text())

    def test_timeout_preserves_attempted_arguments_and_partial_streams_without_exit(
        self,
    ):
        for index, streams in enumerate(
            ((b"partial version\n", b"native diagnostic\n"), (None, None))
        ):
            with self.subTest(streams=streams):
                evidence = self.root / f"timeout-{index}"
                timeout = subprocess.TimeoutExpired(
                    self.arguments, 30, output=streams[0], stderr=streams[1]
                )
                code, receipt = self.invoke(evidence, timeout)
                self.assertEqual(code, 1)
                self.assertIs(receipt["confirmed"], False)
                self.assertEqual(receipt["arguments"], self.arguments)
                self.assertIsNone(receipt["exit_code"])
                self.assertIn("TimeoutExpired", receipt["error"])
                self.assertEqual(receipt["input_receipt"], self.receipt)
                self.assertEqual(
                    (evidence / "compiler.stdout").read_bytes(), streams[0] or b""
                )
                self.assertEqual(
                    (evidence / "compiler.stderr").read_bytes(), streams[1] or b""
                )

    def test_completed_nonzero_exit_retains_actual_code_and_both_streams(self):
        evidence = self.root / "nonzero"
        completed = subprocess.CompletedProcess(
            self.arguments, 17, b"actual output\n", b"actual error\n"
        )
        code, receipt = self.invoke(evidence, completed)
        self.assertEqual(code, 1)
        self.assertIs(receipt["confirmed"], False)
        self.assertEqual(receipt["arguments"], self.arguments)
        self.assertEqual(receipt["exit_code"], 17)
        self.assertEqual((evidence / "compiler.stdout").read_bytes(), completed.stdout)
        self.assertEqual((evidence / "compiler.stderr").read_bytes(), completed.stderr)


if __name__ == "__main__":
    unittest.main()
