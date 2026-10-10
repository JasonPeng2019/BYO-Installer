"""CI glue contracts: no real toolchain acquisition, compiler or product runs."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import run_installed_analysis_ci as ci


class InstalledAnalysisCiContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.archive = self.root / "bundle.zip"
        self.archive.write_bytes(b"measured fixture archive, not a product")
        self.receipt = {
            "schema": "arm-test-toolchain-input/v1",
            "target": "linux-x86_64",
            "compiler": str(self.root / "compiler"),
            "compiler_sha256": "a" * 64,
            "archive": {"sha256": "b" * 64},
        }
        self.arguments = [
            "--expected-target",
            "linux-x86_64-glibc-2.28",
            "--bundle",
            str(self.root / "bundle"),
            "--archive",
            str(self.archive),
            "--workspace-source",
            str(self.root / "workspace"),
            "--evidence",
            str(self.root / "evidence/core"),
            "--arm-input-dir",
            str(self.root / "arm-inputs"),
            "--artifact-label",
            "candidate-fixture-sha",
        ]

    def invoke(self, *, target="linux-x86_64", result=0, failure=None):
        with (
            mock.patch.object(ci.analysis_tools, "host_target", return_value=target),
            mock.patch.object(
                ci.arm, "acquire", return_value=self.receipt, side_effect=failure
            ) as acquire,
            mock.patch.object(ci.smoke, "main", return_value=result) as smoke,
        ):
            code = ci.main(self.arguments)
        return code, acquire, smoke

    def test_host_mismatch_refuses_before_network_or_smoke(self):
        with contextlib.redirect_stderr(io.StringIO()):
            code, acquire, smoke = self.invoke(target="macos-aarch64")
        self.assertEqual(code, 2)
        acquire.assert_not_called()
        smoke.assert_not_called()

    def test_measured_archive_and_pinned_compiler_bind_existing_smoke_arguments(self):
        code, acquire, smoke = self.invoke(result=3)
        self.assertEqual(code, 3)
        acquire.assert_called_once_with("linux-x86_64", self.root / "arm-inputs")
        arguments = ci.smoke.parser().parse_args(smoke.call_args.args[0])
        self.assertEqual(arguments.platform, "linux-x86_64")
        self.assertEqual(arguments.archive, self.archive.resolve(strict=True))
        self.assertEqual(
            arguments.archive_sha256,
            hashlib.sha256(self.archive.read_bytes()).hexdigest(),
        )
        self.assertEqual(arguments.arm_gxx, Path(self.receipt["compiler"]))
        self.assertEqual(arguments.arm_gxx_sha256, self.receipt["compiler_sha256"])
        self.assertEqual(arguments.artifact_label, "candidate-fixture-sha")
        self.assertEqual(arguments.python_workspace, self.root / "workspace")
        self.assertEqual(arguments.scratch, self.root / "evidence/core")
        self.assertEqual(
            json.loads((self.root / "evidence/core.arm-test-input.json").read_text()),
            self.receipt,
        )
        self.assertFalse((self.root / "evidence/core").exists())

    def test_acquisition_failure_never_calls_smoke(self):
        with contextlib.redirect_stderr(io.StringIO()):
            code, acquire, smoke = self.invoke(
                failure=RuntimeError("archive pin differs")
            )
        self.assertEqual(code, 2)
        acquire.assert_called_once()
        smoke.assert_not_called()

    def test_sibling_retry_preserves_first_attempt_receipt(self):
        code, _, _ = self.invoke()
        self.assertEqual(code, 0)
        first_path = self.root / "evidence/core.arm-test-input.json"
        first_bytes = first_path.read_bytes()
        self.arguments[self.arguments.index("--evidence") + 1] = str(
            self.root / "evidence/core-retry"
        )
        self.arguments[self.arguments.index("--arm-input-dir") + 1] = str(
            self.root / "arm-inputs-retry"
        )
        self.receipt = {**self.receipt, "compiler": str(self.root / "retry-compiler")}
        code, _, _ = self.invoke()
        self.assertEqual(code, 0)
        self.assertEqual(first_path.read_bytes(), first_bytes)
        second_path = self.root / "evidence/core-retry.arm-test-input.json"
        self.assertEqual(json.loads(second_path.read_text()), self.receipt)
        self.assertNotEqual(first_path.read_bytes(), second_path.read_bytes())

    def test_existing_attempt_receipt_refuses_before_acquisition(self):
        receipt_path = self.root / "evidence/core.arm-test-input.json"
        receipt_path.parent.mkdir()
        receipt_path.write_bytes(b"retained prior attempt")
        with contextlib.redirect_stderr(io.StringIO()):
            code, acquire, smoke = self.invoke()
        self.assertEqual(code, 2)
        acquire.assert_not_called()
        smoke.assert_not_called()
        self.assertEqual(receipt_path.read_bytes(), b"retained prior attempt")

    def test_missing_archive_refuses_before_acquisition(self):
        self.archive.unlink()
        with contextlib.redirect_stderr(io.StringIO()):
            code, acquire, smoke = self.invoke()
        self.assertEqual(code, 2)
        acquire.assert_not_called()
        smoke.assert_not_called()

    def test_windows_rustc_path_is_forwarded_without_a_shell(self):
        self.arguments[1] = "windows-x86_64"
        rustc = self.root / "actual compiler/rustc.exe"
        self.arguments += ["--rustc", str(rustc)]
        self.receipt["target"] = "windows-x86_64"
        code, acquire, smoke = self.invoke(target="windows-x86_64")
        self.assertEqual(code, 0)
        self.assertEqual(acquire.call_args.args[0], "windows-x86_64")
        self.assertEqual(
            ci.smoke.parser().parse_args(smoke.call_args.args[0]).rustc, rustc
        )


if __name__ == "__main__":
    unittest.main()
