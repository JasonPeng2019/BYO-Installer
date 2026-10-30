"""Exact deferred-helper joins and real read-only Windows terminal controls."""

from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import deferred_launcher_cleanup as cleanup


class DeferredCleanupJoins(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="deferred-joins-")
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        target = root / ".byo-update-0123456789abcdef.exe"
        target.write_bytes(b"exact previous launcher fixture")
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        self.contract = cleanup.source_contract(
            Path(__file__).resolve().parents[2] / "launcher/src/install.rs"
        )
        self.parent = {"pid": 123, "creation_filetime": 100}
        self.expected = {
            "contract": self.contract,
            "previous_launcher_sha256": digest,
            "target_directory": str(root),
            "helper_image": str(root / "helper.exe"),
        }
        self.receipt = {
            "schema": "windows-launcher-deferred-cleanup-observation/v1",
            "parent_pid": 123,
            "parent_creation_filetime": 100,
            "requested_parent_pid": 123,
            "helper_pid": 456,
            "helper_creation_filetime": 200,
            "helper_image": self.expected["helper_image"],
            "target": str(target),
            "target_sha256_before_spawn": digest,
            **{
                key: self.contract[key]
                for key in (
                    "script_sha256",
                    "parent_wait_ms",
                    "delete_attempts",
                    "delete_retry_ms",
                )
            },
        }
        self.child = {
            "pid": 456,
            "creation_filetime": 200,
            "parent_pid": 123,
            "parent_creation_filetime": 100,
            "image": self.expected["helper_image"],
            "alive_after": True,
        }

    def test_source_contract_and_exact_nonempty_join(self):
        self.assertEqual(self.contract["post_parent_seconds"], 120)
        row, child, target = cleanup.select_observation(
            [self.receipt], self.parent, [self.child], self.expected
        )
        self.assertEqual(row, self.receipt)
        self.assertIs(child, self.child)
        self.assertEqual(target.read_bytes(), b"exact previous launcher fixture")

    def test_missing_ambiguous_or_mismatched_observations_never_qualify(self):
        cases = [
            ([], [self.child]),
            ([self.receipt, self.receipt], [self.child]),
            ([self.receipt], []),
        ]
        for key, value in (
            ("schema", "wrong"),
            ("parent_pid", 124),
            ("parent_creation_filetime", 99),
            ("requested_parent_pid", None),
            ("helper_pid", 457),
            ("helper_creation_filetime", 201),
            ("script_sha256", "0" * 64),
            ("target_sha256_before_spawn", "0" * 64),
            ("delete_attempts", 121),
            (
                "target",
                str(
                    Path(self.temporary.name).parent
                    / ".byo-update-0123456789abcdef.exe"
                ),
            ),
        ):
            receipt = {**self.receipt, key: value}
            cases.append(([receipt], [self.child]))
        for key, value in (
            ("creation_filetime", None),
            ("creation_filetime", 201),
            ("parent_creation_filetime", 99),
            ("parent_pid", 1),
            ("alive_after", None),
            ("image", str(Path(self.temporary.name) / "foreign.exe")),
        ):
            cases.append(([self.receipt], [{**self.child, key: value}]))
        cases.append(([self.receipt], [self.child, {**self.child, "pid": 789}]))
        for number, (rows, children) in enumerate(cases):
            with self.subTest(control=number):
                with self.assertRaises(ValueError):
                    cleanup.select_observation(
                        copy.deepcopy(rows),
                        self.parent,
                        copy.deepcopy(children),
                        self.expected,
                    )

    def test_changed_tombstone_cannot_use_the_old_image_receipt(self):
        Path(self.receipt["target"]).write_bytes(b"different current image")
        with self.assertRaisesRegex(ValueError, "tombstone differs"):
            cleanup.select_observation(
                [self.receipt], self.parent, [self.child], self.expected
            )

    def test_deferred_oracle_preserves_ordinary_failure_and_requires_every_terminal_axis(
        self,
    ):
        """Algorithm controls; real Windows kernel observations are tested below."""

        directory = Path(self.temporary.name) / "spawns"
        directory.mkdir()
        import json

        (directory / "actual-control.json").write_text(
            json.dumps(self.receipt), encoding="utf-8"
        )
        target = Path(self.receipt["target"])

        class NativeControl:
            def __init__(self, code=0, denied=False, close_error=False):
                self.code, self.denied, self.close_error = code, denied, close_error
                self.closed = False

            def retain_exact(self, identity):
                if self.denied:
                    raise PermissionError("controlled denied exact handle")
                return 10

            def observe_retained(self, handle, identity):
                return {"terminal": True, "exit_code": self.code, "test_control": True}

            def release_retained(self, handle):
                self.closed = True
                if self.close_error:
                    raise OSError("controlled close failure")

        for label, code, exists, at, denied, close_error, outcome in (
            ("natural-zero", 0, False, 0, False, False, "PASS"),
            ("natural-nonzero", 3, False, 0, False, False, "FAIL"),
            ("target-remains", 0, True, 121, False, False, "TIMEOUT"),
            ("late-positive", 0, False, 121, False, False, "TIMEOUT"),
            ("denied", 0, False, 0, True, False, "ERROR"),
            ("close-error", 0, False, 0, False, True, "ERROR"),
        ):
            with self.subTest(control=label):
                target.write_bytes(b"exact previous launcher fixture")
                if not exists:
                    target.unlink()
                native = NativeControl(code, denied, close_error)
                with patch.object(cleanup.time, "monotonic", return_value=at):
                    result = cleanup.qualify(
                        directory, native, self.parent, [self.child], self.expected, 0
                    )
                self.assertEqual(result["outcome"], outcome, result)
                self.assertEqual(result["ordinary_axis"], "FAIL")
                self.assertEqual(result["ordinary_survivors"], [self.child])
                self.assertEqual(result["interventions"], [])
                self.assertEqual(native.closed, not denied)


@unittest.skipUnless(os.name == "nt", "Real retained Windows kernel process objects")
class DeferredNativeTerminal(unittest.TestCase):
    def test_live_wrong_birth_and_natural_nonzero_terminal_are_distinct(self):
        from test_code_analysis_installed import Setup, WindowsProcesses

        native = WindowsProcesses()
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                "import sys; print('ready', flush=True); sys.stdin.readline(); sys.exit(3)",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.addCleanup(process.stderr.close)
        self.addCleanup(process.stdout.close)
        self.addCleanup(process.stdin.close)
        handle = None
        try:
            self.assertEqual(process.stdout.readline().strip(), b"ready")
            identity = native.identity(process.pid)
            self.assertIsNotNone(identity)
            with self.assertRaisesRegex(Setup, "wrong exact identity"):
                native.retain_exact(
                    {**identity, "creation_filetime": identity["creation_filetime"] + 1}
                )
            self.assertIsNone(process.poll())
            handle = native.retain_exact(identity)
            self.assertFalse(native.observe_retained(handle, identity)["terminal"])
            process.stdin.write(b"release\n")
            process.stdin.flush()
            process.wait(timeout=5)
            terminal = native.observe_retained(handle, identity)
            self.assertTrue(terminal["terminal"])
            self.assertEqual(terminal["exit_code"], 3)
            self.assertEqual(
                terminal["creation_filetime"], identity["creation_filetime"]
            )
        finally:
            if handle is not None:
                native.release_retained(handle)
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
