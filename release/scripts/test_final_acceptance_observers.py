"""Fresh-interpreter controls for the actual cross-component release ledger.

Small selected bodies measure the observer's accounting, not product acceptance.
The driver and its sibling dependency are copied from the real source checkout.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import final_acceptance_checks as command_observer
import final_public_mcp as public_observer
import psutil


PROBE = """import os
from pathlib import Path
import unittest

class EntryProbe(unittest.TestCase):
    def test_pass(self):
        Path(os.environ["FR08_BODY_MARKER"]).write_text("selected body ran", encoding="utf-8")
        for value in (1, 2):
            with self.subTest(value=value):
                self.assertGreater(value, 0)

    def test_failure(self):
        self.fail("intentional observer fixture failure")

    @unittest.skip("intentional observer fixture skip")
    def test_skipped(self):
        raise AssertionError("skipped body must not run")

if __name__ == "__main__":
    unittest.main()
"""


class ReleaseLedgerEntrypointContracts(unittest.TestCase):
    def setUp(self):
        self.assertEqual(
            os.environ.get("GITHUB_ACTIONS"), "true", "Actions-only control"
        )
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.installer = self.root / "clean installer"
        self.scripts = self.installer / "release/scripts"
        self.tests = self.installer / "Firmware MCP New/tests"
        self.scripts.mkdir(parents=True)
        self.tests.mkdir(parents=True)
        self.cwd = self.root / "unrelated cwd"
        self.cwd.mkdir()
        actual_installer = Path(__file__).resolve().parents[2]
        firmware = actual_installer / "Firmware MCP New"
        if not firmware.is_dir():
            firmware = actual_installer.parent / "BYO-Firmware-MCP"
        for name in ("final_acceptance_suite.py", "process_cleanup_observations.py"):
            shutil.copyfile(firmware / "tests" / name, self.tests / name)
        self.adapter = self.scripts / "final_test_ledger.py"
        shutil.copyfile(Path(__file__).with_name(self.adapter.name), self.adapter)
        self.script = self.scripts / "test_ledger_probe.py"
        self.script.write_text(PROBE, encoding="utf-8")
        (self.tests / "__init__.py").touch()
        (self.tests / "ledger_selection_probe.py").write_text(PROBE, encoding="utf-8")
        retained = os.environ.get("BYO_FINAL_CHILD_EVIDENCE")
        self.evidence = (
            Path(retained) / self._testMethodName
            if retained
            else self.root / "evidence"
        )
        self.evidence.parent.mkdir(parents=True, exist_ok=True)
        self.marker = self.root / "body.txt"

    def invoke(self, *selection):
        environment = dict(os.environ, FR08_BODY_MARKER=str(self.marker))
        environment.pop("PYTHONPATH", None)
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(self.adapter),
                "--evidence",
                str(self.evidence),
                *selection,
            ],
            cwd=self.cwd,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.evidence.mkdir(parents=True, exist_ok=True)
        (self.evidence / "stdout.log").write_text(completed.stdout, encoding="utf-8")
        (self.evidence / "stderr.log").write_text(completed.stderr, encoding="utf-8")
        (self.evidence / "command.json").write_text(
            json.dumps(
                {
                    "argv": completed.args,
                    "cwd": str(self.cwd),
                    "exit": completed.returncode,
                    "pythonpath_removed": True,
                    "isolated_python": True,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self.assertTrue((self.evidence / "result.json").is_file(), completed.stderr)
        result = json.loads((self.evidence / "result.json").read_text(encoding="utf-8"))
        start = json.loads((self.evidence / "start.json").read_text(encoding="utf-8"))
        self.assertEqual(
            start["ledger_source"],
            str((self.tests / "final_acceptance_suite.py").resolve()),
        )
        self.assertEqual(
            start["ledger_sha256"],
            hashlib.sha256(
                (self.tests / "final_acceptance_suite.py").read_bytes()
            ).hexdigest(),
        )
        self.assertLessEqual(start["at_monotonic"], result["at_monotonic"])
        return completed, result

    def suite_events(self, result):
        self.assertEqual(len(result["suites"]), 1)
        suite = result["suites"][0]
        raw = (Path(suite["directory"]) / "events.jsonl").read_text(encoding="utf-8")
        events = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual(
            [e["id"] for e in events if e["kind"] == "start"], suite["loaded"]
        )
        self.assertEqual(
            [e["id"] for e in events if e["kind"] == "stop"], suite["loaded"]
        )
        self.assertEqual(set(suite["methods"]), set(suite["loaded"]))
        self.assertEqual(suite["testsRun"], len(suite["loaded"]))
        self.assertFalse(suite["fixture_outcomes"])
        self.assertFalse(suite["loaded_without_method_outcome"])
        self.assertLessEqual(suite["started_monotonic"], suite["completed_monotonic"])
        return suite, events

    def test_script_entrypoint_retains_actual_failure_skip_and_subtests(self):
        completed, result = self.invoke("--script", str(self.script))
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(result["exit"], 1)
        self.assertIsNone(result["error"])
        self.assertFalse(result["evidence_gaps"])
        self.assertEqual(self.marker.read_text(encoding="utf-8"), "selected body ran")
        suite, events = self.suite_events(result)
        self.assertEqual(suite["result"], "FAIL")
        self.assertEqual(
            suite["methods"],
            {
                "__main__.EntryProbe.test_failure": "FAIL",
                "__main__.EntryProbe.test_pass": "PASS",
                "__main__.EntryProbe.test_skipped": "SKIP",
            },
        )
        self.assertEqual(
            [e["outcome"] for e in events if e["kind"] == "subtest"], ["PASS", "PASS"]
        )
        self.assertTrue(
            any(
                "intentional observer fixture failure" in (e.get("traceback") or "")
                for e in events
            )
        )

    def test_unittest_names_runs_only_the_selected_real_body(self):
        selected = "tests.ledger_selection_probe.EntryProbe.test_pass"
        completed, result = self.invoke("--unittest-names", selected)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["selected_unittest_names"], [selected])
        self.assertEqual(result["exit"], 0)
        self.assertFalse(result["evidence_gaps"])
        self.assertEqual(self.marker.read_text(encoding="utf-8"), "selected body ran")
        suite, events = self.suite_events(result)
        self.assertEqual(suite["loaded"], [selected])
        self.assertEqual(suite["methods"], {selected: "PASS"})
        self.assertEqual(
            [e["parent"] for e in events if e["kind"] == "subtest"],
            [selected, selected],
        )

    def test_standalone_script_does_not_invent_declared_method_execution(self):
        self.script.write_text(
            "import os\nfrom pathlib import Path\n"
            'def test_declared_but_unexecuted():\n    raise AssertionError("must not run")\n'
            'if __name__ == "__main__":\n'
            '    Path(os.environ["FR08_BODY_MARKER"]).write_text("command ran", '
            'encoding="utf-8")\n',
            encoding="utf-8",
        )
        completed, result = self.invoke("--script", str(self.script), "--command-only")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(self.marker.read_text(encoding="utf-8"), "command ran")
        self.assertEqual(result["suites"], [])
        self.assertEqual(
            result["accounting"], "command-only; no executed method records claimed"
        )
        self.assertFalse(result["evidence_gaps"])

    def test_missing_runner_remains_nonpass_and_retains_command_exit(self):
        self.script.write_text("raise SystemExit(7)\n", encoding="utf-8")
        completed, result = self.invoke("--script", str(self.script))
        self.assertEqual(completed.returncode, 7, completed.stderr)
        self.assertEqual(result["exit"], 7)
        self.assertEqual(result["suites"], [])
        self.assertEqual(
            result["evidence_gaps"], ["No actual unittest runner invocation"]
        )

    def test_zero_exit_without_promised_unittest_runner_is_nonpass(self):
        self.script.write_text("raise SystemExit(0)\n", encoding="utf-8")
        completed, result = self.invoke("--script", str(self.script))
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(result["exit"], 0)
        self.assertEqual(result["suites"], [])
        self.assertEqual(
            result["evidence_gaps"], ["No actual unittest runner invocation"]
        )


COMMAND_DESCENDANT_PROBE = r"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from final_acceptance_checks import command_identity

mode, directory = sys.argv[1], Path(sys.argv[2])
if mode == "child":
    (directory / "child-ready.json").write_text(
        json.dumps(command_identity(os.getpid())), encoding="utf-8")
    deadline = time.monotonic() + 60
    while not (directory / "release").exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    (directory / "child-finished.json").write_text("normal child exit", encoding="utf-8")
else:
    child = subprocess.Popen(
        [sys.executable, "-B", __file__, "child", str(directory),
         "multiprocessing.resource_tracker"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 10
    while not (directory / "child-ready.json").is_file() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not (directory / "child-ready.json").is_file():
        raise RuntimeError("actual child failed to become ready")
    (directory / "parent-ready.json").write_text(json.dumps({
        "identity": command_identity(os.getpid()), "child_launcher_pid": child.pid,
        "at_monotonic": time.monotonic(),
    }), encoding="utf-8")
    # Remain live across multiple real owner snapshots, not a later PID lookup.
    time.sleep(0.6)
    if mode == "timeout":
        time.sleep(60)
    elif mode != "leak":
        (directory / "release").touch()
        raise SystemExit(child.wait(timeout=10) or (7 if mode == "failure" else 0))
"""


class CapturedCommandDescendantContracts(unittest.TestCase):
    def setUp(self):
        self.assertEqual(
            os.environ.get("GITHUB_ACTIONS"), "true", "Actions-only controls"
        )
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        shutil.copyfile(
            Path(command_observer.__file__), self.root / "final_acceptance_checks.py"
        )
        self.script = self.root / "command_probe.py"
        self.script.write_text(COMMAND_DESCENDANT_PROBE, encoding="utf-8")
        retained = os.environ.get("BYO_FINAL_CHILD_EVIDENCE")
        self.evidence = (
            Path(retained) / self._testMethodName
            if retained
            else self.root / "evidence"
        )
        self.evidence.mkdir(parents=True)
        self.addCleanup(self.emergency_fixture_cleanup)

    def emergency_fixture_cleanup(self):
        import psutil

        actions = []
        for name in ("child-ready.json", "parent-ready.json"):
            for path in self.evidence.glob("*/" + name):
                try:
                    data = json.loads(path.read_bytes())
                    facts = (
                        data["identity"]
                        if isinstance(data.get("identity"), dict)
                        else data
                    )
                    pid, birth = facts["pid"], facts["creation_time"]
                    current = command_observer.command_identity(pid, birth)
                    if command_observer.command_state(current) == "live":
                        action = {"source": str(path), "before": current}
                        actions.append(action)
                        process = psutil.Process(pid)
                        if process.create_time() == birth:
                            process.kill()
                            process.wait(timeout=15)
                        action["after"] = command_observer.command_identity(pid, birth)
                except (OSError, ValueError, KeyError, psutil.Error) as exc:
                    actions.append({"source": str(path), "error": repr(exc)})
        (self.evidence / "fixture-emergency-cleanup.json").write_text(
            json.dumps(actions, indent=2) + "\n", encoding="utf-8"
        )
        self.assertFalse(
            actions,
            "fixture emergency intervention is a failed control: " + repr(actions),
        )

    def invoke(self, mode, timeout=15):
        directory = self.evidence / mode
        directory.mkdir()
        command = [sys.executable, "-B", str(self.script), mode, str(directory)]
        with (
            (directory / "stdout.log").open("wb") as out,
            (directory / "stderr.log").open("wb") as err,
        ):
            code, timed_out, cleanup, gaps = command_observer.run_finite(
                command, self.root, out, err, timeout
            )
        record = {
            "command": command,
            "cwd": str(self.root),
            "exit": code,
            "timed_out": timed_out,
            "cleanup": cleanup,
            "gaps": gaps,
        }
        (directory / "result.json").write_text(
            json.dumps(record, indent=2) + "\n", encoding="utf-8"
        )
        self.assertFalse([gap for gap in gaps if not gap.get("terminal_race")], record)
        ready = json.loads((directory / "child-ready.json").read_bytes())
        exact = [
            row
            for row in cleanup
            if row["pid"] == ready["pid"]
            and row["creation_time"] == ready["creation_time"]
        ]
        self.assertEqual(len(exact), 1, record)
        row = exact[0]
        captured = row["first_capture"]
        identity = captured["identity"]
        self.assertEqual(identity["identity"], "same_birth")
        self.assertEqual(identity["birth_after_queries"], ready["creation_time"])
        self.assertEqual(identity["cmdline"], ready["cmdline"])
        self.assertEqual(identity["exe"], ready["exe"])
        self.assertEqual(identity["ppid"], captured["parent_identity"]["pid"])
        self.assertEqual(captured["parent_identity"]["identity"], "observed")
        self.assertEqual(captured["boundary"], "during command")
        self.assertLessEqual(captured["at_monotonic"], row["command_exit_monotonic"])
        self.assertLessEqual(row["command_exit_monotonic"], row["judgment_monotonic"])
        self.assertIn("unknown", captured["role"])
        self.assertIn("role_gap", captured)
        self.assertEqual(row["command_exit"], code)
        self.assertEqual(row["timed_out"], timed_out)
        return directory, code, timed_out, row, cleanup

    def test_normal_child_exit_retains_exact_attribution_and_nonzero_command_then_continues(
        self,
    ):
        for mode, expected in (("failure", 7), ("pass", 0)):
            with self.subTest(mode=mode):
                directory, code, timed_out, row, cleanup = self.invoke(mode)
                self.assertEqual(code, expected)
                self.assertFalse(timed_out)
                self.assertEqual(
                    (directory / "child-finished.json").read_text(encoding="utf-8"),
                    "normal child exit",
                )
                self.assertTrue(row["normal_wait_completed"])
                self.assertTrue(row["natural_terminal"])
                self.assertFalse(row["survived_command"])
                self.assertIsNone(row["intervention"])
                self.assertTrue(all(item["cleanup"] == "gone" for item in cleanup))
                self.assertTrue(all(item["natural_terminal"] for item in cleanup))

    def test_helper_shaped_leak_retains_zero_exit_failed_judgment_and_emergency_facts(
        self,
    ):
        directory, code, timed_out, row, cleanup = self.invoke("leak")
        self.assertEqual(code, 0)
        self.assertFalse(timed_out)
        self.assertFalse((directory / "child-finished.json").exists())
        self.assertTrue(row["survived_command"])
        self.assertEqual(row["final_state"], "live")
        self.assertFalse(row["natural_terminal"])
        self.assertIn(
            "multiprocessing.resource_tracker",
            row["first_capture"]["identity"]["cmdline"],
        )
        self.assertEqual(row["intervention"]["kind"], "post-command-emergency-kill")
        self.assertLessEqual(
            row["judgment_monotonic"], row["intervention"]["at_monotonic"]
        )
        self.assertEqual(
            command_observer.command_state(row["intervention"]["before"]), "live"
        )
        self.assertTrue(
            all(
                command_observer.command_state(item["after_cleanup"])
                in ("gone", "terminal")
                for item in cleanup
            )
        )
        # This is the release command's actual final aggregate condition.
        self.assertTrue(
            any(
                item["survived_command"] or item["cleanup"] != "gone"
                for item in cleanup
            )
        )

    def test_timeout_preserves_intervention_and_never_claims_normal_finalization(self):
        _, code, timed_out, row, cleanup = self.invoke("timeout", timeout=2)
        self.assertNotEqual(code, 0)
        self.assertTrue(timed_out)
        self.assertFalse(row["normal_wait_completed"])
        self.assertFalse(row["natural_terminal"])
        self.assertEqual(row["timeout_intervention"]["kind"], "timeout-command.kill")
        self.assertTrue(
            all(
                command_observer.command_state(item["after_cleanup"])
                in ("gone", "terminal")
                for item in cleanup
            )
        )

    def test_unavailable_diagnostic_metadata_keeps_real_natural_exit_and_failure_code(
        self,
    ):
        actual = command_observer.command_identity

        def missing_diagnostics(pid, birth=None):
            facts = actual(pid, birth)
            if facts.get("identity") in ("observed", "same_birth"):
                facts.update(
                    exe={"unavailable": "controlled metadata fault"},
                    cmdline={"unavailable": "controlled metadata fault"},
                )
            return facts

        for mode, expected in (("pass", 0), ("failure", 7)):
            with self.subTest(mode=mode):
                directory = self.evidence / (mode + "-metadata")
                directory.mkdir()
                with (
                    mock.patch.object(
                        command_observer, "command_identity", missing_diagnostics
                    ),
                    (directory / "stdout.log").open("wb") as out,
                    (directory / "stderr.log").open("wb") as err,
                ):
                    code, timed_out, cleanup, gaps = command_observer.run_finite(
                        [sys.executable, "-B", str(self.script), mode, str(directory)],
                        self.root,
                        out,
                        err,
                        15,
                    )
                record = {
                    "exit": code,
                    "timed_out": timed_out,
                    "cleanup": cleanup,
                    "gaps": gaps,
                }
                (directory / "result.json").write_text(
                    json.dumps(record, indent=2), encoding="utf-8"
                )
                self.assertEqual(code, expected)
                self.assertFalse(timed_out)
                self.assertTrue(cleanup)
                self.assertTrue(any(row.get("evidence_gaps") for row in cleanup))
                self.assertFalse(
                    command_observer.command_observation_failed(cleanup, gaps), record
                )
                self.assertTrue(all(row["natural_terminal"] for row in cleanup))

    def test_unreadable_zombie_birth_is_unavailable_and_never_absence(self):
        with mock.patch(
            "psutil.Process", side_effect=psutil.ZombieProcess(os.getpid())
        ):
            facts = command_observer.command_identity(os.getpid(), 1.0)
        self.assertEqual(facts["identity"], "unavailable")
        self.assertEqual(facts["error"], "ZombieProcess")
        self.assertEqual(command_observer.command_state(facts), "unknown")

    def test_native_metadata_system_error_retains_birth_and_never_invents_status(self):
        def native_failure(process):
            try:
                raise PermissionError("directed native metadata denial")
            except PermissionError as cause:
                raise SystemError("native query returned an exception") from cause

        original = command_observer.command_identity(os.getpid())
        birth = original["creation_time"]
        with mock.patch.object(psutil.Process, "cmdline", native_failure):
            facts = command_observer.command_identity(os.getpid(), birth)
        self.assertEqual(command_observer.command_state(facts), "live")
        self.assertEqual(facts["cmdline"]["unavailable"], "SystemError")
        self.assertIn("PermissionError", facts["cmdline"]["cause"])
        with mock.patch.object(psutil.Process, "status", native_failure):
            facts = command_observer.command_identity(os.getpid(), birth)
        self.assertEqual(command_observer.command_state(facts), "unknown")
        self.assertEqual(facts["status"]["unavailable"], "SystemError")

    def test_old_birth_retirement_requires_complete_prior_witness_and_never_owns_replacement(
        self,
    ):
        original = command_observer.command_identity(os.getpid())
        birth = original["creation_time"]
        exact = command_observer.command_identity(os.getpid(), birth)
        # A directed record-level fault control, not a claim of observed PID reuse.
        changed = {**exact, "identity": "reused", "creation_time": birth + 1}
        capture = {"first_capture": {"identity": exact}}
        with mock.patch(
            "psutil.Process.kill", side_effect=AssertionError("replacement signal")
        ):
            self.assertEqual(command_observer.command_state(changed), "unknown")
            self.assertEqual(
                command_observer.captured_identity_state(changed, capture),
                "retired_exact_identity",
            )
            self.assertEqual(
                command_observer.captured_identity_state(
                    changed, {"first_capture": {"identity": {}}}
                ),
                "unknown",
            )
            self.assertEqual(
                command_observer.captured_identity_state(
                    {**changed, "creation_time": float("nan")}, capture
                ),
                "unknown",
            )

    def test_identity_queries_cannot_reap_signal_or_accept_reuse_as_absence(self):
        identity = command_observer.command_identity(os.getpid())
        with (
            mock.patch(
                "psutil.Process.wait", side_effect=AssertionError("observer wait")
            ),
            mock.patch(
                "psutil.Process.kill", side_effect=AssertionError("observer kill")
            ),
            mock.patch(
                "psutil.Process.terminate",
                side_effect=AssertionError("observer terminate"),
            ),
            mock.patch(
                "os.waitpid", create=True, side_effect=AssertionError("observer reap")
            ),
        ):
            exact = command_observer.command_identity(
                os.getpid(), identity["creation_time"]
            )
            reused = command_observer.command_identity(
                os.getpid(), identity["creation_time"] + 1
            )
            owned, gaps = {}, []
            command_observer.capture_command_descendants(
                os.getpid(), identity["creation_time"], owned, gaps
            )
        record = {
            "exact": exact,
            "reused": reused,
            "captured": list(owned.values()),
            "gaps": gaps,
        }
        (self.evidence / "identities.json").write_text(
            json.dumps(record, indent=2), encoding="utf-8"
        )
        self.assertEqual(command_observer.command_state(exact), "live")
        self.assertEqual(command_observer.command_state(reused), "unknown")
        self.assertEqual(
            command_observer.command_state({"identity": "unavailable"}), "unknown"
        )
        self.assertEqual(
            command_observer.command_state({"identity": "missing"}), "unknown"
        )
        self.assertEqual(
            command_observer.command_state(
                {"identity": "same_birth", "status": "running"}
            ),
            "unknown",
        )
        self.assertFalse(gaps, record)


CLEANUP_OUTER = "install::tests::windows_cleanup_helper_deletes_an_exited_executable"
CLEANUP_CHILD = "install::tests::windows_cleanup_helper_child_process"
AFTER = "collector-after-command"
EPHEMERAL = command_observer.EPHEMERAL_IMAGE


class ChildReceiptImageContracts(unittest.TestCase):
    """Collector image binding when a child's own tested cleanup deletes it."""

    def setUp(self):
        self.assertEqual(
            os.environ.get("GITHUB_ACTIONS"), "true", "Actions-only control"
        )
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.receipts = self.root / "receipts"
        self.receipts.mkdir()
        self.parent = self.root / "persistent parent.exe"
        self.parent.write_bytes(b"persistent parent image")
        self.child = self.root / ".byo-uninstall-live-test.exe"
        self.child.write_bytes(b"running ephemeral child image")
        self.digest = hashlib.sha256(self.child.read_bytes()).hexdigest()
        self.images = {path: path.stat() for path in (self.parent, self.child)}
        retained = os.environ.get("BYO_FINAL_CHILD_EVIDENCE")
        self.evidence = (
            Path(retained) / self._testMethodName
            if retained
            else self.root / "evidence"
        )
        self.evidence.mkdir(parents=True, exist_ok=True)

    def receipt(self, kind, image, method, digest, details):
        facts = self.images[image]
        record = {
            "schema": "fr05-rust-child/v1",
            "kind": kind,
            "pid": os.getpid(),
            "executable": str(image),
            "executable_sha256": digest,
            "executable_hash_method": method,
            "executable_bytes": facts.st_size,
            "executable_modified_unix_nanos": str(facts.st_mtime_ns),
            "details": details,
        }
        for stream in ("stdout", "stderr"):
            path = self.receipts / f"{kind}.{stream}.log"
            path.write_bytes(b"")
            record[stream] = str(path)
            record[stream + "_sha256"] = hashlib.sha256(b"").hexdigest()
        (self.receipts / f"{kind}.json").write_text(
            json.dumps(record, indent=2), encoding="utf-8"
        )

    def dispatch_and_start(self, digest, method=EPHEMERAL, **declaration):
        details = {
            "outer_test": CLEANUP_OUTER,
            "child_name": CLEANUP_CHILD,
            "phase": "live-cleanup-target",
            "executable": str(self.child),
            "ephemeral_image": True,
            **declaration,
        }
        self.receipt("dispatch", self.parent, AFTER, None, details)
        start = {"child_name": CLEANUP_CHILD, "phase": "live-cleanup-target"}
        self.receipt("helper-start", self.child, method, digest, start)

    def collect(self):
        result = command_observer.child_receipts(self.receipts)
        (self.evidence / "child-receipts.json").write_text(
            json.dumps(result, indent=2), encoding="utf-8"
        )
        return result

    def kinds(self, result):
        return sorted(record["kind"] for record in result["records"])

    def record(self, result, kind):
        (match,) = [row for row in result["records"] if row["kind"] == kind]
        return match

    def test_declared_deleted_image_keeps_the_running_childs_digest(self):
        self.dispatch_and_start(self.digest)
        self.child.unlink()
        result = self.collect()
        self.assertEqual(result["errors"], [])
        start = self.record(result, "helper-start")
        self.assertEqual(start["collected_executable_sha256"], self.digest)
        qualification = start["executable_hash_qualification"]
        self.assertIn("deleted it before collection", qualification)
        parent = hashlib.sha256(self.parent.read_bytes()).hexdigest()
        dispatch = self.record(result, "dispatch")
        self.assertEqual(dispatch["collected_executable_sha256"], parent)

    def test_present_declared_image_is_still_collector_hashed(self):
        self.dispatch_and_start(self.digest)
        result = self.collect()
        self.assertEqual(result["errors"], [])
        start = self.record(result, "helper-start")
        self.assertEqual(start["collected_executable_sha256"], self.digest)
        qualification = start["executable_hash_qualification"]
        self.assertIn("hashed after command", qualification)
        self.dispatch_and_start("0" * 64)
        mismatch = self.collect()
        self.assertEqual(len(mismatch["errors"]), 1, mismatch)
        self.assertIn("digest mismatch", mismatch["errors"][0]["error"])
        self.assertEqual(self.kinds(mismatch), ["dispatch"])

    def test_undeclared_or_other_declaration_is_an_error(self):
        self.child.unlink()
        for declaration in (
            {"ephemeral_image": False},
            {"phase": "other-phase"},
            {"child_name": "other-child"},
            {"executable": str(self.parent)},
        ):
            with self.subTest(declaration=declaration):
                self.dispatch_and_start(self.digest, **declaration)
                result = self.collect()
                self.assertEqual(len(result["errors"]), 1, result)
                self.assertIn("not parent-declared", result["errors"][0]["error"])
                self.assertEqual(self.kinds(result), ["dispatch"])

    def test_deleted_image_without_a_child_measurement_is_an_error(self):
        self.child.unlink()
        cases = ((AFTER, None), (EPHEMERAL, None), (EPHEMERAL, "x" * 64))
        for method, digest in cases:
            with self.subTest(method=method, digest=digest):
                self.dispatch_and_start(digest, method)
                result = self.collect()
                self.assertEqual(len(result["errors"]), 1, result)
                self.assertEqual(self.kinds(result), ["dispatch"])

    def test_conflicting_child_measurements_of_one_image_are_an_error(self):
        self.dispatch_and_start(self.digest)
        complete = {"child_name": CLEANUP_CHILD, "phase": "live-cleanup-target"}
        self.receipt("helper-complete", self.child, EPHEMERAL, "0" * 64, complete)
        self.child.unlink()
        result = self.collect()
        self.assertEqual(len(result["errors"]), 1, result)
        self.assertIn("digest mismatch", result["errors"][0]["error"])


class OwnedInstalledObservationContracts(unittest.TestCase):
    """Actions source controls; never label a synthetic record native evidence.

    Actual compiled selector/installed qualification runs in final_public_mcp,
    with raw commands and no mocked launcher/doctor/platform path responses.
    """

    def setUp(self):
        self.assertEqual(
            os.environ.get("GITHUB_ACTIONS"), "true", "Actions-only control"
        )
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.owner = public_observer.OwnedObservationEnvironment(self.root)
        retained = os.environ.get("BYO_FINAL_CHILD_EVIDENCE")
        self.evidence = (
            Path(retained) / self._testMethodName
            if retained
            else self.root / "evidence"
        )
        self.evidence.mkdir(parents=True)

    def retain(self, name, value):
        (self.evidence / name).write_text(
            json.dumps(
                {"evidence_kind": "SOURCE_CONTROL_ONLY", "detail": value}, indent=2
            )
            + "\n",
            encoding="utf-8",
        )

    def test_supported_forwarding_matches_actual_launcher_and_uses_owned_inputs(self):
        source = Path(__file__).resolve().parents[2] / "launcher/src/main.rs"
        raw = source.read_text(encoding="utf-8")
        block = raw.split("const SIDECAR_ENVIRONMENT:", 1)[1].split("];", 1)[0]
        actual = tuple(re.findall(r'"([A-Za-z_]+)"', block))
        self.assertEqual(public_observer.SIDECAR_ENVIRONMENT, actual)
        environment = self.owner.forwarded_environment()
        for unsupported in (
            "BYO_HOME",
            "BYO_MCP_MONITOR_ROOT",
            "BYO_MCP_ARTIFACT_ROOT",
            "XDG_DATA_HOME",
            "PYTHONPATH",
        ):
            self.assertNotIn(unsupported, environment)
        self.assertEqual(environment["BYO_SIDECAR_COMPILED"], "1")
        for name in (
            "HOME",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "PROGRAMDATA",
            "TMPDIR",
            "TEMP",
            "TMP",
        ):
            self.assertTrue(self.owner.owned_path(environment[name]).is_dir())
        self.retain(
            "supported-inputs.json",
            {
                "launcher_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "forwarded_environment": environment,
            },
        )
        # Fresh real interpreter observes forwarding's actual platformdirs
        # selector only. It cannot resolve/open/write a monitor or user store.
        # Its result is source-level dependency evidence, not compiled evidence.
        child = subprocess.run(
            [
                sys.executable,
                "-B",
                "-c",
                "import json;from platformdirs import user_data_dir;"
                "print(json.dumps({'app_data':user_data_dir('BYO',appauthor=False,roaming=False)}))",
            ],
            env=environment,
            cwd=self.owner.project,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
            check=False,
        )
        self.retain(
            "source-platform-selector.json",
            {
                "argv": child.args,
                "exit": child.returncode,
                "stdout": child.stdout,
                "stderr": child.stderr,
            },
        )
        self.assertEqual(child.returncode, 0, child.stderr)
        candidate = json.loads(child.stdout)["app_data"]
        if os.name == "nt":
            # Windows shell APIs may ignore supplied profile variables.
            # Observing an outside path is a correct refusal, never a pass
            # for installed isolation. Inspect the path, never its contents.
            if not Path(candidate).resolve().is_relative_to(self.owner.root):
                with self.assertRaisesRegex(RuntimeError, "outside owned"):
                    self.owner.owned_path(candidate)
        else:
            self.owner.owned_path(candidate)
        with self.assertRaisesRegex(RuntimeError, "not qualified"):
            self.owner.require_qualified()

    def test_outside_unknown_and_alias_routes_refused_without_qualification_or_store_io(
        self,
    ):
        # Deliberately synthetic record to exercise admission, never qualification.
        record = {
            "schema": "fr16-read-only-paths/v1",
            "store_resolver_called": False,
            "denied_io": [],
            "monitor_override": None,
            "local_env_absent": True,
            "dotenv_candidates": [str(self.root / ".env")],
            "platform": sys.platform,
            "platformdirs_version": "source-control",
            "pid": os.getpid(),
            "creation_time": 1.0,
            "project": str(self.owner.project),
            "runtime": str(self.root),
            "cwd": str(self.root),
            "runs": str(self.owner.project / ".firm/runs"),
            "operator": str(self.owner.project / ".byo-monitor"),
        }
        outside = self.root / "outside-unopened-store"
        for candidate in (None, "relative", str(outside)):
            with self.subTest(candidate=candidate):
                with self.assertRaises(RuntimeError):
                    self.owner.check_candidates(
                        {**record, "app_data": candidate}, self.root
                    )
                self.assertFalse(outside.exists())
                self.assertIsNone(self.owner.qualification)
        if os.name != "nt":
            alias = self.owner.root / "alias"
            alias.symlink_to(self.root, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "outside owned"):
                self.owner.owned_path(str(alias / "outside-unopened-store"))
        self.retain(
            "refusals.json",
            {
                "unknown_relative_outside_refused": True,
                "outside_store_created": outside.exists(),
                "native_isolation": "UNRUN",
            },
        )

    def test_ordinary_sequence_waits_and_refuses_overlap_without_retry(self):
        marker = self.owner.root / "ordinary-writer"
        argv = [
            sys.executable,
            "-B",
            "-c",
            "import sys;from pathlib import Path;p=Path(sys.argv[1]);"
            "f=p.open('x');f.write(sys.argv[2]);f.close();p.unlink()",
            str(marker),
        ]
        results = []
        # These are real finite control children, not product/status/doctor mocks.
        for label in ("status-control", "doctor-control", "init-control"):
            with self.owner.ordinary(label):
                with self.assertRaisesRegex(RuntimeError, "already active"):
                    with self.owner.ordinary("unintended-overlap"):
                        self.fail("overlapping ordinary body ran")
                child = subprocess.run(
                    [*argv, label],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                results.append(
                    {
                        "argv": child.args,
                        "exit": child.returncode,
                        "stdout": child.stdout,
                        "stderr": child.stderr,
                    }
                )
                self.assertEqual(child.returncode, 0, child.stderr)
            self.assertFalse(marker.exists())
        events = self.owner.events
        self.assertEqual(
            [row["name"] for row in events],
            ["status-control", "doctor-control", "init-control"],
        )
        for before, after in zip(events, events[1:]):
            self.assertLessEqual(
                before["completed_monotonic"], after["started_monotonic"]
            )
        self.retain("ordinary-sequence.json", {"events": events, "commands": results})
        with self.assertRaisesRegex(RuntimeError, "not qualified"):
            self.owner.require_qualified()


if __name__ == "__main__":
    unittest.main()
