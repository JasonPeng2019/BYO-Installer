"""Fresh-interpreter controls for the actual cross-component release ledger.

Small selected bodies measure the observer's accounting, not product acceptance.
The driver and its sibling dependency are copied from the real source checkout.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import final_acceptance_checks as command_observer


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
        self.assertEqual(os.environ.get("GITHUB_ACTIONS"), "true", "Actions-only control")
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
            Path(retained) / self._testMethodName if retained else self.root / "evidence"
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
            start["ledger_source"], str(self.tests / "final_acceptance_suite.py")
        )
        self.assertEqual(
            start["ledger_sha256"],
            hashlib.sha256((self.tests / "final_acceptance_suite.py").read_bytes()).hexdigest(),
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
        self.assertEqual([e["id"] for e in events if e["kind"] == "stop"], suite["loaded"])
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
            [e["parent"] for e in events if e["kind"] == "subtest"], [selected, selected]
        )

    def test_standalone_script_does_not_invent_declared_method_execution(self):
        self.script.write_text(
            'import os\nfrom pathlib import Path\n'
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
        self.assertEqual(result["evidence_gaps"], ["No actual unittest runner invocation"])

    def test_zero_exit_without_promised_unittest_runner_is_nonpass(self):
        self.script.write_text("raise SystemExit(0)\n", encoding="utf-8")
        completed, result = self.invoke("--script", str(self.script))
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(result["exit"], 0)
        self.assertEqual(result["suites"], [])
        self.assertEqual(result["evidence_gaps"], ["No actual unittest runner invocation"])


COMMAND_DESCENDANT_PROBE = r'''
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
'''


class CapturedCommandDescendantContracts(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.environ.get("GITHUB_ACTIONS"), "true", "Actions-only controls")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        shutil.copyfile(Path(command_observer.__file__), self.root / "final_acceptance_checks.py")
        self.script = self.root / "command_probe.py"
        self.script.write_text(COMMAND_DESCENDANT_PROBE, encoding="utf-8")
        retained = os.environ.get("BYO_FINAL_CHILD_EVIDENCE")
        self.evidence = Path(retained) / self._testMethodName if retained else self.root / "evidence"
        self.evidence.mkdir(parents=True)
        self.addCleanup(self.emergency_fixture_cleanup)

    def emergency_fixture_cleanup(self):
        import psutil

        actions = []
        for name in ("child-ready.json", "parent-ready.json"):
            for path in self.evidence.glob("*/" + name):
                try:
                    data = json.loads(path.read_bytes())
                    facts = data["identity"] if isinstance(data.get("identity"), dict) else data
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
        self.assertFalse(actions, "fixture emergency intervention is a failed control: " + repr(actions))

    def invoke(self, mode, timeout=15):
        directory = self.evidence / mode
        directory.mkdir()
        command = [sys.executable, "-B", str(self.script), mode, str(directory)]
        with (directory / "stdout.log").open("wb") as out, (directory / "stderr.log").open("wb") as err:
            code, timed_out, cleanup, gaps = command_observer.run_finite(
                command, self.root, out, err, timeout
            )
        record = {"command": command, "cwd": str(self.root), "exit": code,
                  "timed_out": timed_out, "cleanup": cleanup, "gaps": gaps}
        (directory / "result.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        self.assertFalse([gap for gap in gaps if not gap.get("terminal_race")], record)
        ready = json.loads((directory / "child-ready.json").read_bytes())
        exact = [row for row in cleanup if row["pid"] == ready["pid"]
                 and row["creation_time"] == ready["creation_time"]]
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

    def test_normal_child_exit_retains_exact_attribution_and_nonzero_command_then_continues(self):
        for mode, expected in (("failure", 7), ("pass", 0)):
            with self.subTest(mode=mode):
                directory, code, timed_out, row, cleanup = self.invoke(mode)
                self.assertEqual(code, expected)
                self.assertFalse(timed_out)
                self.assertEqual((directory / "child-finished.json").read_text(encoding="utf-8"),
                                 "normal child exit")
                self.assertTrue(row["normal_wait_completed"])
                self.assertTrue(row["natural_terminal"])
                self.assertFalse(row["survived_command"])
                self.assertIsNone(row["intervention"])
                self.assertTrue(all(item["cleanup"] == "gone" for item in cleanup))
                self.assertTrue(all(item["natural_terminal"] for item in cleanup))

    def test_helper_shaped_leak_retains_zero_exit_failed_judgment_and_emergency_facts(self):
        directory, code, timed_out, row, cleanup = self.invoke("leak")
        self.assertEqual(code, 0)
        self.assertFalse(timed_out)
        self.assertFalse((directory / "child-finished.json").exists())
        self.assertTrue(row["survived_command"])
        self.assertEqual(row["final_state"], "live")
        self.assertFalse(row["natural_terminal"])
        self.assertIn("multiprocessing.resource_tracker", row["first_capture"]["identity"]["cmdline"])
        self.assertEqual(row["intervention"]["kind"], "post-command-emergency-kill")
        self.assertLessEqual(row["judgment_monotonic"], row["intervention"]["at_monotonic"])
        self.assertEqual(command_observer.command_state(row["intervention"]["before"]), "live")
        self.assertTrue(all(command_observer.command_state(item["after_cleanup"]) in ("gone", "terminal")
                            for item in cleanup))
        # This is the release command's actual final aggregate condition.
        self.assertTrue(any(item["survived_command"] or item["cleanup"] != "gone" for item in cleanup))

    def test_timeout_preserves_intervention_and_never_claims_normal_finalization(self):
        _, code, timed_out, row, cleanup = self.invoke("timeout", timeout=2)
        self.assertNotEqual(code, 0)
        self.assertTrue(timed_out)
        self.assertFalse(row["normal_wait_completed"])
        self.assertFalse(row["natural_terminal"])
        self.assertEqual(row["timeout_intervention"]["kind"], "timeout-command.kill")
        self.assertTrue(all(command_observer.command_state(item["after_cleanup"]) in ("gone", "terminal")
                            for item in cleanup))

    def test_identity_queries_cannot_reap_signal_or_accept_reuse_as_absence(self):
        identity = command_observer.command_identity(os.getpid())
        with (
            mock.patch("psutil.Process.wait", side_effect=AssertionError("observer wait")),
            mock.patch("psutil.Process.kill", side_effect=AssertionError("observer kill")),
            mock.patch("psutil.Process.terminate", side_effect=AssertionError("observer terminate")),
            mock.patch("os.waitpid", create=True, side_effect=AssertionError("observer reap")),
        ):
            exact = command_observer.command_identity(os.getpid(), identity["creation_time"])
            reused = command_observer.command_identity(os.getpid(), identity["creation_time"] + 1)
            owned, gaps = {}, []
            command_observer.capture_command_descendants(os.getpid(), identity["creation_time"], owned, gaps)
        record = {"exact": exact, "reused": reused, "captured": list(owned.values()), "gaps": gaps}
        (self.evidence / "identities.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
        self.assertEqual(command_observer.command_state(exact), "live")
        self.assertEqual(command_observer.command_state(reused), "unknown")
        self.assertEqual(command_observer.command_state({"identity": "unavailable"}), "unknown")
        self.assertEqual(command_observer.command_state({"identity": "missing"}), "unknown")
        self.assertEqual(command_observer.command_state({"identity": "same_birth", "status": "running"}), "unknown")
        self.assertFalse(gaps, record)



if __name__ == "__main__":
    unittest.main()
