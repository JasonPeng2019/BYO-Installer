#!/usr/bin/env python3
"""Behavior controls for test_code_analysis_portable_smoke.py.

These are platform-neutral unit/contract controls of the smoke's own logic
(argument handling, platform mapping, process identity, quoting, ELF checks,
fixture binding and the MCP client). When run on Windows they are
Windows-host controls; they are NOT native macOS/Linux product evidence.
Each RED control mutates exactly one input and must be rejected.

Run: python release/scripts/test_code_analysis_portable_smoke_controls.py -v
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_code_analysis_portable_smoke as smoke  # noqa: E402

SCRIPT = Path(smoke.__file__).resolve()
HOST = "windows-host" if os.name == "nt" else "posix-host"

FAKE_SERVER = r"""
import json, sys
mode = sys.argv[1]
for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    method = message["method"]
    if method == "initialize":
        result = {"serverInfo": {"name": "fake", "version": "9.9.9"}}
    elif method == "tools/list":
        schema = {"type": "object", "properties": {}, "additionalProperties": False}
        if mode == "board":
            schema = {"type": "object", "properties": {"board_id": {}},
                      "additionalProperties": False}
        result = {"tools": [{"name": n, "inputSchema": schema} for n in sys.argv[2:]]}
    else:
        text = json.dumps({"status": "ok", "tool": message["params"]["name"]})
        if mode == "nonjson":
            text = "prefix " + text
        content = [{"type": "text", "text": text}]
        if mode == "monitor":
            content.append({"type": "text", "text": "monitoring prompt"})
        result = {"content": content}
    if mode == "notify":
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/message",
                                     "params": {}}) + "\n")
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": message["id"],
                                 "result": result}) + "\n")
    sys.stdout.flush()
"""

SPAWNER = r"""
import subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(%s)" % sys.argv[1]])
time.sleep(float(sys.argv[2]))
"""


def run_script(*args: str, timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True,
                          text=True, encoding="utf-8", timeout=timeout)


class Temp(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="portable-smoke-controls-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)


class CommandLine(Temp):
    def required(self, scratch: Path, **overrides) -> list[str]:
        values = {"--platform": smoke.host_platform() or "linux-x86_64",
                  "--bundle": str(self.dir / "no-bundle"), "--scratch": str(scratch),
                  "--arm-gxx": str(self.dir / "no-g++"), "--artifact-label": "control"}
        values.update(overrides)
        return [x for k, v in values.items() if v is not None for x in (k, v)]

    def test_help_documents_inputs_and_exits(self):
        result = run_script("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        for word in ("--platform", "--bundle", "--scratch", "--arm-gxx", "--rustc",
                     "--python-workspace", "--artifact-label", "macos-aarch64",
                     "linux-x86_64", "PENDING", "never earns PASS"):
            self.assertIn(word, result.stdout)

    def test_missing_required_argument_is_usage_error(self):
        result = run_script(*self.required(self.dir / "s", **{"--arm-gxx": None}))
        self.assertEqual(result.returncode, 2)
        self.assertIn("--arm-gxx", result.stderr)

    def test_missing_bundle_is_setup_failure_with_evidence(self):
        scratch = self.dir / "fresh"
        result = run_script(*self.required(scratch))
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        report = json.loads((scratch / "evidence/report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["gates"]["preflight"]["status"], "SETUP_FAILURE")
        self.assertIn("bundle prerequisite missing", report["gates"]["preflight"]["reason"])
        self.assertEqual(report["gates"]["install"]["status"], "PENDING")
        summary = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertEqual(summary["status"], "SETUP_FAILURE")
        manifest = json.loads((scratch / "evidence/manifest.json").read_text(encoding="utf-8"))
        self.assertIn("report.json", manifest["files"])

    def test_platform_mismatch_is_setup_failure(self):
        other = next(t for t in smoke.PLATFORMS if t != smoke.host_platform())
        scratch = self.dir / "mismatch"
        result = run_script(*self.required(scratch, **{"--platform": other}))
        self.assertEqual(result.returncode, 2)
        report = json.loads((scratch / "evidence/report.json").read_text(encoding="utf-8"))
        self.assertIn("run natively", report["gates"]["preflight"]["reason"])

    def test_existing_scratch_is_refused_untouched(self):
        scratch = self.dir / "existing"
        scratch.mkdir()
        (scratch / "keep.txt").write_text("keep", encoding="utf-8")
        result = run_script(*self.required(scratch))
        self.assertEqual(result.returncode, 2)
        self.assertIn("must be NEW", result.stdout)
        self.assertEqual(sorted(p.name for p in scratch.iterdir()), ["keep.txt"])

    def test_unknown_platform_rejected(self):
        result = run_script(*self.required(self.dir / "s", **{"--platform": "linux-arm64"}))
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid choice", result.stderr)


class PlatformTable(unittest.TestCase):
    def test_executable_names(self):
        self.assertEqual(smoke.exe_name("windows-x86_64", "byo"), "byo.exe")
        for tag in ("macos-aarch64", "macos-x86_64", "linux-x86_64"):
            self.assertEqual(smoke.exe_name(tag, "byo"), "byo")

    def test_manifest_platform_strings(self):
        self.assertEqual(smoke.PLATFORMS["macos-aarch64"][2:4], ("macos", "aarch64"))
        self.assertEqual(smoke.PLATFORMS["linux-x86_64"][2:4], ("linux", "x86_64"))

    def test_host_detection(self):
        cases = {("Darwin", "arm64"): "macos-aarch64", ("Darwin", "x86_64"): "macos-x86_64",
                 ("Linux", "x86_64"): "linux-x86_64", ("Windows", "AMD64"): "windows-x86_64",
                 ("Linux", "aarch64"): None}
        for (system, machine), tag in cases.items():
            with mock.patch.object(smoke.platform, "system", return_value=system), \
                 mock.patch.object(smoke.platform, "machine", return_value=machine):
                self.assertEqual(smoke.host_platform(), tag, (system, machine))

    def test_posix_environment_is_isolated(self):
        with tempfile.TemporaryDirectory() as raw:
            lab = Path(raw)
            env = smoke.isolated_environment("linux-x86_64", lab / "home", lab, [])
            self.assertEqual(env["PATH"].split(os.pathsep)[0], str(lab / "home" / "bin"))
            self.assertTrue(env["HOME"].startswith(str(lab)))
            self.assertTrue(env["TMPDIR"].startswith(str(lab)))
            self.assertNotIn("USERPROFILE", env)


class Pure(unittest.TestCase):
    def test_include_search_parser(self):
        text = ("ignoring nonexistent directory\n#include \"...\" search starts here:\n"
                "#include <...> search starts here:\n /opt/arm/lib/gcc/arm-none-eabi/14/include\n"
                " /opt/arm/lib/gcc/arm-none-eabi/14/include-fixed\n /opt/arm/arm-none-eabi/include\n"
                " /System/Library/Frameworks (framework directory)\nEnd of search list.\n /late\n")
        self.assertEqual(smoke.parse_include_search(text), [
            os.path.normpath("/opt/arm/lib/gcc/arm-none-eabi/14/include"),
            os.path.normpath("/opt/arm/lib/gcc/arm-none-eabi/14/include-fixed"),
            os.path.normpath("/opt/arm/arm-none-eabi/include")])
        self.assertEqual(smoke.parse_include_search("no list\n"), [])

    def test_elf_checker(self):
        header = bytearray(64)
        header[:6] = b"\x7fELF\x01\x01"
        header[16:18] = (1).to_bytes(2, "little")
        header[18:20] = (40).to_bytes(2, "little")
        self.assertTrue(smoke.elf_arm_relocatable(bytes(header)))
        for offset, value in ((4, 2), (5, 2), (16, 2), (18, 62), (0, 0)):
            mutated = bytearray(header)
            mutated[offset] = value
            self.assertFalse(smoke.elf_arm_relocatable(bytes(mutated)), offset)
        self.assertFalse(smoke.elf_arm_relocatable(b"MZ" + bytes(62)))

    def test_shell_override_round_trip(self):
        argv = [["/opt/arm gnu/bin/arm-none-eabi-g++", "-I", "/p/it's $HOME", "-c",
                 "src/a b.c", "-o", "build/a.o"]]
        script = smoke.posix_override_script(argv)
        self.assertTrue(script.startswith("#!/bin/sh\n"))
        self.assertEqual(shlex.split(script.splitlines()[-1]), argv[0])

    def test_windows_override_encoding(self):
        argv = [["C:/a b/g++.exe", "-c", "src/main.c"], ["x", "y"]]
        text = smoke.windows_override_commands(argv)
        self.assertEqual([line.split("\x1f") for line in text.splitlines()], argv)
        with self.assertRaises(smoke.Setup):
            smoke.windows_override_commands([["bad\nfield"]])

    def test_fixture_binding_green_and_red(self):
        originals = json.loads(smoke.ARM_ORIGINALS.read_text(encoding="utf-8"))
        bound = smoke.check_fixture_binding(originals)
        self.assertEqual(set(bound), set(smoke.ARM_FIXTURE))
        with mock.patch.dict(smoke.ARM_FIXTURE, {"src/main.c": smoke.ARM_FIXTURE["src/main.c"] + " "}):
            with self.assertRaises(smoke.Setup):
                smoke.check_fixture_binding(originals)
        missing = {"files": {k: v for k, v in originals["files"].items() if k != "src/startup.c"}}
        with self.assertRaises(smoke.Setup):
            smoke.check_fixture_binding(missing)

    def test_defect_and_semantic_line_positions(self):
        header = smoke.SEMANTIC["include/symbols.hpp"].splitlines()
        self.assertTrue(header[1].startswith("int choose(int"))
        self.assertTrue(header[3].startswith("template<class T> T twice"))
        self.assertIn("int *p = 0", smoke.DEFECT.decode())


class FakePs:
    """psutil-shaped fake for unobservable/reused-PID branches."""

    class NoSuchProcess(Exception):
        pass

    class AccessDenied(Exception):
        pass

    class ZombieProcess(NoSuchProcess):
        pass

    class TimeoutExpired(Exception):
        pass

    STATUS_ZOMBIE = "zombie"

    def __init__(self, behaviour):
        self.behaviour = behaviour
        self.killed = []

    def Process(self, pid):  # noqa: N802 - psutil API shape
        fake = self
        mode = self.behaviour

        class P:
            def create_time(self):
                if mode == "denied":
                    raise fake.AccessDenied()
                if mode == "gone":
                    raise fake.NoSuchProcess()
                return 200.0 if mode == "reused" else 100.0

            def status(self):
                return "zombie" if mode == "zombie" else "running"

            def kill(self):
                fake.killed.append(pid)

        return P()


class Identity(unittest.TestCase):
    def test_unknown_reused_zombie_and_gone(self):
        identity = {"pid": 7, "create_time": 100.0}
        self.assertIsNone(smoke.Processes(FakePs("denied")).alive(identity))
        self.assertIs(smoke.Processes(FakePs("reused")).alive(identity), False)
        self.assertIs(smoke.Processes(FakePs("gone")).alive(identity), False)
        self.assertIs(smoke.Processes(FakePs("zombie")).alive(identity), False)
        self.assertIs(smoke.Processes(FakePs("live")).alive(identity), True)

    def test_terminate_refuses_other_incarnation_and_unknown(self):
        identity = {"pid": 7, "create_time": 100.0}
        reused = FakePs("reused")
        self.assertTrue(smoke.Processes(reused).terminate_exact(identity))
        self.assertEqual(reused.killed, [])
        denied = FakePs("denied")
        self.assertIsNone(smoke.Processes(denied).terminate_exact(identity))
        self.assertEqual(denied.killed, [])


@unittest.skipIf(not hasattr(smoke, "Processes"), "smoke import failed")
class RealProcesses(Temp):
    def setUp(self):
        super().setUp()
        try:
            self.native = smoke.Processes()
        except ImportError:
            self.skipTest("psutil unavailable: real-process controls UNVERIFIED")
        self.evidence = smoke.Evidence(self.dir / "evidence", self.native)
        self.env = {**os.environ, "PYTHONUTF8": "1"}

    def test_natural_exit_proves_child_identity_and_preserves_peer(self):
        peer = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        self.addCleanup(peer.wait, 10)
        self.addCleanup(peer.kill)
        peer_identity = self.native.identity(peer.pid)
        result = self.evidence.run("tree", [sys.executable, "-c", SPAWNER, "0.6", "1.0"],
                                   self.env, self.dir, timeout=30)
        children = [p for p in result.observed_processes if p["pid"] != result.observed_processes[0]["pid"]]
        self.assertTrue(children, "child identity was not sampled")
        self.assertTrue(all(p["alive_after"] is False for p in result.observed_processes))
        self.assertNotIn(peer.pid, {p["pid"] for p in result.observed_processes})
        self.assertIs(self.native.alive(peer_identity), True)
        self.assertEqual(self.evidence.emergency, [])

    def test_surviving_child_is_red_and_cleanup_is_recorded(self):
        with self.assertRaises(smoke.Red) as caught:
            self.evidence.run("orphan", [sys.executable, "-c", SPAWNER, "60", "0.8"],
                              self.env, self.dir, timeout=30, settle=0.5)
        self.assertIn("survived", str(caught.exception))
        self.assertEqual(len(self.evidence.emergency), 1)
        self.assertIs(self.evidence.emergency[0]["confirmed"], True)

    def test_timeout_and_exit_mismatch(self):
        with self.assertRaises(smoke.Setup):
            self.evidence.run("slow", [sys.executable, "-c", "import time; time.sleep(30)"],
                              self.env, self.dir, timeout=0.5, setup=True)
        self.assertTrue(self.evidence.emergency)
        with self.assertRaises(smoke.Red) as caught:
            self.evidence.run("exit3", [sys.executable, "-c", "raise SystemExit(3)"],
                              self.env, self.dir)
        self.assertIn("exit 3, expected 0", str(caught.exception))
        record = json.loads(next((self.dir / "evidence/commands").glob("*-exit3/command.json"))
                            .read_text(encoding="utf-8"))
        self.assertEqual(record["exit"], 3)

    def test_unobserved_leader_never_earns_product_credit(self):
        quick = [sys.executable, "-c", "pass"]
        with mock.patch.object(self.native, "identity", return_value=None):
            with self.assertRaisesRegex(smoke.Unverified, "before identity observation"):
                self.evidence.run("product-quick", quick, self.env, self.dir)
            result = self.evidence.run("setup-quick", quick, self.env, self.dir, setup=True)
        record = json.loads((result.evidence / "command.json").read_text(encoding="utf-8"))
        self.assertEqual(record["unobserved_leader"], {"pid": record["unobserved_leader"]["pid"]})
        self.assertIsInstance(record["unobserved_leader"]["pid"], int)
        self.assertEqual(record["processes"], [])

    def mcp(self, mode: str, tools=smoke.TOOLS) -> smoke.Mcp:
        server = self.dir / "fake_server.py"
        server.write_text(FAKE_SERVER, encoding="utf-8")
        client = smoke.Mcp(self.evidence, [sys.executable, str(server), mode, *tools],
                           self.env, self.dir, f"{mode}-{time.monotonic_ns()}",
                           request_timeout=20)
        self.addCleanup(lambda: client.closed or client.close())
        return client

    def test_mcp_green_with_notification_and_monitoring_block(self):
        for mode in ("ok", "notify", "monitor"):
            client = self.mcp(mode)
            client.initialize("9.9.9")
            value = client.tool("get_code_hover", {})
            self.assertEqual(value["tool"], "get_code_hover")
            record = client.close()
            self.assertEqual(record["exit"], 0)
            self.assertFalse(record["eof_timeout"])
            self.assertTrue(all(p["alive_after"] is False for p in record["processes"]))
        self.assertEqual(client.results[-1]["monitoring_blocks"], ["monitoring prompt"])

    def test_mcp_red_cases(self):
        client = self.mcp("nonjson")
        client.initialize("9.9.9")
        with self.assertRaisesRegex(smoke.Red, "not intact JSON"):
            client.tool("get_code_hover", {})
        client.close()
        with self.assertRaisesRegex(smoke.Red, "needs a board"):
            self.mcp("board").initialize("9.9.9")
        with self.assertRaisesRegex(smoke.Red, "omitted find_code_references"):
            self.mcp("ok", tools=[t for t in smoke.TOOLS if t != "find_code_references"]
                     ).initialize("9.9.9")
        with self.assertRaisesRegex(smoke.Red, "serverInfo version"):
            self.mcp("ok").initialize("0.1.8")


class SourceShape(unittest.TestCase):
    """Guards for portability claims in the delivered script bytes."""

    def test_no_windows_only_apis(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for forbidden in ("ctypes", "OpenProcess", "Get-CimInstance", "taskkill", "/IM "):
            self.assertNotIn(forbidden, text)

    def test_stdout_summary_is_ascii_and_evidence_utf8(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("ensure_ascii=True", text)
        self.assertIn('encoding="utf-8"', text)

    def test_script_identity(self):
        digest = hashlib.sha256(SCRIPT.read_bytes()).hexdigest()
        print(f"\n[{HOST}] portable smoke sha256 {digest}", file=sys.stderr)


if __name__ == "__main__":
    unittest.main()
