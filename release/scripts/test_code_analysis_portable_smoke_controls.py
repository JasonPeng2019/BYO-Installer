#!/usr/bin/env python3
"""Behavior controls for test_code_analysis_portable_smoke.py.

These are platform-neutral unit/contract controls of the smoke's own logic
(argument handling, platform mapping, archive binding, managed companion driver,
PATH/loader poisoning, process identity, quoting, ELF checks, fixture binding and
the MCP client) plus test_installed_e2e.py's exact-target resource leak allowance. When run on Windows they are
Windows-host controls; they are NOT native macOS/Linux product evidence.
Each RED control mutates exactly one input and must be rejected.

Run: python release/scripts/test_code_analysis_portable_smoke_controls.py -v
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_code_analysis_portable_smoke as smoke  # noqa: E402
import test_installed_e2e as e2e  # noqa: E402

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
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
    )


class Temp(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="portable-smoke-controls-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)


class CommandLine(Temp):
    CORE = (
        "--expected-target",
        "--bundle",
        "--archive",
        "--evidence",
        "--workspace-source",
        "--arm-gxx",
        "--arm-gxx-sha256",
        "--artifact-label",
    )

    def required(self, scratch: Path, **overrides) -> list[str]:
        values = {
            "--expected-target": smoke.host_platform() or "linux-x86_64",
            "--bundle": str(self.dir / "no-bundle"),
            "--archive": str(self.dir / "no-bundle.zip"),
            "--evidence": str(scratch),
            "--workspace-source": str(self.dir / "no-workspace"),
            "--arm-gxx": str(self.dir / "no-g++"),
            "--arm-gxx-sha256": "0" * 64,
            "--artifact-label": "control",
        }
        values.update(overrides)
        return [x for k, v in values.items() if v is not None for x in (k, v)]

    def test_help_documents_inputs_and_exits(self):
        result = run_script("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        for word in (
            *self.CORE,
            "--platform",
            "--scratch",
            "--python-workspace",
            "--rustc",
            "--arm-gcc",
            "macos-aarch64",
            "linux-x86_64-glibc-2.28",
            "PENDING",
            "never earns PASS",
            "run_cppcheck",
            "TrustedRuntimeContext",
            "not complete OS",
        ):
            self.assertIn(word, result.stdout)

    def test_each_missing_core_argument_is_named_usage_error(self):
        for flag in self.CORE:
            scratch = self.dir / f"missing{flag}"
            result = run_script(*self.required(scratch, **{flag: None}))
            self.assertEqual(result.returncode, 2, flag)
            self.assertIn(flag, result.stderr)
            self.assertFalse(scratch.exists(), flag)

    def test_aliases_share_canonical_destinations(self):
        canonical = smoke.parser().parse_args(self.required(self.dir / "c"))
        aliased = self.required(self.dir / "c")
        for old, new in (
            ("--platform", "--expected-target"),
            ("--scratch", "--evidence"),
            ("--python-workspace", "--workspace-source"),
        ):
            aliased[aliased.index(new)] = old
        self.assertEqual(vars(smoke.parser().parse_args(aliased)), vars(canonical))

    def test_missing_bundle_is_setup_failure_with_evidence(self):
        scratch = self.dir / "fresh"
        result = run_script(*self.required(scratch))
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        report = json.loads(
            (scratch / "evidence/report.json").read_text(encoding="utf-8")
        )
        self.assertEqual(report["gates"]["preflight"]["status"], "SETUP_FAILURE")
        self.assertIn(
            "bundle prerequisite missing", report["gates"]["preflight"]["reason"]
        )
        for gate in ("archive-binding", "install", "managed-companion-verify"):
            self.assertEqual(report["gates"][gate]["status"], "PENDING")
        summary = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertEqual(summary["status"], "SETUP_FAILURE")
        self.assertIn("not complete OS", summary["scope"])
        manifest = json.loads(
            (scratch / "evidence/manifest.json").read_text(encoding="utf-8")
        )
        self.assertIn("report.json", manifest["files"])

    def test_platform_mismatch_is_setup_failure(self):
        other = next(t for t in smoke.PLATFORMS if t != smoke.host_platform())
        scratch = self.dir / "mismatch"
        result = run_script(*self.required(scratch, **{"--expected-target": other}))
        self.assertEqual(result.returncode, 2)
        report = json.loads(
            (scratch / "evidence/report.json").read_text(encoding="utf-8")
        )
        self.assertIn("run natively", report["gates"]["preflight"]["reason"])

    def test_glibc_alias_normalizes_to_canonical_target(self):
        if smoke.host_platform() == "linux-x86_64":
            self.skipTest("alias mismatch control needs a non-Linux host")
        scratch = self.dir / "glibc"
        result = run_script(
            *self.required(scratch, **{"--expected-target": "linux-x86_64-glibc-2.28"})
        )
        self.assertEqual(result.returncode, 2)
        report = json.loads(
            (scratch / "evidence/report.json").read_text(encoding="utf-8")
        )
        self.assertEqual(report["expected_target"], "linux-x86_64")
        self.assertIn(
            "--expected-target linux-x86_64 but", report["gates"]["preflight"]["reason"]
        )

    def test_existing_scratch_is_refused_untouched(self):
        scratch = self.dir / "existing"
        scratch.mkdir()
        (scratch / "keep.txt").write_text("keep", encoding="utf-8")
        result = run_script(*self.required(scratch))
        self.assertEqual(result.returncode, 2)
        self.assertIn("must be NEW", result.stdout)
        self.assertEqual(sorted(p.name for p in scratch.iterdir()), ["keep.txt"])

    def test_unknown_platform_rejected(self):
        result = run_script(
            *self.required(self.dir / "s", **{"--expected-target": "linux-arm64"})
        )
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
        cases = {
            ("Darwin", "arm64"): "macos-aarch64",
            ("Darwin", "x86_64"): "macos-x86_64",
            ("Linux", "x86_64"): "linux-x86_64",
            ("Windows", "AMD64"): "windows-x86_64",
            ("Linux", "aarch64"): None,
        }
        for (system, machine), tag in cases.items():
            with (
                mock.patch.object(smoke.platform, "system", return_value=system),
                mock.patch.object(smoke.platform, "machine", return_value=machine),
            ):
                self.assertEqual(smoke.host_platform(), tag, (system, machine))

    def test_posix_environment_is_isolated(self):
        with tempfile.TemporaryDirectory() as raw:
            lab = Path(raw)
            env = smoke.isolated_environment("linux-x86_64", lab / "home", lab, [])
            self.assertEqual(
                env["PATH"].split(os.pathsep)[0], str(lab / "home" / "bin")
            )
            self.assertTrue(env["HOME"].startswith(str(lab)))
            self.assertTrue(env["TMPDIR"].startswith(str(lab)))
            self.assertNotIn("USERPROFILE", env)


class Pure(unittest.TestCase):
    def test_include_search_parser(self):
        text = (
            'ignoring nonexistent directory\n#include "..." search starts here:\n'
            "#include <...> search starts here:\n /opt/arm/lib/gcc/arm-none-eabi/14/include\n"
            " /opt/arm/lib/gcc/arm-none-eabi/14/include-fixed\n /opt/arm/arm-none-eabi/include\n"
            " /System/Library/Frameworks (framework directory)\nEnd of search list.\n /late\n"
        )
        self.assertEqual(
            smoke.parse_include_search(text),
            [
                os.path.normpath("/opt/arm/lib/gcc/arm-none-eabi/14/include"),
                os.path.normpath("/opt/arm/lib/gcc/arm-none-eabi/14/include-fixed"),
                os.path.normpath("/opt/arm/arm-none-eabi/include"),
            ],
        )
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
        argv = [
            [
                "/opt/arm gnu/bin/arm-none-eabi-g++",
                "-I",
                "/p/it's $HOME",
                "-c",
                "src/a b.c",
                "-o",
                "build/a.o",
            ]
        ]
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
        with mock.patch.dict(
            smoke.ARM_FIXTURE, {"src/main.c": smoke.ARM_FIXTURE["src/main.c"] + " "}
        ):
            with self.assertRaises(smoke.Setup):
                smoke.check_fixture_binding(originals)
        missing = {
            "files": {
                k: v for k, v in originals["files"].items() if k != "src/startup.c"
            }
        }
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
        result = self.evidence.run(
            "tree",
            [sys.executable, "-c", SPAWNER, "0.6", "1.0"],
            self.env,
            self.dir,
            timeout=30,
        )
        children = [
            p
            for p in result.observed_processes
            if p["pid"] != result.observed_processes[0]["pid"]
        ]
        self.assertTrue(children, "child identity was not sampled")
        self.assertTrue(
            all(p["alive_after"] is False for p in result.observed_processes)
        )
        self.assertNotIn(peer.pid, {p["pid"] for p in result.observed_processes})
        self.assertIs(self.native.alive(peer_identity), True)
        self.assertEqual(self.evidence.emergency, [])

    def test_surviving_child_is_red_and_cleanup_is_recorded(self):
        with self.assertRaises(smoke.Red) as caught:
            self.evidence.run(
                "orphan",
                [sys.executable, "-c", SPAWNER, "60", "0.8"],
                self.env,
                self.dir,
                timeout=30,
                settle=0.5,
            )
        self.assertIn("survived", str(caught.exception))
        # A Windows venv python.exe is a redirector that spawns the base
        # interpreter, so one orphan may be two owned processes.
        emergency = self.evidence.emergency
        self.assertIn(len(emergency), (1, 2))
        self.assertTrue(all(entry["confirmed"] is True for entry in emergency))
        self.assertTrue(
            all(
                "time.sleep(60)" in " ".join(entry["identity"]["argv"])
                for entry in emergency
            )
        )

    def test_timeout_and_exit_mismatch(self):
        with self.assertRaises(smoke.Setup):
            self.evidence.run(
                "slow",
                [sys.executable, "-c", "import time; time.sleep(30)"],
                self.env,
                self.dir,
                timeout=0.5,
                setup=True,
            )
        self.assertTrue(self.evidence.emergency)
        with self.assertRaises(smoke.Red) as caught:
            self.evidence.run(
                "exit3",
                [sys.executable, "-c", "raise SystemExit(3)"],
                self.env,
                self.dir,
            )
        self.assertIn("exit 3, expected 0", str(caught.exception))
        record = json.loads(
            next(
                (self.dir / "evidence/commands").glob("*-exit3/command.json")
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(record["exit"], 3)

    def test_unobserved_leader_never_earns_product_credit(self):
        quick = [sys.executable, "-c", "pass"]
        with mock.patch.object(self.native, "identity", return_value=None):
            with self.assertRaisesRegex(
                smoke.Unverified, "before identity observation"
            ):
                self.evidence.run("product-quick", quick, self.env, self.dir)
            result = self.evidence.run(
                "setup-quick", quick, self.env, self.dir, setup=True
            )
        record = json.loads(
            (result.evidence / "command.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            record["unobserved_leader"], {"pid": record["unobserved_leader"]["pid"]}
        )
        self.assertIsInstance(record["unobserved_leader"]["pid"], int)
        self.assertEqual(record["processes"], [])

    def mcp(self, mode: str, tools=smoke.TOOLS) -> smoke.Mcp:
        server = self.dir / "fake_server.py"
        server.write_text(FAKE_SERVER, encoding="utf-8")
        client = smoke.Mcp(
            self.evidence,
            [sys.executable, str(server), mode, *tools],
            self.env,
            self.dir,
            f"{mode}-{time.monotonic_ns()}",
            request_timeout=20,
        )
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
            self.mcp(
                "ok", tools=[t for t in smoke.TOOLS if t != "find_code_references"]
            ).initialize("9.9.9")
        with self.assertRaisesRegex(smoke.Red, "serverInfo version"):
            self.mcp("ok").initialize("0.1.8")


def stub_smoke(**attributes) -> smoke.Smoke:
    instance = smoke.Smoke.__new__(smoke.Smoke)
    instance.report = {}
    for key, value in attributes.items():
        setattr(instance, key, value)
    return instance


class ArchiveBinding(Temp):
    """Archive bytes/modes/inventory must equal the expanded bundle before install."""

    def make(
        self,
        target: str,
        *,
        archive_mode: int = 0o755,
        archived=None,
        extra=None,
        symlink: bool = False,
        name: str | None = None,
    ):
        bundle = self.dir / "byo-0.1.8-control"
        leaves = {"byo": b"launcher bytes", "analysis/runtime.json": b"{}\n"}
        for relative, data in leaves.items():
            (bundle / relative).parent.mkdir(parents=True, exist_ok=True)
            (bundle / relative).write_bytes(data)
        system, arch = smoke.PLATFORMS[target][2:4]
        manifest = {
            "platform": system,
            "architecture": arch,
            "files": [
                {
                    "path": r,
                    "executable": r == "byo",
                    "sha256": hashlib.sha256(d).hexdigest(),
                    "size": len(d),
                }
                for r, d in leaves.items()
            ],
        }
        (bundle / "release-manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        contents = {
            **{r: (bundle / r).read_bytes() for r in smoke.tree_record(bundle)},
            **(archived or {}),
            **(extra or {}),
        }
        kind = "tar.gz" if system == "linux" else "zip"
        archive = self.dir / (name or f"{bundle.name}.{kind}")
        if kind == "zip":
            with zipfile.ZipFile(archive, "w") as handle:
                for relative, data in contents.items():
                    info = zipfile.ZipInfo(f"{bundle.name}/{relative}")
                    mode = archive_mode if relative == "byo" else 0o644
                    info.external_attr = (stat.S_IFREG | mode) << 16
                    handle.writestr(info, data)
        else:
            with tarfile.open(archive, "w:gz") as handle:
                for relative, data in contents.items():
                    info = tarfile.TarInfo(f"{bundle.name}/{relative}")
                    info.size = len(data)
                    info.mode = archive_mode if relative == "byo" else 0o644
                    handle.addfile(info, io.BytesIO(data))
                if symlink:
                    info = tarfile.TarInfo(f"{bundle.name}/link")
                    info.type, info.linkname = tarfile.SYMTYPE, "byo"
                    handle.addfile(info)
        args = SimpleNamespace(platform=target, archive=archive, archive_sha256=None)
        return stub_smoke(
            args=args,
            bundle=bundle,
            manifest=manifest,
            bundle_before=smoke.tree_record(bundle),
        )

    def bind(self, binder):
        with mock.patch.object(
            smoke, "executable_bit", lambda path: path.name == "byo"
        ):
            return binder.archive_binding()

    def reset(self):
        shutil.rmtree(self.dir)
        self.dir.mkdir()

    def test_green_zip_and_tar(self):
        for target in ("macos-aarch64", "linux-x86_64"):
            with self.subTest(target=target):
                binder = self.make(target)
                detail = self.bind(binder)
                self.assertEqual(
                    (detail["leaves"], detail["posix_modes_checked"]), (3, 3)
                )
                self.assertEqual(binder.report["archive"]["sha256"], detail["sha256"])
                self.reset()

    def test_archive_digest_name_and_presence_are_setup(self):
        binder = self.make("macos-aarch64")
        binder.args.archive_sha256 = "0" * 64
        with self.assertRaisesRegex(smoke.Setup, "--archive-sha256"):
            self.bind(binder)
        binder.args.archive_sha256 = None
        binder.args.archive = self.dir / "absent.zip"
        with self.assertRaisesRegex(smoke.Setup, "missing"):
            self.bind(binder)
        self.reset()
        with self.assertRaisesRegex(smoke.Setup, "must be"):
            self.bind(self.make("macos-aarch64", name="other.zip"))

    def test_byte_inventory_mode_and_entry_type_mutations_are_red(self):
        cases = (
            ({"archived": {"byo": b"tampered launcher"}}, "bytes differ"),
            ({"extra": {"stray.txt": b"x"}}, "inventories differ"),
            ({"archive_mode": 0o644}, "executable mode"),
            ({"extra": {"../escape": b"x"}}, "outside the bundle root|static archive"),
        )
        for options, message in cases:
            with self.subTest(options=options):
                with self.assertRaisesRegex(smoke.Red, message):
                    self.bind(self.make("macos-aarch64", **options))
                self.reset()
        with self.assertRaisesRegex(smoke.Red, "static archive|not a regular"):
            self.bind(self.make("linux-x86_64", symlink=True))


COMPANION_STUB = """
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class TrustedRuntimeContext:
    runtime_root: Path
    runtime_manifest_sha256: str
    managed: bool = True


def run_cppcheck(project_root, target=".", *, runtime_context=None):
    status = (Path(project_root) / "status.txt").read_text(encoding="utf-8")
    return {"status": status, "call": [
        type(project_root).__name__, str(project_root), target,
        str(runtime_context.runtime_root), runtime_context.runtime_manifest_sha256,
        runtime_context.managed]}
"""


class Companion(Temp):
    def setUp(self):
        super().setUp()
        self.ws = self.dir / "workspace"
        (self.ws / "internal").mkdir(parents=True)
        (self.ws / "internal/__init__.py").write_text("", encoding="utf-8")
        (self.ws / "internal/code_analysis.py").write_text(
            COMPANION_STUB, encoding="utf-8"
        )
        self.decoy = self.dir / "decoy"
        (self.decoy / "internal").mkdir(parents=True)
        (self.decoy / "internal/__init__.py").write_text(
            "raise SystemExit('decoy')\n", encoding="utf-8"
        )
        self.driver = self.dir / "driver.py"
        self.driver.write_text(smoke.COMPANION_DRIVER, encoding="utf-8")
        self.project = self.dir / "project µ"
        self.project.mkdir()

    def test_driver_calls_managed_source_api_in_isolation(self):
        env = {**os.environ, "PYTHONPATH": str(self.decoy)}
        for status, code in (("pass", 0), ("findings_failed", 1), ("blocked", 2)):
            (self.project / "status.txt").write_text(status, encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(self.driver),
                    str(self.ws),
                    str(self.dir / "runtime"),
                    "ab" * 32,
                    str(self.project),
                    ".",
                ],
                cwd=self.decoy,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=60,
            )
            self.assertEqual(result.returncode, code, result.stderr)
            value = json.loads(result.stdout)
            self.assertTrue(
                smoke.same_path(value["module"], self.ws / "internal/code_analysis.py")
            )
            self.assertEqual(
                value["result"]["call"],
                [
                    "WindowsPath" if os.name == "nt" else "PosixPath",
                    str(self.project),
                    ".",
                    str(self.dir / "runtime"),
                    "ab" * 32,
                    True,
                ],
            )

    def result_checker(self):
        cppcheck = self.dir / "cppcheck.exe"
        cppcheck.write_bytes(b"installed cppcheck")
        report = self.dir / "reports/one"
        report.mkdir(parents=True)
        checker = stub_smoke(workspace=self.ws, cppcheck=cppcheck)
        entry = {
            "source_report": str(report),
            "status": "pass",
            "executable_origin": "managed_runtime",
        }
        result = {
            "status": "pass",
            "executable_origin": "managed_runtime",
            "report_directory": str(report),
            "executable": str(cppcheck),
            "executable_sha256": smoke.sha256(cppcheck),
            "runtime_manifest_sha256": "ab" * 32,
        }
        return checker, entry, result

    def outcome(self, result: dict, module: Path | None = None):
        module = module or self.ws / "internal/code_analysis.py"
        return SimpleNamespace(
            stdout="noise\n"
            + json.dumps({"module": str(module), "result": result})
            + "\n"
        )

    def test_returned_result_must_match_retained_managed_report(self):
        checker, entry, result = self.result_checker()
        returned = checker.companion_result("c", self.outcome(result), entry)
        self.assertEqual(returned["status"], "pass")
        mutations = (
            ({"executable_origin": "path"}, None, "executable_origin"),
            ({"status": "findings_failed"}, None, "status"),
            ({"report_directory": str(self.dir)}, None, "report directory"),
            ({"executable_sha256": "0" * 64}, None, "mapped installed"),
            ({}, self.decoy / "internal/code_analysis.py", "not the workspace"),
        )
        for change, module, message in mutations:
            with self.subTest(change=change, module=module):
                with self.assertRaisesRegex(smoke.Red, message):
                    checker.companion_result(
                        "c", self.outcome({**result, **change}, module), entry
                    )
        with self.assertRaisesRegex(smoke.Red, "single JSON"):
            checker.companion_result("c", SimpleNamespace(stdout="Traceback\n"), entry)


class Poison(Temp):
    def test_fake_analyzers_shadow_path_and_loader_search(self):
        for tag in ("windows-x86_64", "linux-x86_64"):
            base = {"PATH": str(self.dir / "bin"), "BYO_HOME": "h"}
            poison = self.dir / f"poison-{tag}"
            env = smoke.poisoned_environment(tag, base, poison)
            self.assertEqual(env["PATH"].split(os.pathsep)[0], str(poison))
            for name in smoke.LOADER_VARIABLES:
                self.assertEqual(env[name], str(poison))
            self.assertNotIn("LD_PRELOAD", env)
            self.assertNotIn("DYLD_INSERT_LIBRARIES", env)
            self.assertEqual(base["PATH"], str(self.dir / "bin"))
            for stem in ("cppcheck", "clangd"):
                data = (poison / smoke.exe_name(tag, stem)).read_bytes()
                if tag.startswith("windows"):
                    self.assertFalse(data.startswith(b"MZ"))
                else:
                    self.assertIn(b"fake-analyzer-ran.txt", data)
                    self.assertIn(b"exit 97", data)
            if tag == smoke.host_platform():
                found = shutil.which("cppcheck", path=env["PATH"])
                self.assertTrue(found and smoke.same_path(Path(found).parent, poison))

    @unittest.skipIf(os.name == "nt", "POSIX fake execution needs /bin/sh")
    def test_posix_fake_records_marker(self):
        poison = self.dir / "poison"
        smoke.poisoned_environment("linux-x86_64", {"PATH": "/usr/bin:/bin"}, poison)
        result = subprocess.run([str(poison / "cppcheck")], check=False)
        self.assertEqual(result.returncode, 97)
        self.assertTrue((poison / "fake-analyzer-ran.txt").is_file())


class InstalledE2eResourceAllowance(Temp):
    """The lifecycle gate's leak guard allows only exact-target locked resources."""

    HEADER = "analysis/clangd/lib/clang/23/include/stddef.h"

    def setUp(self):
        super().setUp()
        self.bundle = self.dir / "bundle"
        self.data = b"/* locked resource */\n"
        for relative in (self.HEADER, "src/evil.h"):
            (self.bundle / relative).parent.mkdir(parents=True, exist_ok=True)
            (self.bundle / relative).write_bytes(self.data)
        digest = hashlib.sha256(self.data).hexdigest()
        self.leaf = {
            "executable": False,
            "kind": "analysis-resource",
            "sha256": digest,
            "size": len(self.data),
            "runtime_path": self.HEADER,
            "upstream_path": "lib/clang/23/include/stddef.h",
        }
        self.manifest = {
            "platform": "linux",
            "architecture": "x86_64",
            "files": [
                {
                    "path": self.HEADER,
                    "kind": "analysis-resource",
                    "executable": False,
                    "sha256": digest,
                    "size": len(self.data),
                }
            ],
        }

    def lock(self, record: dict, version: int = 2) -> Path:
        path = self.dir / f"lock-{time.monotonic_ns()}.json"
        value = (
            {"schema_version": 2, "targets": {"linux-x86_64": record}}
            if version == 2
            else {"schema_version": 1, **record}
        )
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def record(self, **leaf) -> dict:
        return {
            "platform": "linux",
            "architecture": "x86_64",
            "programs": {"clangd": {"selected_files": [{**self.leaf, **leaf}]}},
        }

    def unexpected(self, lock: Path, leaked=None, manifest=None) -> list[str]:
        return e2e.unexpected_development_files(
            self.bundle,
            manifest or self.manifest,
            [self.HEADER, "src/evil.h"] if leaked is None else leaked,
            lock,
        )

    def test_locked_header_allowed_arbitrary_header_rejected(self):
        self.assertEqual(self.unexpected(self.lock(self.record())), ["src/evil.h"])
        self.assertEqual(self.unexpected(self.lock(self.record()), [self.HEADER]), [])
        self.assertEqual(self.unexpected(self.dir / "absent.json", []), [])

    def test_hash_kind_and_classification_mutations_are_rejected(self):
        leaked = [self.HEADER]
        self.assertEqual(
            self.unexpected(self.lock(self.record(sha256="0" * 64)), leaked), leaked
        )
        self.assertEqual(
            self.unexpected(self.lock(self.record(kind="license")), leaked), leaked
        )
        manifest = json.loads(json.dumps(self.manifest))
        manifest["files"][0]["kind"] = "analysis-data"
        self.assertEqual(
            self.unexpected(self.lock(self.record()), leaked, manifest), leaked
        )
        (self.bundle / self.HEADER).write_bytes(self.data.upper())
        self.assertEqual(self.unexpected(self.lock(self.record()), leaked), leaked)

    def test_missing_exact_target_lock_is_producer_dependency(self):
        windows_only = self.lock({**self.record(), "platform": "windows"}, version=1)
        with self.assertRaisesRegex(e2e.AcceptanceFailure, "producer dependency"):
            self.unexpected(windows_only)
        other_target = self.lock({**self.record(), "architecture": "aarch64"})
        with self.assertRaisesRegex(e2e.AcceptanceFailure, "producer dependency"):
            self.unexpected(other_target)

    def test_current_repository_lock_is_windows_only_seam(self):
        windows = {"platform": "windows", "architecture": "x86_64"}
        resources = e2e.locked_analysis_resources(windows)
        self.assertTrue(resources)
        self.assertTrue(
            all(p.startswith("analysis/clangd/lib/clang/") for p in resources)
        )
        with self.assertRaisesRegex(e2e.AcceptanceFailure, "producer dependency"):
            e2e.locked_analysis_resources(self.manifest)
        print(
            f"\n[{HOST}] repository lock: {len(resources)} Windows resource leaves; "
            "no native macOS/Linux target record (producer dependency)",
            file=sys.stderr,
        )


class SourceShape(unittest.TestCase):
    """Guards for portability claims in the delivered script bytes."""

    def test_no_windows_only_apis(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for forbidden in (
            "ctypes",
            "OpenProcess",
            "Get-CimInstance",
            "taskkill",
            "/IM ",
        ):
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
