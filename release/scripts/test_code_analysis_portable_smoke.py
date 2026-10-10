#!/usr/bin/env python3
"""Portable native installed core smoke for Cppcheck verification and clangd MCP tools.

Run this ON the native host directly after a native BYO build. Targets:
windows-x86_64, macos-aarch64, macos-x86_64, linux-x86_64 (alias
linux-x86_64-glibc-2.28). The target must match the host and the bundle's
release-manifest.json platform/architecture; it is a claim this script checks,
never one it assumes. Nothing is downloaded, built into the product or installed
outside the caller-owned evidence directory.

Required inputs (all explicit; a missing/invalid one exits 2 before any launch):

  --expected-target TAG   expected native target (alias --platform)
  --bundle DIR            expanded native release bundle (contains byo[.exe] and
                          release-manifest.json); read-only, rechecked at the end
  --archive FILE          the release archive the bundle was expanded from (ZIP;
                          tar.gz for Linux). Its bytes are hashed, statically
                          validated, and every leaf/mode is proved equal to
                          --bundle BEFORE the public `byo install-runtime --bundle`
  --evidence DIR          NEW caller-owned directory (alias --scratch); holds the
                          private BYO_HOME, projects, profile/temp dirs, evidence/
  --workspace-source DIR  clean accepted agent-workspace checkout (alias
                          --python-workspace). The companion is the direct SOURCE
                          API internal.code_analysis.run_cppcheck with a managed
                          TrustedRuntimeContext bound to the installed manifest,
                          in an isolated `python -I` child. It is not a shipped
                          Python CLI; PATH origin never earns credit.
  --arm-gxx PATH          real arm-none-eabi-g++ executable (GNU Arm Embedded)
  --arm-gxx-sha256 HEX    independent digest the compiler bytes must match
  --artifact-label TEXT   recorded verbatim (e.g. existing-windows-artifact,
                          candidate-<commit>)

Optional: --arm-gcc PATH (defaults to the arm-none-eabi-gcc sibling).
Windows requires --rustc PATH (the actual compiler with its bundled rust-lld).
(Windows setup input: compiles the native build override; POSIX uses /bin/sh),
--archive-sha256 HEX (independent archive digest), --install-timeout SECONDS.

Host prerequisites: Python >= 3.12 with psutil (server/build dependency set);
git on PATH (workspace provenance); POSIX: /bin/sh; Windows: rustc whose bundled
rust-lld links the override (MSVC link.exe is avoided: it leaves a VCTIP.EXE child).

Core gates (public commands except the companion SOURCE API): archive binding,
`byo install-runtime --bundle`, `byo init --project`, Rust `byo workflow tool
verify --project P .` with a real build override that compiles the three-unit
ARM fixture with the configured compiler (ELF32 ARM objects checked) and then
Cppcheck clean/defect/restored (exit 0/13/0), the managed companion on the same
installed runtime and project (pass/findings_failed/pass, origin managed_runtime,
mapped executable and digest), then `byo mcp serve --project P` over stdio: all
five tools, saved-file defect/restore freshness, live clangd query-driver via
psutil, an unaffected same-image peer, natural stdin EOF exit 0 and proved exit
of every exact owned (PID, create_time) identity. Product commands run with
fake cppcheck/clangd first on PATH and library search variables pointed at the
poison directory. Unknown or unavailable observation never earns PASS.

A scoped PASS covers only the named target, the supplied bundle and these core
checks. It is not complete OS, all-profile or all-behavior acceptance: native
matrix, corruption, timeout/cancellation, update/uninstall, resource, missing-data
and no-board/tier/profile cases are separate gates.

Exit: 0 all core gates PASS; 1 product RED; 2 setup failure/missing prerequisite
or unverifiable observation; 3 a gate is PENDING. Evidence: <evidence>/evidence/
report.json (sorted-key UTF-8 JSON), commands/NNN-*/{command.json,stdout.log,
stderr.log}, mcp-*/ transcripts and manifest.json (SHA256 of every file).

Example (macOS Apple silicon, after a native build):

  python3 release/scripts/test_code_analysis_portable_smoke.py \
    --bundle "$BUNDLE" --archive "$ARCHIVE" --expected-target macos-aarch64 \
    --workspace-source AgentWorkspace --evidence /tmp/byo-smoke-$(date +%s) \
    --arm-gxx /opt/arm-gnu/bin/arm-none-eabi-g++ --arm-gxx-sha256 <hex> \
    --artifact-label candidate-<sha>

A Windows-host run proves only the Windows bundle it was given. Helper controls
(test_code_analysis_portable_smoke_controls.py) are behavior tests of this
script, not native macOS/Linux evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import queue
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import threading
import time
import traceback
import zipfile
from pathlib import Path

SCHEMA = "portable-installed-code-analysis-smoke/v1"
ROOT = Path(__file__).resolve().parents[2]
ARM_ORIGINALS = ROOT / "launcher/tests/fixtures/cppcheck-acceptance/arm-originals.json"
TOOLS = (
    "get_code_analysis_status",
    "find_code_definition",
    "find_code_references",
    "get_code_hover",
    "get_code_diagnostics",
)
GATES = (
    "preflight",
    "archive-binding",
    "install",
    "rust-firmware-verify",
    "managed-companion-verify",
    "mcp-semantic",
    "mcp-natural-eof",
    "preservation",
)
# The public launcher maps a failed verify to its WorkflowPolicy exit category.
WORKFLOW_POLICY_EXIT = 13
PLATFORMS = {
    "windows-x86_64": ("Windows", {"amd64", "x86_64"}, "windows", "x86_64", ".exe"),
    "macos-aarch64": ("Darwin", {"arm64", "aarch64"}, "macos", "aarch64", ""),
    "macos-x86_64": ("Darwin", {"x86_64"}, "macos", "x86_64", ""),
    "linux-x86_64": ("Linux", {"x86_64", "amd64"}, "linux", "x86_64", ""),
}
TARGET_ALIASES = {"linux-x86_64-glibc-2.28": "linux-x86_64"}
LOADER_VARIABLES = (
    "LD_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
)
# Isolated `python -I` child: imports ONLY the verified workspace source tree and
# calls the managed SOURCE API. argv: workspace runtime_root manifest_sha project target.
COMPANION_DRIVER = """import json, sys
from pathlib import Path
workspace, runtime, digest, project, target = sys.argv[1:6]
sys.path.insert(0, workspace)
from internal import code_analysis
module = Path(code_analysis.__file__).resolve()
if not module.is_relative_to(Path(workspace).resolve()):
    raise SystemExit(f"imported {module} outside the workspace source")
context = code_analysis.TrustedRuntimeContext(
    runtime_root=Path(runtime), runtime_manifest_sha256=digest, managed=True)
result = code_analysis.run_cppcheck(Path(project), target, runtime_context=context)
print(json.dumps({"module": str(module), "result": result}, ensure_ascii=True))
raise SystemExit({"pass": 0, "findings_failed": 1}.get(result["status"], 2))
"""

# Authoritative ARM fixture bytes. Their SHA256/size must equal arm-originals.json.
ARM_FIXTURE = {
    "src/main.c": '#include "firmware.h"\nvolatile uint32_t firmware_heartbeat;\nvoid firmware_main(void) {\n    for (;;) { firmware_heartbeat = advance_heartbeat(firmware_heartbeat); }\n}\n',
    "src/heartbeat.cpp": '#include "firmware.h"\ntemplate<typename T> T increment(T value) { return value + T(HEARTBEAT_STEP); }\nuint32_t advance_heartbeat(uint32_t current) { return increment(current); }\n',
    "src/startup.c": '#include "firmware.h"\nextern uint32_t _stack_top, _data_load, _data_start, _data_end, _bss_start, _bss_end;\nvoid reset_handler(void);\nvoid default_handler(void) { for (;;) {} }\n__attribute__((used,section(".isr_vector")))\nconst uintptr_t vectors[] = { (uintptr_t)&_stack_top, (uintptr_t)reset_handler,\n    (uintptr_t)default_handler, (uintptr_t)default_handler };\nvoid reset_handler(void) {\n    uintptr_t source = (uintptr_t)&_data_load;\n    for (uintptr_t dest = (uintptr_t)&_data_start; dest < (uintptr_t)&_data_end; dest += sizeof(uint32_t)) {\n        *(uint32_t*)dest = *(const uint32_t*)source; source += sizeof(uint32_t);\n    }\n    for (uintptr_t dest = (uintptr_t)&_bss_start; dest < (uintptr_t)&_bss_end; dest += sizeof(uint32_t)) { *(uint32_t*)dest = 0; }\n    firmware_main();\n}\n',
    "include/firmware.h": '#ifndef FIRMWARE_H\n#define FIRMWARE_H\n#include <stdint.h>\n#include "build_config.h"\n#ifdef __cplusplus\nextern "C" {\n#endif\nextern volatile uint32_t firmware_heartbeat;\nuint32_t advance_heartbeat(uint32_t current);\nvoid firmware_main(void);\n#ifdef __cplusplus\n}\nstatic_assert(sizeof(void*) == 4 && sizeof(long) == 4, "ARM ILP32 ABI required");\n#else\n_Static_assert(sizeof(void*) == 4 && sizeof(long) == 4, "ARM ILP32 ABI required");\n#endif\n#endif\n',
    "config/arm32.xml": '<?xml version="1.0"?>\n<platform>\n  <char_bit>8</char_bit>\n  <default-sign>unsigned</default-sign>\n  <sizeof>\n    <bool>1</bool>\n    <short>2</short>\n    <int>4</int>\n    <long>4</long>\n    <long-long>8</long-long>\n    <float>4</float>\n    <double>8</double>\n    <long-double>8</long-double>\n    <pointer>4</pointer>\n    <size_t>4</size_t>\n    <wchar_t>4</wchar_t>\n  </sizeof>\n</platform>\n',
    "build/generated/build_config.h": "#define HEARTBEAT_STEP 3u\n",
}
# The recorded originals store these two files with CRLF line endings.
ARM_CRLF = frozenset({"config/arm32.xml", "build/generated/build_config.h"})
ARM_FLAGS = [
    "-mcpu=cortex-m4",
    "-mthumb",
    "-mfloat-abi=soft",
    "-ffreestanding",
    "-fdata-sections",
    "-ffunction-sections",
    "-g",
    "-O1",
    "-DBYO_TARGET_ARM=1",
]
ARM_UNITS = (
    ("src/main.c", "gcc", ["-std=c11"]),
    ("src/heartbeat.cpp", "gxx", ["-std=c++17", "-fno-exceptions", "-fno-rtti"]),
    ("src/startup.c", "gcc", ["-std=c11"]),
)
DEFECT = b"\nint installed_defect(void) { int *p = 0; return *p; }\n"

# Semantic fixture (overloads/template/cross-file, non-BMP before a CRLF query).
# newlib.h exists only in the ARM toolchain, so a clean result needs query-driver.
SEMANTIC = {
    "include/symbols.hpp": '#pragma once\nint choose(int value);\ndouble choose(double value);\ntemplate<class T> T twice(T value) { return value + value; }\nextern int shared;\n#include <newlib.h>\nstatic_assert(sizeof(void *) == 4 && sizeof(_NEWLIB_VERSION) > 1, "ARM32 newlib target");\n',
    "src/symbols.cpp": '#include "symbols.hpp"\nint choose(int value) { return value + 1; }\ndouble choose(double value) { return value + 0.5; }\nint shared = 7;\n',
    "src/main.cpp": '#include "symbols.hpp"\n/* \U0001f600 µ */ int use_int() { return choose(2) + twice(3) + shared; }\ndouble use_double() { return choose(2.0); }\n',
    "src/other.cpp": '#include "symbols.hpp"\nint use_other() { return shared; }\n',
}
USER_FILES = {
    ".clangd": "# User-owned clangd settings; preserve exactly.\n",
    ".clang-format": "BasedOnStyle: LLVM\n",
    "customer.txt": "unrelated user file µ\n",
}

WINDOWS_OVERRIDE_RS = r"""//! Smoke build override: runs the real ARM compiler argv listed in
//! build/override-commands.txt (fields separated by U+001F). No analyzer here.
use std::{env, fs, io::Write, process::Command};
fn main() {
    let target = env::args().nth(1).expect("verify target argv");
    let spec = fs::read_to_string("build/override-commands.txt").expect("commands");
    let mut log = fs::OpenOptions::new().create(true).append(true)
        .open("build/override-invocations.log").expect("log");
    writeln!(log, "{target}").expect("log write");
    for line in spec.lines().filter(|l| !l.is_empty()) {
        let argv: Vec<&str> = line.split('\u{1f}').collect();
        let status = Command::new(argv[0]).args(&argv[1..]).status().expect("spawn compiler");
        if !status.success() { std::process::exit(status.code().unwrap_or(1)); }
    }
}
"""


class Red(RuntimeError):
    """Product behavior contradicted the public contract."""


class Setup(RuntimeError):
    """Missing prerequisite or harness/setup fault; never product evidence."""


class Unverified(RuntimeError):
    """Required observation unavailable/unknown; never earns success."""


class Pending(RuntimeError):
    """Gate intentionally not exercised in this invocation."""


def require(condition: object, message: str) -> None:
    if not condition:
        raise Red(message)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def file_record(path: Path) -> dict:
    return {"path": str(path), "sha256": sha256(path), "size": path.stat().st_size}


def tree_record(root: Path) -> dict:
    return {
        p.relative_to(root).as_posix(): {"sha256": sha256(p), "size": p.stat().st_size}
        for p in sorted(root.rglob("*"))
        if p.is_file() and not p.is_symlink()
    }


def executable_bit(path: Path) -> bool:
    return bool(path.stat().st_mode & 0o111)


def archive_leaves(archive: Path, kind: str, bundle_name: str) -> dict:
    """Hash every regular leaf under bundle_name/; any other entry type is RED."""
    leaves, prefix = {}, bundle_name + "/"

    def add(name: str, data: bytes, mode: int) -> None:
        if not name.startswith(prefix) or name[len(prefix) :] in leaves:
            raise Red(f"archive leaf outside the bundle root or duplicated: {name!r}")
        leaves[name[len(prefix) :]] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "mode": mode,
        }

    if kind == "zip":
        with zipfile.ZipFile(archive) as handle:
            for member in handle.infolist():
                file_type = (member.external_attr >> 16) & 0o170000
                if member.is_dir():
                    continue
                if file_type not in (0, stat.S_IFREG):
                    raise Red(f"ZIP entry is not a regular file: {member.filename!r}")
                add(
                    member.filename,
                    handle.read(member),
                    (member.external_attr >> 16) & 0o7777,
                )
    else:
        with tarfile.open(archive, "r:gz") as handle:
            for member in handle.getmembers():
                if member.isdir():
                    continue
                if not member.isfile():
                    raise Red(f"tar entry is not a regular file: {member.name!r}")
                add(
                    member.name, handle.extractfile(member).read(), member.mode & 0o7777
                )
    return leaves


def dumps(value) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dumps(value), encoding="utf-8", newline="\n")


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def host_platform() -> str | None:
    system, machine = platform.system(), platform.machine().lower()
    for tag, (want_system, machines, *_rest) in PLATFORMS.items():
        if system == want_system and machine in machines:
            return tag
    return None


def exe_name(tag: str, stem: str) -> str:
    return stem + PLATFORMS[tag][4]


def same_path(left, right) -> bool:
    try:
        return Path(left).resolve() == Path(right).resolve() or os.path.samefile(
            left, right
        )
    except OSError:
        return False


def fixture_bytes(relative: str) -> bytes:
    text = ARM_FIXTURE[relative]
    if relative in ARM_CRLF:
        text = text.replace("\n", "\r\n")
    return text.encode("utf-8")


def check_fixture_binding(originals: dict) -> dict:
    """Bind every embedded fixture file to the authoritative recorded bytes."""
    checked = {}
    for relative in ARM_FIXTURE:
        data = fixture_bytes(relative)
        expected = originals["files"].get(relative)
        if expected is None:
            raise Setup(f"no authoritative record for fixture {relative}")
        actual = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        if actual != {"sha256": expected["sha256"], "size": expected["size"]}:
            raise Setup(f"embedded fixture {relative} differs from {ARM_ORIGINALS}")
        checked[relative] = actual
    return checked


def parse_include_search(stderr: str) -> list[str]:
    """Extract the compiler's own `#include <...>` search list from -v output."""
    lines, active, found = stderr.splitlines(), False, []
    for line in lines:
        if line.startswith("#include <...> search starts here"):
            active = True
            continue
        if line.startswith("End of search list"):
            break
        if active and line.startswith(" "):
            path = line.strip()
            if path.endswith("(framework directory)"):
                continue
            found.append(os.path.normpath(path))
    return found


def elf_arm_relocatable(data: bytes) -> bool:
    """ELF32, little-endian, ET_REL, EM_ARM (40)."""
    return (
        len(data) > 52
        and data[:4] == b"\x7fELF"
        and data[4] == 1
        and data[5] == 1
        and int.from_bytes(data[16:18], "little") == 1
        and int.from_bytes(data[18:20], "little") == 40
    )


def posix_override_script(commands: list[list[str]]) -> str:
    """A /bin/sh override executing explicit argv; every field shell-quoted."""
    lines = [
        "#!/bin/sh",
        "# Smoke build override: real ARM compiler argv only; no analyzer here.",
        "set -eu",
        'printf "%s\\n" "${1:-}" >> build/override-invocations.log',
    ]
    lines += [" ".join(shlex.quote(a) for a in argv) for argv in commands]
    return "\n".join(lines) + "\n"


def windows_override_commands(commands: list[list[str]]) -> str:
    for argv in commands:
        for field in argv:
            if "\x1f" in field or "\n" in field or "\r" in field:
                raise Setup(f"override argv field cannot be encoded: {field!r}")
    return "".join("\x1f".join(argv) + "\n" for argv in commands)


# ---------------------------------------------------------------- processes


class Processes:
    """Exact (pid, create_time) observation through psutil. None means unknown."""

    def __init__(self, psutil_module=None):
        if psutil_module is None:
            import psutil as psutil_module  # noqa: PLC0415 - explicit prerequisite
        self.ps = psutil_module

    def identity(self, pid: int) -> dict | None:
        ps = self.ps
        try:
            process = ps.Process(pid)
            with process.oneshot():
                created = process.create_time()
                record = {"pid": pid, "create_time": created}
                for key, call in (
                    ("ppid", process.ppid),
                    ("image", process.exe),
                    ("argv", process.cmdline),
                    ("status", process.status),
                ):
                    try:
                        record[key] = call()
                    except (ps.AccessDenied, ps.ZombieProcess, OSError):
                        record[key] = None
            return record
        except ps.NoSuchProcess:
            return None
        except ps.AccessDenied:
            return None

    def alive(self, identity: dict) -> bool | None:
        ps = self.ps
        try:
            process = ps.Process(identity["pid"])
            created = process.create_time()
        except ps.NoSuchProcess:
            return False
        except (ps.AccessDenied, OSError):
            return None
        if created != identity["create_time"]:
            return False  # The PID now names another incarnation.
        try:
            return process.status() != ps.STATUS_ZOMBIE
        except ps.NoSuchProcess:
            return False
        except (ps.AccessDenied, OSError):
            return None

    def children(self, identity: dict) -> list[dict]:
        ps = self.ps
        try:
            process = ps.Process(identity["pid"])
            if process.create_time() != identity["create_time"]:
                return []
            kids = process.children()
        except (ps.NoSuchProcess, ps.AccessDenied, OSError):
            return []
        found = []
        for kid in kids:
            record = self.identity(kid.pid)
            if record and record["create_time"] >= identity["create_time"]:
                record["parent_pid"] = identity["pid"]
                record["parent_create_time"] = identity["create_time"]
                found.append(record)
        return found

    def terminate_exact(self, identity: dict) -> bool | None:
        """Kill only the proved live exact identity; return proved-exit state."""
        if self.alive(identity) is not True:
            return self.alive(identity) is False or None
        try:
            process = self.ps.Process(identity["pid"])
            if process.create_time() != identity["create_time"]:
                return True
            process.kill()
            process.wait(5)
        except self.ps.NoSuchProcess:
            pass
        except (self.ps.AccessDenied, OSError, self.ps.TimeoutExpired):
            return None
        state = self.alive(identity)
        return None if state is None else not state


class Owned:
    """Sample a launched tree; only descendants of live recorded identities."""

    def __init__(self, process: subprocess.Popen, native: Processes):
        self.native = native
        root = native.identity(process.pid)
        # A leader that exits (or hides) before its identity is read leaves its
        # descendants unbindable; callers record that and never credit cleanup.
        self.unobserved_leader = None if root else {"pid": process.pid}
        self.records = {(root["pid"], root["create_time"]): root} if root else {}
        self.error = None
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.sample, daemon=True)
        self.thread.start()

    def sample_once(self) -> None:
        for _ in range(8):
            added = False
            for record in list(self.records.values()):
                if self.native.alive(record) is not True:
                    continue
                for child in self.native.children(record):
                    key = (child["pid"], child["create_time"])
                    if key not in self.records:
                        self.records[key] = child
                        added = True
            if not added:
                return

    def sample(self) -> None:
        try:
            while not self.stop.wait(0.005):
                self.sample_once()
        except Exception as exc:  # retained; finish() reports unverifiable
            self.error = exc

    def finish(self) -> list[dict]:
        self.stop.set()
        self.thread.join(timeout=5)
        if self.thread.is_alive() or self.error is not None:
            raise Unverified(f"process sampling failed: {self.error!r}")
        return [
            {**r, "alive_after": self.native.alive(r)} for r in self.records.values()
        ]


# ---------------------------------------------------------------- evidence


class Evidence:
    def __init__(self, root: Path, native: Processes):
        root.mkdir(parents=True)
        self.root, self.native, self.number = root, native, 0
        self.emergency: list[dict] = []

    def directory(self, name: str) -> Path:
        self.number += 1
        path = self.root / "commands" / f"{self.number:03d}-{name}"
        path.mkdir(parents=True)
        return path

    def cleanup(self, label: str, identities: list[dict]) -> None:
        for identity in identities:
            if identity.get("alive_after") is True:
                confirmed = self.native.terminate_exact(identity)
                identity["emergency_cleanup_confirmed"] = confirmed
                self.emergency.append(
                    {"command": label, "identity": identity, "confirmed": confirmed}
                )

    def run(
        self,
        name: str,
        argv: list[str],
        env: dict,
        cwd: Path,
        *,
        expected: int | None = 0,
        timeout: float = 180,
        setup: bool = False,
        settle: float = 5,
    ) -> subprocess.CompletedProcess:
        path = self.directory(name)
        record = {
            "argv": argv,
            "cwd": str(cwd),
            "setup_command": setup,
            "timeout_seconds": timeout,
            "environment": {
                k: env[k]
                for k in sorted(env)
                if k in ("PATH", "BYO_HOME", "HOME", "TMPDIR", "TEMP", "TMP")
                or k.startswith(("AGENT_WORKSPACE_", "XDG_", "LD_", "DYLD_"))
            },
        }
        write_json(path / "command.json", record)
        started = time.monotonic()
        with (
            (path / "stdout.log").open("wb") as out,
            (path / "stderr.log").open("wb") as err,
        ):
            try:
                process = subprocess.Popen(
                    argv,
                    cwd=cwd,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=out,
                    stderr=err,
                )
            except OSError as exc:
                record["spawn_error"] = repr(exc)
                write_json(path / "command.json", record)
                raise (Setup if setup else Red)(f"{name}: spawn failed: {exc!r}")
            owned = Owned(process, self.native)
            forced = False
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                forced = True
            try:
                identities = owned.finish()
            except Unverified as exc:
                record.update(
                    exit=process.returncode,
                    observation_failure=str(exc),
                    processes=[
                        {**r, "alive_after": None} for r in owned.records.values()
                    ],
                )
                write_json(path / "command.json", record)
                raise
            deadline = time.monotonic() + settle
            while (
                any(i["alive_after"] is not False for i in identities)
                and time.monotonic() < deadline
            ):
                time.sleep(0.05)
                for identity in identities:
                    identity["alive_after"] = self.native.alive(identity)
        record.update(
            exit=process.returncode,
            elapsed_seconds=round(time.monotonic() - started, 3),
            timeout=forced,
            processes=identities,
            unobserved_leader=owned.unobserved_leader,
        )
        write_json(path / "command.json", record)  # Failure facts before cleanup.
        self.cleanup(name, identities)
        if forced:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            record["exit"] = process.returncode
        write_json(path / "command.json", record)
        error = Setup if setup else Red
        if forced:
            raise error(f"{name}: deadline {timeout}s exceeded; {path}")
        if any(i["alive_after"] is True for i in identities):
            raise error(f"{name}: owned descendant survived exit; {path}")
        if any(i["alive_after"] is None for i in identities):
            raise Unverified(f"{name}: descendant exit unobservable; {path}")
        if owned.unobserved_leader and not setup:
            raise Unverified(
                f"{name}: leader exited before identity observation; "
                f"descendant cleanup unproved; {path}"
            )
        result = subprocess.CompletedProcess(
            argv,
            process.returncode,
            (path / "stdout.log").read_text(encoding="utf-8", errors="replace"),
            (path / "stderr.log").read_text(encoding="utf-8", errors="replace"),
        )
        result.observed_processes = identities
        result.evidence = path
        if expected is not None and process.returncode != expected:
            raise error(
                f"{name}: exit {process.returncode}, expected {expected}; {path}"
            )
        return result


# ---------------------------------------------------------------- MCP client


class Mcp:
    """Newline-delimited JSON-RPC over the public `byo mcp serve` stdio."""

    def __init__(
        self,
        evidence: Evidence,
        argv: list[str],
        env: dict,
        cwd: Path,
        label: str,
        *,
        request_timeout: float = 90,
    ):
        self.evidence = evidence
        self.path = evidence.root / f"mcp-{label}"
        self.path.mkdir(parents=True)
        self.argv, self.request_timeout = argv, request_timeout
        self.record = {"argv": argv, "cwd": str(cwd), "PATH": env.get("PATH")}
        write_json(self.path / "command.json", self.record)
        self.err = (self.path / "stderr.log").open("wb")
        self.out = (self.path / "stdout.jsonl").open("wb")
        self.sent = (self.path / "requests.jsonl").open("w", encoding="utf-8")
        self.process = subprocess.Popen(
            argv,
            env=env,
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.err,
        )
        self.owned = Owned(self.process, evidence.native)
        self.inbox: queue.Queue = queue.Queue()
        self.next_id, self.closed = 0, False
        self.results: list[dict] = []
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def read(self) -> None:
        try:
            for line in iter(self.process.stdout.readline, b""):
                self.out.write(line)
                self.out.flush()
                try:
                    self.inbox.put(json.loads(line))
                except (ValueError, UnicodeError) as exc:
                    self.inbox.put(Red(f"non-JSON MCP stdout line: {exc}"))
            self.inbox.put(Red("MCP stdout EOF before response"))
        except Exception as exc:
            self.inbox.put(Red(f"MCP stdout reader failed: {exc!r}"))

    def send(self, packet: dict) -> None:
        line = json.dumps(packet, ensure_ascii=False, separators=(",", ":")) + "\n"
        self.sent.write(line)
        self.sent.flush()
        self.process.stdin.write(line.encode("utf-8"))
        self.process.stdin.flush()

    def request(self, method: str, params: dict) -> dict:
        self.next_id += 1
        ident = self.next_id
        self.send({"jsonrpc": "2.0", "id": ident, "method": method, "params": params})
        deadline = time.monotonic() + self.request_timeout
        while True:
            try:
                item = self.inbox.get(timeout=max(0.001, deadline - time.monotonic()))
            except queue.Empty as exc:
                raise Red(f"MCP {method} exceeded {self.request_timeout}s") from exc
            if isinstance(item, Exception):
                raise item
            require(
                isinstance(item, dict) and item.get("jsonrpc") == "2.0",
                f"invalid JSON-RPC message: {item!r}",
            )
            if "id" not in item:
                continue  # Server notifications (logging/progress) are retained only.
            require(item["id"] == ident, f"unexpected reply id: {item!r}")
            require("error" not in item, f"MCP {method} protocol error: {item!r}")
            require(isinstance(item.get("result"), dict), f"MCP {method} lacks result")
            return item["result"]

    def initialize(self, version: str) -> list[dict]:
        result = self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "portable-installed-analysis-smoke",
                    "version": "1",
                },
            },
        )
        require(
            result.get("serverInfo", {}).get("version") == version,
            f"serverInfo version differs from bundle {version}: {result!r}",
        )
        self.send(
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
        )
        tools = self.request("tools/list", {})["tools"]
        write_json(self.path / "tools.json", tools)
        names = {t["name"]: t for t in tools}
        for name in TOOLS:
            require(name in names, f"tools/list omitted {name}")
            schema = names[name].get("inputSchema", {})
            require(
                "board_id" not in schema.get("properties", {}), f"{name} needs a board"
            )
            require(
                schema.get("additionalProperties") is False,
                f"{name} accepts unknown arguments",
            )
        return tools

    def tool(self, name: str, arguments: dict) -> dict:
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        require(not result.get("isError"), f"{name} tool error: {result!r}")
        texts = [
            b.get("text") for b in result.get("content", []) if b.get("type") == "text"
        ]
        require(texts, f"{name} returned no text block")
        try:
            value = json.loads(texts[0])
        except ValueError as exc:
            raise Red(f"{name}: first text block is not intact JSON") from exc
        require(isinstance(value, dict), f"{name}: result is not a JSON object")
        self.results.append(
            {
                "tool": name,
                "arguments": arguments,
                "result": value,
                "monitoring_blocks": texts[1:],
            }
        )
        return value

    def close(self, *, eof_timeout: float = 25) -> dict:
        """Natural stdin EOF; records failures BEFORE any emergency cleanup."""
        if self.closed:
            return self.record
        self.closed = True
        started = time.monotonic()
        try:
            self.process.stdin.close()
        except OSError:
            pass
        forced = False
        try:
            self.process.wait(timeout=eof_timeout)
        except subprocess.TimeoutExpired:
            forced = True
        try:
            identities = self.owned.finish()
        except Unverified as exc:
            identities = [
                {**r, "alive_after": None} for r in self.owned.records.values()
            ]
            self.record["observation_failure"] = str(exc)
        deadline = time.monotonic() + 5
        while (
            any(i["alive_after"] is not False for i in identities)
            and time.monotonic() < deadline
        ):
            time.sleep(0.05)
            for identity in identities:
                identity["alive_after"] = self.evidence.native.alive(identity)
        self.record.update(
            exit=self.process.returncode,
            eof_timeout=forced,
            unobserved_leader=self.owned.unobserved_leader,
            eof_seconds=round(time.monotonic() - started, 3),
            processes=identities,
        )
        write_json(self.path / "command.json", self.record)
        self.evidence.cleanup(f"mcp:{self.path.name}", identities)
        if forced:
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        self.reader.join(timeout=5)
        self.record["reader_stopped"] = not self.reader.is_alive()
        if self.record["reader_stopped"]:
            self.process.stdout.close()
        for stream in (self.err, self.sent, self.out):
            stream.close()
        write_json(self.path / "command.json", self.record)
        write_json(self.path / "results.json", self.results)
        return self.record


# ---------------------------------------------------------------- environment


def isolated_environment(
    tag: str, home: Path, lab: Path, extra_path: list[Path]
) -> dict:
    profile, temp = lab / "profile", lab / "temp"
    for path in (profile, temp):
        path.mkdir(parents=True, exist_ok=True)
    env = {
        "BYO_HOME": str(home),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    if tag.startswith("windows"):
        keep = {
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "PATHEXT",
            "NUMBER_OF_PROCESSORS",
            "PROCESSOR_ARCHITECTURE",
            "PROGRAMDATA",
        }
        env.update({k: v for k, v in os.environ.items() if k.upper() in keep})
        system = Path(os.environ["SystemRoot"])
        path = [home / "bin", system / "System32", system]
        env.update(
            USERPROFILE=str(profile),
            APPDATA=str(profile / "roaming"),
            LOCALAPPDATA=str(profile / "local"),
            TEMP=str(temp),
            TMP=str(temp),
        )
        for key in ("APPDATA", "LOCALAPPDATA"):
            Path(env[key]).mkdir(parents=True, exist_ok=True)
    else:
        path = [home / "bin", Path("/usr/bin"), Path("/bin")]
        env.update(
            HOME=str(profile),
            TMPDIR=str(temp),
            XDG_DATA_HOME=str(profile / "xdg-data"),
            XDG_CONFIG_HOME=str(profile / "xdg-config"),
            XDG_CACHE_HOME=str(profile / "xdg-cache"),
            XDG_STATE_HOME=str(profile / "xdg-state"),
            LANG=os.environ.get("LANG", "C.UTF-8"),
        )
    env["PATH"] = os.pathsep.join(str(p) for p in [*path, *extra_path])
    return env


def poisoned_environment(tag: str, env: dict, poison: Path) -> dict:
    """Put fake analyzers first on PATH and point library search at them.

    A fake that runs writes a marker (POSIX) or fails to load (Windows: not a PE),
    so PATH resolution can never pass silently. Preload-injection variables are not
    set: they would abort unrelated host tools (compiler, shell) independently of
    product resolution. On Windows the loader variables are inert by design.
    """
    poison.mkdir(parents=True)
    marker = poison / "fake-analyzer-ran.txt"
    for stem in ("cppcheck", "clangd"):
        if tag.startswith("windows"):
            (poison / f"{stem}.exe").write_bytes(b"not a PE image: PATH fallback\n")
        else:
            script = poison / stem
            script.write_text(
                f"#!/bin/sh\necho {stem} >> {shlex.quote(str(marker))}\nexit 97\n",
                encoding="utf-8",
                newline="\n",
            )
            script.chmod(0o755)
    poisoned = {**env, "PATH": os.pathsep.join((str(poison), env["PATH"]))}
    poisoned.update({name: str(poison) for name in LOADER_VARIABLES})
    return poisoned


# ---------------------------------------------------------------- gates


class Smoke:
    def __init__(self, args, report: dict):
        self.args, self.report = args, report
        self.gates = report["gates"]
        self.native: Processes | None = None
        self.evidence: Evidence | None = None

    # Each gate converts its exception class into one recorded status.
    def gate(self, name: str, action) -> bool:
        print(f"gate {name}", flush=True)
        try:
            detail = action()
            self.gates[name] = {
                "status": "PASS",
                **({"detail": detail} if detail else {}),
            }
            return True
        except Exception as exc:
            status = {
                Red: "RED",
                Setup: "SETUP_FAILURE",
                Unverified: "UNVERIFIED",
                Pending: "PENDING",
            }.get(type(exc))
            if status is None:
                # Malformed public fields are product RED; anything else is setup.
                status = (
                    "RED"
                    if isinstance(exc, (KeyError, TypeError, ValueError))
                    and name != "preflight"
                    else "SETUP_FAILURE"
                )
            self.gates[name] = {"status": status, "reason": str(exc) or repr(exc)}
            if status not in ("PENDING",):
                self.gates[name]["traceback"] = traceback.format_exc()
            print(
                f"  {status}: {str(exc)}".encode("ascii", "backslashreplace").decode(),
                flush=True,
            )
            return False

    def preflight(self):
        a, r = self.args, self.report
        if sys.version_info < (3, 12):
            raise Setup("Python >= 3.12 is required (the workspace source requires it)")
        if a.platform not in PLATFORMS:
            raise Setup(f"unknown --expected-target {a.platform}")
        host = host_platform()
        r["host"] = {
            "system": platform.system(),
            "machine": platform.machine(),
            "python": sys.version,
            "detected_tag": host,
        }
        if host != a.platform:
            raise Setup(
                f"--expected-target {a.platform} but this host is {host}; run natively"
            )
        try:
            self.native = Processes()
        except ImportError as exc:
            raise Setup(
                "psutil is required (pip install from the existing server deps)"
            ) from exc
        r["psutil_version"] = self.native.ps.__version__
        bundle = a.bundle.resolve()
        launcher = bundle / exe_name(a.platform, "byo")
        manifest_path = bundle / "release-manifest.json"
        for path in (launcher, manifest_path, bundle / "analysis/runtime.json"):
            if not path.is_file():
                raise Setup(f"bundle prerequisite missing: {path}")
        manifest = read_json(manifest_path)
        _, _, want_os, want_arch, _ = PLATFORMS[a.platform]
        if (manifest.get("platform"), manifest.get("architecture")) != (
            want_os,
            want_arch,
        ):
            raise Setup(
                f"bundle is {manifest.get('platform')}/{manifest.get('architecture')}, not {a.platform}"
            )
        gxx = a.arm_gxx.resolve()
        gcc = (a.arm_gcc or gxx.with_name(gxx.name.replace("g++", "gcc"))).resolve()
        for path in (gxx, gcc):
            if not path.is_file():
                raise Setup(f"ARM compiler missing: {path}")
        gxx_ref = file_record(gxx)
        if not re.fullmatch(r"[0-9a-fA-F]{64}", a.arm_gxx_sha256 or ""):
            raise Setup("--arm-gxx-sha256 must be a 64-hex trusted compiler digest")
        if gxx_ref["sha256"] != a.arm_gxx_sha256.lower():
            raise Setup("ARM g++ bytes differ from --arm-gxx-sha256")
        if a.platform.startswith("windows"):
            if not a.rustc or not a.rustc.is_file():
                raise Setup("Windows override requires an existing --rustc executable")
        elif not Path("/bin/sh").is_file():
            raise Setup("POSIX override requires /bin/sh")
        workspace = a.python_workspace.resolve()
        if not (workspace / "internal/code_analysis.py").is_file():
            raise Setup(
                f"--workspace-source lacks internal/code_analysis.py: {workspace}"
            )
        git = shutil.which("git")
        if git is None:
            raise Setup("git is required on the host PATH for workspace provenance")
        originals = read_json(ARM_ORIGINALS)
        r["fixture_binding"] = {
            "originals": file_record(ARM_ORIGINALS),
            "files": check_fixture_binding(originals),
        }
        r["bundle"] = {
            "root": str(bundle),
            "manifest": file_record(manifest_path),
            "version": manifest["version"],
            "source": manifest.get("source"),
            "launcher": file_record(launcher),
        }
        print("  hashing bundle inventory", flush=True)
        self.bundle_before = tree_record(bundle)
        r["bundle"]["file_count"] = len(self.bundle_before)
        self.compilers = {"gcc": gcc, "gxx": gxx}
        r["compilers"] = {"gcc": file_record(gcc), "gxx": gxx_ref}
        self.manifest, self.bundle, self.version = manifest, bundle, manifest["version"]
        lab = a.scratch / "lab"
        self.lab, self.home = lab, lab / "home"
        self.evidence = Evidence(a.scratch / "evidence" / "native", self.native)
        self.env = isolated_environment(a.platform, self.home, lab, [])
        r["path_shadowing"] = {
            n: shutil.which(n, path=self.env["PATH"]) for n in ("clangd", "cppcheck")
        }
        git_env = {
            **self.env,
            "PATH": os.pathsep.join((self.env["PATH"], str(Path(git).parent))),
        }
        head = self.evidence.run(
            "workspace-git-head",
            [git, "-C", str(workspace), "rev-parse", "HEAD"],
            git_env,
            lab,
            setup=True,
        ).stdout.strip()
        dirty = self.evidence.run(
            "workspace-git-status",
            [
                git,
                "-C",
                str(workspace),
                "status",
                "--porcelain",
                "--untracked-files=all",
            ],
            git_env,
            lab,
            setup=True,
        ).stdout
        if dirty.strip():
            raise Setup(f"--workspace-source is not a clean checkout: {dirty[:400]!r}")
        self.workspace = workspace
        r["workspace_source"] = {
            "root": str(workspace),
            "commit": head,
            "code_analysis": file_record(workspace / "internal/code_analysis.py"),
        }
        banner = self.evidence.run(
            "arm-gxx-version",
            [str(gxx), "--version"],
            self.env,
            lab,
            setup=True,
            timeout=60,
        )
        r["compilers"]["gxx_version"] = banner.stdout.splitlines()[:1]
        probe = lab / "include-probe.c"
        probe.write_bytes(b"int probe;\n")
        search = self.evidence.run(
            "arm-gcc-include-search",
            [
                str(gcc),
                *ARM_FLAGS[:3],
                "-E",
                "-v",
                "-x",
                "c",
                str(probe),
                "-o",
                os.devnull,
            ],
            self.env,
            lab,
            setup=True,
            timeout=60,
        )
        self.system_includes = [
            p
            for p in parse_include_search(search.stderr)
            if "include-fixed" not in p and Path(p).is_dir()
        ]
        if not self.system_includes:
            raise Setup("ARM compiler reported no usable system include directories")
        r["compilers"]["system_includes"] = self.system_includes

    def archive_binding(self):
        """Bind the archive bytes to the expanded bundle before any install."""
        a, bundle = self.args, self.bundle
        archive = a.archive.resolve()
        if not archive.is_file():
            raise Setup(f"--archive missing: {archive}")
        kind = "tar.gz" if PLATFORMS[a.platform][2] == "linux" else "zip"
        if (
            not archive.name.endswith("." + kind)
            or archive.name != f"{bundle.name}.{kind}"
        ):
            raise Setup(
                f"--archive must be {bundle.name}.{kind} for {a.platform}: {archive}"
            )
        record = file_record(archive)
        if a.archive_sha256 and record["sha256"] != a.archive_sha256.lower():
            raise Setup("archive bytes differ from --archive-sha256")
        self.report["archive"] = record
        scripts = str(Path(__file__).resolve().parent)
        if scripts not in sys.path:
            sys.path.insert(0, scripts)
        import verify_build_output  # Shared exact-target archive/payload validator.

        try:
            verify_build_output.validate_archive(
                archive, kind, bundle.name, self.manifest
            )
        except (RuntimeError, KeyError, ValueError, OSError) as exc:
            raise Red(f"static archive validation failed: {exc}") from exc
        leaves = archive_leaves(archive, kind, bundle.name)
        expanded = self.bundle_before
        missing, extra = (
            sorted(set(expanded) - set(leaves)),
            sorted(set(leaves) - set(expanded)),
        )
        require(
            not missing and not extra,
            f"archive/bundle inventories differ: missing {missing[:10]}, extra {extra[:10]}",
        )
        differ = [
            n
            for n, leaf in leaves.items()
            if (leaf["sha256"], leaf["size"])
            != (expanded[n]["sha256"], expanded[n]["size"])
        ]
        require(
            not differ, f"archive bytes differ from the expanded bundle: {differ[:10]}"
        )
        executables = {f["path"] for f in self.manifest["files"] if f.get("executable")}
        modes = {}
        if not a.platform.startswith("windows"):
            for name, leaf in leaves.items():
                archived = bool(leaf["mode"] & 0o111)
                local = executable_bit(bundle / name)
                want = name in executables
                require(
                    archived == local == want,
                    f"executable mode differs for {name}: archive {oct(leaf['mode'])}",
                )
                modes[name] = oct(leaf["mode"])
        return {
            "kind": kind,
            "sha256": record["sha256"],
            "leaves": len(leaves),
            "validated_by": "verify_build_output.validate_archive + leaf equality",
            "posix_modes_checked": len(modes),
            "manifest_executables": sorted(executables),
        }

    def install(self):
        e, lab = self.evidence, self.lab
        e.run(
            "public-install-runtime",
            [
                str(self.bundle / exe_name(self.args.platform, "byo")),
                "install-runtime",
                "--bundle",
                str(self.bundle),
            ],
            self.env,
            lab,
            timeout=self.args.install_timeout,
        )
        self.byo = self.home / "bin" / exe_name(self.args.platform, "byo")
        require(
            self.byo.is_file(), "install-runtime did not create the public launcher"
        )
        current = read_json(self.home / "data/current.json")
        require(
            current.get("version") == self.version, f"current.json differs: {current}"
        )
        self.runtime = self.home / "data/versions" / self.version
        self.assert_runtime()
        mapping = read_json(self.runtime / "analysis/runtime.json")
        self.mapping = mapping
        self.clangd = self.runtime / mapping["programs"]["clangd"]["executable"]
        self.cppcheck = self.runtime / mapping["programs"]["cppcheck"]["executable"]
        for program in (self.clangd, self.cppcheck):
            require(program.is_file(), f"mapped analyzer missing: {program}")
        self.report["installed"] = {
            "home": str(self.home),
            "runtime": str(self.runtime),
            "launcher": file_record(self.byo),
            "current": current,
            "mapping": mapping,
            "clangd": file_record(self.clangd),
            "cppcheck": file_record(self.cppcheck),
        }
        self.arm = self.arm_project()
        self.semantic = self.semantic_project()
        for project in (self.arm, self.semantic):
            e.run(
                f"public-init-{project.name.split()[0]}",
                [str(self.byo), "init", "--project", str(project)],
                self.env,
                lab,
            )
        self.preserved = {
            str(p / n): file_record(p / n)
            for p in (self.arm, self.semantic)
            for n in USER_FILES
        }
        self.build_override()
        self.poison = lab / "poison"
        self.product_env = poisoned_environment(
            self.args.platform, self.env, self.poison
        )
        self.poison_before = tree_record(self.poison)
        self.report["poison"] = {
            "directory": str(self.poison),
            "files": self.poison_before,
            "variables": {k: self.product_env[k] for k in LOADER_VARIABLES},
            "path_first": str(self.poison),
        }
        self.manifest_sha256 = sha256(self.runtime / "release-manifest.json")
        require(
            self.manifest_sha256 == self.report["bundle"]["manifest"]["sha256"],
            "installed release-manifest.json differs from the bundle manifest",
        )

    def assert_runtime(self):
        for item in self.manifest["files"]:
            path = self.runtime / item["path"]
            require(
                path.is_file() and sha256(path) == item["sha256"],
                f"installed runtime file differs from manifest: {item['path']}",
            )

    def arm_project(self) -> Path:
        project = self.lab / "arm firmware project"
        for relative in ARM_FIXTURE:
            target = project / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(fixture_bytes(relative))
        for name, text in USER_FILES.items():
            (project / name).write_bytes(text.encode("utf-8"))
        includes = [
            str(project / "include"),
            str(project / "build/generated"),
            *self.system_includes,
        ]
        self.arm_commands, database = [], []
        for relative, driver, extra in ARM_UNITS:
            argv = [str(self.compilers[driver]), *ARM_FLAGS]
            for include in includes:
                argv += ["-I", include]
            output = "build/" + Path(relative).stem + ".o"
            argv += [*extra, "-c", str(project / relative), "-o", output]
            self.arm_commands.append(argv)
            database.append(
                {
                    "directory": str(project),
                    "file": str(project / relative),
                    "arguments": argv,
                    "output": str(project / output),
                }
            )
        write_json(project / "build/compile_commands.json", database)
        write_json(
            project / "byo-analysis.json",
            {
                "schema_version": 1,
                "compilation_database": "build/compile_commands.json",
                "cppcheck": {"platform_file": "config/arm32.xml"},
                "clangd": {
                    "query_driver_paths": [
                        str(self.compilers["gcc"]),
                        str(self.compilers["gxx"]),
                    ]
                },
            },
        )
        return project

    def semantic_project(self) -> Path:
        project = self.lab / "semantic project µ"
        for relative, text in SEMANTIC.items():
            target = project / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(text.replace("\n", "\r\n").encode("utf-8"))
        for name, text in USER_FILES.items():
            (project / name).write_bytes(text.encode("utf-8"))
        gxx = str(self.compilers["gxx"])
        write_json(
            project / "build/compile_commands.json",
            [
                {
                    "directory": str(project),
                    "file": str(project / r),
                    "arguments": [
                        gxx,
                        "-mcpu=cortex-m4",
                        "-mthumb",
                        "-std=c++17",
                        "-Iinclude",
                        "-c",
                        r,
                    ],
                }
                for r in ("src/main.cpp", "src/symbols.cpp", "src/other.cpp")
            ],
        )
        write_json(
            project / "byo-analysis.json",
            {
                "schema_version": 1,
                "compilation_database": "build/compile_commands.json",
                "clangd": {"query_driver_paths": [gxx]},
            },
        )
        return project

    def build_override(self):
        target = self.arm / "bin" / "verify-firmware-local"
        target.parent.mkdir(exist_ok=True)
        if self.args.platform.startswith("windows"):
            source = self.lab / "override-src" / "verify_override.rs"
            source.parent.mkdir()
            source.write_text(WINDOWS_OVERRIDE_RS, encoding="utf-8")
            built = self.lab / "override-src" / "verify_override.exe"
            build_env = {
                **os.environ,
                "RUSTUP_AUTO_INSTALL": "0",
                "VSCMD_SKIP_SENDTELEMETRY": "1",
            }
            self.evidence.run(
                "compile-build-override",
                [
                    str(self.args.rustc),
                    "--edition=2021",
                    "-C",
                    "linker=rust-lld",
                    "-C",
                    "linker-flavor=lld-link",
                    str(source),
                    "-o",
                    str(built),
                ],
                build_env,
                self.lab,
                setup=True,
                timeout=180,
            )
            shutil.copyfile(built, target)
            (self.arm / "build/override-commands.txt").write_text(
                windows_override_commands(self.arm_commands), encoding="utf-8"
            )
            kind = "rustc-compiled override executing explicit ARM argv"
        else:
            target.write_text(
                posix_override_script(self.arm_commands), encoding="utf-8"
            )
            target.chmod(0o755)
            kind = "/bin/sh override executing shell-quoted explicit ARM argv"
        self.report["build_override"] = {
            "kind": kind,
            "program": file_record(target),
            "commands": self.arm_commands,
        }

    def objects_clean(self, label: str) -> dict:
        found = {}
        for relative, _driver, _extra in ARM_UNITS:
            path = self.arm / "build" / (Path(relative).stem + ".o")
            require(path.is_file(), f"{label}: override produced no {path.name}")
            require(
                elf_arm_relocatable(path.read_bytes()),
                f"{label}: {path.name} is not an ELF32 ARM relocatable object",
            )
            found[path.name] = file_record(path)
        return found

    def check_report(self, name: str, outcome, status: str, analyzer_exit: int) -> dict:
        reports = self.arm / ".firm/code-analysis/reports"
        new = set(reports.glob("*/result.json")) - self._reports_before
        require(
            len(new) == 1, f"{name}: expected one new static report, got {len(new)}"
        )
        path = new.pop()
        copied = self.evidence.root / "analysis-reports" / name
        shutil.copytree(path.parent, copied)
        result = read_json(path)
        require(
            result["status"] == status, f"{name}: status {result['status']} != {status}"
        )
        require(
            result["process_exit_code"] == analyzer_exit,
            f"{name}: analyzer exit {result['process_exit_code']} != {analyzer_exit}",
        )
        require(
            same_path(result["executable"], self.cppcheck),
            f"{name}: executed {result['executable']}, not mapped installed Cppcheck",
        )
        require(
            result["executable_sha256"] == sha256(self.cppcheck),
            f"{name}: executable digest differs",
        )
        require(
            result["version"] == self.mapping["programs"]["cppcheck"]["version"],
            f"{name}: version {result['version']} differs from mapping",
        )
        require(
            result["compilation_database_sha256"]
            == sha256(self.arm / "build/compile_commands.json"),
            f"{name}: database digest differs",
        )
        require(
            same_path(result["platform_file"], self.arm / "config/arm32.xml"),
            f"{name}: explicit ARM platform not used",
        )
        argv = result["argv"]
        for flag in ("--error-exitcode=1", "--xml", "--xml-version=2"):
            require(flag in argv, f"{name}: argv lacks {flag}")
        require(
            any(a.startswith("--project=") for a in argv)
            and any(a.startswith("--platform=") for a in argv),
            f"{name}: argv lacks database/platform",
        )
        require(
            result["scope"]["selected_count"] == 3 and result["scope"]["kind"] == "all",
            f"{name}: scope differs: {result['scope']}",
        )
        require((copied / "report.xml").is_file(), f"{name}: XML report missing")
        if status == "findings_failed":
            require(
                any(d.get("id") == "nullPointer" for d in result["diagnostics"]),
                f"{name}: injected null dereference not reported",
            )
        # Bind the runner's analysis PIDs to independently observed exact exits.
        pids = {
            e["pid"]
            for e in result["owned_processes"]
            if isinstance(e, dict) and e.get("phase") == "analysis" and e.get("pid")
        }
        require(pids, f"{name}: runner recorded no analysis process")
        observed = [
            i
            for i in outcome.observed_processes
            if i["pid"] in pids
            and (i.get("image") is None or same_path(i["image"], self.cppcheck))
        ]
        if {i["pid"] for i in observed} != pids:
            raise Unverified(
                f"{name}: analysis PIDs {sorted(pids)} not independently "
                "observed with create_time; no cleanup credit"
            )
        require(
            all(i["alive_after"] is False for i in observed),
            f"{name}: analysis identity not proved exited",
        )
        require(
            result.get("runtime_manifest_sha256") == self.manifest_sha256
            and same_path(result.get("runtime_root"), self.runtime),
            f"{name}: report not bound to the installed runtime manifest",
        )
        return {
            "report": str(copied),
            "source_report": str(path.parent),
            "status": result["status"],
            "analyzer_exit": result["process_exit_code"],
            "process_exit": outcome.returncode,
            "analysis_identities": observed,
            "executable_origin": result.get("executable_origin"),
        }

    def runner(
        self, name: str, argv: list[str], env: dict, failure_exit: int, origin: str
    ) -> list[dict]:
        source = self.arm / "src/main.c"
        clean = fixture_bytes("src/main.c")
        database = file_record(self.arm / "build/compile_commands.json")
        log = self.arm / "build/override-invocations.log"
        phases = []
        try:
            for phase, data, status, analyzer_exit, exit_code in (
                ("clean", clean, "pass", 0, 0),
                ("defect", clean + DEFECT, "findings_failed", 1, failure_exit),
                ("restored", clean, "pass", 0, 0),
            ):
                source.write_bytes(data)
                runs = (
                    len(log.read_text(encoding="utf-8").splitlines())
                    if log.is_file()
                    else 0
                )
                self._reports_before = set(
                    (self.arm / ".firm/code-analysis/reports").glob("*/result.json")
                )
                outcome = self.evidence.run(
                    f"{name}-{phase}", [*argv, "."], env, self.arm, expected=exit_code
                )
                entry = self.check_report(
                    f"{name}-{phase}", outcome, status, analyzer_exit
                )
                require(
                    entry["executable_origin"] == origin,
                    f"{name}-{phase}: origin {entry['executable_origin']} != {origin}",
                )
                if name == "companion":
                    entry["returned"] = self.companion_result(
                        f"{name}-{phase}", outcome, entry
                    )
                else:
                    text = outcome.stdout + outcome.stderr
                    require(
                        ("VERIFY: PASS" in text) == (status == "pass"),
                        f"{name}-{phase}: final VERIFY text disagrees with state",
                    )
                if name == "rust":
                    after = len(log.read_text(encoding="utf-8").splitlines())
                    require(
                        after == runs + 1,
                        f"{name}-{phase}: build override not run once",
                    )
                    entry["objects"] = self.objects_clean(f"{name}-{phase}")
                phases.append({"phase": phase, **entry})
        finally:
            source.write_bytes(clean)
        require(
            file_record(self.arm / "build/compile_commands.json") == database,
            f"{name}: project database mutated",
        )
        return phases

    def rust_verify(self):
        argv = [str(self.byo), "workflow", "tool", "verify", "--project", str(self.arm)]
        phases = self.runner(
            "rust", argv, self.product_env, WORKFLOW_POLICY_EXIT, "managed_runtime"
        )
        project = self.arm
        self.report["arm_fixture"] = {
            "root": str(project),
            "sources": {r: file_record(project / r) for r in ARM_FIXTURE},
            "abi_platform": file_record(project / "config/arm32.xml"),
            "compile_database": file_record(project / "build/compile_commands.json"),
            "objects": self.objects_clean("final"),
            "build_override": file_record(project / "bin/verify-firmware-local"),
        }
        return {
            "route": "installed public Rust runner with real ARM build override",
            "phases": phases,
        }

    def companion_result(self, name: str, outcome, entry: dict) -> dict:
        lines = [x for x in outcome.stdout.splitlines() if x.startswith("{")]
        require(len(lines) == 1, f"{name}: companion printed no single JSON result")
        returned = json.loads(lines[0])
        result = returned["result"]
        require(
            same_path(returned["module"], self.workspace / "internal/code_analysis.py"),
            f"{name}: imported {returned['module']}, not the workspace source",
        )
        require(
            same_path(result["report_directory"], entry["source_report"]),
            f"{name}: returned report directory differs from the retained report",
        )
        for key in ("status", "executable_origin"):
            require(
                result[key] == entry[key],
                f"{name}: returned {key} differs from result.json",
            )
        require(
            same_path(result["executable"], self.cppcheck)
            and result["executable_sha256"] == sha256(self.cppcheck),
            f"{name}: returned executable is not the mapped installed Cppcheck",
        )
        return {
            "module": returned["module"],
            "status": result["status"],
            "executable": result["executable"],
            "executable_sha256": result["executable_sha256"],
            "runtime_manifest_sha256": result["runtime_manifest_sha256"],
        }

    def companion_verify(self):
        driver = self.lab / "companion" / "managed_companion.py"
        driver.parent.mkdir()
        driver.write_text(COMPANION_DRIVER, encoding="utf-8", newline="\n")
        # The driver needs only the stdlib and the workspace. A Windows venv
        # python.exe is a redirector process; the base interpreter avoids that
        # extra live layer between the sampled leader and fast analysis PIDs.
        python = getattr(sys, "_base_executable", None) or sys.executable
        argv = [
            python,
            "-I",
            "-B",
            str(driver),
            str(self.workspace),
            str(self.runtime),
            self.manifest_sha256,
            str(self.arm),
        ]
        return {
            "route": "direct SOURCE API internal.code_analysis.run_cppcheck with "
            "TrustedRuntimeContext(managed=True); not a shipped Python CLI",
            "workspace": self.report["workspace_source"],
            "driver": file_record(driver),
            "python": file_record(Path(python)),
            "host_python": sys.executable,
            "runtime_root": str(self.runtime),
            "runtime_manifest_sha256": self.manifest_sha256,
            "phases": self.runner(
                "companion", argv, self.product_env, 1, "managed_runtime"
            ),
        }

    def live_clangd(self, server: Mcp) -> dict:
        server.owned.sample_once()
        live = [
            r
            for r in list(server.owned.records.values())
            if r.get("image")
            and same_path(r["image"], self.clangd)
            and self.native.alive(r) is True
        ]
        if len(live) != 1:
            raise Unverified(f"expected one live owned clangd session, saw {len(live)}")
        identity = self.native.identity(live[0]["pid"])
        if (
            not identity
            or identity["create_time"] != live[0]["create_time"]
            or not identity.get("argv")
        ):
            raise Unverified("live clangd argv unobservable for the exact identity")
        drivers = [
            a.split("=", 1)[1]
            for a in identity["argv"]
            if a.startswith("--query-driver=")
        ]
        require(
            len(drivers) == 1 and same_path(drivers[0], self.compilers["gxx"]),
            f"clangd query-driver allowlist differs: {identity['argv']}",
        )
        return identity

    def mcp(self):
        p = self.semantic
        server = Mcp(
            self.evidence,
            [str(self.byo), "mcp", "serve", "--project", str(p)],
            self.product_env,
            p,
            "semantic",
        )
        self.server, self.peer = server, None
        server.initialize(self.version)

        def check(value: dict, file_path: str | None = None):
            require(
                value.get("status") == "ok" and value.get("backend") == "clangd",
                f"nonpass analysis response: {value!r}",
            )
            require(
                same_path(value["project_root"], p),
                "analysis used another project root",
            )
            require(
                value["compilation_database_sha256"]
                == sha256(p / "build/compile_commands.json"),
                "stale database digest",
            )
            if file_path:
                require(
                    value["source"]["sha256"] == sha256(p / file_path),
                    "stale saved-file source digest",
                )
            return value

        def position(relative: str, line: int, token: str) -> dict:
            text = (p / relative).read_text(encoding="utf-8").splitlines()[line - 1]
            return {
                "file_path": relative,
                "line": line,
                "column": text.index(token) + 1,
                "timeout_seconds": 60,
            }

        def points(value: dict) -> set:
            return {
                (Path(x["path"]).name, x["range"]["start"]["line"])
                for x in value["data"]["locations"]
            }

        status = check(server.tool("get_code_analysis_status", {}))
        require(
            status["data"]["executable_origin"] == "managed_runtime",
            "clangd resolved through PATH",
        )
        require(
            same_path(status["data"]["executable"], self.clangd),
            "status names another clangd executable",
        )
        main = "src/main.cpp"
        query = position(main, 2, "choose")
        definition = check(server.tool("find_code_definition", query), main)
        require(
            points(definition) & {("symbols.hpp", 2), ("symbols.cpp", 2)},
            f"int overload definition differs: {points(definition)}",
        )
        template = check(
            server.tool("find_code_definition", position(main, 2, "twice")), main
        )
        require(("symbols.hpp", 4) in points(template), "template definition differs")
        hover = check(server.tool("get_code_hover", query), main)
        require("choose" in json.dumps(hover["data"]), "hover lacks the symbol")
        check(
            server.tool("get_code_hover", position("src/other.cpp", 2, "shared")),
            "src/other.cpp",
        )
        ref_args = {
            **position(main, 2, "shared"),
            "include_declaration": True,
            "max_results": 100,
        }
        deadline = time.monotonic() + 45
        while True:
            refs = check(server.tool("find_code_references", ref_args), main)
            if {("main.cpp", 2), ("other.cpp", 2)} <= points(refs):
                break
            require(
                time.monotonic() < deadline,
                f"cross-file references missing: {points(refs)}",
            )
            time.sleep(0.3)
        require(
            refs["index_completeness"] == "unverified",
            "references overclaim completeness",
        )
        column = ref_args["column"]
        require(
            any(
                x["range"]["start"] == {"line": 2, "column": column}
                for x in refs["data"]["locations"]
                if Path(x["path"]).name == "main.cpp"
            ),
            "non-BMP CRLF code-point column differs",
        )

        def diagnostics(label: str) -> dict:
            value = check(
                server.tool(
                    "get_code_diagnostics", {"file_path": main, "timeout_seconds": 60}
                ),
                main,
            )
            data = value["data"]
            require(
                data["returned_count"] == len(data["diagnostics"])
                and data["truncated"] is False,
                f"{label}: diagnostic counts disagree",
            )
            return value

        clean = diagnostics("clean")
        require(
            clean["data"]["diagnostics"] == [],
            f"real ARM target/newlib context not clean: {clean['data']}",
        )
        session = self.live_clangd(server)
        source = p / main
        original = source.read_bytes()
        try:
            source.write_bytes(
                original.replace(b"choose(2)", b"unknown_saved_symbol(2)")
            )
            bad = diagnostics("saved-defect")
            require(
                any(
                    "unknown_saved_symbol" in d["message"]
                    for d in bad["data"]["diagnostics"]
                ),
                "saved-file defect not diagnosed",
            )
        finally:
            source.write_bytes(original)
        restored = diagnostics("saved-restored")
        require(restored["data"]["diagnostics"] == [], "restored file not clean")
        versions = [v["source"]["document_version"] for v in (clean, bad, restored)]
        require(
            versions[0] < versions[1] < versions[2],
            f"document versions stale: {versions}",
        )
        # Unaffected peer: same installed image, not a descendant of the server.
        self.peer = subprocess.Popen(
            [str(self.clangd)],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=self.lab,
            env=self.env,
        )
        self.peer_identity = self.native.identity(self.peer.pid)
        if not self.peer_identity:
            raise Unverified("peer identity unobservable")
        require(
            (self.peer.pid, self.peer_identity["create_time"])
            not in server.owned.records,
            "peer became owned by the server",
        )
        self.report["mcp"] = {
            "session": session,
            "peer": self.peer_identity,
            "document_versions": versions,
            "transcript": str(server.path),
        }

    def mcp_eof(self):
        server = getattr(self, "server", None)
        if server is None:
            raise Setup("no MCP server was started")
        record = server.close()
        peer_alive = self.native.alive(self.peer_identity) if self.peer else None
        self.report["mcp_eof"] = {"record": record, "peer_alive_after_eof": peer_alive}
        require(not record["eof_timeout"], "server did not exit after stdin EOF")
        require(record["exit"] == 0, f"server EOF exit {record['exit']} != 0")
        states = [i["alive_after"] for i in record["processes"]]
        require(True not in states, "an owned identity survived natural EOF")
        if (
            None in states
            or "observation_failure" in record
            or record["unobserved_leader"]
        ):
            raise Unverified("owned exit after EOF not observable for every identity")
        require(
            any(
                i.get("image") and same_path(i["image"], self.clangd)
                for i in record["processes"]
            ),
            "no clangd identity was owned",
        )
        if self.peer:
            if peer_alive is not True:
                raise (Red if peer_alive is False else Unverified)(
                    "unaffected peer did not survive server EOF"
                )
        return {"owned_identities": len(states), "eof_seconds": record["eof_seconds"]}

    def retire_peer(self):
        peer = getattr(self, "peer", None)
        if peer is None:
            return
        try:
            peer.stdin.close()
            peer.wait(timeout=10)
            forced = False
        except (OSError, subprocess.TimeoutExpired):
            forced = True
            confirmed = self.native.terminate_exact(self.peer_identity)
            self.evidence.emergency.append(
                {
                    "command": "peer",
                    "identity": self.peer_identity,
                    "confirmed": confirmed,
                }
            )
        self.report["peer_retirement"] = {
            "exit": peer.poll(),
            "forced": forced,
            "alive_after": self.native.alive(self.peer_identity),
        }

    def preservation(self):
        require(tree_record(self.bundle) == self.bundle_before, "input bundle changed")
        for name, ref in self.report["compilers"].items():
            if isinstance(ref, dict) and "sha256" in ref:
                require(
                    file_record(Path(ref["path"])) == ref, f"compiler {name} changed"
                )
        for path, ref in self.preserved.items():
            require(file_record(Path(path)) == ref, f"user file changed: {path}")
        self.assert_runtime()
        require(
            tree_record(self.poison) == self.poison_before,
            "a fake PATH analyzer ran or the poison directory changed",
        )
        if self.evidence.emergency:
            raise Red(f"emergency cleanup was required: {self.evidence.emergency}")


def run(args) -> int:
    report = {
        "schema": SCHEMA,
        "argv": sys.argv,
        "artifact_label": args.artifact_label,
        "expected_target": args.platform,
        "script": file_record(Path(__file__).resolve()),
        "gates": {g: {"status": "PENDING"} for g in GATES},
        "evidence_class": "native installed core smoke for the given bundle on this host only",
        "scope": f"core smoke of the supplied {args.platform} bundle/archive only; not "
        "complete OS, all-profile or all-behavior acceptance",
        "limitations": [
            "Proves only the supplied bundle and archive on the host that ran it.",
            "Companion is the managed SOURCE API from --workspace-source; no shipped "
            "Python CLI is claimed.",
            "Build override compiles the ARM fixture objects; no link or hardware step.",
            "Native matrix, corruption, timeout/cancellation, update/uninstall, resource, "
            "missing-data and no-board/tier/profile cases are separate gates.",
        ],
    }
    scratch = args.scratch
    if scratch.exists():
        print(
            json.dumps(
                {
                    "status": "SETUP_FAILURE",
                    "exit": 2,
                    "error": f"--evidence must be NEW: {scratch}",
                }
            ),
            flush=True,
        )
        return 2
    scratch.mkdir(parents=True)
    smoke = Smoke(args, report)
    try:
        if smoke.gate("preflight", smoke.preflight) and smoke.gate(
            "archive-binding", smoke.archive_binding
        ):
            if smoke.gate("install", smoke.install):
                smoke.gate("rust-firmware-verify", smoke.rust_verify)
                smoke.gate("managed-companion-verify", smoke.companion_verify)
                if smoke.gate("mcp-semantic", smoke.mcp) or getattr(
                    smoke, "server", None
                ):
                    smoke.gate("mcp-natural-eof", smoke.mcp_eof)
                smoke.retire_peer()
                smoke.gate("preservation", smoke.preservation)
    finally:
        server = getattr(smoke, "server", None)
        if server is not None and not server.closed:
            server.close()
        if getattr(smoke, "peer", None) is not None and "peer_retirement" not in report:
            smoke.retire_peer()
        if smoke.evidence is not None:
            report["emergency_cleanup"] = smoke.evidence.emergency
    states = [g["status"] for g in report["gates"].values()]
    code = (
        1
        if "RED" in states
        else 2
        if {"SETUP_FAILURE", "UNVERIFIED"} & set(states)
        else 3
        if "PENDING" in states
        else 0
    )
    report["exit"] = code
    report["status"] = {0: "PASS", 1: "RED", 2: "SETUP_FAILURE", 3: "PENDING"}[code]
    evidence = scratch / "evidence"
    write_json(evidence / "report.json", report)
    write_json(
        evidence / "manifest.json",
        {
            "schema": SCHEMA + "#manifest",
            "files": {
                k: v for k, v in tree_record(evidence).items() if k != "manifest.json"
            },
        },
    )
    print(
        json.dumps(
            {
                "status": report["status"],
                "exit": code,
                "scope": report["scope"],
                "evidence": str(evidence),
                "manifest_sha256": sha256(evidence / "manifest.json"),
                "gates": {k: v["status"] for k, v in report["gates"].items()},
            },
            ensure_ascii=True,
        ),
        flush=True,
    )
    return code


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument(
        "--expected-target",
        "--platform",
        dest="platform",
        required=True,
        choices=sorted([*PLATFORMS, *TARGET_ALIASES]),
    )
    p.add_argument("--bundle", required=True, type=Path)
    p.add_argument("--archive", required=True, type=Path)
    p.add_argument("--archive-sha256")
    p.add_argument("--evidence", "--scratch", dest="scratch", required=True, type=Path)
    p.add_argument(
        "--workspace-source",
        "--python-workspace",
        dest="python_workspace",
        required=True,
        type=Path,
    )
    p.add_argument("--arm-gxx", required=True, type=Path)
    p.add_argument("--arm-gxx-sha256", required=True)
    p.add_argument("--arm-gcc", type=Path)
    p.add_argument(
        "--rustc",
        type=Path,
        help="Required on Windows: actual rustc with bundled rust-lld",
    )
    p.add_argument("--artifact-label", required=True)
    p.add_argument("--install-timeout", type=float, default=300)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    args.platform = TARGET_ALIASES.get(args.platform, args.platform)
    args.scratch = args.scratch.absolute()
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
