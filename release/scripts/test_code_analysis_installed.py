#!/usr/bin/env python3
"""Independent Windows x86_64 analysis acceptance through executable interfaces.

Preparation is not installed acceptance. No artifact is built or downloaded here.
Run the focused RED first on an actual pre-packaging bundle (absence of the
analysis mapping/programs is RED; absence of the bundle itself is SETUP_FAILURE):

  python release/scripts/test_code_analysis_installed.py --archive-only \
    --archive C:/inputs/byo.zip --archive-sha256 <64 hex> \
    --cppcheck-sha256 <independently established raw candidate SHA256> \
    --bundle C:/inputs/byo --evidence C:/evidence/initial-red

Later run against the exact final ZIP AND matching expanded bundle, adding:

  --cppcheck-inputs C:/inputs/cppcheck-windows-packaging-inputs.json
  --cppcheck-source C:/inputs/cppcheck-source
  --clangd-inputs C:/inputs/clangd-windows-packaging-input.json
  --clangd-root C:/inputs/clangd_23.1.0
  --arm-fixture "C:/inputs/built ARM firmware"
  --python-workspace C:/inputs/accepted-workspace --python-commit <exact commit>
  --rustc C:/existing/bin/rustc.exe --rustc-sha256 <64 hex>
  --availability-inputs C:/inputs/availability.json --availability-sha256 <64 hex>

All input paths are read/copy only. Accepted Cppcheck/clangd/ARM hashes are checked
independently. The Python workspace must be a clean, exact Git checkout; only its
tracked bin/internal/modes files are copied, never imported by this test. Its
PUBLIC bin/verify uses the private installed Cppcheck directory on PATH. This is
explicitly companion-source-runner evidence using installed native bytes, not
proof of a shipped Python entrypoint. The report keeps that limitation visible.
Rust and MCP use managed resolution with no analysis directories on PATH.
ROOT confirmed the public route: Python is source-run using installed Cppcheck;
Rust is the installed public verify runner. The immutable workflow pack contains
compiled guidance/modes, not a public Python verify entrypoint. No private context
injection or guessed sidecar helper is used. This comparison does not claim that
Python source scripts are shipped in the installed capsule.

Availability input schema: installed-analysis-availability/v3 (committed at
release/scripts/fixtures/code-analysis-installed/availability/manifest.json, bound
by an explicit --availability-sha256). "fixtures" maps a name to exact passive
.firm files as {sha256,size,base64}; each case is {state, variant, profile,
board_id, fixture}. revoked_unvalidated needs BOTH variants "revoked" and
"unvalidated"; other states use variant null. Duplicate/unknown labels, fields,
variants or fixtures are setup failure. Before launch, independent stdlib checks
validate the policy pointer/generation/digests and attachment cache (schema,
board, confirmed=false with an absolute revoked_at, stable identities, no
persisted authority) and DERIVE the expected public tier, policy_status,
setup_incomplete, policy_digest and identity from the bytes; a label that the
bytes do not support is setup failure. Bytes are written into the private
project after public init. Public server_health_check (narrative_logging
enabled/not_built) and get_capabilities(board_id) must equal the derivation; all
five analysis tools must answer; their results are retained per variant in
availability-<state>[-<variant>]-<profile>.json. Protected project bytes and the
manifest are rechecked after the queries. A group passes only when every
required variant passes. --installed-profile selects the expected COMPILED
archive profile; it cannot change it. A professional invocation requires a
separately compiled professional archive. Without inputs, the fresh no-board
case runs for this archive profile. No policy creation, board unlock, probing,
connection or fake MCP backend.

--cppcheck-sha256 is mandatory, including archive-only preparation. Establish it
independently before inspecting the bundle (e.g. reviewed build-byte receipt or
independent rebuild comparison). ZIP, expanded bytes, inventory, mapping and
both public runners are checked against it. A manifest claim is not an oracle.
The genuine second-version bundle needs --update-cppcheck-sha256 as its own
independent raw digest plus --update-manifest-sha256; it must not reuse the first
digest by assumption. --validator-contract-checks exercises validator negatives
with private mutations, returning 3 on success because installed gates are pending.

Dependencies: native Windows AMD64, Python >=3.11 (stdlib only), existing cached
rustc/MSVC link environment for the *build-control* fixture, PowerShell for owned
child command-line evidence, final native bundle. No Cargo dependency install.
The build control validates the frozen genuine ARM ELF/map; it does not rebuild
mutated source. Only analyzers are real in the clean/defect/restored smoke gate.
Normal builds, unit/quality checks and install.ps1 bootstrap remain separate gates.

The public native `install-runtime --bundle` installer entrypoint is used without
--modify-path so isolated tests never change the user's registry PATH. The ZIP
is independently checked byte for byte before that install. Runtime, projects,
profile/cache/temp directories are under a short mkdtemp root with spaces and
non-ASCII names. Source paths stay below 260 UTF-16 units: the pinned Cppcheck
cannot analyze longer source paths reliably. Default labs are retained on failure;
successful labs are removed unless --keep-lab. Evidence is always retained, with
raw stdout/stderr, MCP requests/replies, actual argv/exits, PID + creation FILETIME,
source/report hashes and a SHA256 manifest. Cleanup selects owned identities only.

Exit: 0 all executable gates pass; 1 product assertion RED; 2 setup failure;
3 required gate pending (also used by successful --archive-only preparation).
The report always enumerates remaining gates; no staged/fake/source success is
promoted to final installed proof. Pass this report to ROOT for exact final-source
validation. Do not run this against writable production installations.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import zipfile
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures/code-analysis-installed"
CPP_INPUT_SHA = "e8f71939bafaba468ac299a3995e30ddf05c82365176a2f7c82365f55b57b4d3"
# MSVC rebuilds vary in PE timestamp/checksum/CodeView bytes. The caller must
# supply an independently established raw candidate digest, never a bundle claim.
CLANG_EXE_SHA = "dbd52c13d21ef9d284f4f0627efe76c81adf2fe0998f230127f554a54fc9dde7"
CLANG_INPUT_SHA = "4b6a35d3950b05b2708021da3f2f78ea29cab0922a35cda07a5229af733191b2"
ARM_INPUT_SHA = "ab3a5ea27dd222b753def82b36066c1e803c8eec76d0b2947f2d61e893ed6291"
TOOLS = (
    "get_code_analysis_status",
    "find_code_definition",
    "find_code_references",
    "get_code_hover",
    "get_code_diagnostics",
)
STATES = (
    "no_board",
    "no_setup",
    "setup_lite",
    "setup_full",
    "revoked_unvalidated",
    "corrupt_policy",
)
GATES = (
    "archive",
    "immutable-inputs",
    "install",
    "rust-arm",
    "python-arm",
    "mcp-no-board",
    "mcp-availability",
    "stdio-idle-eof-cleanup",
    "missing-data-corrupt-version",
    "doctor-status-report",
    "relocation",
    "update-preservation",
    "project-global-uninstall",
)


class Red(RuntimeError):
    """Observed public behavior contradicts the acceptance contract."""


class Setup(RuntimeError):
    """Input/environment unavailable; never counts as product RED."""


class Pending(RuntimeError):
    """Required executable gate cannot yet be exercised."""


class Halt(Exception):
    """Stop dependent work after a prerequisite gate; retain the gate result."""


def require(condition: object, message: str) -> None:
    if not condition:
        raise Red(message)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(data)
    return h.hexdigest()


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def file_record(path: Path) -> dict:
    return {"sha256": digest(path), "size": path.stat().st_size}


def tree_record(root: Path) -> dict:
    result = {}
    for path in sorted(root.rglob("*")):
        if is_reparse(path):
            raise Setup(f"read-only input contains a reparse path: {path}")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = file_record(path)
    return result


def is_reparse(path: Path) -> bool:
    return bool(getattr(path.lstat(), "st_file_attributes", 0) & 0x400)


def reported_path(value: str) -> Path:
    """Resolve a product-reported Windows path, including the extended form."""
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return Path(value).resolve()


def below(root: Path, relative: str) -> Path:
    p = PurePosixPath(relative)
    if (
        not relative
        or p.is_absolute()
        or any(x in (".", "..") for x in p.parts)
        or "\\" in relative
        or ":" in relative
    ):
        raise Setup(f"unsafe inventory path: {relative!r}")
    target = root.joinpath(*p.parts)
    if not target.resolve().is_relative_to(root.resolve()):
        raise Setup(f"inventory escapes root: {relative}")
    return target


def verify_file(path: Path, record: dict, *, product: bool = False) -> None:
    error = Red if product else Setup
    if not path.is_file() or is_reparse(path):
        raise error(f"required regular file missing: {path}")
    if file_record(path) != {"sha256": record["sha256"], "size": record["size"]}:
        raise error(f"size/SHA256 mismatch: {path}")


def expected_digest(value: str | None, option: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(c not in "0123456789abcdefABCDEF" for c in value)
    ):
        raise Setup(
            f"{option} requires an explicit independent 64-hex executable digest"
        )
    return value.lower()


def program_identity(
    bundle: Path, inventory: dict, mapping: dict, expected: str
) -> None:
    """Bind the declared location, inventoried identity and bytes to the oracle."""
    expected = expected_digest(expected, "--cppcheck-sha256")
    expected_mapping = {
        "schema_version": 1,
        "platform": "windows",
        "architecture": "x86_64",
        "programs": {
            "cppcheck": {
                "executable": "analysis/cppcheck/cppcheck.exe",
                "version": "2.22.0",
                "cfg_dir": "analysis/cppcheck/cfg",
                "platforms_dir": "analysis/cppcheck/platforms",
                "dependencies": [],
                "sbom_ref": "byo-analysis:cppcheck",
                "licenses": [
                    f"analysis/cppcheck/licenses/{name}"
                    for name in (
                        "COPYING",
                        "picojson-LICENSE",
                        "simplecpp-LICENSE",
                        "tinyxml2-LICENSE",
                    )
                ],
            },
            "clangd": {
                "executable": "analysis/clangd/bin/clangd.exe",
                "version": "23.1.0",
                "resource_dir": "analysis/clangd/lib/clang/23",
                "dependencies": [],
                "licenses": ["analysis/clangd/LICENSE.TXT"],
                "sbom_ref": "byo-analysis:clangd",
            },
        },
    }
    require(
        mapping == expected_mapping,
        "analysis mapping differs from the accepted pinned layout",
    )
    for name, relative, version, sha in (
        ("cppcheck", "analysis/cppcheck/cppcheck.exe", "2.22.0", expected),
        ("clangd", "analysis/clangd/bin/clangd.exe", "23.1.0", CLANG_EXE_SHA),
    ):
        record = mapping["programs"][name]
        require(
            record["executable"] == relative and record["version"] == version,
            f"{name} mapping path/version differs from the accepted contract",
        )
        require(relative in inventory, f"manifest lacks {name} executable")
        require(
            inventory[relative].get("kind") == "analysis-executable"
            and inventory[relative].get("executable") is True,
            f"manifest {name} executable classification changed",
        )
        require(
            inventory[relative]["sha256"] == sha,
            f"manifest {name} SHA256 differs from independent identity",
        )
        verify_file(below(bundle, relative), inventory[relative], product=True)
        require(
            digest(below(bundle, relative)) == sha, f"unpinned {name} binary shipped"
        )


class WindowsProcesses:
    """Independent native process observations; no image-name termination."""

    def __init__(self):
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.k.OpenProcess.restype = wintypes.HANDLE
        self.k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.k.CloseHandle.argtypes = [wintypes.HANDLE]
        self.k.GetProcessTimes.argtypes = [wintypes.HANDLE] + [
            ctypes.POINTER(wintypes.FILETIME)
        ] * 4
        self.k.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self.k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.k.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.k.GetSystemTimePreciseAsFileTime.argtypes = [
            ctypes.POINTER(wintypes.FILETIME)
        ]
        self.nt = ctypes.WinDLL("ntdll")
        self.nt.NtQuerySystemInformation.argtypes = [
            wintypes.ULONG,
            ctypes.c_void_p,
            wintypes.ULONG,
            ctypes.POINTER(wintypes.ULONG),
        ]
        self.buffer = ctypes.create_string_buffer(1 << 21)

    def now(self) -> int:
        current = wintypes.FILETIME()
        self.k.GetSystemTimePreciseAsFileTime(ctypes.byref(current))
        return (current.dwHighDateTime << 32) | current.dwLowDateTime

    def identity(self, pid: int, *, image: bool = True) -> dict | None:
        # None ONLY when Win32 proves no such PID (ERROR_INVALID_PARAMETER).
        # Access denied and every query failure is unobservable, never absence.
        handle = self.k.OpenProcess(0x1000 | 0x100000, False, pid)
        if not handle:
            error = ctypes.get_last_error()
            if error == 87:
                return None
            raise Setup(f"PID {pid} identity unobservable: OpenProcess error {error}")
        try:
            times = [wintypes.FILETIME() for _ in range(4)]
            if not self.k.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
                raise Setup(
                    f"PID {pid} identity unobservable: GetProcessTimes error "
                    f"{ctypes.get_last_error()}"
                )
            created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
            buf = ctypes.create_unicode_buffer(32768)
            size = wintypes.DWORD(len(buf))
            if image and not self.k.QueryFullProcessImageNameW(
                handle, 0, buf, ctypes.byref(size)
            ):
                raise Setup(
                    f"PID {pid} identity unobservable: QueryFullProcessImageNameW "
                    f"error {ctypes.get_last_error()}"
                )
            state = self.k.WaitForSingleObject(handle, 0)
            if state not in (0, 258):
                raise Setup(f"PID {pid} liveness unobservable: wait result {state}")
            return {
                "pid": pid,
                "creation_filetime": created,
                "image": buf.value if image else None,
                "alive": state == 258,
            }
        finally:
            self.k.CloseHandle(handle)

    def snapshot(self) -> dict:
        # One atomic SystemProcessInformation copy. A Python Toolhelp walk over
        # hundreds of host processes outlasts a short analyzer. x64 entry
        # offsets: next entry 0x00, PID 0x50, parent PID 0x58.
        size = wintypes.ULONG()
        while True:
            status = self.nt.NtQuerySystemInformation(
                5, self.buffer, len(self.buffer), ctypes.byref(size)
            )
            if status & 0xFFFFFFFF != 0xC0000004:
                break
            self.buffer = ctypes.create_string_buffer(
                max(size.value, 2 * len(self.buffer))
            )
        if status:
            raise Setup(f"Windows process snapshot failed: {status & 0xFFFFFFFF:#x}")
        view = memoryview(self.buffer).cast("B")
        entries = {}
        offset = 0
        while True:
            pid = int.from_bytes(view[offset + 0x50 : offset + 0x58], "little")
            parent = int.from_bytes(view[offset + 0x58 : offset + 0x60], "little")
            entries[pid] = parent
            step = int.from_bytes(view[offset : offset + 4], "little")
            if not step:
                return entries
            offset += step

    def alive(self, identity: dict) -> bool:
        # False only for proven absence: no PID, a later creation time on a
        # reused PID, or the exact PID+creation signalled exited. Unobservable
        # states raise Setup and can never earn cleanup credit.
        current = self.identity(identity["pid"], image=False)
        return bool(
            current
            and current["alive"]
            and current["creation_filetime"] == identity["creation_filetime"]
        )

    def terminate(self, identity: dict) -> None:
        # Query and terminate through the SAME retained handle after checking time.
        handle = self.k.OpenProcess(0x1000 | 0x100000 | 1, False, identity["pid"])
        if not handle:
            error = ctypes.get_last_error()
            if error == 87:
                return
            raise Setup(
                f"PID {identity['pid']} termination unobservable: OpenProcess error {error}"
            )
        try:
            times = [wintypes.FILETIME() for _ in range(4)]
            if not self.k.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
                raise Setup(
                    f"PID {identity['pid']} termination identity unobservable: "
                    f"GetProcessTimes error {ctypes.get_last_error()}"
                )
            created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
            if created != identity["creation_filetime"]:
                return
            state = self.k.WaitForSingleObject(handle, 0)
            if state == 0:
                return
            if state != 258:
                raise Setup(
                    f"PID {identity['pid']} termination liveness unobservable: {state}"
                )
            if not self.k.TerminateProcess(handle, 99):
                raise Setup(
                    f"PID {identity['pid']} TerminateProcess failed: {ctypes.get_last_error()}"
                )
            require(
                self.k.WaitForSingleObject(handle, 5000) == 0,
                f"owned PID {identity['pid']} cleanup unconfirmed",
            )
        finally:
            self.k.CloseHandle(handle)


class Owned:
    """Sample descendants only while their recorded parent identity is alive."""

    def __init__(self, process: subprocess.Popen, native: WindowsProcesses):
        self.native = native
        identity = native.identity(process.pid)
        if identity is None:
            raise Setup(f"could not record launched PID/creation: {process.pid}")
        self.records = {(identity["pid"], identity["creation_filetime"]): identity}
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.sample, daemon=True)
        self.thread.start()

    def sample_once(self) -> None:
        started = self.native.now()
        parents = self.native.snapshot()
        # Breadth-first capture permits launcher -> sidecar -> clangd in one sample.
        for _ in range(8):
            live = {r["pid"]: r for r in self.records.values() if self.native.alive(r)}
            added = False
            for pid, parent in parents.items():
                if parent not in live:
                    continue
                child = self.native.identity(pid)
                if (
                    child
                    and child["creation_filetime"] >= live[parent]["creation_filetime"]
                ):
                    # Snapshot and identity acquisition are separate system
                    # calls. A PID reused after the snapshot belongs to a
                    # process created after it started, so reject those and
                    # recheck the parent without a second costly snapshot:
                    # one cycle must fit inside a ~0.1 s analyzer lifetime.
                    if child["creation_filetime"] >= started or not self.native.alive(
                        live[parent]
                    ):
                        continue
                    key = (pid, child["creation_filetime"])
                    if key not in self.records:
                        child["parent_pid"] = parent
                        child["parent_creation_filetime"] = live[parent][
                            "creation_filetime"
                        ]
                        self.records[key] = child
                        added = True
            if not added:
                break

    def sample(self) -> None:
        try:
            while not self.stop.wait(0.005):
                self.sample_once()
        except Exception as exc:
            self.error = exc

    def finish(self, forced: bool = False) -> list[dict]:
        self.stop.set()
        self.thread.join(timeout=5)
        require(not self.thread.is_alive(), "owned process sampler did not stop")
        if isinstance(getattr(self, "error", None), Setup):
            raise Setup(f"process sampling unobservable: {self.error}")
        require(
            not hasattr(self, "error"),
            f"process sampling failed: {getattr(self, 'error', '')!r}",
        )
        if forced:
            for record in reversed(list(self.records.values())):
                self.native.terminate(record)
        return [
            {**r, "alive_after": self.native.alive(r)} for r in self.records.values()
        ]


class Evidence:
    def __init__(self, root: Path):
        if root.exists():
            raise Setup(f"evidence directory must be NEW: {root}")
        root.mkdir(parents=True)
        self.root = root
        self.native = WindowsProcesses()
        self.number = 0
        self.report = {
            "schema": "installed-code-analysis-acceptance/v1",
            "invocation": sys.argv,
            "script": file_record(Path(__file__)),
            "gates": {g: {"status": "PENDING"} for g in GATES},
            "availability_cases": {
                f"{state}-{profile}": {
                    "status": "PENDING",
                    "reason": "not exercised against this installed archive",
                }
                for state in STATES
                for profile in ("personal", "professional")
            },
            "installed_acceptance": False,
            "limitations": [
                "Preparation is not final independent installed acceptance.",
                "Python companion code is a pinned source input; native analysis bytes are installed.",
                "ARM build control validates frozen artifacts, without rebuilding mutated sources.",
                "Long source paths are unsupported; no support assertion above 259 UTF-16 units.",
                "Linux/macOS/WSL/Docker/hardware checks were not performed.",
            ],
        }

    def directory(self, name: str) -> Path:
        self.number += 1
        path = self.root / "commands" / f"{self.number:03d}-{name}"
        path.mkdir(parents=True)
        return path

    def run(
        self,
        name: str,
        argv: list[str],
        env: dict,
        cwd: Path,
        expected: int | None = 0,
        timeout: float = 150,
        *,
        setup_command: bool = False,
        cleanup_timeout: float = 5,
    ) -> subprocess.CompletedProcess:
        path = self.directory(name)
        record = {
            "argv": argv,
            "cwd": str(cwd),
            "environment": {
                k: env[k]
                for k in (
                    "PATH",
                    "BYO_HOME",
                    "AGENT_WORKSPACE_HOST_ROOT",
                    "AGENT_WORKSPACE_MODE",
                    "USERPROFILE",
                    "APPDATA",
                    "LOCALAPPDATA",
                    "TEMP",
                    "TMP",
                )
                if k in env
            },
        }
        write_json(path / "command.json", record)
        started = time.monotonic()
        with (
            (path / "stdout.log").open("wb") as out,
            (path / "stderr.log").open("wb") as err,
        ):
            process = subprocess.Popen(
                argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err
            )
            owned = Owned(process, self.native)
            forced = False
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                forced = True
            identities = owned.finish(forced)
            if forced:
                process.wait(timeout=5)
            elif not setup_command:
                cleanup_deadline = time.monotonic() + cleanup_timeout
                while (
                    any(self.native.alive(p) for p in identities)
                    and time.monotonic() < cleanup_deadline
                ):
                    time.sleep(0.1)
                for identity in identities:
                    identity["alive_at_parent_exit"] = identity["alive_after"]
                    identity["alive_after"] = self.native.alive(identity)
        record.update(
            exit=process.returncode,
            elapsed_seconds=time.monotonic() - started,
            timeout=forced,
            processes=identities,
            cleanup_timeout_seconds=cleanup_timeout,
        )
        write_json(path / "command.json", record)
        for identity in identities:
            if identity["alive_after"]:
                self.native.terminate(identity)
                identity["emergency_cleanup_confirmed"] = not self.native.alive(
                    identity
                )
        record["setup_command"] = setup_command
        write_json(path / "command.json", record)
        require(not forced, f"{name}: deadline exceeded; retained {path}")
        if setup_command:
            # MSVC may spawn its persistent vctip telemetry helper while linking
            # this fixture. Setup owns/cleans that exact child, and records the
            # cleanup. Production invocations always assert natural child exit.
            require(
                not any(self.native.alive(p) for p in identities),
                f"{name}: setup child cleanup unconfirmed",
            )
        else:
            require(
                not any(p["alive_after"] for p in identities),
                f"{name}: owned child remained alive; {path}",
            )
        result = subprocess.CompletedProcess(
            argv,
            process.returncode,
            (path / "stdout.log").read_text(encoding="utf-8", errors="replace"),
            (path / "stderr.log").read_text(encoding="utf-8", errors="replace"),
        )
        result.observed_processes = identities
        if expected is not None:
            require(
                result.returncode == expected,
                f"{name}: actual exit {result.returncode}, expected {expected}; logs: {path}",
            )
        return result

    def gate(self, name: str, action) -> bool:
        print(f"gate {name}", flush=True)
        try:
            action()
            self.report["gates"][name] = {"status": "PASS"}
            return True
        except (Red, Setup, Pending) as exc:
            status = (
                "RED"
                if isinstance(exc, Red)
                else "SETUP_FAILURE"
                if isinstance(exc, Setup)
                else "PENDING"
            )
            self.report["gates"][name] = {"status": status, "reason": str(exc)}
            print(f"{status}: {exc}", flush=True)
            return False
        except (KeyError, TypeError, ValueError, ET.ParseError) as exc:
            # Missing/wrongly typed public result fields and malformed XML/JSON
            # are product failures. Input-schema failures belong to setup.
            status = "SETUP_FAILURE" if name == "immutable-inputs" else "RED"
            self.report["gates"][name] = {"status": status, "reason": repr(exc)}
            (self.root / f"{name}-exception.log").write_text(
                traceback.format_exc(), encoding="utf-8"
            )
            print(f"{status}: {exc}", flush=True)
            return False
        except Exception as exc:
            self.report["gates"][name] = {
                "status": "SETUP_FAILURE",
                "reason": repr(exc),
            }
            (self.root / f"{name}-exception.log").write_text(
                traceback.format_exc(), encoding="utf-8"
            )
            print(f"SETUP_FAILURE: {exc}", flush=True)
            return False

    def save(self) -> int:
        states = [v["status"] for v in self.report["gates"].values()]
        self.report["installed_acceptance"] = all(s == "PASS" for s in states)
        self.report["exit"] = (
            1
            if "RED" in states
            else 2
            if "SETUP_FAILURE" in states
            else 3
            if "PENDING" in states
            else 0
        )
        write_json(self.root / "report.json", self.report)
        manifest = {
            "schema": "installed-analysis-evidence/v1",
            "files": tree_record(self.root),
        }
        write_json(self.root / "manifest.json", manifest)
        print(
            f"evidence {self.root}; manifest SHA256 {digest(self.root / 'manifest.json')}",
            flush=True,
        )
        return self.report["exit"]


def archive_gate(args, evidence: Evidence) -> dict:
    expected_cppcheck = expected_digest(args.cppcheck_sha256, "--cppcheck-sha256")
    evidence.report["expected_cppcheck_sha256"] = expected_cppcheck
    if not args.archive.is_file() or not args.bundle.is_dir():
        raise Setup(
            "actual built ZIP and expanded bundle are required; source staging is not a bundle"
        )
    if digest(args.archive) != args.archive_sha256:
        raise Setup("explicit archive SHA256 disagrees with supplied ZIP")
    manifest_path = args.bundle / "release-manifest.json"
    if not manifest_path.is_file():
        raise Setup("built bundle has no release-manifest.json")
    manifest = read_json(manifest_path)
    require(
        manifest.get("platform") == "windows"
        and manifest.get("architecture") == "x86_64",
        "release target must be windows/x86_64",
    )
    inventory = {f["path"]: f for f in manifest["files"]}
    require(
        len(inventory) == len(manifest["files"]), "duplicate release inventory entries"
    )
    require(
        len({p.casefold() for p in inventory}) == len(inventory),
        "case-colliding release inventory",
    )
    # Focused RED happens before installation, on delivered public package bytes.
    required = (
        "analysis/runtime.json",
        "analysis/cppcheck/cppcheck.exe",
        "analysis/clangd/bin/clangd.exe",
    )
    missing = [
        p for p in required if p not in inventory or not below(args.bundle, p).is_file()
    ]
    require(not missing, f"missing shipped analysis mapping/programs: {missing}")
    actual = tree_record(args.bundle)
    for relative, record in inventory.items():
        verify_file(below(args.bundle, relative), record, product=True)
    require(
        set(actual) - set(inventory)
        <= {"release-manifest.json", "release-manifest.sig"},
        "bundle contains uninventoried payload",
    )
    with zipfile.ZipFile(args.archive) as z:
        leaves = [i for i in z.infolist() if not i.is_dir()]
        names = [i.filename for i in leaves]
        require(
            len(set(n.casefold() for n in names)) == len(names),
            "ZIP duplicate/case-colliding names",
        )
        zip_files = {}
        for member in leaves:
            relative = PurePosixPath(member.filename)
            require(
                len(relative.parts) >= 2 and relative.parts[0] == args.bundle.name,
                f"ZIP root differs from supplied bundle: {member.filename}",
            )
            leaf = "/".join(relative.parts[1:])
            below(args.bundle, leaf)
            with z.open(member) as stream:
                h = hashlib.sha256()
                size = 0
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    h.update(block)
                    size += len(block)
            zip_files[leaf] = {"sha256": h.hexdigest(), "size": size}
        require(zip_files == actual, "ZIP bytes differ from the expanded bundle")
    mapping = read_json(args.bundle / "analysis/runtime.json")
    require(
        mapping.get("schema_version") == 1
        and mapping.get("platform") == "windows"
        and mapping.get("architecture") == "x86_64",
        "analysis mapping target/schema invalid",
    )
    program_identity(args.bundle, inventory, mapping, expected_cppcheck)
    for program in ("cppcheck", "clangd"):
        record = mapping["programs"][program]
        require(record["licenses"], f"{program} has no license inventory")
        for relative in [*record["licenses"], *record["dependencies"]]:
            require(
                relative in inventory and below(args.bundle, relative).is_file(),
                f"missing support/license {relative}",
            )
    for prefix in (
        "analysis/cppcheck/cfg/",
        "analysis/cppcheck/platforms/",
        "analysis/clangd/lib/clang/23/include/",
    ):
        require(
            any(p.startswith(prefix) for p in inventory),
            f"missing shipped data namespace {prefix}",
        )
    require(
        not any(
            ".cache" in PurePosixPath(p).parts
            or "compile_commands.json" in PurePosixPath(p).parts
            for p in inventory
        ),
        "release contains project analysis cache/database",
    )
    sbom = read_json(args.bundle / "sbom.cdx.json")
    for name in ("cppcheck", "clangd"):
        app = [
            c for c in sbom["components"] if c.get("bom-ref") == f"byo-analysis:{name}"
        ]
        require(
            len(app) == 1 and app[0]["version"] == mapping["programs"][name]["version"],
            f"SBOM {name} identity mismatch",
        )
    evidence.report["artifact"] = {
        "archive": str(args.archive),
        **file_record(args.archive),
        "manifest": file_record(manifest_path),
        "files": actual,
        "source": manifest.get("source"),
        "version": manifest["version"],
    }
    return manifest


def input_gate(args, evidence: Evidence, lab: Path) -> dict:
    needed = (
        "cppcheck_inputs",
        "cppcheck_source",
        "clangd_inputs",
        "clangd_root",
        "arm_fixture",
        "python_workspace",
        "python_commit",
        "rustc",
        "rustc_sha256",
    )
    missing = [name for name in needed if getattr(args, name) is None]
    if missing:
        raise Setup(f"full execution requires explicit read-only inputs: {missing}")
    if (
        digest(args.cppcheck_inputs) != CPP_INPUT_SHA
        or digest(args.clangd_inputs) != CLANG_INPUT_SHA
    ):
        raise Setup(
            "Cppcheck/clangd packaging input manifest differs from accepted pinned bytes"
        )
    cpp = read_json(args.cppcheck_inputs)
    clang = read_json(args.clangd_inputs)
    protected = {}
    for path in (args.cppcheck_inputs, args.clangd_inputs, args.rustc):
        protected[str(path)] = file_record(path)
    if digest(args.rustc) != args.rustc_sha256:
        raise Setup("existing rustc digest differs from explicit dependency identity")
    verify_file(Path(cpp["program_candidate"]["path"]), cpp["program_candidate"])
    protected[cpp["program_candidate"]["path"]] = file_record(
        Path(cpp["program_candidate"]["path"])
    )
    for item in cpp["data_and_licenses"]:
        path = below(args.cppcheck_source, item["upstream_relative_path"])
        verify_file(path, item)
        verify_file(below(args.bundle, item["runtime_path"]), item, product=True)
        protected[str(path)] = file_record(path)
    # Ship clangd, its license and resource headers. Upstream compiler-rt
    # libraries and sanitizer ignorelists are link inputs for compiled programs,
    # not clangd runtime dependencies (clangd.exe imports only system DLLs).
    clangd_payload = {
        relative
        for relative in clang["files"]
        if relative in ("bin/clangd.exe", "LICENSE.TXT")
        or relative.startswith("lib/clang/23/include/")
    }
    for relative, item in clang["files"].items():
        path = below(args.clangd_root, relative)
        verify_file(path, item)
        if relative in clangd_payload:
            verify_file(
                below(args.bundle, f"analysis/clangd/{relative}"), item, product=True
            )
        protected[str(path)] = file_record(path)
    clangd_bundle = args.bundle / "analysis/clangd"
    shipped_clangd = {
        path.relative_to(clangd_bundle).as_posix()
        for path in clangd_bundle.rglob("*")
        if not path.is_dir()
    }
    if shipped_clangd != clangd_payload:
        raise Red(
            "clangd payload differs from upstream executable, license and headers: "
            f"{sorted(shipped_clangd ^ clangd_payload)[:5]}"
        )
    arm_inventory = (
        ROOT / "launcher/tests/fixtures/cppcheck-acceptance/arm-originals.json"
    )
    if digest(arm_inventory) != ARM_INPUT_SHA:
        raise Setup("accepted ARM inventory bytes changed")
    arm = read_json(arm_inventory)
    if tree_record(args.arm_fixture) != arm["files"]:
        raise Setup("genuine ARM fixture must match all 15 accepted original files")
    elf = (args.arm_fixture / "build/firmware.elf").read_bytes()
    if elf[:5] != b"\x7fELF\x01" or int.from_bytes(elf[18:20], "little") != 40:
        raise Setup(
            "fixture must contain genuine 32-bit ARM ELF, not host-native synthetic output"
        )
    for relative, item in arm["files"].items():
        protected[str(below(args.arm_fixture, relative))] = item
    git = shutil.which("git")
    if git is None:
        raise Setup(
            "existing Git is required to bind the read-only Python source input"
        )
    git_env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0", "PYTHONDONTWRITEBYTECODE": "1"}
    commit = evidence.run(
        "python-input-commit",
        [git, "rev-parse", "HEAD"],
        git_env,
        args.python_workspace,
    ).stdout.strip()
    require(
        commit == args.python_commit,
        "Python input HEAD differs from explicit accepted commit",
    )
    recorded_source = evidence.report["artifact"]["source"].get("agent_workspace", {})
    require(
        recorded_source.get("commit") == commit
        and not recorded_source.get("dirty", False),
        "bundle workspace provenance differs from the pinned public Python source input",
    )
    status = evidence.run(
        "python-input-clean",
        [git, "status", "--porcelain", "--untracked-files=no"],
        git_env,
        args.python_workspace,
    ).stdout
    if status.strip():
        raise Setup("Python read-only input has tracked modifications")
    names = evidence.run(
        "python-input-files",
        [git, "ls-files", "bin", "internal", "modes"],
        git_env,
        args.python_workspace,
    ).stdout.splitlines()
    if "bin/verify" not in names:
        raise Setup("Python input has no public bin/verify entrypoint")
    python_copy = lab / "companion Python workspace µ"
    for relative in names:
        source = below(args.python_workspace, relative)
        protected[str(source)] = file_record(source)
        destination = below(python_copy, relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    evidence.report["read_only_inputs"] = protected
    evidence.report["python_runner"] = {
        "code_origin": "companion_source",
        "commit": commit,
        "entrypoint": "bin/verify",
        "shipping_proof": False,
    }
    return {"protected": protected, "python": python_copy, "arm": arm}


def isolated_environment(home: Path, lab: Path) -> dict:
    system = Path(os.environ["SystemRoot"])
    allowed = {
        k: v
        for k, v in os.environ.items()
        if k.upper()
        in {
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "PATHEXT",
            "NUMBER_OF_PROCESSORS",
            "PROCESSOR_ARCHITECTURE",
            "PROCESSOR_ARCHITEW6432",
            "PROGRAMDATA",
        }
    }
    allowed.update(
        BYO_HOME=str(home),
        PATH=os.pathsep.join(
            (
                str(home / "bin"),
                str(system / "System32"),
                str(system),
                str(system / "System32/WindowsPowerShell/v1.0"),
            )
        ),
        USERPROFILE=str(lab / "profile µ"),
        APPDATA=str(lab / "profile µ/roaming"),
        LOCALAPPDATA=str(lab / "profile µ/local"),
        TEMP=str(lab / "temp µ"),
        TMP=str(lab / "temp µ"),
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONUTF8="1",
        GIT_CONFIG_NOSYSTEM="1",
    )
    # Public Python verify invokes Git for change/memory-risk assessment. Only
    # that existing executable's directory is admitted, then analysis absence
    # is checked again. No ambient developer PATH is inherited.
    git = shutil.which("git")
    if git is None:
        raise Setup("public Python verification requires existing Git")
    allowed["PATH"] += os.pathsep + str(Path(git).parent)
    for key in ("USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP"):
        Path(allowed[key]).mkdir(parents=True, exist_ok=True)
    for name in ("cppcheck", "clangd"):
        if shutil.which(name, path=allowed["PATH"]):
            raise Setup(f"sanitized PATH unexpectedly resolves system {name}")
    return allowed


def copy_arm(args, lab: Path, name: str, evidence: Evidence) -> Path:
    project = lab / f"ARM {name} µ 测试"
    shutil.copytree(args.arm_fixture, project)
    old = str(args.arm_fixture)
    value = read_json(project / "build/compile_commands.json")

    def relocate(item):
        if isinstance(item, str):
            for source, dest in (
                (old.replace("\\", "\\\\"), str(project).replace("\\", "\\\\")),
                (old.replace("\\", "/"), str(project).replace("\\", "/")),
                (old.replace("/", "\\"), str(project).replace("/", "\\")),
            ):
                item = item.replace(source, dest)
            return item
        if isinstance(item, list):
            return [relocate(v) for v in item]
        if isinstance(item, dict):
            return {k: relocate(v) for k, v in item.items()}
        return item

    relocated = relocate(value)
    # The inventory records the original root. Explicit fixture may be relocated.
    original = read_json(
        ROOT / "launcher/tests/fixtures/cppcheck-acceptance/arm-originals.json"
    )["original_root"]
    if original != old:
        old = original
        relocated = relocate(relocated)
    write_json(project / "build/compile_commands.json", relocated)
    require(len(relocated) == 3, "ARM selected-build database must contain three units")
    for entry in relocated:
        args_list = entry.get("arguments", [])
        require(
            "-mcpu=cortex-m4" in args_list and "-mthumb" in args_list,
            "ARM database lacks the genuine fixture's explicit Cortex-M4/Thumb target",
        )
        require(
            any(a.startswith("-I") for a in args_list)
            and any(a.startswith("-D") for a in args_list),
            "ARM database lacks truthful include/define argv",
        )
        require(
            Path(entry["file"]).resolve().is_relative_to(project.resolve()),
            "ARM database still names a protected source outside the private project",
        )
    target_abi = ET.parse(project / "config/arm32.xml").getroot()
    require(
        target_abi.findtext("sizeof/pointer") == "4"
        and target_abi.findtext("sizeof/long") == "4",
        "ARM target ABI must use 32-bit pointers and long, not the host ABI",
    )
    for source in project.glob("src/*"):
        if len(str(source).encode("utf-16-le")) // 2 >= 260:
            raise Setup(
                f"private source path exceeds pinned Cppcheck source-path limit: {source}"
            )
    (project / ".clangd").write_text(
        "# User-owned configuration, preserve exactly.\n", encoding="utf-8"
    )
    # Firmware mode requires a project-owned .clang-format; init never creates it.
    (project / ".clang-format").write_text("BasedOnStyle: LLVM\n", encoding="utf-8")
    (project / "customer.txt").write_text("unrelated user file µ\n", encoding="utf-8")
    write_json(evidence.root / f"{name}-relocated-inputs.json", tree_record(project))
    return project


def compile_build_control(args, lab: Path, env: dict, evidence: Evidence) -> Path:
    output = lab / "build-control.exe"
    # Retain the user's existing toolchain/link PATH for this build-only command.
    # Analysis processes always receive isolated_environment instead.
    build_env = {
        **os.environ,
        "RUSTUP_AUTO_INSTALL": "0",
        "CARGO_NET_OFFLINE": "true",
        "VSCMD_SKIP_SENDTELEMETRY": "1",
    }
    evidence.run(
        "compile-arm-build-control",
        [
            str(args.rustc),
            "--edition=2021",
            "--target",
            "x86_64-pc-windows-msvc",
            str(FIXTURES / "build_control.rs"),
            "-o",
            str(output),
        ],
        build_env,
        lab,
        timeout=120,
        setup_command=True,
    )
    evidence.report["build_control"] = {
        "source": file_record(FIXTURES / "build_control.rs"),
        "executable": file_record(output),
        "purpose": "frozen ARM ELF/map validation; no firmware rebuild",
    }
    return output


def preserve_snapshot(project: Path) -> dict:
    return {
        p: file_record(project / p)
        for p in ("byo-analysis.json", ".clangd", "customer.txt")
    }


def assert_preserved(project: Path, snapshot: dict) -> None:
    for relative, item in snapshot.items():
        verify_file(project / relative, item, product=True)


def assert_runtime(runtime: Path, manifest: dict) -> None:
    for item in manifest["files"]:
        verify_file(below(runtime, item["path"]), item, product=True)


def report_once(
    evidence: Evidence,
    project: Path,
    name: str,
    command: list[str],
    env: dict,
    runtime: Path,
    target: str,
    status: str,
    process_exit: int | None,
    count: int | None,
    kind: str | None,
    cppcheck_sha256: str | None = None,
    failure_exit: int = 1,
) -> dict:
    cppcheck_sha256 = expected_digest(
        cppcheck_sha256 or evidence.report.get("expected_cppcheck_sha256"),
        "runner expected Cppcheck identity",
    )
    reports = project / ".firm/code-analysis/reports"
    before = set(reports.glob("*/result.json"))
    outcome = evidence.run(
        name, command, env, project, expected=0 if status == "pass" else failure_exit
    )
    require(
        ("VERIFY: PASS" in outcome.stdout + outcome.stderr) == (status == "pass"),
        f"{name}: final verification text disagrees with exit/state",
    )
    new = set(reports.glob("*/result.json")) - before
    require(
        len(new) == 1,
        f"{name}: expected exactly one retained static-analysis report, got {len(new)}",
    )
    result_path = new.pop()
    result = read_json(result_path)
    copied = evidence.root / "analysis-reports" / name
    shutil.copytree(result_path.parent, copied)
    require(
        result["status"] == status,
        f"{name}: analysis {result['status']} != {status}; {copied}",
    )
    if process_exit is not None:
        require(
            result["process_exit_code"] == process_exit,
            f"{name}: real analyzer exit differs from {process_exit}",
        )
        require(
            reported_path(result["executable"])
            == (runtime / "analysis/cppcheck/cppcheck.exe").resolve(),
            f"{name}: runner did not execute installed Cppcheck",
        )
        require(
            result["executable_sha256"] == cppcheck_sha256
            and result["version"] == "2.22.0",
            f"{name}: real executable/version identity differs",
        )
        require(
            result["compilation_database_sha256"]
            == digest(project / "build/compile_commands.json"),
            f"{name}: selected database digest not recorded",
        )
        require(
            reported_path(result["platform_file"])
            == (project / "config/arm32.xml").resolve(),
            f"{name}: explicit ARM ABI platform not used",
        )
        argv = result["argv"]
        require(
            read_json(copied / "argv.json") == argv,
            f"{name}: actual argv report differs",
        )
        for flag in (
            "--error-exitcode=1",
            "--xml",
            "--xml-version=2",
            "--enable=warning,performance,portability,information,missingInclude",
        ):
            require(flag in argv, f"{name}: missing required analyzer argv {flag}")
        require(
            any(a.startswith("--project=") for a in argv)
            and any(a.startswith("--platform=") for a in argv),
            f"{name}: no compilation database/platform argv",
        )
        for relative in (
            "version.stdout.log",
            "version.stderr.log",
            "analysis.stdout.log",
            "analysis.stderr.log",
            "report.xml",
            "owned-processes.json",
        ):
            require(
                (copied / relative).is_file(),
                f"{name}: missing full evidence {relative}",
            )
        xml = ET.parse(copied / "report.xml").getroot()
        require(
            xml.tag == "results" and xml.get("version") == "2",
            f"{name}: unusable real XML report",
        )
        events = result["owned_processes"]
        identities = []
        for event in events:
            if (
                isinstance(event, dict)
                and event.get("pid")
                and event.get("creation_filetime")
            ):
                identities.append(event)
        # The public Python runner currently logs PIDs without creation times.
        # Bind those PIDs to independent native descendant observations, never
        # manufacture a creation identity from a bare PID after process exit.
        observed = outcome.observed_processes
        for event in events:
            if (
                isinstance(event, dict)
                and event.get("pid")
                and not event.get("creation_filetime")
            ):
                matches = [
                    r
                    for r in observed
                    if r["pid"] == event["pid"]
                    and Path(r["image"]).resolve()
                    == reported_path(result["executable"])
                ]
                identities.extend(matches)
        require(
            identities, f"{name}: runner supplied no PID+creation ownership evidence"
        )
        for identity in identities:
            require(
                not evidence.native.alive(identity),
                f"{name}: recorded analyzer identity remains alive",
            )
        write_json(
            copied / "independent-liveness.json",
            [{**r, "alive_after": False} for r in identities],
        )
        analysis_pids = {
            e["pid"] for e in events if e.get("phase") == "analysis" and e.get("pid")
        }
        require(
            analysis_pids <= {i["pid"] for i in identities},
            f"{name}: analysis PID+creation observation incomplete; never credit bare-PID cleanup",
        )
    if count is not None:
        require(
            result["scope"]["selected_count"] == count,
            f"{name}: scope count differs from {count}",
        )
    if kind is not None:
        require(
            result["scope"]["kind"] == kind, f"{name}: scope kind differs from {kind}"
        )
    require(
        result["scope"]["requested_path"] == target,
        f"{name}: local override lost requested target",
    )
    if status == "findings_failed":
        require(
            any(d["id"] == "nullPointer" for d in result["diagnostics"]),
            f"{name}: genuine injected null dereference not found",
        )
    return result


def arm_runner(
    evidence: Evidence,
    project: Path,
    command_prefix: list[str],
    env: dict,
    runtime: Path,
    name: str,
    native: bool,
) -> None:
    source = project / "src/main.c"
    clean = source.read_bytes()
    database = file_record(project / "build/compile_commands.json")
    platform_file = file_record(project / "config/arm32.xml")
    results = []
    # The public launcher reports a failed verify as its WorkflowPolicy exit
    # category; the companion Python runner exits 1.
    failure_exit = 13 if native else 1
    try:
        for phase, data, status, code in (
            ("clean", clean, "pass", 0),
            (
                "defect",
                clean + b"\nint installed_defect(void) { int *p = 0; return *p; }\n",
                "findings_failed",
                1,
            ),
            ("restored", clean, "pass", 0),
        ):
            source.write_bytes(data)
            result = report_once(
                evidence,
                project,
                f"{name}-{phase}",
                [*command_prefix, "."],
                env,
                runtime,
                ".",
                status,
                code,
                3,
                "all",
                failure_exit=failure_exit,
            )
            if native:
                require(
                    result["executable_origin"] == "managed_runtime",
                    "Rust unexpectedly used PATH resolution",
                )
            else:
                require(
                    result["executable_origin"] == "path",
                    "companion source runner origin must be reported honestly",
                )
            results.append(result)
        for target, kind, count in (
            ("src/heartbeat.cpp", "source", 1),
            ("src", "directory", 3),
            ("include/firmware.h", "header_all", 3),
        ):
            report_once(
                evidence,
                project,
                f"{name}-scope-{kind}",
                [*command_prefix, target],
                env,
                runtime,
                target,
                "pass",
                0,
                count,
                kind,
            )
        # A defect in a different unit MUST still fail a header-scoped override.
        source.write_bytes(
            clean + b"\nint header_defect(void) { int *p = 0; return *p; }\n"
        )
        report_once(
            evidence,
            project,
            f"{name}-header-defect",
            [*command_prefix, "include/firmware.h"],
            env,
            runtime,
            "include/firmware.h",
            "findings_failed",
            1,
            3,
            "header_all",
            failure_exit=failure_exit,
        )
    finally:
        source.write_bytes(clean)
    verify_file(project / "build/compile_commands.json", database, product=True)
    verify_file(project / "config/arm32.xml", platform_file, product=True)
    write_json(
        evidence.root / f"{name}-0-1-0.json",
        {"actual_exits": [r["process_exit_code"] for r in results]},
    )


def semantic_project(lab: Path) -> Path:
    project = lab / "semantic project µ 测试"
    project.mkdir()
    (project / "src").mkdir()
    (project / "include").mkdir()
    # The non-BMP character precedes the queried symbol on the same CRLF line.
    files = {
        "include/symbols.hpp": "#pragma once\nint choose(int value);\ndouble choose(double value);\ntemplate<class T> T twice(T value) { return value + value; }\nextern int shared;\n",
        "src/symbols.cpp": '#include "symbols.hpp"\nint choose(int value) { return value + 1; }\ndouble choose(double value) { return value + 0.5; }\nint shared = 7;\n',
        "src/main.cpp": '#include "symbols.hpp"\n/* 😀 µ */ int use_int() { return choose(2) + twice(3) + shared; }\ndouble use_double() { return choose(2.0); }\n',
        "src/other.cpp": '#include "symbols.hpp"\nint use_other() { return shared; }\n',
        ".clangd": "# Keep user-owned clangd settings exactly.\n",
        "customer.txt": "user file µ\n",
    }
    for relative, text in files.items():
        below(project, relative).write_bytes(text.replace("\n", "\r\n").encode("utf-8"))
    database = [
        {
            "directory": str(project),
            "file": str(project / relative),
            "arguments": [
                "clang++",
                "--target=arm-none-eabi",
                "-std=c++17",
                "-Iinclude",
                "-c",
                relative,
            ],
        }
        for relative in ("src/main.cpp", "src/symbols.cpp", "src/other.cpp")
    ]
    write_json(project / "build/compile_commands.json", database)
    write_json(
        project / "byo-analysis.json",
        {"schema_version": 1, "compilation_database": "build/compile_commands.json"},
    )
    return project


class Mcp:
    def __init__(
        self,
        evidence: Evidence,
        byo: Path,
        project: Path,
        env: dict,
        version: str,
        label: str,
    ):
        self.evidence, self.project = evidence, project
        self.path = evidence.directory(f"mcp-{label}")
        self.argv = [str(byo), "mcp", "serve", "--project", str(project)]
        self.err = (self.path / "stderr.log").open("wb")
        self.out = (self.path / "stdout.jsonl").open("wb")
        self.requests = (self.path / "requests.jsonl").open("w", encoding="utf-8")
        self.record = {"argv": self.argv, "cwd": str(project), "PATH": env["PATH"]}
        write_json(self.path / "command.json", self.record)
        self.process = subprocess.Popen(
            self.argv,
            env=env,
            cwd=project,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.err,
        )
        self.owned = Owned(self.process, evidence.native)
        self.inbox = queue.Queue()
        self.next_id = 0
        self.closed = False
        # Validated public results per tool, retained in availability reports.
        self.results: dict[str, list] = {}
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()
        try:
            result = self.request(
                "initialize",
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "independent-installed-analysis",
                        "version": "1",
                    },
                },
            )
            require(
                result.get("serverInfo", {}).get("version") == version,
                "MCP initialization version differs from final release",
            )
            self.send(
                {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
            )
            inventory = self.request("tools/list", {})["tools"]
            tools = {t["name"]: t for t in inventory}
            for name in TOOLS:
                require(name in tools, f"installed MCP tools/list omitted {name}")
                schema = tools[name]["inputSchema"]
                require(
                    "board_id" not in schema.get("properties", {}),
                    f"{name} requires board setup",
                )
                require(
                    schema.get("additionalProperties") is False,
                    f"{name} accepts unknown argument overrides",
                )
            write_json(self.path / "tools.json", inventory)
        except Exception:
            self.close(check=False)
            raise

    def read(self) -> None:
        try:
            for line in iter(self.process.stdout.readline, b""):
                self.out.write(line)
                self.out.flush()
                try:
                    self.inbox.put(json.loads(line))
                except (ValueError, UnicodeError) as exc:
                    self.inbox.put(Red(f"non-JSON MCP stdout: {exc}"))
            self.inbox.put(Red("MCP stdout EOF before response"))
        except Exception as exc:
            self.inbox.put(Red(f"MCP stdout reader failed: {exc}"))

    def send(self, packet: dict) -> None:
        line = json.dumps(packet, ensure_ascii=False, separators=(",", ":")) + "\n"
        self.requests.write(line)
        self.requests.flush()
        self.process.stdin.write(line.encode("utf-8"))
        self.process.stdin.flush()

    def request(self, method: str, params: dict) -> dict:
        self.next_id += 1
        identifier = self.next_id
        self.send(
            {"jsonrpc": "2.0", "id": identifier, "method": method, "params": params}
        )
        deadline = time.monotonic() + 75
        while True:
            try:
                item = self.inbox.get(timeout=max(0.001, deadline - time.monotonic()))
            except queue.Empty as exc:
                raise Red(f"installed MCP {method} timed out; {self.path}") from exc
            if isinstance(item, Exception):
                raise item
            require(
                isinstance(item, dict) and item.get("jsonrpc") == "2.0",
                "invalid MCP JSON-RPC stdout",
            )
            if "id" not in item:
                continue
            require(
                item["id"] == identifier, f"unexpected MCP reply identifier: {item}"
            )
            require(
                "error" not in item, f"MCP {method} returned protocol error: {item}"
            )
            require(
                isinstance(item.get("result"), dict),
                f"MCP {method} returned malformed/missing result",
            )
            return item["result"]

    def tool(self, name: str, arguments: dict, *, analysis: bool = True) -> dict:
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        require(
            not result.get("isError"), f"{name} MCP tool execution failed: {result}"
        )
        texts = [
            b["text"] for b in result.get("content", []) if b.get("type") == "text"
        ]
        require(texts, f"{name} supplied no text result")
        try:
            value = json.loads(texts[0])
        except ValueError as exc:
            raise Red(f"{name}: analysis text block is not intact JSON") from exc
        require(
            isinstance(value, dict), f"{name}: public tool result must be a JSON object"
        )
        if analysis:
            require(value.get("status") == "ok", f"{name} nonpass response: {value}")
            require(
                value.get("backend") == "clangd", f"{name} did not use semantic backend"
            )
            require(
                reported_path(value["project_root"]) == self.project.resolve(),
                "MCP analysis used runtime cwd as project",
            )
            require(
                value["compilation_database_sha256"]
                == digest(self.project / "build/compile_commands.json"),
                "MCP analysis used another compilation database",
            )
            if "file_path" in arguments:
                source = self.project / arguments["file_path"]
                require(
                    value["source"]["sha256"] == digest(source),
                    "MCP returned a stale saved-file source hash",
                )
                require(
                    isinstance(value["source"]["document_version"], int),
                    "MCP result lacks synchronized document version",
                )
        self.results.setdefault(name, []).append(
            {"arguments": arguments, "result": value}
        )
        return value

    def record_child_argv(self, env: dict) -> None:
        observations = [
            {**r, "alive_at_argv_observation": self.evidence.native.alive(r)}
            for r in list(self.owned.records.values())
            if Path(r["image"]).name.casefold() == "clangd.exe"
        ]
        # Version probes and sessions replaced after database changes remain in
        # Owned for EOF cleanup. Only the current live session has inspectable argv.
        write_json(self.path / "clangd-argv-selection.json", observations)
        children = [r for r in observations if r["alive_at_argv_observation"]]
        require(
            children,
            "no live owned clangd PID+creation was observed; sampling gap remains RED",
        )
        powershell = (
            Path(os.environ["SystemRoot"])
            / "System32/WindowsPowerShell/v1.0/powershell.exe"
        )
        for child in children:
            require(
                self.evidence.native.alive(child),
                "owned clangd exited before argv observation",
            )
            command = (
                f"Get-CimInstance Win32_Process -Filter 'ProcessId={child['pid']}' | "
                "Select-Object ProcessId,ParentProcessId,CreationDate,ExecutablePath,CommandLine | ConvertTo-Json -Compress"
            )
            output = self.evidence.run(
                "owned-clangd-argv",
                [str(powershell), "-NoProfile", "-NonInteractive", "-Command", command],
                env,
                self.project,
            ).stdout
            value = json.loads(output)
            require(
                value
                and value.get("CommandLine")
                and value["ProcessId"] == child["pid"],
                "owned clangd actual argv unavailable",
            )
            require(
                self.evidence.native.alive(child),
                "clangd PID identity changed during argv observation",
            )
            write_json(
                self.path / f"clangd-{child['pid']}.json",
                {"identity": child, "native_observation": value},
            )

    def close(self, *, check: bool = True) -> None:
        if self.closed:
            return
        self.closed = True
        # No active request is outstanding. EOF must close the idle session child.
        if self.process.stdin and not self.process.stdin.closed:
            self.process.stdin.close()
        forced = False
        try:
            self.process.wait(timeout=25)
        except subprocess.TimeoutExpired:
            forced = True
        records = self.owned.finish(forced)
        if forced:
            self.process.wait(timeout=5)
        survivors = [r for r in records if r["alive_after"]]
        # Retain failure BEFORE emergency cleanup; cleanup never earns a PASS.
        self.record.update(
            exit=self.process.returncode, eof_timeout=forced, processes=records
        )
        write_json(self.path / "command.json", self.record)
        for record in survivors:
            self.evidence.native.terminate(record)
        self.reader.join(timeout=5)
        self.err.close()
        self.requests.close()
        if not self.reader.is_alive():
            self.out.close()
        if check:
            require(
                not forced and self.process.returncode == 0 and not survivors,
                f"stdio EOF left idle owned children or nonzero exit; {self.path}",
            )
            require(
                not self.reader.is_alive(),
                "MCP stdout reader remained after process EOF",
            )


def position(project: Path, relative: str, line: int, token: str) -> dict:
    text = (project / relative).read_text(encoding="utf-8").splitlines()[line - 1]
    return {
        "file_path": relative,
        "line": line,
        "column": text.index(token) + 1,
        "timeout_seconds": 60,
    }


def location_points(result: dict) -> set[tuple[str, int]]:
    points = set()
    for location in result["data"]["locations"]:
        require(
            location.get("position_mapping") == "available",
            "semantic location could not map to saved source positions",
        )
        points.add((Path(location["path"]).name, location["range"]["start"]["line"]))
    return points


def check_diagnostics(result: dict, *, empty: bool) -> None:
    data = result["data"]
    require(
        data["returned_count"] == len(data["diagnostics"]),
        "diagnostic returned_count disagrees",
    )
    require(
        data["observed_count"] == len(data["diagnostics"])
        and data["truncated"] is False,
        "diagnostics unexpectedly truncated",
    )
    require(
        bool(data["diagnostics"]) != empty,
        "fresh diagnostics did not reflect the current saved revision",
    )


def semantic_queries(server: Mcp, runtime: Path, env: dict, *, full: bool) -> None:
    status = server.tool("get_code_analysis_status", {})
    data = status["data"]
    require(
        data["executable_origin"] == "managed_runtime",
        "installed MCP clangd fell back to PATH",
    )
    require(
        reported_path(data["executable"])
        == (runtime / "analysis/clangd/bin/clangd.exe").resolve(),
        "installed MCP resolved another clangd executable",
    )
    # The public status reports the executable's own --version banner.
    require(
        (data["version"] or "").split()[:3] == ["clangd", "version", "23.1.0"],
        "installed clangd version disagrees with pinned input",
    )
    main = "src/main.cpp"
    query = position(server.project, main, 2, "choose")
    definition = server.tool("find_code_definition", query)
    require(
        location_points(definition) & {("symbols.hpp", 2), ("symbols.cpp", 2)},
        "int overload resolves to wrong declaration/definition",
    )
    hover = server.tool("get_code_hover", query)
    require(
        "choose" in hover["data"]["contents"]["value"]
        and "int" in hover["data"]["contents"]["value"],
        "hover does not identify the selected overload",
    )
    # Warm both files through genuine queries, then await bounded background index.
    server.tool(
        "get_code_hover", position(server.project, "src/other.cpp", 2, "shared")
    )
    ref_args = {
        **position(server.project, main, 2, "shared"),
        "include_declaration": True,
        "max_results": 100,
    }
    deadline = time.monotonic() + 45
    while True:
        refs = server.tool("find_code_references", ref_args)
        points = location_points(refs)
        if {("main.cpp", 2), ("other.cpp", 2)} <= points:
            break
        require(
            time.monotonic() < deadline,
            f"genuine cross-file references missing: {points}",
        )
        time.sleep(0.3)
    require(
        refs["index_completeness"] == "unverified",
        "references overclaim global completeness",
    )
    require(
        refs["data"]["returned_count"] == len(refs["data"]["locations"])
        and not refs["data"]["truncated"],
        "reference counts/truncation disagree",
    )
    clean = server.tool(
        "get_code_diagnostics", {"file_path": main, "timeout_seconds": 60}
    )
    check_diagnostics(clean, empty=True)
    if full:
        double = server.tool(
            "find_code_definition", position(server.project, main, 3, "choose")
        )
        require(
            location_points(double) & {("symbols.hpp", 3), ("symbols.cpp", 3)},
            "double overload resolves to int overload",
        )
        template = server.tool(
            "find_code_definition", position(server.project, main, 2, "twice")
        )
        require(
            ("symbols.hpp", 4) in location_points(template),
            "template definition not resolved",
        )
        # Exact code-point positions AFTER non-BMP on CRLF lines (not just lines).
        main_position = position(server.project, main, 2, "shared")
        main_locations = [
            location
            for location in refs["data"]["locations"]
            if reported_path(location["path"]) == (server.project / main).resolve()
        ]
        require(
            any(
                location["range"]["start"]
                == {"line": 2, "column": main_position["column"]}
                and location["range"]["end"]
                == {"line": 2, "column": main_position["column"] + len("shared")}
                for location in main_locations
            ),
            "returned CRLF/non-BMP code-point range differs",
        )
        source = server.project / main
        original = source.read_bytes()
        try:
            source.write_bytes(
                original.replace(b"choose(2)", b"unknown_saved_symbol(2)")
            )
            bad = server.tool(
                "get_code_diagnostics", {"file_path": main, "timeout_seconds": 60}
            )
            check_diagnostics(bad, empty=False)
            require(
                any(
                    "unknown_saved_symbol" in d["message"]
                    for d in bad["data"]["diagnostics"]
                ),
                "saved-file defect was not diagnosed",
            )
            require(
                bad["source"]["document_version"] > clean["source"]["document_version"],
                "saved change reused old document version",
            )
            source.write_bytes(original)
            restored = server.tool(
                "get_code_diagnostics", {"file_path": main, "timeout_seconds": 60}
            )
            check_diagnostics(restored, empty=True)
            require(
                restored["source"]["document_version"]
                > bad["source"]["document_version"],
                "restored empty diagnostics reused stale revision",
            )
            # The independently known empty file must produce genuine versioned zero.
            empty = server.project / "src/empty.cpp"
            empty.write_bytes(b"// genuinely empty saved translation unit\r\n")
            database = server.project / "build/compile_commands.json"
            commands = read_json(database)
            commands.append(
                {
                    "directory": str(server.project),
                    "file": str(empty),
                    "arguments": [
                        "clang++",
                        "--target=arm-none-eabi",
                        "-c",
                        "src/empty.cpp",
                    ],
                }
            )
            original_db = database.read_bytes()
            try:
                write_json(database, commands)
                blank = server.tool(
                    "get_code_diagnostics",
                    {"file_path": "src/empty.cpp", "timeout_seconds": 60},
                )
                check_diagnostics(blank, empty=True)
            finally:
                database.write_bytes(original_db)
                empty.unlink()
            changed_hover = server.tool("get_code_hover", query)
            require(
                "choose" in changed_hover["data"]["contents"]["value"],
                "saved-file recovery left stale semantic session",
            )
        finally:
            source.write_bytes(original)
    # Leave the process idle with a completed request, observe real child argv,
    # then close stdio. There is no requirement for an automatic idle timer.
    time.sleep(0.5)
    server.record_child_argv(env)


AVAILABILITY_SCHEMA = "installed-analysis-availability/v3"
VARIANTS = {"revoked_unvalidated": ("revoked", "unvalidated")}
# Independent stdlib copy of the accepted server's persisted-authority denylist
# (firmstore/store.py PERSISTED_AUTHORITY_KEYS at server ade75ef2).
AUTHORITY_KEYS = frozenset(
    {
        "active_gate",
        "active_permission",
        "active_plan",
        "gate",
        "gate_open",
        "gate_state",
        "gates",
        "permission",
        "permission_grant",
        "permission_state",
        "permissions",
        "plan",
        "plan_grant",
        "plans",
        "remaining_calls",
        "unlocked_tools",
    }
)
ATTACHMENTS = ".firm/cache/attachments.json"


def canonical_digest(value) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def is_hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(c in "0123456789abcdef" for c in value)
    )


def absolute_timestamp(value: object, field: str) -> None:
    from datetime import datetime

    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise Setup(f"attachment {field} is not an absolute timestamp") from exc
    if not isinstance(value, str) or parsed.utcoffset() is None:
        raise Setup(f"attachment {field} must carry an explicit timezone")


def no_authority(value, location: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).strip().lower().replace("-", "_") in AUTHORITY_KEYS:
                raise Setup(f"{location} persists run-scoped authority {key!r}")
            no_authority(item, f"{location}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            no_authority(item, f"{location}[{index}]")


def attachment_records(raw: bytes) -> list[dict]:
    """Accepted AttachmentCache.load_records schema/semantics, reimplemented."""
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise Setup(f"attachment cache is malformed: {exc}") from exc
    no_authority(document, "attachment cache")
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != 1
        or set(document) != {"schema_version", "records"}
        or not isinstance(document["records"], list)
    ):
        raise Setup("attachment cache must be schema_version 1 with only records")
    fields = {
        "board_id",
        "probe_family",
        "probe_usb_serial",
        "uart_usb_serial",
        "uart_vid",
        "uart_pid",
        "confirmed",
        "confirmed_at",
        "revoked_at",
    }
    for record in document["records"]:
        if not isinstance(record, dict) or not set(record) <= fields:
            raise Setup("attachment record has unknown fields")
        if (fields - {"revoked_at"}) - set(record):
            raise Setup("attachment record misses required fields")
        board = record["board_id"]
        if (
            not isinstance(board, str)
            or not board
            or len(board) > 64
            or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_" for c in board)
        ):
            raise Setup("attachment record board_id is invalid")
        for field in ("probe_family", "probe_usb_serial", "uart_usb_serial"):
            if not isinstance(record[field], str) or not record[field].strip():
                raise Setup(f"attachment {field} is not a stable identity")
        for field in ("uart_vid", "uart_pid"):
            value = record[field]
            if type(value) is not int or not 0 <= value <= 0xFFFF:
                raise Setup(f"attachment {field} is not a USB identifier")
        if type(record["confirmed"]) is not bool:
            raise Setup("attachment confirmed must be boolean")
        absolute_timestamp(record["confirmed_at"], "confirmed_at")
        revoked = record.get("revoked_at")
        if revoked is not None:
            absolute_timestamp(revoked, "revoked_at")
        if record["confirmed"] == (revoked is not None):
            raise Setup(
                "confirmed records must not have revoked_at; unconfirmed records need revoked_at"
            )
    return document["records"]


# Exact accepted snapshot procedure: the only full/lite snapshots these passive
# fixtures may carry are the ones accepted server ade75ef2 validated through
# CapabilityPolicyRepository.commit (SafetyMapDocument schema, semantic profile
# digest, lite normalization) when generating the committed manifest; see its
# generation_receipt. Canonical digests of (profile, map) / lite map. Structural
# links are also checked independently below; no product API runs here.
# The independently accepted manifest is SHA256
# 606e37a51e17a765b1e8042204fe5ee56758e478b6eccb39f767adf606b0b734.
# Its setup_full/unvalidated and historical revoked snapshots share the full
# pair; revoked's current no-setup generation has null snapshots. setup_lite
# uses the lite digest. New snapshots need independent validation and new pins.
# These pins also independently match the handwritten accepted source fixtures
# tests/tiered_acceptance_fixtures/legacy_full_v2.json (profile/memory_map) and
# lite_confirmation.json (board_id="lite_board", regions/flash); they are not
# learned from the candidate manifest at validation time.
ACCEPTED_FULL_SNAPSHOTS = {
    (
        "d66e62f266d2c2f1be3c51efbc4e127fac3da51da7630751656eb7c16f197c40",
        "8b6862503f7abe05e260a6a2d3e76743d2f0f4fefdab0b63c9702c476756e5d1",
    )
}
ACCEPTED_LITE_MAPS = {
    "ff3d4c987d3acca37d05ab81b277d5a9d9d6b84aa16ddf6bb49abed9ac51bc3a"
}


def check_snapshots(board: str, tier: str, profile, memory_map) -> None:
    """Accepted _validate_full/_validate_lite_snapshot links plus exact binding."""
    if tier == "no-setup":
        if profile is not None or memory_map is not None:
            raise Setup("no-setup policy carries an active profile or map snapshot")
        return
    if not isinstance(memory_map, dict):
        raise Setup(f"{tier} policy map snapshot is not an object")
    if memory_map.get("board_id") != board:
        raise Setup(f"{tier} policy map snapshot names another board")
    if tier == "setup-lite":
        if profile is not None:
            raise Setup("setup-lite passive fixture carries an unvalidated profile")
        if set(memory_map) not in (
            {"board_id", "regions", "flash"},
            {"board_id", "regions", "flash", "recovery"},
        ):
            raise Setup("setup-lite map snapshot fields are invalid")
        if canonical_digest(memory_map) not in ACCEPTED_LITE_MAPS:
            raise Setup("setup-lite map snapshot is not an accepted validated snapshot")
        return
    if not isinstance(profile, dict):
        raise Setup("setup-full policy profile snapshot is not an object")
    identity, sources = memory_map.get("identity"), memory_map.get("source_digests")
    if (
        type(profile.get("schema_version")) is not int
        or profile["schema_version"] != 2
        or profile.get("board_id") != board
        or profile.get("safety_ref") != f".firm/safety/{board}/memory_map.yaml"
    ):
        raise Setup("setup-full profile snapshot is not this board's schema-v2 profile")
    if type(memory_map.get("schema_version")) is not int or memory_map[
        "schema_version"
    ] not in (2, 3):
        raise Setup("setup-full map snapshot has an unsupported authority schema")
    if (
        not isinstance(identity, dict)
        or identity.get("mcu_part_number") != profile.get("mcu_part_number")
        or identity.get("pyocd_target") != profile.get("pyocd_target")
        or not isinstance(identity.get("pyocd_target"), str)
    ):
        raise Setup("setup-full profile/map target identity is contradictory")
    if not isinstance(sources, dict) or not is_hex(sources.get("semantic_profile"), 64):
        raise Setup("setup-full map lacks its semantic profile digest link")
    if (canonical_digest(profile), canonical_digest(memory_map)) not in (
        ACCEPTED_FULL_SNAPSHOTS
    ):
        raise Setup("setup-full snapshots are not an accepted validated snapshot pair")


def policy_state(board: str, files: dict, data: dict) -> dict:
    """Independently validate the passive pointer/generation (accepted v1 contract)."""
    prefix = f".firm/capabilities/{board}/"
    pointer_path = prefix + "current.json"
    if pointer_path not in files:
        raise Setup("named board lacks its passive policy pointer")
    try:
        pointer = json.loads(data[pointer_path].decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise Setup(f"policy pointer is malformed: {exc}") from exc
    if not isinstance(pointer, dict) or set(pointer) != {
        "schema_version",
        "board_id",
        "generation_id",
        "generation_digest",
    }:
        raise Setup("policy pointer fields are invalid")
    if pointer["schema_version"] != 1 or pointer["board_id"] != board:
        raise Setup("policy pointer names another board or schema")
    if not is_hex(pointer["generation_id"], 32):
        raise Setup("policy pointer generation id is invalid")
    generation_path = f"{prefix}generations/{pointer['generation_id']}.json"
    if generation_path not in files:
        raise Setup("committed policy generation is absent from the fixture")
    raw = data[generation_path]
    if hashlib.sha256(raw).hexdigest() != pointer["generation_digest"]:
        raise Setup("policy generation bytes differ from the pointer digest")
    document = json.loads(raw.decode("utf-8"))
    keys = {
        "schema_version",
        "board_id",
        "tier",
        "setup_incomplete",
        "profile_snapshot",
        "map_snapshot",
        "evidence",
        "retained_generations",
        "legacy_migrated",
        "policy_digest",
    }
    if not isinstance(document, dict) or set(document) != keys:
        raise Setup("policy generation fields are invalid")
    if document["schema_version"] != 1 or document["board_id"] != board:
        raise Setup("policy generation names another board or schema")
    material = {k: v for k, v in document.items() if k != "policy_digest"}
    if document["policy_digest"] != canonical_digest(material):
        raise Setup("policy digest does not match its generation")
    tier = document["tier"]
    if tier not in ("no-setup", "setup-lite", "setup-full"):
        raise Setup("policy tier is invalid")
    if (
        type(document["setup_incomplete"]) is not bool
        or type(document["legacy_migrated"]) is not bool
        or document["legacy_migrated"]
    ):
        raise Setup("policy flags are not JSON booleans or are migrated")
    check_snapshots(board, tier, document["profile_snapshot"], document["map_snapshot"])
    if not isinstance(document["retained_generations"], list) or not all(
        is_hex(item, 32) for item in document["retained_generations"]
    ):
        raise Setup("policy retained generations are malformed")
    return {
        "tier": tier,
        "policy_status": "setup-incomplete"
        if document["setup_incomplete"]
        else "committed",
        "setup_incomplete": document["setup_incomplete"],
        "policy_digest": document["policy_digest"],
    }


def expected_identity(tier: str | None) -> dict | None:
    if tier is None:
        return {"assertion": None, "capability": None}
    if tier == "setup-full":
        # No live connection: public discovery cannot prove identity.
        return {
            "assertion": "not-asserted",
            "capability": None,
            "proof_required": "exact-or-compatible",
        }
    if tier == "setup-lite":
        return {"assertion": "trusted-not-proven", "capability": None}
    return {"assertion": "not-asserted", "capability": None}


def check_passive_case(case: dict) -> dict:
    """Derive expected public values from validated fixture BYTES, never labels."""
    board = case.get("board_id")
    if (
        not isinstance(board, str)
        or not 1 <= len(board) <= 64
        or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_" for c in board)
    ):
        raise Setup("availability board_id must be a real safe board identifier")
    files = case.get("files")
    if not isinstance(files, dict) or any(
        not isinstance(p, str) or not p.startswith(".firm/") for p in files
    ):
        raise Setup("availability inputs must contain only passive .firm fixture files")
    state, variant = case.get("state"), case.get("variant")
    if variant not in VARIANTS.get(state, (None,)):
        raise Setup(f"unrecognized variant {variant!r} for state {state!r}")
    if state == "no_board":
        if files:
            raise Setup("no-board case cannot contain board/policy fixtures")
        return {
            "tier": "no-setup",
            "policy_status": "committed",
            "setup_incomplete": False,
            "policy_digest": None,
            "identity": expected_identity("no-setup"),
            "attachment": None,
        }
    allowed = (f".firm/capabilities/{board}/", ATTACHMENTS)
    unrelated = [p for p in files if not p.startswith(allowed)]
    if unrelated:
        raise Setup(f"unrelated fixture files cannot establish state: {unrelated}")
    data = case.get("data")
    if not isinstance(data, dict) or set(data) != set(files):
        raise Setup("passive fixture bytes do not match the declared file set")
    for relative, record in files.items():
        below(Path("."), relative)
        raw = data[relative]
        if not isinstance(raw, bytes) or {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
        } != {"sha256": record.get("sha256"), "size": record.get("size")}:
            raise Setup(f"passive fixture bytes differ from their record: {relative}")
    if state == "corrupt_policy":
        # Only an ACTUAL undecodable pointer is a corruption the product must
        # report; an absent pointer is a fresh no-setup board, not corruption.
        pointer_path = f".firm/capabilities/{board}/current.json"
        if set(files) != {pointer_path}:
            raise Setup(
                "corrupt_policy fixture must hold exactly its malformed pointer"
            )
        try:
            json.loads(data[pointer_path].decode("utf-8"))
        except (UnicodeError, ValueError):
            pass
        else:
            raise Setup("corrupt_policy fixture needs an undecodable policy pointer")
        return {
            "tier": None,
            "policy_status": "corrupt",
            "setup_incomplete": False,
            "policy_digest": None,
            "identity": expected_identity(None),
            "attachment": None,
        }
    try:
        expected = policy_state(board, files, data)
    except (ValueError, KeyError, TypeError) as exc:
        raise Setup(f"passive policy is malformed: {exc!r}") from exc
    attachment = None
    if ATTACHMENTS in files:
        records = attachment_records(data[ATTACHMENTS])
        mine = [r for r in records if r["board_id"] == board]
        if variant != "revoked":
            raise Setup("only the revoked variant may carry attachment cache state")
        if not mine or any(r["confirmed"] for r in mine):
            raise Setup("revoked variant needs only unconfirmed records for this board")
        attachment = mine
    tier, incomplete = expected["tier"], expected["setup_incomplete"]
    required = {
        "no_setup": tier == "no-setup" and not incomplete,
        "setup_lite": tier == "setup-lite" and not incomplete,
        "setup_full": tier == "setup-full" and not incomplete,
        "revoked_unvalidated": attachment is not None
        if variant == "revoked"
        else tier == "setup-full" and attachment is None,
    }[state]
    if not required:
        raise Setup(
            f"validated fixture ({tier}, setup_incomplete={incomplete}, "
            f"revoked_attachment={attachment is not None}) is not {state}/{variant}"
        )
    return {**expected, "identity": expected_identity(tier), "attachment": attachment}


def check_availability_witnesses(
    case: dict, expected: dict, health: dict, capabilities: dict
) -> None:
    """Compare real public values with the fixture-derived expectation.

    Every witness key must be explicitly present (a valid null is explicit) and
    compare with exact JSON types, so 0 never stands in for false.
    """
    expected_profile = {"personal": "enabled", "professional": "not_built"}[
        case["profile"]
    ]
    require(
        isinstance(health, dict)
        and "narrative_logging" in health
        and strict_equal(health["narrative_logging"], expected_profile),
        f"compiled profile witness mismatch: narrative_logging={health.get('narrative_logging')!r}"
        if isinstance(health, dict)
        else "health witness is not an object",
    )
    require(isinstance(capabilities, dict), "capabilities witness is not an object")
    fields = (
        "board_id",
        "tier",
        "policy_status",
        "setup_incomplete",
        "policy_digest",
        "identity",
    )
    missing = [field for field in fields if field not in capabilities]
    require(not missing, f"public witness omits required keys: {missing}")
    require(
        strict_equal(capabilities["board_id"], case["board_id"]),
        "public witness names a different board",
    )
    require(
        type(capabilities["setup_incomplete"]) is bool,
        f"public setup_incomplete is not a JSON boolean: {capabilities['setup_incomplete']!r}",
    )
    for field in ("tier", "policy_status", "setup_incomplete"):
        require(
            strict_equal(capabilities[field], expected[field]),
            f"public {field} witness mismatch: {capabilities[field]!r} != {expected[field]!r}",
        )
    actual_digest = capabilities["policy_digest"]
    if expected["policy_digest"] is None:
        require(
            expected["tier"] is None
            and actual_digest is None
            or expected["tier"] is not None
            and is_hex(actual_digest, 64),
            "public policy digest witness is invalid",
        )
    else:
        require(
            strict_equal(actual_digest, expected["policy_digest"]),
            "public policy digest differs from the passive generation",
        )
    require(
        strict_equal(capabilities["identity"], expected["identity"]),
        f"public identity witness mismatch: {capabilities['identity']!r}",
    )


def strict_equal(actual, expected) -> bool:
    """JSON equality with exact types (bool is not int, dict keys must match)."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            strict_equal(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            strict_equal(a, e) for a, e in zip(actual, expected)
        )
    return actual == expected


def check_tool_coverage(results: dict) -> None:
    missing = [name for name in TOOLS if not results.get(name)]
    require(not missing, f"availability case did not exercise tools: {missing}")


def case_label(case: dict) -> str:
    variant = case.get("variant")
    return "-".join(
        part for part in (case["state"], variant, case["profile"]) if part is not None
    )


def load_availability_inputs(path: Path, sha256: str) -> list[dict]:
    if digest(path) != sha256:
        raise Setup("availability input manifest differs from explicit digest")
    try:
        inputs = json.loads(path.read_bytes().decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise Setup(f"availability input manifest is malformed: {exc}") from exc
    return parse_availability_inputs(inputs)


def parse_availability_inputs(inputs) -> list[dict]:
    """Resolve the v3 manifest: exact base64 passive bytes plus case claims."""
    import base64
    import binascii

    if not isinstance(inputs, dict) or inputs.get("schema") != AVAILABILITY_SCHEMA:
        raise Setup(f"availability inputs must use {AVAILABILITY_SCHEMA}")
    if not set(inputs) <= {"schema", "generation_receipt", "fixtures", "cases"}:
        raise Setup("availability manifest has unrecognized fields")
    fixtures = inputs.get("fixtures")
    if not isinstance(fixtures, dict):
        raise Setup("availability manifest needs a fixtures object")
    decoded = {}
    for name, entries in fixtures.items():
        if not isinstance(entries, dict):
            raise Setup(f"availability fixture {name!r} is not a file map")
        files, data = {}, {}
        for relative, entry in entries.items():
            if not isinstance(entry, dict) or set(entry) != {
                "sha256",
                "size",
                "base64",
            }:
                raise Setup(f"fixture file record is invalid: {name}/{relative}")
            try:
                raw = base64.b64decode(entry["base64"], validate=True)
            except (binascii.Error, TypeError, ValueError) as exc:
                raise Setup(f"fixture bytes are not base64: {name}/{relative}") from exc
            files[relative] = {"sha256": entry["sha256"], "size": entry["size"]}
            data[relative] = raw
        decoded[name] = (files, data)
    cases = inputs.get("cases")
    if not isinstance(cases, list) or not cases:
        raise Setup("availability inputs need a non-empty case list")
    seen = set()
    resolved = []
    for case in cases:
        if not isinstance(case, dict) or set(case) != {
            "state",
            "variant",
            "profile",
            "board_id",
            "fixture",
        }:
            raise Setup("availability case has missing or unrecognized fields")
        state, variant, profile = case["state"], case["variant"], case["profile"]
        if state not in STATES or profile not in ("personal", "professional"):
            raise Setup(
                f"unrecognized availability state/profile {state!r}/{profile!r}"
            )
        if variant not in VARIANTS.get(state, (None,)):
            raise Setup(f"unrecognized variant {variant!r} for state {state!r}")
        key = (state, variant, profile)
        if key in seen:
            raise Setup(f"duplicate availability case {key}")
        seen.add(key)
        if case["fixture"] not in decoded:
            raise Setup(
                f"availability case names an absent fixture {case['fixture']!r}"
            )
        files, data = decoded[case["fixture"]]
        resolved.append({**case, "files": dict(files), "data": dict(data)})
    return resolved


def group_status(state: str, variants: dict) -> dict:
    """A revoked_unvalidated group earns credit only from both variant reports."""
    needed = VARIANTS.get(state, (None,))
    statuses = [variants.get(v, {}).get("status", "PENDING") for v in needed]
    for status in ("RED", "SETUP_FAILURE", "PENDING"):
        if status in statuses:
            missing = [v for v in needed if v not in variants]
            return {
                "status": status,
                "reason": f"variants {dict(zip(needed, statuses))}; missing {missing}"
                if state in VARIANTS
                else variants.get(None, {}).get("reason", "not exercised"),
                "variants": variants,
            }
    return {"status": "PASS", "variants": variants}


def availability_gate(
    args,
    evidence: Evidence,
    lab: Path,
    base_project: Path,
    byo: Path,
    env: dict,
    runtime: Path,
    version: str,
) -> None:
    results = evidence.report["availability_cases"]
    if args.availability_inputs is None or args.availability_sha256 is None:
        # A fresh public server with no policy/board fixture is real no-board
        # evidence. Other pairs remain pending, without preventing this call.
        cases = [
            {
                "state": "no_board",
                "variant": None,
                "profile": args.installed_profile,
                "board_id": "installed_no_board",
                "fixture": None,
                "files": {},
                "data": {},
                "manifest": None,
            }
        ]
    else:
        manifest = (args.availability_inputs, file_record(args.availability_inputs))
        cases = [
            {**case, "manifest": manifest}
            for case in load_availability_inputs(
                args.availability_inputs, args.availability_sha256
            )
        ]
        evidence.report["availability_inputs"] = file_record(args.availability_inputs)
        evidence.report["read_only_inputs"][str(args.availability_inputs)] = (
            file_record(args.availability_inputs)
        )
    observed: dict[str, dict] = {}
    for case in cases:
        group = f"{case['state']}-{case['profile']}"
        variants = observed.setdefault(group, {})
        if case["profile"] != args.installed_profile:
            variants[case["variant"]] = {
                "status": "PENDING",
                "reason": "requires a separate compiled archive and invocation for this profile",
            }
            continue
        label = case_label(case)
        try:
            availability_case(
                case, evidence, lab, base_project, byo, env, runtime, version
            )
        except (Red, Setup, Pending, KeyError, TypeError, ValueError) as exc:
            variants[case["variant"]] = {
                "status": "PENDING"
                if isinstance(exc, Pending)
                else "SETUP_FAILURE"
                if isinstance(exc, Setup)
                else "RED",
                "reason": str(exc),
                "evidence": str(evidence.root / f"availability-{label}.json"),
            }
        else:
            variants[case["variant"]] = {
                "status": "PASS",
                "evidence": str(evidence.root / f"availability-{label}.json"),
            }
    for group, variants in observed.items():
        results[group] = group_status(group.rsplit("-", 1)[0], variants)
    statuses = [r["status"] for r in results.values()]
    for status, error in (("RED", Red), ("SETUP_FAILURE", Setup), ("PENDING", Pending)):
        if status in statuses:
            raise error(
                f"availability pairs remain {status}; see availability_cases for individual observed credit"
            )


def availability_case(case, evidence, lab, base_project, byo, env, runtime, version):
    label = case_label(case)
    # Validate passive bytes before any server launch; labels are not evidence.
    expected = check_passive_case(case)
    project = lab / f"availability {label} µ"
    shutil.copytree(
        base_project,
        project,
        ignore=shutil.ignore_patterns(
            ".firm",
            ".agent-workspace",
            ".generated",
            ".agents",
            ".claude",
            ".codex",
            ".mcp.json",
            "AGENTS.md",
            "CLAUDE.md",
        ),
    )
    # Relocate every compile command explicitly into the private project.
    commands = read_json(project / "build/compile_commands.json")
    for command in commands:
        command["directory"] = str(project)
        command["file"] = str(project / "src" / Path(command["file"]).name)
    write_json(project / "build/compile_commands.json", commands)
    evidence.run(
        f"init-{label}", [str(byo), "init", "--project", str(project)], env, lab
    )
    for relative in case["files"]:
        target = below(project, relative)
        require(
            not target.exists(),
            f"public init pre-created passive fixture path {relative}",
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(case["data"][relative])
    protected = {p: file_record(below(project, p)) for p in case["files"]}
    require(
        protected == {p: dict(r) for p, r in case["files"].items()},
        "copied passive bytes differ from the fixture manifest",
    )
    report_path = evidence.root / f"availability-{label}.json"
    record = {
        "case": {k: case[k] for k in ("state", "variant", "profile", "board_id")},
        "fixture": case["fixture"],
        "manifest": None
        if case["manifest"] is None
        else {"path": str(case["manifest"][0]), **case["manifest"][1]},
        "expected_from_fixture": expected,
        "fixture_files": case["files"],
        "archive_sha256": evidence.report["artifact"]["sha256"],
        "source": evidence.report["artifact"]["source"],
        "sidecar": file_record(runtime / "sidecar/byo-mcp-sidecar.exe"),
        "installed_credit": False,
    }
    server = Mcp(evidence, byo, project, env, version, label)
    try:
        health = server.tool("server_health_check", {}, analysis=False)
        capabilities = server.tool(
            "get_capabilities", {"board_id": case["board_id"]}, analysis=False
        )
        record["public_witnesses"] = {
            "server_health_check": health,
            "get_capabilities": capabilities,
        }
        write_json(report_path, record)
        check_availability_witnesses(case, expected, health, capabilities)
        try:
            semantic_queries(server, runtime, env, full=False)
        finally:
            record["tool_results"] = {n: server.results.get(n, []) for n in TOOLS}
            write_json(report_path, record)
        check_tool_coverage(server.results)
    finally:
        server.close()
    # Protected bytes are rechecked in the private project AND the read-only manifest.
    for relative, item in protected.items():
        verify_file(below(project, relative), item, product=True)
    if case["manifest"] is not None:
        verify_file(*case["manifest"])
    record["preserved"] = protected
    record["installed_credit"] = True
    write_json(report_path, record)


def negative_runtime_gate(
    evidence: Evidence,
    runtime: Path,
    rust_project: Path,
    python_project: Path,
    rust_command: list[str],
    python_command: list[str],
    env: dict,
    python_env: dict,
) -> None:
    for label, affected in (
        ("missing-data", runtime / "analysis/cppcheck/cfg/std.cfg"),
        ("corrupt-version-program", runtime / "analysis/cppcheck/cppcheck.exe"),
    ):
        backup = affected.with_name(affected.name + ".acceptance-backup")
        require(affected.is_file(), f"negative control prerequisite absent: {affected}")
        affected.rename(backup)
        try:
            if label == "corrupt-version-program":
                # Real shipped clangd answers --version with an incompatible
                # program identity. No successful fake analyzer is involved.
                shutil.copy2(runtime / "analysis/clangd/bin/clangd.exe", affected)
            for runner, project, command, selected_env in (
                ("rust", rust_project, rust_command, env),
                ("python", python_project, python_command, python_env),
            ):
                before = set(
                    (project / ".firm/code-analysis/reports").glob("*/result.json")
                )
                outcome = evidence.run(
                    f"negative-{runner}-{label}",
                    [*command, "."],
                    selected_env,
                    project,
                    expected=None,
                )
                require(
                    outcome.returncode != 0
                    and "VERIFY: PASS" not in outcome.stdout + outcome.stderr,
                    f"{runner} passed with {label}",
                )
                paths = (
                    set((project / ".firm/code-analysis/reports").glob("*/result.json"))
                    - before
                )
                for result_path in paths:
                    result = read_json(result_path)
                    require(
                        result["status"] != "pass",
                        f"{runner} static report passed with {label}",
                    )
                    shutil.copytree(
                        result_path.parent,
                        evidence.root
                        / "analysis-reports"
                        / f"negative-{runner}-{label}",
                    )
                if runner == "rust" and not paths:
                    # A verified install can reject mutated inventory before
                    # verify. Record that boundary; it is nonpass, not analyzer
                    # version-probe evidence.
                    write_json(
                        evidence.root / f"negative-{runner}-{label}.json",
                        {
                            "exit": outcome.returncode,
                            "boundary": "launcher-integrity-rejection-before-static-report",
                        },
                    )
                else:
                    require(
                        len(paths) == 1,
                        f"{runner}: negative control lacks a retained static result",
                    )
        finally:
            if affected.exists():
                affected.unlink()
            backup.rename(affected)


def doctor_gate(
    evidence: Evidence, byo: Path, project: Path, env: dict, runtime: Path
) -> None:
    doctor = evidence.run(
        "doctor-analysis", [str(byo), "doctor", "--global", "--json"], env, project
    )
    json.loads(doctor.stdout)
    status = evidence.run(
        "status-analysis", [str(byo), "status", "--project", str(project)], env, project
    )
    # Require public diagnostics to name managed analysis and supporting data;
    # release manifest presence alone is insufficient doctor/status evidence.
    for label, output in (
        ("doctor", doctor.stdout + doctor.stderr),
        ("status", status.stdout + status.stderr),
    ):
        for token in ("cppcheck", "clangd", "cfg", "platforms"):
            require(
                token in output.casefold(),
                f"{label} does not identify managed analysis/data: {token}",
            )
    reports = list((evidence.root / "analysis-reports").glob("rust-*/result.json"))
    require(reports, "no installed public verify report to inspect")
    result = read_json(reports[0])
    for field in (
        "runtime_root",
        "runtime_manifest_sha256",
        "analysis_mapping_sha256",
        "data_paths",
    ):
        require(
            result.get(field),
            f"installed static report does not identify managed data: {field}",
        )
    require(
        reported_path(result["runtime_root"]) == runtime.resolve(),
        "static report managed root differs",
    )


def availability_contract_checks(check, path: Path, sha256: str, scratch: Path) -> dict:
    """Passive-state/public-witness negatives over the real v3 fixture bytes."""
    import copy

    cases = load_availability_inputs(path, sha256)
    by_label = {case_label(c): c for c in cases}
    expected = {}
    for label, case in by_label.items():
        check(
            f"fixture-{label}",
            lambda c=case, n=label: expected.update({n: check_passive_case(c)}),
        )

    def record_of(raw: bytes) -> dict:
        return {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}

    def edited(label, relative, change=None, *, drop=False):
        case = copy.deepcopy(by_label[label])
        if drop:
            case["files"].pop(relative)
            case["data"].pop(relative)
        else:
            raw = change(case["data"].get(relative))
            case["data"][relative] = raw
            case["files"][relative] = record_of(raw)
        return case

    def cache(transform):
        def change(raw):
            document = json.loads(raw)
            transform(document, document["records"][0])
            return json.dumps(document).encode("utf-8")

        return change

    def relabel(label, **fields):
        return {**copy.deepcopy(by_label[label]), **fields}

    revoked = "revoked_unvalidated-revoked-personal"
    unvalidated = "revoked_unvalidated-unvalidated-personal"
    full = "setup_full-personal"
    negatives = {
        "revocation-missing-revoked-at": edited(
            revoked, ATTACHMENTS, cache(lambda d, r: r.pop("revoked_at"))
        ),
        "revocation-null-revoked-at": edited(
            revoked, ATTACHMENTS, cache(lambda d, r: r.update(revoked_at=None))
        ),
        "revocation-naive-timestamp": edited(
            revoked,
            ATTACHMENTS,
            cache(lambda d, r: r.update(revoked_at="2026-02-01T00:00:00")),
        ),
        "revocation-invalid-timestamp": edited(
            revoked, ATTACHMENTS, cache(lambda d, r: r.update(revoked_at="revoked"))
        ),
        "revocation-cache-missing": edited(revoked, ATTACHMENTS, drop=True),
        "revocation-wrong-board": edited(
            revoked, ATTACHMENTS, cache(lambda d, r: r.update(board_id="other_board"))
        ),
        "revocation-confirmed-and-revoked": edited(
            revoked, ATTACHMENTS, cache(lambda d, r: r.update(confirmed=True))
        ),
        "revocation-active-attachment": edited(
            revoked,
            ATTACHMENTS,
            cache(lambda d, r: (r.update(confirmed=True), r.pop("revoked_at"))),
        ),
        "revocation-unstable-probe-identity": edited(
            revoked, ATTACHMENTS, cache(lambda d, r: r.update(probe_usb_serial=" "))
        ),
        "revocation-boolean-usb-id": edited(
            revoked, ATTACHMENTS, cache(lambda d, r: r.update(uart_vid=True))
        ),
        "revocation-cache-schema": edited(
            revoked, ATTACHMENTS, cache(lambda d, r: d.update(schema_version=2))
        ),
        "revocation-persisted-authority": edited(
            revoked, ATTACHMENTS, cache(lambda d, r: r.update(permission="granted"))
        ),
        "revocation-unknown-field": edited(
            revoked, ATTACHMENTS, cache(lambda d, r: r.update(extra=1))
        ),
        "revocation-malformed-json": edited(revoked, ATTACHMENTS, lambda raw: b"{"),
        "unvalidated-with-cache": edited(
            unvalidated,
            ATTACHMENTS,
            lambda raw: by_label[revoked]["data"][ATTACHMENTS],
        ),
        "unvalidated-label-on-lite": relabel(
            "setup_lite-personal", state="revoked_unvalidated", variant="unvalidated"
        ),
        "unvalidated-label-on-no-setup": relabel(
            "no_setup-personal", state="revoked_unvalidated", variant="unvalidated"
        ),
        "setup-full-label-on-no-setup": relabel(
            "no_setup-personal", state="setup_full"
        ),
        "no-setup-label-on-full": relabel(full, state="no_setup"),
        "setup-lite-label-on-full": relabel(full, state="setup_lite"),
        "setup-full-label-on-incomplete": relabel(
            revoked, state="setup_full", variant=None
        ),
        "corrupt-label-on-valid-policy": relabel(full, state="corrupt_policy"),
        "full-label-on-corrupt-policy": relabel(
            "corrupt_policy-personal", state="setup_full"
        ),
        "wrong-board": relabel(full, board_id="other_board"),
        "unrelated-fixture-file": edited(
            full, ".firm/unrelated.json", lambda raw: b"{}\n"
        ),
        "non-passive-fixture-file": edited(full, "bin/verify", lambda raw: b"x"),
        "fixture-bytes-differ-from-record": relabel(
            full, data={k: v + b" " for k, v in by_label[full]["data"].items()}
        ),
        "no-board-with-policy": relabel(full, state="no_board"),
        "invalid-board-identifier": relabel("no_board-personal", board_id="../fixture"),
        "unrecognized-variant": relabel(revoked, variant="stale"),
        "missing-variant": relabel(revoked, variant=None),
    }
    pointer_path = ".firm/capabilities/legacy_full/current.json"
    pointer = json.loads(by_label[full]["data"][pointer_path])
    generation_path = (
        f".firm/capabilities/legacy_full/generations/{pointer['generation_id']}.json"
    )

    def canonical(value) -> bytes:
        return (
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()

    def retiered(move_pointer: bool) -> dict:
        case = copy.deepcopy(by_label[full])
        document = json.loads(case["data"][generation_path])
        document["tier"] = "setup-lite"
        raw = canonical(document)
        case["data"][generation_path] = raw
        case["files"][generation_path] = record_of(raw)
        if move_pointer:
            moved = canonical(
                {**pointer, "generation_digest": record_of(raw)["sha256"]}
            )
            case["data"][pointer_path] = moved
            case["files"][pointer_path] = record_of(moved)
        return case

    negatives["generation-differs-from-pointer"] = retiered(False)
    negatives["policy-digest-stale"] = retiered(True)
    negatives["pointer-schema"] = edited(
        full, pointer_path, lambda raw: canonical({**pointer, "schema_version": 2})
    )
    negatives["pointer-board"] = edited(
        full,
        pointer_path,
        lambda raw: canonical({**pointer, "board_id": "other_board"}),
    )
    negatives["generation-missing"] = edited(full, generation_path, drop=True)

    def regenerated(label, mutate) -> dict:
        # Self-consistent semantic mutation: recompute the canonical policy
        # digest, generation file hash, pointer digest and every file record.
        case = copy.deepcopy(by_label[label])
        prefix = f".firm/capabilities/{case['board_id']}/"
        current = json.loads(case["data"][prefix + "current.json"])
        target = f"{prefix}generations/{current['generation_id']}.json"
        document = json.loads(case["data"][target])
        mutate(document)
        document["policy_digest"] = canonical_digest(
            {k: v for k, v in document.items() if k != "policy_digest"}
        )
        raw = canonical(document)
        moved = canonical({**current, "generation_digest": record_of(raw)["sha256"]})
        for relative, value in ((target, raw), (prefix + "current.json", moved)):
            case["data"][relative] = value
            case["files"][relative] = record_of(value)
        return case

    def profile_edit(**fields):
        return lambda d: d["profile_snapshot"].update(fields)

    def map_edit(change):
        return lambda d: change(d["map_snapshot"])

    semantic = {
        "full-nonobject-map": lambda d: d.update(map_snapshot="memory_map"),
        "full-invalid-profile-schema": profile_edit(schema_version=1),
        "full-boolean-profile-schema": profile_edit(schema_version=True),
        "full-mismatched-profile-target": profile_edit(pyocd_target="stm32f103rc"),
        "full-mismatched-profile-mcu": profile_edit(mcu_part_number="STM32F103RC"),
        "full-profile-other-board": profile_edit(board_id="other_board"),
        "full-profile-other-safety-ref": profile_edit(
            safety_ref=".firm/safety/other_board/memory_map.yaml"
        ),
        "full-nonobject-profile": lambda d: d.update(profile_snapshot=[]),
        "full-map-unsupported-schema": map_edit(lambda m: m.update(schema_version=1)),
        "full-map-other-board": map_edit(lambda m: m.update(board_id="other_board")),
        "full-map-missing-semantic-link": map_edit(
            lambda m: m["source_digests"].pop("semantic_profile")
        ),
        "full-map-forged-semantic-link": map_edit(
            lambda m: m["source_digests"].update(semantic_profile="a" * 64)
        ),
        "full-map-empty-regions": map_edit(lambda m: m.update(regions=[])),
        "full-map-nonobject-identity": map_edit(lambda m: m.update(identity="nrf")),
        "full-linked-but-unaccepted-snapshot": profile_edit(display_name="edited"),
        "policy-nonboolean-legacy-flag": lambda d: d.update(legacy_migrated=0),
        "policy-migrated-legacy-flag": lambda d: d.update(legacy_migrated=True),
        "policy-nonboolean-setup-incomplete": lambda d: d.update(setup_incomplete=0),
        "no-setup-stray-profile": lambda d: d.update(
            tier="no-setup", map_snapshot=None
        ),
    }
    lite_semantic = {
        "lite-nonobject-map": lambda d: d.update(map_snapshot=["regions"]),
        "lite-invalid-map-fields": map_edit(lambda m: m.update(identity={})),
        "lite-map-other-board": map_edit(lambda m: m.update(board_id="other_board")),
        "lite-unaccepted-map": map_edit(lambda m: m.update(regions=[])),
        "lite-with-unvalidated-profile": lambda d: d.update(
            profile_snapshot={"board_id": "lite_board", "schema_version": 2}
        ),
        "lite-nonboolean-legacy-flag": lambda d: d.update(legacy_migrated=0),
        "no-setup-active-map": lambda d: d.update(
            tier="no-setup", profile_snapshot=None
        ),
    }
    corrupt_pointer = ".firm/capabilities/corrupt_board/current.json"
    for profile in ("personal", "professional"):
        for name, base, mutations in (
            ("full", f"setup_full-{profile}", semantic),
            ("unvalidated", f"revoked_unvalidated-unvalidated-{profile}", semantic),
            ("lite", f"setup_lite-{profile}", lite_semantic),
        ):
            check(
                f"passive-{name}-recomputed-identity-{profile}",
                lambda b=base: check_passive_case(regenerated(b, lambda d: None)),
            )
            for label, mutate in mutations.items():
                suffix = f"unvalidated-{profile}" if name == "unvalidated" else profile
                negatives[f"{label}-{suffix}"] = regenerated(base, mutate)
        corrupt_label = f"corrupt_policy-{profile}"
        negatives[f"corrupt-missing-pointer-{profile}"] = edited(
            corrupt_label, corrupt_pointer, drop=True
        )
        negatives[f"corrupt-valid-json-pointer-{profile}"] = edited(
            corrupt_label, corrupt_pointer, lambda raw: b"{}\n"
        )
        negatives[f"corrupt-with-attachment-cache-{profile}"] = edited(
            corrupt_label,
            ATTACHMENTS,
            lambda raw: by_label[revoked]["data"][ATTACHMENTS],
        )
    for label, case in negatives.items():
        check(f"passive-{label}", lambda c=case: check_passive_case(c), Setup)

    original = json.loads(path.read_bytes().decode("utf-8"))

    def parse(mutate):
        document = copy.deepcopy(original)
        mutate(document)
        return lambda: parse_availability_inputs(document)

    def bad_base64(document):
        entry = next(iter(document["fixtures"]["setup_full"].values()))
        entry["base64"] = "***"

    manifest_negatives = {
        "old-schema": lambda d: d.update(schema="installed-analysis-availability/v2"),
        "duplicate-case": lambda d: d["cases"].append(dict(d["cases"][0])),
        "unknown-state": lambda d: d["cases"][0].update(state="revoked"),
        "unknown-profile": lambda d: d["cases"][0].update(profile="enterprise"),
        "variant-on-plain-state": lambda d: d["cases"][0].update(variant="revoked"),
        "missing-variant-field": lambda d: d["cases"][4].pop("variant"),
        "unknown-case-field": lambda d: d["cases"][0].update(root="states"),
        "absent-fixture": lambda d: d["cases"][0].update(fixture="missing"),
        "bad-base64": bad_base64,
        "unknown-manifest-field": lambda d: d.update(credit=True),
        "empty-cases": lambda d: d.update(cases=[]),
    }
    for label, mutate in manifest_negatives.items():
        check(f"manifest-{label}", parse(mutate), Setup)
    check(
        "manifest-explicit-digest",
        lambda: load_availability_inputs(path, "0" * 64),
        Setup,
    )

    profiles = {"personal": "enabled", "professional": "not_built"}
    for label, case in by_label.items():
        values = expected[label]
        health = {"narrative_logging": profiles[case["profile"]]}
        other = "not_built" if case["profile"] == "personal" else "enabled"
        payload = {
            "board_id": case["board_id"],
            "tier": values["tier"],
            "policy_status": values["policy_status"],
            "setup_incomplete": values["setup_incomplete"],
            "policy_digest": values["policy_digest"]
            or (None if values["tier"] is None else "a" * 64),
            "identity": copy.deepcopy(values["identity"]),
        }
        check(
            f"public-{label}",
            lambda c=case, v=values, h=health, p=payload: check_availability_witnesses(
                c, v, h, p
            ),
        )
        identity = payload["identity"]
        wrong = {
            "profile-label-only": ({"narrative_logging": case["profile"]}, payload),
            "other-profile": ({"narrative_logging": other}, payload),
            "board": (health, {**payload, "board_id": "other_board"}),
            "tier": (
                health,
                {
                    **payload,
                    "tier": "setup-full"
                    if values["tier"] == "setup-lite"
                    else "setup-lite",
                },
            ),
            "policy-status": (health, {**payload, "policy_status": "legacy-migrated"}),
            "setup-incomplete": (
                health,
                {**payload, "setup_incomplete": not payload["setup_incomplete"]},
            ),
            "policy-digest": (health, {**payload, "policy_digest": "b" * 63 + "x"}),
            "identity-proven": (
                health,
                {**payload, "identity": {**identity, "assertion": "proven"}},
            ),
            "identity-capability": (
                health,
                {**payload, "identity": {**identity, "capability": "exact"}},
            ),
        }
        if values["policy_digest"] is not None:
            wrong["policy-digest-other"] = (
                health,
                {**payload, "policy_digest": "c" * 64},
            )
        if values["tier"] is None:
            wrong["corrupt-with-digest"] = (
                health,
                {**payload, "policy_digest": "d" * 64},
            )
        for field in payload:
            wrong[f"missing-{field}"] = (
                health,
                {k: v for k, v in payload.items() if k != field},
            )
        wrong["setup-incomplete-as-int"] = (
            health,
            {**payload, "setup_incomplete": int(payload["setup_incomplete"])},
        )
        wrong["tier-wrong-type"] = (health, {**payload, "tier": 0})
        wrong["policy-status-wrong-type"] = (health, {**payload, "policy_status": None})
        wrong["policy-digest-wrong-type"] = (health, {**payload, "policy_digest": 0})
        wrong["identity-wrong-type"] = (health, {**payload, "identity": []})
        wrong["identity-null-as-false"] = (
            health,
            {
                **payload,
                "identity": {
                    k: (False if v is None else v) for k, v in identity.items()
                },
            },
        )
        wrong["board-wrong-type"] = (
            health,
            {**payload, "board_id": [case["board_id"]]},
        )
        wrong["health-missing-profile"] = ({}, payload)
        wrong["health-not-object"] = ([], payload)
        wrong["capabilities-not-object"] = (health, [payload])
        for name, (h, p) in wrong.items():
            check(
                f"public-{label}-wrong-{name}",
                lambda c=case, v=values, h=h, p=p: check_availability_witnesses(
                    c, v, h, p
                ),
                Red,
            )

    complete = {name: [{"result": {}}] for name in TOOLS}
    check("tool-coverage-complete", lambda: check_tool_coverage(complete))
    for name in TOOLS:
        partial = {k: v for k, v in complete.items() if k != name}
        check(
            f"tool-coverage-missing-{name}",
            lambda p=partial: check_tool_coverage(p),
            Red,
        )
    check(
        "tool-coverage-empty-results",
        lambda: check_tool_coverage({**complete, TOOLS[-1]: []}),
        Red,
    )

    def aggregate(state, variants, status):
        def action():
            observed = group_status(state, variants)["status"]
            require(observed == status, f"group aggregated {observed}, not {status}")

        return action

    passed = {"status": "PASS"}
    both = "revoked_unvalidated"
    for name, state, variants, status in (
        ("both-variants", both, {"revoked": passed, "unvalidated": passed}, "PASS"),
        ("revoked-only", both, {"revoked": passed}, "PENDING"),
        ("unvalidated-only", both, {"unvalidated": passed}, "PENDING"),
        (
            "variant-red",
            both,
            {"revoked": passed, "unvalidated": {"status": "RED"}},
            "RED",
        ),
        ("label-without-variant", both, {None: passed}, "PENDING"),
        ("plain-state", "setup_full", {None: passed}, "PASS"),
        ("plain-state-missing", "setup_full", {}, "PENDING"),
    ):
        check(f"variant-ledger-{name}", aggregate(state, variants, status))

    protected = scratch / "protected-attachments.json"
    protected.parent.mkdir(parents=True, exist_ok=True)
    protected.write_bytes(by_label[revoked]["data"][ATTACHMENTS])
    record = file_record(protected)
    check(
        "protected-bytes-unchanged",
        lambda: verify_file(protected, record, product=True),
    )
    protected.write_bytes(protected.read_bytes().replace(b"REVOKED", b"ACTIVE!"))
    check(
        "protected-bytes-changed",
        lambda: verify_file(protected, record, product=True),
        Red,
    )
    return {
        "manifest": file_record(path),
        "cases": sorted(by_label),
        "expected_from_fixture": expected,
    }


class _FakeKernel:
    """Mocked kernel32 observation failures; no OS process is queried."""

    def __init__(
        self,
        open_error=0,
        times=True,
        image=True,
        wait=258,
        created=7,
        terminate=True,
        opened=True,
    ):
        self.open_error, self.times, self.image = open_error, times, image
        self.wait, self.created = wait, created
        self.terminate, self.terminated = terminate, []
        self.opened = opened

    def OpenProcess(self, access, inherit, pid):
        ctypes.set_last_error(self.open_error)
        return 0 if self.open_error or not self.opened else 1

    def GetProcessTimes(self, handle, created, *rest):
        if not self.times:
            ctypes.set_last_error(5)
            return 0
        created._obj.dwHighDateTime = 0
        created._obj.dwLowDateTime = self.created
        return 1

    def QueryFullProcessImageNameW(self, handle, flags, buffer, size):
        if not self.image:
            ctypes.set_last_error(31)
            return 0
        buffer.value = "C:/owned/analyzer.exe"
        return 1

    def WaitForSingleObject(self, handle, timeout):
        return self.wait

    def CloseHandle(self, handle):
        return 1

    def TerminateProcess(self, handle, code):
        self.terminated.append((handle, code))
        if not self.terminate:
            ctypes.set_last_error(5)
            return 0
        self.wait = 0
        return 1


def process_observer_checks(check, scratch: Path) -> dict:
    """Unobservable identity never earns absence; real exact owned cleanup."""
    owned = {"pid": 4242, "creation_filetime": 7}

    def mocked(**kernel):
        native = object.__new__(WindowsProcesses)
        native.k = _FakeKernel(**kernel)
        return native

    def expect(action, value):
        def run():
            observed = action()
            require(observed == value, f"observed {observed!r}, expected {value!r}")

        return run

    for name, kernel in (
        ("open-access-denied", {"open_error": 5}),
        ("open-unknown-error", {"open_error": 6}),
        ("open-no-error-reported", {"opened": False}),
        ("get-process-times-failed", {"times": False}),
        ("wait-failed", {"wait": 0xFFFFFFFF}),
    ):
        check(
            f"observer-{name}-identity",
            lambda k=kernel: mocked(**k).identity(4242),
            Setup,
        )
        check(
            f"observer-{name}-alive",
            lambda k=kernel: mocked(**k).alive(owned),
            Setup,
        )
    check(
        "observer-image-query-failed-identity",
        lambda: mocked(image=False).identity(4242),
        Setup,
    )
    check(
        "observer-win32-proved-no-pid",
        expect(lambda: mocked(open_error=87).identity(4242), None),
    )
    check(
        "observer-win32-proved-no-pid-absent",
        expect(lambda: mocked(open_error=87).alive(owned), False),
    )
    check("observer-exact-alive", expect(lambda: mocked().alive(owned), True))
    check("observer-exact-exited", expect(lambda: mocked(wait=0).alive(owned), False))
    check(
        "observer-pid-reused-later-creation",
        expect(lambda: mocked(created=9).alive(owned), False),
    )

    def stopped(native):
        tracker = object.__new__(Owned)
        tracker.native = native
        tracker.records = {(4242, 7): {**owned, "image": "x"}}
        tracker.stop = threading.Event()
        tracker.thread = threading.Thread(target=lambda: None)
        tracker.thread.start()
        tracker.thread.join()
        return tracker

    check(
        "observer-cleanup-access-denied-no-credit",
        lambda: stopped(mocked(open_error=5)).finish(),
        Setup,
    )

    def sampler_unobservable():
        tracker = stopped(mocked(open_error=87))
        tracker.error = Setup("PID 4242 identity unobservable: OpenProcess error 5")
        tracker.finish()

    check("observer-sampler-unobservable-is-setup", sampler_unobservable, Setup)

    for name, kernel in (
        ("access-denied", {"open_error": 5}),
        ("times-failed", {"times": False}),
        ("wait-failed", {"wait": 0xFFFFFFFF}),
        ("terminate-failed", {"terminate": False}),
    ):
        check(
            f"observer-termination-{name}-no-credit",
            lambda k=kernel: mocked(**k).terminate(owned),
            Setup,
        )

    def termination_guard(**kernel):
        native = mocked(**kernel)
        native.terminate(owned)
        require(not native.k.terminated, "terminated a reused or exited identity")

    check(
        "observer-termination-reused-pid-untouched",
        lambda: termination_guard(created=9),
    )
    check("observer-termination-exited-untouched", lambda: termination_guard(wait=0))

    def mocked_exact_termination():
        native = mocked()
        native.terminate(owned)
        require(native.k.terminated == [(1, 99)], "exact termination was not attempted")
        require(not native.alive(owned), "exact termination exit was not observed")

    check("observer-termination-exact-exit", mocked_exact_termination)

    # Actual exact owned processes: a target terminated through its retained
    # PID+creation handle, an unaffected same-image peer and a naturally
    # completing version probe. Nothing is selected by name.
    native = WindowsProcesses()
    command = [sys.executable, "-I", "-c"]
    target_argv = command + ["import time; time.sleep(60)"]
    peer_argv = command + ["import time; time.sleep(3)"]
    probe_argv = [sys.executable, "-I", "--version"]
    receipt = {
        "python": file_record(Path(sys.executable)),
        "argv": {"target": target_argv, "peer": peer_argv, "probe": probe_argv},
        "installed_credit": False,
        "compiled_credit": False,
    }
    target = subprocess.Popen(target_argv)
    peer = subprocess.Popen(peer_argv)
    probe = subprocess.Popen(
        probe_argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    tracker = None
    try:
        tracker = Owned(target, native)
        target_identity = native.identity(target.pid)
        peer_identity = native.identity(peer.pid)
        probe_identity = native.identity(probe.pid)
        require(
            all((peer_identity, probe_identity, target_identity)),
            "owned process identity unavailable",
        )
        require(
            Path(peer_identity["image"]) == Path(target_identity["image"]),
            "peer is not a same-image process",
        )
        reused = {**target_identity, "creation_filetime": 1}
        receipt["pid_reuse_identity_alive"] = native.alive(reused)
        receipt["target_alive_before"] = native.alive(target_identity)
        native.terminate(target_identity)
        receipt["target_alive_after_exact_termination"] = native.alive(target_identity)
        receipt["target_exit"] = target.wait(timeout=10)
        receipt["peer_alive_after_target_termination"] = native.alive(peer_identity)
        receipt["owned_records"] = tracker.finish()
        tracker = None
        receipt["probe_stdout"], receipt["probe_stderr"] = probe.communicate(timeout=30)
        receipt["probe_exit"] = probe.returncode
        receipt["probe_alive_after_natural_exit"] = native.alive(probe_identity)
        receipt["peer_exit"] = peer.wait(timeout=30)
        receipt["peer_alive_after_natural_exit"] = native.alive(peer_identity)
        receipt.update(target=target_identity, peer=peer_identity, probe=probe_identity)
    finally:
        if tracker is not None:
            tracker.stop.set()
        for process in (target, peer, probe):
            if process.poll() is None:
                # Only processes launched here, through their retained handle.
                process.kill()
                process.wait(timeout=10)
    scratch.mkdir(parents=True, exist_ok=True)
    write_json(scratch / "process-observer.json", receipt)
    for key, value in {
        "pid_reuse_identity_alive": False,
        "target_alive_before": True,
        "target_alive_after_exact_termination": False,
        "target_exit": 99,
        "peer_alive_after_target_termination": True,
        "probe_exit": 0,
        "probe_alive_after_natural_exit": False,
        "peer_exit": 0,
        "peer_alive_after_natural_exit": False,
    }.items():
        check(f"observer-real-{key}", expect(lambda k=key: receipt.get(k), value))
    check(
        "observer-real-owned-records-absent",
        lambda: require(
            receipt.get("owned_records")
            and not any(r["alive_after"] for r in receipt["owned_records"]),
            "owned target record still alive",
        ),
    )

    # Exercise the actual command timeout boundary: successful emergency
    # termination is retained failure evidence and cannot become command PASS.
    emergency = Evidence(scratch / "emergency-cleanup")
    check(
        "observer-emergency-cleanup-remains-red",
        lambda: emergency.run(
            "owned-timeout",
            command + ["import time; time.sleep(60)"],
            dict(os.environ),
            scratch.resolve(),
            timeout=0.1,
        ),
        Red,
    )
    emergency_path = emergency.root / "commands/001-owned-timeout/command.json"
    emergency_record = read_json(emergency_path)
    check(
        "observer-emergency-cleanup-confirmed-but-failed",
        lambda: require(
            emergency_record["timeout"] is True
            and emergency_record["exit"] == 99
            and bool(emergency_record["processes"])
            and all(
                r["creation_filetime"] and r["alive_after"] is False
                for r in emergency_record["processes"]
            ),
            "emergency cleanup lacks exact identity/exit or timeout failure",
        ),
    )
    receipt["emergency_cleanup"] = {
        "record": file_record(emergency_path),
        "path": str(emergency_path),
        "command_status": "RED",
        "installed_credit": False,
    }
    write_json(scratch / "process-observer.json", receipt)
    return {"receipt": file_record(scratch / "process-observer.json"), **receipt}


def validator_contract_checks(args, evidence: Evidence) -> None:
    """Executable validator tests only; synthetic mutations earn no installed credit."""
    import copy

    archive_gate(args, evidence)
    manifest = read_json(args.bundle / "release-manifest.json")
    inventory = {item["path"]: item for item in manifest["files"]}
    mapping = read_json(args.bundle / "analysis/runtime.json")
    expected = expected_digest(args.cppcheck_sha256, "--cppcheck-sha256")
    checks = []

    def check(label, action, error=None):
        try:
            action()
        except (Red, Setup, Pending) as exc:
            require(
                error is not None and isinstance(exc, error),
                f"{label}: unexpected failure {exc}",
            )
            checks.append(
                {
                    "case": label,
                    "status": "PASS",
                    "observed": type(exc).__name__,
                    "reason": str(exc),
                }
            )
        else:
            require(error is None, f"{label}: validator admitted a negative control")
            checks.append({"case": label, "status": "PASS", "observed": "accepted"})

    check("missing-oracle", lambda: expected_digest(None, "--cppcheck-sha256"), Setup)
    check(
        "malformed-oracle",
        lambda: expected_digest("not-a-digest", "--cppcheck-sha256"),
        Setup,
    )
    check(
        "wrong-oracle",
        lambda: program_identity(args.bundle, inventory, mapping, "0" * 64),
        Red,
    )
    check(
        "explicit-candidate",
        lambda: program_identity(args.bundle, inventory, mapping, expected),
    )
    with tempfile.TemporaryDirectory(
        prefix="byo validator ", dir=args.temp_parent
    ) as temporary:
        bundle = Path(temporary)
        for name in ("cppcheck", "clangd"):
            relative = mapping["programs"][name]["executable"]
            destination = below(bundle, relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(below(args.bundle, relative), destination)
        bad_mapping = copy.deepcopy(mapping)
        bad_mapping["programs"]["cppcheck"]["executable"] = (
            "analysis/clangd/bin/clangd.exe"
        )
        check(
            "altered-mapping-path",
            lambda: program_identity(bundle, inventory, bad_mapping, expected),
            Red,
        )
        bad_mapping = copy.deepcopy(mapping)
        bad_mapping["programs"]["cppcheck"]["version"] = "0.0.0"
        check(
            "altered-mapping-version",
            lambda: program_identity(bundle, inventory, bad_mapping, expected),
            Red,
        )
        for name, field, value in (
            ("cppcheck", "cfg_dir", "analysis/cppcheck/platforms"),
            ("cppcheck", "platforms_dir", "analysis/cppcheck/cfg"),
            ("cppcheck", "licenses", []),
            ("cppcheck", "dependencies", ["unexpected.dll"]),
            ("clangd", "resource_dir", "analysis/cppcheck/cfg"),
            ("clangd", "sbom_ref", "byo-analysis:cppcheck"),
        ):
            altered = copy.deepcopy(mapping)
            altered["programs"][name][field] = value
            check(
                f"altered-mapping-{name}-{field}",
                lambda: program_identity(bundle, inventory, altered, expected),
                Red,
            )
        bad_inventory = copy.deepcopy(inventory)
        relative = "analysis/cppcheck/cppcheck.exe"
        bad_inventory[relative]["sha256"] = "0" * 64
        check(
            "altered-manifest-digest",
            lambda: program_identity(bundle, bad_inventory, mapping, expected),
            Red,
        )
        bad_inventory = copy.deepcopy(inventory)
        bad_inventory[relative]["size"] += 1
        check(
            "altered-manifest-size",
            lambda: program_identity(bundle, bad_inventory, mapping, expected),
            Red,
        )
        bad_inventory = copy.deepcopy(inventory)
        bad_inventory[relative]["executable"] = False
        check(
            "altered-manifest-classification",
            lambda: program_identity(bundle, bad_inventory, mapping, expected),
            Red,
        )
        executable = below(bundle, relative)
        original = executable.read_bytes()
        executable.write_bytes(original + b"validator-only wrong binary")
        bad_inventory[relative] = {**inventory[relative], **file_record(executable)}
        check(
            "self-consistent-wrong-binary",
            lambda: program_identity(bundle, bad_inventory, mapping, expected),
            Red,
        )
        # Independent second oracle tests plumbing, not a real distinct-version
        # installed update. Real update still requires its own built input.
        other_expected = digest(executable)
        check(
            "second-explicit-oracle",
            lambda: program_identity(bundle, bad_inventory, mapping, other_expected),
        )
        check(
            "second-oracle-not-first",
            lambda: program_identity(bundle, inventory, mapping, other_expected),
            Red,
        )
    if args.availability_inputs is not None and args.availability_sha256 is not None:
        availability_path = args.availability_inputs
        availability_sha = args.availability_sha256
        binding = "explicit --availability-inputs/--availability-sha256"
    else:
        availability_path = (
            Path(__file__).resolve().parent
            / "fixtures/code-analysis-installed/availability/manifest.json"
        )
        availability_sha = digest(availability_path)
        binding = "script-relative committed fixture (self-digest, no oracle credit)"
    availability = availability_contract_checks(
        check, availability_path, availability_sha, evidence.root / "contract-scratch"
    )
    availability["binding"] = binding
    observer = process_observer_checks(check, evidence.root / "contract-scratch")
    write_json(
        evidence.root / "validator-contract.json",
        {
            "checks": checks,
            "script": file_record(Path(__file__)),
            "archive": file_record(args.archive),
            "expected_cppcheck_sha256": expected,
            "availability": availability,
            "process_observer": observer,
            "installed_credit": False,
        },
    )


def main() -> int:
    # Gate reasons quote non-ASCII lab paths; a legacy console codepage must not
    # turn a recorded gate result into an unrelated harness exception.
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(errors="backslashreplace")
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument(
        "--evidence", type=Path, required=True, help="NEW persistent evidence directory"
    )
    parser.add_argument(
        "--archive-only",
        action="store_true",
        help="focused pre-packaging RED; other gates stay pending",
    )
    for name in (
        "cppcheck-inputs",
        "cppcheck-source",
        "clangd-inputs",
        "clangd-root",
        "arm-fixture",
        "python-workspace",
        "rustc",
        "availability-inputs",
        "update-bundle",
    ):
        parser.add_argument(f"--{name}", type=Path)
    for name in (
        "python-commit",
        "cppcheck-sha256",
        "rustc-sha256",
        "availability-sha256",
        "update-manifest-sha256",
        "update-cppcheck-sha256",
    ):
        parser.add_argument(f"--{name}")
    parser.add_argument(
        "--temp-parent",
        type=Path,
        help="existing short local temp root; default native TEMP",
    )
    parser.add_argument("--keep-lab", action="store_true")
    parser.add_argument(
        "--install-timeout-seconds",
        type=int,
        default=120,
        help="native installation deadline (default 120); recorded in invocation",
    )
    parser.add_argument(
        "--validator-contract-checks",
        action="store_true",
        help="focused executable validator checks with private mutations; no installed credit",
    )
    parser.add_argument(
        "--installed-profile",
        choices=("personal", "professional"),
        default="personal",
        help="compiled archive profile; verified through public health, never runtime flags",
    )
    args = parser.parse_args()
    if args.install_timeout_seconds <= 0:
        parser.error("--install-timeout-seconds must be positive")
    if (
        os.name != "nt"
        or platform.machine().lower() not in {"amd64", "x86_64"}
        or sys.maxsize <= 2**32
    ):
        parser.error(
            "native 64-bit Windows AMD64 only; no other platform checks are allowed"
        )
    if len(args.archive_sha256) != 64 or any(
        c not in "0123456789abcdefABCDEF" for c in args.archive_sha256
    ):
        parser.error("--archive-sha256 must be an explicit 64-hex artifact digest")
    args.archive_sha256 = args.archive_sha256.lower()
    for key, value in vars(args).items():
        if isinstance(value, Path):
            setattr(args, key, value.resolve())
    try:
        evidence = Evidence(args.evidence)
    except Setup as exc:
        print(f"SETUP_FAILURE: {exc}", file=sys.stderr)
        return 2
    manifest = {}

    if args.validator_contract_checks:
        evidence.gate(
            "validator-contract", lambda: validator_contract_checks(args, evidence)
        )
        return evidence.save()

    def inspect_archive():
        manifest.update(archive_gate(args, evidence))

    if not evidence.gate("archive", inspect_archive) or args.archive_only:
        return evidence.save()

    lab = Path(tempfile.mkdtemp(prefix="byo installed µ ", dir=args.temp_parent))
    evidence.report["lab"] = str(lab)
    evidence.report["cleanup"] = {
        "policy": "retain failed labs; successful labs removed unless --keep-lab",
        "selection": "PID plus creation FILETIME; no broad name kills",
    }
    inputs = {}

    def inspect_inputs():
        inputs.update(input_gate(args, evidence, lab))

    installed = {}
    success = False
    try:
        if not evidence.gate("immutable-inputs", inspect_inputs):
            raise Halt()
        home = lab / "isolated BYO home µ 测试"
        env = isolated_environment(home, lab)
        bundle_copy = lab / "relocated bundle µ" / args.bundle.name
        shutil.copytree(args.bundle, bundle_copy)
        version = manifest["version"]
        byo = home / "bin/byo.exe"
        runtime = home / "data/versions" / version
        rust_project = copy_arm(args, lab, "shared-runners", evidence)
        python_project = rust_project
        semantic = semantic_project(lab)
        projects = (rust_project, semantic)
        snapshots = {project: preserve_snapshot(project) for project in projects}
        evidence.report["cross_runner_project"] = str(rust_project)

        def install():
            evidence.run(
                "install-public-native-entrypoint",
                [
                    str(bundle_copy / "byo.exe"),
                    "install-runtime",
                    "--bundle",
                    str(bundle_copy),
                ],
                env,
                lab,
                timeout=args.install_timeout_seconds,
            )
            require(byo.is_file(), "native public installation did not create byo.exe")
            assert_runtime(runtime, manifest)
            for project in projects:
                evidence.run(
                    f"init-{project.name}",
                    [str(byo), "init", "--project", str(project)],
                    env,
                    lab,
                )
                assert_preserved(project, snapshots[project])
            installed.update(home=home, env=env, byo=byo, runtime=runtime)

        if not evidence.gate("install", install):
            raise Halt()
        control = compile_build_control(args, lab, env, evidence)
        for project in (rust_project,):
            (project / "bin").mkdir(exist_ok=True)
            shutil.copy2(control, project / "bin/verify-firmware-local")
        rust_command = [
            str(byo),
            "workflow",
            "tool",
            "verify",
            "--project",
            str(rust_project),
        ]
        python_command = [
            sys.executable,
            str(inputs["python"] / "bin/verify"),
            "--mode",
            "firmware",
        ]
        python_env = {
            **env,
            "AGENT_WORKSPACE_HOST_ROOT": str(python_project),
            "AGENT_WORKSPACE_MODE": "firmware",
            "PATH": os.pathsep.join((str(runtime / "analysis/cppcheck"), env["PATH"])),
        }
        require(
            Path(shutil.which("cppcheck", path=python_env["PATH"])).resolve()
            == (runtime / "analysis/cppcheck/cppcheck.exe").resolve(),
            "companion Python PATH does not resolve installed Cppcheck",
        )
        evidence.gate(
            "rust-arm",
            lambda: arm_runner(
                evidence, rust_project, rust_command, env, runtime, "rust", True
            ),
        )
        evidence.gate(
            "python-arm",
            lambda: arm_runner(
                evidence,
                python_project,
                python_command,
                python_env,
                runtime,
                "python",
                False,
            ),
        )

        def mcp_no_board():
            before = preserve_snapshot(semantic)
            server = Mcp(evidence, byo, semantic, env, version, "no-board")
            try:
                semantic_queries(server, runtime, env, full=True)
            finally:
                # Idle EOF cleanup is observed and recorded even after a RED query.
                if evidence.gate("stdio-idle-eof-cleanup", server.close):
                    evidence.report["gates"]["stdio-idle-eof-cleanup"]["evidence"] = (
                        str(server.path)
                    )
            require(
                evidence.report["gates"]["stdio-idle-eof-cleanup"]["status"] == "PASS",
                f"stdio EOF cleanup failed; {server.path}",
            )
            assert_preserved(semantic, before)

        evidence.gate("mcp-no-board", mcp_no_board)
        evidence.gate(
            "mcp-availability",
            lambda: availability_gate(
                args, evidence, lab, semantic, byo, env, runtime, version
            ),
        )
        evidence.gate(
            "missing-data-corrupt-version",
            lambda: negative_runtime_gate(
                evidence,
                runtime,
                rust_project,
                python_project,
                rust_command,
                python_command,
                env,
                python_env,
            ),
        )
        evidence.gate(
            "doctor-status-report",
            lambda: doctor_gate(evidence, byo, rust_project, env, runtime),
        )

        # Move the entire installed home after all servers have exited. Project
        # integrations are refreshed through their public update route.
        relocated_home = lab / "moved installed home 测试 µ"
        relocated_runners = False

        def relocate():
            nonlocal home, env, byo, runtime, rust_command, python_env
            nonlocal relocated_runners
            home.rename(relocated_home)
            home = relocated_home
            env = isolated_environment(home, lab)
            byo = home / "bin/byo.exe"
            runtime = home / "data/versions" / version
            assert_runtime(runtime, manifest)
            for project in projects:
                evidence.run(
                    f"relocation-update-{project.name}",
                    [str(byo), "workspace", "update", "--project", str(project)],
                    env,
                    lab,
                )
                assert_preserved(project, snapshots[project])
            rust_command = [
                str(byo),
                "workflow",
                "tool",
                "verify",
                "--project",
                str(rust_project),
            ]
            python_env = {
                **env,
                "AGENT_WORKSPACE_HOST_ROOT": str(python_project),
                "AGENT_WORKSPACE_MODE": "firmware",
                "PATH": os.pathsep.join(
                    (str(runtime / "analysis/cppcheck"), env["PATH"])
                ),
            }
            report_once(
                evidence,
                rust_project,
                "relocated-rust",
                [*rust_command, "."],
                env,
                runtime,
                ".",
                "pass",
                0,
                3,
                "all",
            )
            report_once(
                evidence,
                python_project,
                "relocated-python",
                [*python_command, "."],
                python_env,
                runtime,
                ".",
                "pass",
                0,
                3,
                "all",
            )
            relocated_runners = True
            server = Mcp(evidence, byo, semantic, env, version, "relocated")
            try:
                semantic_queries(server, runtime, env, full=False)
            finally:
                server.close()

        # A RED relocated MCP query keeps relocation RED, but once the moved home
        # and both runners passed, update and uninstall still have a valid start.
        if not evidence.gate("relocation", relocate) and not relocated_runners:
            raise Halt()

        def update():
            # An optional second immutable built bundle enables a version-change
            # update. Reinstalling the exact bundle is recorded as same-version
            # only; it cannot earn the actual update-preservation gate.
            if args.update_bundle is None or args.update_manifest_sha256 is None:
                raise Pending(
                    "a second hash-bound built bundle/version is required for actual runtime update preservation"
                )
            updated_cppcheck = expected_digest(
                args.update_cppcheck_sha256, "--update-cppcheck-sha256"
            )
            if (
                digest(args.update_bundle / "release-manifest.json")
                != args.update_manifest_sha256
            ):
                raise Setup(
                    "second immutable update manifest differs from explicit SHA256"
                )
            other = read_json(args.update_bundle / "release-manifest.json")
            require(
                other["version"] != version,
                "same-version reinstall is not update evidence",
            )
            require(
                other["source"]["agent_workspace"]["commit"] == args.python_commit,
                "update Python runner source differs; supply a matching independent input in a separate invocation",
            )
            for item in other["files"]:
                verify_file(below(args.update_bundle, item["path"]), item)
            # A distinct build needs its own independent raw oracle, even when
            # the manifest's digest is explicitly bound too.
            update_inventory = {item["path"]: item for item in other["files"]}
            require(
                len(update_inventory) == len(other["files"]),
                "duplicate update inventory entries",
            )
            program_identity(
                args.update_bundle,
                update_inventory,
                read_json(args.update_bundle / "analysis/runtime.json"),
                updated_cppcheck,
            )
            evidence.report["update_input"] = {
                "manifest": file_record(args.update_bundle / "release-manifest.json"),
                "version": other["version"],
                "expected_cppcheck_sha256": updated_cppcheck,
                "files": tree_record(args.update_bundle),
            }
            evidence.run(
                "update-public-installer",
                [str(byo), "install-runtime", "--bundle", str(args.update_bundle)],
                env,
                lab,
            )
            for project in projects:
                evidence.run(
                    f"update-project-{project.name}",
                    [str(byo), "workspace", "update", "--project", str(project)],
                    env,
                    lab,
                )
                assert_preserved(project, snapshots[project])
            updated_runtime = home / "data/versions" / other["version"]
            assert_runtime(updated_runtime, other)
            report_once(
                evidence,
                rust_project,
                "updated-rust",
                [*rust_command, "."],
                env,
                updated_runtime,
                ".",
                "pass",
                0,
                3,
                "all",
                cppcheck_sha256=updated_cppcheck,
            )
            updated_python_env = {
                **python_env,
                "PATH": os.pathsep.join(
                    (str(updated_runtime / "analysis/cppcheck"), env["PATH"])
                ),
            }
            report_once(
                evidence,
                python_project,
                "updated-python",
                [*python_command, "."],
                updated_python_env,
                updated_runtime,
                ".",
                "pass",
                0,
                3,
                "all",
                cppcheck_sha256=updated_cppcheck,
            )
            server = Mcp(evidence, byo, semantic, env, other["version"], "updated")
            try:
                semantic_queries(server, updated_runtime, env, full=False)
            finally:
                server.close()

        evidence.gate("update-preservation", update)

        def uninstall():
            # Project then global uninstall both preserve project-owned files.
            evidence.run(
                "project-uninstall",
                [str(byo), "uninstall", "--project", str(rust_project)],
                env,
                lab,
            )
            assert_preserved(rust_project, snapshots[rust_project])
            evidence.run(
                "project-reinit",
                [str(byo), "init", "--project", str(rust_project)],
                env,
                lab,
            )
            # The public Windows self-delete helper intentionally outlives its
            # parent while waiting for the running image/Defender handles. Use
            # the existing installed-test contract's finite 130-second grace.
            evidence.run(
                "global-uninstall",
                [str(byo), "uninstall", "--global"],
                env,
                lab,
                cleanup_timeout=130,
            )
            for project in projects:
                assert_preserved(project, snapshots[project])
            deadline = time.monotonic() + 30
            while byo.exists() and time.monotonic() < deadline:
                time.sleep(0.1)
            require(
                not byo.exists() and not (home / "data/current.json").exists(),
                "global uninstall left active product",
            )

        evidence.gate("project-global-uninstall", uninstall)
        success = all(g["status"] == "PASS" for g in evidence.report["gates"].values())
    except Halt:
        pass
    except (Setup, Red) as exc:
        evidence.report["gates"]["install"] = {
            "status": "SETUP_FAILURE" if isinstance(exc, Setup) else "RED",
            "reason": str(exc),
        }
        (evidence.root / "execution-exception.log").write_text(
            traceback.format_exc(), encoding="utf-8"
        )
    except Exception as exc:
        evidence.report["gates"]["install"] = {
            "status": "SETUP_FAILURE",
            "reason": repr(exc),
        }
        (evidence.root / "execution-exception.log").write_text(
            traceback.format_exc(), encoding="utf-8"
        )
    finally:
        if inputs:
            changed = [
                p
                for p, item in inputs["protected"].items()
                if not Path(p).is_file() or file_record(Path(p)) != item
            ]
            evidence.report["read_only_inputs_unchanged"] = not changed
            if changed:
                evidence.report["gates"]["immutable-inputs"] = {
                    "status": "RED",
                    "reason": f"protected inputs changed: {changed}",
                }
                success = False
        # Retain entire private lab reports before any successful lab removal.
        for project in lab.glob("*"):
            reports = project / ".firm/code-analysis/reports"
            if reports.is_dir():
                destination = evidence.root / "all-project-reports" / project.name
                shutil.copytree(reports, destination, dirs_exist_ok=True)
        if success and not args.keep_lab:
            shutil.rmtree(lab)
            evidence.report["cleanup"]["lab_removed"] = True
        else:
            evidence.report["cleanup"]["lab_removed"] = False
    return evidence.save()


if __name__ == "__main__":
    raise SystemExit(main())
