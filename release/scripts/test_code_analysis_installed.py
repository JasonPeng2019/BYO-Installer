#!/usr/bin/env python3
"""Independent Windows x86_64 analysis acceptance through executable interfaces.

Preparation is not installed acceptance. No artifact is built or downloaded here.
Run the focused RED first on an actual pre-packaging bundle (absence of the
analysis mapping/programs is RED; absence of the bundle itself is SETUP_FAILURE):

  python release/scripts/test_code_analysis_installed.py --archive-only \
    --archive C:/inputs/byo.zip --archive-sha256 <64 hex> \
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

Availability input schema: {"schema":"installed-analysis-availability/v1",
"cases":[{"state":"setup_lite","profile":"professional","root":"...",
"files":{".firm/...":{"sha256":"...","size":123}},
"witness":{"tool":"get_capabilities","arguments":{...},
"state_pointer":"/some/public/tier", "profile_pointer":"/some/public/profile",
"equals":{"/some/public/tier":"setup-lite","/some/public/profile":"professional"}}}]}. Supply ALL twelve
state/profile pairs: no_board, no_setup, setup_lite, setup_full,
revoked_unvalidated, corrupt_policy x personal, professional. Files are existing
passive policy/profile fixtures, copied without internal APIs. The public witness
must demonstrate the actual state/profile; labels alone earn no credit. This test
does not create policies, unlock a board, probe hardware, or fake an MCP backend.
Missing cases/witnesses are pending gates and exit nonzero, never skipped credit.

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
# Final 0.1.8 artifact rebuilt by the accepted lock recipe (/pathmap, /PDBALTPATH),
# not the earlier probe input. The MSVC link is not bit-reproducible: an
# independent rebuild from the same pins differed only in COFF/debug timestamps,
# CheckSum and the CodeView GUID, and matched after zeroing exactly those fields.
CPP_EXE_SHA = "3bc2924b33d707644b7b80c2d619907f3b7517a17c8c62120a0cfae212df0f13"
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

    def identity(self, pid: int) -> dict | None:
        handle = self.k.OpenProcess(0x1000 | 0x100000, False, pid)
        if not handle:
            return None
        try:
            times = [wintypes.FILETIME() for _ in range(4)]
            if not self.k.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
                return None
            created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
            buf = ctypes.create_unicode_buffer(32768)
            size = wintypes.DWORD(len(buf))
            if not self.k.QueryFullProcessImageNameW(
                handle, 0, buf, ctypes.byref(size)
            ):
                return None
            return {
                "pid": pid,
                "creation_filetime": created,
                "image": buf.value,
                "alive": self.k.WaitForSingleObject(handle, 0) == 258,
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
        current = self.identity(identity["pid"])
        return bool(
            current
            and current["alive"]
            and current["creation_filetime"] == identity["creation_filetime"]
        )

    def terminate(self, identity: dict) -> None:
        # Query and terminate through the SAME retained handle after checking time.
        handle = self.k.OpenProcess(0x1000 | 0x100000 | 1, False, identity["pid"])
        if not handle:
            return
        try:
            times = [wintypes.FILETIME() for _ in range(4)]
            if self.k.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
                created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
                if created == identity["creation_filetime"]:
                    self.k.TerminateProcess(handle, 99)
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
            self.error = repr(exc)

    def finish(self, forced: bool = False) -> list[dict]:
        self.stop.set()
        self.thread.join(timeout=5)
        require(not self.thread.is_alive(), "owned process sampler did not stop")
        require(
            not hasattr(self, "error"),
            f"process sampling failed: {getattr(self, 'error', '')}",
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
    for program, sha in (("cppcheck", CPP_EXE_SHA), ("clangd", CLANG_EXE_SHA)):
        record = mapping["programs"][program]
        require(
            digest(below(args.bundle, record["executable"])) == sha,
            f"unpinned {program} binary shipped",
        )
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
    cppcheck_sha256: str = CPP_EXE_SHA,
    failure_exit: int = 1,
) -> dict:
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
        return value

    def record_child_argv(self, env: dict) -> None:
        children = [
            r
            for r in list(self.owned.records.values())
            if Path(r["image"]).name.casefold() == "clangd.exe"
        ]
        require(
            children,
            "no real owned clangd PID+creation was observed; sampling gap remains RED",
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
    if args.availability_inputs is None or args.availability_sha256 is None:
        raise Pending(
            "all safety tiers/profiles require immutable passive fixtures and PUBLIC state/profile witnesses; no private test seams allowed"
        )
    if digest(args.availability_inputs) != args.availability_sha256:
        raise Setup("availability input manifest differs from explicit digest")
    inputs = read_json(args.availability_inputs)
    if inputs.get("schema") != "installed-analysis-availability/v1":
        raise Setup("unsupported availability input schema")
    cases = inputs["cases"]
    needed = {
        (state, profile) for state in STATES for profile in ("personal", "professional")
    }
    actual = {(c["state"], c["profile"]) for c in cases}
    if actual != needed or len(cases) != len(needed):
        raise Pending(
            f"required state/profile pairs missing or duplicated: {sorted(needed - actual)}"
        )
    for case in cases:
        label = f"{case['state']}-{case['profile']}"
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
        for relative, record in case["files"].items():
            source = below(Path(case["root"]), relative)
            verify_file(source, record)
            target = below(project, relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        witness = case.get("witness", {})
        if witness.get("tool") not in {
            "get_capabilities",
            "get_server_info",
            "get_code_analysis_status",
        } or not witness.get("equals"):
            raise Pending(f"{label} lacks a passive PUBLIC state/profile witness")
        equals = witness["equals"]
        state_pointer, profile_pointer = (
            witness.get("state_pointer"),
            witness.get("profile_pointer"),
        )
        if (
            state_pointer not in equals
            or profile_pointer not in equals
            or equals[profile_pointer] != case["profile"]
            or str(equals[state_pointer]).replace("-", "_") != case["state"]
        ):
            raise Pending(
                f"{label} public witness must explicitly identify both the actual state and monitoring profile"
            )
        protected = {p: file_record(below(project, p)) for p in case["files"]}
        server = Mcp(evidence, byo, project, env, version, label)
        try:
            observed = server.tool(
                witness["tool"], witness.get("arguments", {}), analysis=False
            )
            for pointer, expected in witness["equals"].items():
                require(pointer.startswith("/"), "witness pointer must be JSON pointer")
                value = observed
                for part in pointer[1:].split("/"):
                    key = part.replace("~1", "/").replace("~0", "~")
                    value = value[int(key)] if isinstance(value, list) else value[key]
                require(
                    value == expected,
                    f"{label} public state/profile witness mismatch: {pointer}={value!r}",
                )
            semantic_queries(server, runtime, env, full=False)
        finally:
            server.close()
        for relative, record in protected.items():
            verify_file(below(project, relative), record, product=True)
        write_json(
            evidence.root / f"availability-{label}.json",
            {"public_witness": observed, "preserved": protected},
        )


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
        "rustc-sha256",
        "availability-sha256",
        "update-manifest-sha256",
    ):
        parser.add_argument(f"--{name}")
    parser.add_argument(
        "--temp-parent",
        type=Path,
        help="existing short local temp root; default native TEMP",
    )
    parser.add_argument("--keep-lab", action="store_true")
    args = parser.parse_args()
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
                server.close()
            assert_preserved(semantic, before)
            evidence.report["gates"]["stdio-idle-eof-cleanup"] = {
                "status": "PASS",
                "evidence": str(server.path),
            }

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

        def relocate():
            nonlocal home, env, byo, runtime, rust_command, python_env
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
            server = Mcp(evidence, byo, semantic, env, version, "relocated")
            try:
                semantic_queries(server, runtime, env, full=False)
            finally:
                server.close()

        if not evidence.gate("relocation", relocate):
            raise Halt()

        def update():
            # An optional second immutable built bundle enables a version-change
            # update. Reinstalling the exact bundle is recorded as same-version
            # only; it cannot earn the actual update-preservation gate.
            if args.update_bundle is None or args.update_manifest_sha256 is None:
                raise Pending(
                    "a second hash-bound built bundle/version is required for actual runtime update preservation"
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
            # Each rebuild links a new Cppcheck hash; bind the update runtime to
            # its own explicitly hash-bound manifest, never to the first pin.
            updated_cppcheck = [
                item["sha256"]
                for item in other["files"]
                if item["path"] == "analysis/cppcheck/cppcheck.exe"
            ]
            require(
                len(updated_cppcheck) == 1,
                "update manifest lacks one installed Cppcheck record",
            )
            evidence.report["update_input"] = {
                "manifest": file_record(args.update_bundle / "release-manifest.json"),
                "version": other["version"],
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
                cppcheck_sha256=updated_cppcheck[0],
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
                cppcheck_sha256=updated_cppcheck[0],
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
