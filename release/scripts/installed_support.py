"""Shared installed command/MCP transport; assertions live in the scenarios."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import queue
import shutil
import subprocess
import sys
import tarfile
import zipfile
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, TextIO

class AcceptanceFailure(RuntimeError):
    pass


@dataclass
class InitializedMcp:
    """A running MCP server and its file-backed diagnostic capture."""

    process: subprocess.Popen[str]
    diagnostics: TextIO
    initialization_raw: str = ""


def invoke(
    argv: list[str],
    *,
    env: dict[str, str],
    cwd: Path | None = None,
    stdin: str | None = None,
    expected: int = 0,
    timeout: float = 60,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            input=stdin,
            text=True,
            # The launcher emits UTF-8 on every platform. Without an explicit
            # encoding, text mode decodes with the locale codepage (cp1252 on the
            # hosted Windows runner), which mojibakes non-ASCII receipt paths such
            # as a Unicode project directory and breaks path-identity assertions.
            encoding="utf-8",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AcceptanceFailure(
            f"{argv!r} timed out after {timeout}s\nstdout:\n{exc.stdout!r}\nstderr:\n{exc.stderr!r}"
        ) from exc
    if completed.returncode != expected:
        raise AcceptanceFailure(
            f"{' '.join(argv)} returned {completed.returncode}, expected {expected}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def read_line(stream: Any, timeout: float = 30.0) -> str:
    result: queue.Queue[object] = queue.Queue(maxsize=1)

    def reader() -> None:
        try:
            result.put(stream.readline())
        except BaseException as exc:
            result.put(exc)

    threading.Thread(target=reader, daemon=True).start()
    try:
        item = result.get(timeout=timeout)
    except queue.Empty as exc:
        raise AcceptanceFailure("MCP initialization response timed out") from exc
    if isinstance(item, BaseException):
        raise AcceptanceFailure(f"MCP response read failed: {item}") from item
    if not item:
        raise AcceptanceFailure("MCP server closed stdout before initialization")
    return str(item)


def start_initialized_mcp(
    byo: Path,
    project: Path,
    env: dict[str, str],
    expected_version: str,
    *,
    cwd: Path | None = None,
    diagnostics_path: Path | None = None,
) -> InitializedMcp:
    # RegistryFastMCP redirects every non-protocol write to stderr so stdout
    # remains valid JSON-RPC. A PIPE would therefore deadlock startup once the
    # server fills the OS pipe before this harness gets around to reading it.
    # Keep diagnostics for a useful failure report, but let the operating system
    # write them directly to a temporary file instead of applying backpressure.
    diagnostics = (
        diagnostics_path.open("w+t", encoding="utf-8")
        if diagnostics_path is not None
        else tempfile.TemporaryFile(mode="w+t", encoding="utf-8")
    )
    process = subprocess.Popen(
        [str(byo), "mcp", "serve", "--project", str(project)],
        env=env,
        cwd=cwd or project,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=diagnostics,
        text=True,
        # Decode the sidecar's UTF-8 JSON-RPC stream explicitly; see invoke().
        encoding="utf-8",
        bufsize=1,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    try:
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "byo-acceptance", "version": "1"},
            },
        }
        process.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
        process.stdin.flush()
        initialization_raw = read_line(process.stdout)
        response = json.loads(initialization_raw)
        if response.get("id") != 1 or not isinstance(response.get("result"), dict):
            raise AcceptanceFailure(
                f"invalid MCP initialization response: {response!r}"
            )
        server_info = response["result"].get("serverInfo", {})
        if server_info.get("version") != expected_version:
            raise AcceptanceFailure(
                f"MCP server version was not bound to the release: {server_info!r}"
            )
        process.stdin.write(
            '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n'
        )
        process.stdin.flush()
    except Exception as exc:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        diagnostics.seek(0)
        diagnostic_text = diagnostics.read()
        diagnostics.close()
        raise AcceptanceFailure(
            f"MCP initialization failed: {exc}\nstderr:\n{diagnostic_text}"
        ) from exc
    return InitializedMcp(
        process=process, diagnostics=diagnostics, initialization_raw=initialization_raw
    )


def stop_mcp(server: InitializedMcp) -> None:
    process = server.process
    if process.stdin is not None:
        process.stdin.close()
    try:
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait(timeout=5)
            raise AcceptanceFailure(
                "MCP server did not stop after protocol EOF"
            ) from exc
        if process.returncode != 0:
            server.diagnostics.seek(0)
            diagnostics = server.diagnostics.read()
            raise AcceptanceFailure(
                f"MCP server returned {process.returncode} after EOF:\n{diagnostics}"
            )
    finally:
        server.diagnostics.close()


@contextlib.contextmanager
def installed_directory(*, prefix: str):
    """Keep failed owned inputs where the ordinary CI artifact upload can find them."""
    destination = os.environ.get("BYO_TEST_FAILURES")
    parent = Path(destination).resolve() if destination else None
    if parent is not None:
        parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    try:
        yield root
    except BaseException:
        print(f"Installed fixture inputs retained: {root}", file=sys.stderr)
        raise
    else:
        shutil.rmtree(root)


class OwnedChild:
    """Observe an explicitly owned live child; retain Windows kill authority by handle."""

    def __init__(self, process):
        self.process = process
        self.pid, self.birth = process.pid, process.create_time()
        self.image, self.argv = process.exe(), process.cmdline()
        self.handle = None
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            self.api = ctypes.WinDLL("kernel32", use_last_error=True)
            self.api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            self.api.OpenProcess.restype = wintypes.HANDLE
            self.api.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
            self.api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            self.api.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
            self.api.CloseHandle.argtypes = [wintypes.HANDLE]
            self.handle = self.api.OpenProcess(0x100000 | 0x1000 | 1, False, self.pid)
            if not self.handle:
                raise AcceptanceFailure(f"Cannot retain owned child handle: {self.pid}")
            times = [wintypes.FILETIME() for _ in range(4)]
            if not self.api.GetProcessTimes(self.handle, *(ctypes.byref(t) for t in times)):
                self.close()
                raise AcceptanceFailure(f"Cannot observe owned child birth: {self.pid}")
            self.native_birth = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
            if not process.is_running() or process.create_time() != self.birth:
                self.close()
                raise AcceptanceFailure(f"Owned child changed during observation: {self.pid}")

    def alive(self):
        if self.handle is not None:
            result = self.api.WaitForSingleObject(self.handle, 0)
            if result not in (0, 258):
                raise AcceptanceFailure(f"Unknown owned child state: {self.pid}")
            return result == 258
        import psutil

        return self.process.is_running() and self.process.status() != psutil.STATUS_ZOMBIE

    def retire(self):
        # Called only after a failed natural-EOF assertion. A retained handle
        # addresses its original generation; psutil checks PID reuse on POSIX.
        if self.alive():
            if self.handle is not None:
                if not self.api.TerminateProcess(self.handle, 1):
                    raise AcceptanceFailure(f"Cannot retire owned child: {self.pid}")
            else:
                self.process.kill()

    def close(self):
        if self.handle is not None:
            self.api.CloseHandle(self.handle)
            self.handle = None


class Mcp:
    """One ordinary installed MCP connection, including natural-EOF assertions."""

    def __init__(self, byo, project, env, version, *, logs):
        logs.mkdir(parents=True, exist_ok=True)
        self.path = logs / "protocol.jsonl"
        self.server = start_initialized_mcp(byo, project, env, version,
                                          diagnostics_path=logs / "stderr.log")
        self.next_id = 1
        self.children = {}
        self.closed = False

    def request(self, method, params):
        self.next_id += 1
        request = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params}
        process = self.server.process
        assert process.stdin is not None and process.stdout is not None
        with self.path.open("a", encoding="utf-8") as transcript:
            transcript.write(json.dumps({"sent": request}, ensure_ascii=False) + "\n")
            process.stdin.write(json.dumps(request, ensure_ascii=False) + "\n")
            process.stdin.flush()
            while True:
                line = read_line(process.stdout, timeout=90)
                transcript.write(line)
                response = json.loads(line)
                if response.get("id") == self.next_id:
                    if "error" in response:
                        raise AcceptanceFailure(f"{method}: {response['error']}")
                    return response["result"]

    def tool(self, name, arguments):
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError"):
            raise AcceptanceFailure(f"{name}: {result}")
        text = "\n".join(item["text"] for item in result.get("content", []) if item.get("type") == "text")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text

    def observe_children(self):
        import psutil

        for child in psutil.Process(self.server.process.pid).children(recursive=True):
            key = child.pid, child.create_time()
            if key not in self.children:
                self.children[key] = OwnedChild(child)
        return list(self.children.values())

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.observe_children()
            stop_mcp(self.server)  # Exits naturally, or raises before cleanup can mask it.
            deadline = time.monotonic() + 5
            while any(child.alive() for child in self.children.values()) and time.monotonic() < deadline:
                time.sleep(0.05)
            remaining = [child.pid for child in self.children.values() if child.alive()]
            if remaining:
                raise AcceptanceFailure(f"Owned children survived natural MCP EOF: {remaining}")
        finally:
            cleanup_errors = []
            for child in self.children.values():
                try:
                    child.retire()
                except Exception as error:
                    cleanup_errors.append(str(error))
                finally:
                    child.close()
            if cleanup_errors:
                detail = "Owned child cleanup failed: " + "; ".join(cleanup_errors)
                if sys.exc_info()[0] is None:
                    raise AcceptanceFailure(detail)
                print(detail, file=sys.stderr)

    def __enter__(self):
        return self

    def __exit__(self, kind, error, traceback):
        try:
            self.close()
        except Exception as cleanup_error:
            if error is None:
                raise
            print(f"Additional MCP cleanup failure: {cleanup_error}", file=sys.stderr)


@contextlib.contextmanager
def installed_lab(bundle_variable="BYO_INSTALLED_BUNDLE"):
    """Install one supplied genuine bundle into an owned home; never build a product."""
    import pytest
    from types import SimpleNamespace

    supplied = os.environ.get(bundle_variable)
    if not supplied:
        pytest.skip(f"UNRUN installed prerequisite: supply {bundle_variable}")
    if os.name == "nt" and os.environ.get("GITHUB_ACTIONS") != "true":
        pytest.skip("UNRUN Windows lab prerequisite: a disposable hosted account with native KnownFolders")
    bundle = Path(supplied).resolve(strict=True)
    manifest = json.loads((bundle / "release-manifest.json").read_text(encoding="utf-8"))
    with installed_directory(prefix="byo-installed-") as root:
        home, profile, temporary = (root / part for part in ("product", "profile", "temp"))
        profile.mkdir(); temporary.mkdir()
        allowed = ("PATH", "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL")
        env = {key: os.environ[key] for key in allowed if key in os.environ}
        env.update({"BYO_HOME": str(home), "HOME": str(profile), "USERPROFILE": str(profile),
                    "APPDATA": str(profile / "roaming"), "LOCALAPPDATA": str(profile / "local"),
                    "TMPDIR": str(temporary), "TEMP": str(temporary), "TMP": str(temporary),
                    "PYTHONUTF8": "1"})
        suffix = ".exe" if os.name == "nt" else ""
        invoke([str(bundle / ("byo" + suffix)), "install-runtime", "--bundle", str(bundle)],
               env=env, cwd=root, timeout=300)
        byo = home / "bin" / ("byo" + suffix)
        current = json.loads((home / "data/current.json").read_text(encoding="utf-8"))
        runtime = home / "data" / current["relative_runtime"]
        assert byo.is_file() and runtime.is_dir(), current
        assert current["version"] == manifest["version"], current
        assert (runtime / "release-manifest.json").read_bytes() == (bundle / "release-manifest.json").read_bytes()
        yield SimpleNamespace(root=root, home=home, env=env, byo=byo, runtime=runtime,
                              bundle=bundle, version=manifest["version"], manifest=manifest)



def sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


MAX_ENTRIES = 20_000
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024


def safe_relative(name: str, seen: set[str]) -> Path:
    path = PurePosixPath(name)
    normalized = name.rstrip("/").lower()
    if (
        "\\" in name
        or path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or normalized in seen
    ):
        raise RuntimeError(f"candidate archive contains an unsafe path: {name!r}")
    seen.add(normalized)
    return Path(*path.parts)


def extract_exact(archive: Path, destination: Path) -> Path:
    seen: set[str] = set()
    total = 0
    entries = 0
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as handle:
            for member in handle.infolist():
                entries += 1
                relative = safe_relative(member.filename, seen)
                file_type = (member.external_attr >> 16) & 0o170000
                if file_type not in {0, 0o040000, 0o100000}:
                    raise RuntimeError("candidate ZIP contains a forbidden entry type")
                if member.file_size > MAX_FILE_BYTES:
                    raise RuntimeError("candidate ZIP contains an oversized file")
                total += member.file_size
                target = destination / relative
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with handle.open(member) as source, target.open("xb") as output:
                        shutil.copyfileobj(source, output)
                    if os.name != "nt" and member.external_attr >> 16:
                        target.chmod((member.external_attr >> 16) & 0o777)
                if entries > MAX_ENTRIES or total > MAX_TOTAL_BYTES:
                    raise RuntimeError("candidate ZIP exceeds extraction limits")
    else:
        with tarfile.open(archive, "r:gz") as handle:
            for member in handle:
                entries += 1
                relative = safe_relative(member.name, seen)
                if not (member.isfile() or member.isdir()):
                    raise RuntimeError("candidate tar contains a forbidden entry type")
                if member.size > MAX_FILE_BYTES:
                    raise RuntimeError("candidate tar contains an oversized file")
                total += member.size
                target = destination / relative
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = handle.extractfile(member)
                    if source is None:
                        raise RuntimeError("candidate tar file could not be read")
                    with source, target.open("xb") as output:
                        shutil.copyfileobj(source, output)
                    if os.name != "nt":
                        target.chmod(member.mode & 0o777)
                if entries > MAX_ENTRIES or total > MAX_TOTAL_BYTES:
                    raise RuntimeError("candidate tar exceeds extraction limits")
    roots = [path for path in destination.iterdir() if path.is_dir()]
    if entries == 0 or len(roots) != 1:
        raise RuntimeError("candidate archive does not contain exactly one bundle")
    return roots[0]


def run_checked(argv: list[str]) -> str:
    completed = subprocess.run(
        argv,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"{argv!r} failed:\n{completed.stdout}")
    return completed.stdout


def verify_platform(bundle: Path, archive: Path, public_key: Path | None) -> list[str]:
    evidence: list[str] = []
    if sys.platform == "darwin":
        subprocess.run(
            ["xattr", "-w", "com.apple.quarantine", "0081;BYO", str(bundle)], check=True
        )
        evidence.append(
            run_checked(["codesign", "--verify", "--deep", "--strict", str(bundle)])
        )
        for executable in (
            bundle / "byo",
            bundle / "sidecar/byo-mcp-sidecar",
        ):
            evidence.append(
                run_checked(["spctl", "--assess", "--type", "execute", str(executable)])
            )
    elif os.name == "nt":
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            raise RuntimeError("PowerShell is unavailable")
        script = Path(__file__).with_name("verify_authenticode.ps1")
        evidence.append(
            run_checked(
                [
                    powershell,
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                    str(script),
                    "-Bundle",
                    str(bundle),
                ]
            )
        )
    else:
        libc = run_checked(["getconf", "GNU_LIBC_VERSION"]).strip()
        if libc != "glibc 2.28":
            raise RuntimeError(
                f"clean Linux runner is not the declared baseline: {libc}"
            )
        signature = archive.with_name(f"{archive.name}.sig")
        if public_key is None or not signature.is_file():
            raise RuntimeError(
                "Linux clean test requires the detached signature and public key"
            )
        evidence.append(
            run_checked(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-rawin",
                    "-pubin",
                    "-inkey",
                    str(public_key),
                    "-sigfile",
                    str(signature),
                    "-in",
                    str(archive),
                ]
            )
        )
    return evidence
