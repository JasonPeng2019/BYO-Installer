"""Finite hosted-VM installed forwarding/store preparation, separate from final acceptance.

Reuse the strict compiled selector and normal installed MCP clients. The extra
store boundary is available only after actual OS profile/KnownFolder ownership
and this job's ephemeral hosted-runner provenance are recorded. The original
OwnedObservationEnvironment and its default strict refusal stay unchanged.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import traceback
import uuid

from final_public_mcp import OwnedObservationEnvironment, SIDECAR_ENVIRONMENT, digest, snapshot
from test_installed_e2e import read_line, start_initialized_mcp, stop_mcp


def write(path, record):
    path.write_text(json.dumps(record, indent=2, default=str) + "\n", encoding="utf-8")


def native_boundary():
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise RuntimeError("Only the assigned existing workflow's ephemeral hosted VM qualifies")
    record = {name: os.environ.get(name) for name in (
        "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
        "GITHUB_JOB", "RUNNER_NAME", "RUNNER_ENVIRONMENT", "ImageOS", "ImageVersion",
    )}
    assert record["GITHUB_REPOSITORY"] == "JasonPeng2019/BYO-Installer"
    assert all(record[name] for name in ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB"))
    record.update(platform=platform.platform(), machine=platform.machine(), node=platform.node())
    if os.name == "nt":
        token = wintypes.HANDLE()
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        userenv = ctypes.WinDLL("userenv", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        advapi.OpenProcessToken.restype = wintypes.BOOL
        userenv.GetUserProfileDirectoryW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        userenv.GetUserProfileDirectoryW.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            size = wintypes.DWORD()
            userenv.GetUserProfileDirectoryW(token, None, ctypes.byref(size))
            buffer = ctypes.create_unicode_buffer(size.value)
            if not userenv.GetUserProfileDirectoryW(token, buffer, ctypes.byref(size)):
                raise ctypes.WinError(ctypes.get_last_error())
            profile = Path(buffer.value).resolve(strict=True)
        finally:
            kernel.CloseHandle(token)
        shell = ctypes.WinDLL("shell32", use_last_error=True)
        shell.SHGetKnownFolderPath.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.HANDLE, ctypes.POINTER(wintypes.LPWSTR)]
        shell.SHGetKnownFolderPath.restype = ctypes.c_long
        ole = ctypes.WinDLL("ole32")
        ole.CoTaskMemFree.argtypes = [ctypes.c_void_p]
        guid = ctypes.create_string_buffer(uuid.UUID("f1b32785-6fba-4fcf-9d55-7b8e7f157091").bytes_le)
        output = wintypes.LPWSTR()
        if shell.SHGetKnownFolderPath(guid, 0, None, ctypes.byref(output)) != 0:
            raise RuntimeError("native LocalAppData KnownFolder unavailable")
        try:
            local = Path(output.value).resolve(strict=True)
        finally:
            ole.CoTaskMemFree(ctypes.cast(output, ctypes.c_void_p))
        assert local.is_relative_to(profile)
        who = subprocess.check_output(["whoami", "/user", "/fo", "csv", "/nh"], text=True).strip()
        sid = next(csv.reader([who]))[-1]
        assert sid.startswith("S-1-")
        groups = subprocess.check_output(["whoami", "/groups", "/fo", "csv", "/nh"], text=True)
        group_sids = {value for row in csv.reader(groups.splitlines()) for value in row if value.startswith("S-1-")}
        owners = {}
        for path in (profile, local):
            command = ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                       "& { param($p) (Get-Acl -LiteralPath $p).GetOwner([System.Security.Principal.SecurityIdentifier]).Value }",
                       str(path)]
            owner = subprocess.check_output(command, text=True).strip()
            assert owner in {sid, *group_sids}, (path, owner, sid)
            owners[str(path)] = {"owner_sid": owner, "identity": [path.stat().st_dev, path.stat().st_ino]}
        record.update(token_account_sid=sid, token_group_sids=sorted(group_sids), native_api="GetUserProfileDirectoryW + SHGetKnownFolderPath(LocalAppData)",
                      knownfolder=str(local), ownership=owners)
        app_data = local / "BYO"
    else:
        import pwd

        entry = pwd.getpwuid(os.getuid())
        profile = Path(entry.pw_dir).resolve(strict=True)
        assert profile.stat().st_uid == os.getuid()
        app_data = profile / ("Library/Application Support/BYO" if sys.platform == "darwin" else ".local/share/BYO")
        owners = {}
        path = app_data.parent
        while path.is_relative_to(profile):
            if path.exists():
                assert path.resolve() == path and path.stat().st_uid == os.getuid(), path
                owners[str(path)] = {"uid": path.stat().st_uid, "identity": [path.stat().st_dev, path.stat().st_ino]}
            if path == profile:
                break
            path = path.parent
        record.update(uid=os.getuid(), gid=os.getgid(), passwd_name=entry.pw_name,
                      native_api="getuid + getpwuid", ownership=owners)
    assert app_data.resolve() == app_data and app_data.is_relative_to(profile)
    record.update(native_profile=str(profile), app_data=str(app_data),
                  scope="This ephemeral Actions job only; no local account or final ROOT common freeze claimed")
    return record


class HostedObservationEnvironment(OwnedObservationEnvironment):
    def __init__(self, evidence, boundary):
        self.native = boundary
        super().__init__(evidence)
        self.environment["HOME"] = boundary["native_profile"]
        self.environment["USERPROFILE"] = boundary["native_profile"]
        if os.name == "nt":
            self.environment["LOCALAPPDATA"] = boundary["knownfolder"]
            self.environment["APPDATA"] = str(Path(boundary["native_profile"]) / "AppData/Roaming")
            drive, tail = os.path.splitdrive(boundary["native_profile"])
            self.environment.update(HOMEDRIVE=drive, HOMEPATH=tail)

    def owned_path(self, raw):
        if raw and Path(raw).is_absolute():
            path = Path(raw).resolve()
            native = Path(self.native["app_data"])
            if path == native or path.is_relative_to(native):
                return path
        return super().owned_path(raw)

    def check_candidates(self, record, runtime):
        super().check_candidates(record, runtime)
        if Path(record["app_data"]).resolve() != Path(self.native["app_data"]):
            raise RuntimeError("Compiled selector differs from the OS-qualified native store")

    def require_qualified(self):
        super().require_qualified()
        for raw, expected in self.native["ownership"].items():
            path = Path(raw)
            assert [path.stat().st_dev, path.stat().st_ino] == expected["identity"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    commands, wire = [], []
    record = {"schema": "bc05-hosted-installed-observation/v1", "outcome": "UNRUN"}
    server = None
    observations = None
    try:
        boundary = native_boundary()
        write(evidence / "native-boundary.json", boundary)
        record["native_boundary"] = boundary
        observations = HostedObservationEnvironment(evidence, boundary)
        bundle = args.bundle.resolve(strict=True)
        manifest = json.loads((bundle / "release-manifest.json").read_text(encoding="utf-8"))
        version = manifest["version"]
        suffix = ".exe" if os.name == "nt" else ""

        def command(name, argv, environment=None, cwd=None):
            if observations.qualification is not None:
                observations.require_qualified()
            result = subprocess.run(argv, env=environment or observations.environment,
                                    cwd=cwd or observations.project, capture_output=True,
                                    text=True, encoding="utf-8", timeout=120, check=False)
            commands.append({"name": name, "argv": argv, "exit": result.returncode,
                             "stdout": result.stdout, "stderr": result.stderr})
            write(evidence / "commands.json", commands)
            if result.returncode != 0:
                raise RuntimeError(f"{name} exited {result.returncode}")
            return result

        record["compiled_selector_qualification"] = observations.qualify(bundle, version, command)
        root = Path(boundary["app_data"])
        before_store = snapshot(root)
        record["store_before"] = before_store
        command("install", [str(bundle / ("byo" + suffix)), "install-runtime", "--bundle", str(bundle)])
        byo = observations.home / "bin" / ("byo" + suffix)
        runtime = observations.home / "data/versions" / version
        sidecar = runtime / "sidecar" / ("byo-mcp-sidecar" + suffix)
        assert digest(byo) == observations.qualification["launcher_sha256"]
        assert digest(sidecar) == observations.qualification["sidecar_sha256"]
        before_runtime = snapshot(runtime)
        command("status", [str(byo), "status"])
        command("doctor", [str(byo), "doctor", "--global", "--json"])
        command("init", [str(byo), "init", "--project", str(observations.project)])
        server = start_initialized_mcp(byo, observations.project, observations.environment, version,
                                       cwd=runtime, diagnostics_path=evidence / "mcp-stderr.log")
        wire.append({"initialize": server.initialization_raw})
        import psutil

        qualification = {
            "bc05_hosted_preparation_authorized": True, "source_commit": os.environ["GITHUB_SHA"],
            "ci_input_sha256": digest(Path(__file__).resolve().parents[2] / "bc01-ci/CI-INPUTS.json"),
            "os_account_proof_sha256": digest(evidence / "native-boundary.json"),
            "native_knownfolder_proof_sha256": digest(evidence / "native-boundary.json"),
            "sidecar_environment_contains_no_credentials": True,
            "credential_boundary": "Actual installed launcher clears child environment to the exact nonsecret whitelist; no client/provider environment inspected",
        }
        write(evidence / "observer-qualification.json", qualification)
        expected = {name: observations.environment.get(name) for name in SIDECAR_ENVIRONMENT}
        write(evidence / "expected.json", expected)
        command("actual-forwarding", [sys.executable, "-B", str(Path(__file__).with_name("final_forwarded_environment.py")),
                "--qualification", str(evidence / "observer-qualification.json"),
                "--launcher-pid", str(server.process.pid), "--launcher-birth", str(psutil.Process(server.process.pid).create_time()),
                "--launcher-sha256", digest(byo), "--sidecar", str(sidecar), "--sidecar-sha256", digest(sidecar),
                "--expected", str(evidence / "expected.json"), "--evidence", str(evidence / "actual-forwarding.json")])

        def tool(number, name, arguments):
            request = {"jsonrpc": "2.0", "id": number, "method": "tools/call",
                       "params": {"name": name, "arguments": arguments}}
            wire.append({"send": request})
            server.process.stdin.write(json.dumps(request) + "\n")
            server.process.stdin.flush()
            while True:
                reply = json.loads(read_line(server.process.stdout))
                wire.append({"receive": reply})
                write(evidence / "wire.json", wire)
                if reply.get("id") == number:
                    assert "error" not in reply, reply
                    result = reply["result"]
                    assert not result.get("isError"), result
                    return "\n".join(item.get("text", "") for item in result.get("content", []))

        record["handshake"] = tool(10, "initialization_handshake", {"workspace_path": str(observations.project)})
        health = json.loads(tool(11, "server_health_check", {}))
        record["health"] = health
        assert health["recording"]["store_state"] == "app_data", health
        stop_mcp(server)
        record["protocol_eof_exit"] = server.process.returncode
        server = None
        after_store = snapshot(root)
        new_records = {path: value for path, value in after_store.items()
                       if path.startswith("server_data/") and path.endswith(".jsonl") and path not in before_store}
        assert new_records, "No new owned workspace records after actual installed handshake"
        for path, value in before_store.items():
            assert after_store.get(path) == value, "An earlier store entry changed: " + path
        record["new_workspace_records"] = new_records
        record["runtime_unchanged"] = snapshot(runtime) == before_runtime
        assert record["runtime_unchanged"]
        record["outcome"] = "PASS"
    except Exception:
        record.update(outcome="FAIL", traceback=traceback.format_exc())
    finally:
        if server is not None:
            try:
                stop_mcp(server)
                record["cleanup_exit"] = server.process.returncode
            except Exception:
                record["cleanup_error"] = traceback.format_exc()
                record["outcome"] = "FAIL"
        record["commands"] = commands
        record["wire"] = wire
        if observations is not None:
            record["qualified_environment"] = observations.qualification
        write(evidence / "result.json", record)
    print(json.dumps({"outcome": record["outcome"], "evidence": str(evidence)}), flush=True)
    return int(record["outcome"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
