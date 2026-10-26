"""Actions-only public compiled MCP checks, using an exact built bundle.

No probe is connected, no private backend seam is enabled, and no installed
response is replaced. Retains a private normal install plus every wire/CLI exit.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import traceback

from test_installed_e2e import read_line, start_initialized_mcp, stop_mcp


# Keep this projection equal to launcher/src/main.rs::SIDECAR_ENVIRONMENT.
# The observer controls check the frozen source; this is not a new allowlist.
SIDECAR_ENVIRONMENT = (
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "PATH",
    "SystemRoot",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
)

# Executed only by the exact compiled sidecar's existing run-hook command.
# Inspect every candidate without resolve_store_root(), _usable(), salt/token
# reads or server import. Audit denial is fatal even if an importer catches it.
READ_ONLY_PATH_PROBE = r"""
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

runtime, project, version = sys.argv[1:]
runtime = Path(runtime).resolve(strict=True)
denied = []
process_metadata = {Path("/proc/stat"), Path(f"/proc/{os.getpid()}/stat")}

def read_only(event, args):
    if event == "open":
        path, mode, flags = args
        writing = flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
        resolved = Path(os.fsdecode(path)).resolve() if isinstance(path, (str, bytes)) else None
        allowed_read = resolved is not None and (resolved.is_relative_to(runtime) or (sys.platform == "linux" and resolved in process_metadata))
        if writing or not allowed_read:
            denied.append(event)
            raise PermissionError("path qualification refuses store/content I/O outside the exact runtime")
    elif event in ("os.mkdir", "os.remove", "os.rename", "os.rmdir", "os.chmod", "os.chown", "os.link", "os.symlink", "subprocess.Popen", "os.system", "socket.connect"):
        denied.append(event)
        raise PermissionError("path qualification is read-only")

sys.addaudithook(read_only)
from pyocd_debug_mcp import sidecar
context = sidecar._install_runtime_context(SimpleNamespace(
    project_root=project, runtime_root=str(runtime), launcher_version=version,
    workflow_protocol=1), require_capsule=False)
from pyocd_debug_mcp import local_env
dotenv_candidates = [Path.cwd() / ".env", Path(local_env.__file__).resolve().parents[2] / ".env"]
assert all(path.resolve().is_relative_to(runtime) and not path.exists() for path in dotenv_candidates), "release .env routing needs ROOT qualification"
from pyocd_debug_mcp.monitor import paths
import platformdirs
import psutil

assert paths._cached_root is None and paths._override_root is None
assert not os.environ.get(paths.MONITOR_ROOT_ENV)
app_data = paths._app_data_candidate()
operator = paths._operator_candidate()
assert paths._cached_root is None and not denied, denied
print(json.dumps({
    "schema": "fr16-read-only-paths/v1", "pid": os.getpid(),
    "creation_time": psutil.Process().create_time(), "executable": sys.executable,
    "platform": sys.platform, "platformdirs_version": platformdirs.__version__,
    "monitor_module": str(paths.__file__), "store_resolver_called": False,
    "denied_io": denied, "app_data": None if app_data is None else str(app_data),
    "operator": None if operator is None else str(operator),
    "project": str(context.project_root), "runtime": str(context.runtime_root),
    "runs": os.environ["PYOCD_MCP_RUNS_ROOT"], "cwd": str(Path.cwd()),
    "monitor_override": os.environ.get(paths.MONITOR_ROOT_ENV),
    "local_env_absent": True, "dotenv_candidates": [str(path) for path in dotenv_candidates],
}, sort_keys=True))
"""


class OwnedObservationEnvironment:
    """One fresh observation owner; qualification precedes product mutations.

    Path selection is observed in the real bundled sidecar with both inherited
    and projected environments. This does not claim a native launcher forwarding
    observation: the frozen allowlist/source and later full installed pass must
    also be joined. Windows Known Folder selection may ignore profile variables;
    an outside result requires a separately qualified disposable OS profile.
    """

    def __init__(self, evidence):
        self.root = evidence.resolve(strict=True) / "owned-observation"
        self.root.mkdir(mode=0o700, exist_ok=False)
        self.home = self.root / "product-home"
        self.profile = self.root / "profile"
        self.project = self.root / "external-project"
        self.temp = self.root / "temp"
        for path in (self.home, self.profile, self.project, self.temp):
            path.mkdir(mode=0o700)
        self.environment = {
            name: os.environ[name]
            for name in (
                "PATH",
                "SystemRoot",
                "WINDIR",
                "COMSPEC",
                "PATHEXT",
                "LANG",
                "LC_ALL",
            )
            if name in os.environ
        }
        self.environment.update(
            BYO_HOME=str(self.home),
            HOME=str(self.profile),
            USERPROFILE=str(self.profile),
            APPDATA=str(self.profile / "roaming"),
            LOCALAPPDATA=str(self.profile / "local"),
            PROGRAMDATA=str(self.profile / "program-data"),
            TMPDIR=str(self.temp),
            TEMP=str(self.temp),
            TMP=str(self.temp),
            PYTHONDONTWRITEBYTECODE="1",
        )
        if os.name == "nt":
            drive, tail = os.path.splitdrive(str(self.profile))
            self.environment.update(HOMEDRIVE=drive, HOMEPATH=tail)
        for name in ("APPDATA", "LOCALAPPDATA", "PROGRAMDATA"):
            Path(self.environment[name]).mkdir(mode=0o700)
        self._writer = threading.Lock()
        self.events = []
        self.qualification = None
        self._identity = self._identities()

    def owned_path(self, raw):
        if not raw or not Path(raw).is_absolute():
            raise RuntimeError("unqualified/unknown effective path")
        path = Path(raw).resolve()
        if not path.is_relative_to(self.root.resolve(strict=True)):
            raise RuntimeError(f"effective path outside owned environment: {path}")
        return path

    def _identities(self):
        identities = {}
        for path in (self.root, self.home, self.profile, self.project, self.temp):
            self.owned_path(str(path))
            facts = path.stat()
            if hasattr(os, "getuid") and facts.st_uid != os.getuid():
                raise RuntimeError(f"observation directory has another owner: {path}")
            identities[str(path)] = [facts.st_dev, facts.st_ino]
        return identities

    def forwarded_environment(self):
        return {
            **{
                name: self.environment[name]
                for name in SIDECAR_ENVIRONMENT
                if name in self.environment
            },
            "BYO_SIDECAR_COMPILED": "1",
        }

    @contextmanager
    def ordinary(self, name):
        """Refuse overlapping ordinary work; intentional contention is separate."""
        if not self._writer.acquire(blocking=False):
            raise RuntimeError("ordinary observation already active; no retry")
        event = {"name": name, "started_monotonic": time.monotonic()}
        self.events.append(event)
        try:
            yield
        finally:
            event["completed_monotonic"] = time.monotonic()
            self._writer.release()

    def require_qualified(self):
        if (
            self.qualification is None
            or self._identities() != self._identity
            or self.environment != self.qualification["environment"]
        ):
            raise RuntimeError("owned effective environment is not qualified")
        for path in self.qualification["public_paths"].values():
            self.owned_path(path)
        for record in self.qualification["observed_selectors"]:
            for name in ("app_data", "operator", "project", "runs"):
                self.owned_path(record[name])

    def check_candidates(self, record, runtime):
        """Validate real probe output; this alone never authorizes execution."""
        if (
            record.get("schema") != "fr16-read-only-paths/v1"
            or record.get("store_resolver_called") is not False
            or record.get("denied_io") != []
            or record.get("monitor_override")
            or record.get("local_env_absent") is not True
            or record.get("platform") != sys.platform
            or not isinstance(record.get("platformdirs_version"), str)
            or not record["platformdirs_version"]
            or not isinstance(record.get("pid"), int)
            or record["pid"] <= 0
            or not isinstance(record.get("creation_time"), (int, float))
            or not 0 < record["creation_time"] < float("inf")
        ):
            raise RuntimeError("read-only path qualification incomplete")
        for name in ("app_data", "operator", "project", "runs"):
            self.owned_path(record.get(name))
        if not record.get("dotenv_candidates") or any(
            not Path(path).resolve().is_relative_to(runtime)
            for path in record["dotenv_candidates"]
        ):
            raise RuntimeError("release local environment routing is unqualified")
        if (
            Path(record["project"]).resolve() != self.project
            or Path(record["operator"]).resolve() != self.project / ".byo-monitor"
            or Path(record["runs"]).resolve() != self.project / ".firm/runs"
            or Path(record["runtime"]).resolve() != runtime
            or Path(record["cwd"]).resolve() != runtime
        ):
            raise RuntimeError("sidecar effective runtime/project context mismatch")

    def qualify(self, bundle, version, command):
        """Read-only public paths + actual sidecar selectors, before install.

        command retains argv/env/cwd/raw streams/exits. It must perform one
        synchronous invocation. It is not a doctor/status preflight.
        """
        suffix = ".exe" if os.name == "nt" else ""
        launcher = bundle / ("byo" + suffix)
        sidecar = bundle / "sidecar" / ("byo-mcp-sidecar" + suffix)
        manifest = json.loads(
            (bundle / "release-manifest.json").read_text(encoding="utf-8")
        )
        for image in (launcher, sidecar):
            declared = [
                row
                for row in manifest["files"]
                if row["path"] == image.relative_to(bundle).as_posix()
            ]
            if (
                len(declared) != 1
                or not declared[0]["executable"]
                or not image.resolve(strict=True).is_relative_to(bundle)
                or digest(image) != declared[0]["sha256"]
            ):
                raise RuntimeError(
                    "qualification executable is not bound to the bundle inventory"
                )
        paths = json.loads(
            command(
                "qualify-launcher-paths",
                [str(launcher), "paths"],
                environment=self.environment,
                cwd=self.project,
            ).stdout
        )
        expected = {
            name: str(self.home / name)
            for name in ("data", "config", "state", "cache", "bin")
        }
        if paths != expected:
            raise RuntimeError(
                f"public launcher paths differ from owned layout: {paths}"
            )
        for path in paths.values():
            self.owned_path(path)
        script = self.root / "read_only_paths.py"
        script.write_text(READ_ONLY_PATH_PROBE, encoding="utf-8")
        observed = []
        for label, environment in (
            ("inherited", self.environment),
            ("forwarded", self.forwarded_environment()),
        ):
            reply = command(
                "qualify-sidecar-" + label,
                [
                    str(sidecar),
                    "run-hook",
                    str(script),
                    str(bundle),
                    str(self.project),
                    version,
                ],
                environment=environment,
                cwd=bundle,
            )
            record = json.loads(reply.stdout)
            self.check_candidates(record, bundle)
            if Path(record["executable"]).resolve(strict=True) != sidecar.resolve(
                strict=True
            ):
                raise RuntimeError(
                    "path selector did not run in the exact compiled sidecar"
                )
            observed.append({"environment_kind": label, **record})
        # Every possible monitor fallback is owned before _usable may probe it.
        for record in observed:
            for name in ("app_data", "operator"):
                self.owned_path(record[name]).mkdir(parents=True, exist_ok=True)
        self.qualification = {
            "environment": dict(self.environment),
            "runtime": str(bundle),
            "public_paths": paths,
            "observed_selectors": observed,
            "directory_identities": self._identity,
            "launcher_sha256": digest(launcher),
            "sidecar_sha256": digest(sidecar),
            "boundary": "actual compiled selectors; forwarding projection is source-bound, not observed launcher forwarding",
            "native_installed_acceptance": "UNRUN",
        }
        self.require_qualified()
        return self.qualification


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(root):
    return {
        p.relative_to(root).as_posix(): digest(p)
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--firmware-source", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Compiled acceptance is Actions-only after ROOT freeze")
    bundle = args.bundle.resolve(strict=True)
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    manifest = json.loads(
        (bundle / "release-manifest.json").read_text(encoding="utf-8")
    )
    version = manifest["version"]
    suffix = ".exe" if os.name == "nt" else ""
    observations = OwnedObservationEnvironment(evidence)
    home, project = observations.home, observations.project
    environment = observations.environment
    records, commands, wire = [], [], []
    server = None
    request_id = 10

    def save():
        (evidence / "ledger.json").write_text(
            json.dumps(
                {
                    "source_bundle": str(bundle),
                    "manifest_sha256": digest(bundle / "release-manifest.json"),
                    "cases": records,
                    "commands": commands,
                    "wire": wire,
                    "owned_environment": observations.qualification,
                    "owned_inputs": {
                        "root": str(observations.root),
                        "environment": environment,
                        "project": str(project),
                    },
                    "ordinary_sequence": observations.events,
                },
                indent=2,
                default=str,
            )
            + "\n",
            encoding="utf-8",
        )

    def raw_command(
        name, argv, expected=0, stdin=None, cwd=None, environment=environment
    ):
        start = time.monotonic()
        try:
            result = subprocess.run(
                argv,
                cwd=cwd,
                env=environment,
                input=stdin,
                text=True,
                encoding="utf-8",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=90,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            commands.append(
                {
                    "name": name,
                    "argv": argv,
                    "cwd": str(cwd),
                    "environment": environment,
                    "outcome": "TIMEOUT",
                    "exit": None,
                    "stdout": str(exc.stdout),
                    "stderr": str(exc.stderr),
                }
            )
            save()
            raise
        commands.append(
            {
                "name": name,
                "argv": argv,
                "cwd": str(cwd),
                "environment": environment,
                "expected_exit": expected,
                "exit": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "seconds": time.monotonic() - start,
            }
        )
        save()
        if result.returncode != expected:
            raise AssertionError(
                f"{name} exit {result.returncode}, expected {expected}"
            )
        return result

    def command(name, argv, expected=0, stdin=None, cwd=None):
        observations.require_qualified()
        if server is not None and server.process.poll() is None:
            raise RuntimeError(
                "ordinary CLI observation cannot overlap the MCP session"
            )
        with observations.ordinary(name):
            return raw_command(name, argv, expected, stdin, cwd or project)

    def case(name, function, prerequisite=True):
        if not prerequisite:
            records.append(
                {
                    "case": name,
                    "outcome": "BLOCKED",
                    "reason": "private install/project/protocol prerequisite failed; independent CLI/source checks continue",
                }
            )
            save()
            return False
        try:
            detail = function()
            records.append({"case": name, "outcome": "PASS", "detail": detail})
            return True
        except Exception:
            records.append(
                {"case": name, "outcome": "FAIL", "traceback": traceback.format_exc()}
            )
            return False
        finally:
            save()

    def rpc(method, parameters):
        nonlocal request_id
        request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": parameters,
        }
        wire.append({"send": request})
        save()
        server.process.stdin.write(json.dumps(request) + "\n")
        server.process.stdin.flush()
        while True:
            raw = read_line(server.process.stdout)
            reply = json.loads(raw)
            wire.append({"receive_raw": raw, "receive": reply})
            save()
            if reply.get("jsonrpc") != "2.0":
                raise AssertionError("non-protocol stdout")
            if reply.get("id") == request_id:
                if "error" in reply:
                    raise AssertionError(reply)
                return reply["result"]

    def tool(name, arguments):
        result = rpc("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError"):
            raise AssertionError(result)
        text = "\n".join(item.get("text", "") for item in result.get("content", []))
        return json.loads(text)

    qualified = case(
        "FR16.owned-effective-environment-before-effects",
        lambda: observations.qualify(bundle, version, raw_command),
    )
    if not qualified:
        blocked = [
            "VI14.private-install",
            "FR16.private-installed-identity",
            "FR16.ordinary-status",
            "FR16.ordinary-global-doctor",
            "VI14.external-project-init",
            "VI15.compiled-probe-child",
            "VI15.real-probe-worker-selftest",
            "VI15.initialize-from-runtime-cwd",
            "VI15.real-tools-list",
            "FR16.actual-monitor-store-health",
            "VI15.named-overview-controlled-no-probe",
            "VI15.public-relative-input-and-output",
            "VI15.immutable-runtime-destination-refusal",
            "VI15.ELF-symbol-public-path",
            "VI15.setup-public-path",
            "VI15.flash-plan-public-path",
            "VI15.protocol-EOF-and-lease-cleanup",
            "VI15.post-collection-runtime-health",
            "VI15.U1-native-client-enforcement",
            "VI15.runtime-byte-preservation",
            *[
                f"VI14.guard-latency-{label}-{i}"
                for i in range(5)
                for label in ("normal", "blocked")
            ],
            *["VI14.guard-" + label for label in ("oversized", "NUL", "malformed")],
        ]
        records.extend(
            {
                "case": name,
                "outcome": "BLOCKED",
                "dependency": "FR16.owned-effective-environment-before-effects",
                "reason": "Effective routing unqualified. ROOT must qualify owned OS profile/known-folder routing if platform selectors ignore supplied inputs. No stateful product operation or store-content inspection attempted.",
            }
            for name in blocked
        )
        save()
        return 1

    installed = case(
        "VI14.private-install",
        lambda: command(
            "install-runtime",
            [
                str(bundle / ("byo" + suffix)),
                "install-runtime",
                "--bundle",
                str(bundle),
            ],
        ),
    )
    byo = home / "bin" / ("byo" + suffix)
    runtime = home / "data/versions" / version
    observations.owned_path(str(runtime))

    def installed_identity():
        # Read only this newly created private installation's configuration.
        observations.require_qualified()
        locator_path = observations.owned_path(str(home / "bin/.byo-install.json"))
        current_path = observations.owned_path(str(home / "data/current.json"))
        locator = json.loads(locator_path.read_text(encoding="utf-8"))
        current = json.loads(current_path.read_text(encoding="utf-8"))
        expected = observations.qualification["public_paths"]
        assert locator["schema"] == 1 and locator["product"] == "byo", locator
        assert locator["paths"] == expected, locator
        assert current["version"] == version, current
        assert (
            observations.owned_path(str(home / "data" / current["relative_runtime"]))
            == runtime
        ), current
        assert current["manifest_sha256"] == digest(bundle / "release-manifest.json"), (
            current
        )
        observations.owned_path(str(runtime))
        assert digest(runtime / "release-manifest.json") == digest(
            bundle / "release-manifest.json"
        )
        assert digest(byo) == observations.qualification["launcher_sha256"]
        assert (
            digest(runtime / "sidecar" / ("byo-mcp-sidecar" + suffix))
            == observations.qualification["sidecar_sha256"]
        )
        paths = json.loads(command("installed-paths", [str(byo), "paths"]).stdout)
        assert paths == expected, paths
        observations.qualify(runtime.resolve(strict=True), version, raw_command)
        return {
            "locator": locator,
            "current": current,
            "effective_paths": paths,
            "public_launcher": str(byo.resolve(strict=True)),
            "runtime": str(runtime.resolve(strict=True)),
        }

    bound = case("FR16.private-installed-identity", installed_identity, installed)
    case(
        "FR16.ordinary-status",
        lambda: command("status", [str(byo), "status"]),
        bound,
    )
    case(
        "FR16.ordinary-global-doctor",
        lambda: command("doctor", [str(byo), "doctor", "--global", "--json"]),
        bound,
    )
    initialized = case(
        "VI14.external-project-init",
        lambda: command("init", [str(byo), "init", "--project", str(project)]),
        bound,
    )
    immutable = snapshot(runtime) if bound else {}
    sidecar = bundle / "sidecar" / ("byo-mcp-sidecar" + suffix)
    case(
        "VI15.compiled-probe-child",
        lambda: command(
            "probe-list", [str(sidecar), "probe-list", "list", "--probes"], cwd=bundle
        ),
    )
    case(
        "VI15.real-probe-worker-selftest",
        lambda: command(
            "self-test",
            [
                str(sidecar),
                "self-test",
                "--runtime-root",
                str(bundle),
                "--launcher-version",
                version,
            ],
            cwd=bundle,
        ),
    )

    def initialize():
        nonlocal server
        server = start_initialized_mcp(
            byo,
            project,
            environment,
            version,
            cwd=runtime,
            diagnostics_path=evidence / "mcp-stderr.log",
        )
        wire.append({"initialize_response_raw": server.initialization_raw})
        return {"pid": server.process.pid, "cwd": str(runtime), "project": str(project)}

    protocol = case("VI15.initialize-from-runtime-cwd", initialize, initialized)

    def tools():
        names = {item["name"] for item in rpc("tools/list", {})["tools"]}
        assert {
            "initialization_handshake",
            "setup_overview",
            "collect_build_artifacts",
            "server_health_check",
        } <= names
        return sorted(names)

    case("VI15.real-tools-list", tools, protocol)

    def monitor_health():
        reply = tool("server_health_check", {})
        state = reply["recording"]["store_state"]
        assert state in ("app_data", "operator_root"), reply
        selector = observations.qualification["observed_selectors"][-1]
        root = observations.owned_path(
            selector["app_data" if state == "app_data" else "operator"]
        )
        assert (root / "server_data").is_dir(), reply
        assert (root / "simulated_remote").is_dir(), reply
        return {"public_health": reply, "qualified_store_candidate": str(root)}

    case("FR16.actual-monitor-store-health", monitor_health, protocol)

    def overview():
        reply = tool("setup_overview", {"board_names": ["Hosted final acceptance"]})
        assert reply["status"] == "setup_no_probe", reply
        assert reply["code"] == "discovery/no-native-probe", reply
        assert reply["connections"] == [] and reply["routes"] == []
        return reply

    case("VI15.named-overview-controlled-no-probe", overview, protocol)
    # This is only a reviewed fixture serializer. All installed decisions and
    # replies below come from actual public tool calls in the compiled child.
    sys.path.insert(0, str(args.firmware_source.resolve() / "tests"))
    from elf_symbol_fixture import ElfSymbol, elf32_symbols

    inputs = project / "build-inputs"
    inputs.mkdir()
    (inputs / "program.elf").write_bytes(
        elf32_symbols([ElfSymbol("final_value", 0x20000024)])
    )
    (inputs / "program.map").write_text(
        "Final acceptance ARM linker map\n", encoding="utf-8"
    )

    def collect():
        source_bytes = {
            "elf": (inputs / "program.elf").read_bytes(),
            "map": (inputs / "program.map").read_bytes(),
        }
        reply = tool(
            "collect_build_artifacts",
            {
                "output_dir": "collected",
                "elf_path": "build-inputs/program.elf",
                "map_path": "build-inputs/program.map",
                "expected_roles": ["elf", "map"],
            },
        )
        assert reply["status"] == "artifacts_collected", reply
        collected = (project / "collected").resolve(strict=True)
        output = Path(reply["output_dir"])
        assert collected.is_dir() and output.samefile(collected), reply
        assert collected.name == "collected" and collected.parent.samefile(project), (
            reply
        )
        manifest_path = Path(reply["manifest_path"])
        assert manifest_path.name == "build-manifest.json", reply
        assert manifest_path.samefile(collected / "build-manifest.json"), reply
        collected_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert set(reply["canonical_paths"]) == {"elf", "map"}, reply
        for role, expected, canonical_name in (
            ("elf", inputs / "program.elf", "firmware.elf"),
            ("map", inputs / "program.map", "firmware.map"),
        ):
            actual = Path(reply["canonical_paths"][role])
            assert actual.name == canonical_name and actual.is_file(), reply
            assert actual.parent.samefile(collected), reply
            assert actual.samefile(collected / canonical_name), reply
            assert expected.read_bytes() == source_bytes[role], reply
            assert actual.read_bytes() == source_bytes[role], reply
            expected_digest = hashlib.sha256(source_bytes[role]).hexdigest()
            assert digest(actual) == expected_digest, reply
            record = reply["artifacts"][role]
            assert record["path"] == canonical_name, reply
            assert record["sha256"] == expected_digest, reply
            assert record["size_bytes"] == expected.stat().st_size, reply
            assert collected_manifest["artifacts"][role]["path"] == canonical_name, (
                reply
            )
            assert collected_manifest["artifacts"][role]["sha256"] == expected_digest, (
                reply
            )
            assert collected_manifest["artifacts"][role]["size_bytes"] == len(
                source_bytes[role]
            ), reply
        return reply

    case("VI15.public-relative-input-and-output", collect, protocol)

    def refuse_destination():
        reply = tool(
            "collect_build_artifacts",
            {
                "output_dir": str(runtime / "must-not-create"),
                "elf_path": "build-inputs/program.elf",
                "expected_roles": ["elf"],
            },
        )
        assert reply["status"] == "artifact_collection_refused", reply
        assert "runtime" in reply["message"].lower()
        assert snapshot(runtime) == immutable
        return reply

    case("VI15.immutable-runtime-destination-refusal", refuse_destination, protocol)
    # Meaningful symbol/setup/plan positives require a real connected board and
    # authority. Never replace those responses on a hardware-free hosted runner.
    for name in (
        "ELF-symbol-public-path",
        "setup-public-path",
        "flash-plan-public-path",
    ):
        records.append(
            {
                "case": "VI15." + name,
                "outcome": "BLOCKED",
                "reason": "hosted no-probe target lacks real board/validated authority; supported source regressions and VI16 Windows physical sequence supply separate evidence",
            }
        )

    def eof():
        stop_mcp(server)
        drained = queue.Queue()

        def drain():
            drained.put(server.process.stdout.read())

        threading.Thread(target=drain, daemon=True).start()
        tail = drained.get(timeout=10)
        for line in tail.splitlines():
            if line.strip():
                payload = json.loads(line)
                wire.append({"receive_at_EOF_raw": line, "receive": payload})
                assert payload.get("jsonrpc") == "2.0", payload
        save()
        assert server.process.poll() == 0
        assert not list((home / "state/leases").glob("*.json"))
        return {"exit": server.process.returncode, "leases": []}

    case("VI15.protocol-EOF-and-lease-cleanup", eof, protocol)
    if server is not None and server.process.poll() is None:
        # Exact owned Popen only; forced cleanup is recorded separately, never EOF PASS.
        server.process.kill()
        server.process.wait(timeout=15)
        records.append(
            {
                "case": "VI15.forced-cleanup",
                "outcome": "ERROR",
                "pid": server.process.pid,
                "exit": server.process.returncode,
            }
        )

    for index in range(5):
        for label, payload, expected in (
            ("normal", json.dumps({"command": "git status"}), 0),
            ("blocked", json.dumps({"command": "rm -rf /"}), 2),
        ):
            case(
                f"VI14.guard-latency-{label}-{index}",
                lambda label=label, payload=payload, expected=expected: command(
                    label,
                    [str(byo), "hook", "guard-dangerous", "--project", str(project)],
                    expected=expected,
                    stdin=payload,
                ),
                initialized,
            )
    for label, payload in (
        ("oversized", json.dumps({"command": "x" * 65537})),
        ("NUL", '{"command":"git\u0000status"}'.replace("\\u0000", "\0")),
        ("malformed", "{bad json"),
    ):
        case(
            "VI14.guard-" + label,
            lambda payload=payload: command(
                "guard-input",
                [str(byo), "hook", "guard-dangerous", "--project", str(project)],
                expected=2,
                stdin=payload,
            ),
            initialized,
        )

    case(
        "VI15.post-collection-runtime-health",
        lambda: command("doctor", [str(byo), "doctor", "--global", "--json"]),
        installed,
    )
    records.append(
        {
            "case": "VI15.U1-native-client-enforcement",
            "outcome": "UNVERIFIED",
            "reason": "requires supported client/version/trust evidence; protocol/JSON/CLI shape alone is insufficient",
        }
    )
    records.append(
        {
            "case": "VI15.runtime-byte-preservation",
            "outcome": "PASS" if bound and snapshot(runtime) == immutable else "FAIL",
        }
    )
    save()
    return int(
        any(record["outcome"] not in ("PASS", "UNVERIFIED") for record in records)
    )


if __name__ == "__main__":
    raise SystemExit(main())
