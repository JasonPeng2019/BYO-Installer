"""Actions-only public compiled MCP checks, using an exact built bundle.

No probe is connected, no private backend seam is enabled, and no installed
response is replaced. Retains a private normal install plus every wire/CLI exit.
"""

from __future__ import annotations

import argparse
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
    home, project = evidence / "private-home", evidence / "external-project"
    project.mkdir()
    environment = dict(
        os.environ,
        BYO_HOME=str(home),
        BYO_MCP_MONITOR_ROOT=str(evidence / "monitor"),
        PYTHONDONTWRITEBYTECODE="1",
    )
    # Preserve Windows shell API variables; no source seam/provider overrides.
    for key in (
        "BYO_MCP_TEST_SEAMS",
        "BYO_MCP_TEST_FAULTS",
        "PYOCD_CLI",
        "BYO_RUNTIME_ROOT",
        "BYO_MCP_ARTIFACT_ROOT",
    ):
        environment.pop(key, None)
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
                },
                indent=2,
                default=str,
            )
            + "\n",
            encoding="utf-8",
        )

    def command(name, argv, expected=0, stdin=None, cwd=None):
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
    initialized = case(
        "VI14.external-project-init",
        lambda: command("init", [str(byo), "init", "--project", str(project)]),
        installed,
    )
    immutable = snapshot(runtime) if installed else {}
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
        for role, expected in (
            ("elf", inputs / "program.elf"),
            ("map", inputs / "program.map"),
        ):
            actual = Path(reply["canonical_paths"][role])
            assert actual.is_relative_to(project) and digest(actual) == digest(expected)
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
            "outcome": "PASS"
            if installed and snapshot(runtime) == immutable
            else "FAIL",
        }
    )
    save()
    return int(
        any(record["outcome"] not in ("PASS", "UNVERIFIED") for record in records)
    )


if __name__ == "__main__":
    raise SystemExit(main())
