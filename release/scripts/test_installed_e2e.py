#!/usr/bin/env python3
"""Exercise an assembled development bundle through the public installer contract."""

from __future__ import annotations

import argparse
import json
import os
import queue
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

ROOT = Path(__file__).resolve().parents[2]


class AcceptanceFailure(RuntimeError):
    pass


@dataclass
class InitializedMcp:
    """A running MCP server and its file-backed diagnostic capture."""

    process: subprocess.Popen[str]
    diagnostics: TextIO


def invoke(
    argv: list[str],
    *,
    env: dict[str, str],
    cwd: Path | None = None,
    stdin: str | None = None,
    expected: int = 0,
) -> subprocess.CompletedProcess[str]:
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
        timeout=60,
        check=False,
    )
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
) -> InitializedMcp:
    # RegistryFastMCP redirects every non-protocol write to stderr so stdout
    # remains valid JSON-RPC. A PIPE would therefore deadlock startup once the
    # server fills the OS pipe before this harness gets around to reading it.
    # Keep diagnostics for a useful failure report, but let the operating system
    # write them directly to a temporary file instead of applying backpressure.
    diagnostics = tempfile.TemporaryFile(mode="w+t", encoding="utf-8")
    process = subprocess.Popen(
        [str(byo), "mcp", "serve", "--project", str(project)],
        env=env,
        cwd=project,
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
        response = json.loads(read_line(process.stdout))
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
    return InitializedMcp(process=process, diagnostics=diagnostics)


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


def wait_until_absent(path: Path, *, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while path.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    if path.exists():
        raise AcceptanceFailure(f"uninstall left BYO path behind: {path}")


def phase(name: str) -> None:
    """Write an unbuffered acceptance checkpoint for hosted-run diagnosis."""

    print(f"BYO installed acceptance: {name}", flush=True)


def output_names_path(output: str, expected: Path) -> bool:
    """Return whether diagnostic output names the expected existing path.

    Windows can report the same path through long-name and 8.3 aliases. Prefer
    the literal fast path, then compare normalized text so an extended-length
    prefix still works after purge removes the path. Finally, compare each
    existing diagnostic line by filesystem identity so an 8.3 alias does not
    weaken the path-reporting acceptance check.
    """

    if str(expected) in output:
        return True
    expected_text = comparable_diagnostic_path(expected)
    for line in output.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        if comparable_diagnostic_path(candidate) == expected_text:
            return True
        try:
            if os.path.samefile(candidate, expected):
                return True
        except (FileNotFoundError, NotADirectoryError, OSError, ValueError):
            continue
    return False


def comparable_diagnostic_path(path: str | Path) -> str:
    """Normalize a diagnostic path without requiring it to still exist."""

    normalized = os.path.normcase(os.path.normpath(str(path)))
    if os.name != "nt":
        return normalized
    extended_unc = "\\\\?\\unc\\"
    if normalized.casefold().startswith(extended_unc):
        return "\\\\" + normalized[len(extended_unc) :]
    extended = "\\\\?\\"
    if normalized.startswith(extended):
        return normalized[len(extended) :]
    return normalized


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    bundle = args.bundle.resolve(strict=True)
    manifest = json.loads(
        (bundle / "release-manifest.json").read_text(encoding="utf-8")
    )
    expected_version = manifest.get("version")
    if not isinstance(expected_version, str) or not expected_version:
        raise AcceptanceFailure("bundle manifest contains no release version")
    archive_suffix = ".tar.gz" if manifest.get("platform") == "linux" else ".zip"
    archive = (
        args.archive
        if args.archive is not None
        else bundle.parent / f"{bundle.name}{archive_suffix}"
    ).resolve(strict=True)
    if not archive.is_file():
        raise AcceptanceFailure("bundle archive is missing")
    bundle_launcher = bundle / ("byo.exe" if os.name == "nt" else "byo")
    if not bundle_launcher.is_file():
        raise AcceptanceFailure("bundle launcher is missing")
    leaked = [
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file()
        and (
            path.suffix.lower()
            in {".c", ".h", ".md", ".py", ".pyc", ".pyi", ".rs", ".sh", ".ps1"}
            or "__pycache__" in path.parts
            or path.name in {"Cargo.toml", "pyproject.toml", "uv.lock"}
        )
    ]
    if leaked:
        raise AcceptanceFailure(f"bundle leaked source or development files: {leaked}")

    with tempfile.TemporaryDirectory(prefix="byo-installed-e2e-") as raw_root:
        root = Path(raw_root)
        bootstrap_archive = root / "downloaded BYO bundle"
        shutil.copyfile(archive, bootstrap_archive)
        home = root / "isolated product home"
        project = root / "firmware project"
        project.mkdir()
        (project / ".codex").mkdir()
        (project / ".claude").mkdir()
        (project / ".codex" / "config.toml").write_text(
            "[unrelated]\npreserved = true\n", encoding="utf-8"
        )
        (project / ".claude" / "settings.json").write_text(
            '{"unrelated":{"preserved":true}}\n', encoding="utf-8"
        )
        (project / ".claude" / "settings.local.json").write_text(
            '{"enabledMcpjsonServers":["byo","customer"],"unrelated":true}\n',
            encoding="utf-8",
        )
        (project / ".mcp.json").write_text(
            '{"mcpServers":{"customer":{"command":"customer-server"}}}\n',
            encoding="utf-8",
        )
        (project / "AGENTS.md").write_text(
            "# Customer instructions\n\nPreserve this text.\n", encoding="utf-8"
        )
        (project / "CLAUDE.md").write_text(
            "# Customer Claude instructions\n\nPreserve this Claude text.\n",
            encoding="utf-8",
        )
        env = {
            **os.environ,
            "BYO_HOME": str(home),
            "PATH": os.pathsep.join((str(home / "bin"), os.environ.get("PATH", ""))),
        }
        if os.name == "nt":
            # Match a normal PowerShell environment, where HOME is not
            # guaranteed. The launcher must preserve the native Windows
            # profile variables needed by the compiled sidecar.
            env.pop("HOME", None)

        phase("pre-install validation")
        invoke([str(bundle_launcher), "status"], env=env, expected=20)
        if os.name == "nt":
            powershell = shutil.which("pwsh") or shutil.which("powershell")
            if not powershell:
                raise AcceptanceFailure(
                    "PowerShell is unavailable for Windows install testing"
                )
            install_script = str(ROOT / "install.ps1").replace("'", "''")
            bootstrap_bundle = str(bootstrap_archive).replace("'", "''")
            install_command = [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                (
                    f"& {{ & '{install_script}' -Bundle '{bootstrap_bundle}'; "
                    "if ($null -eq (Get-Command byo -ErrorAction SilentlyContinue)) "
                    "{ throw 'BYO was not available on PATH after installation.' } }"
                ),
            ]
            native_env = {**env}
            native_env.pop("BYO_HOME", None)
            native_env.pop("HOME", None)
            native_local = root / "native Windows local app data"
            native_roaming = root / "native Windows roaming app data"
            native_env["LOCALAPPDATA"] = str(native_local)
            native_env["APPDATA"] = str(native_roaming)
            invoke(install_command, env=native_env, cwd=ROOT)
            native_byo = native_local / "BYO" / "bin" / "byo.exe"
            if not native_byo.is_file():
                raise AcceptanceFailure(
                    "default Windows install did not use LOCALAPPDATA without HOME"
                )
            invoke([str(native_byo), "status"], env=native_env)
            invoke([str(native_byo), "uninstall", "--global"], env=native_env)
            wait_until_absent(native_local / "BYO")
            for tombstone in native_local.glob(".byo-uninstall-*.exe"):
                # Windows can keep the just-exited executable open while
                # Defender or another scanner finishes inspecting it. The
                # product helper retries for roughly two minutes, so verify
                # that bounded guarantee instead of applying the generic
                # ten-second directory-removal deadline to the live image.
                wait_until_absent(tombstone, timeout=130.0)
        else:
            install_command = [
                str(ROOT / "install.sh"),
                "--bundle",
                str(bootstrap_archive),
            ]
        phase("install primary runtime")
        invoke(install_command, env=env, cwd=ROOT)
        byo = home / "bin" / ("byo.exe" if os.name == "nt" else "byo")
        if not byo.is_file():
            raise AcceptanceFailure("public launcher was not installed")

        paths = json.loads(invoke([str(byo), "paths"], env=env).stdout)
        if Path(paths["data"]) != home / "data":
            raise AcceptanceFailure("BYO_HOME product path resolution was incorrect")
        invoke([str(byo), "doctor", "--global", "--json"], env=env)
        status = json.loads(invoke([str(byo), "status"], env=env).stdout)
        if status.get("runtime_version") != expected_version or bool(
            status.get("development_unsigned")
        ) != bool(manifest.get("development_unsigned")):
            raise AcceptanceFailure("installed runtime status was incorrect")
        unsigned_metadata = root / "unsigned-channel.json"
        unsigned_metadata.write_text("{}\n", encoding="utf-8")
        phase("initialize primary project")
        invoke(
            [
                str(byo),
                "update",
                "--metadata-file",
                str(unsigned_metadata),
                "--dry-run",
            ],
            env=env,
            expected=23 if manifest.get("development_unsigned") else 40,
        )

        phase("exercise workflow routes")
        invoke(
            [str(byo), "init", "--project", str(project), "--dry-run"],
            env=env,
        )
        if (project / ".agent-workspace").exists():
            raise AcceptanceFailure("init --dry-run changed the project")
        offline_env = {
            **env,
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "",
        }
        invoke([str(byo), "init", "--project", str(project)], env=offline_env)
        invoke(
            [str(byo), "doctor", "--project", str(project), "--json"],
            env=env,
        )
        if "preserved = true" not in (project / ".codex/config.toml").read_text(
            encoding="utf-8"
        ):
            raise AcceptanceFailure(
                "init did not preserve unrelated Codex configuration"
            )
        claude_settings = json.loads(
            (project / ".claude/settings.json").read_text(encoding="utf-8")
        )
        if claude_settings.get("unrelated", {}).get("preserved") is not True:
            raise AcceptanceFailure("init changed unrelated Claude configuration")
        if not claude_settings.get("hooks"):
            raise AcceptanceFailure("init did not configure Claude hooks")
        claude_mcp = json.loads((project / ".mcp.json").read_text(encoding="utf-8"))
        if (
            claude_mcp.get("mcpServers", {}).get("customer", {}).get("command")
            != "customer-server"
        ):
            raise AcceptanceFailure("init changed an unrelated Claude MCP server")
        if claude_mcp.get("mcpServers", {}).get("byo", {}).get("command") != "byo":
            raise AcceptanceFailure("init did not configure the Claude BYO MCP server")
        for client in (".codex", ".claude"):
            loader = project / client / "skills/mcp-help/SKILL.md"
            if not loader.is_file():
                raise AcceptanceFailure(
                    f"init did not project the model-invocable mcp-help skill for {client}"
                )
            loader_text = loader.read_text(encoding="utf-8")
            if (
                "name: mcp-help" not in loader_text
                or "disable-model-invocation: false" not in loader_text
                or "user-invocable: true" not in loader_text
                or "!`byo workflow guidance mcp-help`" not in loader_text
            ):
                raise AcceptanceFailure(
                    f"{client} mcp-help loader does not expose verified skill metadata"
                )
            if client == ".codex":
                model_policy = project / client / "skills/mcp-help/agents/openai.yaml"
                if not model_policy.is_file() or (
                    "allow_implicit_invocation: true"
                    not in model_policy.read_text(encoding="utf-8")
                ):
                    raise AcceptanceFailure(
                        "Codex mcp-help policy does not allow intended implicit invocation"
                    )
            manual_loader = (
                project / client / "skills/implement-firmware-large/SKILL.md"
            )
            if not manual_loader.is_file():
                raise AcceptanceFailure(
                    f"init did not project the user-invocable manual skill for {client}"
                )
            manual_loader_text = manual_loader.read_text(encoding="utf-8")
            if (
                "name: implement-firmware-large" not in manual_loader_text
                or "disable-model-invocation: true" not in manual_loader_text
                or "user-invocable: true" not in manual_loader_text
                or "!`byo workflow guidance implement-firmware-large`"
                not in manual_loader_text
            ):
                raise AcceptanceFailure(
                    f"{client} implement-firmware-large loader does not retain manual invocation metadata"
                )
            if client == ".codex":
                manual_policy = (
                    project
                    / client
                    / "skills/implement-firmware-large/agents/openai.yaml"
                )
                if not manual_policy.is_file() or (
                    "allow_implicit_invocation: false"
                    not in manual_policy.read_text(encoding="utf-8")
                ):
                    raise AcceptanceFailure(
                        "Codex implement-firmware-large policy permits implicit invocation"
                    )
            permission_loader = project / client / "skills/downgrade/SKILL.md"
            if not permission_loader.is_file():
                raise AcceptanceFailure(
                    f"init did not project the downgrade manual skill for {client}"
                )
            permission_loader_text = permission_loader.read_text(encoding="utf-8")
            if (
                "name: downgrade" not in permission_loader_text
                or "disable-model-invocation: true" not in permission_loader_text
                or "user-invocable: true" not in permission_loader_text
                or "!`byo workflow guidance downgrade`" not in permission_loader_text
            ):
                raise AcceptanceFailure(
                    f"{client} downgrade loader does not retain manual invocation metadata"
                )
            if client == ".codex":
                permission_policy = (
                    project / client / "skills/downgrade/agents/openai.yaml"
                )
                if not permission_policy.is_file() or (
                    "allow_implicit_invocation: false"
                    not in permission_policy.read_text(encoding="utf-8")
                ):
                    raise AcceptanceFailure(
                        "Codex downgrade policy permits implicit invocation"
                    )
        if "Preserve this text." not in (project / "AGENTS.md").read_text(
            encoding="utf-8"
        ):
            raise AcceptanceFailure("init changed unrelated AGENTS.md content")
        if "Preserve this Claude text." not in (project / "CLAUDE.md").read_text(
            encoding="utf-8"
        ):
            raise AcceptanceFailure("init changed unrelated CLAUDE.md content")
        forbidden = [
            path
            for path in project.rglob("*")
            if path.is_file() and path.suffix in {".py", ".sh", ".ps1"}
        ]
        if forbidden:
            raise AcceptanceFailure(
                f"project capsule leaked implementation source: {forbidden}"
            )

        invoke(
            [str(byo), "workflow", "guidance", "verify", "--project", str(project)],
            env=env,
        )
        invoke(
            [str(byo), "workflow", "agent", "verifier", "--project", str(project)],
            env=env,
        )
        invoke(
            [
                str(byo),
                "workflow",
                "tool",
                "task-path",
                "--project",
                str(project),
                "plan",
            ],
            env=env,
        )
        invoke(
            [str(byo), "hook", "guard-dangerous", "--project", str(project)],
            env=env,
            stdin='{"schema":1,"command":"git status"}',
        )
        invoke(
            [str(byo), "hook", "guard-dangerous", "--project", str(project)],
            env=env,
            stdin='{"schema":1,"command":"git reset --hard"}',
            expected=2,
        )
        invoke(
            [str(byo), "mode", "firmware-full", "--project", str(project)],
            env=env,
            expected=11,
        )
        invoke(
            [
                str(byo),
                "mode",
                "firmware-full",
                "--allow-full-access",
                "--project",
                str(project),
            ],
            env=env,
        )
        invoke(
            [str(byo), "mode", "firmware", "--project", str(project)],
            env=env,
        )
        invoke([str(byo), "mode", "research", "--project", str(project)], env=env)
        invoke(
            [
                str(byo),
                "mode",
                "research-full",
                "--allow-full-access",
                "--project",
                str(project),
            ],
            env=env,
        )
        invoke(
            [str(byo), "mode", "firmware", "--project", str(project)],
            env=env,
        )

        managed_skill = project / ".codex/skills/byo-firmware/SKILL.md"
        original_skill = managed_skill.read_bytes()
        managed_skill.write_bytes(original_skill + b"\nmodified\n")
        invoke(
            [str(byo), "doctor", "--project", str(project)],
            env=env,
            expected=31,
        )
        managed_skill.write_bytes(original_skill)
        invoke([str(byo), "doctor", "--project", str(project)], env=env)
        claude_skill = project / ".claude/skills/byo-firmware/SKILL.md"
        original_claude_skill = claude_skill.read_bytes()
        claude_skill.write_bytes(original_claude_skill + b"\nmodified\n")
        invoke(
            [str(byo), "doctor", "--project", str(project)],
            env=env,
            expected=31,
        )
        claude_skill.write_bytes(original_claude_skill)
        invoke([str(byo), "doctor", "--project", str(project)], env=env)

        phase("exercise MCP and manual-permission route")
        mcp = start_initialized_mcp(byo, project, env, expected_version)
        try:
            manual_command = [
                str(byo),
                "workflow",
                "tool",
                "manual-permission",
                "--project",
                str(project),
                "--",
                "--action",
                "downgrade",
                "--board-id",
                "acceptance-board",
                "--policy-digest",
                "a" * 64,
            ]
            manual = invoke(manual_command, env=env)
            if (
                len(manual.stdout.splitlines()) != 1
                or json.loads(manual.stdout).get("status") != "manual_grant_unlocked"
            ):
                raise AcceptanceFailure(
                    "installed manual-permission route did not return one unlock result"
                )
            repeated = invoke(manual_command, env=env, expected=1)
            if (
                len(repeated.stdout.splitlines()) != 1
                or json.loads(repeated.stdout).get("code") != "manual/already-reserved"
            ):
                raise AcceptanceFailure(
                    "installed manual-permission route did not return one refusal result"
                )
            leases = list((home / "state" / "leases").glob("*.json"))
            if len(leases) != 1:
                raise AcceptanceFailure(
                    f"expected one live runtime lease, found {leases}"
                )
            invoke(
                [str(byo), "workspace", "update", "--project", str(project)],
                env=env,
                expected=11,
            )
            blocked_uninstall = invoke(
                [str(byo), "uninstall", "--global"], env=env, expected=42
            )
            if not output_names_path(blocked_uninstall.stderr, project):
                raise AcceptanceFailure(
                    "lease-blocked global uninstall did not report the registered "
                    f"project\nstderr:\n{blocked_uninstall.stderr}"
                )
        finally:
            stop_mcp(mcp)
        if list((home / "state" / "leases").glob("*.json")):
            raise AcceptanceFailure("runtime lease remained after MCP exit")
        invoke(
            [str(byo), "workspace", "update", "--project", str(project)],
            env=env,
        )

        phase("verify runtime integrity and project edge cases")
        runtime = home / "data" / "versions" / expected_version
        pack = runtime / "workflow" / "workspace.pack"
        original_pack = pack.read_bytes()
        try:
            pack.write_bytes(original_pack + b"corruption")
            invoke([str(byo), "status"], env=env, expected=21)
        finally:
            pack.write_bytes(original_pack)
        invoke([str(byo), "status"], env=env)

        sidecar = (
            runtime
            / "sidecar"
            / ("byo-mcp-sidecar.exe" if os.name == "nt" else "byo-mcp-sidecar")
        )
        sidecar_backup = root / sidecar.name
        shutil.copy2(sidecar, sidecar_backup)
        try:
            with sidecar.open("ab") as handle:
                handle.write(b"corruption")
            invoke([str(byo), "status"], env=env, expected=21)
        finally:
            shutil.copy2(sidecar_backup, sidecar)
        invoke([str(byo), "repair"], env=env)

        unicode_project = root / "firmware-µ-测试"
        unicode_project.mkdir()
        invoke([str(byo), "init", "--project", str(unicode_project)], env=offline_env)
        invoke([str(byo), "doctor", "--project", str(unicode_project)], env=env)

        monorepo = root / "monorepo"
        nested_project = monorepo / "firmware" / "board"
        nested_project.mkdir(parents=True)
        (monorepo / ".git").mkdir()
        invoke([str(byo), "init", "--project", str(nested_project)], env=offline_env)

        if os.name != "nt" and (not hasattr(os, "geteuid") or os.geteuid() != 0):
            read_only = root / "read only project"
            read_only.mkdir()
            read_only.chmod(0o555)
            try:
                invoke(
                    [str(byo), "init", "--project", str(read_only)],
                    env=env,
                    expected=11,
                )
            finally:
                read_only.chmod(0o755)

        phase("exercise project and global uninstall lifecycle")
        firm_marker = project / ".firm" / "preserve-me"
        firm_marker.parent.mkdir(exist_ok=True)
        firm_marker.write_text("preserved\n", encoding="utf-8")
        invoke(
            [str(byo), "uninstall", "--project", str(project)],
            env=env,
        )
        if not firm_marker.is_file():
            raise AcceptanceFailure("ordinary project uninstall removed .firm state")
        uninstalled_mcp = json.loads(
            (project / ".mcp.json").read_text(encoding="utf-8")
        )
        if "byo" in uninstalled_mcp.get("mcpServers", {}):
            raise AcceptanceFailure("project uninstall left the Claude BYO MCP server")
        if (
            uninstalled_mcp.get("mcpServers", {}).get("customer", {}).get("command")
            != "customer-server"
        ):
            raise AcceptanceFailure(
                "project uninstall removed an unrelated Claude MCP server"
            )
        if "Preserve this Claude text." not in (project / "CLAUDE.md").read_text(
            encoding="utf-8"
        ):
            raise AcceptanceFailure(
                "project uninstall removed unrelated CLAUDE.md content"
            )
        local_settings = json.loads(
            (project / ".claude/settings.local.json").read_text(encoding="utf-8")
        )
        if "byo" in local_settings.get("enabledMcpjsonServers", []):
            raise AcceptanceFailure("project uninstall left Claude's BYO MCP approval")
        if local_settings.get("enabledMcpjsonServers") != ["customer"]:
            raise AcceptanceFailure(
                "project uninstall changed another Claude MCP approval"
            )

        purge_project = root / "purge project"
        purge_project.mkdir()
        customer_file = purge_project / "customer.txt"
        customer_file.write_text("preserve\n", encoding="utf-8")
        invoke([str(byo), "init", "--project", str(purge_project)], env=offline_env)
        (purge_project / ".firm" / "purge-me").parent.mkdir(exist_ok=True)
        (purge_project / ".firm" / "purge-me").write_text("remove\n", encoding="utf-8")
        invoke(
            [str(byo), "uninstall", "--purge", "--project", str(purge_project)],
            env=env,
        )
        for relative in (
            ".agent-workspace",
            ".agent-backups",
            ".firm",
            ".generated/byo",
        ):
            if (purge_project / relative).exists():
                raise AcceptanceFailure(
                    f"project purge left dedicated BYO path {relative}"
                )
        if not customer_file.is_file():
            raise AcceptanceFailure("project purge removed unrelated project content")

        invoke([str(byo), "init", "--project", str(project)], env=offline_env)
        if not firm_marker.is_file():
            raise AcceptanceFailure("reinstall over preserved state removed .firm data")
        registered_projects = (project, unicode_project, nested_project)
        receipt_paths = tuple(
            Path(os.path.realpath(registered_project))
            for registered_project in registered_projects
        )
        global_receipt = invoke([str(byo), "uninstall", "--global"], env=env)
        for registered_project, receipt_path in zip(
            registered_projects, receipt_paths, strict=True
        ):
            if not output_names_path(global_receipt.stdout, receipt_path):
                raise AcceptanceFailure(
                    "global uninstall receipt omitted a project integration: "
                    f"{receipt_path}\nstdout:\n{global_receipt.stdout}"
                )
            if (registered_project / ".agent-workspace/manifest.json").exists():
                raise AcceptanceFailure(
                    "global uninstall left a registered project integration: "
                    f"{registered_project}"
                )
        if firm_marker.exists() or (project / ".firm").exists():
            raise AcceptanceFailure("global uninstall did not purge project .firm data")
        if byo.exists() or (home / "data/current.json").exists():
            raise AcceptanceFailure(
                "global uninstall left the active launcher or pointer"
            )

        # Clean-machine: reinstalling after a full global purge must recreate a
        # usable project integration from scratch.
        invoke(install_command, env=env, cwd=ROOT)
        if not byo.is_file():
            raise AcceptanceFailure("product reinstall did not restore the launcher")
        invoke([str(byo), "init", "--project", str(project)], env=offline_env)
        if firm_marker.exists():
            raise AcceptanceFailure("product reinstall resurrected purged .firm data")
        invoke([str(byo), "uninstall", "--global"], env=env)

        phase("exercise custom installation location")
        custom_root = root / "custom product location"
        custom_env = {
            key: value for key, value in os.environ.items() if key != "BYO_HOME"
        }
        custom_env["PATH"] = os.pathsep.join(
            (str(custom_root / "bin"), custom_env.get("PATH", ""))
        )
        if os.name == "nt":
            custom_install_command = [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(ROOT / "install.ps1"),
                "-Bundle",
                str(bundle),
                "-InstallDir",
                str(custom_root),
            ]
        else:
            custom_install_command = [
                str(ROOT / "install.sh"),
                "--bundle",
                str(bundle),
                "--install-dir",
                str(custom_root),
            ]
        invoke(custom_install_command, env=custom_env, cwd=ROOT)
        custom_byo = custom_root / "bin" / ("byo.exe" if os.name == "nt" else "byo")
        custom_paths = json.loads(
            invoke([str(custom_byo), "paths"], env=custom_env).stdout
        )
        actual_custom_data = Path(custom_paths["data"])
        expected_custom_data = custom_root / "data"
        try:
            custom_data_matches = actual_custom_data.samefile(expected_custom_data)
        except OSError:
            custom_data_matches = False
        if not custom_data_matches:
            raise AcceptanceFailure(
                "custom installation was not rediscovered without BYO_HOME: "
                f"expected {expected_custom_data}, got {actual_custom_data}"
            )
        invoke([str(custom_byo), "doctor", "--global"], env=custom_env)
        invoke(
            [str(custom_byo), "uninstall", "--global"],
            env=custom_env,
        )
        if custom_byo.exists() or (custom_root / "bin/.byo-install.json").exists():
            raise AcceptanceFailure("custom installation locator was not removed")

    print("BYO installed acceptance: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
