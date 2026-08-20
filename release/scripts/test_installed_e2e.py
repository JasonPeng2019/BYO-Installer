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
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


class AcceptanceFailure(RuntimeError):
    pass


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
) -> subprocess.Popen[str]:
    process = subprocess.Popen(
        [str(byo), "mcp", "serve", "--project", str(project)],
        env=env,
        cwd=project,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
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
        diagnostics = process.stderr.read() if process.stderr is not None else ""
        raise AcceptanceFailure(
            f"MCP initialization failed: {exc}\nstderr:\n{diagnostics}"
        ) from exc
    return process


def stop_mcp(process: subprocess.Popen[str]) -> None:
    if process.stdin is not None:
        process.stdin.close()
    try:
        process.wait(timeout=20)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait(timeout=5)
        raise AcceptanceFailure("MCP server did not stop after protocol EOF") from exc
    if process.returncode != 0:
        diagnostics = process.stderr.read() if process.stderr is not None else ""
        raise AcceptanceFailure(
            f"MCP server returned {process.returncode} after EOF:\n{diagnostics}"
        )


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

        invoke([str(bundle_launcher), "status"], env=env, expected=20)
        if os.name == "nt":
            powershell = shutil.which("pwsh") or shutil.which("powershell")
            if not powershell:
                raise AcceptanceFailure(
                    "PowerShell is unavailable for Windows install testing"
                )
            install_command = [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(ROOT / "install.ps1"),
                "-Bundle",
                str(bootstrap_archive),
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
        else:
            install_command = [
                str(ROOT / "install.sh"),
                "--bundle",
                str(bootstrap_archive),
            ]
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
        for skill_id in ("mcp-help", "verify", "board-setup"):
            loader = project / f".claude/skills/{skill_id}/SKILL.md"
            if not loader.is_file():
                raise AcceptanceFailure(
                    f"init did not project native Claude skill {skill_id}"
                )
            loader_text = loader.read_text(encoding="utf-8")
            if (
                f"name: {skill_id}" not in loader_text
                or f"!`byo workflow guidance {skill_id}`" not in loader_text
            ):
                raise AcceptanceFailure(
                    f"Claude skill loader {skill_id} does not load private guidance"
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

        mcp = start_initialized_mcp(byo, project, env, expected_version)
        leases = list((home / "state" / "leases").glob("*.json"))
        if len(leases) != 1:
            raise AcceptanceFailure(f"expected one live runtime lease, found {leases}")
        invoke(
            [str(byo), "workspace", "update", "--project", str(project)],
            env=env,
            expected=11,
        )
        blocked_uninstall = invoke(
            [str(byo), "uninstall", "--global"], env=env, expected=42
        )
        if str(project) not in blocked_uninstall.stderr:
            raise AcceptanceFailure(
                "lease-blocked global uninstall did not report the registered project"
            )
        stop_mcp(mcp)
        if list((home / "state" / "leases").glob("*.json")):
            raise AcceptanceFailure("runtime lease remained after MCP exit")
        invoke(
            [str(byo), "workspace", "update", "--project", str(project)],
            env=env,
        )

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
        global_receipt = invoke([str(byo), "uninstall", "--global"], env=env)
        for registered_project in (project, unicode_project, nested_project):
            if str(registered_project) not in global_receipt.stdout:
                raise AcceptanceFailure(
                    "global uninstall receipt omitted a project integration: "
                    f"{registered_project}"
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
