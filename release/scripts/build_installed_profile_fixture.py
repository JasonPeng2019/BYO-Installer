"""Actions-only genuine distinct-version/professional build for retained tests.

The canonical candidate stays unchanged. Detached local Git children change
only version metadata, the documented build-time narrative constant and the
matching source lock. No ref/tag is pushed and these test assets are unpublished.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parents[2]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, record):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")


def git(cwd, *argv):
    return (
        subprocess.check_output(["git", "-c", "core.autocrlf=false", *argv], cwd=cwd)
        .decode()
        .strip()
    )


def tree(root):
    result = {}
    for entry in subprocess.check_output(
        ["git", "ls-tree", "-rz", "HEAD"], cwd=root
    ).split(b"\0"):
        if entry:
            fields, name = entry.split(b"\t", 1)
            mode, kind, blob = fields.decode().split()
            if kind != "blob":
                raise RuntimeError("Unexpected non-file in exact fixture source")
            relative = name.decode()
            result[relative] = {
                "mode": mode,
                "blob": blob,
                "sha256": sha(root / relative),
            }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("evidence", "analysis-input-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("Fixture compilation is Windows Actions only")
    output = args.evidence.resolve()
    output.mkdir(parents=True, exist_ok=False)
    lock = json.loads((ROOT / "release/source-lock.json").read_bytes())
    original_version = tomllib.loads((ROOT / "launcher/Cargo.toml").read_text())[
        "package"
    ]["version"]
    major, minor, patch = map(int, original_version.split("."))
    fixture_version = f"{major}.{minor}.{patch + 1}"
    canonical = {
        "installer": git(ROOT, "rev-parse", "HEAD"),
        "firmware": lock["firmware_mcp"]["commit"],
        "agent_workspace": lock["agent_workspace"]["commit"],
    }
    record = {
        "schema": "genuine-installed-profile-build/v1",
        "at": datetime.now(timezone.utc).isoformat(),
        "canonical_event_sha": os.environ["GITHUB_SHA"],
        "github_run_id": os.environ["GITHUB_RUN_ID"],
        "github_run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "canonical_sources": canonical,
        "version": fixture_version,
        "profile": "professional",
        "source_changes": {},
        "commands": [],
        "remote_ref_mutations": 0,
        "publication": False,
        "outcome": "ERROR",
    }

    def run(name, argv, *, cwd=ROOT, environment=None, timeout=300):
        command = {"name": name, "argv": argv, "cwd": str(cwd), "exit": None}
        record["commands"].append(command)
        try:
            with (
                (output / f"{name}.stdout").open("xb") as stdout,
                (output / f"{name}.stderr").open("xb") as stderr,
            ):
                completed = subprocess.run(
                    argv,
                    cwd=cwd,
                    env=environment,
                    stdout=stdout,
                    stderr=stderr,
                    stdin=subprocess.DEVNULL,
                    timeout=timeout,
                    check=False,
                )
            command.update(
                exit=completed.returncode,
                outcome="PASS" if completed.returncode == 0 else "FAIL",
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            command.update(
                outcome="TIMEOUT"
                if isinstance(error, subprocess.TimeoutExpired)
                else "ERROR",
                error=repr(error),
            )
            raise
        if completed.returncode:
            raise RuntimeError(
                f"Fixture {name} failed with exit {completed.returncode}"
            )

    def clone(source, destination, commit, repository):
        run(
            "clone-" + destination.name.replace(" ", "-"),
            [
                "git",
                "-c",
                "core.autocrlf=false",
                "clone",
                "--no-hardlinks",
                "--no-checkout",
                str(source),
                str(destination),
            ],
        )
        git(destination, "checkout", "--detach", commit)
        git(
            destination,
            "remote",
            "set-url",
            "origin",
            "https://github.com/" + repository + ".git",
        )
        if git(destination, "status", "--porcelain"):
            raise RuntimeError("Fixture clone is not an exact clean starting source")

    def change(path, old, new):
        data = path.read_bytes()
        if data.count(old) != 1:
            raise RuntimeError(
                "Declared fixture transform does not uniquely match " + str(path)
            )
        path.write_bytes(data.replace(old, new))

    def seal_source(name, path, parent, allowed, before):
        changed = set(git(path, "diff", "--name-only").splitlines())
        if changed != set(allowed):
            raise RuntimeError("Undeclared fixture source delta: " + str(changed))
        git(path, "add", "--", *allowed)
        git(
            path,
            "-c",
            "user.name=BYO Actions Fixture",
            "-c",
            "user.email=fixture@invalid.example",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "Declare genuine professional version fixture for retained installed checks",
        )
        child = git(path, "rev-parse", "HEAD")
        if git(path, "rev-parse", "HEAD^") != parent or git(
            path, "status", "--porcelain"
        ):
            raise RuntimeError("Fixture child ancestry/clean state differs")
        after = tree(path)
        if set(after) != set(before) or {
            p for p in before if before[p] != after[p]
        } != set(allowed):
            raise RuntimeError(
                "Complete fixture source inventory differs beyond its declared changes"
            )
        bundle = output / (name + "-source.bundle")
        git(path, "bundle", "create", str(bundle), "HEAD", "^" + parent)
        verification = git(path, "bundle", "verify", str(bundle))
        record["source_changes"][name] = {
            "parent": parent,
            "commit": child,
            "tree": git(path, "rev-parse", "HEAD^{tree}"),
            "allowed_paths": allowed,
            "before": before,
            "after": after,
            "bundle_sha256": sha(bundle),
            "bundle_verify": verification,
            "bundle_verify_exit": 0,
            "required_existing_parent": parent,
            "detached_local_only": True,
        }
        return child

    try:
        installer = output / "installer"
        clone(ROOT, installer, canonical["installer"], "JasonPeng2019/BYO-Installer")
        firmware = installer / "Firmware MCP New"
        clone(
            ROOT / "Firmware MCP New",
            firmware,
            canonical["firmware"],
            lock["firmware_mcp"]["repository"],
        )
        clone(
            ROOT / "AgentWorkspace",
            installer / "AgentWorkspace",
            canonical["agent_workspace"],
            lock["agent_workspace"]["repository"],
        )
        fw_before, installer_before = tree(firmware), tree(installer)
        old, new = original_version.encode(), fixture_version.encode()
        change(
            firmware / "pyproject.toml",
            b'version = "' + old + b'"',
            b'version = "' + new + b'"',
        )
        change(
            firmware / "src/pyocd_debug_mcp/__init__.py",
            b'__version__ = "' + old + b'"',
            b'__version__ = "' + new + b'"',
        )
        change(
            firmware / "uv.lock",
            b'name = "pyocd-debug-mcp"\nversion = "' + old + b'"',
            b'name = "pyocd-debug-mcp"\nversion = "' + new + b'"',
        )
        change(
            firmware / "src/pyocd_debug_mcp/monitor/build_profile.py",
            b"NARRATIVE_LOGGING: bool = True",
            b"NARRATIVE_LOGGING: bool = False",
        )
        fw_child = seal_source(
            "firmware",
            firmware,
            canonical["firmware"],
            [
                "pyproject.toml",
                "uv.lock",
                "src/pyocd_debug_mcp/__init__.py",
                "src/pyocd_debug_mcp/monitor/build_profile.py",
            ],
            fw_before,
        )
        change(
            installer / "launcher/Cargo.toml",
            b'version = "' + old + b'"',
            b'version = "' + new + b'"',
        )
        change(
            installer / "launcher/Cargo.lock",
            b'name = "byo"\nversion = "' + old + b'"',
            b'name = "byo"\nversion = "' + new + b'"',
        )
        fixture_lock = json.loads((installer / "release/source-lock.json").read_bytes())
        fixture_lock["firmware_mcp"]["commit"] = fw_child
        (installer / "release/source-lock.json").write_text(
            json.dumps(fixture_lock, indent=2) + "\n", encoding="utf-8"
        )
        inst_child = seal_source(
            "installer",
            installer,
            canonical["installer"],
            ["launcher/Cargo.toml", "launcher/Cargo.lock", "release/source-lock.json"],
            installer_before,
        )
        environment = {**os.environ, "UV_PYTHON": "3.12.13"}
        # The existing builder supports clean standalone Git sources. This
        # *disclosed test child* has its own real HEAD, not the canonical event
        # HEAD. Keep the actual event in this external receipt; do not pretend
        # its derived commit is an Actions event or a canonical source gate.
        environment.pop("GITHUB_SHA", None)
        record["child_build_environment"] = {
            "GITHUB_SHA": "absent for genuine standalone Git fixture provenance",
            "actual_workflow_event_sha": os.environ["GITHUB_SHA"],
            "actual_fixture_installer_head": inst_child,
        }
        run(
            "fixture-dependencies",
            [
                "uv",
                "sync",
                "--project",
                str(firmware),
                "--locked",
                "--all-groups",
                "--python",
                "3.12.13",
            ],
            cwd=installer,
            environment=environment,
            timeout=900,
        )
        run(
            "fixture-build",
            [
                str(firmware / ".venv/Scripts/python.exe"),
                "-B",
                str(installer / "release/scripts/build_release.py"),
                "--version",
                fixture_version,
                "--analysis-input-dir",
                str(args.analysis_input_dir.resolve()),
            ],
            cwd=installer,
            environment=environment,
            timeout=7200,
        )
        bundle = installer / "release/dist" / f"byo-{fixture_version}-windows-x86_64"
        manifest = json.loads((bundle / "release-manifest.json").read_bytes())
        if (
            manifest["version"] != fixture_version
            or manifest["source"]["firmware_mcp"]["commit"] != fw_child
            or manifest["source"]["installer"]["commit"] != inst_child
        ):
            raise RuntimeError("Genuine fixture artifact/source identity differs")
        if (
            tree(firmware) != record["source_changes"]["firmware"]["after"]
            or tree(installer) != record["source_changes"]["installer"]["after"]
        ):
            raise RuntimeError("Build changed fixture source")
        record.update(
            outcome="PASS",
            bundle=str(bundle),
            archive=str(bundle) + ".zip",
            manifest_sha256=sha(bundle / "release-manifest.json"),
            source_lock_sha256=sha(installer / "release/source-lock.json"),
            fixture_installer=str(installer),
            fixture_firmware=str(firmware),
        )
    except Exception as error:
        import traceback

        record.update(error=repr(error), traceback=traceback.format_exc())
        raise
    finally:
        write(output / "PROFILE-FIXTURE.json", record)
    print(
        json.dumps(
            {
                "outcome": record["outcome"],
                "version": fixture_version,
                "publication": False,
            }
        )
    )


if __name__ == "__main__":
    main()
