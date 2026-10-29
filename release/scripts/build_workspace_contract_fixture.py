"""Actions-only, disclosed successor of one pinned retirement-test invocation.

The product/workspace pin and original checkout remain unchanged. The effective
test tree is a detached local child, with its complete delta, bundle and exact
source inventories retained. It is never published as the unchanged base pin.
"""

from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PIN = "1cedcc2521281ad7ec82598daced2e8659ea917c"
TEST = "tests/test_cppcheck_posix_ownership.py"
BASELINE_SHA256 = "43975a64108392003daae081dc922cc709f568a6124a5fb61a10bda3ab710d88"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def revise(data):
    if sha(data) != BASELINE_SHA256:
        raise RuntimeError(
            "Retirement fixture requires its exact qualified pinned baseline"
        )
    original = data.decode("utf-8")
    functions = [
        node
        for node in ast.walk(ast.parse(data))
        if isinstance(node, ast.FunctionDef)
        and node.name
        == "test_captured_parent_retirement_during_observation_keeps_exact_scope"
    ]
    if len(functions) != 1:
        raise RuntimeError("Exact retirement contract function is missing or ambiguous")
    function = functions[0]
    lines = original.splitlines(keepends=True)
    text = "".join(lines[function.lineno - 1 : function.end_lineno])
    replacements = (
        (
            "    armed = threading.Event()\n    ids: dict[str, int] = {}\n    births: dict[int, str] = {}\n",
            "    armed = threading.Event()\n    staging_thread = threading.get_ident()\n    ids: dict[str, int] = {}\n    births: dict[int, str] = {}\n",
        ),
        (
            '        if stage == "capture" and armed.is_set() and not staged and pid == ids["parent"]:\n',
            '        if stage == "capture" and armed.is_set() and not staged and pid == ids["parent"] and threading.get_ident() == staging_thread:\n',
        ),
        (
            '        if stage == "chain" and armed.is_set() and not staged and parent[0] == ids["parent"]:\n',
            '        if stage == "chain" and armed.is_set() and not staged and parent[0] == ids["parent"] and threading.get_ident() == staging_thread:\n',
        ),
        (
            '        owned.finish()\n        assert staged == [("exited", "gone")], staged\n',
            '        assert owned.deadline is not None\n        with posix._RETAINED_GUARD:\n            retained = posix._RETAINED[leader]\n        retained._capture(owned.deadline)\n        owned.finish()\n        assert staged == [("exited", "gone")], staged\n',
        ),
    )
    for before, after in replacements:
        if text.count(before) != 1:
            raise RuntimeError("Declared retirement fixture edit is not unique")
        text = text.replace(before, after)
    text = (
        "".join(lines[: function.lineno - 1])
        + text
        + "".join(lines[function.end_lineno :])
    )
    old = [
        ast.dump(node)
        for node in ast.walk(ast.parse(data))
        if isinstance(node, ast.Assert)
    ]
    new = [
        ast.dump(node)
        for node in ast.walk(ast.parse(text))
        if isinstance(node, ast.Assert)
    ]
    if any(new.count(item) < old.count(item) for item in old):
        raise RuntimeError("An original assertion was removed or changed")
    return text.encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("Workspace contract fixture preparation is Actions only")
    source = args.source.resolve(strict=True)
    output = args.evidence.resolve()
    output.mkdir(parents=True, exist_ok=False)
    fixture = output / "effective-workspace"
    record = {
        "schema": "workspace-retirement-contract-fixture/v1",
        "at": datetime.now(timezone.utc).isoformat(),
        "base_pin": PIN,
        "base_test_sha256": BASELINE_SHA256,
        "effective_source": str(fixture),
        "canonical_event_sha": os.environ["GITHUB_SHA"],
        "commands": [],
        "remote_ref_mutations": 0,
        "outcome": "ERROR",
        "scope": "Actual owner capture on the test's staging thread and existing deadline; all original assertions, pairs and production source preserved",
    }

    def run(name, argv, cwd=ROOT, timeout=300):
        completed = subprocess.run(
            argv, cwd=cwd, capture_output=True, timeout=timeout, check=False
        )
        (output / (name + ".stdout")).write_bytes(completed.stdout)
        (output / (name + ".stderr")).write_bytes(completed.stderr)
        record["commands"].append(
            {"name": name, "argv": argv, "cwd": str(cwd), "exit": completed.returncode}
        )
        if completed.returncode:
            raise RuntimeError(
                f"Workspace fixture {name} exited {completed.returncode}"
            )
        return completed.stdout

    def git(cwd, *argv):
        return (
            subprocess.check_output(
                ["git", "-c", "core.autocrlf=false", *argv], cwd=cwd
            )
            .decode()
            .strip()
        )

    def inventory(root):
        entries = subprocess.check_output(["git", "ls-tree", "-rz", "HEAD"], cwd=root)
        rows = {}
        for item in entries.split(b"\0"):
            if not item:
                continue
            meta, path = item.split(b"\t", 1)
            mode, kind, blob = meta.decode().split()
            if kind != "blob":
                raise RuntimeError("Unexpected non-file workspace source input")
            name = path.decode()
            rows[name] = {
                "mode": mode,
                "blob": blob,
                "sha256": sha((root / name).read_bytes()),
            }
        return rows

    try:
        lock = json.loads((ROOT / "release/source-lock.json").read_bytes())
        if (
            lock["agent_workspace"]["commit"] != PIN
            or git(source, "rev-parse", "HEAD") != PIN
            or git(source, "status", "--porcelain")
        ):
            raise RuntimeError(
                "Original workspace is not the exact clean pinned subject"
            )
        original = inventory(source)
        run(
            "clone",
            [
                "git",
                "-c",
                "core.autocrlf=false",
                "clone",
                "--no-hardlinks",
                "--no-checkout",
                str(source),
                str(fixture),
            ],
        )
        git(fixture, "checkout", "--detach", PIN)
        git(fixture, "remote", "remove", "origin")
        before = inventory(fixture)
        if original != before:
            raise RuntimeError("Fixture clone differs from its pinned baseline")
        target = fixture / TEST
        baseline = target.read_bytes()
        target.write_bytes(revise(baseline))
        revised_ast = ast.dump(ast.parse(target.read_bytes()))
        run("locked-dependencies", ["uv", "sync", "--locked", "--dev"], fixture)
        run(
            "format-owned-revision",
            ["uv", "run", "--no-sync", "ruff", "format", TEST],
            fixture,
        )
        if ast.dump(ast.parse(target.read_bytes())) != revised_ast:
            raise RuntimeError("Formatting changed the declared fixture semantics")
        changed = git(fixture, "diff", "--name-only").splitlines()
        if changed != [TEST]:
            raise RuntimeError("Undeclared effective workspace delta")
        (output / "EFFECTIVE-DELTA.patch").write_bytes(
            subprocess.check_output(["git", "diff", "--binary"], cwd=fixture)
        )
        git(fixture, "add", "--", TEST)
        git(
            fixture,
            "-c",
            "user.name=BYO Actions Fixture",
            "-c",
            "user.email=fixture@invalid.example",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "Qualify exact parent retirement injection on its existing owner deadline",
        )
        child = git(fixture, "rev-parse", "HEAD")
        after = inventory(fixture)
        if (
            git(fixture, "rev-parse", "HEAD^") != PIN
            or git(fixture, "status", "--porcelain")
            or original != inventory(source)
            or set(before) != set(after)
            or {name for name in before if before[name] != after[name]} != {TEST}
        ):
            raise RuntimeError(
                "Workspace source custody/declared fixture delta differs"
            )
        bundle = output / "effective-workspace.bundle"
        git(fixture, "bundle", "create", str(bundle), "HEAD", "^" + PIN)
        verification = run(
            "bundle-verify", ["git", "bundle", "verify", str(bundle)], fixture
        )
        record.update(
            outcome="PASS",
            effective_commit=child,
            effective_tree=git(fixture, "rev-parse", "HEAD^{tree}"),
            before=before,
            after=after,
            original_source_unchanged=True,
            delta_sha256=sha((output / "EFFECTIVE-DELTA.patch").read_bytes()),
            bundle_sha256=sha(bundle.read_bytes()),
            bundle_verification=verification.decode(),
            effective_test_sha256=sha(target.read_bytes()),
        )
    finally:
        (output / "FIXTURE.json").write_text(
            json.dumps(record, indent=2) + "\n", encoding="utf-8"
        )
    print(
        json.dumps(
            {"outcome": record["outcome"], "base_pin": PIN, "effective_commit": child}
        )
    )


if __name__ == "__main__":
    main()
