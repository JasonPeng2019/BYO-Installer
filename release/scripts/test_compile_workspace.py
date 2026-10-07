#!/usr/bin/env python3
"""Focused checks for compiled workflow skill metadata (stdlib only)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import compile_workspace as compiler

ROOT = Path(__file__).resolve().parents[2]


def _workspace_source() -> Path:
    checked_out = ROOT / "AgentWorkspace"
    if checked_out.is_dir():
        return checked_out
    local_workspace = ROOT.parent / ".agent-workspace"
    if local_workspace.is_dir():
        return local_workspace
    raise AssertionError("AgentWorkspace source checkout is unavailable")


def test_real_workspace_catalog_contains_native_skill_metadata() -> None:
    catalog = json.loads(compiler._compile_modes(_workspace_source()))
    assert catalog["schema"] == 2
    assert catalog["workflow_protocol"] == 1
    assert [mode["name"] for mode in catalog["modes"]] == ["firmware", "firmware-full"]
    enabled_skills = {skill for mode in catalog["modes"] for skill in mode["skills"]}
    assert set(catalog["skills"]) == enabled_skills
    assert all(
        metadata["resource"].startswith(("skills-src/common/", "skills-src/firmware/"))
        for metadata in catalog["skills"].values()
    )
    assert "research-claim-critic" not in catalog["agents"]
    verify = catalog["skills"]["verify"]
    assert verify["resource"].endswith("/verify/SKILL.md")
    assert "verify" in verify["description"].lower()
    assert verify["user_invocable"] is True
    assert isinstance(verify["disable_model_invocation"], bool)
    firmware = next(mode for mode in catalog["modes"] if mode["name"] == "firmware")
    assert "mcp-help" in firmware["skills"]


def test_workspace_partition_excludes_non_firmware_workflows() -> None:
    rules = compiler._load_policy(ROOT / "release/policies/workspace-partition.toml")
    for relative in (
        "modes/research.toml",
        "modes/software.toml",
        "skills-src/research/repro-guard/SKILL.md",
        "skills-src/software/api-design/SKILL.md",
        "instructions/research.md",
        "instructions/software.md",
        "agents/research-claim-critic.md",
    ):
        assert compiler._classify(relative, rules) == "developer-only"
    for relative in (
        "skills-src/common/verify/SKILL.md",
        "skills-src/firmware/mcp-help/SKILL.md",
        "instructions/common.md",
        "instructions/firmware.md",
        "agents/adversarial-critic.md",
    ):
        assert compiler._classify(relative, rules) == "embed"


def test_real_workspace_pack_excludes_other_families() -> None:
    workspace = _workspace_source()
    with tempfile.TemporaryDirectory(prefix="byo-firmware-pack-") as raw_root:
        root = Path(raw_root)
        source = root / "source"
        source.mkdir()
        tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=workspace)
        for raw in tracked.split(b"\0"):
            if not raw:
                continue
            relative = Path(os.fsdecode(raw))
            original = workspace / relative
            if not original.is_file():
                continue
            destination = source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(original, destination)

        report = root / "report.json"
        compiler.compile_pack(
            source,
            ROOT / "release/policies/workspace-partition.toml",
            root / "workspace.pack",
            report,
            "0.1.7",
        )
        packed = set(json.loads(report.read_text(encoding="utf-8"))["packed_resources"])
        assert "compiled/workflow.json" in packed
        assert "skills-src/firmware/mcp-help/SKILL.md" in packed
        assert not any(
            resource.startswith(("skills-src/research/", "skills-src/software/"))
            or resource
            in {
                "instructions/research.md",
                "instructions/software.md",
                "agents/research-claim-critic.md",
            }
            for resource in packed
        )


def test_skill_metadata_folds_description_and_validates_identity() -> None:
    with tempfile.TemporaryDirectory(prefix="byo-skill-metadata-") as raw_root:
        source = Path(raw_root)
        skill = source / "skills-src/common/example/SKILL.md"
        skill.parent.mkdir(parents=True)
        skill.write_text(
            "---\n"
            "name: example\n"
            "description: >-\n"
            "  First line for discovery.\n"
            "  Second line for selection.\n"
            "disable-model-invocation: false\n"
            "user-invocable: true\n"
            "---\n\n# Example\n",
            encoding="utf-8",
        )
        metadata = compiler._skill_metadata(skill, source)
        assert metadata["description"] == (
            "First line for discovery. Second line for selection."
        )
        assert metadata["disable_model_invocation"] is False
        assert metadata["user_invocable"] is True

        skill.write_text(
            skill.read_text(encoding="utf-8").replace("name: example", "name: wrong"),
            encoding="utf-8",
        )
        try:
            compiler._skill_metadata(skill, source)
        except compiler.CompileError as error:
            assert "identity mismatch" in str(error)
        else:
            raise AssertionError("skill identity mismatch was accepted")


def test_manual_permission_developer_helper_reference_is_rejected() -> None:
    source = (
        b"Run .agent-workspace/bin/manual-permission with the exact server bindings.\n"
    )

    try:
        compiler._compile_runtime_references(
            "skills-src/firmware/downgrade/SKILL.md", source
        )
    except compiler.CompileError as error:
        assert "developer-only commands" in str(error)
    else:
        raise AssertionError("manual-permission developer helper was accepted")


def main() -> int:
    tests = [
        value for name, value in sorted(globals().items()) if name.startswith("test_")
    ]
    for test in tests:
        test()
        print(f"ok  {test.__name__}")
    print(f"\n{len(tests)} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
