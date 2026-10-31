#!/usr/bin/env python3
"""Focused checks for compiled workflow skill metadata (stdlib only)."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import compile_workspace as compiler

ROOT = Path(__file__).resolve().parents[2]


def _workspace_source() -> Path:
    """Locate real source, including the flat two-product development layout.

    BYO_WORKSPACE_SOURCE selects an already qualified pinned checkout/export;
    it neither acquires source nor changes the release source lock.
    """
    configured = os.environ.get("BYO_WORKSPACE_SOURCE")
    candidates = (
        [Path(configured)]
        if configured
        else [
            ROOT / "AgentWorkspace",
            ROOT.parent / "CodexClaudeWorkflow",
            ROOT.parent / ".agent-workspace",
        ]
    )
    for candidate in candidates:
        if (
            all(
                (candidate / name).is_file()
                for name in ("internal/agent_workspace.py", "modes/firmware.toml")
            )
            and (candidate / "skills-src").is_dir()
        ):
            return candidate.resolve(strict=True)
    raise AssertionError(
        "Pinned workspace source is unavailable; set BYO_WORKSPACE_SOURCE to "
        "the qualified source checkout (not a generated runtime directory)"
    )


def test_explicit_workspace_source_refuses_an_incomplete_runtime_directory() -> None:
    with tempfile.TemporaryDirectory(prefix="byo-workspace-locator-") as raw_root:
        with patch.dict(os.environ, {"BYO_WORKSPACE_SOURCE": raw_root}):
            try:
                _workspace_source()
            except AssertionError as error:
                assert "qualified source checkout" in str(error)
            else:
                raise AssertionError("incomplete workspace input was accepted")


def test_real_workspace_catalog_contains_native_skill_metadata() -> None:
    catalog = json.loads(compiler._compile_modes(_workspace_source()))
    assert catalog["schema"] == 2
    assert catalog["workflow_protocol"] == 1
    verify = catalog["skills"]["verify"]
    assert verify["resource"].endswith("/verify/SKILL.md")
    assert "verify" in verify["description"].lower()
    assert verify["user_invocable"] is True
    assert isinstance(verify["disable_model_invocation"], bool)
    firmware = next(mode for mode in catalog["modes"] if mode["name"] == "firmware")
    assert "mcp-help" in firmware["skills"]


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
