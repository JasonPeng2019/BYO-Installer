#!/usr/bin/env python3
"""Self-contained checks for the launcher path-remap helper in build_release.py.

Run directly (stdlib only, no pytest):

    python release/scripts/test_build_release.py
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import build_release as br

SEP = "\x1f"


def test_remap_adds_cargo_and_checkout_placeholders() -> None:
    # CARGO_HOME is resolved (canonicalized) before being used as a prefix.
    env = {"CARGO_HOME": "/c"}
    encoded = br.remap_encoded_rustflags(env)
    parts = encoded.split(SEP)
    assert f"--remap-path-prefix={Path('/c').resolve()}=/cargo" in parts, parts
    assert f"--remap-path-prefix={br.ROOT}=/src" in parts, parts


def test_remap_is_space_safe_via_encoded_separator() -> None:
    # A checkout path containing a space must survive as exactly one token — the
    # whole point of CARGO_ENCODED_RUSTFLAGS over whitespace-split RUSTFLAGS.
    encoded = br.remap_encoded_rustflags({"CARGO_HOME": "/c"})
    assert encoded.split(SEP).count(f"--remap-path-prefix={br.ROOT}=/src") == 1


def test_remap_preserves_existing_flags_and_folds_plain_rustflags() -> None:
    env = {
        "CARGO_HOME": "/c",
        "CARGO_ENCODED_RUSTFLAGS": "-Cdebuginfo=0",
        "RUSTFLAGS": "-C opt-level=2",
    }
    encoded = br.remap_encoded_rustflags(env)
    parts = encoded.split(SEP)
    assert "-Cdebuginfo=0" in parts
    assert "-C" in parts and "opt-level=2" in parts
    # Plain RUSTFLAGS is consumed so cargo does not see both variables at once.
    assert "RUSTFLAGS" not in env


def test_release_version_defaults_to_matching_component_metadata() -> None:
    with (
        patch.object(br, "launcher_version", return_value="1.2.3"),
        patch.object(br, "sidecar_version", return_value="1.2.3"),
    ):
        assert br.release_version(None) == "1.2.3"
        assert br.release_version("1.2.3") == "1.2.3"


def test_release_version_rejects_component_or_requested_drift() -> None:
    with (
        patch.object(br, "launcher_version", return_value="1.2.3"),
        patch.object(br, "sidecar_version", return_value="1.2.4"),
    ):
        try:
            br.release_version(None)
        except RuntimeError as error:
            assert "must match" in str(error)
        else:
            raise AssertionError("mismatched component versions were accepted")

    with (
        patch.object(br, "launcher_version", return_value="1.2.3"),
        patch.object(br, "sidecar_version", return_value="1.2.3"),
    ):
        try:
            br.release_version("1.2.2")
        except RuntimeError as error:
            assert "must match" in str(error)
        else:
            raise AssertionError("a stale requested release version was accepted")


def test_development_matrix_derives_bundle_version() -> None:
    workflow = (br.ROOT / ".github/workflows/build-matrix.yml").read_text(
        encoding="utf-8"
    )
    assert "steps.release.outputs.version" in workflow
    assert "--version 0." not in workflow
    assert "bundle: byo-0." not in workflow


def main() -> int:
    tests = [v for n, v in sorted(globals().items()) if n.startswith("test_")]
    for test in tests:
        test()
        print(f"ok  {test.__name__}")
    print(f"\n{len(tests)} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
