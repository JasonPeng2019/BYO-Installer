#!/usr/bin/env python3
"""Self-contained checks for the launcher path-remap helper in build_release.py.

Run directly (stdlib only, no pytest):

    python release/scripts/test_build_release.py
"""

from __future__ import annotations

from pathlib import Path
from unittest import SkipTest
from unittest.mock import patch
import os
import re
import shutil
import subprocess
import tempfile
import json

import build_release as br
from test_analysis_tools import fixture, pe
import analysis_tools

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


def test_windows_release_launcher_uses_static_crt() -> None:
    with patch.object(br.platform, "system", return_value="Windows"):
        flags = br.remap_encoded_rustflags({}).split(SEP)
    assert "-Ctarget-feature=+crt-static" in flags


def test_public_launcher_closure_rejects_bundle_only_crt() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        launcher = Path(temporary) / "byo.exe"
        for kind in ("ordinary", "delay"):
            launcher.write_bytes(pe(**{kind: "vcruntime140.dll"}))
            try:
                br.public_launcher_closure(launcher)
            except RuntimeError as error:
                assert "Redistributable dependency" in str(error)
            else:
                raise AssertionError(f"public launcher accepted {kind} CRT import")
        launcher.write_bytes(pe())
        assert list(br.public_launcher_closure(launcher)["images"]) == ["byo.exe"]


def windows_input_step(workflow: str) -> str:
    # Extract the exact preparation block; execute it locally with fixture
    # downloads, so a missing hash guard or early GITHUB_ENV write fails.
    match = re.search(
        r"      - name: Prepare pinned Windows analysis inputs\n"
        r"(?:(?!      - name:).)*?        run: \|\n"
        r"((?:          [^\n]*\n|\n)+)",
        workflow,
        re.DOTALL,
    )
    assert match, "Windows job has no pinned analysis input preparation"
    return "\n".join(line[10:] for line in match[1].splitlines())


def test_windows_workflows_prepare_hash_checked_inputs_for_every_stage() -> None:
    for filename, job, stages in (
        ("build-matrix.yml", "build", 1),
        ("release.yml", "windows", 2),
    ):
        workflow = (br.ROOT / ".github/workflows" / filename).read_text("utf-8")
        # Job steps are indented more than two spaces.
        section = re.split(r"\n  [a-z][\w-]*:\n", workflow.split(f"  {job}:\n", 1)[1])[
            0
        ]
        script = windows_input_step(section)
        python_version = analysis_tools.load_lock()["windows_native"]["source"][
            "python_version"
        ]
        assert python_version in section, (
            "Windows build Python must match pinned native inputs"
        )
        assert "Get-FileHash" in script and "$source.sha256" in script
        assert "BYO_ANALYSIS_INPUT_DIR=" in script
        calls = [
            line
            for line in section.splitlines()
            if "python release/scripts/build_release.py " in line
        ]
        if job == "build":
            # The other-platform build step is explicitly excluded on Windows.
            assert "if: runner.os != 'Windows'" in section
            calls = [line for line in calls if "--analysis-input-dir" in line]
        assert len(calls) == stages, calls
        assert all(
            '"$BYO_ANALYSIS_INPUT_DIR"' in line
            or '"${{ env.BYO_ANALYSIS_INPUT_DIR }}"' in line
            for line in calls
        )
        assert section.index("Prepare pinned Windows analysis inputs") < section.index(
            "python release/scripts/build_release.py "
        )


def test_windows_input_preparation_refuses_changed_downloads() -> None:
    if os.name != "nt":
        raise SkipTest("native Windows input preparation")
    powershell = shutil.which("pwsh") or shutil.which("powershell")
    assert powershell, "Windows PowerShell is required"
    for filename in ("build-matrix.yml", "release.yml"):
        script = windows_input_step(
            (br.ROOT / ".github/workflows" / filename).read_text("utf-8")
        )
        for corrupt in (False, True):
            with tempfile.TemporaryDirectory(prefix="byo-ci-inputs-") as temporary:
                root = Path(temporary)
                (root / "release").mkdir()
                payload = b"pinned test archive"
                sources = {
                    name: {
                        "archive": f"{name}.zip",
                        "url": f"https://example.invalid/{name}",
                        "sha256": analysis_tools.sha256(payload),
                    }
                    for name in ("cppcheck", "clangd")
                }
                lock = {
                    "programs": {
                        name: {"source": source} for name, source in sources.items()
                    }
                }
                (root / "release/analysis-tools.lock.json").write_text(
                    json.dumps(lock), "utf-8"
                )
                (root / "payload").write_bytes(payload)
                (root / "corrupt").write_bytes(b"changed archive")
                fixture_script = root / "prepare.ps1"
                fixture_script.write_text(
                    "function Invoke-WebRequest { param($Uri, $OutFile, [switch]$UseBasicParsing) "
                    "$fixture='payload'; if ($env:BYO_TEST_BAD_INPUT -eq '1' -and $Uri.EndsWith('/clangd')) { $fixture='corrupt' }; "
                    "Copy-Item -LiteralPath $fixture -Destination $OutFile }\n"
                    + script,
                    "utf-8",
                )
                completed = subprocess.run(
                    [
                        powershell,
                        "-NoProfile",
                        "-NonInteractive",
                        "-File",
                        str(fixture_script),
                    ],
                    cwd=root,
                    env={
                        **os.environ,
                        "RUNNER_TEMP": str(root),
                        "GITHUB_ENV": str(root / "github-env"),
                        "BYO_TEST_BAD_INPUT": "1" if corrupt else "0",
                    },
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if corrupt:
                    assert completed.returncode != 0, completed.stdout
                    assert "SHA-256 mismatch" in completed.stderr
                    assert not (root / "github-env").exists()
                else:
                    assert completed.returncode == 0, completed.stderr
                    for source in sources.values():
                        assert (
                            root / "byo-analysis-inputs" / source["archive"]
                        ).read_bytes() == payload
                    assert "BYO_ANALYSIS_INPUT_DIR=" in (root / "github-env").read_text(
                        "utf-8-sig"
                    )


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


def test_windows_python_rejects_stale_metadata_and_wrong_source():
    with tempfile.TemporaryDirectory() as temporary:
        source = Path(temporary).resolve()
        identity = {
            "python": "python.exe",
            "distribution_version": "0.1.8",
            "source_version": "0.1.8",
            "source_file": str(source / "src/pyocd_debug_mcp/__init__.py"),
        }

        def result(value):
            return subprocess.CompletedProcess([], 0, json.dumps(value), "")

        with patch.object(br.subprocess, "run", return_value=result(identity)):
            assert (
                br.validate_windows_build_python(Path("python.exe"), source, "0.1.8")[
                    "identity"
                ]
                == identity
            )
        for changed in (
            {**identity, "distribution_version": "0.1.7"},
            {**identity, "source_file": str(source / "wrong/__init__.py")},
        ):
            with patch.object(br.subprocess, "run", return_value=result(changed)):
                try:
                    br.validate_windows_build_python(
                        Path("python.exe"), source, "0.1.8"
                    )
                    raise AssertionError("stale metadata/source was accepted")
                except RuntimeError as error:
                    assert "isolated matching" in str(error)


def test_development_matrix_derives_bundle_version() -> None:
    workflow = (br.ROOT / ".github/workflows/build-matrix.yml").read_text(
        encoding="utf-8"
    )
    assert "steps.release.outputs.version" in workflow
    assert "--version 0." not in workflow
    assert "bundle: byo-0." not in workflow


def test_final_payload_hashes_are_reused_in_sbom():
    with tempfile.TemporaryDirectory() as temporary:
        bundle = Path(temporary)
        (bundle / "sidecar").mkdir()
        native = bundle / "sidecar/dependency.dll"
        native.write_bytes(b"final transformed native bytes")
        report = bundle / "report.xml"
        report.write_text(
            '<report nuitka_version="test"><python python_version="3.12.0"/><distributions/></report>'
        )
        files = br.payload_inventory(bundle)
        with patch.object(
            br, "digest", side_effect=AssertionError("SBOM rehashed a payload")
        ):
            br.write_sbom(bundle, report, "0.1.8", files)
        sbom = json.loads((bundle / "sbom.cdx.json").read_bytes())
        dependency = next(
            c for c in sbom["components"] if c["name"] == "sidecar/dependency.dll"
        )
        assert (
            dependency["hashes"][0]["content"]
            == next(f for f in files if f["path"] == "sidecar/dependency.dll")["sha256"]
        )
        assert not any(f["path"] == "sbom.cdx.json" for f in files)


def test_windows_finalization_preserves_signed_analysis_bytes():
    lock, data, _, _ = fixture()
    # Signing changes executable bytes; those transformed bytes must survive
    # finalization and become the SBOM/inventory identity without rebuilding.
    path = lock["programs"]["cppcheck"]["executable"]
    data[path] += b"simulated Authenticode transformation"
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        bundle, evidence = root / "bundle", root / "evidence"
        for name, value in data.items():
            target = bundle / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(value)
        provenance = {
            "sources": {
                name: program["source"] for name, program in lock["programs"].items()
            },
            "recipe": lock["programs"]["cppcheck"]["recipe"],
        }
        analysis_tools.write_json(evidence / "cppcheck-build.json", provenance)
        with patch.object(analysis_tools, "load_lock", return_value=lock):
            saved, recorded = br.signed_analysis_inputs(bundle, evidence)
        assert saved[path] == data[path]
        assert recorded == provenance


def main() -> int:
    tests = [v for n, v in sorted(globals().items()) if n.startswith("test_")]
    passed = skipped = 0
    for test in tests:
        try:
            test()
        except SkipTest as error:
            skipped += 1
            print(f"skip {test.__name__}: {error}")
        else:
            passed += 1
            print(f"ok  {test.__name__}")
    print(f"\n{passed} passed, {skipped} skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
