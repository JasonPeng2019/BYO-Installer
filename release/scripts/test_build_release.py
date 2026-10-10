#!/usr/bin/env python3
"""Self-contained checks for the launcher path-remap helper in build_release.py.

Run directly (stdlib only, no pytest):

    python release/scripts/test_build_release.py
"""

from __future__ import annotations

from contextlib import chdir, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import SkipTest
from unittest.mock import patch
import os
import re
import subprocess
import sys
import tempfile
import json

import build_release as br
from test_analysis_tools import fixture, pe
import analysis_tools
import verify_build_output

SEP = "\x1f"


def check_windows_output_destination(output_kind: str) -> None:
    if os.name != "nt":
        raise SkipTest("native Windows builder output paths")
    with tempfile.TemporaryDirectory(prefix="byo-output-") as temporary:
        root = Path(temporary).resolve()
        checkout = root / "installer"
        checkout.mkdir()
        caller = root / "caller with spaces \u00e9"
        caller.mkdir()
        build = root / "build"
        dist = build / "nuitka/sidecar.dist"
        dist.mkdir(parents=True)
        (dist / "byo-mcp-sidecar.exe").write_bytes(b"sidecar fixture")
        (build / "workspace.pack").write_bytes(b"workspace fixture")
        (build / "nuitka-compilation-report.xml").write_text("<report/>", "utf-8")
        cargo = root / "cargo"
        (cargo / "release").mkdir(parents=True)
        (cargo / "release/byo.exe").write_bytes(pe())
        inputs = root / "inputs"
        inputs.mkdir()
        output_args = {
            "relative": ["--output", "release/dist"],
            "absolute": ["--output", str(root / "absolute output \u00e9")],
            "default": [],
        }[output_kind]
        expected_output = {
            "relative": caller / "release/dist",
            "absolute": root / "absolute output \u00e9",
            "default": checkout / "release/dist",
        }[output_kind]
        expected_bundle = expected_output / "byo-0.1.8-windows-x86_64"
        self_tests = []

        def run_fixture(argv, **kwargs):
            if "self-test" not in argv:
                return
            self_tests.append(argv)
            # Exercise the sidecar's absolute-root contract at the run seam;
            # compilers, analyzers and the real compiled sidecar stay untouched.
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import argparse, pathlib; p = argparse.ArgumentParser(); "
                    "p.add_argument('command'); p.add_argument('--runtime-root'); "
                    "p.add_argument('--launcher-version'); a = p.parse_args(); "
                    "p.error('runtime root must be an absolute path') "
                    "if not pathlib.Path(a.runtime_root).is_absolute() else None",
                    *argv[1:],
                ],
                cwd=checkout,
                check=True,
                timeout=10,
            )
            runtime_root = Path(argv[argv.index("--runtime-root") + 1])
            assert runtime_root == expected_bundle, argv
            assert Path(argv[0]).is_absolute(), argv
            assert Path(argv[0]).samefile(runtime_root / "sidecar/byo-mcp-sidecar.exe")
            assert kwargs["env"]["BYO_SIDECAR_COMPILED"] == "1"

        def write_fixture_sbom(bundle, *_args):
            (bundle / "sbom.cdx.json").write_text("{}", "utf-8")

        with (
            chdir(caller),
            redirect_stdout(StringIO()),
            patch.object(br, "ROOT", checkout),
            patch.object(
                sys,
                "argv",
                [
                    "build_release.py",
                    "--build-dir",
                    str(build),
                    "--analysis-input-dir",
                    str(inputs),
                    "--reuse-sidecar",
                    *output_args,
                ],
            ),
            patch.dict(os.environ, {"CARGO_TARGET_DIR": str(cargo)}),
            patch.object(br, "release_version", return_value="0.1.8"),
            patch.object(br, "source_provenance", return_value={}),
            patch.object(br, "validate_windows_build_python", return_value={}),
            patch.object(br, "export_clean_workspace"),
            patch.object(br, "run", side_effect=run_fixture),
            patch.object(br, "collect_private_symbols", return_value=root / "symbols"),
            patch.object(br, "write_sbom", side_effect=write_fixture_sbom),
            patch.object(br, "toolchain_provenance", return_value={}),
            patch.object(analysis_tools, "stage_windows", return_value=None),
            patch.object(analysis_tools, "stage_windows_native"),
            # Analyzer staging is mocked here, so the final archive validator
            # is a seam; its own contracts live in test_verify_build_output.py.
            patch.object(verify_build_output, "validate_archive") as validated,
        ):
            assert br.main() == 0
        assert len(self_tests) == 1, self_tests
        assert (expected_bundle / "release-manifest.json").is_file()
        archive = expected_output / f"{expected_bundle.name}.zip"
        assert archive.is_file()
        assert validated.call_count == 1, validated.call_args_list
        assert Path(validated.call_args.args[0]) == archive, validated.call_args
        assert validated.call_args.kwargs.get("expected_target") == "windows-x86_64"
        assert (expected_output / f"{expected_bundle.name}.sha256").read_text() == (
            f"{br.digest(archive)}  {archive.name}\n"
        )


def test_windows_relative_output_uses_absolute_runtime_root() -> None:
    check_windows_output_destination("relative")


def test_windows_absolute_output_uses_absolute_runtime_root() -> None:
    check_windows_output_destination("absolute")


def test_windows_default_output_uses_absolute_runtime_root() -> None:
    check_windows_output_destination("default")


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


BUILD_INVOCATION = re.compile(r"release/scripts/build_release\.py ")
ACQUIRE = re.compile(
    r"release/scripts/acquire_analysis_inputs\.py --expected-target "
    r"(\"\$EXPECTED_TARGET\"|[a-z0-9_-]+) --output (\"[^\"]+\")"
)


def workflow_jobs(filename: str) -> tuple[str, dict[str, str]]:
    text = (br.ROOT / ".github/workflows" / filename).read_text("utf-8")
    parts = re.split(r"(?m)^  ([a-z][\w-]*):\n", text.split("\njobs:\n", 1)[1])
    return text, dict(zip(parts[1::2], parts[2::2]))


def test_every_analyzer_build_acquires_pinned_inputs_explicitly() -> None:
    # Workflow contract (static text; pending until ROOT integrates the
    # workflows): each archive build first runs the explicit target-pinned
    # acquisition CLI and passes exactly that directory to build_release.py.
    expected = {
        ("build-matrix.yml", "build"): ({"macos-aarch64", "macos-x86_64", "windows-x86_64"}, 2),
        ("build-matrix.yml", "linux-x86_64"): ({"linux-x86_64"}, 1),
        ("release.yml", "build"): ({"macos-aarch64", "macos-x86_64", "linux-x86_64"}, 1),
        ("release.yml", "windows"): ({"windows-x86_64"}, 2),
    }
    seen = set()
    windows_python = analysis_tools.load_lock(target="windows-x86_64")["windows_native"][
        "source"
    ]["python_version"]
    for filename in ("build-matrix.yml", "release.yml"):
        text, jobs = workflow_jobs(filename)
        # Inline lock parsing/downloads would bypass the hash-pinned CLI.
        for forbidden in ("Invoke-WebRequest", "Get-FileHash", "ConvertFrom-Json"):
            assert forbidden not in text, (filename, forbidden)
        for job, section in jobs.items():
            builds = [
                line for line in section.splitlines() if BUILD_INVOCATION.search(line)
            ]
            if not builds:
                continue
            seen.add((filename, job))
            targets, count = expected[(filename, job)]
            assert len(builds) == count, (filename, job, builds)
            acquisitions = list(ACQUIRE.finditer(section))
            assert len(acquisitions) == 1, (filename, job)
            acquisition = acquisitions[0]
            target = acquisition[1]
            if target == '"$EXPECTED_TARGET"':
                assert "EXPECTED_TARGET: ${{ matrix.target }}" in section[: acquisition.start()]
                matrix = set(re.findall(r"(?m)^ +- target: ([a-z0-9_-]+)$", section))
                assert matrix == targets, (filename, job, matrix)
            else:
                assert {target} == targets, (filename, job, target)
            first_build = min(section.index(line) for line in builds)
            assert acquisition.start() < first_build, (filename, job)
            assert "BYO_ANALYSIS_INPUT_DIR=" in section[acquisition.end() : first_build]
            for line in builds:
                if '"${args[@]}"' in line:
                    arrays = re.findall(r"(?m)^ +args=\((.*)\)$", section)
                    assert any('--analysis-input-dir "$BYO_ANALYSIS_INPUT_DIR"' in a for a in arrays)
                else:
                    assert '--analysis-input-dir "$BYO_ANALYSIS_INPUT_DIR"' in line, line
            if "windows-x86_64" in targets:
                assert windows_python in section, (
                    "Windows build Python must match pinned native inputs"
                )
            if "linux-x86_64" in targets:
                # Linux Cppcheck needs measured GCC runtime inputs in the same
                # directory before the build; never generated by the builder.
                staging = section[acquisition.end() : first_build]
                assert "/gcc-runtime" in staging, (filename, job)
                if "prepare_gcc_runtime_inputs.py" in staging:
                    for flag in ("--compiler", "--notices", "--package", "--source", "--output"):
                        assert flag in staging, (filename, job, flag)
                    assert '--output "$input_dir/gcc-runtime"' in staging
                else:
                    for leaf in ("COPYING3", "COPYING.RUNTIME", "provenance.json"):
                        assert leaf in staging, (filename, job, leaf)
    assert seen == set(expected), seen


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
