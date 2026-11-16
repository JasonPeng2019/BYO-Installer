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


def test_linux_zlib_sbom_rejects_staged_to_final_inventory_drift() -> None:
    # This boundary consumes the final measured inventory. License ownership
    # and RPM identity must survive even for libz.so.1's versioned suffix.
    with tempfile.TemporaryDirectory(prefix="byo-zlib-sbom-") as temporary:
        root = Path(temporary)
        bundle = root / "bundle"
        delivered = {
            "sidecar/libz.so.1": (b"fixture library bytes", "native-dependency"),
            "sidecar/licenses/zlib/LICENSE": (b"fixture license bytes", "license"),
        }
        staged = []
        for relative, (data, kind) in delivered.items():
            path = bundle / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o644)
            staged.append(
                {
                    "path": relative,
                    "sha256": analysis_tools.sha256(data),
                    "size": len(data),
                    "kind": kind,
                    "executable": False,
                }
            )
        provenance = {
            "package": "zlib-1.2.11-25.el8.x86_64",
            "version": "1.2.11",
            "source_rpm": "zlib-1.2.11-25.el8.src.rpm",
            "license": "zlib",
            "files": staged,
        }
        report = root / "report.xml"
        report.write_text(
            '<report nuitka_version="2.8.9"><python python_version="3.12.0"/><distributions/></report>',
            encoding="utf-8",
        )
        final = br.payload_inventory(bundle)
        assert sorted(staged, key=lambda leaf: leaf["path"]) == final
        with patch.object(
            br, "digest", side_effect=AssertionError("SBOM rehashed payload")
        ):
            br.write_sbom(
                bundle, report, "0.1.8", final, linux_sidecar_provenance=provenance
            )
        for selected in staged:
            for label, change in (
                ("missing", None),
                ("hash", {"sha256": "0" * 64}),
                ("size", {"size": selected["size"] + 1}),
                ("kind", {"kind": "sidecar"}),
                ("mode", {"executable": True}),
            ):
                changed = [
                    {**leaf, **change}
                    if leaf["path"] == selected["path"]
                    else dict(leaf)
                    for leaf in final
                    if leaf["path"] != selected["path"] or change is not None
                ]
                try:
                    br.write_sbom(
                        bundle,
                        report,
                        "0.1.8",
                        changed,
                        linux_sidecar_provenance=provenance,
                    )
                except RuntimeError as error:
                    assert "inventory differs from staging" in str(error), error
                    assert selected["path"] in str(error), error
                else:
                    raise AssertionError(
                        f"Accepted zlib {label} drift: {selected['path']}"
                    )
            # Rehashing modified delivered bytes cannot erase the earlier RPM
            # measurement, for either the library or its owned notice.
            path = bundle / selected["path"]
            original = path.read_bytes()
            path.write_bytes(original + b"changed after staging")
            try:
                br.write_sbom(
                    bundle,
                    report,
                    "0.1.8",
                    br.payload_inventory(bundle),
                    linux_sidecar_provenance=provenance,
                )
            except RuntimeError as error:
                assert "inventory differs from staging" in str(error), error
            else:
                raise AssertionError(
                    f"Accepted remeasured zlib drift: {selected['path']}"
                )
            path.write_bytes(original)


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
