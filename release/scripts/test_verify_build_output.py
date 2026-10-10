#!/usr/bin/env python3
"""Self-contained checks for the content-leakage scan in verify_build_output.py.

Run directly (stdlib only, no pytest):

    python release/scripts/test_verify_build_output.py

Exits non-zero on the first failed assertion.
"""

from __future__ import annotations

import struct
import argparse
import contextlib
import io
import json
import os
import stat
import sys
import tarfile
import types
import zipfile
from unittest.mock import patch
import tempfile
from pathlib import Path, PurePosixPath

import verify_build_output as vbo
import analysis_tools
from test_analysis_tools import fixture


def _bundle(files: dict[str, bytes]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="byo-leakscan-"))
    for rel, data in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return root


def test_personal_home_and_username_are_flagged() -> None:
    bundle = _bundle(
        {
            "byo": b"\x00\x01machine code /Users/benjaminhuh/.cargo/registry/foo.rs\x00",
        }
    )
    needles = vbo.build_leak_needles(
        # Keep the simulated macOS path POSIX-formatted when this test runs on
        # Windows; pathlib.Path would convert it to a backslash path there.
        home=PurePosixPath("/Users/benjaminhuh"),
        user="benjaminhuh",
        checkout_root=PurePosixPath(
            "/Users/benjaminhuh/Documents/GitHub/Embedded CLI/InstallerWork"
        ),
        extra=[],
    )
    findings = vbo.scan_bundle_for_leaks(bundle, needles)
    labels = {label for _, label, _ in findings}
    assert "build-home-path" in labels, findings
    assert "build-username" in labels, findings


def test_shared_ci_account_paths_are_tolerated() -> None:
    # Upstream toolchain/dependency paths under a shared CI account must not fail
    # a clean build. This mirrors the real bundles (/Users/runner/.cargo/...,
    # /Users/sysadmin/build/..., and upstream wheels' /Users/runner/work/<pkg>/).
    bundle = _bundle(
        {
            "byo": b"panic at /Users/runner/.cargo/registry/src/anyhow-1.0/src/error.rs",
            "sidecar/_yaml.so": b"/Users/runner/work/pyyaml/pyyaml/libyaml/scanner.c",
            "sidecar/_hashlib.so": b"/Users/sysadmin/build/v3.12.10/Modules/_blake2/blake2.c",
        }
    )
    needles = vbo.build_leak_needles(
        home=Path("/Users/runner"),
        user="runner",
        checkout_root=Path("/Users/runner/work/BYO-Installer/BYO-Installer"),
        extra=[],
    )
    findings = vbo.scan_bundle_for_leaks(bundle, needles)
    assert findings == [], findings


def test_windows_runner_account_is_tolerated() -> None:
    # GitHub's Windows runner account is `runneradmin`; upstream Rust->Python
    # extensions embed C:\Users\runneradmin\.cargo\... which must not fail a clean
    # build (regression: the account was missing from the generic set).
    leak = (
        rb"internal error C:\Users\runneradmin\.cargo\registry\src\index\pydantic_core"
    )
    bundle = _bundle({"sidecar/_pydantic_core.pyd": leak})
    needles = vbo.build_leak_needles(
        home=Path("C:/Users/runneradmin"),
        user="runneradmin",
        checkout_root=None,
        extra=[],
    )
    assert vbo.scan_bundle_for_leaks(bundle, needles) == []


def test_our_checkout_path_is_flagged_even_on_ci() -> None:
    checkout = Path("/Users/runner/work/BYO-Installer/BYO-Installer")
    bundle = _bundle({"sidecar/foo.so": f"built at {checkout}/launcher".encode()})
    needles = vbo.build_leak_needles(
        home=Path("/Users/runner"), user="runner", checkout_root=checkout, extra=[]
    )
    findings = vbo.scan_bundle_for_leaks(bundle, needles)
    assert any(label == "build-checkout-path" for _, label, _ in findings), findings


def test_private_key_material_is_flagged() -> None:
    bundle = _bundle(
        {"workflow/blob": b"junk-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n"}
    )
    needles = vbo.build_leak_needles(
        home=Path("/Users/runner"), user="runner", checkout_root=None, extra=[]
    )
    findings = vbo.scan_bundle_for_leaks(bundle, needles)
    assert any(label == "openssh-private-key" for _, label, _ in findings), findings


def test_utf16le_windows_path_is_flagged() -> None:
    leak = "/Users/benjaminhuh".encode("utf-16-le")
    bundle = _bundle({"byo.exe": b"MZ\x90\x00" + leak + b"\x00\x00"})
    needles = vbo.build_leak_needles(
        home=PurePosixPath("/Users/benjaminhuh"),
        user="benjaminhuh",
        checkout_root=None,
        extra=[],
    )
    findings = vbo.scan_bundle_for_leaks(bundle, needles)
    assert any(label == "build-home-path" for _, label, _ in findings), findings


def test_allow_suppresses_a_verified_false_positive() -> None:
    bundle = _bundle({"byo": b"local dev /Users/benjaminhuh/.cargo/registry/x.rs"})
    needles = vbo.build_leak_needles(
        home=PurePosixPath("/Users/benjaminhuh"),
        user="benjaminhuh",
        checkout_root=None,
        extra=[],
    )
    findings = vbo.scan_bundle_for_leaks(
        bundle, needles, allow=("/Users/benjaminhuh/.cargo",)
    )
    assert findings == [], findings


def _macho(n_stab: int, other: int = 2) -> bytes:
    nsyms = n_stab + other
    header = bytearray(32)
    struct.pack_into("<I", header, 0, vbo.MACHO_MAGIC_64_LE)
    struct.pack_into("<I", header, 16, 1)  # ncmds
    symoff = 32 + 24  # after the header and one LC_SYMTAB
    symtab = bytearray(16 * nsyms)
    for i in range(nsyms):
        symtab[i * 16 + 4] = 0xE0 if i < n_stab else 0x0F  # N_STAB vs normal type
    lc = bytearray(24)
    struct.pack_into("<II", lc, 0, vbo.MACHO_LC_SYMTAB, 24)
    struct.pack_into("<IIII", lc, 8, symoff, nsyms, symoff + len(symtab), 1)
    return bytes(header + lc + symtab)


def _elf(section_names: list[str]) -> bytes:
    names = [*section_names, ".shstrtab"]
    strtab = bytearray(b"\x00")
    offsets: dict[str, int] = {}
    for name in names:
        offsets[name] = len(strtab)
        strtab += name.encode() + b"\x00"
    shentsize, shoff = 64, 64
    strtab_off = shoff + shentsize * len(names)
    data = bytearray(strtab_off + len(strtab))
    data[:4] = b"\x7fELF"
    data[4], data[5] = 2, 1  # 64-bit, little-endian
    struct.pack_into("<Q", data, 40, shoff)
    struct.pack_into("<H", data, 58, shentsize)
    struct.pack_into("<H", data, 60, len(names))
    struct.pack_into("<H", data, 62, len(names) - 1)  # shstrndx -> .shstrtab
    for index, name in enumerate(names):
        header = shoff + index * shentsize
        struct.pack_into("<I", data, header, offsets[name])
        struct.pack_into(
            "<Q", data, header + 24, strtab_off if name == ".shstrtab" else 0
        )
        if name == ".shstrtab":
            # sh_size bounds every name lookup; a zero size is an invalid table.
            struct.pack_into("<Q", data, header + 32, len(strtab))
    data[strtab_off : strtab_off + len(strtab)] = strtab
    return bytes(data)


def _pe(pointer: int, count: int) -> bytes:
    data = bytearray(200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 64)  # e_lfanew
    data[64:68] = b"PE\x00\x00"
    struct.pack_into("<II", data, 64 + 4 + 8, pointer, count)
    return bytes(data)


def test_macho_strip_check_passes_when_clean_fails_when_debug() -> None:
    assert vbo.macho_debug_stab_count(_macho(0), 8) == 0
    assert vbo.macho_debug_stab_count(_macho(100), 8) > 8  # early-exits over the limit
    bundle = _bundle({"byo": _macho(1), "sidecar/byo-mcp-sidecar": _macho(0)})
    for exe in vbo.shipped_executables(bundle, "macos"):
        vbo.assert_stripped(exe, "macos")  # no raise
    dirty = _bundle({"byo": _macho(500)})
    try:
        vbo.assert_stripped(dirty / "byo", "macos")
        raise AssertionError("expected unstripped Mach-O to fail")
    except RuntimeError as error:
        assert "not stripped" in str(error)


def test_elf_strip_check_keys_on_symtab_not_debug_gdb_scripts() -> None:
    # A stripped Rust binary keeps the harmless `.debug_gdb_scripts`; only a real
    # `.symtab` counts as unstripped.
    assert vbo.elf_has_symtab(_elf([".text", ".debug_gdb_scripts"])) is False
    assert vbo.elf_has_symtab(_elf([".text", ".symtab"])) is True
    vbo.assert_stripped(
        _bundle({"byo": _elf([".text", ".debug_gdb_scripts"])}) / "byo", "linux"
    )


def test_pe_strip_check_requires_zeroed_coff_symbol_table() -> None:
    assert vbo.pe_coff_symbol_table(_pe(0, 0)) == (0, 0)
    vbo.assert_stripped(_bundle({"byo.exe": _pe(0, 0)}) / "byo.exe", "windows")
    try:
        vbo.assert_stripped(_bundle({"byo.exe": _pe(4096, 12)}) / "byo.exe", "windows")
        raise AssertionError("expected PE with a symbol table to fail")
    except RuntimeError as error:
        assert "not stripped" in str(error)


def test_real_bundles_are_stripped_when_present() -> None:
    # Integration guard: when the real per-target bundles exist locally, the
    # shipped launcher and sidecar must pass the strip check. Skipped in CI, where
    # release/dist is not checked out (main() covers the freshly built bundle).
    dist = Path(__file__).resolve().parents[1] / "dist"
    checked = 0
    for platform, name in (
        ("macos", "byo-0.1.0-macos-x86_64"),
        ("linux", "byo-0.1.0-linux-x86_64"),
        ("windows", "byo-0.1.0-windows-x86_64"),
    ):
        bundle = dist / name
        if not bundle.is_dir():
            continue
        for exe in vbo.shipped_executables(bundle, platform):
            if exe.is_file():
                vbo.assert_stripped(exe, platform)
                checked += 1
    print(f"    (real-bundle strip check exercised {checked} executable(s))")


def test_windows_zip_actual_bytes_and_resource_negatives() -> None:
    lock, data, files, sbom = fixture()
    data["sbom.cdx.json"] = json.dumps(sbom).encode()
    files.append(
        {
            "path": "sbom.cdx.json",
            "kind": "metadata",
            "executable": False,
            "size": len(data["sbom.cdx.json"]),
            "sha256": analysis_tools.sha256(data["sbom.cdx.json"]),
        }
    )
    manifest = {
        "platform": "windows",
        "architecture": "x86_64",
        "development_unsigned": True,
        "files": files,
    }
    data["release-manifest.json"] = json.dumps(manifest).encode()
    with tempfile.TemporaryDirectory() as temporary:
        archive = Path(temporary) / "byo-test.zip"

        def write(leaves):
            with zipfile.ZipFile(archive, "w") as output:
                for path, value in leaves.items():
                    output.writestr("byo-test/" + path, value)

        with patch.object(analysis_tools, "load_lock", return_value=lock):
            write(data)
            vbo.validate_archive(archive, "zip", "byo-test", manifest)
            for extra in (
                "analysis/clangd/lib/clang/23/include/extra.h",
                "sidecar/extra.dll",
                ".firm/report.json",
                ".cache/x",
                "analysis/cppcheck/addons/a.py",
                "sidecar/private.pdb",
            ):
                write({**data, extra: b"unselected"})
                try:
                    vbo.validate_archive(archive, "zip", "byo-test", manifest)
                    raise AssertionError(extra)
                except RuntimeError as error:
                    assert "inventory" in str(error), error
            changed = dict(data)
            changed["analysis/clangd/lib/clang/23/include/stddef.h"] += b"corrupt"
            write(changed)
            try:
                vbo.validate_archive(archive, "zip", "byo-test", manifest)
                raise AssertionError("changed archived bytes passed")
            except RuntimeError as error:
                assert "byte mismatch" in str(error), error
            moved = dict(data)
            moved["analysis/clangd/stddef.h"] = moved.pop(
                "analysis/clangd/lib/clang/23/include/stddef.h"
            )
            write(moved)
            try:
                vbo.validate_archive(archive, "zip", "byo-test", manifest)
                raise AssertionError("misplaced resource passed")
            except RuntimeError as error:
                assert "inventory" in str(error), error
            write(data)
            try:
                vbo.validate_archive(
                    archive, "zip", "byo-test", {**manifest, "version": "different"}
                )
                raise AssertionError("different archive manifest passed")
            except RuntimeError as error:
                assert "manifest differs" in str(error), error


def test_windows_inventory_rejects_rehashed_arbitrary_source() -> None:
    lock, data, files, sbom = fixture()
    data["sbom.cdx.json"] = json.dumps(sbom).encode()
    for path in (
        "sidecar/arbitrary.cpp",
        "sidecar/private.pdb",
        ".firm/code-analysis/result.json",
        ".cache/project.json",
        "sidecar/addons/script.txt",
    ):
        raw = b"bad payload"
        data[path] = raw
        manifest = {
            "files": files
            + [
                {
                    "path": path,
                    "size": len(raw),
                    "sha256": analysis_tools.sha256(raw),
                    "kind": "sidecar",
                    "executable": False,
                }
            ]
        }
        with patch.object(analysis_tools, "load_lock", return_value=lock):
            try:
                vbo.validate_windows_payload(manifest, data.__getitem__)
                raise AssertionError(path)
            except RuntimeError as error:
                assert "source/development" in str(error), error


# Native archive contract. These are platform-neutral: they build archives in
# memory and never execute payload bytes. `validate_payload` is replaced so each
# check isolates the archive layer (type, target, modes, entry kinds); native
# payload bytes are covered by test_analysis_portability.py.
SOURCE_LOCK = {
    "agent_workspace": {"repository": "example/agent", "commit": "a" * 40},
    "firmware_mcp": {"repository": "example/firmware", "commit": "b" * 40},
}
SOURCE = {
    key: {"repository": value["repository"], "commit": value["commit"]}
    for key, value in SOURCE_LOCK.items()
}
EXECUTABLE = b"native payload bytes are never executed"


def _native_manifest(platform: str, architecture: str) -> dict:
    return {
        "platform": platform,
        "architecture": architecture,
        "development_unsigned": True,
        "source": SOURCE,
        "files": [
            {
                "path": "bin/byo",
                "sha256": analysis_tools.sha256(EXECUTABLE),
                "size": len(EXECUTABLE),
                "kind": "executable",
                "executable": True,
            }
        ],
    }


def _entries(manifest: dict, overrides: dict | None = None) -> list[tuple]:
    """(name, data or None for a directory, mode, tar type) in archive order."""
    entries = {
        "byo-test": (None, 0o755, tarfile.DIRTYPE),
        "byo-test/bin": (None, 0o755, tarfile.DIRTYPE),
        "byo-test/bin/byo": (EXECUTABLE, 0o755, tarfile.REGTYPE),
        "byo-test/release-manifest.json": (
            json.dumps(manifest).encode(),
            0o644,
            tarfile.REGTYPE,
        ),
    }
    entries.update(overrides or {})
    return [(name, *value) for name, value in entries.items()]


def _write_tar(path: Path, entries) -> None:
    with tarfile.open(path, "w:gz") as output:
        for name, data, mode, kind in entries:
            info = tarfile.TarInfo(name)
            info.mode, info.type = mode, kind
            if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                info.linkname = "byo-test/bin/byo"
            if data is None or kind != tarfile.REGTYPE:
                output.addfile(info)
            else:
                info.size = len(data)
                output.addfile(info, io.BytesIO(data))


def _write_zip(path: Path, entries) -> None:
    with zipfile.ZipFile(path, "w") as output:
        for name, data, mode, kind in entries:
            if data is None:
                info = zipfile.ZipInfo(name + "/")
                info.external_attr = ((stat.S_IFDIR | mode) << 16) | 0x10
                output.writestr(info, b"")
                continue
            info = zipfile.ZipInfo(name)
            file_type = stat.S_IFLNK if kind == tarfile.SYMTYPE else stat.S_IFREG
            info.external_attr = (file_type | mode) << 16
            output.writestr(info, data)


def _expect_archive_error(archive: Path, kind: str, manifest, fragment: str, **kw):
    with patch.object(vbo, "validate_payload") as payload:
        try:
            vbo.validate_archive(archive, kind, "byo-test", manifest, **kw)
        except RuntimeError as error:
            assert fragment in str(error), (fragment, error)
        else:
            raise AssertionError(f"accepted archive; expected {fragment!r}")
        assert not payload.called, "payload validated after archive rejection"


def test_native_tar_and_zip_archives_bind_target_type_and_modes() -> None:
    cases = (
        ("linux", "x86_64", "linux-x86_64-glibc-2.28", "tar.gz", ".tar.gz", _write_tar),
        ("macos", "aarch64", "macos-aarch64", "zip", ".zip", _write_zip),
        ("macos", "x86_64", "macos-x86_64", "zip", ".zip", _write_zip),
    )
    for platform, architecture, target, kind, suffix, write in cases:
        manifest = _native_manifest(platform, architecture)
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / f"byo-test{suffix}"
            write(archive, _entries(manifest))
            observed = []

            def inspect(checked, read_bytes, *, read_mode):
                # The readers are scoped to the open archive; use them in-call.
                observed.append(
                    (
                        checked,
                        read_bytes("bin/byo"),
                        read_mode("bin/byo"),
                        read_mode("release-manifest.json"),
                    )
                )

            with patch.object(vbo, "validate_payload", side_effect=inspect) as payload:
                vbo.validate_archive(
                    archive, kind, "byo-test", manifest, expected_target=target
                )
            assert payload.call_count == 1, target
            assert observed == [(manifest, EXECUTABLE, 0o755, 0o644)], target

            other = "windows-x86_64" if platform != "windows" else "linux-x86_64"
            _expect_archive_error(
                archive,
                kind,
                manifest,
                "differs from explicit target",
                expected_target=other,
            )
            sibling = {"aarch64": "x86_64", "x86_64": "aarch64"}[architecture]
            if platform == "macos":
                _expect_archive_error(
                    archive,
                    kind,
                    manifest,
                    "differs from explicit target",
                    expected_target=f"macos-{sibling}",
                )
            _expect_archive_error(
                archive, kind, {**manifest, "version": "other"}, "manifest differs"
            )
            write(
                archive,
                _entries(manifest, {"byo-test/bin": (None, 0o700, tarfile.DIRTYPE)}),
            )
            _expect_archive_error(archive, kind, manifest, "directory permissions")
            write(
                archive,
                _entries(
                    manifest,
                    {
                        "byo-test/release-manifest.json": (
                            json.dumps(manifest).encode(),
                            0o600,
                            tarfile.REGTYPE,
                        )
                    },
                ),
            )
            _expect_archive_error(archive, kind, manifest, "metadata permissions")
            write(
                archive,
                _entries(manifest, {"byo-test/extra": (None, 0o755, tarfile.DIRTYPE)}),
            )
            _expect_archive_error(archive, kind, manifest, "misplaced directory")
            write(
                archive,
                _entries(
                    manifest, {"byo-test/bin/extra": (b"x", 0o644, tarfile.REGTYPE)}
                ),
            )
            _expect_archive_error(archive, kind, manifest, "payload inventory")


def test_native_archive_type_and_suffix_follow_target() -> None:
    for platform, architecture, wrong_kind, write in (
        ("linux", "x86_64", "zip", _write_zip),
        ("macos", "aarch64", "tar.gz", _write_tar),
        ("macos", "x86_64", "tar.gz", _write_tar),
    ):
        manifest = _native_manifest(platform, architecture)
        with tempfile.TemporaryDirectory() as temporary:
            suffix = ".zip" if wrong_kind == "zip" else ".tar.gz"
            archive = Path(temporary) / f"byo-test{suffix}"
            write(archive, _entries(manifest))
            _expect_archive_error(archive, wrong_kind, manifest, "Archive type differs")
    with tempfile.TemporaryDirectory() as temporary:
        manifest = _native_manifest("linux", "x86_64")
        tgz = Path(temporary) / "byo-test.tgz"
        _write_tar(tgz, _entries(manifest))
        _expect_archive_error(tgz, "tar.gz", manifest, "did not produce a .tar.gz")
        not_zip = Path(temporary) / "byo-test.tar"
        _write_zip(not_zip, _entries(_native_manifest("macos", "aarch64")))
        _expect_archive_error(not_zip, "zip", None, "did not produce a .zip")
        _expect_archive_error(tgz, "tar", manifest, "unsupported archive contract")


def test_native_archives_reject_links_and_special_entries() -> None:
    manifest = _native_manifest("linux", "x86_64")
    with tempfile.TemporaryDirectory() as temporary:
        archive = Path(temporary) / "byo-test.tar.gz"
        for kind in (
            tarfile.SYMTYPE,
            tarfile.LNKTYPE,
            tarfile.FIFOTYPE,
            tarfile.CHRTYPE,
        ):
            _write_tar(
                archive,
                _entries(manifest, {"byo-test/bin/link": (None, 0o755, kind)}),
            )
            _expect_archive_error(archive, "tar.gz", manifest, "forbidden non-file")
        _write_tar(
            archive,
            _entries(manifest, {"byo-test/bin/byo": (None, 0o755, tarfile.SYMTYPE)}),
        )
        _expect_archive_error(archive, "tar.gz", manifest, "forbidden non-file")
        _write_tar(
            archive,
            _entries(manifest, {"byo-test/../escape": (b"x", 0o644, tarfile.REGTYPE)}),
        )
        _expect_archive_error(archive, "tar.gz", manifest, "Unsafe")
    macos = _native_manifest("macos", "aarch64")
    with tempfile.TemporaryDirectory() as temporary:
        archive = Path(temporary) / "byo-test.zip"
        _write_zip(
            archive,
            _entries(macos, {"byo-test/bin/link": (b"byo", 0o755, tarfile.SYMTYPE)}),
        )
        _expect_archive_error(archive, "zip", macos, "forbidden non-file")
        with zipfile.ZipFile(archive, "w") as output:
            for name, data, mode, _ in _entries(macos):
                info = zipfile.ZipInfo(name + ("/" if data is None else ""))
                info.external_attr = (stat.S_IFREG | mode) << 16
                output.writestr(info, data or b"")
        _expect_archive_error(archive, "zip", macos, "directory spelling")


class _CommandLine:
    """Run `verify_build_output.py analysis-archive` against a temporary root."""

    def __init__(self, temporary: str) -> None:
        self.root = Path(temporary) / "root"
        (self.root / "release").mkdir(parents=True)
        (self.root / "release/source-lock.json").write_text(json.dumps(SOURCE_LOCK))
        self.receipt = Path(temporary) / "receipt.json"
        self.locks: list[str] = []
        self.native = types.ModuleType("native_formats")
        self.native.validate_closure = lambda lock, read_bytes: {
            "native_closure": lock["target"],
            "manifest_seen": bool(read_bytes("release-manifest.json")),
        }

    def load_lock(self, *, target=None, **_):
        self.locks.append(target)
        return {"target": target}

    def run(self, *argv: str):
        output = io.StringIO()
        with (
            patch.object(vbo, "ROOT", self.root),
            patch.object(vbo, "validate_archive") as validated,
            patch.object(analysis_tools, "load_lock", side_effect=self.load_lock),
            patch.object(
                analysis_tools,
                "validate_pe_closure",
                return_value={"pe_closure": "checked"},
            ) as pe,
            patch.dict(sys.modules, {"native_formats": self.native}),
            patch.object(sys, "argv", ["verify_build_output.py", *argv]),
            contextlib.redirect_stdout(output),
        ):
            code = vbo.main()
        return code, validated, pe, output.getvalue()


def _cli_archive(directory: Path, platform: str, architecture: str, **manifest_changes):
    manifest = {**_native_manifest(platform, architecture), **manifest_changes}
    if platform == "linux":
        archive = directory / "byo-test.tar.gz"
        _write_tar(archive, _entries(manifest))
    else:
        archive = directory / "byo-test.zip"
        _write_zip(archive, _entries(manifest))
    return archive, manifest


def test_analysis_archive_cli_requires_target_and_writes_receipt() -> None:
    cases = (
        ("linux", "x86_64", "linux-x86_64-glibc-2.28", "linux-x86_64", "tar.gz"),
        ("macos", "aarch64", "macos-aarch64", "macos-aarch64", "zip"),
        ("macos", "x86_64", "macos-x86_64", "macos-x86_64", "zip"),
        ("windows", "x86_64", "windows-x86_64", "windows-x86_64", "zip"),
    )
    for platform, architecture, spelled, target, kind in cases:
        with tempfile.TemporaryDirectory() as temporary:
            cli = _CommandLine(temporary)
            archive, manifest = _cli_archive(Path(temporary), platform, architecture)
            code, validated, pe, printed = cli.run(
                "analysis-archive",
                "--expected-target",
                spelled,
                "--archive",
                str(archive),
                "--receipt",
                str(cli.receipt),
            )
            assert code == 0, target
            assert validated.call_count == 1, target
            args, kwargs = validated.call_args
            assert (Path(args[0]), args[1], args[2], args[3]) == (
                archive,
                kind,
                "byo-test",
                manifest,
            ), target
            assert kwargs == {"expected_target": target}, target
            receipt = json.loads(cli.receipt.read_text())
            assert receipt["target"] == target
            assert receipt["source"] == SOURCE
            assert receipt["archive_sha256"] == vbo.sha256(archive)
            assert receipt["manifest_sha256"] == analysis_tools.sha256(
                json.dumps(manifest).encode()
            )
            assert json.loads(printed)["archive_sha256"] == receipt["archive_sha256"]
            if platform == "windows":
                assert pe.call_count == 1 and receipt["pe_closure"] == "checked"
                assert cli.locks == []
            else:
                assert not pe.called
                assert cli.locks == [target], cli.locks
                assert receipt["native_closure"] == target
            native_on_windows = os.name == "nt" and platform != "windows"
            assert receipt["evidence_kind"].startswith(
                "Windows-host platform-neutral"
                if native_on_windows
                else "static archive"
            ), receipt["evidence_kind"]

            # The generic command has no implicit or host-derived target.
            cli.receipt.unlink()
            try:
                cli.run(
                    "analysis-archive",
                    "--archive",
                    str(archive),
                    "--receipt",
                    str(cli.receipt),
                )
                raise AssertionError("analysis-archive accepted a missing target")
            except SystemExit as exit_:
                assert exit_.code == 2
            assert not cli.receipt.exists()


def test_windows_analysis_archive_alias_is_retained_and_windows_only() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        cli = _CommandLine(temporary)
        archive, manifest = _cli_archive(Path(temporary), "windows", "x86_64")
        code, validated, pe, _ = cli.run(
            "windows-analysis-archive",
            "--archive",
            str(archive),
            "--receipt",
            str(cli.receipt),
        )
        assert code == 0 and pe.call_count == 1
        assert validated.call_args.kwargs == {"expected_target": "windows-x86_64"}
        assert json.loads(cli.receipt.read_text())["target"] == "windows-x86_64"
        for other in ("linux-x86_64", "macos-aarch64", "macos-x86_64"):
            cli.receipt.unlink(missing_ok=True)
            try:
                cli.run(
                    "windows-analysis-archive",
                    "--expected-target",
                    other,
                    "--archive",
                    str(archive),
                    "--receipt",
                    str(cli.receipt),
                )
                raise AssertionError(f"alias accepted {other}")
            except RuntimeError as error:
                assert "requires Windows x86_64" in str(error), error
            assert not cli.receipt.exists()


def test_analysis_archive_cli_rejects_source_pin_and_root_manifest_drift() -> None:
    drifted = {
        "agent_workspace": {**SOURCE["agent_workspace"], "commit": "c" * 40},
        "firmware_mcp": SOURCE["firmware_mcp"],
    }
    for source in (drifted, {"agent_workspace": SOURCE["agent_workspace"]}, {}):
        with tempfile.TemporaryDirectory() as temporary:
            cli = _CommandLine(temporary)
            archive, _ = _cli_archive(Path(temporary), "linux", "x86_64", source=source)
            try:
                cli.run(
                    "analysis-archive",
                    "--expected-target",
                    "linux-x86_64",
                    "--archive",
                    str(archive),
                    "--receipt",
                    str(cli.receipt),
                )
                raise AssertionError("source pin drift passed")
            except RuntimeError as error:
                assert "source pin mismatch" in str(error), error
            assert not cli.receipt.exists()
    with tempfile.TemporaryDirectory() as temporary:
        cli = _CommandLine(temporary)
        manifest = _native_manifest("macos", "aarch64")
        archive = Path(temporary) / "byo-test.zip"
        entries = _entries(manifest)
        second = [
            (n.replace("byo-test", "byo-other", 1), d, m, k) for n, d, m, k in entries
        ]
        for layout in ([], entries + second):
            if layout:
                _write_zip(archive, layout)
            else:
                zipfile.ZipFile(archive, "w").close()
            try:
                cli.run(
                    "analysis-archive",
                    "--expected-target",
                    "macos-aarch64",
                    "--archive",
                    str(archive),
                    "--receipt",
                    str(cli.receipt),
                )
                raise AssertionError("ambiguous root manifest passed")
            except RuntimeError as error:
                assert "one root release manifest" in str(error), error
            assert not cli.receipt.exists()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--windows-only", action="store_true")
    args = parser.parse_args()
    tests = [
        value for name, value in sorted(globals().items()) if name.startswith("test_")
    ]
    if args.windows_only:
        tests = [
            test
            for test in tests
            if test.__name__
            not in {
                "test_macho_strip_check_passes_when_clean_fails_when_debug",
                "test_elf_strip_check_keys_on_symtab_not_debug_gdb_scripts",
                "test_real_bundles_are_stripped_when_present",
            }
        ]
    for test in tests:
        test()
        print(f"ok  {test.__name__}")
    print(f"\n{len(tests)} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
