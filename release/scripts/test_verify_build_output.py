#!/usr/bin/env python3
"""Self-contained checks for the content-leakage scan in verify_build_output.py.

Run directly (stdlib only, no pytest):

    python release/scripts/test_verify_build_output.py

Exits non-zero on the first failed assertion.
"""

from __future__ import annotations

import struct
import tempfile
from pathlib import Path

import verify_build_output as vbo


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
        home=Path("/Users/benjaminhuh"),
        user="benjaminhuh",
        checkout_root=Path(
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
        home=Path("/Users/benjaminhuh"),
        user="benjaminhuh",
        checkout_root=None,
        extra=[],
    )
    findings = vbo.scan_bundle_for_leaks(bundle, needles)
    assert any(label == "build-home-path" for _, label, _ in findings), findings


def test_allow_suppresses_a_verified_false_positive() -> None:
    bundle = _bundle({"byo": b"local dev /Users/benjaminhuh/.cargo/registry/x.rs"})
    needles = vbo.build_leak_needles(
        home=Path("/Users/benjaminhuh"),
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
