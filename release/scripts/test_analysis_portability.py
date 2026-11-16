"""Four-target analyzer packaging contracts (stdlib unittest only).

Windows-host platform-neutral fixtures: lock, target, path, native-format,
closure, SBOM, mode and recipe checks below read synthetic ELF/Mach-O bytes
through parsers only. Nothing here executes a fake ELF or Mach-O program, and
passing on a Windows host is not native macOS/Linux evidence. The mocked
``stage_native`` GCC provenance cases need POSIX path semantics and are skipped
(labeled) on Windows; they never run a compiler.
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import re
import shlex
import struct
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import analysis_tools as tools
import verify_build_output as vbo

TARGETS = {
    "windows-x86_64": ("windows", "x86_64"),
    "macos-aarch64": ("macos", "aarch64"),
    "macos-x86_64": ("macos", "x86_64"),
    "linux-x86_64": ("linux", "x86_64"),
}
NATIVE_TARGETS = ("macos-aarch64", "macos-x86_64", "linux-x86_64")
LOCK_PATH = tools.ROOT / "release/analysis-tools.lock.json"
INTERPRETER = "/lib64/ld-linux-x86-64.so.2"
MACOS_12 = 0x000C0000
GCC_NOTICES = (
    "analysis/cppcheck/licenses/GCC-COPYING3",
    "analysis/cppcheck/licenses/GCC-COPYING.RUNTIME",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def elf_image(
    *,
    executable: bool = True,
    kind: int | None = None,
    machine: int = 62,
    ident: bytes = b"\x7fELF\x02\x01\x01",
    interpreter: str | None = "default",
    needed: tuple[str, ...] = ("libc.so.6", "libm.so.6"),
    runpath: str | None = None,
    rpath: str | None = None,
    soname: str | None = None,
    versions: tuple[tuple[str, str], ...] = (("libc.so.6", "GLIBC_2.17"),),
    defined: tuple[str, ...] = (),
    extra_tags: tuple[tuple[int, int], ...] = (),
    symtab: bool = False,
) -> bytes:
    """Little-endian ELF64 with one LOAD covering the file plus INTERP/DYNAMIC."""

    if interpreter == "default":
        interpreter = INTERPRETER if executable else None
    kind = kind if kind is not None else (2 if executable else 3)
    strings = bytearray(b"\0")

    def add(value: str) -> int:
        index = len(strings)
        strings.extend(value.encode() + b"\0")
        return index

    needed_index = [add(name) for name in needed]
    runpath_index = add(runpath) if runpath is not None else None
    rpath_index = add(rpath) if rpath is not None else None
    soname_index = add(soname) if soname is not None else None
    groups: dict[str, list[str]] = {}
    for library, version in versions:
        groups.setdefault(library, []).append(version)
    group_index = [
        (add(library), [add(version) for version in values])
        for library, values in groups.items()
    ]
    defined_index = [add(name) for name in defined]

    phnum = 2 + (interpreter is not None)
    start = 64 + 56 * phnum
    body = bytearray()
    interp_off = start
    if interpreter is not None:
        body += interpreter.encode() + b"\0"
    strtab_off = start + len(body)
    body += strings
    verneed_off = start + len(body)
    for i, (library, names) in enumerate(group_index):
        following = 16 + 16 * len(names) if i + 1 < len(group_index) else 0
        body += struct.pack("<HHIII", 1, len(names), library, 16, following)
        for j, name in enumerate(names):
            body += struct.pack(
                "<IHHII", 0, 0, 0, name, 16 if j + 1 < len(names) else 0
            )
    verdef_off = start + len(body)
    for i, name in enumerate(defined_index):
        following = 28 if i + 1 < len(defined_index) else 0
        body += struct.pack("<HHHHIII", 1, 0, i + 1, 1, 0, 20, following)
        body += struct.pack("<II", name, 0)
    entries = [(1, index) for index in needed_index]
    entries += [(5, strtab_off), (10, len(strings))]
    if soname_index is not None:
        entries.append((14, soname_index))
    if rpath_index is not None:
        entries.append((15, rpath_index))
    if runpath_index is not None:
        entries.append((29, runpath_index))
    if group_index:
        entries += [(0x6FFFFFFE, verneed_off), (0x6FFFFFFF, len(group_index))]
    if defined_index:
        entries += [(0x6FFFFFFC, verdef_off), (0x6FFFFFFD, len(defined_index))]
    entries += list(extra_tags) + [(0, 0)]
    dynamic_off = start + len(body)
    for tag, value in entries:
        body += struct.pack("<qQ", tag, value)
    shoff = shnum = shstrndx = 0
    if symtab:
        names = b"\0.text\0.symtab\0.shstrtab\0"
        names_off = start + len(body)
        body += names
        shoff = start + len(body)
        shnum, shstrndx = 3, 2
        for name_index in (1, 7, 15):
            header = bytearray(64)
            struct.pack_into("<I", header, 0, name_index)
            if name_index == 15:
                struct.pack_into("<QQ", header, 24, names_off, len(names))
            body += header
    total = start + len(body)
    headers = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, total, total, 0x1000)
    if interpreter is not None:
        size = len(interpreter) + 1
        headers += struct.pack(
            "<IIQQQQQQ", 3, 4, interp_off, interp_off, 0, size, size, 1
        )
    dynamic_size = 16 * len(entries)
    headers += struct.pack(
        "<IIQQQQQQ", 2, 6, dynamic_off, dynamic_off, 0, dynamic_size, dynamic_size, 8
    )
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident.ljust(16, b"\0"),
        kind,
        machine,
        1,
        0,
        64,
        shoff,
        0,
        64,
        56,
        phnum,
        64 if shnum else 0,
        shnum,
        shstrndx,
    )
    return header + headers + bytes(body)


def _command_with_string(command: int, prefix: bytes, value: str) -> bytes:
    payload = value.encode() + b"\0"
    size = 8 + len(prefix) + len(payload)
    size += -size % 8
    return (struct.pack("<II", command, size) + prefix + payload).ljust(size, b"\0")


def macho_image(
    architecture: str = "aarch64",
    *,
    executable: bool = True,
    cpu: int | None = None,
    filetype: int | None = None,
    magic: int = 0xFEEDFACF,
    loads: tuple[str, ...] = ("/usr/lib/libSystem.B.dylib", "/usr/lib/libc++.1.dylib"),
    install_name: str | None = None,
    rpaths: tuple[str, ...] = (),
    minima: tuple[tuple[str, int], ...] = (("build", MACOS_12),),
    dyld: str | None = "default",
    extra: tuple[bytes, ...] = (),
    stabs: int = 0,
) -> bytes:
    """Thin little-endian Mach-O 64 with dylib, rpath, minimum-OS and symtab commands."""

    cpu = (
        cpu
        if cpu is not None
        else {"aarch64": 0x0100000C, "x86_64": 0x01000007}[architecture]
    )
    filetype = filetype if filetype is not None else (2 if executable else 6)
    if dyld == "default":
        dyld = "/usr/lib/dyld" if executable else None
    commands = []
    if dyld is not None:
        commands.append(_command_with_string(0xE, struct.pack("<I", 12), dyld))
    if install_name is not None:
        commands.append(
            _command_with_string(
                0xD, struct.pack("<IIII", 24, 2, 0x10000, 0x10000), install_name
            )
        )
    for name in loads:
        commands.append(
            _command_with_string(
                0xC, struct.pack("<IIII", 24, 2, 0x10000, 0x10000), name
            )
        )
    for path in rpaths:
        commands.append(_command_with_string(0x8000001C, struct.pack("<I", 12), path))
    for kind, value in minima:
        if kind == "build":
            commands.append(struct.pack("<6I", 0x32, 24, 1, value, value, 0))
        else:
            commands.append(struct.pack("<4I", 0x24, 16, value, value))
    commands.extend(extra)
    symbols = b""
    if stabs:
        size_without = sum(len(c) for c in commands) + 24
        symoff = 32 + size_without
        nsyms = stabs + 1
        table = bytearray(16 * nsyms)
        for i in range(stabs):
            table[16 * i + 4] = 0xE0
        table[16 * stabs + 4] = 0x0F
        symbols = bytes(table) + b"\0"
        commands.append(
            struct.pack("<6I", 0x2, 24, symoff, nsyms, symoff + 16 * nsyms, 1)
        )
    blob = b"".join(commands)
    subtype = 0 if cpu == 0x0100000C else 3
    header = struct.pack(
        "<8I", magic, cpu, subtype, filetype, len(commands), len(blob), 0, 0
    )
    return header + blob + symbols


def native_executable(target: str, **changes) -> bytes:
    platform, architecture = TARGETS[target]
    if platform == "linux":
        return elf_image(**changes)
    return macho_image(architecture, **changes)


def static_runtime(**changes) -> dict:
    runtime = {
        "package": "fixture gcc-c++ package (not real provenance)",
        "source": "fixture://gcc-source-reference",
        "compiler_sha256": sha256(b"fixture g++"),
        "libraries": {
            "libstdc++.a": {"sha256": sha256(b"fixture libstdc++.a"), "size": 19},
            "libgcc.a": {"sha256": sha256(b"fixture libgcc.a"), "size": 16},
        },
        "notices": {
            path: {
                "sha256": sha256(f"notice {path}".encode()),
                "size": len(f"notice {path}"),
            }
            for path in GCC_NOTICES
        },
    }
    runtime.update(changes)
    return runtime


def native_fixture(
    target: str, *, runtime: dict | None = None, executables: dict | None = None
) -> tuple[dict, dict[str, bytes], list[dict], dict]:
    lock = copy.deepcopy(tools.load_lock(target=target))
    data: dict[str, bytes] = {}
    for name, program in lock["programs"].items():
        keep = [f for f in program["selected_files"] if f["kind"] == "license"]
        suffix = "/std.cfg" if name == "cppcheck" else "/include/stddef.h"
        keep += [
            f for f in program["selected_files"] if f["runtime_path"].endswith(suffix)
        ]
        keep += [
            f for f in program["selected_files"] if f["kind"] == "analysis-executable"
        ]
        executable = (executables or {}).get(name) or native_executable(target)
        for leaf in keep:
            value = (
                executable
                if leaf["kind"] == "analysis-executable"
                else f"fixture {leaf['runtime_path']}".encode()
            )
            leaf.update(size=len(value), sha256=sha256(value))
            data[leaf["runtime_path"]] = value
        program["selected_files"] = keep
        data[program["executable"]] = executable
        for path in program.get("additional_licenses", []):
            data[path] = f"notice {path}".encode()
    data["analysis/runtime.json"] = json.dumps(tools.mapping(lock)).encode()
    files = [
        {
            "path": path,
            "size": len(value),
            "sha256": sha256(value),
            "kind": tools.classification(path, lock)[0],
            "executable": tools.classification(path, lock)[1],
        }
        for path, value in sorted(data.items())
    ]
    provenance = {}
    if target == "linux-x86_64":
        provenance["static_runtime"] = static_runtime() if runtime is None else runtime
    components, dependencies = tools.sbom_components(lock, files, provenance)
    return lock, data, files, {"components": components, "dependencies": dependencies}


def with_sbom_leaf(data: dict[str, bytes], files: list[dict], sbom: dict) -> list[dict]:
    data["sbom.cdx.json"] = json.dumps(sbom).encode()
    return files + [
        {
            "path": "sbom.cdx.json",
            "kind": "metadata",
            "executable": False,
            "size": len(data["sbom.cdx.json"]),
            "sha256": sha256(data["sbom.cdx.json"]),
        }
    ]


def native_modes(files: list[dict]):
    executables = {leaf["path"] for leaf in files if leaf["executable"]}
    return lambda name: 0o755 if name in executables else 0o644


def raw_lock() -> dict:
    return json.loads(LOCK_PATH.read_bytes())


def write_lock(directory: Path, document) -> Path:
    path = directory / "analysis-tools.lock.json"
    path.write_text(document if isinstance(document, str) else json.dumps(document))
    return path


class LockRejectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def assert_rejected(
        self, document, pattern: str, target: str = "linux-x86_64"
    ) -> None:
        path = write_lock(self.directory, document)
        with self.assertRaisesRegex(RuntimeError, pattern):
            tools.load_lock(path, target=target)

    def test_unchanged_copy_loads_for_every_target(self) -> None:
        path = write_lock(self.directory, raw_lock())
        for target in TARGETS:
            self.assertEqual(
                tools.load_lock(path, target=target)["platform"], TARGETS[target][0]
            )


    def test_row_identity_must_match_its_key(self) -> None:
        for target in TARGETS:
            with self.subTest(target):
                document = raw_lock()
                document["targets"][target]["architecture"] = (
                    "aarch64" if target.endswith("x86_64") else "x86_64"
                )
                # Any mismatched row poisons the whole lock, not only the selected one.
                other = (
                    "windows-x86_64" if target != "windows-x86_64" else "linux-x86_64"
                )
                self.assert_rejected(document, "target record mismatch", other)


    def test_selected_paths_are_safe_owned_and_case_unique(self) -> None:
        cases = {
            "backslash": "analysis\\clangd\\x.h",
            "parent": "analysis/clangd/../x.h",
            "other owner": "analysis/cppcheck/x.h",
            "reserved": "analysis/clangd/NUL.h",
        }
        for label, path in cases.items():
            with self.subTest(label):
                document = raw_lock()
                document["targets"]["macos-x86_64"]["programs"]["clangd"][
                    "selected_files"
                ][-1]["runtime_path"] = path
                with self.assertRaises(RuntimeError):
                    tools.load_lock(
                        write_lock(self.directory, document), target="macos-x86_64"
                    )
        document = raw_lock()
        files = document["targets"]["macos-x86_64"]["programs"]["clangd"][
            "selected_files"
        ]
        files[-1]["runtime_path"] = (
            files[-2]["runtime_path"]
            .upper()
            .replace("ANALYSIS/CLANGD", "analysis/clangd")
        )
        with self.assertRaises(RuntimeError):
            tools.load_lock(write_lock(self.directory, document), target="macos-x86_64")


class TargetAndNamespaceTests(unittest.TestCase):

    def test_runtime_mapping_is_per_target(self) -> None:
        for target in TARGETS:
            with self.subTest(target):
                lock = tools.load_lock(target=target)
                mapped = tools.mapping(lock)
                self.assertEqual(
                    (mapped["platform"], mapped["architecture"]), TARGETS[target]
                )
                self.assertEqual(
                    mapped["programs"]["clangd"]["executable"],
                    lock["programs"]["clangd"]["executable"],
                )
                licenses = mapped["programs"]["cppcheck"]["licenses"]
                if target == "linux-x86_64":
                    self.assertEqual(licenses[-2:], list(GCC_NOTICES))
                    for notice in GCC_NOTICES:
                        self.assertEqual(
                            tools.classification(notice, lock), ("license", False)
                        )
                else:
                    self.assertFalse(any("GCC-" in path for path in licenses))
                    for notice in GCC_NOTICES:
                        with self.assertRaisesRegex(
                            RuntimeError,
                            "Unselected analysis payload: " + re.escape(notice),
                        ):
                            tools.classification(notice, lock)


class ElfHeaderTests(unittest.TestCase):
    def test_accepts_x86_64_executable_pie_and_private_library(self) -> None:
        info = __import__("native_formats").elf(elf_image(), True)
        self.assertEqual(
            (info["format"], info["machine"], info["type"], info["interpreter"]),
            ("ELF64", 62, 2, INTERPRETER),
        )
        self.assertEqual(info["needed"], ["libc.so.6", "libm.so.6"])
        self.assertEqual(
            info["versions"], [{"library": "libc.so.6", "version": "GLIBC_2.17"}]
        )
        pie = __import__("native_formats").elf(elf_image(kind=3), True)
        self.assertEqual(pie["type"], 3)
        library = __import__("native_formats").elf(
            elf_image(executable=False, soname="libx.so.1", defined=("X_1",)), False
        )
        self.assertEqual(
            (library["soname"], library["defined_versions"]), ("libx.so.1", ["X_1"])
        )

    def test_rejects_wrong_class_endianness_machine_and_type(self) -> None:
        import native_formats

        cases = {
            "ELF32": (elf_image(ident=b"\x7fELF\x01\x01\x01"), "little-endian ELF64"),
            "big endian": (
                elf_image(ident=b"\x7fELF\x02\x02\x01"),
                "little-endian ELF64",
            ),
            "Mach-O bytes": (macho_image(), "little-endian ELF64"),
            "PE bytes": (b"MZ" + b"\0" * 126, "little-endian ELF64"),
            "truncated": (elf_image()[:63], "little-endian ELF64"),
            "aarch64 machine": (elf_image(machine=183), "Wrong ELF architecture"),
            "relocatable": (elf_image(kind=1), "Wrong ELF architecture"),
            "core file": (elf_image(kind=4), "Wrong ELF architecture"),
        }
        for label, (data, pattern) in cases.items():
            with self.subTest(label), self.assertRaisesRegex(RuntimeError, pattern):
                native_formats.elf(data, True)
        with self.assertRaisesRegex(RuntimeError, "Wrong ELF architecture"):
            native_formats.elf(elf_image(kind=2), False)


class MachOHeaderTests(unittest.TestCase):
    def test_accepts_thin_arm64_and_x86_64_with_macos_12_floor(self) -> None:
        import native_formats

        for architecture, cpu in (("aarch64", 0x0100000C), ("x86_64", 0x01000007)):
            with self.subTest(architecture):
                info = native_formats.macho(
                    macho_image(architecture), architecture, True
                )
                self.assertEqual(
                    (info["cpu"], info["type"], info["minimum_os"]), (cpu, 2, MACOS_12)
                )
                self.assertEqual(
                    info["needed"],
                    ["/usr/lib/libSystem.B.dylib", "/usr/lib/libc++.1.dylib"],
                )
        legacy = native_formats.macho(
            macho_image(minima=(("legacy", 0x000B0000),)), "aarch64", True
        )
        self.assertEqual(legacy["minimum_os"], 0x000B0000)

    def test_rejects_wrong_slice_fat_endianness_and_file_type(self) -> None:
        import native_formats

        fat = struct.pack(">II", 0xCAFEBABE, 2) + macho_image()[8:]
        cases = {
            "arm64 for Intel": (
                macho_image("aarch64"),
                "x86_64",
                True,
                "Wrong Mach-O CPU",
            ),
            "Intel for arm64": (
                macho_image("x86_64"),
                "aarch64",
                True,
                "Wrong Mach-O CPU",
            ),
            "universal": (fat, "aarch64", True, "thin little-endian Mach-O 64"),
            "32-bit": (
                macho_image(magic=0xFEEDFACE),
                "aarch64",
                True,
                "thin little-endian Mach-O 64",
            ),
            "big endian": (
                struct.pack(">I", 0xFEEDFACF) + macho_image()[4:],
                "aarch64",
                True,
                "thin little-endian",
            ),
            "ELF bytes": (elf_image(), "aarch64", True, "thin little-endian Mach-O 64"),
            "dylib as executable": (
                macho_image(executable=False),
                "aarch64",
                True,
                "file type",
            ),
            "executable as dylib": (macho_image(), "aarch64", False, "file type"),
            "bundle type": (macho_image(filetype=8), "aarch64", True, "file type"),
        }
        for label, (data, architecture, executable, pattern) in cases.items():
            with self.subTest(label), self.assertRaisesRegex(RuntimeError, pattern):
                native_formats.macho(data, architecture, executable)


def linux_closure_lock(dependencies=("analysis/clangd/lib/libfoo.so.1",)) -> dict:
    return {
        "platform": "linux",
        "architecture": "x86_64",
        "programs": {
            "cppcheck": {
                "executable": "analysis/cppcheck/cppcheck",
                "dependencies": [],
            },
            "clangd": {
                "executable": "analysis/clangd/bin/clangd",
                "dependencies": list(dependencies),
            },
        },
    }


def macos_closure_lock(
    architecture="aarch64", dependencies=("analysis/clangd/lib/libfoo.dylib",)
) -> dict:
    lock = linux_closure_lock(dependencies)
    lock.update(platform="macos", architecture=architecture)
    return lock


class LinuxClosureTests(unittest.TestCase):
    def images(self, **changes) -> dict[str, bytes]:
        exe = dict(
            needed=("libfoo.so.1", "libc.so.6"),
            runpath="$ORIGIN/../lib",
            versions=(("libc.so.6", "GLIBC_2.28"), ("libfoo.so.1", "FOO_1")),
        )
        exe.update(changes.pop("exe", {}))
        lib = dict(
            executable=False,
            soname="libfoo.so.1",
            defined=("FOO_1",),
            needed=("libc.so.6",),
            versions=(),
        )
        lib.update(changes.pop("lib", {}))
        return {
            "analysis/cppcheck/cppcheck": elf_image(**changes.pop("cppcheck", {})),
            "analysis/clangd/bin/clangd": elf_image(**exe),
            "analysis/clangd/lib/libfoo.so.1": elf_image(**lib),
        }

    def validate(self, images, lock=None):
        import native_formats

        return native_formats.validate_closure(
            lock or linux_closure_lock(), images.__getitem__
        )

    def test_os_baseline_and_origin_private_library_pass(self) -> None:
        result = self.validate(self.images())
        self.assertEqual(
            (result["platform"], result["architecture"]), ("linux", "x86_64")
        )
        self.assertIn("not baseline execution", result["evidence_kind"])
        cppcheck_only = {
            "analysis/cppcheck/cppcheck": elf_image(),
            "analysis/clangd/bin/clangd": elf_image(),
        }
        self.validate(cppcheck_only, linux_closure_lock(()))


    def test_search_paths_must_select_the_private_lib_directory(self) -> None:
        cases = {
            "absolute runpath": ("/usr/lib", "Nonportable native search path"),
            "mixed runpath": (
                "$ORIGIN/../lib:/opt/lib",
                "Nonportable native search path",
            ),
            "escaping runpath": ("$ORIGIN/../../lib", "escapes private library root"),
            "sibling dir": ("$ORIGIN/../share", "escapes private library root"),
            "bare origin outside lib": ("$ORIGIN", "Bare loader origin"),
            "absolute after origin": ("$ORIGIN//lib", "Empty/absolute"),
        }
        for label, (value, pattern) in cases.items():
            with self.subTest(label), self.assertRaisesRegex(RuntimeError, pattern):
                self.validate(self.images(exe={"runpath": value}))
        with self.assertRaisesRegex(RuntimeError, "Nonportable native search path"):
            self.validate(self.images(exe={"runpath": None, "rpath": "/usr/local/lib"}))
        with self.assertRaisesRegex(
            RuntimeError, "Unresolved/undeclared native import"
        ):
            self.validate(self.images(exe={"runpath": None}))


class MacOSClosureTests(unittest.TestCase):
    def images(self, architecture="aarch64", **changes) -> dict[str, bytes]:
        exe = dict(
            loads=("@rpath/libfoo.dylib", "/usr/lib/libSystem.B.dylib"),
            rpaths=("@loader_path/../lib",),
        )
        exe.update(changes.pop("exe", {}))
        lib = dict(
            executable=False,
            install_name="@rpath/libfoo.dylib",
            loads=("/usr/lib/libSystem.B.dylib",),
        )
        lib.update(changes.pop("lib", {}))
        return {
            "analysis/cppcheck/cppcheck": macho_image(
                architecture, **changes.pop("cppcheck", {})
            ),
            "analysis/clangd/bin/clangd": macho_image(architecture, **exe),
            "analysis/clangd/lib/libfoo.dylib": macho_image(architecture, **lib),
        }

    def validate(self, images, lock=None):
        import native_formats

        return native_formats.validate_closure(
            lock or macos_closure_lock(), images.__getitem__
        )

    def test_os_frameworks_and_rpath_private_library_pass_for_both_slices(self) -> None:
        for architecture in ("aarch64", "x86_64"):
            with self.subTest(architecture):
                result = self.validate(
                    self.images(architecture), macos_closure_lock(architecture)
                )
                self.assertEqual(result["architecture"], architecture)
        loader = self.images(
            exe={"loads": ("@loader_path/../lib/libfoo.dylib",), "rpaths": ()}
        )
        self.validate(loader)


    def test_rpaths_and_install_names_stay_private(self) -> None:
        for rpath, pattern in (
            ("/usr/local/lib", "Nonportable"),
            ("@executable_path/../lib", "Nonportable"),
            ("@loader_path/../../lib", "escapes"),
        ):
            with self.subTest(rpath), self.assertRaisesRegex(RuntimeError, pattern):
                self.validate(self.images(exe={"rpaths": (rpath,)}))
        with self.assertRaisesRegex(RuntimeError, "install name is not portable"):
            self.validate(
                self.images(lib={"install_name": "/usr/local/lib/libfoo.dylib"})
            )
        with self.assertRaisesRegex(
            RuntimeError, "Unreferenced private native dependencies"
        ):
            self.validate(self.images(exe={"loads": ("/usr/lib/libSystem.B.dylib",)}))
        with self.assertRaisesRegex(RuntimeError, "Wrong Mach-O CPU"):
            self.validate(self.images("x86_64"), macos_closure_lock("aarch64"))


class NativePayloadTests(unittest.TestCase):
    def test_reduced_native_fixtures_validate_for_each_native_target(self) -> None:
        for target in NATIVE_TARGETS:
            with self.subTest(target):
                lock, data, files, sbom = native_fixture(target)
                tools.validate_analysis(files, data.__getitem__, sbom, lock)

    def test_inventory_sbom_and_mapping_tamper_fail(self) -> None:
        for target in NATIVE_TARGETS:
            with self.subTest(target):
                lock, data, files, sbom = native_fixture(target)
                cases = {}
                cases["duplicate inventory"] = (
                    files + [files[0]],
                    data,
                    sbom,
                    "Duplicate payload inventory",
                )
                duplicate = copy.deepcopy(sbom)
                duplicate["components"].append(duplicate["components"][0])
                cases["duplicate component"] = (
                    files,
                    data,
                    duplicate,
                    "Duplicate SBOM component",
                )
                owners = copy.deepcopy(sbom)
                owners["dependencies"][0]["dependsOn"].append(
                    "byo-analysis-file:analysis/cppcheck/extra"
                )
                cases["foreign ownership ref"] = (
                    files,
                    data,
                    owners,
                    "ownership namespace differs",
                )
                mapped = dict(data)
                mapped["analysis/runtime.json"] = data["analysis/runtime.json"].replace(
                    b"{", b'{"platform": "windows", ', 1
                )
                cases["duplicate mapping key"] = (
                    files,
                    mapped,
                    sbom,
                    "Duplicate JSON key",
                )
                retarget = dict(data)
                other = "linux" if target.startswith("macos") else "macos"
                retarget["analysis/runtime.json"] = json.dumps(
                    dict(tools.mapping(lock), platform=other)
                ).encode()
                cases["mapping platform"] = (
                    files,
                    retarget,
                    sbom,
                    "runtime mapping differs",
                )
                kind = copy.deepcopy(sbom)
                for component in kind["components"]:
                    for item in component.get("properties", []):
                        if (
                            item["name"] == "byo:analysis-kind"
                            and item["value"] == "analysis-resource"
                        ):
                            item["value"] = "analysis-data"
                cases["file kind"] = (files, data, kind, "")
                for label, (f, d, s, pattern) in cases.items():
                    with (
                        self.subTest(label),
                        self.assertRaisesRegex(RuntimeError, pattern),
                    ):
                        tools.validate_analysis(f, d.__getitem__, s, lock)


class NativeModeAndStripTests(unittest.TestCase):
    def payload(self, target, **fixture_options):
        lock, data, files, sbom = native_fixture(target, **fixture_options)
        files = with_sbom_leaf(data, files, sbom)
        platform, architecture = TARGETS[target]
        manifest = {"platform": platform, "architecture": architecture, "files": files}
        return lock, data, manifest

    def validate(self, lock, manifest, data, read_mode):
        with mock.patch.object(tools, "load_lock", return_value=lock) as loaded:
            vbo.validate_payload(manifest, data.__getitem__, read_mode=read_mode)
        loaded.assert_called_with(
            target=f"{manifest['platform']}-{manifest['architecture']}"
        )

    def test_native_payload_requires_exact_modes(self) -> None:
        for target in NATIVE_TARGETS:
            with self.subTest(target):
                lock, data, manifest = self.payload(target)
                modes = native_modes(manifest["files"])
                self.validate(lock, manifest, data, modes)
                executable = lock["programs"]["clangd"]["executable"]
                for label, read_mode in {
                    "no mode reader": None,
                    "executable 0644": lambda name: 0o644,
                    "data 0755": lambda name: 0o755,
                    "group-writable executable": lambda name: (
                        0o775 if name == executable else modes(name)
                    ),
                    "setuid executable": lambda name: (
                        0o4755 if name == executable else modes(name)
                    ),
                }.items():
                    with (
                        self.subTest(label),
                        self.assertRaisesRegex(RuntimeError, "permissions"),
                    ):
                        self.validate(lock, manifest, data, read_mode)


GCC_LIBRARIES = {
    "libstdc++.a": b"fixture archive: libstdc++.a\n",
    "libgcc.a": b"fixture archive: libgcc.a\n",
    "libgcc_eh.a": b"fixture archive: libgcc_eh.a\n",
}


@unittest.skipUnless(
    os.name == "posix",
    "mocked native Linux staging needs POSIX path semantics; pending on Windows host",
)
class LinuxGccRuntimeInputTests(unittest.TestCase):
    """Drives stage_native through mocked commands; no compiler or analyzer runs."""

    def setUp(self) -> None:
        import analysis_native

        self.native = analysis_native
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        # macOS temporary paths traverse /var -> /private/var; inputs must be link-free.
        root = Path(self.temporary.name).resolve()
        self.root = root
        self.inputs = root / "inputs"
        self.tools_dir = root / "toolchain"
        self.bundle, self.evidence = root / "bundle", root / "evidence"
        for directory in (self.inputs, self.tools_dir, self.inputs / "gcc-runtime"):
            directory.mkdir(parents=True, exist_ok=True)
        self.compiler = self.tools_dir / "g++"
        self.compiler.write_bytes(b"fixture g++ identity")
        self.cmake = self.tools_dir / "cmake"
        self.cmake.write_bytes(b"fixture cmake identity")
        self.linker = self.tools_dir / "ld"
        self.linker.write_bytes(b"fixture ld identity")
        self.libraries = {}
        for name, value in GCC_LIBRARIES.items():
            path = self.tools_dir / name
            path.write_bytes(value)
            self.libraries[name] = path
        self.link_inputs = set(GCC_LIBRARIES)
        self.baseline = "glibc 2.28"
        self.lock = self.make_lock()
        self.write_gcc_inputs()

    def make_lock(self) -> dict:
        lock = copy.deepcopy(tools.load_lock(target="linux-x86_64"))
        cpp, clangd = lock["programs"]["cppcheck"], lock["programs"]["clangd"]
        options = b"# fixture compileroptions.cmake\n"
        cpp["recipe"]["upstream_compileroptions_sha256"] = sha256(options)
        cpp["selected_files"] = [
            f for f in cpp["selected_files"] if f["runtime_path"].endswith("/std.cfg")
        ]
        members = {
            cpp["source"]["archive_prefix"] + "cmake/compileroptions.cmake": options
        }
        for leaf in cpp["selected_files"]:
            value = f"fixture {leaf['runtime_path']}".encode()
            leaf.update(size=len(value), sha256=sha256(value))
            members[leaf["upstream_path"]] = value
        archive = self.inputs / cpp["source"]["archive"]
        with tarfile.open(archive, "w:gz") as handle:
            for name, value in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(value)
                handle.addfile(info, io.BytesIO(value))
        cpp["source"]["sha256"] = sha256(archive.read_bytes())
        keep = [
            f
            for f in clangd["selected_files"]
            if f["kind"] in {"analysis-executable", "license"}
            or f["runtime_path"].endswith("/include/stddef.h")
        ]
        clangd["selected_files"] = keep
        archive = self.inputs / clangd["source"]["archive"]
        with zipfile.ZipFile(archive, "w") as handle:
            for leaf in keep:
                value = (
                    elf_image()
                    if leaf["kind"] == "analysis-executable"
                    else f"fixture {leaf['runtime_path']}".encode()
                )
                leaf.update(size=len(value), sha256=sha256(value))
                handle.writestr(leaf["upstream_path"], value)
        clangd["source"].update(
            sha256=sha256(archive.read_bytes()), size=archive.stat().st_size
        )
        return lock

    def write_gcc_inputs(self, document=None, *, notices=None) -> None:
        directory = self.inputs / "gcc-runtime"
        for name, value in (
            notices
            or {
                "COPYING3": b"fixture GPLv3 text",
                "COPYING.RUNTIME": b"fixture runtime exception",
            }
        ).items():
            if value is None:
                (directory / name).unlink(missing_ok=True)
            else:
                (directory / name).write_bytes(value)
        if document is None:
            document = {
                "schema_version": 1,
                "compiler_sha256": sha256(self.compiler.read_bytes()),
                "package": "fixture gcc-toolset package (not real provenance)",
                "source": "fixture://gcc-source",
                "static_libraries": {
                    name: sha256(value) for name, value in GCC_LIBRARIES.items()
                },
            }
        (directory / "provenance.json").write_text(
            document if isinstance(document, str) else json.dumps(document)
        )

    def tool(self, name: str) -> dict:
        path = {"g++": self.compiler}.get(name, self.tools_dir / name)
        path.write_bytes(
            path.read_bytes() if path.exists() else f"fixture {name}".encode()
        )
        return {"path": str(path), "sha256": sha256(path.read_bytes())}

    def command(self, argv, evidence, receipt, step, *, cwd=None) -> str:
        receipt["commands"].append({"step": step, "argv": argv})
        if step == "cmake-identity":
            return "cmake version 3.28.3"
        if step == "glibc-baseline":
            return self.baseline
        if step == "configure":
            build = Path(argv[argv.index("-B") + 1])
            flags = next(
                part for part in argv if part.startswith("-DCMAKE_EXE_LINKER_FLAGS=")
            )
            self.map_path = Path(
                shlex.split(flags.split(" ", 2)[-1])[-1].split(",", 2)[2]
            )
            record = build / "CMakeFiles/3.28.3/CMakeCXXCompiler.cmake"
            record.parent.mkdir(parents=True)
            record.write_text(
                f'set(CMAKE_CXX_COMPILER "{self.compiler}")\n'
                'set(CMAKE_CXX_COMPILER_ID "GNU")\n'
                'set(CMAKE_CXX_COMPILER_VERSION "12.2.1")\n'
            )
            (build / "CMakeCache.txt").write_text(
                f"CMAKE_LINKER:FILEPATH={self.linker}\n"
            )
            return ""
        if step == "build":
            build = Path(argv[argv.index("--build") + 1])
            (build / "bin").mkdir(parents=True)
            (build / "bin/cppcheck").write_bytes(elf_image())
            self.map_path.write_text(
                "".join(
                    f"LOAD {self.libraries[name]}\n"
                    for name in sorted(self.link_inputs)
                )
            )
            return ""
        if step.startswith("static-library-"):
            return str(self.libraries[step[len("static-library-") :]])
        return f"{step} fixture output"

    def stage(self) -> dict:
        native = self.native
        with (
            mock.patch.object(native.tools, "host_target", return_value="linux-x86_64"),
            mock.patch.object(
                native.tools, "load_lock", return_value=copy.deepcopy(self.lock)
            ),
            mock.patch.object(native.tools, "find_cmake", return_value=str(self.cmake)),
            mock.patch.object(native, "_tool", side_effect=self.tool),
            mock.patch.object(native, "_command", side_effect=self.command),
            mock.patch.object(
                native.subprocess,
                "run",
                side_effect=AssertionError("no process may run"),
            ),
        ):
            return native.stage_native(
                self.bundle, self.inputs, self.evidence, target="linux-x86_64"
            )

    def test_all_selected_static_inputs_are_measured_and_notices_shipped(self) -> None:
        receipt = self.stage()
        runtime = receipt["static_runtime"]
        self.assertEqual(
            set(runtime),
            {"package", "source", "compiler_sha256", "libraries", "notices"},
        )
        self.assertEqual(set(runtime["libraries"]), set(GCC_LIBRARIES))
        for name, value in GCC_LIBRARIES.items():
            self.assertEqual(
                runtime["libraries"][name],
                {"sha256": sha256(value), "size": len(value)},
            )
        self.assertEqual(set(runtime["notices"]), set(GCC_NOTICES))
        self.assertEqual(
            (self.bundle / GCC_NOTICES[0]).read_bytes(), b"fixture GPLv3 text"
        )
        self.assertEqual(
            (self.bundle / GCC_NOTICES[1]).read_bytes(), b"fixture runtime exception"
        )
        self.assertEqual(runtime["compiler_sha256"], sha256(self.compiler.read_bytes()))
        self.assertTrue(
            any(
                "-Wl,-Map," in part
                for c in receipt["commands"]
                if c["step"] == "configure"
                for part in c["argv"]
            )
        )
        self.assertEqual(
            receipt["gcc_input_sha256"],
            sha256((self.inputs / "gcc-runtime/provenance.json").read_bytes()),
        )
        self.assertEqual(receipt["native_closure_before_strip"]["platform"], "linux")
        for path in (self.bundle / "analysis").rglob("*"):
            expected = (
                0o755 if path.is_dir() or path.name in {"cppcheck", "clangd"} else 0o644
            )
            self.assertEqual(path.stat().st_mode & 0o7777, expected, path)


    def test_tampered_or_unrecorded_selected_library_hash_is_refused(self) -> None:
        for name in GCC_LIBRARIES:
            with self.subTest(name):
                document = json.loads(
                    (self.inputs / "gcc-runtime/provenance.json").read_text()
                )
                document["static_libraries"][name] = sha256(b"other " + name.encode())
                self.write_gcc_inputs(document)
                with self.assertRaisesRegex(
                    RuntimeError,
                    f"Supply matching GCC static library provenance: {re.escape(name)}",
                ):
                    self.stage()
                self.write_gcc_inputs()
        # A linked runtime archive that provenance does not name is not silently accepted.
        document = json.loads((self.inputs / "gcc-runtime/provenance.json").read_text())
        del document["static_libraries"]["libgcc_eh.a"]
        self.write_gcc_inputs(document)
        with self.assertRaisesRegex(
            RuntimeError, "unrecorded GCC static runtime input"
        ):
            self.stage()

APPLE_LIPO_FLAGS = frozenset(
    {
        "-arch",
        "-archs",
        "-create",
        "-detailed_info",
        "-extract",
        "-extract_family",
        "-fat64",
        "-hideARM64",
        "-info",
        "-output",
        "-remove",
        "-replace",
        "-segalign",
        "-thin",
        "-verify_arch",
    }
)
LIPO_SLICES = {"aarch64": "arm64", "x86_64": "x86_64"}
MACOS_TARGETS = ("macos-aarch64", "macos-x86_64")


def fat_image(slices: dict[str, bytes]) -> bytes:
    """Synthetic universal wrapper; only the fixture lipo reads past the magic."""

    return struct.pack(">II", 0xCAFEBABE, len(slices)) + b"".join(slices.values())


@unittest.skipUnless(
    os.name == "posix",
    "mocked native macOS staging needs POSIX path semantics; pending on Windows host",
)
class MacOSAppleLipoStagingTests(unittest.TestCase):
    """Drives stage_native through a fixture Apple host at subprocess.run.

    The real _tool and _command record lipo identity and command receipts.
    Nothing executes and passing here is not native macOS evidence.
    """

    def setUp(self) -> None:
        import analysis_native

        self.native = analysis_native
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        # macOS temporary paths traverse /var -> /private/var; inputs must be link-free.
        self.root = Path(self.temporary.name).resolve()
        self.inputs, toolchain = self.root / "inputs", self.root / "toolchain"
        self.sdk = toolchain / "MacOSX.sdk"
        self.sdk.mkdir(parents=True)
        self.inputs.mkdir()
        (self.sdk / "SDKSettings.json").write_text('{"Version": "15.5"}')
        self.cmake, self.compiler, self.make, self.lipo, self.linker = (
            toolchain / name for name in ("cmake", "clang++", "make", "lipo", "ld")
        )
        for path in (self.cmake, self.compiler, self.make, self.lipo, self.linker):
            path.write_bytes(f"fixture {path.name} identity".encode())
        self.slices = {
            name: macho_image(architecture)
            for architecture, name in LIPO_SLICES.items()
        }
        self.calls: list[list[str]] = []

    def make_lock(self, target: str) -> dict:
        lock = copy.deepcopy(tools.load_lock(target=target))
        cpp, clangd = lock["programs"]["cppcheck"], lock["programs"]["clangd"]
        options = b"# fixture compileroptions.cmake\n"
        cpp["recipe"]["upstream_compileroptions_sha256"] = sha256(options)
        cpp["selected_files"] = [
            f for f in cpp["selected_files"] if f["runtime_path"].endswith("/std.cfg")
        ]
        members = {
            cpp["source"]["archive_prefix"] + "cmake/compileroptions.cmake": options
        }
        for leaf in cpp["selected_files"]:
            value = f"fixture {leaf['runtime_path']}".encode()
            leaf.update(size=len(value), sha256=sha256(value))
            members[leaf["upstream_path"]] = value
        archive = self.inputs / cpp["source"]["archive"]
        with tarfile.open(archive, "w:gz") as handle:
            for name, value in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(value)
                handle.addfile(info, io.BytesIO(value))
        cpp["source"]["sha256"] = sha256(archive.read_bytes())
        clangd["selected_files"] = [
            f
            for f in clangd["selected_files"]
            if f["kind"] in {"analysis-executable", "license"}
            or f["runtime_path"].endswith("/include/stddef.h")
        ]
        archive = self.inputs / clangd["source"]["archive"]
        with zipfile.ZipFile(archive, "w") as handle:
            for leaf in clangd["selected_files"]:
                value = (
                    fat_image(self.slices)
                    if leaf["kind"] == "analysis-executable"
                    else f"fixture {leaf['runtime_path']}".encode()
                )
                leaf.update(size=len(value), sha256=sha256(value))
                handle.writestr(leaf["upstream_path"], value)
        clangd["source"].update(
            sha256=sha256(archive.read_bytes()), size=archive.stat().st_size
        )
        return lock

    def apple_lipo(self, argv: list[str]) -> tuple[int, str]:
        fatal = f"fatal error: {argv[0]}: "
        unknown = [
            part
            for part in argv[1:]
            if part.startswith("-") and part not in APPLE_LIPO_FLAGS
        ]
        if unknown:
            return 1, fatal + f"unknown flag: {unknown[0]}\n"
        if "-thin" not in argv or "-output" not in argv:
            return 1, fatal + "fixture models only <input> -thin <arch> -output\n"
        source, architecture = Path(argv[1]), argv[argv.index("-thin") + 1]
        if source.read_bytes()[:4] != b"\xca\xfe\xba\xbe":
            return 1, fatal + f"input file ({source}) must be a fat file\n"
        if architecture not in self.slices:
            return 1, fatal + (
                f"fat input file ({source}) does not contain the specified "
                f"architecture ({architecture}) to thin it to\n"
            )
        Path(argv[argv.index("-output") + 1]).write_bytes(self.slices[architecture])
        return 0, ""

    def apple_host(self, argv, **_) -> subprocess.CompletedProcess:
        argv = list(argv)
        self.calls.append(argv)
        stdout, code, stderr = "", 0, ""
        if argv[0] == str(self.lipo):
            code, stderr = self.apple_lipo(argv)
        elif argv[0] == str(self.cmake) and "-B" in argv:
            build = Path(argv[argv.index("-B") + 1])
            record = build / "CMakeFiles/3.28.3/CMakeCXXCompiler.cmake"
            record.parent.mkdir(parents=True)
            record.write_text(
                f'set(CMAKE_CXX_COMPILER "{self.compiler}")\n'
                'set(CMAKE_CXX_COMPILER_ID "AppleClang")\n'
                'set(CMAKE_CXX_COMPILER_VERSION "17.0.0.17000013")\n'
            )
            (build / "CMakeCache.txt").write_text(
                f"CMAKE_LINKER:FILEPATH={self.linker}\n"
            )
        elif argv[0] == str(self.cmake) and "--build" in argv:
            output = Path(argv[argv.index("--build") + 1]) / "bin/cppcheck"
            output.parent.mkdir(parents=True)
            output.write_bytes(macho_image(self.architecture))
        else:
            stdout = {
                (str(self.cmake), "--version"): "cmake version 3.28.3\n",
                ("sw_vers", "-productVersion"): "15.7.9\n",
                ("xcrun", "--find", "clang++"): f"{self.compiler}\n",
                ("xcrun", "--show-sdk-path"): f"{self.sdk}\n",
                ("xcrun", "--show-sdk-version"): "15.5\n",
                (str(self.compiler), "--version"): "Apple clang version 17.0.0\n",
                (str(self.make), "--version"): "GNU Make 3.81\n",
                (str(self.linker), "-v"): "@(#)PROGRAM:ld fixture\n",
            }.get(tuple(argv))
            if stdout is None:
                stdout, code, stderr = "", 127, f"fixture host does not model {argv}"
        return subprocess.CompletedProcess(argv, code, stdout, stderr)

    def stage(self, target: str) -> dict:
        native = self.native
        self.architecture = TARGETS[target][1]
        self.lock = self.make_lock(target)
        work = Path(tempfile.mkdtemp(dir=self.root))
        self.bundle, self.evidence = work / "bundle", work / "evidence"
        tools_on_path = {"lipo": str(self.lipo), "make": str(self.make)}
        with (
            mock.patch.object(native.tools, "host_target", return_value=target),
            mock.patch.object(
                native.tools, "load_lock", return_value=copy.deepcopy(self.lock)
            ),
            mock.patch.object(native.tools, "find_cmake", return_value=str(self.cmake)),
            mock.patch.object(native.shutil, "which", side_effect=tools_on_path.get),
            mock.patch.object(
                native,
                "_macos_translation_identity",
                return_value={
                    "sysctl": "sysctl.proc_translated",
                    "result": 0,
                    "errno": 0,
                    "translated": 0,
                },
            ),
            mock.patch.object(native.subprocess, "run", side_effect=self.apple_host),
        ):
            return native.stage_native(
                self.bundle, self.inputs, self.evidence, target=target
            )

    def thin_bundle(self, receipt: dict) -> None:
        native = self.native
        with (
            mock.patch.object(
                native.tools, "host_target", return_value=f"macos-{self.architecture}"
            ),
            mock.patch.object(native.subprocess, "run", side_effect=self.apple_host),
        ):
            native.thin_macos_bundle(self.bundle, self.lock, receipt, self.evidence)

    def private_python_image(self, **changes) -> bytes:
        # Synthetic control ID only: the rejected native Python ID was not uploaded.
        fields = {
            "executable": False,
            "install_name": "/fixture/build/Python",
            "rpaths": ("@loader_path",),
        }
        fields.update(changes)
        return macho_image(self.architecture, **fields)

    def add_private_python(self, data: bytes) -> Path:
        python = self.bundle / "sidecar/Python"
        python.parent.mkdir(parents=True, exist_ok=True)
        python.write_bytes(data)
        (python.parent / "byo-mcp-sidecar").write_bytes(
            macho_image(
                self.architecture,
                loads=("/usr/lib/libSystem.B.dylib", "@rpath/Python"),
                rpaths=("@loader_path",),
            )
        )
        return python

    def private_python_closure(self) -> dict:
        return self.native.native_formats.validate_bundle_closure(
            [
                {"path": "sidecar/Python", "executable": False},
                {"path": "sidecar/byo-mcp-sidecar", "executable": True},
            ],
            lambda name: (self.bundle / name).read_bytes(),
            "macos",
            self.architecture,
        )

    def normalize_private_python(
        self,
        receipt: dict,
        edited: bytes,
        *,
        fail_edit=False,
        host=None,
        no_tools=False,
    ) -> None:
        install_tool = self.compiler.parent / "install_name_tool"
        codesign = self.compiler.parent / "codesign"
        for path in (install_tool, codesign):
            path.write_bytes(f"fixture {path.name} identity".encode())

        def identity_host(argv, **kwargs):
            argv = list(argv)
            if argv[0] not in {str(install_tool), str(codesign)}:
                return self.apple_host(argv, **kwargs)
            self.calls.append(argv)
            if argv[0] == str(install_tool):
                if fail_edit:
                    return subprocess.CompletedProcess(
                        argv, 7, "", "fixture install_name_tool failure"
                    )
                Path(argv[-1]).write_bytes(edited)
            elif "--force" in argv:
                # Distinct synthetic bytes model the post-edit integrity receipt.
                Path(argv[-1]).write_bytes(edited + b"fixture adhoc integrity")
            stderr = "Signature=adhoc\n" if "--display" in argv else ""
            return subprocess.CompletedProcess(argv, 0, "", stderr)

        with (
            mock.patch.object(
                self.native.tools,
                "host_target",
                return_value=host or f"macos-{self.architecture}",
            ),
            mock.patch.object(
                self.native.shutil,
                "which",
                side_effect=(
                    AssertionError("unexpected identity tool discovery")
                    if no_tools
                    else {
                        "install_name_tool": str(install_tool),
                        "codesign": str(codesign),
                    }.get
                ),
            ),
            mock.patch.object(self.native.subprocess, "run", side_effect=identity_host),
        ):
            self.native.thin_macos_bundle(
                self.bundle, self.lock, receipt, self.evidence
            )

    def test_thin_private_python_identity_and_integrity_receipts_both_targets(self):
        for target in MACOS_TARGETS:
            with self.subTest(target):
                receipt = self.stage(target)
                before = self.private_python_image()
                edited = self.private_python_image(install_name="@rpath/Python")
                after = edited + b"fixture adhoc integrity"
                python = self.add_private_python(before)
                consumer = (python.parent / "byo-mcp-sidecar").read_bytes()
                with self.assertRaisesRegex(
                    RuntimeError, "absolute/unportable install name: sidecar/Python"
                ):
                    self.private_python_closure()
                self.calls.clear()
                start = len(receipt["commands"])
                self.normalize_private_python(receipt, edited)
                self.assertEqual(python.read_bytes(), after)
                self.assertEqual(
                    (python.parent / "byo-mcp-sidecar").read_bytes(), consumer
                )
                images = self.private_python_closure()["images"]
                self.assertEqual(
                    images["sidecar/Python"]["install_name"], "@rpath/Python"
                )
                self.assertEqual(
                    images["sidecar/byo-mcp-sidecar"]["resolved_private_imports"],
                    {"@rpath/Python": "sidecar/Python"},
                )
                before_image = self.native.native_formats.macho(
                    before, self.architecture, False
                )
                after_image = self.native.native_formats.macho(
                    after, self.architecture, False
                )
                native_fields = {
                    "format": "Mach-O64",
                    "cpu": {"aarch64": 0x0100000C, "x86_64": 0x01000007}[
                        self.architecture
                    ],
                    "type": 6,
                    "minimum_os": MACOS_12,
                    "needed": ["/usr/lib/libSystem.B.dylib", "/usr/lib/libc++.1.dylib"],
                    "search_paths": ["@loader_path"],
                }
                self.assertEqual(
                    before_image,
                    {**native_fields, "install_name": "/fixture/build/Python"},
                )
                self.assertEqual(
                    after_image, {**native_fields, "install_name": "@rpath/Python"}
                )
                self.assertEqual(
                    receipt["transformations"][-1],
                    {
                        "path": "sidecar/Python",
                        "before_sha256": sha256(before),
                        "normalized_sha256": sha256(edited),
                        "after_sha256": sha256(after),
                        "before_install_name": "/fixture/build/Python",
                        "after_install_name": "@rpath/Python",
                        "before_image": before_image,
                        "after_image": after_image,
                        "adhoc_integrity": "verified",
                    },
                )
                install_tool = self.compiler.parent / "install_name_tool"
                codesign = self.compiler.parent / "codesign"
                for name, path in (
                    ("install_name_tool", install_tool),
                    ("codesign", codesign),
                ):
                    self.assertEqual(
                        receipt["tools"][name],
                        {"path": str(path), "sha256": sha256(path.read_bytes())},
                    )
                expected = [
                    [str(codesign), "--display", "--verbose=4", str(python)],
                    [str(codesign), "--verify", "--strict", "--verbose=2", str(python)],
                    [str(install_tool), "-id", "@rpath/Python", str(python)],
                    [
                        str(codesign),
                        "--force",
                        "--sign",
                        "-",
                        "--preserve-metadata=identifier,entitlements,flags",
                        "--timestamp=none",
                        str(python),
                    ],
                    [str(codesign), "--verify", "--strict", "--verbose=2", str(python)],
                ]
                self.assertEqual(self.calls, expected)
                commands = receipt["commands"][start:]
                self.assertEqual([c["argv"] for c in commands], expected)
                self.assertEqual(
                    [c["step"] for c in commands],
                    [
                        "inspect-private-dylib-signature",
                        "verify-private-dylib-before-normalization",
                        "normalize-private-dylib-identity",
                        "repair-private-dylib-adhoc-integrity",
                        "verify-private-dylib-after-normalization",
                    ],
                )
                self.assertEqual([c["exit_code"] for c in commands], [0] * 5)
                self.assertEqual([c["stdout"] for c in commands], [""] * 5)
                self.assertEqual(
                    [c["stderr"] for c in commands], ["Signature=adhoc\n"] + [""] * 4
                )
                self.assertEqual(
                    json.loads((self.evidence / "cppcheck-build.json").read_text()),
                    receipt,
                )

    def sidecar_executable_image(self, *rpaths: str, **changes) -> bytes:
        fields = {
            "loads": ("/usr/lib/libSystem.B.dylib", "@rpath/Python"),
            "rpaths": rpaths,
        }
        fields.update(changes)
        return macho_image(self.architecture, **fields)

    def test_thin_private_executable_origin_rpath_and_integrity_receipts(self):
        for target in MACOS_TARGETS:
            with self.subTest(target):
                receipt = self.stage(target)
                python = self.add_private_python(
                    self.private_python_image(install_name="@rpath/Python")
                )
                retained_python = python.read_bytes()
                sidecar = python.parent / "byo-mcp-sidecar"
                before = self.sidecar_executable_image("$ORIGIN")
                edited = self.sidecar_executable_image("@loader_path")
                after = edited + b"fixture adhoc integrity"
                sidecar.write_bytes(before)
                with self.assertRaisesRegex(
                    RuntimeError,
                    r"host/cwd search: sidecar/byo-mcp-sidecar: \$ORIGIN$",
                ):
                    self.private_python_closure()
                self.calls.clear()
                start = len(receipt["commands"])
                self.normalize_private_python(receipt, edited)
                self.assertEqual(sidecar.read_bytes(), after)
                self.assertEqual(python.read_bytes(), retained_python)
                images = self.private_python_closure()["images"]
                self.assertEqual(
                    images["sidecar/byo-mcp-sidecar"]["resolved_private_imports"],
                    {"@rpath/Python": "sidecar/Python"},
                )
                before_image = self.native.native_formats.macho(
                    before, self.architecture, True
                )
                after_image = self.native.native_formats.macho(
                    after, self.architecture, True
                )
                self.assertEqual(before_image["search_paths"], ["$ORIGIN"])
                self.assertEqual(
                    after_image, {**before_image, "search_paths": ["@loader_path"]}
                )
                self.assertEqual(
                    receipt["transformations"][-1],
                    {
                        "path": "sidecar/byo-mcp-sidecar",
                        "before_sha256": sha256(before),
                        "normalized_sha256": sha256(edited),
                        "after_sha256": sha256(after),
                        "before_search_paths": ["$ORIGIN"],
                        "after_search_paths": ["@loader_path"],
                        "before_image": before_image,
                        "after_image": after_image,
                        "adhoc_integrity": "verified",
                    },
                )
                install_tool = self.compiler.parent / "install_name_tool"
                codesign = self.compiler.parent / "codesign"
                expected = [
                    [str(codesign), "--display", "--verbose=4", str(sidecar)],
                    [
                        str(codesign),
                        "--verify",
                        "--strict",
                        "--verbose=2",
                        str(sidecar),
                    ],
                    [
                        str(install_tool),
                        "-rpath",
                        "$ORIGIN",
                        "@loader_path",
                        str(sidecar),
                    ],
                    [
                        str(codesign),
                        "--force",
                        "--sign",
                        "-",
                        "--preserve-metadata=identifier,entitlements,flags",
                        "--timestamp=none",
                        str(sidecar),
                    ],
                    [
                        str(codesign),
                        "--verify",
                        "--strict",
                        "--verbose=2",
                        str(sidecar),
                    ],
                ]
                self.assertEqual(self.calls, expected)
                commands = receipt["commands"][start:]
                self.assertEqual([c["argv"] for c in commands], expected)
                self.assertEqual(
                    [c["step"] for c in commands],
                    [
                        "inspect-private-executable-signature",
                        "verify-private-executable-before-normalization",
                        "normalize-private-executable-rpath",
                        "repair-private-executable-adhoc-integrity",
                        "verify-private-executable-after-normalization",
                    ],
                )
                self.assertEqual(
                    json.loads((self.evidence / "cppcheck-build.json").read_text()),
                    receipt,
                )


    WHEEL_DYLIB = (
        "sidecar/cmsis_pack_manager/cmsis_pack_manager/libcmsis_pack_manager.dylib"
    )
    WHEEL_HOST_ID = "/fixture/build/target/release/deps/libcmsis_pack_manager.dylib"

    def wheel_dylib_image(self, install_name: str, **changes) -> bytes:
        fields = {
            "executable": False,
            "install_name": install_name,
            "loads": ("/usr/lib/libSystem.B.dylib",),
        }
        fields.update(changes)
        return macho_image(self.architecture, **fields)

    def add_wheel_dylib(self, data: bytes) -> Path:
        path = self.bundle / self.WHEEL_DYLIB
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def wheel_dylib_closure(self) -> dict:
        return self.native.native_formats.validate_bundle_closure(
            [
                {"path": "sidecar/Python", "executable": False},
                {"path": self.WHEEL_DYLIB, "executable": False},
                {"path": "sidecar/byo-mcp-sidecar", "executable": True},
            ],
            lambda name: (self.bundle / name).read_bytes(),
            "macos",
            self.architecture,
        )

    def test_thin_private_wheel_dylib_identity_and_integrity_receipts(self):
        for target in MACOS_TARGETS:
            with self.subTest(target):
                receipt = self.stage(target)
                python = self.add_private_python(
                    self.private_python_image(install_name="@rpath/Python")
                )
                retained_python = python.read_bytes()
                consumer = (python.parent / "byo-mcp-sidecar").read_bytes()
                before = self.wheel_dylib_image(self.WHEEL_HOST_ID)
                edited = self.wheel_dylib_image("@rpath/libcmsis_pack_manager.dylib")
                after = edited + b"fixture adhoc integrity"
                dylib = self.add_wheel_dylib(before)
                with self.assertRaisesRegex(
                    RuntimeError,
                    f"absolute/unportable install name: {self.WHEEL_DYLIB}$",
                ):
                    self.wheel_dylib_closure()
                self.calls.clear()
                start = len(receipt["commands"])
                self.normalize_private_python(receipt, edited)
                self.assertEqual(dylib.read_bytes(), after)
                self.assertEqual(python.read_bytes(), retained_python)
                self.assertEqual(
                    (python.parent / "byo-mcp-sidecar").read_bytes(), consumer
                )
                self.wheel_dylib_closure()
                before_image = self.native.native_formats.macho(
                    before, self.architecture, False
                )
                after_image = self.native.native_formats.macho(
                    after, self.architecture, False
                )
                self.assertEqual(
                    after_image,
                    {
                        **before_image,
                        "install_name": "@rpath/libcmsis_pack_manager.dylib",
                    },
                )
                self.assertEqual(
                    receipt["transformations"][-1],
                    {
                        "path": self.WHEEL_DYLIB,
                        "before_sha256": sha256(before),
                        "normalized_sha256": sha256(edited),
                        "after_sha256": sha256(after),
                        "before_install_name": self.WHEEL_HOST_ID,
                        "after_install_name": "@rpath/libcmsis_pack_manager.dylib",
                        "before_image": before_image,
                        "after_image": after_image,
                        "adhoc_integrity": "verified",
                    },
                )
                install_tool = self.compiler.parent / "install_name_tool"
                codesign = self.compiler.parent / "codesign"
                expected = [
                    [str(codesign), "--display", "--verbose=4", str(dylib)],
                    [str(codesign), "--verify", "--strict", "--verbose=2", str(dylib)],
                    [
                        str(install_tool),
                        "-id",
                        "@rpath/libcmsis_pack_manager.dylib",
                        str(dylib),
                    ],
                    [
                        str(codesign),
                        "--force",
                        "--sign",
                        "-",
                        "--preserve-metadata=identifier,entitlements,flags",
                        "--timestamp=none",
                        str(dylib),
                    ],
                    [str(codesign), "--verify", "--strict", "--verbose=2", str(dylib)],
                ]
                self.assertEqual(self.calls, expected)
                commands = receipt["commands"][start:]
                self.assertEqual([c["argv"] for c in commands], expected)
                self.assertEqual(
                    [c["step"] for c in commands],
                    [
                        "inspect-private-dylib-signature",
                        "verify-private-dylib-before-normalization",
                        "normalize-private-dylib-identity",
                        "repair-private-dylib-adhoc-integrity",
                        "verify-private-dylib-after-normalization",
                    ],
                )
                self.assertEqual(
                    json.loads((self.evidence / "cppcheck-build.json").read_text()),
                    receipt,
                )


    def test_both_targets_stage_past_lipo_identity_and_thin_with_it(self) -> None:
        identity = {"path": str(self.lipo), "sha256": sha256(self.lipo.read_bytes())}
        for target in MACOS_TARGETS:
            with self.subTest(target):
                self.calls.clear()
                receipt = self.stage(target)
                slice_name = LIPO_SLICES[self.architecture]
                clangd = self.bundle / "analysis/clangd/bin/clangd"
                self.assertEqual(receipt["tools"]["lipo"], identity)
                recorded = json.loads(
                    (self.evidence / "cppcheck-build.json").read_text()
                )
                self.assertEqual(recorded["tools"]["lipo"], identity)
                self.assertEqual(
                    [c["exit_code"] for c in recorded["commands"]],
                    [0] * len(recorded["commands"]),
                )
                # Identification continues to the compiler, make and locked recipe.
                self.assertIn([str(self.compiler), "--version"], self.calls)
                self.assertIn([str(self.make), "--version"], self.calls)
                configure = [argv for argv in self.calls if "-B" in argv]
                self.assertEqual(len(configure), 1)
                self.assertIn(f"-DCMAKE_OSX_ARCHITECTURES={slice_name}", configure[0])
                # lipo is invoked only to thin clangd, via the measured path.
                self.assertEqual(
                    [argv for argv in self.calls if argv[0] == str(self.lipo)],
                    [
                        [
                            str(self.lipo),
                            str(clangd),
                            "-thin",
                            slice_name,
                            "-output",
                            str(clangd.with_name("clangd.thin")),
                        ]
                    ],
                )
                self.assertEqual(clangd.read_bytes(), self.slices[slice_name])
                self.assertIn(
                    {
                        "path": "analysis/clangd/bin/clangd",
                        "before_sha256": sha256(fat_image(self.slices)),
                        "after_sha256": sha256(self.slices[slice_name]),
                    },
                    receipt["transformations"],
                )
                self.assertEqual(
                    receipt["native_closure_before_strip"]["architecture"],
                    self.architecture,
                )
                # Later dependency thinning uses the same retained identity.
                dependency = self.bundle / "python/fixture.so"
                dependency.parent.mkdir(parents=True)
                dependency.write_bytes(fat_image(self.slices))
                self.calls.clear()
                self.thin_bundle(receipt)
                self.assertEqual(
                    self.calls,
                    [
                        [
                            identity["path"],
                            str(dependency),
                            "-thin",
                            slice_name,
                            "-output",
                            f"{dependency}.byo-thin",
                        ]
                    ],
                )
                self.assertEqual(dependency.read_bytes(), self.slices[slice_name])
                self.assertEqual(
                    receipt["transformations"][-1],
                    {
                        "path": "python/fixture.so",
                        "before_sha256": sha256(fat_image(self.slices)),
                        "after_sha256": sha256(self.slices[slice_name]),
                    },
                )

    def test_unsupported_lipo_flags_and_thinning_errors_remain_failures(self) -> None:
        # Fixture control: the observed Apple rejection still fails a command.
        receipt = {"commands": []}
        evidence = self.root / "control"
        with (
            mock.patch.object(
                self.native.subprocess, "run", side_effect=self.apple_host
            ),
            self.assertRaisesRegex(RuntimeError, r"apple-lipo-version failed \(1\)"),
        ):
            self.native._command(
                [str(self.lipo), "-version"], evidence, receipt, "apple-lipo-version"
            )
        self.assertEqual(receipt["commands"][-1]["exit_code"], 1)
        self.assertIn("unknown flag: -version", receipt["commands"][-1]["stderr"])
        full = dict(self.slices)
        for target in MACOS_TARGETS:
            slice_name = LIPO_SLICES[TARGETS[target][1]]
            partial = {k: v for k, v in full.items() if k != slice_name}
            with self.subTest(target, step="thin-clangd"):
                self.slices = partial
                with self.assertRaisesRegex(
                    RuntimeError, r"Native analyzer thin-clangd failed \(1\)"
                ):
                    self.stage(target)
                recorded = json.loads(
                    (self.evidence / "cppcheck-build.json").read_text()
                )
                self.assertEqual(recorded["tools"]["lipo"]["path"], str(self.lipo))
                failed = recorded["commands"][-1]
                self.assertEqual(
                    (failed["argv"][0], failed["exit_code"]), (str(self.lipo), 1)
                )
                self.assertIn(
                    "does not contain the specified architecture", failed["stderr"]
                )
                self.assertEqual(
                    (self.bundle / "analysis/clangd/bin/clangd").read_bytes(),
                    fat_image(partial),
                )
                self.assertFalse((self.bundle / "analysis/runtime.json").exists())
            with self.subTest(target, step="thin-native-dependency"):
                self.slices = full
                receipt = self.stage(target)
                self.slices = partial
                dependency = self.bundle / "python/fixture.so"
                dependency.parent.mkdir(parents=True)
                dependency.write_bytes(fat_image(full))
                with self.assertRaisesRegex(
                    RuntimeError, r"Native analyzer thin-native-dependency failed \(1\)"
                ):
                    self.thin_bundle(receipt)
                failed = receipt["commands"][-1]
                self.assertEqual(
                    (failed["argv"][0], failed["exit_code"]), (str(self.lipo), 1)
                )
                self.assertEqual(dependency.read_bytes(), fat_image(full))


class LinuxSidecarZlibBundleClosureTests(unittest.TestCase):
    """Delivered-bundle closure for the Nuitka sidecar ``libz.so.1`` import.

    Linux bundle run 38108880368 rejected ``sidecar/binascii.so: libz.so.1``;
    its sidecar binaries were not uploaded. Pinned Nuitka 2.8.9 omits
    ``libz.so*`` from Linux standalone output and gives copied ELF images
    DT_RPATH ``$ORIGIN``. These synthetic images model that shape through the
    byte parser only; they are not measured sidecar bytes or loader evidence.
    """

    BINASCII = "sidecar/binascii.so"
    ZLIB_ERROR = (
        "Unresolved or ambiguous private native import: sidecar/binascii.so: libz.so.1"
    )

    def images(self, binascii=None, zlib=None, **extra) -> dict[str, bytes]:
        module = dict(
            executable=False,
            needed=("libz.so.1", "libc.so.6"),
            rpath="$ORIGIN",
            versions=(("libz.so.1", "ZLIB_1.2.0"), ("libc.so.6", "GLIBC_2.2.5")),
        )
        module.update(binascii or {})
        library = dict(
            executable=False,
            soname="libz.so.1",
            needed=("libc.so.6",),
            versions=(("libc.so.6", "GLIBC_2.14"),),
            defined=("libz.so.1", "ZLIB_1.2.0"),
        )
        library.update(zlib or {})
        images = {
            "sidecar/byo-mcp-sidecar": elf_image(rpath="$ORIGIN"),
            self.BINASCII: elf_image(**module),
            "sidecar/libz.so.1": elf_image(**library),
        }
        images.update(extra)
        return {path: data for path, data in images.items() if data is not None}

    def validate(self, images: dict[str, bytes]) -> dict:
        import native_formats

        files = [
            {"path": path, "executable": path == "sidecar/byo-mcp-sidecar"}
            for path in images
        ]
        return native_formats.validate_bundle_closure(
            files, images.__getitem__, "linux", "x86_64"
        )

    def test_zlib_import_needs_a_loader_selected_private_copy(self) -> None:
        for label, binascii in {
            "DT_RPATH": {},
            "DT_RUNPATH": {"rpath": None, "runpath": "$ORIGIN"},
        }.items():
            with self.subTest(label):
                result = self.validate(self.images(binascii))
                self.assertEqual(
                    result["images"][self.BINASCII]["resolved_private_imports"],
                    {"libz.so.1": "sidecar/libz.so.1"},
                )
        # The failed Actions shape: no private copy means no OS/host fallback.
        with self.assertRaisesRegex(RuntimeError, re.escape(self.ZLIB_ERROR)):
            self.validate(self.images(**{"sidecar/libz.so.1": None}))
        with self.assertRaisesRegex(RuntimeError, re.escape(self.ZLIB_ERROR)):
            self.validate(
                self.images(
                    **{
                        "sidecar/libz.so.1": None,
                        "sidecar/zlib/libz.so.1": self.images()["sidecar/libz.so.1"],
                    }
                )
            )


class MacOSSidecarLibffiBundleClosureTests(unittest.TestCase):
    """Delivered-bundle closure for the sidecar CFFI ``/usr/lib/libffi.dylib`` import.

    macOS ARM bundle run 38118455116 rejected ``sidecar/_cffi_backend.so:
    /usr/lib/libffi.dylib``; Apple's libffi project installs into ``/usr/lib``.
    The synthetic MH_BUNDLE models that import shape through the byte parser
    only; it is not measured sidecar bytes or loader evidence.
    """

    CFFI = "sidecar/_cffi_backend.so"
    LIBFFI = "/usr/lib/libffi.dylib"

    def test_bundle_allows_exact_os_libffi_but_analyzers_do_not(self) -> None:
        import native_formats

        for architecture in ("aarch64", "x86_64"):

            def bundle(name, architecture=architecture):
                image = macho_image(
                    architecture,
                    executable=False,
                    filetype=8,
                    loads=(name, "/usr/lib/libSystem.B.dylib"),
                )
                return native_formats.validate_bundle_closure(
                    [{"path": self.CFFI, "executable": False}],
                    {self.CFFI: image}.__getitem__,
                    "macos",
                    architecture,
                )

            with self.subTest(architecture, case="exact OS libffi"):
                info = bundle(self.LIBFFI)["images"][self.CFFI]
                self.assertIn(self.LIBFFI, info["needed"])
                self.assertEqual(info["resolved_private_imports"], {})
            for name in (
                "/opt/homebrew/opt/libffi/lib/libffi.8.dylib",
                "/usr/local/opt/libffi/lib/libffi.8.dylib",
                "/usr/local/lib/libffi.dylib",
                "/usr/lib/libffi.8.dylib",
                "/usr/lib/../local/lib/libffi.dylib",
            ):
                with (
                    self.subTest(architecture, case=name),
                    self.assertRaisesRegex(
                        RuntimeError,
                        re.escape(
                            f"Unresolved non-OS Mach-O import: {self.CFFI}: {name}"
                        ),
                    ),
                ):
                    bundle(name)
            # Analyzer closure keeps its narrower OS policy for the same import.
            with (
                self.subTest(architecture, case="analyzer refusal"),
                self.assertRaisesRegex(
                    RuntimeError,
                    re.escape(
                        f"Non-OS absolute/unresolved Mach-O import: {self.LIBFFI}"
                    ),
                ),
            ):
                native_formats.validate_closure(
                    macos_closure_lock(architecture),
                    MacOSClosureTests.images(
                        self,
                        architecture,
                        cppcheck={"loads": ("/usr/lib/libSystem.B.dylib", self.LIBFFI)},
                    ).__getitem__,
                )


class MacOSSidecarAppKitBundleClosureTests(unittest.TestCase):
    """Delivered-bundle closure for the sidecar hidapi AppKit framework import.

    The locked hidapi 0.15.0 macOS wheels' ``hid.cpython-312-darwin.so`` (arm64
    and x86_64) import ``/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit``
    and the sidecar bundles ``hid``. The synthetic MH_BUNDLE models that import
    shape through the byte parser only; it is not measured sidecar bytes or
    loader evidence.
    """

    HID = "sidecar/hid.cpython-312-darwin.so"
    APPKIT = "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit"

    def test_bundle_allows_exact_os_appkit_but_analyzers_do_not(self) -> None:
        import native_formats

        for architecture in ("aarch64", "x86_64"):

            def bundle(name, architecture=architecture):
                image = macho_image(
                    architecture,
                    executable=False,
                    filetype=8,
                    loads=(
                        "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit",
                        "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
                        name,
                        "/usr/lib/libSystem.B.dylib",
                    ),
                )
                return native_formats.validate_bundle_closure(
                    [{"path": self.HID, "executable": False}],
                    {self.HID: image}.__getitem__,
                    "macos",
                    architecture,
                )

            with self.subTest(architecture, case="exact OS AppKit"):
                info = bundle(self.APPKIT)["images"][self.HID]
                self.assertIn(self.APPKIT, info["needed"])
                self.assertEqual(info["resolved_private_imports"], {})
            for name in (
                "/System/Library/Frameworks/AppKit.framework/AppKit",
                "/System/Library/Frameworks/AppKit.framework/Versions/A/AppKit",
                "/Library/Frameworks/AppKit.framework/Versions/C/AppKit",
                "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa",
                "/System/Library/Frameworks/../../../usr/local/lib/AppKit",
            ):
                with (
                    self.subTest(architecture, case=name),
                    self.assertRaisesRegex(
                        RuntimeError,
                        re.escape(
                            f"Unresolved non-OS Mach-O import: {self.HID}: {name}"
                        ),
                    ),
                ):
                    bundle(name)
            # Analyzer closure keeps its narrower OS policy for the same import.
            with (
                self.subTest(architecture, case="analyzer refusal"),
                self.assertRaisesRegex(
                    RuntimeError,
                    re.escape(
                        f"Non-OS absolute/unresolved Mach-O import: {self.APPKIT}"
                    ),
                ),
            ):
                native_formats.validate_closure(
                    macos_closure_lock(architecture),
                    MacOSClosureTests.images(
                        self,
                        architecture,
                        cppcheck={"loads": ("/usr/lib/libSystem.B.dylib", self.APPKIT)},
                    ).__getitem__,
                )


@unittest.skipUnless(os.name == "posix", "mocked Linux zlib RPM paths; Actions only")
class LinuxSidecarZlibStagingTests(unittest.TestCase):
    """Mock loader/RPM measurements; parse fixture ELF, never execute it.

    Requires the owner's stage_linux_sidecar_zlib addition. The earlier
    closure controls alone pass without that addition; this staging path
    discriminates the missing private dependency and records its ownership.
    """

    def setUp(self) -> None:
        import build_release

        self.br = build_release
        self.prepare_fixture()

    def prepare_fixture(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="byo-zlib-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        self.bundle, self.evidence = root / "bundle", root / "evidence"
        images = LinuxSidecarZlibBundleClosureTests().images()
        self.library_bytes = images.pop("sidecar/libz.so.1")
        for relative, data in images.items():
            path = self.bundle / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o755 if relative.endswith("byo-mcp-sidecar") else 0o644)
        self.consumer = self.bundle / "sidecar/binascii.so"
        self.source = root / "libz.so.1.2.11"
        self.source.write_bytes(self.library_bytes)
        selected = root / "libz.so.1"
        selected.symlink_to(self.source)
        self.notice = root / "LICENSE"
        self.notice.write_bytes(b"fixture zlib license notice, not upstream evidence\n")
        self.tools = {}
        for name in ("ldd", "rpm"):
            tool = root / name
            tool.write_bytes(f"fixture {name}; never executed".encode())
            self.tools[name] = tool
        self.ldd_output = (
            "\tlinux-vdso.so.1 (0x00007fff)\n"
            f"\tlibz.so.1 => {selected} (0x00007fff)\n"
            "\tlibc.so.6 => /lib64/libc.so.6 (0x00007fff)\n"
        )
        self.rpm_header = [
            "zlib",
            "1.2.11",
            "25.el8",
            "x86_64",
            "zlib-1.2.11-25.el8.src.rpm",
            "zlib",
            "8",
        ]
        self.rpm_rows = [
            [str(self.source), sha256(self.library_bytes), ""],
            [str(self.notice), sha256(self.notice.read_bytes()), "l"],
        ]
        self.failed_tool = None
        self.measurements = []

    def measure(self, argv, **kwargs):
        name = next(name for name, path in self.tools.items() if str(path) == argv[0])
        self.assertEqual(kwargs["cwd"], self.bundle / "sidecar")
        self.assertFalse(any(key.startswith("LD_") for key in kwargs["env"]))
        self.assertEqual(kwargs["env"]["LC_ALL"], "C")
        self.assertEqual(kwargs["env"]["BYO_ZLIB_FIXTURE"], "retained")
        self.assertTrue(kwargs["capture_output"])
        self.assertTrue(kwargs["text"])
        self.assertFalse(kwargs["check"])
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        if name == "ldd":
            self.assertEqual(argv[1:], [str(self.consumer)])
            output = self.ldd_output
        else:
            self.assertEqual(argv[1:3], ["-qf", "--qf"])
            self.assertEqual(argv[-1], str(self.source))
            output = (
                "\n".join("\t".join(row) for row in [self.rpm_header, *self.rpm_rows])
                + "\n"
            )
        result = subprocess.CompletedProcess(
            argv, 1 if self.failed_tool == name else 0, output, f"fixture {name} stderr"
        )
        self.measurements.append(result)
        return result

    def stage(self) -> dict:
        with (
            mock.patch.object(self.br.platform, "system", return_value="Linux"),
            mock.patch.object(
                self.br.shutil, "which", side_effect=lambda name: str(self.tools[name])
            ),
            mock.patch.object(self.br.subprocess, "run", side_effect=self.measure),
            mock.patch.dict(
                os.environ,
                {
                    "LD_LIBRARY_PATH": "/untrusted",
                    "LD_PRELOAD": "untrusted.so",
                    "LD_AUDIT": "audit.so",
                    "LC_ALL": "untrusted",
                    "BYO_ZLIB_FIXTURE": "retained",
                },
            ),
        ):
            return self.br.stage_linux_sidecar_zlib(self.bundle, self.evidence)

    def test_staging_restores_private_closure_and_measured_inventory_sbom(self) -> None:
        import native_formats

        before = self.br.payload_inventory(self.bundle)

        def read(relative):
            return (self.bundle / relative).read_bytes()

        with self.assertRaisesRegex(
            RuntimeError, "Unresolved or ambiguous private native import"
        ):
            native_formats.validate_bundle_closure(before, read, "linux", "x86_64")
        consumer_bytes = self.consumer.read_bytes()
        receipt = self.stage()
        self.assertEqual(receipt["schema"], 1)
        self.assertEqual(receipt["library"], "libz.so.1")
        self.assertEqual(receipt["required_by"], "sidecar/binascii.so")
        self.assertEqual(receipt["consumer_sha256"], sha256(consumer_bytes))
        self.assertEqual(
            receipt["consumer_native"]["needed"], ["libz.so.1", "libc.so.6"]
        )
        self.assertEqual(receipt["source_path"], str(self.source))
        self.assertEqual(receipt["source_sha256"], sha256(self.library_bytes))
        self.assertEqual(receipt["native"]["soname"], "libz.so.1")
        self.assertEqual(receipt["native"]["machine"], 62)
        self.assertEqual(receipt["package"], "zlib-1.2.11-25.el8.x86_64")
        self.assertEqual(receipt["source_rpm"], "zlib-1.2.11-25.el8.src.rpm")
        self.assertEqual(receipt["license"], "zlib")
        self.assertEqual(self.consumer.read_bytes(), consumer_bytes)
        self.assertEqual(self.source.read_bytes(), self.library_bytes)
        self.assertEqual(len(self.measurements), 2)
        for name, tool in self.tools.items():
            self.assertEqual(
                receipt["tools"][name],
                {
                    "path": str(tool),
                    "sha256": sha256(tool.read_bytes()),
                },
            )
        self.assertEqual(
            receipt["commands"],
            [
                {
                    "argv": result.args,
                    "exit_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }
                for result in self.measurements
            ],
        )
        self.assertEqual(
            json.loads((self.evidence / "linux-sidecar-zlib.json").read_bytes()),
            receipt,
        )
        files = self.br.payload_inventory(self.bundle)
        staged = [
            leaf
            for leaf in files
            if leaf["path"]
            in {
                "sidecar/libz.so.1",
                "sidecar/licenses/zlib/LICENSE",
            }
        ]
        self.assertEqual(
            sorted(receipt["files"], key=lambda leaf: leaf["path"]), staged
        )
        self.assertEqual(
            {leaf["kind"] for leaf in staged}, {"native-dependency", "license"}
        )
        self.assertTrue(all(leaf["executable"] is False for leaf in staged))
        self.assertEqual(read("sidecar/libz.so.1"), self.library_bytes)
        self.assertEqual(
            read("sidecar/licenses/zlib/LICENSE"), self.notice.read_bytes()
        )
        closure = native_formats.validate_bundle_closure(files, read, "linux", "x86_64")
        self.assertEqual(
            closure["images"]["sidecar/binascii.so"]["resolved_private_imports"],
            {"libz.so.1": "sidecar/libz.so.1"},
        )
        report = self.evidence / "report.xml"
        report.write_text(
            '<report nuitka_version="2.8.9"><python python_version="3.12.0"/><distributions/></report>'
        )
        with mock.patch.object(
            self.br, "digest", side_effect=AssertionError("SBOM rehashed payload")
        ):
            self.br.write_sbom(
                self.bundle, report, "0.1.8", files, linux_sidecar_provenance=receipt
            )
        sbom = json.loads((self.bundle / "sbom.cdx.json").read_bytes())
        components = {leaf["bom-ref"]: leaf for leaf in sbom["components"]}
        reference = "byo-native:sidecar/libz.so.1"
        zlib = components[reference]
        self.assertEqual(
            (zlib["type"], zlib["name"], zlib["version"]), ("library", "zlib", "1.2.11")
        )
        self.assertEqual(
            zlib["hashes"], [{"alg": "SHA-256", "content": sha256(self.library_bytes)}]
        )
        self.assertEqual(zlib["licenses"], [{"license": {"name": "zlib"}}])
        properties = {leaf["name"]: leaf["value"] for leaf in zlib["properties"]}
        self.assertEqual(properties["byo:linux:package"], receipt["package"])
        self.assertEqual(properties["byo:linux:source-rpm"], receipt["source_rpm"])
        self.assertEqual(
            properties["byo:linux:license-notice"], "sidecar/licenses/zlib/LICENSE"
        )
        notice_ref = "byo-native:sidecar/licenses/zlib/LICENSE"
        self.assertEqual(
            components[notice_ref]["hashes"],
            [
                {"alg": "SHA-256", "content": sha256(self.notice.read_bytes())},
            ],
        )
        self.assertIn(
            {"ref": reference, "dependsOn": [notice_ref]}, sbom["dependencies"]
        )


    def test_existing_destinations_and_linked_license_ancestors_are_rejected(
        self,
    ) -> None:
        for relative in ("sidecar/libz.so.1", "sidecar/licenses/zlib/LICENSE"):
            with self.subTest(relative):
                self.prepare_fixture()
                destination = self.bundle / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(b"existing private payload")
                with self.assertRaisesRegex(RuntimeError, "payload already exists"):
                    self.stage()
                self.assertEqual(destination.read_bytes(), b"existing private payload")
        for relative in ("sidecar/licenses", "sidecar/licenses/zlib"):
            with self.subTest(relative):
                self.prepare_fixture()
                outside = self.source.parent / "outside"
                outside.mkdir()
                destination = self.bundle / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.symlink_to(outside, target_is_directory=True)
                with self.assertRaisesRegex(
                    RuntimeError, "destination escapes through a link"
                ):
                    self.stage()
                self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
