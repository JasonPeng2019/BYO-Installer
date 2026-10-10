#!/usr/bin/env python3
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
MACOS_13 = 0x000D0000
GCC_NOTICES = (
    "analysis/cppcheck/licenses/GCC-COPYING3",
    "analysis/cppcheck/licenses/GCC-COPYING.RUNTIME",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Synthetic native images (parsed only, never executed)
# --------------------------------------------------------------------------


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


# --------------------------------------------------------------------------
# Native payload fixture (reduced pinned selection, synthetic bytes)
# --------------------------------------------------------------------------


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


def resource_aggregate(program: dict) -> str:
    prefix = program["source"]["archive_prefix"]
    rows = sorted(
        (
            {
                "path": leaf["upstream_path"][len(prefix) :],
                "sha256": leaf["sha256"],
                "size": leaf["size"],
            }
            for leaf in program["selected_files"]
            if leaf["kind"] == "analysis-resource"
        ),
        key=lambda row: row["path"],
    )
    return sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode())


# --------------------------------------------------------------------------
# Lock v2: exact rows, counts, sources and recipes (checked-in lock)
# --------------------------------------------------------------------------


class LockV2ContractTests(unittest.TestCase):
    def test_raw_lock_has_exactly_four_target_rows(self) -> None:
        document = raw_lock()
        self.assertEqual(set(document), {"schema_version", "targets"})
        self.assertIs(type(document["schema_version"]), int)
        self.assertEqual(document["schema_version"], 2)
        self.assertEqual(set(document["targets"]), set(TARGETS))
        self.assertEqual(len(document["targets"]), 4)
        for target, identity in TARGETS.items():
            row = document["targets"][target]
            self.assertEqual((row["platform"], row["architecture"]), identity, target)
            self.assertEqual(set(row["programs"]), {"cppcheck", "clangd"}, target)

    def test_explicit_target_selection_is_host_independent(self) -> None:
        for target, identity in TARGETS.items():
            with self.subTest(target):
                for host in TARGETS:
                    with mock.patch.object(tools, "host_target", return_value=host):
                        lock = tools.load_lock(target=target)
                    self.assertEqual((lock["platform"], lock["architecture"]), identity)
        alias = tools.load_lock(target="linux-x86_64-glibc-2.28")
        self.assertEqual(
            (alias["platform"], alias["architecture"]), ("linux", "x86_64")
        )

    def test_executable_paths_versions_and_dependencies_per_target(self) -> None:
        for target in TARGETS:
            with self.subTest(target):
                lock = tools.load_lock(target=target)
                suffix = ".exe" if target.startswith("windows") else ""
                self.assertEqual(
                    lock["programs"]["cppcheck"]["executable"],
                    f"analysis/cppcheck/cppcheck{suffix}",
                )
                self.assertEqual(
                    lock["programs"]["clangd"]["executable"],
                    f"analysis/clangd/bin/clangd{suffix}",
                )
                self.assertEqual(lock["programs"]["cppcheck"]["version"], "2.22.0")
                self.assertEqual(lock["programs"]["clangd"]["version"], "23.1.0")
                for program in lock["programs"].values():
                    self.assertEqual(program["dependencies"], [])

    def test_selection_counts_are_exact_per_target(self) -> None:
        resources = {
            "windows-x86_64": 332,
            "macos-aarch64": 335,
            "macos-x86_64": 335,
            "linux-x86_64": 338,
        }
        for target, count in resources.items():
            with self.subTest(target):
                lock = tools.load_lock(target=target)
                cppcheck = lock["programs"]["cppcheck"]["selected_files"]
                clangd = lock["programs"]["clangd"]["selected_files"]
                self.assertEqual(len(cppcheck), 70)
                self.assertEqual(
                    sum(f["runtime_path"].endswith(".cfg") for f in cppcheck), 51
                )
                self.assertEqual(
                    sum("/platforms/" in f["runtime_path"] for f in cppcheck), 15
                )
                self.assertEqual(sum(f["kind"] == "license" for f in cppcheck), 4)
                self.assertFalse(
                    any(f["kind"] == "analysis-executable" for f in cppcheck)
                )
                self.assertEqual(
                    sum(f["kind"] == "analysis-resource" for f in clangd), count
                )
                self.assertEqual(len(clangd), count + 2)
                self.assertEqual(
                    [
                        f["runtime_path"]
                        for f in clangd
                        if f["kind"] == "analysis-executable"
                    ],
                    [lock["programs"]["clangd"]["executable"]],
                )
                headers = [
                    f for f in clangd if "/lib/clang/23/include/" in f["runtime_path"]
                ]
                share = [
                    f for f in clangd if "/lib/clang/23/share/" in f["runtime_path"]
                ]
                if target != "windows-x86_64":
                    self.assertEqual(len(headers), 333)
                    self.assertEqual(len(share), 5 if target == "linux-x86_64" else 2)
                for leaf in cppcheck + clangd:
                    self.assertEqual(
                        leaf["executable"], leaf["kind"] == "analysis-executable"
                    )

    def test_native_resource_aggregates_match_contract_and_recipe(self) -> None:
        expected = {
            "linux-x86_64": "24981bae953d0733809deec24e08f379f37fe302538d8d7e00fcaafc50e60cc7",
            "macos-aarch64": "6a7350a53628fd3c0e8253b4a95ba6a986c69c37fabec4baa1d6e5d71afa299b",
            "macos-x86_64": "6a7350a53628fd3c0e8253b4a95ba6a986c69c37fabec4baa1d6e5d71afa299b",
        }
        for target, digest in expected.items():
            with self.subTest(target):
                clangd = tools.load_lock(target=target)["programs"]["clangd"]
                self.assertEqual(resource_aggregate(clangd), digest)
                self.assertEqual(clangd["recipe"]["resource_selection_sha256"], digest)

    def test_native_upstream_notices_and_executable_inputs_are_pinned(self) -> None:
        executables = {
            "linux-x86_64": (
                "5a535973dd1274270c8a0d34677fe4758d8c9aaa164aa3701602c957c42dc9e2",
                148913784,
            ),
            "macos-aarch64": (
                "23197c85e1fbe16de89666bb6d1132b36b02213906b09e12d687eda8cc3b6a57",
                177144960,
            ),
            "macos-x86_64": (
                "23197c85e1fbe16de89666bb6d1132b36b02213906b09e12d687eda8cc3b6a57",
                177144960,
            ),
        }
        for target, identity in executables.items():
            with self.subTest(target):
                clangd = tools.load_lock(target=target)["programs"]["clangd"]
                [executable] = [
                    f
                    for f in clangd["selected_files"]
                    if f["kind"] == "analysis-executable"
                ]
                [notice] = [
                    f for f in clangd["selected_files"] if f["kind"] == "license"
                ]
                self.assertEqual((executable["sha256"], executable["size"]), identity)
                self.assertEqual(
                    (notice["sha256"], notice["size"]),
                    (
                        "8d85c1057d742e597985c7d4e6320b015a9139385cff4cbae06ffc0ebe89afee",
                        15141,
                    ),
                )

    def test_sources_are_pinned_per_target(self) -> None:
        cppcheck_sha = (
            "68ed9efb7aad635b7f4c121662689b2377d1d745dc9e76227566516a9617f343"
        )
        clangd = {
            "windows-x86_64": (
                "clangd-windows-23.1.0.zip",
                "23412a240756a162e7b98a282f36aa2a23a88db5ce16a0cbc4fef7253768c810",
                None,
            ),
            "macos-aarch64": (
                "clangd-mac-23.1.0.zip",
                "1082e6638223b785ca2daf0939f13afcd0bb95c84ee9a4bbaff4745365159253",
                100060151,
            ),
            "macos-x86_64": (
                "clangd-mac-23.1.0.zip",
                "1082e6638223b785ca2daf0939f13afcd0bb95c84ee9a4bbaff4745365159253",
                100060151,
            ),
            "linux-x86_64": (
                "clangd-linux-23.1.0.zip",
                "e53b1a96196095faedb7642cf64964f7fb9ad4a0c1f00dd2c172a3d9dcbafdfd",
                117949007,
            ),
        }
        for target, (archive, digest, size) in clangd.items():
            with self.subTest(target):
                lock = tools.load_lock(target=target)
                cpp = lock["programs"]["cppcheck"]["source"]
                self.assertEqual(cpp["sha256"], cppcheck_sha)
                self.assertTrue(cpp["url"].startswith("https://codeload.github.com/"))
                source = lock["programs"]["clangd"]["source"]
                self.assertEqual(
                    (source["archive"], source["sha256"], source.get("size")),
                    (archive, digest, size),
                )
                self.assertEqual(
                    source["url"],
                    f"https://github.com/clangd/clangd/releases/download/23.1.0/{archive}",
                )

    def test_native_recipes_are_target_specific_and_static(self) -> None:
        clangd_keys = {
            "output_identity",
            "resource_selection_sha256",
            "selection",
            "transformations",
        }
        cppcheck_keys = {
            "build_argv",
            "configure_argv",
            "output",
            "output_identity",
            "upstream_compileroptions_sha256",
        }
        transformations = {
            "linux-x86_64": ["patchelf --remove-rpath"],
            "macos-aarch64": ["lipo -thin arm64"],
            "macos-x86_64": ["lipo -thin x86_64"],
        }
        for target in NATIVE_TARGETS:
            with self.subTest(target):
                lock = tools.load_lock(target=target)
                clangd = lock["programs"]["clangd"]["recipe"]
                cppcheck = lock["programs"]["cppcheck"]["recipe"]
                self.assertEqual(set(clangd), clangd_keys)
                self.assertEqual(set(cppcheck), cppcheck_keys)
                self.assertEqual(clangd["transformations"], transformations[target])
                configure = cppcheck["configure_argv"]
                for flag in (
                    "-DBUILD_SHARED_LIBS=OFF",
                    "-DBUILD_CORE_DLL=OFF",
                    "-DFILESDIR:STRING=",
                    "-DUSE_MATCHCOMPILER=Off",
                ):
                    self.assertIn(flag, configure)
                self.assertEqual(cppcheck["output"], "bin/cppcheck")
                if target == "linux-x86_64":
                    self.assertIn(
                        "-DCMAKE_EXE_LINKER_FLAGS=-static-libstdc++ -static-libgcc",
                        configure,
                    )
                    self.assertFalse(any("OSX" in part for part in configure))
                else:
                    arch = "arm64" if target == "macos-aarch64" else "x86_64"
                    self.assertIn("-DCMAKE_OSX_DEPLOYMENT_TARGET=12.0", configure)
                    self.assertIn(f"-DCMAKE_OSX_ARCHITECTURES={arch}", configure)
        self.assertIsNone(
            tools.load_lock(target="windows-x86_64")["programs"]["clangd"].get("recipe")
        )

    def test_only_linux_cppcheck_declares_gcc_runtime_notices(self) -> None:
        for target in TARGETS:
            with self.subTest(target):
                lock = tools.load_lock(target=target)
                expected = list(GCC_NOTICES) if target == "linux-x86_64" else None
                self.assertEqual(
                    lock["programs"]["cppcheck"].get("additional_licenses"), expected
                )
                self.assertIsNone(lock["programs"]["clangd"].get("additional_licenses"))
                self.assertEqual(target == "windows-x86_64", "windows_native" in lock)


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

    def test_closed_target_set_and_schema_version_type(self) -> None:
        base = raw_lock()
        cases = []
        for value in (True, 1, 2.0, "2", 3):
            document = copy.deepcopy(base)
            document["schema_version"] = value
            cases.append((f"schema {value!r}", document))
        missing = copy.deepcopy(base)
        del missing["targets"]["macos-x86_64"]
        cases.append(("missing row", missing))
        extra = copy.deepcopy(base)
        extra["targets"]["linux-aarch64"] = copy.deepcopy(
            extra["targets"]["linux-x86_64"]
        )
        cases.append(("fifth row", extra))
        alias = copy.deepcopy(base)
        alias["targets"]["linux-x86_64-glibc-2.28"] = alias["targets"].pop(
            "linux-x86_64"
        )
        cases.append(("alias key", alias))
        top = copy.deepcopy(base)
        top["platform"] = "windows"
        cases.append(("extra top-level key", top))
        for label, document in cases:
            with self.subTest(label):
                self.assert_rejected(document, "exactly the four supported targets")

    def test_v1_windows_lock_is_not_accepted(self) -> None:
        windows = raw_lock()["targets"]["windows-x86_64"]
        self.assert_rejected(
            dict(windows, schema_version=1), "exactly the four", "windows-x86_64"
        )

    def test_duplicate_json_keys_are_rejected(self) -> None:
        text = json.dumps(raw_lock())
        duplicated = text.replace(
            '"schema_version": 2', '"schema_version": 2, "schema_version": 2', 1
        )
        self.assertNotEqual(text, duplicated)
        self.assert_rejected(duplicated, "Duplicate JSON key")

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

    def test_program_identity_is_target_shaped(self) -> None:
        cases = {
            "linux exe suffix": (
                "linux-x86_64",
                "cppcheck",
                "executable",
                "analysis/cppcheck/cppcheck.exe",
            ),
            "windows no suffix": (
                "windows-x86_64",
                "clangd",
                "executable",
                "analysis/clangd/bin/clangd",
            ),
            "mac wrong layout": (
                "macos-aarch64",
                "clangd",
                "executable",
                "analysis/clangd/clangd",
            ),
            "version shape": ("macos-x86_64", "cppcheck", "version", "2.22"),
            "duplicate dependency": (
                "linux-x86_64",
                "clangd",
                "dependencies",
                ["analysis/clangd/lib/libx.so.1", "analysis/clangd/lib/libx.so.1"],
            ),
            "dependencies not list": ("linux-x86_64", "clangd", "dependencies", None),
        }
        for label, (target, program, key, value) in cases.items():
            with self.subTest(label):
                document = raw_lock()
                document["targets"][target]["programs"][program][key] = value
                self.assert_rejected(
                    document, "Invalid analysis program target/identity", target
                )

    def test_program_set_must_be_exact(self) -> None:
        document = raw_lock()
        document["targets"]["macos-aarch64"]["programs"]["clang-tidy"] = {}
        self.assert_rejected(document, "target record mismatch", "macos-aarch64")

    def test_pinned_archive_and_leaf_identity_types(self) -> None:
        def mutate_source(field, value):
            def change(program):
                program["source"][field] = value

            return change

        def mutate_leaf(field, value):
            def change(program):
                program["selected_files"][0][field] = value

            return change

        cases = {
            "uppercase sha": (
                mutate_source("sha256", "A" * 64),
                "Invalid pinned analysis archive",
            ),
            "nested archive": (
                mutate_source("archive", "dir/clangd.zip"),
                "Invalid pinned analysis archive",
            ),
            "bool size": (mutate_leaf("size", True), "Invalid pinned file identity"),
            "float size": (mutate_leaf("size", 1.0), "Invalid pinned file identity"),
            "negative size": (mutate_leaf("size", -1), "Invalid pinned file identity"),
            "string executable": (
                mutate_leaf("executable", "false"),
                "Invalid pinned file identity",
            ),
            "short leaf sha": (
                mutate_leaf("sha256", "0" * 63),
                "Invalid pinned file identity",
            ),
        }
        for label, (change, pattern) in cases.items():
            with self.subTest(label):
                document = raw_lock()
                change(document["targets"]["linux-x86_64"]["programs"]["clangd"])
                self.assert_rejected(document, pattern)

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

    def test_gcc_notice_namespace_cannot_collide(self) -> None:
        document = raw_lock()
        cppcheck = document["targets"]["linux-x86_64"]["programs"]["cppcheck"]
        cppcheck["additional_licenses"] = [
            GCC_NOTICES[0],
            GCC_NOTICES[0].upper().replace("ANALYSIS/CPPCHECK", "analysis/cppcheck"),
        ]
        self.assert_rejected(document, "Case-colliding payload namespace")


class TargetAndNamespaceTests(unittest.TestCase):
    def test_canonical_targets_and_alias(self) -> None:
        self.assertEqual(tools.TARGETS, TARGETS)
        for target in TARGETS:
            self.assertEqual(tools.canonical_target(target), target)
            self.assertEqual(vbo.expected_identity(target), TARGETS[target])
        self.assertEqual(
            tools.canonical_target("linux-x86_64-glibc-2.28"), "linux-x86_64"
        )
        self.assertEqual(
            vbo.expected_identity("linux-x86_64-glibc-2.28"), ("linux", "x86_64")
        )
        for bad in (
            "linux-aarch64",
            "windows-aarch64",
            "macos-universal",
            "Linux-x86_64",
            "",
            "linux-x86_64-glibc-2.17",
        ):
            with (
                self.subTest(bad),
                self.assertRaisesRegex(RuntimeError, "Unsupported analysis target"),
            ):
                tools.canonical_target(bad)

    def test_host_target_maps_supported_hosts_and_refuses_others(self) -> None:
        cases = {
            ("Windows", "AMD64"): "windows-x86_64",
            ("Darwin", "arm64"): "macos-aarch64",
            ("Darwin", "x86_64"): "macos-x86_64",
            ("Linux", "x86_64"): "linux-x86_64",
        }
        for (system, machine), target in cases.items():
            with (
                mock.patch.object(tools.platform, "system", return_value=system),
                mock.patch.object(tools.platform, "machine", return_value=machine),
            ):
                self.assertEqual(tools.host_target(), target)
        for system, machine in (
            ("Linux", "aarch64"),
            ("FreeBSD", "amd64"),
            ("Windows", "ARM64"),
        ):
            with (
                mock.patch.object(tools.platform, "system", return_value=system),
                mock.patch.object(tools.platform, "machine", return_value=machine),
            ):
                with self.assertRaises(RuntimeError):
                    tools.host_target()

    def test_strict_json_rejects_duplicates_and_non_objects(self) -> None:
        self.assertEqual(tools.strict_json(b'{"a": {"b": 1}}'), {"a": {"b": 1}})
        with self.assertRaisesRegex(RuntimeError, "Duplicate JSON key"):
            tools.strict_json(b'{"a": {"b": 1, "b": 2}}')
        for value in (b"[]", b"1", b'"x"'):
            with self.assertRaisesRegex(RuntimeError, "Expected a JSON object"):
                tools.strict_json(value)

    def test_safe_namespace_rejects_aliases_and_file_ancestors(self) -> None:
        tools.safe_namespace(
            [
                "analysis/clangd/bin/clangd",
                "analysis/clangd/lib/clang/23/include/stddef.h",
            ]
        )
        with self.assertRaisesRegex(RuntimeError, "Case-colliding"):
            tools.safe_namespace(["analysis/clangd/a.h", "analysis/Clangd/b.h"])
        with self.assertRaisesRegex(RuntimeError, "Case-colliding"):
            tools.safe_namespace(["analysis/x/LICENSE", "analysis/x/license"])
        with self.assertRaisesRegex(RuntimeError, "also an ancestor"):
            tools.safe_namespace(["analysis/clangd/bin", "analysis/clangd/bin/clangd"])
        for unsafe in (
            "analysis/../x",
            "analysis\\x",
            "/analysis/x",
            "analysis/x/",
            "analysis/AUX.h",
        ):
            with self.subTest(unsafe), self.assertRaises(RuntimeError):
                tools.safe_namespace([unsafe])

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
                    self.assertIsNone(tools.classification(GCC_NOTICES[0], lock))


# --------------------------------------------------------------------------
# Native image headers (parsers only)
# --------------------------------------------------------------------------


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

    def test_rejects_loader_and_table_hazards(self) -> None:
        import native_formats

        cases = {
            "musl interpreter": (
                elf_image(interpreter="/lib/ld-musl-x86_64.so.1"),
                True,
                "Unsupported Linux interpreter",
            ),
            "library as executable": (
                elf_image(executable=False),
                True,
                "shared library presented as an executable",
            ),
            "executable as library": (
                elf_image(kind=3),
                False,
                "executable presented as a private library",
            ),
            "DT_AUDIT": (
                elf_image(extra_tags=((0x6FFFFEFC, 1),)),
                True,
                "audit/filter",
            ),
            "DT_DEPAUDIT": (
                elf_image(extra_tags=((0x6FFFFEFB, 1),)),
                True,
                "audit/filter",
            ),
            "DT_FILTER": (
                elf_image(extra_tags=((0x7FFFFFFF, 1),)),
                True,
                "audit/filter",
            ),
            "DT_AUXILIARY": (
                elf_image(extra_tags=((0x7FFFFFFD, 1),)),
                True,
                "audit/filter",
            ),
            "duplicate strtab": (
                elf_image(extra_tags=((5, 0),)),
                True,
                "Duplicate singleton",
            ),
            "string outside table": (
                elf_image(extra_tags=((1, 4096),)),
                True,
                "outside its table",
            ),
        }
        for label, (data, executable, pattern) in cases.items():
            with self.subTest(label), self.assertRaisesRegex(RuntimeError, pattern):
                native_formats.elf(data, executable)
        no_headers = bytearray(elf_image())
        struct.pack_into("<H", no_headers, 56, 0)
        with self.assertRaisesRegex(RuntimeError, "program header table"):
            native_formats.elf(bytes(no_headers), True)
        unterminated = elf_image()
        unterminated = unterminated[
            : unterminated.rindex(struct.pack("<qQ", 0, 0))
        ] + struct.pack("<qQ", 0x6FFFFFF0, 0)
        with self.assertRaisesRegex(RuntimeError, "Unterminated ELF dynamic table"):
            native_formats.elf(unterminated, True)


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

    def test_rejects_minimum_os_and_loader_hazards(self) -> None:
        import native_formats

        environment = _command_with_string(
            0x27, struct.pack("<I", 12), "DYLD_INSERT_LIBRARIES=x"
        )
        cases = {
            "macOS 13": (macho_image(minima=(("build", MACOS_13),)), "above macOS 12"),
            "missing minimum": (macho_image(minima=()), "minimum OS missing"),
            "ambiguous minimum": (
                macho_image(minima=(("build", MACOS_12), ("legacy", MACOS_12))),
                "ambiguous",
            ),
            "iOS platform": (
                macho_image(minima=()) and _replace_build_platform(macho_image(), 2),
                "platform/build version",
            ),
            "custom dyld": (macho_image(dyld="/tmp/dyld"), "dynamic loader"),
            "dyld environment": (
                macho_image(extra=(environment,)),
                "undeclared loader environment",
            ),
        }
        for label, (data, pattern) in cases.items():
            with self.subTest(label), self.assertRaisesRegex(RuntimeError, pattern):
                native_formats.macho(data, "aarch64", True)
        truncated = bytearray(macho_image())
        struct.pack_into("<I", truncated, 20, len(truncated))
        with self.assertRaisesRegex(
            RuntimeError, "Truncated Mach-O load command table"
        ):
            native_formats.macho(bytes(truncated), "aarch64", True)


def _replace_build_platform(data: bytes, platform: int) -> bytes:
    value = bytearray(data)
    marker = struct.pack("<II", 0x32, 24)
    offset = value.index(marker)
    struct.pack_into("<I", value, offset + 8, platform)
    return bytes(value)


# --------------------------------------------------------------------------
# Native import closure (static byte inspection; not baseline execution)
# --------------------------------------------------------------------------


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

    def test_glibc_floor_is_2_28(self) -> None:
        for version in ("GLIBC_2.29", "GLIBC_2.34", "GLIBC_PRIVATE", "GLIBC_3.0"):
            with (
                self.subTest(version),
                self.assertRaisesRegex(RuntimeError, "Unsupported baseline symbol"),
            ):
                self.validate(
                    self.images(cppcheck={"versions": (("libc.so.6", version),)})
                )
        self.validate(
            self.images(cppcheck={"versions": (("libc.so.6", "GLIBC_2.28.0"),)})
        )
        with self.assertRaisesRegex(RuntimeError, "no declared import"):
            self.validate(
                self.images(
                    cppcheck={"versions": (("libpthread.so.0", "GLIBC_2.2.5"),)}
                )
            )

    def test_static_runtime_libraries_cannot_be_dynamic_imports(self) -> None:
        for library in ("libstdc++.so.6", "libgcc_s.so.1", "libz.so.1"):
            with (
                self.subTest(library),
                self.assertRaisesRegex(
                    RuntimeError, "Unresolved/undeclared native import"
                ),
            ):
                self.validate(self.images(cppcheck={"needed": ("libc.so.6", library)}))

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

    def test_private_libraries_are_declared_referenced_and_named(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "Invalid private library location"):
            self.validate(
                self.images(), linux_closure_lock(("analysis/clangd/libfoo.so.1",))
            )
        with self.assertRaisesRegex(RuntimeError, "Invalid private library location"):
            self.validate(
                self.images(),
                linux_closure_lock(("analysis/cppcheck/lib/libfoo.so.1",)),
            )
        unreferenced = self.images(
            exe={"needed": ("libc.so.6",), "versions": (), "runpath": "$ORIGIN/../lib"}
        )
        with self.assertRaisesRegex(
            RuntimeError, "Unreferenced private native dependencies"
        ):
            self.validate(unreferenced)
        with self.assertRaisesRegex(RuntimeError, "SONAME differs"):
            self.validate(self.images(lib={"soname": "libbar.so.1"}))
        with self.assertRaisesRegex(
            RuntimeError, "Unresolved private ELF symbol version"
        ):
            self.validate(self.images(exe={"versions": (("libfoo.so.1", "FOO_2"),)}))
        with self.assertRaisesRegex(RuntimeError, "Absolute/relative ELF import"):
            self.validate(
                self.images(cppcheck={"needed": ("/lib64/libc.so.6",), "versions": ()})
            )
        with self.assertRaisesRegex(RuntimeError, "private library"):
            self.validate(self.images(lib={"interpreter": INTERPRETER, "kind": 3}))


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

    def test_non_os_absolute_and_executable_relative_imports_fail(self) -> None:
        for name in (
            "/opt/homebrew/lib/libzstd.1.dylib",
            "/usr/local/lib/libfoo.dylib",
            "@executable_path/../lib/libfoo.dylib",
            "@rpath/sub/libfoo.dylib",
        ):
            with (
                self.subTest(name),
                self.assertRaisesRegex(
                    RuntimeError, "absolute/unresolved Mach-O import"
                ),
            ):
                self.validate(
                    self.images(
                        cppcheck={"loads": ("/usr/lib/libSystem.B.dylib", name)}
                    )
                )

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


# --------------------------------------------------------------------------
# Final payload: SBOM, recipe, GCC runtime provenance, modes and strip checks
# --------------------------------------------------------------------------


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

    def test_recipes_are_bound_in_the_sbom(self) -> None:
        for target in NATIVE_TARGETS:
            for program, pattern in (
                ("clangd", "clangd SBOM recipe"),
                ("cppcheck", "Cppcheck SBOM recipe"),
            ):
                with self.subTest(target=target, program=program):
                    lock, data, files, sbom = native_fixture(target)
                    application = next(
                        c
                        for c in sbom["components"]
                        if c["bom-ref"] == f"byo-analysis:{program}"
                    )
                    for item in application["properties"]:
                        if item["name"] == "byo:analysis:recipe":
                            recipe = json.loads(item["value"])
                            if program == "clangd":
                                recipe["transformations"] = []
                            else:
                                recipe["configure_argv"] = recipe["configure_argv"][:-1]
                            item["value"] = json.dumps(recipe, sort_keys=True)
                    with self.assertRaisesRegex(RuntimeError, pattern):
                        tools.validate_analysis(files, data.__getitem__, sbom, lock)

    def test_selected_resource_bytes_are_exact(self) -> None:
        for target in NATIVE_TARGETS:
            with self.subTest(target):
                lock, data, files, sbom = native_fixture(target)
                header = next(p for p in data if p.endswith("/include/stddef.h"))
                data[header] += b"changed"
                with self.assertRaisesRegex(
                    RuntimeError, "Pinned upstream bytes changed"
                ):
                    tools.validate_analysis(files, data.__getitem__, sbom, lock)

    def test_closure_runs_on_final_native_bytes(self) -> None:
        cases = {
            "linux-x86_64": elf_image(needed=("libc.so.6", "libstdc++.so.6")),
            "macos-aarch64": macho_image(
                "aarch64", loads=("/opt/homebrew/lib/libzstd.1.dylib",)
            ),
            "macos-x86_64": macho_image("aarch64"),
        }
        for target, executable in cases.items():
            with self.subTest(target):
                lock, data, files, sbom = native_fixture(
                    target, executables={"cppcheck": executable}
                )
                with self.assertRaises(RuntimeError):
                    tools.validate_analysis(files, data.__getitem__, sbom, lock)

    def test_linux_gcc_runtime_provenance_is_required_and_exact(self) -> None:
        with self.assertRaisesRegex(
            RuntimeError, "measured GCC static runtime provenance"
        ):
            native_fixture("linux-x86_64", runtime={})
        lock, data, files, sbom = native_fixture("linux-x86_64")
        removed = copy.deepcopy(sbom)
        removed["components"] = [
            c
            for c in removed["components"]
            if c["bom-ref"] != "byo-analysis:cppcheck:gcc-runtime"
        ]
        with self.assertRaisesRegex(RuntimeError, "GCC static runtime SBOM ownership"):
            tools.validate_analysis(files, data.__getitem__, removed, lock)
        libraries = static_runtime()["libraries"]
        notices = static_runtime()["notices"]
        bad_runtimes = {
            "missing libgcc.a": static_runtime(
                libraries={"libstdc++.a": libraries["libstdc++.a"]}
            ),
            "unknown library": static_runtime(
                libraries=dict(libraries, **{"libz.a": libraries["libgcc.a"]})
            ),
            "compiler not hex": static_runtime(compiler_sha256="not-a-digest"),
            "empty package": static_runtime(package=""),
            "empty source": static_runtime(source=""),
            "extra key": dict(static_runtime(), schema_version=1),
            "missing notice": static_runtime(
                notices={GCC_NOTICES[0]: notices[GCC_NOTICES[0]]}
            ),
            "library size bool": static_runtime(
                libraries=dict(
                    libraries, **{"libgcc.a": {"sha256": "0" * 64, "size": True}}
                )
            ),
            "library zero size": static_runtime(
                libraries=dict(
                    libraries, **{"libgcc.a": {"sha256": "0" * 64, "size": 0}}
                )
            ),
            "library extra field": static_runtime(
                libraries=dict(
                    libraries,
                    **{"libgcc.a": dict(libraries["libgcc.a"], path="/usr/lib")},
                )
            ),
        }
        for label, runtime in bad_runtimes.items():
            with self.subTest(label):
                lock, data, files, sbom = native_fixture(
                    "linux-x86_64", runtime=runtime
                )
                with self.assertRaisesRegex(RuntimeError, "GCC static"):
                    tools.validate_analysis(files, data.__getitem__, sbom, lock)
        with_eh = static_runtime(
            libraries=dict(
                libraries, **{"libgcc_eh.a": {"sha256": "1" * 64, "size": 3}}
            )
        )
        lock, data, files, sbom = native_fixture("linux-x86_64", runtime=with_eh)
        tools.validate_analysis(files, data.__getitem__, sbom, lock)

    def test_gcc_notice_bytes_must_match_recorded_identity(self) -> None:
        lock, data, files, sbom = native_fixture("linux-x86_64")
        tampered = dict(data)
        tampered[GCC_NOTICES[1]] = b"different runtime exception text"
        files = [
            dict(
                leaf,
                size=len(tampered[leaf["path"]]),
                sha256=sha256(tampered[leaf["path"]]),
            )
            if leaf["path"] == GCC_NOTICES[1]
            else leaf
            for leaf in files
        ]
        with self.assertRaisesRegex(RuntimeError, "Pinned upstream bytes changed"):
            tools.validate_analysis(files, tampered.__getitem__, sbom, lock)
        lock, data, files, sbom = native_fixture("linux-x86_64")
        missing = [leaf for leaf in files if leaf["path"] != GCC_NOTICES[0]]
        with self.assertRaises((RuntimeError, KeyError)):
            tools.validate_analysis(missing, data.__getitem__, sbom, lock)


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

    def test_native_executables_must_be_stripped(self) -> None:
        unstripped = {
            "linux-x86_64": elf_image(symtab=True),
            "macos-aarch64": macho_image("aarch64", stabs=40),
            "macos-x86_64": macho_image("x86_64", stabs=40),
        }
        for target, executable in unstripped.items():
            with self.subTest(target):
                lock, data, manifest = self.payload(
                    target, executables={"cppcheck": executable}
                )
                with self.assertRaisesRegex(RuntimeError, "not stripped"):
                    self.validate(lock, manifest, data, native_modes(manifest["files"]))

    def test_windows_wrapper_keeps_target_free_manifest_and_refuses_native(
        self,
    ) -> None:
        with self.assertRaisesRegex(RuntimeError, "requires Windows x86_64"):
            vbo.validate_windows_payload(
                {"platform": "linux", "architecture": "x86_64", "files": []},
                {}.__getitem__,
            )
        with self.assertRaisesRegex(RuntimeError, "requires Windows x86_64"):
            vbo.validate_windows_payload(
                {"architecture": "aarch64", "files": []}, {}.__getitem__
            )

    def test_payload_target_comes_from_manifest_identity(self) -> None:
        for manifest in (
            {"platform": "linux", "files": []},
            {"platform": "linux", "architecture": "aarch64", "files": []},
            {"architecture": "x86_64", "files": []},
        ):
            with (
                self.subTest(manifest),
                self.assertRaisesRegex(RuntimeError, "Unsupported analysis target"),
            ):
                vbo.validate_payload(
                    manifest, {}.__getitem__, read_mode=lambda name: 0o644
                )

    def test_shipped_executables_include_native_analyzers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            for target in NATIVE_TARGETS:
                lock = tools.load_lock(target=target)
                tools.write_json(bundle / "analysis/runtime.json", tools.mapping(lock))
                platform = TARGETS[target][0]
                shipped = {
                    path.relative_to(bundle).as_posix()
                    for path in vbo.shipped_executables(bundle, platform)
                }
                self.assertEqual(
                    shipped,
                    {
                        "byo",
                        "sidecar/byo-mcp-sidecar",
                        "analysis/cppcheck/cppcheck",
                        "analysis/clangd/bin/clangd",
                    },
                )
            windows = {
                path.relative_to(bundle).as_posix()
                for path in vbo.shipped_executables(bundle, "windows")
            }
            self.assertEqual(windows, {"byo.exe", "sidecar/byo-mcp-sidecar.exe"})


# --------------------------------------------------------------------------
# Native staging host gate and Linux GCC runtime input provenance
# --------------------------------------------------------------------------


class NativeStagingHostGateTests(unittest.TestCase):
    def test_staging_refuses_windows_and_cross_targets_before_reading_inputs(
        self,
    ) -> None:
        import analysis_native

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for host in TARGETS:
                for target in TARGETS:
                    if (
                        host == target
                        and target != "windows-x86_64"
                        and os.name == "posix"
                    ):
                        continue
                    with self.subTest(host=host, target=target):
                        with (
                            mock.patch.object(
                                analysis_native.tools, "host_target", return_value=host
                            ),
                            mock.patch.object(
                                analysis_native.tools,
                                "load_lock",
                                side_effect=AssertionError,
                            ),
                        ):
                            with self.assertRaisesRegex(
                                RuntimeError, "matching native host"
                            ):
                                analysis_native.stage_native(
                                    root / "b", root / "i", root / "e", target=target
                                )
                        self.assertFalse((root / "e").exists())

    def test_probes_refuse_foreign_targets(self) -> None:
        for target in NATIVE_TARGETS:
            lock = tools.load_lock(target=target)
            host = "windows-x86_64"
            with (
                self.subTest(target),
                mock.patch.object(tools, "host_target", return_value=host),
                mock.patch.object(
                    tools.subprocess, "run", side_effect=AssertionError("executed")
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "matching native host"):
                    tools.probe_programs(Path("bundle"), lock)


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

    def test_libgcc_eh_is_recorded_only_when_the_link_map_uses_it(self) -> None:
        self.link_inputs.discard("libgcc_eh.a")
        receipt = self.stage()
        self.assertEqual(
            set(receipt["static_runtime"]["libraries"]), {"libstdc++.a", "libgcc.a"}
        )

    def test_required_static_libraries_must_participate_in_the_link(self) -> None:
        for name in ("libstdc++.a", "libgcc.a"):
            with self.subTest(name):
                self.link_inputs = set(GCC_LIBRARIES) - {name}
                with self.assertRaisesRegex(
                    RuntimeError,
                    f"Link map does not prove actual static input: {re.escape(name)}",
                ):
                    self.stage()

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

    def test_provenance_identity_must_be_exact(self) -> None:
        good = json.loads((self.inputs / "gcc-runtime/provenance.json").read_text())
        cases = {
            "schema bool": dict(good, schema_version=True),
            "schema float": dict(good, schema_version=1.0),
            "schema 2": dict(good, schema_version=2),
            "extra key": dict(good, libraries={}),
            "missing source": {k: v for k, v in good.items() if k != "source"},
            "compiler mismatch": dict(good, compiler_sha256=sha256(b"another g++")),
            "empty package": dict(good, package=""),
            "non-string source": dict(good, source=["fixture"]),
            "missing libgcc.a": dict(
                good,
                static_libraries={
                    "libstdc++.a": good["static_libraries"]["libstdc++.a"]
                },
            ),
            "libraries not object": dict(good, static_libraries=[]),
            "not an object": [],
        }
        for label, document in cases.items():
            with self.subTest(label):
                self.write_gcc_inputs(document)
                with self.assertRaisesRegex(
                    RuntimeError,
                    "gcc-runtime/provenance.json must bind|Expected a JSON object",
                ):
                    self.stage()
                self.assertFalse((self.bundle / "analysis").exists())
        duplicate = json.dumps(good).replace(
            '"package"', '"package": "x", "package"', 1
        )
        self.write_gcc_inputs(duplicate)
        with self.assertRaisesRegex(RuntimeError, "Duplicate JSON key"):
            self.stage()

    def test_notices_and_provenance_are_required_regular_inputs(self) -> None:
        for name in ("COPYING3", "COPYING.RUNTIME", "provenance.json"):
            with self.subTest(name):
                saved = (self.inputs / "gcc-runtime" / name).read_bytes()
                (self.inputs / "gcc-runtime" / name).unlink()
                with self.assertRaisesRegex(
                    RuntimeError, "Supply a regular local input"
                ):
                    self.stage()
                (self.inputs / "gcc-runtime" / name).write_bytes(saved)
        self.write_gcc_inputs(notices={"COPYING3": b"", "COPYING.RUNTIME": b"fixture"})
        with self.assertRaisesRegex(RuntimeError, "Empty GCC runtime notice: COPYING3"):
            self.stage()
        self.write_gcc_inputs(
            notices={"COPYING3": b"fixture", "COPYING.RUNTIME": b"fixture"}
        )
        target = self.inputs / "gcc-runtime/COPYING3"
        target.unlink()
        os.symlink(self.compiler, target)
        with self.assertRaisesRegex(RuntimeError, "regular local input"):
            self.stage()

    def test_builder_baseline_must_be_glibc_2_28(self) -> None:
        for baseline in ("glibc 2.31", "glibc 2.17", "musl"):
            with self.subTest(baseline):
                self.baseline = baseline
                with self.assertRaisesRegex(
                    RuntimeError, "controlled glibc 2.28 native builder"
                ):
                    self.stage()

    def test_pinned_archives_are_hash_checked_before_any_command(self) -> None:
        archive = self.inputs / self.lock["programs"]["clangd"]["source"]["archive"]
        archive.write_bytes(archive.read_bytes() + b"x")
        with self.assertRaisesRegex(
            RuntimeError, "Supply the pinned local clangd archive"
        ):
            self.stage()
        self.assertFalse(self.evidence.exists())


if __name__ == "__main__":
    unittest.main()
