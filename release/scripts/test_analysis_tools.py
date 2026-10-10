"""Windows staging contract and import-closure negatives (stdlib only)."""

from __future__ import annotations

import copy
import io
import json
import struct
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import analysis_tools as tools


def pe(ordinary: str | None = None, delay: str | None = None) -> bytes:
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 64)
    data[64:68] = b"PE\0\0"
    struct.pack_into("<HH", data, 68, 0x8664, 1)
    struct.pack_into("<H", data, 84, 240)
    opt = 88
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<Q", data, opt + 24, 0x140000000)
    struct.pack_into("<I", data, opt + 60, 512)
    struct.pack_into("<I", data, opt + 108, 16)
    struct.pack_into("<IIII", data, opt + 240 + 8, 512, 4096, 512, 512)
    if ordinary:
        struct.pack_into("<II", data, opt + 112 + 8, 4096, 40)
        struct.pack_into("<I", data, 512 + 12, 4224)
        data[640 : 640 + len(ordinary) + 1] = ordinary.encode() + b"\0"
    if delay:
        struct.pack_into("<II", data, opt + 112 + 13 * 8, 4352, 64)
        struct.pack_into("<II", data, 768, 1, 4480)
        data[896 : 896 + len(delay) + 1] = delay.encode() + b"\0"
    return bytes(data)


def fixture() -> tuple[dict, dict[str, bytes], list[dict], dict]:
    # Windows regression fixture: always the explicit Windows lock record,
    # independent of the host that runs these platform-neutral tests.
    lock = copy.deepcopy(tools.load_lock(target="windows-x86_64"))
    data = {}
    for name, program in lock["programs"].items():
        selected = [f for f in program["selected_files"] if f["kind"] == "license"]
        if name == "cppcheck":
            selected += [
                f
                for f in program["selected_files"]
                if f["runtime_path"].endswith(("/std.cfg", "/win64.xml"))
            ]
        else:
            selected += [
                f
                for f in program["selected_files"]
                if f["runtime_path"].endswith("/stddef.h")
            ]
        if name == "clangd":
            selected += [
                f
                for f in program["selected_files"]
                if f["kind"] == "analysis-executable"
            ]
        for leaf in selected:
            value = (
                pe()
                if leaf["kind"] == "analysis-executable"
                else leaf["runtime_path"].encode()
            )
            leaf.update(size=len(value), sha256=tools.sha256(value))
            data[leaf["runtime_path"]] = value
        program["selected_files"] = selected
        data[program["executable"]] = pe()
    data["analysis/runtime.json"] = json.dumps(tools.mapping(lock)).encode()
    for leaf in lock.get("windows_native", {}).get("selected_files", []):
        value = pe() if leaf["kind"] == "native-dependency" else b"test Windows notice"
        leaf.update(size=len(value), sha256=tools.sha256(value))
        data[leaf["runtime_path"]] = value
    files = [
        {
            "path": path,
            "size": len(value),
            "sha256": tools.sha256(value),
            "kind": tools.classification(path, lock)[0],
            "executable": tools.classification(path, lock)[1],
        }
        for path, value in sorted(data.items())
    ]
    components, dependencies = tools.sbom_components(lock, files, {})
    native_components, native_dependencies = tools.native_sbom(files, lock)
    components.extend(native_components)
    dependencies.extend(native_dependencies)
    return lock, data, files, {"components": components, "dependencies": dependencies}


class WindowsAnalysisTests(unittest.TestCase):
    @unittest.skipUnless(tools.os.name == "nt", "native Windows staging")
    def test_stage_copies_pinned_archive_data_before_source_cleanup(self):
        lock, data, _, _ = fixture()
        recipe = lock["programs"]["cppcheck"]["recipe"]
        patch = (tools.ROOT / recipe["patch"]).read_bytes()
        # Supply the real patch context in a small local archive. Only native
        # compilation is stubbed; Git, extraction, byte checks and staging run.
        options = b"\n" * 204 + b"".join(
            line[1:]
            for line in patch.splitlines(keepends=True)[3:]
            if line[:1] in (b" ", b"-")
        )
        patched = options.replace(
            b"    add_compile_options($<$<NOT:$<CONFIG:Debug>>:/MD>) # Runtime Library - Multi-threaded DLL\n",
            b"",
        ).replace(
            b"    add_compile_options($<$<CONFIG:Debug>:/MDd>) # Runtime Library - Multi-threaded Debug DLL\n",
            b"",
        )
        recipe["upstream_compileroptions_sha256"] = tools.sha256(options)
        recipe["patched_compileroptions_sha256"] = tools.sha256(patched)
        run_native = subprocess.run
        staged_sources = []
        with tempfile.TemporaryDirectory(prefix="byo-stage-test-") as temporary:
            root = Path(temporary)
            for field in ("patch", "utf8_manifest"):
                target = root / recipe[field]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((tools.ROOT / recipe[field]).read_bytes())
            cpp = lock["programs"]["cppcheck"]
            archive = root / cpp["source"]["archive"]
            with tarfile.open(archive, "w:gz") as handle:
                members = {
                    cpp["source"]["archive_prefix"]
                    + "cmake/compileroptions.cmake": options,
                    **{
                        f["upstream_path"]: data[f["runtime_path"]]
                        for f in cpp["selected_files"]
                    },
                }
                for name, value in members.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(value)
                    handle.addfile(member, io.BytesIO(value))
            cpp["source"]["sha256"] = tools.sha256(archive.read_bytes())
            clang = lock["programs"]["clangd"]
            archive = root / clang["source"]["archive"]
            with zipfile.ZipFile(archive, "w") as handle:
                for leaf in clang["selected_files"]:
                    handle.writestr(leaf["upstream_path"], data[leaf["runtime_path"]])
            clang["source"]["sha256"] = tools.sha256(archive.read_bytes())
            cmake = root / "cmake.exe"
            cmake.write_bytes(b"test native compiler identity")

            def run(argv, **kwargs):
                if argv[0] == "git":
                    return run_native(argv, **kwargs)
                if "-S" in argv:
                    staged_sources.append(Path(argv[argv.index("-S") + 1]))
                elif "--build" in argv:
                    build = Path(argv[argv.index("--build") + 1])
                    output = build / recipe["output"]
                    output.parent.mkdir(parents=True)
                    output.write_bytes(pe())
                    compiler = build / "CMakeFiles/test/CMakeCXXCompiler.cmake"
                    compiler.parent.mkdir(parents=True)
                    compiler.write_text(
                        'set(CMAKE_CXX_COMPILER_VERSION "test")\nset(CMAKE_CXX_COMPILER_ID "MSVC")\nset(CMAKE_CXX_COMPILER_ARCHITECTURE_ID x64)\n'
                    )
                    (build / "CMakeCache.txt").write_text(
                        f"CMAKE_LINKER:FILEPATH={cmake}\n"
                    )
                    (build / "cppcheck.vcxproj").write_text(
                        '<Project xmlns="urn:test"><WindowsTargetPlatformVersion>test</WindowsTargetPlatformVersion><PlatformToolset>v143</PlatformToolset></Project>'
                    )
                return subprocess.CompletedProcess(argv, 0, stdout="test linker\n")

            bundle = root / "bundle"
            with (
                mock.patch.object(tools, "ROOT", root),
                mock.patch.object(tools, "load_lock", return_value=lock),
                mock.patch.object(
                    tools.subprocess, "check_output", return_value="test CMake\n"
                ),
                mock.patch.object(tools.subprocess, "run", side_effect=run),
            ):
                tools.stage_windows(bundle, root, root / "evidence", cmake)
            self.assertTrue(staged_sources)
            self.assertFalse(staged_sources[0].exists())
            for name in ("cppcheck", "clangd"):
                for leaf in lock["programs"][name]["selected_files"]:
                    self.assertEqual(
                        (bundle / leaf["runtime_path"]).read_bytes(),
                        data[leaf["runtime_path"]],
                    )
            self.assertEqual(
                json.loads((bundle / "analysis/runtime.json").read_bytes()),
                tools.mapping(lock),
            )

    def test_pinned_selection_counts_and_portable_recipe(self):
        lock = tools.load_lock(target="windows-x86_64")
        self.assertEqual(
            (lock["platform"], lock["architecture"]), ("windows", "x86_64")
        )
        cpp = lock["programs"]["cppcheck"]["selected_files"]
        clang = lock["programs"]["clangd"]["selected_files"]
        self.assertEqual(
            sum(f["runtime_path"].startswith("analysis/cppcheck/cfg/") for f in cpp), 51
        )
        self.assertEqual(
            sum(
                f["runtime_path"].startswith("analysis/cppcheck/platforms/")
                for f in cpp
            ),
            15,
        )
        self.assertEqual(sum(f["kind"] == "license" for f in cpp), 4)
        self.assertEqual(sum(f["kind"] == "analysis-resource" for f in clang), 332)
        self.assertNotIn("C:/Users", json.dumps(lock))
        recipe = lock["programs"]["cppcheck"]["recipe"]
        for field in ("patch", "utf8_manifest"):
            self.assertEqual(
                tools.sha256((tools.ROOT / recipe[field]).read_bytes()),
                recipe[field + "_sha256"],
            )

    def test_mapping_inventory_and_sbom_agree(self):
        lock, data, files, sbom = fixture()
        tools.validate_analysis(files, data.__getitem__, sbom, lock)

    def test_windows_native_missing_modified_or_unowned_dependencies_block(self):
        lock, data, files, sbom = fixture()
        with mock.patch.object(tools, "load_lock", return_value=lock):
            tools.validate_windows_native(files, data.__getitem__, sbom, True)
            with self.assertRaisesRegex(RuntimeError, "Missing or misclassified"):
                tools.validate_windows_native(
                    [f for f in files if f["path"] != "vcruntime140.dll"],
                    data.__getitem__,
                    sbom,
                    True,
                )
            changed = dict(data)
            changed["vcruntime140.dll"] += b"changed"
            with self.assertRaisesRegex(RuntimeError, "Pinned upstream bytes changed"):
                tools.validate_windows_native(files, changed.__getitem__, sbom, True)
            unowned = copy.deepcopy(sbom)
            unowned["dependencies"] = [
                d
                for d in unowned["dependencies"]
                if d["ref"] != "byo-windows:msvc-runtime"
            ]
            with self.assertRaisesRegex(RuntimeError, "ownership mismatch"):
                tools.validate_windows_native(files, data.__getitem__, unowned, True)

    def test_modified_resource_rejected_even_with_rehashed_inventory(self):
        lock, data, files, sbom = fixture()
        path = "analysis/clangd/lib/clang/23/include/stddef.h"
        data[path] += b"extra source"
        next(f for f in files if f["path"] == path).update(
            size=len(data[path]), sha256=tools.sha256(data[path])
        )
        with self.assertRaisesRegex(RuntimeError, "Pinned upstream bytes changed"):
            tools.validate_analysis(files, data.__getitem__, sbom, lock)

    def test_unselected_and_misplaced_source_rejected(self):
        lock, _, _, _ = fixture()
        for path in (
            "analysis/clangd/lib/clang/23/include/extra.h",
            "analysis/cppcheck/addons/a.py",
            "analysis/clangd/stddef.h",
        ):
            with self.assertRaisesRegex(RuntimeError, "Unselected"):
                tools.classification(path, lock)

    def test_sbom_relationship_and_hash_required(self):
        for change in ("relationship", "hash"):
            lock, data, files, sbom = fixture()
            if change == "relationship":
                sbom["dependencies"][0]["dependsOn"] = []
            else:
                sbom["components"][1]["hashes"][0]["content"] = "0" * 64
            with self.assertRaisesRegex(RuntimeError, "SBOM"):
                tools.validate_analysis(files, data.__getitem__, sbom, lock)

    def test_mapping_unknown_field_not_ignored(self):
        lock, data, files, sbom = fixture()
        value = tools.mapping(lock)
        value["private_hashes"] = []
        data["analysis/runtime.json"] = json.dumps(value).encode()
        with self.assertRaisesRegex(RuntimeError, "mapping differs"):
            tools.validate_analysis(files, data.__getitem__, sbom, lock)

    def test_pe_ordinary_and_delay_imports(self):
        parsed = tools.pe_imports(pe("KERNEL32.dll", "api-ms-win-core-file-l1-1-0.dll"))
        self.assertEqual(parsed["machine"], "AMD64")
        self.assertEqual(parsed["format"], "PE32+")
        self.assertEqual(parsed["ordinary"], ["kernel32.dll"])
        self.assertEqual(parsed["delay"], ["api-ms-win-core-file-l1-1-0.dll"])

    def test_pe_wrong_machine_format_and_truncation_rejected(self):
        for offset, value in ((68, 0x14C), (88, 0x10B)):
            data = bytearray(pe())
            struct.pack_into("<H", data, offset, value)
            with self.assertRaisesRegex(RuntimeError, r"PE32\+/AMD64"):
                tools.pe_imports(bytes(data))
        with self.assertRaises(RuntimeError):
            tools.pe_imports(b"MZ")

    def test_named_and_ordinal_import_thunks_and_missing_bundled_symbol(self):
        data = bytearray(pe("local.dll", "kernel32.dll"))
        struct.pack_into("<I", data, 512, 4256)
        struct.pack_into("<Q", data, 672, 4296)
        data[714:734] = b"GetCurrentProcessId\0"
        struct.pack_into("<I", data, 768 + 16, 4544)
        struct.pack_into("<Q", data, 960, (1 << 63) | 7)
        parsed = tools.pe_imports(bytes(data))
        self.assertEqual(
            parsed["symbols"]["ordinary"]["local.dll"], ["GetCurrentProcessId"]
        )
        self.assertEqual(parsed["symbols"]["delay"]["kernel32.dll"], ["#7"])
        leaves = {
            "analysis/cppcheck/cppcheck.exe": bytes(data),
            "analysis/cppcheck/local.dll": pe(),
        }
        with self.assertRaisesRegex(RuntimeError, "Unresolved bundled PE symbol"):
            tools.validate_pe_closure(
                [{"path": name} for name in leaves], leaves.__getitem__
            )

    def test_missing_adjacent_delay_dependency_cannot_use_path(self):
        files = [{"path": "analysis/cppcheck/cppcheck.exe"}]

        def missing(name, symbols):
            raise RuntimeError("Unresolved: " + name)

        with self.assertRaisesRegex(RuntimeError, "missing.dll"):
            tools.validate_pe_closure(files, lambda _: pe(delay="missing.dll"), missing)

    def test_adjacent_dependency_and_explicit_os_receipt(self):
        data = {
            "analysis/cppcheck/cppcheck.exe": pe("local.dll", "kernel32.dll"),
            "analysis/cppcheck/local.dll": pe(),
        }
        calls = []

        def system(name, symbols):
            calls.append(name)
            return {"import": name, "module": name, "sha256": "a" * 64}

        receipt = tools.validate_pe_closure(
            [{"path": p} for p in data], data.__getitem__, system
        )
        self.assertEqual(calls, ["kernel32.dll"])
        self.assertEqual(len(receipt["images"]), 2)
        self.assertTrue(
            any(e["to"] == "analysis/cppcheck/local.dll" for e in receipt["imports"])
        )

    def test_actual_system32_symbols_and_missing_symbol_blocker(self):
        result = tools.system_module("kernel32.dll", ["GetCurrentProcessId"])
        self.assertEqual(result["search"], "LOAD_LIBRARY_SEARCH_SYSTEM32")
        self.assertEqual(result["symbols"][0]["symbol"], "GetCurrentProcessId")
        with self.assertRaisesRegex(
            RuntimeError, "Unresolved Windows OS/API-set symbol"
        ):
            tools.system_module(
                "kernel32.dll", ["BYO_missing_export_for_negative_test"]
            )

    def test_installed_vc_redist_is_not_a_windows_os_module(self):
        for name in (
            "vcruntime140.dll",
            "msvcp140.dll",
            "concrt140.dll",
            "msvcr120.dll",
        ):
            with self.assertRaisesRegex(RuntimeError, "Redistributable dependency"):
                tools.system_module(name, [])

    def test_windows_path_aliases_rejected(self):
        for path in (
            "../escape",
            "a//b",
            "a/./b",
            "a/CON.txt",
            "a/file:stream",
            "C:/a",
            "a/name.",
            "a\\b",
        ):
            with self.assertRaises(RuntimeError):
                tools.safe_relative(path)

    def test_source_inputs_missing_fail_before_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "pinned local"):
                tools.stage_windows(root / "bundle", root, root / "evidence")


if __name__ == "__main__":
    unittest.main()
