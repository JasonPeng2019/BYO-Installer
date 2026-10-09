"""Windows staging contract and import-closure negatives (stdlib only)."""

from __future__ import annotations

import copy
import json
import struct
import tempfile
import unittest
from pathlib import Path

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
    lock = copy.deepcopy(tools.load_lock())
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
    return lock, data, files, {"components": components, "dependencies": dependencies}


class WindowsAnalysisTests(unittest.TestCase):
    def test_pinned_selection_counts_and_portable_recipe(self):
        lock = tools.load_lock()
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
