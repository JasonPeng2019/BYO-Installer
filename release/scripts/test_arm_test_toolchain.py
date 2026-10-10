"""ARM archive/receipt contracts with small synthetic bytes and mocked network.

These do not download a toolchain, execute a compiler or establish native ARM
build proof. Tests run on GitHub; the full installed smoke supplies real proof.
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import tempfile
import tarfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import acquire_arm_test_toolchain as arm
import acquire_analysis_inputs as inputs
from test_acquire_analysis_inputs import serve

COMPILER = b"synthetic compiler bytes; never executable proof\n"


def source_and_archive(target, *, member=None, contents=COMPILER):
    is_windows = target == "windows-x86_64"
    source = {
        "archive_layout": "flat" if is_windows else "rooted",
        "version": "1.0.rel1",
        "archive": "fixture.zip" if is_windows else "fixture.tar.xz",
        "url": "https://example.invalid/fixture.zip"
        if is_windows
        else "https://example.invalid/fixture.tar.xz",
        "checksum_url": "https://example.invalid/fixture.sha256asc",
        "sha256": "",
        "directory": "fixture",
        "compiler": "bin/arm-none-eabi-g++.exe"
        if is_windows
        else "bin/arm-none-eabi-g++",
    }
    data = io.BytesIO()
    name = member or (
        source["compiler"] if is_windows else f"fixture/{source['compiler']}"
    )
    if is_windows:
        with zipfile.ZipFile(data, "w") as archive:
            archive.writestr(name, contents)
    else:
        with tarfile.open(fileobj=data, mode="w:xz") as archive:
            info = tarfile.TarInfo(name)
            info.size = len(contents)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(contents))
    payload = data.getvalue()
    source["sha256"] = hashlib.sha256(payload).hexdigest()
    return source, payload


class ArmInputContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def acquire_fixture(self, target, source, payload, output):
        network, calls = serve({source["url"]: payload})
        with (
            mock.patch.object(arm, "load_source", return_value=source),
            mock.patch.object(inputs.urllib.request, "urlopen", side_effect=network),
        ):
            receipt = arm.acquire(target, output)
        return receipt, calls

    def test_four_explicit_upstream_pins_and_intel_version_are_recorded(self):
        lock = json.loads(arm.LOCK.read_text(encoding="utf-8"))
        self.assertEqual(set(lock["targets"]), set(arm.TARGETS))
        for target in arm.TARGETS:
            with self.subTest(target=target):
                source = arm.load_source(target)
                self.assertEqual(source, lock["targets"][target])
                self.assertTrue(source["url"].startswith("https://developer.arm.com/"))
                self.assertEqual(source["checksum_url"], source["url"] + ".sha256asc")
                self.assertEqual(len(source["sha256"]), 64)
        self.assertEqual(arm.load_source("macos-x86_64")["version"], "14.2.rel1")

    def test_verified_archives_bind_actual_compiler_bytes_on_all_four_targets(self):
        for target in arm.TARGETS:
            with self.subTest(target=target):
                source, payload = source_and_archive(target)
                receipt, calls = self.acquire_fixture(
                    target, source, payload, self.root / target
                )
                compiler = Path(receipt["compiler"])
                self.assertEqual(compiler.read_bytes(), COMPILER)
                self.assertEqual(
                    receipt["compiler_sha256"], hashlib.sha256(COMPILER).hexdigest()
                )
                self.assertEqual(
                    receipt["archive"]["sha256"], hashlib.sha256(payload).hexdigest()
                )
                self.assertEqual(receipt["archive"]["size"], len(payload))
                self.assertEqual(receipt["target"], target)
                self.assertEqual(calls, [source["url"]])
                compiler.relative_to((self.root / target).resolve())

    def test_digest_mismatch_refuses_extraction_and_leaves_no_download_partial(self):
        source, payload = source_and_archive("linux-x86_64")
        source["sha256"] = "0" * 64
        output = self.root / "inputs"
        with self.assertRaisesRegex(RuntimeError, "SHA-256"):
            self.acquire_fixture("linux-x86_64", source, payload, output)
        self.assertFalse((output / "toolchain").exists())
        self.assertEqual(list(output.glob("*.partial")), [])

    def test_flat_windows_vendor_zip_is_wrapped_in_the_owned_vendor_root(self):
        source, _ = source_and_archive("windows-x86_64")
        source["archive_layout"] = "flat"
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            archive.writestr(".version", b"vendor version metadata")
            archive.writestr(source["compiler"], COMPILER)
        payload = data.getvalue()
        source["sha256"] = hashlib.sha256(payload).hexdigest()
        receipt, _ = self.acquire_fixture(
            "windows-x86_64", source, payload, self.root / "flat-windows"
        )
        vendor_root = Path(receipt["root"])
        self.assertEqual(
            (vendor_root / ".version").read_bytes(), b"vendor version metadata"
        )
        self.assertEqual(Path(receipt["compiler"]).read_bytes(), COMPILER)
        self.assertEqual(vendor_root.name, source["directory"])

    def test_existing_extraction_is_refused_before_network_and_is_preserved(self):
        source, payload = source_and_archive("linux-x86_64")
        output = self.root / "inputs"
        extracted = output / "toolchain"
        extracted.mkdir(parents=True)
        marker = extracted / "unrelated"
        marker.write_bytes(b"preserve")
        with (
            mock.patch.object(arm, "load_source", return_value=source),
            mock.patch.object(inputs.urllib.request, "urlopen") as network,
        ):
            with self.assertRaisesRegex(RuntimeError, "fresh"):
                arm.acquire("linux-x86_64", output)
            network.assert_not_called()
        self.assertEqual(marker.read_bytes(), b"preserve")

    def test_cached_archive_is_rehashed_and_reused_without_network(self):
        source, payload = source_and_archive("windows-x86_64")
        output = self.root / "inputs"
        output.mkdir()
        (output / source["archive"]).write_bytes(payload)
        with (
            mock.patch.object(arm, "load_source", return_value=source),
            mock.patch.object(inputs.urllib.request, "urlopen") as network,
        ):
            receipt = arm.acquire("windows-x86_64", output)
            network.assert_not_called()
        self.assertEqual(Path(receipt["compiler"]).read_bytes(), COMPILER)

    def test_missing_compiler_and_escaped_archive_members_never_produce_receipt(self):
        for target in ("windows-x86_64", "linux-x86_64"):
            for member in (
                "fixture/README",
                "../escape",
                "/escape",
                "foreign/compiler",
            ):
                with self.subTest(target=target, member=member):
                    source, payload = source_and_archive(target, member=member)
                    output = self.root / f"case-{len(list(self.root.iterdir()))}"
                    with self.assertRaises((RuntimeError, tarfile.FilterError)):
                        self.acquire_fixture(target, source, payload, output)
        self.assertFalse((self.root / "escape").exists())

    def test_unknown_target_or_malformed_lock_refuses_before_effects(self):
        with self.assertRaises(ValueError):
            arm.load_source("linux-aarch64")
        lock = json.loads(arm.LOCK.read_text(encoding="utf-8"))
        for altered in (dict(lock, schema_version=True), dict(lock, surprise=1)):
            path = self.root / "lock.json"
            path.write_text(json.dumps(altered), encoding="utf-8")
            with mock.patch.object(arm, "LOCK", path), self.assertRaises(ValueError):
                arm.load_source("linux-x86_64")
        source = copy.deepcopy(lock)
        source["targets"]["linux-x86_64"]["sha256"] = "wrong"
        path.write_text(json.dumps(source), encoding="utf-8")
        with mock.patch.object(arm, "LOCK", path), self.assertRaises(ValueError):
            arm.load_source("linux-x86_64")


if __name__ == "__main__":
    unittest.main()
