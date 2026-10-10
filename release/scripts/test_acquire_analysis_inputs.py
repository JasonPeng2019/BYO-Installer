#!/usr/bin/env python3
"""Contracts for the explicit, hash-pinned analyzer input acquisition CLI.

Windows-host platform-neutral fixtures: every case uses temporary directories,
mocked network responses and in-memory bytes. No analyzer archive is fetched and
no native program is executed.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import acquire_analysis_inputs as acquire_inputs
import analysis_tools


TARGETS = ("windows-x86_64", "macos-aarch64", "macos-x86_64", "linux-x86_64")
CPPCHECK_BYTES = b"cppcheck source archive bytes\n"
CLANGD_BYTES = b"clangd release archive bytes\n"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source(archive: str, data: bytes, url: str | None = None) -> dict:
    return {
        "archive": archive,
        "url": url or f"https://example.invalid/releases/{archive}",
        "sha256": sha256(data),
    }


def lock_for(target: str) -> dict:
    platform, architecture = target.split("-", 1)
    return {
        "platform": platform,
        "architecture": architecture,
        "programs": {
            "cppcheck": {"source": source("cppcheck-src.tar.gz", CPPCHECK_BYTES)},
            "clangd": {"source": source(f"clangd-{platform}.zip", CLANGD_BYTES)},
        },
    }


class Response:
    """Minimal urlopen response with a controllable final URL."""

    def __init__(self, data: bytes, final_url: str, on_read=None) -> None:
        self.stream = io.BytesIO(data)
        self.final_url = final_url
        self.on_read = on_read

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *exc: object) -> None:
        self.stream.close()

    def geturl(self) -> str:
        return self.final_url

    def read(self, size: int = -1) -> bytes:
        if self.on_read is not None:
            callback, self.on_read = self.on_read, None
            callback()
        return self.stream.read(size)


def serve(payloads: dict[str, bytes], redirects: dict[str, str] | None = None):
    """Return a urlopen replacement serving bytes by request URL."""

    calls: list[str] = []

    def urlopen(request, timeout=None):
        url = request.full_url
        calls.append(url)
        if timeout is None:
            raise AssertionError("Acquisition must bound network waits")
        return Response(payloads[url], (redirects or {}).get(url, url))

    return urlopen, calls


def refuse_network(*args: object, **kwargs: object):
    raise AssertionError("Network must not be used for this case")


def partials(directory: Path) -> list[str]:
    if not directory.exists():
        return []
    return sorted(
        path.name for path in directory.iterdir() if path.name.endswith(".partial")
    )


def symlink_or_skip(link: Path, target: Path, *, directory: bool) -> None:
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError) as error:
        raise unittest.SkipTest(
            f"Host cannot create symlinks for this fixture ({error}); "
            "the symlink refusal stays pending on this runner"
        ) from error


class AcquisitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.output = self.root / "inputs"
        self.lock = lock_for("windows-x86_64")
        patcher = mock.patch.object(
            acquire_inputs.analysis_tools, "load_lock", side_effect=self.load_lock
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.temporary.cleanup)
        self.requested_targets: list[str] = []

    def load_lock(self, *args: object, **kwargs: object) -> dict:
        if args or set(kwargs) != {"target"}:
            raise AssertionError(f"load_lock must be target-explicit: {args} {kwargs}")
        self.requested_targets.append(kwargs["target"])
        return copy.deepcopy(self.lock)

    def urls(self) -> dict[str, bytes]:
        programs = self.lock["programs"]
        return {
            programs["cppcheck"]["source"]["url"]: CPPCHECK_BYTES,
            programs["clangd"]["source"]["url"]: CLANGD_BYTES,
        }

    def acquire(self, urlopen, target: str = "windows-x86_64") -> dict:
        with mock.patch.object(
            acquire_inputs.urllib.request, "urlopen", side_effect=urlopen
        ):
            return acquire_inputs.acquire(target, self.output)

    def test_downloads_verify_and_publish_each_pinned_archive_once(self) -> None:
        urlopen, calls = serve(self.urls())
        receipt = self.acquire(urlopen)
        self.assertEqual(sorted(calls), sorted(self.urls()))
        self.assertEqual(
            (self.output / "cppcheck-src.tar.gz").read_bytes(), CPPCHECK_BYTES
        )
        self.assertEqual(
            (self.output / "clangd-windows.zip").read_bytes(), CLANGD_BYTES
        )
        self.assertEqual(partials(self.output), [])
        self.assertEqual(receipt["target"], "windows-x86_64")
        self.assertEqual(Path(receipt["input_dir"]), self.output.resolve())
        self.assertEqual(
            {
                item["archive"]: (item["sha256"], item["size"])
                for item in receipt["archives"]
            },
            {
                "cppcheck-src.tar.gz": (sha256(CPPCHECK_BYTES), len(CPPCHECK_BYTES)),
                "clangd-windows.zip": (sha256(CLANGD_BYTES), len(CLANGD_BYTES)),
            },
        )

    def test_matching_existing_pins_are_reused_without_network(self) -> None:
        self.output.mkdir()
        (self.output / "cppcheck-src.tar.gz").write_bytes(CPPCHECK_BYTES)
        (self.output / "clangd-windows.zip").write_bytes(CLANGD_BYTES)
        before = {path.name: path.stat().st_mtime_ns for path in self.output.iterdir()}
        receipt = self.acquire(refuse_network)
        self.assertEqual(len(receipt["archives"]), 2)
        self.assertEqual(
            {path.name: path.stat().st_mtime_ns for path in self.output.iterdir()},
            before,
        )

    def test_partial_reuse_downloads_only_missing_archive(self) -> None:
        self.output.mkdir()
        (self.output / "cppcheck-src.tar.gz").write_bytes(CPPCHECK_BYTES)
        urlopen, calls = serve(self.urls())
        self.acquire(urlopen)
        self.assertEqual(calls, [self.lock["programs"]["clangd"]["source"]["url"]])
        self.assertEqual(
            (self.output / "clangd-windows.zip").read_bytes(), CLANGD_BYTES
        )

    def test_hash_mismatch_cannot_publish_and_cleans_temporary_file(self) -> None:
        payloads = self.urls()
        clangd_url = self.lock["programs"]["clangd"]["source"]["url"]
        payloads[clangd_url] = CLANGD_BYTES + b"tampered"
        urlopen, _ = serve(payloads)
        with self.assertRaisesRegex(
            RuntimeError, "SHA-256 mismatch for clangd-windows.zip"
        ):
            self.acquire(urlopen)
        self.assertFalse((self.output / "clangd-windows.zip").exists())
        self.assertEqual(partials(self.output), [])

    def test_differing_existing_input_is_preserved_and_refused(self) -> None:
        self.output.mkdir()
        foreign = b"user supplied different archive"
        (self.output / "clangd-windows.zip").write_bytes(foreign)
        with self.assertRaisesRegex(
            RuntimeError, "Existing input differs from its pin"
        ):
            self.acquire(refuse_network)
        self.assertEqual((self.output / "clangd-windows.zip").read_bytes(), foreign)
        self.assertEqual(partials(self.output), [])

    def test_existing_directory_in_archive_slot_is_refused(self) -> None:
        (self.output / "clangd-windows.zip").mkdir(parents=True)
        with self.assertRaisesRegex(
            RuntimeError, "Existing input differs from its pin"
        ):
            self.acquire(refuse_network)
        self.assertTrue((self.output / "clangd-windows.zip").is_dir())

    def test_input_appearing_during_download_is_never_overwritten(self) -> None:
        clangd_url = self.lock["programs"]["clangd"]["source"]["url"]
        racer = b"written by a concurrent invocation"

        def urlopen(request, timeout=None):
            data = self.urls()[request.full_url]
            if request.full_url != clangd_url:
                return Response(data, request.full_url)
            return Response(
                data,
                request.full_url,
                on_read=lambda: (self.output / "clangd-windows.zip").write_bytes(racer),
            )

        with self.assertRaisesRegex(RuntimeError, "Input appeared while downloading"):
            self.acquire(urlopen)
        self.assertEqual((self.output / "clangd-windows.zip").read_bytes(), racer)
        self.assertEqual(partials(self.output), [])

    def test_transport_failure_cleans_temporary_file(self) -> None:
        def urlopen(request, timeout=None):
            raise OSError("connection reset")

        with self.assertRaisesRegex(OSError, "connection reset"):
            self.acquire(urlopen)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_https_redirect_to_plain_http_is_refused(self) -> None:
        clangd_url = self.lock["programs"]["clangd"]["source"]["url"]
        urlopen, _ = serve(
            self.urls(), {clangd_url: "http://mirror.invalid/clangd-windows.zip"}
        )
        with self.assertRaisesRegex(RuntimeError, "Insecure archive redirect"):
            self.acquire(urlopen)
        self.assertFalse((self.output / "clangd-windows.zip").exists())
        self.assertEqual(partials(self.output), [])

    def test_unsafe_pinned_sources_are_refused_before_any_write(self) -> None:
        good = self.lock["programs"]["clangd"]["source"]
        cases = {
            "plain http": {"url": "http://example.invalid/clangd-windows.zip"},
            "file scheme": {"url": "file:///tmp/clangd-windows.zip"},
            "no host": {"url": "https:///clangd-windows.zip"},
            "userinfo": {"url": "https://user:secret@example.invalid/clangd.zip"},
            "username only": {"url": "https://user@example.invalid/clangd.zip"},
            "nested archive": {"archive": "nested/clangd-windows.zip"},
            "parent archive": {"archive": "../clangd-windows.zip"},
            "absolute archive": {"archive": "/clangd-windows.zip"},
            "backslash archive": {"archive": "..\\clangd-windows.zip"},
            "short digest": {"sha256": good["sha256"][:63]},
            "uppercase digest": {"sha256": good["sha256"].upper()},
            "non-hex digest": {"sha256": "g" * 64},
        }
        for label, change in cases.items():
            with self.subTest(label):
                self.lock = lock_for("windows-x86_64")
                self.lock["programs"]["clangd"]["source"].update(change)
                with self.assertRaises((RuntimeError, ValueError)):
                    self.acquire(refuse_network)
                self.assertFalse(self.output.exists(), label)

    def test_conflicting_duplicate_archive_sources_are_refused(self) -> None:
        self.lock["programs"]["clangd"]["source"] = dict(
            self.lock["programs"]["cppcheck"]["source"], sha256=sha256(b"other")
        )
        with self.assertRaisesRegex(RuntimeError, "Conflicting pinned archive sources"):
            self.acquire(refuse_network)
        self.assertFalse(self.output.exists())

    def test_identical_shared_archive_source_is_fetched_once(self) -> None:
        self.lock["programs"]["clangd"]["source"] = copy.deepcopy(
            self.lock["programs"]["cppcheck"]["source"]
        )
        shared = self.lock["programs"]["cppcheck"]["source"]
        urlopen, calls = serve({shared["url"]: CPPCHECK_BYTES})
        receipt = self.acquire(urlopen)
        self.assertEqual(calls, [shared["url"]])
        self.assertEqual(
            [item["archive"] for item in receipt["archives"]], ["cppcheck-src.tar.gz"]
        )
        self.assertEqual((self.output / shared["archive"]).read_bytes(), CPPCHECK_BYTES)
        self.assertEqual(receipt["archives"][0]["sha256"], sha256(CPPCHECK_BYTES))
        self.assertEqual(receipt["archives"][0]["size"], len(CPPCHECK_BYTES))

    def test_symlinked_output_directory_is_refused(self) -> None:
        real = self.root / "real"
        real.mkdir()
        symlink_or_skip(self.output, real, directory=True)
        with self.assertRaisesRegex(RuntimeError, "must not be a symlink"):
            self.acquire(refuse_network)
        self.assertEqual(list(real.iterdir()), [])

    def test_symlinked_archive_slot_is_refused_and_left_untouched(self) -> None:
        self.output.mkdir()
        elsewhere = self.root / "elsewhere.zip"
        elsewhere.write_bytes(CLANGD_BYTES)
        symlink_or_skip(self.output / "clangd-windows.zip", elsewhere, directory=False)
        urlopen, _ = serve(self.urls())
        with self.assertRaisesRegex(RuntimeError, "must not be a symlink"):
            self.acquire(urlopen)
        self.assertTrue((self.output / "clangd-windows.zip").is_symlink())
        self.assertEqual(elsewhere.read_bytes(), CLANGD_BYTES)

    def test_each_supported_target_routes_to_its_own_lock_record(self) -> None:
        for target in TARGETS:
            with self.subTest(target):
                self.lock = lock_for(target)
                self.output = self.root / target
                self.requested_targets.clear()
                urlopen, _ = serve(self.urls())
                receipt = self.acquire(urlopen, target)
                self.assertEqual(self.requested_targets, [target])
                self.assertEqual(receipt["target"], target)
                platform = target.split("-", 1)[0]
                self.assertTrue((self.output / f"clangd-{platform}.zip").is_file())


class CommandLineTests(unittest.TestCase):
    def run_main(self, argv: list[str]) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(sys, "argv", ["acquire_analysis_inputs.py", *argv]),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            try:
                status = acquire_inputs.main()
            except SystemExit as exit_:
                status = exit_.code
        return status, stdout.getvalue(), stderr.getvalue()

    def test_cli_targets_are_exactly_the_four_supported_targets(self) -> None:
        self.assertEqual(tuple(acquire_inputs.TARGETS), TARGETS)

    def test_cli_success_prints_receipt_and_routes_expected_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "inputs"
            receipt = {
                "target": "linux-x86_64",
                "input_dir": str(output),
                "archives": [],
            }
            with mock.patch.object(
                acquire_inputs, "acquire", return_value=receipt
            ) as called:
                status, stdout, _ = self.run_main(
                    ["--expected-target", "linux-x86_64", "--output", str(output)]
                )
        self.assertEqual(status, 0)
        called.assert_called_once_with("linux-x86_64", output)
        self.assertEqual(json.loads(stdout), receipt)

    def test_cli_acquisition_failure_exits_two_with_reason(self) -> None:
        with mock.patch.object(
            acquire_inputs,
            "acquire",
            side_effect=RuntimeError("Pinned archive SHA-256 mismatch"),
        ):
            status, stdout, stderr = self.run_main(
                ["--expected-target", "macos-aarch64", "--output", "inputs"]
            )
        self.assertEqual(status, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "Analyzer input acquisition failed: Pinned archive SHA-256 mismatch", stderr
        )

    def test_cli_os_and_value_errors_also_exit_two(self) -> None:
        for error in (OSError("disk full"), ValueError("Unsafe relative path")):
            with self.subTest(type(error).__name__):
                with mock.patch.object(acquire_inputs, "acquire", side_effect=error):
                    status, _, stderr = self.run_main(
                        ["--expected-target", "macos-x86_64", "--output", "inputs"]
                    )
                self.assertEqual(status, 2)
                self.assertIn(str(error), stderr)

    def test_cli_rejects_missing_unknown_or_alias_targets(self) -> None:
        cases = (
            ["--output", "inputs"],
            ["--expected-target", "linux-aarch64", "--output", "inputs"],
            ["--expected-target", "linux-x86_64-glibc-2.28", "--output", "inputs"],
            ["--expected-target", "windows-x86_64"],
        )
        for argv in cases:
            with self.subTest(argv):
                with mock.patch.object(
                    acquire_inputs, "acquire", side_effect=AssertionError
                ):
                    status, _, _ = self.run_main(argv)
                self.assertEqual(status, 2)


class PinnedLockRoutingTests(unittest.TestCase):
    """Uses the checked-in v2 lock; execution pending until lock v2 is integrated."""

    def test_checked_in_lock_sources_pass_validation_for_every_target(self) -> None:
        class Attempted(Exception):
            pass

        def urlopen(request, timeout=None):
            self.assertTrue(request.full_url.startswith("https://"))
            raise Attempted(request.full_url)

        for target in TARGETS:
            with self.subTest(target), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "inputs"
                record = analysis_tools.load_lock(target=target)
                expected = {
                    program["source"]["archive"]
                    for program in record["programs"].values()
                }
                self.assertEqual(len(expected), 2, target)
                with (
                    mock.patch.object(
                        acquire_inputs.urllib.request, "urlopen", side_effect=urlopen
                    ),
                    self.assertRaises(Attempted),
                ):
                    acquire_inputs.acquire(target, output)
                self.assertEqual(sorted(path.name for path in output.iterdir()), [])


# --------------------------------------------------------------------------
# prepare_gcc_runtime_inputs.py: explicit native Linux GCC runtime input prep
# --------------------------------------------------------------------------

GCC_LIBRARY_NAMES = ("libstdc++.a", "libgcc.a", "libgcc_eh.a")
GCC_NOTICE_BYTES = {
    "COPYING3": b"fixture GPLv3 notice text\n",
    "COPYING.RUNTIME": b"fixture GCC runtime library exception text\n",
}
PROVENANCE_KEYS = {
    "schema_version",
    "compiler_sha256",
    "package",
    "source",
    "static_libraries",
}


class GccRuntimeInputPreparationTests(unittest.TestCase):
    """Windows-host platform-neutral contracts for the Linux-only input helper.

    The native Linux guard is satisfied by patching ``sys.platform`` and every
    ``-print-file-name`` compiler query is mocked; no compiler runs here. Real
    toolchain measurement stays pending on a GitHub Linux runner.
    """

    @classmethod
    def setUpClass(cls) -> None:
        # Imported here so a missing producer fails these tests loudly while the
        # acquisition contracts above remain runnable on their own.
        import prepare_gcc_runtime_inputs

        cls.prep = prepare_gcc_runtime_inputs

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name).resolve()
        self.toolchain = root / "toolchain"
        self.notices = root / "notices"
        self.output = root / "prepared" / "gcc-runtime"
        self.toolchain.mkdir()
        self.notices.mkdir()
        self.compiler = self.toolchain / "g++"
        self.compiler.write_bytes(b"fixture selected g++ bytes\n")
        self.libraries = {}
        for name in GCC_LIBRARY_NAMES:
            path = self.toolchain / "lib" / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(f"fixture static archive {name}\n".encode())
            self.libraries[name] = path
        for name, data in GCC_NOTICE_BYTES.items():
            (self.notices / name).write_bytes(data)
        self.answers: dict[str, str] = {
            name: str(path) for name, path in self.libraries.items()
        }
        self.queries: list[tuple[list[str], dict]] = []

    def query(self, argv, **kwargs) -> str:
        self.queries.append((list(argv), kwargs))
        self.assertEqual(kwargs.get("text"), True)
        self.assertIsNotNone(kwargs.get("timeout"))
        prefix = "-print-file-name="
        self.assertEqual(len(argv), 2)
        self.assertTrue(argv[1].startswith(prefix), argv)
        answer = self.answers[argv[1][len(prefix) :]]
        if isinstance(answer, BaseException):
            raise answer
        return answer + "\n"

    def run_prepare(
        self,
        *,
        platform: str = "linux",
        package: str = "gcc-toolset-12-gcc-c++-12.2.1-7.el8",
        source: str = "gcc-toolset-12-gcc-12.2.1-7.el8.src.rpm",
        compiler: Path | None = None,
    ):
        with (
            mock.patch.object(self.prep.sys, "platform", platform),
            mock.patch.object(
                self.prep.subprocess, "check_output", side_effect=self.query
            ),
            mock.patch.object(
                self.prep.subprocess,
                "run",
                side_effect=AssertionError("no process may run"),
            ),
        ):
            return self.prep.prepare(
                compiler or self.compiler, self.notices, package, source, self.output
            )

    def assert_nothing_published(self) -> None:
        self.assertFalse(
            self.output.exists(),
            "failed preparation must not create its output directory",
        )

    def test_measures_selected_compiler_libraries_and_writes_inputs_as_supplied(
        self,
    ) -> None:
        package = "gcc-toolset-12-gcc-c++ 12.2.1-7.el8 (x86_64)"
        source = "https://vault.example.invalid/gcc-toolset-12-gcc-12.2.1-7.el8.src.rpm"
        provenance = self.run_prepare(package=package, source=source)
        expected = {
            "schema_version": 1,
            "compiler_sha256": sha256(self.compiler.read_bytes()),
            "package": package,
            "source": source,
            "static_libraries": {
                name: sha256(path.read_bytes()) for name, path in self.libraries.items()
            },
        }
        self.assertEqual(provenance, expected)
        self.assertEqual(set(provenance), PROVENANCE_KEYS)
        self.assertIs(type(provenance["schema_version"]), int)
        self.assertEqual(
            sorted(path.name for path in self.output.iterdir()),
            sorted(["COPYING3", "COPYING.RUNTIME", "provenance.json"]),
        )
        for name, data in GCC_NOTICE_BYTES.items():
            self.assertEqual((self.output / name).read_bytes(), data)
        written = (self.output / "provenance.json").read_bytes()
        self.assertTrue(written.endswith(b"\n"))
        self.assertEqual(analysis_tools.strict_json(written), expected)
        self.assertEqual(
            [argv for argv, _ in self.queries],
            [
                [str(self.compiler), f"-print-file-name={name}"]
                for name in GCC_LIBRARY_NAMES
            ],
        )

    def test_library_hashes_are_measured_from_the_reported_bytes(self) -> None:
        relocated = self.toolchain / "other" / "libgcc.a"
        relocated.parent.mkdir()
        relocated.write_bytes(
            b"different libgcc.a bytes reported by the selected compiler\n"
        )
        self.answers["libgcc.a"] = str(relocated)
        provenance = self.run_prepare()
        self.assertEqual(
            provenance["static_libraries"]["libgcc.a"], sha256(relocated.read_bytes())
        )
        self.assertNotEqual(
            provenance["static_libraries"]["libgcc.a"],
            sha256(self.libraries["libgcc.a"].read_bytes()),
        )
        self.assertEqual(
            provenance["static_libraries"]["libstdc++.a"],
            sha256(self.libraries["libstdc++.a"].read_bytes()),
        )

    def test_compiler_identity_is_the_resolved_selected_file(self) -> None:
        link = self.toolchain / "c++"
        symlink_or_skip(link, self.compiler, directory=False)
        provenance = self.run_prepare(compiler=link)
        self.assertEqual(
            provenance["compiler_sha256"], sha256(self.compiler.read_bytes())
        )
        self.assertTrue(all(argv[0] == str(self.compiler) for argv, _ in self.queries))

    def test_native_linux_guard_runs_before_any_query_or_write(self) -> None:
        for platform in ("win32", "darwin", "cygwin", "linux2"):
            with (
                self.subTest(platform),
                self.assertRaisesRegex(RuntimeError, "requires native Linux"),
            ):
                self.run_prepare(platform=platform)
        self.assertEqual(self.queries, [])
        self.assert_nothing_published()

    def test_package_and_source_references_are_required(self) -> None:
        for field in ("package", "source"):
            for value in ("", "   ", "\t\n"):
                with self.subTest(field=field, value=value):
                    with self.assertRaisesRegex(
                        RuntimeError, "compiler package and corresponding source"
                    ):
                        self.run_prepare(**{field: value})
        self.assertEqual(self.queries, [])
        self.assert_nothing_published()

    def test_compiler_must_be_an_existing_regular_file(self) -> None:
        with self.assertRaises(OSError):
            self.run_prepare(compiler=self.toolchain / "missing-g++")
        with self.assertRaisesRegex(RuntimeError, "not a regular file"):
            self.run_prepare(compiler=self.toolchain / "lib")
        self.assertEqual(self.queries, [])
        self.assert_nothing_published()

    def test_toolchain_notices_must_be_present_nonempty_regular_files(self) -> None:
        for name, data in GCC_NOTICE_BYTES.items():
            path = self.notices / name
            with self.subTest(case=f"missing {name}"):
                path.unlink()
                with self.assertRaisesRegex(
                    RuntimeError, "Supply the selected toolchain notice"
                ):
                    self.run_prepare()
            with self.subTest(case=f"directory {name}"):
                path.mkdir()
                with self.assertRaisesRegex(
                    RuntimeError, "Supply the selected toolchain notice"
                ):
                    self.run_prepare()
                path.rmdir()
            with self.subTest(case=f"empty {name}"):
                path.write_bytes(b"")
                with self.assertRaisesRegex(RuntimeError, "Toolchain notice is empty"):
                    self.run_prepare()
            path.write_bytes(data)
        self.assertEqual(self.queries, [])
        self.assert_nothing_published()

    def test_symlinked_notice_is_refused(self) -> None:
        real = self.toolchain / "COPYING3.real"
        real.write_bytes(GCC_NOTICE_BYTES["COPYING3"])
        (self.notices / "COPYING3").unlink()
        symlink_or_skip(self.notices / "COPYING3", real, directory=False)
        with self.assertRaisesRegex(
            RuntimeError, "Supply the selected toolchain notice"
        ):
            self.run_prepare()
        self.assert_nothing_published()

    def test_every_static_library_must_be_located_as_an_absolute_regular_file(
        self,
    ) -> None:
        for name in GCC_LIBRARY_NAMES:
            # GCC echoes the bare name when it cannot find a library.
            cases = {
                "bare name": name,
                "relative path": f"lib/{name}",
                "missing absolute path": str(self.toolchain / "absent" / name),
                "directory": str(self.toolchain / "lib"),
                "empty": "",
            }
            for label, answer in cases.items():
                with self.subTest(library=name, case=label):
                    self.answers = {
                        key: str(path) for key, path in self.libraries.items()
                    }
                    self.answers[name] = answer
                    with self.assertRaisesRegex(
                        RuntimeError,
                        re.escape(f"Selected compiler cannot locate {name}"),
                    ):
                        self.run_prepare()
                    self.assert_nothing_published()

    def test_compiler_query_failures_propagate_without_output(self) -> None:
        failures = {
            "nonzero exit": subprocess_error("called"),
            "timeout": subprocess_error("timeout"),
            "unexecutable": PermissionError("not executable"),
        }
        for label, error in failures.items():
            with self.subTest(label):
                self.answers = {key: str(path) for key, path in self.libraries.items()}
                self.answers["libgcc.a"] = error
                with self.assertRaises(type(error)):
                    self.run_prepare()
                self.assert_nothing_published()

    def test_existing_output_is_never_replaced(self) -> None:
        self.output.mkdir(parents=True)
        accepted = {
            "COPYING3": b"accepted notice\n",
            "provenance.json": b'{"accepted": true}\n',
        }
        for name, data in accepted.items():
            (self.output / name).write_bytes(data)
        with self.assertRaises(FileExistsError):
            self.run_prepare()
        self.assertEqual(
            {path.name: path.read_bytes() for path in self.output.iterdir()}, accepted
        )
        empty = self.output.parent / "empty"
        empty.mkdir()
        self.output = empty
        with self.assertRaises(FileExistsError):
            self.run_prepare()
        self.assertEqual(list(empty.iterdir()), [])
        blocker = self.output.parent / "file"
        blocker.write_bytes(b"keep")
        self.output = blocker
        with self.assertRaises(OSError):
            self.run_prepare()
        self.assertEqual(blocker.read_bytes(), b"keep")

    def test_prepared_identity_matches_the_staging_input_schema(self) -> None:
        provenance = self.run_prepare()
        document = analysis_tools.strict_json(
            (self.output / "provenance.json").read_bytes()
        )
        self.assertEqual(set(document), PROVENANCE_KEYS)
        self.assertIs(type(document["schema_version"]), int)
        self.assertEqual(document["schema_version"], 1)
        self.assertLessEqual(
            {"libstdc++.a", "libgcc.a"}, set(document["static_libraries"])
        )
        self.assertLessEqual(set(document["static_libraries"]), set(GCC_LIBRARY_NAMES))
        for value in [
            document["compiler_sha256"],
            *document["static_libraries"].values(),
        ]:
            self.assertRegex(value, r"\A[0-9a-f]{64}\Z")
        self.assertEqual(document, provenance)


def subprocess_error(kind: str) -> Exception:
    import subprocess

    if kind == "timeout":
        return subprocess.TimeoutExpired(["g++"], 10)
    return subprocess.CalledProcessError(1, ["g++"])


class GccRuntimeInputCommandLineTests(unittest.TestCase):
    """CLI routing for prepare_gcc_runtime_inputs.py; ``prepare`` is mocked."""

    @classmethod
    def setUpClass(cls) -> None:
        import prepare_gcc_runtime_inputs

        cls.prep = prepare_gcc_runtime_inputs

    ARGV = [
        "prepare_gcc_runtime_inputs.py",
        "--compiler",
        "toolchain/g++",
        "--notices",
        "notices",
        "--package",
        "fixture package",
        "--source",
        "fixture source",
        "--output",
        "out/gcc-runtime",
    ]

    def invoke(self, argv, behavior):
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(self.prep, "prepare", side_effect=behavior) as prepared,
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            try:
                code = self.prep.main()
            except SystemExit as exit_:
                code = exit_.code
        return code, stdout.getvalue(), stderr.getvalue(), prepared

    def test_success_prints_the_provenance_receipt(self) -> None:
        receipt = {"schema_version": 1, "package": "fixture package"}
        code, stdout, stderr, prepared = self.invoke(self.ARGV, lambda *args: receipt)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout), receipt)
        self.assertEqual(stderr, "")
        prepared.assert_called_once_with(
            Path("toolchain/g++"),
            Path("notices"),
            "fixture package",
            "fixture source",
            Path("out/gcc-runtime"),
        )

    def test_failures_exit_2_with_a_diagnostic_and_no_receipt(self) -> None:
        for error in (
            RuntimeError("requires native Linux"),
            FileExistsError("out/gcc-runtime"),
            ValueError("bad"),
            subprocess_error("called"),
            subprocess_error("timeout"),
        ):
            with self.subTest(type(error).__name__):
                code, stdout, stderr, _ = self.invoke(self.ARGV, error)
                self.assertEqual(code, 2)
                self.assertEqual(stdout, "")
                self.assertTrue(
                    stderr.startswith("GCC runtime input preparation failed: "), stderr
                )

    def test_every_explicit_argument_is_required(self) -> None:
        for flag in ("--compiler", "--notices", "--package", "--source", "--output"):
            with self.subTest(flag):
                index = self.ARGV.index(flag)
                argv = self.ARGV[:index] + self.ARGV[index + 2 :]
                code, stdout, _, prepared = self.invoke(
                    argv, AssertionError("must not prepare")
                )
                self.assertEqual(code, 2)
                self.assertEqual(stdout, "")
                prepared.assert_not_called()


if __name__ == "__main__":
    unittest.main()
