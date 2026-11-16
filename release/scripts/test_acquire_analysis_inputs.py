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
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import acquire_analysis_inputs as acquire_inputs
import analysis_tools


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

    def test_https_redirect_to_plain_http_is_refused(self) -> None:
        clangd_url = self.lock["programs"]["clangd"]["source"]["url"]
        urlopen, _ = serve(
            self.urls(), {clangd_url: "http://mirror.invalid/clangd-windows.zip"}
        )
        with self.assertRaisesRegex(RuntimeError, "Insecure archive redirect"):
            self.acquire(urlopen)
        self.assertFalse((self.output / "clangd-windows.zip").exists())
        self.assertEqual(partials(self.output), [])

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


if __name__ == "__main__":
    unittest.main()
