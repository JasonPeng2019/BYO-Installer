"""Local native analyzer recipes; never acquisition, installation or cross execution."""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

import analysis_tools as tools
import native_formats


def _macos_translation_identity() -> dict:
    # Apple's documented sysctlbyname contract: ENOENT means native; other
    # errors are unknown. Query this Python process rather than a subprocess
    # which could independently select a different universal-binary slice.
    # https://developer.apple.com/documentation/apple-silicon/about-the-rosetta-translation-environment
    library = ctypes.CDLL(None, use_errno=True)
    function = library.sysctlbyname
    function.argtypes = [
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    function.restype = ctypes.c_int
    translated = ctypes.c_int()
    size = ctypes.c_size_t(ctypes.sizeof(translated))
    result = function(
        b"sysctl.proc_translated", ctypes.byref(translated), ctypes.byref(size), None, 0
    )
    error = ctypes.get_errno() if result else 0
    if result and error != errno.ENOENT:
        raise RuntimeError(
            f"Cannot establish native macOS process architecture: sysctl errno {error}"
        )
    if not result and (
        size.value != ctypes.sizeof(translated) or translated.value not in {0, 1}
    ):
        raise RuntimeError("Invalid macOS translation identity")
    value = 0 if result else translated.value
    if value:
        raise RuntimeError(
            "Translated x86_64 process on Apple silicon is not an Intel-native builder"
        )
    return {
        "sysctl": "sysctl.proc_translated",
        "result": result,
        "errno": error,
        "translated": value,
    }


def _regular(path: Path) -> None:
    if not path.is_file() or path.is_symlink() or path.is_junction():
        raise RuntimeError(f"Supply a regular local input, without links: {path}")
    for parent in path.parents:
        if parent.is_symlink() or parent.is_junction():
            raise RuntimeError(f"Local input traverses a link: {path}")


def _tool(name: str) -> dict:
    found = shutil.which(name)
    if not found:
        raise RuntimeError(
            f"Native analyzer recipe requires installed {name}; no automatic installation is performed"
        )
    path = Path(found).resolve(strict=True)
    return {"path": str(path), "sha256": tools.sha256(path.read_bytes())}


def _command(
    argv: list[str],
    evidence: Path,
    receipt: dict,
    step: str,
    *,
    cwd: Path | None = None,
) -> str:
    result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=False)
    receipt["commands"].append(
        {
            "step": step,
            "argv": argv,
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    )
    tools.write_json(evidence / "cppcheck-build.json", receipt)
    if result.returncode:
        raise RuntimeError(
            f"Native analyzer {step} failed ({result.returncode}); see {evidence / 'cppcheck-build.json'}"
        )
    return result.stdout.strip() or result.stderr.strip()


def _extract_source(archive_path: Path, source_dir: Path, prefix: str) -> None:
    with tarfile.open(archive_path, "r:gz") as archive:
        seen = set()
        for member in archive.getmembers():
            if member.name.rstrip("/") == prefix.rstrip("/") and member.isdir():
                continue
            if not member.name.startswith(prefix):
                raise RuntimeError("Cppcheck source prefix changed")
            relative = tools.safe_relative(member.name[len(prefix) :].rstrip("/"))
            if relative.casefold() in seen or not (member.isfile() or member.isdir()):
                raise RuntimeError(
                    "Cppcheck source archive contains duplicate/link/special entries"
                )
            seen.add(relative.casefold())
            target = source_dir / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
                target.chmod(0o644)


def stage_native(
    bundle: Path,
    input_dir: Path,
    evidence: Path,
    cmake: Path | None = None,
    *,
    target: str | None = None,
) -> dict:
    target = (
        tools.canonical_target(target) if target is not None else tools.host_target()
    )
    if (
        target == "windows-x86_64"
        or tools.host_target() != target
        or os.name != "posix"
    ):
        raise RuntimeError(
            f"Native analyzer staging requires the matching native host: {target}; cross execution is unsupported"
        )
    lock = tools.load_lock(target=target)
    archives = {}
    for name, program in lock["programs"].items():
        source = program["source"]
        archive = input_dir / source["archive"]
        _regular(archive)
        if tools.sha256(archive.read_bytes()) != source["sha256"] or (
            "size" in source and archive.stat().st_size != source["size"]
        ):
            raise RuntimeError(f"Supply the pinned local {name} archive: {archive}")
        archives[name] = archive
    evidence.mkdir(parents=True, exist_ok=True)
    recipe = lock["programs"]["cppcheck"]["recipe"]
    receipt = {
        "schema_version": 1,
        "target": target,
        "actual_host": {
            "system": platform.system(),
            "architecture": platform.machine(),
            "release": platform.release(),
        },
        "lock_sha256": tools.sha256(
            (tools.ROOT / "release/analysis-tools.lock.json").read_bytes()
        ),
        "sources": {name: p["source"] for name, p in lock["programs"].items()},
        "recipe": recipe,
        "commands": [],
        "transformations": [],
        "tools": {},
    }
    cmake_path = Path(tools.find_cmake(cmake)).resolve(strict=True)
    receipt["tools"]["cmake"] = {
        "path": str(cmake_path),
        "sha256": tools.sha256(cmake_path.read_bytes()),
    }
    receipt["cmake"] = _command(
        [str(cmake_path), "--version"], evidence, receipt, "cmake-identity"
    ).splitlines()[0]
    match = re.search(r"cmake version (\d+)\.(\d+)", receipt["cmake"])
    if not match or tuple(map(int, match.groups())) < (3, 22):
        raise RuntimeError("Native Cppcheck requires CMake >=3.22")
    gcc_input = None
    gcc_libraries = {}
    if lock["platform"] == "linux":
        baseline = _command(
            ["getconf", "GNU_LIBC_VERSION"], evidence, receipt, "glibc-baseline"
        )
        if baseline != "glibc 2.28":
            raise RuntimeError(
                f"Linux Cppcheck recipe requires a controlled glibc 2.28 native builder, observed {baseline}"
            )
        receipt["actual_host"]["baseline"] = baseline
        receipt["tools"]["compiler"] = _tool("g++")
        compiler = receipt["tools"]["compiler"]["path"]
        gcc_dir = input_dir / "gcc-runtime"
        for name in ("COPYING3", "COPYING.RUNTIME", "provenance.json"):
            _regular(gcc_dir / name)
        gcc_input = tools.strict_json((gcc_dir / "provenance.json").read_bytes())
        if (
            set(gcc_input)
            != {
                "schema_version",
                "compiler_sha256",
                "package",
                "source",
                "static_libraries",
            }
            or type(gcc_input["schema_version"]) is not int
            or gcc_input["schema_version"] != 1
            or gcc_input["compiler_sha256"] != receipt["tools"]["compiler"]["sha256"]
            or any(
                not isinstance(gcc_input[key], str) or not gcc_input[key]
                for key in ("package", "source")
            )
            or not isinstance(gcc_input["static_libraries"], dict)
            or not {"libstdc++.a", "libgcc.a"} <= set(gcc_input["static_libraries"])
            or set(gcc_input["static_libraries"])
            - {"libstdc++.a", "libgcc.a", "libgcc_eh.a"}
            or any(
                not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value)
                for value in gcc_input["static_libraries"].values()
            )
        ):
            raise RuntimeError(
                "gcc-runtime/provenance.json must bind the actual compiler, package/source reference and selected static library hashes"
            )
        receipt["gcc_input_sha256"] = tools.sha256(
            (gcc_dir / "provenance.json").read_bytes()
        )
        for name in gcc_input["static_libraries"]:
            supplied_path = _command(
                [compiler, "-print-file-name=" + name],
                evidence,
                receipt,
                "static-library-" + name,
            )
            selected = Path(supplied_path).resolve(strict=True)
            _regular(selected)
            digest = tools.sha256(selected.read_bytes())
            if gcc_input["static_libraries"][name] != digest:
                raise RuntimeError(
                    f"Supply matching GCC static library provenance: {name} ({digest})"
                )
            gcc_libraries[name] = {
                "path": selected,
                "sha256": digest,
                "size": selected.stat().st_size,
            }
        receipt["tools"]["patchelf"] = _tool("patchelf")
        _command(
            [receipt["tools"]["patchelf"]["path"], "--version"],
            evidence,
            receipt,
            "patchelf-identity",
        )
    else:
        receipt["actual_host"]["baseline"] = _command(
            ["sw_vers", "-productVersion"], evidence, receipt, "macos-version"
        )
        host_version = receipt["actual_host"]["baseline"]
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", host_version) or tuple(
            map(int, host_version.split(".")[:2])
        ) < (12, 0):
            raise RuntimeError(
                f"Native macOS builder must run macOS 12 or newer, observed {host_version}"
            )
        receipt["actual_host"]["translation_identity"] = _macos_translation_identity()
        compiler = _command(
            ["xcrun", "--find", "clang++"], evidence, receipt, "xcode-compiler"
        )
        receipt["tools"]["compiler"] = {
            "path": compiler,
            "sha256": tools.sha256(Path(compiler).read_bytes()),
        }
        receipt["sdk"] = _command(
            ["xcrun", "--show-sdk-path"], evidence, receipt, "xcode-sdk-path"
        )
        receipt["sdk_version"] = _command(
            ["xcrun", "--show-sdk-version"], evidence, receipt, "xcode-sdk-version"
        )
        sdk = Path(receipt["sdk"]).resolve(strict=True)
        receipt["sdk_settings"] = {
            name: {
                "sha256": tools.sha256((sdk / name).read_bytes()),
                "size": (sdk / name).stat().st_size,
            }
            for name in ("SDKSettings.json", "SDKSettings.plist")
            if (sdk / name).is_file()
        }
        if not receipt["sdk_settings"]:
            raise RuntimeError(
                "Xcode SDK identity metadata is missing; supply installed Xcode command-line tools"
            )
        receipt["tools"]["lipo"] = _tool("lipo")
        _command(
            [receipt["tools"]["lipo"]["path"], "-version"],
            evidence,
            receipt,
            "lipo-identity",
        )
    receipt["compiler"] = _command(
        [compiler, "--version"], evidence, receipt, "compiler-identity"
    )
    receipt["tools"]["make"] = _tool("make")
    _command(
        [receipt["tools"]["make"]["path"], "--version"],
        evidence,
        receipt,
        "make-identity",
    )
    with tempfile.TemporaryDirectory(prefix="byo-cppcheck-") as temporary:
        # Canonicalize this owned root before deriving paths: macOS /var is a
        # system alias. Keep no-follow validation on inputs and generated files.
        work = Path(temporary).resolve(strict=True)
        source_dir, build_dir = work / "source", work / "build"
        source_dir.mkdir()
        prefix = lock["programs"]["cppcheck"]["source"]["archive_prefix"]
        _extract_source(archives["cppcheck"], source_dir, prefix)
        actual_data = {
            prefix + path.relative_to(source_dir).as_posix()
            for pattern in ("cfg/*.cfg", "platforms/*.xml")
            for path in source_dir.glob(pattern)
        }
        expected_data = {
            leaf["upstream_path"]
            for leaf in lock["programs"]["cppcheck"]["selected_files"]
            if leaf["kind"] == "analysis-data"
        }
        if actual_data != expected_data:
            raise RuntimeError(
                "Cppcheck exact source data selection is incomplete or stale"
            )
        options = source_dir / "cmake/compileroptions.cmake"
        if (
            tools.sha256(options.read_bytes())
            != recipe["upstream_compileroptions_sha256"]
        ):
            raise RuntimeError(
                "Native Cppcheck compiler-option source identity changed"
            )
        prefix_maps = " ".join(
            shlex.quote(f"-f{kind}-prefix-map={path}={stable}")
            for path, stable in (
                (source_dir, "/cppcheck-src"),
                (build_dir, "/cppcheck-build"),
            )
            for kind in ("file", "debug")
        )
        substitutions = {
            "source_dir": str(source_dir),
            "build_dir": str(build_dir),
            "prefix_maps": prefix_maps,
            "compiler": compiler,
        }
        configure = [part.format(**substitutions) for part in recipe["configure_argv"]]
        configure[0] = str(cmake_path)
        if gcc_input:
            configure = [
                part + " " + shlex.quote(f"-Wl,-Map,{build_dir / 'cppcheck-link.map'}")
                if part.startswith("-DCMAKE_EXE_LINKER_FLAGS=")
                else part
                for part in configure
            ]
        _command(configure, evidence, receipt, "configure")
        cache = (build_dir / "CMakeCache.txt").read_text()
        compiler_record = next(build_dir.glob("CMakeFiles/*/CMakeCXXCompiler.cmake"))
        text = compiler_record.read_text()
        for field in (
            "CMAKE_CXX_COMPILER",
            "CMAKE_CXX_COMPILER_ID",
            "CMAKE_CXX_COMPILER_VERSION",
        ):
            match = re.search(r"set\(" + field + r'\s+"?([^"\n)]+)"?\)', text)
            if not match:
                raise RuntimeError(f"CMake did not record actual {field}")
            receipt[field] = match[1]
        if Path(receipt["CMAKE_CXX_COMPILER"]).resolve() != Path(
            compiler
        ).resolve() or (gcc_input and receipt["CMAKE_CXX_COMPILER_ID"] != "GNU"):
            raise RuntimeError(
                "Native Cppcheck compiler differs from the approved recipe"
            )
        linker_match = re.search(r"^CMAKE_LINKER:[^=]+=(.+)$", cache, re.MULTILINE)
        if not linker_match:
            raise RuntimeError("CMake did not record actual linker")
        linker = Path(linker_match[1]).resolve(strict=True)
        receipt["tools"]["linker"] = {
            "path": str(linker),
            "sha256": tools.sha256(linker.read_bytes()),
        }
        receipt["linker"] = _command(
            [str(linker), "--version" if gcc_input else "-v"],
            evidence,
            receipt,
            "linker-identity",
        )
        shutil.copy2(compiler_record, evidence / "CMakeCXXCompiler.cmake")
        shutil.copy2(build_dir / "CMakeCache.txt", evidence / "CMakeCache.txt")
        build_argv = [part.format(**substitutions) for part in recipe["build_argv"]]
        build_argv[0] = str(cmake_path)
        _command(build_argv, evidence, receipt, "build")
        if gcc_input:
            link_map = (build_dir / "cppcheck-link.map").read_text()
            shutil.copy2(
                build_dir / "cppcheck-link.map", evidence / "cppcheck-link.map"
            )
            libraries = {}
            mapped_archives = {
                Path(match[1].strip()).resolve()
                for match in re.finditer(
                    r"(?m)^(?:LOAD[ \t]+)?(/[^\n(]+?\.a)(?=\(|[ \t]*$)", link_map
                )
            }
            selected_runtime_paths = {
                identity["path"] for identity in gcc_libraries.values()
            }
            if any(
                path.name in {"libstdc++.a", "libgcc.a", "libgcc_eh.a"}
                and path not in selected_runtime_paths
                for path in mapped_archives
            ):
                raise RuntimeError(
                    "Link map contains an unrecorded GCC static runtime input; supply its matching compiler-selected provenance"
                )
            for name, selected_identity in gcc_libraries.items():
                selected = selected_identity["path"]
                if selected not in mapped_archives:
                    if name in {"libstdc++.a", "libgcc.a"}:
                        raise RuntimeError(
                            f"Link map does not prove actual static input: {name}"
                        )
                    continue
                libraries[name] = {
                    key: selected_identity[key] for key in ("sha256", "size")
                }
                if tools.sha256(selected.read_bytes()) != selected_identity["sha256"]:
                    raise RuntimeError(
                        f"GCC static runtime input changed during build: {name}"
                    )
                receipt.setdefault("static_library_paths", {})[name] = str(selected)
            notices = {}
            for name in ("COPYING3", "COPYING.RUNTIME"):
                data = (input_dir / "gcc-runtime" / name).read_bytes()
                if not data:
                    raise RuntimeError(f"Empty GCC runtime notice: {name}")
                target_path = bundle / "analysis/cppcheck/licenses" / ("GCC-" + name)
                target_path.parent.mkdir(parents=True, exist_ok=True)
                target_path.write_bytes(data)
                notices["analysis/cppcheck/licenses/GCC-" + name] = {
                    "sha256": tools.sha256(data),
                    "size": len(data),
                }
            receipt["static_runtime"] = {
                "package": gcc_input["package"],
                "source": gcc_input["source"],
                "compiler_sha256": gcc_input["compiler_sha256"],
                "libraries": libraries,
                "notices": notices,
            }
        program = lock["programs"]["cppcheck"]
        output = build_dir / recipe["output"]
        _regular(output)
        executable = bundle / program["executable"]
        executable.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(output, executable)
        receipt["recipe_output"] = {
            "sha256": tools.sha256(output.read_bytes()),
            "size": output.stat().st_size,
        }
        for leaf in program["selected_files"]:
            if not leaf["upstream_path"].startswith(prefix):
                raise RuntimeError("Cppcheck selection escaped source prefix")
            path = bundle / leaf["runtime_path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(
                tools.checked_bytes(
                    (source_dir / leaf["upstream_path"][len(prefix) :]).read_bytes(),
                    leaf,
                )
            )
    program = lock["programs"]["clangd"]
    with zipfile.ZipFile(archives["clangd"]) as archive:
        seen, actual = set(), set()
        prefix = program["source"]["archive_prefix"]
        for info in archive.infolist():
            path = tools.safe_relative(info.filename.rstrip("/"))
            mode = info.external_attr >> 16
            if path.casefold() in seen or stat.S_IFMT(mode) not in {
                0,
                stat.S_IFREG,
                stat.S_IFDIR,
            }:
                raise RuntimeError(
                    "Native clangd input contains duplicates/links/special entries"
                )
            seen.add(path.casefold())
            if path != prefix.rstrip("/") and not path.startswith(prefix):
                raise RuntimeError("Native clangd archive prefix changed")
            if info.is_dir():
                continue
            relative = path[len(prefix) :]
            if relative in {"bin/clangd", "LICENSE.TXT"} or relative.startswith(
                ("lib/clang/23/include/", "lib/clang/23/share/")
            ):
                actual.add(path)
        if actual != {leaf["upstream_path"] for leaf in program["selected_files"]}:
            raise RuntimeError(
                "Native clangd exact include/share input selection changed"
            )
        for leaf in program["selected_files"]:
            path = bundle / leaf["runtime_path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(
                tools.checked_bytes(archive.read(leaf["upstream_path"]), leaf)
            )
    executable = bundle / program["executable"]
    before = tools.sha256(executable.read_bytes())
    if lock["platform"] == "linux":
        _command(
            [receipt["tools"]["patchelf"]["path"], "--remove-rpath", str(executable)],
            evidence,
            receipt,
            "remove-clangd-runpath",
        )
    else:
        thin = executable.with_name("clangd.thin")
        _command(
            [
                receipt["tools"]["lipo"]["path"],
                str(executable),
                "-thin",
                "arm64" if lock["architecture"] == "aarch64" else "x86_64",
                "-output",
                str(thin),
            ],
            evidence,
            receipt,
            "thin-clangd",
        )
        os.replace(thin, executable)
    receipt["transformations"].append(
        {
            "path": program["executable"],
            "before_sha256": before,
            "after_sha256": tools.sha256(executable.read_bytes()),
        }
    )
    tools.write_json(bundle / "analysis/runtime.json", tools.mapping(lock))
    normalize_modes(bundle, lock)
    receipt["native_closure_before_strip"] = native_formats.validate_closure(
        lock, lambda name: (bundle / name).read_bytes()
    )
    tools.write_json(evidence / "cppcheck-build.json", receipt)
    return receipt


def normalize_modes(bundle: Path, lock: dict) -> None:
    executables = {p["executable"] for p in lock["programs"].values()}
    for path in (bundle / "analysis", *(bundle / "analysis").rglob("*")):
        if path.is_symlink() or path.is_junction():
            raise RuntimeError(f"Native analysis payload contains a link: {path}")
        if not (path.is_dir() or path.is_file()):
            raise RuntimeError(
                f"Native analysis payload contains a special file: {path}"
            )
        path.chmod(
            0o755
            if path.is_dir() or path.relative_to(bundle).as_posix() in executables
            else 0o644
        )


def thin_macos_bundle(bundle: Path, lock: dict, receipt: dict, evidence: Path) -> None:
    """Thin selected upstream wheel images too; the runtime target is never universal."""
    if tools.host_target() != f"macos-{lock['architecture']}" or os.name != "posix":
        raise RuntimeError("Mach-O thinning requires the matching native macOS host")
    lipo = receipt["tools"]["lipo"]["path"]
    for path in sorted(bundle.rglob("*")):
        if path.is_symlink() or path.is_junction():
            raise RuntimeError(f"Native macOS payload contains a link: {path}")
        if not path.is_file():
            continue
        with path.open("rb") as stream:
            magic = stream.read(4)
        if magic not in {
            b"\xca\xfe\xba\xbe",
            b"\xbe\xba\xfe\xca",
            b"\xca\xfe\xba\xbf",
            b"\xbf\xba\xfe\xca",
        }:
            continue
        thin = path.with_name(path.name + ".byo-thin")
        if thin.exists():
            raise RuntimeError(f"Native thinning scratch already exists: {thin}")
        before = tools.sha256(path.read_bytes())
        _command(
            [
                lipo,
                str(path),
                "-thin",
                "arm64" if lock["architecture"] == "aarch64" else "x86_64",
                "-output",
                str(thin),
            ],
            evidence,
            receipt,
            "thin-native-dependency",
        )
        os.replace(thin, path)
        receipt["transformations"].append(
            {
                "path": path.relative_to(bundle).as_posix(),
                "before_sha256": before,
                "after_sha256": tools.sha256(path.read_bytes()),
            }
        )
    tools.write_json(evidence / "cppcheck-build.json", receipt)
