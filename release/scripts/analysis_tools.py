"""Pinned four-target analysis staging and final-byte checks for the release builder.

Inputs are supplied local archives. This module never downloads programs and has
no runtime resolver: analysis/runtime.json is the product's only mapping.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
TARGETS = {
    "windows-x86_64": ("windows", "x86_64"),
    "macos-aarch64": ("macos", "aarch64"),
    "macos-x86_64": ("macos", "x86_64"),
    "linux-x86_64": ("linux", "x86_64"),
}


def canonical_target(target: str) -> str:
    if target == "linux-x86_64-glibc-2.28":
        target = "linux-x86_64"
    if target not in TARGETS:
        raise RuntimeError(f"Unsupported analysis target: {target!r}")
    return target


def host_target() -> str:
    system = {"Windows": "windows", "Darwin": "macos", "Linux": "linux"}.get(
        platform.system()
    )
    machine = platform.machine().lower()
    arch = {
        "amd64": "x86_64",
        "x86_64": "x86_64",
        "arm64": "aarch64",
        "aarch64": "aarch64",
    }.get(machine)
    return canonical_target(f"{system}-{arch}")


def strict_json(data: bytes | str) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise RuntimeError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    value = json.loads(data, object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise RuntimeError("Expected a JSON object")
    return value


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def safe_relative(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise RuntimeError(f"Unsafe Windows payload path: {value!r}")
    for part in value.split("/"):
        stem = part.split(".")[0].upper()
        if (
            not part
            or part in {".", ".."}
            or part.endswith((".", " "))
            or any(ord(c) < 32 or c in '<>:"|?*' for c in part)
            or stem in {"CON", "PRN", "AUX", "NUL"}
            or re.fullmatch(r"(?:COM|LPT)[1-9]", stem)
        ):
            raise RuntimeError(f"Unsafe Windows payload path: {value!r}")
    return value


def safe_namespace(leaves: list[str]) -> None:
    """Require exact ancestor spelling, no case aliases, and no file ancestors."""
    names = {}
    files = set(leaves)
    for leaf in leaves:
        safe_relative(leaf)
        for path in (PurePosixPath(leaf), *PurePosixPath(leaf).parents):
            name = str(path)
            if name == ".":
                continue
            old = names.setdefault(name.casefold(), name)
            if old != name:
                raise RuntimeError(f"Case-colliding payload namespace: {old}, {name}")
            if name != leaf and name in files:
                raise RuntimeError(f"Payload file is also an ancestor: {name}")


def load_lock(path: Path | None = None, target: str | None = None) -> dict:
    """Select an explicit target, or the supported native host; never default to Windows."""
    document = strict_json(
        Path(path or ROOT / "release/analysis-tools.lock.json").read_bytes()
    )
    target = canonical_target(target) if target is not None else host_target()
    if (
        set(document) != {"schema_version", "targets"}
        or type(document.get("schema_version")) is not int
        or document["schema_version"] != 2
        or not isinstance(document.get("targets"), dict)
        or set(document["targets"]) != set(TARGETS)
    ):
        raise RuntimeError(
            "Analysis lock v2 requires exactly the four supported targets"
        )
    lock = document["targets"][target]
    for key, identity in TARGETS.items():
        record = document["targets"][key]
        if (
            not isinstance(record, dict)
            or (record.get("platform"), record.get("architecture")) != identity
        ):
            raise RuntimeError(f"Analysis lock target record mismatch: {key}")
    if (lock.get("platform"), lock.get("architecture")) != TARGETS[target] or set(
        lock.get("programs", {})
    ) != {"cppcheck", "clangd"}:
        raise RuntimeError(f"Analysis lock target record mismatch: {target}")
    seen = set()
    for name in ("cppcheck", "clangd"):
        program = lock["programs"][name]
        suffix = ".exe" if lock["platform"] == "windows" else ""
        executable = (
            f"analysis/{name}/"
            + ("bin/clangd" if name == "clangd" else "cppcheck")
            + suffix
        )
        if (
            program.get("executable") != executable
            or not re.fullmatch(
                r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)",
                program.get("version", ""),
            )
            or not isinstance(program.get("dependencies"), list)
            or len(set(program["dependencies"])) != len(program["dependencies"])
        ):
            raise RuntimeError(f"Invalid analysis program target/identity: {name}")
        source = program["source"]
        if not re.fullmatch(
            "[0-9a-f]{64}", source.get("sha256", "")
        ) or "/" in safe_relative(source["archive"]):
            raise RuntimeError(f"Invalid pinned analysis archive: {name}")
        for leaf in program["selected_files"]:
            path = safe_relative(leaf["runtime_path"])
            safe_relative(leaf["upstream_path"])
            if path.casefold() in seen or not path.startswith(f"analysis/{name}/"):
                raise RuntimeError(f"Duplicate or misplaced selected file: {path}")
            seen.add(path.casefold())
            if (
                not re.fullmatch("[0-9a-f]{64}", leaf["sha256"])
                or type(leaf["size"]) is not int
                or leaf["size"] < 0
                or type(leaf["executable"]) is not bool
            ):
                raise RuntimeError(f"Invalid pinned file identity: {path}")
        safe_namespace(
            [f["runtime_path"] for f in program["selected_files"]]
            + program.get("additional_licenses", [])
        )
        selected_paths = {f["runtime_path"] for f in program["selected_files"]}
        if name == "cppcheck":
            required = {
                "analysis/cppcheck/cfg/std.cfg",
                "analysis/cppcheck/licenses/COPYING",
                "analysis/cppcheck/licenses/simplecpp-LICENSE",
                "analysis/cppcheck/licenses/tinyxml2-LICENSE",
                "analysis/cppcheck/licenses/picojson-LICENSE",
            }
            if not required <= selected_paths or not any(
                p.startswith("analysis/cppcheck/platforms/") and p.endswith(".xml")
                for p in selected_paths
            ):
                raise RuntimeError("Cppcheck lock omits required data/notices")
        else:
            resource_dir = (
                f"analysis/clangd/lib/clang/{program['version'].split('.')[0]}"
            )
            if (
                program.get("resource_dir") != resource_dir
                or not {
                    resource_dir + "/include/stddef.h",
                    "analysis/clangd/LICENSE.TXT",
                }
                <= selected_paths
            ):
                raise RuntimeError(
                    "clangd lock omits resources/notices or mismatches version major"
                )
    for leaf in lock.get("windows_native", {}).get("selected_files", []):
        path = safe_relative(leaf["runtime_path"])
        safe_relative(leaf["upstream_path"])
        if path.casefold() in seen or leaf["executable"] is not False:
            raise RuntimeError(f"Duplicate/executable native dependency: {path}")
        seen.add(path.casefold())
        if not re.fullmatch("[0-9a-f]{64}", leaf["sha256"]) or leaf["size"] < 0:
            raise RuntimeError(f"Invalid pinned native identity: {path}")
    return lock


def mapping(lock: dict) -> dict:
    programs = {}
    for name, program in lock["programs"].items():
        item = {
            "version": program["version"],
            "executable": program["executable"],
            "dependencies": program["dependencies"],
            "sbom_ref": f"byo-analysis:{name}",
            "licenses": [
                f["runtime_path"]
                for f in program["selected_files"]
                if f["kind"] == "license"
            ]
            + program.get("additional_licenses", []),
        }
        if name == "cppcheck":
            item.update(
                cfg_dir="analysis/cppcheck/cfg",
                platforms_dir="analysis/cppcheck/platforms",
            )
        else:
            item["resource_dir"] = program["resource_dir"]
        programs[name] = item
    return {
        "schema_version": 1,
        "platform": lock["platform"],
        "architecture": lock["architecture"],
        "programs": programs,
    }


def checked_bytes(data: bytes, leaf: dict) -> bytes:
    if len(data) != leaf["size"] or sha256(data) != leaf["sha256"]:
        raise RuntimeError(
            f"Pinned upstream bytes changed: {leaf.get('runtime_path', leaf.get('archive'))}"
        )
    return data


def find_cmake(explicit: Path | None) -> str:
    if explicit is not None:
        if not explicit.is_file():
            raise RuntimeError(f"CMake is missing: {explicit}")
        return str(explicit.resolve())
    found = shutil.which("cmake")
    if found:
        return found
    if os.name != "nt":
        raise RuntimeError(
            "Native packaging requires installed CMake >=3.22; supply --analysis-cmake. No automatic installation is performed."
        )
    locator = (
        Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)"))
        / "Microsoft Visual Studio/Installer/vswhere.exe"
    )
    if locator.is_file():
        installation = subprocess.check_output(
            [
                str(locator),
                "-latest",
                "-products",
                "*",
                "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                "-property",
                "installationPath",
            ],
            text=True,
        ).strip()
        candidate = (
            Path(installation)
            / "Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe"
        )
        if installation and candidate.is_file():
            return str(candidate)
    raise RuntimeError(
        "Windows packaging requires installed VS 2022 x64 tools and CMake; supply --analysis-cmake. No automatic installation is performed."
    )


def stage_windows(
    bundle: Path, input_dir: Path, evidence: Path, cmake: Path | None = None
) -> dict:
    if os.name != "nt":
        raise RuntimeError("Windows analysis staging requires a native Windows builder")
    lock = load_lock(target="windows-x86_64")
    evidence.mkdir(parents=True, exist_ok=True)
    archives = {}
    for name, program in lock["programs"].items():
        source = program["source"]
        archive = input_dir / source["archive"]
        if not archive.is_file() or sha256(archive.read_bytes()) != source["sha256"]:
            raise RuntimeError(f"Supply the pinned local {name} archive: {archive}")
        archives[name] = archive
    recipe = lock["programs"]["cppcheck"]["recipe"]
    for key in ("patch", "utf8_manifest"):
        if sha256((ROOT / recipe[key]).read_bytes()) != recipe[key + "_sha256"]:
            raise RuntimeError(
                f"Pinned {key} bytes changed; check Git newline conversion"
            )
    cmake_exe = find_cmake(cmake)
    provenance = {
        "schema_version": 1,
        "sources": {name: p["source"] for name, p in lock["programs"].items()},
        "recipe": recipe,
        "cmake": subprocess.check_output(
            [cmake_exe, "--version"], text=True
        ).splitlines()[0],
        "cmake_sha256": sha256(Path(cmake_exe).read_bytes()),
        "commands": [],
    }
    # A short, fresh private build avoids adding this checkout's long pathname to
    # the measured legacy Cppcheck source-path problem. Only this owned directory
    # is cleaned by TemporaryDirectory; supplied archives/fixtures are read only.
    with tempfile.TemporaryDirectory(prefix="byo-cppcheck-") as temporary:
        work = Path(temporary)
        source_dir, build_dir = work / "source", work / "build"
        source_dir.mkdir()
        prefix = lock["programs"]["cppcheck"]["source"]["archive_prefix"]
        with tarfile.open(archives["cppcheck"], "r:gz") as archive:
            seen = set()
            for member in archive.getmembers():
                if member.name.rstrip("/") == prefix.rstrip("/") and member.isdir():
                    continue
                if not member.name.startswith(prefix):
                    raise RuntimeError("Cppcheck source archive prefix changed")
                relative = member.name[len(prefix) :].rstrip("/")
                if not relative:
                    continue
                safe_relative(relative)
                if relative.casefold() in seen or not (
                    member.isfile() or member.isdir()
                ):
                    raise RuntimeError(
                        "Cppcheck source has duplicate/nonregular entries"
                    )
                seen.add(relative.casefold())
                target = source_dir / relative
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.extractfile(member).read())
        options = source_dir / "cmake/compileroptions.cmake"
        if sha256(options.read_bytes()) != recipe["upstream_compileroptions_sha256"]:
            raise RuntimeError(
                "Cppcheck compiler options differ from accepted upstream"
            )
        patch_argv = [
            part.format(patch=str(ROOT / recipe["patch"]))
            for part in recipe["patch_argv"]
        ]
        # Keep the accepted LF upstream/transformed source bytes independent of
        # the developer's Git autocrlf setting; the patch itself is -text.
        for argv in (patch_argv[:-1] + ["--check", patch_argv[-1]], patch_argv):
            result = subprocess.run(argv, cwd=source_dir, check=False)
            provenance["commands"].append(
                {"step": "patch", "argv": argv, "exit_code": result.returncode}
            )
            write_json(evidence / "cppcheck-build.json", provenance)
            result.check_returncode()
        if sha256(options.read_bytes()) != recipe["patched_compileroptions_sha256"]:
            raise RuntimeError("Cppcheck patched options differ from accepted recipe")
        substitutions = {
            "source_dir": str(source_dir),
            "build_dir": str(build_dir),
            "utf8_manifest": str(ROOT / recipe["utf8_manifest"]),
        }
        for step in ("configure", "build"):
            argv = [part.format(**substitutions) for part in recipe[step + "_argv"]]
            argv[0] = cmake_exe
            with (evidence / f"cppcheck-{step}.log").open("wb") as log:
                result = subprocess.run(
                    argv, stdout=log, stderr=subprocess.STDOUT, check=False
                )
            provenance["commands"].append(
                {"step": step, "argv": argv, "exit_code": result.returncode}
            )
            write_json(evidence / "cppcheck-build.json", provenance)
            if result.returncode:
                raise RuntimeError(
                    f"Cppcheck {step} failed ({result.returncode}); see {evidence / ('cppcheck-' + step + '.log')}"
                )
        compiler = next(build_dir.glob("CMakeFiles/*/CMakeCXXCompiler.cmake"))
        compiler_text = compiler.read_text()
        for field in (
            "CMAKE_CXX_COMPILER_VERSION",
            "CMAKE_CXX_COMPILER_ID",
            "CMAKE_CXX_COMPILER_ARCHITECTURE_ID",
        ):
            match = re.search(r"set\(" + field + r'\s+"?([^"\s)]+)"?\)', compiler_text)
            if not match:
                raise RuntimeError(f"CMake did not record {field}")
            provenance[field] = match[1]
        cache = (build_dir / "CMakeCache.txt").read_text()
        for field in (
            "CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION",
            "CMAKE_VS_PLATFORM_TOOLSET",
        ):
            match = re.search(r"^" + field + r":[^=]+=(.+)$", cache, re.MULTILINE)
            if match:
                provenance[field] = match[1]
        for project in build_dir.rglob("cppcheck.vcxproj"):
            document = ET.parse(project).getroot()
            for tag, field in (
                ("WindowsTargetPlatformVersion", "windows_sdk"),
                ("PlatformToolset", "msvc_toolset"),
            ):
                values = {
                    node.text
                    for node in document.iter()
                    if node.tag.endswith("}" + tag) and node.text
                }
                if len(values) == 1:
                    provenance[field] = values.pop()
        linker_match = re.search(r"^CMAKE_LINKER:[^=]+=(.+)$", cache, re.MULTILINE)
        if linker_match:
            linker = Path(linker_match[1])
            output = subprocess.run(
                [str(linker), "/?"], capture_output=True, text=True, check=False
            )
            provenance["linker"] = output.stdout.splitlines()[0]
            provenance["linker_sha256"] = sha256(linker.read_bytes())
        if any(
            not provenance.get(field)
            for field in ("windows_sdk", "msvc_toolset", "linker")
        ):
            raise RuntimeError(
                "Cppcheck build did not record actual SDK/toolset/linker identity"
            )
        # Actual compiler/linker paths and versions remain in private evidence;
        # portable source/recipe identities go into the shipped SBOM.
        shutil.copy2(compiler, evidence / "CMakeCXXCompiler.cmake")
        shutil.copy2(build_dir / "CMakeCache.txt", evidence / "CMakeCache.txt")
        output = build_dir / recipe["output"]
        executable = bundle / lock["programs"]["cppcheck"]["executable"]
        executable.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(output, executable)
        provenance["executable_sha256"] = sha256(executable.read_bytes())
        provenance["executable_size"] = executable.stat().st_size
        for leaf in lock["programs"]["cppcheck"]["selected_files"]:
            target = bundle / leaf["runtime_path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            upstream = leaf["upstream_path"]
            if not upstream.startswith(prefix):
                raise RuntimeError("Selected Cppcheck data escaped its pinned archive")
            target.write_bytes(
                checked_bytes((source_dir / upstream[len(prefix) :]).read_bytes(), leaf)
            )
    with zipfile.ZipFile(archives["clangd"]) as archive:
        names = archive.namelist()
        if len(names) != len(set(name.casefold() for name in names)):
            raise RuntimeError("clangd upstream archive has duplicate entries")
        for leaf in lock["programs"]["clangd"]["selected_files"]:
            target = bundle / leaf["runtime_path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(checked_bytes(archive.read(leaf["upstream_path"]), leaf))
    write_json(bundle / "analysis/runtime.json", mapping(lock))
    write_json(evidence / "cppcheck-build.json", provenance)
    return provenance


def classification(relative: str, lock: dict) -> tuple[str, bool] | None:
    if relative == "analysis/runtime.json":
        return "metadata", False
    for leaf in lock.get("windows_native", {}).get("selected_files", []):
        if relative == leaf["runtime_path"]:
            return leaf["kind"], leaf["executable"]
    for program in lock["programs"].values():
        if relative == program["executable"]:
            return "analysis-executable", True
        if relative in program.get("additional_licenses", []):
            return "license", False
        for leaf in program["selected_files"]:
            if relative == leaf["runtime_path"]:
                return leaf["kind"], leaf["executable"]
        if relative in program["dependencies"]:
            return "analysis-dependency", False
    if relative.startswith("analysis/"):
        raise RuntimeError(f"Unselected analysis payload: {relative}")
    return None


def stage_windows_native(
    bundle: Path, python: Path, report: Path, evidence: Path, signed: bool = False
) -> None:
    """Place the pinned launcher dependency beside its EXE, never from PATH."""
    native = load_lock(target="windows-x86_64")["windows_native"]
    identity = json.loads(
        subprocess.check_output(
            [
                str(python),
                "-c",
                "import sys,json,platform;print(json.dumps({'base':sys.base_prefix,'version':platform.python_version()}))",
            ],
            text=True,
        )
    )
    if identity["version"] != native["source"]["python_version"]:
        raise RuntimeError(
            "Pinned Windows native dependency interpreter version changed"
        )
    base = Path(identity["base"])
    dlls = {
        n.attrib["dest_path"]: n.attrib
        for n in ET.parse(report).getroot().iter("included_dll")
    }
    receipt = {"source": native["source"], "interpreter": identity, "files": []}
    for leaf in native["selected_files"]:
        upstream = base / safe_relative(leaf["upstream_path"])
        original = checked_bytes(upstream.read_bytes(), leaf)
        if leaf["kind"] == "native-dependency":
            name = leaf["upstream_path"]
            node = dlls.get(name)
            if (
                not node
                or node.get("source_path", "").replace("\\", "/")
                != "${sys.real_prefix}/" + name
                or node.get("ignored") != "no"
            ):
                raise RuntimeError(
                    f"Nuitka did not select the pinned interpreter DLL: {name}"
                )
            selected = (bundle / "sidecar" / name).read_bytes()
            pe_imports(selected)
            if not signed:
                checked_bytes(selected, leaf)
            data = selected
        else:
            data = original
        target = bundle / leaf["runtime_path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        receipt["files"].append(
            {
                "path": leaf["runtime_path"],
                "source": str(upstream),
                "source_sha256": leaf["sha256"],
                "final_sha256": sha256(data),
            }
        )
    write_json(evidence / "windows-native-inputs.json", receipt)


def native_sbom(files: list[dict], lock: dict) -> tuple[list[dict], list[dict]]:
    native = lock.get("windows_native")
    if not native:
        return [], []
    inventory = {f["path"]: f for f in files}
    ref = "byo-windows:msvc-runtime"
    refs = []
    components = [
        {
            "type": "library",
            "bom-ref": ref,
            "name": native["name"],
            "version": native["version"],
            "licenses": [
                {
                    "license": {
                        "name": "Microsoft Distributable Code; conditions recorded in CPython Windows binary notice"
                    }
                }
            ],
            "properties": [
                {
                    "name": "byo:windows:source",
                    "value": json.dumps(native["source"], sort_keys=True),
                },
                {"name": "byo:windows:license-notice", "value": native["license"]},
                {
                    "name": "byo:windows:distribution-review",
                    "value": native["distribution_review"],
                },
            ],
        }
    ]
    for leaf in native["selected_files"]:
        path = leaf["runtime_path"]
        if path not in inventory:
            raise RuntimeError(f"Missing pinned Windows native inventory: {path}")
        file_ref = "byo-windows:file:" + path
        refs.append(file_ref)
        components.append(
            {
                "type": "file",
                "bom-ref": file_ref,
                "name": path,
                "hashes": [{"alg": "SHA-256", "content": inventory[path]["sha256"]}],
                "properties": [
                    {"name": "byo:windows:owner", "value": ref},
                    {
                        "name": "byo:windows:upstream",
                        "value": "${sys.real_prefix}/" + leaf["upstream_path"],
                    },
                ],
            }
        )
    return components, [{"ref": ref, "dependsOn": refs}]


def validate_windows_native(
    files: list[dict], read_bytes, sbom: dict, unsigned: bool
) -> None:
    lock = load_lock(target="windows-x86_64")
    native = lock.get("windows_native")
    if not native:
        return
    inventory = {f["path"]: f for f in files}
    for leaf in native["selected_files"]:
        path = leaf["runtime_path"]
        entry = inventory.get(path)
        if not entry or (entry["kind"], entry["executable"]) != (leaf["kind"], False):
            raise RuntimeError(
                f"Missing or misclassified Windows native dependency: {path}"
            )
        if unsigned or leaf["kind"] == "license":
            checked_bytes(read_bytes(path), leaf)
    components, dependencies = native_sbom(files, lock)
    actual = {c.get("bom-ref"): c for c in sbom.get("components", [])}
    for expected in components:
        if actual.get(expected["bom-ref"]) != expected:
            raise RuntimeError("Windows native source/license/hash SBOM mismatch")
    if any(d not in sbom.get("dependencies", []) for d in dependencies):
        raise RuntimeError("Windows native dependency SBOM ownership mismatch")


def sbom_components(
    lock: dict, files: list[dict], provenance: dict
) -> tuple[list[dict], list[dict]]:
    indexed = {leaf["path"]: leaf for leaf in files}
    components, dependencies = [], []
    for name, program in lock["programs"].items():
        reference = f"byo-analysis:{name}"
        licenses = [
            f["runtime_path"]
            for f in program["selected_files"]
            if f["kind"] == "license"
        ] + program.get("additional_licenses", [])
        properties = [
            {"name": "byo:analysis-license-path", "value": path} for path in licenses
        ]
        properties += [
            {
                "name": "byo:analysis:upstream",
                "value": json.dumps(program["source"], sort_keys=True),
            }
        ]
        if name == "cppcheck":
            properties += [
                {
                    "name": "byo:analysis:recipe",
                    "value": json.dumps(program["recipe"], sort_keys=True),
                },
                {
                    "name": "byo:analysis-build-toolchain",
                    "value": json.dumps(
                        {
                            k: v
                            for k, v in provenance.items()
                            if k.startswith("CMAKE_")
                            and k != "CMAKE_CXX_COMPILER"
                            or k in {"cmake", "windows_sdk", "msvc_toolset", "linker"}
                        },
                        sort_keys=True,
                    ),
                },
            ]
        else:
            properties.append(
                {
                    "name": "byo:analysis:recipe",
                    "value": (
                        "Copy the pinned official Windows release executable, LICENSE.TXT and exact lock-selected 332 include resources; exclude upstream compiler runtime libraries and PDBs."
                        if lock["platform"] == "windows"
                        else json.dumps(program["recipe"], sort_keys=True)
                    ),
                }
            )
        components.append(
            {
                "type": "application",
                "bom-ref": reference,
                "name": name,
                "version": program["version"],
                "hashes": [
                    {
                        "alg": "SHA-256",
                        "content": indexed[program["executable"]]["sha256"],
                    }
                ],
                "licenses": [
                    {
                        "license": {
                            "name": "GPL-3.0-or-later"
                            if name == "cppcheck"
                            else "Apache-2.0 WITH LLVM-exception"
                        }
                    }
                ],
                "externalReferences": [
                    {"type": "distribution", "url": program["source"]["url"]}
                ],
                "properties": properties,
            }
        )
        owned = []
        for path, leaf in sorted(indexed.items()):
            if not path.startswith(f"analysis/{name}/"):
                continue
            ref = f"byo-analysis-file:{path}"
            owned.append(ref)
            selected = next(
                (
                    item
                    for item in program["selected_files"]
                    if item["runtime_path"] == path
                ),
                None,
            )
            components.append(
                {
                    "type": "file",
                    "bom-ref": ref,
                    "name": path,
                    "hashes": [{"alg": "SHA-256", "content": leaf["sha256"]}],
                    "properties": [
                        {"name": "byo:analysis-owner", "value": reference},
                        {"name": "byo:analysis-kind", "value": leaf["kind"]},
                        *(
                            [
                                {
                                    "name": "byo:analysis:upstream_path",
                                    "value": selected["upstream_path"],
                                }
                            ]
                            if selected
                            else []
                        ),
                    ],
                }
            )
        for library, notice in program.get("static_linked_notices", {}).items():
            ref = f"byo-analysis:cppcheck:{library}"
            owned.append(ref)
            components.append(
                {
                    "type": "library",
                    "bom-ref": ref,
                    "name": library,
                    "properties": [
                        {"name": "byo:static-linked", "value": "true"},
                        {"name": "byo:analysis-license-path", "value": notice},
                        {
                            "name": "byo:analysis-source-commit",
                            "value": program["source"]["commit"],
                        },
                    ],
                }
            )
        if name == "cppcheck" and lock["platform"] == "linux":
            runtime = provenance.get("static_runtime")
            if not runtime:
                raise RuntimeError(
                    "Linux Cppcheck SBOM requires measured GCC static runtime provenance"
                )
            ref = "byo-analysis:cppcheck:gcc-runtime"
            owned.append(ref)
            components.append(
                {
                    "type": "library",
                    "bom-ref": ref,
                    "name": "GCC static runtime",
                    "properties": [
                        {"name": "byo:static-linked", "value": "true"},
                        {
                            "name": "byo:analysis-build-toolchain",
                            "value": json.dumps(runtime, sort_keys=True),
                        },
                        *[
                            {"name": "byo:analysis-license-path", "value": p}
                            for p in program["additional_licenses"]
                        ],
                    ],
                }
            )
        dependencies.append({"ref": reference, "dependsOn": owned})
    return components, dependencies


def validate_analysis(
    files: list[dict], read_bytes, sbom: dict, lock: dict | None = None
) -> None:
    lock = lock or load_lock()
    indexed = {leaf["path"]: leaf for leaf in files}
    if len(indexed) != len(files):
        raise RuntimeError("Duplicate payload inventory path")
    actual_mapping = strict_json(read_bytes("analysis/runtime.json"))
    if type(
        actual_mapping.get("schema_version")
    ) is not int or actual_mapping != mapping(lock):
        raise RuntimeError("Analysis runtime mapping differs from pinned selection")
    expected = {"analysis/runtime.json"}
    components = {c["bom-ref"]: c for c in sbom["components"]}
    if len(components) != len(sbom["components"]):
        raise RuntimeError("Duplicate SBOM component identity")
    relationships = {
        d["ref"]: set(d["dependsOn"]) for d in sbom.get("dependencies", [])
    }
    if len(relationships) != len(sbom.get("dependencies", [])):
        raise RuntimeError("Duplicate SBOM dependency owner")
    for name, program in lock["programs"].items():
        expected.add(program["executable"])
        expected.update(program["dependencies"])
        owner = f"byo-analysis:{name}"
        if components.get(owner, {}).get("version") != program["version"]:
            raise RuntimeError(f"Missing analysis SBOM program/version: {name}")
        application = components[owner]
        properties = {
            item["name"]: item["value"] for item in application.get("properties", [])
        }
        licenses = [
            leaf["runtime_path"]
            for leaf in program["selected_files"]
            if leaf["kind"] == "license"
        ] + program.get("additional_licenses", [])
        recorded_notices = [
            item["value"]
            for item in application.get("properties", [])
            if item["name"] == "byo:analysis-license-path"
        ]
        if (
            application.get("type") != "application"
            or application.get("name") != name
            or not application.get("licenses")
            or recorded_notices != licenses
            or properties.get("byo:analysis:upstream")
            != json.dumps(program["source"], sort_keys=True)
            or not properties.get("byo:analysis:recipe")
        ):
            raise RuntimeError(f"Analysis SBOM source/license/recipe mismatch: {name}")
        if name == "cppcheck" and properties["byo:analysis:recipe"] != json.dumps(
            program["recipe"], sort_keys=True
        ):
            raise RuntimeError("Cppcheck SBOM recipe differs from the pinned build")
        if (
            name == "clangd"
            and lock["platform"] != "windows"
            and properties["byo:analysis:recipe"]
            != json.dumps(program["recipe"], sort_keys=True)
        ):
            raise RuntimeError(
                "clangd SBOM recipe differs from the pinned transformations"
            )
        for selected in program["selected_files"]:
            path = selected["runtime_path"]
            expected.add(path)
            # Upstream-pinned resources, data and notices must retain exact bytes.
            # Platform signing can change an executable, whose final inventory
            # and SBOM identities are checked below instead.
            if selected["kind"] != "analysis-executable":
                checked_bytes(read_bytes(path), selected)
        expected.update(program.get("additional_licenses", []))
        for path in sorted(p for p in expected if p.startswith(f"analysis/{name}/")):
            leaf = indexed.get(path)
            if leaf is None or (leaf["kind"], leaf["executable"]) != classification(
                path, lock
            ):
                raise RuntimeError(f"Missing/misclassified analysis payload: {path}")
            ref = f"byo-analysis-file:{path}"
            component = components.get(ref, {})
            properties = {
                p["name"]: p["value"] for p in component.get("properties", [])
            }
            if (
                ref not in relationships.get(owner, set())
                or properties.get("byo:analysis-owner") != owner
                or properties.get("byo:analysis-kind") != leaf["kind"]
                or component.get("type") != "file"
                or component.get("name") != path
                or component.get("hashes")
                != [{"alg": "SHA-256", "content": leaf["sha256"]}]
            ):
                raise RuntimeError(f"Analysis SBOM ownership/hash mismatch: {path}")
            selected = next(
                (
                    item
                    for item in program["selected_files"]
                    if item["runtime_path"] == path
                ),
                None,
            )
            if (
                selected
                and properties.get("byo:analysis:upstream_path")
                != selected["upstream_path"]
            ):
                raise RuntimeError(f"Analysis SBOM upstream path mismatch: {path}")
        if components[owner].get("hashes") != [
            {"alg": "SHA-256", "content": indexed[program["executable"]]["sha256"]}
        ]:
            raise RuntimeError(f"Analysis SBOM program hash mismatch: {name}")
        for library, notice in program.get("static_linked_notices", {}).items():
            ref = f"byo-analysis:cppcheck:{library}"
            static = components.get(ref, {})
            properties = {p["name"]: p["value"] for p in static.get("properties", [])}
            if (
                static.get("type") != "library"
                or static.get("name") != library
                or ref not in relationships.get(owner, set())
                or properties.get("byo:static-linked") != "true"
                or properties.get("byo:analysis-license-path") != notice
                or properties.get("byo:analysis-source-commit")
                != program["source"]["commit"]
            ):
                raise RuntimeError(
                    f"Missing static-linked component provenance: {library}"
                )
        if name == "cppcheck" and lock["platform"] == "linux":
            ref = "byo-analysis:cppcheck:gcc-runtime"
            static = components.get(ref, {})
            properties = {p["name"]: p["value"] for p in static.get("properties", [])}
            if (
                static.get("type") != "library"
                or properties.get("byo:static-linked") != "true"
                or ref not in relationships.get(owner, set())
            ):
                raise RuntimeError("Missing Linux GCC static runtime SBOM ownership")
            runtime = strict_json(properties.get("byo:analysis-build-toolchain", "{}"))
            if (
                set(runtime)
                != {"package", "source", "compiler_sha256", "libraries", "notices"}
                or not runtime["package"]
                or not runtime["source"]
                or not re.fullmatch("[0-9a-f]{64}", runtime["compiler_sha256"])
                or not {"libstdc++.a", "libgcc.a"} <= set(runtime["libraries"])
                or set(runtime["libraries"])
                - {"libstdc++.a", "libgcc.a", "libgcc_eh.a"}
                or set(runtime["notices"]) != set(program["additional_licenses"])
            ):
                raise RuntimeError("Invalid GCC static runtime provenance")
            for path, identity in runtime["notices"].items():
                checked_bytes(read_bytes(path), identity)
            for identity in runtime["libraries"].values():
                if (
                    set(identity) != {"sha256", "size"}
                    or not re.fullmatch("[0-9a-f]{64}", identity["sha256"])
                    or type(identity["size"]) is not int
                    or identity["size"] <= 0
                ):
                    raise RuntimeError("Invalid measured GCC static library identity")
        expected_owned = {
            f"byo-analysis-file:{path}"
            for path in expected
            if path.startswith(f"analysis/{name}/")
        }
        expected_owned.update(
            f"byo-analysis:cppcheck:{library}"
            for library in program.get("static_linked_notices", {})
        )
        if name == "cppcheck" and lock["platform"] == "linux":
            expected_owned.add("byo-analysis:cppcheck:gcc-runtime")
        if relationships.get(owner) != expected_owned:
            raise RuntimeError(
                f"Analysis SBOM ownership namespace differs from selection: {name}"
            )
    if {p for p in indexed if p.startswith("analysis/")} != expected:
        raise RuntimeError("Unselected or missing analysis namespace entries")
    if (
        indexed.get("analysis/runtime.json", {}).get("kind"),
        indexed.get("analysis/runtime.json", {}).get("executable"),
    ) != ("metadata", False):
        raise RuntimeError(
            "Analysis mapping must be inventoried metadata/nonexecutable"
        )
    if lock["platform"] != "windows":
        import native_formats

        native_formats.validate_closure(lock, read_bytes)


def pe_imports(data: bytes) -> dict:
    """Read PE32+/AMD64 ordinary and delay imports without dumpbin or PATH."""

    def unpack(fmt, offset):
        if offset < 0 or offset + struct.calcsize(fmt) > len(data):
            raise RuntimeError("Truncated PE image")
        return struct.unpack_from(fmt, data, offset)

    if data[:2] != b"MZ":
        raise RuntimeError("Expected PE image")
    pe = unpack("<I", 60)[0]
    if data[pe : pe + 4] != b"PE\0\0":
        raise RuntimeError("Invalid PE signature")
    machine, count = unpack("<HH", pe + 4)
    optional_size = unpack("<H", pe + 20)[0]
    opt = pe + 24
    if machine != 0x8664 or unpack("<H", opt)[0] != 0x20B or optional_size < 112:
        raise RuntimeError("Windows payload must be PE32+/AMD64")
    image_base = unpack("<Q", opt + 24)[0]
    directory_count = unpack("<I", opt + 108)[0]
    header_size = unpack("<I", opt + 60)[0]
    sections = []
    for index in range(count):
        offset = opt + optional_size + index * 40
        virtual_size, rva, raw_size, raw = unpack("<IIII", offset + 8)
        sections.append((rva, max(virtual_size, raw_size), raw, raw_size))

    def address(rva):
        if rva < header_size:
            return rva
        for start, size, raw, raw_size in sections:
            if start <= rva < start + size and rva - start < raw_size:
                return raw + rva - start
        raise RuntimeError("PE import address outside file-backed sections")

    def text_at(rva):
        start = address(rva)
        end = data.find(b"\0", start)
        if end < 0:
            raise RuntimeError("Unterminated PE import name")
        return data[start:end].decode("ascii")

    def dll_name(rva):
        name = text_at(rva).lower()
        safe_relative(name)
        if "/" in name or not name.endswith(".dll"):
            raise RuntimeError("Unsafe PE import name")
        return name

    imports = {}
    symbols = {"ordinary": {}, "delay": {}}
    for index, kind, width in ((1, "ordinary", 20), (13, "delay", 32)):
        result = []
        if directory_count > index:
            if 112 + (index + 1) * 8 > optional_size:
                raise RuntimeError("Truncated PE data directory")
            rva, size = unpack("<II", opt + 112 + index * 8)
            if bool(rva) != bool(size):
                raise RuntimeError("Invalid PE import directory")
            if rva:
                terminated = False
                for displacement in range(0, size, width):
                    fields = unpack(
                        "<" + "I" * (width // 4), address(rva + displacement)
                    )
                    if not any(fields):
                        terminated = True
                        break
                    if kind == "ordinary":
                        name_rva = fields[3]
                        thunk_rva = fields[0] or fields[4]
                    else:
                        if fields[0] not in (0, 1):
                            raise RuntimeError("Invalid PE delay import attributes")
                        name_rva = (
                            fields[1] if fields[0] & 1 else fields[1] - image_base
                        )
                        thunk_rva = (
                            fields[4] if fields[0] & 1 else fields[4] - image_base
                        )
                    name = dll_name(name_rva)
                    result.append(name)
                    requested = symbols[kind].setdefault(name, [])
                    if thunk_rva:
                        for slot in range(len(data) // 8):
                            value = unpack("<Q", address(thunk_rva + slot * 8))[0]
                            if value == 0:
                                break
                            symbol = (
                                "#" + str(value & 0xFFFF)
                                if value & (1 << 63)
                                else text_at(value + 2)
                            )
                            if not symbol:
                                raise RuntimeError("Empty PE import symbol")
                            requested.append(symbol)
                        else:
                            raise RuntimeError("Unterminated PE import thunk table")
                if not terminated:
                    raise RuntimeError("Unterminated PE import directory")
        imports[kind] = sorted(set(result))
    exports = {}
    if directory_count:
        rva, size = unpack("<II", opt + 112)
        if rva:
            fields = unpack("<IIHHIIIIIII", address(rva))
            base, functions, names, table, name_table, ordinals = fields[5:]
            if functions > len(data) // 4 or names > len(data) // 4:
                raise RuntimeError("PE export tables exceed image bounds")
            for index in range(functions):
                target = unpack("<I", address(table + index * 4))[0]
                if target:
                    exports["#" + str(base + index)] = (
                        text_at(target) if rva <= target < rva + size else None
                    )
            for index in range(names):
                name = text_at(unpack("<I", address(name_table + index * 4))[0])
                ordinal = unpack("<H", address(ordinals + index * 2))[0]
                key = "#" + str(base + ordinal)
                if ordinal >= functions or key not in exports or name in exports:
                    raise RuntimeError("Invalid/duplicate PE export name/ordinal")
                exports[name] = exports[key]
    return {
        "machine": "AMD64",
        "format": "PE32+",
        **imports,
        "symbols": symbols,
        "exports": exports,
    }


def system_module(name: str, symbols: list[str]) -> dict:
    """Resolve OS imports with LOAD_LIBRARY_SEARCH_SYSTEM32, never ambient PATH."""
    if re.fullmatch(
        r"(?:vcruntime|msvcp|concrt|vcomp|msvcr)[0-9].*\.dll", name.lower()
    ):
        raise RuntimeError(
            f"Redistributable dependency must be inventoried beside its program, not assumed from System32: {name}"
        )
    if os.name != "nt":
        raise RuntimeError("Windows OS import testing requires a native Windows host")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LoadLibraryExW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    kernel.LoadLibraryExW.restype = ctypes.c_void_p
    kernel.GetModuleFileNameW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    kernel.FreeLibrary.argtypes = [ctypes.c_void_p]
    kernel.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    kernel.GetProcAddress.restype = ctypes.c_void_p
    kernel.GetModuleHandleExW.argtypes = [
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    handle = kernel.LoadLibraryExW(name, None, 0x800)
    if not handle:
        raise RuntimeError(
            f"Unresolved Windows OS/API-set import: {name} ({ctypes.get_last_error()})"
        )
    descriptions = {}

    def describe(module_handle):
        identity = (
            module_handle.value
            if isinstance(module_handle, ctypes.c_void_p)
            else module_handle
        )
        if identity in descriptions:
            return descriptions[identity]
        buffer = ctypes.create_unicode_buffer(32768)
        length = kernel.GetModuleFileNameW(module_handle, buffer, len(buffer))
        if not length or length >= len(buffer):
            raise RuntimeError(f"Cannot identify loaded OS module: {name}")
        path = Path(buffer.value).resolve()
        system32 = (Path(os.environ["SystemRoot"]) / "System32").resolve()
        if path.parent != system32:
            raise RuntimeError(f"OS import resolved outside System32: {name}")
        data = path.read_bytes()
        pe_imports(data)
        descriptions[identity] = {
            "module": path.name.lower(),
            "sha256": sha256(data),
            "size": len(data),
        }
        return descriptions[identity]

    try:
        module = describe(handle)
        checked, forwarded = [], {}
        for symbol in symbols:
            buffer = ctypes.create_string_buffer(symbol.encode("ascii"))
            pointer = (
                ctypes.c_void_p(int(symbol[1:]))
                if symbol.startswith("#")
                else ctypes.cast(buffer, ctypes.c_void_p)
            )
            procedure = kernel.GetProcAddress(handle, pointer)
            if not procedure:
                raise RuntimeError(
                    f"Unresolved Windows OS/API-set symbol: {name}:{symbol}"
                )
            owner = ctypes.c_void_p()
            # FROM_ADDRESS | UNCHANGED_REFCOUNT: inspect the actual symbol owner,
            # including OS forwarded exports, without acquiring another lease.
            if not kernel.GetModuleHandleExW(0x6, procedure, ctypes.byref(owner)):
                raise RuntimeError(f"Cannot identify OS symbol owner: {name}:{symbol}")
            owned = describe(owner)
            forwarded[owned["module"]] = owned
            checked.append({"symbol": symbol, "module": owned["module"]})
        return {
            "import": name,
            **module,
            "search": "LOAD_LIBRARY_SEARCH_SYSTEM32",
            "symbols": checked,
            "symbol_modules": sorted(
                forwarded.values(), key=lambda entry: entry["module"]
            ),
        }
    finally:
        kernel.FreeLibrary(handle)


def validate_pe_closure(
    files: list[dict], read_bytes, resolve_system=system_module
) -> dict:
    images = {
        f["path"]: pe_imports(read_bytes(f["path"]))
        for f in files
        if PurePosixPath(f["path"]).suffix.lower() in {".exe", ".dll", ".pyd"}
    }
    os_requests = {}
    edges = []

    def target_for(path, name):
        directories = {PurePosixPath(path).parent}
        if path.startswith("sidecar/"):
            directories.add(PurePosixPath("sidecar"))
        candidates = [
            p
            for p in images
            if PurePosixPath(p).name.lower() == name
            and PurePosixPath(p).parent in directories
        ]
        if len(candidates) > 1:
            raise RuntimeError(f"Ambiguous bundled DLL import: {path}: {name}")
        return candidates[0] if candidates else None

    def resolve_symbol(path, name, symbol, seen):
        key = (path, name, symbol)
        if key in seen:
            raise RuntimeError("Cyclic forwarded PE export")
        seen = seen | {key}
        target = target_for(path, name)
        if target is None:
            os_requests.setdefault(name, set()).add(symbol)
            return "windows-system32:" + name
        exports = images[target]["exports"]
        if symbol not in exports:
            raise RuntimeError(f"Unresolved bundled PE symbol: {path}:{name}:{symbol}")
        forward = exports[symbol]
        if forward:
            module, forwarded_symbol = forward.rsplit(".", 1)
            return resolve_symbol(
                target, module.lower() + ".dll", forwarded_symbol, seen
            )
        return target

    for path, image in sorted(images.items()):
        for kind in ("ordinary", "delay"):
            for name in image[kind]:
                target = target_for(path, name)
                if target is None:
                    os_requests.setdefault(name, set())
                requested = image["symbols"][kind][name]
                checked = [
                    {"symbol": symbol, "to": resolve_symbol(path, name, symbol, set())}
                    for symbol in requested
                ]
                edges.append(
                    {
                        "from": path,
                        "kind": kind,
                        "import": name,
                        "to": target or "windows-system32:" + name,
                        "symbols": checked,
                    }
                )
    os_modules = [
        resolve_system(name, sorted(symbols))
        for name, symbols in sorted(os_requests.items())
    ]
    version = os.sys.getwindowsversion() if os.name == "nt" else None
    return {
        "schema_version": 1,
        "tested_os": {
            "major": version.major,
            "minor": version.minor,
            "build": version.build,
        }
        if version
        else None,
        "support_limit": "Import resolution tested only on this recorded Windows build. Static closure does not prove installed/clean-host behavior or older Windows compatibility.",
        "images": images,
        "imports": edges,
        "os_modules": os_modules,
    }


def probe_programs(bundle: Path, lock: dict | None = None) -> dict:
    lock = lock or load_lock()
    target = f"{lock['platform']}-{lock['architecture']}"
    if host_target() != target:
        raise RuntimeError(f"Version probes require matching native host: {target}")
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP"}
    }
    environment["PATH"] = (
        str(Path(os.environ["SystemRoot"]) / "System32")
        if lock["platform"] == "windows"
        else "/usr/bin:/bin"
    )
    evidence = {}
    for name, program in lock["programs"].items():
        executable = bundle / program["executable"]
        if lock["platform"] == "windows":
            pe_imports(executable.read_bytes())
        else:
            import native_formats

            if (
                executable.is_symlink()
                or not executable.is_file()
                or not os.access(executable, os.X_OK)
            ):
                raise RuntimeError(
                    f"Native analysis executable is not accessible: {executable}"
                )
            if lock["platform"] == "linux":
                native_formats.elf(executable.read_bytes(), True)
            else:
                native_formats.macho(
                    executable.read_bytes(), lock["architecture"], True
                )
        argv = [str(executable), "--version"]
        result = subprocess.run(
            argv,
            cwd=executable.parent,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=5,
            check=False,
        )
        match = re.search(
            r"^"
            + ("Cppcheck " if name == "cppcheck" else "clangd version ")
            + r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
            result.stdout,
        )
        version = match[1] if match else ""
        if version.count(".") == 1:
            version += ".0"
        evidence[name] = {
            "argv": argv,
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "version": version,
            "sha256": sha256(executable.read_bytes()),
            "path_policy": "OS tools only on PATH; exact inventoried executable; loader overrides absent",
        }
        if result.returncode or result.stderr or version != program["version"]:
            raise RuntimeError(f"Pinned {name} version probe failed: {evidence[name]}")
    return evidence
