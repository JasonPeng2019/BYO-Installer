#!/usr/bin/env python3
"""Build one target-native BYO release bundle and deterministic update archive."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]


def run(
    argv: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None
) -> None:
    print("+", " ".join(argv), flush=True)
    subprocess.run(argv, cwd=cwd, env=env, check=True)


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def canonical_json(document: object) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def launcher_version() -> str:
    with (ROOT / "launcher" / "Cargo.toml").open("rb") as handle:
        return str(tomllib.load(handle)["package"]["version"])


def sidecar_version() -> str:
    with (ROOT / "Firmware MCP New" / "pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def signing_configuration(args: argparse.Namespace) -> tuple[Path, str, str]:
    raw_key = args.signing_key or os.environ.get("BYO_RELEASE_SIGNING_KEY")
    key_id = args.key_id or os.environ.get("BYO_RELEASE_KEY_ID")
    encoded_keys = os.environ.get("BYO_RELEASE_PUBLIC_KEYS")
    if not raw_key or not key_id or not encoded_keys:
        raise RuntimeError(
            "production builds require --signing-key/BYO_RELEASE_SIGNING_KEY, "
            "--key-id/BYO_RELEASE_KEY_ID, and BYO_RELEASE_PUBLIC_KEYS"
        )
    key = Path(raw_key).expanduser().resolve(strict=True)
    if not key.is_file():
        raise RuntimeError("release signing key must be a regular file")
    try:
        keyring = json.loads(encoded_keys)
    except json.JSONDecodeError as exc:
        raise RuntimeError("BYO_RELEASE_PUBLIC_KEYS must be a JSON object") from exc
    if (
        not isinstance(keyring, dict)
        or not isinstance(keyring.get(key_id), str)
        or len(keyring[key_id]) != 64
    ):
        raise RuntimeError(
            "the active release key ID is absent from BYO_RELEASE_PUBLIC_KEYS"
        )
    return key, key_id, encoded_keys


def sign_ed25519(payload: bytes, key: Path) -> str:
    with tempfile.TemporaryDirectory(prefix="byo-release-sign-") as temporary_directory:
        payload_path = Path(temporary_directory) / "payload"
        payload_path.write_bytes(payload)
        completed = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(key),
                "-in",
                str(payload_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    if completed.returncode != 0:
        diagnostic = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"OpenSSL Ed25519 signing failed: {diagnostic}")
    if len(completed.stdout) != 64:
        raise RuntimeError("OpenSSL returned an invalid Ed25519 signature length")
    return completed.stdout.hex()


def write_manifest_signature(
    bundle: Path, manifest: object, key: Path, key_id: str
) -> None:
    envelope = {
        "schema": 1,
        "algorithm": "Ed25519",
        "key_id": key_id,
        "signature": sign_ed25519(canonical_json(manifest), key),
    }
    (bundle / "release-manifest.sig").write_text(
        json.dumps(envelope, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def sign_macos_files(bundle: Path, identity: str) -> None:
    candidates: list[Path] = []
    for candidate in bundle.rglob("*"):
        if not candidate.is_file():
            continue
        completed = subprocess.run(
            ["file", "-b", str(candidate)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if "Mach-O" in completed.stdout:
            candidates.append(candidate)
    for candidate in sorted(candidates, key=lambda path: len(path.parts), reverse=True):
        run(
            [
                "codesign",
                "--force",
                "--options",
                "runtime",
                "--timestamp",
                "--sign",
                identity,
                str(candidate),
            ]
        )
        run(["codesign", "--verify", "--strict", "--verbose=2", str(candidate)])
    if not candidates:
        raise RuntimeError(
            "macOS production bundle did not contain any signable Mach-O files"
        )


def deterministic_tar_gz(bundle: Path, output: Path, epoch: int) -> None:
    temporary = output.with_suffix(output.suffix + ".tmp")
    if temporary.exists():
        temporary.unlink()
    with temporary.open("wb") as raw:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, mtime=epoch
        ) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
            ) as archive:
                entries = [bundle, *sorted(bundle.rglob("*"))]
                for path in entries:
                    relative = Path(bundle.name) / path.relative_to(bundle)
                    info = archive.gettarinfo(str(path), arcname=relative.as_posix())
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mtime = epoch
                    info.mode = (
                        0o755
                        if path.is_dir() or bool(path.stat().st_mode & stat.S_IXUSR)
                        else 0o644
                    )
                    if path.is_file():
                        with path.open("rb") as source:
                            archive.addfile(info, source)
                    else:
                        archive.addfile(info)
    os.replace(temporary, output)


def deterministic_zip(bundle: Path, output: Path, epoch: int) -> None:
    temporary = output.with_suffix(output.suffix + ".tmp")
    if temporary.exists():
        temporary.unlink()
    zip_epoch = min(max(epoch, 315532800), 4354819198)
    timestamp = time.gmtime(zip_epoch)[:6]
    with zipfile.ZipFile(
        temporary,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        entries = [bundle, *sorted(bundle.rglob("*"))]
        for path in entries:
            relative = (Path(bundle.name) / path.relative_to(bundle)).as_posix()
            is_directory = path.is_dir()
            name = (
                f"{relative}/"
                if is_directory and not relative.endswith("/")
                else relative
            )
            mode = (
                0o040755
                if is_directory
                else 0o100755
                if bool(path.stat().st_mode & stat.S_IXUSR)
                else 0o100644
            )
            info = zipfile.ZipInfo(filename=name, date_time=timestamp)
            info.create_system = 3
            info.external_attr = mode << 16
            if is_directory:
                info.external_attr |= 0x10
            info.compress_type = zipfile.ZIP_DEFLATED
            if path.is_file():
                archive.writestr(info, path.read_bytes())
            else:
                archive.writestr(info, b"")
    os.replace(temporary, output)


def platform_name() -> str:
    return {"Darwin": "macos", "Windows": "windows", "Linux": "linux"}[
        platform.system()
    ]


def archive_type() -> tuple[str, str]:
    return ("tar.gz", "tar.gz") if platform_name() == "linux" else ("zip", "zip")


def architecture() -> str:
    machine = platform.machine().lower()
    return {
        "amd64": "x86_64",
        "x86_64": "x86_64",
        "arm64": "aarch64",
        "aarch64": "aarch64",
    }.get(machine, machine)


def purl(kind: str, name: str, version: str) -> str:
    return f"pkg:{kind}/{quote(name, safe='')}@{quote(version, safe='')}"


def write_sbom(bundle: Path, nuitka_report: Path, version: str) -> None:
    """Write a deterministic CycloneDX inventory of bundled dependencies."""

    report = ET.parse(nuitka_report).getroot()
    components: list[dict[str, object]] = []
    references: set[str] = set()

    def add(component: dict[str, object]) -> None:
        reference = str(component["bom-ref"])
        if reference not in references:
            references.add(reference)
            components.append(component)

    for raw in report.findall("./distributions/distribution"):
        name = raw.attrib.get("name", "")
        dependency_version = raw.attrib.get("version", "")
        if not name or not dependency_version:
            raise RuntimeError(
                "Nuitka report contains incomplete Python distribution metadata"
            )
        reference = purl("pypi", name, dependency_version)
        add(
            {
                "type": "library",
                "bom-ref": reference,
                "name": name,
                "version": dependency_version,
                "purl": reference,
                "properties": [{"name": "byo:ecosystem", "value": "python"}],
            }
        )

    with (ROOT / "launcher/Cargo.lock").open("rb") as handle:
        cargo_lock = tomllib.load(handle)
    for raw in cargo_lock.get("package", []):
        if not isinstance(raw, dict) or raw.get("name") == "byo":
            continue
        name = raw.get("name")
        dependency_version = raw.get("version")
        if not isinstance(name, str) or not isinstance(dependency_version, str):
            raise RuntimeError("Cargo.lock contains incomplete package metadata")
        reference = purl("cargo", name, dependency_version)
        component: dict[str, object] = {
            "type": "library",
            "bom-ref": reference,
            "name": name,
            "version": dependency_version,
            "purl": reference,
            "properties": [{"name": "byo:ecosystem", "value": "rust"}],
        }
        checksum = raw.get("checksum")
        if isinstance(checksum, str):
            component["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        add(component)

    python = report.find("./python")
    if python is None or not python.attrib.get("python_version"):
        raise RuntimeError("Nuitka report contains no Python runtime version")
    python_version = python.attrib["python_version"]
    python_reference = f"pkg:generic/cpython@{quote(python_version, safe='')}"
    add(
        {
            "type": "framework",
            "bom-ref": python_reference,
            "name": "CPython",
            "version": python_version,
            "purl": python_reference,
        }
    )

    native_suffixes = {".dylib", ".dll", ".pyd", ".so"}
    for path in sorted(
        candidate for candidate in bundle.rglob("*") if candidate.is_file()
    ):
        if path.suffix.lower() not in native_suffixes:
            continue
        relative = path.relative_to(bundle).as_posix()
        add(
            {
                "type": "file",
                "bom-ref": f"byo-native:{relative}",
                "name": relative,
                "hashes": [{"alg": "SHA-256", "content": digest(path)}],
                "properties": [{"name": "byo:bundled-native-file", "value": "true"}],
            }
        )

    components.sort(key=lambda component: str(component["bom-ref"]))
    nuitka_version = report.attrib.get("nuitka_version", "unknown")
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": f"pkg:generic/byo@{quote(version, safe='')}",
                "name": "BYO",
                "version": version,
            },
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "Nuitka",
                        "version": nuitka_version,
                    }
                ]
            },
        },
        "components": components,
    }
    (bundle / "sbom.cdx.json").write_text(
        json.dumps(sbom, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def command_output(argv: list[str], *, cwd: Path = ROOT) -> str:
    return subprocess.check_output(argv, cwd=cwd, text=True).strip()


def load_source_lock() -> dict[str, object]:
    path = ROOT / "release" / "source-lock.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != 1
        or not isinstance(payload.get("agent_workspace"), dict)
        or not isinstance(payload.get("firmware_mcp"), dict)
    ):
        raise RuntimeError("release/source-lock.json is invalid")
    return payload


def validate_external_checkout(
    *,
    label: str,
    source: Path,
    locked: object,
) -> dict[str, str]:
    if not isinstance(locked, dict):
        raise RuntimeError(f"{label} source lock is invalid")
    repository = locked.get("repository")
    branch = locked.get("branch")
    commit = locked.get("commit")
    if (
        not isinstance(repository, str)
        or not repository
        or not isinstance(branch, str)
        or not branch
        or not isinstance(commit, str)
        or len(commit) != 40
    ):
        raise RuntimeError(f"{label} source lock is incomplete")
    if command_output(["git", "status", "--porcelain"], cwd=source):
        raise RuntimeError(f"{label} must be clean before release assembly")
    actual_commit = command_output(["git", "rev-parse", "HEAD"], cwd=source)
    if actual_commit != commit:
        raise RuntimeError(
            f"{label} is at {actual_commit}, but release/source-lock.json requires {commit}"
        )
    actual_branch = command_output(["git", "branch", "--show-current"], cwd=source)
    if actual_branch not in {"", branch}:
        raise RuntimeError(
            f"{label} must be detached at the lock or on {branch}, got {actual_branch}"
        )
    remote = command_output(["git", "remote", "get-url", "origin"], cwd=source)
    normalized_remote = remote.removesuffix(".git").removesuffix("/")
    if not normalized_remote.endswith(f"github.com/{repository}"):
        raise RuntimeError(
            f"{label} origin does not match locked repository {repository}"
        )
    return {"repository": repository, "commit": commit}


def installer_source(production: bool) -> dict[str, str]:
    try:
        commit = command_output(["git", "rev-parse", "HEAD"])
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            "the top-level installer workspace must be a Git repository"
        ) from exc
    if production and command_output(["git", "status", "--porcelain"]):
        raise RuntimeError("production builds require a clean installer worktree")
    workflow_commit = os.environ.get("GITHUB_SHA")
    if workflow_commit and workflow_commit != commit:
        raise RuntimeError(
            f"GITHUB_SHA {workflow_commit} does not match installer HEAD {commit}"
        )
    return {
        "repository": "JasonPeng2019/BYO-Installer",
        "commit": commit,
    }


def source_provenance(production: bool) -> dict[str, dict[str, str]]:
    locked = load_source_lock()
    return {
        "installer": installer_source(production),
        "agent_workspace": validate_external_checkout(
            label="AgentWorkspace",
            source=ROOT / "AgentWorkspace",
            locked=locked["agent_workspace"],
        ),
        "firmware_mcp": validate_external_checkout(
            label="Firmware MCP",
            source=ROOT / "Firmware MCP New",
            locked=locked["firmware_mcp"],
        ),
    }


def toolchain_provenance(python: Path, nuitka_report: Path) -> dict[str, str]:
    report = ET.parse(nuitka_report).getroot()
    nuitka_version = report.attrib.get("nuitka_version")
    python_node = report.find("./python")
    python_version = (
        python_node.attrib.get("python_version") if python_node is not None else None
    )
    if not nuitka_version or not python_version:
        raise RuntimeError(
            "Nuitka report does not identify the Python and Nuitka toolchains"
        )
    executable_version = command_output(
        [str(python), "-c", "import platform; print(platform.python_version())"]
    )
    if executable_version != python_version:
        raise RuntimeError(
            f"Nuitka report Python {python_version} does not match builder {executable_version}"
        )
    return {
        "rustc": command_output(["rustc", "--version"]),
        "cargo": command_output(["cargo", "--version"]),
        "python": python_version,
        "nuitka": nuitka_version,
    }


def export_clean_workspace(destination: Path) -> None:
    source = ROOT / "AgentWorkspace"
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    raw_files = subprocess.check_output(["git", "-C", str(source), "ls-files", "-z"])
    for raw in raw_files.split(b"\0"):
        if not raw:
            continue
        relative = Path(os.fsdecode(raw))
        source_file = source / relative
        destination_file = destination / relative
        destination_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_file, destination_file)


def normalize_macos_libusb_install_name(python: Path) -> None:
    """Repair the bundled wheel's host-absolute Mach-O identity for relocation.

    The current libusb-package wheel identifies its own dylib as
    /usr/local/lib/libusb-1.0.0.dylib. Nuitka correctly refuses the resulting
    collision with a Homebrew libusb. A standalone artifact must use a
    relocatable identity.
    """
    if platform.system() != "Darwin":
        return
    site_packages = subprocess.check_output(
        [
            str(python),
            "-c",
            "import pathlib,libusb_package; "
            "print(pathlib.Path(libusb_package.__file__).parent)",
        ],
        text=True,
    ).strip()
    dylib = Path(site_packages) / "libusb-1.0.dylib"
    identity = subprocess.check_output(
        ["otool", "-D", str(dylib)], text=True
    ).splitlines()[-1]
    if identity.strip().startswith("/usr/local/"):
        run(["install_name_tool", "-id", "@rpath/libusb-1.0.dylib", str(dylib)])


def collect_private_symbols(
    bundle: Path,
    launcher: Path,
    nuitka_output: Path,
    nuitka_report: Path,
    *,
    production: bool,
) -> Path:
    symbol_root = ROOT / "release" / "symbols" / bundle.name
    if symbol_root.exists():
        shutil.rmtree(symbol_root)
    symbol_root.mkdir(parents=True)
    shutil.copy2(nuitka_report, symbol_root / nuitka_report.name)
    sidecar = (
        bundle
        / "sidecar"
        / ("byo-mcp-sidecar.exe" if os.name == "nt" else "byo-mcp-sidecar")
    )

    collected: list[Path] = [symbol_root / nuitka_report.name]
    if platform.system() == "Darwin":
        for candidate in (bundle / "byo", sidecar):
            destination = symbol_root / f"{candidate.name}.dSYM"
            completed = subprocess.run(
                ["dsymutil", str(candidate), "-o", str(destination)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if completed.returncode == 0 and destination.is_dir():
                collected.append(destination)
            elif production:
                raise RuntimeError(
                    f"failed to preserve dSYM for {candidate.name}: {completed.stderr.strip()}"
                )
            run(["strip", "-S", "-x", str(candidate)])
    elif platform.system() == "Windows":
        pdbs = {
            *launcher.parent.glob("*.pdb"),
            *nuitka_output.rglob("*.pdb"),
        }
        for pdb in sorted(pdbs):
            destination = symbol_root / pdb.name
            if destination.exists() and digest(destination) != digest(pdb):
                raise RuntimeError(f"private symbol filename collision: {pdb.name}")
            shutil.copy2(pdb, destination)
            collected.append(destination)
        if production and len(collected) == 1:
            raise RuntimeError("Windows production build produced no private PDB files")
    elif platform.system() == "Linux":
        for candidate in (bundle / "byo", sidecar):
            destination = symbol_root / f"{candidate.name}.debug"
            run(["objcopy", "--only-keep-debug", str(candidate), str(destination)])
            run(["strip", "--strip-unneeded", str(candidate)])
            run(["objcopy", f"--add-gnu-debuglink={destination}", str(candidate)])
            collected.append(destination)

    inventory = []
    for path in sorted(
        candidate for candidate in symbol_root.rglob("*") if candidate.is_file()
    ):
        inventory.append(
            {
                "path": path.relative_to(symbol_root).as_posix(),
                "sha256": digest(path),
                "size": path.stat().st_size,
            }
        )
    (symbol_root / "symbols.json").write_text(
        json.dumps({"schema": 1, "files": inventory}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return symbol_root


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", default="0.1.1")
    parser.add_argument("--channel", default="development")
    parser.add_argument("--output", type=Path, default=ROOT / "release" / "dist")
    parser.add_argument(
        "--production",
        action="store_true",
        help="Build without development escape hatches and require manifest/platform signing",
    )
    parser.add_argument("--signing-key", type=Path)
    parser.add_argument("--key-id")
    parser.add_argument("--codesign-identity")
    parser.add_argument(
        "--prepare-platform-signing",
        action="store_true",
        help="Assemble a Windows production bundle, then stop before signed metadata",
    )
    parser.add_argument(
        "--platform-signing-complete",
        action="store_true",
        help="Require and verify Windows Authenticode signatures before finalization",
    )
    parser.add_argument(
        "--reuse-launcher",
        action="store_true",
        help="Reuse launcher/target/release/byo(.exe), for protected signing finalization only",
    )
    parser.add_argument(
        "--reuse-sidecar",
        action="store_true",
        help="Reuse an existing successful Nuitka *.dist output while rebuilding the Rust bundle",
    )
    parser.add_argument(
        "--python",
        type=Path,
        default=ROOT
        / "Firmware MCP New"
        / ".venv"
        / ("Scripts/python.exe" if os.name == "nt" else "bin/python"),
    )
    args = parser.parse_args()
    versions = {launcher_version(), sidecar_version()}
    if versions != {args.version}:
        raise RuntimeError(
            f"release version {args.version!r} must match launcher and sidecar versions "
            f"{sorted(versions)!r}"
        )
    if args.production and args.channel == "development":
        raise RuntimeError("production builds must use a non-development channel")
    if (args.prepare_platform_signing or args.platform_signing_complete) and (
        not args.production or platform.system() != "Windows"
    ):
        raise RuntimeError(
            "platform-signing stages are valid only for Windows production builds"
        )
    if args.prepare_platform_signing and args.platform_signing_complete:
        raise RuntimeError(
            "prepare and finalize platform-signing stages are mutually exclusive"
        )
    if args.reuse_launcher and not args.platform_signing_complete:
        raise RuntimeError(
            "--reuse-launcher is restricted to signed Windows finalization"
        )
    sources = source_provenance(args.production)
    signing: tuple[Path, str, str] | None = (
        signing_configuration(args) if args.production else None
    )
    build = ROOT / "release" / "build"
    pack = build / "workspace.pack"
    report = build / "workspace-classification.json"
    workspace_export = build / "agent-workspace-source"
    export_clean_workspace(workspace_export)
    run(
        [
            sys.executable,
            str(ROOT / "release/scripts/compile_workspace.py"),
            "--source",
            str(workspace_export),
            "--policy",
            str(ROOT / "release/policies/workspace-partition.toml"),
            "--output",
            str(pack),
            "--report",
            str(report),
            "--version",
            args.version,
        ]
    )

    if not args.reuse_launcher:
        cargo = ["cargo", "build", "--release", "--locked"]
        cargo_environment = os.environ.copy()
        if args.production:
            cargo.append("--no-default-features")
            assert signing is not None
            cargo_environment["BYO_RELEASE_PUBLIC_KEYS"] = signing[2]
        run(cargo, cwd=ROOT / "launcher", env=cargo_environment)
    launcher = (
        ROOT / "launcher/target/release" / ("byo.exe" if os.name == "nt" else "byo")
    )
    if not launcher.is_file():
        raise RuntimeError("native Rust launcher output is missing")

    nuitka_output = build / "nuitka"
    nuitka_report = build / "nuitka-compilation-report.xml"
    nuitka_output.mkdir(parents=True, exist_ok=True)
    mcp = ROOT / "Firmware MCP New"
    if not args.reuse_sidecar:
        for stale_dist in nuitka_output.glob("*.dist"):
            shutil.rmtree(stale_dist)
        normalize_macos_libusb_install_name(args.python)
        run(
            [
                str(args.python),
                "-m",
                "nuitka",
                "--mode=standalone",
                "--assume-yes-for-downloads",
                "--disable-cache=ccache",
                f"--report={nuitka_report}",
                "--report-diffable",
                f"--output-dir={nuitka_output}",
                "--output-filename=byo-mcp-sidecar",
                "--include-package=pyocd_debug_mcp",
                "--include-data-files=src/pyocd_debug_mcp/probe_families.json=pyocd_debug_mcp/probe_families.json",
                "src/pyocd_debug_mcp/sidecar.py",
            ],
            cwd=mcp,
            env={
                **os.environ,
                "PYTHONPATH": str(mcp / "src"),
                "NUITKA_CACHE_DIR": str(
                    Path(tempfile.gettempdir()) / "byo-nuitka-cache"
                ),
            },
        )
    dist_candidates = sorted(nuitka_output.glob("*.dist"))
    if len(dist_candidates) != 1:
        raise RuntimeError(
            f"expected one Nuitka standalone directory, got {dist_candidates}"
        )

    bundle = args.output / f"byo-{args.version}-{platform_name()}-{architecture()}"
    if bundle.exists():
        shutil.rmtree(bundle)
    (bundle / "sidecar").mkdir(parents=True)
    (bundle / "workflow").mkdir()
    shutil.copy2(launcher, bundle / launcher.name)
    for child in dist_candidates[0].iterdir():
        destination = bundle / "sidecar" / child.name
        if child.is_dir():
            shutil.copytree(child, destination)
        else:
            shutil.copy2(child, destination)
    shutil.copy2(pack, bundle / "workflow/workspace.pack")

    if not nuitka_report.is_file():
        raise RuntimeError(
            "Nuitka compilation report is missing; run a fresh sidecar build"
        )
    symbol_root = collect_private_symbols(
        bundle,
        launcher,
        nuitka_output,
        nuitka_report,
        production=args.production,
    )

    if args.production:
        if platform.system() == "Darwin":
            if not args.codesign_identity:
                raise RuntimeError(
                    "macOS production builds require --codesign-identity"
                )
            sign_macos_files(bundle, args.codesign_identity)
        elif platform.system() == "Windows":
            if args.prepare_platform_signing:
                print(json.dumps({"prepared_bundle": str(bundle)}, sort_keys=True))
                return 0
            if not args.platform_signing_complete:
                raise RuntimeError(
                    "Windows production assembly requires prepare, protected Authenticode "
                    "signing, and finalization stages"
                )
            powershell = shutil.which("pwsh") or shutil.which("powershell")
            if not powershell:
                raise RuntimeError(
                    "PowerShell is required to verify Authenticode signatures"
                )
            run(
                [
                    powershell,
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                    str(ROOT / "release/scripts/verify_authenticode.ps1"),
                    "-Bundle",
                    str(bundle),
                ]
            )

    write_sbom(bundle, nuitka_report, args.version)
    toolchains = toolchain_provenance(args.python, nuitka_report)

    files = []
    for path in sorted(
        candidate for candidate in bundle.rglob("*") if candidate.is_file()
    ):
        relative = path.relative_to(bundle).as_posix()
        executable = relative in {
            "byo",
            "byo.exe",
            "sidecar/byo-mcp-sidecar",
            "sidecar/byo-mcp-sidecar.exe",
        }
        if executable and os.name != "nt":
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        kind = (
            "launcher"
            if relative in {"byo", "byo.exe"}
            else "workflow"
            if relative == "workflow/workspace.pack"
            else "metadata"
            if relative == "sbom.cdx.json"
            else "sidecar"
        )
        files.append(
            {
                "path": relative,
                "sha256": digest(path),
                "size": path.stat().st_size,
                "kind": kind,
                "executable": executable,
            }
        )
    manifest = {
        "schema": 1,
        "product": "byo",
        "version": args.version,
        "channel": args.channel,
        "platform": platform_name(),
        "architecture": architecture(),
        "launcher_protocol": 1,
        "sidecar_protocol": 1,
        "worker_protocol": 1,
        "workflow_protocol": 1,
        "capsule_schema": 1,
        "project_state_schema": 1,
        "development_unsigned": not args.production,
        "source": sources,
        "toolchain": toolchains,
        "files": files,
    }
    (bundle / "release-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if args.production:
        assert signing is not None
        write_manifest_signature(bundle, manifest, signing[0], signing[1])

    sidecar = (
        bundle
        / "sidecar"
        / ("byo-mcp-sidecar.exe" if os.name == "nt" else "byo-mcp-sidecar")
    )
    run(
        [
            str(sidecar),
            "self-test",
            "--runtime-root",
            str(bundle),
            "--launcher-version",
            args.version,
        ],
        env={**os.environ, "BYO_SIDECAR_COMPILED": "1"},
    )

    args.output.mkdir(parents=True, exist_ok=True)
    archive_kind, archive_extension = archive_type()
    archive = args.output / f"{bundle.name}.{archive_extension}"
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    if archive_kind == "zip":
        deterministic_zip(bundle, archive, epoch)
    else:
        deterministic_tar_gz(bundle, archive, epoch)
    checksums = args.output / f"{bundle.name}.sha256"
    checksums.write_text(f"{digest(archive)}  {archive.name}\n", encoding="utf-8")
    if args.production:
        assert signing is not None
        (args.output / f"{archive.name}.sig").write_bytes(
            bytes.fromhex(sign_ed25519(archive.read_bytes(), signing[0]))
        )
    print(
        json.dumps(
            {
                "bundle": str(bundle),
                "archive": str(archive),
                "archive_type": archive_kind,
                "archive_sha256": digest(archive),
                "manifest_sha256": digest(bundle / "release-manifest.json"),
                "private_symbols": str(symbol_root),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
