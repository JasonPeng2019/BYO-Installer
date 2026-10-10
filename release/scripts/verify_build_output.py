#!/usr/bin/env python3
"""Fail a native build when its bundle, provenance, or archive contract drifts."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import stat
import struct
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

import analysis_tools

ROOT = Path(__file__).resolve().parents[2]
FORBIDDEN_SUFFIXES = {
    ".c",
    ".h",
    ".md",
    ".ps1",
    ".py",
    ".pyc",
    ".pyi",
    ".rs",
    ".sh",
}
MAX_ENTRIES = 20_000

# Shared build/service accounts whose home directories legitimately appear inside
# shipped binaries via upstream toolchain and dependency debug paths — e.g. Rust
# registry sources under `/Users/runner/.cargo/...` or `/root/.cargo/...`, and the
# python.org CPython build tree under `/Users/sysadmin/build/...`. These are not a
# leak of *our* build machine, so identity needles are not derived from them. A
# *personal* login name (anything not in this set) must never appear.
GENERIC_BUILD_ACCOUNTS = frozenset(
    {
        "runner",
        "runneradmin",  # GitHub-hosted Windows runner account
        "root",
        "sysadmin",
        "admin",
        "administrator",
        "containeradministrator",
        "builder",
        "build",
        "user",
        "github",
        "vsts",
        "circleci",
        "azureuser",
        "ec2-user",
        "ubuntu",
    }
)

# Key material must never ride along inside a customer artifact.
SECRET_PATTERNS: tuple[tuple[str, "re.Pattern[bytes]"], ...] = (
    ("openssh-private-key", re.compile(rb"BEGIN OPENSSH PRIVATE KEY")),
    ("pem-private-key", re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
)

# Read whole files below this size; larger files fall back to a chunked
# exact-needle scan so memory stays bounded on a pathological artifact.
MAX_SCAN_BYTES = 512 * 1024 * 1024

# A correctly stripped Mach-O keeps ~0–1 residual debug-map stabs (observed: 1),
# while an unstripped build carries tens of thousands. This threshold cleanly
# separates the two without being brittle about the exact residual.
MACHO_MAX_STAB = 8
MACHO_MAGIC_64_LE = 0xFEEDFACF
MACHO_LC_SYMTAB = 0x2
MACHO_N_STAB = 0xE0


def sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def expected_identity(target: str) -> tuple[str, str]:
    return analysis_tools.TARGETS[analysis_tools.canonical_target(target)]


def validate_archive_paths(names: list[str], bundle_name: str) -> None:
    if not names or len(names) > MAX_ENTRIES:
        raise RuntimeError("archive is empty or contains too many entries")
    seen: set[str] = set()
    analysis_tools.safe_relative(bundle_name)
    if "/" in bundle_name:
        raise RuntimeError("Archive requires a single bundle root")
    for name in names:
        if name.endswith("//"):
            raise RuntimeError(f"Archive contains noncanonical path: {name}")
        analysis_tools.safe_relative(name.rstrip("/"))
        path = PurePosixPath(name)
        normalized = name.rstrip("/").lower()
        if (
            "\\" in name
            or path.is_absolute()
            or not path.parts
            or path.parts[0] != bundle_name
            or any(part in {"", ".", ".."} for part in path.parts)
            or normalized in seen
        ):
            raise RuntimeError(
                f"archive contains an unsafe or duplicate path: {name!r}"
            )
        seen.add(normalized)


def validate_archive(
    archive: Path,
    archive_type: str,
    bundle_name: str,
    expected_manifest: dict | None = None,
    *,
    expected_target: str | None = None,
) -> None:
    def validate_members(members: dict, directories: dict, read_bytes, read_mode):
        manifest = analysis_tools.strict_json(read_bytes("release-manifest.json"))
        target = analysis_tools.canonical_target(
            f"{manifest.get('platform')}-{manifest.get('architecture')}"
        )
        if expected_target is not None and target != analysis_tools.canonical_target(
            expected_target
        ):
            raise RuntimeError("Archive manifest target differs from explicit target")
        if expected_manifest is not None and manifest != expected_manifest:
            raise RuntimeError("Archive manifest differs from the assembled bundle")
        expected_kind = "tar.gz" if manifest["platform"] == "linux" else "zip"
        if archive_type != expected_kind:
            raise RuntimeError("Archive type differs from target contract")
        expected = {leaf["path"] for leaf in manifest["files"]} | {
            "release-manifest.json"
        }
        if manifest.get("development_unsigned") is False:
            expected.add("release-manifest.sig")
        if set(members) != expected:
            raise RuntimeError(
                f"Archive leaves differ from payload inventory: {sorted(set(members) ^ expected)}"
            )
        allowed_directories = {bundle_name}
        for name in expected:
            for parent in PurePosixPath(f"{bundle_name}/{name}").parents:
                if str(parent) != ".":
                    allowed_directories.add(str(parent))
        if set(directories) - allowed_directories:
            raise RuntimeError("Archive contains unknown/misplaced directory entries")
        if manifest["platform"] != "windows":
            if any(mode != 0o755 for mode in directories.values()):
                raise RuntimeError("Native archive directory permissions must be 0755")
            if any(
                read_mode(name) != 0o644
                for name in expected
                if name in {"release-manifest.json", "release-manifest.sig"}
            ):
                raise RuntimeError("Native archive metadata permissions must be 0644")
        validate_payload(manifest, read_bytes, read_mode=read_mode)

    if archive_type == "zip":
        if archive.suffix != ".zip":
            raise RuntimeError("ZIP target did not produce a .zip archive")
        with zipfile.ZipFile(archive) as handle:
            members = handle.infolist()
            validate_archive_paths([member.filename for member in members], bundle_name)
            for member in members:
                file_type = (member.external_attr >> 16) & 0o170000
                if file_type not in {0, 0o040000, 0o100000}:
                    raise RuntimeError("ZIP contains a forbidden non-file entry")
                if (file_type == stat.S_IFDIR and not member.is_dir()) or (
                    file_type == stat.S_IFREG and member.is_dir()
                ):
                    raise RuntimeError(
                        "ZIP entry type disagrees with its directory spelling"
                    )
            leaves = {
                m.filename[len(bundle_name) + 1 :]: m for m in members if not m.is_dir()
            }
            directories = {
                m.filename.rstrip("/"): stat.S_IMODE(m.external_attr >> 16)
                for m in members
                if m.is_dir()
            }
            validate_members(
                leaves,
                directories,
                lambda name: handle.read(f"{bundle_name}/{name}"),
                lambda name: stat.S_IMODE(leaves[name].external_attr >> 16),
            )
    elif archive_type == "tar.gz":
        if not archive.name.endswith(".tar.gz"):
            raise RuntimeError("Linux target did not produce a .tar.gz archive")
        with tarfile.open(archive, "r:gz") as handle:
            members = handle.getmembers()
            validate_archive_paths([member.name for member in members], bundle_name)
            if any(
                member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}
                for member in members
            ):
                raise RuntimeError("tar archive contains a forbidden non-file entry")
            leaves = {m.name[len(bundle_name) + 1 :]: m for m in members if m.isfile()}
            directories = {m.name.rstrip("/"): m.mode for m in members if m.isdir()}
            validate_members(
                leaves,
                directories,
                lambda name: handle.extractfile(leaves[name]).read(),
                lambda name: leaves[name].mode,
            )
    else:
        raise RuntimeError(f"unsupported archive contract: {archive_type}")


def validate_payload(manifest: dict, read_bytes, *, read_mode=None) -> None:
    """Check actual leaf bytes; upstream resource exceptions are exact and owned."""
    seen = set()
    target = analysis_tools.canonical_target(
        f"{manifest.get('platform')}-{manifest.get('architecture')}"
    )
    lock = analysis_tools.load_lock(target=target)
    native = lock["platform"] != "windows"
    analysis_tools.safe_namespace([leaf["path"] for leaf in manifest["files"]])
    pinned_resources = {
        f["runtime_path"]
        for f in lock["programs"]["clangd"]["selected_files"]
        if f["kind"] == "analysis-resource"
    }
    for leaf in manifest["files"]:
        if (
            set(leaf) != {"path", "sha256", "size", "kind", "executable"}
            or type(leaf["size"]) is not int
            or leaf["size"] < 0
            or type(leaf["executable"]) is not bool
            or not re.fullmatch("[0-9a-f]{64}", leaf["sha256"])
        ):
            raise RuntimeError("Invalid Windows payload inventory entry")
        name = analysis_tools.safe_relative(leaf["path"])
        if name.casefold() in seen or name in {
            "release-manifest.json",
            "release-manifest.sig",
        }:
            raise RuntimeError(f"Duplicate/circular inventory entry: {name}")
        seen.add(name.casefold())
        data = read_bytes(name)
        if len(data) != leaf["size"] or analysis_tools.sha256(data) != leaf["sha256"]:
            raise RuntimeError(f"Payload inventory byte mismatch: {name}")
        if native and (
            read_mode is None
            or read_mode(name) != (0o755 if leaf["executable"] else 0o644)
        ):
            raise RuntimeError(
                f"Native payload has incorrect executable/data permissions: {name}"
            )
        path = PurePosixPath(name)
        forbidden = (
            path.suffix.lower()
            in FORBIDDEN_SUFFIXES
            | {
                ".cpp",
                ".cc",
                ".cxx",
                ".hpp",
                ".hxx",
                ".hh",
                ".pdb",
                ".obj",
                ".o",
                ".lib",
                ".a",
                ".log",
                ".debug",
                ".inc",
                ".inl",
                ".asm",
                ".s",
                ".m",
                ".mm",
                ".cmake",
            }
            or any(
                part.lower()
                in {
                    ".firm",
                    ".cache",
                    ".git",
                    ".svn",
                    ".venv",
                    "__pycache__",
                    "addons",
                    "reports",
                    "cmakefiles",
                }
                for part in path.parts
            )
            or path.name.lower()
            in {
                "cargo.toml",
                "pyproject.toml",
                "uv.lock",
                "cmakecache.txt",
                "compile_commands.json",
            }
        )
        forbidden = forbidden or any(part.endswith(".dSYM") for part in path.parts)
        if forbidden and name not in pinned_resources:
            raise RuntimeError(
                f"Windows payload leaked source/development file: {name}"
            )
    analysis_tools.validate_analysis(
        manifest["files"],
        read_bytes,
        analysis_tools.strict_json(read_bytes("sbom.cdx.json")),
        lock,
    )
    if not native:
        analysis_tools.validate_windows_native(
            manifest["files"],
            read_bytes,
            analysis_tools.strict_json(read_bytes("sbom.cdx.json")),
            manifest.get("development_unsigned") is True,
        )
    if not native and manifest.get("development_unsigned") is True:
        program = lock["programs"]["clangd"]
        executable = next(
            leaf
            for leaf in program["selected_files"]
            if leaf["kind"] == "analysis-executable"
        )
        analysis_tools.checked_bytes(read_bytes(program["executable"]), executable)
    if native:
        import native_formats

        native_formats.validate_bundle_closure(
            manifest["files"], read_bytes, lock["platform"], lock["architecture"]
        )
        for leaf in manifest["files"]:
            if leaf["executable"] or leaf["kind"] == "analysis-dependency":
                assert_stripped_bytes(
                    read_bytes(leaf["path"]), lock["platform"], leaf["path"]
                )


def validate_windows_payload(manifest: dict, read_bytes) -> None:
    """Retained Windows caller interface."""
    if (
        manifest.get("platform", "windows"),
        manifest.get("architecture", "x86_64"),
    ) != (
        "windows",
        "x86_64",
    ):
        raise RuntimeError("Windows payload validator requires Windows x86_64")
    validate_payload(
        {"platform": "windows", "architecture": "x86_64", **manifest}, read_bytes
    )


def validate_bundle(bundle: Path, manifest: dict) -> None:
    native = manifest.get("platform") != "windows"
    if bundle.is_symlink() or bundle.is_junction() or not bundle.is_dir():
        raise RuntimeError(
            "Bundle root must be a regular directory without a link/reparse entry"
        )
    expected = {f["path"] for f in manifest["files"]} | {"release-manifest.json"}
    if manifest.get("development_unsigned") is False:
        expected.add("release-manifest.sig")
    actual = set()
    directories = {
        str(parent)
        for name in expected
        for parent in PurePosixPath(name).parents
        if str(parent) != "."
    }
    for path in bundle.rglob("*"):
        if path.is_symlink() or path.is_junction():
            raise RuntimeError(f"Bundle contains a link/reparse entry: {path}")
        if path.is_file():
            if not stat.S_ISREG(path.stat().st_mode) or path.stat().st_nlink != 1:
                raise RuntimeError(
                    f"Bundle contains a special/hard-linked entry: {path}"
                )
            actual.add(path.relative_to(bundle).as_posix())
        elif path.is_dir() and path.relative_to(bundle).as_posix() not in directories:
            raise RuntimeError(f"Bundle contains an unknown directory: {path}")
        elif not path.is_dir():
            raise RuntimeError(f"Bundle contains a special entry: {path}")
        if native and path.is_dir() and stat.S_IMODE(path.stat().st_mode) != 0o755:
            raise RuntimeError(f"Bundle directory permissions must be 0755: {path}")
    if native:
        for name in ("release-manifest.json", "release-manifest.sig"):
            if (
                name in expected
                and stat.S_IMODE((bundle / name).stat().st_mode) != 0o644
            ):
                raise RuntimeError(f"Bundle metadata permissions must be 0644: {name}")
    if actual != expected:
        raise RuntimeError(
            f"Bundle leaves differ from inventory: {sorted(actual ^ expected)}"
        )
    validate_payload(
        manifest,
        lambda name: (bundle / name).read_bytes(),
        read_mode=lambda name: stat.S_IMODE((bundle / name).stat().st_mode),
    )


def validate_windows_bundle(bundle: Path, manifest: dict) -> None:
    validate_bundle(bundle, manifest)


def _needle_encodings(text: str) -> list[bytes]:
    """A build identifier can be embedded as UTF-8 (ELF/Mach-O strings) or as
    UTF-16LE (Windows PE/PDB paths), so search for both forms."""
    encodings = [text.encode("utf-8")]
    utf16 = text.encode("utf-16-le")
    if utf16 not in encodings:
        encodings.append(utf16)
    return encodings


def build_leak_needles(
    *,
    home: Path | None,
    user: str | None,
    checkout_root: Path | None,
    extra: list[str],
) -> list[tuple[str, bytes]]:
    """Assemble the byte needles whose presence in a shipped file would prove the
    build machine leaked its own identity or internal layout.

    Identity needles (home dir + login name) are derived from the build
    environment and *skipped for shared CI/build accounts* (see
    ``GENERIC_BUILD_ACCOUNTS``), whose home directories legitimately show up in
    upstream toolchain/dependency debug paths. The absolute checkout path is
    always a needle — it reveals internal layout regardless of the account.
    """
    needles: list[tuple[str, bytes]] = []

    def add(label: str, text: str) -> None:
        text = text.strip()
        if not text:
            return
        for encoded in _needle_encodings(text):
            needles.append((label, encoded))

    is_generic = bool(user) and user.lower() in GENERIC_BUILD_ACCOUNTS
    if user and not is_generic:
        for separator in ("/", "\\"):
            add("build-username", f"{separator}{user}{separator}")
    if home is not None and not is_generic:
        add("build-home-path", str(home))
    if checkout_root is not None:
        add("build-checkout-path", str(checkout_root))
    for value in extra:
        add("extra-needle", value)
    return needles


def _context(data: bytes, start: int, length: int, radius: int = 48) -> str:
    """Render a short, printable snippet around a match for the error message."""
    window = data[max(0, start - radius) : start + length + radius]
    text = window.decode("latin-1")
    return "".join(char if 0x20 <= ord(char) < 0x7F else "." for char in text)


def _suppressed(data: bytes, start: int, length: int, allow: list[bytes]) -> bool:
    if not allow:
        return False
    window = data[max(0, start - 64) : start + length + 64]
    return any(token in window for token in allow)


def _matches_in(
    data: bytes,
    needles: list[tuple[str, bytes]],
    patterns: tuple[tuple[str, "re.Pattern[bytes]"], ...],
    allow: list[bytes],
) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for label, needle in needles:
        index = data.find(needle)
        if index != -1 and not _suppressed(data, index, len(needle), allow):
            hits.append((label, _context(data, index, len(needle))))
    for label, pattern in patterns:
        match = pattern.search(data)
        if match and not _suppressed(data, match.start(), len(match.group()), allow):
            hits.append((label, _context(data, match.start(), len(match.group()))))
    return hits


def _scan_file(
    path: Path,
    needles: list[tuple[str, bytes]],
    patterns: tuple[tuple[str, "re.Pattern[bytes]"], ...],
    allow: list[bytes],
) -> list[tuple[str, str]]:
    size = path.stat().st_size
    if size <= MAX_SCAN_BYTES:
        return _matches_in(path.read_bytes(), needles, patterns, allow)
    # Oversized artifact: stream with overlap so exact needles spanning a chunk
    # boundary are still caught. Regexes are skipped on this rare path.
    max_needle = max((len(needle) for _, needle in needles), default=0)
    overlap = max(max_needle - 1, 0)
    seen: set[tuple[str, str]] = set()
    hits: list[tuple[str, str]] = []
    carry = b""
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            window = carry + chunk
            for hit in _matches_in(window, needles, (), allow):
                if hit not in seen:
                    seen.add(hit)
                    hits.append(hit)
            carry = window[-overlap:] if overlap else b""
    return hits


def scan_bundle_for_leaks(
    bundle: Path,
    needles: list[tuple[str, bytes]],
    *,
    patterns: tuple[tuple[str, "re.Pattern[bytes]"], ...] = SECRET_PATTERNS,
    allow: tuple[str, ...] = (),
) -> list[tuple[str, str, str]]:
    """Scan every shipped file for build-machine identity or key material.

    Returns ``(relative_path, label, snippet)`` for each hit. An empty list means
    the bundle is clean.
    """
    allow_bytes = [encoded for token in allow for encoded in _needle_encodings(token)]
    findings: list[tuple[str, str, str]] = []
    for path in sorted(bundle.rglob("*")):
        if not path.is_file():
            continue
        for label, snippet in _scan_file(path, needles, patterns, allow_bytes):
            findings.append((path.relative_to(bundle).as_posix(), label, snippet))
    return findings


def _current_user() -> str | None:
    try:
        return getpass.getuser()
    except Exception:
        return None


def macho_debug_stab_count(data: bytes, limit: int) -> int | None:
    """Count Mach-O debug-map stab symbols (`N_STAB`) in a thin 64-bit image,
    stopping once `limit` is exceeded. Returns None if the bytes are not a thin
    little-endian Mach-O 64 image (the only form our per-target bundles ship)."""
    if len(data) < 32 or struct.unpack_from("<I", data, 0)[0] != MACHO_MAGIC_64_LE:
        return None
    ncmds = struct.unpack_from("<I", data, 16)[0]
    offset = 32
    count = 0
    for _ in range(ncmds):
        if offset + 8 > len(data):
            raise RuntimeError("Truncated Mach-O load command")
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmdsize < 8 or offset + cmdsize > len(data):
            raise RuntimeError("Invalid Mach-O load command bounds")
        if cmd == MACHO_LC_SYMTAB:
            if cmdsize != 24:
                raise RuntimeError("Invalid Mach-O symbol command")
            symoff, nsyms = struct.unpack_from("<II", data, offset + 8)
            if symoff + nsyms * 16 > len(data):
                raise RuntimeError("Truncated Mach-O symbol table")
            for index in range(nsyms):
                entry = symoff + index * 16
                if data[entry + 4] & MACHO_N_STAB:
                    count += 1
                    if count > limit:
                        return count
        offset += cmdsize
    return count


def elf_has_symtab(data: bytes) -> bool | None:
    """Whether a 64-bit ELF carries a `.symtab` section (removed by stripping).
    Returns None if the bytes are not a 64-bit ELF."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2:
        return None
    endian = "<" if data[5] == 1 else ">"
    shoff = struct.unpack_from(endian + "Q", data, 40)[0]
    shentsize = struct.unpack_from(endian + "H", data, 58)[0]
    shnum = struct.unpack_from(endian + "H", data, 60)[0]
    shstrndx = struct.unpack_from(endian + "H", data, 62)[0]
    if shnum == 0 and shoff == 0:
        return False
    if (
        shentsize != 64
        or shnum == 0
        or shstrndx >= shnum
        or shoff < 64
        or shoff + shnum * shentsize > len(data)
    ):
        raise RuntimeError("Invalid ELF section table")
    strtab_hdr = shoff + shstrndx * shentsize
    strtab_off = struct.unpack_from(endian + "Q", data, strtab_hdr + 24)[0]
    strtab_size = struct.unpack_from(endian + "Q", data, strtab_hdr + 32)[0]
    if strtab_off + strtab_size > len(data):
        raise RuntimeError("Truncated ELF section-name table")
    for index in range(shnum):
        header = shoff + index * shentsize
        name_off = struct.unpack_from(endian + "I", data, header)[0]
        if name_off >= strtab_size:
            raise RuntimeError("Invalid ELF section-name offset")
        end = data.find(b"\x00", strtab_off + name_off, strtab_off + strtab_size)
        if end < 0:
            raise RuntimeError("Unterminated ELF section name")
        if data[strtab_off + name_off : end] == b".symtab":
            return True
    return False


def pe_coff_symbol_table(data: bytes) -> tuple[int, int] | None:
    """The PE COFF `(PointerToSymbolTable, NumberOfSymbols)`, both 0 when stripped.
    Returns None if the bytes are not a PE image."""
    if len(data) < 64 or data[:2] != b"MZ":
        return None
    lfanew = struct.unpack_from("<I", data, 60)[0]
    if data[lfanew : lfanew + 4] != b"PE\x00\x00":
        return None
    coff = lfanew + 4
    pointer, count = struct.unpack_from("<II", data, coff + 8)
    return pointer, count


def assert_stripped(path: Path, platform: str) -> None:
    """Fail if a shipped executable still carries a debug symbol table. The
    private symbols were separated to `release/symbols/`; the customer artifact
    must not re-ship them. Parsers are calibrated against real stripped bundles:
    macOS keeps ~0–1 residual stabs, Linux drops `.symtab`, Windows zeroes the
    COFF symbol table (its symbols live in the separate `.pdb`)."""
    assert_stripped_bytes(path.read_bytes(), platform, path.name)


def assert_stripped_bytes(data: bytes, platform: str, name: str) -> None:
    if platform == "macos":
        count = macho_debug_stab_count(data, MACHO_MAX_STAB)
        if count is None:
            raise RuntimeError(
                f"{name}: not a thin Mach-O 64 image; cannot verify strip"
            )
        if count > MACHO_MAX_STAB:
            raise RuntimeError(
                f"{name}: {count}+ Mach-O debug symbols present — not stripped"
            )
    elif platform == "linux":
        present = elf_has_symtab(data)
        if present is None:
            raise RuntimeError(f"{name}: not a 64-bit ELF; cannot verify strip")
        if present:
            raise RuntimeError(f"{name}: ELF .symtab present — not stripped")
    elif platform == "windows":
        table = pe_coff_symbol_table(data)
        if table is None:
            raise RuntimeError(f"{name}: not a PE image; cannot verify strip")
        pointer, count = table
        if pointer != 0 or count != 0:
            raise RuntimeError(
                f"{name}: PE COFF symbol table present ({count} symbols) — not stripped"
            )
    else:
        raise RuntimeError(f"unsupported platform for strip verification: {platform}")


def shipped_executables(bundle: Path, platform: str) -> list[Path]:
    """The two executables the pipeline strips: the public launcher and the
    sidecar's main binary. Bundled dependency `.so`/`.dylib` from upstream wheels
    are not our strip target and are excluded."""
    suffix = ".exe" if platform == "windows" else ""
    result = [bundle / f"byo{suffix}", bundle / "sidecar" / f"byo-mcp-sidecar{suffix}"]
    if platform != "windows" and (bundle / "analysis/runtime.json").is_file():
        mapping = analysis_tools.strict_json(
            (bundle / "analysis/runtime.json").read_bytes()
        )
        result += [
            bundle / program["executable"] for program in mapping["programs"].values()
        ]
    return result


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] in {
        "windows-analysis-archive",
        "analysis-archive",
    }:
        windows_alias = sys.argv[1] == "windows-analysis-archive"
        parser = argparse.ArgumentParser(
            description="Static target-specific analysis archive checks; signatures and native execution are separate gates"
        )
        parser.add_argument("--archive", type=Path, required=True)
        parser.add_argument("--receipt", type=Path, required=True)
        parser.add_argument(
            "--expected-target",
            required=not windows_alias,
            default="windows-x86_64" if windows_alias else None,
        )
        args = parser.parse_args(sys.argv[2:])
        target = analysis_tools.canonical_target(args.expected_target)
        if windows_alias and target != "windows-x86_64":
            raise RuntimeError("windows-analysis-archive requires Windows x86_64")
        expected_platform, _ = expected_identity(target)
        archive_kind = "tar.gz" if expected_platform == "linux" else "zip"
        archive_context = (
            zipfile.ZipFile(args.archive)
            if archive_kind == "zip"
            else tarfile.open(args.archive, "r:gz")
        )
        with archive_context as archive:
            names = archive.namelist() if archive_kind == "zip" else archive.getnames()
            manifests = [
                name
                for name in names
                if len(PurePosixPath(name).parts) == 2
                and PurePosixPath(name).name == "release-manifest.json"
            ]
            if len(manifests) != 1:
                raise RuntimeError("Archive requires one root release manifest")
            name = PurePosixPath(manifests[0]).parent.as_posix()

            def read_bytes(path):
                full = f"{name}/{path}"
                return (
                    archive.read(full)
                    if archive_kind == "zip"
                    else archive.extractfile(full).read()
                )

            data = read_bytes("release-manifest.json")
            manifest = analysis_tools.strict_json(data)
            lock = json.loads((ROOT / "release/source-lock.json").read_bytes())
            for key in ("agent_workspace", "firmware_mcp"):
                if manifest.get("source", {}).get(key) != {
                    "repository": lock[key]["repository"],
                    "commit": lock[key]["commit"],
                }:
                    raise RuntimeError(
                        f"Windows analysis archive {key} source pin mismatch"
                    )
            validate_archive(
                args.archive, archive_kind, name, manifest, expected_target=target
            )
            if expected_platform == "windows":
                result = analysis_tools.validate_pe_closure(
                    manifest["files"], read_bytes
                )
            else:
                import native_formats

                result = native_formats.validate_closure(
                    analysis_tools.load_lock(target=target), read_bytes
                )
        result.update(
            archive_sha256=sha256(args.archive),
            manifest_sha256=analysis_tools.sha256(data),
            source=manifest["source"],
            target=target,
            evidence_kind="Windows-host platform-neutral archive verification"
            if os.name == "nt" and expected_platform != "windows"
            else "static archive verification; probes/installed behavior are separate gates",
        )
        analysis_tools.write_json(args.receipt, result)
        print(
            json.dumps(
                {
                    "receipt": str(args.receipt),
                    "archive_sha256": result["archive_sha256"],
                },
                sort_keys=True,
            )
        )
        return 0
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--expected-target", required=True)
    parser.add_argument("--archive-type", choices=("zip", "tar.gz"), required=True)
    parser.add_argument(
        "--no-leak-scan",
        action="store_true",
        help="disable the embedded content-leakage scan (discouraged)",
    )
    parser.add_argument(
        "--leak-allow",
        action="append",
        default=[],
        metavar="SUBSTR",
        help="suppress leakage hits whose surrounding bytes contain SUBSTR (repeatable)",
    )
    parser.add_argument(
        "--leak-string",
        action="append",
        default=[],
        metavar="TEXT",
        help="additional literal string that must not appear in the bundle (repeatable)",
    )
    parser.add_argument(
        "--leak-user",
        default=None,
        help="override the build-username needle (default: current login name)",
    )
    parser.add_argument(
        "--leak-home",
        default=None,
        help="override the build home-path needle (default: current home directory)",
    )
    args = parser.parse_args()

    platform, architecture = expected_identity(args.expected_target)
    bundles = sorted(
        path
        for path in args.dist.iterdir()
        if path.is_dir() and path.name.startswith("byo-")
    )
    if len(bundles) != 1:
        raise RuntimeError(f"expected exactly one native bundle, found {bundles}")
    bundle = bundles[0]
    manifest_path = bundle / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (
        manifest.get("platform") != platform
        or manifest.get("architecture") != architecture
    ):
        raise RuntimeError("release manifest target does not match the native job")
    if manifest.get("development_unsigned") is not True:
        raise RuntimeError(
            "unprotected build jobs may only produce development candidates"
        )

    lock = json.loads((ROOT / "release/source-lock.json").read_text(encoding="utf-8"))
    source = manifest.get("source", {})
    for manifest_key, lock_key in (
        ("agent_workspace", "agent_workspace"),
        ("firmware_mcp", "firmware_mcp"),
    ):
        if source.get(manifest_key, {}).get("commit") != lock[lock_key]["commit"]:
            raise RuntimeError(
                f"manifest {manifest_key} commit does not match source lock"
            )
    installer_commit = source.get("installer", {}).get("commit", "")
    if len(installer_commit) != 40:
        raise RuntimeError("manifest does not contain the installer source commit")
    toolchain = manifest.get("toolchain", {})
    if any(
        not isinstance(toolchain.get(key), str) or not toolchain[key]
        for key in (
            "rustc",
            "cargo",
            "python",
            "nuitka",
        )
    ):
        raise RuntimeError("manifest does not contain complete toolchain provenance")

    validate_bundle(bundle, manifest)
    leak_scan = "skipped"
    if not args.no_leak_scan:
        needles = build_leak_needles(
            home=Path(args.leak_home) if args.leak_home else Path.home(),
            user=args.leak_user if args.leak_user is not None else _current_user(),
            checkout_root=ROOT,
            extra=args.leak_string,
        )
        findings = scan_bundle_for_leaks(bundle, needles, allow=tuple(args.leak_allow))
        if findings:
            rendered = "\n".join(
                f"  {rel}: [{label}] {snippet}" for rel, label, snippet in findings[:50]
            )
            more = "" if len(findings) <= 50 else f"\n  … and {len(findings) - 50} more"
            raise RuntimeError(
                "bundle leaked build-machine identity or key material "
                f"({len(findings)} hit(s)):\n{rendered}{more}\n"
                "Release artifacts are built on the signed CI matrix under a shared "
                "account; a local build embeds your home path and login name. If a "
                "match is a verified false positive, pass --leak-allow <substring>."
            )
        leak_scan = "clean"

    for executable in shipped_executables(bundle, platform):
        if not executable.is_file():
            raise RuntimeError(f"shipped executable is missing: {executable}")
        assert_stripped(executable, platform)

    archives = sorted(
        path
        for path in args.dist.iterdir()
        if path.is_file()
        and (path.name == f"{bundle.name}.zip" or path.name == f"{bundle.name}.tar.gz")
    )
    if len(archives) != 1:
        raise RuntimeError(f"expected one explicit release archive, found {archives}")
    archive = archives[0]
    validate_archive(
        archive,
        args.archive_type,
        bundle.name,
        manifest,
        expected_target=args.expected_target,
    )
    pe_receipt = None
    if platform == "windows":
        pe_receipt = ROOT / "release/build/analysis-evidence/verified-pe-closure.json"
        analysis_tools.write_json(
            pe_receipt,
            analysis_tools.validate_pe_closure(
                manifest["files"], lambda name: (bundle / name).read_bytes()
            ),
        )
    checksum = (args.dist / f"{bundle.name}.sha256").read_text(encoding="utf-8").strip()
    if checksum != f"{sha256(archive)}  {archive.name}":
        raise RuntimeError("archive checksum receipt does not match the exact artifact")
    symbol_root = ROOT / "release" / "symbols" / bundle.name
    symbol_inventory = json.loads(
        (symbol_root / "symbols.json").read_text(encoding="utf-8")
    )
    symbol_paths = {
        item.get("path")
        for item in symbol_inventory.get("files", [])
        if isinstance(item, dict)
    }
    if "nuitka-compilation-report.xml" not in symbol_paths:
        raise RuntimeError(
            "private symbol output is missing the Nuitka compilation report"
        )
    expected_symbol_suffix = {
        "macos": ".dSYM/",
        "windows": ".pdb",
        "linux": ".debug",
    }[platform]
    if not any(
        (
            expected_symbol_suffix in str(path)
            if platform == "macos"
            else str(path).endswith(expected_symbol_suffix)
        )
        for path in symbol_paths
    ):
        raise RuntimeError(f"private symbol output is incomplete for {platform}")
    print(
        json.dumps(
            {
                "archive": str(archive),
                "archive_sha256": sha256(archive),
                "manifest_sha256": sha256(manifest_path),
                "leak_scan": leak_scan,
                "strip_check": "clean",
                "target": args.expected_target,
                **({"pe_closure_receipt": str(pe_receipt)} if pe_receipt else {}),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
