#!/usr/bin/env python3
"""Fail a native build when its bundle, provenance, or archive contract drifts."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import re
import struct
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

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
    values = {
        "macos-aarch64": ("macos", "aarch64"),
        "macos-x86_64": ("macos", "x86_64"),
        "windows-x86_64": ("windows", "x86_64"),
        "linux-x86_64-glibc-2.28": ("linux", "x86_64"),
    }
    try:
        return values[target]
    except KeyError as exc:
        raise RuntimeError(f"unsupported build target contract: {target}") from exc


def validate_archive_paths(names: list[str], bundle_name: str) -> None:
    if not names or len(names) > MAX_ENTRIES:
        raise RuntimeError("archive is empty or contains too many entries")
    seen: set[str] = set()
    for name in names:
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


def validate_archive(archive: Path, archive_type: str, bundle_name: str) -> None:
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
    elif archive_type == "tar.gz":
        if not archive.name.endswith(".tar.gz"):
            raise RuntimeError("Linux target did not produce a .tar.gz archive")
        with tarfile.open(archive, "r:gz") as handle:
            members = handle.getmembers()
            validate_archive_paths([member.name for member in members], bundle_name)
            if any(not (member.isfile() or member.isdir()) for member in members):
                raise RuntimeError("tar archive contains a forbidden non-file entry")
    else:
        raise RuntimeError(f"unsupported archive contract: {archive_type}")


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
            break
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmd == MACHO_LC_SYMTAB:
            symoff, nsyms = struct.unpack_from("<II", data, offset + 8)
            for index in range(nsyms):
                entry = symoff + index * 16
                if entry + 5 > len(data):
                    break
                if data[entry + 4] & MACHO_N_STAB:
                    count += 1
                    if count > limit:
                        return count
        if cmdsize == 0:
            break
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
    strtab_hdr = shoff + shstrndx * shentsize
    strtab_off = struct.unpack_from(endian + "Q", data, strtab_hdr + 24)[0]
    for index in range(shnum):
        header = shoff + index * shentsize
        name_off = struct.unpack_from(endian + "I", data, header)[0]
        end = data.index(b"\x00", strtab_off + name_off)
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
    data = path.read_bytes()
    if platform == "macos":
        count = macho_debug_stab_count(data, MACHO_MAX_STAB)
        if count is None:
            raise RuntimeError(
                f"{path.name}: not a thin Mach-O 64 image; cannot verify strip"
            )
        if count > MACHO_MAX_STAB:
            raise RuntimeError(
                f"{path.name}: {count}+ Mach-O debug symbols present — not stripped"
            )
    elif platform == "linux":
        present = elf_has_symtab(data)
        if present is None:
            raise RuntimeError(f"{path.name}: not a 64-bit ELF; cannot verify strip")
        if present:
            raise RuntimeError(f"{path.name}: ELF .symtab present — not stripped")
    elif platform == "windows":
        table = pe_coff_symbol_table(data)
        if table is None:
            raise RuntimeError(f"{path.name}: not a PE image; cannot verify strip")
        pointer, count = table
        if pointer != 0 or count != 0:
            raise RuntimeError(
                f"{path.name}: PE COFF symbol table present ({count} symbols) — not stripped"
            )
    else:
        raise RuntimeError(f"unsupported platform for strip verification: {platform}")


def shipped_executables(bundle: Path, platform: str) -> list[Path]:
    """The two executables the pipeline strips: the public launcher and the
    sidecar's main binary. Bundled dependency `.so`/`.dylib` from upstream wheels
    are not our strip target and are excluded."""
    suffix = ".exe" if platform == "windows" else ""
    return [bundle / f"byo{suffix}", bundle / "sidecar" / f"byo-mcp-sidecar{suffix}"]


def main() -> int:
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

    forbidden = [
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file()
        and (
            path.suffix.lower() in FORBIDDEN_SUFFIXES
            or "__pycache__" in path.parts
            or path.name in {"Cargo.toml", "pyproject.toml", "uv.lock"}
        )
    ]
    if forbidden:
        raise RuntimeError(f"bundle leaked source or development files: {forbidden}")

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
    validate_archive(archive, args.archive_type, bundle.name)
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
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
