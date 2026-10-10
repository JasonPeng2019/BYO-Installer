"""Bounded, platform-neutral ELF/Mach-O inspection for analyzer packaging.

This module reads bytes only. It never loads a library or runs another target's
program. The release gate uses the same inspection for expanded and archive bytes.
"""

from __future__ import annotations

import posixpath
import re
import struct


def _unpack(data: bytes, fmt: str, offset: int):
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise RuntimeError("Truncated native image structure")
    return struct.unpack_from(fmt, data, offset)


def _string(data: bytes, offset: int, end: int) -> str:
    if not 0 <= offset < end <= len(data):
        raise RuntimeError("Native string offset outside its table")
    terminator = data.find(b"\0", offset, end)
    if terminator < 0:
        raise RuntimeError("Unterminated native image string")
    try:
        return data[offset:terminator].decode("ascii")
    except UnicodeDecodeError as exc:
        raise RuntimeError("Non-ASCII native loader input") from exc


def elf(data: bytes, executable: bool) -> dict:
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise RuntimeError("Expected complete little-endian ELF64 image")
    kind, machine, version = _unpack(data, "<HHI", 16)
    if machine != 62 or version != 1 or kind not in ({2, 3} if executable else {3}):
        raise RuntimeError("Wrong ELF architecture/version/type")
    phoff = _unpack(data, "<Q", 32)[0]
    ehsize, phsize, phnum = _unpack(data, "<HHH", 52)
    if (
        ehsize != 64
        or phsize != 56
        or not phnum
        or phoff < 64
        or phoff + phsize * phnum > len(data)
    ):
        raise RuntimeError("Invalid ELF program header table")
    segments, dynamic, interpreter = [], None, None
    for i in range(phnum):
        ptype, flags, offset, address, _, filesz, memsz, align = _unpack(
            data, "<IIQQQQQQ", phoff + i * phsize
        )
        if filesz > memsz or offset + filesz > len(data):
            raise RuntimeError("ELF segment extends outside image")
        if ptype == 1:
            segments.append((address, offset, filesz))
        elif ptype == 2:
            if dynamic is not None or filesz % 16:
                raise RuntimeError("Duplicate/malformed ELF dynamic segment")
            dynamic = (offset, filesz)
        elif ptype == 3:
            if interpreter is not None:
                raise RuntimeError("Duplicate ELF interpreter")
            interpreter = _string(data, offset, offset + filesz)

    def address_offset(address: int, size: int = 1) -> int:
        matches = [
            offset + address - start
            for start, offset, length in segments
            if start <= address and address + size <= start + length
        ]
        if len(matches) != 1:
            raise RuntimeError("ELF virtual address outside unique file-backed LOAD")
        return matches[0]

    tags = {}
    if dynamic:
        offset, size = dynamic
        terminated = False
        for current in range(offset, offset + size, 16):
            tag, value = _unpack(data, "<qQ", current)
            if tag == 0:
                terminated = True
                break
            tags.setdefault(tag, []).append(value)
        if not terminated:
            raise RuntimeError("Unterminated ELF dynamic table")
    for tag in (
        5,
        10,
        14,
        15,
        29,
        0x6FFFFFFB,
        0x6FFFFFFC,
        0x6FFFFFFD,
        0x6FFFFFFE,
        0x6FFFFFFF,
    ):
        if len(tags.get(tag, [])) > 1:
            raise RuntimeError("Duplicate singleton ELF dynamic tag")
    needs, paths, versions, definitions, soname = [], [], [], [], None
    if any(tag in tags for tag in (1, 14, 15, 29, 0x6FFFFFFC, 0x6FFFFFFE)):
        if not tags.get(5) or not tags.get(10):
            raise RuntimeError("ELF dynamic string table missing")
        string_size = tags[10][0]
        string_base = address_offset(tags[5][0], string_size)

        def dyn_string(index):
            return _string(data, string_base + index, string_base + string_size)

        needs = [dyn_string(index) for index in tags.get(1, [])]
        paths = [dyn_string(index) for tag in (15, 29) for index in tags.get(tag, [])]
        soname = dyn_string(tags[14][0]) if 14 in tags else None
        if 0x6FFFFFFE in tags:
            if 0x6FFFFFFF not in tags or tags[0x6FFFFFFF][0] > len(data) // 16:
                raise RuntimeError("Invalid ELF version-needs count")
            current = tags[0x6FFFFFFE][0]
            for i in range(tags[0x6FFFFFFF][0]):
                pos = address_offset(current, 16)
                revision, count, library_index, aux, following = _unpack(
                    data, "<HHIII", pos
                )
                if revision != 1 or not count or count > len(data) // 16:
                    raise RuntimeError("Malformed ELF version-needs record")
                library = dyn_string(library_index)
                cursor = current + aux
                for j in range(count):
                    _, _, _, name_index, next_aux = _unpack(
                        data, "<IHHII", address_offset(cursor, 16)
                    )
                    versions.append(
                        {"library": library, "version": dyn_string(name_index)}
                    )
                    if bool(next_aux) != (j + 1 < count):
                        raise RuntimeError(
                            "Malformed ELF version-needs auxiliary chain"
                        )
                    cursor += next_aux
                if bool(following) != (i + 1 < tags[0x6FFFFFFF][0]):
                    raise RuntimeError("Malformed ELF version-needs chain")
                current += following
        if 0x6FFFFFFC in tags:
            if 0x6FFFFFFD not in tags or tags[0x6FFFFFFD][0] > len(data) // 20:
                raise RuntimeError("Invalid ELF version-definition count")
            current = tags[0x6FFFFFFC][0]
            for i in range(tags[0x6FFFFFFD][0]):
                revision, _, _, count, _, auxiliary, following = _unpack(
                    data, "<HHHHIII", address_offset(current, 20)
                )
                if (
                    revision != 1
                    or not count
                    or not auxiliary
                    or count > len(data) // 8
                ):
                    raise RuntimeError("Malformed ELF version definition")
                cursor = current + auxiliary
                for j in range(count):
                    name_index, next_aux = _unpack(
                        data, "<II", address_offset(cursor, 8)
                    )
                    definitions.append(dyn_string(name_index))
                    if bool(next_aux) != (j + 1 < count):
                        raise RuntimeError(
                            "Malformed ELF version-definition auxiliary chain"
                        )
                    cursor += next_aux
                if bool(following) != (i + 1 < tags[0x6FFFFFFD][0]):
                    raise RuntimeError("Malformed ELF version-definition chain")
                current += following
    pie = bool(tags.get(0x6FFFFFFB, [0])[0] & 0x08000000)
    if executable and kind == 3 and not (interpreter or pie):
        raise RuntimeError("ELF shared library presented as an executable")
    if not executable and interpreter:
        raise RuntimeError("ELF executable presented as a private library")
    if interpreter is not None and interpreter != "/lib64/ld-linux-x86-64.so.2":
        raise RuntimeError(f"Unsupported Linux interpreter: {interpreter}")
    # Loader hooks that would add undeclared imports are not part of this recipe.
    if any(tag in tags for tag in (0x7FFFFFFD, 0x7FFFFFFF, 0x6FFFFEFC, 0x6FFFFEFB)):
        raise RuntimeError("ELF contains undeclared audit/filter loader input")
    return {
        "format": "ELF64",
        "machine": machine,
        "type": kind,
        "interpreter": interpreter,
        "needed": needs,
        "search_paths": paths,
        "versions": versions,
        "defined_versions": definitions,
        "soname": soname,
    }


def macho(
    data: bytes, architecture: str, executable: bool, *, allow_bundle: bool = False
) -> dict:
    if len(data) < 32 or data[:4] != b"\xcf\xfa\xed\xfe":
        raise RuntimeError("Expected a complete thin little-endian Mach-O 64 image")
    _, cpu, subtype, kind, count, size, flags, _ = _unpack(data, "<8I", 0)
    expected = {"aarch64": 0x0100000C, "x86_64": 0x01000007}[architecture]
    if cpu != expected or kind not in (
        {2} if executable else {6, 8} if allow_bundle else {6}
    ):
        raise RuntimeError("Wrong Mach-O CPU/file type")
    if subtype & 0x00FFFFFF not in ({0} if architecture == "aarch64" else {0, 3}):
        raise RuntimeError("Specialized Mach-O CPU subtype exceeds the target baseline")
    if size > len(data) - 32 or count > size // 8:
        raise RuntimeError("Truncated Mach-O load command table")
    loads, rpaths, minima, install_name = [], [], [], None
    offset = 32
    for _ in range(count):
        command, length = _unpack(data, "<II", offset)
        if length < 8 or length % 8 or offset + length > 32 + size:
            raise RuntimeError("Invalid Mach-O load command bounds")
        if command in {0xC, 0xD, 0x20, 0x80000018, 0x8000001F, 0x80000023}:
            if length < 24:
                raise RuntimeError("Truncated Mach-O dylib command")
            name_offset = _unpack(data, "<I", offset + 8)[0]
            if name_offset < 24:
                raise RuntimeError("Invalid Mach-O dylib string")
            name = _string(data, offset + name_offset, offset + length)
            if command == 0xD:
                if install_name is not None:
                    raise RuntimeError("Duplicate Mach-O install name")
                install_name = name
            else:
                loads.append(name)
        elif command == 0x19:
            if length < 72:
                raise RuntimeError("Truncated Mach-O segment command")
            vmaddr, vmsize, fileoff, filesize, _, _, sections, _ = _unpack(
                data, "<QQQQIIII", offset + 24
            )
            if (
                length != 72 + 80 * sections
                or fileoff + filesize > len(data)
                or filesize > vmsize
            ):
                raise RuntimeError("Invalid Mach-O segment/section bounds")
            for index in range(sections):
                section = offset + 72 + 80 * index
                _, section_size, section_offset = _unpack(data, "<QQI", section + 32)
                section_flags = _unpack(data, "<I", section + 64)[0]
                if section_flags & 0xFF not in {
                    1,
                    0xC,
                    0x12,
                } and section_offset + section_size > len(data):
                    raise RuntimeError("Mach-O section extends beyond image")
        elif command == 0xE:
            name_offset = _unpack(data, "<I", offset + 8)[0]
            if (
                name_offset < 12
                or _string(data, offset + name_offset, offset + length)
                != "/usr/lib/dyld"
            ):
                raise RuntimeError("Unsupported Mach-O dynamic loader")
        elif command == 0x2:
            if length != 24:
                raise RuntimeError("Malformed Mach-O symbol table command")
            symoff, nsyms, stroff, strsize = _unpack(data, "<4I", offset + 8)
            if symoff + nsyms * 16 > len(data) or stroff + strsize > len(data):
                raise RuntimeError("Mach-O symbol/string table extends beyond image")
        elif command == 0x8000001C:
            name_offset = _unpack(data, "<I", offset + 8)[0]
            if name_offset < 12:
                raise RuntimeError("Invalid Mach-O rpath string")
            rpaths.append(_string(data, offset + name_offset, offset + length))
        elif command == 0x24:
            if length != 16:
                raise RuntimeError("Malformed Mach-O minimum version command")
            minima.append(_unpack(data, "<I", offset + 8)[0])
        elif command == 0x32:
            if length < 24:
                raise RuntimeError("Truncated Mach-O build version")
            target, minimum, _, tools = _unpack(data, "<4I", offset + 8)
            if target != 1 or length != 24 + tools * 8:
                raise RuntimeError("Wrong Mach-O platform/build version")
            minima.append(minimum)
        elif command in {0x6, 0x7, 0x9, 0x10, 0x27}:
            raise RuntimeError("Mach-O contains undeclared loader environment/input")
        offset += length
    if (
        offset != 32 + size
        or len(minima) != 1
        or not minima[0]
        or minima[0] > 0x000C0000
    ):
        raise RuntimeError("Mach-O minimum OS missing/ambiguous/above macOS 12")
    return {
        "format": "Mach-O64",
        "cpu": cpu,
        "type": kind,
        "minimum_os": minima[0],
        "needed": loads,
        "search_paths": rpaths,
        "install_name": install_name,
    }


def validate_bundle_closure(
    files: list[dict], read_bytes, platform: str, architecture: str
) -> dict:
    """Check every delivered native image, including launcher/sidecar wheel libraries.

    Analyzer-specific imports are checked separately with their narrower OS policy
    and explicit mapping dependencies. This gate also catches a sidecar wheel
    silently raising the product's OS baseline.
    """
    images = {}
    for leaf in files:
        data = read_bytes(leaf["path"])
        if data[:4] in {
            b"\xca\xfe\xba\xbe",
            b"\xbe\xba\xfe\xca",
            b"\xca\xfe\xba\xbf",
            b"\xbf\xba\xfe\xca",
        }:
            raise RuntimeError(
                f"Universal Mach-O must be thinned before delivery: {leaf['path']}"
            )
        if data[:4] == b"\x7fELF":
            if platform != "linux":
                raise RuntimeError("ELF image in a non-Linux bundle")
            images[leaf["path"]] = elf(data, leaf["executable"])
        elif data[:4] in {
            b"\xcf\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xce",
        }:
            if platform != "macos":
                raise RuntimeError("Mach-O image in a non-macOS bundle")
            images[leaf["path"]] = macho(
                data, architecture, leaf["executable"], allow_bundle=True
            )
        elif data[:2] == b"MZ":
            raise RuntimeError(f"PE image in a native POSIX bundle: {leaf['path']}")
        elif leaf["executable"]:
            raise RuntimeError(
                f"Native executable is a script/invalid image: {leaf['path']}"
            )
    linux_os = LINUX_OS | {"libgcc_s.so.1"}
    macos_os = MACOS_OS | {
        "/usr/lib/libobjc.A.dylib",
        "/usr/lib/libc++abi.dylib",
        "/usr/lib/libiconv.2.dylib",
        "/usr/lib/libbz2.1.0.dylib",
        "/usr/lib/liblzma.5.dylib",
        "/usr/lib/libncurses.5.4.dylib",
        "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit",
        "/System/Library/Frameworks/Security.framework/Versions/A/Security",
        "/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/SystemConfiguration",
    }
    for path, info in images.items():
        origin = posixpath.dirname(path)
        private_root = (
            ("analysis/" + path.split("/")[1])
            if path.startswith("analysis/")
            else "sidecar"
            if path.startswith("sidecar/")
            else ""
        )
        executable_origin = (
            posixpath.dirname(path)
            if path
            in {
                "byo",
                "sidecar/byo-mcp-sidecar",
                "analysis/cppcheck/cppcheck",
                "analysis/clangd/bin/clangd",
            }
            else "sidecar"
            if private_root == "sidecar"
            else "analysis/clangd/bin"
            if private_root == "analysis/clangd"
            else "analysis/cppcheck"
        )

        def resolve(value):
            tokens = (
                {"$ORIGIN": origin}
                if platform == "linux"
                else {"@loader_path": origin, "@executable_path": executable_origin}
            )
            for token, directory in tokens.items():
                if value == token or value.startswith(token + "/"):
                    tail = value[len(token) :].lstrip("/")
                    if (
                        tail.startswith("/")
                        or "\\" in tail
                        or value.startswith(token + "//")
                    ):
                        break
                    result = posixpath.normpath(posixpath.join(directory, tail))
                    if private_root and (
                        result == private_root or result.startswith(private_root + "/")
                    ):
                        return result
            raise RuntimeError(
                f"Native loader input escapes private payload or uses host/cwd search: {path}: {value}"
            )

        search = []
        for value in info["search_paths"]:
            search.extend(
                resolve(part)
                for part in (value.split(":") if platform == "linux" else [value])
            )
        resolved_imports = {}
        for needed in info["needed"]:
            if needed in (linux_os if platform == "linux" else macos_os):
                continue
            if platform == "linux":
                if "/" in needed or not needed:
                    raise RuntimeError(f"Nonportable ELF import: {path}: {needed}")
                matches = list(
                    dict.fromkeys(
                        directory + "/" + needed
                        for directory in search
                        if directory + "/" + needed in images
                    )
                )
            elif needed.startswith(("@loader_path/", "@executable_path/")):
                matches = [resolve(needed)]
            elif needed.startswith("@rpath/") and "/" not in needed[len("@rpath/") :]:
                matches = list(
                    dict.fromkeys(
                        directory + "/" + needed[len("@rpath/") :]
                        for directory in search
                        if directory + "/" + needed[len("@rpath/") :] in images
                    )
                )
            else:
                raise RuntimeError(f"Unresolved non-OS Mach-O import: {path}: {needed}")
            if len(matches) != 1 or matches[0] not in images:
                raise RuntimeError(
                    f"Unresolved or ambiguous private native import: {path}: {needed}"
                )
            resolved_imports[needed] = matches[0]
        if platform == "linux":
            for requirement in info["versions"]:
                library, version = requirement["library"], requirement["version"]
                if library not in info["needed"]:
                    raise RuntimeError("Version requirement has no matching DT_NEEDED")
                if library in LINUX_OS:
                    match = re.fullmatch(
                        r"GLIBC_([0-9]+)\.([0-9]+)(?:\.([0-9]+))?", version
                    )
                    if not match or tuple(int(p or 0) for p in match.groups()) > (
                        2,
                        28,
                        0,
                    ):
                        raise RuntimeError(
                            f"Native bundle exceeds glibc 2.28 ABI: {path}: {version}"
                        )
                elif library == "libgcc_s.so.1":
                    match = re.fullmatch(
                        r"GCC_([0-9]+)\.([0-9]+)(?:\.([0-9]+))?", version
                    )
                    if not match or tuple(int(p or 0) for p in match.groups()) > (
                        7,
                        0,
                        0,
                    ):
                        raise RuntimeError(
                            f"Native bundle exceeds baseline GCC runtime ABI: {path}: {version}"
                        )
                elif (
                    version not in images[resolved_imports[library]]["defined_versions"]
                ):
                    raise RuntimeError(
                        f"Private ELF library does not define needed version: {path}: {requirement}"
                    )
        elif info["type"] == 6:
            install_name = info["install_name"]
            if not install_name or not install_name.startswith(
                ("@rpath/", "@loader_path/")
            ):
                raise RuntimeError(
                    f"Native private dylib has an absolute/unportable install name: {path}"
                )
        info["resolved_private_imports"] = resolved_imports
    return {
        "platform": platform,
        "architecture": architecture,
        "images": images,
        "evidence_kind": "static delivered-native-image closure; native baseline execution is a separate gate",
    }


LINUX_OS = frozenset(
    {
        "libpthread.so.0",
        "librt.so.1",
        "libdl.so.2",
        "libm.so.6",
        "libc.so.6",
        "ld-linux-x86-64.so.2",
        "libresolv.so.2",
        "libutil.so.1",
    }
)
MACOS_OS = frozenset(
    {
        "/usr/lib/libSystem.B.dylib",
        "/usr/lib/libresolv.9.dylib",
        "/usr/lib/libedit.3.dylib",
        "/usr/lib/libz.1.dylib",
        "/usr/lib/libc++.1.dylib",
        "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
    }
)


def validate_closure(lock: dict, read_bytes) -> dict:
    result = {}
    for name, program in lock["programs"].items():
        private_root = f"analysis/{name}/lib"
        dependencies = program["dependencies"]
        for path in dependencies:
            suffix = (
                r"[^/]+\.so(?:\.[0-9]+)*"
                if lock["platform"] == "linux"
                else r"[^/]+\.dylib"
            )
            if not re.fullmatch(re.escape(private_root) + "/" + suffix, path):
                raise RuntimeError(f"Invalid private library location: {path}")
        images = {}
        for path in [program["executable"], *dependencies]:
            images[path] = (
                elf(read_bytes(path), path == program["executable"])
                if lock["platform"] == "linux"
                else macho(
                    read_bytes(path),
                    lock["architecture"],
                    path == program["executable"],
                )
            )
        used = set()
        for path, info in images.items():
            origin = posixpath.dirname(path)

            def resolve_loader(value: str) -> str:
                token = "$ORIGIN/" if lock["platform"] == "linux" else "@loader_path/"
                if value == token.rstrip("/"):
                    if origin != private_root:
                        raise RuntimeError(
                            "Bare loader origin does not select the private library directory"
                        )
                    return origin
                if not value.startswith(token):
                    raise RuntimeError(
                        f"Nonportable native search path: {path}: {value}"
                    )
                relative = value[len(token) :]
                if not relative or relative.startswith("/") or "\\" in relative:
                    raise RuntimeError("Empty/absolute native search path")
                resolved = posixpath.normpath(posixpath.join(origin, relative))
                if resolved != private_root and not resolved.startswith(
                    private_root + "/"
                ):
                    raise RuntimeError(
                        f"Native loader reference escapes private library root: {value}"
                    )
                return resolved

            search = []
            for value in info["search_paths"]:
                for part in value.split(":" if lock["platform"] == "linux" else "\0"):
                    directory = resolve_loader(part)
                    if directory != private_root:
                        raise RuntimeError(
                            "Native library search must select the exact private lib directory"
                        )
                    search.append(directory)
            for needed in info["needed"]:
                if lock["platform"] == "linux":
                    if "/" in needed or not needed:
                        raise RuntimeError(f"Absolute/relative ELF import: {needed}")
                    if needed in LINUX_OS:
                        continue
                    resolved = [
                        d + "/" + needed for d in search if d + "/" + needed in images
                    ]
                else:
                    if needed in MACOS_OS:
                        continue
                    if needed.startswith("@loader_path/"):
                        resolved = [resolve_loader(needed)]
                    elif (
                        needed.startswith("@rpath/")
                        and "/" not in needed[len("@rpath/") :]
                    ):
                        resolved = [
                            d + "/" + needed[len("@rpath/") :]
                            for d in search
                            if d + "/" + needed[len("@rpath/") :] in images
                        ]
                    else:
                        raise RuntimeError(
                            f"Non-OS absolute/unresolved Mach-O import: {needed}"
                        )
                if len(resolved) != 1 or resolved[0] not in dependencies:
                    raise RuntimeError(
                        f"Unresolved/undeclared native import: {path}: {needed}"
                    )
                used.add(resolved[0])
            if lock["platform"] == "linux":
                if info["soname"] and info["soname"] != posixpath.basename(path):
                    raise RuntimeError(
                        "Private ELF SONAME differs from inventoried basename"
                    )
                for item in info["versions"]:
                    if item["library"] not in info["needed"]:
                        raise RuntimeError(
                            "ELF version requirement has no declared import"
                        )
                    match = re.fullmatch(
                        r"GLIBC_([0-9]+)\.([0-9]+)(?:\.([0-9]+))?", item["version"]
                    )
                    if item["library"] in LINUX_OS and (
                        not match
                        or tuple(int(p or 0) for p in match.groups()) > (2, 28, 0)
                    ):
                        raise RuntimeError(
                            f"Unsupported baseline symbol requirement: {item}"
                        )
                    if item["library"] not in LINUX_OS:
                        private = private_root + "/" + item["library"]
                        if (
                            private not in images
                            or item["version"]
                            not in images[private]["defined_versions"]
                        ):
                            raise RuntimeError(
                                f"Unresolved private ELF symbol version: {item}"
                            )
            elif path in dependencies:
                identity = info["install_name"]
                if identity not in {
                    "@rpath/" + posixpath.basename(path),
                    "@loader_path/" + posixpath.basename(path),
                }:
                    raise RuntimeError("Private Mach-O install name is not portable")
        if set(dependencies) != used:
            raise RuntimeError(
                f"Unreferenced private native dependencies: {sorted(set(dependencies) - used)}"
            )
        result[name] = images
    return {
        "platform": lock["platform"],
        "architecture": lock["architecture"],
        "programs": result,
        "evidence_kind": "static native byte inspection; not baseline execution",
    }
