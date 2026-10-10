"""Prepare explicitly supplied GCC runtime notices and provenance on native Linux.

This is a separate input-preparation step. It queries the selected compiler for
static library paths, hashes actual bytes, and creates a fresh gcc-runtime input
directory. Package/source references must describe that selected toolchain.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from acquire_analysis_inputs import digest


def prepare(
    compiler: Path, notices: Path, package: str, source: str, output: Path
) -> dict:
    if sys.platform != "linux":
        raise RuntimeError("GCC runtime input preparation requires native Linux")
    if not package.strip() or not source.strip():
        raise RuntimeError(
            "Supply the selected compiler package and corresponding source reference"
        )
    compiler = compiler.resolve(strict=True)
    if not compiler.is_file():
        raise RuntimeError(f"Selected compiler is not a regular file: {compiler}")
    payload = {}
    for name in ("COPYING3", "COPYING.RUNTIME"):
        path = notices / name
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"Supply the selected toolchain notice: {path}")
        data = path.read_bytes()
        if not data:
            raise RuntimeError(f"Toolchain notice is empty: {path}")
        payload[name] = data
    libraries = {}
    for name in ("libstdc++.a", "libgcc.a", "libgcc_eh.a"):
        value = subprocess.check_output(
            [str(compiler), f"-print-file-name={name}"], text=True, timeout=10
        ).strip()
        path = Path(value)
        if not path.is_absolute() or not path.is_file():
            raise RuntimeError(f"Selected compiler cannot locate {name}: {value!r}")
        libraries[name] = digest(path)
    provenance = {
        "schema_version": 1,
        "compiler_sha256": digest(compiler),
        "package": package,
        "source": source,
        "static_libraries": libraries,
    }
    payload["provenance.json"] = (
        json.dumps(provenance, indent=2, sort_keys=True) + "\n"
    ).encode()
    # Every input has been measured before creating output. A fresh directory
    # prevents this preparation step from replacing supplied or accepted inputs.
    output.mkdir(parents=True, exist_ok=False)
    for name, data in payload.items():
        (output / name).write_bytes(data)
    return provenance


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--notices", type=Path, required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = prepare(
            args.compiler, args.notices, args.package, args.source, args.output
        )
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(2, f"GCC runtime input preparation failed: {error}\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
