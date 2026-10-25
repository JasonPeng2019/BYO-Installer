"""Read interpreter and installed dependency facts inside the Actions process."""

from __future__ import annotations

import importlib.metadata as metadata
import importlib.util
import json
import os
import platform
import sys
from typing import Any


def main() -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("FR13 environment probes execute only in GitHub Actions")
    result: dict[str, Any] = {
        "version": list(sys.version_info[:3]),
        "python": sys.version,
        "executable": sys.executable,
        "prefix": sys.prefix,
        "base_prefix": sys.base_prefix,
        "machine": platform.machine(),
        "packages": {},
        "distributions": [],
    }
    if len(sys.argv) > 1:
        result["distributions"] = sorted(
            (d.metadata.get("Name", ""), d.version) for d in metadata.distributions()
        )
        for name in ("psutil", "ruff", "pyright", "pyocd_debug_mcp"):
            try:
                spec = importlib.util.find_spec(name)
                result["packages"][name] = {
                    "available": spec is not None,
                    "path": spec.origin if spec else None,
                }
            except Exception as exc:
                result["packages"][name] = {"available": False, "error": repr(exc)}
        try:
            import psutil

            result["psutil_import"] = {
                "ok": True,
                "path": psutil.__file__,
                "version": psutil.__version__,
            }
        except Exception as exc:
            result["psutil_import"] = {"ok": False, "error": repr(exc)}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
