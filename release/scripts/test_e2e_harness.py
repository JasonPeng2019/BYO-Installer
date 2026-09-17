#!/usr/bin/env python3
"""Focused process-lifecycle checks for the installed acceptance harness."""

from __future__ import annotations

import io
import subprocess
from pathlib import Path
from unittest.mock import patch

import test_installed_e2e as acceptance


class _InitializedMcpProcess:
    def __init__(self, *args: object, **kwargs: object) -> None:
        del args
        self.kwargs = kwargs
        self.stdin = io.StringIO()
        self.stdout = io.StringIO(
            '{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"version":"1.2.3"}}}\n'
        )

    def poll(self) -> None:
        return None


def test_mcp_start_captures_diagnostics_without_an_unread_pipe() -> None:
    """The stdio server may emit more stderr than an OS pipe can hold."""

    created: list[_InitializedMcpProcess] = []

    def spawn(*args: object, **kwargs: object) -> _InitializedMcpProcess:
        process = _InitializedMcpProcess(*args, **kwargs)
        created.append(process)
        return process

    with patch.object(acceptance.subprocess, "Popen", side_effect=spawn):
        server = acceptance.start_initialized_mcp(
            Path("/bundle/byo"),
            Path("/project"),
            {},
            "1.2.3",
        )

    assert len(created) == 1
    stderr = created[0].kwargs["stderr"]
    assert stderr is not subprocess.PIPE
    assert hasattr(stderr, "seek") and hasattr(stderr, "read")
    server.diagnostics.close()


def main() -> int:
    tests = [
        value for name, value in sorted(globals().items()) if name.startswith("test_")
    ]
    for test in tests:
        test()
        print(f"ok  {test.__name__}")
    print(f"\n{len(tests)} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
