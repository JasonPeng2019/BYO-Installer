#!/usr/bin/env python3
"""Run a reviewed MCP HIL call contract against one exact fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import IO, Any

APPROVED_DESTRUCTIVE = {
    "backend_mass_erase_recovery",
    "debug_unlock",
    "reset",
    "reflash_fixture",
}
PLACEHOLDERS = ("REPLACE_", "replace-")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_line(stream: IO[str], timeout: float = 30.0) -> str:
    result: queue.Queue[object] = queue.Queue(maxsize=1)

    def reader() -> None:
        try:
            result.put(stream.readline())
        except BaseException as exc:
            result.put(exc)

    threading.Thread(target=reader, daemon=True).start()
    item = result.get(timeout=timeout)
    if isinstance(item, BaseException):
        raise RuntimeError(f"MCP read failed: {item}") from item
    if not item:
        raise RuntimeError("MCP server closed its protocol stream")
    return str(item)


class Client:
    def __init__(self, byo: Path, project: Path) -> None:
        self.process = subprocess.Popen(
            [str(byo), "mcp", "serve", "--project", str(project)],
            cwd=project,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        assert self.process.stdin is not None and self.process.stdout is not None
        self.stdin = self.process.stdin
        self.stdout = self.process.stdout
        self.request_id = 0
        self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "byo-hil", "version": "1"},
            },
        )
        self.notify("notifications/initialized", {})

    def notify(self, method: str, params: dict[str, object]) -> None:
        self.stdin.write(
            json.dumps({"jsonrpc": "2.0", "method": method, "params": params}) + "\n"
        )
        self.stdin.flush()

    def request(self, method: str, params: dict[str, object]) -> dict[str, Any]:
        self.request_id += 1
        self.stdin.write(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": self.request_id,
                    "method": method,
                    "params": params,
                },
                separators=(",", ":"),
            )
            + "\n"
        )
        self.stdin.flush()
        response = json.loads(read_line(self.stdout))
        if response.get("id") != self.request_id or "error" in response:
            raise RuntimeError(f"MCP request failed: {response}")
        result = response.get("result")
        if not isinstance(result, dict):
            raise RuntimeError(f"MCP returned a malformed result: {response}")
        return result

    def call(
        self, name: str, arguments: dict[str, object], expectation: str
    ) -> dict[str, Any]:
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        is_error = bool(result.get("isError"))
        text = "\n".join(
            str(item.get("text", ""))
            for item in result.get("content", [])
            if isinstance(item, dict) and item.get("type") == "text"
        )
        refused = "refus" in text.casefold() or "permission" in text.casefold()
        if expectation == "success" and (is_error or refused):
            raise RuntimeError(f"HIL call {name} did not succeed: {result}")
        if expectation == "refusal" and not (is_error or refused):
            raise RuntimeError(f"HIL call {name} was expected to refuse: {result}")
        return result

    def close(self) -> None:
        self.stdin.close()
        try:
            self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
            raise RuntimeError("MCP process tree did not stop after protocol EOF")
        if self.process.returncode != 0:
            diagnostics = self.process.stderr.read() if self.process.stderr else ""
            raise RuntimeError(f"MCP exited {self.process.returncode}: {diagnostics}")


def validate_fixture(path: Path, destructive: bool) -> dict[str, Any]:
    fixture = json.loads(path.read_text(encoding="utf-8"))
    rendered = json.dumps(fixture)
    if any(marker in rendered for marker in PLACEHOLDERS) or "0" * 64 in rendered:
        raise RuntimeError(
            "HIL fixture still contains placeholder identities or hashes"
        )
    for field in ("firmware", "memory_map"):
        artifact = (path.parent / fixture[field]["path"]).resolve(strict=True)
        if digest(artifact) != fixture[field]["sha256"]:
            raise RuntimeError(f"HIL {field} hash does not match the reviewed fixture")
    operations = set(fixture["destructive_operations"])
    if not operations <= APPROVED_DESTRUCTIVE:
        raise RuntimeError("fixture requests an operation outside ADR-0007")
    if destructive:
        if (
            fixture["role"] != "sacrificial"
            or fixture["destructive_authorized"] is not True
            or not fixture["destructive_calls"]
            or os.environ.get("BYO_HIL_ALLOW_DESTRUCTIVE") != "1"
        ):
            raise RuntimeError("destructive HIL gates are incomplete")
    return fixture


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("safe", "destructive"))
    parser.add_argument("--byo", type=Path, required=True)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    destructive = args.mode == "destructive"
    fixture = validate_fixture(args.fixture.resolve(strict=True), destructive)
    byo = args.byo.resolve(strict=True)
    if digest(byo) != args.artifact_sha256:
        raise RuntimeError(
            "installed launcher does not match the approved candidate hash"
        )
    project = args.project.resolve(strict=True)

    lock = Path(
        os.environ.get(
            "BYO_HIL_LOCK", str(Path.home() / f".byo-hil-{fixture['fixture_id']}")
        )
    )
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise RuntimeError("the physical HIL fixture is already locked") from exc
    started = time.time()
    results: list[dict[str, object]] = []
    client: Client | None = None
    try:
        client = Client(byo, project)
        tools = client.request("tools/list", {}).get("tools", [])
        available = {item.get("name") for item in tools if isinstance(item, dict)}
        calls = fixture["safe_calls"] + (
            fixture["destructive_calls"] if destructive else []
        )
        for call in calls:
            if call["name"] not in available:
                raise RuntimeError(f"reviewed HIL tool is unavailable: {call['name']}")
            encoded = json.dumps(call["arguments"])
            if fixture["board_id"] not in encoded:
                raise RuntimeError("HIL call is not bound to the allowlisted board ID")
            result = client.call(call["name"], call["arguments"], call["expect"])
            result_text = json.dumps(result)
            if call["name"] in {"connect", "connect_override", "get_board_info"} and (
                fixture["probe_uid"] not in result_text
            ):
                raise RuntimeError(
                    "live probe identity does not match the allowlisted fixture"
                )
            results.append({"name": call["name"], "result": result})
    finally:
        try:
            if client is not None:
                client.close()
        finally:
            os.close(descriptor)
            lock.unlink(missing_ok=True)

    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(
        json.dumps(
            {
                "schema": 1,
                "mode": args.mode,
                "fixture_id": fixture["fixture_id"],
                "board_model": fixture["board_model"],
                "probe_family": fixture["probe_family"],
                "artifact_sha256": args.artifact_sha256,
                "fixture_firmware_sha256": fixture["firmware"]["sha256"],
                "duration_seconds": round(time.time() - started, 3),
                "platform": sys.platform,
                "results": results,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
