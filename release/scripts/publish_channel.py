#!/usr/bin/env python3
"""Upload immutable channel history first and atomically replace its pointer last."""

from __future__ import annotations

import argparse
import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def request(
    method: str,
    url: str,
    token: str,
    payload: object | None = None,
) -> dict[str, object] | None:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    raw = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "BYO-channel-publisher",
            **({"Content-Type": "application/json"} if body is not None else {}),
        },
    )
    try:
        with urllib.request.urlopen(raw, timeout=60) as response:
            content = response.read()
    except urllib.error.HTTPError as exc:
        diagnostic = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub channel API failed ({exc.code}): {diagnostic}") from exc
    return json.loads(content) if content else None


def content_url(repository: str, path: str, branch: str) -> str:
    encoded = urllib.parse.quote(path, safe="/")
    return f"https://api.github.com/repos/{repository}/contents/{encoded}?ref={urllib.parse.quote(branch)}"


def put_url(repository: str, path: str) -> str:
    encoded = urllib.parse.quote(path, safe="/")
    return f"https://api.github.com/repos/{repository}/contents/{encoded}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--branch", default="channels")
    parser.add_argument("--history", type=Path, required=True)
    parser.add_argument("--pointer", type=Path, required=True)
    parser.add_argument("--channel", choices=("canary", "beta", "stable"), required=True)
    args = parser.parse_args()
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN is required")
    document = json.loads(args.history.read_text(encoding="utf-8"))
    if document != json.loads(args.pointer.read_text(encoding="utf-8")):
        raise RuntimeError("channel history and pointer are not byte-equivalent documents")
    sequence = document.get("signed", {}).get("sequence")
    if not isinstance(sequence, int) or sequence < 1:
        raise RuntimeError("signed channel document has no valid sequence")
    history_path = f"channels/{args.channel}/{sequence}.json"
    pointer_path = f"channels/{args.channel}.json"

    try:
        request("GET", content_url(args.repository, history_path, args.branch), token)
    except RuntimeError as exc:
        if "(404)" not in str(exc):
            raise
    else:
        raise RuntimeError("immutable channel sequence already exists")
    history_payload = {
        "message": f"Publish immutable {args.channel} channel sequence {sequence}",
        "content": base64.b64encode(args.history.read_bytes()).decode("ascii"),
        "branch": args.branch,
    }
    request("PUT", put_url(args.repository, history_path), token, history_payload)

    pointer_sha: str | None = None
    try:
        existing = request("GET", content_url(args.repository, pointer_path, args.branch), token)
        if isinstance(existing, dict) and isinstance(existing.get("sha"), str):
            pointer_sha = existing["sha"]
    except RuntimeError as exc:
        if "(404)" not in str(exc):
            raise
    pointer_payload: dict[str, object] = {
        "message": f"Promote {args.channel} channel to sequence {sequence}",
        "content": base64.b64encode(args.pointer.read_bytes()).decode("ascii"),
        "branch": args.branch,
    }
    if pointer_sha:
        pointer_payload["sha"] = pointer_sha
    request("PUT", put_url(args.repository, pointer_path), token, pointer_payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
