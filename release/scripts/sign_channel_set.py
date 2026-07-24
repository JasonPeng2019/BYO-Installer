#!/usr/bin/env python3
"""Sign one atomic multi-platform channel sequence and current pointer."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from sign_channel import (
    archive_type,
    canonical_json,
    digest,
    parse_existing_channel,
    parse_manifest,
    sign,
    validate_archive,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--release",
        action="append",
        nargs=3,
        metavar=("BUNDLE", "ARCHIVE", "HTTPS_URL"),
        required=True,
    )
    parser.add_argument("--channel", choices=("canary", "beta", "stable"), required=True)
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--history-output", type=Path, required=True)
    parser.add_argument("--pointer-output", type=Path, required=True)
    parser.add_argument("--existing", type=Path)
    parser.add_argument("--sequence", type=int)
    parser.add_argument("--generated-at")
    parser.add_argument("--expires-at")
    args = parser.parse_args()

    key = args.signing_key.resolve(strict=True)
    releases: list[dict[str, object]] = []
    identities: set[tuple[str, str, str]] = set()
    versions: set[str] = set()
    for raw_bundle, raw_archive, url in args.release:
        bundle = Path(raw_bundle).resolve(strict=True)
        archive = Path(raw_archive).resolve(strict=True)
        parsed_url = urlparse(url)
        if parsed_url.scheme != "https" or not parsed_url.netloc:
            raise RuntimeError("every release URL must be absolute HTTPS")
        manifest = parse_manifest(bundle, key, args.key_id)
        validate_archive(bundle, archive)
        kind = archive_type(archive)
        expected_kind = "tar.gz" if manifest["platform"] == "linux" else "zip"
        if kind != expected_kind:
            raise RuntimeError("release archive type does not match its signed platform")
        identity = (
            str(manifest["version"]),
            str(manifest["platform"]),
            str(manifest["architecture"]),
        )
        if identity in identities:
            raise RuntimeError(f"duplicate release identity: {identity}")
        identities.add(identity)
        versions.add(identity[0])
        releases.append(
            {
                "version": identity[0],
                "platform": identity[1],
                "architecture": identity[2],
                "url": url,
                "archive_type": kind,
                "archive_sha256": digest(archive),
                "archive_size": archive.stat().st_size,
                "manifest_sha256": digest(bundle / "release-manifest.json"),
            }
        )
    expected_targets = {
        ("macos", "aarch64"),
        ("macos", "x86_64"),
        ("windows", "x86_64"),
        ("linux", "x86_64"),
    }
    actual_targets = {(platform, architecture) for _, platform, architecture in identities}
    if len(versions) != 1 or actual_targets != expected_targets:
        raise RuntimeError("channel publication requires one version for all four V1 targets")

    previous_releases: list[dict[str, object]] = []
    previous_sequence = 0
    if args.existing:
        previous_releases, previous_sequence = parse_existing_channel(
            args.existing.resolve(strict=True),
            key,
            args.key_id,
            args.channel,
        )
    sequence = args.sequence if args.sequence is not None else previous_sequence + 1
    if sequence <= previous_sequence or sequence < 1:
        raise RuntimeError("channel sequence must increase monotonically")
    generated_at = args.generated_at or datetime.now(UTC).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    generated = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    if generated.tzinfo is None:
        raise RuntimeError("generated-at must include a timezone")
    expires_at = args.expires_at or (
        generated + timedelta(days=7)
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    if expires.tzinfo is None or expires <= generated:
        raise RuntimeError("expires-at must be after generated-at")

    new_version = next(iter(versions))
    retained = [
        item for item in previous_releases if str(item.get("version")) != new_version
    ]
    retained.extend(releases)
    retained.sort(
        key=lambda item: (
            str(item.get("version", "")),
            str(item.get("platform", "")),
            str(item.get("architecture", "")),
        )
    )
    signed = {
        "schema": 1,
        "product": "byo",
        "channel": args.channel,
        "sequence": sequence,
        "generated_at": generated_at,
        "expires_at": expires_at,
        "releases": retained,
    }
    document = {
        "schema": 1,
        "signed": signed,
        "signatures": [
            {
                "algorithm": "Ed25519",
                "key_id": args.key_id,
                "signature": sign(canonical_json(signed), key),
            }
        ],
    }
    encoded = json.dumps(document, indent=2, sort_keys=True) + "\n"
    expected_history_name = f"{sequence}.json"
    if args.history_output.name != expected_history_name:
        raise RuntimeError(f"immutable history output must be named {expected_history_name}")
    for path in (args.history_output, args.pointer_output):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(encoded, encoding="utf-8")
    print(
        json.dumps(
            {
                "channel": args.channel,
                "sequence": sequence,
                "history": str(args.history_output),
                "pointer": str(args.pointer_output),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
