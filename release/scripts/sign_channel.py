#!/usr/bin/env python3
"""Create or update one signed BYO release-channel metadata document."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import subprocess
import tarfile
import tempfile
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

MAX_ARCHIVE_ENTRIES = 20_000
MAX_EXTRACTED_FILE_BYTES = 512 * 1024 * 1024
MAX_EXTRACTED_BYTES = 2 * 1024 * 1024 * 1024


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


def sign(payload: bytes, key: Path) -> str:
    with tempfile.TemporaryDirectory(prefix="byo-channel-sign-") as temporary_directory:
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
        raise RuntimeError("OpenSSL returned an invalid Ed25519 signature")
    return completed.stdout.hex()


def parse_manifest(bundle: Path, signing_key: Path, key_id: str) -> dict[str, object]:
    manifest_path = bundle / "release-manifest.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    required = ("version", "platform", "architecture", "channel")
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != 1
        or payload.get("product") != "byo"
        or any(not isinstance(payload.get(field), str) for field in required)
        or payload.get("development_unsigned") is not False
    ):
        raise RuntimeError("channel publication requires a signed production bundle")
    envelope = json.loads((bundle / "release-manifest.sig").read_text(encoding="utf-8"))
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"schema", "algorithm", "key_id", "signature"}
        or envelope.get("schema") != 1
        or envelope.get("algorithm") != "Ed25519"
        or envelope.get("key_id") != key_id
        or not isinstance(envelope.get("signature"), str)
        or len(envelope["signature"]) != 128
    ):
        raise RuntimeError(
            "release manifest signature envelope does not match the active key"
        )
    expected = sign(canonical_json(payload), signing_key)
    if not hmac.compare_digest(envelope["signature"], expected):
        raise RuntimeError(
            "release manifest signature does not verify with the active signing key"
        )
    return payload


def archive_type(archive: Path) -> str:
    if archive.name.endswith(".tar.gz"):
        return "tar.gz"
    if archive.suffix.lower() == ".zip":
        return "zip"
    raise RuntimeError("release archive must have an explicit .tar.gz or .zip suffix")


def validate_member_path(bundle: Path, name: str, seen: set[str]) -> PurePosixPath:
    path = PurePosixPath(name)
    normalized = name.rstrip("/").lower()
    if (
        "\\" in name
        or path.is_absolute()
        or not path.parts
        or path.parts[0] != bundle.name
        or any(part in {"", ".", ".."} for part in path.parts)
        or normalized in seen
    ):
        raise RuntimeError("release archive contains an unsafe or duplicate entry")
    seen.add(normalized)
    return path


def validate_archive(bundle: Path, archive: Path) -> None:
    expected_manifest = (bundle / "release-manifest.json").read_bytes()
    expected_signature = (bundle / "release-manifest.sig").read_bytes()
    seen_manifest = seen_signature = False
    entries = 0
    expanded = 0
    seen: set[str] = set()
    if archive_type(archive) == "tar.gz":
        with tarfile.open(archive, mode="r:gz") as tar:
            for member in tar:
                entries += 1
                validate_member_path(bundle, member.name, seen)
                if not (member.isfile() or member.isdir()):
                    raise RuntimeError(
                        "release archive contains a forbidden non-file entry"
                    )
                if member.size > MAX_EXTRACTED_FILE_BYTES:
                    raise RuntimeError("release archive contains an oversized file")
                expanded += member.size
                if entries > MAX_ARCHIVE_ENTRIES or expanded > MAX_EXTRACTED_BYTES:
                    raise RuntimeError("release archive exceeds extraction limits")
                if member.name == f"{bundle.name}/release-manifest.json":
                    extracted = tar.extractfile(member)
                    if (
                        extracted is None
                        or extracted.read(4 * 1024 * 1024 + 1) != expected_manifest
                    ):
                        raise RuntimeError(
                            "archive release manifest does not match the bundle"
                        )
                    seen_manifest = True
                elif member.name == f"{bundle.name}/release-manifest.sig":
                    extracted = tar.extractfile(member)
                    if (
                        extracted is None
                        or extracted.read(64 * 1024 + 1) != expected_signature
                    ):
                        raise RuntimeError(
                            "archive release signature does not match the bundle"
                        )
                    seen_signature = True
    else:
        with zipfile.ZipFile(archive, mode="r") as zipped:
            for member in zipped.infolist():
                entries += 1
                validate_member_path(bundle, member.filename, seen)
                unix_type = (member.external_attr >> 16) & 0o170000
                if unix_type not in {0, 0o040000, 0o100000}:
                    raise RuntimeError(
                        "release ZIP contains a forbidden non-file entry"
                    )
                if member.file_size > MAX_EXTRACTED_FILE_BYTES:
                    raise RuntimeError("release archive contains an oversized file")
                expanded += member.file_size
                if entries > MAX_ARCHIVE_ENTRIES or expanded > MAX_EXTRACTED_BYTES:
                    raise RuntimeError("release archive exceeds extraction limits")
                if member.filename == f"{bundle.name}/release-manifest.json":
                    if zipped.read(member) != expected_manifest:
                        raise RuntimeError(
                            "archive release manifest does not match the bundle"
                        )
                    seen_manifest = True
                elif member.filename == f"{bundle.name}/release-manifest.sig":
                    if zipped.read(member) != expected_signature:
                        raise RuntimeError(
                            "archive release signature does not match the bundle"
                        )
                    seen_signature = True
    if entries == 0:
        raise RuntimeError("release archive is empty")
    if not seen_manifest or not seen_signature:
        raise RuntimeError("release archive is missing signed runtime metadata")


def parse_existing_channel(
    path: Path,
    signing_key: Path,
    key_id: str,
    expected_channel: str,
) -> tuple[list[dict[str, object]], int]:
    existing = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(existing, dict)
        or set(existing) != {"schema", "signed", "signatures"}
        or existing.get("schema") != 1
        or not isinstance(existing.get("signed"), dict)
        or not isinstance(existing.get("signatures"), list)
    ):
        raise RuntimeError("existing channel document is incompatible")

    signed = existing["signed"]
    if (
        signed.get("schema") != 1
        or signed.get("product") != "byo"
        or signed.get("channel") != expected_channel
        or not isinstance(signed.get("releases"), list)
        or not isinstance(signed.get("sequence"), int)
        or signed["sequence"] < 1
    ):
        raise RuntimeError("existing channel document is incompatible")

    expected_signature = sign(canonical_json(signed), signing_key)
    signature_matches = any(
        isinstance(item, dict)
        and set(item) == {"algorithm", "key_id", "signature"}
        and item.get("algorithm") == "Ed25519"
        and item.get("key_id") == key_id
        and isinstance(item.get("signature"), str)
        and len(item["signature"]) == 128
        and hmac.compare_digest(item["signature"], expected_signature)
        for item in existing["signatures"]
    )
    if not signature_matches:
        raise RuntimeError(
            "existing channel document does not verify with the active signing key"
        )

    releases = [item for item in signed["releases"] if isinstance(item, dict)]
    if len(releases) != len(signed["releases"]):
        raise RuntimeError("existing channel release list is malformed")
    return releases, signed["sequence"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--existing", type=Path)
    parser.add_argument("--generated-at")
    parser.add_argument("--expires-at")
    parser.add_argument("--sequence", type=int)
    args = parser.parse_args()

    bundle = args.bundle.resolve(strict=True)
    archive = args.archive.resolve(strict=True)
    key = args.signing_key.resolve(strict=True)
    if not archive.is_file() or not key.is_file():
        raise RuntimeError("archive and signing key must be regular files")
    parsed_url = urlparse(args.url)
    if parsed_url.scheme != "https" or not parsed_url.netloc:
        raise RuntimeError("release artifact URL must be absolute HTTPS")

    manifest = parse_manifest(bundle, key, args.key_id)
    validate_archive(bundle, archive)
    releases: list[dict[str, object]] = []
    previous_sequence = 0
    if args.existing:
        releases, previous_sequence = parse_existing_channel(
            args.existing,
            key,
            args.key_id,
            str(manifest["channel"]),
        )

    sequence = args.sequence if args.sequence is not None else previous_sequence + 1
    if sequence <= previous_sequence or sequence < 1:
        raise RuntimeError(
            "channel sequence must be positive and greater than the existing document"
        )
    generated_at = args.generated_at or datetime.now(UTC).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")
    generated_time = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    if generated_time.tzinfo is None:
        raise RuntimeError("channel generated-at timestamp must include a timezone")
    expires_at = args.expires_at or (generated_time + timedelta(days=7)).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")
    expires_time = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    if expires_time.tzinfo is None or expires_time <= generated_time:
        raise RuntimeError("channel expires-at timestamp must be after generated-at")

    artifact = {
        "version": manifest["version"],
        "platform": manifest["platform"],
        "architecture": manifest["architecture"],
        "url": args.url,
        "archive_type": archive_type(archive),
        "archive_sha256": digest(archive),
        "archive_size": archive.stat().st_size,
        "manifest_sha256": digest(bundle / "release-manifest.json"),
    }
    identity = (
        artifact["version"],
        artifact["platform"],
        artifact["architecture"],
    )
    releases = [
        item
        for item in releases
        if (item.get("version"), item.get("platform"), item.get("architecture"))
        != identity
    ]
    releases.append(artifact)
    releases.sort(
        key=lambda item: (
            str(item.get("version", "")),
            str(item.get("platform", "")),
            str(item.get("architecture", "")),
        )
    )
    signed = {
        "schema": 1,
        "product": "byo",
        "channel": manifest["channel"],
        "sequence": sequence,
        "generated_at": generated_at,
        "expires_at": expires_at,
        "releases": releases,
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
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
