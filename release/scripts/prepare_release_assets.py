#!/usr/bin/env python3
"""Collect four signed candidates into one immutable-publication asset set."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGETS = {
    ("macos", "aarch64"): "macos-aarch64",
    ("macos", "x86_64"): "macos-x86_64",
    ("windows", "x86_64"): "windows-x86_64",
    ("linux", "x86_64"): "linux-x86_64",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--release-run-id", required=True)
    parser.add_argument("--clean-run-id", required=True)
    parser.add_argument("--safe-hil-run-id", required=True)
    parser.add_argument("--destructive-hil-run-id", required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError("publication output must be a new directory")
    args.output.mkdir(parents=True)

    bundles = [
        path
        for path in args.candidates.rglob("byo-*")
        if path.is_dir() and (path / "release-manifest.json").is_file()
    ]
    records: list[dict[str, object]] = []
    observed: set[tuple[str, str]] = set()
    versions: set[str] = set()
    source_documents: list[object] = []
    target_toolchains: dict[str, object] = {}
    for bundle in bundles:
        manifest_path = bundle / "release-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        identity = (str(manifest["platform"]), str(manifest["architecture"]))
        target = TARGETS.get(identity)
        if target is None or identity in observed:
            raise RuntimeError(f"unexpected or duplicate signed target: {identity}")
        observed.add(identity)
        versions.add(str(manifest["version"]))
        source_documents.append(manifest["source"])
        target_toolchains[target] = manifest["toolchain"]
        if manifest.get("development_unsigned") is not False:
            raise RuntimeError("publication candidate is development-unsigned")

        archive_suffix = ".tar.gz" if identity[0] == "linux" else ".zip"
        archive = bundle.parent / f"{bundle.name}{archive_suffix}"
        required = [
            archive,
            bundle.parent / f"{bundle.name}.sha256",
            bundle.parent / f"{archive.name}.sig",
            bundle / "release-manifest.sig",
            bundle / "sbom.cdx.json",
        ]
        if any(not path.is_file() for path in required):
            raise RuntimeError(
                f"signed target {target} is missing required publication assets"
            )
        copies = {
            archive: archive.name,
            required[1]: required[1].name,
            required[2]: required[2].name,
            manifest_path: f"release-manifest-{target}.json",
            required[3]: f"release-manifest-{target}.sig",
            required[4]: f"sbom-{target}.cdx.json",
        }
        notarization = bundle.parent / f"{bundle.name}.notarization.json"
        if identity[0] == "macos":
            if not notarization.is_file():
                raise RuntimeError(
                    f"macOS target {target} is missing its notarization log"
                )
            copies[notarization] = f"notarization-{target}.json"
        for source, name in copies.items():
            shutil.copy2(source, args.output / name)
        records.append(
            {
                "target": target,
                "archive": archive.name,
                "archive_sha256": digest(archive),
                "manifest": f"release-manifest-{target}.json",
                "manifest_sha256": digest(manifest_path),
                "sbom": f"sbom-{target}.cdx.json",
            }
        )
    if observed != set(TARGETS) or len(versions) != 1:
        raise RuntimeError(
            "publication requires one identical version across all four targets"
        )
    if any(document != source_documents[0] for document in source_documents[1:]):
        raise RuntimeError("target manifests do not identify identical source commits")
    protocol_fields = (
        "launcher_protocol",
        "sidecar_protocol",
        "worker_protocol",
        "workflow_protocol",
        "capsule_schema",
        "project_state_schema",
    )
    manifests = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in args.output.glob("release-manifest-*.json")
    ]
    if any(
        tuple(manifest[field] for field in protocol_fields)
        != tuple(manifests[0][field] for field in protocol_fields)
        for manifest in manifests[1:]
    ):
        raise RuntimeError(
            "target manifests do not expose one behavioral protocol contract"
        )

    installers = []
    for name in ("install.sh", "install.ps1"):
        source = ROOT / name
        if not source.is_file():
            raise RuntimeError(f"publication installer is missing: {source}")
        destination = args.output / name
        shutil.copy2(source, destination)
        installers.append({"name": name, "sha256": digest(destination)})

    index = {
        "schema": 1,
        "version": next(iter(versions)),
        "source": source_documents[0],
        "toolchains": dict(sorted(target_toolchains.items())),
        "artifacts": sorted(records, key=lambda value: str(value["target"])),
        "installers": installers,
        "evidence": {
            "release_run_id": args.release_run_id,
            "clean_run_id": args.clean_run_id,
            "safe_hil_run_id": args.safe_hil_run_id,
            "destructive_hil_run_id": args.destructive_hil_run_id,
        },
    }
    (args.output / "release-index.json").write_text(
        json.dumps(index, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
