#!/usr/bin/env python3
"""Build a deterministic, allow-listed BYO workflow resource pack."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import struct
import sys
import tomllib
import zlib
from pathlib import Path, PurePosixPath

MAGIC = b"BYOWPK1\n"
ALLOWED_CLASSES = {
    "compile",
    "embed",
    "public-template",
    "user-template",
    "developer-only",
    "forbidden",
}
PACKED_CLASSES = {"compile", "embed", "public-template", "user-template"}
FORBIDDEN_PARTS = {".git", ".hg", ".svn", "__pycache__", ".pytest_cache"}
FORBIDDEN_NAMES = {".env", ".env.local", ".DS_Store"}


class CompileError(RuntimeError):
    pass


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for current, directories, names in os.walk(root, followlinks=False):
        directories.sort()
        names.sort()
        base = Path(current)
        for directory in tuple(directories):
            candidate = base / directory
            if candidate.is_symlink():
                raise CompileError(f"symlinked directory is forbidden: {candidate}")
        for name in names:
            candidate = base / name
            if candidate.is_symlink():
                raise CompileError(f"symlinked file is forbidden: {candidate}")
            files.append(candidate)
    return files


def _load_policy(path: Path) -> list[tuple[str, str]]:
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if document.get("schema") != 1 or not isinstance(document.get("rule"), list):
        raise CompileError("partition policy must use schema 1 and contain rules")
    rules: list[tuple[str, str]] = []
    for index, raw in enumerate(document["rule"]):
        if not isinstance(raw, dict) or set(raw) != {"pattern", "class"}:
            raise CompileError(f"policy rule {index} has missing or unknown fields")
        pattern, release_class = raw["pattern"], raw["class"]
        if not isinstance(pattern, str) or not pattern:
            raise CompileError(f"policy rule {index} has an invalid pattern")
        if release_class not in ALLOWED_CLASSES:
            raise CompileError(f"policy rule {index} has an invalid class")
        rules.append((pattern, release_class))
    return rules


def _classify(relative: str, rules: list[tuple[str, str]]) -> str:
    matches = [
        release_class
        for pattern, release_class in rules
        if fnmatch.fnmatchcase(relative, pattern)
    ]
    if len(matches) != 1:
        qualifier = "unclassified" if not matches else "classified more than once"
        raise CompileError(f"{relative} is {qualifier}")
    return matches[0]


def _scan_for_leaks(relative: str, payload: bytes) -> None:
    path = PurePosixPath(relative)
    if (
        any(part in FORBIDDEN_PARTS for part in path.parts)
        or path.name in FORBIDDEN_NAMES
    ):
        raise CompileError(f"forbidden generated or credential-like input: {relative}")
    if b"\x00" not in payload:
        lowered = payload.lower()
        for marker in (b"-----begin private key-----", b"github_pat_", b"sk-proj-"):
            if marker in lowered:
                raise CompileError(f"credential-like content found in {relative}")


def _compile_runtime_references(relative: str, payload: bytes) -> bytes:
    if not relative.startswith(("skills-src/", "instructions/", "agents/")):
        return payload
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CompileError(f"workflow guidance is not UTF-8: {relative}") from exc
    commands = {
        "task-path": "byo workflow tool task-path",
        "require-mode": "byo workflow tool require-mode",
        "check-plan": "byo workflow tool check-plan",
        "record-review": "byo workflow tool record-review",
        "risk-status": "byo workflow tool risk-status",
        "query": "byo workflow tool query",
        "verify": "byo workflow tool verify",
    }
    for source_name, replacement in commands.items():
        pattern = (
            r"(?<![A-Za-z0-9_-])"
            r"(?:\.agent-workspace/|\./)?bin/"
            + re.escape(source_name)
            + r"(?![A-Za-z0-9_-])"
        )
        text = re.sub(pattern, replacement, text)
    text = re.sub(
        r"(?<![A-Za-z0-9_-])(?:\.agent-workspace/|\./)?bin/verify-firmware"
        r"(?![A-Za-z0-9_-])",
        "byo workflow tool verify --backend firmware",
        text,
    )
    text = re.sub(
        r"(?<![A-Za-z0-9_-])(?:\.agent-workspace/|\./)?bin/verify-software"
        r"(?![A-Za-z0-9_-])",
        "byo workflow tool verify --backend software",
        text,
    )
    text = re.sub(
        r"(?<![A-Za-z0-9_-])(?:\.agent-workspace/|\./)?bin/(?:claude-mode|codex-mode)"
        r"(?![A-Za-z0-9_-])",
        "byo mode",
        text,
    )
    unresolved = {
        match.group(1)
        for match in re.finditer(
            r"(?<![A-Za-z0-9_-])(?:\.agent-workspace/|\./)?bin/([A-Za-z0-9_-]+)",
            text,
        )
        if match.group(1) not in {"verify-firmware-local", "verify-software-local"}
    }
    if unresolved:
        raise CompileError(
            f"packed workflow {relative} still references developer-only commands: "
            + ", ".join(sorted(unresolved))
        )
    return text.encode("utf-8")


def _deep_merge(
    base: dict[str, object], overlay: dict[str, object]
) -> dict[str, object]:
    result = dict(base)
    for key, value in overlay.items():
        if key == "extends":
            result[key] = list(value) if isinstance(value, list) else value
        elif isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(
                dict(result[key]),  # type: ignore[arg-type]
                value,
            )
        else:
            result[key] = value
    return result


def _string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise CompileError(f"{label} must be an array of non-empty strings")
    return list(value)


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise CompileError(f"{label} must be a non-empty string")
    return value


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _string(value, label)


def _integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise CompileError(f"{label} must be an integer")
    return value


def _valid_identifier(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= 128
        and all(
            character.isascii()
            and (character.islower() or character.isdigit() or character == "-")
            for character in value
        )
    )


def _compile_modes(source: Path) -> bytes:
    mode_dir = source / "modes"
    raw_modes: dict[str, dict[str, object]] = {}
    for path in sorted(mode_dir.glob("*.toml")):
        try:
            value = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise CompileError(f"invalid mode TOML {path.name}: {exc}") from exc
        if (
            not isinstance(value, dict)
            or value.get("name") != path.stem
            or not _valid_identifier(path.stem)
        ):
            raise CompileError(f"mode identity mismatch in {path.name}")
        raw_modes[path.stem] = value
    if not raw_modes:
        raise CompileError("workspace contains no mode definitions")

    def resolve(name: str, lineage: tuple[str, ...] = ()) -> dict[str, object]:
        if name in lineage:
            raise CompileError(
                f"cyclic mode inheritance: {' -> '.join((*lineage, name))}"
            )
        if name not in raw_modes:
            raise CompileError(f"mode {name!r} extends an unknown mode")
        current = raw_modes[name]
        extends = _string_list(current.get("extends", []), f"modes/{name}.toml extends")
        merged: dict[str, object] = {}
        for parent in extends:
            merged = _deep_merge(merged, resolve(parent, (*lineage, name)))
        return _deep_merge(merged, current)

    def family(name: str, lineage: tuple[str, ...] = ()) -> str:
        if name in lineage:
            raise CompileError(
                f"cyclic mode inheritance: {' -> '.join((*lineage, name))}"
            )
        parents = _string_list(
            raw_modes[name].get("extends", []),
            f"modes/{name}.toml extends",
        )
        if not parents:
            return name
        roots = {family(parent, (*lineage, name)) for parent in parents}
        if len(roots) != 1:
            raise CompileError(f"mode {name!r} resolves to multiple families")
        return next(iter(roots))

    available_skills: dict[str, str] = {}
    for skill_path in sorted((source / "skills-src").glob("*/*/SKILL.md")):
        skill_id = skill_path.parent.name
        if not _valid_identifier(skill_id):
            raise CompileError(f"invalid skill identifier {skill_id!r}")
        if skill_id in available_skills:
            raise CompileError(f"duplicate skill identifier {skill_id!r}")
        available_skills[skill_id] = skill_path.relative_to(source).as_posix()

    compiled_modes: list[dict[str, object]] = []
    for name in sorted(raw_modes):
        merged = resolve(name)
        family_name = family(name)
        try:
            skills = merged["skills"]
            verify = merged["verify"]
            codex = merged["codex"]
            workflow = merged["workflow"]
            structure = merged["structure"]
        except KeyError as exc:
            raise CompileError(
                f"mode {name!r} is missing inherited section {exc}"
            ) from exc
        if not all(
            isinstance(section, dict)
            for section in (skills, verify, codex, workflow, structure)
        ):
            raise CompileError(f"mode {name!r} contains a non-table section")
        skill_names = [
            *_string_list(skills.get("common"), f"mode {name} skills.common"),
            *_string_list(skills.get("mode"), f"mode {name} skills.mode"),
        ]
        if len(set(skill_names)) != len(skill_names):
            raise CompileError(f"mode {name!r} contains duplicate skills")
        missing = sorted(set(skill_names) - set(available_skills))
        if missing:
            raise CompileError(
                f"mode {name!r} references missing skills: {', '.join(missing)}"
            )
        instruction_ids = ["instructions/common.md", f"instructions/{family_name}.md"]
        for resource_id in instruction_ids:
            if not (source / resource_id).is_file():
                raise CompileError(f"mode {name!r} references missing {resource_id}")
        compiled_modes.append(
            {
                "name": name,
                "family": family_name,
                "extends": _string_list(
                    raw_modes[name].get("extends", []),
                    f"mode {name} extends",
                ),
                "full_access": codex.get("sandbox_mode") == "danger-full-access",
                "skills": skill_names,
                "instruction_resources": instruction_ids,
                "verify": {
                    "backend": _string(
                        verify.get("backend"),
                        f"mode {name} verify.backend",
                    ),
                    "required_tools": _string_list(
                        verify.get("required_tools"),
                        f"mode {name} verify.required_tools",
                    ),
                },
                "codex": {
                    "permission_profile": _string(
                        codex.get("permission_profile"),
                        f"mode {name} codex.permission_profile",
                    ),
                    "sandbox_mode": _optional_string(
                        codex.get("sandbox_mode"),
                        f"mode {name} codex.sandbox_mode",
                    ),
                    "approval_policy": _string(
                        codex.get("approval_policy"),
                        f"mode {name} codex.approval_policy",
                    ),
                    "web_search": _string(
                        codex.get("web_search"),
                        f"mode {name} codex.web_search",
                    ),
                },
                "workflow": {
                    "one_way_doors": _string_list(
                        workflow.get("one_way_doors"),
                        f"mode {name} workflow.one_way_doors",
                    ),
                    "adversarial_triggers": _string_list(
                        workflow.get("adversarial_triggers"),
                        f"mode {name} workflow.adversarial_triggers",
                    ),
                },
                "structure": {
                    "version": _integer(
                        structure.get("version"),
                        f"mode {name} structure.version",
                    ),
                    "default_visibility": _string(
                        structure.get("default_visibility"),
                        f"mode {name} structure.default_visibility",
                    ),
                    "required_dirs": _string_list(
                        structure.get("required_dirs"),
                        f"mode {name} structure.required_dirs",
                    ),
                    "required_files": _string_list(
                        structure.get("required_files"),
                        f"mode {name} structure.required_files",
                    ),
                    "forbidden_paths": _string_list(
                        structure.get("forbidden_paths"),
                        f"mode {name} structure.forbidden_paths",
                    ),
                },
            }
        )
    agents: dict[str, str] = {}
    for path in sorted((source / "agents").glob("*.md")):
        agent_id = path.stem
        if not _valid_identifier(agent_id):
            raise CompileError(f"invalid agent identifier {agent_id!r}")
        agents[agent_id] = path.relative_to(source).as_posix()
    payload = {
        "schema": 1,
        "workflow_protocol": 1,
        "modes": compiled_modes,
        "skills": available_skills,
        "agents": agents,
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def compile_pack(
    source: Path, policy: Path, output: Path, report: Path, version: str
) -> str:
    source = source.resolve(strict=True)
    if not source.is_dir():
        raise CompileError("workspace source must be a directory")
    rules = _load_policy(policy.resolve(strict=True))
    classified: list[dict[str, object]] = []
    records: list[tuple[str, str, bytes, bytes, str]] = []

    for path in _source_files(source):
        relative = path.relative_to(source).as_posix()
        payload = _compile_runtime_references(relative, path.read_bytes())
        _scan_for_leaks(relative, payload)
        release_class = _classify(relative, rules)
        if release_class == "forbidden":
            raise CompileError(f"policy forbids source input: {relative}")
        digest = _sha256(payload)
        classified.append(
            {
                "path": relative,
                "class": release_class,
                "sha256": digest,
                "size": len(payload),
            }
        )
        if release_class in PACKED_CLASSES and not (
            release_class == "compile" and relative.startswith("modes/")
        ):
            records.append(
                (relative, release_class, payload, zlib.compress(payload, 9), digest)
            )

    compiled_modes = _compile_modes(source)
    records.append(
        (
            "compiled/workflow.json",
            "compile",
            compiled_modes,
            zlib.compress(compiled_modes, 9),
            _sha256(compiled_modes),
        )
    )

    offset = 0
    index: list[dict[str, object]] = []
    bodies: list[bytes] = []
    for relative, release_class, payload, compressed, digest in records:
        index.append(
            {
                "id": relative,
                "class": release_class,
                "sha256": digest,
                "offset": offset,
                "compressed_size": len(compressed),
                "original_size": len(payload),
            }
        )
        bodies.append(compressed)
        offset += len(compressed)

    header = {
        "schema": 1,
        "product": "byo",
        "workspace_version": version,
        "workflow_protocol": 1,
        "compression": "zlib",
        "resources": index,
    }
    header_bytes = json.dumps(
        header, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    payload = (
        MAGIC + struct.pack(">Q", len(header_bytes)) + header_bytes + b"".join(bodies)
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(
        json.dumps(
            {
                "schema": 1,
                "workspace_version": version,
                "source": str(source),
                "classified": classified,
                "packed_resources": [record[0] for record in records],
                "customer_visible_templates": [
                    record[0]
                    for record in records
                    if record[1] in {"public-template", "user-template"}
                ],
                "pack_sha256": _sha256(payload),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return _sha256(payload)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    try:
        digest = compile_pack(
            args.source, args.policy, args.output, args.report, args.version
        )
    except (CompileError, OSError, tomllib.TOMLDecodeError) as exc:
        print(f"workspace compiler: {exc}", file=sys.stderr)
        return 1
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
