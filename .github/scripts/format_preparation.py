"""Actions-only source-format authoring, never product/acceptance execution.

ROOT stages this helper on an isolated preparation ref after FR06 closes. It is
not part of the product candidate. This file must not execute on the local PC.
"""
from __future__ import annotations

import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def main() -> int:
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('Formatting authoring runs in GitHub Actions only')
    root = Path.cwd().resolve()
    firmware = root / 'Firmware MCP New'
    evidence = root / 'format-preparation-evidence'
    evidence.mkdir(exist_ok=False)
    records, errors = [], []

    def sha(raw: bytes) -> str:
        return hashlib.sha256(raw).hexdigest()

    def write(name: str, data: object) -> None:
        (evidence / name).write_text(json.dumps(data, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')

    def git(where: Path, *args: str) -> bytes:
        return subprocess.check_output(['git', '--no-optional-locks', *args], cwd=where)

    def invoke(name: str, argv: list[str], cwd: Path) -> None:
        started = time.monotonic()
        record = {'name': name, 'argv': argv, 'cwd': str(cwd), 'started_at': datetime.now(timezone.utc).isoformat()}
        try:
            result = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=900)
            stdout, stderr, code = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as exc:
            stdout, stderr, code = exc.stdout or b'', exc.stderr or b'', None
            record['error'] = 'TIMEOUT; command authoring incomplete'
        except OSError as exc:
            stdout, stderr, code = b'', str(exc).encode(), None
            record['error'] = type(exc).__name__ + ': ' + str(exc)
        (evidence / (name + '.stdout.log')).write_bytes(stdout)
        (evidence / (name + '.stderr.log')).write_bytes(stderr)
        record.update({'exit_code': code, 'seconds': time.monotonic() - started,
                       'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr)})
        records.append(record)
        if code != 0:
            errors.append(name + ': unsuccessful authoring command; inspect exact streams/exit')

    def tracked(where: Path) -> dict[str, bytes]:
        return {raw.decode(): (where / raw.decode()).read_bytes()
                for raw in git(where, 'ls-files', '-z').split(b'\0') if raw}

    def inventory(files: dict[str, bytes]) -> dict[str, dict[str, object]]:
        return {p: {'bytes': len(raw), 'sha256': sha(raw)} for p, raw in files.items()}

    expected_firmware = os.environ['BYO_FORMAT_FIRMWARE_COMMIT']
    original_installer = os.environ['BYO_FORMAT_INSTALLER_SOURCE_COMMIT']
    common = os.environ['BYO_FORMAT_COMMON_BASE']
    for value in (expected_firmware, original_installer, common):
        if len(value) != 40 or any(c not in '0123456789abcdef' for c in value):
            raise ValueError('Preparation must bind exact full Git commits')
    firmware_head = git(firmware, 'rev-parse', 'HEAD').decode().strip()
    installer_head = git(root, 'rev-parse', 'HEAD').decode().strip()
    if firmware_head != expected_firmware or git(root, 'rev-parse', 'HEAD^').decode().strip() != original_installer:
        raise RuntimeError('Actual preparation checkouts do not match bound source commits')
    overlays = set(git(root, 'diff', '--name-only', original_installer, installer_head).decode().splitlines())
    if overlays != {'.github/workflows/build-matrix.yml', '.github/scripts/format_preparation.py'}:
        raise RuntimeError('Preparation ref must add only its exact temporary workflow/helper overlay')
    if git(root, 'status', '--porcelain', '--untracked-files=no').strip() or git(firmware, 'status', '--porcelain').strip():
        raise RuntimeError('Preparation sources are not initially clean')
    before = {'firmware': tracked(firmware), 'installer': tracked(root)}
    write('SOURCE-BEFORE.json', {k: inventory(v) for k, v in before.items()})
    write('BINDING.json', {'at': datetime.now(timezone.utc).isoformat(), 'common_base': common,
                          'firmware_commit': firmware_head, 'installer_source_commit': original_installer,
                          'installer_preparation_commit': installer_head, 'temporary_overlay': sorted(overlays),
                          'run_id': os.environ['GITHUB_RUN_ID'], 'run_attempt': os.environ['GITHUB_RUN_ATTEMPT'],
                          'workflow': os.environ['GITHUB_WORKFLOW'], 'scope': 'FORMAT AUTHORING ONLY; no product acceptance'})
    interpreter = ['uv', 'run', '--no-sync', '--project', str(firmware), 'python', '-B', '-m', 'ruff']
    invoke('ruff-version', interpreter + ['--version'], root)
    if (evidence / 'ruff-version.stdout.log').read_bytes().strip() != b'ruff 0.15.21':
        errors.append('Actual locked Ruff differs from the bound expected0.15.21; do not apply artifact')
    invoke('rustfmt-version', ['rustup', 'run', '1.97.1', 'rustfmt', '--version'], root)
    invoke('firmware-format', interpreter + ['format', 'src', 'tests'], firmware)
    invoke('release-format', interpreter + ['format', 'release/scripts', 'hil'], root)
    invoke('launcher-format', ['cargo', '+1.97.1', 'fmt', '--manifest-path', 'launcher/Cargo.toml'], root)
    after = {'firmware': tracked(firmware), 'installer': tracked(root)}
    write('SOURCE-AFTER.json', {k: inventory(v) for k, v in after.items()})
    changes = []
    for component in before:
        if set(before[component]) != set(after[component]):
            errors.append(component + ': tracked source inventory changed')
        for path in sorted(set(before[component]) & set(after[component])):
            old, new = before[component][path], after[component][path]
            if old == new:
                continue
            allowed = ((component == 'firmware' and path.startswith(('src/', 'tests/')) and path.endswith(('.py', '.pyi')))
                       or (component == 'installer' and path.startswith(('release/scripts/', 'hil/')) and path.endswith(('.py', '.pyi')))
                       or (component == 'installer' and path.startswith('launcher/') and path.endswith('.rs')))
            if not allowed:
                errors.append('Unexpected formatted path: ' + component + '/' + path)
            record = {'component': component, 'path': path, 'before_sha256': sha(old), 'after_sha256': sha(new), 'allowed': allowed}
            if path.endswith(('.py', '.pyi')):
                try:
                    record['AST_equal'] = ast.dump(ast.parse(old), include_attributes=False) == ast.dump(ast.parse(new), include_attributes=False)
                except (SyntaxError, UnicodeError) as exc:
                    record['AST_equal'] = False
                    record['AST_error'] = str(exc)
                if not record['AST_equal']:
                    errors.append('Python AST changed: ' + component + '/' + path)
            changes.append(record)
    for component, where, prefix in (('firmware', firmware, 'BYO-Firmware-MCP'), ('installer', root, 'BYO-Installer')):
        patch = git(where, 'diff', '--binary', '--full-index', '--no-ext-diff',
                    '--src-prefix=a/MCP_Server_Dev/' + prefix + '/', '--dst-prefix=b/MCP_Server_Dev/' + prefix + '/')
        (evidence / (component + '.patch')).write_bytes(patch)
    write('AUTHORING.json', {'commands': records, 'changed_paths': changes, 'errors': errors,
                            'outcome': 'ERROR' if errors else 'PATCH_PREPARED',
                            'all_product_acceptance': 'UNRUN; no tests, fixtures, quality pass, build, installed/client/model/device acceptance',
                            'limits': 'ROOT/W-FR07 must verify exact source/patch/AST/Rust semantics before use; this is code authoring only'})
    return int(bool(errors))


if __name__ == '__main__':
    raise SystemExit(main())
