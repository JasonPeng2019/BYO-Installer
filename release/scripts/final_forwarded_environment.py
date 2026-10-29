"""Observe the actual installed launcher's sidecar after native qualification.

Use only after ROOT account/KnownFolder qualification and exact freeze. Read
only an already captured, credential-free, owned child. Never launch/reap/signal
processes or inspect a client/provider environment. An unreadable observation is
UNVERIFIED, never inferred from the source whitelist or a projected environment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


NAMES = (
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "PATH",
    "SystemRoot",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--launcher-pid", type=int, required=True)
    parser.add_argument("--launcher-birth", type=float, required=True)
    parser.add_argument("--launcher-sha256", required=True)
    parser.add_argument("--sidecar", type=Path, required=True)
    parser.add_argument("--sidecar-sha256", required=True)
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    if args.evidence.exists():
        raise RuntimeError("one observation reservation cannot be overwritten")
    qualification = json.loads(args.qualification.read_text(encoding="utf-8"))
    final = qualification.get("acceptance_execution_authorized") is True
    preparation = qualification.get("bc05_hosted_preparation_authorized") is True
    if not final and not preparation:
        raise RuntimeError("exact execution authority required")
    bindings = (
        ("execution_card_sha256", "freeze_commit")
        if final
        else ("ci_input_sha256", "source_commit")
    )
    for key in (
        *bindings,
        "os_account_proof_sha256",
        "native_knownfolder_proof_sha256",
    ):
        if not qualification.get(key):
            raise RuntimeError("missing effective native boundary: " + key)
    if qualification.get("sidecar_environment_contains_no_credentials") is not True:
        raise RuntimeError(
            "do not inspect any potentially credential-bearing process environment"
        )
    expected = json.loads(args.expected.read_text(encoding="utf-8"))
    if not set(expected) <= set(NAMES):
        raise RuntimeError(
            "expected environment must contain only the nonsecret product whitelist"
        )
    image = args.sidecar.resolve(strict=True)
    if hashlib.sha256(image.read_bytes()).hexdigest() != args.sidecar_sha256:
        raise RuntimeError("sidecar image does not match the frozen installed manifest")
    import psutil

    record = {
        "schema": "v-final-actual-forwarding/v1",
        "outcome": "UNVERIFIED",
        "launcher_pid": args.launcher_pid,
        "launcher_birth": args.launcher_birth,
        "sidecar": str(image),
        "sidecar_sha256": args.sidecar_sha256,
    }
    try:
        parent = psutil.Process(args.launcher_pid)
        if parent.create_time() != args.launcher_birth:
            raise RuntimeError("launcher identity was reused")
        launcher = Path(parent.exe()).resolve(strict=True)
        if hashlib.sha256(launcher.read_bytes()).hexdigest() != args.launcher_sha256:
            raise RuntimeError("actual launcher image differs from the frozen manifest")
        record.update(launcher=str(launcher), launcher_sha256=args.launcher_sha256)
        matches = []
        for child in parent.children(recursive=True):
            birth = child.create_time()
            if birth < args.launcher_birth or Path(child.exe()).resolve() != image:
                continue
            matches.append((child, birth))
        if len(matches) != 1:
            raise RuntimeError("actual installed sidecar must be uniquely attributable")
        child, birth = matches[0]
        # The exact native qualification binds this compiled credential-free child. Only
        # selected nonsecret values are retained; client/provider env is never read.
        environment = child.environ()
        folded = {k.casefold(): v for k, v in environment.items()}
        selected = {name: folded.get(name.casefold()) for name in NAMES}
        del environment, folded
        if child.create_time() != birth or parent.create_time() != args.launcher_birth:
            raise RuntimeError("process identity changed during observation")
        mismatches = {
            name: {"expected": expected.get(name), "actual": selected[name]}
            for name in NAMES
            if selected[name] != expected.get(name)
        }
        record.update(
            sidecar_pid=child.pid,
            sidecar_birth=birth,
            observed=selected,
            mismatches=mismatches,
            outcome="FAIL" if mismatches else "PASS",
        )
    except (OSError, psutil.Error, RuntimeError) as exc:
        record.update(error_type=type(exc).__name__, reason=str(exc))
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    args.evidence.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return int(record["outcome"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
