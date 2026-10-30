"""Qualify only the launcher's existing, exact deferred Windows cleanup contract.

The ordinary child-wait result stays raw. A later natural exit is a separate
axis, tied to source, spawn, parent and target facts; image names grant nothing.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import time


def source_contract(path: Path) -> dict:
    data = path.read_bytes()
    scripts = re.findall(r'let cleanup = r#"(.*?)"#;', data.decode("utf-8"), re.S)
    if len(scripts) != 1:
        raise ValueError("Exact deferred cleanup source script is missing or ambiguous")
    script = scripts[0]
    attempts = re.findall(r"for\(\$i=0;\$i -lt (\d+);\$i\+\+\)", script)
    sleeps = re.findall(r"Start-Sleep -Seconds (\d+)", script)
    waits = re.findall(r"WaitForExit\((\d+)\)", script)
    if len(attempts) != 1 or len(sleeps) != 1 or len(waits) != 1:
        raise ValueError("Deferred cleanup has no unique existing bounded contract")
    facts = {
        "source": str(path.resolve()),
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "script_sha256": hashlib.sha256(script.encode()).hexdigest(),
        "parent_wait_ms": int(waits[0]),
        "delete_attempts": int(attempts[0]),
        "delete_retry_ms": int(sleeps[0]) * 1000,
    }
    if any(
        facts[key] <= 0
        for key in ("parent_wait_ms", "delete_attempts", "delete_retry_ms")
    ):
        raise ValueError("Deferred cleanup contract must be finite and nonempty")
    facts["post_parent_seconds"] = (
        facts["delete_attempts"] * facts["delete_retry_ms"] / 1000
    )
    return facts


def select_observation(rows, parent, captured, expected):
    """Join one actual spawn receipt to exact independently captured identities."""

    if len(rows) != 1:
        raise ValueError(
            "Deferred cleanup requires exactly one actual spawn observation"
        )
    row = rows[0]
    required = {
        "schema": "windows-launcher-deferred-cleanup-observation/v1",
        "parent_pid": parent["pid"],
        "parent_creation_filetime": parent["creation_filetime"],
        "requested_parent_pid": parent["pid"],
        "target_sha256_before_spawn": expected["previous_launcher_sha256"],
        **{
            key: expected["contract"][key]
            for key in (
                "script_sha256",
                "parent_wait_ms",
                "delete_attempts",
                "delete_retry_ms",
            )
        },
    }
    if any(
        row.get(key) != value or type(row.get(key)) is not type(value)
        for key, value in required.items()
    ):
        raise ValueError("Deferred spawn source/parent/target contract differs")
    target = Path(row["target"])
    if (
        target.parent.resolve() != Path(expected["target_directory"]).resolve()
        or not re.fullmatch(r"\.byo-update-[0-9a-f]{16}\.exe", target.name)
        or target.is_symlink()
    ):
        raise ValueError("Deferred target is not the exact owned update tombstone")
    live = [item for item in captured if item.get("alive_after") is True]
    if len(live) != 1:
        raise ValueError(
            "Other captured live children cannot receive a deferred exemption"
        )
    helper = live[0]
    fields = {
        "pid": row.get("helper_pid"),
        "creation_filetime": row.get("helper_creation_filetime"),
        "parent_pid": parent["pid"],
        "parent_creation_filetime": parent["creation_filetime"],
    }
    if any(
        helper.get(key) != value or type(value) is not int or value <= 0
        for key, value in fields.items()
    ):
        raise ValueError("Deferred helper lacks its exact captured birth/parent join")

    def normalize(path):
        return os.path.normcase(str(Path(path).resolve()))

    image = normalize(expected["helper_image"])
    if (
        normalize(row.get("helper_image", "")) != image
        or normalize(helper.get("image") or "") != image
    ):
        raise ValueError(
            "Deferred helper executable differs from its source-bound spawn"
        )
    if helper["creation_filetime"] < parent["creation_filetime"]:
        raise ValueError("Deferred helper predates its actual parent")
    if target.exists() and (
        not target.is_file()
        or hashlib.sha256(target.read_bytes()).hexdigest()
        != expected["previous_launcher_sha256"]
    ):
        raise ValueError("Current owned tombstone differs from its exact prior image")
    return row, helper, target


def qualify(directory, native, parent, captured, expected, parent_exit_at):
    report = {
        "schema": "deferred-cleanup-qualification/v1",
        "outcome": "ERROR",
        "ordinary_axis": "FAIL",
        "ordinary_survivors": [
            dict(item) for item in captured if item.get("alive_after") is True
        ],
        "contract": expected["contract"],
        "parent_exit_monotonic": parent_exit_at,
        "interventions": [],
    }
    handle = None
    try:
        paths = sorted(Path(directory).glob("*.json"))
        rows = [json.loads(path.read_bytes()) for path in paths]
        row, helper, target = select_observation(rows, parent, captured, expected)
        report.update(
            spawn=row,
            observation_files=[
                {
                    "path": str(path),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
                for path in paths
            ],
        )
        handle = native.retain_exact(helper)
        deadline = parent_exit_at + expected["contract"]["post_parent_seconds"]
        report["deadline_monotonic"] = deadline
        while True:
            observed = native.observe_retained(handle, helper)
            report["terminal_observation"] = observed
            report["target_exists"] = target.exists()
            report["observed_at_monotonic"] = time.monotonic()
            if (
                observed["terminal"]
                and observed["exit_code"] == 0
                and not report["target_exists"]
            ):
                if report["observed_at_monotonic"] <= deadline:
                    report["outcome"] = "PASS"
                else:
                    report["outcome"] = "TIMEOUT"
                break
            if observed["terminal"] and observed["exit_code"] != 0:
                report["outcome"] = "FAIL"
                break
            if time.monotonic() >= deadline:
                report["outcome"] = "TIMEOUT"
                break
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    except Exception as error:
        report["error"] = repr(error)
    finally:
        if handle is not None:
            try:
                native.release_retained(handle)
            except Exception as error:
                report.update(outcome="ERROR", handle_close_error=repr(error))
    return report
