"""Execute exact recorder bytes against a real joined thread in Actions only."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTROL_METHOD = "thread_error_fixture.OrdinaryThreadProbe.test_joined_ordinary_thread"


def exercise(helper: Path, firmware: Path, directory: Path, fault: bool) -> dict:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("Thread accounting controls execute only in GitHub Actions")
    directory.mkdir(parents=True, exist_ok=False)
    copied = directory / "run_unittest.py"
    shutil.copyfile(helper, copied)
    for name in ("thread_error_fixture.py", "thread_error_wrapper.py"):
        shutil.copyfile(HERE / name, directory / name)
    frozen_input_bytes = (HERE / "CI-INPUTS.json").read_bytes()
    frozen = json.loads(frozen_input_bytes)
    declared = frozen["nested_control_declared_methods_inventory_only"]["thread_error_fixture"]
    if declared != [CONTROL_METHOD]:
        raise RuntimeError("Frozen nested control declarations differ from the real fixture")
    mini_index = {
        "declared_methods_inventory_only": {"thread_error_fixture": declared},
        "declarations_are_execution_evidence": False,
    }
    (directory / "CI-INPUTS.json").write_text(json.dumps(mini_index, indent=2) + "\n")
    command = [
        sys.executable,
        "-B",
        str(directory / "thread_error_wrapper.py"),
        str(copied),
        str(directory),
        "--module",
        "thread_error_fixture",
        "--firmware",
        str(firmware),
        "--output",
        str(directory / "methods"),
    ]
    with (
        (directory / "stdout.log").open("wb") as stdout,
        (directory / "stderr.log").open("wb") as stderr,
    ):
        completed = subprocess.run(
            command,
            env={**os.environ, "FR13_THREAD_CONTROL_FAULT": "1" if fault else "0"},
            stdout=stdout,
            stderr=stderr,
            timeout=30,
            check=False,
        )
    summary = json.loads((directory / "methods/summary.json").read_bytes())
    events = [
        json.loads(line) for line in (directory / "methods/events.jsonl").read_bytes().splitlines()
    ]
    result = {
        "argv": command,
        "exit_code": completed.returncode,
        "fault": fault,
        "helper_source": str(helper),
        "parent_frozen_input_sha256": hashlib.sha256(frozen_input_bytes).hexdigest(),
        "nested_declared_inventory_only": declared,
        "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
        "copied_helper_sha256": hashlib.sha256(copied.read_bytes()).hexdigest(),
        "fixture_sha256": hashlib.sha256(
            (directory / "thread_error_fixture.py").read_bytes()
        ).hexdigest(),
        "summary": summary,
        "events": events,
        "loaded": json.loads((directory / "methods/loaded.json").read_bytes()),
        "prior_handler": json.loads((directory / "prior-handler.json").read_bytes())
        if fault
        else None,
        "hook_lifetime": json.loads((directory / "hook-lifetime.json").read_bytes()),
        "stderr": (directory / "stderr.log").read_text(encoding="utf-8"),
        "scope": "Real stdlib thread and real recorder CLI; no product or dependency substitution",
    }
    (directory / "CONTROL.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result
