"""Focused Windows installed-public MCP proof using a genuine ARM compiler.

Requires an immutable ROOT artifact receipt and its SHA, a separately hash-bound
frozen installed-validator helper, and the actual ARM compiler's SHA. All
projects, installs, transcripts and cleanup evidence stay in a NEW short root.
This supplies compiled smoke evidence; B/update/final acceptance stays pending.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import traceback
from ctypes import wintypes
from pathlib import Path


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def record(path: Path) -> dict:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size": path.stat().st_size,
    }


def save(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def verify(ref: dict) -> dict:
    actual = record(Path(ref["path"]))
    if any(actual[k] != ref[k] for k in ("sha256", "size")):
        raise ValueError(f"input bytes differ: {ref!r}; actual {actual!r}")
    return actual


def snapshot(root: Path) -> dict:
    return {str(p.resolve()): record(p) for p in sorted(root.rglob("*")) if p.is_file()}


class Held:
    """Retain the observation handle across replacement/EOF; errors stay unknown."""

    def __init__(self, native, identity: dict):
        self.native = native
        self.identity = dict(identity)
        self.handle = native.k.OpenProcess(0x1000 | 0x100000, False, identity["pid"])
        if not self.handle:
            raise OSError(ctypes.get_last_error(), "retained OpenProcess failed")
        try:
            self.observe()
        except Exception:
            native.k.CloseHandle(self.handle)
            self.handle = None
            raise

    def observe(self) -> dict:
        times = [wintypes.FILETIME() for _ in range(4)]
        if not self.native.k.GetProcessTimes(
            self.handle, *[ctypes.byref(t) for t in times]
        ):
            raise OSError(ctypes.get_last_error(), "retained GetProcessTimes failed")
        creation = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        if creation != self.identity["creation_filetime"] or not creation:
            raise OSError("retained creation identity changed or missing")
        state = self.native.k.WaitForSingleObject(self.handle, 0)
        if state not in (0, 258):
            raise OSError(f"retained wait is unobservable: {state}")
        return {
            **self.identity,
            "retained_creation": creation,
            "wait": state,
            "alive": state == 258,
        }

    def close(self) -> None:
        if self.handle:
            self.native.k.CloseHandle(self.handle)
            self.handle = None


def split_windows(command: str) -> list[str]:
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    shell.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    count = ctypes.c_int()
    argv = shell.CommandLineToArgvW(command, ctypes.byref(count))
    if not argv:
        raise OSError(ctypes.get_last_error(), "CommandLineToArgvW failed")
    try:
        return [argv[i] for i in range(count.value)]
    finally:
        kernel.LocalFree(argv)


SOURCE = (
    "#include <newlib.h>\r\n"
    "#include <cstdint>\r\n"
    'static_assert(sizeof(void *) == 4, "ARM32 query driver target");\r\n'
    'static_assert(sizeof(_NEWLIB_VERSION) > 1, "newlib driver includes");\r\n'
    "#if MODE == 2\r\n#error acceptance-database-mode-two\r\n#endif\r\n"
    "int twice(int value) { return value + value; }\r\n"
    "/* \U0001f600 \u00fc */ int main() { std::uint8_t zero = 0; return twice(zero) + twice(1); }\r\n"
)
SECOND = (
    "#include <newlib.h>\r\n"
    'static_assert(sizeof(void *) == 4, "second ARM TU");\r\n'
    "int other() { return sizeof(_NEWLIB_VERSION); }\r\n"
)


def run(args, report: dict) -> None:
    root = args.evidence.resolve()
    if root.exists():
        raise ValueError(f"evidence root must be NEW: {root}")
    root.mkdir(parents=True)
    if os.name != "nt" or platform.machine().lower() not in ("amd64", "x86_64"):
        raise ValueError("native Windows x86_64 required")
    receipt_ref = record(args.receipt)
    if receipt_ref["sha256"] != args.receipt_sha256:
        raise ValueError("ROOT receipt SHA differs")
    card = load(args.receipt)
    inputs = [receipt_ref]
    for ref in card["active_required_references"]:
        inputs.append(verify(ref))  # Byte-bound JSON evidence records are leaves.
    for key in ("artifact", "manifest", "tester_script", "expanded_file_manifest"):
        inputs.append(verify(card[key]))
    helper_path = Path(card["tester_script"]["path"])
    if card["tester_script"]["sha256"] != args.tester_sha256:
        raise ValueError("frozen helper explicit SHA differs")
    bundle = Path(card["bundle_root"])
    expanded = load(Path(card["expanded_file_manifest"]["path"]))
    for ref in expanded["files"]:
        inputs.append(verify({**ref, "path": str(bundle / ref["path"])}))
    expected_names = {x["path"].replace("\\", "/") for x in expanded["files"]}
    if expected_names != {
        str(p.relative_to(bundle)).replace("\\", "/")
        for p in bundle.rglob("*")
        if p.is_file()
    }:
        raise ValueError("expanded bundle inventory differs")
    compiler = args.arm_root.resolve() / "bin/arm-none-eabi-g++.exe"
    compiler_ref = record(compiler)
    if compiler_ref["sha256"] != args.compiler_sha256:
        raise ValueError("real compiler explicit SHA differs")
    arm_before = snapshot(args.arm_root)
    protected = {x["path"]: x for x in inputs}
    prepared = None
    if args.prepared_home_input:
        prepared_ref = record(args.prepared_home_input)
        if prepared_ref["sha256"] != args.prepared_home_sha256:
            raise ValueError("prepared-home input explicit SHA differs")
        prepared = load(args.prepared_home_input)
        if prepared["schema"] != "verified-private-home-input/v1":
            raise ValueError("unsupported prepared-home schema")
        for key, expected in (
            ("artifact_zip", card["artifact"]),
            ("manifest", card["manifest"]),
            ("helper", card["tester_script"]),
        ):
            if prepared[key] != expected:
                raise ValueError(
                    f"prepared-home {key} differs from current artifact inputs"
                )
        source_home = Path(prepared["source_home"]).resolve()
        source_refs = prepared["source_home_files"]
        if len(source_refs) != 487:
            raise ValueError("prepared-home requires all 487 source file references")
        source_inventory = snapshot(source_home)
        for ref in source_refs:
            actual = verify(ref)
            if not Path(actual["path"]).is_relative_to(source_home):
                raise ValueError("prepared-home file outside source home")
            protected[actual["path"]] = actual
        if set(source_inventory) != {
            str(Path(x["path"]).resolve()) for x in source_refs
        }:
            raise ValueError("prepared-home inventory has missing or extra files")
        protected[prepared_ref["path"]] = prepared_ref
        for ref in prepared["public_setup_receipts"]:
            actual = verify(ref)
            setup = load(Path(ref["path"]))
            if (
                setup.get("exit") != 0
                or setup.get("timeout") is not False
                or setup.get("observation_failure")
                or not setup.get("processes")
                or any(p.get("alive_after") is not False for p in setup["processes"])
            ):
                raise ValueError(
                    "original public setup has no complete natural-exit proof"
                )
            protected[actual["path"]] = actual
        report["prepared_home"] = {
            "input": prepared_ref,
            "source": str(source_home),
            "source_files": source_refs,
            "no_new_install_lifecycle_credit": True,
            "failed0920_PID1596_future_state": "UNKNOWN",
        }
    if args.protected_receipt:
        protected_ref = record(args.protected_receipt)
        if protected_ref["sha256"] != args.protected_sha256:
            raise ValueError("protected receipt explicit SHA differs")
        protected[str(args.protected_receipt.resolve())] = protected_ref
        for ref in load(args.protected_receipt)["records_after"]:
            protected[ref["path"]] = verify(ref)
    protected.update(arm_before)
    protected[str(Path(__file__).resolve())] = record(Path(__file__))
    report.update(
        script=record(Path(__file__)),
        helper=record(helper_path),
        receipt=receipt_ref,
        artifact=card["artifact"],
        artifact_source=card["source"],
        tester_source=card["test_repository_source"],
        compiler=compiler_ref,
        arm_inventory=arm_before,
        protected_before=protected,
        expanded_files=len(expanded["files"]),
    )
    save(root / "inputs.json", report)
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(
        "frozen_installed_helper", helper_path
    )
    h = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = h
    spec.loader.exec_module(h)
    evidence = h.Evidence(root / "native")
    report["native_commands"] = str(evidence.root)
    lab = root / "lab"
    lab.mkdir()
    home = lab / "home"
    env = h.isolated_environment(home, lab)
    # The successful isolated compiler control changed both object and temp
    # placement. Keep both ASCII here; Unicode source/project remains exercised.
    compiler_temp = lab / "compiler-temp"
    compiler_temp.mkdir()
    env["TMP"] = env["TEMP"] = str(compiler_temp)
    project = lab / "project \u00fc\u6d4b\U0001f600"
    (project / "src").mkdir(parents=True)
    extended = Path("\\\\?\\" + str(project))
    source = project / "src/main.cpp"
    source.write_bytes(SOURCE.encode("utf-8"))
    (project / "customer.txt").write_bytes(b"customer passive bytes\r\n")
    (project / ".clangd").write_bytes(b"# user clangd settings\r\n")
    passive = {
        str(p): record(p) for p in (project / "customer.txt", project / ".clangd")
    }
    config = project / "byo-analysis.json"
    database = project / "build/compile_commands.json"
    flags = [str(compiler), "-mcpu=cortex-m4", "-mthumb", "-std=c++17"]
    # The pinned assembler cannot write a Unicode absolute output filename.
    # Keep source/project Unicode and use the accepted template's ASCII output
    # placement. This changes no compiler flags or selected source semantics.
    objects = lab / "objects"
    objects.mkdir()

    def entry(name: str, mode: int) -> dict:
        return {
            "directory": str(project),
            "file": name,
            "arguments": [
                *flags,
                f"-DMODE={mode}",
                "-c",
                name,
                "-o",
                str(objects / (Path(name).stem + ".o")),
            ],
        }

    def compile_one(label: str, name: str, mode: int, expected: int | None = 0):
        result = evidence.run(
            label,
            entry(name, mode)["arguments"],
            env,
            project,
            expected=expected,
            timeout=60,
        )
        report.setdefault("compiler_steps", []).append(
            {
                "label": label,
                "source": record(project / name),
                "argv": result.args,
                "exit": result.returncode,
                "object": record(objects / (Path(name).stem + ".o"))
                if result.returncode == 0
                else None,
            }
        )
        return result

    server = None
    peer = None
    peer_held = None
    held = []
    completed = False
    try:
        banner = evidence.run(
            "real-arm-version", [str(compiler), "--version"], env, lab
        )
        h.require("14.3.1" in banner.stdout, "ARM GCC version differs")
        if prepared is None:
            evidence.run(
                "public-install",
                [str(bundle / "byo.exe"), "install-runtime", "--bundle", str(bundle)],
                env,
                lab,
                timeout=300,
            )
        else:
            shutil.copytree(source_home, home)
            copied = []
            for ref in source_refs:
                target = home / Path(ref["path"]).relative_to(source_home)
                copied.append(verify({**ref, "path": str(target)}))
            if set(snapshot(home)) != {x["path"] for x in copied}:
                raise ValueError(
                    "copied home inventory differs from 487 bound source files"
                )
            report["prepared_home"]["copied_files"] = copied
            report["prepared_home"]["copied_target"] = str(home)
        runtime = home / "data/versions" / card["version"]
        byo = home / "bin/byo.exe"
        current = load(home / "data/current.json")
        if current != {
            "schema": 1,
            "version": card["version"],
            "relative_runtime": f"versions/{card['version']}",
            "manifest_sha256": card["manifest"]["sha256"],
        }:
            raise ValueError(
                "current.json is not bound to the exact relative A runtime"
            )
        if any(
            record(byo)[k] != record(bundle / "byo.exe")[k] for k in ("sha256", "size")
        ):
            raise ValueError("copied public launcher differs from exact A bundle")
        h.assert_runtime(runtime, load(Path(card["manifest"]["path"])))
        evidence.run(
            "public-init", [str(byo), "init", "--project", str(extended)], env, lab
        )
        save(
            config,
            {
                "schema_version": 1,
                "compilation_database": "build/compile_commands.json",
            },
        )
        save(database, [entry("src/main.cpp", 1)])
        compile_one("compile-main-clean", "src/main.cpp", 1)
        server = h.Mcp(evidence, byo, extended, env, card["version"], "compiled")
        # Only canonical test comparisons use the normal spelling; the actual
        # public argv/cwd above retain the explicit extended project root.
        server.project = project
        health = server.tool("server_health_check", {}, analysis=False)
        h.require(
            health.get("narrative_logging") == "enabled", "personal health differs"
        )
        report["public_health"] = health

        def diagnose(
            label: str, name: str = "src/main.cpp", *, analysis: bool = True
        ) -> dict:
            value = server.tool(
                "get_code_diagnostics",
                {"file_path": name, "timeout_seconds": 60},
                analysis=analysis,
            )
            report.setdefault("diagnostics", []).append(
                {"label": label, "result": value}
            )
            return value

        def messages(value: dict) -> list[str]:
            return [x["message"] for x in value["data"]["diagnostics"]]

        def generation() -> Held:
            server.owned.sample_once()
            live = [
                x
                for x in list(server.owned.records.values())
                if isinstance(x.get("image"), str)
                and Path(x["image"]).name.lower() == "clangd.exe"
                and evidence.native.alive(x)
            ]
            h.require(len(live) == 1, f"expected one exact live owned session: {live}")
            identity = Held(evidence.native, live[0])
            held.append(identity)
            h.require(
                Path(identity.identity["image"]).samefile(
                    runtime / "analysis/clangd/bin/clangd.exe"
                ),
                "owned session used another clangd executable",
            )
            h.require(identity.observe()["alive"] is True, "session not live")
            return identity

        baseline = diagnose("without-query-driver", analysis=False)
        h.require(
            baseline["status"] == "incomplete"
            and baseline["code"] == "analysis/compile-context-missing",
            "empty-driver control did not report incomplete compile context",
        )
        h.require(
            baseline["source"]["sha256"] == record(source)["sha256"]
            and baseline["compilation_database_sha256"] == record(database)["sha256"],
            "empty-driver control returned stale source/database",
        )
        h.require(
            any(
                any(header in m.lower() for header in ("newlib", "cstdint"))
                for m in messages(baseline)
            ),
            "negative control did not expose missing driver system includes",
        )
        without = generation()
        relative = os.path.relpath(compiler, project)
        save(
            config,
            {
                "schema_version": 1,
                "compilation_database": "build/compile_commands.json",
                "clangd": {"query_driver_paths": [relative]},
            },
        )
        report["relative_query_driver"] = relative
        passive[str(config)] = record(config)
        clean = diagnose("with-relative-query-driver")
        h.require(messages(clean) == [], f"real ARM target/includes not clean: {clean}")
        first = generation()
        h.require(without.observe()["alive"] is False, "old no-driver session survived")

        def prove_argv(identity: Held):
            server.record_child_argv(env)
            path = server.path / f"clangd-{identity.identity['pid']}.json"
            observed = load(path)
            argv = split_windows(observed["native_observation"]["CommandLine"])
            allow = [
                a[len("--query-driver=") :]
                for a in argv
                if a.startswith("--query-driver=")
            ]
            h.require(
                len(allow) == 1 and allow[0] and "," not in allow[0],
                f"allowlist not a single nonempty executable: {argv}",
            )
            h.require(
                h.reported_path(allow[0]).samefile(compiler), "actual driver differs"
            )
            h.require(identity.observe()["alive"] is True, "argv identity exited")
            report.setdefault("actual_clangd_argv", []).append(
                {"identity": identity.observe(), "argv": argv, "receipt": record(path)}
            )

        prove_argv(first)
        source.write_bytes(
            SOURCE.replace(
                "return twice(zero)", "return acceptance_undefined_symbol"
            ).encode("utf-8")
        )
        defective = compile_one("compile-main-defect", "src/main.cpp", 1, expected=None)
        h.require(defective.returncode != 0, "real compiler accepted undefined symbol")
        defect = diagnose("saved-defect")
        h.require(
            any("acceptance_undefined_symbol" in m for m in messages(defect)),
            "saved defect not diagnosed",
        )
        source.write_bytes(SOURCE.encode("utf-8"))
        compile_one("compile-main-restored", "src/main.cpp", 1)
        restored = diagnose("saved-restored")
        h.require(messages(restored) == [], "restored diagnostics not empty")
        h.require(
            clean["source"]["document_version"]
            < defect["source"]["document_version"]
            < restored["source"]["document_version"],
            "saved versions not advancing",
        )
        line = SOURCE.splitlines()[8]
        column = line.index("twice") + 1
        query = {
            "file_path": "src/main.cpp",
            "line": 9,
            "column": column,
            "timeout_seconds": 60,
        }
        definition = server.tool("find_code_definition", query)
        h.require(
            any(
                x["range"]["start"]["line"] == 8
                for x in definition["data"]["locations"]
            ),
            "definition differs",
        )
        hover = server.tool("get_code_hover", query)
        h.require("twice" in json.dumps(hover["data"]), "hover differs")
        refs = server.tool(
            "find_code_references", {**query, "include_declaration": True}
        )
        h.require(
            any(
                x["range"]["start"] == {"line": 9, "column": column}
                for x in refs["data"]["locations"]
            ),
            "non-BMP CRLF position differs",
        )
        status = server.tool("get_code_analysis_status", {})
        h.require(
            status["data"]["executable_origin"] == "managed_runtime",
            "PATH analyzer used",
        )
        clangd = runtime / "analysis/clangd/bin/clangd.exe"
        peer = subprocess.Popen(
            [str(clangd)],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=lab,
            env=env,
        )
        peer_identity = evidence.native.identity(peer.pid)
        h.require(peer_identity and peer_identity["alive"] is True, "peer unobservable")
        peer_held = Held(evidence.native, peer_identity)
        h.require(
            Path(peer_identity["image"]).samefile(first.identity["image"]),
            "peer is not the same installed image",
        )
        h.require(
            peer.pid not in {k[0] for k in server.owned.records}, "peer became owned"
        )
        second_source = project / "src/second.cpp"
        second_source.write_bytes(SECOND.encode("utf-8"))
        compile_one("compile-real-second-TU-before-DB", "src/second.cpp", 1)
        mode_two = compile_one(
            "compile-main-mode-two-control", "src/main.cpp", 2, expected=None
        )
        h.require(
            mode_two.returncode != 0, "compiler accepted database mode-two #error"
        )
        old_db = record(database)
        save(database, [entry("src/main.cpp", 2), entry("src/second.cpp", 1)])
        report["database_transition"] = {
            "before": old_db,
            "after": record(database),
            "second_source": record(second_source),
            "second_object": record(objects / "second.o"),
        }
        second_result = diagnose("truthfully-compiled-second-TU", "src/second.cpp")
        h.require(messages(second_result) == [], "compiled second TU not clean")
        replaced = diagnose("database-mode-two")
        h.require(
            any(
                "acceptance-database-mode-two" in m.lower() for m in messages(replaced)
            ),
            "database edit did not change current diagnostics",
        )
        second = generation()
        h.require(
            second.identity["creation_filetime"] != first.identity["creation_filetime"],
            "database replacement reused old session",
        )
        h.require(
            first.observe()["alive"] is False and second.observe()["alive"] is True,
            "old/new exact session lifecycle differs",
        )
        prove_argv(second)
        report["before_eof"] = [x.observe() for x in held]
        started = time.monotonic()
        server.close()
        report["natural_eof"] = {
            "seconds": time.monotonic() - started,
            "public_receipt": record(server.path / "command.json"),
            "retained_after": [x.observe() for x in held],
            "peer_after": peer_held.observe(),
        }
        h.require(
            all(x.observe()["alive"] is False for x in held),
            "owned session survived EOF",
        )
        h.require(peer_held.observe()["alive"] is True, "unrelated peer was killed")
        h.require(
            all(
                x["alive_after"] is False
                for x in load(server.path / "command.json")["processes"]
            ),
            "an owned exact incarnation survived natural EOF",
        )
        peer.stdin.close()
        peer_exit = peer.wait(timeout=10)
        report["peer_retirement"] = {
            "exit": peer_exit,
            "forced": False,
            "retained_after": peer_held.observe(),
        }
        # The unrelated peer has no LSP initialization/shutdown exchange. Its
        # polite EOF can return 1; capture that actual exit without confusing
        # fixture retirement with the public server's mandatory clean exit 0.
        h.require(peer_held.observe()["alive"] is False, "peer EOF did not prove exit")
        h.assert_runtime(runtime, load(Path(card["manifest"]["path"])))
        for ref in passive.values():
            verify(ref)
        report["public_tool_results"] = server.results
        report["compiled_gaps"] = {
            name: "PASS"
            for name in (
                "extended_public_root",
                "relative_real_ARM_driver",
                "nonempty_exact_allowlist",
                "ARM32_newlib_target_includes",
                "compiler_clean_defect_restored",
                "Unicode_CRLF_all_five_tools",
                "real_second_TU_compiled_before_DB",
                "DB_replacement_current_diagnostics",
                "old_exact_exit_new_exact_live",
                "natural_public_EOF_all_owned_exit",
                "unaffected_same_image_peer",
            )
        }
        completed = True
    finally:
        report["emergency_cleanup"] = []
        if server is not None and not server.closed:
            server.close(check=False)
            report["failure_server_close"] = load(server.path / "command.json")
        if server is not None and server.closed:
            close_receipt = load(server.path / "command.json")
            if close_receipt.get("eof_timeout") or any(
                p.get("alive_after") is not False
                for p in close_receipt.get("processes", [])
            ):
                report["emergency_cleanup"].append({"public_server": close_receipt})
        if peer is not None and peer.poll() is None:
            peer.stdin.close()
            try:
                peer.wait(timeout=10)
            except subprocess.TimeoutExpired:
                evidence.native.terminate(peer_held.identity)
                peer.wait(timeout=5)
                report["emergency_cleanup"].append({"peer": peer_held.identity})
        for identity in held + ([peer_held] if peer_held else []):
            identity.close()
        report["protected_after"] = {p: verify(ref) for p, ref in protected.items()}
        if prepared is not None and snapshot(source_home) != source_inventory:
            raise ValueError(
                "original prepared home changed; source inventory not preserved"
            )
        if snapshot(args.arm_root) != arm_before:
            raise ValueError("ARM package dependencies changed")
        report["passive_preserved"] = passive
        report["compiled_milestone"] = completed and not report["emergency_cleanup"]
        save(root / "progress.json", report)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "receipt",
        "arm-root",
        "evidence",
        "protected-receipt",
        "prepared-home-input",
    ):
        parser.add_argument(
            "--" + name,
            type=Path,
            required=name not in ("protected-receipt", "prepared-home-input"),
        )
    for name in ("receipt-sha256", "tester-sha256", "compiler-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--protected-sha256")
    parser.add_argument("--prepared-home-sha256")
    args = parser.parse_args()
    if bool(args.prepared_home_input) != bool(args.prepared_home_sha256):
        parser.error("prepared-home input and SHA must be provided together")
    report = {
        "schema": "installed-compiled-smoke/v1",
        "argv": sys.argv,
        "compiled_milestone": False,
        "installed_final_acceptance": False,
        "pending": [
            "independent max review",
            "B professional",
            "A-to-B update",
            "final acceptance",
        ],
    }
    try:
        run(args, report)
        report["status"] = "PASS"
        code = 0
    except Exception as exc:
        report.update(
            status="SETUP_FAILURE"
            if isinstance(exc, (OSError, ValueError)) or type(exc).__name__ == "Setup"
            else "RED",
            error=repr(exc),
            traceback=traceback.format_exc(),
            compiled_milestone=False,
        )
        code = 2 if report["status"] == "SETUP_FAILURE" else 1
    report["exit"] = code
    if args.evidence.exists():
        save(args.evidence / "report.json", report)
    print(
        json.dumps(
            {
                "status": report["status"],
                "exit": code,
                "evidence": str(args.evidence),
                "error": report.get("error"),
            }
        ),
        flush=True,
    )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
