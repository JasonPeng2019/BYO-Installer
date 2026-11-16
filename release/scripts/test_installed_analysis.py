"""Necessary installed analysis and public transport scenarios.

Uses supplied genuine bundles, a real vendor ARM compiler and the pinned source
companion. Missing inputs are UNRUN prerequisites, never substituted by fakes.
Product compilation, real models and physical boards are not launched here.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from installed_support import Mcp, installed_lab, invoke

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def snapshot(root):
    return {p.relative_to(root).as_posix(): digest(p) for p in root.rglob("*") if p.is_file()}


def protected_project(root):
    return {path: sha for path, sha in snapshot(root).items()
            if not path.startswith((".firm/code-analysis/", "build/.cache/clangd/index/"))}



def arm_compilers():
    supplied = os.environ.get("BYO_TEST_ARM_GNU_ROOT")
    if not supplied:
        pytest.skip("UNRUN native input: supply the acquired GNU Arm 14.3.1 BYO_TEST_ARM_GNU_ROOT")
    suffix = ".exe" if os.name == "nt" else ""
    root = Path(supplied).resolve(strict=True)
    compilers = {name: root / "bin" / ("arm-none-eabi-" + tool + suffix)
                 for name, tool in (("gcc", "gcc"), ("gxx", "g++"))}
    version = subprocess.run([str(compilers["gxx"]), "--version"], capture_output=True,
                             text=True, encoding="utf-8", timeout=30, check=True)
    assert "14.3.1" in version.stdout, version
    return compilers


def project(lab, name, files, compilers, *, semantic=False):
    root = lab.root / (name + " µ 中")
    for relative, text in {**files, **USER_FILES}.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.replace("\n", "\r\n").encode("utf-8"))
    invoke([str(lab.byo), "init", "--project", str(root)], env=lab.env)
    units = [(r, "gxx", ["-std=c++17"]) for r in files if r.endswith(".cpp")] if semantic else ARM_UNITS
    include_query = invoke([str(compilers["gxx"]), "-mcpu=cortex-m4", "-mthumb", "-E", "-v", "-x", "c++", "-"],
                           env=lab.env, cwd=root, stdin="")
    includes = parse_include_search(include_query.stderr)
    assert includes, include_query.stderr
    commands, database = [], []
    for relative, compiler, extra in units:
        output = root / "build" / (Path(relative).stem + ".o")
        argv = [str(compilers[compiler]), *ARM_FLAGS, *extra, "-I", str(root / "include"),
                "-I", str(root / "build/generated"), "-c", str(root / relative), "-o", str(output)]
        for include in includes:
            argv += ["-I", include]
        commands.append(argv)
        database.append({"directory": str(root), "file": str(root / relative),
                         "arguments": argv, "output": str(output)})
    write_json(root / "build/compile_commands.json", database)
    config = {"schema_version": 1, "compilation_database": "build/compile_commands.json",
              "clangd": {"query_driver_paths": list(map(str, compilers.values()))}}
    if not semantic:
        config["cppcheck"] = {"platform_file": "config/arm32.xml"}
    write_json(root / "byo-analysis.json", config)
    return root, commands


def build_override(lab, root, commands):
    target = root / "bin/verify-firmware-local"
    target.parent.mkdir(exist_ok=True)
    if os.name == "nt":
        compiler = shutil.which("rustc")
        if not compiler:
            pytest.skip("UNRUN Windows input: rustc is needed for the native test build override")
        source = lab.root / "build-override.rs"
        source.write_text(WINDOWS_OVERRIDE_RS, encoding="utf-8")
        built = lab.root / "build-override.exe"
        invoke([compiler, "--edition=2021", "-C", "linker=rust-lld", "-C", "linker-flavor=lld-link",
                str(source), "-o", str(built)], env={**os.environ, "VSCMD_SKIP_SENDTELEMETRY": "1"}, timeout=180)
        shutil.copyfile(built, target)
        (root / "build/override-commands.txt").write_text(windows_override_commands(commands), encoding="utf-8")
    else:
        target.write_text(posix_override_script(commands), encoding="utf-8")
        target.chmod(0o755)


def verify(lab, root, target=".", *, owner="rust", expected=0):
    before = set((root / ".firm/code-analysis/reports").glob("*/result.json"))
    if owner == "rust":
        argv = [str(lab.byo), "workflow", "tool", "verify", "--project", str(root), target]
    else:
        workspace = os.environ.get("BYO_TEST_WORKSPACE_SOURCE")
        if not workspace:
            pytest.skip("UNRUN companion input: supply pinned BYO_TEST_WORKSPACE_SOURCE")
        driver = lab.root / "companion.py"
        driver.write_text(COMPANION_DRIVER, encoding="utf-8")
        argv = [getattr(sys, "_base_executable", None) or sys.executable, "-I", "-B", str(driver),
                str(Path(workspace).resolve()), str(lab.runtime), digest(lab.runtime / "release-manifest.json"), str(root), target]
    completed = invoke(argv, cwd=root, env=lab.env, expected=expected, timeout=180)
    created = set((root / ".firm/code-analysis/reports").glob("*/result.json")) - before
    assert len(created) == 1, (created, completed.stdout, completed.stderr)
    result = json.loads(created.pop().read_text(encoding="utf-8"))
    assert result["executable_origin"] == "managed_runtime", result
    assert result["executable_sha256"] == digest(Path(result["executable"])), result
    if owner == "rust":
        assert ("VERIFY: PASS" in completed.stdout + completed.stderr) == (expected == 0), completed
    else:
        returned = json.loads(completed.stdout.splitlines()[-1])["result"]
        assert returned["status"] == result["status"], returned
    return result


def position(root, relative, line, token):
    text = (root / relative).read_text(encoding="utf-8").splitlines()[line - 1]
    return {"file_path": relative, "line": line, "column": text.index(token) + 1, "timeout_seconds": 60}


def checked(value, root, source=None):
    assert value["status"] == "ok" and value["backend"] == "clangd", value
    assert Path(value["project_root"]).samefile(root), value
    assert value["compilation_database_sha256"] == digest(root / "build/compile_commands.json"), value
    if source:
        assert value["source"]["sha256"] == digest(root / source), value
    return value


def locations(value):
    return {(Path(p["path"]).name, p["range"]["start"]["line"]) for p in value["data"]["locations"]}


def live_clangd(server, lab):
    children = [child for child in server.observe_children()
                if Path(child.image).name in ("clangd", "clangd.exe") and child.alive()]
    assert len(children) == 1, [(c.pid, c.image, c.argv) for c in children]
    relative = lab.manifest["platform"] == "windows"
    assert Path(children[0].image).samefile(lab.runtime / "analysis/clangd/bin" / ("clangd.exe" if relative else "clangd"))
    return children[0]


def test_managed_semantics_saved_changes_database_transition_and_natural_eof():
    compilers = arm_compilers()
    with installed_lab() as lab:
        root, commands = project(lab, "semantic", SEMANTIC, compilers, semantic=True)
        for command in commands:
            invoke(command, env=lab.env, cwd=root)
        source = root / "src/main.cpp"
        source.write_bytes(source.read_bytes() + b"\n#ifdef BYO_CONTEXT_CHANGED\n#error actual_database_change\n#endif\n")
        config = json.loads((root / "byo-analysis.json").read_text(encoding="utf-8"))
        write_json(root / "byo-analysis.json", {**config, "clangd": {"query_driver_paths": []}})
        with Mcp(lab.byo, root, lab.env, lab.version, logs=lab.root / "mcp") as server:
            status = checked(server.tool("get_code_analysis_status", {}), root)
            assert status["data"]["executable_origin"] == "managed_runtime", status
            control = server.tool("get_code_diagnostics", {"file_path": "src/main.cpp", "timeout_seconds": 60})
            assert control["status"] == "incomplete" and control["code"] == "analysis/compile-context-missing", control
            write_json(root / "byo-analysis.json", config)
            query = position(root, "src/main.cpp", 2, "choose")
            definition = checked(server.tool("find_code_definition", query), root, "src/main.cpp")
            assert locations(definition) & {("symbols.hpp", 2), ("symbols.cpp", 2)}, definition
            template = checked(server.tool("find_code_definition", position(root, "src/main.cpp", 2, "twice")), root)
            assert ("symbols.hpp", 4) in locations(template), template
            hover = checked(server.tool("get_code_hover", query), root)
            assert "choose" in json.dumps(hover["data"]), hover
            checked(server.tool("get_code_hover", position(root, "src/other.cpp", 2, "shared")), root)
            refs_args = {**position(root, "src/main.cpp", 2, "shared"), "include_declaration": True, "max_results": 100}
            deadline = time.monotonic() + 45
            while True:
                refs = checked(server.tool("find_code_references", refs_args), root)
                if {("main.cpp", 2), ("other.cpp", 2)} <= locations(refs):
                    break
                assert time.monotonic() < deadline, refs
                time.sleep(0.3)
            assert refs["index_completeness"] == "unverified", refs
            assert any(Path(p["path"]).name == "main.cpp" and p["range"]["start"] == {
                "line": 2, "column": refs_args["column"]} for p in refs["data"]["locations"]), refs

            def diagnose():
                value = checked(server.tool("get_code_diagnostics", {"file_path": "src/main.cpp", "timeout_seconds": 60}), root, "src/main.cpp")
                assert value["data"]["returned_count"] == len(value["data"]["diagnostics"]), value
                assert value["data"]["truncated"] is False, value
                return value

            clean = diagnose()
            assert clean["data"]["diagnostics"] == [], clean
            first = live_clangd(server, lab)
            assert any(a.startswith("--query-driver=") and str(compilers["gxx"]) in a for a in first.argv), first.argv
            original = source.read_bytes()
            try:
                source.write_bytes(original.replace(b"choose(2)", b"unknown_saved_symbol(2)"))
                bad = diagnose()
                assert any("unknown_saved_symbol" in d["message"] for d in bad["data"]["diagnostics"]), bad
            finally:
                source.write_bytes(original)
            restored = diagnose()
            assert restored["data"]["diagnostics"] == [], restored
            assert clean["source"]["document_version"] < bad["source"]["document_version"] < restored["source"]["document_version"]
            database = json.loads((root / "build/compile_commands.json").read_text(encoding="utf-8"))
            database[0]["arguments"].append("-DBYO_CONTEXT_CHANGED=1")
            invoke(database[0]["arguments"], env=lab.env, cwd=root, expected=1)
            write_json(root / "build/compile_commands.json", database)
            changed = diagnose()
            assert any("actual_database_change" in d["message"] for d in changed["data"]["diagnostics"]), changed
            second = live_clangd(server, lab)
            assert (second.pid, second.birth) != (first.pid, first.birth)
            assert not first.alive() and second.alive()
            peer = subprocess.Popen([second.image], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, env=lab.env, cwd=lab.root)
            try:
                server.close()
                assert peer.poll() is None, "natural server EOF affected the unrelated peer"
            finally:
                assert peer.stdin is not None
                peer.stdin.close()
                try:
                    peer.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    peer.kill(); peer.wait(timeout=5)


@pytest.mark.parametrize("owner", ["rust", "companion"])
def test_real_arm_build_clean_defect_restore_and_selected_scope(owner):
    compilers = arm_compilers()
    with installed_lab() as lab:
        root, commands = project(lab, "arm", ARM_FIXTURE, compilers)
        build_override(lab, root, commands)
        source = root / "src/main.c"
        original = source.read_bytes()
        before_database = digest(root / "build/compile_commands.json")
        try:
            for data, status, expected in ((original, "pass", 0),
                                           (original + DEFECT, "findings_failed", 13 if owner == "rust" else 1),
                                           (original, "pass", 0)):
                source.write_bytes(data)
                result = verify(lab, root, owner=owner, expected=expected)
                assert result["status"] == status, result
                if owner == "rust":
                    for relative, _, _ in ARM_UNITS:
                        obj = (root / "build" / (Path(relative).stem + ".o")).read_bytes()
                        assert obj[:6] == b"\x7fELF\x01\x01" and int.from_bytes(obj[18:20], "little") == 40
            # Source selection excludes the erroneous unselected unit; full
            # scope still detects it. Both independent verifiers own this rule.
            other = root / "src/heartbeat.cpp"
            saved = other.read_bytes()
            try:
                other.write_bytes(saved + DEFECT)
                result = verify(lab, root, "src/main.c", owner=owner)
                assert result["status"] == "pass", result
                result = verify(lab, root, owner=owner, expected=13 if owner == "rust" else 1)
                assert result["status"] == "findings_failed", result
            finally:
                other.write_bytes(saved)
        finally:
            source.write_bytes(original)
        assert digest(root / "build/compile_commands.json") == before_database


def test_failed_build_override_cannot_report_pass_with_clean_analysis():
    compilers = arm_compilers()
    with installed_lab() as lab:
        root, commands = project(lab, "failed build", ARM_FIXTURE, compilers)
        build_override(lab, root, commands)
        (root / "build/force-failure").touch()
        result = verify(lab, root, expected=13)
        assert result["status"] == "pass", "the clean analyzer control isolates the failed build"
        assert len((root / "build/override-invocations.log").read_text().splitlines()) == 1


@pytest.mark.parametrize("profile,bundle_variable", [
    ("personal", "BYO_INSTALLED_BUNDLE"),
    ("professional", "BYO_INSTALLED_PROFESSIONAL_BUNDLE"),
])
def test_compiled_profile_forwarding_passivity_and_private_records(profile, bundle_variable):
    compilers = arm_compilers()
    with installed_lab(bundle_variable) as lab:
        root, _ = project(lab, "private-installed-path", SEMANTIC, compilers, semantic=True)
        lab.env.update({"BYO_TEST_NOT_FORWARDED": "private-test-value",
                        "PYTHONPATH": str(lab.root / "poison"),
                        "LD_LIBRARY_PATH": str(lab.root / "poison")})
        if os.name == "nt":
            from platformdirs import user_data_dir
            monitor = Path(user_data_dir("BYO", appauthor=False, roaming=False))
        elif sys.platform == "darwin":
            monitor = Path(lab.env["HOME"]) / "Library/Application Support/BYO"
        else:
            monitor = Path(lab.env["HOME"]) / ".local/share/BYO"
        before_monitor = snapshot(monitor)
        before_project = protected_project(root)
        with Mcp(lab.byo, root, lab.env, lab.version, logs=lab.root / "profile-mcp") as server:
            health = server.tool("server_health_check", {})
            assert health["narrative_logging"] == ("enabled" if profile == "personal" else "not_built"), health
            names = {tool["name"] for tool in server.request("tools/list", {})["tools"]}
            assert ("submit_routine_checkin" in names) == (profile == "personal"), names
            server.tool("initialization_handshake", {"workspace_path": str(root)})
            checked(server.tool("get_code_hover", position(root, "src/main.cpp", 2, "choose")), root)
            payloads = [entry["path"] for entry in lab.manifest["files"]
                        if Path(entry["path"]).name in ("byo-mcp-sidecar", "byo-mcp-sidecar.exe")]
            assert len(payloads) == 1, payloads
            sidecars = [child for child in server.observe_children()
                        if Path(child.image).samefile(lab.runtime / payloads[0])]
            assert len(sidecars) == 1, [(c.pid, c.image) for c in sidecars]
            # This is our credential-free test child, never a client/provider.
            forwarded = sidecars[0].process.environ()
            for key in ("HOME", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA"):
                assert forwarded.get(key) == lab.env[key], (key, forwarded.get(key), lab.env[key])
            assert not {"BYO_TEST_NOT_FORWARDED", "PYTHONPATH", "LD_LIBRARY_PATH"} & forwarded.keys()
        assert protected_project(root) == before_project, "read-only installed MCP calls changed the project"
        changed = [p for p, sha in snapshot(monitor).items() if before_monitor.get(p) != sha]
        if profile == "personal":
            assert changed, "personal compiled monitor produced no persisted records"
        else:
            assert not changed, "professional build persisted narrative monitoring"
        for relative in changed:
            data = (monitor / relative).read_bytes()
            for sentinel in (str(root), root.name):
                assert sentinel.encode("utf-8") not in data, relative
                assert sentinel.encode("utf-16-le") not in data, relative


def test_analysis_remains_available_in_canonical_no_setup_lite_and_full_inputs():
    compilers = arm_compilers()
    inputs = json.loads((ROOT / "release/scripts/fixtures/code-analysis-installed/availability/manifest.json").read_text(encoding="utf-8"))
    with installed_lab() as lab:
        cases = [case for case in inputs["cases"] if case["profile"] == "personal"
                 and case["state"] in ("no_setup", "setup_lite", "setup_full")]
        assert {case["state"] for case in cases} == {"no_setup", "setup_lite", "setup_full"}
        for case in cases:
            root, _ = project(lab, case["state"], SEMANTIC, compilers, semantic=True)
            for relative, item in inputs["fixtures"][case["fixture"]].items():
                path = (root / relative).resolve()
                assert path.is_relative_to(root.resolve()) and relative.startswith(".firm/")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(base64.b64decode(item["base64"], validate=True))
            protected = snapshot(root / ".firm")
            with Mcp(lab.byo, root, lab.env, lab.version, logs=lab.root / ("tier-" + case["state"])) as server:
                capability = server.tool("get_capabilities", {"board_id": case["board_id"]})
                assert capability["tier"] == case["state"].replace("_", "-"), capability
                assert capability["board_id"] == case["board_id"], capability
                checked(server.tool("get_code_hover", position(root, "src/main.cpp", 2, "choose")), root)
            assert all((root / ".firm" / path).is_file() and digest(root / ".firm" / path) == sha for path, sha in protected.items()), "analysis mutated the passive board policy"


def test_genuine_distinct_version_activation_and_rollback_preserve_authored_state():
    supplied = os.environ.get("BYO_INSTALLED_OLD_BUNDLE")
    if not supplied:
        pytest.skip("UNRUN upgrade prerequisite: supply a genuine distinct-version BYO_INSTALLED_OLD_BUNDLE")
    old = Path(supplied).resolve(strict=True)
    old_version = json.loads((old / "release-manifest.json").read_text(encoding="utf-8"))["version"]
    with installed_lab() as lab:
        assert old_version != lab.version, "same-version reinstall is not upgrade proof"
        invoke([str(lab.byo), "install-runtime", "--bundle", str(old)], env=lab.env, timeout=300)
        root = lab.root / "upgrade project"
        root.mkdir()
        invoke([str(lab.byo), "init", "--project", str(root)], env=lab.env)
        authored = {".agent-workspace/PLAN.md": b"authored plan\n",
                    ".agent-workspace/HANDOFF.md": b"authored handoff\n",
                    ".firm/customer-state": b"preserve firmware state\n"}
        for relative, data in authored.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        for argv, version in ((["install-runtime", "--bundle", str(lab.bundle)], lab.version),
                              (["rollback", "--version", old_version], old_version)):
            invoke([str(lab.byo), *argv], env=lab.env, timeout=300)
            invoke([str(lab.byo), "workspace", "update", "--project", str(root)], env=lab.env)
            current = json.loads((lab.home / "data/current.json").read_text(encoding="utf-8"))
            assert current["version"] == version, current
            invoke([str(lab.byo), "doctor", "--project", str(root), "--json"], env=lab.env)
            for relative, data in authored.items():
                assert (root / relative).read_bytes() == data, relative

COMPANION_DRIVER = """import json, sys
from pathlib import Path
workspace, runtime, digest, project, target = sys.argv[1:6]
sys.path.insert(0, workspace)
from internal import code_analysis
module = Path(code_analysis.__file__).resolve()
if not module.is_relative_to(Path(workspace).resolve()):
    raise SystemExit(f"imported {module} outside the workspace source")
context = code_analysis.TrustedRuntimeContext(
    runtime_root=Path(runtime), runtime_manifest_sha256=digest, managed=True)
result = code_analysis.run_cppcheck(Path(project), target, runtime_context=context)
print(json.dumps({"module": str(module), "result": result}, ensure_ascii=True))
raise SystemExit({"pass": 0, "findings_failed": 1}.get(result["status"], 2))
"""


ARM_FIXTURE = {
    "src/main.c": '#include "firmware.h"\nvolatile uint32_t firmware_heartbeat;\nvoid firmware_main(void) {\n    for (;;) { firmware_heartbeat = advance_heartbeat(firmware_heartbeat); }\n}\n',
    "src/heartbeat.cpp": '#include "firmware.h"\ntemplate<typename T> T increment(T value) { return value + T(HEARTBEAT_STEP); }\nuint32_t advance_heartbeat(uint32_t current) { return increment(current); }\n',
    "src/startup.c": '#include "firmware.h"\nextern uint32_t _stack_top, _data_load, _data_start, _data_end, _bss_start, _bss_end;\nvoid reset_handler(void);\nvoid default_handler(void) { for (;;) {} }\n__attribute__((used,section(".isr_vector")))\nconst uintptr_t vectors[] = { (uintptr_t)&_stack_top, (uintptr_t)reset_handler,\n    (uintptr_t)default_handler, (uintptr_t)default_handler };\nvoid reset_handler(void) {\n    uintptr_t source = (uintptr_t)&_data_load;\n    for (uintptr_t dest = (uintptr_t)&_data_start; dest < (uintptr_t)&_data_end; dest += sizeof(uint32_t)) {\n        *(uint32_t*)dest = *(const uint32_t*)source; source += sizeof(uint32_t);\n    }\n    for (uintptr_t dest = (uintptr_t)&_bss_start; dest < (uintptr_t)&_bss_end; dest += sizeof(uint32_t)) { *(uint32_t*)dest = 0; }\n    firmware_main();\n}\n',
    "include/firmware.h": '#ifndef FIRMWARE_H\n#define FIRMWARE_H\n#include <stdint.h>\n#include "build_config.h"\n#ifdef __cplusplus\nextern "C" {\n#endif\nextern volatile uint32_t firmware_heartbeat;\nuint32_t advance_heartbeat(uint32_t current);\nvoid firmware_main(void);\n#ifdef __cplusplus\n}\nstatic_assert(sizeof(void*) == 4 && sizeof(long) == 4, "ARM ILP32 ABI required");\n#else\n_Static_assert(sizeof(void*) == 4 && sizeof(long) == 4, "ARM ILP32 ABI required");\n#endif\n#endif\n',
    "config/arm32.xml": '<?xml version="1.0"?>\n<platform>\n  <char_bit>8</char_bit>\n  <default-sign>unsigned</default-sign>\n  <sizeof>\n    <bool>1</bool>\n    <short>2</short>\n    <int>4</int>\n    <long>4</long>\n    <long-long>8</long-long>\n    <float>4</float>\n    <double>8</double>\n    <long-double>8</long-double>\n    <pointer>4</pointer>\n    <size_t>4</size_t>\n    <wchar_t>4</wchar_t>\n  </sizeof>\n</platform>\n',
    "build/generated/build_config.h": "#define HEARTBEAT_STEP 3u\n",
}


ARM_FLAGS = [
    "-mcpu=cortex-m4",
    "-mthumb",
    "-mfloat-abi=soft",
    "-ffreestanding",
    "-fdata-sections",
    "-ffunction-sections",
    "-g",
    "-O1",
    "-DBYO_TARGET_ARM=1",
]


ARM_UNITS = (
    ("src/main.c", "gcc", ["-std=c11"]),
    ("src/heartbeat.cpp", "gxx", ["-std=c++17", "-fno-exceptions", "-fno-rtti"]),
    ("src/startup.c", "gcc", ["-std=c11"]),
)


DEFECT = b"\nint installed_defect(void) { int *p = 0; return *p; }\n"


SEMANTIC = {
    "include/symbols.hpp": '#pragma once\nint choose(int value);\ndouble choose(double value);\ntemplate<class T> T twice(T value) { return value + value; }\nextern int shared;\n#include <newlib.h>\nstatic_assert(sizeof(void *) == 4 && sizeof(_NEWLIB_VERSION) > 1, "ARM32 newlib target");\n',
    "src/symbols.cpp": '#include "symbols.hpp"\nint choose(int value) { return value + 1; }\ndouble choose(double value) { return value + 0.5; }\nint shared = 7;\n',
    "src/main.cpp": '#include "symbols.hpp"\n/* \U0001f600 µ */ int use_int() { return choose(2) + twice(3) + shared; }\ndouble use_double() { return choose(2.0); }\n',
    "src/other.cpp": '#include "symbols.hpp"\nint use_other() { return shared; }\n',
}


USER_FILES = {
    ".clangd": "# User-owned clangd settings; preserve exactly.\n",
    ".clang-format": "BasedOnStyle: LLVM\n",
    "customer.txt": "unrelated user file µ\n",
}


WINDOWS_OVERRIDE_RS = r"""//! Smoke build override: runs the real ARM compiler argv listed in
//! build/override-commands.txt (fields separated by U+001F). No analyzer here.
use std::{env, fs, io::Write, process::Command};
fn main() {
    let target = env::args().nth(1).expect("verify target argv");
    let spec = fs::read_to_string("build/override-commands.txt").expect("commands");
    let mut log = fs::OpenOptions::new().create(true).append(true)
        .open("build/override-invocations.log").expect("log");
    writeln!(log, "{target}").expect("log write");
    if std::path::Path::new("build/force-failure").exists() { std::process::exit(17); }
    fs::create_dir_all("build/generated").expect("generated directory");
    fs::write("build/generated/build_config.h", "#define HEARTBEAT_STEP 3u\n").expect("generated header");
    for line in spec.lines().filter(|l| !l.is_empty()) {
        let argv: Vec<&str> = line.split('\u{1f}').collect();
        let status = Command::new(argv[0]).args(&argv[1..]).status().expect("spawn compiler");
        if !status.success() { std::process::exit(status.code().unwrap_or(1)); }
    }
}
"""


def parse_include_search(stderr: str) -> list[str]:
    """Extract the compiler's own `#include <...>` search list from -v output."""
    lines, active, found = stderr.splitlines(), False, []
    for line in lines:
        if line.startswith("#include <...> search starts here"):
            active = True
            continue
        if line.startswith("End of search list"):
            break
        if active and line.startswith(" "):
            path = line.strip()
            if path.endswith("(framework directory)"):
                continue
            found.append(os.path.normpath(path))
    return found


def posix_override_script(commands: list[list[str]]) -> str:
    """A /bin/sh override executing explicit argv; every field shell-quoted."""
    lines = [
        "#!/bin/sh",
        "# Smoke build override: real ARM compiler argv only; no analyzer here.",
        "set -eu",
        'printf "%s\\n" "${1:-}" >> build/override-invocations.log',
    ]
    lines += ["test ! -f build/force-failure || exit 17", "mkdir -p build/generated",
              "printf '%s\\n' '#define HEARTBEAT_STEP 3u' > build/generated/build_config.h"]
    lines += [" ".join(shlex.quote(a) for a in argv) for argv in commands]
    return "\n".join(lines) + "\n"


def windows_override_commands(commands: list[list[str]]) -> str:
    for argv in commands:
        for field in argv:
            if "\x1f" in field or "\n" in field or "\r" in field:
                raise ValueError(f"override argv field cannot be encoded: {field!r}")
    return "".join("\x1f".join(argv) + "\n" for argv in commands)



def test_signed_clean_candidate():
    """The signed-release VM owns signature, exact archive and installed lifecycle proof."""
    from installed_support import extract_exact, sha256, verify_platform, installed_directory

    supplied = os.environ.get("BYO_SIGNED_CANDIDATE")
    if not supplied:
        pytest.skip("UNRUN signed-release prerequisite: supply BYO_SIGNED_CANDIDATE")
    candidate = Path(supplied).resolve(strict=True)
    archives = [p for p in candidate.rglob("byo-*")
                if p.is_file() and (p.suffix == ".zip" or p.name.endswith(".tar.gz"))]
    assert len(archives) == 1, archives
    archive = archives[0]
    stem = archive.name.removesuffix(".zip").removesuffix(".tar.gz")
    checksums = list(candidate.rglob(stem + ".sha256"))
    assert len(checksums) == 1, checksums
    assert checksums[0].read_text(encoding="utf-8").split()[0] == sha256(archive)
    with installed_directory(prefix="byo-clean-release-") as root:
        bundle = extract_exact(archive, root)
        key = os.environ.get("BYO_RELEASE_PUBLIC_KEY")
        evidence = verify_platform(bundle, archive, Path(key) if key else None)
        (root / "signature.txt").write_text("\n".join(evidence), encoding="utf-8")
        invoke([sys.executable, str(ROOT / "release/scripts/test_installed_e2e.py"),
                "--bundle", str(bundle)], env=dict(os.environ), timeout=900)
