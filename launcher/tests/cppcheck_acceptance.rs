//! Independent Windows x86_64 acceptance tests for the packaged Cppcheck static
//! step of `byo workflow tool verify`.
//!
//! Default tests drive the real `byo` binary against a private sealed development
//! runtime whose `analysis/cppcheck/cppcheck.exe` is the scripted AMD64 fake from
//! `fixtures/cppcheck-acceptance/fake_tool.rs`. A decoy `cppcheck.exe` on PATH
//! records any forbidden PATH resolution, and every fake invocation leaves an
//! identity record (pid plus creation time) used to prove owned-process cleanup.
//!
//! The `#[ignore]` tests use the recorded pinned Cppcheck 2.22.0 candidate, its
//! accepted data/notice inputs and the built ARM firmware fixture. They read
//! `BYO_CPPCHECK_PACKAGING_INPUTS`, `BYO_CPPCHECK_SOURCE_DIR` and
//! `BYO_ARM_FIXTURE_DIR` and never modify those inputs.
#![cfg(all(windows, target_arch = "x86_64"))]

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{mpsc, OnceLock};
use std::time::{Duration, Instant};

use flate2::write::ZlibEncoder;
use flate2::Compression;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sysinfo::{ProcessesToUpdate, System};
use walkdir::WalkDir;
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessTimes, OpenProcess, TerminateProcess,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
};

const BYO: &str = env!("CARGO_BIN_EXE_byo");
const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");
const RUNTIME_VERSION: &str = "0.1.8";
const PINNED_VERSION: &str = "2.22.0";
const WORKFLOW_POLICY_EXIT: i32 = 13;
const ENABLE: &str = "--enable=warning,performance,portability,information,missingInclude";
const ENABLE_STYLE: &str =
    "--enable=warning,performance,portability,information,missingInclude,style";
const RUNTIME_EXECUTABLE: &str = "analysis/cppcheck/cppcheck.exe";
const REPORTS: &str = ".firm/code-analysis/reports";
const PROJECT_NAME: &str = "work space café";
const DEFAULT_PLATFORM: &str = "config/platform.xml";
const BYO_GUARD: Duration = Duration::from_secs(180);
const STILL_ACTIVE: u32 = 259;

// Evidence names written by the accepted Python runner; the Rust runner must
// keep parity so both runners' report directories are comparable.
const RESULT_FILE: &str = "result.json";
const ARGV_FILE: &str = "argv.json";
const REPORT_XML: &str = "report.xml";
const ANALYSIS_STDOUT: &str = "analysis.stdout.log";
const ANALYSIS_STDERR: &str = "analysis.stderr.log";
const VERSION_STDOUT: &str = "version.stdout.log";
const INPUTS_SHA256: &str = "e8f71939bafaba468ac299a3995e30ddf05c82365176a2f7c82365f55b57b4d3";

// ---------------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------------

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

fn sha256_file(path: &Path) -> String {
    sha256_bytes(&read(path))
}

fn write(path: &Path, bytes: impl AsRef<[u8]>) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", parent.display()));
    }
    fs::write(path, bytes)
        .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
}

fn write_json(path: &Path, value: &Value) {
    write(path, serde_json::to_vec_pretty(value).unwrap());
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&read(path))
        .unwrap_or_else(|error| panic!("invalid JSON in {}: {error}", path.display()))
}

fn copy_file(from: &Path, to: &Path) {
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::copy(from, to).unwrap_or_else(|error| {
        panic!(
            "cannot copy {} to {}: {error}",
            from.display(),
            to.display()
        )
    });
}

fn copy_tree(from: &Path, to: &Path) {
    for entry in WalkDir::new(from).follow_links(false) {
        let entry = entry.unwrap();
        let relative = entry.path().strip_prefix(from).unwrap();
        let target = to.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target).unwrap();
        } else {
            copy_file(entry.path(), &target);
        }
    }
}

fn tree_hashes(root: &Path) -> Vec<(String, String)> {
    let mut hashes = Vec::new();
    for entry in WalkDir::new(root).follow_links(false).sort_by_file_name() {
        let entry = entry.unwrap();
        if entry.file_type().is_file() {
            let relative = entry.path().strip_prefix(root).unwrap();
            hashes.push((relative.display().to_string(), sha256_file(entry.path())));
        }
    }
    hashes
}

/// Strip a local `\\?\` verbatim prefix so paths stay comparable and usable.
fn plain(path: PathBuf) -> PathBuf {
    let text = path.display().to_string();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => path,
    }
}

/// Windows path identity for assertions: no verbatim prefix, one separator
/// spelling, case-insensitive.
fn norm(text: &str) -> String {
    let text = text.strip_prefix(r"\\?\").unwrap_or(text);
    text.replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}

fn norm_path(path: &Path) -> String {
    norm(&path.display().to_string())
}

fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn parity_dir() -> PathBuf {
    Path::new(MANIFEST_DIR).join("tests/fixtures/code-analysis")
}

fn parity(name: &str) -> PathBuf {
    parity_dir().join(name)
}

fn acceptance_dir() -> PathBuf {
    Path::new(MANIFEST_DIR).join("tests/fixtures/cppcheck-acceptance")
}

fn expected() -> &'static Value {
    static EXPECTED: OnceLock<Value> = OnceLock::new();
    EXPECTED.get_or_init(|| read_json(&parity("expected.json")))
}

fn xml_ids(xml: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(xml);
    text.split("<error id=\"")
        .skip(1)
        .map(|rest| rest.split('"').next().unwrap_or_default().to_string())
        .collect()
}

fn rustc() -> PathBuf {
    if let Some(rustc) = std::env::var_os("RUSTC") {
        return PathBuf::from(rustc);
    }
    let cargo = std::env::var_os("CARGO")
        .map(PathBuf::from)
        .or_else(|| option_env!("CARGO").map(PathBuf::from));
    if let Some(sibling) = cargo.and_then(|cargo| cargo.parent().map(|dir| dir.join("rustc.exe"))) {
        if sibling.is_file() {
            return sibling;
        }
    }
    PathBuf::from("rustc")
}

/// Compile the scripted fake once per test binary into Cargo's test temp dir.
fn fake_exe() -> &'static Path {
    static FAKE: OnceLock<PathBuf> = OnceLock::new();
    FAKE.get_or_init(|| {
        let source = acceptance_dir().join("fake_tool.rs");
        let digest = sha256_file(&source);
        let directory = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cppcheck-acceptance-fake");
        fs::create_dir_all(&directory).unwrap();
        let target = directory.join(format!("fake-{}.exe", &digest[..16]));
        if !target.is_file() {
            let temporary =
                directory.join(format!("fake-{}-{}.exe", &digest[..16], std::process::id()));
            let output = Command::new(rustc())
                .args(["--edition", "2021", "-C", "opt-level=1"])
                .args(["-C", "target-feature=+crt-static", "-o"])
                .arg(&temporary)
                .arg(&source)
                .output()
                .expect("rustc must be available to build the scripted fake analyzer");
            assert!(
                output.status.success(),
                "fake analyzer compilation failed:\n{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            if fs::rename(&temporary, &target).is_err() {
                let _ = fs::remove_file(&temporary);
            }
        }
        assert!(target.is_file(), "fake analyzer was not produced");
        target
    })
}

// ---------------------------------------------------------------------------
// Process identity (pid plus creation time) for owned-process assertions
// ---------------------------------------------------------------------------

fn filetime(value: FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

fn process_creation(pid: u32) -> Option<u64> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        let ok = GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user);
        CloseHandle(handle);
        (ok != 0).then(|| filetime(created))
    }
}

/// Open a process only if it is still the recorded incarnation.
fn open_identified(pid: u32, creation: u64, access: u32) -> Option<HANDLE> {
    unsafe {
        let handle = OpenProcess(access | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        let ok = GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user);
        if ok == 0 || filetime(created) != creation {
            CloseHandle(handle);
            return None;
        }
        Some(handle)
    }
}

fn process_alive(pid: u32, creation: u64) -> bool {
    let Some(handle) = open_identified(pid, creation, 0) else {
        return false;
    };
    unsafe {
        let mut code = 0u32;
        let ok = GetExitCodeProcess(handle, &mut code);
        CloseHandle(handle);
        ok != 0 && code == STILL_ACTIVE
    }
}

fn kill_identified(pid: u32, creation: u64) {
    if let Some(handle) = open_identified(pid, creation, PROCESS_TERMINATE) {
        unsafe {
            TerminateProcess(handle, 1);
            CloseHandle(handle);
        }
    }
}

fn identity(record: &Value) -> Option<(u32, u64)> {
    Some((
        u32::try_from(record["pid"].as_u64()?).ok()?,
        record["creation"].as_u64()?,
    ))
}

fn read_records(directory: &Path) -> Vec<Value> {
    let mut records: Vec<Value> = fs::read_dir(directory)
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
                .map(|entry| read_json(&entry.path()))
                .collect()
        })
        .unwrap_or_default();
    records.sort_by_key(|record| record["nanos"].as_u64().unwrap_or(0));
    records
}

// ---------------------------------------------------------------------------
// Workspace pack and sealed development runtime
// ---------------------------------------------------------------------------

fn workspace_pack() -> Vec<u8> {
    let catalog = json!({
        "schema": 2,
        "workflow_protocol": 1,
        "modes": [{
            "name": "firmware",
            "family": "firmware",
            "extends": [],
            "full_access": false,
            "skills": [],
            "instruction_resources": [],
            "verify": {"backend": "firmware", "required_tools": []},
            "codex": {
                "permission_profile": "workspace-access",
                "sandbox_mode": null,
                "approval_policy": "on-request",
                "web_search": "cached"
            },
            "workflow": {"one_way_doors": [], "adversarial_triggers": []},
            "structure": {
                "version": 1,
                "default_visibility": "shared",
                "required_dirs": [],
                "required_files": [],
                "forbidden_paths": []
            }
        }],
        "skills": {},
        "agents": {}
    });
    let resources = [
        (
            "compiled/workflow.json",
            "compiled",
            serde_json::to_vec(&catalog).unwrap(),
        ),
        (
            "templates/PLAN.template.md",
            "template",
            b"# Plan\n".to_vec(),
        ),
        (
            "templates/HANDOFF.template.md",
            "template",
            b"# Handoff\n".to_vec(),
        ),
    ];
    let mut body = Vec::new();
    let mut index = Vec::new();
    for (id, class, bytes) in resources {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&bytes).unwrap();
        let compressed = encoder.finish().unwrap();
        index.push(json!({
            "id": id,
            "class": class,
            "sha256": sha256_bytes(&bytes),
            "offset": body.len(),
            "compressed_size": compressed.len(),
            "original_size": bytes.len()
        }));
        body.extend(compressed);
    }
    let header = serde_json::to_vec(&json!({
        "schema": 1,
        "product": "byo",
        "workspace_version": RUNTIME_VERSION,
        "workflow_protocol": 1,
        "compression": "zlib",
        "resources": index
    }))
    .unwrap();
    let mut pack = b"BYOWPK1\n".to_vec();
    pack.extend((header.len() as u64).to_be_bytes());
    pack.extend(header);
    pack.extend(body);
    pack
}

fn payload_kind(path: &str) -> (&'static str, bool) {
    match path {
        "analysis/runtime.json" | "sbom.cdx.json" => ("metadata", false),
        "analysis/cppcheck/cppcheck.exe" | "analysis/clangd/bin/clangd.exe" => {
            ("analysis-executable", true)
        }
        "workflow/workspace.pack" => ("workflow-pack", false),
        "analysis/clangd/LICENSE.TXT" => ("license", false),
        other if other.starts_with("analysis/cppcheck/licenses/") => ("license", false),
        other if other.starts_with("analysis/clangd/lib/clang/") => ("analysis-resource", false),
        other if other.ends_with(".dll") => ("analysis-dependency", false),
        _ => ("analysis-data", false),
    }
}

fn runtime_leaves(root: &Path) -> Vec<String> {
    let mut leaves = Vec::new();
    for entry in WalkDir::new(root).follow_links(false).sort_by_file_name() {
        let entry = entry.unwrap();
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if relative != "release-manifest.json" && relative != "release-manifest.sig" {
            leaves.push(relative);
        }
    }
    leaves
}

fn file_ref(path: &str) -> String {
    format!("byo-analysis-file:{path}")
}

fn build_sbom(root: &Path, leaves: &[String]) -> Value {
    let mapping: Value = fs::read(root.join("analysis/runtime.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null);
    let mut components = Vec::new();
    let mut dependencies = Vec::new();
    for (program, prefix, license) in [
        ("cppcheck", "analysis/cppcheck/", "GPL-3.0-or-later"),
        (
            "clangd",
            "analysis/clangd/",
            "Apache-2.0 WITH LLVM-exception",
        ),
    ] {
        let version = mapping
            .pointer(&format!("/programs/{program}/version"))
            .and_then(Value::as_str)
            .unwrap_or(if program == "cppcheck" {
                PINNED_VERSION
            } else {
                "23.1.0"
            });
        components.push(json!({
            "type": "application",
            "bom-ref": format!("byo-analysis:{program}"),
            "name": program,
            "version": version,
            "licenses": [{"expression": license}],
            "properties": [
                {"name": "byo:analysis:upstream", "value": format!("acceptance fixture upstream for {program}")},
                {"name": "byo:analysis:recipe", "value": format!("acceptance fixture recipe for {program}")}
            ]
        }));
        let mut links = Vec::new();
        for leaf in leaves.iter().filter(|leaf| leaf.starts_with(prefix)) {
            components.push(json!({
                "type": "file",
                "bom-ref": file_ref(leaf),
                "name": leaf,
                "hashes": [{"alg": "SHA-256", "content": sha256_file(&root.join(leaf))}]
            }));
            links.push(file_ref(leaf));
        }
        dependencies.push(json!({"ref": format!("byo-analysis:{program}"), "dependsOn": links}));
    }
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components,
        "dependencies": dependencies
    })
}

fn release_manifest(root: &Path) -> Value {
    let files: Vec<Value> = runtime_leaves(root)
        .iter()
        .map(|leaf| {
            let bytes = read(&root.join(leaf));
            let (kind, executable) = payload_kind(leaf);
            json!({
                "path": leaf,
                "sha256": sha256_bytes(&bytes),
                "size": bytes.len(),
                "kind": kind,
                "executable": executable
            })
        })
        .collect();
    let revision = json!({"repository": "cppcheck-acceptance", "commit": "0".repeat(40)});
    json!({
        "schema": 1,
        "product": "byo",
        "version": RUNTIME_VERSION,
        "channel": "development",
        "platform": "windows",
        "architecture": "x86_64",
        "launcher_protocol": 1,
        "sidecar_protocol": 1,
        "worker_protocol": 1,
        "workflow_protocol": 1,
        "capsule_schema": 1,
        "project_state_schema": 1,
        "development_unsigned": true,
        "source": {
            "installer": revision.clone(),
            "agent_workspace": revision.clone(),
            "firmware_mcp": revision
        },
        "toolchain": {"rustc": "test", "cargo": "test", "python": "test", "nuitka": "test"},
        "files": files
    })
}

/// Accepted pinned-program inputs for the `#[ignore]` real-program tests.
struct RealInputs {
    executable: PathBuf,
    executable_sha256: String,
    data: Vec<(PathBuf, String)>,
}

fn required_env(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| {
        panic!("real-program acceptance requires {name}; see the module documentation")
    }))
}

fn real_inputs() -> RealInputs {
    let manifest = required_env("BYO_CPPCHECK_PACKAGING_INPUTS");
    assert_eq!(
        sha256_file(&manifest),
        INPUTS_SHA256,
        "development input manifest changed"
    );
    let inputs = read_json(&manifest);
    let source = required_env("BYO_CPPCHECK_SOURCE_DIR");
    let candidate = &inputs["program_candidate"];
    let executable = PathBuf::from(candidate["path"].as_str().unwrap());
    let executable_sha256 = candidate["sha256"].as_str().unwrap().to_string();
    let bytes = read(&executable);
    assert_eq!(
        sha256_bytes(&bytes),
        executable_sha256,
        "pinned candidate hash changed"
    );
    assert_eq!(bytes.len() as u64, candidate["size"].as_u64().unwrap());
    let mut data = Vec::new();
    for item in inputs["data_and_licenses"].as_array().unwrap() {
        let upstream = source.join(item["upstream_relative_path"].as_str().unwrap());
        let bytes = read(&upstream);
        assert_eq!(
            sha256_bytes(&bytes),
            item["sha256"].as_str().unwrap(),
            "accepted data input changed: {}",
            upstream.display()
        );
        assert_eq!(bytes.len() as u64, item["size"].as_u64().unwrap());
        data.push((upstream, item["runtime_path"].as_str().unwrap().to_string()));
    }
    assert_eq!(
        data.len(),
        70,
        "accepted inputs list 51 cfg, 15 platforms and 4 notices"
    );
    RealInputs {
        executable,
        executable_sha256,
        data,
    }
}

enum Analyzer<'a> {
    Fake,
    Real(&'a RealInputs),
}

// ---------------------------------------------------------------------------
// Private lab: product root, runtime, project, PATH decoy and fake control
// ---------------------------------------------------------------------------

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    elapsed: Duration,
}

struct Verify {
    run: Run,
    records: Vec<Value>,
    report: Option<PathBuf>,
    result: Option<Value>,
}

impl Verify {
    fn context(&self) -> String {
        let clip = |text: &str| {
            if text.len() > 6000 {
                format!("{}...[clipped]", &text[..text.floor_char_boundary(6000)])
            } else {
                text.to_string()
            }
        };
        format!(
            "byo exit {:?} after {:?}\nphases {:?}\nreport {:?}\n--- stdout\n{}\n--- stderr\n{}\n--- result\n{}",
            self.run.code,
            self.run.elapsed,
            self.phases(),
            self.report,
            clip(&self.run.stdout),
            clip(&self.run.stderr),
            self.result
                .as_ref()
                .map(|result| serde_json::to_string_pretty(result).unwrap())
                .unwrap_or_else(|| "<no result.json>".to_string())
        )
    }

    fn result(&self) -> &Value {
        self.result.as_ref().unwrap_or_else(|| {
            panic!(
                "no static-step {REPORTS}/<run>/{RESULT_FILE} was written\n{}",
                self.context()
            )
        })
    }

    fn report(&self) -> &Path {
        self.result();
        self.report.as_deref().unwrap()
    }

    fn status(&self) -> &str {
        self.result()["status"]
            .as_str()
            .unwrap_or_else(|| panic!("result.status missing\n{}", self.context()))
    }

    fn code(&self) -> Option<&str> {
        self.result()["code"].as_str()
    }

    fn phases(&self) -> Vec<String> {
        self.records
            .iter()
            .map(|record| record["phase"].as_str().unwrap_or("?").to_string())
            .collect()
    }

    fn records(&self, phase: &str) -> Vec<&Value> {
        self.records
            .iter()
            .filter(|record| record["phase"] == phase)
            .collect()
    }

    fn analysis(&self) -> &Value {
        let analyses = self.records("analysis");
        assert_eq!(
            analyses.len(),
            1,
            "expected one analysis\n{}",
            self.context()
        );
        analyses[0]
    }

    fn argv(&self) -> Vec<String> {
        serde_json::from_value(self.result()["argv"].clone())
            .unwrap_or_else(|_| panic!("result.argv must be a string array\n{}", self.context()))
    }

    fn output(&self) -> String {
        format!("{}\n{}", self.run.stdout, self.run.stderr)
    }

    fn expect_pass(&self) {
        assert_eq!(
            self.run.code,
            Some(0),
            "verify must pass\n{}",
            self.context()
        );
        assert!(
            self.run.stdout.contains("VERIFY: PASS"),
            "{}",
            self.context()
        );
        assert_eq!(self.status(), "pass", "{}", self.context());
    }

    fn expect_fail(&self) {
        assert_eq!(
            self.run.code,
            Some(WORKFLOW_POLICY_EXIT),
            "verify must fail with the workflow-policy exit\n{}",
            self.context()
        );
        assert!(
            self.run.stdout.contains("VERIFY: FAIL"),
            "{}",
            self.context()
        );
        assert!(
            !self.run.stdout.contains("VERIFY: PASS"),
            "{}",
            self.context()
        );
    }

    fn expect_outcome(&self, status: &str, code: &str) {
        self.expect_fail();
        assert_eq!(self.status(), status, "{}", self.context());
        assert_eq!(self.code(), Some(code), "{}", self.context());
        for field in ["message", "remedy"] {
            assert!(
                self.result()[field]
                    .as_str()
                    .is_some_and(|text| !text.trim().is_empty()),
                "non-pass result needs {field}\n{}",
                self.context()
            );
        }
    }

    /// Exactly one owned version probe and one analysis, never a PATH program.
    fn expect_static_once(&self) {
        assert!(
            self.records("decoy").is_empty(),
            "PATH cppcheck ran\n{}",
            self.context()
        );
        assert_eq!(self.records("version").len(), 1, "{}", self.context());
        assert_eq!(self.records("analysis").len(), 1, "{}", self.context());
    }

    /// Rejected before any analyzer process was spawned.
    fn expect_not_executed(&self) {
        for phase in ["decoy", "version", "analysis"] {
            assert!(
                self.records(phase).is_empty(),
                "{phase} process must not run\n{}",
                self.context()
            );
        }
        if let Some(result) = &self.result {
            assert_eq!(
                result["argv"],
                json!([]),
                "unspawned argv\n{}",
                self.context()
            );
            assert!(result["process_exit_code"].is_null(), "{}", self.context());
        }
    }

    fn expect_not_analyzed(&self) {
        for phase in ["decoy", "analysis"] {
            assert!(
                self.records(phase).is_empty(),
                "{phase} process must not run\n{}",
                self.context()
            );
        }
    }
}

struct Lab {
    root: PathBuf,
    home: PathBuf,
    user: PathBuf,
    runtime: PathBuf,
    project: PathBuf,
    peers: Vec<Child>,
    real_analyzer: bool,
}

static LAB_COUNTER: AtomicU32 = AtomicU32::new(0);

impl Lab {
    fn new(name: &str) -> Self {
        Self::create(name, PROJECT_NAME, Analyzer::Fake, |project| {
            copy_tree(&parity("project"), project)
        })
    }

    fn create(
        name: &str,
        project_name: &str,
        analyzer: Analyzer<'_>,
        populate: impl FnOnce(&Path),
    ) -> Self {
        let base = std::env::var_os("BYO_CPPCHECK_ACCEPTANCE_LABS")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("byo-cppcheck-acceptance"));
        fs::create_dir_all(&base).unwrap();
        let root = base.join(format!(
            "{name}-{}-{}",
            std::process::id(),
            LAB_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        fs::create_dir_all(&root).unwrap();
        let root = plain(root.canonicalize().unwrap());
        let home = root.join("home");
        let user = root.join("user");
        let runtime = home.join("data/versions").join(RUNTIME_VERSION);
        let project = root.join(project_name);
        for directory in [
            root.join("fake-control/records"),
            root.join("tools"),
            root.join("path-decoy"),
            user.join("AppData/Local"),
            user.join("AppData/Roaming"),
            runtime.clone(),
            project.clone(),
        ] {
            fs::create_dir_all(directory).unwrap();
        }
        let fake = fake_exe();
        copy_file(fake, &root.join("tools/make.exe"));
        copy_file(fake, &root.join("path-decoy/cppcheck.exe"));

        write(&runtime.join("workflow/workspace.pack"), workspace_pack());
        copy_file(
            &parity("runtime-mapping.json"),
            &runtime.join("analysis/runtime.json"),
        );
        let cppcheck = runtime.join("analysis/cppcheck");
        let real_analyzer = matches!(&analyzer, Analyzer::Real(_));
        match analyzer {
            Analyzer::Fake => {
                copy_file(fake, &cppcheck.join("cppcheck.exe"));
                let model = "<?xml version=\"1.0\"?>\n<def format=\"2\"/>\n";
                write(&cppcheck.join("cfg/std.cfg"), model);
                write(&cppcheck.join("cfg/avr.cfg"), model);
                copy_file(
                    &parity("project/config/platform.xml"),
                    &cppcheck.join("platforms/arm32-wchar_t2.xml"),
                );
                for notice in [
                    "COPYING",
                    "simplecpp-LICENSE",
                    "tinyxml2-LICENSE",
                    "picojson-LICENSE",
                ] {
                    write(
                        &cppcheck.join("licenses").join(notice),
                        format!("{notice} acceptance notice\n"),
                    );
                }
            }
            Analyzer::Real(inputs) => {
                copy_file(&inputs.executable, &cppcheck.join("cppcheck.exe"));
                for (upstream, runtime_path) in &inputs.data {
                    copy_file(upstream, &runtime.join(runtime_path));
                }
            }
        }
        let clangd = runtime.join("analysis/clangd");
        copy_file(fake, &clangd.join("bin/clangd.exe"));
        write(
            &clangd.join("lib/clang/23/include/stddef.h"),
            "/* acceptance stub */\n",
        );
        write(&clangd.join("LICENSE.TXT"), "clangd acceptance notice\n");

        populate(&project);
        if !project.join("Makefile").is_file() {
            write(
                &project.join("Makefile"),
                "all:\n\t@echo scripted by tools/make.exe\n",
            );
        }
        let lab = Self {
            root,
            home,
            user,
            runtime,
            project,
            peers: Vec::new(),
            real_analyzer,
        };
        lab.seal();
        lab.control(&[]);
        let init = lab.byo(&[
            "init".into(),
            "--project".into(),
            lab.project.clone().into_os_string(),
            "--mode".into(),
            "firmware".into(),
        ]);
        assert_eq!(
            init.code,
            Some(0),
            "byo init failed\n{}\n{}",
            init.stdout,
            init.stderr
        );
        lab
    }

    fn runtime_exe(&self) -> PathBuf {
        self.runtime.join(RUNTIME_EXECUTABLE)
    }

    fn mapping(&self) -> Value {
        read_json(&self.runtime.join("analysis/runtime.json"))
    }

    fn set_mapping(&self, mapping: &Value) {
        write_json(&self.runtime.join("analysis/runtime.json"), mapping);
    }

    fn seal(&self) {
        self.seal_with(|_| {}, |_| {});
    }

    /// Regenerate SBOM, inventory and current.json so the launcher's existing
    /// integrity checks accept the runtime and only analysis validation decides.
    fn seal_with(
        &self,
        sbom_edit: impl FnOnce(&mut Value),
        manifest_edit: impl FnOnce(&mut Value),
    ) {
        let _ = fs::remove_file(self.runtime.join("sbom.cdx.json"));
        let _ = fs::remove_file(self.runtime.join("release-manifest.json"));
        let leaves = runtime_leaves(&self.runtime);
        let mut sbom = build_sbom(&self.runtime, &leaves);
        sbom_edit(&mut sbom);
        write_json(&self.runtime.join("sbom.cdx.json"), &sbom);
        let mut manifest = release_manifest(&self.runtime);
        manifest_edit(&mut manifest);
        let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        write(&self.runtime.join("release-manifest.json"), &bytes);
        write_json(
            &self.home.join("data/current.json"),
            &json!({
                "schema": 1,
                "version": RUNTIME_VERSION,
                "relative_runtime": format!("versions/{RUNTIME_VERSION}"),
                "manifest_sha256": sha256_bytes(&bytes)
            }),
        );
    }

    fn control(&self, settings: &[(&str, &str)]) {
        let mut text = format!(
            "analysis.xml={}\nanalysis.exit=0\n",
            parity("clean.xml").display()
        );
        for (key, value) in settings {
            text.push_str(&format!("{key}={value}\n"));
        }
        write(&self.root.join("fake-control/control.txt"), text);
    }

    fn config(&self, value: &Value) {
        write_json(&self.project.join("byo-analysis.json"), value);
    }

    fn config_raw(&self, text: &str) {
        write(&self.project.join("byo-analysis.json"), text);
    }

    fn command(&self) -> Command {
        let mut command = Command::new(BYO);
        command.env_clear();
        for key in [
            "SystemRoot",
            "SYSTEMDRIVE",
            "windir",
            "TEMP",
            "TMP",
            "PATHEXT",
        ] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        let system_root =
            PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()));
        let path = std::env::join_paths([
            self.root.join("tools"),
            self.root.join("path-decoy"),
            system_root.join("System32"),
        ])
        .unwrap();
        command
            .env("PATH", path)
            .env("BYO_HOME", &self.home)
            .env("HOME", &self.user)
            .env("USERPROFILE", &self.user)
            .env("LOCALAPPDATA", self.user.join("AppData/Local"))
            .env("APPDATA", self.user.join("AppData/Roaming"))
            .current_dir(&self.root);
        command
    }

    fn byo(&self, arguments: &[OsString]) -> Run {
        let started = Instant::now();
        let mut child = self
            .command()
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn byo");
        let (sender, receiver) = mpsc::channel();
        for (stream, mut pipe) in [
            (
                0,
                Box::new(child.stdout.take().unwrap()) as Box<dyn Read + Send>,
            ),
            (
                1,
                Box::new(child.stderr.take().unwrap()) as Box<dyn Read + Send>,
            ),
        ] {
            let sender = sender.clone();
            std::thread::spawn(move || {
                let mut bytes = Vec::new();
                let _ = pipe.read_to_end(&mut bytes);
                let _ = sender.send((stream, bytes));
            });
        }
        let mut system = System::new();
        let mut observed = BTreeSet::new();
        let status = loop {
            if self.real_analyzer {
                system.refresh_processes(ProcessesToUpdate::All, true);
                for (pid, process) in system.processes() {
                    if process
                        .exe()
                        .is_some_and(|path| norm_path(path) == norm_path(&self.runtime_exe()))
                    {
                        if let Some(creation) = process_creation(pid.as_u32()) {
                            observed.insert((pid.as_u32(), creation));
                        }
                    }
                }
            }
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if started.elapsed() > BYO_GUARD {
                let _ = child.kill();
                let _ = child.wait();
                for (pid, creation) in &observed {
                    kill_identified(*pid, *creation);
                }
                panic!("byo {arguments:?} exceeded the {BYO_GUARD:?} test guard");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let elapsed = started.elapsed();
        let mut outputs = [Vec::new(), Vec::new()];
        for _ in 0..2 {
            let (stream, bytes) = receiver
                .recv_timeout(Duration::from_secs(20))
                .expect("byo output pipe stayed open after exit: a descendant survived");
            outputs[stream] = bytes;
        }
        // Retain every invocation, including init and repeated clean/defect/restore
        // verifies. Reports alone do not retain launcher exit or build output.
        static INVOCATION: AtomicU32 = AtomicU32::new(0);
        let evidence = self
            .root
            .join("invocations")
            .join(format!("{:04}", INVOCATION.fetch_add(1, Ordering::SeqCst)));
        write(&evidence.join("stdout.log"), &outputs[0]);
        write(&evidence.join("stderr.log"), &outputs[1]);
        write_json(
            &evidence.join("command.json"),
            &json!({
                "executable": BYO,
                "executable_sha256": sha256_file(Path::new(BYO)),
                "argv": arguments.iter().map(|arg| arg.to_string_lossy()).collect::<Vec<_>>(),
                "cwd": self.root,
                "exit": status.code(),
                "elapsed_seconds": elapsed.as_secs_f64(),
                "project_inputs": tree_hashes(&self.project),
                "observed_analyzer_identities": observed,
            "fake_processes": read_records(&self.root.join("fake-control/records")),
            "observed_analyzer_cleanup": observed.iter().map(|(pid, creation)| json!({
                "pid": pid, "creation": creation, "alive_after_launcher_exit": process_alive(*pid, *creation)
            })).collect::<Vec<_>>(),
            }),
        );
        // This independent observer records only the exact private image and
        // checks PID plus creation time, never a global process-name cleanup.
        for (pid, creation) in &observed {
            let alive = process_alive(*pid, *creation);
            if alive {
                kill_identified(*pid, *creation);
            }
            assert!(
                !alive,
                "owned real analyzer survived verify: {pid}/{creation}"
            );
        }
        Run {
            code: status.code(),
            stdout: String::from_utf8_lossy(&outputs[0]).into_owned(),
            stderr: String::from_utf8_lossy(&outputs[1]).into_owned(),
            elapsed,
        }
    }

    fn report_dirs(&self) -> BTreeSet<PathBuf> {
        fs::read_dir(self.project.join(REPORTS))
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|entry| entry.path().is_dir())
                    .map(|entry| entry.path())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn verify(&self, target: Option<&str>) -> Verify {
        let records = self.root.join("fake-control/records");
        let _ = fs::remove_dir_all(&records);
        fs::create_dir_all(&records).unwrap();
        let before = self.report_dirs();
        let mut arguments: Vec<OsString> = vec![
            "workflow".into(),
            "tool".into(),
            "verify".into(),
            "--project".into(),
            self.project.clone().into_os_string(),
        ];
        if let Some(target) = target {
            arguments.push(target.into());
        }
        let run = self.byo(&arguments);
        let created: Vec<PathBuf> = self.report_dirs().difference(&before).cloned().collect();
        let mut outcome = Verify {
            run,
            records: read_records(&records),
            report: None,
            result: None,
        };
        assert!(
            created.len() <= 1,
            "one verify created several report directories {created:?}\n{}",
            outcome.context()
        );
        outcome.report = created.into_iter().next();
        outcome.result = outcome.report.as_ref().and_then(|report| {
            fs::read(report.join(RESULT_FILE)).ok().map(|bytes| {
                serde_json::from_slice(&bytes)
                    .unwrap_or_else(|error| panic!("{RESULT_FILE} is not valid JSON: {error}"))
            })
        });
        // Save fake PID/creation records separately before the next verify clears
        // the control directory. Real children use the runner's owned evidence.
        if let Some(report) = &outcome.report {
            write_json(
                &report.join("acceptance-processes.json"),
                &json!(outcome.records),
            );
        }
        self.assert_owned_processes_gone(&outcome);
        outcome
    }

    /// The analyzer, its version probe and any descendant are owned by verify
    /// and must be gone once verify returns.
    fn assert_owned_processes_gone(&self, outcome: &Verify) {
        for record in outcome.records.iter().filter(|record| {
            matches!(
                record["phase"].as_str(),
                Some("version" | "analysis" | "descendant")
            )
        }) {
            let (pid, creation) =
                identity(record).expect("owned fake must record PID and creation");
            assert!(pid > 0 && creation > 0, "invalid owned identity: {record}");
        }
        let owned: Vec<(String, u32, u64)> = outcome
            .records
            .iter()
            .filter(|record| {
                matches!(
                    record["phase"].as_str(),
                    Some("version" | "analysis" | "descendant")
                )
            })
            .filter_map(|record| {
                let (pid, creation) = identity(record)?;
                Some((record["phase"].as_str()?.to_string(), pid, creation))
            })
            .collect();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut survivors;
        loop {
            survivors = owned
                .iter()
                .filter(|(_, pid, creation)| process_alive(*pid, *creation))
                .cloned()
                .collect::<Vec<_>>();
            if survivors.is_empty() || Instant::now() > deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        for (_, pid, creation) in &survivors {
            kill_identified(*pid, *creation);
        }
        assert!(
            survivors.is_empty(),
            "owned analyzer processes survived verify: {survivors:?}\n{}",
            outcome.context()
        );
    }

    /// An unrelated process running the same runtime image; cleanup must not
    /// select processes by image name.
    fn spawn_peer(&mut self) -> u32 {
        let child = Command::new(self.runtime_exe())
            .arg("--fake-peer")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn peer");
        let pid = child.id();
        self.peers.push(child);
        let marker = format!("-{pid}-peer.json");
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            let seen = fs::read_dir(self.root.join("fake-control/records"))
                .map(|entries| {
                    entries
                        .flatten()
                        .any(|entry| entry.file_name().to_string_lossy().ends_with(&marker))
                })
                .unwrap_or(false);
            if seen {
                return pid;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("peer process never started");
    }

    fn peer_running(&mut self, pid: u32) -> bool {
        self.peers
            .iter_mut()
            .find(|peer| peer.id() == pid)
            .is_some_and(|peer| matches!(peer.try_wait(), Ok(None)))
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        for peer in &mut self.peers {
            let _ = peer.kill();
            let _ = peer.wait();
        }
        for record in read_records(&self.root.join("fake-control/records")) {
            if let Some((pid, creation)) = identity(&record) {
                kill_identified(pid, creation);
            }
        }
        if std::thread::panicking() || std::env::var_os("BYO_CPPCHECK_ACCEPTANCE_LABS").is_some() {
            eprintln!("kept acceptance lab {}", self.root.display());
        } else {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn default_config() -> Value {
    json!({"schema_version": 1, "cppcheck": {"platform_file": DEFAULT_PLATFORM}})
}

fn config_with(fields: Value) -> Value {
    let mut config = default_config();
    for (key, value) in fields.as_object().unwrap() {
        config["cppcheck"][key] = value.clone();
    }
    config
}

/// Required flags exactly once, no forbidden extras, managed executable first.
fn check_argv(
    outcome: &Verify,
    lab: &Lab,
    style: bool,
    platform: &Path,
    suppressions: Option<&Path>,
) -> Vec<String> {
    let argv = outcome.argv();
    let context = outcome.context();
    assert!(
        argv.len() > 1,
        "argv must contain the executable and flags\n{context}"
    );
    assert_eq!(norm(&argv[0]), norm_path(&lab.runtime_exe()), "{context}");
    let rest = &argv[1..];
    let enable = if style { ENABLE_STYLE } else { ENABLE };
    let required = [
        enable,
        "--error-exitcode=1",
        "--xml",
        "--xml-version=2",
        "--safety",
    ];
    for flag in required {
        assert_eq!(
            rest.iter().filter(|argument| *argument == flag).count(),
            1,
            "{flag} must appear exactly once\n{context}"
        );
    }
    let valued = |prefix: &str| -> Vec<&str> {
        rest.iter()
            .filter_map(|argument| argument.strip_prefix(prefix))
            .collect()
    };
    assert_eq!(valued("--project=").len(), 1, "{context}");
    let platforms = valued("--platform=");
    assert_eq!(platforms.len(), 1, "{context}");
    assert_eq!(
        norm(platforms[0]),
        norm_path(platform),
        "target ABI XML\n{context}"
    );
    let lists = valued("--suppressions-list=");
    match suppressions {
        None => assert!(
            lists.is_empty(),
            "no suppressions were configured\n{context}"
        ),
        Some(path) => {
            assert_eq!(lists.len(), 1, "{context}");
            assert_eq!(norm(lists[0]), norm_path(path), "{context}");
        }
    }
    for argument in rest {
        let allowed = required.contains(&argument.as_str())
            || argument.starts_with("--project=")
            || argument.starts_with("--platform=")
            || argument.starts_with("--suppressions-list=");
        assert!(
            allowed,
            "unexpected Cppcheck argument {argument:?}\n{context}"
        );
    }
    argv
}

/// Canonical sources listed in the database the analyzer actually read.
fn analyzed_sources(outcome: &Verify, project: &Path) -> BTreeSet<String> {
    let text = outcome.analysis()["project_text"]
        .as_str()
        .unwrap_or_else(|| panic!("analyzer could not read --project\n{}", outcome.context()));
    let entries: Vec<Value> = serde_json::from_str(text).unwrap();
    entries
        .iter()
        .map(|entry| {
            let directory = PathBuf::from(entry["directory"].as_str().unwrap());
            let directory = if directory.is_absolute() {
                directory
            } else {
                project.join(directory)
            };
            let file = PathBuf::from(entry["file"].as_str().unwrap());
            let file = if file.is_absolute() {
                file
            } else {
                directory.join(file)
            };
            norm_path(&lexical(&plain(file)))
        })
        .collect()
}

fn project_paths(project: &Path, relatives: &[&str]) -> Vec<String> {
    relatives
        .iter()
        .map(|relative| norm_path(&project.join(relative)))
        .collect()
}

fn string_list(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("expected an array, found {value}"))
        .iter()
        .map(|item| norm(item.as_str().unwrap()))
        .collect()
}

// ---------------------------------------------------------------------------
// Normal, override and failed-build paths
// ---------------------------------------------------------------------------

#[test]
fn managed_static_step_runs_once_after_build_with_full_evidence() {
    let lab = Lab::new("normal");
    let database = lab.project.join("compile_commands.json");
    let database_before = read(&database);
    let outcome = lab.verify(None);
    outcome.expect_pass();
    assert_eq!(
        outcome.phases(),
        ["build", "version", "analysis"],
        "build, owned version probe, then one analysis\n{}",
        outcome.context()
    );
    let build = &outcome.records("build")[0];
    assert_eq!(
        norm(build["cwd"].as_str().unwrap()),
        norm_path(&lab.project)
    );
    let version = outcome.records("version")[0];
    assert_eq!(
        norm(version["exe"].as_str().unwrap()),
        norm_path(&lab.runtime_exe())
    );
    assert_eq!(version["argv"], json!(["--version"]));
    let analysis = outcome.analysis();
    assert_eq!(
        norm(analysis["exe"].as_str().unwrap()),
        norm_path(&lab.runtime_exe())
    );
    assert_eq!(
        norm(analysis["cwd"].as_str().unwrap()),
        norm_path(&lab.project)
    );
    assert_eq!(analysis["platform_exists"], json!(true));

    let result = outcome.result();
    let context = outcome.context();
    assert_eq!(result["backend"], "cppcheck", "{context}");
    assert_eq!(
        norm(result["project_root"].as_str().unwrap()),
        norm_path(&lab.project)
    );
    assert_eq!(
        norm(result["compilation_database"].as_str().unwrap()),
        norm_path(&database),
        "{context}"
    );
    assert_eq!(
        result["compilation_database_sha256"],
        sha256_bytes(&database_before)
    );
    assert_eq!(
        norm(result["executable"].as_str().unwrap()),
        norm_path(&lab.runtime_exe())
    );
    assert_eq!(result["executable_origin"], "managed_runtime", "{context}");
    assert_eq!(result["version"], PINNED_VERSION, "{context}");
    assert_eq!(
        result["executable_sha256"],
        sha256_file(&lab.runtime_exe()),
        "{context}"
    );
    assert_eq!(
        norm(result["runtime_root"].as_str().unwrap()),
        norm_path(&lab.runtime)
    );
    assert_eq!(
        result["runtime_manifest_sha256"],
        sha256_file(&lab.runtime.join("release-manifest.json")),
        "{context}"
    );
    assert_eq!(
        result["analysis_mapping_sha256"],
        sha256_file(&lab.runtime.join("analysis/runtime.json")),
        "{context}"
    );
    assert_eq!(
        norm(result["data_paths"]["cfg_dir"].as_str().unwrap()),
        norm_path(&lab.runtime.join("analysis/cppcheck/cfg")),
        "{context}"
    );
    assert_eq!(
        norm(result["data_paths"]["platforms_dir"].as_str().unwrap()),
        norm_path(&lab.runtime.join("analysis/cppcheck/platforms")),
        "{context}"
    );
    let platform = lab.project.join(DEFAULT_PLATFORM);
    assert_eq!(
        norm(result["platform_file"].as_str().unwrap()),
        norm_path(&platform)
    );
    let scope = &result["scope"];
    assert_eq!(scope["requested_path"], ".", "{context}");
    assert_eq!(scope["kind"], "all", "{context}");
    assert_eq!(
        string_list(&scope["translation_units"]),
        project_paths(&lab.project, &["src/a.c", "src/sub/b.cpp"]),
        "{context}"
    );
    assert_eq!(scope["selected_count"], 2, "{context}");
    assert_eq!(result["timeout_seconds"].as_f64(), Some(120.0), "{context}");
    assert_eq!(result["process_exit_code"], 0, "{context}");
    assert!(result["diagnostics"].is_array(), "{context}");
    assert_eq!(result["coverage_reasons"], json!([]), "{context}");
    assert!(result["warnings"].is_array(), "{context}");
    assert!(result["display_truncated"].is_boolean(), "{context}");
    assert_eq!(
        norm(result["report_directory"].as_str().unwrap()),
        norm_path(outcome.report()),
        "{context}"
    );

    let argv = check_argv(&outcome, &lab, false, &platform, None);
    assert_eq!(
        analysis["argv"],
        json!(argv[1..]),
        "recorded argv is the real argv\n{context}"
    );
    let report = outcome.report();
    assert_eq!(read_json(&report.join(ARGV_FILE)), json!(argv), "{context}");
    let xml = read(&parity("clean.xml"));
    assert_eq!(
        read(&report.join(ANALYSIS_STDERR)),
        xml,
        "complete stderr retained"
    );
    assert_eq!(
        String::from_utf8_lossy(&read(&report.join(REPORT_XML))).trim(),
        String::from_utf8_lossy(&xml).trim()
    );
    assert!(
        String::from_utf8_lossy(&read(&report.join(ANALYSIS_STDOUT)))
            .contains("Checking fake translation units")
    );
    assert!(
        String::from_utf8_lossy(&read(&report.join(VERSION_STDOUT))).contains("Cppcheck 2.22.0")
    );
    assert_eq!(
        analyzed_sources(&outcome, &lab.project),
        project_paths(&lab.project, &["src/a.c", "src/sub/b.cpp"])
            .into_iter()
            .collect(),
        "{context}"
    );
    assert_eq!(
        read(&database),
        database_before,
        "input database must not change"
    );
    assert!(
        norm(&outcome.output().replace(r"\\?\", "")).contains(&norm_path(report)),
        "summary must name the full report path\n{context}"
    );
}

#[test]
fn managed_resolution_needs_no_cppcheck_on_path() {
    let lab = Lab::new("no-path");
    fs::remove_file(lab.root.join("path-decoy/cppcheck.exe")).unwrap();
    let outcome = lab.verify(None);
    outcome.expect_pass();
    outcome.expect_static_once();
    assert_eq!(outcome.result()["executable_origin"], "managed_runtime");
}

fn install_override(lab: &Lab) {
    copy_file(fake_exe(), &lab.project.join("bin/verify-firmware-local"));
}

#[test]
fn local_override_receives_target_and_static_step_still_runs_once() {
    let lab = Lab::new("override");
    install_override(&lab);
    let outcome = lab.verify(None);
    outcome.expect_pass();
    assert_eq!(
        outcome.phases(),
        ["build", "version", "analysis"],
        "{}",
        outcome.context()
    );
    let build = outcome.records("build")[0];
    assert!(
        norm(build["exe"].as_str().unwrap()).ends_with("verify-firmware-local"),
        "the project override is the build step\n{}",
        outcome.context()
    );
    assert_eq!(string_list(&build["argv"]), [norm_path(&lab.project)]);

    let outcome = lab.verify(Some("src/a.c"));
    outcome.expect_pass();
    outcome.expect_static_once();
    let build = outcome.records("build")[0];
    assert_eq!(
        string_list(&build["argv"]),
        [norm_path(&lab.project.join("src/a.c"))]
    );
    assert_eq!(outcome.result()["scope"]["kind"], "source");
}

#[test]
fn failed_build_or_override_still_runs_static_step_once_and_fails() {
    let lab = Lab::new("failed-build");
    lab.control(&[("build.fail", "1")]);
    let outcome = lab.verify(None);
    outcome.expect_fail();
    outcome.expect_static_once();
    assert_eq!(
        outcome.phases(),
        ["build", "version", "analysis"],
        "{}",
        outcome.context()
    );
    assert!(
        outcome.output().contains("SCRIPTED BUILD FAILURE"),
        "{}",
        outcome.context()
    );
    assert_eq!(outcome.status(), "pass", "the static step itself was clean");

    install_override(&lab);
    let outcome = lab.verify(None);
    outcome.expect_fail();
    outcome.expect_static_once();
    assert_eq!(
        outcome.phases(),
        ["build", "version", "analysis"],
        "{}",
        outcome.context()
    );
}

#[test]
fn static_step_sees_headers_generated_by_the_build() {
    let lab = Lab::new("generated");
    let generated = "build/generated/config.h";
    let base = [
        ("analysis.require", generated),
        ("analysis.exit_when_missing", "1"),
    ];
    let missing_xml = parity("missing-include.xml").display().to_string();
    let mut with_generation = base.to_vec();
    with_generation.push(("analysis.xml_when_missing", &missing_xml));
    with_generation.push((
        "build.generate",
        "build/generated/config.h=#define GENERATED 1",
    ));
    lab.control(&with_generation);
    let outcome = lab.verify(None);
    outcome.expect_pass();
    assert_eq!(outcome.analysis()["missing_required"], json!([]));

    fs::remove_file(lab.project.join(generated)).unwrap();
    let mut without_generation = base.to_vec();
    without_generation.push(("analysis.xml_when_missing", &missing_xml));
    lab.control(&without_generation);
    let outcome = lab.verify(None);
    outcome.expect_outcome("blocked", "analysis/coverage-incomplete");
    assert_eq!(outcome.result()["process_exit_code"], 1);
    assert!(
        !outcome.result()["coverage_reasons"]
            .as_array()
            .unwrap()
            .is_empty(),
        "{}",
        outcome.context()
    );
}

// ---------------------------------------------------------------------------
// Managed runtime validation: blocked with no PATH fallback
// ---------------------------------------------------------------------------

fn expect_runtime_blocked(lab: &Lab, case: &str) {
    let outcome = lab.verify(None);
    outcome.expect_outcome("blocked", "analysis/executable-unavailable");
    outcome.expect_not_executed();
    assert!(
        outcome.result()["executable_origin"] != "path",
        "{case}: managed mode never falls back to PATH\n{}",
        outcome.context()
    );
}

fn mapping_case(name: &str, edit: impl FnOnce(&mut Value)) {
    let lab = Lab::new(name);
    let mut mapping = lab.mapping();
    edit(&mut mapping);
    lab.set_mapping(&mapping);
    lab.seal();
    expect_runtime_blocked(&lab, name);
}

#[test]
fn runtime_mapping_missing_blocks() {
    let lab = Lab::new("mapping-missing");
    fs::remove_file(lab.runtime.join("analysis/runtime.json")).unwrap();
    lab.seal();
    expect_runtime_blocked(&lab, "mapping-missing");
}

#[test]
fn runtime_mapping_unknown_field_blocks() {
    mapping_case("mapping-unknown-field", |mapping| {
        mapping["programs"]["cppcheck"]["extra"] = json!(true)
    });
}

#[test]
fn runtime_mapping_path_escape_blocks() {
    mapping_case("mapping-path-escape", |mapping| {
        mapping["programs"]["cppcheck"]["cfg_dir"] = json!("analysis/cppcheck/../../workflow")
    });
}

#[test]
fn runtime_mapping_bool_schema_blocks() {
    mapping_case("mapping-bool-schema", |mapping| {
        mapping["schema_version"] = json!(true)
    });
}

#[test]
fn runtime_mapping_target_mismatch_blocks() {
    mapping_case("mapping-target", |mapping| {
        mapping["platform"] = json!("linux")
    });
}

#[test]
fn runtime_mapping_clangd_resource_major_mismatch_blocks() {
    mapping_case("mapping-clangd-major", |mapping| {
        mapping["programs"]["clangd"]["resource_dir"] = json!("analysis/clangd/lib/clang/22")
    });
}

#[test]
fn runtime_missing_managed_executable_blocks() {
    let lab = Lab::new("managed-missing");
    fs::remove_file(lab.runtime_exe()).unwrap();
    lab.seal();
    expect_runtime_blocked(&lab, "managed-missing");
}

#[test]
fn runtime_missing_std_cfg_blocks() {
    let lab = Lab::new("missing-data");
    fs::remove_file(lab.runtime.join("analysis/cppcheck/cfg/std.cfg")).unwrap();
    lab.seal();
    expect_runtime_blocked(&lab, "missing-data");
}

#[test]
fn runtime_empty_platforms_directory_blocks() {
    let lab = Lab::new("empty-platforms");
    fs::remove_file(
        lab.runtime
            .join("analysis/cppcheck/platforms/arm32-wchar_t2.xml"),
    )
    .unwrap();
    lab.seal();
    expect_runtime_blocked(&lab, "empty-platforms");
}

#[test]
fn runtime_missing_mandatory_notice_blocks() {
    let lab = Lab::new("missing-notice");
    fs::remove_file(
        lab.runtime
            .join("analysis/cppcheck/licenses/picojson-LICENSE"),
    )
    .unwrap();
    lab.seal();
    expect_runtime_blocked(&lab, "missing-notice");
}

#[test]
fn runtime_unapproved_payload_blocks() {
    let lab = Lab::new("unapproved-payload");
    copy_file(fake_exe(), &lab.runtime.join("analysis/cppcheck/extra.dll"));
    lab.seal();
    expect_runtime_blocked(&lab, "unapproved-payload");
}

#[test]
fn runtime_non_pe_executable_blocks() {
    let lab = Lab::new("non-pe");
    write(&lab.runtime_exe(), "@echo Cppcheck 2.22.0\r\n");
    lab.seal();
    expect_runtime_blocked(&lab, "non-pe");
}

#[test]
fn runtime_sbom_hash_or_provenance_mismatch_blocks() {
    let lab = Lab::new("sbom-hash");
    lab.seal_with(
        |sbom| {
            for component in sbom["components"].as_array_mut().unwrap() {
                if component["name"] == RUNTIME_EXECUTABLE {
                    component["hashes"][0]["content"] = json!("0".repeat(64));
                }
            }
        },
        |_| {},
    );
    expect_runtime_blocked(&lab, "sbom-hash");

    let lab = Lab::new("sbom-provenance");
    lab.seal_with(
        |sbom| {
            for component in sbom["components"].as_array_mut().unwrap() {
                if component["bom-ref"] == "byo-analysis:cppcheck" {
                    component.as_object_mut().unwrap().remove("properties");
                }
            }
        },
        |_| {},
    );
    expect_runtime_blocked(&lab, "sbom-provenance");
}

#[test]
fn runtime_payload_misclassified_in_inventory_blocks() {
    let lab = Lab::new("misclassified");
    lab.seal_with(
        |_| {},
        |manifest| {
            for file in manifest["files"].as_array_mut().unwrap() {
                if file["path"] == "analysis/cppcheck/cfg/std.cfg" {
                    file["kind"] = json!("metadata");
                }
            }
        },
    );
    expect_runtime_blocked(&lab, "misclassified");
}

#[test]
fn runtime_release_target_mismatch_never_analyzes() {
    let lab = Lab::new("release-target");
    lab.seal_with(
        |_| {},
        |manifest| manifest["architecture"] = json!("aarch64"),
    );
    let outcome = lab.verify(None);
    outcome.expect_not_executed();
    assert!(
        matches!(outcome.run.code, Some(13 | 21 | 22)),
        "{}",
        outcome.context()
    );
    if let Some(result) = &outcome.result {
        assert_eq!(result["status"], "blocked", "{}", outcome.context());
    }
}

#[test]
fn tampered_unsealed_runtime_is_refused_before_any_analyzer_runs() {
    let lab = Lab::new("managed-hash-mismatch");
    let mut bytes = read(&lab.runtime_exe());
    bytes.push(0);
    write(&lab.runtime_exe(), bytes);
    let outcome = lab.verify(None);
    outcome.expect_not_executed();
    assert!(
        outcome.run.code.is_some_and(|code| code != 0),
        "{}",
        outcome.context()
    );
    assert!(
        !outcome.run.stdout.contains("VERIFY: PASS"),
        "{}",
        outcome.context()
    );

    let lab = Lab::new("managed-missing-unsealed");
    fs::remove_file(lab.runtime_exe()).unwrap();
    let outcome = lab.verify(None);
    outcome.expect_not_executed();
    assert!(
        outcome.run.code.is_some_and(|code| code != 0),
        "{}",
        outcome.context()
    );
}

// ---------------------------------------------------------------------------
// Owned version probe
// ---------------------------------------------------------------------------

#[test]
fn version_probe_outcomes_are_classified_without_analysis() {
    let lab = Lab::new("version");
    lab.control(&[("version.mode", "wrong")]);
    let outcome = lab.verify(None);
    outcome.expect_outcome("blocked", "analysis/executable-unavailable");
    outcome.expect_not_analyzed();
    assert_eq!(outcome.records("version").len(), 1);

    for mode in ["garbage", "stderr", "fail"] {
        lab.control(&[("version.mode", mode)]);
        let outcome = lab.verify(None);
        outcome.expect_outcome("execution_error", "analysis/version-failed");
        outcome.expect_not_analyzed();
        assert_eq!(outcome.records("version").len(), 1, "{mode}");
    }

    lab.control(&[("version.mode", "hang")]);
    let outcome = lab.verify(None);
    outcome.expect_fail();
    outcome.expect_not_analyzed();
    assert_eq!(outcome.status(), "execution_error", "{}", outcome.context());
    assert!(
        matches!(
            outcome.code(),
            Some("analysis/timeout" | "analysis/version-failed")
        ),
        "{}",
        outcome.context()
    );
    assert!(
        outcome.run.elapsed < Duration::from_secs(60),
        "the 5 s probe cap must bound a hung probe\n{}",
        outcome.context()
    );
}

#[test]
fn unsupported_or_mismatched_runtime_version_blocks() {
    let lab = Lab::new("version-unsupported");
    let mut mapping = lab.mapping();
    mapping["programs"]["cppcheck"]["version"] = json!("2.21.0");
    lab.set_mapping(&mapping);
    lab.seal();
    lab.control(&[("version.mode", "wrong")]);
    let outcome = lab.verify(None);
    outcome.expect_outcome("blocked", "analysis/version-unsupported");
    outcome.expect_not_analyzed();

    lab.control(&[("version.mode", "ok")]);
    let outcome = lab.verify(None);
    outcome.expect_outcome("blocked", "analysis/executable-unavailable");
    outcome.expect_not_analyzed();
}

// ---------------------------------------------------------------------------
// Project configuration, database and scope
// ---------------------------------------------------------------------------

#[test]
fn invalid_configuration_is_rejected_before_execution() {
    let lab = Lab::new("config");
    for case in expected()["config_cases"].as_array().unwrap() {
        lab.config(&case["json"]);
        let outcome = lab.verify(None);
        outcome.expect_outcome("blocked", "analysis/config-invalid");
        outcome.expect_not_executed();
        let field = case["field"].as_str().unwrap();
        assert!(
            outcome.result()["message"]
                .as_str()
                .unwrap()
                .contains(field),
            "message must name {field}\n{}",
            outcome.context()
        );
    }
    for (name, text) in [
        (
            "duplicate-key",
            r#"{"schema_version":1,"schema_version":1,"cppcheck":{"platform_file":"config/platform.xml"}}"#,
        ),
        (
            "nan-timeout",
            r#"{"schema_version":1,"cppcheck":{"platform_file":"config/platform.xml","timeout_seconds":NaN}}"#,
        ),
        (
            "infinite-timeout",
            r#"{"schema_version":1,"cppcheck":{"platform_file":"config/platform.xml","timeout_seconds":1e400}}"#,
        ),
        (
            "bool-timeout",
            r#"{"schema_version":1,"cppcheck":{"platform_file":"config/platform.xml","timeout_seconds":true}}"#,
        ),
        (
            "string-style",
            r#"{"schema_version":1,"cppcheck":{"platform_file":"config/platform.xml","enable_style":"true"}}"#,
        ),
        ("null-section", r#"{"schema_version":1,"cppcheck":null}"#),
        (
            "float-schema",
            r#"{"schema_version":1.0,"cppcheck":{"platform_file":"config/platform.xml"}}"#,
        ),
        ("malformed", r#"{"schema_version":1,"#),
        (
            "unknown-nested",
            r#"{"schema_version":1,"cppcheck":{"platform_file":"config/platform.xml","force":true}}"#,
        ),
        (
            "missing-platform-file",
            r#"{"schema_version":1,"cppcheck":{"platform_file":"config/absent.xml"}}"#,
        ),
        (
            "missing-suppressions-file",
            r#"{"schema_version":1,"cppcheck":{"platform_file":"config/platform.xml","suppressions_file":"config/absent.txt"}}"#,
        ),
    ] {
        lab.config_raw(text);
        let outcome = lab.verify(None);
        assert_eq!(
            outcome.code(),
            Some("analysis/config-invalid"),
            "{name}\n{}",
            outcome.context()
        );
        outcome.expect_outcome("blocked", "analysis/config-invalid");
        outcome.expect_not_executed();
    }
}

#[test]
fn explicit_target_platform_is_required() {
    let lab = Lab::new("platform");
    lab.config(&json!({"schema_version": 1}));
    let outcome = lab.verify(None);
    outcome.expect_outcome("blocked", "analysis/platform-missing");
    outcome.expect_not_executed();

    fs::remove_file(lab.project.join("byo-analysis.json")).unwrap();
    let outcome = lab.verify(None);
    outcome.expect_outcome("blocked", "analysis/platform-missing");
    outcome.expect_not_executed();
    assert!(
        !lab.project.join("byo-analysis.json").exists(),
        "configuration is never created automatically"
    );

    write(
        &lab.project.join("config/other.xml"),
        read(&parity("project/config/platform.xml")),
    );
    lab.config(&config_with(json!({"platform_file": "config/other.xml"})));
    let outcome = lab.verify(None);
    outcome.expect_pass();
    check_argv(
        &outcome,
        &lab,
        false,
        &lab.project.join("config/other.xml"),
        None,
    );
}

#[test]
fn target_abi_must_be_complete_positive_and_unambiguous() {
    let lab = Lab::new("abi-invalid");
    let complete = String::from_utf8(read(&parity("project/config/platform.xml"))).unwrap();
    let platform = lab.project.join(DEFAULT_PLATFORM);
    for (name, xml) in [
        ("malformed", "<platform>".to_string()),
        ("host-defaults", "<platform/>".to_string()),
        (
            "missing-pointer",
            complete.replace("<pointer>4</pointer>", ""),
        ),
        ("zero-int", complete.replace("<int>4</int>", "<int>0</int>")),
        (
            "fractional-int",
            complete.replace("<int>4</int>", "<int>3.5</int>"),
        ),
        (
            "overflow-int",
            complete.replace("<int>4</int>", "<int>4294967296</int>"),
        ),
        (
            "duplicate-int",
            complete.replace("<int>4</int>", "<int>4</int><int>2</int>"),
        ),
        ("invalid-sign", complete.replace("signed", "unknown")),
    ] {
        assert_ne!(xml, complete, "{name}: mutation must change the fixture");
        write(&platform, &xml);
        let outcome = lab.verify(None);
        outcome.expect_outcome("blocked", "analysis/config-invalid");
        outcome.expect_not_executed();
        assert!(
            outcome.result()["message"]
                .as_str()
                .unwrap()
                .contains("platform_file"),
            "{name}"
        );
    }
}

#[test]
fn shared_fixture_identity_is_verified_before_parity() {
    let manifest = read_json(&parity("manifest.json"));
    let files = manifest["sha256"].as_object().unwrap();
    assert_eq!(files.len(), 37, "38 shared files includes manifest itself");
    for (relative, digest) in files {
        assert_eq!(
            sha256_file(&parity(relative)),
            digest.as_str().unwrap(),
            "{relative}"
        );
    }
}

#[test]
fn filtered_database_preserves_exact_argv_output_and_opaque_command() {
    let lab = Lab::new("argv-identity");
    let outcome = lab.verify(Some("src/a.c"));
    outcome.expect_pass();
    let passed: Vec<Value> =
        serde_json::from_str(outcome.analysis()["project_text"].as_str().unwrap()).unwrap();
    assert_eq!(passed.len(), 1);
    let original = parity_database();
    assert_eq!(
        passed[0]["arguments"], original[0]["arguments"],
        "spaces are part of an argv element"
    );
    assert_eq!(passed[0]["output"], original[0]["output"]);

    // Shell text is opaque data. If somebody executes it, the private marker
    // exists; merely comparing scope could miss an accidental shell execution.
    let marker = lab.project.join("never-execute.txt");
    let command = format!("cc -c src/a.c && echo executed>\"{}\"", marker.display());
    write_json(
        &lab.project.join("compile_commands.json"),
        &json!([
            {"directory": ".", "file": "src/a.c", "command": command}
        ]),
    );
    let outcome = lab.verify(None);
    outcome.expect_pass();
    let passed: Vec<Value> =
        serde_json::from_str(outcome.analysis()["project_text"].as_str().unwrap()).unwrap();
    assert_eq!(passed[0]["command"], command);
    assert!(passed[0].get("arguments").is_none());
    assert!(
        !marker.exists(),
        "compilation shell text must never execute"
    );
}

fn parity_database() -> Vec<Value> {
    serde_json::from_value(read_json(&parity("project/compile_commands.json"))).unwrap()
}

#[test]
fn database_cases_follow_the_shared_contract() {
    let lab = Lab::new("database");
    let database = lab.project.join("compile_commands.json");
    for case in expected()["database_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let mut entries = parity_database();
        let mut extra = entries[case["append_entry"].as_u64().unwrap() as usize].clone();
        if let Some(argument) = case.get("append_argument") {
            extra["arguments"]
                .as_array_mut()
                .unwrap()
                .push(argument.clone());
        }
        if let Some(command) = case.get("additional_command") {
            extra["command"] = command.clone();
        }
        entries.push(extra);
        write_json(&database, &json!(entries));
        if case["status"] == "blocked" {
            for target in [None, Some("src/sub")] {
                let outcome = lab.verify(target);
                outcome.expect_outcome("blocked", "analysis/database-conflict");
                outcome.expect_not_executed();
            }
        } else {
            let outcome = lab.verify(None);
            outcome.expect_pass();
            assert_eq!(
                outcome.result()["scope"]["selected_count"],
                case["selected_count"],
                "{name}\n{}",
                outcome.context()
            );
            let text = outcome.analysis()["project_text"]
                .as_str()
                .unwrap()
                .to_string();
            assert!(
                !text.contains("never_execute"),
                "{name}: arguments are preferred over command\n{}",
                outcome.context()
            );
        }
    }

    write(&database, read(&parity("command-only.json")));
    let outcome = lab.verify(None);
    outcome.expect_pass();
    assert_eq!(outcome.result()["scope"]["selected_count"], 1);

    let mut empty_arguments = parity_database();
    empty_arguments[0]["arguments"] = json!([]);
    let mut missing_source = parity_database();
    missing_source[0]["file"] = json!("src/absent.c");
    let mut neither = parity_database();
    neither[0].as_object_mut().unwrap().remove("arguments");
    for (name, value) in [
        ("object", json!({})),
        ("empty", json!([])),
        ("empty-arguments", json!(empty_arguments)),
        ("missing-source", json!(missing_source)),
        ("no-command", json!(neither)),
    ] {
        write_json(&database, &value);
        let outcome = lab.verify(None);
        assert_eq!(
            outcome.code(),
            Some("analysis/database-invalid"),
            "{name}\n{}",
            outcome.context()
        );
        outcome.expect_outcome("blocked", "analysis/database-invalid");
        outcome.expect_not_executed();
    }
    write(&database, read(&parity("project/compile_commands.json")));
}

#[test]
fn database_discovery_is_missing_ambiguous_or_explicit() {
    let lab = Lab::new("discovery");
    let root_database = lab.project.join("compile_commands.json");
    let build_database = lab.project.join("build/compile_commands.json");
    copy_file(&root_database, &build_database);
    let outcome = lab.verify(None);
    outcome.expect_outcome("blocked", "analysis/database-ambiguous");
    outcome.expect_not_executed();

    lab.config(&json!({
        "schema_version": 1,
        "compilation_database": "build/compile_commands.json",
        "cppcheck": {"platform_file": DEFAULT_PLATFORM}
    }));
    let outcome = lab.verify(None);
    outcome.expect_pass();
    assert_eq!(
        norm(outcome.result()["compilation_database"].as_str().unwrap()),
        norm_path(&build_database)
    );

    copy_file(&build_database, &lab.project.join("build/commands.json"));
    lab.config(&json!({
        "schema_version": 1,
        "compilation_database": "build/commands.json",
        "cppcheck": {"platform_file": DEFAULT_PLATFORM}
    }));
    let outcome = lab.verify(None);
    outcome.expect_outcome("blocked", "analysis/database-invalid");
    outcome.expect_not_executed();

    fs::remove_file(&build_database).unwrap();
    lab.config(&json!({
        "schema_version": 1,
        "compilation_database": "build/compile_commands.json",
        "cppcheck": {"platform_file": DEFAULT_PLATFORM}
    }));
    let outcome = lab.verify(None);
    outcome.expect_outcome("blocked", "analysis/database-invalid");
    outcome.expect_not_executed();

    lab.config(&default_config());
    fs::remove_file(&root_database).unwrap();
    let outcome = lab.verify(None);
    outcome.expect_outcome("blocked", "analysis/database-missing");
    outcome.expect_not_executed();
}

#[test]
fn scope_selects_source_directory_and_header_units() {
    let lab = Lab::new("scope");
    for case in expected()["selection"].as_array().unwrap() {
        let target = case["target"].as_str().unwrap();
        let outcome = lab.verify(Some(target));
        if case["status"] == "blocked" {
            outcome.expect_outcome("blocked", case["code"].as_str().unwrap());
            outcome.expect_not_executed();
            continue;
        }
        outcome.expect_pass();
        outcome.expect_static_once();
        let sources: Vec<&str> = case["sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|source| source.as_str().unwrap())
            .collect();
        let scope = &outcome.result()["scope"];
        let context = outcome.context();
        assert_eq!(
            scope["requested_path"], target,
            "raw requested path\n{context}"
        );
        assert_eq!(scope["kind"], case["kind"], "{context}");
        assert_eq!(
            string_list(&scope["translation_units"]),
            project_paths(&lab.project, &sources),
            "{context}"
        );
        assert_eq!(scope["selected_count"], sources.len(), "{context}");
        assert_eq!(
            analyzed_sources(&outcome, &lab.project),
            project_paths(&lab.project, &sources).into_iter().collect(),
            "the analyzer reads exactly the selected units\n{context}"
        );
    }
}

#[test]
fn assembly_units_block_full_scope_but_not_selected_cpp_scope() {
    let lab = Lab::new("assembly-coverage");
    write(&lab.project.join("src/startup.s"), ".text\n");
    let mut entries = parity_database();
    entries.push(json!({"directory": ".", "file": "src/startup.s", "arguments": ["cc", "-c", "src/startup.s"]}));
    write_json(&lab.project.join("compile_commands.json"), &json!(entries));
    let outcome = lab.verify(None);
    outcome.expect_outcome("blocked", "analysis/coverage-incomplete");
    outcome.expect_not_executed();
    assert_eq!(outcome.result()["scope"]["selected_count"], 3);
    let outcome = lab.verify(Some("src/sub"));
    outcome.expect_pass();
    assert_eq!(outcome.result()["scope"]["selected_count"], 1);
    assert_eq!(
        analyzed_sources(&outcome, &lab.project),
        project_paths(&lab.project, &["src/sub/b.cpp"])
            .into_iter()
            .collect()
    );
}

// ---------------------------------------------------------------------------
// Suppressions and style
// ---------------------------------------------------------------------------

#[test]
fn suppressions_keep_coverage_diagnostics_visible() {
    let lab = Lab::new("suppressions");
    let file = lab.project.join("config/suppressions.txt");
    lab.config(&config_with(
        json!({"suppressions_file": "config/suppressions.txt"}),
    ));
    let platform = lab.project.join(DEFAULT_PLATFORM);
    for text in [
        "nullPointer\n",
        "// project rules\n# more\nnullPointer:src/a.c:3\r\n",
    ] {
        write(&file, text);
        let outcome = lab.verify(None);
        outcome.expect_pass();
        check_argv(&outcome, &lab, false, &platform, Some(&file));
        assert_eq!(
            outcome.analysis()["suppressions_text"],
            text,
            "{}",
            outcome.context()
        );
    }
    for rule in [
        "missingInclude",
        "missingIncludeSystem",
        "*",
        "missing*",
        "unknown*",
        "missingInclude:src/a.c",
        "missingInclude:src/a.c:1",
        "missingIncludeSystem:src/*.c:1",
        "missing*:src/*.c",
        "checkLevelNormal",
        "toomanyconfigs",
    ] {
        write(&file, format!("nullPointer\n{rule}\n"));
        let outcome = lab.verify(None);
        assert_eq!(
            outcome.code(),
            Some("analysis/config-invalid"),
            "{rule}\n{}",
            outcome.context()
        );
        outcome.expect_outcome("blocked", "analysis/config-invalid");
        outcome.expect_not_executed();
        let message = outcome.result()["message"].as_str().unwrap();
        assert!(
            message.contains("suppressions_file") && message.contains(rule),
            "{message}"
        );
        assert!(!outcome.result()["coverage_reasons"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    lab.control(&[("analysis.reject_bom_suppressions", "1")]);
    write(&file, "\u{feff}nullPointer\n");
    let outcome = lab.verify(None);
    outcome.expect_fail();
    assert_eq!(outcome.status(), "execution_error", "{}", outcome.context());
    assert_eq!(outcome.records("analysis").len(), 1);

    write(&file, "\u{feff}missingInclude\n");
    let outcome = lab.verify(None);
    outcome.expect_fail();
    assert_ne!(outcome.status(), "pass", "{}", outcome.context());
}

#[test]
fn style_checks_are_opt_in() {
    let lab = Lab::new("style");
    let platform = lab.project.join(DEFAULT_PLATFORM);
    let outcome = lab.verify(None);
    outcome.expect_pass();
    check_argv(&outcome, &lab, false, &platform, None);

    lab.config(&config_with(json!({"enable_style": true})));
    let outcome = lab.verify(None);
    outcome.expect_pass();
    check_argv(&outcome, &lab, true, &platform, None);

    lab.config(&config_with(json!({"enable_style": false})));
    let outcome = lab.verify(None);
    outcome.expect_pass();
    check_argv(&outcome, &lab, false, &platform, None);
}

// ---------------------------------------------------------------------------
// XML and exit classification
// ---------------------------------------------------------------------------

fn classification_code(status: &str) -> &'static str {
    match status {
        "findings_failed" => "analysis/findings",
        "blocked" => "analysis/coverage-incomplete",
        "execution_error" => "analysis/execution-failed",
        other => panic!("no classification code for {other}"),
    }
}

#[test]
fn every_parity_report_is_classified_like_the_reference_runner() {
    let lab = Lab::new("classification");
    let platform = lab.project.join(DEFAULT_PLATFORM);
    for case in expected()["diagnostics"].as_array().unwrap() {
        let name = case["xml"].as_str().unwrap();
        let exit = case["exit_code"].as_i64().unwrap();
        let style = case["style"].as_bool().unwrap_or(false);
        lab.config(&config_with(json!({"enable_style": style})));
        let xml = parity(name);
        let exit_text = exit.to_string();
        let xml_text = xml.display().to_string();
        lab.control(&[("analysis.xml", &xml_text), ("analysis.exit", &exit_text)]);
        let outcome = lab.verify(None);
        let context = format!("case {name}\n{}", outcome.context());
        outcome.expect_static_once();
        check_argv(&outcome, &lab, style, &platform, None);
        assert_eq!(outcome.result()["process_exit_code"], exit, "{context}");
        match case["status"].as_str().unwrap() {
            "pass" => outcome.expect_pass(),
            "malformed" => outcome.expect_outcome("execution_error", "analysis/report-invalid"),
            status => {
                outcome.expect_outcome(status, classification_code(status));
                let ids: Vec<String> = outcome.result()["diagnostics"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|diagnostic| diagnostic["id"].as_str().unwrap().to_string())
                    .collect();
                assert_eq!(
                    ids,
                    xml_ids(&read(&xml)),
                    "every diagnostic is preserved\n{context}"
                );
                if status == "blocked" {
                    assert!(
                        !outcome.result()["coverage_reasons"]
                            .as_array()
                            .unwrap()
                            .is_empty(),
                        "{context}"
                    );
                }
            }
        }
        if case["status"] == "pass" {
            let ids: Vec<String> = outcome.result()["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .map(|diagnostic| diagnostic["id"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(ids, xml_ids(&read(&xml)), "{context}");
        }
    }
}

#[test]
fn findings_carry_resolved_locations() {
    let lab = Lab::new("locations");
    let xml = parity("findings.xml").display().to_string();
    lab.control(&[("analysis.xml", &xml), ("analysis.exit", "1")]);
    let outcome = lab.verify(None);
    outcome.expect_outcome("findings_failed", "analysis/findings");
    let finding = &outcome.result()["diagnostics"][0];
    let context = outcome.context();
    assert_eq!(finding["id"], "nullPointer", "{context}");
    assert_eq!(finding["severity"], "error", "{context}");
    assert_eq!(finding["message"], "fixture diagnostic", "{context}");
    assert_eq!(
        finding["verbose_message"], "complete fixture diagnostic",
        "{context}"
    );
    assert_eq!(finding["inconclusive"], false, "{context}");
    let location = &finding["locations"][0];
    assert_eq!(
        norm(location["file"].as_str().unwrap()),
        norm_path(&lab.project.join("src/a.c"))
    );
    assert_eq!(location["line"], 1, "{context}");
    assert_eq!(location["column"], 1, "{context}");
}

#[test]
fn analyzer_anomalies_are_execution_errors() {
    let lab = Lab::new("anomalies");
    let mismatched = lab.root.join("version-mismatch.xml");
    write(
        &mismatched,
        String::from_utf8(read(&parity("clean.xml")))
            .unwrap()
            .replace("version=\"2.22.0\"", "version=\"2.21.0\""),
    );
    let mismatched = mismatched.display().to_string();
    let cases: [(&str, Vec<(&str, &str)>); 5] = [
        (
            "stdout-error",
            vec![(
                "analysis.stdout_text",
                "cppcheck: error: unrecognized command line option",
            )],
        ),
        (
            "stderr-prefix",
            vec![("analysis.stderr_prefix", "unexplained stderr\\n")],
        ),
        ("no-xml", vec![("analysis.no_xml", "1")]),
        ("crash", vec![("analysis.crash", "1")]),
        ("xml-version", vec![("analysis.xml", &mismatched)]),
    ];
    for (name, settings) in cases {
        lab.control(&settings);
        let outcome = lab.verify(None);
        outcome.expect_fail();
        assert_eq!(
            outcome.status(),
            "execution_error",
            "{name}\n{}",
            outcome.context()
        );
        assert_eq!(outcome.records("analysis").len(), 1, "{name}");
        assert!(outcome.report().join(ANALYSIS_STDERR).is_file(), "{name}");
    }
}

#[test]
fn mixed_diagnostics_keep_all_records_and_use_contract_precedence() {
    let lab = Lab::new("mixed-diagnostics");
    let xml = lab.root.join("mixed.xml");
    for (ids, status) in [
        (
            vec![("nullPointer", "error"), ("missingInclude", "information")],
            "blocked",
        ),
        (
            vec![
                ("nullPointer", "error"),
                ("missingInclude", "information"),
                ("syntaxError", "error"),
            ],
            "execution_error",
        ),
    ] {
        let errors: String = ids
            .iter()
            .map(|(id, severity)| {
                format!("<error id=\"{id}\" severity=\"{severity}\" msg=\"mixed fixture\"/>")
            })
            .collect();
        write(&xml, format!("<?xml version=\"1.0\"?><results version=\"2\"><cppcheck version=\"2.22.0\"/><errors>{errors}</errors></results>"));
        lab.control(&[
            ("analysis.xml", &xml.display().to_string()),
            ("analysis.exit", "1"),
        ]);
        let outcome = lab.verify(None);
        outcome.expect_outcome(status, classification_code(status));
        let actual: Vec<&str> = outcome.result()["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["id"].as_str().unwrap())
            .collect();
        assert_eq!(actual, ids.iter().map(|(id, _)| *id).collect::<Vec<_>>());
    }
}

#[test]
fn complete_stdout_is_retained() {
    let lab = Lab::new("stdout");
    lab.control(&[("analysis.stdout_lines", "3000")]);
    let outcome = lab.verify(None);
    outcome.expect_pass();
    let stdout = String::from_utf8(read(&outcome.report().join(ANALYSIS_STDOUT))).unwrap();
    let markers: Vec<&str> = stdout
        .lines()
        .filter(|line| line.starts_with("FAKE-STDOUT-MARKER-"))
        .collect();
    assert_eq!(markers.len(), 3000);
    assert_eq!(markers.first(), Some(&"FAKE-STDOUT-MARKER-000"));
    assert_eq!(markers.last(), Some(&"FAKE-STDOUT-MARKER-2999"));
}

// ---------------------------------------------------------------------------
// Deadline, ownership, evidence and paths
// ---------------------------------------------------------------------------

#[test]
fn deadline_kills_exactly_the_owned_process_tree() {
    let mut lab = Lab::new("deadline");
    lab.config(&config_with(json!({"timeout_seconds": 3})));
    lab.control(&[("analysis.descendant", "1"), ("analysis.hang", "1")]);
    let peer = lab.spawn_peer();
    let outcome = lab.verify(None);
    outcome.expect_outcome("execution_error", "analysis/timeout");
    assert_eq!(
        outcome.records("descendant").len(),
        1,
        "{}",
        outcome.context()
    );
    assert_eq!(outcome.result()["timeout_seconds"].as_f64(), Some(3.0));
    assert!(
        outcome.result()["process_exit_code"].is_null(),
        "{}",
        outcome.context()
    );
    assert!(
        outcome.run.elapsed < Duration::from_secs(60),
        "finite deadline\n{}",
        outcome.context()
    );
    assert!(
        lab.peer_running(peer),
        "an unrelated process using the same image must survive cleanup"
    );
}

#[test]
fn version_and_analysis_share_one_finite_deadline() {
    let lab = Lab::new("shared-deadline");
    lab.config(&config_with(json!({"timeout_seconds": 5})));
    // Each phase fits 5 s independently, their sum does not. A fresh budget
    // per process would falsely accept this otherwise clean XML report.
    lab.control(&[("version.delay_ms", "3000"), ("analysis.delay_ms", "3000")]);
    let outcome = lab.verify(None);
    outcome.expect_outcome("execution_error", "analysis/timeout");
    assert_eq!(outcome.records("version").len(), 1);
    assert!(outcome.records("analysis").len() <= 1);
    assert!(
        outcome.run.elapsed < Duration::from_secs(25),
        "{}",
        outcome.context()
    );
}

#[test]
fn evidence_write_failure_cannot_pass() {
    let lab = Lab::new("evidence");
    write(&lab.project.join(REPORTS), "not a directory\n");
    let outcome = lab.verify(None);
    outcome.expect_fail();
    assert!(
        outcome.records("analysis").is_empty(),
        "{}",
        outcome.context()
    );
    assert!(outcome.records("decoy").is_empty(), "{}", outcome.context());
}

#[test]
fn long_project_paths_reach_the_analyzer() {
    let base = std::env::temp_dir().join("byo-cppcheck-acceptance");
    let probe = plain(
        fs::create_dir_all(&base)
            .and_then(|_| base.canonicalize())
            .unwrap(),
    );
    let used = probe.display().to_string().len() + "\\long-00000-000\\".len();
    let name = format!(
        "long path {}",
        "x".repeat(200usize.saturating_sub(used + 10))
    );
    let lab = Lab::create("long", &name, Analyzer::Fake, |project| {
        copy_tree(&parity("project"), project)
    });
    let outcome = lab.verify(None);
    outcome.expect_pass();
    let project_file = outcome.analysis()["project_file"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        norm(&project_file).len() > 260 || lab.project.display().to_string().len() >= 180,
        "{project_file}"
    );
    assert_eq!(outcome.analysis()["platform_exists"], json!(true));
    assert_eq!(
        analyzed_sources(&outcome, &lab.project),
        project_paths(&lab.project, &["src/a.c", "src/sub/b.cpp"])
            .into_iter()
            .collect()
    );
}

// ---------------------------------------------------------------------------
// Real pinned Cppcheck 2.22.0 (ignored unless the recorded inputs are supplied)
// ---------------------------------------------------------------------------

fn rewrite_strings(value: &mut Value, replacements: &[(String, String)]) {
    match value {
        Value::String(text) => {
            for (from, to) in replacements {
                *text = text.replace(from.as_str(), to.as_str());
            }
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| rewrite_strings(item, replacements)),
        Value::Object(map) => map
            .values_mut()
            .for_each(|item| rewrite_strings(item, replacements)),
        _ => {}
    }
}

fn copy_arm_fixture(fixture: &Path, project: &Path) {
    copy_tree(fixture, project);
    let old = fixture.display().to_string();
    let new = project.display().to_string();
    let replacements = [
        (old.replace('\\', "\\\\"), new.replace('\\', "\\\\")),
        (old.replace('\\', "/"), new.replace('\\', "/")),
        (old.replace('/', "\\"), new.replace('/', "\\")),
    ];
    let database = project.join("build/compile_commands.json");
    let mut value = read_json(&database);
    rewrite_strings(&mut value, &replacements);
    let serialized = serde_json::to_string(&value).unwrap();
    assert!(
        !serialized.contains(&old.replace('\\', "/")),
        "unrelocated protected input path"
    );
    write_json(&database, &value);
}

#[test]
#[ignore = "needs BYO_CPPCHECK_PACKAGING_INPUTS, BYO_CPPCHECK_SOURCE_DIR and BYO_ARM_FIXTURE_DIR"]
fn real_cppcheck_arm_firmware_clean_defect_restored() {
    let inputs = real_inputs();
    let fixture = required_env("BYO_ARM_FIXTURE_DIR");
    let before = tree_hashes(&fixture);
    let originals = read_json(&acceptance_dir().join("arm-originals.json"));
    assert_eq!(
        before.len(),
        15,
        "genuine built ARM fixture must have 15 originals"
    );
    for (relative, expected) in originals["files"].as_object().unwrap() {
        let path = fixture.join(relative);
        assert_eq!(
            sha256_file(&path),
            expected["sha256"].as_str().unwrap(),
            "{relative}"
        );
        assert_eq!(
            read(&path).len() as u64,
            expected["size"].as_u64().unwrap(),
            "{relative}"
        );
    }
    let lab = Lab::create(
        "arm",
        "arm firmware fixture",
        Analyzer::Real(&inputs),
        |project| copy_arm_fixture(&fixture, project),
    );
    let main = lab.project.join("src/main.c");
    let clean = read(&main);

    let outcome = lab.verify(None);
    outcome.expect_pass();
    let result = outcome.result();
    assert_eq!(result["process_exit_code"], 0, "{}", outcome.context());
    assert_eq!(result["version"], PINNED_VERSION);
    assert_eq!(result["executable_sha256"], inputs.executable_sha256);
    assert_eq!(result["executable_origin"], "managed_runtime");
    assert_eq!(
        result["scope"]["selected_count"],
        3,
        "{}",
        outcome.context()
    );
    assert_eq!(
        norm(result["platform_file"].as_str().unwrap()),
        norm_path(&lab.project.join("config/arm32.xml"))
    );

    let mut defect = clean.clone();
    defect.extend_from_slice(b"\nint defect(void) { int *pointer = 0; return *pointer; }\n");
    write(&main, &defect);
    let outcome = lab.verify(None);
    outcome.expect_outcome("findings_failed", "analysis/findings");
    assert_eq!(
        outcome.result()["process_exit_code"],
        1,
        "{}",
        outcome.context()
    );
    let finding = outcome.result()["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|diagnostic| diagnostic["id"] == "nullPointer")
        .unwrap_or_else(|| panic!("nullPointer expected\n{}", outcome.context()));
    assert_eq!(
        norm(finding["locations"][0]["file"].as_str().unwrap()),
        norm_path(&main)
    );

    write(&main, &clean);
    let outcome = lab.verify(None);
    outcome.expect_pass();
    assert_eq!(outcome.result()["process_exit_code"], 0);

    for (target, kind, count) in [
        ("src/heartbeat.cpp", "source", 1),
        ("src", "directory", 3),
        ("include/firmware.h", "header_all", 3),
    ] {
        let outcome = lab.verify(Some(target));
        outcome.expect_pass();
        assert_eq!(
            outcome.result()["scope"]["kind"],
            kind,
            "{}",
            outcome.context()
        );
        assert_eq!(
            outcome.result()["scope"]["selected_count"],
            count,
            "{}",
            outcome.context()
        );
    }

    let generated = lab.project.join("build/generated/build_config.h");
    let header = read(&generated);
    fs::remove_file(&generated).unwrap();
    let outcome = lab.verify(None);
    outcome.expect_outcome("blocked", "analysis/coverage-incomplete");
    write(&generated, header);

    install_override(&lab);
    let outcome = lab.verify(None);
    outcome.expect_pass();
    assert_eq!(outcome.records("build").len(), 1);
    assert_eq!(outcome.result()["process_exit_code"], 0);
    lab.control(&[("build.fail", "1")]);
    let outcome = lab.verify(None);
    outcome.expect_fail();
    assert_eq!(outcome.status(), "pass", "{}", outcome.context());
    assert_eq!(
        tree_hashes(&fixture),
        before,
        "the ARM fixture must not change"
    );
}

struct RealCase {
    name: &'static str,
    units: &'static [(&'static str, &'static str)],
    entries: &'static [(&'static str, &'static str, &'static [&'static str])],
    platform: &'static str,
    style: bool,
    suppressions: Option<&'static str>,
    status: &'static str,
    ids: &'static [&'static str],
}

const REAL_CASES: &[RealCase] = &[
    RealCase {
        name: "clean",
        units: &[("src/clean.c", "clean.c")],
        entries: &[(".", "src/clean.c", &[])],
        platform: "ilp32.xml",
        style: false,
        suppressions: None,
        status: "pass",
        ids: &[],
    },
    RealCase {
        name: "null",
        units: &[("src/null_deref.c", "null_deref.c")],
        entries: &[(".", "src/null_deref.c", &[])],
        platform: "ilp32.xml",
        style: false,
        suppressions: None,
        status: "findings_failed",
        ids: &["nullPointer"],
    },
    RealCase {
        name: "null-suppressed",
        units: &[("src/null_deref.c", "null_deref.c")],
        entries: &[(".", "src/null_deref.c", &[])],
        platform: "ilp32.xml",
        style: false,
        suppressions: Some("nullPointer\n"),
        status: "pass",
        ids: &[],
    },
    RealCase {
        name: "null-file-line-suppressed",
        units: &[("src/null_deref.c", "null_deref.c")],
        entries: &[(".", "src/null_deref.c", &[])],
        platform: "ilp32.xml",
        style: false,
        suppressions: Some("nullPointer:*/null_deref.c:4\n"),
        status: "pass",
        ids: &[],
    },
    RealCase {
        name: "null-wildcard-suppressed",
        units: &[("src/null_deref.c", "null_deref.c")],
        entries: &[(".", "src/null_deref.c", &[])],
        platform: "ilp32.xml",
        style: false,
        suppressions: Some("null*:*/null_deref.c\n"),
        status: "pass",
        ids: &[],
    },
    RealCase {
        name: "missing-generated",
        units: &[("src/uses_generated.c", "uses_generated.c")],
        entries: &[(".", "src/uses_generated.c", &[])],
        platform: "ilp32.xml",
        style: false,
        suppressions: None,
        status: "blocked",
        ids: &["missingInclude"],
    },
    RealCase {
        name: "missing-system",
        units: &[("src/uses_system.c", "uses_system.c")],
        entries: &[(".", "src/uses_system.c", &[])],
        platform: "ilp32.xml",
        style: false,
        suppressions: None,
        status: "blocked",
        ids: &["missingIncludeSystem"],
    },
    RealCase {
        name: "style-off",
        units: &[("src/style_unread.c", "style_unread.c")],
        entries: &[(".", "src/style_unread.c", &[])],
        platform: "ilp32.xml",
        style: false,
        suppressions: None,
        status: "pass",
        ids: &[],
    },
    RealCase {
        name: "style-on",
        units: &[("src/style_unread.c", "style_unread.c")],
        entries: &[(".", "src/style_unread.c", &[])],
        platform: "ilp32.xml",
        style: true,
        suppressions: None,
        status: "findings_failed",
        ids: &["unreadVariable"],
    },
    RealCase {
        name: "shift-int16",
        units: &[("src/platform_shift.c", "platform_shift.c")],
        entries: &[(".", "src/platform_shift.c", &[])],
        platform: "int16.xml",
        style: false,
        suppressions: None,
        status: "findings_failed",
        ids: &["shiftTooManyBits"],
    },
    RealCase {
        name: "shift-ilp32",
        units: &[("src/platform_shift.c", "platform_shift.c")],
        entries: &[(".", "src/platform_shift.c", &[])],
        platform: "ilp32.xml",
        style: false,
        suppressions: None,
        status: "pass",
        ids: &[],
    },
    RealCase {
        name: "syntax",
        units: &[("src/syntax_broken.c", "syntax_broken.c")],
        entries: &[(".", "src/syntax_broken.c", &[])],
        platform: "ilp32.xml",
        style: false,
        suppressions: None,
        status: "execution_error",
        ids: &["syntaxError"],
    },
    RealCase {
        name: "suppressed-critical-syntax",
        units: &[("src/syntax_broken.c", "syntax_broken.c")],
        entries: &[(".", "src/syntax_broken.c", &[])],
        platform: "ilp32.xml",
        style: false,
        suppressions: Some("syntaxError\n"),
        status: "execution_error",
        ids: &[],
    },
    RealCase {
        name: "gated-on",
        units: &[("src/gated_null.c", "gated_null.c")],
        entries: &[(".", "src/gated_null.c", &["-DBYO_GATED_DEFECT"])],
        platform: "ilp32.xml",
        style: false,
        suppressions: None,
        status: "findings_failed",
        ids: &["nullPointer"],
    },
    RealCase {
        name: "gated-off",
        units: &[("src/gated_null.c", "gated_null.c")],
        entries: &[(".", "src/gated_null.c", &[])],
        platform: "ilp32.xml",
        style: false,
        suppressions: None,
        status: "pass",
        ids: &[],
    },
    RealCase {
        name: "entry-include",
        units: &[
            ("sub/uses_entry_header.c", "uses_entry_header.c"),
            ("sub/inc/entry_local.h", "inc/entry_local.h"),
        ],
        entries: &[("sub", "uses_entry_header.c", &["-Iinc"])],
        platform: "ilp32.xml",
        style: false,
        suppressions: None,
        status: "findings_failed",
        ids: &["nullPointer"],
    },
    RealCase {
        name: "entry-no-include",
        units: &[
            ("sub/uses_entry_header.c", "uses_entry_header.c"),
            ("sub/inc/entry_local.h", "inc/entry_local.h"),
        ],
        entries: &[("sub", "uses_entry_header.c", &[])],
        platform: "ilp32.xml",
        style: false,
        suppressions: None,
        status: "blocked",
        ids: &["missingInclude"],
    },
    RealCase {
        name: "bom-suppression",
        units: &[("src/null_deref.c", "null_deref.c")],
        entries: &[(".", "src/null_deref.c", &[])],
        platform: "ilp32.xml",
        style: false,
        suppressions: Some("\u{feff}nullPointer\n"),
        status: "execution_error",
        ids: &[],
    },
];

#[test]
#[ignore = "needs BYO_CPPCHECK_PACKAGING_INPUTS and BYO_CPPCHECK_SOURCE_DIR"]
fn real_cppcheck_source_cases_classify_like_the_pinned_program() {
    let inputs = real_inputs();
    let real = acceptance_dir().join("real");
    let lab = Lab::create(
        "real-sources",
        PROJECT_NAME,
        Analyzer::Real(&inputs),
        |project| copy_tree(&parity("project"), project),
    );
    for case in REAL_CASES {
        for stale in ["src", "sub", "config"] {
            let _ = fs::remove_dir_all(lab.project.join(stale));
        }
        for (destination, source) in case.units {
            copy_file(&real.join(source), &lab.project.join(destination));
        }
        copy_file(
            &real.join("config").join(case.platform),
            &lab.project.join("config").join(case.platform),
        );
        let entries: Vec<Value> = case
            .entries
            .iter()
            .map(|(directory, file, extra)| {
                let mut arguments = vec!["gcc".to_string()];
                arguments.extend(extra.iter().map(|item| item.to_string()));
                arguments.extend(["-c".to_string(), file.to_string()]);
                json!({"directory": directory, "file": file, "arguments": arguments})
            })
            .collect();
        write_json(&lab.project.join("compile_commands.json"), &json!(entries));
        let mut cppcheck = json!({
            "platform_file": format!("config/{}", case.platform),
            "enable_style": case.style
        });
        if let Some(text) = case.suppressions {
            write(&lab.project.join("config/suppressions.txt"), text);
            cppcheck["suppressions_file"] = json!("config/suppressions.txt");
        }
        lab.config(&json!({"schema_version": 1, "cppcheck": cppcheck}));
        let outcome = lab.verify(None);
        let context = format!("real case {}\n{}", case.name, outcome.context());
        match case.status {
            "pass" => outcome.expect_pass(),
            "execution_error" => {
                outcome.expect_fail();
                assert_eq!(outcome.status(), "execution_error", "{context}");
            }
            status => outcome.expect_outcome(status, classification_code(status)),
        }
        let ids: Vec<&str> = outcome.result()["diagnostics"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item["id"].as_str())
                    .collect()
            })
            .unwrap_or_default();
        for id in case.ids {
            assert!(ids.contains(id), "{id} expected\n{context}");
        }
    }
}
