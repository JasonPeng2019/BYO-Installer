//! Independent consumer checks: real owned Cppcheck and clangd version probes
//! retain their POSIX receipts through runtime_status and the doctor consumer.
#![cfg(unix)]
use super::native_format::Target;
use super::*;
use crate::manifest::{ReleaseFile, ReleaseManifest};
use std::sync::OnceLock;

// argv[0] selects the role; FAIL keeps both output streams useful.
const FAKE: &str = r#"
fn main() {
    let name = std::env::args().next().unwrap_or_default();
    let cppcheck = std::path::Path::new(&name).file_name().is_some_and(|n| n == "cppcheck");
    if FAIL {
        println!("fixture output");
        eprintln!("fixture failure");
        std::process::exit(if cppcheck { 3 } else { 4 });
    }
    if cppcheck {
        println!("Cppcheck 2.22.0");
    } else {
        println!("clangd version 23.1.0 (fixture)");
    }
}
"#;

fn rustc() -> PathBuf {
    if let Some(rustc) = std::env::var_os("RUSTC") {
        return PathBuf::from(rustc);
    }
    let cargo = std::env::var_os("CARGO")
        .map(PathBuf::from)
        .or_else(|| option_env!("CARGO").map(PathBuf::from));
    if let Some(sibling) = cargo.and_then(|cargo| cargo.parent().map(|dir| dir.join("rustc"))) {
        if sibling.is_file() {
            return sibling;
        }
    }
    PathBuf::from("rustc")
}

/// Compile each native fake once per test binary.
fn fake(fail: bool) -> &'static Path {
    static FAKES: [OnceLock<PathBuf>; 2] = [OnceLock::new(), OnceLock::new()];
    FAKES[usize::from(fail)].get_or_init(|| {
        let directory = std::env::temp_dir().join(format!(
            "byo-receipt-fake-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&directory).unwrap();
        let source = directory.join("fake.rs");
        fs::write(&source, format!("const FAIL: bool = {fail};\n{FAKE}")).unwrap();
        let target = directory.join("fake");
        let output = std::process::Command::new(rustc())
            .args(["--edition", "2021", "-o"])
            .arg(&target)
            .arg(&source)
            .output()
            .expect("rustc must be available to build the native fake analyzer");
        assert!(
            output.status.success(),
            "fake analyzer compilation failed:\n{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        target
    })
}

struct Fixture {
    root: PathBuf,
    release: ReleaseManifest,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Minimal complete inventoried runtime, following runtime.rs's fixture.
fn fixture(cppcheck_fails: bool, clangd_fails: bool) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "byo-receipt-consumer-{:016x}",
        rand::random::<u64>()
    ));
    fs::create_dir(&root).unwrap();
    let root = canonical(&root).unwrap();
    let target = Target::host().unwrap();
    let platform = if cfg!(target_os = "macos") {
        "macos"
    } else {
        std::env::consts::OS
    };
    let mut mapping = json!({"schema_version":1,"platform":platform,"architecture":std::env::consts::ARCH,"programs":{}});
    for (name, fails) in [("cppcheck", cppcheck_fails), ("clangd", clangd_fails)] {
        let executable = target.executable(name);
        fs::create_dir_all(root.join(&executable).parent().unwrap()).unwrap();
        fs::copy(fake(fails), root.join(&executable)).unwrap();
        let mut licenses: Vec<String> = if name == "cppcheck" {
            [
                "COPYING",
                "simplecpp-LICENSE",
                "tinyxml2-LICENSE",
                "picojson-LICENSE",
            ]
            .iter()
            .map(|v| format!("analysis/cppcheck/licenses/{v}"))
            .collect()
        } else {
            vec!["analysis/clangd/LICENSE.TXT".into()]
        };
        if name == "cppcheck" && target == Target::Linux {
            licenses.extend([
                "analysis/cppcheck/licenses/GCC-COPYING3".into(),
                "analysis/cppcheck/licenses/GCC-COPYING.RUNTIME".into(),
            ]);
        }
        for path in &licenses {
            fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
            fs::write(root.join(path), b"fixture notice").unwrap();
        }
        let mut program = json!({"version":if name=="cppcheck" {"2.22.0"} else {"23.1.0"},"executable":executable,"licenses":licenses,"dependencies":[],"sbom_ref":format!("byo-analysis:{name}")});
        if name == "cppcheck" {
            program["cfg_dir"] = json!("analysis/cppcheck/cfg");
            program["platforms_dir"] = json!("analysis/cppcheck/platforms");
            for path in [
                "analysis/cppcheck/cfg/std.cfg",
                "analysis/cppcheck/platforms/target.xml",
            ] {
                fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
                fs::write(root.join(path), b"fixture data").unwrap();
            }
        } else {
            program["resource_dir"] = json!("analysis/clangd/lib/clang/23");
            fs::create_dir_all(root.join("analysis/clangd/lib/clang/23/include")).unwrap();
            fs::write(
                root.join("analysis/clangd/lib/clang/23/include/stddef.h"),
                b"fixture header",
            )
            .unwrap();
        }
        mapping["programs"][name] = program;
    }
    write_json(&root.join("analysis/runtime.json"), &mapping).unwrap();
    let relative = |path: &Path| {
        path.strip_prefix(&root)
            .unwrap()
            .to_str()
            .unwrap()
            .replace('\\', "/")
    };
    let mut components = Vec::new();
    let mut relationships = Vec::new();
    for name in ["cppcheck", "clangd"] {
        let owner = format!("byo-analysis:{name}");
        components.push(json!({"type":"application","bom-ref":owner,"name":name,"version":mapping["programs"][name]["version"],"licenses":[{"expression":"fixture"}],"properties":[{"name":"byo:analysis:upstream","value":"fixture"},{"name":"byo:analysis:recipe","value":"fixture"}]}));
        let mut references = Vec::new();
        for entry in walkdir::WalkDir::new(root.join(format!("analysis/{name}"))) {
            let entry = entry.unwrap();
            if !entry.file_type().is_file() {
                continue;
            }
            let path = relative(entry.path());
            let reference = format!("byo-analysis-file:{path}");
            components.push(json!({"type":"file","bom-ref":reference,"name":path,"hashes":[{"alg":"SHA-256","content":crate::manifest::sha256_file(entry.path()).unwrap()}]}));
            references.push(reference);
        }
        relationships.push(json!({"ref":owner,"dependsOn":references}));
    }
    write_json(
        &root.join("sbom.cdx.json"),
        &json!({"components":components,"dependencies":relationships}),
    )
    .unwrap();
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(&root) {
        let entry = entry.unwrap();
        if !entry.file_type().is_file() {
            continue;
        }
        let path = relative(entry.path());
        let executable =
            [target.executable("cppcheck"), target.executable("clangd")].contains(&path);
        let kind = if executable {
            "analysis-executable"
        } else if path.contains("/licenses/") || path.ends_with("LICENSE.TXT") {
            "license"
        } else if ["analysis/runtime.json", "sbom.cdx.json"].contains(&path.as_str()) {
            "metadata"
        } else {
            "analysis-data"
        };
        files.push(ReleaseFile {
            path,
            sha256: crate::manifest::sha256_file(entry.path()).unwrap(),
            size: entry.metadata().unwrap().len(),
            kind: kind.into(),
            executable,
        });
    }
    let revision = json!({"repository":"fixture","commit":"fixture"});
    let release: ReleaseManifest = serde_json::from_value(json!({"schema":1,"product":"byo","version":"0.1.8","channel":"development","platform":platform,"architecture":std::env::consts::ARCH,"launcher_protocol":1,"sidecar_protocol":1,"worker_protocol":1,"workflow_protocol":1,"capsule_schema":1,"project_state_schema":1,"development_unsigned":true,"source":{"installer":revision,"agent_workspace":revision,"firmware_mcp":revision},"toolchain":{"rustc":"fixture","cargo":"fixture","python":"unused","nuitka":"unused"},"files":files})).unwrap();
    write_json(&root.join("release-manifest.json"), &release).unwrap();
    Fixture { root, release }
}

/// One real owned-session receipt whose exit came from the native fake.
fn assert_receipt(receipt: &Value, phase: &str, exit: i64) {
    assert_eq!(receipt["phase"], phase, "{receipt}");
    assert_eq!(receipt["ownership"], "posix_session", "{receipt}");
    let pid = receipt["pid"].as_i64().unwrap();
    assert!(pid > 0 && pid != i64::from(std::process::id()), "{receipt}");
    assert_eq!(receipt["process_group"], pid, "{receipt}");
    assert_eq!(receipt["session"], pid, "{receipt}");
    assert!(receipt["start_identity"].is_array(), "{receipt}");
    assert_eq!(receipt["cleanup"], "confirmed", "{receipt}");
    assert_eq!(receipt["scope_confirmed"], true, "{receipt}");
    assert_eq!(
        receipt["coverage"], "retained_group_and_captured_descendants",
        "{receipt}"
    );
    assert_eq!(
        receipt["unobserved_detached_descendants"], "not_proven",
        "{receipt}"
    );
    assert_eq!(receipt["leader_reaped"], true, "{receipt}");
    assert_eq!(receipt["terminal_exit_code"], exit, "{receipt}");
    assert_eq!(receipt["process_exit_code"], exit, "{receipt}");
    assert!(receipt["cleanup_error"].is_null(), "{receipt}");
    assert!(receipt["output_persistence_error"].is_null(), "{receipt}");
}

fn receipts(value: &Value) -> &Vec<Value> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("owned_processes missing: {value}"))
}

/// The actual owned history: per probe, the stopped-before-exec event and then
/// the terminal receipt for the same phase/PID/start identity.
fn assert_history(events: &[Value], fixture: &Fixture, phases: &[(&str, i64)]) {
    assert_eq!(events.len(), phases.len() * 2, "{events:?}");
    let target = Target::host().unwrap();
    for (pair, (phase, exit)) in events.chunks(2).zip(phases) {
        let (start, terminal) = (&pair[0], &pair[1]);
        let program = if *phase == "version" {
            "cppcheck"
        } else {
            "clangd"
        };
        let executable = native(&fixture.root.join(target.executable(program)));
        assert_eq!(start["phase"], *phase, "{start}");
        assert_eq!(start["stopped_before_exec"], true, "{start}");
        assert_eq!(start["argv"], json!([executable, "--version"]), "{start}");
        assert_eq!(start["cwd"], json!(fixture.root), "{start}");
        assert_receipt(terminal, phase, *exit);
        for key in ["phase", "pid", "start_identity", "process_group", "session"] {
            assert_eq!(start[key], terminal[key], "{key}: {start} / {terminal}");
        }
    }
}

/// The doctor consumer keeps its former unavailable shape plus the receipts.
fn assert_unavailable(fixture: &Fixture, error: &Problem, phases: &[(&str, i64)]) {
    // Former consumer reason: "{code}: {message} {remedy}".
    assert_eq!(
        error.to_string(),
        format!("{}: {} {}", error.code, error.message, error.remedy)
    );
    let doctor = crate::managed_analysis_status(&fixture.root, &fixture.release).unwrap();
    assert_eq!(doctor["status"], "unavailable", "{doctor}");
    assert_eq!(doctor["reason"], error.to_string(), "{doctor}");
    assert_eq!(doctor["runtime_root"], json!(fixture.root), "{doctor}");
    assert!(doctor["runtime_manifest_sha256"].is_null(), "{doctor}");
    assert!(doctor["analysis_mapping_sha256"].is_null(), "{doctor}");
    assert_eq!(
        doctor["programs"],
        json!({"cppcheck":null,"clangd":null}),
        "{doctor}"
    );
    assert_history(receipts(&doctor["owned_processes"]), fixture, phases);
}

#[test]
fn ready_status_retains_cppcheck_and_clangd_probe_receipts() {
    let fixture = fixture(false, false);
    let status = runtime_status(&fixture.root, &fixture.release).unwrap();
    assert_eq!(status["status"], "ready", "{status}");
    let all = receipts(&status["owned_processes"]);
    assert_history(all, &fixture, &[("version", 0), ("clangd-version", 0)]);
    let cppcheck = &status["programs"]["cppcheck"]["version_probe"];
    let clangd = &status["programs"]["clangd"]["version_probe"];
    assert_eq!(
        cppcheck["stdout"],
        "Cppcheck 2.22.0
",
        "{status}"
    );
    assert_eq!(
        clangd["stdout"],
        "clangd version 23.1.0 (fixture)
"
    );
    // Each program object carries exactly its own full event slice.
    assert_eq!(cppcheck["owned_processes"], json!(&all[..2]), "{status}");
    assert_eq!(clangd["owned_processes"], json!(&all[2..]), "{status}");

    let doctor = crate::managed_analysis_status(&fixture.root, &fixture.release).unwrap();
    assert_eq!(doctor["status"], "ready", "{doctor}");
    let forwarded = receipts(&doctor["owned_processes"]);
    assert_history(
        forwarded,
        &fixture,
        &[("version", 0), ("clangd-version", 0)],
    );
    assert_eq!(
        doctor["programs"]["cppcheck"]["version_probe"]["owned_processes"],
        json!(&forwarded[..2]),
        "{doctor}"
    );
    assert_eq!(
        doctor["programs"]["clangd"]["version_probe"]["owned_processes"],
        json!(&forwarded[2..]),
        "{doctor}"
    );
}

#[test]
fn cppcheck_probe_failure_retains_its_receipt() {
    let fixture = fixture(true, false);
    let error = runtime_status(&fixture.root, &fixture.release).unwrap_err();
    assert_eq!(error.code, "analysis/version-failed", "{error:?}");
    assert!(error.message.contains("(exit 3)"), "{error:?}");
    let retained = receipts(&error.details["owned_processes"]);
    assert_history(retained, &fixture, &[("version", 3)]);
    assert_unavailable(&fixture, &error, &[("version", 3)]);
}

#[test]
fn clangd_probe_failure_retains_both_receipts() {
    let fixture = fixture(false, true);
    let error = runtime_status(&fixture.root, &fixture.release).unwrap_err();
    assert_eq!(error.code, "analysis/executable-unavailable", "{error:?}");
    assert!(error.message.contains("(exit 4)"), "{error:?}");
    let retained = receipts(&error.details["owned_processes"]);
    let phases = [("version", 0), ("clangd-version", 4)];
    assert_history(retained, &fixture, &phases);
    assert_unavailable(&fixture, &error, &phases);
}
