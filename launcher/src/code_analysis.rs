//! Required selected-build Cppcheck verification for the managed Windows runtime.

mod config;
mod process;
pub(crate) mod runtime;
mod xml;

use config::{load_config, select_scope, Entry};
use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Problem>;
const COVERAGE_IDS: &[&str] = &[
    "missingInclude",
    "missingIncludeSystem",
    "toomanyconfigs",
    "unknownMacro",
    "noValidConfiguration",
    "checkLevelNormal",
    "normalCheckLevelMaxBranches",
    "normalCheckLevelConditionExpressions",
    "cppcheckLimit",
    "includeNestedTooDeeply",
];
const EXECUTION_IDS: &[&str] = &[
    "internalError",
    "cppcheckError",
    "syntaxError",
    "preprocessorErrorDirective",
    "instantiationError",
    "internalAstError",
    "directiveAsMacroParameter",
    "unhandledChar",
    "missingFile",
    "premium-internalError",
    "premium-invalidArgument",
    "premium-invalidLicense",
];

#[derive(Debug)]
pub(crate) struct Problem {
    code: String,
    status: &'static str,
    message: String,
    remedy: String,
    details: Value,
}
impl Problem {
    fn blocked(code: &str, message: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            code: format!("analysis/{code}"),
            status: "blocked",
            message: message.into(),
            remedy: remedy.into(),
            details: json!({}),
        }
    }
    fn execution(code: &str, message: impl Into<String>) -> Self {
        Self {
            status: "execution_error",
            ..Self::blocked(
                code,
                message,
                "Inspect the retained evidence, correct the cause and rerun verify.",
            )
        }
    }
}
impl From<std::io::Error> for Problem {
    fn from(error: std::io::Error) -> Self {
        Self::execution("execution-failed", error.to_string())
    }
}
impl From<serde_json::Error> for Problem {
    fn from(error: serde_json::Error) -> Self {
        Self::execution("execution-failed", error.to_string())
    }
}

/// One clock starts before configuration. A configured budget changes the end,
/// never the start. Cleanup receives reserved time inside this same budget.
pub(crate) struct Budget {
    started: Instant,
    seconds: f64,
}
impl Budget {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            seconds: 120.0,
        }
    }
    fn configure(&mut self, seconds: f64) -> Result<()> {
        if !seconds.is_finite() || seconds <= 0.0 {
            return Err(Problem::blocked(
                "config-invalid",
                "cppcheck.timeout_seconds must be positive and finite.",
                "Use a positive finite timeout.",
            ));
        }
        self.seconds = seconds;
        self.remaining().map(|_| ())
    }
    fn remaining(&self) -> Result<Duration> {
        let seconds = self.seconds - self.started.elapsed().as_secs_f64();
        if seconds <= 0.0 {
            return Err(Problem::execution(
                "timeout",
                "Cppcheck verification deadline expired.",
            ));
        }
        // The public schema permits every positive finite number. Saturating
        // its native wait representation does not impose a second config limit.
        let remaining = Duration::try_from_secs_f64(seconds).unwrap_or(Duration::MAX);
        if remaining.is_zero() {
            Err(Problem::execution(
                "timeout",
                "Cppcheck verification deadline expired.",
            ))
        } else {
            Ok(remaining)
        }
    }
}

fn canonical(path: &Path) -> std::io::Result<PathBuf> {
    let path = path.canonicalize()?;
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        Ok(PathBuf::from(format!(r"\\{rest}")))
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        Ok(PathBuf::from(rest))
    } else {
        Ok(path)
    }
}
fn native(path: &Path) -> String {
    let text = path.to_string_lossy();
    if text.encode_utf16().count() >= 260 && !text.starts_with(r"\\?\") {
        format!(r"\\?\{text}")
    } else {
        text.into_owned()
    }
}
fn read(path: &Path, budget: &Budget) -> Result<Vec<u8>> {
    budget.remaining()?;
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        budget.remaining()?;
        let size = file.read(&mut chunk)?;
        if size == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..size]);
    }
    budget.remaining()?;
    Ok(bytes)
}
fn merge(target: &mut Value, fields: Value) {
    if let Some(fields) = fields.as_object() {
        for (name, value) in fields {
            target[name] = value.clone();
        }
    }
}

#[derive(Debug)]
struct Report {
    diagnostics: Vec<Value>,
    warnings: Vec<String>,
    version: String,
}
fn report_invalid(message: impl Into<String>) -> Problem {
    Problem::execution("report-invalid", message)
}
fn extract_xml(data: &[u8]) -> Result<Vec<u8>> {
    let find = |needle: &[u8]| data.windows(needle.len()).position(|part| part == needle);
    let start = find(b"<?xml")
        .or_else(|| find(b"<results"))
        .ok_or_else(|| report_invalid("Cppcheck did not emit XML."))?;
    let end = data
        .windows(10)
        .rposition(|part| part == b"</results>")
        .ok_or_else(|| report_invalid("Cppcheck XML is incomplete."))?
        + 10;
    if start > end
        || !data[..start].iter().all(u8::is_ascii_whitespace)
        || !data[end..].iter().all(u8::is_ascii_whitespace)
    {
        return Err(report_invalid("Unexplained stderr outside the XML report."));
    }
    Ok(data[start..end].to_vec())
}
fn parse_report(data: &[u8], root: &Path, entries: &[Entry]) -> Result<Report> {
    let document = xml::parse(data).map_err(report_invalid)?;
    let programs = document.named("cppcheck");
    let errors = document.named("errors");
    if document.name != "results"
        || document.attr("version") != Some("2")
        || programs.len() != 1
        || errors.len() != 1
        || programs[0].attr("version").unwrap_or("").is_empty()
    {
        return Err(report_invalid(
            "Report must contain XML-v2 results, one cppcheck version and one errors element.",
        ));
    }
    let mut diagnostics = Vec::new();
    let mut warnings = Vec::new();
    for error in &errors[0].children {
        let id = error.attr("id").unwrap_or("");
        let severity = error.attr("severity").unwrap_or("");
        if error.name != "error"
            || id.is_empty()
            || ![
                "error",
                "warning",
                "performance",
                "portability",
                "style",
                "information",
                "debug",
            ]
            .contains(&severity)
            || error.attr("msg").is_none()
        {
            return Err(report_invalid("Malformed Cppcheck diagnostic record."));
        }
        let mut locations = Vec::new();
        for location in error.named("location") {
            let mut file = location.attr("file").map(String::from);
            if let Some(reported) = &file {
                let path = Path::new(reported);
                if path.is_absolute() {
                    file = Some(
                        canonical(path)
                            .unwrap_or_else(|_| path.to_path_buf())
                            .display()
                            .to_string(),
                    );
                } else {
                    let candidates: std::collections::BTreeSet<_> = std::iter::once(root)
                        .chain(entries.iter().map(|entry| entry.directory.as_path()))
                        .filter_map(|directory| canonical(&directory.join(path)).ok())
                        .filter(|path| path.is_file())
                        .collect();
                    if candidates.len() == 1 {
                        file = Some(candidates.first().unwrap().display().to_string());
                    } else {
                        warnings.push(format!("Location path could not be resolved uniquely: {reported}; preserved as reported."));
                    }
                }
            }
            let coordinate = |name| -> Result<Option<u64>> {
                match location.attr(name) {
                    None | Some("0") => Ok(None),
                    Some(raw) if raw.bytes().all(|c| c.is_ascii_digit()) && !raw.is_empty() => raw
                        .parse::<u64>()
                        .ok()
                        .filter(|n| *n > 0)
                        .map(Some)
                        .ok_or_else(|| {
                            report_invalid(format!("Invalid XML location {name}: {raw}"))
                        }),
                    Some(raw) => Err(report_invalid(format!(
                        "Invalid XML location {name}: {raw}"
                    ))),
                }
            };
            locations.push(
                json!({"file":file,"line":coordinate("line")?,"column":coordinate("column")?}),
            );
        }
        diagnostics.push(json!({"id":id,"severity":severity,"message":error.attr("msg"),"verbose_message":error.attr("verbose"),"inconclusive":error.attr("inconclusive")==Some("true"),"locations":locations}));
    }
    Ok(Report {
        diagnostics,
        warnings,
        version: programs[0].attr("version").unwrap().to_owned(),
    })
}
fn classify(diagnostics: &[Value], exit: i64, style: bool) -> (String, Vec<String>) {
    let mut failures = Vec::new();
    let mut coverage = Vec::new();
    let mut findings = false;
    for diagnostic in diagnostics {
        let id = diagnostic["id"].as_str().unwrap_or("");
        let severity = diagnostic["severity"].as_str().unwrap_or("");
        let message = diagnostic["message"].as_str().unwrap_or("");
        if EXECUTION_IDS.contains(&id) {
            failures.push(format!("{id}: {message}"));
        } else if id == "checkersReport" {
            let text = message
                .strip_suffix(" (use --checkers-report=<filename> to see details)")
                .unwrap_or(message);
            let normal = text.strip_prefix("Active checkers: ").and_then(|text| text.split_once('/')).is_some_and(|(active,total)| {
                !active.is_empty() && !total.is_empty() && active.bytes().chain(total.bytes()).all(|c| c.is_ascii_digit())
                    && matches!((active.parse::<u64>(),total.parse::<u64>()),(Ok(a),Ok(t)) if a > 0 && a <= t)
            });
            let explained = text == "Active checkers: There was critical errors"
                && diagnostics.iter().any(|other| {
                    other["id"]
                        .as_str()
                        .is_some_and(|id| COVERAGE_IDS.contains(&id) || EXECUTION_IDS.contains(&id))
                });
            if !normal && !explained {
                failures.push(format!("Unusable checkersReport: {message}"));
            }
        } else if COVERAGE_IDS.contains(&id) {
            coverage.push(format!("{id}: {message}"));
        } else if ["error", "warning", "performance", "portability"].contains(&severity)
            || severity == "style" && style
        {
            findings = true;
        } else if ["information", "debug"].contains(&severity)
            && !["purgedConfiguration", "unmatchedSuppression"].contains(&id)
        {
            coverage.push(format!(
                "Unclassified {severity} diagnostic for Cppcheck 2.22: {id}: {message}"
            ));
        }
    }
    if ![0, 1].contains(&exit)
        || exit == 1 && !findings && coverage.is_empty() && failures.is_empty()
    {
        failures.push(format!("Unexplained process exit {exit}."));
    }
    if !failures.is_empty() {
        failures.extend(coverage);
        ("execution_error".into(), failures)
    } else if !coverage.is_empty() {
        ("blocked".into(), coverage)
    } else {
        (
            if findings { "findings_failed" } else { "pass" }.into(),
            Vec::new(),
        )
    }
}

fn glob_matches(pattern: &[u8], value: &[u8]) -> bool {
    let (mut p, mut v, mut star, mut mark) = (0, 0, None, 0);
    while v < value.len() {
        if p < pattern.len() && pattern[p] == value[v] {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            mark = v;
        } else if let Some(s) = star {
            p = s + 1;
            mark += 1;
            v = mark;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}
fn validate_suppressions(data: &[u8], budget: &Budget) -> Result<()> {
    // Match the pinned native ID grammar. Do not trim leading whitespace or BOM:
    // those invalid rules must be rejected by Cppcheck, never silently repaired.
    for (index, line) in data.split(|c| *c == b'\r' || *c == b'\n').enumerate() {
        budget.remaining()?;
        let comment = line
            .iter()
            .position(|c| *c == b'#')
            .into_iter()
            .chain(line.windows(2).position(|s| s == b"//"))
            .min();
        let rule = if let Some(end) = comment {
            let mut part = &line[..end];
            while part.last().is_some_and(u8::is_ascii_whitespace) {
                part = &part[..part.len() - 1];
            }
            part
        } else {
            line
        };
        let pattern = rule.split(|c| *c == b':').next().unwrap_or_default();
        if pattern.is_empty()
            || !(pattern[0].is_ascii_alphabetic() || b"_.*-".contains(&pattern[0]))
            || !pattern
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || b"_.*-".contains(c))
        {
            continue;
        }
        let hidden: Vec<_> = COVERAGE_IDS
            .iter()
            .filter(|id| glob_matches(pattern, id.as_bytes()))
            .collect();
        if !hidden.is_empty() {
            return Err(Problem::blocked("config-invalid", format!("cppcheck.suppressions_file line {} can hide coverage diagnostics {hidden:?}: {}", index+1,String::from_utf8_lossy(rule)), "Remove rules matching coverage diagnostics; correct include/build configuration and retain finding suppressions."));
        }
    }
    Ok(())
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}
fn normalize_version(version: &str) -> String {
    if version.split('.').count() == 2 {
        format!("{version}.0")
    } else {
        version.into()
    }
}
fn probe(
    program: &runtime::Program,
    root: &Path,
    budget: &Budget,
    directory: &Path,
    events: &mut Vec<Value>,
) -> Result<String> {
    let argv = vec![program.executable.display().to_string(), "--version".into()];
    let code = process::run_owned(
        &argv,
        root,
        budget,
        directory,
        "version",
        events,
        Some(Duration::from_secs(5)),
    )?;
    let output = read(&directory.join("version.stdout.log"), budget)?;
    let text = String::from_utf8_lossy(&output);
    let text = text.trim();
    let version = text.strip_prefix("Cppcheck ").filter(|v| {
        let parts: Vec<_> = v.split('.').collect();
        [2, 3].contains(&parts.len())
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()))
    });
    if code != 0
        || version.is_none()
        || !read(&directory.join("version.stderr.log"), budget)?.is_empty()
    {
        return Err(Problem::execution(
            "version-failed",
            format!("Cppcheck version probe failed (exit {code}): {text}"),
        ));
    }
    let version = normalize_version(version.unwrap());
    if version != program.version {
        let mut error = Problem::blocked(
            "executable-unavailable",
            format!(
                "Runtime version expected {}, observed {version}.",
                program.version
            ),
            "Restore matching inventoried executable bytes.",
        );
        error.details = json!({"version":version});
        return Err(error);
    }
    if version != "2.22.0" {
        let mut error = Problem::blocked(
            "version-unsupported",
            format!("Diagnostic classification is pinned to Cppcheck 2.22.0; observed {version}."),
            "Use Cppcheck 2.22.0 or validate a new diagnostic corpus.",
        );
        error.details = json!({"version":version});
        return Err(error);
    }
    Ok(version)
}

pub(crate) fn run_cppcheck(
    project: &Path,
    target: &str,
    active: &crate::project::Runtime,
) -> Value {
    run_with_runtime(project, target, &active.root, &active.release)
}
fn run_with_runtime(
    project: &Path,
    target: &str,
    runtime_root: &Path,
    release: &crate::manifest::ReleaseManifest,
) -> Value {
    let mut budget = Budget::new();
    let root = canonical(project).unwrap_or_else(|_| project.to_path_buf());
    let directory = root
        .join(".firm/code-analysis/reports")
        .join(hex::encode(rand::random::<[u8; 16]>()));
    let mut result = json!({"status":"blocked","backend":"cppcheck","code":null,"message":null,"remedy":null,"project_root":root,"compilation_database":null,"compilation_database_sha256":null,"executable":null,"version":null,"executable_origin":null,"executable_sha256":null,"runtime_root":runtime_root,"runtime_manifest_sha256":null,"analysis_mapping_sha256":null,"data_paths":{},"platform_file":null,"scope":{"requested_path":target,"kind":if target=="."{"all"}else{"source"},"translation_units":[],"selected_count":0},"argv":[],"timeout_seconds":120.0,"process_exit_code":null,"diagnostics":[],"coverage_reasons":[],"warnings":[],"report_directory":null,"display_truncated":false,"owned_processes":[],"input_hashes":{},"source_hashes":{}});
    let mut events = Vec::new();
    let execution = (|| -> Result<()> {
        fs::create_dir_all(directory.parent().unwrap())?;
        fs::create_dir(&directory)?;
        result["report_directory"] = json!(directory);
        for name in [
            "version.stdout.log",
            "version.stderr.log",
            "analysis.stdout.log",
            "analysis.stderr.log",
            "report.xml",
        ] {
            fs::write(directory.join(name), [])?;
        }
        let config = load_config(&root, &mut budget)?;
        merge(&mut result, config.summary(&budget));
        if config.platform.is_none() {
            return Err(Problem::blocked(
                "platform-missing",
                "Explicit cppcheck.platform_file target XML is required.",
                "Set cppcheck.platform_file in byo-analysis.json for the selected target ABI.",
            ));
        }
        let (scope, entries) = select_scope(&config, target, &budget)?;
        result["scope"] = serde_json::to_value(&scope)?;
        if scope.kind == "header_all" {
            result["warnings"].as_array_mut().unwrap().push(json!("Header context is inferred from all selected-build translation units; the header has no independent compile command."));
        }
        for snapshot in &config.snapshots {
            result["input_hashes"][snapshot.path.display().to_string()] = json!(snapshot.hash);
        }
        if let Some(path) = &config.suppressions {
            let snapshot = config.snapshots.iter().find(|s| s.path == *path).unwrap();
            snapshot.recheck(&budget)?;
            let bytes = read(path, &budget)?;
            fs::write(directory.join("suppressions.txt"), &bytes)?;
            result["suppressions_file"] = json!(path);
            result["suppressions_sha256"] = json!(snapshot.hash);
            validate_suppressions(&bytes, &budget)?;
        }
        let mut sources = Vec::new();
        for entry in &entries {
            let (snapshot, _) = config::Snapshot::capture(&entry.source, &budget)?;
            result["source_hashes"][entry.source.display().to_string()] = json!(snapshot.hash);
            sources.push(snapshot);
        }
        let program = runtime::resolve(runtime_root, release, &budget)?;
        merge(&mut result, program.fields.clone());
        result["version"] = json!(probe(&program, &root, &budget, &directory, &mut events)?);
        let filtered: Vec<_> = entries
            .iter()
            .map(|entry| {
                let mut raw = entry.raw.clone();
                raw["directory"] = json!(entry.directory);
                raw["file"] = json!(entry.source);
                if raw.get("arguments").is_some() {
                    raw.as_object_mut().unwrap().remove("command");
                }
                raw
            })
            .collect();
        write_json(&directory.join("compile_commands.json"), &filtered)?;
        let enable = format!(
            "warning,performance,portability,information,missingInclude{}",
            if config.style { ",style" } else { "" }
        );
        let mut argv = vec![
            program.executable.display().to_string(),
            format!("--enable={enable}"),
            "--error-exitcode=1".into(),
            "--xml".into(),
            "--xml-version=2".into(),
            "--safety".into(),
            format!(
                "--project={}",
                native(&directory.join("compile_commands.json"))
            ),
            format!("--platform={}", native(config.platform.as_ref().unwrap())),
        ];
        if let Some(path) = &config.suppressions {
            argv.push(format!("--suppressions-list={}", native(path)));
        }
        result["argv"] = json!(argv);
        write_json(&directory.join("argv.json"), &argv)?;
        program.recheck(&budget)?;
        let exit = process::run_owned(
            &argv,
            &root,
            &budget,
            &directory,
            "analysis",
            &mut events,
            None,
        )?;
        result["process_exit_code"] = json!(exit);
        let stderr = read(&directory.join("analysis.stderr.log"), &budget)?;
        fs::write(directory.join("report.xml"), &stderr)?;
        let xml = extract_xml(&stderr)?;
        fs::write(directory.join("report.xml"), &xml)?;
        let report = parse_report(&xml, &root, &entries)?;
        result["diagnostics"] = json!(report.diagnostics);
        result["warnings"]
            .as_array_mut()
            .unwrap()
            .extend(report.warnings.into_iter().map(Value::String));
        if normalize_version(&report.version) != result["version"] {
            return Err(report_invalid(format!(
                "XML version {} differs from probe {}.",
                report.version, result["version"]
            )));
        }
        let output = read(&directory.join("analysis.stdout.log"), &budget)?;
        let output = String::from_utf8_lossy(&output).to_ascii_lowercase();
        if output.contains("cppcheck: error:") || output.contains("cppcheck: warning:") {
            return Err(Problem::execution(
                "execution-failed",
                "Cppcheck reported an execution/configuration problem on stdout.",
            ));
        }
        for snapshot in config.snapshots.iter().chain(&sources) {
            snapshot.recheck(&budget)?;
        }
        if root.join("byo-analysis.json").try_exists()? != config.present {
            return Err(Problem::execution(
                "configuration-changed",
                "byo-analysis.json presence changed during analysis.",
            ));
        }
        program.recheck(&budget)?;
        let (status, reasons) = classify(&report.diagnostics, exit, config.style);
        result["status"] = json!(status);
        result["coverage_reasons"] = json!(reasons
            .iter()
            .filter(|reason| !reason.starts_with("Unexplained"))
            .collect::<Vec<_>>());
        if status != "pass" {
            let mut error=Problem::blocked(if status=="blocked"{"coverage-incomplete"}else if status=="execution_error"{"execution-failed"}else{"findings"},if reasons.is_empty(){"Cppcheck reported actionable findings.".into()}else{reasons.join("; ")},"Correct configuration/coverage problems and findings, then rerun verify; inspect full report evidence.");
            error.status = if status == "blocked" {
                "blocked"
            } else if status == "execution_error" {
                "execution_error"
            } else {
                "findings_failed"
            };
            return Err(error);
        }
        budget.remaining()?;
        Ok(())
    })();
    if let Err(error) = execution {
        merge(&mut result, error.details);
        result["status"] = json!(error.status);
        result["code"] = json!(error.code);
        result["message"] = json!(error.message);
        result["remedy"] = json!(error.remedy);
    }
    result["owned_processes"] = json!(events);
    result["display_truncated"] = json!(
        result["diagnostics"].as_array().unwrap().len()
            + result["warnings"].as_array().unwrap().len()
            > 20
    );
    result["elapsed_seconds"] = json!(budget.started.elapsed().as_secs_f64());
    let retained = (|| -> Result<()> {
        if result["report_directory"].is_null() {
            return Ok(());
        }
        if fs::metadata(directory.join("report.xml"))?.len() == 0 {
            fs::write(
                directory.join("report.xml"),
                fs::read(directory.join("analysis.stderr.log"))?,
            )?;
        }
        write_json(&directory.join("argv.json"), &result["argv"])?;
        write_json(&directory.join("owned-processes.json"), &events)?;
        write_json(&directory.join("result.json"), &result)?;
        if result["status"] == "pass" {
            budget.remaining()?;
        }
        Ok(())
    })();
    if let Err(error) = retained {
        result["status"] = json!("execution_error");
        result["code"] = json!("analysis/evidence-write-failed");
        result["message"] = json!(format!(
            "Cannot retain complete evidence: {}",
            error.message
        ));
        result["remedy"] = json!("Restore writable .firm/code-analysis/reports and rerun.");
        // Best effort error receipt; inability to persist can never become pass.
        let _ = write_json(&directory.join("result.json"), &result);
    }
    result
}
pub(crate) fn render_analysis(result: &Value) -> String {
    let scope = &result["scope"];
    let mut lines = vec![
        format!(
            "Cppcheck {}; {} scope, {} translation units",
            result["status"].as_str().unwrap_or("execution_error"),
            scope["kind"].as_str().unwrap_or("source"),
            scope["selected_count"]
        ),
        format!(
            "executable: {} (version {}, origin {})",
            result["executable"], result["version"], result["executable_origin"]
        ),
        format!(
            "database: {} (SHA-256 {})",
            result["compilation_database"], result["compilation_database_sha256"]
        ),
        format!("platform: {}", result["platform_file"]),
        format!("argv: {}", result["argv"]),
    ];
    let mut display: Vec<_> = result["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_owned())
        .collect();
    display.extend(result["diagnostics"].as_array().unwrap().iter().map(|d| {
        format!(
            "{}:{}: {} [{}]: {}",
            d["locations"][0]["file"],
            d["locations"][0]["line"],
            d["id"],
            d["severity"],
            d["message"]
        )
    }));
    lines.extend(display.into_iter().take(20));
    if result["display_truncated"] == true {
        lines.push("Display truncated to 20 items; full diagnostics/logs are retained.".into());
    }
    if result["status"] != "pass" {
        lines.push(format!(
            "{}\nRemedy: {}",
            result["message"], result["remedy"]
        ));
    }
    lines.push(format!("Evidence: {}", result["report_directory"]));
    lines.join("\n")
}

#[cfg(test)]
mod owner_tests {
    use super::*;
    use serde_json::Value;
    use std::path::PathBuf;

    fn fixtures() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/code-analysis")
    }

    #[test]
    fn shared_xml_exit_contract() {
        let expected: Value =
            serde_json::from_slice(&std::fs::read(fixtures().join("expected.json")).unwrap())
                .unwrap();
        for case in expected["diagnostics"].as_array().unwrap() {
            let data = std::fs::read(fixtures().join(case["xml"].as_str().unwrap())).unwrap();
            let parsed = parse_report(&data, &fixtures(), &[]);
            if case["status"] == "malformed" {
                assert!(parsed.is_err());
            } else {
                let report = parsed.unwrap();
                assert_eq!(
                    classify(
                        &report.diagnostics,
                        case["exit_code"].as_i64().unwrap(),
                        case["style"].as_bool().unwrap_or(false)
                    )
                    .0,
                    case["status"].as_str().unwrap(),
                    "{}",
                    case["xml"]
                );
            }
        }
    }

    #[test]
    fn shared_source_directory_header_scope() {
        let root = canonical(&fixtures().join("project")).unwrap();
        let mut budget = Budget::new();
        let config = load_config(&root, &mut budget).unwrap();
        let expected: Value =
            serde_json::from_slice(&std::fs::read(fixtures().join("expected.json")).unwrap())
                .unwrap();
        for case in expected["selection"].as_array().unwrap() {
            let scope = select_scope(&config, case["target"].as_str().unwrap(), &budget);
            if case["status"] == "blocked" {
                assert_eq!(scope.unwrap_err().code, "analysis/scope-empty");
            } else {
                let (scope, entries) = scope.unwrap();
                assert_eq!(scope.kind, case["kind"].as_str().unwrap());
                let sources: Vec<_> = entries
                    .iter()
                    .map(|entry| {
                        entry
                            .source
                            .strip_prefix(&root)
                            .unwrap()
                            .to_string_lossy()
                            .replace('\\', "/")
                    })
                    .collect();
                let expected: Vec<_> = case["sources"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap())
                    .collect();
                assert_eq!(sources, expected);
            }
        }
    }

    #[test]
    fn suppressions_cannot_hide_coverage_even_with_file_or_line() {
        for rule in [
            "missingInclude",
            "missingIncludeSystem:vendor.h:2",
            "missing*:vendor.h",
            "*:vendor.h:2",
            "unknownMacro",
            "cppcheckLimit",
            "normalCheckLevel*",
        ] {
            assert!(
                validate_suppressions(rule.as_bytes(), &Budget::new()).is_err(),
                "{rule}"
            );
        }
        for rule in [
            "nullPointer:src/a.c:4",
            "// missingInclude",
            "# missingInclude",
            "unreadVariable",
        ] {
            assert!(validate_suppressions(rule.as_bytes(), &Budget::new()).is_ok());
        }
    }

    #[test]
    fn malformed_or_unexplained_output_never_passes() {
        for xml in ["", "<results version=\"2\"><errors/></results>", "<results version=\"2\"><cppcheck version=\"2.22\"/><errors><error id=\"x\" severity=\"novel\" msg=\"x\"/></errors></results>"] {
            assert!(parse_report(xml.as_bytes(), &fixtures(), &[]).is_err());
        }
        assert!(extract_xml(b"garbage<results></results>").is_err());
        assert_eq!(classify(&[], 1, false).0, "execution_error");
        assert_eq!(classify(&[], 2, false).0, "execution_error");
        assert!(parse_report(b"<results xmlns=\"urn:other\" version=\"2\"><cppcheck version=\"2.22\"/><errors/></results>", &fixtures(), &[]).is_err());
    }

    fn copy_project() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "byo-ri-owner-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        for entry in walkdir::WalkDir::new(fixtures().join("project")) {
            let entry = entry.unwrap();
            let path = root.join(
                entry
                    .path()
                    .strip_prefix(fixtures().join("project"))
                    .unwrap(),
            );
            if entry.file_type().is_dir() {
                fs::create_dir_all(path).unwrap();
            } else {
                fs::copy(entry.path(), path).unwrap();
            }
        }
        canonical(&root).unwrap()
    }
    #[test]
    fn strict_schema_abi_and_single_budget() {
        let root = copy_project();
        for (text, field) in [
            (r#"{"schema_version":true}"#, "schema_version"),
            (r#"{"schema_version":1.0}"#, "schema_version"),
            (r#"{"schema_version":1,"extra":true}"#, "extra"),
            (r#"{"schema_version":1,"cppcheck":null}"#, "cppcheck"),
            (
                r#"{"schema_version":1,"cppcheck":{"enable_style":1}}"#,
                "enable_style",
            ),
            (
                r#"{"schema_version":1,"cppcheck":{"timeout_seconds":0}}"#,
                "timeout_seconds",
            ),
            (
                r#"{"schema_version":1,"schema_version":1}"#,
                "schema_version",
            ),
        ] {
            fs::write(root.join("byo-analysis.json"), text).unwrap();
            let error = load_config(&root, &mut Budget::new()).unwrap_err();
            assert_eq!(error.status, "blocked");
            assert!(error.message.contains(field), "{}", error.message);
        }
        fs::copy(
            fixtures().join("project/byo-analysis.json"),
            root.join("byo-analysis.json"),
        )
        .unwrap();
        for platform in ["<platform/>","<platform><char_bit>8</char_bit><default-sign>signed</default-sign><sizeof><int>4</int></sizeof></platform>"] {
            fs::write(root.join("config/platform.xml"),platform).unwrap();
            assert!(load_config(&root,&mut Budget::new()).unwrap_err().message.contains("platform_file"));
        }
        let mut budget = Budget::new();
        budget.started -= Duration::from_secs(1);
        assert_eq!(budget.configure(0.5).unwrap_err().code, "analysis/timeout");
        assert!(budget.remaining().is_err());
        assert!(Budget::new().configure(1e100).is_ok());
    }
    #[test]
    fn clangd_missing_resources_warn_but_drive_relative_syntax_blocks() {
        let root = copy_project();
        let mut settings: Value =
            serde_json::from_slice(&fs::read(root.join("byo-analysis.json")).unwrap()).unwrap();
        settings["clangd"] = json!({"query_driver_paths":["missing/compiler.exe"]});
        write_json(&root.join("byo-analysis.json"), &settings).unwrap();
        assert_eq!(
            load_config(&root, &mut Budget::new())
                .unwrap()
                .warnings
                .len(),
            1
        );
        settings["clangd"]["query_driver_paths"] = json!(["C:compiler.exe"]);
        write_json(&root.join("byo-analysis.json"), &settings).unwrap();
        assert_eq!(
            load_config(&root, &mut Budget::new()).unwrap_err().code,
            "analysis/config-invalid"
        );
    }
    #[test]
    fn shared_database_config_and_command_parity() {
        let root = copy_project();
        let expected: Value =
            serde_json::from_slice(&fs::read(fixtures().join("expected.json")).unwrap()).unwrap();
        let base: Value =
            serde_json::from_slice(&fs::read(root.join("compile_commands.json")).unwrap()).unwrap();
        for case in expected["database_cases"].as_array().unwrap() {
            let mut db = base.clone();
            let mut appended = db[case["append_entry"].as_u64().unwrap() as usize].clone();
            if let Some(value) = case.get("append_argument") {
                appended["arguments"]
                    .as_array_mut()
                    .unwrap()
                    .push(value.clone());
            }
            if let Some(value) = case.get("additional_command") {
                appended["command"] = value.clone();
            }
            db.as_array_mut().unwrap().push(appended);
            write_json(&root.join("compile_commands.json"), &db).unwrap();
            let loaded = load_config(&root, &mut Budget::new());
            if case["status"] == "blocked" {
                assert_eq!(loaded.unwrap_err().code, "analysis/database-conflict");
            } else {
                assert_eq!(
                    loaded.unwrap().entries.len(),
                    case["selected_count"].as_u64().unwrap() as usize
                );
            }
        }
        for case in expected["config_cases"].as_array().unwrap() {
            write_json(&root.join("byo-analysis.json"), &case["json"]).unwrap();
            assert!(load_config(&root, &mut Budget::new())
                .unwrap_err()
                .message
                .contains(case["field"].as_str().unwrap()));
        }
        fs::copy(
            fixtures().join("project/byo-analysis.json"),
            root.join("byo-analysis.json"),
        )
        .unwrap();
        fs::copy(
            fixtures().join("command-only.json"),
            root.join("compile_commands.json"),
        )
        .unwrap();
        let config = load_config(&root, &mut Budget::new()).unwrap();
        assert!(config.entries[0].raw["command"]
            .as_str()
            .unwrap()
            .contains('"'));
    }
    #[test]
    fn only_root_build_candidates_and_real_file_identity() {
        let root = copy_project();
        fs::create_dir(root.join("build")).unwrap();
        fs::copy(
            root.join("compile_commands.json"),
            root.join("build/compile_commands.json"),
        )
        .unwrap();
        assert_eq!(
            load_config(&root, &mut Budget::new()).unwrap_err().code,
            "analysis/database-ambiguous"
        );
        fs::remove_file(root.join("build/compile_commands.json")).unwrap();
        fs::hard_link(
            root.join("compile_commands.json"),
            root.join("build/compile_commands.json"),
        )
        .unwrap();
        assert_eq!(
            load_config(&root, &mut Budget::new())
                .unwrap()
                .entries
                .len(),
            2
        );
        fs::remove_file(root.join("compile_commands.json")).unwrap();
        fs::rename(root.join("build"), root.join("board")).unwrap();
        assert_eq!(
            load_config(&root, &mut Budget::new()).unwrap_err().code,
            "analysis/database-missing"
        );
    }

    #[test]
    fn failed_evidence_creation_cannot_pass_or_launch_a_child() {
        let root = copy_project();
        fs::write(root.join(".firm"), "not a report directory").unwrap();
        // Runtime is deliberately absent; report creation must fail first.
        let release = crate::manifest::ReleaseManifest {
            schema: 1,
            product: "byo".into(),
            version: "0.1.8".into(),
            channel: "preview".into(),
            platform: "windows".into(),
            architecture: "x86_64".into(),
            launcher_protocol: 1,
            sidecar_protocol: 1,
            worker_protocol: 1,
            workflow_protocol: 1,
            capsule_schema: 1,
            project_state_schema: 1,
            development_unsigned: true,
            source: crate::manifest::SourceProvenance {
                installer: crate::manifest::SourceRevision {
                    repository: "test".into(),
                    commit: "test".into(),
                },
                agent_workspace: crate::manifest::SourceRevision {
                    repository: "test".into(),
                    commit: "test".into(),
                },
                firmware_mcp: crate::manifest::SourceRevision {
                    repository: "test".into(),
                    commit: "test".into(),
                },
            },
            toolchain: crate::manifest::ToolchainProvenance {
                rustc: "test".into(),
                cargo: "test".into(),
                python: "unused".into(),
                nuitka: "unused".into(),
            },
            files: Vec::new(),
        };
        let result = run_with_runtime(&root, ".", &root.join("missing-runtime"), &release);
        assert_eq!(result["status"], "execution_error");
        assert!(result["report_directory"].is_null());
        assert!(result["owned_processes"].as_array().unwrap().is_empty());
    }

    /// Explicit source smoke inputs, staged by the lane's read-only input
    /// receipt script. This is intentionally not an installed-product test.
    #[test]
    #[ignore = "requires explicitly staged pinned Windows ARM development inputs"]
    fn pinned_native_arm_and_failure_smoke() {
        let context: Value = serde_json::from_slice(
            &fs::read(
                std::env::var_os("BYO_RI_NATIVE_CONTEXT").expect("explicit owner smoke context"),
            )
            .unwrap(),
        )
        .unwrap();
        let root = canonical(Path::new(context["project"].as_str().unwrap())).unwrap();
        let runtime_root = canonical(Path::new(context["runtime"].as_str().unwrap())).unwrap();
        let mut release = crate::manifest::verify_runtime(&runtime_root).unwrap();
        let mut receipts = Vec::new();
        {
            let mut run = |name: &str,
                           target: &str,
                           expected: &str,
                           release: &crate::manifest::ReleaseManifest| {
                let result = run_with_runtime(&root, target, &runtime_root, release);
                eprintln!("{name}: {}", render_analysis(&result));
                receipts.push(json!({"case":name,"result":result}));
                write_json(Path::new(context["receipt"].as_str().unwrap()), &receipts).unwrap();
                assert_eq!(result["status"], expected, "{name}: {result}");
                for event in result["owned_processes"].as_array().unwrap() {
                    assert!(event["creation_filetime"].as_u64().unwrap() > 0);
                    if event.get("cleanup").is_some() {
                        assert_eq!(event["cleanup"], "confirmed");
                    }
                }
                result
            };
            run("ARM clean", ".", "pass", &release);
            let main = root.join("src/main.c");
            let original = fs::read(&main).unwrap();
            let mut defect = original.clone();
            defect.extend_from_slice(b"\nint owner_null_defect(void) { int *p = 0; return *p; }\n");
            fs::write(&main, &defect).unwrap();
            let defect_result = run("ARM defect", ".", "findings_failed", &release);
            assert_eq!(defect_result["process_exit_code"], 1);
            fs::write(&main, &original).unwrap();
            run("ARM restored", ".", "pass", &release);
            let header = root.join("build/generated/build_config.h");
            let generated = fs::read(&header).unwrap();
            fs::remove_file(&header).unwrap();
            run("missing generated header", ".", "blocked", &release);
            fs::write(&header, &generated).unwrap();
            let header_result = run("header recovered", "include/firmware.h", "pass", &release);
            assert_eq!(header_result["scope"]["kind"], "header_all");
            assert_eq!(header_result["scope"]["selected_count"], 3);
            run("source scope", "src/main.c", "pass", &release);
            run("directory scope", "src", "pass", &release);
            let database = root.join("build/compile_commands.json");
            let original_db = fs::read(&database).unwrap();
            let mut db: Value = serde_json::from_slice(&original_db).unwrap();
            for record in db.as_array_mut().unwrap() {
                record["command"] = json!("NEVER_EXECUTE invalid shell text");
            }
            write_json(&database, &db).unwrap();
            run("argv preferred over command", ".", "pass", &release);
            // Native Cppcheck must interpret command-only quoting, not this runner.
            for record in db.as_array_mut().unwrap() {
                let args = record["arguments"].as_array().unwrap();
                let quoted: Vec<_> = args
                    .iter()
                    .map(|arg| format!("\"{}\"", arg.as_str().unwrap().replace('\\', "/")))
                    .collect();
                record["command"] = json!(quoted.join(" "));
                record.as_object_mut().unwrap().remove("arguments");
            }
            write_json(&database, &db).unwrap();
            run("command-only quoting", ".", "pass", &release);
            fs::write(&database, &original_db).unwrap();
            let config_path = root.join("byo-analysis.json");
            let original_config = fs::read(&config_path).unwrap();
            let mut config: Value = serde_json::from_slice(&original_config).unwrap();
            let mut style_source = original.clone();
            style_source
                .extend_from_slice(b"\nint owner_style(void) { int unused = 42; return 0; }\n");
            fs::write(&main, style_source).unwrap();
            run("style excluded by default", ".", "pass", &release);
            config["cppcheck"]["enable_style"] = json!(true);
            write_json(&config_path, &config).unwrap();
            let styled = run("style explicitly enabled", ".", "findings_failed", &release);
            assert!(styled["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["severity"] == "style"));
            config["cppcheck"]["enable_style"] = json!(false);
            config["cppcheck"]["suppressions_file"] = json!("config/suppressions.txt");
            write_json(&config_path, &config).unwrap();
            let suppression = root.join("config/suppressions.txt");
            fs::write(&main, &defect).unwrap();
            fs::write(&suppression, "nullPointer\n").unwrap();
            run("finding suppression", ".", "pass", &release);
            for (name, rule, status) in [
                (
                    "coverage suppression",
                    "missing*:include/firmware.h:2\n",
                    "blocked",
                ),
                (
                    "BOM invalid suppression",
                    "\u{feff}missingInclude\n",
                    "execution_error",
                ),
                (
                    "leading whitespace invalid suppression",
                    " missingInclude\n",
                    "execution_error",
                ),
            ] {
                fs::write(&suppression, rule).unwrap();
                run(name, ".", status, &release);
            }
            fs::write(&main, &original).unwrap();
            fs::write(&config_path, &original_config).unwrap();
            let std_cfg = runtime_root.join("analysis/cppcheck/cfg/std.cfg");
            let std_bytes = fs::read(&std_cfg).unwrap();
            fs::remove_file(&std_cfg).unwrap();
            run("missing required data", ".", "blocked", &release);
            fs::write(&std_cfg, std_bytes).unwrap();
            let exe = runtime_root.join("analysis/cppcheck/cppcheck.exe");
            let exe_bytes = fs::read(&exe).unwrap();
            fs::remove_file(&exe).unwrap();
            run("missing program", ".", "blocked", &release);
            fs::write(&exe, exe_bytes).unwrap();
            let mapping_path = runtime_root.join("analysis/runtime.json");
            let mapping_bytes = fs::read(&mapping_path).unwrap();
            fs::remove_file(&mapping_path).unwrap();
            run(
                "managed missing mapping never uses PATH",
                ".",
                "blocked",
                &release,
            );
            fs::write(&mapping_path, &mapping_bytes).unwrap();
            let exe_original = fs::read(&exe).unwrap();
            fs::write(&exe, b"untrusted native bytes").unwrap();
            run(
                "managed hash mismatch never uses PATH",
                ".",
                "blocked",
                &release,
            );
            fs::write(&exe, exe_original).unwrap();
            let original_release = release.clone();
            for (case, update) in [
                ("mapping unknown field", json!({"unexpected":1})),
                (
                    "mapping path escape",
                    json!({"executable":"../cppcheck.exe"}),
                ),
            ] {
                let mut modified: Value = serde_json::from_slice(&mapping_bytes).unwrap();
                for (key, value) in update.as_object().unwrap() {
                    modified["programs"]["cppcheck"][key] = value.clone();
                }
                write_json(&mapping_path, &modified).unwrap();
                for leaf in &mut release.files {
                    if leaf.path == "analysis/runtime.json" {
                        leaf.size = fs::metadata(&mapping_path).unwrap().len();
                        leaf.sha256 = crate::manifest::sha256_file(&mapping_path).unwrap();
                    }
                }
                write_json(&runtime_root.join("release-manifest.json"), &release).unwrap();
                run(case, ".", "blocked", &release);
            }
            release = original_release.clone();
            fs::write(&mapping_path, &mapping_bytes).unwrap();
            release.architecture = "aarch64".into();
            write_json(&runtime_root.join("release-manifest.json"), &release).unwrap();
            run("manifest target mismatch", ".", "blocked", &release);
            release = original_release;
            write_json(&runtime_root.join("release-manifest.json"), &release).unwrap();
            // A native fault-injection program exercises an unusable probe. Genuine
            // analysis above always uses the pinned Cppcheck bytes; retain both hashes.
            let original_exe = fs::read(&exe).unwrap();
            fs::copy(context["empty_version_program"].as_str().unwrap(), &exe).unwrap();
            let fault_hash = crate::manifest::sha256_file(&exe).unwrap();
            let fault_size = fs::metadata(&exe).unwrap().len();
            let sbom_path = runtime_root.join("sbom.cdx.json");
            let original_sbom = fs::read(&sbom_path).unwrap();
            let mut sbom: Value = serde_json::from_slice(&original_sbom).unwrap();
            for leaf in sbom["components"].as_array_mut().unwrap() {
                if leaf["name"] == "analysis/cppcheck/cppcheck.exe" {
                    leaf["hashes"] = json!([{"alg":"SHA-256","content":fault_hash}]);
                }
            }
            write_json(&sbom_path, &sbom).unwrap();
            let release_before_fault = release.clone();
            for leaf in &mut release.files {
                if leaf.path == "analysis/cppcheck/cppcheck.exe" {
                    leaf.sha256 = fault_hash.clone();
                    leaf.size = fault_size;
                } else if leaf.path == "sbom.cdx.json" {
                    leaf.sha256 = crate::manifest::sha256_file(&sbom_path).unwrap();
                    leaf.size = fs::metadata(&sbom_path).unwrap().len();
                }
            }
            write_json(&runtime_root.join("release-manifest.json"), &release).unwrap();
            let fault = run(
                "empty version probe (native fault injection)",
                ".",
                "execution_error",
                &release,
            );
            assert_eq!(fault["code"], "analysis/version-failed");
            assert!(fault["process_exit_code"].is_null());
            fs::write(&exe, original_exe).unwrap();
            fs::write(&sbom_path, original_sbom).unwrap();
            release = release_before_fault;
            write_json(&runtime_root.join("release-manifest.json"), &release).unwrap();
            let mut mapping: Value = serde_json::from_slice(&mapping_bytes).unwrap();
            mapping["programs"]["cppcheck"]["version"] = json!("2.21.0");
            write_json(&mapping_path, &mapping).unwrap();
            let sbom_path = runtime_root.join("sbom.cdx.json");
            let sbom_bytes = fs::read(&sbom_path).unwrap();
            let mut sbom: Value = serde_json::from_slice(&sbom_bytes).unwrap();
            for app in sbom["components"].as_array_mut().unwrap() {
                if app["bom-ref"] == "byo-analysis:cppcheck" {
                    app["version"] = json!("2.21.0");
                }
            }
            write_json(&sbom_path, &sbom).unwrap();
            let original_release = release.clone();
            for leaf in &mut release.files {
                if ["analysis/runtime.json", "sbom.cdx.json"].contains(&leaf.path.as_str()) {
                    let path = runtime_root.join(&leaf.path);
                    leaf.size = fs::metadata(&path).unwrap().len();
                    leaf.sha256 = crate::manifest::sha256_file(&path).unwrap();
                }
            }
            write_json(&runtime_root.join("release-manifest.json"), &release).unwrap();
            run("version mismatch", ".", "blocked", &release);
            fs::write(&mapping_path, mapping_bytes).unwrap();
            fs::write(&sbom_path, sbom_bytes).unwrap();
            release = original_release;
            write_json(&runtime_root.join("release-manifest.json"), &release).unwrap();
        }
        let header = root.join("build/generated/build_config.h");
        let paths: crate::paths::ProductPaths =
            serde_json::from_value(context["product_paths"].clone()).unwrap();
        // current.json binds the final staged manifest bytes, never an install.
        let mut current: Value =
            serde_json::from_slice(&fs::read(paths.current()).unwrap()).unwrap();
        current["manifest_sha256"] = json!(crate::manifest::sha256_file(
            &runtime_root.join("release-manifest.json")
        )
        .unwrap());
        write_json(&paths.current(), &current).unwrap();
        let mut verify = |name: &str, expected: i32| {
            let reports = root.join(".firm/code-analysis/reports");
            let before: std::collections::BTreeSet<_> = fs::read_dir(&reports)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            // The existing workflow accepts canonical Windows project roots,
            // including their verbatim prefix, as project::canonical_project does.
            let code =
                crate::workflow::verify_for_owner_test(&root.canonicalize().unwrap(), &paths, &[])
                    .unwrap();
            let after: Vec<_> = fs::read_dir(&reports)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| !before.contains(path))
                .collect();
            assert_eq!(after.len(), 1, "{name}: static analysis exactly once");
            let result: Value =
                serde_json::from_slice(&fs::read(after[0].join("result.json")).unwrap()).unwrap();
            receipts.push(json!({"case":name,"workflow_exit_code":code,"result":result}));
            write_json(Path::new(context["receipt"].as_str().unwrap()), &receipts).unwrap();
            assert_eq!(code, expected, "{name}");
            assert_eq!(
                result["status"], "pass",
                "{name}: analysis after build handling"
            );
        };
        let override_path = root.join("bin/verify-firmware-local");
        fs::create_dir_all(override_path.parent().unwrap()).unwrap();
        fs::copy(
            context["override_program"].as_str().unwrap(),
            &override_path,
        )
        .unwrap();
        fs::remove_file(&header).unwrap();
        verify("local override regenerates header before analysis", 0);
        fs::write(root.join(".owner-build-fail"), "deliberate failed build").unwrap();
        fs::remove_file(&header).unwrap();
        verify(
            "failed local build still analyzes exactly once",
            crate::error::ExitCategory::WorkflowPolicy as i32,
        );
        fs::remove_file(root.join(".owner-build-fail")).unwrap();
        assert_eq!(
            fs::read_to_string(root.join("override-invocations.log"))
                .unwrap()
                .lines()
                .count(),
            2
        );
        fs::remove_file(&override_path).unwrap();
        // Normal native CMake build on the relocated fixture, then one analysis.
        fs::remove_file(&header).unwrap();
        verify("normal ARM CMake build then exactly one analysis", 0);
        let ninja_file = root.join("build/build.ninja");
        let ninja_bytes = fs::read(&ninja_file).unwrap();
        fs::remove_file(&ninja_file).unwrap();
        verify(
            "failed normal CMake build still analyzes exactly once",
            crate::error::ExitCategory::WorkflowPolicy as i32,
        );
        fs::write(&ninja_file, ninja_bytes).unwrap();
    }
}
