use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde::Serialize;
use serde_json::Value;
use walkdir::WalkDir;

use crate::paths::ProductPaths;

const MAX_HOOK_INPUT_BYTES: u64 = 64 * 1024;
const MAX_HOOK_OUTPUT_BYTES: usize = 16 * 1024;
const MAX_GUIDANCE_BYTES: usize = 256 * 1024;
const HANDOFF_CAP: usize = 8_000;
const PLAN_CAP: usize = 4_000;
const TASK_STUB_MARKER: &str = "Auto-created local workspace stub";
const MAX_WORKFLOW_FILE_BYTES: u64 = 1024 * 1024;
const MAX_TRANSCRIPT_BYTES: u64 = 256 * 1024;

fn valid_resource_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub fn print_guidance(project: &Path, skill: &str, paths: &ProductPaths) -> Result<()> {
    if !valid_resource_id(skill) {
        bail!("workflow skill identifier is invalid");
    }
    let runtime = crate::project::active_runtime(paths)?;
    let mode_name = crate::project::capsule_mode(project)?;
    let mode = runtime.pack.mode(&mode_name)?;
    let mut sections = Vec::new();
    for resource in &mode.instruction_resources {
        sections.push(String::from_utf8(runtime.pack.resource(resource)?)?);
    }
    sections.push(String::from_utf8(
        runtime.pack.skill_resource(&mode, skill)?,
    )?);
    let output = sections.join("\n\n---\n\n");
    if output.len() > MAX_GUIDANCE_BYTES {
        bail!("compiled workflow guidance exceeds the output bound");
    }
    print!("{output}");
    if !output.ends_with('\n') {
        println!();
    }
    Ok(())
}

pub fn print_agent(project: &Path, agent: &str, paths: &ProductPaths) -> Result<()> {
    if !valid_resource_id(agent) {
        bail!("workflow agent identifier is invalid");
    }
    crate::project::doctor_project(project, paths)?;
    let runtime = crate::project::active_runtime(paths)?;
    let output = String::from_utf8(runtime.pack.agent_resource(agent)?)?;
    if output.len() > MAX_GUIDANCE_BYTES {
        bail!("compiled agent guidance exceeds the output bound");
    }
    print!("{output}");
    if !output.ends_with('\n') {
        println!();
    }
    Ok(())
}

fn argument_value(arguments: &[String], name: &str) -> Result<Option<String>> {
    let mut found = None;
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == name {
            let value = arguments
                .get(index + 1)
                .with_context(|| format!("{name} requires a value"))?;
            if found.replace(value.clone()).is_some() {
                bail!("{name} may be supplied only once");
            }
            index += 2;
        } else {
            index += 1;
        }
    }
    Ok(found)
}

fn positional_arguments(
    arguments: &[String],
    valued_flags: &[&str],
    bool_flags: &[&str],
) -> Result<Vec<String>> {
    let mut values = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if valued_flags.contains(&argument.as_str()) {
            if index + 1 >= arguments.len() {
                bail!("{argument} requires a value");
            }
            index += 2;
        } else if bool_flags.contains(&argument.as_str()) {
            index += 1;
        } else if argument.starts_with('-') {
            bail!("unsupported workflow tool option: {argument}");
        } else {
            values.push(argument.clone());
            index += 1;
        }
    }
    Ok(values)
}

fn bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        bail!(
            "workflow input is not a bounded regular file: {}",
            path.display()
        );
    }
    std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))
}

fn existing_project_path(project: &Path, raw: &str) -> Result<std::path::PathBuf> {
    let candidate = Path::new(raw);
    let candidate = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        project.join(candidate)
    };
    let resolved = candidate
        .canonicalize()
        .with_context(|| format!("workflow path does not exist: {}", candidate.display()))?;
    if !resolved.starts_with(project) {
        bail!("workflow path escapes the project root");
    }
    Ok(resolved)
}

fn tool_task_path(project: &Path, arguments: &[String]) -> Result<i32> {
    let positional = positional_arguments(arguments, &[], &[])?;
    let relative = match positional.as_slice() {
        [kind] if kind == "plan" => ".agent-workspace/PLAN.md".to_string(),
        [kind] if kind == "handoff" => ".agent-workspace/HANDOFF.md".to_string(),
        [kind, slug]
            if kind == "spec"
                && valid_resource_id(slug)
                && !slug.starts_with('-')
                && !slug.ends_with('-') =>
        {
            format!(".agent-workspace/specs/SPEC-{slug}.md")
        }
        _ => bail!("usage: byo workflow tool task-path <plan|handoff> | spec <slug>"),
    };
    println!("{}", project.join(relative).display());
    Ok(0)
}

fn tool_require_mode(project: &Path, paths: &ProductPaths, arguments: &[String]) -> Result<i32> {
    let positional = positional_arguments(arguments, &[], &[])?;
    if positional.len() < 2 {
        bail!("usage: byo workflow tool require-mode <skill> <allowed-mode>...");
    }
    let runtime = crate::project::active_runtime(paths)?;
    let active = crate::project::capsule_mode(project)?;
    let mode = runtime.pack.mode(&active)?;
    let skill = &positional[0];
    if !mode.skills.iter().any(|allowed| allowed == skill) {
        bail!(
            "skill {skill:?} is not authorized by active mode {}",
            mode.name
        );
    }
    if !positional[1..]
        .iter()
        .any(|allowed| allowed == &mode.name || allowed == &mode.family)
    {
        bail!(
            "skill {skill:?} requires mode {}; current mode is {}",
            positional[1..].join("|"),
            mode.name
        );
    }
    println!(
        "MODE: OK\n  skill   : {skill}\n  current : {} (compiled capsule)",
        mode.name
    );
    Ok(0)
}

fn section<'a>(text: &'a str, heading: &str) -> Option<&'a str> {
    let marker = format!("## {heading}");
    let start = text.find(&marker)? + marker.len();
    let tail = &text[start..];
    let end = tail.find("\n## ").unwrap_or(tail.len());
    Some(&tail[..end])
}

fn concrete_section(value: Option<&str>) -> bool {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            !["todo", "tbd", "<fill", "replace me", "none yet"]
                .iter()
                .any(|placeholder| value.to_ascii_lowercase().contains(placeholder))
        })
        .unwrap_or(false)
}

fn tool_check_plan(project: &Path, arguments: &[String]) -> Result<i32> {
    let raw_path = argument_value(arguments, "--path")?
        .unwrap_or_else(|| ".agent-workspace/PLAN.md".to_string());
    let positional = positional_arguments(arguments, &["--path"], &[])?;
    if !positional.is_empty() {
        bail!("check-plan accepts only --path");
    }
    let path = existing_project_path(project, &raw_path)?;
    let text = String::from_utf8(bounded_file(&path, MAX_WORKFLOW_FILE_BYTES)?)
        .context("PLAN.md is not valid UTF-8")?;
    let requirements = [
        ("Goal", "state a concrete done condition in `## Goal`"),
        ("Milestones", "add concrete milestones in `## Milestones`"),
        (
            "Definition of done",
            "list concrete acceptance criteria in `## Definition of done`",
        ),
        (
            "Verification plan",
            "list concrete checks in `## Verification plan`",
        ),
    ];
    let failures: Vec<_> = requirements
        .iter()
        .filter(|(heading, _)| !concrete_section(section(&text, heading)))
        .map(|(_, remedy)| *remedy)
        .collect();
    println!(
        "PLAN: {}\n  path    : {}",
        if failures.is_empty() { "PASS" } else { "FAIL" },
        path.display()
    );
    if !failures.is_empty() {
        println!("FAILURES");
        for failure in failures {
            println!("  - {failure}");
        }
        return Ok(crate::error::ExitCategory::WorkflowPolicy as i32);
    }
    println!("NEXT: proceed to adversarial PLAN.md review");
    Ok(0)
}

fn command_output(
    project: &Path,
    program: &str,
    arguments: &[&str],
) -> Result<std::process::Output> {
    Command::new(program)
        .args(arguments)
        .current_dir(project)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("failed to execute {program}"))
}

fn tool_risk_status(project: &Path, paths: &ProductPaths, arguments: &[String]) -> Result<i32> {
    let positional = positional_arguments(arguments, &["--mode"], &["--staged", "--worktree"])?;
    if !positional.is_empty()
        || (arguments.contains(&"--staged".to_string())
            && arguments.contains(&"--worktree".to_string()))
    {
        bail!("usage: byo workflow tool risk-status [--staged|--worktree] [--mode <mode>]");
    }
    let active = crate::project::capsule_mode(project)?;
    if let Some(requested) = argument_value(arguments, "--mode")? {
        if requested != active {
            bail!("requested mode {requested} does not match active mode {active}");
        }
    }
    let runtime = crate::project::active_runtime(paths)?;
    let mode = runtime.pack.mode(&active)?;
    let staged = arguments.iter().any(|argument| argument == "--staged");
    let mut name_arguments = vec!["diff", "--name-only"];
    let mut stat_arguments = vec!["diff", "--numstat"];
    if staged {
        name_arguments.push("--cached");
        stat_arguments.push("--cached");
    }
    let names = command_output(project, "git", &name_arguments)?;
    let stats = command_output(project, "git", &stat_arguments)?;
    if !names.status.success() || !stats.status.success() {
        bail!("git diff failed while computing workflow risk");
    }
    let changed: Vec<_> = String::from_utf8(names.stdout)?
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    let (mut added, mut deleted) = (0_u64, 0_u64);
    for line in String::from_utf8(stats.stdout)?.lines() {
        let mut values = line.split('\t');
        added += values
            .next()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        deleted += values
            .next()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
    }
    let mut categories = Vec::new();
    let joined = changed.join("\n").to_ascii_lowercase();
    for trigger in &mode.workflow.one_way_doors {
        let words: Vec<_> = trigger
            .split_whitespace()
            .filter(|word| word.len() >= 4)
            .collect();
        if words
            .iter()
            .any(|word| joined.contains(&word.to_ascii_lowercase()))
        {
            categories.push(trigger.clone());
        }
    }
    if changed.len() > 10 || added + deleted > 300 {
        categories.push("large diff".to_string());
    }
    categories.sort();
    categories.dedup();
    println!(
        "RISK: {}\n  mode    : {}\n  scope   : {}\n  files   : {}\n  stats   : +{} / -{}",
        if categories.is_empty() {
            "NONE"
        } else {
            "PRESENT"
        },
        active,
        if staged { "staged" } else { "worktree" },
        changed.len(),
        added,
        deleted
    );
    if !categories.is_empty() {
        println!("CATEGORIES");
        for category in categories {
            println!("  - {category}");
        }
    }
    Ok(0)
}

fn regex_escape(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        if r"\.^$|?*+()[]{}".contains(character) {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

fn tool_query(project: &Path, arguments: &[String]) -> Result<i32> {
    let positional = positional_arguments(arguments, &["--lang", "--path"], &[])?;
    if positional.len() != 2 {
        bail!("usage: byo workflow tool query <def|refs|imports|type|module-deps> <target> [--path <scope>]");
    }
    let kind = &positional[0];
    let target = &positional[1];
    if target.is_empty() || target.len() > 512 || target.contains('\0') {
        bail!("query target is invalid");
    }
    let scope = argument_value(arguments, "--path")?.unwrap_or_else(|| ".".to_string());
    let scope = existing_project_path(project, &scope)?;
    let escaped = regex_escape(target);
    let pattern = match kind.as_str() {
        "def" => format!(r"\b(class|def|fn|struct|enum|type|#define)\s+{escaped}\b"),
        "refs" | "type" => format!(r"\b{escaped}\b"),
        "imports" => format!(r"\b(import|from|use|include)\b.*\b{escaped}\b"),
        "module-deps" => escaped,
        _ => bail!("unsupported query kind: {kind}"),
    };
    let status = Command::new("rg")
        .args(["--line-number", "--color", "never", "--max-columns", "400"])
        .arg(pattern)
        .arg(scope)
        .current_dir(project)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("query requires ripgrep (`rg`) on PATH")?;
    if status.success() {
        Ok(0)
    } else {
        Ok(crate::error::ExitCategory::WorkflowPolicy as i32)
    }
}

fn program_available(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn run_check(project: &Path, program: &str, arguments: &[String]) -> Result<bool> {
    eprintln!("+ {program} {}", arguments.join(" "));
    let status = Command::new(program)
        .args(arguments)
        .current_dir(project)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("failed to execute verification tool {program}"))?;
    Ok(status.success())
}

fn forbidden_structure_path(path: &Path, patterns: &[String]) -> bool {
    let rendered = path.to_string_lossy();
    patterns.iter().any(|pattern| {
        pattern
            .strip_prefix("*.")
            .map(|suffix| rendered.ends_with(&format!(".{suffix}")))
            .unwrap_or_else(|| path.iter().any(|part| part == pattern.as_str()))
    })
}

fn tool_verify(project: &Path, paths: &ProductPaths, arguments: &[String]) -> Result<i32> {
    let positional = positional_arguments(arguments, &["--backend"], &[])?;
    if positional.len() > 1 {
        bail!("usage: byo workflow tool verify [path] [--backend <software|firmware>]");
    }
    let target = existing_project_path(
        project,
        positional.first().map(String::as_str).unwrap_or("."),
    )?;
    let active = crate::project::capsule_mode(project)?;
    let runtime = crate::project::active_runtime(paths)?;
    let mode = runtime.pack.mode(&active)?;
    if let Some(backend) = argument_value(arguments, "--backend")? {
        if backend != mode.verify.backend {
            bail!(
                "requested verify backend {backend} does not match active backend {}",
                mode.verify.backend
            );
        }
    }
    let mut passed = true;
    for required in &mode.structure.required_dirs {
        if !project.join(required).is_dir() {
            eprintln!("VERIFY: missing required directory {required}");
            passed = false;
        }
    }
    for required in &mode.structure.required_files {
        if !project.join(required).is_file() {
            eprintln!("VERIFY: missing required file {required}");
            passed = false;
        }
    }
    for entry in WalkDir::new(project).follow_links(false) {
        let entry = entry?;
        let relative = entry.path().strip_prefix(project)?;
        if forbidden_structure_path(relative, &mode.structure.forbidden_paths) {
            eprintln!("VERIFY: forbidden project path {}", relative.display());
            passed = false;
        }
    }

    let override_path = project
        .join("bin")
        .join(format!("verify-{}-local", mode.verify.backend));
    let mut substantive = false;
    if override_path.is_file() {
        substantive = true;
        passed &= run_check(
            project,
            override_path.to_string_lossy().as_ref(),
            &[target.display().to_string()],
        )?;
    } else if mode.verify.backend == "software" && project.join("pyproject.toml").is_file() {
        let target_argument = target.display().to_string();
        for (program, arguments) in [
            ("ruff", vec!["check".to_string(), target_argument.clone()]),
            (
                "ruff",
                vec![
                    "format".to_string(),
                    "--check".to_string(),
                    target_argument.clone(),
                ],
            ),
            ("pytest", vec![target_argument.clone()]),
        ] {
            if !program_available(program) {
                eprintln!("VERIFY: required tool is missing: {program}");
                passed = false;
                continue;
            }
            substantive = true;
            passed &= run_check(project, program, &arguments)?;
        }
        let type_checker = ["basedpyright", "pyright"]
            .into_iter()
            .find(|program| program_available(program));
        if let Some(program) = type_checker {
            substantive = true;
            passed &= run_check(project, program, &[target_argument])?;
        } else {
            eprintln!("VERIFY: basedpyright or pyright is required");
            passed = false;
        }
    } else if mode.verify.backend == "firmware" {
        if project.join("build").is_dir() && project.join("CMakeLists.txt").is_file() {
            substantive = true;
            passed &= run_check(
                project,
                "cmake",
                &["--build".to_string(), "build".to_string()],
            )?;
        } else if project.join("Makefile").is_file() {
            substantive = true;
            passed &= run_check(project, "make", &[])?;
        } else {
            eprintln!(
                "VERIFY: firmware project needs a configured CMake build, Makefile, or bin/verify-firmware-local"
            );
            passed = false;
        }
        if program_available("cppcheck") {
            substantive = true;
            passed &= run_check(
                project,
                "cppcheck",
                &[
                    "--enable=warning,style,performance,portability".to_string(),
                    target.display().to_string(),
                ],
            )?;
        }
    } else {
        bail!(
            "unsupported compiled verification backend: {}",
            mode.verify.backend
        );
    }
    if !substantive {
        eprintln!("VERIFY: no substantive verification check ran");
        passed = false;
    }
    println!("VERIFY: {}", if passed { "PASS" } else { "FAIL" });
    Ok(if passed {
        0
    } else {
        crate::error::ExitCategory::WorkflowPolicy as i32
    })
}

#[derive(Serialize)]
struct ReviewRecord<'a> {
    schema: u32,
    kind: &'a str,
    scope: &'a str,
    verdict: &'a str,
    origin: &'a str,
    mode: String,
    subject_sha256: String,
    transcript_sha256: String,
    recorded_at: String,
}

fn tool_record_review(project: &Path, arguments: &[String]) -> Result<i32> {
    let kind = argument_value(arguments, "--kind")?.context("--kind is required")?;
    let origin = argument_value(arguments, "--origin")?.context("--origin is required")?;
    let scope = argument_value(arguments, "--scope")?.context("--scope is required")?;
    let transcript_source =
        argument_value(arguments, "--transcript")?.context("--transcript is required")?;
    let positional = positional_arguments(
        arguments,
        &[
            "--kind",
            "--origin",
            "--scope",
            "--transcript",
            "--plan-path",
            "--mode",
        ],
        &[],
    )?;
    if !positional.is_empty()
        || !["plan", "diff"].contains(&kind.as_str())
        || !["forked", "fallback", "cross-family"].contains(&origin.as_str())
        || !["plan", "staged", "worktree"].contains(&scope.as_str())
    {
        bail!("record-review arguments are invalid");
    }
    let transcript = if transcript_source == "-" {
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(MAX_TRANSCRIPT_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_TRANSCRIPT_BYTES {
            bail!("review transcript is too large");
        }
        String::from_utf8(bytes).context("review transcript is not UTF-8")?
    } else {
        String::from_utf8(bounded_file(
            &existing_project_path(project, &transcript_source)?,
            MAX_TRANSCRIPT_BYTES,
        )?)
        .context("review transcript is not UTF-8")?
    };
    let verdict = ["SHIP", "REVISE", "BLOCK"]
        .into_iter()
        .find(|verdict| {
            transcript
                .lines()
                .any(|line| line.trim() == format!("VERDICT: {verdict}"))
        })
        .context("review transcript must contain one exact VERDICT: SHIP, REVISE, or BLOCK line")?;
    let subject = if kind == "plan" {
        let raw = argument_value(arguments, "--plan-path")?
            .unwrap_or_else(|| ".agent-workspace/PLAN.md".to_string());
        bounded_file(
            &existing_project_path(project, &raw)?,
            MAX_WORKFLOW_FILE_BYTES,
        )?
    } else {
        let mut command = Command::new("git");
        command.arg("diff");
        if scope == "staged" {
            command.arg("--cached");
        }
        let output = command
            .current_dir(project)
            .stdin(Stdio::null())
            .output()
            .context("failed to capture reviewed git diff")?;
        if !output.status.success() {
            bail!("failed to capture reviewed git diff");
        }
        output.stdout
    };
    let active = crate::project::capsule_mode(project)?;
    if let Some(requested) = argument_value(arguments, "--mode")? {
        if requested != active {
            bail!("review mode does not match the active capsule mode");
        }
    }
    let record = ReviewRecord {
        schema: 1,
        kind: &kind,
        scope: &scope,
        verdict,
        origin: &origin,
        mode: active,
        subject_sha256: crate::manifest::sha256_bytes(&subject),
        transcript_sha256: crate::manifest::sha256_bytes(transcript.as_bytes()),
        recorded_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    };
    let path = project
        .join(".firm/workflow/reviews")
        .join(format!("{kind}-{scope}.json"));
    crate::manifest::write_json(&path, &record)?;
    println!(
        "REVIEW: OK\n  kind    : {kind}\n  scope   : {scope}\n  verdict : {verdict}\n  record  : {}",
        path.display()
    );
    Ok(0)
}

pub fn run_tool(
    project: &Path,
    name: &str,
    arguments: &[String],
    paths: &ProductPaths,
) -> Result<i32> {
    crate::project::doctor_project(project, paths)?;
    match name {
        "task-path" => tool_task_path(project, arguments),
        "require-mode" => tool_require_mode(project, paths, arguments),
        "check-plan" => tool_check_plan(project, arguments),
        "record-review" => tool_record_review(project, arguments),
        "risk-status" => tool_risk_status(project, paths, arguments),
        "query" => tool_query(project, arguments),
        "verify" => tool_verify(project, paths, arguments),
        _ => bail!("unknown compiled workflow tool: {name}"),
    }
}

fn read_hook_payload() -> Result<Value> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_HOOK_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_HOOK_INPUT_BYTES {
        bail!("hook input exceeds {} bytes", MAX_HOOK_INPUT_BYTES);
    }
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Object(Default::default()));
    }
    let payload: Value =
        serde_json::from_slice(&bytes).context("hook input is not valid UTF-8 JSON")?;
    let object = payload
        .as_object()
        .context("hook input must be a JSON object")?;
    if let Some(schema) = object.get("schema") {
        if schema.as_u64() != Some(1) {
            bail!("hook input schema is unsupported");
        }
    }
    Ok(payload)
}

fn nested_command(payload: &Value, key: &str) -> Option<String> {
    payload
        .get(key)
        .and_then(Value::as_object)
        .and_then(|value| value.get("command"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn extract_command(payload: &Value) -> String {
    nested_command(payload, "tool_input")
        .or_else(|| nested_command(payload, "toolInput"))
        .or_else(|| {
            payload
                .get("command")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .or_else(|| nested_command(payload, "input"))
        .unwrap_or_default()
}

fn normalize_command(command: &str) -> Result<String> {
    if command.len() > 32 * 1024 || command.contains('\0') {
        bail!("hook command is too large or contains NUL");
    }
    Ok(command.split_whitespace().collect::<Vec<_>>().join(" "))
}

fn dangerous_reason(command: &str, mode: &str) -> Option<&'static str> {
    let normalized = command.to_ascii_lowercase();
    for (needle, reason) in [
        ("rm -rf /", "blocking destructive root delete"),
        (" of=/dev/", "blocking raw device write"),
        ("mkfs", "blocking filesystem format"),
        ("shutdown", "blocking machine control command"),
        ("reboot", "blocking machine control command"),
        ("git reset --hard", "blocking destructive git reset"),
        ("git checkout --", "blocking destructive git checkout"),
    ] {
        if normalized.contains(needle) {
            return Some(reason);
        }
    }
    if (normalized.contains("curl") || normalized.contains("wget"))
        && (normalized.contains("| sh")
            || normalized.contains("| bash")
            || normalized.contains("| zsh"))
    {
        return Some("blocking download-pipe-shell");
    }
    if normalized.contains(".git/")
        && ![
            "git status",
            "git diff",
            "git log",
            "git show",
            "git rev-parse",
        ]
        .iter()
        .any(|allowed| normalized.contains(allowed))
    {
        return Some("direct .git mutation is blocked; use non-destructive git commands only");
    }
    if normalized.contains("west flash") {
        return if mode.starts_with("firmware") {
            Some("blocking unguarded firmware flash action")
        } else {
            Some("west flash requires firmware mode")
        };
    }
    if (normalized.contains("verify-firmware") || normalized.contains("firmware-build"))
        && !mode.starts_with("firmware")
    {
        return Some("firmware backend tooling requires firmware mode");
    }
    None
}

fn bounded_task_content(path: &Path, maximum: usize) -> String {
    let Ok(text) = std::fs::read_to_string(path) else {
        return String::new();
    };
    if text.contains(TASK_STUB_MARKER) || text.trim().is_empty() {
        return String::new();
    }
    let trimmed = text.trim();
    if trimmed.len() <= maximum {
        trimmed.to_string()
    } else {
        format!(
            "{}\n… [truncated at {maximum} bytes; read {} for the rest]",
            &trimmed[..trimmed.floor_char_boundary(maximum)],
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("task file")
        )
    }
}

fn emit_bounded(output: &str) -> Result<()> {
    if output.len() > MAX_HOOK_OUTPUT_BYTES {
        bail!("hook output exceeds {} bytes", MAX_HOOK_OUTPUT_BYTES);
    }
    if !output.is_empty() {
        println!("{output}");
    }
    Ok(())
}

fn hook_guard_dangerous(project: &Path, payload: &Value) -> Result<i32> {
    let command = normalize_command(&extract_command(payload))?;
    if command.is_empty() {
        return Ok(0);
    }
    let mode = crate::project::capsule_mode(project)?;
    if let Some(reason) = dangerous_reason(&command, &mode) {
        eprintln!("{reason}");
        return Ok(2);
    }
    Ok(0)
}

fn hook_precompact(project: &Path) -> Result<i32> {
    let handoff = project.join(".agent-workspace/HANDOFF.md");
    let plan = project.join(".agent-workspace/PLAN.md");
    let mut reminder = String::from(
        "Compact only at a verified slice boundary. Keep PLAN.md, HANDOFF.md, open questions, decisions, and the next command.",
    );
    if !handoff.is_file() {
        reminder.push_str(" Write HANDOFF.md before compaction.");
    }
    if plan.is_file() {
        reminder.push_str(" Confirm PLAN.md reflects the current milestone.");
    }
    emit_bounded(&reminder)?;
    Ok(0)
}

fn hook_sessionstart(project: &Path, payload: &Value) -> Result<i32> {
    let source = payload
        .get("source")
        .or_else(|| payload.get("trigger"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let plan_path = project.join(".agent-workspace/PLAN.md");
    let handoff_path = project.join(".agent-workspace/HANDOFF.md");
    let mode = crate::project::capsule_mode(project)?;
    let mut sections = Vec::new();
    if source != "startup" {
        let handoff = bounded_task_content(&handoff_path, HANDOFF_CAP);
        if !handoff.is_empty() {
            sections.push(format!(
                "--- HANDOFF.md (resume source of truth) ---\n{handoff}"
            ));
        }
        let plan = bounded_task_content(&plan_path, PLAN_CAP);
        if !plan.is_empty() {
            sections.push(format!("--- PLAN.md (head) ---\n{plan}"));
        }
    }
    if sections.is_empty() {
        if plan_path.is_file() {
            sections.push("Read .agent-workspace/PLAN.md before editing.".to_string());
        }
        if handoff_path.is_file() {
            sections.push(
                "Read .agent-workspace/HANDOFF.md; it is the resume source of truth.".to_string(),
            );
        }
    }
    sections.push(format!(
        "Current mode: {mode}. Load a mode-authorized workflow with `byo workflow guidance <skill>`."
    ));
    emit_bounded(&sections.join("\n\n"))?;
    Ok(0)
}

pub fn run_hook(project: &Path, hook_name: &str, paths: &ProductPaths) -> Result<i32> {
    crate::project::doctor_project(project, paths)?;
    let payload = match read_hook_payload() {
        Ok(payload) => payload,
        Err(error) if hook_name == "guard-dangerous" => {
            eprintln!("BYO hook input error: {error:#}; blocking to fail closed.");
            return Ok(2);
        }
        Err(error) => {
            eprintln!("BYO hook input error: {error:#}; continuing advisory hook.");
            return Ok(0);
        }
    };
    match hook_name {
        "guard-dangerous" => hook_guard_dangerous(project, &payload),
        "precompact-handoff" => hook_precompact(project),
        "sessionstart-resume" => hook_sessionstart(project, &payload),
        _ => bail!("unknown stable hook identifier: {hook_name}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dangerous_patterns_and_mode_boundaries_are_deterministic() {
        assert!(dangerous_reason("rm -rf /", "software").is_some());
        assert!(dangerous_reason("west flash", "software").is_some());
        assert!(dangerous_reason("west flash", "firmware").is_some());
        assert!(dangerous_reason("git status --short", "software").is_none());
    }

    #[test]
    fn resource_identifiers_are_bounded() {
        assert!(valid_resource_id("verify-firmware-hil"));
        assert!(!valid_resource_id("../secret"));
        assert!(!valid_resource_id("Uppercase"));
    }
}
