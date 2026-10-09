//! Scripted Windows stand-in for Cppcheck and for firmware build commands.
//!
//! `tests/cppcheck_acceptance.rs` compiles this std-only file with rustc into a
//! genuine AMD64 PE32+ executable and copies it into each private test lab. The
//! file stem selects the role: `cppcheck` is the analyzer, every other stem
//! (`make`, `verify-firmware-local`) is a build command. Behaviour is read from
//! `<lab>/fake-control/control.txt` (`key=value` lines) and every invocation
//! appends one JSON record under `<lab>/fake-control/records/`, so the fake
//! never writes inside the runtime namespace it may be installed in.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct FileTime {
    low: u32,
    high: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> isize;
    fn GetProcessTimes(
        process: isize,
        creation: *mut FileTime,
        exit: *mut FileTime,
        kernel: *mut FileTime,
        user: *mut FileTime,
    ) -> i32;
}

fn creation_time() -> u64 {
    let mut times = [FileTime::default(); 4];
    let ok = unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut times[0],
            &mut times[1],
            &mut times[2],
            &mut times[3],
        )
    };
    if ok == 0 {
        return 0;
    }
    (u64::from(times[0].high) << 32) | u64::from(times[0].low)
}

fn control_dir(exe: &Path) -> PathBuf {
    exe.ancestors()
        .map(|ancestor| ancestor.join("fake-control"))
        .find(|candidate| candidate.is_dir())
        .unwrap_or_else(|| {
            eprintln!(
                "fake tool: no fake-control directory above {}",
                exe.display()
            );
            std::process::exit(97)
        })
}

fn control(dir: &Path) -> Vec<(String, String)> {
    fs::read_to_string(dir.join("control.txt"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let line = line.trim_end_matches('\r');
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=').unwrap_or((line, ""));
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

fn value<'a>(settings: &'a [(String, String)], key: &str) -> Option<&'a str> {
    settings
        .iter()
        .rev()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

fn values<'a>(settings: &'a [(String, String)], key: &str) -> Vec<&'a str> {
    settings
        .iter()
        .filter(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
        .collect()
}

fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_optional(text: Option<String>) -> String {
    text.map(|text| json_string(&text))
        .unwrap_or_else(|| "null".to_string())
}

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0)
}

fn argument_after<'a>(arguments: &'a [String], prefix: &str) -> Option<&'a str> {
    arguments.iter().find_map(|item| item.strip_prefix(prefix))
}

fn read_lossy(path: &str) -> Option<String> {
    fs::read(path)
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

fn record(dir: &Path, phase: &str, exe: &Path, arguments: &[String], extra: &[(&str, String)]) {
    let records = dir.join("records");
    let _ = fs::create_dir_all(&records);
    let pid = std::process::id();
    let cwd = std::env::current_dir()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    let argv = arguments
        .iter()
        .map(|item| json_string(item))
        .collect::<Vec<_>>()
        .join(",");
    let mut body = format!(
        "{{\"phase\":{},\"pid\":{pid},\"creation\":{},\"nanos\":{},\"exe\":{},\"cwd\":{},\"argv\":[{argv}]",
        json_string(phase),
        creation_time(),
        nanos(),
        json_string(&exe.display().to_string()),
        json_string(&cwd),
    );
    for (key, rendered) in extra {
        body.push_str(&format!(",{}:{rendered}", json_string(key)));
    }
    body.push('}');
    let name = format!("{}-{pid}-{phase}", nanos());
    let temporary = records.join(format!("{name}.tmp"));
    if fs::write(&temporary, body.as_bytes()).is_ok() {
        let _ = fs::rename(&temporary, records.join(format!("{name}.json")));
    }
}

fn sleep_forever() -> ! {
    loop {
        std::thread::sleep(Duration::from_secs(600));
    }
}

fn unescape(text: &str) -> String {
    text.replace("\\n", "\n")
}

fn build(dir: &Path, exe: &Path, arguments: &[String], settings: &[(String, String)]) -> i32 {
    record(dir, "build", exe, arguments, &[]);
    for item in values(settings, "build.generate") {
        if let Some((relative, content)) = item.split_once('=') {
            let target = PathBuf::from(relative);
            if let Some(parent) = target.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if fs::write(&target, unescape(content)).is_err() {
                eprintln!("fake build: cannot generate {relative}");
                return 3;
            }
        }
    }
    if value(settings, "build.fail").is_some() {
        println!("SCRIPTED BUILD FAILURE");
        return 2;
    }
    println!("fake build ok");
    0
}

fn descendant(dir: &Path, exe: &Path, arguments: &[String]) -> ! {
    record(dir, "descendant", exe, arguments, &[]);
    sleep_forever()
}

fn spawn_descendant(dir: &Path, exe: &Path) {
    let child = Command::new(exe)
        .arg("--fake-descendant")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let Ok(child) = child else {
        eprintln!("fake analyzer: cannot spawn descendant");
        std::process::exit(96);
    };
    let marker = format!("-{}-descendant.json", child.id());
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let seen = fs::read_dir(dir.join("records"))
            .map(|entries| {
                entries
                    .flatten()
                    .any(|entry| entry.file_name().to_string_lossy().ends_with(&marker))
            })
            .unwrap_or(false);
        if seen {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn version(dir: &Path, exe: &Path, arguments: &[String], settings: &[(String, String)]) -> i32 {
    let mode = value(settings, "version.mode").unwrap_or("ok");
    record(
        dir,
        "version",
        exe,
        arguments,
        &[("mode", json_string(mode))],
    );
    delay(settings, "version.delay_ms");
    match mode {
        "ok" => {
            println!("Cppcheck 2.22.0");
            0
        }
        "wrong" => {
            println!("Cppcheck 2.21.0");
            0
        }
        "garbage" => {
            println!("not a version banner");
            0
        }
        "stderr" => {
            println!("Cppcheck 2.22.0");
            eprintln!("unexpected probe diagnostic");
            0
        }
        "fail" => {
            println!("Cppcheck 2.22.0");
            3
        }
        "hang" => sleep_forever(),
        other => {
            eprintln!("fake analyzer: unknown version.mode {other}");
            98
        }
    }
}

fn analysis(dir: &Path, exe: &Path, arguments: &[String], settings: &[(String, String)]) -> i32 {
    let project = argument_after(arguments, "--project=").map(str::to_string);
    let project_text = project.as_deref().and_then(read_lossy);
    let suppressions_text = argument_after(arguments, "--suppressions-list=").and_then(read_lossy);
    let platform_exists = argument_after(arguments, "--platform=")
        .map(|path| Path::new(path).is_file())
        .unwrap_or(false);
    let required = values(settings, "analysis.require");
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|path| !Path::new(path).is_file())
        .collect();
    let missing_rendered = missing
        .iter()
        .map(|item| json_string(item))
        .collect::<Vec<_>>()
        .join(",");
    let bom_line = suppressions_text
        .as_deref()
        .filter(|text| text.starts_with('\u{feff}'))
        .and_then(|text| text.lines().next())
        .map(|line| line.trim_end_matches('\r').to_string());
    record(
        dir,
        "analysis",
        exe,
        arguments,
        &[
            ("project_file", json_optional(project)),
            ("project_text", json_optional(project_text)),
            ("suppressions_text", json_optional(suppressions_text)),
            ("platform_exists", platform_exists.to_string()),
            ("missing_required", format!("[{missing_rendered}]")),
        ],
    );
    if let (Some(line), Some(_)) = (
        bom_line,
        value(settings, "analysis.reject_bom_suppressions"),
    ) {
        // Pinned Cppcheck 2.22.0 treats a UTF-8 BOM as part of the first
        // suppression id: it reports on stdout, exits 1 and writes no XML.
        println!("cppcheck: error: Failed to add suppression. Invalid id \"{line}\"");
        return 1;
    }
    if value(settings, "analysis.descendant").is_some() {
        spawn_descendant(dir, exe);
    }
    delay(settings, "analysis.delay_ms");
    if value(settings, "analysis.hang").is_some() {
        sleep_forever();
    }
    if value(settings, "analysis.crash").is_some() {
        std::process::abort();
    }
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "Checking fake translation units ...");
    for index in 0..value(settings, "analysis.stdout_lines")
        .and_then(|count| count.parse::<u32>().ok())
        .unwrap_or(0)
    {
        let _ = writeln!(stdout, "FAKE-STDOUT-MARKER-{index:03}");
    }
    if let Some(line) = value(settings, "analysis.stdout_text") {
        let _ = writeln!(stdout, "{}", unescape(line));
    }
    let _ = stdout.flush();
    let mut stderr = std::io::stderr().lock();
    if let Some(text) = value(settings, "analysis.stderr_prefix") {
        let _ = write!(stderr, "{}", unescape(text));
    }
    let report = if missing.is_empty() {
        value(settings, "analysis.xml")
    } else {
        value(settings, "analysis.xml_when_missing").or(value(settings, "analysis.xml"))
    };
    if value(settings, "analysis.no_xml").is_none() {
        if let Some(report) = report {
            match fs::read(report) {
                Ok(bytes) => {
                    let _ = stderr.write_all(&bytes);
                }
                Err(error) => {
                    eprintln!("fake analyzer: cannot read {report}: {error}");
                    return 95;
                }
            }
        }
    }
    let _ = stderr.flush();
    if !missing.is_empty() {
        if let Some(code) = value(settings, "analysis.exit_when_missing") {
            return code.parse().unwrap_or(94);
        }
    }
    value(settings, "analysis.exit")
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

fn delay(settings: &[(String, String)], key: &str) {
    if let Some(ms) = value(settings, key).and_then(|ms| ms.parse::<u64>().ok()) {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

fn main() {
    let exe = std::env::current_exe().unwrap_or_else(|_| std::process::exit(99));
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let dir = control_dir(&exe);
    let settings = control(&dir);
    let stem = exe
        .file_stem()
        .map(|stem| stem.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let in_decoy = exe
        .components()
        .any(|part| part.as_os_str().to_string_lossy() == "path-decoy");
    let code = if in_decoy {
        // A PATH Cppcheck must never be selected by managed resolution; it
        // answers like a real tool so an accidental PATH lookup is visible.
        record(&dir, "decoy", &exe, &arguments, &[]);
        println!("Cppcheck 2.22.0");
        0
    } else if stem == "cppcheck" {
        match arguments.first().map(String::as_str) {
            Some("--fake-descendant") => descendant(&dir, &exe, &arguments),
            Some("--fake-peer") => {
                record(&dir, "peer", &exe, &arguments, &[]);
                sleep_forever()
            }
            Some("--version") if arguments.len() == 1 => version(&dir, &exe, &arguments, &settings),
            _ => analysis(&dir, &exe, &arguments, &settings),
        }
    } else {
        build(&dir, &exe, &arguments, &settings)
    };
    std::process::exit(code);
}
