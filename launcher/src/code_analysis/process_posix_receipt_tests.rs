//! Independent receipt checks for output persistence after real POSIX cleanup.
//! Every case runs the actual owned fork/stop/exec/cleanup/reap path and then
//! observes the kernel directly; receipts are compared with those observations.
use super::*;
use std::path::PathBuf;

/// An unrelated direct child of the test process, outside the owned session.
struct Peer {
    child: std::process::Child,
    identity: Observation,
}
impl Peer {
    fn spawn() -> Self {
        let child = std::process::Command::new("sleep")
            .arg("30")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let identity = observe(child.id() as i32).unwrap().expect("peer identity");
        Self { child, identity }
    }
    fn assert_unaffected(&mut self) {
        assert_eq!(
            self.child.try_wait().unwrap(),
            None,
            "unrelated peer exited"
        );
        let now = observe(self.identity.pid)
            .unwrap()
            .expect("unrelated peer vanished");
        assert!(same(&now, &self.identity) && !now.zombie, "{now:?}");
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Native retained-wait probe: Some(ECHILD) once the direct child is reaped.
fn retained_wait_errno(pid: i32) -> Option<i32> {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let waited = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if waited == 0 {
        None
    } else {
        std::io::Error::last_os_error().raw_os_error()
    }
}

fn echoed(text: &str, key: &str) -> Option<i32> {
    text.lines()
        .find_map(|line| line.strip_prefix(key))
        .and_then(|value| value.trim().parse().ok())
}

/// The exact recorded identity is gone or is no longer a live process.
fn assert_identity_retired(pid: i32, recorded: &Value) {
    if let Some(now) = observe(pid).unwrap() {
        assert!(
            now.zombie || json!(now.start) != *recorded,
            "{pid} is still live with recorded identity {recorded}: {now:?}"
        );
    }
}

struct Call {
    stream: String,
    leader: Option<i32>,
    wait_errno: Option<i32>,
    leader_now: std::result::Result<Option<Observation>, String>,
}

struct Run {
    root: PathBuf,
    argv: Vec<String>,
    result: Result<i64>,
    events: Vec<Value>,
    calls: Vec<Call>,
}
impl Drop for Run {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn run(script: &str, fail: Option<&str>) -> Run {
    let root =
        std::env::temp_dir().join(format!("byo-posix-receipt-{:016x}", rand::random::<u64>()));
    fs::create_dir(&root).unwrap();
    let mut budget = Budget::new();
    budget.configure(5.0).unwrap();
    let argv: Vec<String> = vec!["/bin/sh".into(), "-c".into(), script.into()];
    let mut events = Vec::new();
    let mut calls = Vec::new();
    let result = run_owned_with_persistence(
        &argv,
        &root,
        &budget,
        &root,
        "analysis",
        &mut events,
        None,
        |file, stream| {
            // Observe the kernel at callback time; assertions run after return so
            // a failure cannot panic while run_owned holds SIGNAL_LOCK.
            let leader = fs::read_to_string(root.join("analysis.stdout.log"))
                .ok()
                .and_then(|text| echoed(&text, "pid="));
            calls.push(Call {
                stream: stream.into(),
                leader,
                wait_errno: leader.and_then(retained_wait_errno),
                leader_now: leader
                    .map_or(Ok(None), observe)
                    .map_err(|error| error.to_string()),
            });
            if fail == Some(stream) {
                return Err(std::io::Error::other(format!(
                    "injected {stream} persistence failure"
                )));
            }
            file.sync_all()
        },
    );
    Run {
        root,
        argv,
        result,
        events,
        calls,
    }
}

/// Production history for one successful spawn: the stopped-before-exec
/// identity event, then the terminal receipt for the same leader.
fn terminal_after_startup<'a>(events: &'a [Value], argv: &[String], cwd: &Path) -> &'a Value {
    assert_eq!(events.len(), 2, "{events:?}");
    let (start, terminal) = (&events[0], &events[1]);
    assert_eq!(start["phase"], "analysis", "{start}");
    assert_eq!(start["stopped_before_exec"], true, "{start}");
    assert_eq!(start["argv"], json!(argv), "{start}");
    assert_eq!(start["cwd"], json!(cwd), "{start}");
    assert!(start["start_identity"].is_array(), "{start}");
    assert_eq!(terminal["ownership"], "posix_session", "{terminal}");
    for key in ["phase", "pid", "start_identity", "process_group", "session"] {
        assert_eq!(start[key], terminal[key], "{key}: {start} / {terminal}");
    }
    terminal
}

const SCRIPT: &str = "echo pid=$$; sleep 60 & echo bg=$!; echo diag >&2;";

/// Assert the receipt and kernel state prove cleanup/reap independently of
/// the operation result, then return the receipt.
fn assert_post_reap(run: &Run, exit: i64, streams: &[&str]) -> Value {
    let receipt = terminal_after_startup(&run.events, &run.argv, &run.root).clone();
    let stdout = fs::read_to_string(run.root.join("analysis.stdout.log")).unwrap();
    let stderr = fs::read_to_string(run.root.join("analysis.stderr.log")).unwrap();
    let pid = echoed(&stdout, "pid=").expect("leader pid output");
    let background = echoed(&stdout, "bg=").expect("descendant pid output");
    assert!(stderr.contains("diag"), "{stderr:?}");
    assert_eq!(receipt["pid"], pid, "{receipt}");
    assert_eq!(receipt["process_group"], pid, "{receipt}");
    assert_eq!(receipt["session"], pid, "{receipt}");
    assert_eq!(receipt["ownership"], "posix_session", "{receipt}");
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
    assert!(receipt["execution_error"].is_null(), "{receipt}");
    let descendant = receipt["descendants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["pid"] == background)
        .unwrap_or_else(|| panic!("{background} missing from {receipt}"))
        .clone();
    assert_eq!(descendant["cleanup"], "confirmed", "{receipt}");
    assert_eq!(descendant["session"], pid, "{receipt}");
    assert_eq!(
        run.calls
            .iter()
            .map(|call| call.stream.as_str())
            .collect::<Vec<_>>(),
        streams
    );
    // Persistence ran only after the actual direct child was reaped.
    for call in &run.calls {
        assert_eq!(call.leader, Some(pid));
        assert_eq!(call.wait_errno, Some(libc::ECHILD), "{}", call.stream);
        if let Some(now) = call.leader_now.as_ref().unwrap() {
            assert!(json!(now.start) != receipt["start_identity"], "{now:?}");
        }
    }
    assert_eq!(retained_wait_errno(pid), Some(libc::ECHILD));
    assert_identity_retired(pid, &receipt["start_identity"]);
    assert_identity_retired(background, &descendant["start_identity"]);
    receipt
}

fn assert_persistence_error(run: &Run, receipt: &Value, stream: &str) {
    let error = run.result.as_ref().unwrap_err();
    assert_eq!(error.code, "analysis/evidence-write-failed", "{error:?}");
    assert!(
        error.message.contains(&format!("analysis {stream}:"))
            && error
                .message
                .contains(&format!("injected {stream} persistence failure")),
        "{error:?}"
    );
    assert_eq!(receipt["output_persistence_error"], error.message.as_str());
}

#[test]
fn stdout_persistence_failure_after_normal_exit_keeps_reap_proof() {
    let mut peer = Peer::spawn();
    let run = run(&format!("{SCRIPT} exit 0"), Some("stdout"));
    let receipt = assert_post_reap(&run, 0, &["stdout"]);
    assert_persistence_error(&run, &receipt, "stdout");
    peer.assert_unaffected();
}

#[test]
fn stderr_persistence_failure_after_nonzero_exit_keeps_reap_proof() {
    let mut peer = Peer::spawn();
    let run = run(&format!("{SCRIPT} exit 7"), Some("stderr"));
    let receipt = assert_post_reap(&run, 7, &["stdout", "stderr"]);
    assert_persistence_error(&run, &receipt, "stderr");
    peer.assert_unaffected();
}

#[test]
fn persistence_failure_after_signal_termination_keeps_reap_proof() {
    let mut peer = Peer::spawn();
    let run = run(
        &format!("{SCRIPT} kill -USR1 $$; sleep 5; exit 0"),
        Some("stdout"),
    );
    let receipt = assert_post_reap(&run, -i64::from(libc::SIGUSR1), &["stdout"]);
    assert_persistence_error(&run, &receipt, "stdout");
    peer.assert_unaffected();
}

#[test]
fn successful_persistence_returns_the_exit_after_reap() {
    let mut peer = Peer::spawn();
    let run = run(&format!("{SCRIPT} exit 3"), None);
    let receipt = assert_post_reap(&run, 3, &["stdout", "stderr"]);
    assert_eq!(*run.result.as_ref().unwrap(), 3);
    assert!(receipt["output_persistence_error"].is_null(), "{receipt}");
    peer.assert_unaffected();
}

#[test]
fn startup_failure_stays_unconfirmed_and_never_persists() {
    // Child setup (chdir) fails before the stop/exec boundary. Its direct reap
    // is real, but the covered group/descendant set was never established.
    // Mid-cleanup denial has no unprivileged native seam; the pure denied
    // identity and probe-error controls in `tests` cover that observation path.
    let mut peer = Peer::spawn();
    let root = std::env::temp_dir().join(format!(
        "byo-posix-receipt-startup-{:016x}",
        rand::random::<u64>()
    ));
    fs::create_dir(&root).unwrap();
    let mut budget = Budget::new();
    budget.configure(5.0).unwrap();
    let argv = vec!["/bin/sh".into(), "-c".into(), "exit 0".into()];
    let mut events = Vec::new();
    let mut streams = Vec::new();
    let error = run_owned_with_persistence(
        &argv,
        &root.join("absent-cwd"),
        &budget,
        &root,
        "analysis",
        &mut events,
        None,
        |_, stream| {
            streams.push(stream.to_owned());
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(error.code, "analysis/execution-failed", "{error:?}");
    assert!(streams.is_empty(), "{streams:?}");
    assert_eq!(events.len(), 1, "{events:?}");
    let receipt = &events[0];
    let pid = receipt["pid"].as_i64().unwrap() as i32;
    assert_eq!(receipt["ownership"], "posix_startup", "{receipt}");
    assert_eq!(receipt["exec_started"], false, "{receipt}");
    assert_eq!(receipt["cleanup"], "unconfirmed", "{receipt}");
    assert_eq!(receipt["scope_confirmed"], false, "{receipt}");
    assert_eq!(
        receipt["coverage"], "retained_group_and_captured_descendants",
        "{receipt}"
    );
    assert_eq!(
        receipt["unobserved_detached_descendants"], "not_proven",
        "{receipt}"
    );
    assert_eq!(receipt["leader_reaped"], true, "{receipt}");
    assert_eq!(receipt["terminal_exit_code"], 127, "{receipt}");
    assert!(receipt["start_identity"].is_null(), "{receipt}");
    assert_eq!(receipt["execution_error"], error.message.as_str());
    assert_eq!(retained_wait_errno(pid), Some(libc::ECHILD));
    peer.assert_unaffected();
    fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn production_sync_failure_after_reap_keeps_terminal_exit() {
    // Seam-free: the public run_owned and its real sync_all. Linux rejects fsync
    // on /dev/null, so a pre-placed stderr link fails only at persistence time.
    assert!(
        File::create("/dev/null").unwrap().sync_all().is_err(),
        "precondition: Linux /dev/null rejects fsync"
    );
    let mut peer = Peer::spawn();
    let root = std::env::temp_dir().join(format!(
        "byo-posix-receipt-sync-{:016x}",
        rand::random::<u64>()
    ));
    fs::create_dir(&root).unwrap();
    std::os::unix::fs::symlink("/dev/null", root.join("analysis.stderr.log")).unwrap();
    let mut budget = Budget::new();
    budget.configure(5.0).unwrap();
    let argv: Vec<String> = vec!["/bin/sh".into(), "-c".into(), "echo pid=$$; exit 5".into()];
    let mut events = Vec::new();
    let error = run_owned(&argv, &root, &budget, &root, "analysis", &mut events, None).unwrap_err();
    assert_eq!(error.code, "analysis/evidence-write-failed", "{error:?}");
    assert!(error.message.contains("analysis stderr:"), "{error:?}");
    let receipt = terminal_after_startup(&events, &argv, &root);
    let stdout = fs::read_to_string(root.join("analysis.stdout.log")).unwrap();
    let pid = echoed(&stdout, "pid=").expect("leader pid output");
    assert_eq!(receipt["pid"], pid, "{receipt}");
    assert_eq!(receipt["cleanup"], "confirmed", "{receipt}");
    assert_eq!(receipt["scope_confirmed"], true, "{receipt}");
    assert_eq!(receipt["leader_reaped"], true, "{receipt}");
    assert_eq!(receipt["terminal_exit_code"], 5, "{receipt}");
    assert_eq!(receipt["process_exit_code"], 5, "{receipt}");
    assert!(receipt["cleanup_error"].is_null(), "{receipt}");
    assert_eq!(receipt["output_persistence_error"], error.message.as_str());
    assert_eq!(retained_wait_errno(pid), Some(libc::ECHILD));
    assert_identity_retired(pid, &receipt["start_identity"]);
    peer.assert_unaffected();
    fs::remove_dir_all(root).unwrap();
}
