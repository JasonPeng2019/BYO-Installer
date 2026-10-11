//! Independent macOS checks for one identity observation whose process retires
//! between the live BSD metadata read and getsid. Retirement is real: the exact
//! direct child is killed and natively waited (retained, never reaped) inside
//! the invocation-local session read, before the actual getsid call.
use super::*;

/// A direct child of the test process, outside every owned session.
struct Direct {
    child: std::process::Child,
    identity: Observation,
    reaped: bool,
}
impl Direct {
    fn spawn() -> Self {
        let child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let identity = observe(child.id() as i32)
            .unwrap()
            .expect("direct child identity");
        assert!(!identity.zombie, "{identity:?}");
        Self {
            child,
            identity,
            reaped: false,
        }
    }
    fn assert_live(&mut self) {
        assert_eq!(self.child.try_wait().unwrap(), None, "direct child exited");
        let now = observe(self.identity.pid)
            .unwrap()
            .expect("live direct child vanished");
        assert!(same(&now, &self.identity) && !now.zombie, "{now:?}");
    }
    /// Asserts the BSD snapshot handed to the session read is this live child.
    fn assert_live_snapshot(&self, info: &libc::proc_bsdinfo) {
        assert_eq!(info.pbi_pid as i32, self.identity.pid);
        assert_eq!(
            (info.pbi_start_tvsec, info.pbi_start_tvusec),
            self.identity.start
        );
        assert_ne!(
            info.pbi_status,
            libc::SZOMB,
            "snapshot was already terminal"
        );
    }
}
impl Drop for Direct {
    fn drop(&mut self) {
        // After a manual waitpid the numeric PID is no longer ours to signal.
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Retained native wait for an exact direct child: (si_pid, si_code, si_status),
/// or si_pid 0 while it is live. WNOWAIT keeps the PID reserved.
fn retained_wait(pid: i32, block: bool) -> (i32, i32, i32) {
    let flags = libc::WEXITED | libc::WNOWAIT | if block { 0 } else { libc::WNOHANG };
    loop {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        if unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, flags) } == 0 {
            return unsafe { (info.si_pid(), info.si_code, info.si_status()) };
        }
        let error = std::io::Error::last_os_error();
        assert_eq!(
            error.raw_os_error(),
            Some(libc::EINTR),
            "waitid({pid}): {error}"
        );
    }
}

fn real_getsid(pid: i32) -> std::io::Result<libc::pid_t> {
    let session = unsafe { libc::getsid(pid) };
    if session < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(session)
    }
}

#[test]
fn retirement_after_live_bsd_info_before_getsid_is_absent_not_unknown() {
    let mut target = Direct::spawn();
    let mut peer = Direct::spawn();
    let pid = target.identity.pid;
    let mut staged = None;
    let observed = observe_with_session(pid, |info| {
        target.assert_live_snapshot(info);
        assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
        // Authoritative native wait: the exact child has exited, unreaped.
        assert_eq!(
            retained_wait(pid, true),
            (pid, libc::CLD_KILLED, libc::SIGKILL)
        );
        let session = real_getsid(pid);
        staged = Some(session.as_ref().map(|_| ()).map_err(|e| e.raw_os_error()));
        session
    });
    assert_eq!(
        staged,
        Some(Err(Some(libc::ESRCH))),
        "actual getsid after real retirement"
    );
    // Positive retirement: neither the stale live identity/namespace nor an
    // unknown-identity error.
    assert_eq!(
        observed.expect("positive ESRCH is not an unknown identity"),
        None
    );

    // The retained terminal evidence used by discover/cleanup is intact.
    assert_eq!(
        retained_wait(pid, false),
        (pid, libc::CLD_KILLED, libc::SIGKILL)
    );
    assert_eq!(exited(pid).unwrap(), Some(-i64::from(libc::SIGKILL)));
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    target.reaped = true;
    assert!(libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL);
    assert!(observe(pid)
        .unwrap()
        .is_none_or(|now| !same(&now, &target.identity)));

    peer.assert_live();
}

#[test]
fn live_child_denied_or_unclassified_session_reads_remain_errors() {
    let mut target = Direct::spawn();
    let mut peer = Direct::spawn();
    let pid = target.identity.pid;
    for code in [libc::EPERM, libc::EACCES, libc::EINVAL] {
        let injected = std::io::Error::from_raw_os_error(code);
        let kind = injected.kind();
        let mut calls = 0;
        let error = observe_with_session(pid, |info| {
            calls += 1;
            target.assert_live_snapshot(info);
            Err(std::io::Error::from_raw_os_error(code))
        })
        .expect_err("a live child's failed session read must stay an error");
        assert_eq!(calls, 1);
        assert_eq!(error.kind(), kind, "{error}");
        assert!(
            error.to_string().contains(&format!("getsid({pid})")),
            "{error}"
        );
        // The control never retired or reaped the exact child.
        assert_eq!(retained_wait(pid, false).0, 0);
        target.assert_live();
    }
    peer.assert_live();
}
