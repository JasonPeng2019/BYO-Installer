//! Owned POSIX sessions. The child stops before exec, so native start identity
//! is captured before any analyzer instruction or descendant can run.
use super::super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::os::unix::{ffi::OsStrExt, io::AsRawFd};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex, TryLockError,
};

static SIGNAL_LOCK: Mutex<()> = Mutex::new(());
static CANCELLED: AtomicBool = AtomicBool::new(false);
extern "C" fn cancelled(_: libc::c_int) {
    CANCELLED.store(true, Ordering::SeqCst);
}
struct Signals(Vec<(i32, libc::sigaction)>);
impl Signals {
    fn install() -> Result<Self> {
        CANCELLED.store(false, Ordering::SeqCst);
        let mut guard = Self(Vec::new());
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = cancelled as *const () as usize;
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
            }
            let mut old = unsafe { std::mem::zeroed() };
            if unsafe { libc::sigaction(signal, &action, &mut old) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            guard.0.push((signal, old));
        }
        Ok(guard)
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        for (signal, old) in &self.0 {
            unsafe {
                libc::sigaction(*signal, old, std::ptr::null_mut());
            }
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Observation {
    pid: i32,
    start: (u64, u64),
    parent: i32,
    group: i32,
    session: i32,
    zombie: bool,
}
#[cfg(target_os = "linux")]
fn observe(pid: i32) -> std::io::Result<Option<Observation>> {
    let text = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let fields: Vec<_> = text
        .rsplit_once(") ")
        .ok_or_else(|| std::io::Error::other("Malformed proc stat"))?
        .1
        .split_whitespace()
        .collect();
    let number = |n: usize| -> std::io::Result<u64> {
        fields
            .get(n)
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| std::io::Error::other("Malformed proc identity"))
    };
    Ok(Some(Observation {
        pid,
        start: (number(19)?, 0),
        parent: number(1)? as i32,
        group: number(2)? as i32,
        session: number(3)? as i32,
        zombie: matches!(fields.first(), Some(&"Z") | Some(&"X")),
    }))
}
#[cfg(target_os = "macos")]
fn observe(pid: i32) -> std::io::Result<Option<Observation>> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let length = std::mem::size_of_val(&info) as i32;
    let read = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            1, // Include zombies so their exact start identity remains observable.
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            length,
        )
    };
    if read != length {
        let e = std::io::Error::last_os_error();
        return if read == 0 && matches!(e.raw_os_error(), Some(libc::ESRCH) | Some(libc::ENOENT)) {
            Ok(None)
        } else {
            Err(std::io::Error::new(
                e.kind(),
                format!("proc_pidinfo({pid}, PROC_PIDTBSDINFO): {e}"),
            ))
        };
    }
    let session = unsafe { libc::getsid(pid) };
    let zombie = info.pbi_status == libc::SZOMB;
    if session < 0
        && !(zombie && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH))
    {
        let error = std::io::Error::last_os_error();
        return Err(std::io::Error::new(
            error.kind(),
            format!("getsid({pid}) during identity observation: {error}"),
        ));
    }
    Ok(Some(Observation {
        pid,
        start: (info.pbi_start_tvsec, info.pbi_start_tvusec),
        parent: info.pbi_ppid as i32,
        group: info.pbi_pgid as i32,
        session: session.max(0),
        zombie,
    }))
}
fn same(a: &Observation, b: &Observation) -> bool {
    a.pid == b.pid && a.start == b.start
}
fn namespace_with(
    owner_session: i32,
    session: impl FnOnce() -> std::io::Result<Option<i32>>,
    group: impl FnOnce() -> std::io::Result<Option<i32>>,
) -> std::io::Result<(Option<i32>, Option<i32>)> {
    let session = session()?;
    // A process group belongs to one session. A fresh different session proves
    // this PID cannot be in our group; avoid an unnecessary denied group query.
    if session.is_some_and(|session| session != owner_session) {
        return Ok((None, session));
    }
    Ok((group()?, session))
}
fn namespace(pid: i32, owner_session: i32) -> std::io::Result<(Option<i32>, Option<i32>)> {
    let checked = |value, call| {
        if value >= 0 {
            Ok(Some(value))
        } else {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(None)
            } else {
                Err(std::io::Error::new(
                    error.kind(),
                    format!("{call}({pid}) namespace prefilter: {error}"),
                ))
            }
        }
    };
    namespace_with(
        owner_session,
        || checked(unsafe { libc::getsid(pid) }, "getsid"),
        || checked(unsafe { libc::getpgid(pid) }, "getpgid"),
    )
}
#[cfg(target_os = "macos")]
fn native_group_members(group: i32, remaining: &impl Fn() -> Result<Duration>) -> Result<Vec<i32>> {
    // Darwin sys/proc_info.h: PROC_PGRP_ONLY = 2. Query the kernel group list,
    // including members sysinfo could not populate, before confirming cleanup.
    let mut pids = vec![0i32; 32];
    loop {
        remaining()?;
        let bytes = i32::try_from(pids.len() * std::mem::size_of::<i32>())
            .map_err(|_| Problem::execution("cleanup-failed", "Native group list is too large"))?;
        // libproc converts syscall failure to zero. Clear errno so an empty
        // successful list cannot be confused with a denied/failed enumeration.
        let read = unsafe {
            *libc::__error() = 0;
            libc::proc_listpids(2, group as u32, pids.as_mut_ptr().cast(), bytes)
        };
        let error = std::io::Error::last_os_error();
        if read < 0 || (read == 0 && error.raw_os_error() != Some(0)) {
            return Err(Problem::execution(
                "cleanup-failed",
                format!("proc_listpids(PROC_PGRP_ONLY, {group}): {}", error),
            ));
        }
        if read % std::mem::size_of::<i32>() as i32 != 0 {
            return Err(Problem::execution(
                "cleanup-failed",
                "Malformed native group list",
            ));
        }
        if read < bytes {
            pids.truncate(read as usize / std::mem::size_of::<i32>());
            pids.retain(|pid| *pid > 0);
            return Ok(pids);
        }
        pids.resize(pids.len() * 2, 0);
    }
}
fn observe_candidates(
    candidates: BTreeSet<i32>,
    remaining: &impl Fn() -> Result<Duration>,
    mut observation: impl FnMut(i32) -> Result<Option<Observation>>,
) -> Result<Vec<Observation>> {
    let mut values = Vec::new();
    for pid in candidates {
        remaining()?;
        if let Some(value) = observation(pid)? {
            values.push(value);
        }
    }
    Ok(values)
}
fn candidate_pids(
    leader: &Observation,
    owned: &BTreeMap<i32, Observation>,
    parents: &[(i32, Option<i32>)],
    membership: impl Fn(i32) -> std::io::Result<(Option<i32>, Option<i32>)>,
    remaining: &impl Fn() -> Result<Duration>,
) -> Result<BTreeSet<i32>> {
    // These are candidates for strict native observation, not ownership proof.
    // Always retain captured PIDs, including detached children omitted by sysinfo.
    let mut candidates: BTreeSet<_> = owned.keys().copied().collect();
    candidates.insert(leader.pid);
    for (pid, _) in parents {
        remaining()?;
        if !candidates.contains(pid) {
            let (group, session) = membership(*pid)?;
            if group == Some(leader.group) || session == Some(leader.session) {
                candidates.insert(*pid);
            }
        }
    }
    loop {
        let mut changed = false;
        for (pid, parent) in parents {
            remaining()?;
            if parent.is_some_and(|parent| candidates.contains(&parent)) {
                changed |= candidates.insert(*pid);
            }
        }
        if !changed {
            return Ok(candidates);
        }
    }
}
fn table(
    leader: &Observation,
    owned: &BTreeMap<i32, Observation>,
    remaining: &impl Fn() -> Result<Duration>,
) -> Result<Vec<Observation>> {
    // Fresh sysinfo enumeration supplies process IDs, never cached image identity.
    let mut system = sysinfo::System::new();
    remaining()?;
    system.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::All,
        true,
        sysinfo::ProcessRefreshKind::nothing(),
    );
    let parents: Vec<_> = system
        .processes()
        .iter()
        .filter(|(pid, _)| pid.as_u32() > 0)
        .map(|(pid, process)| {
            (
                pid.as_u32() as i32,
                process.parent().map(|parent| parent.as_u32() as i32),
            )
        })
        .collect();
    let candidates = candidate_pids(
        leader,
        owned,
        &parents,
        |pid| namespace(pid, leader.session),
        remaining,
    )?;
    #[cfg(target_os = "macos")]
    let candidates = {
        let mut candidates = candidates;
        candidates.extend(native_group_members(leader.group, remaining)?);
        candidates
    };
    observe_candidates(candidates, remaining, |pid| {
        if pid == leader.pid && exited(leader.pid)?.is_some() {
            let mut terminal = leader.clone();
            terminal.zombie = true;
            return Ok(Some(terminal));
        }
        // macOS can deny proc_pidinfo for unrelated protected processes. Only
        // inspect candidates, and never suppress a candidate's identity error.
        observe(pid).map_err(|error| {
            Problem::execution(
                "execution-failed",
                format!("observe owned candidate PID {pid}: {error}"),
            )
        })
    })
}
fn discover(
    leader: &Observation,
    owned: &mut BTreeMap<i32, Observation>,
    remaining: &impl Fn() -> Result<Duration>,
) -> Result<Vec<Observation>> {
    let mut values = table(leader, owned, remaining)?;
    if !values.iter().any(|value| same(value, leader)) && exited(leader.pid)?.is_some() {
        // A retained WNOWAIT child is still the exact child captured before
        // exec. Its wait proof remains valid when the live native view is gone.
        let mut terminal = leader.clone();
        terminal.zombie = true;
        values.push(terminal);
    }
    loop {
        let mut changed = false;
        for value in &values {
            remaining()?;
            let parent = values.iter().find(|p| p.pid == value.parent);
            let related = parent.is_some_and(|p| owned.get(&p.pid).is_some_and(|old| same(old, p)));
            if value.session == leader.session || related {
                match owned.get(&value.pid) {
                    Some(old) if same(old, value) => {}
                    _ => {
                        owned.insert(value.pid, value.clone());
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
    Ok(values)
}
fn signal_exact(value: &Observation, signal: i32) -> Result<()> {
    if let Some(current) = observe(value.pid)? {
        if same(value, &current) && !current.zombie && unsafe { libc::kill(value.pid, signal) } != 0
        {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::ESRCH) {
                return Err(Problem::execution(
                    "execution-failed",
                    format!(
                        "kill({}, {signal}) after exact identity {:?}: {e}",
                        value.pid, value.start
                    ),
                ));
            }
        }
    }
    Ok(())
}
struct Owned {
    leader: Observation,
    descendants: BTreeMap<i32, Observation>,
    reaped: bool,
}
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.reaped {
            // The unreaped direct child reserves this PID/session identity.
            unsafe {
                libc::kill(-self.leader.group, libc::SIGKILL);
            }
            for value in self.descendants.values() {
                let _ = signal_exact(value, libc::SIGKILL);
            }
            unsafe {
                libc::waitpid(self.leader.pid, std::ptr::null_mut(), libc::WNOHANG);
            }
        }
    }
}
fn exited(pid: i32) -> Result<Option<i64>> {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // WNOWAIT retains the direct child, preventing PID/group reuse until cleanup.
    if unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    } != 0
    {
        let e = std::io::Error::last_os_error();
        return if e.raw_os_error() == Some(libc::EINTR) {
            Ok(None)
        } else {
            Err(Problem::execution(
                "execution-failed",
                format!("waitid({pid}, WNOWAIT): {e}"),
            ))
        };
    }
    if unsafe { info.si_pid() } == 0 {
        return Ok(None);
    }
    let status = unsafe { info.si_status() };
    Ok(Some(if info.si_code == libc::CLD_EXITED {
        i64::from(status)
    } else {
        -i64::from(status)
    }))
}
fn cstring(value: &std::ffi::OsStr) -> Result<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| Problem::execution("execution-failed", "NUL in native process input"))
}

pub(in crate::code_analysis) fn run_owned(
    argv: &[String],
    cwd: &Path,
    budget: &Budget,
    directory: &Path,
    phase: &str,
    events: &mut Vec<Value>,
    phase_limit: Option<Duration>,
) -> Result<i64> {
    let phase_start = Instant::now();
    budget.remaining()?;
    if argv.is_empty() {
        return Err(Problem::execution("execution-failed", "Empty native argv"));
    }
    let arguments: Vec<_> = argv
        .iter()
        .map(|v| cstring(std::ffi::OsStr::new(v)))
        .collect::<Result<_>>()?;
    let mut pointers: Vec<_> = arguments.iter().map(|v| v.as_ptr()).collect();
    pointers.push(std::ptr::null());
    let environment: Vec<_> = std::env::vars_os()
        .filter(|(key, _)| {
            let key = key.to_string_lossy();
            !key.starts_with("DYLD_") && !key.starts_with("LD_")
        })
        .map(|(key, value)| {
            let mut text = key;
            text.push("=");
            text.push(value);
            cstring(&text)
        })
        .collect::<Result<_>>()?;
    let mut envp: Vec<_> = environment.iter().map(|v| v.as_ptr()).collect();
    envp.push(std::ptr::null());
    let cwd_native = cstring(cwd.as_os_str())?;
    let out = File::create(directory.join(format!("{phase}.stdout.log")))?;
    let err = File::create(directory.join(format!("{phase}.stderr.log")))?;
    let input = File::open("/dev/null")?;
    let remaining = || -> Result<Duration> {
        let mut left = budget.remaining()?;
        if let Some(limit) = phase_limit {
            left =
                left.min(limit.checked_sub(phase_start.elapsed()).ok_or_else(|| {
                    Problem::execution("timeout", "Version phase deadline expired")
                })?);
        }
        if left.is_zero() {
            return Err(Problem::execution("timeout", "Process deadline expired"));
        }
        Ok(left)
    };
    let _lock = loop {
        match SIGNAL_LOCK.try_lock() {
            Ok(guard) => break guard,
            Err(TryLockError::WouldBlock) => {
                std::thread::sleep(Duration::from_millis(2).min(remaining()?));
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(Problem::execution(
                    "execution-failed",
                    "Signal ownership lock poisoned",
                ));
            }
        }
    };
    let signals = Signals::install()?;
    let reserve = Duration::from_millis(1500).min(remaining()? / 4);
    let execution_budget = phase_start.elapsed() + remaining()?.saturating_sub(reserve);
    let mut pipe = [0; 2];
    if unsafe { libc::pipe(pipe.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // Own both pipe ends with File before any later fallible operation.
    use std::os::unix::io::FromRawFd;
    let reader = unsafe { File::from_raw_fd(pipe[0]) };
    let writer = unsafe { File::from_raw_fd(pipe[1]) };
    if unsafe { libc::fcntl(pipe[1], libc::F_SETFD, libc::FD_CLOEXEC) } < 0
        || unsafe { libc::fcntl(pipe[0], libc::F_SETFL, libc::O_NONBLOCK) } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if pid == 0 {
        // After fork use only async-signal-safe syscalls and preallocated inputs.
        unsafe {
            libc::close(pipe[0]);
            for (signal, old) in &signals.0 {
                libc::sigaction(*signal, old, std::ptr::null_mut());
            }
            let ready = libc::setsid() >= 0
                && libc::chdir(cwd_native.as_ptr()) == 0
                && libc::dup2(input.as_raw_fd(), 0) >= 0
                && libc::dup2(out.as_raw_fd(), 1) >= 0
                && libc::dup2(err.as_raw_fd(), 2) >= 0;
            if ready {
                libc::raise(libc::SIGSTOP);
                libc::execve(arguments[0].as_ptr(), pointers.as_ptr(), envp.as_ptr());
            }
            #[cfg(target_os = "linux")]
            let errno = *libc::__errno_location();
            #[cfg(target_os = "macos")]
            let errno = *libc::__error();
            libc::write(
                pipe[1],
                (&errno as *const i32).cast(),
                std::mem::size_of::<i32>(),
            );
            libc::_exit(127);
        }
    }
    drop(writer);
    let mut startup_reaped = false;
    let startup = (|| -> Result<Observation> {
        loop {
            remaining()?;
            if CANCELLED.load(Ordering::SeqCst) {
                return Err(Problem::execution(
                    "cancelled",
                    "Owned analysis cancelled during startup",
                ));
            }
            let mut status = 0;
            let waited =
                unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::WUNTRACED) };
            if waited == pid {
                if !libc::WIFSTOPPED(status) {
                    startup_reaped = true;
                    return Err(Problem::execution(
                        "execution-failed",
                        "Native child setup failed before exec",
                    ));
                }
                let leader = observe(pid)?.ok_or_else(|| {
                    Problem::execution("cleanup-failed", "Stopped child identity unavailable")
                })?;
                if leader.group != pid || leader.session != pid {
                    return Err(Problem::execution(
                        "cleanup-failed",
                        "Native session ownership not established",
                    ));
                }
                return Ok(leader);
            }
            if waited < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                    startup_reaped = true;
                }
                return Err(std::io::Error::last_os_error().into());
            }
            std::thread::sleep(Duration::from_millis(2).min(remaining()?));
        }
    })();
    let leader = match startup {
        Ok(leader) => leader,
        Err(error) => {
            // A stopped or running direct child is still ours; never signal a
            // numeric PID after waitpid has already reaped that child.
            if !startup_reaped {
                let mut status = 0;
                let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if waited == pid {
                    startup_reaped = true;
                } else if waited == 0 {
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                    }
                    while remaining().is_ok() {
                        if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } == pid {
                            startup_reaped = true;
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(2));
                    }
                }
            }
            events.push(json!({"phase":phase,"pid":pid,"cleanup":if startup_reaped {"confirmed"} else {"unconfirmed"},"ownership":"posix_startup","exec_started":false}));
            return Err(error);
        }
    };
    events.push(json!({"phase":phase,"pid":pid,"start_identity":leader.start,"process_group":leader.group,"session":leader.session,"argv":argv,"cwd":cwd,"stopped_before_exec":true}));
    let mut owned = Owned {
        leader: leader.clone(),
        descendants: BTreeMap::from([(pid, leader)]),
        reaped: false,
    };
    let execution = (|| -> Result<i64> {
        signal_exact(&owned.leader, libc::SIGCONT)?;
        loop {
            discover(&owned.leader, &mut owned.descendants, &remaining)?;
            if CANCELLED.load(Ordering::SeqCst) {
                return Err(Problem::execution(
                    "cancelled",
                    "Owned analysis cancelled by signal",
                ));
            }
            let mut errno = 0i32;
            let count = unsafe {
                libc::read(
                    reader.as_raw_fd(),
                    (&mut errno as *mut i32).cast(),
                    std::mem::size_of::<i32>(),
                )
            };
            if count > 0 {
                return Err(std::io::Error::from_raw_os_error(errno).into());
            }
            if let Some(code) = exited(pid)? {
                return Ok(code);
            }
            if phase_start.elapsed() >= execution_budget {
                return Err(Problem::execution(
                    "timeout",
                    format!("Cppcheck {phase} timed out"),
                ));
            }
            std::thread::sleep(Duration::from_millis(5).min(remaining()?));
        }
    })();
    let cleanup_start = Instant::now();
    let mut group_signal_errno = None;
    let mut group_probe_errno = None;
    let cleanup = (|| -> Result<i64> {
        discover(&owned.leader, &mut owned.descendants, &remaining)?;
        // The leader remains an unreaped exact child, anchoring this group even
        // after normal exit. Detached descendants are signalled by start token.
        if unsafe { libc::kill(-pid, libc::SIGKILL) } != 0 {
            let error = std::io::Error::last_os_error();
            group_signal_errno = error.raw_os_error();
            // Darwin returns EPERM for a group containing only zombies. This
            // is not exit proof: the loop still requires strict native group
            // observations, every captured descendant and retained leader exit.
            if error.raw_os_error() != Some(libc::ESRCH)
                && !(cfg!(target_os = "macos") && error.raw_os_error() == Some(libc::EPERM))
            {
                return Err(Problem::execution(
                    "cleanup-failed",
                    format!("kill(-{pid}, SIGKILL): {error}"),
                ));
            }
        }
        loop {
            remaining()?;
            let values = discover(&owned.leader, &mut owned.descendants, &remaining)?;
            for value in owned.descendants.values() {
                if value.pid == pid && exited(pid)?.is_some() {
                    continue;
                }
                signal_exact(value, libc::SIGKILL)?;
            }
            let mut live = values.iter().any(|current| {
                !current.zombie
                    && (current.group == pid
                        || current.session == pid
                        || owned
                            .descendants
                            .get(&current.pid)
                            .is_some_and(|old| same(old, current)))
            });
            // A list omission or an already-exited leader is not exit proof for
            // a retained descendant. Read every exact native identity again.
            for value in owned.descendants.values() {
                remaining()?;
                if value.pid == pid && exited(pid)?.is_some() {
                    continue;
                }
                if let Some(current) = observe(value.pid)? {
                    live |= same(value, &current) && !current.zombie;
                }
            }
            let group_exists = if unsafe { libc::kill(-pid, 0) } == 0 {
                true
            } else {
                let error = std::io::Error::last_os_error();
                group_probe_errno = error.raw_os_error();
                match error.raw_os_error() {
                    Some(libc::ESRCH) => false,
                    Some(libc::EPERM) if cfg!(target_os = "macos") => true,
                    _ => {
                        return Err(Problem::execution(
                            "cleanup-failed",
                            format!("kill(-{pid}, 0): {error}"),
                        ))
                    }
                }
            };
            if group_exists && !values.iter().any(|value| value.group == pid) {
                return Err(Problem::execution(
                    "cleanup-failed",
                    "Owned group exists but its members could not be observed",
                ));
            }
            if !live && exited(pid)?.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(2).min(remaining()?));
        }
        let mut status = 0;
        if unsafe { libc::waitpid(pid, &mut status, 0) } != pid {
            return Err(std::io::Error::last_os_error().into());
        }
        owned.reaped = true;
        out.sync_all()?;
        err.sync_all()?;
        Ok(if libc::WIFEXITED(status) {
            i64::from(libc::WEXITSTATUS(status))
        } else {
            -i64::from(libc::WTERMSIG(status))
        })
    })();
    let descendants:Vec<_>=owned.descendants.values().filter(|p|p.pid!=pid).map(|p|json!({"pid":p.pid,"start_identity":p.start,"process_group":p.group,"session":p.session,"cleanup":if cleanup.is_ok(){"confirmed"}else{"unconfirmed"}})).collect();
    events.push(json!({"phase":phase,"pid":pid,"start_identity":owned.leader.start,"process_group":pid,"session":pid,"ownership":"posix_session","cleanup":if cleanup.is_ok(){"confirmed"}else{"unconfirmed"},"descendants":descendants,"process_exit_code":execution.as_ref().ok(),"terminal_exit_code":cleanup.as_ref().ok(),"group_signal_errno":group_signal_errno,"group_probe_errno":group_probe_errno,"execution_error":execution.as_ref().err().map(|error|&error.message),"cleanup_error":cleanup.as_ref().err().map(|error|&error.message),"elapsed_seconds":cleanup_start.elapsed().as_secs_f64(),"phase_elapsed_seconds":phase_start.elapsed().as_secs_f64()}));
    cleanup.map_err(|e| {
        Problem::execution(
            "cleanup-failed",
            format!("Cannot confirm owned {phase} cleanup: {}", e.message),
        )
    })?;
    remaining()?;
    if CANCELLED.load(Ordering::SeqCst) {
        return Err(Problem::execution(
            "cancelled",
            "Owned analysis cancelled by signal",
        ));
    }
    execution
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "macos")]
    #[test]
    fn retained_zombie_group_records_native_cleanup_call_evidence() {
        let root = std::env::temp_dir().join(format!(
            "byo-posix-group-proof-{:016x}",
            rand::random::<u64>()
        ));
        fs::create_dir(&root).unwrap();
        let mut budget = Budget::new();
        budget.configure(5.0).unwrap();
        let mut events = Vec::new();
        assert_eq!(
            run_owned(
                &["/bin/sh".into(), "-c".into(), "exit 0".into()],
                &root,
                &budget,
                &root,
                "analysis",
                &mut events,
                None
            )
            .unwrap(),
            0
        );
        let proof = events.last().unwrap();
        assert_eq!(proof["cleanup"], "confirmed");
        assert_eq!(proof["terminal_exit_code"], 0);
        assert_eq!(proof["ownership"], "posix_session");
        assert!(proof["start_identity"].as_array().is_some());
        eprintln!("native retained-group syscall receipt: {proof}");
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn denied_unrelated_group_query_is_excluded_by_fresh_session_proof() {
        let group_called = std::cell::Cell::new(false);
        let result = namespace_with(
            42,
            || Ok(Some(99)),
            || {
                group_called.set(true);
                Err(std::io::Error::from_raw_os_error(libc::EPERM))
            },
        )
        .unwrap();
        assert_eq!(result, (None, Some(99)));
        assert!(!group_called.get());
        // Without fresh different-session proof, denial must remain unknown.
        assert!(namespace_with(
            42,
            || Ok(Some(42)),
            || Err(std::io::Error::from_raw_os_error(libc::EPERM))
        )
        .is_err());
    }
    #[test]
    fn captured_candidate_denied_identity_never_becomes_exit_proof() {
        let leader = Observation {
            pid: 42,
            start: (1, 2),
            parent: 1,
            group: 42,
            session: 42,
            zombie: true,
        };
        let mut child = leader.clone();
        child.pid = 55;
        child.zombie = false;
        let candidates = candidate_pids(
            &leader,
            &BTreeMap::from([(42, leader.clone()), (55, child)]),
            &[],
            |_| panic!("Captured identities must not depend on a namespace prefilter"),
            &|| Ok(Duration::from_secs(1)),
        )
        .unwrap();
        let error = observe_candidates(candidates, &|| Ok(Duration::from_secs(1)), |pid| {
            if pid == 42 {
                Ok(Some(leader.clone()))
            } else {
                Err(Problem::execution(
                    "cleanup-failed",
                    format!("proc_pidinfo({pid}): identity denied"),
                ))
            }
        })
        .unwrap_err();
        assert_eq!(error.code, "analysis/cleanup-failed");
        assert!(error.message.contains("proc_pidinfo(55)"));
    }
    #[test]
    fn candidates_keep_session_group_and_detached_ancestry_without_unrelated_pids() {
        let leader = Observation {
            pid: 42,
            start: (1, 2),
            parent: 1,
            group: 42,
            session: 42,
            zombie: false,
        };
        let mut detached = leader.clone();
        detached.pid = 55;
        detached.group = 55;
        detached.session = 55;
        let owned = BTreeMap::from([(42, leader.clone()), (55, detached)]);
        // 55 is deliberately absent from enumeration; 46 precedes its parent.
        let parents = [
            (100, Some(1)),
            (46, Some(45)),
            (45, Some(42)),
            (47, Some(1)),
            (48, Some(1)),
        ];
        let candidates = candidate_pids(
            &leader,
            &owned,
            &parents,
            |pid| {
                Ok(match pid {
                    47 => (Some(47), Some(42)),
                    48 => (Some(42), Some(99)),
                    _ => (Some(pid), Some(pid)),
                })
            },
            &|| Ok(Duration::from_secs(1)),
        )
        .unwrap();
        assert_eq!(candidates, BTreeSet::from([42, 45, 46, 47, 48, 55]));
        // table() only performs strict identity reads for these candidates:
        // unrelated protected PID 100 must never reach proc_pidinfo.
        assert!(!candidates.contains(&100));
    }
    #[test]
    fn namespace_probe_errors_do_not_become_missing_processes() {
        let leader = Observation {
            pid: 42,
            start: (1, 2),
            parent: 1,
            group: 42,
            session: 42,
            zombie: false,
        };
        let error = candidate_pids(
            &leader,
            &BTreeMap::from([(42, leader.clone())]),
            &[(45, Some(42))],
            |_| Err(std::io::Error::from_raw_os_error(libc::EPERM)),
            &|| Ok(Duration::from_secs(1)),
        )
        .unwrap_err();
        assert!(error.message.contains("permitted"));
    }
    #[test]
    fn exact_identity_rejects_recycled_pid() {
        let a = Observation {
            pid: 42,
            start: (1, 2),
            parent: 1,
            group: 42,
            session: 42,
            zombie: false,
        };
        let mut b = a.clone();
        b.start = (1, 3);
        assert!(!same(&a, &b));
    }
    #[test]
    fn normal_exit_cleans_surviving_group_descendants() {
        let root = std::env::temp_dir().join(format!("byo-posix-{:016x}", rand::random::<u64>()));
        fs::create_dir(&root).unwrap();
        let mut budget = Budget::new();
        budget.configure(5.0).unwrap();
        let argv = vec![
            "/bin/sh".into(),
            "-c".into(),
            "sleep 60 & sleep 0.1; exit 0".into(),
        ];
        let mut events = Vec::new();
        assert_eq!(
            run_owned(&argv, &root, &budget, &root, "analysis", &mut events, None).unwrap(),
            0
        );
        assert_eq!(events.last().unwrap()["cleanup"], "confirmed");
        assert!(!events.last().unwrap()["descendants"]
            .as_array()
            .unwrap()
            .is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exec_failure_still_confirms_exact_cleanup() {
        let root =
            std::env::temp_dir().join(format!("byo-posix-exec-{:016x}", rand::random::<u64>()));
        fs::create_dir(&root).unwrap();
        let mut events = Vec::new();
        let argv = vec![root.join("absent-analyzer").display().to_string()];
        let error = run_owned(
            &argv,
            &root,
            &Budget::new(),
            &root,
            "analysis",
            &mut events,
            None,
        )
        .unwrap_err();
        assert_eq!(
            error.code, "analysis/execution-failed",
            "{error:?}; events={events:?}"
        );
        assert_eq!(events.last().unwrap()["cleanup"], "confirmed");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn phase_deadline_and_cancellation_clean_the_owned_session() {
        let root =
            std::env::temp_dir().join(format!("byo-posix-cancel-{:016x}", rand::random::<u64>()));
        fs::create_dir(&root).unwrap();
        let argv = vec!["/bin/sh".into(), "-c".into(), "echo ready; sleep 60".into()];
        let mut budget = Budget::new();
        budget.configure(10.0).unwrap();
        let mut events = Vec::new();
        assert_eq!(
            run_owned(
                &argv,
                &root,
                &budget,
                &root,
                "version",
                &mut events,
                Some(Duration::from_secs(2))
            )
            .unwrap_err()
            .code,
            "analysis/timeout"
        );
        assert_eq!(events.last().unwrap()["cleanup"], "confirmed");
        assert!(budget.started.elapsed() < Duration::from_secs(3));
        let output = root.join("cancel.stdout.log");
        let watcher = std::thread::spawn(move || {
            let started = Instant::now();
            while started.elapsed() < Duration::from_secs(5) {
                if fs::read(&output).is_ok_and(|bytes| bytes.starts_with(b"ready")) {
                    unsafe {
                        libc::kill(std::process::id() as i32, libc::SIGTERM);
                    }
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            panic!("Cancellation fixture never became ready");
        });
        let mut events = Vec::new();
        let result = run_owned(
            &argv,
            &root,
            &Budget::new(),
            &root,
            "cancel",
            &mut events,
            None,
        );
        watcher.join().unwrap();
        assert_eq!(result.unwrap_err().code, "analysis/cancelled");
        assert_eq!(events.last().unwrap()["cleanup"], "confirmed");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "owned subprocess fixture; runs only from its sentinel directory"]
    fn detached_leaf_fixture() {
        let root = std::env::current_dir().unwrap();
        if !root.join(".byo-posix-child-fixture").is_file() {
            return;
        }
        // Stay in the owned session until the monitor has captured this child.
        std::thread::sleep(Duration::from_millis(600));
        assert!(unsafe { libc::setsid() } > 0);
        let identity = observe(std::process::id() as i32).unwrap().unwrap();
        write_json(
            &root.join("detached.json"),
            &json!({"pid":identity.pid,"start_identity":identity.start,"session":identity.session}),
        )
        .unwrap();
        std::thread::sleep(Duration::from_secs(60));
    }

    #[test]
    #[ignore = "owned subprocess fixture; runs only from its sentinel directory"]
    // normal_exit_cleans_a_captured_detached_child needs this parent to exit
    // while its child is live so the process owner must clean up the orphan.
    #[allow(clippy::zombie_processes)]
    fn detached_process_fixture() {
        let root = std::env::current_dir().unwrap();
        if !root.join(".byo-posix-child-fixture").is_file() {
            return;
        }
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "code_analysis::process::platform::tests::detached_leaf_fixture",
                "--ignored",
                "--exact",
                "--test-threads=1",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let started = Instant::now();
        while !root.join("detached.json").is_file() && started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(5));
        }
        if !root.join("detached.json").is_file() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("Detached fixture never became ready");
        }
        // Drop the handle and exit while the captured detached child is live.
    }

    #[test]
    fn normal_exit_cleans_a_captured_detached_child() {
        let root =
            std::env::temp_dir().join(format!("byo-posix-detached-{:016x}", rand::random::<u64>()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join(".byo-posix-child-fixture"), b"owned fixture").unwrap();
        let argv = vec![
            std::env::current_exe().unwrap().display().to_string(),
            "code_analysis::process::platform::tests::detached_process_fixture".into(),
            "--ignored".into(),
            "--exact".into(),
            "--test-threads=1".into(),
        ];
        let mut budget = Budget::new();
        budget.configure(10.0).unwrap();
        let mut events = Vec::new();
        assert_eq!(
            run_owned(&argv, &root, &budget, &root, "analysis", &mut events, None).unwrap(),
            0
        );
        let child: Value =
            serde_json::from_slice(&fs::read(root.join("detached.json")).unwrap()).unwrap();
        let pid = child["pid"].as_i64().unwrap() as i32;
        assert_ne!(child["session"], events[0]["session"]);
        assert!(events.last().unwrap()["descendants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member["pid"] == pid
                && member["start_identity"] == child["start_identity"]
                && member["cleanup"] == "confirmed"));
        if let Some(current) = observe(pid).unwrap() {
            assert!(json!(current.start) != child["start_identity"] || current.zombie);
        }
        fs::remove_dir_all(root).unwrap();
    }
}
