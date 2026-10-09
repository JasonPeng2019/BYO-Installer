//! Windows ownership is established before a child can execute any instruction.
//! Output goes directly to retained files: no pipe-draining thread can outlive
//! the deadline. Only the three dedicated handles are inherited.
use super::*;
use std::mem::{size_of, size_of_val};
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::JobObjects::*;
use windows_sys::Win32::System::Threading::*;

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}
fn check(success: i32) -> Result<()> {
    if success == 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}
fn inherit(file: &File) -> Result<Handle> {
    let mut copy = std::ptr::null_mut();
    unsafe {
        check(DuplicateHandle(
            GetCurrentProcess(),
            file.as_raw_handle(),
            GetCurrentProcess(),
            &mut copy,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        ))?;
    }
    Ok(Handle(copy))
}
struct Attributes {
    storage: Vec<usize>,
    initialized: bool,
}
impl Attributes {
    fn new(handles: &[HANDLE]) -> Result<Self> {
        let mut bytes = 0;
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut bytes);
        }
        let mut attributes = Self {
            storage: vec![0; bytes.div_ceil(size_of::<usize>())],
            initialized: false,
        };
        unsafe {
            check(InitializeProcThreadAttributeList(
                attributes.pointer(),
                1,
                0,
                &mut bytes,
            ))?;
            attributes.initialized = true;
            check(UpdateProcThreadAttribute(
                attributes.pointer(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                size_of_val(handles),
                std::ptr::null_mut(),
                std::ptr::null(),
            ))?;
        }
        Ok(attributes)
    }
    fn pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                DeleteProcThreadAttributeList(self.pointer());
            }
        }
    }
}

/// Quote Microsoft CRT argv, preserving empty strings, quotes and trailing
/// backslashes. lpApplicationName selects the exact executable; no shell runs.
fn command_line(argv: &[String]) -> Vec<u16> {
    let mut text = String::new();
    for (i, arg) in argv.iter().enumerate() {
        if i != 0 {
            text.push(' ');
        }
        text.push('"');
        let mut slashes = 0;
        for c in arg.chars() {
            if c == '\\' {
                slashes += 1;
                continue;
            }
            text.extend(std::iter::repeat_n(
                '\\',
                if c == '"' { slashes * 2 + 1 } else { slashes },
            ));
            slashes = 0;
            text.push(c);
        }
        text.extend(std::iter::repeat_n('\\', slashes * 2));
        text.push('"');
    }
    text.encode_utf16().chain(Some(0)).collect()
}
fn wide(path: &str) -> Vec<u16> {
    path.encode_utf16().chain(Some(0)).collect()
}
fn creation(process: HANDLE) -> Result<u64> {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    unsafe {
        check(GetProcessTimes(
            process,
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        ))?;
    }
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}
struct Descendant {
    pid: u32,
    created: u64,
    handle: Handle,
}
fn descendants(
    job: HANDLE,
    parent_pid: u32,
    remaining: impl Fn() -> Result<Duration>,
) -> Result<Vec<Descendant>> {
    let mut capacity = 16usize;
    let header_words =
        std::mem::offset_of!(JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList) / size_of::<usize>();
    loop {
        remaining()?;
        let mut storage = vec![0usize; capacity + header_words];
        let list = storage
            .as_mut_ptr()
            .cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>();
        let success = unsafe {
            QueryInformationJobObject(
                job,
                JobObjectBasicProcessIdList,
                list.cast(),
                size_of_val(storage.as_slice()) as u32,
                std::ptr::null_mut(),
            )
        };
        if success == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_MORE_DATA as i32) {
                return Err(error.into());
            }
        }
        let assigned = unsafe { (*list).NumberOfAssignedProcesses as usize };
        let count = unsafe { (*list).NumberOfProcessIdsInList as usize };
        if success == 0 || assigned > count {
            capacity = assigned.max(capacity * 2);
            continue;
        }
        let mut members = Vec::new();
        for &pid in &storage[header_words..header_words + count] {
            remaining()?;
            let pid = u32::try_from(pid).map_err(|_| {
                Problem::execution("cleanup-failed", "Invalid owned Job process identity.")
            })?;
            if pid == parent_pid {
                continue;
            }
            let handle = Handle(unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    0,
                    pid,
                )
            });
            if handle.0.is_null() {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
                    continue; // The enumerated process has already exited.
                }
                return Err(error.into());
            }
            let mut member = 0;
            unsafe {
                check(IsProcessInJob(handle.0, job, &mut member))?;
            }
            if member != 0 {
                members.push(Descendant {
                    pid,
                    created: creation(handle.0)?,
                    handle,
                });
            } // A reused PID outside our Job is left untouched.
        }
        return Ok(members);
    }
}
pub(super) fn run_owned(
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
    if argv.is_empty() || argv.iter().any(|arg| arg.contains('\0')) {
        return Err(Problem::execution(
            "execution-failed",
            "Invalid native argv.",
        ));
    }
    let out = File::create(directory.join(format!("{phase}.stdout.log")))?;
    let err = File::create(directory.join(format!("{phase}.stderr.log")))?;
    let input = File::open("NUL")?;
    let inherited = [inherit(&input)?, inherit(&out)?, inherit(&err)?];
    let handles = inherited.each_ref().map(|h| h.0);
    let mut attributes = Attributes::new(&handles)?;
    let job = Handle(unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) });
    if job.0.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    unsafe {
        check(SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of_val(&limits) as u32,
        ))?;
    }
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of_val(&startup) as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = handles[0];
    startup.StartupInfo.hStdOutput = handles[1];
    startup.StartupInfo.hStdError = handles[2];
    startup.lpAttributeList = attributes.pointer();
    let executable = wide(&argv[0]);
    let cwd_wide = wide(&cwd.display().to_string());
    let mut command = command_line(argv);
    let mut child = PROCESS_INFORMATION::default();
    budget.remaining()?;
    unsafe {
        check(CreateProcessW(
            executable.as_ptr(),
            command.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            std::ptr::null(),
            cwd_wide.as_ptr(),
            &startup.StartupInfo,
            &mut child,
        ))?;
    }
    let process = Handle(child.hProcess);
    let _thread = Handle(child.hThread);
    let mut assigned = false;
    let mut created = None;
    let execution = (|| -> Result<i64> {
        created = Some(creation(process.0)?);
        events.push(json!({"phase":phase,"pid":child.dwProcessId,"creation_filetime":created,"argv":argv,"cwd":cwd,"created_suspended":true}));
        unsafe {
            check(AssignProcessToJobObject(job.0, process.0))?;
        }
        assigned = true;
        // Reserve up to 1.5 s (or one quarter of the remaining budget) for exact
        // Job cleanup. This is part of the configured request, not extra grace.
        let remaining = budget.remaining()?;
        let reserve = Duration::from_millis(1500).min(remaining / 4);
        let mut available = remaining.saturating_sub(reserve);
        if let Some(limit) = phase_limit {
            available = available.min(
                limit
                    .saturating_sub(phase_start.elapsed())
                    .saturating_sub(reserve.min(limit / 4)),
            );
        }
        if available.is_zero() {
            return Err(Problem::execution(
                "timeout",
                format!("Cppcheck {phase} deadline expired before resume."),
            ));
        }
        unsafe {
            if ResumeThread(child.hThread) == u32::MAX {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        let wait_started = Instant::now();
        loop {
            let left = available.saturating_sub(wait_started.elapsed());
            if left.is_zero() {
                return Err(Problem::execution(
                    "timeout",
                    format!("Cppcheck {phase} timed out."),
                ));
            }
            let milliseconds = left.as_millis().max(1).min(u128::from(u32::MAX - 1)) as u32;
            match unsafe { WaitForSingleObject(process.0, milliseconds) } {
                WAIT_OBJECT_0 => break,
                WAIT_TIMEOUT => continue,
                _ => return Err(std::io::Error::last_os_error().into()),
            }
        }
        let mut exit = 0;
        unsafe {
            check(GetExitCodeProcess(process.0, &mut exit))?;
        }
        Ok(i64::from(exit))
    })();
    // Always clean by retained process/Job handles, including startup failures.
    let cleanup_start = Instant::now();
    let mut terminal_exit = 0;
    let mut descendant_events = Vec::new();
    let cleanup = (|| -> Result<()> {
        let remaining = || -> Result<Duration> {
            let mut remaining = budget.remaining()?;
            if let Some(limit) = phase_limit {
                remaining =
                    remaining.min(limit.checked_sub(phase_start.elapsed()).ok_or_else(|| {
                        Problem::execution(
                            "cleanup-failed",
                            "Version probe cleanup exceeded its five-second budget.",
                        )
                    })?);
            }
            Ok(remaining)
        };
        let members = if assigned {
            descendants(job.0, child.dwProcessId, remaining)
        } else {
            Ok(Vec::new())
        };
        if let Ok(members) = &members {
            descendant_events = members.iter().map(|member| {
                json!({"pid":member.pid,"creation_filetime":member.created,"cleanup":"unconfirmed"})
            }).collect();
        }
        if assigned {
            unsafe {
                check(TerminateJobObject(job.0, 1))?;
            }
        } else {
            unsafe {
                check(TerminateProcess(process.0, 1))?;
            }
        }
        // TerminateJobObject initiates termination. Retain exact member handles
        // and wait for them as well as the parent before confirming cleanup.
        let members = members?;
        loop {
            if assigned {
                let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
                unsafe {
                    check(QueryInformationJobObject(
                        job.0,
                        JobObjectBasicAccountingInformation,
                        (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                        size_of_val(&info) as u32,
                        std::ptr::null_mut(),
                    ))?;
                }
                if info.ActiveProcesses == 0
                    && unsafe { WaitForSingleObject(process.0, 0) } == WAIT_OBJECT_0
                    && members.iter().all(|member| unsafe {
                        WaitForSingleObject(member.handle.0, 0) == WAIT_OBJECT_0
                    })
                {
                    // TotalProcesses includes historical children that exited
                    // before enumeration; they have no captured live identity.
                    // The terminated Job must be empty and every retained
                    // process handle signaled before cleanup can be confirmed.
                    break;
                }
            } else if unsafe { WaitForSingleObject(process.0, 0) } == WAIT_OBJECT_0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(2).min(remaining()?));
        }
        // The same retained handle must still denote the recorded creation.
        if created.is_some() && created != Some(creation(process.0)?) {
            return Err(Problem::execution(
                "cleanup-failed",
                "Owned process identity changed.",
            ));
        }
        unsafe {
            check(GetExitCodeProcess(process.0, &mut terminal_exit))?;
        }
        for (member, event) in members.iter().zip(&mut descendant_events) {
            if creation(member.handle.0)? != member.created {
                return Err(Problem::execution(
                    "cleanup-failed",
                    "Owned descendant identity changed.",
                ));
            }
            event["cleanup"] = json!("confirmed");
        }
        out.sync_all()?;
        err.sync_all()?;
        Ok(())
    })();
    events.push(json!({"phase":phase,"pid":child.dwProcessId,"creation_filetime":created,"cleanup":if cleanup.is_ok(){"confirmed"}else{"unconfirmed"},"ownership":if assigned{"windows_job"}else{"suspended_process"},"descendants":descendant_events,"elapsed_seconds":cleanup_start.elapsed().as_secs_f64(),"phase_elapsed_seconds":phase_start.elapsed().as_secs_f64(),"process_exit_code":execution.as_ref().ok().copied(),"terminal_exit_code":if cleanup.is_ok(){Some(terminal_exit)}else{None}}));
    if let Err(error) = cleanup {
        return Err(Problem::execution(
            "cleanup-failed",
            format!("Cannot confirm owned {phase} cleanup: {}", error.message),
        ));
    }
    if phase_limit.is_some_and(|limit| phase_start.elapsed() > limit) {
        return Err(Problem::execution(
            "timeout",
            format!("Cppcheck {phase} deadline expired during output retention or cleanup."),
        ));
    }
    budget.remaining()?;
    execution
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exited_job_descendant_does_not_require_a_live_identity() {
        let root = std::env::temp_dir().join(format!(
            "byo-ri-exited-child-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        fs::create_dir(&root).unwrap();
        let shell = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let argv = vec![
            shell.display().to_string(),
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            "& $env:ComSpec /c exit 0".into(),
        ];
        let mut budget = Budget::new();
        budget.configure(10.0).unwrap();
        let mut events = Vec::new();
        assert_eq!(
            run_owned(&argv, &root, &budget, &root, "analysis", &mut events, None).unwrap(),
            0
        );
        let cleanup = events.last().unwrap();
        assert_eq!(cleanup["cleanup"], "confirmed");
        assert_eq!(cleanup["ownership"], "windows_job");
        for member in cleanup["descendants"].as_array().unwrap() {
            assert_eq!(member["cleanup"], "confirmed");
            assert!(member["pid"].as_u64().unwrap() > 0);
            assert!(member["creation_filetime"].as_u64().unwrap() > 0);
        }
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn version_phase_cap_is_inside_the_existing_request_budget() {
        let root = std::env::temp_dir().join(format!(
            "byo-ri-probe-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        fs::create_dir(&root).unwrap();
        let shell = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let argv = vec![
            shell.display().to_string(),
            "-NoProfile".into(),
            "-Command".into(),
            "Start-Sleep -Seconds 60".into(),
        ];
        let mut budget = Budget::new();
        budget.configure(4.0).unwrap();
        let mut events = Vec::new();
        assert_eq!(
            run_owned(
                &argv,
                &root,
                &budget,
                &root,
                "version",
                &mut events,
                Some(Duration::from_millis(250))
            )
            .unwrap_err()
            .code,
            "analysis/timeout"
        );
        assert_eq!(events.last().unwrap()["cleanup"], "confirmed");
        assert!(budget.started.elapsed() < Duration::from_secs(1));
        assert!(budget.remaining().unwrap() > Duration::from_secs(3));
        write_json(&root.join("owned-processes.json"), &events).unwrap();
    }
    #[test]
    fn deadline_terminates_owned_child_and_descendant_by_creation_identity() {
        let root = std::env::temp_dir().join(format!(
            "byo-ri-job-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        fs::create_dir(&root).unwrap();
        let shell = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let marker = root.join("descendant.json");
        let script=format!("$p = Start-Process -FilePath '{}' -ArgumentList '-NoProfile -Command Start-Sleep -Seconds 60' -PassThru -WindowStyle Hidden; @{{pid=$p.Id;creation=$p.StartTime.ToFileTimeUtc().ToString()}} | ConvertTo-Json -Compress | Set-Content -LiteralPath '{}' -Encoding ASCII; Start-Sleep -Seconds 60",shell.display(),marker.display());
        let argv = vec![
            shell.display().to_string(),
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            script,
        ];
        let mut budget = Budget::new();
        budget.configure(3.0).unwrap();
        let mut events = Vec::new();
        let error = run_owned(
            &argv,
            &root,
            &budget,
            &root,
            "owned-test",
            &mut events,
            None,
        )
        .unwrap_err();
        assert_eq!(error.code, "analysis/timeout");
        assert_eq!(events.last().unwrap()["cleanup"], "confirmed");
        assert!(events[0]["creation_filetime"].as_u64().unwrap() > 0);
        let descendant: Value = serde_json::from_slice(&fs::read(marker).unwrap()).unwrap();
        let descendant_pid = descendant["pid"].as_u64().unwrap() as u32;
        assert!(events.last().unwrap()["descendants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| {
                member["pid"].as_u64() == Some(u64::from(descendant_pid))
                    && member["creation_filetime"].as_u64().unwrap().to_string()
                        == descendant["creation"].as_str().unwrap()
                    && member["cleanup"] == "confirmed"
            }));
        let handle = Handle(unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                descendant_pid,
            )
        });
        if !handle.0.is_null()
            && creation(handle.0).unwrap().to_string() == descendant["creation"].as_str().unwrap()
        {
            assert_eq!(unsafe { WaitForSingleObject(handle.0, 0) }, WAIT_OBJECT_0);
        }
        assert!(budget.started.elapsed() < Duration::from_millis(3200));
        write_json(&root.join("owned-processes.json"), &events).unwrap();
    }
    #[test]
    fn quoting_preserves_empty_quoted_unicode_and_trailing_slashes() {
        let quoted = String::from_utf16(&command_line(&[
            "exe".into(),
            "".into(),
            "a b".into(),
            "a\"b".into(),
            "路径\\".into(),
        ]))
        .unwrap();
        assert_eq!(
            quoted.trim_end_matches('\0'),
            "\"exe\" \"\" \"a b\" \"a\\\"b\" \"路径\\\\\""
        );
    }
}
