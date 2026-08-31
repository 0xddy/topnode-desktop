use std::io;

/// Runs the hidden Unix sidecar guardian mode when the current invocation
/// requests it.
///
/// Normal desktop launches return `None` and continue through the regular
/// bootstrap path. Guardian launches return the exit code that the desktop
/// entry point must propagate without acquiring the single-instance lock.
#[cfg(unix)]
pub async fn run_if_requested() -> io::Result<Option<i32>> {
    let Some(request) = unix::request_from_process_args()? else {
        return Ok(None);
    };
    unix::supervise(request).await.map(Some)
}

/// Windows uses the application-wide Job Object and has no hidden guardian
/// invocation.
#[cfg(not(unix))]
pub fn run_if_requested() -> std::future::Ready<io::Result<Option<i32>>> {
    std::future::ready(Ok(None))
}

#[cfg(unix)]
pub(crate) fn guarded_command(
    sidecar_binary: &std::path::Path,
) -> io::Result<tokio::process::Command> {
    unix::guarded_command(sidecar_binary)
}

#[cfg(unix)]
mod unix {
    use std::{
        ffi::{OsStr, OsString},
        io,
        path::{Path, PathBuf},
        process::{ExitStatus, Stdio},
        time::Duration,
    };

    use nix::{
        errno::Errno,
        sys::signal::{Signal, killpg},
        unistd::{Pid, getpgid, getpid, getppid},
    };
    use tokio::{
        process::{Child, Command},
        signal::unix::{SignalKind, signal},
        time::{MissedTickBehavior, interval},
    };

    const MODE_ARGUMENT: &str = "--topnode-internal-sidecar-guardian";
    const PARENT_CHECK_INTERVAL: Duration = Duration::from_millis(100);
    const PARENT_GONE_EXIT_CODE: i32 = 1;

    #[derive(Debug)]
    pub(super) struct GuardianRequest {
        expected_parent: Pid,
        sidecar_binary: PathBuf,
        sidecar_arguments: Vec<OsString>,
    }

    pub(super) fn guarded_command(sidecar_binary: &Path) -> io::Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .arg(MODE_ARGUMENT)
            .arg(std::process::id().to_string())
            .arg(sidecar_binary);
        Ok(command)
    }

    pub(super) fn request_from_process_args() -> io::Result<Option<GuardianRequest>> {
        request_from_args(std::env::args_os().skip(1))
    }

    fn request_from_args(
        mut arguments: impl Iterator<Item = OsString>,
    ) -> io::Result<Option<GuardianRequest>> {
        let Some(mode) = arguments.next() else {
            return Ok(None);
        };
        if mode != OsStr::new(MODE_ARGUMENT) {
            return Ok(None);
        }

        let expected_parent = arguments
            .next()
            .ok_or_else(|| invalid_request("guardian 缺少父进程 ID"))?;
        let expected_parent = expected_parent
            .to_str()
            .ok_or_else(|| invalid_request("guardian 父进程 ID 不是有效文本"))?
            .parse::<u32>()
            .map_err(|_| invalid_request("guardian 父进程 ID 格式无效"))?;
        let expected_parent = i32::try_from(expected_parent)
            .map(Pid::from_raw)
            .map_err(|_| invalid_request("guardian 父进程 ID 超出平台范围"))?;
        if expected_parent.as_raw() <= 1 {
            return Err(invalid_request("guardian 父进程 ID 必须大于 1"));
        }

        let sidecar_binary = arguments
            .next()
            .map(PathBuf::from)
            .ok_or_else(|| invalid_request("guardian 缺少 sing-box 路径"))?;
        if sidecar_binary.as_os_str().is_empty() {
            return Err(invalid_request("guardian sing-box 路径为空"));
        }

        Ok(Some(GuardianRequest {
            expected_parent,
            sidecar_binary,
            sidecar_arguments: arguments.collect(),
        }))
    }

    pub(super) async fn supervise(request: GuardianRequest) -> io::Result<i32> {
        ensure_expected_parent(request.expected_parent)?;

        // Register before sing-box exists. A normal group SIGTERM must not let
        // the guardian exit before it has observed and reaped the sidecar.
        let mut terminate = signal(SignalKind::terminate())?;
        ensure_expected_parent(request.expected_parent)?;

        let guardian_pid = getpid();
        let guardian_group = getpgid(None).map_err(nix_error)?;
        if guardian_group != guardian_pid {
            return Err(io::Error::other(
                "sidecar guardian 未作为独立进程组组长启动",
            ));
        }

        let mut child = Command::new(&request.sidecar_binary)
            .args(&request.sidecar_arguments)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;

        let mut parent_check = interval(PARENT_CHECK_INTERVAL);
        parent_check.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                status = child.wait() => return status.map(propagated_exit_code),
                received = terminate.recv() => {
                    if received.is_none() {
                        return Err(io::Error::other("sidecar guardian 的 SIGTERM 监听意外关闭"));
                    }
                    // sing-box inherits the guardian's process group and gets
                    // the same SIGTERM with its default post-exec disposition.
                    // Keep the guardian alive so the existing parent-side wait
                    // and SIGKILL fallback still describe the whole group.
                }
                _ = parent_check.tick() => {
                    if getppid() != request.expected_parent {
                        kill_group_after_parent_death(guardian_pid, &mut child)?;
                    }
                }
            }
        }
    }

    fn ensure_expected_parent(expected_parent: Pid) -> io::Result<()> {
        let actual_parent = getppid();
        if actual_parent == expected_parent {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "sidecar guardian 父进程不匹配：期望 {}，实际 {}",
                expected_parent.as_raw(),
                actual_parent.as_raw()
            ),
        ))
    }

    fn kill_group_after_parent_death(guardian_pid: Pid, child: &mut Child) -> io::Result<()> {
        if let Err(error) = killpg(guardian_pid, Signal::SIGKILL) {
            // The group contains this process, so a successful SIGKILL never
            // returns control in practice. If the group call itself fails,
            // still make a best effort to avoid leaking the direct sidecar.
            let _ = child.start_kill();
            return Err(nix_error(error));
        }
        std::process::exit(PARENT_GONE_EXIT_CODE);
    }

    fn propagated_exit_code(status: ExitStatus) -> i32 {
        use std::os::unix::process::ExitStatusExt as _;

        status
            .code()
            .or_else(|| status.signal().map(|signal| 128_i32.saturating_add(signal)))
            .unwrap_or(PARENT_GONE_EXIT_CODE)
    }

    fn invalid_request(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message)
    }

    fn nix_error(error: Errno) -> io::Error {
        io::Error::from_raw_os_error(error as i32)
    }

    #[cfg(test)]
    mod tests {
        use std::{
            env,
            ffi::OsString,
            io::Write as _,
            os::unix::process::CommandExt as _,
            path::PathBuf,
            process::{Command as StdCommand, Stdio},
        };

        use super::{GuardianRequest, getppid, supervise};

        const HELPER_ENVIRONMENT: &str = "TOPNODE_GUARDIAN_TEST_HELPER";
        const EXPECTED_PARENT_ENVIRONMENT: &str = "TOPNODE_GUARDIAN_TEST_PARENT";

        #[tokio::test]
        async fn parent_mismatch_does_not_start_sidecar() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let marker = temporary.path().join("sidecar-started");
            let actual_parent = getppid().as_raw();
            let mismatched_parent = nix::unistd::Pid::from_raw(actual_parent.saturating_add(1));
            let request = GuardianRequest {
                expected_parent: mismatched_parent,
                sidecar_binary: PathBuf::from("/bin/sh"),
                sidecar_arguments: vec![
                    OsString::from("-c"),
                    OsString::from(format!("touch '{}'", marker.display())),
                ],
            };

            let error = supervise(request).await.expect_err("parent mismatch");

            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
            assert!(!marker.exists(), "mismatched guardian started the sidecar");
        }

        #[test]
        fn normal_child_exit_and_stdio_are_propagated() {
            let executable = env::current_exe().expect("test executable");
            let mut command = StdCommand::new(executable);
            command
                .arg("--ignored")
                .arg("--exact")
                .arg("sidecar_guardian::unix::tests::guardian_subprocess_entry")
                .arg("--nocapture")
                .env(HELPER_ENVIRONMENT, "stdio")
                .env(EXPECTED_PARENT_ENVIRONMENT, std::process::id().to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0);
            let mut child = command.spawn().expect("guardian helper");
            child
                .stdin
                .take()
                .expect("guardian stdin")
                .write_all(b"hello\n")
                .expect("write guardian stdin");

            let output = child.wait_with_output().expect("guardian output");

            assert_eq!(output.status.code(), Some(23));
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("out:hello"),
                "stdout was not inherited: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("err:hello"),
                "stderr was not inherited: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        #[test]
        #[ignore]
        fn guardian_subprocess_entry() {
            if env::var_os(HELPER_ENVIRONMENT).as_deref() != Some(std::ffi::OsStr::new("stdio")) {
                return;
            }
            let expected_parent = env::var(EXPECTED_PARENT_ENVIRONMENT)
                .expect("expected parent")
                .parse::<i32>()
                .map(nix::unistd::Pid::from_raw)
                .expect("valid parent");
            let request = GuardianRequest {
                expected_parent,
                sidecar_binary: PathBuf::from("/bin/sh"),
                sidecar_arguments: vec![
                    OsString::from("-c"),
                    OsString::from(
                        "IFS= read -r line; printf 'out:%s\\n' \"$line\"; \
                         printf 'err:%s\\n' \"$line\" >&2; exit 23",
                    ),
                ],
            };
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("guardian runtime");
            let exit_code = runtime.block_on(supervise(request)).expect("guardian run");
            std::process::exit(exit_code);
        }
    }
}
