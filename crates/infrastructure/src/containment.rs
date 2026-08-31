use std::io;

/// Keeps the desktop process and every child it creates inside the strongest
/// process-lifetime container available on the current platform.
///
/// Windows uses a Job Object with `KILL_ON_JOB_CLOSE`, so the operating system
/// tears down the sing-box process tree even when the GUI is terminated without
/// running Rust destructors. Other platforms continue to use the sidecar's
/// process-group teardown until a native parent-death adapter is available.
#[derive(Debug)]
pub struct ProcessContainmentGuard {
    #[cfg(windows)]
    _job_handle: isize,
}

impl ProcessContainmentGuard {
    /// Installs process-tree containment for the current application process.
    ///
    /// # Errors
    ///
    /// On Windows, returns an error when the Job Object cannot be created,
    /// configured, or assigned to the current process.
    pub fn install() -> io::Result<Self> {
        #[cfg(windows)]
        {
            let job = win32job::Job::create().map_err(io::Error::other)?;
            let mut limits = job.query_extended_limit_info().map_err(io::Error::other)?;
            limits.limit_kill_on_job_close();
            // Elevation uses one explicitly flagged, hidden launcher to leave
            // this job before invoking UAC. Do not use SILENT_BREAKAWAY: every
            // ordinary child, including sing-box, must remain contained.
            limits.limit_breakaway_ok();
            job.set_extended_limit_info(&limits)
                .map_err(io::Error::other)?;
            job.assign_current_process().map_err(io::Error::other)?;
            // Closing a kill-on-close job that contains the current process
            // terminates that process immediately. Keep the raw handle open in
            // the process handle table instead; Windows closes it after the
            // application's orderly shutdown has completed, and also closes it
            // when the GUI crashes or is killed.
            let job_handle = job.into_handle();
            Ok(Self {
                _job_handle: job_handle,
            })
        }

        #[cfg(not(windows))]
        {
            Ok(Self {})
        }
    }

    /// Describes the abrupt-parent-death guarantee active on this platform.
    pub const fn capability() -> &'static str {
        if cfg!(windows) {
            "Windows Job Object（内核级进程树回收）"
        } else {
            "正常退出时进程组回收"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ProcessContainmentGuard;

    #[test]
    fn capability_is_never_empty() {
        assert!(!ProcessContainmentGuard::capability().is_empty());
    }
}
