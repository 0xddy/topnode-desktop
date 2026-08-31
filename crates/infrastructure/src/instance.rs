use std::{
    fs::{File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

use fs2::FileExt;
use thiserror::Error;

const RESTART_HANDOFF_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const RESTART_HANDOFF_RETRY: std::time::Duration = std::time::Duration::from_millis(50);

/// Failure to acquire the desktop process' operating-system lock.
#[derive(Debug, Error)]
pub enum InstanceLockError {
    /// Another file handle already owns the exclusive lock.
    #[error("TOPNODE Desktop 已在运行")]
    AlreadyRunning,
    /// The lock file could not be opened.
    #[error("无法打开单实例锁文件 {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The operating system rejected the lock operation.
    #[error("无法锁定单实例文件 {path}: {source}")]
    Lock {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The replacement process did not observe the previous instance release.
    #[error("等待旧实例释放单实例锁超时: {path}")]
    RestartHandoffTimeout { path: PathBuf },
}

/// Holds an operating-system file lock for the lifetime of one desktop process.
#[derive(Debug)]
pub struct InstanceGuard {
    file: File,
}

impl InstanceGuard {
    /// Acquires the application's single-instance lock without waiting.
    ///
    /// # Errors
    ///
    /// Returns [`InstanceLockError::AlreadyRunning`] when another handle owns
    /// the lock. The lock is held by the operating system rather than by a PID
    /// file, so it is also released when the process exits unexpectedly.
    pub fn acquire(path: &Path) -> Result<Self, InstanceLockError> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .map_err(|source| InstanceLockError::Open {
                path: path.to_path_buf(),
                source,
            })?;
        FileExt::try_lock_exclusive(&file).map_err(|error| {
            if is_lock_contention(&error) {
                InstanceLockError::AlreadyRunning
            } else {
                InstanceLockError::Lock {
                    path: path.to_path_buf(),
                    source: error,
                }
            }
        })?;
        Ok(Self { file })
    }

    /// Waits for a previous process to finish graceful shutdown, then acquires
    /// and retains the same operating-system lock without a check/acquire gap.
    ///
    /// This is reserved for the trusted UAC replacement launch. Normal second
    /// instances must continue using [`Self::acquire`] so they activate the
    /// existing window immediately instead of waiting for it to exit.
    ///
    /// # Errors
    ///
    /// Returns a lock/opening error immediately, or
    /// [`InstanceLockError::RestartHandoffTimeout`] if the old process still
    /// owns the lock after the bounded handoff interval.
    pub async fn acquire_after_restart_handoff(path: &Path) -> Result<Self, InstanceLockError> {
        Self::acquire_until(path, tokio::time::Instant::now() + RESTART_HANDOFF_TIMEOUT).await
    }

    async fn acquire_until(
        path: &Path,
        deadline: tokio::time::Instant,
    ) -> Result<Self, InstanceLockError> {
        loop {
            match Self::acquire(path) {
                Ok(guard) => return Ok(guard),
                Err(InstanceLockError::AlreadyRunning) => {}
                Err(error) => return Err(error),
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(InstanceLockError::RestartHandoffTimeout {
                    path: path.to_path_buf(),
                });
            }
            tokio::time::sleep(RESTART_HANDOFF_RETRY).await;
        }
    }
}

impl Drop for InstanceGuard {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

fn is_lock_contention(error: &io::Error) -> bool {
    const WINDOWS_ERROR_LOCK_VIOLATION: i32 = 33;

    error.kind() == io::ErrorKind::WouldBlock
        || (cfg!(windows) && error.raw_os_error() == Some(WINDOWS_ERROR_LOCK_VIOLATION))
}

#[cfg(test)]
mod tests {
    use super::{InstanceGuard, InstanceLockError};

    #[test]
    fn concurrent_acquire_reports_already_running() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let path = directory.path().join("instance.lock");
        let _first = InstanceGuard::acquire(&path).expect("first lock should succeed");

        let second = InstanceGuard::acquire(&path);

        assert!(
            matches!(second, Err(InstanceLockError::AlreadyRunning)),
            "unexpected acquisition result: {second:?}"
        );
    }

    #[test]
    fn dropping_guard_allows_lock_to_be_acquired_again() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let path = directory.path().join("instance.lock");
        let first = InstanceGuard::acquire(&path).expect("first lock should succeed");
        drop(first);

        let _replacement =
            InstanceGuard::acquire(&path).expect("released lock should be acquirable");
    }

    #[tokio::test]
    async fn restart_handoff_waits_and_retains_the_released_lock() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let path = directory.path().join("instance.lock");
        let first = InstanceGuard::acquire(&path).expect("first lock should succeed");
        let release = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(75)).await;
            drop(first);
        });

        let replacement = InstanceGuard::acquire_after_restart_handoff(&path)
            .await
            .expect("replacement should wait for the old lock");
        release.await.expect("release task should finish");

        assert!(matches!(
            InstanceGuard::acquire(&path),
            Err(InstanceLockError::AlreadyRunning)
        ));
        drop(replacement);
    }

    #[tokio::test]
    async fn restart_handoff_timeout_is_bounded() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let path = directory.path().join("instance.lock");
        let _first = InstanceGuard::acquire(&path).expect("first lock should succeed");

        let error = InstanceGuard::acquire_until(
            &path,
            tokio::time::Instant::now() + std::time::Duration::from_millis(25),
        )
        .await
        .expect_err("handoff should time out while the lock remains owned");

        assert!(matches!(
            error,
            InstanceLockError::RestartHandoffTimeout { .. }
        ));
    }
}
