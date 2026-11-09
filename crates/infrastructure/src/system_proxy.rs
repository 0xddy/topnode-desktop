use std::{
    fmt,
    fs::File,
    io::{self, Read, Write},
    net::SocketAddrV4,
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::AppPaths;

#[cfg(any(target_os = "linux", test))]
mod gnome;
#[cfg(any(target_os = "macos", test))]
mod macos;
#[cfg(windows)]
mod wininet;

const JOURNAL_VERSION: u8 = 1;
const MAX_SNAPSHOT_BYTES: usize = 64 * 1_024;
const MAX_JOURNAL_BYTES: usize = 256 * 1_024;

/// Owns the process-local side of a transactional system-proxy lease.
///
/// Call [`Self::initialize`] during application startup so a journal left by a
/// previous crash is reconciled before a new lease is acquired.
#[derive(Clone)]
pub struct SystemProxyManager {
    inner: Arc<SystemProxyManagerInner>,
}

struct SystemProxyManagerInner {
    journal_path: PathBuf,
    backend: Arc<dyn SystemProxyBackend>,
    operation_gate: Mutex<()>,
    active_owner: StdMutex<Option<Uuid>>,
}

impl fmt::Debug for SystemProxyManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemProxyManager")
            .field("journal_path", &self.inner.journal_path)
            .finish_non_exhaustive()
    }
}

impl SystemProxyManager {
    /// Creates a platform manager without touching system proxy settings.
    #[must_use]
    pub fn from_paths(paths: &AppPaths) -> Self {
        Self::new(&paths.system_proxy_journal)
    }

    /// Creates a platform manager without touching system proxy settings.
    #[must_use]
    pub fn new(journal_path: impl Into<PathBuf>) -> Self {
        Self::with_backend(journal_path.into(), Arc::new(PlatformSystemProxyBackend))
    }

    /// Creates a manager and reconciles a journal left by an interrupted run.
    ///
    /// A missing journal succeeds without invoking the platform backend. This
    /// keeps startup usable on unsupported platforms while still failing closed
    /// if an existing lease cannot be safely inspected and restored.
    ///
    /// # Errors
    ///
    /// Returns an error when the journal is malformed or inaccessible, or when
    /// the platform proxy state cannot be queried or restored safely.
    pub async fn initialize(
        journal_path: impl Into<PathBuf>,
    ) -> Result<(Self, ReconcileOutcome), SystemProxyError> {
        let manager = Self::new(journal_path);
        let outcome = manager.reconcile_stale().await?;
        Ok((manager, outcome))
    }

    /// Creates a manager from discovered paths and reconciles stale ownership.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::initialize`].
    pub async fn initialize_from_paths(
        paths: &AppPaths,
    ) -> Result<(Self, ReconcileOutcome), SystemProxyError> {
        Self::initialize(&paths.system_proxy_journal).await
    }

    fn with_backend(journal_path: PathBuf, backend: Arc<dyn SystemProxyBackend>) -> Self {
        Self {
            inner: Arc::new(SystemProxyManagerInner {
                journal_path,
                backend,
                operation_gate: Mutex::new(()),
                active_owner: StdMutex::new(None),
            }),
        }
    }

    /// Acquires ownership of the system proxy and points it at a local listener.
    ///
    /// The manager first writes a `Prepared` journal, applies the complete
    /// desired snapshot, queries it back, and then promotes the journal to
    /// `Active`. The original settings remain opaque and are never logged.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-loopback endpoint, concurrent ownership,
    /// journal failure, unsupported platform backend, or failed apply/verify.
    pub async fn acquire(
        &self,
        endpoint: SocketAddrV4,
    ) -> Result<SystemProxyLease, SystemProxyError> {
        if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
            return Err(SystemProxyError::InvalidEndpoint);
        }

        let _operation = self.inner.operation_gate.lock().await;
        if self.active_owner()?.is_some() {
            return Err(SystemProxyError::AlreadyOwned);
        }

        // A dropped lease or an interrupted predecessor must be settled before
        // a new original snapshot is taken.
        self.reconcile_locked()?;

        let original = self.capture("读取原系统代理")?;
        let applied = self
            .inner
            .backend
            .local_proxy_snapshot(&original, endpoint)
            .map_err(|error| map_backend_error("构造本地系统代理", error))?;
        validate_snapshot(&applied)?;

        let owner = Uuid::new_v4();
        let prepared = ProxyJournal {
            owner,
            phase: JournalPhase::Prepared,
            original,
            applied,
        };
        write_journal(&self.inner.journal_path, &prepared)?;

        if let Err(apply_error) = self.install(&prepared.applied, "应用系统代理") {
            self.rollback_failed_acquire(&prepared);
            return Err(apply_error);
        }

        let observed = match self.capture("回读已应用的系统代理") {
            Ok(observed) => observed,
            Err(error) => {
                self.rollback_failed_acquire(&prepared);
                return Err(error);
            }
        };
        if observed != prepared.applied {
            self.settle_unverified_acquire(&prepared, &observed)?;
            return Err(SystemProxyError::VerificationFailed {
                operation: "应用系统代理",
            });
        }

        let active = ProxyJournal {
            phase: JournalPhase::Active,
            ..prepared
        };
        if let Err(error) = write_journal(&self.inner.journal_path, &active) {
            self.rollback_failed_acquire(&active);
            return Err(error);
        }
        self.set_active_owner(Some(owner))?;

        Ok(SystemProxyLease {
            manager: self.clone(),
            owner,
            armed: true,
            #[cfg(target_os = "macos")]
            endpoint,
        })
    }

    /// Reconciles a stale `Prepared` or `Active` journal.
    ///
    /// Restoration occurs only when the observed system state still exactly
    /// matches this process's applied snapshot. Any external modification is
    /// preserved and ownership is abandoned.
    ///
    /// # Errors
    ///
    /// Returns an error for live process-local ownership, malformed journal,
    /// filesystem failure, unsupported backend, or failed query/restore.
    pub async fn reconcile_stale(&self) -> Result<ReconcileOutcome, SystemProxyError> {
        let _operation = self.inner.operation_gate.lock().await;
        if self.active_owner()?.is_some() {
            return Err(SystemProxyError::AlreadyOwned);
        }
        self.reconcile_locked()
    }

    fn reconcile_locked(&self) -> Result<ReconcileOutcome, SystemProxyError> {
        let Some(journal) = read_journal(&self.inner.journal_path)? else {
            return Ok(ReconcileOutcome::NothingToDo);
        };
        let observed = self.capture("读取待恢复的系统代理")?;

        if observed == journal.original {
            remove_journal(&self.inner.journal_path)?;
            return Ok(match journal.phase {
                JournalPhase::Prepared => ReconcileOutcome::ClearedPrepared,
                JournalPhase::Active => ReconcileOutcome::AlreadyRestored,
            });
        }

        let Some(target) = self.restoration_target(&journal, &observed)? else {
            remove_journal(&self.inner.journal_path)?;
            return Ok(ReconcileOutcome::ExternalChangePreserved);
        };
        self.install(&target, "恢复原系统代理")?;
        let restored = self.capture("回读恢复后的系统代理")?;
        if restored == target {
            remove_journal(&self.inner.journal_path)?;
            return Ok(if target == journal.original {
                ReconcileOutcome::Restored
            } else {
                ReconcileOutcome::ExternalChangePreserved
            });
        }
        if restored != journal.applied {
            remove_journal(&self.inner.journal_path)?;
            return Ok(ReconcileOutcome::ExternalChangePreserved);
        }
        Err(SystemProxyError::VerificationFailed {
            operation: "恢复原系统代理",
        })
    }

    fn restoration_target(
        &self,
        journal: &ProxyJournal,
        observed: &ProxySnapshot,
    ) -> Result<Option<ProxySnapshot>, SystemProxyError> {
        self.inner
            .backend
            .restoration_target(&journal.original, &journal.applied, observed)
            .map_err(|error| map_backend_error("检查系统代理所有权", error))
    }

    fn restore_owner(&self, owner: Uuid) -> Result<RestoreOutcome, SystemProxyError> {
        let Some(journal) = read_journal(&self.inner.journal_path)? else {
            self.set_active_owner(None)?;
            return Ok(RestoreOutcome::AlreadyRestored);
        };
        if journal.owner != owner || journal.phase != JournalPhase::Active {
            return Err(SystemProxyError::LeaseMismatch);
        }

        let observed = self.capture("读取当前系统代理")?;
        let outcome = if observed == journal.original {
            remove_journal(&self.inner.journal_path)?;
            RestoreOutcome::AlreadyRestored
        } else if let Some(target) = self.restoration_target(&journal, &observed)? {
            self.install(&target, "恢复原系统代理")?;
            let restored = self.capture("回读恢复后的系统代理")?;
            if restored == target {
                remove_journal(&self.inner.journal_path)?;
                if target == journal.original {
                    RestoreOutcome::Restored
                } else {
                    RestoreOutcome::ExternalChangePreserved
                }
            } else if restored != journal.applied {
                remove_journal(&self.inner.journal_path)?;
                RestoreOutcome::ExternalChangePreserved
            } else {
                return Err(SystemProxyError::VerificationFailed {
                    operation: "恢复原系统代理",
                });
            }
        } else {
            remove_journal(&self.inner.journal_path)?;
            RestoreOutcome::ExternalChangePreserved
        };
        self.set_active_owner(None)?;
        Ok(outcome)
    }

    fn rollback_failed_acquire(&self, _journal: &ProxyJournal) {
        if let Err(error) = self.reconcile_locked() {
            tracing::warn!(error = %error, "system proxy rollback remains journaled for startup reconciliation");
        }
    }

    fn settle_unverified_acquire(
        &self,
        _journal: &ProxyJournal,
        _observed: &ProxySnapshot,
    ) -> Result<(), SystemProxyError> {
        self.reconcile_locked().map(|_| ())
    }

    fn capture(&self, operation: &'static str) -> Result<ProxySnapshot, SystemProxyError> {
        let snapshot = self
            .inner
            .backend
            .capture()
            .map_err(|error| map_backend_error(operation, error))?;
        validate_snapshot(&snapshot)?;
        Ok(snapshot)
    }

    fn install(
        &self,
        snapshot: &ProxySnapshot,
        operation: &'static str,
    ) -> Result<(), SystemProxyError> {
        self.inner
            .backend
            .install(snapshot)
            .map_err(|error| map_backend_error(operation, error))
    }

    fn active_owner(&self) -> Result<Option<Uuid>, SystemProxyError> {
        self.inner
            .active_owner
            .lock()
            .map(|owner| *owner)
            .map_err(|_| SystemProxyError::InternalState)
    }

    fn set_active_owner(&self, owner: Option<Uuid>) -> Result<(), SystemProxyError> {
        *self
            .inner
            .active_owner
            .lock()
            .map_err(|_| SystemProxyError::InternalState)? = owner;
        Ok(())
    }
}

/// A non-cloneable ownership token for an active system proxy override.
pub struct SystemProxyLease {
    manager: SystemProxyManager,
    owner: Uuid,
    armed: bool,
    #[cfg(target_os = "macos")]
    endpoint: SocketAddrV4,
}

impl fmt::Debug for SystemProxyLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemProxyLease")
            .field("owner", &self.owner)
            .field("armed", &self.armed)
            .finish_non_exhaustive()
    }
}

impl SystemProxyLease {
    #[cfg(target_os = "macos")]
    pub(crate) async fn refresh_services(&self) -> Result<(), SystemProxyError> {
        let _operation = self.manager.inner.operation_gate.lock().await;
        let mut journal = read_journal(&self.manager.inner.journal_path)?
            .ok_or(SystemProxyError::LeaseMismatch)?;
        if journal.owner != self.owner || journal.phase != JournalPhase::Active {
            return Err(SystemProxyError::LeaseMismatch);
        }
        let observed = self.manager.capture("读取网络服务变更")?;
        let update = macos::new_services(
            &journal.original.0,
            &journal.applied.0,
            &observed.0,
            self.endpoint,
        )
        .map_err(|error| map_backend_error("准备新网络服务代理", BackendError::Io(error)))?;
        let Some((original, applied, additions)) = update else {
            return Ok(());
        };
        journal.original = ProxySnapshot(original);
        journal.applied = ProxySnapshot(applied);
        // Persist ownership before touching the newly discovered service.
        write_journal(&self.manager.inner.journal_path, &journal)?;
        self.manager
            .install(&ProxySnapshot(additions.clone()), "应用新网络服务代理")?;
        let current = self.manager.capture("回读新网络服务代理")?;
        if !macos::contains_services(&current.0, &additions)
            .map_err(|error| map_backend_error("验证新网络服务代理", BackendError::Io(error)))?
        {
            return Err(SystemProxyError::VerificationFailed {
                operation: "应用新网络服务代理",
            });
        }
        Ok(())
    }

    /// Restores the original proxy if this lease still owns the observed state.
    ///
    /// # Errors
    ///
    /// Returns an error when ownership metadata changed, the backend cannot
    /// query or restore settings, or restore verification fails. The journal is
    /// retained when restoration remains retryable.
    pub async fn restore(&mut self) -> Result<RestoreOutcome, SystemProxyError> {
        if !self.armed {
            return Ok(RestoreOutcome::AlreadyRestored);
        }
        let manager = self.manager.clone();
        let _operation = manager.inner.operation_gate.lock().await;
        let result = manager.restore_owner(self.owner);
        if result.is_ok() {
            self.armed = false;
        }
        result
    }
}

impl Drop for SystemProxyLease {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(mut active_owner) = self.manager.inner.active_owner.lock()
            && active_owner.as_ref() == Some(&self.owner)
        {
            *active_owner = None;
        }
        tracing::warn!("system proxy lease dropped without explicit restore; journal retained");
    }
}

/// Result of startup reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconcileOutcome {
    NothingToDo,
    ClearedPrepared,
    Restored,
    AlreadyRestored,
    ExternalChangePreserved,
}

/// Result of releasing a live lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreOutcome {
    Restored,
    AlreadyRestored,
    ExternalChangePreserved,
}

/// Safe, redacted failures from system proxy ownership operations.
#[derive(Error)]
pub enum SystemProxyError {
    #[error("当前平台缺少完整且安全的系统代理实现：{0}")]
    Unsupported(&'static str),
    #[error("系统代理已由当前进程中的活动租约持有")]
    AlreadyOwned,
    #[error("系统代理端点必须是非零端口的 IPv4 回环地址")]
    InvalidEndpoint,
    #[error("系统代理租约与持久化所有者不匹配")]
    LeaseMismatch,
    #[error("系统代理租约日志{action}失败")]
    JournalIo {
        action: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("系统代理租约日志损坏：{0}")]
    CorruptJournal(&'static str),
    #[error("系统代理{operation}失败")]
    Backend {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("系统代理{operation}后回读验证失败")]
    VerificationFailed { operation: &'static str },
    #[error("系统代理管理器内部状态不可用")]
    InternalState,
}

impl fmt::Debug for SystemProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(reason) => {
                formatter.debug_tuple("Unsupported").field(reason).finish()
            }
            Self::AlreadyOwned => formatter.write_str("AlreadyOwned"),
            Self::InvalidEndpoint => formatter.write_str("InvalidEndpoint"),
            Self::LeaseMismatch => formatter.write_str("LeaseMismatch"),
            Self::JournalIo { action, source } => formatter
                .debug_struct("JournalIo")
                .field("action", action)
                .field("kind", &source.kind())
                .finish(),
            Self::CorruptJournal(reason) => formatter
                .debug_tuple("CorruptJournal")
                .field(reason)
                .finish(),
            Self::Backend { operation, source } => formatter
                .debug_struct("Backend")
                .field("operation", operation)
                .field("kind", &source.kind())
                .finish(),
            Self::VerificationFailed { operation } => formatter
                .debug_struct("VerificationFailed")
                .field("operation", operation)
                .finish(),
            Self::InternalState => formatter.write_str("InternalState"),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ProxySnapshot(Vec<u8>);

impl fmt::Debug for ProxySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxySnapshot")
            .field("bytes", &"<redacted>")
            .field("length", &self.0.len())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JournalPhase {
    Prepared,
    Active,
}

struct ProxyJournal {
    owner: Uuid,
    phase: JournalPhase,
    original: ProxySnapshot,
    applied: ProxySnapshot,
}

#[derive(Deserialize, Serialize)]
struct StoredProxyJournal {
    version: u8,
    owner: String,
    phase: StoredJournalPhase,
    original: String,
    applied: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum StoredJournalPhase {
    Prepared,
    Active,
}

impl From<JournalPhase> for StoredJournalPhase {
    fn from(value: JournalPhase) -> Self {
        match value {
            JournalPhase::Prepared => Self::Prepared,
            JournalPhase::Active => Self::Active,
        }
    }
}

impl From<StoredJournalPhase> for JournalPhase {
    fn from(value: StoredJournalPhase) -> Self {
        match value {
            StoredJournalPhase::Prepared => Self::Prepared,
            StoredJournalPhase::Active => Self::Active,
        }
    }
}

fn write_journal(path: &Path, journal: &ProxyJournal) -> Result<(), SystemProxyError> {
    validate_snapshot(&journal.original)?;
    validate_snapshot(&journal.applied)?;
    let stored = StoredProxyJournal {
        version: JOURNAL_VERSION,
        owner: journal.owner.to_string(),
        phase: journal.phase.into(),
        original: BASE64.encode(&journal.original.0),
        applied: BASE64.encode(&journal.applied.0),
    };
    let content = serde_json::to_vec(&stored)
        .map_err(|_| SystemProxyError::CorruptJournal("无法序列化日志"))?;
    if content.len() > MAX_JOURNAL_BYTES {
        return Err(SystemProxyError::CorruptJournal("日志超过安全大小限制"));
    }
    atomic_write(path, &content)
}

fn read_journal(path: &Path) -> Result<Option<ProxyJournal>, SystemProxyError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(SystemProxyError::JournalIo {
                action: "读取",
                source,
            });
        }
    };
    let mut content = Vec::new();
    file.take((MAX_JOURNAL_BYTES + 1) as u64)
        .read_to_end(&mut content)
        .map_err(|source| SystemProxyError::JournalIo {
            action: "读取",
            source,
        })?;
    if content.len() > MAX_JOURNAL_BYTES {
        return Err(SystemProxyError::CorruptJournal("日志超过安全大小限制"));
    }
    let stored: StoredProxyJournal = serde_json::from_slice(&content)
        .map_err(|_| SystemProxyError::CorruptJournal("日志格式无效"))?;
    if stored.version != JOURNAL_VERSION {
        return Err(SystemProxyError::CorruptJournal("日志版本不受支持"));
    }
    let owner = Uuid::parse_str(&stored.owner)
        .map_err(|_| SystemProxyError::CorruptJournal("所有者标识无效"))?;
    let original = decode_snapshot(&stored.original)?;
    let applied = decode_snapshot(&stored.applied)?;
    Ok(Some(ProxyJournal {
        owner,
        phase: stored.phase.into(),
        original,
        applied,
    }))
}

fn decode_snapshot(encoded: &str) -> Result<ProxySnapshot, SystemProxyError> {
    if encoded.len() > MAX_SNAPSHOT_BYTES.saturating_mul(2) {
        return Err(SystemProxyError::CorruptJournal("代理快照超过安全大小限制"));
    }
    let bytes = BASE64
        .decode(encoded)
        .map_err(|_| SystemProxyError::CorruptJournal("代理快照编码无效"))?;
    let snapshot = ProxySnapshot(bytes);
    validate_snapshot(&snapshot)?;
    Ok(snapshot)
}

fn validate_snapshot(snapshot: &ProxySnapshot) -> Result<(), SystemProxyError> {
    if snapshot.0.len() > MAX_SNAPSHOT_BYTES {
        return Err(SystemProxyError::CorruptJournal("代理快照超过安全大小限制"));
    }
    Ok(())
}

fn atomic_write(path: &Path, content: &[u8]) -> Result<(), SystemProxyError> {
    let parent = path
        .parent()
        .ok_or(SystemProxyError::CorruptJournal("日志路径缺少父目录"))?;
    std::fs::create_dir_all(parent).map_err(|source| SystemProxyError::JournalIo {
        action: "创建目录",
        source,
    })?;
    #[cfg(not(unix))]
    let options = atomic_write_file::OpenOptions::new();
    #[cfg(unix)]
    let mut options = atomic_write_file::OpenOptions::new();
    #[cfg(unix)]
    {
        atomic_write_file::unix::OpenOptionsExt::preserve_mode(&mut options, false);
        atomic_write_file::unix::OpenOptionsExt::try_preserve_owner(&mut options, false);
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|source| SystemProxyError::JournalIo {
            action: "打开",
            source,
        })?;
    file.write_all(content)
        .map_err(|source| SystemProxyError::JournalIo {
            action: "写入",
            source,
        })?;
    file.commit().map_err(|source| SystemProxyError::JournalIo {
        action: "提交",
        source,
    })
}

fn remove_journal(path: &Path) -> Result<(), SystemProxyError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(SystemProxyError::JournalIo {
            action: "删除",
            source,
        }),
    }
}

trait SystemProxyBackend: Send + Sync {
    fn capture(&self) -> Result<ProxySnapshot, BackendError>;
    fn local_proxy_snapshot(
        &self,
        original: &ProxySnapshot,
        endpoint: SocketAddrV4,
    ) -> Result<ProxySnapshot, BackendError>;
    fn install(&self, snapshot: &ProxySnapshot) -> Result<(), BackendError>;
    fn restoration_target(
        &self,
        original: &ProxySnapshot,
        applied: &ProxySnapshot,
        observed: &ProxySnapshot,
    ) -> Result<Option<ProxySnapshot>, BackendError> {
        Ok((observed == applied).then(|| original.clone()))
    }
}

enum BackendError {
    #[cfg(all(not(windows), not(target_os = "macos")))]
    Unsupported(&'static str),
    #[cfg_attr(
        not(any(windows, test)),
        allow(
            dead_code,
            reason = "constructed by the Windows backend and cross-platform fake backend tests"
        )
    )]
    Io(io::Error),
}

fn map_backend_error(operation: &'static str, error: BackendError) -> SystemProxyError {
    match error {
        #[cfg(all(not(windows), not(target_os = "macos")))]
        BackendError::Unsupported(reason) => SystemProxyError::Unsupported(reason),
        BackendError::Io(source) => SystemProxyError::Backend { operation, source },
    }
}

struct PlatformSystemProxyBackend;

impl SystemProxyBackend for PlatformSystemProxyBackend {
    #[cfg(target_os = "macos")]
    fn restoration_target(
        &self,
        original: &ProxySnapshot,
        applied: &ProxySnapshot,
        observed: &ProxySnapshot,
    ) -> Result<Option<ProxySnapshot>, BackendError> {
        macos::restore_target(&original.0, &applied.0, &observed.0)
            .map(|target| target.map(ProxySnapshot))
            .map_err(BackendError::Io)
    }

    fn capture(&self) -> Result<ProxySnapshot, BackendError> {
        #[cfg(windows)]
        {
            wininet::capture()
                .map(ProxySnapshot)
                .map_err(BackendError::Io)
        }
        #[cfg(target_os = "linux")]
        {
            if !gnome::available() {
                return Err(BackendError::Unsupported("系统代理模式需要 GNOME 桌面"));
            }
            gnome::capture()
                .map(ProxySnapshot)
                .map_err(BackendError::Io)
        }
        #[cfg(target_os = "macos")]
        {
            macos::capture()
                .map(ProxySnapshot)
                .map_err(BackendError::Io)
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            Err(BackendError::Unsupported(platform_unsupported_reason()))
        }
    }

    fn local_proxy_snapshot(
        &self,
        original: &ProxySnapshot,
        endpoint: SocketAddrV4,
    ) -> Result<ProxySnapshot, BackendError> {
        #[cfg(windows)]
        {
            wininet::local_proxy_snapshot(&original.0, endpoint)
                .map(ProxySnapshot)
                .map_err(BackendError::Io)
        }
        #[cfg(target_os = "linux")]
        {
            gnome::local_proxy_snapshot(&original.0, endpoint)
                .map(ProxySnapshot)
                .map_err(BackendError::Io)
        }
        #[cfg(target_os = "macos")]
        {
            macos::local_proxy_snapshot(&original.0, endpoint)
                .map(ProxySnapshot)
                .map_err(BackendError::Io)
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            let _ = (original, endpoint);
            Err(BackendError::Unsupported(platform_unsupported_reason()))
        }
    }

    fn install(&self, snapshot: &ProxySnapshot) -> Result<(), BackendError> {
        #[cfg(windows)]
        {
            wininet::install(&snapshot.0).map_err(BackendError::Io)
        }
        #[cfg(target_os = "linux")]
        {
            gnome::install(&snapshot.0).map_err(BackendError::Io)
        }
        #[cfg(target_os = "macos")]
        {
            macos::install(&snapshot.0).map_err(BackendError::Io)
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            let _ = snapshot;
            Err(BackendError::Unsupported(platform_unsupported_reason()))
        }
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
const fn platform_unsupported_reason() -> &'static str {
    "当前平台的系统代理后端不可用"
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        sync::Mutex as StdMutex,
    };

    use tempfile::TempDir;

    use super::*;

    const ORIGINAL_SECRET: &[u8] = b"flags=13;proxy=old-secret:8181;pac=https://secret/pac";
    const EXTERNAL_SECRET: &[u8] = b"external-owner-secret";

    struct FakeBackend {
        state: StdMutex<FakeState>,
    }

    struct FakeState {
        current: ProxySnapshot,
        installs: Vec<ProxySnapshot>,
        replace_after_install: Option<ProxySnapshot>,
        fail_install: bool,
    }

    impl FakeBackend {
        fn new(current: &[u8]) -> Self {
            Self {
                state: StdMutex::new(FakeState {
                    current: ProxySnapshot(current.to_vec()),
                    installs: Vec::new(),
                    replace_after_install: None,
                    fail_install: false,
                }),
            }
        }

        fn current_is(&self, expected: &[u8]) -> bool {
            self.state
                .lock()
                .is_ok_and(|state| state.current.0 == expected)
        }

        fn set_current(&self, snapshot: &[u8]) {
            if let Ok(mut state) = self.state.lock() {
                state.current = ProxySnapshot(snapshot.to_vec());
            }
        }

        fn replace_after_next_install(&self, snapshot: &[u8]) {
            if let Ok(mut state) = self.state.lock() {
                state.replace_after_install = Some(ProxySnapshot(snapshot.to_vec()));
            }
        }

        fn set_fail_install(&self, fail: bool) {
            if let Ok(mut state) = self.state.lock() {
                state.fail_install = fail;
            }
        }

        fn install_count(&self) -> usize {
            self.state.lock().map_or(0, |state| state.installs.len())
        }
    }

    impl SystemProxyBackend for FakeBackend {
        fn capture(&self) -> Result<ProxySnapshot, BackendError> {
            self.state
                .lock()
                .map(|state| state.current.clone())
                .map_err(|_| BackendError::Io(io::Error::other("fake state poisoned")))
        }

        fn local_proxy_snapshot(
            &self,
            _original: &ProxySnapshot,
            endpoint: SocketAddrV4,
        ) -> Result<ProxySnapshot, BackendError> {
            Ok(ProxySnapshot(
                format!("topnode-owned={endpoint}").into_bytes(),
            ))
        }

        fn install(&self, snapshot: &ProxySnapshot) -> Result<(), BackendError> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| BackendError::Io(io::Error::other("fake state poisoned")))?;
            if state.fail_install {
                return Err(BackendError::Io(io::Error::other("fake install failed")));
            }
            state.installs.push(snapshot.clone());
            state.current = state
                .replace_after_install
                .take()
                .unwrap_or_else(|| snapshot.clone());
            Ok(())
        }
    }

    fn fixture() -> (TempDir, PathBuf, Arc<FakeBackend>, SystemProxyManager) {
        let directory = TempDir::new().expect("temporary directory");
        let path = directory.path().join("system-proxy-lease.v1.json");
        let backend = Arc::new(FakeBackend::new(ORIGINAL_SECRET));
        let manager = SystemProxyManager::with_backend(path.clone(), backend.clone());
        (directory, path, backend, manager)
    }

    fn endpoint() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2_334)
    }

    fn applied_snapshot() -> ProxySnapshot {
        ProxySnapshot(b"topnode-owned=127.0.0.1:2334".to_vec())
    }

    fn prepared_journal() -> ProxyJournal {
        ProxyJournal {
            owner: Uuid::new_v4(),
            phase: JournalPhase::Prepared,
            original: ProxySnapshot(ORIGINAL_SECRET.to_vec()),
            applied: applied_snapshot(),
        }
    }

    #[tokio::test]
    async fn acquire_verifies_and_explicit_restore_round_trips_original() {
        let (_directory, path, backend, manager) = fixture();

        let mut lease = manager.acquire(endpoint()).await.expect("acquire lease");

        assert!(backend.current_is(&applied_snapshot().0));
        let journal = read_journal(&path)
            .expect("read journal")
            .expect("active journal");
        assert!(journal.phase == JournalPhase::Active);
        assert!(journal.original.0 == ORIGINAL_SECRET);
        assert!(journal.applied == applied_snapshot());

        let outcome = lease.restore().await.expect("restore lease");
        assert_eq!(outcome, RestoreOutcome::Restored);
        assert!(backend.current_is(ORIGINAL_SECRET));
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn crash_before_apply_clears_prepared_without_writing_proxy() {
        let (_directory, path, backend, manager) = fixture();
        write_journal(&path, &prepared_journal()).expect("write prepared journal");

        let outcome = manager.reconcile_stale().await.expect("reconcile");

        assert_eq!(outcome, ReconcileOutcome::ClearedPrepared);
        assert!(backend.current_is(ORIGINAL_SECRET));
        assert_eq!(backend.install_count(), 0);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn crash_after_apply_before_active_restores_from_prepared() {
        let (_directory, path, backend, manager) = fixture();
        let journal = prepared_journal();
        write_journal(&path, &journal).expect("write prepared journal");
        backend.set_current(&journal.applied.0);

        let outcome = manager.reconcile_stale().await.expect("reconcile");

        assert_eq!(outcome, ReconcileOutcome::Restored);
        assert!(backend.current_is(ORIGINAL_SECRET));
        assert_eq!(backend.install_count(), 1);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn stale_active_journal_restores_owned_state() {
        let (_directory, path, backend, manager) = fixture();
        let mut journal = prepared_journal();
        journal.phase = JournalPhase::Active;
        backend.set_current(&journal.applied.0);
        write_journal(&path, &journal).expect("write active journal");

        let outcome = manager.reconcile_stale().await.expect("reconcile");

        assert_eq!(outcome, ReconcileOutcome::Restored);
        assert!(backend.current_is(ORIGINAL_SECRET));
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn crash_after_restore_before_delete_only_clears_journal() {
        let (_directory, path, backend, manager) = fixture();
        let mut journal = prepared_journal();
        journal.phase = JournalPhase::Active;
        write_journal(&path, &journal).expect("write active journal");

        let outcome = manager.reconcile_stale().await.expect("reconcile");

        assert_eq!(outcome, ReconcileOutcome::AlreadyRestored);
        assert!(backend.current_is(ORIGINAL_SECRET));
        assert_eq!(backend.install_count(), 0);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn external_change_is_never_overwritten_during_restore() {
        let (_directory, path, backend, manager) = fixture();
        let mut lease = manager.acquire(endpoint()).await.expect("acquire lease");
        backend.set_current(EXTERNAL_SECRET);
        let installs_before_restore = backend.install_count();

        let outcome = lease.restore().await.expect("release ownership");

        assert_eq!(outcome, RestoreOutcome::ExternalChangePreserved);
        assert!(backend.current_is(EXTERNAL_SECRET));
        assert_eq!(backend.install_count(), installs_before_restore);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn failed_restore_keeps_lease_armed_and_owned_for_retry() {
        let (_directory, path, backend, manager) = fixture();
        let mut lease = manager.acquire(endpoint()).await.expect("acquire lease");
        backend.set_fail_install(true);

        let error = lease
            .restore()
            .await
            .expect_err("failed restore remains retryable");

        assert!(matches!(error, SystemProxyError::Backend { .. }));
        assert!(path.exists());
        assert!(backend.current_is(&applied_snapshot().0));
        assert!(matches!(
            manager.acquire(endpoint()).await,
            Err(SystemProxyError::AlreadyOwned)
        ));

        backend.set_fail_install(false);
        assert_eq!(
            lease.restore().await.expect("retry restore"),
            RestoreOutcome::Restored
        );
        assert!(backend.current_is(ORIGINAL_SECRET));
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn query_back_mismatch_fails_acquire_without_overwriting_external_change() {
        let (_directory, path, backend, manager) = fixture();
        backend.replace_after_next_install(EXTERNAL_SECRET);

        let error = manager
            .acquire(endpoint())
            .await
            .expect_err("query-back mismatch must fail");

        assert!(matches!(error, SystemProxyError::VerificationFailed { .. }));
        assert!(backend.current_is(EXTERNAL_SECRET));
        assert_eq!(backend.install_count(), 1);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn dropped_lease_leaves_recoverable_journal() {
        let (_directory, path, backend, manager) = fixture();
        let lease = manager.acquire(endpoint()).await.expect("acquire lease");
        drop(lease);

        let outcome = manager.reconcile_stale().await.expect("reconcile");

        assert_eq!(outcome, ReconcileOutcome::Restored);
        assert!(backend.current_is(ORIGINAL_SECRET));
        assert!(!path.exists());
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn unsupported_platform_still_initializes_when_no_journal_exists() {
        let directory = TempDir::new().expect("temporary directory");
        let path = directory.path().join("system-proxy-lease.v1.json");

        let (manager, outcome) = SystemProxyManager::initialize(&path)
            .await
            .expect("missing journal does not need backend");
        assert_eq!(outcome, ReconcileOutcome::NothingToDo);

        let error = manager
            .acquire(endpoint())
            .await
            .expect_err("platform backend intentionally fails closed");
        assert!(matches!(error, SystemProxyError::Unsupported(_)));
    }

    #[test]
    fn debug_and_errors_do_not_expose_proxy_or_pac_contents() {
        let (_directory, path, _backend, manager) = fixture();
        let snapshot = ProxySnapshot(ORIGINAL_SECRET.to_vec());
        let backend_error = SystemProxyError::Backend {
            operation: "test",
            source: io::Error::other(String::from_utf8_lossy(ORIGINAL_SECRET).into_owned()),
        };

        let rendered = format!("{snapshot:?} {manager:?} {backend_error:?} {backend_error}");

        assert!(!rendered.contains("old-secret"));
        assert!(!rendered.contains("https://secret/pac"));
        assert!(!rendered.contains(&BASE64.encode(ORIGINAL_SECRET)));
        assert!(manager.inner.journal_path == path);
    }
}
