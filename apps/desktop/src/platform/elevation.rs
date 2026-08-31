use std::{
    ffi::{OsStr, OsString},
    fmt, io,
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
    sync::{Arc, OnceLock},
    time::Duration,
};

use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use topnode_infrastructure::{DesktopSettings, InstanceGuard, InstanceLockError};

const ELEVATED_TUN_RESTART_ARGUMENT: &str = "--topnode-internal-elevated-tun-restart";
const ELEVATION_LAUNCHER_ARGUMENT: &str = "--topnode-internal-elevation-launcher";
const HANDOFF_PORT_ARGUMENT: &str = "--topnode-internal-handoff-port";
const HANDOFF_TOKEN_ARGUMENT: &str = "--topnode-internal-handoff-token";
const HANDOFF_TIMEOUT: Duration = Duration::from_secs(5);
const UAC_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
// Remote startup can spend up to 18 seconds on the three ordered configuration
// sources and 60 seconds on the configured API race before UI preflight.
const SUCCESSOR_PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(90);
const HANDOFF_PEER_READ_TIMEOUT: Duration = Duration::from_millis(500);
const HANDOFF_AUTH_PREFIX: &[u8] = b"TOPNODE-TUN-HANDOFF/4 ";
const HANDOFF_SUCCESSOR_KIND: u8 = b'S';
const HANDOFF_LAUNCHER_READY_KIND: u8 = b'L';
const HANDOFF_CANCELLED_KIND: u8 = b'C';
const HANDOFF_LAUNCHER_ERROR_KIND: u8 = b'E';
const HANDOFF_RELEASE: &[u8] = b"TOPNODE-TUN-HANDOFF/4 RELEASE\n";
const HANDOFF_READY: &[u8] = b"TOPNODE-TUN-HANDOFF/4 READY\n";
const HANDOFF_COMMIT: &[u8] = b"TOPNODE-TUN-HANDOFF/4 COMMIT\n";
const HANDOFF_COMMITTED: &[u8] = b"TOPNODE-TUN-HANDOFF/4 COMMITTED\n";
const HANDOFF_FINAL: &[u8] = b"TOPNODE-TUN-HANDOFF/4 FINAL\n";
const HANDOFF_ABORT: &[u8] = b"TOPNODE-TUN-HANDOFF/4 ABORT\n";
const HANDOFF_MAX_MESSAGE_LENGTH: usize = 64;
const HANDOFF_TOKEN_BYTES: usize = 16;
const HANDOFF_TOKEN_HEX_LENGTH: usize = HANDOFF_TOKEN_BYTES * 2;

#[cfg(windows)]
static RESTART_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
#[cfg(windows)]
static RESTART_LAUNCHED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static PRIMARY_INSTANCE_LEASE: OnceLock<Arc<PrimaryInstanceLease>> = OnceLock::new();

/// Result of a user-initiated request to make TUN privileges available.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunElevationOutcome {
    /// The current process already has the required permission.
    NotRequired,
    /// The elevated replacement completed the authenticated handoff and the
    /// current Slint event loop accepted a graceful shutdown request.
    RestartLaunched,
    /// The user dismissed or rejected the Windows UAC prompt.
    Cancelled,
}

/// Failure while checking privileges or performing the trusted UAC handoff.
#[derive(Debug, Error)]
pub enum TunElevationError {
    #[cfg(windows)]
    #[error("Windows TUN 提权接口失败: {0}")]
    Platform(#[source] win_desktop_utils::Error),
    #[error("提权重启的内部启动参数无效: {0}")]
    InvalidHandoff(&'static str),
    #[error("提权重启标记只能由已提权的 Windows 进程使用")]
    HandoffNotElevated,
    #[error("无法创建 TUN 提权交接通道: {0}")]
    HandoffBind(#[source] io::Error),
    #[cfg(windows)]
    #[error("无法启动 TUN 提权隔离程序: {0}")]
    LauncherSpawn(#[source] io::Error),
    #[error("TUN 提权隔离程序启动失败")]
    LauncherFailed,
    #[error("TUN 提权交接通信失败: {0}")]
    HandoffIo(#[source] io::Error),
    #[error("TUN 提权交接等待超时")]
    HandoffTimeout,
    #[error("等待 Windows 管理员授权超时")]
    UacResponseTimeout,
    #[error("TUN 提权交接确认无效")]
    HandoffRejected,
    #[error("TUN 提权交接的单实例状态无效: {0}")]
    InstanceLease(&'static str),
    #[error("TUN 提权交接无法取得单实例锁: {0}")]
    InstanceLock(#[source] InstanceLockError),
    #[cfg(not(windows))]
    #[error("当前平台尚未提供 TUN 权限适配")]
    UnsupportedPlatform,
    #[error("已完成提权交接，但无法请求当前 Slint 事件循环退出: {0}")]
    Shutdown(#[source] slint::EventLoopError),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum StartupKind {
    #[default]
    Normal,
    ElevatedRestartHandoff,
}

/// Startup behavior and, for an elevated replacement, its authenticated parent channel.
pub(crate) struct TunElevationStartupMode {
    kind: StartupKind,
    handoff: Option<ReplacementHandoff>,
}

impl fmt::Debug for TunElevationStartupMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TunElevationStartupMode")
            .field("kind", &self.kind)
            .field("handoff", &self.handoff.as_ref().map(|_| "authenticated"))
            .finish()
    }
}

impl TunElevationStartupMode {
    #[cfg_attr(not(windows), allow(clippy::unused_async))]
    pub(crate) async fn dispatch_launcher_if_requested() -> Result<bool, TunElevationError> {
        let request = parse_startup_request(std::env::args_os().skip(1))?;
        let StartupRequest::ElevationLauncher(credentials) = request else {
            return Ok(false);
        };

        #[cfg(not(windows))]
        {
            let _ = credentials;
            Err(TunElevationError::UnsupportedPlatform)
        }

        #[cfg(windows)]
        {
            run_elevation_launcher(credentials).await?;
            Ok(true)
        }
    }

    fn normal() -> Self {
        Self {
            kind: StartupKind::Normal,
            handoff: None,
        }
    }

    fn elevated(handoff: ReplacementHandoff) -> Self {
        Self {
            kind: StartupKind::ElevatedRestartHandoff,
            handoff: Some(handoff),
        }
    }

    #[cfg(test)]
    pub(crate) fn elevated_without_handoff_for_test() -> Self {
        Self {
            kind: StartupKind::ElevatedRestartHandoff,
            handoff: None,
        }
    }

    pub(crate) fn waits_for_previous_instance(&self) -> bool {
        self.kind == StartupKind::ElevatedRestartHandoff
    }

    pub(crate) fn retain_instance_lock(
        path: PathBuf,
        guard: InstanceGuard,
        gate_path: PathBuf,
        gate_guard: Option<InstanceGuard>,
    ) -> Result<(), TunElevationError> {
        PRIMARY_INSTANCE_LEASE
            .set(Arc::new(PrimaryInstanceLease::new(
                path, guard, gate_path, gate_guard,
            )))
            .map_err(|_| TunElevationError::InstanceLease("单实例锁已被注册"))
    }

    pub(crate) async fn await_successor_commit(&mut self) -> Result<(), TunElevationError> {
        let Some(handoff) = self.handoff.as_mut() else {
            return Ok(());
        };
        handoff.await_commit().await
    }

    pub(crate) async fn acknowledge_successor_commit(&mut self) -> Result<(), TunElevationError> {
        let Some(handoff) = self.handoff.as_mut() else {
            return Ok(());
        };
        let lease = PRIMARY_INSTANCE_LEASE
            .get()
            .cloned()
            .ok_or(TunElevationError::InstanceLease("提权实例未注册单实例锁"))?;
        handoff.acknowledge_commit().await?;
        // FINAL makes the old process exit irreversible. Gate acquisition is
        // therefore retried in the background and cannot kill the committed
        // successor. Releasing the primary lock for any later handoff still
        // waits until the gate is owned.
        lease.acquire_gate_in_background();
        Ok(())
    }
}

struct ReplacementHandoff {
    stream: TcpStream,
}

struct PrimaryInstanceLease {
    path: PathBuf,
    guard: tokio::sync::Mutex<Option<InstanceGuard>>,
    gate_path: PathBuf,
    gate_guard: tokio::sync::Mutex<Option<InstanceGuard>>,
}

impl PrimaryInstanceLease {
    fn new(
        path: PathBuf,
        guard: InstanceGuard,
        gate_path: PathBuf,
        gate_guard: Option<InstanceGuard>,
    ) -> Self {
        Self {
            path,
            guard: tokio::sync::Mutex::new(Some(guard)),
            gate_path,
            gate_guard: tokio::sync::Mutex::new(gate_guard),
        }
    }

    async fn release(&self) -> Result<(), TunElevationError> {
        self.acquire_gate().await?;
        self.guard
            .lock()
            .await
            .take()
            .ok_or(TunElevationError::InstanceLease("单实例锁未持有"))?;
        Ok(())
    }

    async fn acquire_gate(&self) -> Result<(), TunElevationError> {
        if self.gate_guard.lock().await.is_some() {
            return Ok(());
        }
        let gate = match InstanceGuard::acquire_after_restart_handoff(&self.gate_path).await {
            Ok(gate) => gate,
            // Graceful shutdown may include a bounded sidecar stop. Allow one
            // further bounded wait while retaining a finite total deadline.
            Err(InstanceLockError::RestartHandoffTimeout { .. }) => {
                InstanceGuard::acquire_after_restart_handoff(&self.gate_path)
                    .await
                    .map_err(TunElevationError::InstanceLock)?
            }
            Err(error) => return Err(TunElevationError::InstanceLock(error)),
        };
        let mut retained = self.gate_guard.lock().await;
        if retained.is_none() {
            *retained = Some(gate);
        }
        Ok(())
    }

    fn acquire_gate_in_background(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                match self.acquire_gate().await {
                    Ok(()) => {
                        tracing::info!("elevated replacement retained the handoff gate");
                        return;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "elevated replacement is retrying the handoff gate");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });
    }

    async fn restore(&self) -> Result<(), TunElevationError> {
        self.acquire_gate().await?;
        if self.guard.lock().await.is_some() {
            return Ok(());
        }
        let guard = InstanceGuard::acquire_after_restart_handoff(&self.path)
            .await
            .map_err(TunElevationError::InstanceLock)?;
        let mut retained = self.guard.lock().await;
        if retained.is_none() {
            *retained = Some(guard);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct HandoffToken([u8; HANDOFF_TOKEN_BYTES]);

impl fmt::Debug for HandoffToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HandoffToken([REDACTED])")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct HandoffCredentials {
    port: u16,
    token: HandoffToken,
}

impl fmt::Debug for HandoffCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandoffCredentials")
            .field("port", &self.port)
            .field("token", &self.token)
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq)]
enum StartupRequest {
    Normal,
    ElevatedRestart(HandoffCredentials),
    ElevationLauncher(HandoffCredentials),
}

#[derive(Debug)]
enum AuthenticatedPeer {
    Successor(TcpStream),
    LauncherReady,
    Cancelled,
    LauncherFailed,
}

/// Reports whether the current process may start a TUN configuration.
///
/// This check has no side effects: it never displays UAC, starts a process, or
/// mutates settings. Unsupported platforms fail closed.
pub fn tun_permission_available() -> Result<bool, TunElevationError> {
    #[cfg(not(windows))]
    {
        Ok(false)
    }

    #[cfg(windows)]
    {
        win_desktop_utils::is_elevated().map_err(TunElevationError::Platform)
    }
}

/// Requests an authenticated UAC restart of the entire desktop process.
///
/// The old instance binds a random loopback port before launching the elevated
/// replacement. The replacement receives only a fixed, strictly parsed set of
/// internal arguments and proves possession of a one-time random token. The old
/// event loop is asked to stop only after READY/ACK completes within five
/// seconds. The caller must never persist `tun_enabled = true`; the elevated
/// replacement performs that write only after it owns the single-instance lock.
#[cfg_attr(not(windows), allow(clippy::unused_async))]
pub async fn request_tun_elevation_restart() -> Result<TunElevationOutcome, TunElevationError> {
    #[cfg(not(windows))]
    {
        Err(TunElevationError::UnsupportedPlatform)
    }

    #[cfg(windows)]
    {
        request_windows_tun_elevation_restart().await
    }
}

/// Parses and completes the elevated side of the handoff before lock acquisition.
///
/// An internal handoff request is accepted only by an elevated Windows process.
/// That process must connect back and receive the authenticated ACK before it is
/// allowed to wait for the previous instance's lock.
#[cfg_attr(not(windows), allow(clippy::unused_async))]
pub(crate) async fn tun_elevation_startup_mode()
-> Result<TunElevationStartupMode, TunElevationError> {
    #[cfg(not(windows))]
    {
        Ok(TunElevationStartupMode::normal())
    }

    #[cfg(windows)]
    {
        match parse_startup_request(std::env::args_os().skip(1))? {
            StartupRequest::Normal => Ok(TunElevationStartupMode::normal()),
            StartupRequest::ElevatedRestart(credentials) => {
                if !tun_permission_available()? {
                    return Err(TunElevationError::HandoffNotElevated);
                }
                let handoff = ReplacementHandoff::begin(credentials, HANDOFF_TIMEOUT).await?;
                Ok(TunElevationStartupMode::elevated(handoff))
            }
            StartupRequest::ElevationLauncher(_) => Err(TunElevationError::InvalidHandoff(
                "提权隔离程序未在启动入口分派",
            )),
        }
    }
}

/// Applies the fail-closed startup policy to an in-memory settings snapshot.
///
/// The composition root calls this only after retaining the instance lock, and
/// persists a changed snapshot through [`topnode_infrastructure::SettingsStore`].
pub(crate) fn apply_tun_startup_policy(
    mode: &TunElevationStartupMode,
    permission_available: bool,
    settings: &mut DesktopSettings,
) -> Result<bool, TunElevationError> {
    let desired = match mode.kind {
        StartupKind::ElevatedRestartHandoff => {
            if !permission_available {
                return Err(TunElevationError::HandoffNotElevated);
            }
            true
        }
        // A normal launch preserves the user's committed preference. The
        // controller and engine still fail closed unless TUN permission is
        // actually available at connection time.
        StartupKind::Normal => settings.preferences.tun_enabled,
    };
    if settings.preferences.tun_enabled == desired {
        return Ok(false);
    }
    settings.preferences.tun_enabled = desired;
    Ok(true)
}

#[cfg(windows)]
async fn request_windows_tun_elevation_restart() -> Result<TunElevationOutcome, TunElevationError> {
    use std::sync::atomic::Ordering;

    let _guard = RESTART_GATE.lock().await;
    if RESTART_LAUNCHED.load(Ordering::Acquire) {
        return Ok(TunElevationOutcome::RestartLaunched);
    }
    if tun_permission_available()? {
        return Ok(TunElevationOutcome::NotRequired);
    }

    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(TunElevationError::HandoffBind)?;
    let port = listener
        .local_addr()
        .map_err(TunElevationError::HandoffBind)?
        .port();
    let token = HandoffToken(*uuid::Uuid::new_v4().as_bytes());
    let mut launcher = spawn_breakaway_launcher(port, token)?;

    let first_peer = match await_authenticated_peer(&listener, token, HANDOFF_TIMEOUT).await {
        Ok(peer) => peer,
        Err(error) => {
            terminate_elevation_launcher(&mut launcher);
            return Err(error);
        }
    };
    let peer = if matches!(first_peer, AuthenticatedPeer::LauncherReady) {
        tracing::info!("waiting for Windows elevation consent");
        match await_authenticated_peer(&listener, token, UAC_RESPONSE_TIMEOUT).await {
            Err(TunElevationError::HandoffTimeout) => {
                terminate_elevation_launcher(&mut launcher);
                return Err(TunElevationError::UacResponseTimeout);
            }
            Err(error) => {
                terminate_elevation_launcher(&mut launcher);
                return Err(error);
            }
            Ok(peer) => peer,
        }
    } else {
        first_peer
    };
    let mut stream = match peer {
        AuthenticatedPeer::Successor(stream) => {
            tracing::info!("elevated replacement authenticated");
            stream
        }
        AuthenticatedPeer::LauncherReady | AuthenticatedPeer::LauncherFailed => {
            return Err(TunElevationError::LauncherFailed);
        }
        AuthenticatedPeer::Cancelled => {
            tracing::info!("Windows elevation consent was cancelled");
            return Ok(TunElevationOutcome::Cancelled);
        }
    };
    let lease = PRIMARY_INSTANCE_LEASE
        .get()
        .cloned()
        .ok_or(TunElevationError::InstanceLease("主实例未注册单实例锁"))?;

    // The process-wide handoff gate remains held while the ordinary
    // single-instance lock is transferred. Normal launches must acquire that
    // gate first, so none can steal the primary lock from this authenticated
    // successor.
    lease.release().await?;
    let handoff_result = async {
        stream
            .write_all(HANDOFF_RELEASE)
            .await
            .map_err(TunElevationError::HandoffIo)?;
        stream.flush().await.map_err(TunElevationError::HandoffIo)?;
        await_successor_ready(&mut stream, SUCCESSOR_PREFLIGHT_TIMEOUT).await?;
        tracing::info!("elevated replacement preflight completed");
        stream
            .write_all(HANDOFF_COMMIT)
            .await
            .map_err(TunElevationError::HandoffIo)?;
        stream.flush().await.map_err(TunElevationError::HandoffIo)?;
        await_successor_committed(&mut stream, HANDOFF_TIMEOUT).await?;

        // FINAL is only permission to finish once this socket closes. The
        // successor keeps waiting, which leaves a synchronous window for the
        // old process to reject the handoff if Slint cannot accept shutdown.
        stream
            .write_all(HANDOFF_FINAL)
            .await
            .map_err(TunElevationError::HandoffIo)?;
        stream.flush().await.map_err(TunElevationError::HandoffIo)?;
        slint::quit_event_loop().map_err(TunElevationError::Shutdown)
    }
    .await;

    if let Err(error) = handoff_result {
        let _ = stream.write_all(HANDOFF_ABORT).await;
        let _ = stream.flush().await;
        drop(stream);
        lease.restore().await?;
        return Err(error);
    }

    // Closing the authenticated channel after FINAL is the successor's last
    // commit signal. There is no fallible handoff I/O after the old event loop
    // has accepted its shutdown request.
    drop(stream);
    RESTART_LAUNCHED.store(true, Ordering::Release);
    Ok(TunElevationOutcome::RestartLaunched)
}

fn elevated_restart_arguments(port: u16, token: HandoffToken) -> [OsString; 5] {
    handoff_arguments(ELEVATED_TUN_RESTART_ARGUMENT, port, token)
}

fn elevation_launcher_arguments(port: u16, token: HandoffToken) -> [OsString; 5] {
    handoff_arguments(ELEVATION_LAUNCHER_ARGUMENT, port, token)
}

fn handoff_arguments(marker: &'static str, port: u16, token: HandoffToken) -> [OsString; 5] {
    [
        OsString::from(marker),
        OsString::from(HANDOFF_PORT_ARGUMENT),
        OsString::from(port.to_string()),
        OsString::from(HANDOFF_TOKEN_ARGUMENT),
        OsString::from(encode_token(token)),
    ]
}

#[cfg(windows)]
fn spawn_breakaway_launcher(
    port: u16,
    token: HandoffToken,
) -> Result<std::process::Child, TunElevationError> {
    use std::{
        os::windows::process::CommandExt,
        process::{Command, Stdio},
    };

    // These documented Win32 flags are consumed through the safe standard
    // library CommandExt API. BREAKAWAY is honored only because the desktop's
    // containment Job explicitly opts into BREAKAWAY_OK; ordinary children do
    // not receive this flag and remain contained.
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let executable = std::env::current_exe().map_err(TunElevationError::LauncherSpawn)?;
    Command::new(executable)
        .args(elevation_launcher_arguments(port, token))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW)
        .spawn()
        .map_err(TunElevationError::LauncherSpawn)
}

#[cfg(windows)]
fn terminate_elevation_launcher(launcher: &mut std::process::Child) {
    if let Err(error) = launcher.kill() {
        tracing::debug!(%error, "elevation launcher had already stopped");
    }
}

#[cfg(windows)]
async fn run_elevation_launcher(credentials: HandoffCredentials) -> Result<(), TunElevationError> {
    notify_launcher_status(credentials, HANDOFF_LAUNCHER_READY_KIND).await?;
    match win_desktop_utils::restart_as_admin(&elevated_restart_arguments(
        credentials.port,
        credentials.token,
    )) {
        Ok(()) => Ok(()),
        Err(win_desktop_utils::Error::WindowsApi { code: 5 | 1223, .. }) => {
            notify_launcher_status(credentials, HANDOFF_CANCELLED_KIND).await
        }
        Err(error) => {
            notify_launcher_status(credentials, HANDOFF_LAUNCHER_ERROR_KIND).await?;
            Err(TunElevationError::Platform(error))
        }
    }
}

#[cfg(windows)]
async fn notify_launcher_status(
    credentials: HandoffCredentials,
    kind: u8,
) -> Result<(), TunElevationError> {
    tokio::time::timeout(HANDOFF_TIMEOUT, async {
        let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, credentials.port);
        let mut stream = TcpStream::connect(address)
            .await
            .map_err(TunElevationError::HandoffIo)?;
        stream
            .write_all(&auth_message(kind, credentials.token))
            .await
            .map_err(TunElevationError::HandoffIo)?;
        stream.flush().await.map_err(TunElevationError::HandoffIo)
    })
    .await
    .map_err(|_| TunElevationError::HandoffTimeout)?
}

fn parse_startup_request(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<StartupRequest, TunElevationError> {
    let mut arguments = arguments.into_iter();
    let Some(mode) = arguments.next() else {
        return Ok(StartupRequest::Normal);
    };
    let elevated_restart = mode == OsStr::new(ELEVATED_TUN_RESTART_ARGUMENT);
    let elevation_launcher = mode == OsStr::new(ELEVATION_LAUNCHER_ARGUMENT);
    if !elevated_restart && !elevation_launcher {
        return Ok(StartupRequest::Normal);
    }

    let port_flag = arguments
        .next()
        .ok_or(TunElevationError::InvalidHandoff("缺少交接端口标记"))?;
    let port_value = arguments
        .next()
        .ok_or(TunElevationError::InvalidHandoff("缺少交接端口"))?;
    let token_flag = arguments
        .next()
        .ok_or(TunElevationError::InvalidHandoff("缺少交接令牌标记"))?;
    let token_value = arguments
        .next()
        .ok_or(TunElevationError::InvalidHandoff("缺少交接令牌"))?;
    if arguments.next().is_some() {
        return Err(TunElevationError::InvalidHandoff(
            "内部重启标记不允许附加参数",
        ));
    }
    if port_flag != OsStr::new(HANDOFF_PORT_ARGUMENT)
        || token_flag != OsStr::new(HANDOFF_TOKEN_ARGUMENT)
    {
        return Err(TunElevationError::InvalidHandoff("交接参数标记无效"));
    }

    let port = port_value
        .to_str()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or(TunElevationError::InvalidHandoff("交接端口无效"))?;
    let token = token_value
        .to_str()
        .and_then(decode_token)
        .ok_or(TunElevationError::InvalidHandoff("交接令牌无效"))?;

    let credentials = HandoffCredentials { port, token };
    if elevated_restart {
        Ok(StartupRequest::ElevatedRestart(credentials))
    } else {
        Ok(StartupRequest::ElevationLauncher(credentials))
    }
}

async fn await_authenticated_peer(
    listener: &TcpListener,
    token: HandoffToken,
    timeout: Duration,
) -> Result<AuthenticatedPeer, TunElevationError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or(TunElevationError::HandoffTimeout)?;
        let accepted = tokio::time::timeout(remaining, listener.accept())
            .await
            .map_err(|_| TunElevationError::HandoffTimeout)?
            .map_err(TunElevationError::HandoffIo)?;
        let (mut stream, peer) = accepted;
        if !peer.ip().is_loopback() {
            continue;
        }

        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or(TunElevationError::HandoffTimeout)?;
        let peer_timeout = remaining.min(HANDOFF_PEER_READ_TIMEOUT);
        if let Ok(Ok(Some(kind))) =
            tokio::time::timeout(peer_timeout, authenticate_peer(&mut stream, token)).await
        {
            return match kind {
                HANDOFF_SUCCESSOR_KIND => Ok(AuthenticatedPeer::Successor(stream)),
                HANDOFF_LAUNCHER_READY_KIND => Ok(AuthenticatedPeer::LauncherReady),
                HANDOFF_CANCELLED_KIND => Ok(AuthenticatedPeer::Cancelled),
                HANDOFF_LAUNCHER_ERROR_KIND => Ok(AuthenticatedPeer::LauncherFailed),
                _ => continue,
            };
        }
    }
}

async fn authenticate_peer(stream: &mut TcpStream, token: HandoffToken) -> io::Result<Option<u8>> {
    let expected = auth_message(HANDOFF_SUCCESSOR_KIND, token);
    let mut received = vec![0_u8; expected.len()];
    stream.read_exact(&mut received).await?;
    for kind in [
        HANDOFF_SUCCESSOR_KIND,
        HANDOFF_LAUNCHER_READY_KIND,
        HANDOFF_CANCELLED_KIND,
        HANDOFF_LAUNCHER_ERROR_KIND,
    ] {
        if constant_time_eq(&received, &auth_message(kind, token)) {
            return Ok(Some(kind));
        }
    }
    Ok(None)
}

async fn await_successor_ready(
    stream: &mut TcpStream,
    timeout: Duration,
) -> Result<(), TunElevationError> {
    await_successor_message(stream, HANDOFF_READY, timeout).await
}

async fn await_successor_committed(
    stream: &mut TcpStream,
    timeout: Duration,
) -> Result<(), TunElevationError> {
    await_successor_message(stream, HANDOFF_COMMITTED, timeout).await
}

async fn await_successor_message(
    stream: &mut TcpStream,
    expected: &[u8],
    timeout: Duration,
) -> Result<(), TunElevationError> {
    let Some(message) = read_handoff_message(stream, timeout).await? else {
        return Err(TunElevationError::HandoffRejected);
    };
    if constant_time_eq(&message, expected) {
        Ok(())
    } else {
        Err(TunElevationError::HandoffRejected)
    }
}

async fn read_handoff_message(
    stream: &mut TcpStream,
    timeout: Duration,
) -> Result<Option<Vec<u8>>, TunElevationError> {
    tokio::time::timeout(timeout, async {
        let mut message = Vec::with_capacity(HANDOFF_COMMIT.len());
        loop {
            let mut byte = [0_u8; 1];
            let read = stream
                .read(&mut byte)
                .await
                .map_err(TunElevationError::HandoffIo)?;
            if read == 0 {
                return if message.is_empty() {
                    Ok(None)
                } else {
                    Err(TunElevationError::HandoffRejected)
                };
            }
            message.push(byte[0]);
            if byte[0] == b'\n' {
                return Ok(Some(message));
            }
            if message.len() >= HANDOFF_MAX_MESSAGE_LENGTH {
                return Err(TunElevationError::HandoffRejected);
            }
        }
    })
    .await
    .map_err(|_| TunElevationError::HandoffTimeout)?
}

impl ReplacementHandoff {
    async fn begin(
        credentials: HandoffCredentials,
        timeout: Duration,
    ) -> Result<Self, TunElevationError> {
        let mut stream = tokio::time::timeout(timeout, async {
            let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, credentials.port);
            let mut stream = TcpStream::connect(address)
                .await
                .map_err(TunElevationError::HandoffIo)?;
            stream
                .write_all(&auth_message(HANDOFF_SUCCESSOR_KIND, credentials.token))
                .await
                .map_err(TunElevationError::HandoffIo)?;
            stream.flush().await.map_err(TunElevationError::HandoffIo)?;
            Ok::<_, TunElevationError>(stream)
        })
        .await
        .map_err(|_| TunElevationError::HandoffTimeout)??;

        let mut release = vec![0_u8; HANDOFF_RELEASE.len()];
        tokio::time::timeout(timeout, stream.read_exact(&mut release))
            .await
            .map_err(|_| TunElevationError::HandoffTimeout)?
            .map_err(TunElevationError::HandoffIo)?;
        if !constant_time_eq(&release, HANDOFF_RELEASE) {
            return Err(TunElevationError::HandoffRejected);
        }
        Ok(Self { stream })
    }

    async fn await_commit(&mut self) -> Result<(), TunElevationError> {
        self.stream
            .write_all(HANDOFF_READY)
            .await
            .map_err(TunElevationError::HandoffIo)?;
        self.stream
            .flush()
            .await
            .map_err(TunElevationError::HandoffIo)?;

        await_successor_message(&mut self.stream, HANDOFF_COMMIT, HANDOFF_TIMEOUT).await
    }

    async fn acknowledge_commit(&mut self) -> Result<(), TunElevationError> {
        self.stream
            .write_all(HANDOFF_COMMITTED)
            .await
            .map_err(TunElevationError::HandoffIo)?;
        self.stream
            .flush()
            .await
            .map_err(TunElevationError::HandoffIo)?;

        let mut final_authorized = false;
        loop {
            match read_handoff_message(&mut self.stream, HANDOFF_TIMEOUT).await? {
                Some(message) if constant_time_eq(&message, HANDOFF_FINAL) => {
                    final_authorized = true;
                }
                Some(message) if constant_time_eq(&message, HANDOFF_ABORT) => {
                    return Err(TunElevationError::HandoffRejected);
                }
                None if final_authorized => return Ok(()),
                Some(_) | None => return Err(TunElevationError::HandoffRejected),
            }
        }
    }
}

fn auth_message(kind: u8, token: HandoffToken) -> Vec<u8> {
    let mut message = Vec::with_capacity(HANDOFF_AUTH_PREFIX.len() + HANDOFF_TOKEN_HEX_LENGTH + 3);
    message.extend_from_slice(HANDOFF_AUTH_PREFIX);
    message.push(kind);
    message.push(b' ');
    message.extend_from_slice(encode_token(token).as_bytes());
    message.push(b'\n');
    message
}

fn encode_token(token: HandoffToken) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(HANDOFF_TOKEN_HEX_LENGTH);
    for byte in token.0 {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_token(value: &str) -> Option<HandoffToken> {
    if value.len() != HANDOFF_TOKEN_HEX_LENGTH
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return None;
    }

    let mut decoded = [0_u8; HANDOFF_TOKEN_BYTES];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(HandoffToken(decoded))
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsString,
        net::Ipv4Addr,
        time::{Duration, SystemTime},
    };

    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
    };
    use topnode_infrastructure::{DesktopSettings, InstanceGuard, InstanceLockError};

    use super::{
        AuthenticatedPeer, ELEVATED_TUN_RESTART_ARGUMENT, ELEVATION_LAUNCHER_ARGUMENT,
        HANDOFF_CANCELLED_KIND, HANDOFF_COMMIT, HANDOFF_FINAL, HANDOFF_LAUNCHER_ERROR_KIND,
        HANDOFF_PORT_ARGUMENT, HANDOFF_RELEASE, HANDOFF_TOKEN_ARGUMENT, HandoffCredentials,
        HandoffToken, PrimaryInstanceLease, ReplacementHandoff, StartupKind, StartupRequest,
        TunElevationError, TunElevationStartupMode, apply_tun_startup_policy, auth_message,
        await_authenticated_peer, await_successor_committed, await_successor_ready,
        elevated_restart_arguments, elevation_launcher_arguments, encode_token,
        parse_startup_request,
    };

    const TEST_TOKEN: HandoffToken = HandoffToken([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ]);

    #[test]
    fn normal_launch_is_not_treated_as_an_elevation_handoff() {
        assert_eq!(
            parse_startup_request(Vec::<OsString>::new()).expect("normal startup"),
            StartupRequest::Normal
        );
        assert_eq!(
            parse_startup_request([OsString::from("--unrelated")])
                .expect("unrelated startup argument"),
            StartupRequest::Normal
        );
    }

    #[test]
    fn elevation_handoff_accepts_only_the_fixed_argument_shape() {
        let encoded = encode_token(TEST_TOKEN);
        let request = parse_startup_request([
            OsString::from(ELEVATED_TUN_RESTART_ARGUMENT),
            OsString::from(HANDOFF_PORT_ARGUMENT),
            OsString::from("49152"),
            OsString::from(HANDOFF_TOKEN_ARGUMENT),
            OsString::from(&encoded),
        ])
        .expect("trusted handoff");
        assert_eq!(
            request,
            StartupRequest::ElevatedRestart(HandoffCredentials {
                port: 49_152,
                token: TEST_TOKEN,
            })
        );

        assert_eq!(
            parse_startup_request(elevation_launcher_arguments(49_152, TEST_TOKEN))
                .expect("trusted launcher"),
            StartupRequest::ElevationLauncher(HandoffCredentials {
                port: 49_152,
                token: TEST_TOKEN,
            })
        );

        let error = parse_startup_request([
            OsString::from(ELEVATED_TUN_RESTART_ARGUMENT),
            OsString::from(HANDOFF_PORT_ARGUMENT),
            OsString::from("49152"),
            OsString::from(HANDOFF_TOKEN_ARGUMENT),
            OsString::from(encoded),
            OsString::from("--forwarded-argument"),
        ])
        .expect_err("untrusted trailing arguments must be rejected");
        assert!(matches!(error, TunElevationError::InvalidHandoff(_)));
    }

    #[test]
    fn elevation_handoff_rejects_non_whitelisted_values() {
        for arguments in [
            vec![OsString::from(ELEVATED_TUN_RESTART_ARGUMENT)],
            vec![
                OsString::from(ELEVATED_TUN_RESTART_ARGUMENT),
                OsString::from(HANDOFF_PORT_ARGUMENT),
                OsString::from("0"),
                OsString::from(HANDOFF_TOKEN_ARGUMENT),
                OsString::from(encode_token(TEST_TOKEN)),
            ],
            vec![
                OsString::from(ELEVATED_TUN_RESTART_ARGUMENT),
                OsString::from(HANDOFF_PORT_ARGUMENT),
                OsString::from("49152"),
                OsString::from(HANDOFF_TOKEN_ARGUMENT),
                OsString::from("ABCDEF"),
            ],
        ] {
            assert!(matches!(
                parse_startup_request(arguments),
                Err(TunElevationError::InvalidHandoff(_))
            ));
        }
    }

    #[test]
    fn elevated_restart_arguments_are_fixed_and_do_not_expose_tokens_in_debug() {
        let arguments = elevated_restart_arguments(49_152, TEST_TOKEN);
        assert_eq!(arguments[0], ELEVATED_TUN_RESTART_ARGUMENT);
        assert_eq!(arguments[1], HANDOFF_PORT_ARGUMENT);
        assert_eq!(arguments[2], "49152");
        assert_eq!(arguments[3], HANDOFF_TOKEN_ARGUMENT);
        assert_eq!(arguments[4], OsString::from(encode_token(TEST_TOKEN)));
        assert_eq!(
            elevation_launcher_arguments(49_152, TEST_TOKEN)[0],
            ELEVATION_LAUNCHER_ARGUMENT
        );

        let credentials = HandoffCredentials {
            port: 49_152,
            token: TEST_TOKEN,
        };
        assert!(!format!("{credentials:?}").contains(&encode_token(TEST_TOKEN)));
    }

    #[tokio::test]
    async fn successor_owns_instance_lock_before_parent_accepts_ready() {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let lock_path = std::env::temp_dir().join(format!(
            "topnode-elevation-{}-{nonce}.lock",
            std::process::id()
        ));
        let parent_guard = InstanceGuard::acquire(&lock_path).expect("parent lock");
        let gate_path = lock_path.with_extension("handoff.lock");
        let parent_gate_guard = InstanceGuard::acquire(&gate_path).expect("parent handoff gate");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback listener");
        let port = listener.local_addr().expect("listener address").port();
        let parent_lock_path = lock_path.clone();
        let parent_gate_path = gate_path.clone();
        let parent = tokio::spawn(async move {
            let AuthenticatedPeer::Successor(mut stream) =
                await_authenticated_peer(&listener, TEST_TOKEN, Duration::from_secs(1))
                    .await
                    .expect("authenticated successor")
            else {
                panic!("expected successor");
            };
            drop(parent_guard);
            stream
                .write_all(HANDOFF_RELEASE)
                .await
                .expect("release instruction");
            stream.flush().await.expect("release flush");
            await_successor_ready(&mut stream, Duration::from_secs(1))
                .await
                .expect("successor ready");
            assert!(matches!(
                InstanceGuard::acquire(&parent_lock_path),
                Err(InstanceLockError::AlreadyRunning)
            ));
            assert!(matches!(
                InstanceGuard::acquire(&parent_gate_path),
                Err(InstanceLockError::AlreadyRunning)
            ));
            stream
                .write_all(HANDOFF_COMMIT)
                .await
                .expect("commit instruction");
            stream.flush().await.expect("commit flush");
            await_successor_committed(&mut stream, Duration::from_secs(1))
                .await
                .expect("successor committed");
            assert!(matches!(
                InstanceGuard::acquire(&parent_lock_path),
                Err(InstanceLockError::AlreadyRunning)
            ));
            assert!(matches!(
                InstanceGuard::acquire(&parent_gate_path),
                Err(InstanceLockError::AlreadyRunning)
            ));
            stream
                .write_all(HANDOFF_FINAL)
                .await
                .expect("final instruction");
            stream.flush().await.expect("final flush");
            drop(parent_gate_guard);
        });

        let mut replacement = ReplacementHandoff::begin(
            HandoffCredentials {
                port,
                token: TEST_TOKEN,
            },
            Duration::from_secs(1),
        )
        .await
        .expect("replacement should receive lock release");
        let replacement_guard =
            InstanceGuard::acquire(&lock_path).expect("successor must acquire lock before ready");
        replacement
            .await_commit()
            .await
            .expect("replacement should receive commit");
        replacement
            .acknowledge_commit()
            .await
            .expect("replacement should receive final shutdown signal");
        parent.await.expect("parent handshake task");
        let replacement_gate_guard = InstanceGuard::acquire_after_restart_handoff(&gate_path)
            .await
            .expect("successor must acquire the gate after the old process exits");
        drop(replacement_gate_guard);
        drop(replacement_guard);
        std::fs::remove_file(lock_path).expect("temporary lock cleanup");
        std::fs::remove_file(gate_path).expect("temporary gate cleanup");
    }

    #[tokio::test]
    async fn failed_handoff_restores_primary_lock_before_releasing_gate() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let lock_path = directory.path().join("instance.lock");
        let gate_path = directory.path().join("instance-handoff.lock");
        let lease = PrimaryInstanceLease::new(
            lock_path.clone(),
            InstanceGuard::acquire(&lock_path).expect("parent lock"),
            gate_path.clone(),
            Some(InstanceGuard::acquire(&gate_path).expect("parent gate")),
        );

        lease.release().await.expect("handoff releases main lock");
        assert!(matches!(
            InstanceGuard::acquire(&gate_path),
            Err(InstanceLockError::AlreadyRunning)
        ));

        lease
            .restore()
            .await
            .expect("failed handoff restores locks");
        assert!(matches!(
            InstanceGuard::acquire(&gate_path),
            Err(InstanceLockError::AlreadyRunning)
        ));
        assert!(matches!(
            InstanceGuard::acquire(&lock_path),
            Err(InstanceLockError::AlreadyRunning)
        ));
    }

    #[tokio::test]
    async fn parent_handshake_timeout_is_bounded() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback listener");
        let error = await_authenticated_peer(&listener, TEST_TOKEN, Duration::from_millis(20))
            .await
            .expect_err("missing replacement must time out");
        assert!(matches!(error, TunElevationError::HandoffTimeout));
    }

    #[tokio::test]
    async fn parent_distinguishes_cancelled_and_failed_launchers() {
        for (kind, cancelled) in [
            (HANDOFF_CANCELLED_KIND, true),
            (HANDOFF_LAUNCHER_ERROR_KIND, false),
        ] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("loopback listener");
            let address = listener.local_addr().expect("listener address");
            let sender = tokio::spawn(async move {
                let mut stream = TcpStream::connect(address).await.expect("status connect");
                stream
                    .write_all(&auth_message(kind, TEST_TOKEN))
                    .await
                    .expect("status write");
                stream.flush().await.expect("status flush");
            });
            let peer = await_authenticated_peer(&listener, TEST_TOKEN, Duration::from_secs(1))
                .await
                .expect("authenticated launcher status");
            if cancelled {
                assert!(matches!(peer, AuthenticatedPeer::Cancelled));
            } else {
                assert!(matches!(peer, AuthenticatedPeer::LauncherFailed));
            }
            sender.await.expect("status sender");
        }
    }

    #[test]
    fn elevated_handoff_enables_tun_only_with_permission() {
        let mut settings = DesktopSettings::default();
        let startup = TunElevationStartupMode {
            kind: StartupKind::ElevatedRestartHandoff,
            handoff: None,
        };
        assert!(
            apply_tun_startup_policy(&startup, true, &mut settings)
                .expect("elevated handoff should be accepted")
        );
        assert!(settings.preferences.tun_enabled);

        let error = apply_tun_startup_policy(&startup, false, &mut settings)
            .expect_err("non-elevated handoff must fail closed");
        assert!(matches!(error, TunElevationError::HandoffNotElevated));
    }

    #[test]
    fn normal_startup_preserves_committed_tun_setting() {
        let mut settings = DesktopSettings::default();
        settings.preferences.tun_enabled = true;

        assert!(
            !apply_tun_startup_policy(&TunElevationStartupMode::normal(), false, &mut settings,)
                .expect("normal startup policy")
        );
        assert!(settings.preferences.tun_enabled);
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_permission_check_is_fail_closed_without_side_effects() {
        assert!(!super::tun_permission_available().expect("non-Windows permission policy"));
    }
}
