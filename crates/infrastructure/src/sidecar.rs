use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener},
    process::{ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::aead::Generate;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    sync::{Mutex, watch},
    time::{Instant, sleep, timeout},
};
use topnode_domain::{
    ConfigurationValidation, ConnectionCancellation, ConnectionEngine, ConnectionState,
    EngineCapabilities, EngineError, RouteMode, RuntimeConfiguration, RuntimeDescriptor, RuntimeId,
    RuntimeTelemetrySnapshot, StopReason,
};
use zeroize::Zeroizing;

use crate::{
    AppPaths,
    normalizer::normalize_with_local_clash_api,
    system_proxy::{ReconcileOutcome, SystemProxyError, SystemProxyLease, SystemProxyManager},
};

const RUNTIME_ID: &str = "rt1";
const SUPPORTED_SCHEMA: u32 = 1;
pub const SING_BOX_ACP_VERSION: &str = env!("TOPNODE_SING_BOX_ACP_VERSION");
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const READINESS_TIMEOUT: Duration = Duration::from_secs(30);
const READINESS_RETRY_INTERVAL: Duration = Duration::from_millis(100);
const CONTROL_REQUEST_TIMEOUT: Duration = Duration::from_millis(750);
const PROXY_READINESS_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CONTROL_RESPONSE_BYTES: usize = 4 * 1_024;
const MAX_TELEMETRY_RESPONSE_BYTES: usize = 512 * 1_024;
const TELEMETRY_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreProbe {
    pub available: bool,
    pub naive_capabilities: crate::NaiveCapabilities,
    pub version: String,
    pub binary_path: std::path::PathBuf,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct SingBoxSidecar {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    paths: AppPaths,
    descriptor: RuntimeDescriptor,
    state_tx: watch::Sender<ConnectionState>,
    telemetry_tx: watch::Sender<RuntimeTelemetrySnapshot>,
    process: Mutex<Option<ManagedProcess>>,
    prepared: Mutex<Option<PreparedRuntime>>,
    operation_gate: Mutex<()>,
    next_process_id: AtomicU64,
    core_compatible: AtomicBool,
    control_client: reqwest::Client,
    system_proxy: SystemProxyManager,
}

#[derive(Debug)]
struct ManagedProcess {
    generation: u64,
    child: Child,
    started_at_epoch_millis: u64,
    system_proxy_lease: Option<SystemProxyLease>,
    system_proxy_recovery_pending: bool,
}

struct PreparedRuntime {
    fingerprint: [u8; 32],
    controller: SocketAddrV4,
    secret: Zeroizing<String>,
    configuration: Zeroizing<String>,
    reservation: TcpListener,
    system_proxy_endpoint: Option<SocketAddrV4>,
    system_proxy_reservation: Option<TcpListener>,
}

impl std::fmt::Debug for PreparedRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedRuntime")
            .field("controller", &self.controller)
            .field("system_proxy_endpoint", &self.system_proxy_endpoint)
            .field("secret", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct ClashVersionResponse {
    version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClashConnectionsResponse {
    upload_total: u64,
    download_total: u64,
    #[serde(default)]
    connections: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    memory: Option<u64>,
}

#[derive(Clone, Copy)]
struct PreviousTelemetry {
    upload_total: u64,
    download_total: u64,
    sampled_at: Instant,
}

impl SingBoxSidecar {
    /// Creates a stopped sidecar adapter for the supplied application paths.
    ///
    /// # Errors
    ///
    /// Returns an engine error when the built-in runtime identifier is invalid.
    pub fn new(paths: AppPaths) -> Result<Self, EngineError> {
        let runtime_id = RuntimeId::new(RUNTIME_ID)?;
        let (state_tx, _) = watch::channel(ConnectionState::Disconnected);
        let (telemetry_tx, _) = watch::channel(RuntimeTelemetrySnapshot::default());
        let _ = rustls::crypto::ring::default_provider().install_default();
        let control_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(CONTROL_REQUEST_TIMEOUT)
            .timeout(CONTROL_REQUEST_TIMEOUT)
            .build()
            .map_err(|error| {
                EngineError::Process(format!("无法初始化本机 Sidecar 就绪探测：{error}"))
            })?;
        let system_proxy = SystemProxyManager::from_paths(&paths);
        Ok(Self {
            inner: Arc::new(Inner {
                paths,
                descriptor: RuntimeDescriptor {
                    runtime_id,
                    version: format!("{SING_BOX_ACP_VERSION}-sidecar"),
                    supported_schemas: vec![SUPPORTED_SCHEMA],
                    capabilities: EngineCapabilities {
                        latency_test: false,
                        hot_network_update: false,
                        selector_switch: false,
                        ipv6: true,
                    },
                },
                state_tx,
                telemetry_tx,
                process: Mutex::new(None),
                prepared: Mutex::new(None),
                operation_gate: Mutex::new(()),
                next_process_id: AtomicU64::new(1),
                core_compatible: AtomicBool::new(false),
                control_client,
                system_proxy,
            }),
        })
    }

    pub fn paths(&self) -> &AppPaths {
        &self.inner.paths
    }

    /// Restores a system-proxy lease left by an interrupted previous run.
    ///
    /// # Errors
    ///
    /// Returns a redacted platform or journal error when safe reconciliation
    /// cannot be completed. The caller must stop startup in that case.
    pub async fn reconcile_system_proxy(&self) -> Result<ReconcileOutcome, SystemProxyError> {
        self.inner.system_proxy.reconcile_stale().await
    }

    /// Removes runtime configurations left by an earlier abnormal exit.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when an existing session file cannot be removed.
    pub async fn clear_stale_session(&self) -> Result<(), std::io::Error> {
        self.inner.prepared.lock().await.take();
        let stale_paths = [
            self.inner.paths.session_config.clone(),
            self.inner.paths.session_config.with_extension("json.tmp"),
            self.inner.paths.config_dir.join("candidate.json"),
        ];
        let mut first_error = None;
        for path in stale_paths {
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    tracing::error!(path = %path.display(), %error, "failed to remove legacy plaintext runtime configuration");
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub async fn probe(&self) -> CoreProbe {
        self.inner.core_compatible.store(false, Ordering::Release);
        let binary_path = self.inner.paths.sidecar_binary.clone();
        if !binary_path.is_file() {
            return CoreProbe {
                available: false,
                naive_capabilities: crate::NaiveCapabilities::default(),
                version: "未安装".to_owned(),
                message: "请将 sing-box-acp 内核放到应用程序 runtime/core 目录".to_owned(),
                binary_path,
            };
        }

        let mut command = self.command();
        command.arg("version");
        let result = timeout(Duration::from_secs(3), command.output()).await;
        match result {
            Ok(Ok(output)) if output.status.success() => {
                let text = String::from_utf8_lossy(&output.stdout);
                let version = text.lines().next().unwrap_or("sing-box").trim().to_owned();
                let supported = reports_expected_core(&version);
                self.inner
                    .core_compatible
                    .store(supported, Ordering::Release);
                let core = binary_path.clone();
                let probe_text = text.into_owned();
                let qualification = tokio::task::spawn_blocking(move || {
                    crate::naive::verified_capabilities(&core, &probe_text)
                })
                .await
                .unwrap_or_default();
                CoreProbe {
                    available: supported,
                    naive_capabilities: qualification,
                    version,
                    message: if supported {
                        format!("sing-box-acp {SING_BOX_ACP_VERSION} 内核可用")
                    } else {
                        format!("内核版本必须为 {SING_BOX_ACP_VERSION}，已阻止启动")
                    },
                    binary_path,
                }
            }
            Ok(Ok(output)) => CoreProbe {
                available: false,
                naive_capabilities: crate::NaiveCapabilities::default(),
                version: "不可用".to_owned(),
                message: sanitized_process_message(&output.stderr),
                binary_path,
            },
            Ok(Err(error)) => CoreProbe {
                available: false,
                naive_capabilities: crate::NaiveCapabilities::default(),
                version: "不可用".to_owned(),
                message: error.to_string(),
                binary_path,
            },
            Err(_) => CoreProbe {
                available: false,
                naive_capabilities: crate::NaiveCapabilities::default(),
                version: "响应超时".to_owned(),
                message: "sing-box version 执行超时".to_owned(),
                binary_path,
            },
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.inner.paths.sidecar_binary);
        self.configure_command(&mut command);
        command
    }

    #[cfg(unix)]
    fn long_lived_command(&self) -> Result<Command, EngineError> {
        let mut command =
            crate::sidecar_guardian::guarded_command(&self.inner.paths.sidecar_binary)
                .map_err(io_error)?;
        self.configure_command(&mut command);
        Ok(command)
    }

    fn configure_command(&self, command: &mut Command) {
        command
            .current_dir(&self.inner.paths.core_dir)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .arg("--disable-color")
            .arg("-D")
            .arg(&self.inner.paths.config_dir);
        apply_platform_flags(command);
    }

    fn set_state(&self, state: ConnectionState) {
        self.inner.state_tx.send_replace(state);
    }

    fn ensure_compatible(&self, configuration: &RuntimeConfiguration) -> Result<(), EngineError> {
        if configuration.runtime_id() != &self.inner.descriptor.runtime_id {
            return Err(EngineError::UnsupportedRuntime(
                configuration.runtime_id().as_str().to_owned(),
            ));
        }
        if !self
            .inner
            .descriptor
            .supported_schemas
            .contains(&configuration.schema_version())
        {
            return Err(EngineError::UnsupportedSchema(
                configuration.schema_version(),
            ));
        }
        if !self.inner.paths.sidecar_binary.is_file() {
            return Err(EngineError::MissingBinary(
                self.inner.paths.sidecar_binary.clone(),
            ));
        }
        if !self.inner.core_compatible.load(Ordering::Acquire) {
            return Err(EngineError::Process(format!(
                "sing-box-acp 内核尚未通过 {SING_BOX_ACP_VERSION} 版本探测"
            )));
        }
        Ok(())
    }

    async fn wait_until_ready(
        &self,
        child: &mut Child,
        controller: SocketAddrV4,
        secret: &str,
        cancellation: &ConnectionCancellation,
        readiness_timeout: Duration,
    ) -> Result<(), EngineError> {
        let deadline = Instant::now() + readiness_timeout;
        loop {
            if cancellation.is_cancelled() {
                terminate_child_immediately(child).await.map_err(io_error)?;
                return Err(EngineError::Cancelled);
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    return Err(EngineError::Process(format!(
                        "sing-box 在 Clash API 就绪前退出（{status}）"
                    )));
                }
                Ok(None) => {}
                Err(error) => {
                    return Err(EngineError::Process(format!(
                        "无法读取 sing-box 就绪状态：{error}"
                    )));
                }
            }

            let ready = tokio::select! {
                biased;
                () = cancellation.cancelled() => {
                    terminate_child_immediately(child).await.map_err(io_error)?;
                    return Err(EngineError::Cancelled);
                }
                ready = probe_control_api_once(&self.inner.control_client, controller, secret) => ready,
            };
            if ready {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(EngineError::Timeout(
                    "sing-box Clash API 就绪检查".to_owned(),
                ));
            }
            tokio::select! {
                biased;
                () = cancellation.cancelled() => {
                    terminate_child_immediately(child).await.map_err(io_error)?;
                    return Err(EngineError::Cancelled);
                }
                () = sleep(READINESS_RETRY_INTERVAL) => {}
            }
        }
    }

    fn start_telemetry(
        &self,
        generation: u64,
        controller: SocketAddrV4,
        secret: Zeroizing<String>,
    ) {
        let sidecar = self.clone();
        tokio::spawn(async move {
            let mut previous = None;
            loop {
                if !sidecar.is_current_generation(generation).await {
                    return;
                }
                let sampled_at = Instant::now();
                if let Some(response) =
                    fetch_telemetry_once(&sidecar.inner.control_client, controller, &secret).await
                    && sidecar.is_current_generation(generation).await
                {
                    let snapshot = telemetry_snapshot(&response, previous, sampled_at);
                    previous = Some(PreviousTelemetry {
                        upload_total: response.upload_total,
                        download_total: response.download_total,
                        sampled_at,
                    });
                    sidecar.inner.telemetry_tx.send_replace(snapshot);
                }
                sleep(TELEMETRY_INTERVAL).await;
            }
        });
    }

    async fn is_current_generation(&self, generation: u64) -> bool {
        self.inner
            .process
            .lock()
            .await
            .as_ref()
            .is_some_and(|process| process.generation == generation)
    }

    fn reset_telemetry(&self) {
        self.inner
            .telemetry_tx
            .send_replace(RuntimeTelemetrySnapshot::default());
    }

    async fn restore_system_proxy(
        &self,
        process: &mut ManagedProcess,
    ) -> Result<(), SystemProxyError> {
        if let Some(lease) = process.system_proxy_lease.as_mut() {
            lease.restore().await?;
            process.system_proxy_lease = None;
            process.system_proxy_recovery_pending = false;
            return Ok(());
        }
        if process.system_proxy_recovery_pending {
            self.inner.system_proxy.reconcile_stale().await?;
            process.system_proxy_recovery_pending = false;
        }
        Ok(())
    }

    fn start_supervisor(&self, generation: u64) {
        let sidecar = self.clone();
        tokio::spawn(async move {
            #[cfg(target_os = "macos")]
            let mut next_service_refresh = Instant::now();
            loop {
                sleep(Duration::from_millis(400)).await;
                let exit = {
                    let mut process = sidecar.inner.process.lock().await;
                    let Some(managed) = process.as_mut() else {
                        return;
                    };
                    if managed.generation != generation {
                        return;
                    }
                    #[cfg(target_os = "macos")]
                    if Instant::now() >= next_service_refresh {
                        next_service_refresh = Instant::now() + Duration::from_secs(5);
                        if let Some(lease) = managed.system_proxy_lease.as_ref()
                            && let Err(error) = lease.refresh_services().await
                        {
                            sidecar.set_state(ConnectionState::Failed {
                                message: format!("网络服务代理更新失败：{error}"),
                            });
                            let _ = stop_child(&mut managed.child).await;
                        }
                    }
                    match managed.child.try_wait() {
                        Ok(Some(status)) => {
                            let managed = process
                                .take()
                                .expect("observed managed process remains present");
                            Some((managed, format!("sing-box 意外退出（{status}）")))
                        }
                        Ok(None) => None,
                        Err(error) => {
                            let managed = process
                                .take()
                                .expect("observed managed process remains present");
                            Some((managed, format!("无法读取 sing-box 状态：{error}")))
                        }
                    }
                };
                if let Some((mut managed, mut message)) = exit {
                    if let Err(error) = sidecar.restore_system_proxy(&mut managed).await {
                        tracing::error!(
                            ?error,
                            "failed to restore system proxy after sidecar exit"
                        );
                        message.push_str("；系统代理恢复失败，请重新启动应用");
                    }
                    tracing::error!(target: "sing_box", %message);
                    sidecar.reset_telemetry();
                    sidecar.set_state(ConnectionState::Failed { message });
                    return;
                }
            }
        });
    }
}

#[async_trait]
impl ConnectionEngine for SingBoxSidecar {
    fn descriptor(&self) -> RuntimeDescriptor {
        self.inner.descriptor.clone()
    }

    fn subscribe(&self) -> watch::Receiver<ConnectionState> {
        self.inner.state_tx.subscribe()
    }

    fn subscribe_telemetry(&self) -> watch::Receiver<RuntimeTelemetrySnapshot> {
        self.inner.telemetry_tx.subscribe()
    }

    async fn validate(
        &self,
        configuration: &RuntimeConfiguration,
        cancellation: &ConnectionCancellation,
    ) -> Result<ConfigurationValidation, EngineError> {
        let _guard = self.inner.operation_gate.lock().await;
        if cancellation.is_cancelled() {
            self.inner.prepared.lock().await.take();
            self.set_state(ConnectionState::Disconnected);
            return Err(EngineError::Cancelled);
        }
        self.ensure_compatible(configuration)?;
        if self.inner.process.lock().await.is_some() {
            return Err(EngineError::AlreadyRunning);
        }
        if let Err(error) = self.inner.system_proxy.reconcile_stale().await {
            let error = system_proxy_error(error);
            self.set_state(ConnectionState::Failed {
                message: error.to_string(),
            });
            return Err(error);
        }
        if let Err(error) = self.clear_stale_session().await {
            let error = io_error(error);
            self.set_state(ConnectionState::Failed {
                message: error.to_string(),
            });
            return Err(error);
        }
        self.reset_telemetry();
        self.set_state(ConnectionState::Validating);
        let probe = self.probe().await;
        if let Err(error) =
            crate::naive::require_configuration(configuration.payload(), &probe.naive_capabilities)
        {
            self.set_state(ConnectionState::Failed {
                message: error.to_string(),
            });
            return Err(error);
        }
        let prepared = match prepare_runtime(configuration) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.set_state(ConnectionState::Failed {
                    message: error.to_string(),
                });
                return Err(error);
            }
        };
        let mut command = self.command();
        command
            .arg("check")
            .arg("-c")
            .arg("stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let output = command_status_with_input(
            command,
            prepared.configuration.as_bytes(),
            "sing-box check",
            cancellation,
        )
        .await;

        match output {
            Ok(status) if status.success() => {
                *self.inner.prepared.lock().await = Some(prepared);
                Ok(ConfigurationValidation::Valid)
            }
            Ok(status) => {
                tracing::warn!(target: "sing_box", %status, "sidecar configuration check failed");
                let reason = "sing-box 拒绝了运行时配置".to_owned();
                self.set_state(ConnectionState::Failed {
                    message: reason.clone(),
                });
                Ok(ConfigurationValidation::Invalid { reason })
            }
            Err(EngineError::Cancelled) => {
                self.set_state(ConnectionState::Disconnected);
                Err(EngineError::Cancelled)
            }
            Err(error) => {
                self.set_state(ConnectionState::Failed {
                    message: error.to_string(),
                });
                Err(error)
            }
        }
    }

    #[allow(clippy::too_many_lines)] // Keep every child-owning failure path linear and auditable.
    async fn start(
        &self,
        configuration: RuntimeConfiguration,
        cancellation: &ConnectionCancellation,
    ) -> Result<(), EngineError> {
        let _guard = self.inner.operation_gate.lock().await;
        if cancellation.is_cancelled() {
            self.inner.prepared.lock().await.take();
            self.set_state(ConnectionState::Disconnected);
            return Err(EngineError::Cancelled);
        }
        self.ensure_compatible(&configuration)?;
        if self.inner.process.lock().await.is_some() {
            return Err(EngineError::AlreadyRunning);
        }
        let probe = self.probe().await;
        if let Err(error) =
            crate::naive::require_configuration(configuration.payload(), &probe.naive_capabilities)
        {
            self.inner.prepared.lock().await.take();
            self.set_state(ConnectionState::Failed {
                message: error.to_string(),
            });
            return Err(error);
        }
        self.set_state(ConnectionState::Starting);
        let Some(prepared) = self.inner.prepared.lock().await.take() else {
            let error =
                EngineError::InvalidConfiguration("运行时配置必须先通过 sing-box check".to_owned());
            self.set_state(ConnectionState::Failed {
                message: error.to_string(),
            });
            return Err(error);
        };
        if prepared.fingerprint != configuration_fingerprint(&configuration) {
            let error =
                EngineError::InvalidConfiguration("已验证配置与待启动配置不一致".to_owned());
            self.set_state(ConnectionState::Failed {
                message: error.to_string(),
            });
            return Err(error);
        }
        if configuration.preferences().tun_enabled {
            let permission_available = match tun_permission_available() {
                Ok(available) => available,
                Err(error) => {
                    self.set_state(ConnectionState::Failed {
                        message: error.to_string(),
                    });
                    return Err(error);
                }
            };
            if !permission_available {
                let error = EngineError::InsufficientPrivileges;
                self.set_state(ConnectionState::Failed {
                    message: error.to_string(),
                });
                return Err(error);
            }
        }

        let PreparedRuntime {
            fingerprint: _,
            controller,
            secret,
            configuration: checked_configuration,
            reservation,
            system_proxy_endpoint,
            system_proxy_reservation,
        } = prepared;

        #[cfg(unix)]
        let mut command = if cfg!(any(target_os = "linux", target_os = "macos"))
            && configuration.preferences().tun_enabled
        {
            let helper = self
                .inner
                .paths
                .runtime_dir
                .parent()
                .ok_or_else(|| EngineError::Process("缺少安装目录".to_owned()))?
                .join(if cfg!(target_os = "macos") {
                    "topnode-network-bridge"
                } else {
                    "topnode-net-helper"
                });
            let mut command =
                crate::sidecar_guardian::guarded_command(&helper).map_err(io_error)?;
            command.arg("connect");
            command
        } else {
            let mut command = self.long_lived_command()?;
            command.args(["run", "-c", "stdin"]);
            command
        };
        #[cfg(not(unix))]
        let mut command = {
            let mut command = self.command();
            command.args(["run", "-c", "stdin"]);
            command
        };
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // Hold the OS-assigned loopback port until the last possible moment.
        // sing-box has no socket-activation interface, so readiness remains the
        // fail-closed guard for the unavoidable release-to-bind window.
        drop(reservation);
        drop(system_proxy_reservation);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let error = io_error(error);
                self.set_state(ConnectionState::Failed {
                    message: error.to_string(),
                });
                return Err(error);
            }
        };
        if let Some(stdout) = child.stdout.take() {
            tokio::spawn(pipe_logs(stdout, false));
        }
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(pipe_logs(stderr, true));
        }
        if let Err(error) =
            write_child_input(&mut child, checked_configuration.as_bytes(), cancellation).await
        {
            let cleanup = if matches!(error, EngineError::Cancelled) {
                terminate_child_immediately(&mut child).await
            } else {
                stop_child(&mut child).await
            };
            let error = match cleanup {
                Ok(()) => error,
                Err(stop_error) => {
                    tracing::error!(%stop_error, "failed to stop sidecar after stdin write failure");
                    io_error(stop_error)
                }
            };
            self.set_state(if matches!(error, EngineError::Cancelled) {
                ConnectionState::Disconnected
            } else {
                ConnectionState::Failed {
                    message: error.to_string(),
                }
            });
            return Err(error);
        }
        drop(checked_configuration);

        if let Err(error) = self
            .wait_until_ready(
                &mut child,
                controller,
                &secret,
                cancellation,
                if cfg!(unix) && configuration.preferences().tun_enabled {
                    Duration::from_secs(120)
                } else {
                    READINESS_TIMEOUT
                },
            )
            .await
        {
            if !matches!(error, EngineError::Cancelled)
                && let Err(stop_error) = stop_child(&mut child).await
            {
                tracing::error!(%stop_error, "failed to stop sidecar after readiness failure");
            }
            self.set_state(if matches!(error, EngineError::Cancelled) {
                ConnectionState::Disconnected
            } else {
                ConnectionState::Failed {
                    message: error.to_string(),
                }
            });
            return Err(error);
        }

        if let Some(endpoint) = system_proxy_endpoint
            && let Err(error) = wait_until_proxy_ready(&mut child, endpoint, cancellation).await
        {
            if !matches!(error, EngineError::Cancelled)
                && let Err(stop_error) = stop_child(&mut child).await
            {
                tracing::error!(%stop_error, "failed to stop sidecar after proxy readiness failure");
            }
            self.set_state(if matches!(error, EngineError::Cancelled) {
                ConnectionState::Disconnected
            } else {
                ConnectionState::Failed {
                    message: error.to_string(),
                }
            });
            return Err(error);
        }

        if cancellation.is_cancelled() {
            terminate_child_immediately(&mut child)
                .await
                .map_err(io_error)?;
            self.set_state(ConnectionState::Disconnected);
            return Err(EngineError::Cancelled);
        }

        let mut system_proxy_lease = None;
        let mut system_proxy_recovery_pending = false;
        if let Some(endpoint) = system_proxy_endpoint {
            match self.inner.system_proxy.acquire(endpoint).await {
                Ok(lease) => system_proxy_lease = Some(lease),
                Err(error) => {
                    let startup_error = system_proxy_error(error);
                    match self.inner.system_proxy.reconcile_stale().await {
                        Ok(_) => {
                            if let Err(stop_error) = stop_child(&mut child).await {
                                tracing::error!(%stop_error, "failed to stop sidecar after system proxy failure");
                            }
                            self.set_state(ConnectionState::Failed {
                                message: startup_error.to_string(),
                            });
                            return Err(startup_error);
                        }
                        Err(recovery_error) => {
                            tracing::error!(
                                ?recovery_error,
                                "system proxy recovery remains pending"
                            );
                            system_proxy_recovery_pending = true;
                        }
                    }
                }
            }
        }

        let generation = self.inner.next_process_id.fetch_add(1, Ordering::Relaxed);
        let started_at_epoch_millis = epoch_millis();
        *self.inner.process.lock().await = Some(ManagedProcess {
            generation,
            child,
            started_at_epoch_millis,
            system_proxy_lease,
            system_proxy_recovery_pending,
        });
        if system_proxy_recovery_pending {
            let error = EngineError::SystemProxy(
                "系统代理未能安全应用或恢复；连接服务保持运行以避免代理失效".to_owned(),
            );
            self.set_state(ConnectionState::Failed {
                message: error.to_string(),
            });
            self.start_supervisor(generation);
            return Err(error);
        }
        self.start_telemetry(generation, controller, secret);
        self.set_state(ConnectionState::Connected {
            started_at_epoch_millis,
        });
        tracing::info!(target: "sing_box", revision = configuration.revision(), "sidecar control API ready");
        self.start_supervisor(generation);
        Ok(())
    }

    async fn stop(&self, reason: StopReason) -> Result<(), EngineError> {
        let _guard = self.inner.operation_gate.lock().await;
        self.set_state(ConnectionState::Stopping);
        self.inner.prepared.lock().await.take();
        let process = self.inner.process.lock().await.take();
        self.reset_telemetry();
        let Some(mut process) = process else {
            self.set_state(ConnectionState::Disconnected);
            return Ok(());
        };
        tracing::info!(target: "sing_box", ?reason, "stopping sidecar");
        let was_recovery_pending = process.system_proxy_recovery_pending;
        if let Err(error) = self.restore_system_proxy(&mut process).await {
            let error = system_proxy_error(error);
            let started_at_epoch_millis = process.started_at_epoch_millis;
            *self.inner.process.lock().await = Some(process);
            self.set_state(if was_recovery_pending {
                ConnectionState::Failed {
                    message: error.to_string(),
                }
            } else {
                ConnectionState::Connected {
                    started_at_epoch_millis,
                }
            });
            return Err(error);
        }
        match stop_child(&mut process.child).await {
            Ok(()) => {
                self.set_state(ConnectionState::Disconnected);
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                self.set_state(ConnectionState::Disconnected);
                Ok(())
            }
            Err(error) => {
                let error = io_error(error);
                self.set_state(ConnectionState::Failed {
                    message: error.to_string(),
                });
                Err(error)
            }
        }
    }
}

async fn wait_until_proxy_ready(
    child: &mut Child,
    endpoint: SocketAddrV4,
    cancellation: &ConnectionCancellation,
) -> Result<(), EngineError> {
    let deadline = Instant::now() + PROXY_READINESS_TIMEOUT;
    loop {
        if cancellation.is_cancelled() {
            terminate_child_immediately(child).await.map_err(io_error)?;
            return Err(EngineError::Cancelled);
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(EngineError::Process(format!(
                    "sing-box 在本机代理入口就绪前退出（{status}）"
                )));
            }
            Ok(None) => {}
            Err(error) => {
                return Err(EngineError::Process(format!(
                    "无法读取 sing-box 代理入口状态：{error}"
                )));
            }
        }

        let connected = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                terminate_child_immediately(child).await.map_err(io_error)?;
                return Err(EngineError::Cancelled);
            }
            result = timeout(
                CONTROL_REQUEST_TIMEOUT,
                tokio::net::TcpStream::connect(endpoint),
            ) => matches!(result, Ok(Ok(_))),
        };
        if connected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(EngineError::Timeout("本机系统代理入口就绪检查".to_owned()));
        }
        tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                terminate_child_immediately(child).await.map_err(io_error)?;
                return Err(EngineError::Cancelled);
            }
            () = sleep(READINESS_RETRY_INTERVAL) => {}
        }
    }
}

async fn command_status_with_input(
    mut command: Command,
    input: &[u8],
    operation: &str,
    cancellation: &ConnectionCancellation,
) -> Result<ExitStatus, EngineError> {
    let mut child = command.spawn().map_err(io_error)?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| EngineError::Process(format!("{operation} 未创建标准输入管道")))?;
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    let write_result = tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            terminate_child_immediately(&mut child).await.map_err(io_error)?;
            return Err(EngineError::Cancelled);
        }
        result = tokio::time::timeout_at(deadline, async {
            stdin.write_all(input).await?;
            stdin.shutdown().await
        }) => if let Ok(result) = result {
            result
        } else {
                terminate_child_immediately(&mut child).await.map_err(io_error)?;
                return Err(EngineError::Timeout(operation.to_owned()));
        },
    };
    // `sing-box check -c stdin` reads until EOF. On Windows, shutting down the
    // async writer does not release the inherited pipe handle; keeping this
    // value alive while waiting for the child therefore deadlocks every check.
    drop(stdin);

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                let _ = terminate_child_immediately(&mut child).await;
                return Err(io_error(error));
            }
        }
        if Instant::now() >= deadline {
            terminate_child_immediately(&mut child)
                .await
                .map_err(io_error)?;
            return Err(EngineError::Timeout(operation.to_owned()));
        }
        tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                terminate_child_immediately(&mut child).await.map_err(io_error)?;
                return Err(EngineError::Cancelled);
            }
            () = sleep(Duration::from_millis(10)) => {}
        }
    };
    if status.success() {
        write_result.map_err(io_error)?;
    }
    Ok(status)
}

async fn write_child_input(
    child: &mut Child,
    input: &[u8],
    cancellation: &ConnectionCancellation,
) -> Result<(), EngineError> {
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| EngineError::Process("sing-box 未创建标准输入管道".to_owned()))?;
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(EngineError::Cancelled),
        result = timeout(COMMAND_TIMEOUT, async {
            stdin.write_all(input).await?;
            stdin.shutdown().await
        }) => result
            .map_err(|_| EngineError::Timeout("向 sing-box 传递内存配置".to_owned()))?
            .map_err(io_error),
    }
}

fn prepare_runtime(configuration: &RuntimeConfiguration) -> Result<PreparedRuntime, EngineError> {
    let (reservation, controller) = reserve_loopback_port("本机 Sidecar 控制")?;
    let (system_proxy_reservation, system_proxy_endpoint) =
        if configuration.preferences().tun_enabled {
            (None, None)
        } else {
            let (reservation, endpoint) = reserve_loopback_port("本机系统代理")?;
            (Some(reservation), Some(endpoint))
        };
    let random = Zeroizing::new(
        <[u8; 32]>::try_generate()
            .map_err(|_| EngineError::Process("无法生成 Sidecar API 随机密钥".to_owned()))?,
    );
    let secret = Zeroizing::new(URL_SAFE_NO_PAD.encode(*random));
    let normalized = Zeroizing::new(normalize_with_local_clash_api(
        configuration.payload(),
        configuration.preferences(),
        controller,
        &secret,
        system_proxy_endpoint,
    )?);
    Ok(PreparedRuntime {
        fingerprint: configuration_fingerprint(configuration),
        controller,
        secret,
        configuration: normalized,
        reservation,
        system_proxy_endpoint,
        system_proxy_reservation,
    })
}

fn reserve_loopback_port(label: &str) -> Result<(TcpListener, SocketAddrV4), EngineError> {
    let reservation =
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).map_err(io_error)?;
    let endpoint = match reservation.local_addr().map_err(io_error)? {
        SocketAddr::V4(endpoint)
            if endpoint.ip() == &Ipv4Addr::LOCALHOST && endpoint.port() != 0 =>
        {
            endpoint
        }
        _ => {
            return Err(EngineError::Process(format!(
                "操作系统未分配可用的 IPv4 {label}回环端口"
            )));
        }
    };
    Ok((reservation, endpoint))
}

fn configuration_fingerprint(configuration: &RuntimeConfiguration) -> [u8; 32] {
    let mut digest = Sha256::new();
    update_digest_field(&mut digest, configuration.runtime_id().as_str().as_bytes());
    digest.update(configuration.schema_version().to_be_bytes());
    update_digest_field(&mut digest, configuration.revision().as_bytes());
    digest.update(
        configuration
            .expires_at_epoch_seconds()
            .unwrap_or_default()
            .to_be_bytes(),
    );
    update_digest_field(&mut digest, configuration.payload().as_bytes());
    let preferences = configuration.preferences();
    digest.update([
        match preferences.route_mode {
            RouteMode::Rule => 0,
            RouteMode::Global => 1,
        },
        u8::from(preferences.bypass_mainland),
        u8::from(preferences.bypass_lan),
        u8::from(preferences.tun_enabled),
        u8::from(preferences.udp_forwarding_enabled),
        u8::from(preferences.multiplex_enabled),
    ]);
    digest.finalize().into()
}

#[cfg_attr(
    not(windows),
    allow(
        clippy::unnecessary_wraps,
        reason = "the platform-neutral permission boundary can fail on Windows"
    )
)]
fn tun_permission_available() -> Result<bool, EngineError> {
    #[cfg(windows)]
    {
        win_desktop_utils::is_elevated()
            .map_err(|_| EngineError::Process("无法检查 TUN 模式所需的管理员权限".to_owned()))
    }
    #[cfg(not(windows))]
    {
        Ok(crate::tun_helper_available())
    }
}

fn update_digest_field(digest: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    digest.update(length.to_be_bytes());
    digest.update(value);
}

async fn probe_control_api_once(
    client: &reqwest::Client,
    controller: SocketAddrV4,
    secret: &str,
) -> bool {
    let request = client
        .get(format!("http://{controller}/version"))
        .bearer_auth(secret);
    let Ok(mut response) = request.send().await else {
        return false;
    };
    if response.status() != reqwest::StatusCode::OK
        || response.content_length().is_some_and(|length| {
            length > u64::try_from(MAX_CONTROL_RESPONSE_BYTES).unwrap_or(u64::MAX)
        })
    {
        return false;
    }
    let Some(body) = read_bounded_body(&mut response, MAX_CONTROL_RESPONSE_BYTES).await else {
        return false;
    };

    serde_json::from_slice::<ClashVersionResponse>(&body)
        .is_ok_and(|version| version.version == format!("sing-box {SING_BOX_ACP_VERSION}"))
}

async fn fetch_telemetry_once(
    client: &reqwest::Client,
    controller: SocketAddrV4,
    secret: &str,
) -> Option<ClashConnectionsResponse> {
    let mut response = client
        .get(format!("http://{controller}/connections"))
        .bearer_auth(secret)
        .send()
        .await
        .ok()?;
    if response.status() != reqwest::StatusCode::OK
        || response.content_length().is_some_and(|length| {
            length > u64::try_from(MAX_TELEMETRY_RESPONSE_BYTES).unwrap_or(u64::MAX)
        })
    {
        return None;
    }
    let body = read_bounded_body(&mut response, MAX_TELEMETRY_RESPONSE_BYTES).await?;
    serde_json::from_slice(&body).ok()
}

async fn read_bounded_body(response: &mut reqwest::Response, maximum: usize) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(_) => return None,
        };
        let next_length = body.len().checked_add(chunk.len())?;
        if next_length > maximum {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    Some(body)
}

fn telemetry_snapshot(
    response: &ClashConnectionsResponse,
    previous: Option<PreviousTelemetry>,
    sampled_at: Instant,
) -> RuntimeTelemetrySnapshot {
    let (upload_rate, download_rate) = previous.map_or((0, 0), |previous| {
        let elapsed_millis = u64::try_from(
            sampled_at
                .saturating_duration_since(previous.sampled_at)
                .as_millis(),
        )
        .unwrap_or(u64::MAX)
        .max(1);
        (
            bytes_per_second(
                response.upload_total.saturating_sub(previous.upload_total),
                elapsed_millis,
            ),
            bytes_per_second(
                response
                    .download_total
                    .saturating_sub(previous.download_total),
                elapsed_millis,
            ),
        )
    });
    RuntimeTelemetrySnapshot {
        upload_total_bytes: response.upload_total,
        download_total_bytes: response.download_total,
        upload_bytes_per_second: upload_rate,
        download_bytes_per_second: download_rate,
        active_connections: u32::try_from(response.connections.len()).unwrap_or(u32::MAX),
        memory_bytes: response.memory,
        sampled_at_epoch_millis: epoch_millis(),
    }
}

fn bytes_per_second(bytes: u64, elapsed_millis: u64) -> u64 {
    let rate = u128::from(bytes)
        .saturating_mul(1_000)
        .checked_div(u128::from(elapsed_millis))
        .unwrap_or_default();
    u64::try_from(rate).unwrap_or(u64::MAX)
}

async fn pipe_logs<R>(mut reader: R, stderr: bool)
where
    R: AsyncRead + Unpin,
{
    let mut chunk = [0_u8; 2_048];
    let mut line = Vec::with_capacity(4_096);
    let mut truncated = false;
    loop {
        let read = match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => return,
        };
        for byte in &chunk[..read] {
            if *byte == b'\n' {
                emit_log_line(&line, truncated, stderr);
                line.clear();
                truncated = false;
            } else if line.len() < 4_096 {
                line.push(*byte);
            } else {
                truncated = true;
            }
        }
    }
    if !line.is_empty() || truncated {
        emit_log_line(&line, truncated, stderr);
    }
}

fn emit_log_line(bytes: &[u8], truncated: bool, stderr: bool) {
    let category = crate::native_diagnostic::category(&String::from_utf8_lossy(bytes));
    let mut line = sanitize_log_line(&String::from_utf8_lossy(bytes));
    if truncated {
        line.push_str(" …[日志行已截断]");
    }
    let stream = if stderr { "stderr" } else { "stdout" };
    tracing::debug!(target: "sing_box", stream, category, message = %line);
}

fn sanitized_process_message(bytes: &[u8]) -> String {
    let value = String::from_utf8_lossy(bytes);
    let category = crate::native_diagnostic::category(&value);
    let value = sanitize_log_line(value.trim());
    if value.is_empty() {
        "sing-box 未提供错误详情".to_owned()
    } else {
        format!("[{category}] {value}")
    }
}

fn sanitize_log_line(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    if [
        "authorization",
        "password",
        "passwd",
        "token",
        "secret",
        "private_key",
        "private-key",
        "private key",
        "\"outbounds\"",
        "\"inbounds\"",
        "uuid",
        "://",
    ]
    .iter()
    .any(|key| lower.contains(key))
    {
        return "[已隐藏可能包含凭据的 sing-box 日志]".to_owned();
    }
    line.chars().take(4_096).collect()
}

fn reports_expected_core(first_line: &str) -> bool {
    first_line.strip_prefix("sing-box version ") == Some(SING_BOX_ACP_VERSION)
}

#[allow(clippy::needless_pass_by_value)]
fn io_error(error: std::io::Error) -> EngineError {
    EngineError::Io(error.to_string())
}

fn system_proxy_error(error: SystemProxyError) -> EngineError {
    tracing::warn!(?error, "system proxy operation failed");
    let message = error.to_string();
    drop(error);
    EngineError::SystemProxy(message)
}

fn epoch_millis() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

fn apply_platform_flags(command: &mut Command) {
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(unix)]
    command.process_group(0);
}

#[cfg(unix)]
async fn terminate_child_immediately(child: &mut Child) -> Result<(), std::io::Error> {
    let process_group = child
        .id()
        .map(|process_id| nix::unistd::Pid::from_raw(process_id.cast_signed()));
    if let Some(process_group) = process_group
        && let Err(error) =
            nix::sys::signal::killpg(process_group, nix::sys::signal::Signal::SIGKILL)
        && error != nix::errno::Errno::ESRCH
    {
        return Err(std::io::Error::from_raw_os_error(error as i32));
    }
    timeout(Duration::from_secs(2), child.wait())
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "sing-box 进程组未在取消后退出",
            )
        })?
        .map(|_| ())
}

#[cfg(windows)]
async fn terminate_child_immediately(child: &mut Child) -> Result<(), std::io::Error> {
    match child.start_kill() {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {}
        Err(error) => return Err(error),
    }
    timeout(Duration::from_secs(2), child.wait())
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "sing-box 进程未在取消后退出")
        })?
        .map(|_| ())
}

#[cfg(unix)]
fn signal_process_group(
    process_group: nix::unistd::Pid,
    signal: nix::sys::signal::Signal,
) -> Result<(), std::io::Error> {
    match nix::sys::signal::killpg(process_group, signal) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(error) => Err(std::io::Error::from_raw_os_error(error as i32)),
    }
}

#[cfg(unix)]
async fn stop_child(child: &mut Child) -> Result<(), std::io::Error> {
    let process_group = child
        .id()
        .map(|process_id| nix::unistd::Pid::from_raw(process_id.cast_signed()));
    if let Some(process_group) = process_group {
        signal_process_group(process_group, nix::sys::signal::Signal::SIGTERM)?;
    }
    if let Ok(result) = timeout(Duration::from_secs(4), child.wait()).await {
        return result.map(|_| ());
    }
    if let Some(process_group) = process_group {
        signal_process_group(process_group, nix::sys::signal::Signal::SIGKILL)?;
    } else {
        child.kill().await?;
    }
    timeout(Duration::from_secs(2), child.wait())
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "sing-box 进程组未在 SIGKILL 后退出",
            )
        })?
        .map(|_| ())
}

#[cfg(windows)]
async fn stop_child(child: &mut Child) -> Result<(), std::io::Error> {
    child.kill().await
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener},
        process::Stdio,
        thread,
        time::Duration,
    };

    use tokio::time::Instant;
    use topnode_domain::{
        ConnectionCancellation, ConnectionPreferences, EngineError, RuntimeConfiguration, RuntimeId,
    };

    use super::{
        CONTROL_REQUEST_TIMEOUT, ClashConnectionsResponse, PreviousTelemetry, SING_BOX_ACP_VERSION,
        SingBoxSidecar, apply_platform_flags, command_status_with_input, configuration_fingerprint,
        prepare_runtime, probe_control_api_once, reports_expected_core, sanitize_log_line,
        telemetry_snapshot,
    };
    use crate::AppPaths;

    #[test]
    fn sidecar_log_credentials_are_redacted() {
        assert!(!sanitize_log_line("authorization: Bearer abc").contains("abc"));
        assert!(!sanitize_log_line("password=hello").contains("hello"));
    }

    #[test]
    fn ordinary_sidecar_log_is_preserved() {
        assert_eq!(sanitize_log_line("inbound started"), "inbound started");
    }

    #[test]
    fn cli_probe_requires_the_exact_acp_version() {
        assert!(reports_expected_core(&format!(
            "sing-box version {SING_BOX_ACP_VERSION}"
        )));
        let (upstream, _) = SING_BOX_ACP_VERSION
            .split_once('-')
            .expect("ACP revision suffix");
        assert!(!reports_expected_core(&format!(
            "sing-box version {upstream}"
        )));
        assert!(!reports_expected_core(&format!(
            "other version {SING_BOX_ACP_VERSION}"
        )));
    }

    #[test]
    fn cancellation_child_fixture() {
        if std::env::var_os("TOPNODE_SIDECAR_CANCELLATION_CHILD").is_some() {
            thread::sleep(Duration::from_secs(60));
        }
    }

    #[test]
    fn stdin_eof_child_fixture() {
        if std::env::var_os("TOPNODE_STDIN_EOF_CHILD").is_some() {
            let mut input = Vec::new();
            std::io::stdin()
                .read_to_end(&mut input)
                .expect("fixture reads stdin through EOF");
            assert_eq!(input, b"validated configuration");
        }
    }

    #[tokio::test]
    async fn configuration_check_closes_stdin_before_waiting_for_child() {
        let mut command =
            tokio::process::Command::new(std::env::current_exe().expect("current test executable"));
        command
            .arg("--exact")
            .arg("sidecar::tests::stdin_eof_child_fixture")
            .arg("--nocapture")
            .env("TOPNODE_STDIN_EOF_CHILD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        apply_platform_flags(&mut command);

        let result = tokio::time::timeout(
            Duration::from_secs(3),
            command_status_with_input(
                command,
                b"validated configuration",
                "stdin EOF regression",
                &ConnectionCancellation::new(),
            ),
        )
        .await
        .expect("the child must observe EOF without waiting for the command timeout")
        .expect("fixture process");

        assert!(result.success());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pending_readiness_is_cancelled_and_reaps_the_child_promptly() {
        let directory = tempfile::tempdir().expect("temp dir");
        let paths = AppPaths::from_roots(
            &directory.path().join("app/topnode-desktop.exe"),
            directory.path().join("data"),
        );
        let sidecar = SingBoxSidecar::new(paths).expect("sidecar");
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("pending controller");
        let controller = match listener.local_addr().expect("controller address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => panic!("expected IPv4 controller"),
        };

        let mut command =
            tokio::process::Command::new(std::env::current_exe().expect("current test executable"));
        command
            .arg("--exact")
            .arg("sidecar::tests::cancellation_child_fixture")
            .arg("--nocapture")
            .env("TOPNODE_SIDECAR_CANCELLATION_CHILD", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        apply_platform_flags(&mut command);
        let mut child = command.spawn().expect("pending child");

        let cancellation = ConnectionCancellation::new();
        let cancel = cancellation.clone();
        let canceller = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            cancel.cancel();
        });
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            sidecar.wait_until_ready(
                &mut child,
                controller,
                "test-secret",
                &cancellation,
                super::READINESS_TIMEOUT,
            ),
        )
        .await
        .expect("cancellation should beat the readiness deadline");
        canceller.await.expect("canceller task");

        assert_eq!(result, Err(EngineError::Cancelled));
        assert!(
            child.try_wait().expect("child status").is_some(),
            "cancelled readiness must reap the spawned child"
        );
    }

    #[tokio::test]
    async fn startup_cleanup_removes_every_owned_plaintext_candidate() {
        let directory = tempfile::tempdir().expect("temp dir");
        let paths = AppPaths::from_roots(
            &directory.path().join("app/topnode-desktop.exe"),
            directory.path().join("data"),
        );
        paths.ensure_directories().await.expect("runtime dirs");
        let stale_paths = [
            paths.session_config.clone(),
            paths.session_config.with_extension("json.tmp"),
            paths.config_dir.join("candidate.json"),
        ];
        for path in &stale_paths {
            tokio::fs::write(path, b"secret runtime payload")
                .await
                .expect("stale fixture");
        }
        let sidecar = SingBoxSidecar::new(paths).expect("sidecar");

        sidecar.clear_stale_session().await.expect("cleanup");

        assert!(stale_paths.iter().all(|path| !path.exists()));
    }

    #[test]
    fn prepared_runtime_reserves_loopback_port_and_strong_unique_secret() {
        let configuration = runtime_configuration();
        let first = prepare_runtime(&configuration).expect("first preparation");
        let second = prepare_runtime(&configuration).expect("second preparation");

        assert_eq!(first.controller.ip(), &Ipv4Addr::LOCALHOST);
        assert_ne!(first.controller.port(), 0);
        assert!(TcpListener::bind(first.controller).is_err());
        let system_proxy = first
            .system_proxy_endpoint
            .expect("default mode reserves a system proxy endpoint");
        assert_eq!(system_proxy.ip(), &Ipv4Addr::LOCALHOST);
        assert_ne!(system_proxy.port(), 0);
        assert!(TcpListener::bind(system_proxy).is_err());
        assert!(first.secret.len() >= 32);
        assert!(first.secret.as_str() != second.secret.as_str());
    }

    #[test]
    fn tun_runtime_does_not_reserve_a_system_proxy_endpoint() {
        let preferences = ConnectionPreferences {
            tun_enabled: true,
            ..ConnectionPreferences::default()
        };
        let prepared = prepare_runtime(&runtime_configuration_with_preferences(preferences))
            .expect("TUN preparation");

        assert!(prepared.system_proxy_endpoint.is_none());
        assert!(prepared.system_proxy_reservation.is_none());
    }

    #[test]
    fn configuration_fingerprint_includes_tun_preference() {
        let disabled = runtime_configuration();
        let enabled_preferences = ConnectionPreferences {
            tun_enabled: true,
            ..ConnectionPreferences::default()
        };
        let enabled = runtime_configuration_with_preferences(enabled_preferences);

        assert_ne!(
            configuration_fingerprint(&disabled),
            configuration_fingerprint(&enabled)
        );
    }

    #[tokio::test]
    async fn readiness_probe_uses_bearer_secret_and_exact_core_version() {
        let listener =
            TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("fake controller");
        listener
            .set_nonblocking(false)
            .expect("blocking fake controller");
        let controller = match listener.local_addr().expect("controller address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => panic!("expected IPv4 controller"),
        };
        let secret = "abcdefghijklmnopqrstuvwxyzABCDEF0123456789_-";
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("readiness request");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("read timeout");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 512];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).expect("request bytes");
                assert_ne!(read, 0, "request ended before headers");
                request.extend_from_slice(&chunk[..read]);
                assert!(request.len() <= 4_096, "request headers are bounded");
            }
            let request = String::from_utf8(request).expect("ASCII HTTP request");
            assert!(
                request
                    .lines()
                    .any(|line| line
                        .eq_ignore_ascii_case(&format!("Authorization: Bearer {secret}")))
            );
            let body = format!(
                r#"{{"version":"sing-box {SING_BOX_ACP_VERSION}","premium":true,"meta":true}}"#
            );
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .expect("readiness response");
        });
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(CONTROL_REQUEST_TIMEOUT)
            .timeout(CONTROL_REQUEST_TIMEOUT)
            .build()
            .expect("control client");

        assert!(probe_control_api_once(&client, controller, secret).await);
        server.join().expect("fake controller thread");
    }

    #[test]
    fn telemetry_snapshot_is_aggregate_and_computes_elapsed_rates() {
        let response: ClashConnectionsResponse = serde_json::from_str(
            r#"{
                "uploadTotal": 5100,
                "downloadTotal": 9400,
                "connections": [{"host":"private.example"}, {"host":"second.example"}],
                "memory": 123456
            }"#,
        )
        .expect("connections response");
        let sampled_at = Instant::now();
        let previous = PreviousTelemetry {
            upload_total: 1_100,
            download_total: 3_400,
            sampled_at: sampled_at - Duration::from_secs(2),
        };

        let snapshot = telemetry_snapshot(&response, Some(previous), sampled_at);

        assert_eq!(snapshot.upload_total_bytes, 5_100);
        assert_eq!(snapshot.download_total_bytes, 9_400);
        assert_eq!(snapshot.upload_bytes_per_second, 2_000);
        assert_eq!(snapshot.download_bytes_per_second, 3_000);
        assert_eq!(snapshot.active_connections, 2);
        assert_eq!(snapshot.memory_bytes, Some(123_456));
    }

    fn runtime_configuration() -> RuntimeConfiguration {
        runtime_configuration_with_preferences(ConnectionPreferences::default())
    }

    fn runtime_configuration_with_preferences(
        preferences: ConnectionPreferences,
    ) -> RuntimeConfiguration {
        RuntimeConfiguration::new(
            RuntimeId::new("rt1").expect("runtime id"),
            1,
            "test-revision",
            "{}",
            preferences,
        )
        .expect("runtime configuration")
    }
}
