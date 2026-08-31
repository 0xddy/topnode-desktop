use std::{
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use thiserror::Error;
use tokio::sync::{Mutex, watch};
use topnode_domain::{
    ConfigurationValidation, ConnectionCancellation, ConnectionEngine, ConnectionState,
    EngineError, RuntimeTelemetrySnapshot, StopReason,
};

use crate::{ConfigurationRequest, ConfigurationSource, ConfigurationSourceError};

type ExpiryTask = (u64, tokio::task::JoinHandle<()>);
type ActiveCancellation = Option<(u64, ConnectionCancellation)>;

struct ActiveCancellationGuard {
    slot: Arc<StdMutex<ActiveCancellation>>,
    generation: u64,
}

impl Drop for ActiveCancellationGuard {
    fn drop(&mut self) {
        let mut slot = self
            .slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot
            .as_ref()
            .is_some_and(|(generation, _)| *generation == self.generation)
        {
            slot.take();
        }
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ConnectError {
    #[error("连接操作正在进行")]
    Busy,
    #[error("连接已取消")]
    Cancelled,
    #[error(transparent)]
    Configuration(#[from] ConfigurationSourceError),
    #[error(transparent)]
    Engine(#[from] EngineError),
}

/// Owns the complete prepare/fetch/validate/start use case and serializes all
/// connection actions, including configuration acquisition.
pub struct ConnectionCoordinator {
    engine: Arc<dyn ConnectionEngine>,
    configuration_source: Arc<dyn ConfigurationSource>,
    state_tx: watch::Sender<ConnectionState>,
    operation_gate: Arc<Mutex<()>>,
    cancellation_epoch: Arc<AtomicU64>,
    active_cancellation: Arc<StdMutex<ActiveCancellation>>,
    expiry_task: Arc<Mutex<Option<ExpiryTask>>>,
}

impl std::fmt::Debug for ConnectionCoordinator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectionCoordinator")
            .finish_non_exhaustive()
    }
}

impl ConnectionCoordinator {
    pub fn new(
        engine: Arc<dyn ConnectionEngine>,
        configuration_source: Arc<dyn ConfigurationSource>,
    ) -> Self {
        let mut engine_states = engine.subscribe();
        let initial_state = engine_states.borrow_and_update().clone();
        let (state_tx, _) = watch::channel(initial_state);
        let forward_tx = state_tx.clone();
        tokio::spawn(async move {
            while engine_states.changed().await.is_ok() {
                let engine_state = engine_states.borrow_and_update().clone();
                let application_state = forward_tx.borrow().clone();
                // Preparing belongs to the new application generation while
                // the engine is still idle. A delayed terminal notification
                // from the previous generation must not make that fetch look
                // disconnected or failed. Any real validation failure is also
                // published by connect() after the engine call returns.
                if matches!(application_state, ConnectionState::Preparing)
                    && matches!(
                        engine_state,
                        ConnectionState::Disconnected | ConnectionState::Failed { .. }
                    )
                {
                    continue;
                }
                forward_tx.send_replace(engine_state);
            }
        });

        Self {
            engine,
            configuration_source,
            state_tx,
            operation_gate: Arc::new(Mutex::new(())),
            cancellation_epoch: Arc::new(AtomicU64::new(0)),
            active_cancellation: Arc::new(StdMutex::new(None)),
            expiry_task: Arc::new(Mutex::new(None)),
        }
    }

    pub fn subscribe(&self) -> watch::Receiver<ConnectionState> {
        self.state_tx.subscribe()
    }

    pub fn subscribe_telemetry(&self) -> watch::Receiver<RuntimeTelemetrySnapshot> {
        self.engine.subscribe_telemetry()
    }

    /// Invalidates an in-flight connect operation at its next cancellation
    /// boundary without waiting for the operation mutex.
    pub fn cancel_pending(&self) {
        self.cancellation_epoch.fetch_add(1, Ordering::AcqRel);
        let cancellation = self
            .active_cancellation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|(_, cancellation)| cancellation.clone());
        if let Some(cancellation) = cancellation {
            cancellation.cancel();
        }
    }

    /// Acquires, validates, and starts one selected runtime configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectError`] when another action is in flight, configuration
    /// acquisition or metadata validation fails, or the engine cannot start.
    pub async fn connect(&self, request: ConfigurationRequest) -> Result<(), ConnectError> {
        let _guard = self
            .operation_gate
            .try_lock()
            .map_err(|_| ConnectError::Busy)?;
        let state = self.state_tx.borrow().clone();
        if state.is_connected() || state.is_transitioning() {
            return Err(EngineError::AlreadyRunning.into());
        }
        let cancellation_epoch = self
            .cancellation_epoch
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        let cancellation = ConnectionCancellation::new();
        {
            let mut active = self
                .active_cancellation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *active = Some((cancellation_epoch, cancellation.clone()));
        }
        let _cancellation_guard = ActiveCancellationGuard {
            slot: Arc::clone(&self.active_cancellation),
            generation: cancellation_epoch,
        };
        self.ensure_not_cancelled(cancellation_epoch, &cancellation)?;
        tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                self.state_tx.send_replace(ConnectionState::Disconnected);
                return Err(ConnectError::Cancelled);
            }
            () = self.cancel_expiry_task() => {}
        }
        self.ensure_not_cancelled(cancellation_epoch, &cancellation)?;

        self.state_tx.send_replace(ConnectionState::Preparing);
        let expected_endpoint_id = request.selected_endpoint_id.clone();
        let preferences = request.preferences.clone();
        let loaded = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                self.state_tx.send_replace(ConnectionState::Disconnected);
                return Err(ConnectError::Cancelled);
            }
            loaded = self.configuration_source.load(&request) => loaded,
        };
        let client_configuration = match loaded {
            Ok(configuration) => configuration,
            Err(error) => {
                self.fail(error.to_string());
                return Err(error.into());
            }
        };
        self.ensure_not_cancelled(cancellation_epoch, &cancellation)?;
        let configuration = match client_configuration.into_runtime(
            &expected_endpoint_id,
            current_epoch_seconds(),
            preferences,
        ) {
            Ok(configuration) => configuration,
            Err(error) => {
                self.fail(error.to_string());
                return Err(error.into());
            }
        };
        self.ensure_not_cancelled(cancellation_epoch, &cancellation)?;

        let expires_at_epoch_seconds = configuration.expires_at_epoch_seconds();
        let validation = self.engine.validate(&configuration, &cancellation).await;
        if matches!(validation, Err(EngineError::Cancelled)) {
            self.state_tx.send_replace(ConnectionState::Disconnected);
            return Err(ConnectError::Cancelled);
        }
        if self.was_cancelled(cancellation_epoch, &cancellation) {
            return self.cancel_after_engine_activity().await;
        }
        let result = match validation {
            Ok(ConfigurationValidation::Valid) => {
                let result = self.engine.start(configuration, &cancellation).await;
                if matches!(result, Err(EngineError::Cancelled)) {
                    self.state_tx.send_replace(ConnectionState::Disconnected);
                    return Err(ConnectError::Cancelled);
                }
                if result.is_ok() && self.was_cancelled(cancellation_epoch, &cancellation) {
                    return self.cancel_after_engine_activity().await;
                }
                if result.is_ok() {
                    self.schedule_expiry(expires_at_epoch_seconds).await;
                }
                result
            }
            Ok(ConfigurationValidation::Invalid { reason }) => {
                Err(EngineError::InvalidConfiguration(reason))
            }
            Err(error) => Err(error),
        };
        if let Err(error) = &result {
            self.fail(error.to_string());
        }
        result.map_err(ConnectError::from)
    }

    /// Stops the active engine, or succeeds immediately when already stopped.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the engine cannot be stopped.
    pub async fn disconnect(&self, reason: StopReason) -> Result<(), EngineError> {
        self.cancel_pending();
        self.cancel_expiry_task().await;
        let _guard = self.operation_gate.lock().await;
        let state = self.state_tx.borrow().clone();
        if matches!(state, ConnectionState::Disconnected) {
            return Ok(());
        }
        self.engine.stop(reason).await
    }

    fn fail(&self, message: String) {
        self.state_tx
            .send_replace(ConnectionState::Failed { message });
    }

    fn was_cancelled(&self, operation_epoch: u64, cancellation: &ConnectionCancellation) -> bool {
        cancellation.is_cancelled()
            || self.cancellation_epoch.load(Ordering::Acquire) != operation_epoch
    }

    fn ensure_not_cancelled(
        &self,
        operation_epoch: u64,
        cancellation: &ConnectionCancellation,
    ) -> Result<(), ConnectError> {
        if self.was_cancelled(operation_epoch, cancellation) {
            self.state_tx.send_replace(ConnectionState::Disconnected);
            Err(ConnectError::Cancelled)
        } else {
            Ok(())
        }
    }

    async fn cancel_after_engine_activity(&self) -> Result<(), ConnectError> {
        if let Err(error) = self.engine.stop(StopReason::User).await {
            self.fail(error.to_string());
            return Err(error.into());
        }
        self.state_tx.send_replace(ConnectionState::Disconnected);
        Err(ConnectError::Cancelled)
    }

    async fn cancel_expiry_task(&self) {
        if let Some((_, task)) = self.expiry_task.lock().await.take() {
            task.abort();
        }
    }

    async fn schedule_expiry(&self, expires_at_epoch_seconds: Option<u64>) {
        let Some(expires_at_epoch_seconds) = expires_at_epoch_seconds else {
            return;
        };
        let generation = self.cancellation_epoch.load(Ordering::Acquire);
        let engine = Arc::clone(&self.engine);
        let operation_gate = Arc::clone(&self.operation_gate);
        let cancellation_epoch = Arc::clone(&self.cancellation_epoch);
        let state_tx = self.state_tx.clone();
        let expiry_task = Arc::clone(&self.expiry_task);
        let (arm_timer, timer_armed) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            if timer_armed.await.is_err() {
                return;
            }
            wait_until_epoch(expires_at_epoch_seconds).await;
            {
                let mut slot = expiry_task.lock().await;
                if slot
                    .as_ref()
                    .is_some_and(|(task_generation, _)| *task_generation == generation)
                {
                    slot.take();
                }
            }
            if cancellation_epoch
                .compare_exchange(
                    generation,
                    generation.wrapping_add(1),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                return;
            }
            let _guard = operation_gate.lock().await;
            if cancellation_epoch.load(Ordering::Acquire) != generation.wrapping_add(1) {
                return;
            }
            if let Err(error) = engine.stop(StopReason::EntitlementExpired).await {
                state_tx.send_replace(ConnectionState::Failed {
                    message: error.to_string(),
                });
            }
        });
        if let Some((_, previous)) = self.expiry_task.lock().await.replace((generation, task)) {
            previous.abort();
        }
        let _ = arm_timer.send(());
    }
}

async fn wait_until_epoch(target_epoch_seconds: u64) {
    const MAX_SLEEP: Duration = Duration::from_secs(60 * 60);
    loop {
        let remaining = target_epoch_seconds.saturating_sub(current_epoch_seconds());
        if remaining == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_secs(remaining).min(MAX_SLEEP)).await;
    }
}

fn current_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Mutex as StdMutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use tokio::sync::{Notify, watch};
    use topnode_domain::{
        ClientConfiguration, ConfigurationValidation, ConnectionCancellation, ConnectionEngine,
        ConnectionPreferences, ConnectionState, EngineCapabilities, EngineError,
        RuntimeConfiguration, RuntimeDescriptor, RuntimeId, RuntimeTelemetrySnapshot, StopReason,
    };

    use crate::{
        ConfigurationRequest, ConfigurationSource, ConfigurationSourceError, ConnectionCoordinator,
    };

    #[derive(Debug)]
    struct FakeEngine {
        states: watch::Sender<ConnectionState>,
        telemetry: watch::Sender<RuntimeTelemetrySnapshot>,
        starts: AtomicUsize,
        stop_reasons: StdMutex<Vec<StopReason>>,
        failure_point: Option<&'static str>,
    }

    impl FakeEngine {
        fn new(failure_point: Option<&'static str>) -> Self {
            let (states, _) = watch::channel(ConnectionState::Disconnected);
            let (telemetry, _) = watch::channel(RuntimeTelemetrySnapshot::default());
            Self {
                states,
                telemetry,
                starts: AtomicUsize::new(0),
                stop_reasons: StdMutex::new(Vec::new()),
                failure_point,
            }
        }
    }

    #[async_trait]
    impl ConnectionEngine for FakeEngine {
        fn descriptor(&self) -> RuntimeDescriptor {
            RuntimeDescriptor {
                runtime_id: RuntimeId::new("rt1").expect("valid runtime"),
                version: "test".to_owned(),
                supported_schemas: vec![1],
                capabilities: EngineCapabilities {
                    latency_test: false,
                    hot_network_update: false,
                    selector_switch: false,
                    ipv6: false,
                },
            }
        }

        fn subscribe(&self) -> watch::Receiver<ConnectionState> {
            self.states.subscribe()
        }

        fn subscribe_telemetry(&self) -> watch::Receiver<RuntimeTelemetrySnapshot> {
            self.telemetry.subscribe()
        }

        async fn validate(
            &self,
            _configuration: &RuntimeConfiguration,
            _cancellation: &ConnectionCancellation,
        ) -> Result<ConfigurationValidation, EngineError> {
            if self.failure_point == Some("validate") {
                return Err(EngineError::Process("validation failed".to_owned()));
            }
            self.states.send_replace(ConnectionState::Validating);
            Ok(ConfigurationValidation::Valid)
        }

        async fn start(
            &self,
            _configuration: RuntimeConfiguration,
            _cancellation: &ConnectionCancellation,
        ) -> Result<(), EngineError> {
            if self.failure_point == Some("start") {
                return Err(EngineError::Process("start failed".to_owned()));
            }
            self.starts.fetch_add(1, Ordering::Relaxed);
            self.states.send_replace(ConnectionState::Connected {
                started_at_epoch_millis: 1,
            });
            Ok(())
        }

        async fn stop(&self, reason: StopReason) -> Result<(), EngineError> {
            self.stop_reasons.lock().expect("stop reasons").push(reason);
            self.states.send_replace(ConnectionState::Disconnected);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct FakeSource;

    #[async_trait]
    impl ConfigurationSource for FakeSource {
        async fn load(
            &self,
            request: &ConfigurationRequest,
        ) -> Result<ClientConfiguration, ConfigurationSourceError> {
            ClientConfiguration::new(
                request.runtime_id.clone(),
                1,
                "test",
                u64::MAX,
                request.selected_endpoint_id.clone(),
                "{}",
            )
            .map_err(|error| ConfigurationSourceError::Invalid(error.to_string()))
        }
    }

    #[derive(Debug)]
    struct BlockingSource {
        started: Arc<Notify>,
        release: Arc<Notify>,
    }

    #[derive(Debug)]
    struct ExpiringSource;

    #[async_trait]
    impl ConfigurationSource for ExpiringSource {
        async fn load(
            &self,
            request: &ConfigurationRequest,
        ) -> Result<ClientConfiguration, ConfigurationSourceError> {
            ClientConfiguration::new(
                request.runtime_id.clone(),
                1,
                "expiring-test",
                super::current_epoch_seconds() + 2,
                request.selected_endpoint_id.clone(),
                "{}",
            )
            .map_err(|error| ConfigurationSourceError::Invalid(error.to_string()))
        }
    }

    #[async_trait]
    impl ConfigurationSource for BlockingSource {
        async fn load(
            &self,
            request: &ConfigurationRequest,
        ) -> Result<ClientConfiguration, ConfigurationSourceError> {
            self.started.notify_one();
            self.release.notified().await;
            FakeSource.load(request).await
        }
    }

    #[tokio::test]
    async fn complete_connect_use_case_starts_engine_once() {
        let engine = Arc::new(FakeEngine::new(None));
        let source: Arc<dyn ConfigurationSource> = Arc::new(FakeSource);
        let coordinator = ConnectionCoordinator::new(engine.clone(), source);

        coordinator
            .connect(request())
            .await
            .expect("connect should succeed");

        assert_eq!(engine.starts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn engine_errors_are_published_as_failed_state() {
        for failure_point in ["validate", "start"] {
            let engine = Arc::new(FakeEngine::new(Some(failure_point)));
            let source: Arc<dyn ConfigurationSource> = Arc::new(FakeSource);
            let coordinator = ConnectionCoordinator::new(engine, source);
            let states = coordinator.subscribe();

            coordinator
                .connect(request())
                .await
                .expect_err("engine should fail");

            assert!(matches!(
                &*states.borrow(),
                ConnectionState::Failed { message } if message.contains("failed")
            ));
        }
    }

    #[tokio::test]
    async fn disconnect_cancels_configuration_fetch_without_waiting_for_the_source() {
        let engine = Arc::new(FakeEngine::new(None));
        let source = Arc::new(BlockingSource {
            started: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        });
        let coordinator = Arc::new(ConnectionCoordinator::new(engine.clone(), source.clone()));
        let connect_coordinator = Arc::clone(&coordinator);
        let connect = tokio::spawn(async move { connect_coordinator.connect(request()).await });
        source.started.notified().await;

        let disconnect_coordinator = Arc::clone(&coordinator);
        tokio::time::timeout(Duration::from_secs(1), async move {
            disconnect_coordinator
                .disconnect(StopReason::SessionInvalid)
                .await
        })
        .await
        .expect("disconnect should cancel a pending source promptly")
        .expect("disconnect succeeds");

        assert!(matches!(
            connect.await.expect("connect task"),
            Err(super::ConnectError::Cancelled)
        ));
        assert_eq!(engine.starts.load(Ordering::Relaxed), 0);
        assert!(matches!(
            &*coordinator.subscribe().borrow(),
            ConnectionState::Disconnected
        ));
    }

    #[tokio::test]
    async fn disconnect_cancels_connect_while_it_waits_for_the_expiry_slot() {
        let engine = Arc::new(FakeEngine::new(None));
        let source: Arc<dyn ConfigurationSource> = Arc::new(FakeSource);
        let coordinator = Arc::new(ConnectionCoordinator::new(engine.clone(), source));
        let expiry_slot_guard = coordinator.expiry_task.lock().await;
        let connect_coordinator = Arc::clone(&coordinator);
        let connect = tokio::spawn(async move { connect_coordinator.connect(request()).await });

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let cancellation_registered = coordinator
                    .active_cancellation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_some();
                if cancellation_registered {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("connect should register cancellation before waiting for expiry cleanup");

        let disconnect_coordinator = Arc::clone(&coordinator);
        let disconnect = tokio::spawn(async move {
            disconnect_coordinator
                .disconnect(StopReason::SessionInvalid)
                .await
        });
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), connect)
                .await
                .expect("disconnect should wake connect while the expiry slot is locked")
                .expect("connect task"),
            Err(super::ConnectError::Cancelled)
        ));

        drop(expiry_slot_guard);
        tokio::time::timeout(Duration::from_secs(1), disconnect)
            .await
            .expect("disconnect should finish after expiry cleanup is released")
            .expect("disconnect task")
            .expect("disconnect succeeds");
        assert_eq!(engine.starts.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn delayed_terminal_engine_state_does_not_overwrite_a_new_preparing_generation() {
        let engine = Arc::new(FakeEngine::new(None));
        let source = Arc::new(BlockingSource {
            started: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        });
        let coordinator = Arc::new(ConnectionCoordinator::new(engine.clone(), source.clone()));
        let connect_coordinator = Arc::clone(&coordinator);
        let connect = tokio::spawn(async move { connect_coordinator.connect(request()).await });
        source.started.notified().await;

        engine.states.send_replace(ConnectionState::Failed {
            message: "stale generation".to_owned(),
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(matches!(
            &*coordinator.subscribe().borrow(),
            ConnectionState::Preparing
        ));

        coordinator
            .disconnect(StopReason::SessionInvalid)
            .await
            .expect("disconnect succeeds");
        assert!(matches!(
            connect.await.expect("connect task"),
            Err(super::ConnectError::Cancelled)
        ));
    }

    #[tokio::test]
    async fn entitlement_expiry_stops_the_running_engine() {
        let engine = Arc::new(FakeEngine::new(None));
        let source: Arc<dyn ConfigurationSource> = Arc::new(ExpiringSource);
        let coordinator = ConnectionCoordinator::new(engine.clone(), source);
        let states = coordinator.subscribe();

        coordinator
            .connect(request())
            .await
            .expect("connect should succeed before expiry");

        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let stopped_for_expiry = engine
                    .stop_reasons
                    .lock()
                    .expect("stop reasons")
                    .contains(&StopReason::EntitlementExpired);
                let disconnected = matches!(&*states.borrow(), ConnectionState::Disconnected);
                if stopped_for_expiry && disconnected {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("expiry should stop the engine");
    }

    fn request() -> ConfigurationRequest {
        ConfigurationRequest {
            group_id: "group:1".to_owned(),
            selected_endpoint_id: "node:1".to_owned(),
            preferences: ConnectionPreferences::default(),
            runtime_id: RuntimeId::new("rt1").expect("valid runtime"),
            supported_schema_versions: vec![1],
        }
    }
}
