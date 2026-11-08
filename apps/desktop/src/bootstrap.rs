use std::{
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::Context;
use slint::{ComponentHandle, Image, Model, Rgba8Pixel, SharedPixelBuffer};
use topnode_application::{
    ConfigurationSource, ConnectionCoordinator, PanelCoordinator, PanelRepository,
};
use topnode_domain::{
    ConnectionEngine, ShopCouponQuote, ShopOrder, ShopOrderStatus, ShopPaymentStatus,
    UserOrderFilter,
};
use topnode_infrastructure::{
    AppPaths, CoreProbe, DesktopSettings, HttpPanelClient, InstanceActivation, InstanceGuard,
    InstanceLockError, PanelClientOptions, PanelEndpoint, PaymentPresentation,
    ProcessContainmentGuard, ResolvedStartupConfiguration, SessionVault, SettingsStore,
    SingBoxSidecar, StartupConfiguration, StartupConfigurationStore, initialize_logging,
    ping_latency,
};

use crate::{
    AppTray, AppWindow, NavigationPage, build_info,
    controller::{DesktopController, PreferenceChange, TunModeUpdate},
    payment_qr, platform, presentation,
};

pub async fn run() -> anyhow::Result<()> {
    if dispatch_elevation_launcher().await? {
        return Ok(());
    }
    let paths = discover_app_paths().await?;
    let mut elevation_startup_mode = platform::tun_elevation_startup_mode()
        .await
        .context("无法处理 Windows TUN 提权重启")?;
    let Some(instance_guards) =
        acquire_primary_instance(&paths, elevation_startup_mode.waits_for_previous_instance())
            .await?
    else {
        return Ok(());
    };
    platform::TunElevationStartupMode::retain_instance_lock(
        paths.instance_lock.clone(),
        instance_guards.primary,
        paths.instance_handoff_lock.clone(),
        instance_guards.handoff_gate,
    )
    .context("无法保留桌面客户端单实例锁")?;
    let _log_guard = initialize_logging(&paths.log_dir).context("无法初始化日志")?;
    platform::initialize_window_backend().context("无法初始化窗口渲染")?;
    let deferred_activation = elevation_startup_mode.waits_for_previous_instance();
    let instance_activation = InstanceActivationRuntime::start(&paths, deferred_activation).await?;
    let fallback_payment_presentation = load_packaged_startup_configuration(&paths).await?;
    let startup_settings = prepare_startup_settings(&paths, &elevation_startup_mode).await?;
    let _process_containment = install_process_containment();
    let ui = AppWindow::new().context("无法创建登录窗口")?;
    let prepare = controller_preparer(&paths, &startup_settings);
    let Some((remote_startup, controller, probe)) = crate::startup::run(
        &ui,
        fallback_payment_presentation,
        !elevation_startup_mode.waits_for_previous_instance(),
        instance_activation.events(),
        prepare,
    )
    .await?
    else {
        tracing::info!("desktop closed before login was enabled");
        instance_activation.stop().await;
        return Ok(());
    };
    let payment_presentation = remote_startup.payment_presentation();
    log_startup(&remote_startup);
    let settings = controller.settings().await;
    let administrator_mode = startup_settings.administrator_mode;
    configure_ui(
        &ui,
        &probe,
        &settings,
        administrator_mode,
        payment_presentation,
    );
    restore_elevated_successor_ui(&ui, &elevation_startup_mode);

    bind_callbacks(&ui, Arc::clone(&controller), payment_presentation);
    crate::updates::install(&ui, &remote_startup, deferred_activation);
    let tray_lifecycle = install_tray(&ui, Arc::clone(&controller))?;
    finalize_elevated_startup(
        &mut elevation_startup_mode,
        &startup_settings,
        &instance_activation,
        deferred_activation,
    )
    .await?;
    let weak = ui.as_weak();
    let activation_forwarder_task =
        spawn_activation_forwarder(instance_activation.events(), move || {
            let weak = weak.clone();
            weak.upgrade_in_event_loop(move |ui| {
                platform::restore_main_window(&ui, "secondary-instance-activation");
            })
            .is_ok()
        });
    let session_guard_task =
        spawn_presentations(&ui, &controller, tray_lifecycle.tray(), probe.available);
    crate::login::enable(&ui);
    let event_loop_result = run_slint_event_loop(&ui);
    drop(tray_lifecycle);
    activation_forwarder_task.abort();
    let _ = activation_forwarder_task.await;
    session_guard_task.abort();
    let _ = session_guard_task.await;
    instance_activation.stop().await;
    controller.shutdown().await;
    tracing::info!("desktop client stopped");
    event_loop_result.context("Slint 事件循环异常退出")?;
    Ok(())
}

fn spawn_presentations(
    ui: &AppWindow,
    controller: &Arc<DesktopController>,
    tray: &AppTray,
    core_available: bool,
) -> tokio::task::JoinHandle<()> {
    presentation::spawn_state_forwarder(ui, controller.subscribe());
    presentation::spawn_telemetry_forwarder(ui, controller.subscribe_telemetry());
    presentation::spawn_tray_state_forwarder(tray, controller.subscribe(), core_available);
    presentation::spawn_account_forwarder(ui, Arc::clone(controller));
    presentation::spawn_shop_forwarder(ui, controller.subscribe_shop());
    spawn_session_guard(Arc::clone(controller))
}

type PreparedDesktop = (
    ResolvedStartupConfiguration,
    Arc<DesktopController>,
    CoreProbe,
);
type ControllerPreparation =
    std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<PreparedDesktop>> + Send>>;

fn controller_preparer(
    paths: &AppPaths,
    prepared: &PreparedStartupSettings,
) -> impl Fn(ResolvedStartupConfiguration) -> ControllerPreparation + Send + 'static {
    let paths = paths.clone();
    let store = prepared.store.clone();
    let settings = prepared.settings.clone();
    move |startup| {
        let paths = paths.clone();
        let store = store.clone();
        let settings = settings.clone();
        Box::pin(async move {
            let (controller, probe) =
                build_controller(&paths, store, settings, startup.endpoint()).await?;
            Ok((startup, controller, probe))
        })
    }
}

async fn discover_app_paths() -> anyhow::Result<AppPaths> {
    let paths = AppPaths::discover().context("无法确定桌面客户端目录")?;
    paths
        .ensure_directories()
        .await
        .context("无法创建应用数据目录")?;
    Ok(paths)
}

async fn load_packaged_startup_configuration(
    paths: &AppPaths,
) -> anyhow::Result<PaymentPresentation> {
    StartupConfigurationStore::new(&paths.startup_configuration)
        .load()
        .await
        .context("无法读取启动配置 runtime/startup.json")
        .map(StartupConfiguration::payment_presentation)
}

fn run_slint_event_loop(component: &impl ComponentHandle) -> Result<(), slint::PlatformError> {
    tokio::task::block_in_place(|| component.run())
}

fn install_process_containment() -> Option<ProcessContainmentGuard> {
    match ProcessContainmentGuard::install() {
        Ok(guard) => {
            tracing::info!(
                capability = ProcessContainmentGuard::capability(),
                "process containment installed"
            );
            Some(guard)
        }
        Err(error) => {
            tracing::warn!(%error, "process containment unavailable; sidecar will use graceful cleanup only");
            None
        }
    }
}

fn log_startup(startup: &ResolvedStartupConfiguration) {
    tracing::info!(
        version_code = build_info::version_code(),
        version_name = build_info::VERSION_NAME,
        git_commit = build_info::GIT_COMMIT,
        build_target = build_info::BUILD_TARGET,
        sing_box_acp_version = topnode_infrastructure::SING_BOX_ACP_VERSION,
        startup_source = startup.source_url(),
        configuration_attempts = startup.configuration_attempts(),
        probe_response_code = startup.probe_response_code(),
        endpoint = ?startup.endpoint(),
        "desktop client starting"
    );
}

async fn dispatch_elevation_launcher() -> anyhow::Result<bool> {
    platform::TunElevationStartupMode::dispatch_launcher_if_requested()
        .await
        .context("无法完成 Windows 提权隔离启动")
}

#[derive(Debug)]
struct PrimaryInstanceGuards {
    primary: InstanceGuard,
    handoff_gate: Option<InstanceGuard>,
}

async fn acquire_primary_instance(
    paths: &AppPaths,
    waits_for_previous_instance: bool,
) -> anyhow::Result<Option<PrimaryInstanceGuards>> {
    let handoff_gate = if waits_for_previous_instance {
        None
    } else {
        match InstanceGuard::acquire(&paths.instance_handoff_lock) {
            Ok(guard) => Some(guard),
            Err(InstanceLockError::AlreadyRunning) => {
                let _ = InstanceActivation::notify(&paths.instance_activation).await;
                return Ok(None);
            }
            Err(error) => return Err(error).context("无法取得桌面客户端交接门闩锁"),
        }
    };
    let primary = if waits_for_previous_instance {
        InstanceGuard::acquire_after_restart_handoff(&paths.instance_lock).await
    } else {
        InstanceGuard::acquire(&paths.instance_lock)
    };
    match primary {
        Ok(primary) => Ok(Some(PrimaryInstanceGuards {
            primary,
            handoff_gate,
        })),
        Err(InstanceLockError::AlreadyRunning) => {
            // Drop the gate before activation I/O so an exiting secondary can
            // never delay another launch for the notification timeout.
            drop(handoff_gate);
            let _ = InstanceActivation::notify(&paths.instance_activation).await;
            Ok(None)
        }
        Err(error) => Err(error).context("无法取得桌面客户端单实例锁"),
    }
}

#[derive(Debug)]
struct PreparedStartupSettings {
    store: SettingsStore,
    original_settings: DesktopSettings,
    settings: DesktopSettings,
    commit_after_handoff: bool,
    administrator_mode: bool,
}

async fn prepare_startup_settings(
    paths: &AppPaths,
    startup_mode: &platform::TunElevationStartupMode,
) -> anyhow::Result<PreparedStartupSettings> {
    let permission_available =
        platform::tun_permission_available().context("无法检查 TUN 启动权限")?;
    prepare_startup_settings_with_permission(paths, startup_mode, permission_available).await
}

async fn prepare_startup_settings_with_permission(
    paths: &AppPaths,
    startup_mode: &platform::TunElevationStartupMode,
    permission_available: bool,
) -> anyhow::Result<PreparedStartupSettings> {
    let settings_store = SettingsStore::new(&paths.settings_file);
    let original_settings = settings_store
        .load()
        .await
        .context("无法读取 TUN 启动设置")?;
    let mut settings = original_settings.clone();
    let mut changed =
        platform::apply_tun_startup_policy(startup_mode, permission_available, &mut settings)
            .context("无法应用 TUN 启动权限策略")?;
    changed |= settings.ensure_device_id();
    let commit_after_handoff = startup_mode.waits_for_previous_instance() && changed;
    if changed && !commit_after_handoff {
        settings_store
            .save(&settings)
            .await
            .context("无法安全保存启动设置")?;
    }
    Ok(PreparedStartupSettings {
        store: settings_store,
        original_settings,
        settings,
        commit_after_handoff,
        administrator_mode: permission_available,
    })
}

async fn persist_delayed_startup_settings(
    prepared: &PreparedStartupSettings,
) -> Result<bool, std::io::Error> {
    if !prepared.commit_after_handoff {
        return Ok(false);
    }
    prepared.store.save(&prepared.settings).await?;
    Ok(true)
}

async fn rollback_delayed_startup_settings(
    prepared: &PreparedStartupSettings,
) -> Result<(), std::io::Error> {
    prepared.store.save(&prepared.original_settings).await
}

async fn complete_elevated_startup_handoff(
    startup_mode: &mut platform::TunElevationStartupMode,
    startup_settings: &PreparedStartupSettings,
    activation: Option<&InstanceActivationRuntime>,
) -> anyhow::Result<()> {
    startup_mode
        .await_successor_commit()
        .await
        .context("提权实例未能完成启动预交接")?;
    if let Some(activation) = activation {
        activation.publish()?;
    }
    let settings_persisted = match persist_delayed_startup_settings(startup_settings).await {
        Ok(persisted) => persisted,
        Err(error) => {
            rollback_elevated_startup(activation, startup_settings, false, &error.to_string())
                .await?;
            return Err(error).context("无法保存提权启动设置");
        }
    };
    if let Err(handoff_error) = startup_mode.acknowledge_successor_commit().await {
        rollback_elevated_startup(
            activation,
            startup_settings,
            settings_persisted,
            &handoff_error.to_string(),
        )
        .await?;
        return Err(handoff_error).context("提权实例未能完成启动交接");
    }
    Ok(())
}

async fn rollback_elevated_startup(
    activation: Option<&InstanceActivationRuntime>,
    startup_settings: &PreparedStartupSettings,
    settings_persisted: bool,
    cause: &str,
) -> anyhow::Result<()> {
    let activation_result = activation.map(InstanceActivationRuntime::rollback_publication);
    let settings_result = if settings_persisted {
        Some(rollback_delayed_startup_settings(startup_settings).await)
    } else {
        None
    };
    if let Some(result) = activation_result {
        result.with_context(|| format!("启动交接失败后无法恢复激活记录：{cause}"))?;
    }
    if let Some(result) = settings_result {
        result.with_context(|| format!("启动交接失败后无法恢复原设置：{cause}"))?;
    }
    Ok(())
}

async fn finalize_elevated_startup(
    startup_mode: &mut platform::TunElevationStartupMode,
    startup_settings: &PreparedStartupSettings,
    activation: &InstanceActivationRuntime,
    deferred_activation: bool,
) -> anyhow::Result<()> {
    if deferred_activation {
        tracing::info!("elevated replacement acquired the single-instance lock");
        tracing::info!("elevated replacement startup preflight completed");
    }
    complete_elevated_startup_handoff(
        startup_mode,
        startup_settings,
        deferred_activation.then_some(activation),
    )
    .await?;
    Ok(())
}

fn spawn_session_guard(controller: Arc<DesktopController>) -> tokio::task::JoinHandle<()> {
    let mut accounts = controller.subscribe_account();
    tokio::spawn(async move {
        loop {
            let snapshot = accounts.borrow_and_update().clone();
            if !snapshot.is_authenticated()
                && let Err(error) = controller.disconnect_if_session_invalid().await
            {
                tracing::warn!(%error, "failed to disconnect after account session invalidation");
            }
            if accounts.changed().await.is_err() {
                return;
            }
        }
    })
}

async fn build_controller(
    paths: &AppPaths,
    settings_store: SettingsStore,
    settings: DesktopSettings,
    panel_endpoint: &PanelEndpoint,
) -> anyhow::Result<(Arc<DesktopController>, CoreProbe)> {
    let panel_client = Arc::new(HttpPanelClient::new_for_endpoint(
        PanelClientOptions::for_endpoint(panel_endpoint, settings.device_id.clone())
            .with_version_name(build_info::VERSION_NAME),
        panel_endpoint,
        SessionVault::new(paths.session_vault_file.clone()),
    )?);
    let config_source: Arc<dyn ConfigurationSource> = panel_client.clone();
    let panel_repository: Arc<dyn PanelRepository> = panel_client;
    let panel = Arc::new(PanelCoordinator::new(panel_repository));

    let sidecar = Arc::new(SingBoxSidecar::new(paths.clone())?);
    sidecar
        .reconcile_system_proxy()
        .await
        .context("无法恢复上次连接使用的系统代理设置")?;
    sidecar
        .clear_stale_session()
        .await
        .context("无法清理上次遗留的运行时配置")?;
    let probe = sidecar.probe().await;
    let engine: Arc<dyn ConnectionEngine> = sidecar;
    let coordinator = Arc::new(ConnectionCoordinator::new(engine, config_source));
    let controller = Arc::new(DesktopController::new(
        coordinator,
        panel,
        settings_store,
        settings,
    ));
    Ok((controller, probe))
}

fn configure_ui(
    ui: &AppWindow,
    probe: &CoreProbe,
    settings: &DesktopSettings,
    administrator_mode: bool,
    payment_presentation: PaymentPresentation,
) {
    ui.set_administrator_mode(administrator_mode);
    ui.set_checkout_payment_qr_mode(payment_presentation == PaymentPresentation::QrCode);
    ui.set_core_available(probe.available);
    ui.set_notice("".into());
    ui.set_tun_mode(settings.preferences.tun_enabled);
    ui.set_global_mode(settings.preferences.route_mode == topnode_domain::RouteMode::Global);
    ui.set_bypass_mainland(settings.preferences.bypass_mainland);
    ui.set_bypass_lan(settings.preferences.bypass_lan);
    ui.set_udp_forwarding(settings.preferences.udp_forwarding_enabled);
    ui.set_multiplex(settings.preferences.multiplex_enabled);
}

fn restore_elevated_successor_ui(ui: &AppWindow, startup_mode: &platform::TunElevationStartupMode) {
    if startup_mode.waits_for_previous_instance() {
        ui.set_current_page(NavigationPage::Settings);
        ui.set_notice("全局模式已启用，请重新连接。".into());
    }
}

#[derive(Debug)]
struct InstanceActivationRuntime {
    activation: Arc<InstanceActivation>,
    events: tokio::sync::watch::Receiver<u64>,
    server_task: tokio::task::JoinHandle<()>,
}

impl InstanceActivationRuntime {
    async fn start(paths: &AppPaths, defer_publication: bool) -> anyhow::Result<Self> {
        let activation = if defer_publication {
            InstanceActivation::prepare(&paths.instance_activation).await
        } else {
            InstanceActivation::bind(&paths.instance_activation).await
        }
        .context("无法创建单实例激活通道")?;
        let activation = Arc::new(activation);
        let (events, server_task) = spawn_instance_activation_server(Arc::clone(&activation));
        Ok(Self {
            activation,
            events,
            server_task,
        })
    }

    fn events(&self) -> tokio::sync::watch::Receiver<u64> {
        self.events.clone()
    }

    fn publish(&self) -> anyhow::Result<()> {
        self.activation
            .publish()
            .context("无法发布桌面客户端单实例激活通道")
    }

    fn rollback_publication(&self) -> anyhow::Result<()> {
        self.activation
            .rollback_publication()
            .context("无法恢复桌面客户端单实例激活通道")
    }

    async fn stop(self) {
        self.server_task.abort();
        let _ = self.server_task.await;
        drop(self.activation);
    }
}

fn spawn_instance_activation_server(
    activation: Arc<InstanceActivation>,
) -> (
    tokio::sync::watch::Receiver<u64>,
    tokio::task::JoinHandle<()>,
) {
    let (sender, receiver) = tokio::sync::watch::channel(0_u64);
    let task = tokio::spawn(async move {
        loop {
            if let Err(error) = activation.wait_for_notification().await {
                tracing::warn!(%error, "instance activation listener stopped");
                return;
            }
            let generation = (*sender.borrow()).saturating_add(1);
            sender.send_replace(generation);
        }
    });
    (receiver, task)
}

pub(crate) fn spawn_activation_forwarder(
    mut events: tokio::sync::watch::Receiver<u64>,
    restore: impl Fn() -> bool + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let generation = *events.borrow_and_update();
            if generation > 0 && !restore() {
                return;
            }
            if events.changed().await.is_err() {
                return;
            }
        }
    })
}

fn install_tray(
    ui: &AppWindow,
    controller: Arc<DesktopController>,
) -> anyhow::Result<platform::TrayLifecycle> {
    let lifecycle = platform::TrayLifecycle::install(ui).context("无法创建系统托盘")?;
    bind_tray_callbacks(ui, lifecycle.tray(), controller);
    Ok(lifecycle)
}

fn bind_tray_callbacks(ui: &AppWindow, tray: &AppTray, controller: Arc<DesktopController>) {
    let weak = ui.as_weak();
    tray.on_toggle_connection(move || {
        if let Some(ui) = weak.upgrade()
            && ui.get_update_required()
        {
            ui.set_update_visible(true);
            platform::restore_main_window(&ui, "required-update");
            return;
        }
        let controller = Arc::clone(&controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            if let Err(error) = controller.toggle_connection().await {
                let _ = weak.upgrade_in_event_loop(move |ui| {
                    ui.set_notice(error.into());
                    platform::restore_main_window(&ui, "tray-action-error");
                });
            }
        });
    });
}

fn bind_callbacks(
    ui: &AppWindow,
    controller: Arc<DesktopController>,
    payment_presentation: PaymentPresentation,
) {
    crate::login::install(ui, Arc::clone(&controller));
    bind_account_callbacks(ui, &controller);
    bind_profile_account_callbacks(ui, &controller);
    bind_shop_callbacks(ui, &controller, payment_presentation);
    bind_runtime_callbacks(ui, &controller);
    bind_preference_callbacks(ui, controller);
}

fn bind_account_callbacks(ui: &AppWindow, controller: &Arc<DesktopController>) {
    let latency_runner = Arc::new(NodeLatencyRunner::default());

    let account_controller = Arc::clone(controller);
    let runner = Arc::clone(&latency_runner);
    let weak = ui.as_weak();
    ui.on_logout(move || {
        if let Some(ui) = weak.upgrade() {
            crate::login::clear_form(&ui);
        }
        runner.deactivate(&account_controller);
        let controller = Arc::clone(&account_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            crate::login::forget_saved(&weak).await;
            if let Err(error) = controller.logout().await {
                presentation::post_notice(&weak, format!("退出登录未完全完成：{error}"));
            }
            presentation::refresh_account_view(&weak, &controller).await;
        });
    });

    let account_controller = Arc::clone(controller);
    let runner = Arc::clone(&latency_runner);
    let weak = ui.as_weak();
    ui.on_open_node_selector(move || {
        runner.activate();
        runner.start(Arc::clone(&account_controller), weak.clone());
        refresh_node_selector_resources(
            Arc::clone(&account_controller),
            Arc::clone(&runner),
            weak.clone(),
        );
    });

    let account_controller = Arc::clone(controller);
    let runner = Arc::clone(&latency_runner);
    ui.on_close_node_selector(move || {
        runner.deactivate(&account_controller);
    });

    let account_controller = Arc::clone(controller);
    let runner = Arc::clone(&latency_runner);
    let weak = ui.as_weak();
    ui.on_refresh_resources(move || {
        runner.start(Arc::clone(&account_controller), weak.clone());
        refresh_node_selector_resources(
            Arc::clone(&account_controller),
            Arc::clone(&runner),
            weak.clone(),
        );
    });

    let account_controller = Arc::clone(controller);
    let weak = ui.as_weak();
    ui.on_refresh_subscriptions(move || {
        let controller = Arc::clone(&account_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            if let Err(error) = controller.refresh_subscriptions().await {
                presentation::post_notice(&weak, error);
            }
            presentation::refresh_account_view(&weak, &controller).await;
        });
    });

    bind_resource_group_callback(ui, controller, &latency_runner);

    let account_controller = Arc::clone(controller);
    let runner = Arc::clone(&latency_runner);
    let weak = ui.as_weak();
    ui.on_select_node(move |endpoint_id| {
        runner.cancel_current(&account_controller);
        let controller = Arc::clone(&account_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            if let Err(error) = controller.select_node(endpoint_id.to_string()).await {
                presentation::post_notice(&weak, error);
            }
            presentation::refresh_account_view(&weak, &controller).await;
        });
    });
}

fn bind_resource_group_callback(
    ui: &AppWindow,
    controller: &Arc<DesktopController>,
    latency_runner: &Arc<NodeLatencyRunner>,
) {
    let account_controller = Arc::clone(controller);
    let runner = Arc::clone(latency_runner);
    let weak = ui.as_weak();
    ui.on_select_resource_group(move |group_id, entitlement_id| {
        runner.cancel_current(&account_controller);
        let controller = Arc::clone(&account_controller);
        let runner = Arc::clone(&runner);
        let weak = weak.clone();
        tokio::spawn(async move {
            if let Err(error) = controller
                .select_group(group_id.to_string(), entitlement_id.to_string())
                .await
            {
                presentation::post_notice(&weak, error);
            }
            presentation::refresh_account_view(&weak, &controller).await;
            runner.start(controller, weak);
        });
    });
}

fn bind_profile_account_callbacks(ui: &AppWindow, controller: &Arc<DesktopController>) {
    let account_controller = Arc::clone(controller);
    let weak = ui.as_weak();
    ui.on_change_account_password(move |current_password, new_password, confirm_password| {
        let controller = Arc::clone(&account_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            let result = controller
                .change_password(
                    current_password.to_string(),
                    new_password.to_string(),
                    confirm_password.to_string(),
                )
                .await;
            match result {
                Ok(()) => {
                    crate::login::forget_saved(&weak).await;
                    let _ = weak.upgrade_in_event_loop(|ui| crate::login::clear_form(&ui));
                    presentation::post_notice(&weak, "密码修改成功，请使用新密码重新登录。");
                }
                Err(error) => presentation::post_account_settings_error(&weak, error),
            }
            presentation::refresh_account_view(&weak, &controller).await;
        });
    });

    let account_controller = Arc::clone(controller);
    let weak = ui.as_weak();
    ui.on_refresh_balance_details(move || {
        let controller = Arc::clone(&account_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            match controller.load_balance_details().await {
                Ok(transactions) => presentation::post_balance_details(&weak, &transactions),
                Err(error) => presentation::post_balance_details_error(&weak, error),
            }
            presentation::refresh_account_view(&weak, &controller).await;
        });
    });

    let order_generation = Arc::new(AtomicU64::new(0));
    let account_controller = Arc::clone(controller);
    let weak = ui.as_weak();
    ui.on_load_orders(move |filter, page, append| {
        let filter = match filter.as_str() {
            "all" => UserOrderFilter::All,
            "pending" => UserOrderFilter::Pending,
            "paid" => UserOrderFilter::Paid,
            "refunded" => UserOrderFilter::Refunded,
            _ => {
                presentation::post_orders_error(&weak, "订单筛选条件无效");
                return;
            }
        };
        let Ok(page) = u32::try_from(page) else {
            presentation::post_orders_error(&weak, "订单页码无效");
            return;
        };
        let generation = order_generation.fetch_add(1, Ordering::Relaxed) + 1;
        let generation_guard = Arc::clone(&order_generation);
        let controller = Arc::clone(&account_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            let result = controller.load_orders(filter, page).await;
            if generation_guard.load(Ordering::Relaxed) != generation {
                return;
            }
            match result {
                Ok(orders) => presentation::post_orders(&weak, &orders, append),
                Err(error) => presentation::post_orders_error(&weak, error),
            }
        });
    });

    bind_gift_card_callbacks(ui, controller);
    bind_invitation_callbacks(ui, controller);
    bind_subscription_link_callbacks(ui, controller);
    bind_support_ticket_callbacks(ui, controller);
}

fn bind_support_ticket_callbacks(ui: &AppWindow, controller: &Arc<DesktopController>) {
    let detail_generation = Arc::new(AtomicU64::new(0));
    bind_support_ticket_list_callback(ui, controller);
    bind_support_ticket_cancel_callback(ui, &detail_generation);
    bind_support_ticket_open_callback(ui, controller, &detail_generation);
    bind_support_ticket_earlier_callback(ui, controller, &detail_generation);
    bind_support_ticket_create_callback(ui, controller, &detail_generation);
    bind_support_ticket_message_callbacks(ui, controller);
    bind_support_ticket_close_callback(ui, controller);
}

fn bind_support_ticket_list_callback(ui: &AppWindow, controller: &Arc<DesktopController>) {
    let list_generation = Arc::new(AtomicU64::new(0));
    let ticket_controller = Arc::clone(controller);
    let generation_guard = Arc::clone(&list_generation);
    let weak = ui.as_weak();
    ui.on_load_support_tickets(move |requested_page, append| {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let page = if requested_page == 0 {
            ui.get_tickets_list_page().saturating_add(1)
        } else {
            requested_page
        };
        let Ok(page) = u32::try_from(page) else {
            presentation::post_support_tickets_error(&weak, "工单页码无效", append);
            return;
        };
        if append {
            ui.set_tickets_list_loading_more(true);
            ui.set_tickets_list_more_error("".into());
        } else if ui.get_support_tickets().row_count() > 0 {
            ui.set_tickets_list_refreshing(true);
            ui.set_tickets_list_error("".into());
        } else {
            ui.set_tickets_list_loading(true);
            ui.set_tickets_list_error("".into());
        }
        drop(ui);

        let request_generation = generation_guard.fetch_add(1, Ordering::Relaxed) + 1;
        let generation_guard = Arc::clone(&generation_guard);
        let controller = Arc::clone(&ticket_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            let result = controller.load_support_tickets(page).await;
            if generation_guard.load(Ordering::Relaxed) != request_generation {
                return;
            }
            match result {
                Ok(tickets) => presentation::post_support_tickets(&weak, &tickets, append),
                Err(error) => presentation::post_support_tickets_error(&weak, error, append),
            }
        });
    });
}

fn bind_support_ticket_cancel_callback(ui: &AppWindow, detail_generation: &Arc<AtomicU64>) {
    let generation_guard = Arc::clone(detail_generation);
    ui.on_cancel_support_ticket_view(move || {
        generation_guard.fetch_add(1, Ordering::Relaxed);
    });
}

fn bind_support_ticket_open_callback(
    ui: &AppWindow,
    controller: &Arc<DesktopController>,
    detail_generation: &Arc<AtomicU64>,
) {
    let ticket_controller = Arc::clone(controller);
    let generation_guard = Arc::clone(detail_generation);
    let weak = ui.as_weak();
    ui.on_open_support_ticket(move |ticket_id| {
        let ticket_id = ticket_id.to_string();
        let Some(ui) = weak.upgrade() else {
            return;
        };
        if let Some(ticket) = ui
            .get_support_tickets()
            .iter()
            .find(|ticket| ticket.id.as_str() == ticket_id)
        {
            ui.set_selected_ticket_id(ticket.id);
            ui.set_selected_ticket_title(ticket.title);
            ui.set_selected_ticket_number(ticket.ticket_number);
            ui.set_selected_ticket_status_label(ticket.status_label);
            ui.set_selected_ticket_status_tone(ticket.status_tone);
            ui.set_selected_ticket_priority_label(ticket.priority_label);
            ui.set_selected_ticket_closed(ticket.closed);
        } else {
            ui.set_selected_ticket_id(ticket_id.clone().into());
        }
        ui.set_tickets_mode("chat".into());
        ui.set_ticket_detail_loading(true);
        ui.set_ticket_detail_error("".into());
        ui.set_support_ticket_messages(slint::ModelRc::default());
        ui.set_ticket_message_page(0);
        ui.set_ticket_message_total(0);
        ui.set_ticket_has_earlier(false);
        ui.set_ticket_earlier_error("".into());
        ui.set_ticket_send_error("".into());
        drop(ui);

        let request_generation = generation_guard.fetch_add(1, Ordering::Relaxed) + 1;
        let generation_guard = Arc::clone(&generation_guard);
        let controller = Arc::clone(&ticket_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            let result = controller.load_support_ticket(&ticket_id, 1).await;
            if generation_guard.load(Ordering::Relaxed) != request_generation {
                return;
            }
            match result {
                Ok(detail) => presentation::post_support_ticket_opened(&weak, &detail),
                Err(error) => presentation::post_support_ticket_detail_error(&weak, error),
            }
        });
    });
}

fn bind_support_ticket_earlier_callback(
    ui: &AppWindow,
    controller: &Arc<DesktopController>,
    detail_generation: &Arc<AtomicU64>,
) {
    let ticket_controller = Arc::clone(controller);
    let generation_guard = Arc::clone(detail_generation);
    let weak = ui.as_weak();
    ui.on_load_earlier_ticket_messages(move |ticket_id| {
        let ticket_id = ticket_id.to_string();
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let page = ui.get_ticket_message_page().saturating_add(1);
        let Ok(page) = u32::try_from(page) else {
            presentation::post_earlier_support_ticket_error(&weak, "消息页码无效");
            return;
        };
        ui.set_ticket_loading_earlier(true);
        ui.set_ticket_earlier_error("".into());
        drop(ui);

        let request_generation = generation_guard.fetch_add(1, Ordering::Relaxed) + 1;
        let generation_guard = Arc::clone(&generation_guard);
        let controller = Arc::clone(&ticket_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            let result = controller.load_support_ticket(&ticket_id, page).await;
            if generation_guard.load(Ordering::Relaxed) != request_generation {
                return;
            }
            match result {
                Ok(detail) => {
                    presentation::post_earlier_support_ticket_messages(&weak, &detail);
                }
                Err(error) => presentation::post_earlier_support_ticket_error(&weak, error),
            }
        });
    });
}

fn bind_support_ticket_create_callback(
    ui: &AppWindow,
    controller: &Arc<DesktopController>,
    detail_generation: &Arc<AtomicU64>,
) {
    let ticket_controller = Arc::clone(controller);
    let generation_guard = Arc::clone(detail_generation);
    let weak = ui.as_weak();
    ui.on_create_support_ticket(move |title, priority, message| {
        if let Some(ui) = weak.upgrade() {
            ui.set_ticket_creating(true);
            ui.set_ticket_create_error("".into());
        }
        let request_generation = generation_guard.fetch_add(1, Ordering::Relaxed) + 1;
        let generation_guard = Arc::clone(&generation_guard);
        let controller = Arc::clone(&ticket_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            let result = controller
                .create_support_ticket(title.to_string(), priority.as_str(), message.to_string())
                .await;
            if generation_guard.load(Ordering::Relaxed) != request_generation {
                return;
            }
            match result {
                Ok(detail) => presentation::post_support_ticket_opened(&weak, &detail),
                Err(error) => presentation::post_support_ticket_create_error(&weak, error),
            }
        });
    });
}

fn bind_support_ticket_message_callbacks(ui: &AppWindow, controller: &Arc<DesktopController>) {
    let local_message_sequence = Arc::new(AtomicU64::new(0));
    let ticket_controller = Arc::clone(controller);
    let local_sequence = Arc::clone(&local_message_sequence);
    let weak = ui.as_weak();
    ui.on_send_support_ticket_message(move |ticket_id, content| {
        let ticket_id = ticket_id.to_string();
        let content = content.to_string();
        let local_id = format!(
            "local-{}",
            local_sequence.fetch_add(1, Ordering::Relaxed) + 1
        );
        presentation::post_support_ticket_sending(&weak, local_id.clone(), content.clone());
        let controller = Arc::clone(&ticket_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            match controller.reply_support_ticket(&ticket_id, content).await {
                Ok(detail) => {
                    presentation::post_support_ticket_delivered(&weak, &local_id, &detail);
                }
                Err(error) => {
                    presentation::post_support_ticket_send_error(&weak, &local_id, error);
                }
            }
        });
    });
}

fn bind_support_ticket_close_callback(ui: &AppWindow, controller: &Arc<DesktopController>) {
    let ticket_controller = Arc::clone(controller);
    let weak = ui.as_weak();
    ui.on_retry_support_ticket_message(move |ticket_id, local_id, content| {
        let ticket_id = ticket_id.to_string();
        let local_id = local_id.to_string();
        let content = content.to_string();
        presentation::post_support_ticket_retrying(&weak, &local_id);
        let controller = Arc::clone(&ticket_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            match controller.reply_support_ticket(&ticket_id, content).await {
                Ok(detail) => {
                    presentation::post_support_ticket_delivered(&weak, &local_id, &detail);
                }
                Err(error) => {
                    presentation::post_support_ticket_send_error(&weak, &local_id, error);
                }
            }
        });
    });

    let ticket_controller = Arc::clone(controller);
    let weak = ui.as_weak();
    ui.on_close_support_ticket(move |ticket_id| {
        let ticket_id = ticket_id.to_string();
        if let Some(ui) = weak.upgrade() {
            ui.set_ticket_closing(true);
            ui.set_ticket_close_error("".into());
        }
        let controller = Arc::clone(&ticket_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            match controller.close_support_ticket(&ticket_id).await {
                Ok(action) => presentation::post_support_ticket_closed(&weak, &action),
                Err(error) => presentation::post_support_ticket_close_error(&weak, error),
            }
        });
    });
}

fn bind_gift_card_callbacks(ui: &AppWindow, controller: &Arc<DesktopController>) {
    let account_controller = Arc::clone(controller);
    let weak = ui.as_weak();
    ui.on_load_gift_card(move || {
        let controller = Arc::clone(&account_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            match controller.load_gift_card_config().await {
                Ok(config) => presentation::post_gift_card_config(&weak, &config),
                Err(error) => presentation::post_gift_card_initialization_error(&weak, error),
            }
        });
    });

    let gift_card_generation = Arc::new(AtomicU64::new(0));
    let account_controller = Arc::clone(controller);
    let generation_guard = Arc::clone(&gift_card_generation);
    let weak = ui.as_weak();
    ui.on_check_gift_card(move |code| {
        let generation = generation_guard.fetch_add(1, Ordering::Relaxed) + 1;
        let generation_guard = Arc::clone(&generation_guard);
        let controller = Arc::clone(&account_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            let result = controller.check_gift_card(code.as_str()).await;
            if generation_guard.load(Ordering::Relaxed) != generation {
                return;
            }
            match result {
                Ok(check) => presentation::post_gift_card_check(&weak, &check),
                Err(error) => presentation::post_gift_card_check_error(&weak, error),
            }
        });
    });

    let account_controller = Arc::clone(controller);
    let generation_guard = Arc::clone(&gift_card_generation);
    let weak = ui.as_weak();
    ui.on_redeem_gift_card(move |code| {
        let generation = generation_guard.fetch_add(1, Ordering::Relaxed) + 1;
        let generation_guard = Arc::clone(&generation_guard);
        let controller = Arc::clone(&account_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            let result = controller.redeem_gift_card(code.as_str()).await;
            if generation_guard.load(Ordering::Relaxed) != generation {
                return;
            }
            match result {
                Ok(reward) => {
                    presentation::post_gift_card_redeemed(&weak, &reward);
                    presentation::refresh_account_view(&weak, &controller).await;
                }
                Err(error) => presentation::post_gift_card_redeem_error(&weak, error),
            }
        });
    });

    let weak = ui.as_weak();
    ui.on_open_gift_card_purchase(move |url| {
        let url = url.to_string();
        let weak = weak.clone();
        tokio::spawn(async move {
            let opened = tokio::task::spawn_blocking(move || platform::open_url(&url)).await;
            if !matches!(opened, Ok(Ok(()))) {
                presentation::post_notice(&weak, "暂时无法打开礼品卡购买页面。");
            }
        });
    });
}

fn bind_invitation_callbacks(ui: &AppWindow, controller: &Arc<DesktopController>) {
    let invitation_generation = Arc::new(AtomicU64::new(0));
    let account_controller = Arc::clone(controller);
    let generation_guard = Arc::clone(&invitation_generation);
    let weak = ui.as_weak();
    ui.on_load_invitations(move || {
        let generation = generation_guard.fetch_add(1, Ordering::Relaxed) + 1;
        let generation_guard = Arc::clone(&generation_guard);
        let controller = Arc::clone(&account_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            let result = controller.load_invitations().await;
            if generation_guard.load(Ordering::Relaxed) != generation {
                return;
            }
            match result {
                Ok(dashboard) => {
                    match dashboard.summary {
                        Ok(summary) => presentation::post_affiliate_summary(&weak, &summary),
                        Err(error) => presentation::post_affiliate_summary_error(&weak, error),
                    }
                    match dashboard.commissions {
                        Ok(page) => presentation::post_affiliate_commissions(&weak, &page, false),
                        Err(error) => {
                            presentation::post_affiliate_commissions_error(&weak, error);
                        }
                    }
                    match dashboard.transfers {
                        Ok(page) => presentation::post_affiliate_transfers(&weak, &page, false),
                        Err(error) => presentation::post_affiliate_transfers_error(&weak, error),
                    }
                }
                Err(error) => {
                    presentation::post_affiliate_summary_error(&weak, error.clone());
                    presentation::post_affiliate_commissions_error(&weak, error.clone());
                    presentation::post_affiliate_transfers_error(&weak, error);
                }
            }
        });
    });

    let records_generation = Arc::clone(&invitation_generation);
    let account_controller = Arc::clone(controller);
    let generation_guard = Arc::clone(&records_generation);
    let weak = ui.as_weak();
    ui.on_load_invitation_records(move |kind, page, append| {
        let Ok(page) = u32::try_from(page) else {
            post_affiliate_records_error(&weak, kind.as_str(), "邀请记录页码无效");
            return;
        };
        let generation = generation_guard.fetch_add(1, Ordering::Relaxed) + 1;
        let generation_guard = Arc::clone(&generation_guard);
        let controller = Arc::clone(&account_controller);
        let weak = weak.clone();
        let kind = kind.to_string();
        tokio::spawn(async move {
            if kind == "commissions" {
                let result = controller.load_affiliate_commissions(page).await;
                if generation_guard.load(Ordering::Relaxed) != generation {
                    return;
                }
                match result {
                    Ok(page) => presentation::post_affiliate_commissions(&weak, &page, append),
                    Err(error) => presentation::post_affiliate_commissions_error(&weak, error),
                }
            } else if kind == "transfers" {
                let result = controller.load_affiliate_transfers(page).await;
                if generation_guard.load(Ordering::Relaxed) != generation {
                    return;
                }
                match result {
                    Ok(page) => presentation::post_affiliate_transfers(&weak, &page, append),
                    Err(error) => presentation::post_affiliate_transfers_error(&weak, error),
                }
            } else {
                post_affiliate_records_error(&weak, &kind, "邀请记录类型无效");
            }
        });
    });

    let weak = ui.as_weak();
    ui.on_copy_invitation_value(move |label, value| {
        let label = label.to_string();
        let value = value.to_string();
        let weak = weak.clone();
        tokio::spawn(async move {
            let copied = tokio::task::spawn_blocking(move || platform::copy_text(&value)).await;
            if matches!(copied, Ok(Ok(()))) {
                presentation::post_notice(&weak, format!("{label}已复制"));
            } else {
                presentation::post_notice(&weak, "暂时无法复制，请稍后重试。");
            }
        });
    });
}

fn post_affiliate_records_error(weak: &slint::Weak<AppWindow>, kind: &str, message: &str) {
    if kind == "commissions" {
        presentation::post_affiliate_commissions_error(weak, message);
    } else {
        presentation::post_affiliate_transfers_error(weak, message);
    }
}

fn bind_subscription_link_callbacks(ui: &AppWindow, controller: &Arc<DesktopController>) {
    let generation = Arc::new(AtomicU64::new(0));

    let account_controller = Arc::clone(controller);
    let generation_guard = Arc::clone(&generation);
    let weak = ui.as_weak();
    ui.on_load_subscription_link(move || {
        let request_generation = generation_guard.fetch_add(1, Ordering::Relaxed) + 1;
        let generation_guard = Arc::clone(&generation_guard);
        let controller = Arc::clone(&account_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            let result = controller.load_subscription_link().await;
            if generation_guard.load(Ordering::Relaxed) != request_generation {
                return;
            }
            match result {
                Ok(link) => presentation::post_subscription_link(&weak, &link),
                Err(error) => presentation::post_subscription_link_error(&weak, error),
            }
        });
    });

    let account_controller = Arc::clone(controller);
    let generation_guard = Arc::clone(&generation);
    let weak = ui.as_weak();
    ui.on_reset_subscription_link(move || {
        let request_generation = generation_guard.fetch_add(1, Ordering::Relaxed) + 1;
        let generation_guard = Arc::clone(&generation_guard);
        let controller = Arc::clone(&account_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            if let Err(error) = controller.reset_subscription_link().await {
                if generation_guard.load(Ordering::Relaxed) == request_generation {
                    presentation::post_subscription_reset_error(&weak, error);
                }
                return;
            }
            let result = controller.load_subscription_link().await;
            if generation_guard.load(Ordering::Relaxed) != request_generation {
                return;
            }
            match result {
                Ok(link) => {
                    presentation::post_subscription_link(&weak, &link);
                    presentation::post_notice(&weak, "订阅地址已重置");
                }
                Err(_) => presentation::post_subscription_reset_refresh_error(&weak),
            }
        });
    });

    let weak = ui.as_weak();
    ui.on_copy_subscription_link(move |value| {
        let value = value.to_string();
        let weak = weak.clone();
        tokio::spawn(async move {
            if value.trim().is_empty() {
                presentation::post_notice(&weak, "暂无可复制的订阅地址。");
                return;
            }
            let copied = tokio::task::spawn_blocking(move || platform::copy_text(&value)).await;
            if matches!(copied, Ok(Ok(()))) {
                presentation::post_notice(&weak, "订阅地址已复制");
            } else {
                presentation::post_notice(&weak, "暂时无法复制订阅地址，请稍后重试。");
            }
        });
    });
}

fn bind_shop_callbacks(
    ui: &AppWindow,
    controller: &Arc<DesktopController>,
    payment_presentation: PaymentPresentation,
) {
    bind_shop_refresh_callbacks(ui, controller);
    bind_shop_coupon_callback(ui, controller);
    bind_shop_order_callback(ui, controller);
    bind_shop_payment_callback(ui, controller, payment_presentation);
    bind_shop_poll_callback(ui, controller);
    bind_shop_reopen_payment_callback(ui);
}

fn bind_shop_refresh_callbacks(ui: &AppWindow, controller: &Arc<DesktopController>) {
    let shop_controller = Arc::clone(controller);
    let weak = ui.as_weak();
    ui.on_refresh_shop(move || {
        let controller = Arc::clone(&shop_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            if let Err(error) = controller.refresh_shop().await {
                presentation::post_notice(&weak, error);
            }
        });
    });

    let shop_controller = Arc::clone(controller);
    let weak = ui.as_weak();
    ui.on_refresh_profile(move || {
        let controller = Arc::clone(&shop_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            if let Err(error) = controller.refresh_profile().await {
                presentation::post_notice(&weak, error);
            }
            presentation::refresh_account_view(&weak, &controller).await;
        });
    });
}

fn bind_shop_coupon_callback(ui: &AppWindow, controller: &Arc<DesktopController>) {
    let shop_controller = Arc::clone(controller);
    let weak = ui.as_weak();
    ui.on_check_shop_coupon(move |kind, plan_id, product_id, coupon_code| {
        let controller = Arc::clone(&shop_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            let result = controller
                .check_coupon(
                    kind.as_str(),
                    plan_id.as_str(),
                    product_id.as_str(),
                    coupon_code.as_str(),
                )
                .await;
            match result {
                Ok(quote) => {
                    let _ = weak.upgrade_in_event_loop(move |ui| {
                        apply_checkout_coupon(&ui, &quote);
                        ui.set_checkout_stage("confirm".into());
                        ui.set_checkout_error("".into());
                    });
                }
                Err(error) => set_checkout_error(&weak, error),
            }
        });
    });
}

fn bind_shop_order_callback(ui: &AppWindow, controller: &Arc<DesktopController>) {
    let shop_controller = Arc::clone(controller);
    let weak = ui.as_weak();
    ui.on_create_shop_order(move |kind, plan_id, product_id, coupon_code| {
        let controller = Arc::clone(&shop_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            let result = controller
                .create_order(
                    kind.as_str(),
                    plan_id.as_str(),
                    product_id.as_str(),
                    coupon_code.as_str(),
                )
                .await;
            match result {
                Ok(order) => {
                    let _ = weak.upgrade_in_event_loop(move |ui| {
                        apply_checkout_order(&ui, &order);
                        ui.set_checkout_error(
                            checkout_error_for_order(&order).unwrap_or_default().into(),
                        );
                        ui.set_checkout_stage(checkout_stage_for_order(&order).into());
                    });
                }
                Err(error) => set_checkout_error(&weak, error),
            }
        });
    });
}

fn bind_shop_payment_callback(
    ui: &AppWindow,
    controller: &Arc<DesktopController>,
    payment_presentation: PaymentPresentation,
) {
    let shop_controller = Arc::clone(controller);
    let weak = ui.as_weak();
    ui.on_pay_shop_order(move |order_id, payment_method_id, use_balance| {
        let controller = Arc::clone(&shop_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            let result = controller
                .pay_order(order_id.as_str(), payment_method_id.as_str(), use_balance)
                .await;
            match result {
                Ok(order) => {
                    let stage = checkout_stage_for_order(&order);
                    let pay_url = (stage == "waiting")
                        .then(|| checkout_payment_url(&order))
                        .flatten()
                        .map(str::to_owned);
                    let payment_result = if stage == "waiting" {
                        prepare_payment_presentation(payment_presentation, pay_url.as_deref())
                    } else {
                        Ok(None)
                    };
                    let _ = weak.upgrade_in_event_loop(move |ui| {
                        apply_checkout_order(&ui, &order);
                        ui.set_checkout_stage(stage.into());
                        ui.set_checkout_payment_qr_ready(false);
                        ui.set_checkout_payment_qr(Image::default());
                        let presentation_error = match payment_result {
                            Ok(Some(buffer)) => {
                                ui.set_checkout_payment_qr(Image::from_rgba8(buffer));
                                ui.set_checkout_payment_qr_ready(true);
                                None
                            }
                            Ok(None) => None,
                            Err(error) => Some(error),
                        };
                        ui.set_checkout_error(
                            presentation_error
                                .or_else(|| checkout_error_for_order(&order).map(str::to_owned))
                                .unwrap_or_default()
                                .into(),
                        );
                    });
                }
                Err(error) => set_checkout_error(&weak, error),
            }
        });
    });
}

fn bind_shop_poll_callback(ui: &AppWindow, controller: &Arc<DesktopController>) {
    let shop_controller = Arc::clone(controller);
    let weak = ui.as_weak();
    ui.on_poll_shop_order(move |order_id| {
        if let Some(ui) = weak.upgrade() {
            if ui.get_checkout_polling() {
                return;
            }
            ui.set_checkout_polling(true);
        }
        let requested_order_id = order_id.to_string();
        let controller = Arc::clone(&shop_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            let result = controller.get_order(&requested_order_id).await;
            let _ = weak.upgrade_in_event_loop(move |ui| {
                if ui.get_checkout_order_id().as_str() != requested_order_id {
                    return;
                }
                ui.set_checkout_polling(false);
                match result {
                    Ok(Some(order)) => {
                        apply_checkout_order(&ui, &order);
                        if order.status.payment_received() {
                            ui.set_checkout_error("".into());
                            ui.set_checkout_stage("success".into());
                        } else if let Some(error) = checkout_error_for_order(&order) {
                            ui.set_checkout_error(error.into());
                        }
                    }
                    Ok(None) => {}
                    Err(error) => ui.set_checkout_error(error.into()),
                }
            });
        });
    });
}

fn bind_shop_reopen_payment_callback(ui: &AppWindow) {
    let weak = ui.as_weak();
    ui.on_reopen_shop_payment(move |url| {
        if let Err(error) = platform::open_url(url.as_str()) {
            set_checkout_error(&weak, format!("无法打开支付页面：{error}"));
        }
    });
}

fn prepare_payment_presentation(
    presentation: PaymentPresentation,
    payment_url: Option<&str>,
) -> Result<Option<SharedPixelBuffer<Rgba8Pixel>>, String> {
    let payment_url =
        payment_url.ok_or_else(|| "支付已发起，但服务端未返回可用的支付链接。".to_owned())?;
    match presentation {
        PaymentPresentation::QrCode => payment_qr::render_payment_url(payment_url).map(Some),
        PaymentPresentation::Browser => platform::open_url(payment_url)
            .map(|()| None)
            .map_err(|error| format!("支付已发起，但无法打开支付页面：{error}")),
    }
}

fn apply_checkout_coupon(ui: &AppWindow, quote: &ShopCouponQuote) {
    ui.set_checkout_coupon_applied(true);
    ui.set_checkout_coupon_code(quote.code.clone().into());
    ui.set_checkout_coupon_name(quote.name.clone().into());
    ui.set_checkout_coupon_summary(quote.discount_summary.clone().into());
    ui.set_checkout_coupon_discount_label(
        format!(
            "-{}",
            presentation::format_money(quote.discount_amount_cents, &quote.currency)
        )
        .into(),
    );
    ui.set_checkout_coupon_payable_label(
        presentation::format_money(quote.payable_amount_cents, &quote.currency).into(),
    );
}

fn apply_checkout_order(ui: &AppWindow, order: &ShopOrder) {
    let (amount_cents, currency) = order
        .payment
        .as_ref()
        .map_or((order.amount_cents, order.currency.as_str()), |payment| {
            (payment.amount_cents, payment.currency.as_str())
        });
    ui.set_checkout_order_id(order.id.to_string().into());
    ui.set_checkout_order_number(order.order_number.clone().into());
    ui.set_checkout_order_amount_cents(presentation::clamp_i64_to_i32(amount_cents));
    ui.set_checkout_order_amount_label(presentation::format_money(amount_cents, currency).into());
    ui.set_checkout_order_status_label(checkout_order_status_label(order.status).into());
    ui.set_checkout_fulfillment_pending(order.status == ShopOrderStatus::PaidPendingFulfillment);
    if let Some(pay_url) = checkout_payment_url(order) {
        ui.set_checkout_payment_url(pay_url.into());
    }
}

fn checkout_payment_url(order: &ShopOrder) -> Option<&str> {
    order
        .payment
        .as_ref()
        .and_then(|payment| payment.pay_url.as_deref())
        .map(str::trim)
        .filter(|url| !url.is_empty())
}

fn checkout_stage_for_order(order: &ShopOrder) -> &'static str {
    if order.status.payment_received() {
        "success"
    } else if order.status == ShopOrderStatus::Refunded
        || order.payment.as_ref().is_some_and(|payment| {
            matches!(
                payment.status,
                ShopPaymentStatus::Failed | ShopPaymentStatus::Closed | ShopPaymentStatus::Refunded
            )
        })
    {
        "payment"
    } else if order.payment.is_some() {
        "waiting"
    } else {
        "payment"
    }
}

fn checkout_error_for_order(order: &ShopOrder) -> Option<&'static str> {
    if order.status == ShopOrderStatus::Refunded {
        return Some("订单已退款，无法继续支付。");
    }
    match order.payment.as_ref().map(|payment| payment.status) {
        Some(ShopPaymentStatus::Failed) => Some("支付失败，请重新选择支付方式。"),
        Some(ShopPaymentStatus::Closed) => Some("支付会话已关闭，请重新发起支付。"),
        Some(ShopPaymentStatus::Refunded) => Some("款项已退款，无法继续支付。"),
        _ => None,
    }
}

const fn checkout_order_status_label(status: ShopOrderStatus) -> &'static str {
    match status {
        ShopOrderStatus::Pending => "待支付",
        ShopOrderStatus::PaidPendingFulfillment => "已支付，待履约",
        ShopOrderStatus::Paid => "已完成",
        ShopOrderStatus::Refunded => "已退款",
    }
}

fn set_checkout_error(weak: &slint::Weak<AppWindow>, error: String) {
    let _ = weak.upgrade_in_event_loop(move |ui| ui.set_checkout_error(error.into()));
}

const NODE_LATENCY_TIMEOUT: Duration = Duration::from_millis(1_500);
const NODE_LATENCY_ATTEMPTS: usize = 3;
const NODE_LATENCY_RETRY_DELAY: Duration = Duration::from_millis(100);
const NODE_LATENCY_CONCURRENCY: usize = 8;

#[derive(Debug, Default)]
struct NodeLatencyRunner {
    state: StdMutex<NodeLatencyRunnerState>,
}

#[derive(Debug, Default)]
struct NodeLatencyRunnerState {
    active: bool,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl NodeLatencyRunner {
    fn activate(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active = true;
    }

    fn start(&self, controller: Arc<DesktopController>, weak: slint::Weak<AppWindow>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.active {
            return;
        }
        if let Some(task) = state.task.take() {
            task.abort();
        }
        let task = tokio::spawn(async move {
            let batch = controller.begin_node_latency().await;
            presentation::refresh_account_view(&weak, &controller).await;
            let generation = batch.generation;
            let values = measure_node_latencies(batch.targets_by_node_id).await;
            controller.finish_node_latency(generation, values);
            presentation::refresh_account_view(&weak, &controller).await;
        });
        state.task = Some(task);
    }

    fn cancel_current(&self, controller: &DesktopController) {
        self.abort_active_task();
        controller.cancel_node_latency();
    }

    fn deactivate(&self, controller: &DesktopController) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active = false;
        if let Some(task) = state.task.take() {
            task.abort();
        }
        drop(state);
        controller.cancel_node_latency();
    }

    fn abort_active_task(&self) {
        if let Some(task) = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .task
            .take()
        {
            task.abort();
        }
    }
}

fn refresh_node_selector_resources(
    controller: Arc<DesktopController>,
    runner: Arc<NodeLatencyRunner>,
    weak: slint::Weak<AppWindow>,
) {
    tokio::spawn(async move {
        let _ = controller.refresh_resources().await;
        presentation::refresh_account_view(&weak, &controller).await;
        runner.start(controller, weak);
    });
}

async fn measure_node_latencies(targets: Vec<(String, String)>) -> Vec<(String, Option<u64>)> {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(NODE_LATENCY_CONCURRENCY));
    let mut tasks = tokio::task::JoinSet::new();
    for (node_id, target) in targets {
        let semaphore = Arc::clone(&semaphore);
        tasks.spawn(async move {
            let Ok(_permit) = semaphore.acquire_owned().await else {
                return (node_id, None);
            };
            let latency =
                retry_node_latency(NODE_LATENCY_ATTEMPTS, NODE_LATENCY_RETRY_DELAY, || {
                    ping_latency(&target, NODE_LATENCY_TIMEOUT)
                })
                .await;
            (node_id, latency)
        });
    }
    let mut values = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Ok(value) = result {
            values.push(value);
        }
    }
    values
}

async fn retry_node_latency<Probe, ProbeFuture>(
    attempts: usize,
    retry_delay: Duration,
    mut probe: Probe,
) -> Option<u64>
where
    Probe: FnMut() -> ProbeFuture,
    ProbeFuture: std::future::Future<Output = Option<u64>>,
{
    for attempt in 0..attempts {
        if let Some(latency) = probe().await {
            return Some(latency);
        }
        if attempt + 1 < attempts && !retry_delay.is_zero() {
            tokio::time::sleep(retry_delay).await;
        }
    }
    None
}

fn bind_runtime_callbacks(ui: &AppWindow, controller: &Arc<DesktopController>) {
    let weak = ui.as_weak();
    let action_controller = Arc::clone(controller);
    ui.on_toggle_connection(move || {
        if let Some(ui) = weak.upgrade()
            && ui.get_update_required()
        {
            ui.set_update_visible(true);
            return;
        }
        let controller = Arc::clone(&action_controller);
        let weak = weak.clone();
        tokio::spawn(async move {
            if let Err(error) = controller.toggle_connection().await {
                presentation::post_notice(&weak, error);
            }
        });
    });
}

fn bind_preference_callbacks(ui: &AppWindow, controller: Arc<DesktopController>) {
    let tun_controller = Arc::clone(&controller);
    let weak = ui.as_weak();
    ui.on_tun_mode_changed(move |enabled| {
        let controller = Arc::clone(&tun_controller);
        let weak = weak.clone();
        if let Some(ui) = weak.upgrade() {
            ui.set_tun_change_pending(true);
        }
        tokio::spawn(async move {
            let result = controller.set_tun_mode(enabled).await;
            let actual = controller.settings().await.preferences.tun_enabled;
            match result {
                Ok(TunModeUpdate::Restarting) => {}
                Ok(TunModeUpdate::Cancelled) => {
                    let _ = weak.upgrade_in_event_loop(move |ui| {
                        ui.set_tun_mode(actual);
                        ui.set_tun_change_pending(false);
                        ui.set_notice("未获得管理员权限，已保持系统代理模式。".into());
                    });
                }
                Ok(TunModeUpdate::Applied) => {
                    let _ = weak.upgrade_in_event_loop(move |ui| {
                        ui.set_tun_mode(actual);
                        ui.set_tun_change_pending(false);
                    });
                }
                Err(error) => {
                    let _ = weak.upgrade_in_event_loop(move |ui| {
                        ui.set_tun_mode(actual);
                        ui.set_tun_change_pending(false);
                        ui.set_notice(error.into());
                    });
                }
            }
        });
    });

    let preference_controller = Arc::clone(&controller);
    let weak = ui.as_weak();
    ui.on_global_mode_changed(move |enabled| {
        presentation::bind_preference_callback(
            Arc::clone(&preference_controller),
            weak.clone(),
            move || PreferenceChange::GlobalMode(enabled),
        );
    });

    let preference_controller = Arc::clone(&controller);
    let weak = ui.as_weak();
    ui.on_bypass_mainland_changed(move |enabled| {
        presentation::bind_preference_callback(
            Arc::clone(&preference_controller),
            weak.clone(),
            move || PreferenceChange::BypassMainland(enabled),
        );
    });

    let preference_controller = Arc::clone(&controller);
    let weak = ui.as_weak();
    ui.on_bypass_lan_changed(move |enabled| {
        presentation::bind_preference_callback(
            Arc::clone(&preference_controller),
            weak.clone(),
            move || PreferenceChange::BypassLan(enabled),
        );
    });

    let preference_controller = Arc::clone(&controller);
    let weak = ui.as_weak();
    ui.on_udp_forwarding_changed(move |enabled| {
        presentation::bind_preference_callback(
            Arc::clone(&preference_controller),
            weak.clone(),
            move || PreferenceChange::UdpForwarding(enabled),
        );
    });

    let weak = ui.as_weak();
    ui.on_multiplex_changed(move |enabled| {
        presentation::bind_preference_callback(Arc::clone(&controller), weak.clone(), move || {
            PreferenceChange::Multiplex(enabled)
        });
    });
}

#[cfg(test)]
mod checkout_tests {
    use topnode_domain::{ShopOrder, ShopOrderStatus, ShopPaymentSession, ShopPaymentStatus};

    use super::{checkout_error_for_order, checkout_payment_url, checkout_stage_for_order};

    fn order(
        status: ShopOrderStatus,
        payment_status: Option<ShopPaymentStatus>,
        pay_url: Option<&str>,
    ) -> ShopOrder {
        ShopOrder {
            id: 42,
            order_number: "TN42".to_owned(),
            amount_cents: 2_000,
            currency: "CNY".to_owned(),
            status,
            can_pay: true,
            payment: payment_status.map(|payment_status| ShopPaymentSession {
                required: true,
                status: payment_status,
                payment_method_id: Some(7),
                provider: "epay".to_owned(),
                payment_type: "alipay".to_owned(),
                amount_cents: 2_000,
                fee_amount_cents: 0,
                net_amount_cents: 2_000,
                currency: "CNY".to_owned(),
                pay_url: pay_url.map(str::to_owned),
            }),
        }
    }

    #[test]
    fn checkout_moves_through_payment_waiting_and_success() {
        let created = order(ShopOrderStatus::Pending, None, None);
        assert_eq!(checkout_stage_for_order(&created), "payment");

        let paying = order(
            ShopOrderStatus::Pending,
            Some(ShopPaymentStatus::Pending),
            Some("  https://pay.example.test/42  "),
        );
        assert_eq!(checkout_stage_for_order(&paying), "waiting");
        assert_eq!(
            checkout_payment_url(&paying),
            Some("https://pay.example.test/42")
        );

        let paid = order(ShopOrderStatus::Paid, None, None);
        assert_eq!(checkout_stage_for_order(&paid), "success");
    }

    #[test]
    fn failed_payment_returns_to_method_selection_with_a_safe_message() {
        let failed = order(
            ShopOrderStatus::Pending,
            Some(ShopPaymentStatus::Failed),
            None,
        );
        assert_eq!(checkout_stage_for_order(&failed), "payment");
        assert_eq!(
            checkout_error_for_order(&failed),
            Some("支付失败，请重新选择支付方式。")
        );
    }
}

#[cfg(test)]
mod latency_tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use super::retry_node_latency;

    #[tokio::test]
    async fn latency_probe_retries_until_the_first_success() {
        let calls = Arc::new(AtomicUsize::new(0));
        let probe_calls = Arc::clone(&calls);

        let latency = retry_node_latency(3, Duration::ZERO, move || {
            let attempt = probe_calls.fetch_add(1, Ordering::SeqCst);
            async move { (attempt == 2).then_some(42) }
        })
        .await;

        assert_eq!(latency, Some(42));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn latency_probe_stops_after_the_attempt_limit() {
        let calls = Arc::new(AtomicUsize::new(0));
        let probe_calls = Arc::clone(&calls);

        let latency = retry_node_latency(3, Duration::ZERO, move || {
            probe_calls.fetch_add(1, Ordering::SeqCst);
            async { None }
        })
        .await;

        assert_eq!(latency, None);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }
}

#[cfg(test)]
mod startup_settings_tests {
    use std::sync::Arc;

    use topnode_infrastructure::{AppPaths, DesktopSettings, SettingsStore};

    use super::{
        InstanceActivationRuntime, complete_elevated_startup_handoff,
        persist_delayed_startup_settings, prepare_startup_settings_with_permission,
        rollback_delayed_startup_settings,
    };
    use crate::platform::TunElevationStartupMode;

    #[tokio::test]
    async fn elevated_setting_is_not_visible_until_commit_and_rolls_back_on_abort() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let paths = AppPaths::from_roots(
            &directory.path().join("topnode-desktop.exe"),
            directory.path().join("data"),
        );
        paths
            .ensure_directories()
            .await
            .expect("application directories");
        let original = DesktopSettings {
            device_id: "65b59d06-2981-4eb7-9b78-70bb1de12e9c".to_owned(),
            ..DesktopSettings::default()
        };
        let store = SettingsStore::new(&paths.settings_file);
        store.save(&original).await.expect("original settings");

        let startup = TunElevationStartupMode::elevated_without_handoff_for_test();
        let prepared = prepare_startup_settings_with_permission(&paths, &startup, true)
            .await
            .expect("prepare elevated settings");
        assert!(prepared.settings.preferences.tun_enabled);
        assert!(
            !store
                .load()
                .await
                .expect("uncommitted settings")
                .preferences
                .tun_enabled
        );

        assert!(
            persist_delayed_startup_settings(&prepared)
                .await
                .expect("commit settings")
        );
        assert!(
            store
                .load()
                .await
                .expect("committed settings")
                .preferences
                .tun_enabled
        );

        rollback_delayed_startup_settings(&prepared)
            .await
            .expect("rollback settings");
        assert_eq!(store.load().await.expect("rolled back settings"), original);
    }

    #[tokio::test]
    async fn activation_publish_failure_prevents_the_irreversible_handoff() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let paths = AppPaths::from_roots(
            &directory.path().join("topnode-desktop.exe"),
            directory.path().join("data"),
        );
        paths
            .ensure_directories()
            .await
            .expect("application directories");
        let original = DesktopSettings {
            device_id: "65b59d06-2981-4eb7-9b78-70bb1de12e9c".to_owned(),
            ..DesktopSettings::default()
        };
        let store = SettingsStore::new(&paths.settings_file);
        store.save(&original).await.expect("original settings");
        let mut startup = TunElevationStartupMode::elevated_without_handoff_for_test();
        let prepared = prepare_startup_settings_with_permission(&paths, &startup, true)
            .await
            .expect("prepare elevated settings");

        let invalid_metadata_path = directory.path().join("metadata-is-a-directory");
        tokio::fs::create_dir(&invalid_metadata_path)
            .await
            .expect("metadata directory fixture");
        let activation =
            topnode_infrastructure::InstanceActivation::prepare(&invalid_metadata_path)
                .await
                .expect("prepared listener");
        let (_sender, events) = tokio::sync::watch::channel(0_u64);
        let activation = InstanceActivationRuntime {
            activation: Arc::new(activation),
            events,
            server_task: tokio::spawn(async {}),
        };

        let error = complete_elevated_startup_handoff(&mut startup, &prepared, Some(&activation))
            .await
            .expect_err("activation publication should fail before commit");

        assert!(error.to_string().contains("无法发布"));
        assert_eq!(store.load().await.expect("unchanged settings"), original);
        activation.stop().await;
    }
}
