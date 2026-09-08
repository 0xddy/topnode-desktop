use anyhow::Context;
use slint::ComponentHandle;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{mpsc, oneshot, watch};
use topnode_infrastructure::{
    PaymentPresentation, PendingStartupConfiguration, RemoteStartupConfigurationLoader,
    ResolvedStartupConfiguration,
};

use crate::{AppWindow, build_info, platform};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StartupAction {
    Retry,
    Continue,
    Download,
}

/// Keeps configuration discovery and upgrade decisions on the visible login page.
pub async fn run<T, F, Fut>(
    ui: &AppWindow,
    payment: PaymentPresentation,
    user_cold_start: bool,
    activation_events: watch::Receiver<u64>,
    prepare: F,
) -> anyhow::Result<Option<T>>
where
    T: Send + 'static,
    F: Fn(ResolvedStartupConfiguration) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = anyhow::Result<T>> + Send,
{
    let (actions, receiver) = mpsc::unbounded_channel();
    let cancelled = Arc::new(AtomicBool::new(false));
    bind_callbacks(ui, actions, Arc::clone(&cancelled));
    crate::login::bind_preference(ui);
    ui.show().context("无法显示登录页面")?;
    platform::finish_window_frame(ui);
    let (shown, visible) = oneshot::channel();
    slint::Timer::single_shot(std::time::Duration::ZERO, move || {
        let _ = shown.send(());
    });
    let (completed, mut result) = oneshot::channel();
    let weak = ui.as_weak();
    let worker = tokio::spawn(async move {
        if visible.await.is_err() {
            return;
        }
        let (outcome, ()) = tokio::join!(
            load(&weak, payment, user_cold_start, receiver, prepare),
            crate::login::load_saved(&weak),
        );
        let _ = weak.upgrade_in_event_loop(move |ui| {
            let ready = matches!(&outcome, Ok(Some(_)));
            let _ = completed.send(outcome);
            if ready {
                // Keep this exact window visible while the main callbacks are installed.
                let _ = slint::quit_event_loop();
            } else {
                finish(&ui);
            }
        });
    });
    let weak = ui.as_weak();
    let activation = crate::bootstrap::spawn_activation_forwarder(activation_events, move || {
        weak.upgrade_in_event_loop(|ui| {
            platform::restore_main_window(&ui, "login-startup-activation");
        })
        .is_ok()
    });
    let event_loop = tokio::task::block_in_place(slint::run_event_loop);
    worker.abort();
    activation.abort();
    let _ = worker.await;
    let _ = activation.await;
    event_loop.context("登录页面事件循环异常退出")?;
    if cancelled.load(Ordering::Acquire) {
        Ok(None)
    } else {
        result.try_recv().unwrap_or(Ok(None))
    }
}

fn bind_callbacks(
    ui: &AppWindow,
    actions: mpsc::UnboundedSender<StartupAction>,
    cancelled: Arc<AtomicBool>,
) {
    let weak = ui.as_weak();
    let retry = actions.clone();
    ui.on_retry_startup(move || {
        if let Some(ui) = weak.upgrade()
            && ui.get_login_config_failed()
        {
            ui.set_login_config_failed(false);
            ui.set_login_config_status("加载配置中…".into());
            let _ = retry.send(StartupAction::Retry);
        }
    });
    let weak = ui.as_weak();
    let proceed = actions.clone();
    ui.on_dismiss_update(move || {
        if let Some(ui) = weak.upgrade()
            && ui.get_update_visible()
            && !ui.get_update_required()
            && !ui.get_update_opening()
        {
            ui.set_update_visible(false);
            ui.set_login_config_status("正在连接服务…".into());
            let _ = proceed.send(StartupAction::Continue);
        }
    });
    let weak = ui.as_weak();
    ui.on_open_website(move || {
        if let Some(ui) = weak.upgrade() {
            ui.invoke_download_update();
        }
    });
    let weak = ui.as_weak();
    ui.on_download_update(move || {
        if let Some(ui) = weak.upgrade()
            && ui.get_update_visible()
            && !ui.get_update_opening()
        {
            ui.set_update_opening(true);
            ui.set_update_error("".into());
            let _ = actions.send(StartupAction::Download);
        }
    });
    let weak = ui.as_weak();
    let closed = Arc::clone(&cancelled);
    ui.on_close_window(move || {
        closed.store(true, Ordering::Release);
        if let Some(ui) = weak.upgrade() {
            finish(&ui);
        }
    });
    let weak = ui.as_weak();
    ui.on_drag_window(move || {
        if let Some(ui) = weak.upgrade() {
            platform::drag_window(&ui);
        }
    });
    let weak = ui.as_weak();
    ui.on_quit_for_update(move || {
        if let Some(ui) = weak.upgrade() {
            finish(&ui);
        }
    });
    ui.window().on_close_requested(move || {
        cancelled.store(true, Ordering::Release);
        slint::CloseRequestResponse::HideWindow
    });
}

fn finish(ui: &AppWindow) {
    if let Err(error) = ui.hide() {
        tracing::warn!(%error, "failed to hide startup window");
    }
    if let Err(error) = slint::quit_event_loop() {
        tracing::warn!(%error, "failed to leave startup event loop");
    }
}

async fn load<T, F, Fut>(
    ui: &slint::Weak<AppWindow>,
    payment: PaymentPresentation,
    user_cold_start: bool,
    mut actions: mpsc::UnboundedReceiver<StartupAction>,
    prepare: F,
) -> anyhow::Result<Option<T>>
where
    F: Fn(ResolvedStartupConfiguration) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let loader = RemoteStartupConfigurationLoader::production(
        payment,
        build_info::BUILD_TARGET,
        build_info::VERSION_NAME,
    )?;
    let mut prompted_version = None;
    loop {
        show_loading(ui, "加载配置中…")?;
        let attempt = match loader.fetch().await {
            Ok(pending) => {
                let release = pending.desktop_version();
                let current = build_info::version_code();
                if release.requires_update(current)
                    || (user_cold_start
                        && release.is_newer_than(current)
                        && prompted_version != Some(release.version_code()))
                {
                    prompted_version = Some(release.version_code());
                    if !confirm_update(ui, &pending, &mut actions).await? {
                        return Ok(None);
                    }
                }
                show_loading(ui, "正在连接服务…")?;
                match loader.resolve(pending).await {
                    Ok(resolved) => prepare(resolved).await,
                    Err(error) => Err(error.into()),
                }
            }
            Err(error) => Err(error.into()),
        };
        match attempt {
            Ok(resolved) => return Ok(Some(resolved)),
            Err(error) if !user_cold_start => return Err(error),
            Err(error) => {
                tracing::warn!(%error, "remote desktop startup failed");
                ui.upgrade_in_event_loop(move |ui| {
                    ui.set_login_config_failed(true);
                    ui.set_login_config_status("配置加载失败，请重试".into());
                })?;
                if next_action(&mut actions, |action| action == StartupAction::Retry)
                    .await
                    .is_none()
                {
                    return Ok(None);
                }
            }
        }
    }
}

fn show_loading(ui: &slint::Weak<AppWindow>, status: &'static str) -> anyhow::Result<()> {
    ui.upgrade_in_event_loop(move |ui| {
        ui.set_login_config_failed(false);
        ui.set_update_visible(false);

        ui.set_login_config_status(status.into());
    })?;
    Ok(())
}

async fn confirm_update(
    ui: &slint::Weak<AppWindow>,
    pending: &PendingStartupConfiguration,
    actions: &mut mpsc::UnboundedReceiver<StartupAction>,
) -> anyhow::Result<bool> {
    let release = pending.desktop_version().clone();
    let current = build_info::version_code();
    let required = release.requires_update(current);
    let website = pending.website().unwrap_or_default().to_owned();
    ui.upgrade_in_event_loop(move |ui| {
        ui.set_update_version(
            format!("{}（{}）", release.version_name(), release.version_code()).into(),
        );
        ui.set_update_notes(release.update_info().into());
        ui.set_update_required(required);
        ui.set_update_url(
            release
                .available_download_url(current)
                .unwrap_or_default()
                .into(),
        );
        ui.set_website_url(website.into());
        ui.set_login_auto_blocked(true);
        ui.set_login_auto_pending(false);
        ui.set_login_config_status("发现新版本".into());
        ui.set_update_error("".into());
        ui.set_update_visible(true);
    })?;
    let destination = pending
        .desktop_version()
        .available_download_url(current)
        .or(pending.website())
        .unwrap_or_default()
        .to_owned();
    wait_for_update_decision(actions, required, || {
        let destination = destination.clone();
        async move {
            let opened =
                tokio::task::spawn_blocking(move || platform::open_url(&destination)).await;
            let success = matches!(opened, Ok(Ok(())));
            ui.upgrade_in_event_loop(move |ui| {
                ui.set_update_opening(false);
                ui.set_update_error(if success {
                    "".into()
                } else {
                    "无法打开下载页面，请检查默认浏览器设置后重试。".into()
                });
            })?;
            Ok(())
        }
    })
    .await
}

async fn wait_for_update_decision<F, Fut>(
    actions: &mut mpsc::UnboundedReceiver<StartupAction>,
    required: bool,
    mut open_download: F,
) -> anyhow::Result<bool>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    while let Some(action) = next_update_action(actions, required).await {
        if action == StartupAction::Continue {
            return Ok(true);
        }
        // Opening a download is not an exit or a decision to continue login.
        // Keep waiting so the user can return to this window after the browser.
        open_download().await?;
    }
    Ok(false)
}

async fn next_update_action(
    actions: &mut mpsc::UnboundedReceiver<StartupAction>,
    required: bool,
) -> Option<StartupAction> {
    next_action(actions, |action| {
        action == StartupAction::Download || (!required && action == StartupAction::Continue)
    })
    .await
}

async fn next_action(
    actions: &mut mpsc::UnboundedReceiver<StartupAction>,
    accepts: impl Fn(StartupAction) -> bool,
) -> Option<StartupAction> {
    while let Some(action) = actions.recv().await {
        if accepts(action) {
            return Some(action);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{StartupAction, next_update_action, wait_for_update_decision};
    use std::cell::Cell;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn required_update_cannot_continue_even_if_a_defer_action_is_queued() {
        let (sender, mut actions) = mpsc::unbounded_channel();
        sender.send(StartupAction::Continue).unwrap();
        sender.send(StartupAction::Retry).unwrap();
        sender.send(StartupAction::Download).unwrap();
        assert_eq!(
            next_update_action(&mut actions, true).await,
            Some(StartupAction::Download)
        );
    }

    #[tokio::test]
    async fn optional_update_waits_for_the_users_decision() {
        let (sender, mut actions) = mpsc::unbounded_channel();
        sender.send(StartupAction::Retry).unwrap();
        let mut decision = Box::pin(next_update_action(&mut actions, false));
        assert!(futures_poll_pending(&mut decision));
        sender.send(StartupAction::Continue).unwrap();
        assert_eq!(decision.await, Some(StartupAction::Continue));
    }

    #[tokio::test]
    async fn opening_optional_update_keeps_startup_alive_until_the_user_defers() {
        let (sender, mut actions) = mpsc::unbounded_channel();
        let opened = Cell::new(0);
        let mut decision = Box::pin(wait_for_update_decision(&mut actions, false, || {
            opened.set(opened.get() + 1);
            std::future::ready(Ok(()))
        }));
        sender.send(StartupAction::Download).unwrap();
        assert!(futures_poll_pending(&mut decision));
        assert_eq!(opened.get(), 1);
        sender.send(StartupAction::Continue).unwrap();
        assert!(decision.await.unwrap());
    }

    #[tokio::test]
    async fn opening_required_update_keeps_startup_alive_without_allowing_login() {
        let (sender, mut actions) = mpsc::unbounded_channel();
        let opened = Cell::new(0);
        let mut decision = Box::pin(wait_for_update_decision(&mut actions, true, || {
            opened.set(opened.get() + 1);
            std::future::ready(Ok(()))
        }));
        sender.send(StartupAction::Download).unwrap();
        assert!(futures_poll_pending(&mut decision));
        sender.send(StartupAction::Continue).unwrap();
        sender.send(StartupAction::Download).unwrap();
        assert!(futures_poll_pending(&mut decision));
        assert_eq!(opened.get(), 2, "the download can be reopened");
        drop(sender);
        assert!(!decision.await.unwrap());
    }

    fn futures_poll_pending(future: &mut (impl std::future::Future + Unpin)) -> bool {
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        std::pin::Pin::new(future).poll(&mut context).is_pending()
    }

    #[tokio::test]
    async fn closing_the_action_channel_does_not_allow_startup_to_continue() {
        let (sender, mut actions) = mpsc::unbounded_channel();
        sender.send(StartupAction::Continue).unwrap();
        drop(sender);
        assert_eq!(next_update_action(&mut actions, true).await, None);
    }
}
