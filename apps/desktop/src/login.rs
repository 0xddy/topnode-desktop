use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, Ordering},
};

use slint::ComponentHandle;
use topnode_infrastructure::{AutoLoginStore, SavedLogin};

use crate::{AppPhase, AppWindow, controller::DesktopController, platform, presentation};

fn store() -> &'static AutoLoginStore {
    static STORE: OnceLock<AutoLoginStore> = OnceLock::new();
    STORE.get_or_init(AutoLoginStore::default)
}

pub async fn load_saved(weak: &slint::Weak<AppWindow>) {
    let saved = tokio::time::timeout(std::time::Duration::from_secs(3), store().read()).await;
    let _ = weak.upgrade_in_event_loop(move |ui| {
        if ui.get_login_edited() {
            return;
        }
        match saved {
            Ok(Ok(Some(saved))) => {
                ui.set_login_email(saved.email().into());
                ui.set_login_password(saved.password().into());
                ui.set_login_auto(true);
            }
            Ok(Ok(None)) => {}
            _ => ui.set_login_storage_message("无法读取自动登录信息，请手动登录。".into()),
        }
    });
}

pub fn enable(ui: &AppWindow) {
    ui.set_login_config_ready(true);
    ui.set_login_config_failed(false);
    ui.set_login_config_status("".into());
    ui.invoke_arm_auto_login();
}

pub fn bind_preference(ui: &AppWindow) {
    let weak = ui.as_weak();
    ui.on_auto_login_changed(move |enabled| {
        if !enabled {
            let weak = weak.clone();
            tokio::spawn(async move {
                forget_saved(&weak).await;
            });
        }
    });
}

pub fn clear_form(ui: &AppWindow) {
    ui.set_login_auto_pending(false);
    ui.set_login_auto(false);
    ui.set_login_password("".into());
}

pub async fn forget_saved(weak: &slint::Weak<AppWindow>) {
    if let Err(error) = store().clear().await {
        let _ = weak.upgrade_in_event_loop(move |ui| {
            ui.set_login_storage_message(error.to_string().into());
        });
    }
}

pub fn install(ui: &AppWindow, controller: Arc<DesktopController>) {
    bind_preference(ui);
    let weak = ui.as_weak();
    ui.on_close_window(move || {
        if let Some(ui) = weak.upgrade() {
            platform::close_window(&ui);
        }
    });
    let weak = ui.as_weak();
    ui.on_drag_window(move || {
        if let Some(ui) = weak.upgrade() {
            platform::drag_window(&ui);
        }
    });

    let weak = ui.as_weak();
    let in_flight = Arc::new(AtomicBool::new(false));
    ui.on_submit_login(move |email, password| {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        if !can_submit(&ui)
            || email.trim().is_empty()
            || password.is_empty()
            || in_flight.swap(true, Ordering::AcqRel)
        {
            return;
        }
        ui.set_login_auto_pending(false);
        ui.set_login_submitting(true);
        ui.set_login_error("".into());
        let remember = ui.get_login_auto();
        let saved = SavedLogin::new(email.trim().to_owned(), password.to_string());
        let controller = Arc::clone(&controller);
        let weak = weak.clone();
        let in_flight = Arc::clone(&in_flight);
        tokio::spawn(async move {
            if !remember {
                forget_saved(&weak).await;
            }
            let result = controller
                .login(saved.email().into(), saved.password().into())
                .await;
            let authenticated = controller.subscribe_account().borrow().is_authenticated();
            if authenticated
                && remember
                && let Err(error) = store().save(saved).await
            {
                presentation::post_notice(&weak, format!("已登录，但{error}。"));
            }
            presentation::refresh_account_view(&weak, &controller).await;
            let _ = weak.upgrade_in_event_loop(move |ui| {
                ui.set_login_submitting(false);
                if authenticated {
                    ui.set_login_password("".into());
                }
            });
            in_flight.store(false, Ordering::Release);
            if let Err(error) = result {
                tracing::warn!(%error, "account login failed");
            }
        });
    });
}

fn can_submit(ui: &AppWindow) -> bool {
    ui.get_app_phase() == AppPhase::SignedOut
        && ui.get_login_config_ready()
        && !ui.get_update_visible()
        && !ui.get_login_submitting()
}

#[cfg(test)]
mod tests;
