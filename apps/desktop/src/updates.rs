use slint::ComponentHandle;
use topnode_infrastructure::{
    PaymentPresentation, RemoteDesktopVersion, RemoteStartupConfigurationLoader,
    ResolvedStartupConfiguration,
};

use crate::{AppWindow, build_info, platform};

pub fn install(ui: &AppWindow, startup: &ResolvedStartupConfiguration, prompt: bool) {
    ui.set_app_version(
        format!(
            "{}（{}）",
            build_info::VERSION_NAME,
            build_info::version_code()
        )
        .into(),
    );
    apply_release(ui, startup.desktop_version(), startup.website(), prompt);
    bind_check(ui, startup.payment_presentation());
    bind_browser(ui, BrowserDestination::Website);
    bind_browser(ui, BrowserDestination::Update);

    let weak = ui.as_weak();
    ui.on_dismiss_update(move || {
        if let Some(ui) = weak.upgrade()
            && !ui.get_update_required()
            && !ui.get_update_opening()
        {
            ui.set_update_visible(false);
        }
    });
    ui.on_quit_for_update(|| {
        if let Err(error) = slint::quit_event_loop() {
            tracing::warn!(%error, "failed to exit for a desktop update");
        }
    });
}

fn apply_release(
    ui: &AppWindow,
    release: &RemoteDesktopVersion,
    website: Option<&str>,
    prompt: bool,
) {
    let current = build_info::version_code();
    let available = release.is_newer_than(current);
    let required = release.requires_update(current);
    ui.set_website_url(website.unwrap_or_default().into());
    ui.set_update_available(available);
    ui.set_update_required(required);
    ui.set_update_version(
        format!("{}（{}）", release.version_name(), release.version_code()).into(),
    );
    ui.set_update_notes(release.update_info().into());
    ui.set_update_url(
        release
            .available_download_url(current)
            .unwrap_or_default()
            .into(),
    );
    ui.set_update_error("".into());
    ui.set_update_check_status(if available {
        "发现新版本，可查看更新详情。".into()
    } else {
        "当前已是最新版本。".into()
    });
    ui.set_update_visible(available && (prompt || required));
}

fn bind_check(ui: &AppWindow, payment: PaymentPresentation) {
    let weak = ui.as_weak();
    ui.on_check_for_updates(move || {
        let Some(ui) = weak.upgrade() else { return };
        if ui.get_update_checking() {
            return;
        }
        ui.set_update_checking(true);
        ui.set_update_check_status("正在检查更新…".into());
        let weak = weak.clone();
        tokio::spawn(async move {
            let result = match RemoteStartupConfigurationLoader::production(
                payment,
                build_info::BUILD_TARGET,
                build_info::VERSION_NAME,
            ) {
                Ok(loader) => loader.fetch().await,
                Err(error) => Err(error),
            };
            let _ = weak.upgrade_in_event_loop(move |ui| {
                ui.set_update_checking(false);
                match result {
                    Ok(startup) => {
                        apply_release(&ui, startup.desktop_version(), startup.website(), true);
                    }
                    Err(error) => {
                        tracing::warn!(%error, "manual desktop update check failed");
                        ui.set_update_check_status("检查更新失败，请检查网络后重试。".into());
                    }
                }
            });
        });
    });
}

#[derive(Clone, Copy)]
enum BrowserDestination {
    Website,
    Update,
}

fn bind_browser(ui: &AppWindow, destination: BrowserDestination) {
    let weak = ui.as_weak();
    let callback = move || {
        let Some(ui) = weak.upgrade() else { return };
        let (url, opening) = match destination {
            BrowserDestination::Website => (ui.get_website_url(), ui.get_website_opening()),
            BrowserDestination::Update => (ui.get_update_url(), ui.get_update_opening()),
        };
        if opening || url.is_empty() {
            return;
        }
        match destination {
            BrowserDestination::Website => ui.set_website_opening(true),
            BrowserDestination::Update => {
                ui.set_update_opening(true);
                ui.set_update_error("".into());
            }
        }
        let weak = weak.clone();
        tokio::spawn(async move {
            let result =
                tokio::task::spawn_blocking(move || platform::open_url(url.as_str())).await;
            let success = matches!(result, Ok(Ok(())));
            let _ = weak.upgrade_in_event_loop(move |ui| match destination {
                BrowserDestination::Website => {
                    ui.set_website_opening(false);
                    if !success {
                        let message = "无法打开官网，请检查默认浏览器设置后重试。";
                        if ui.get_update_visible() {
                            ui.set_update_error(message.into());
                        } else {
                            ui.set_notice(message.into());
                        }
                    }
                }
                BrowserDestination::Update => {
                    ui.set_update_opening(false);
                    if success {
                        if !ui.get_update_required() {
                            ui.set_update_visible(false);
                        }
                        ui.set_update_check_status(
                            "已在浏览器打开下载，请安装新版后重新启动。".into(),
                        );
                    } else {
                        ui.set_update_error(
                            "无法打开下载页面，请检查默认浏览器设置后重试。".into(),
                        );
                    }
                }
            });
        });
    };
    match destination {
        BrowserDestination::Website => ui.on_open_website(callback),
        BrowserDestination::Update => ui.on_download_update(callback),
    }
}
