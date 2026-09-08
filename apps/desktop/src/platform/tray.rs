use std::fmt;

use slint::{CloseRequestResponse, ComponentHandle, PlatformError};

use crate::{AppTray, AppWindow};

/// Owns the native tray icon and the window lifecycle bindings.
///
/// Keep this value alive for as long as the Slint event loop is running. Closing
/// the main window only hides it; choosing the tray's explicit exit action ends
/// the event loop, after which the composition root can perform async shutdown.
pub struct TrayLifecycle {
    tray: AppTray,
}

impl TrayLifecycle {
    /// Creates the tray icon and binds its show/exit actions to the main window.
    ///
    /// The connection action intentionally remains a separate callback so the
    /// composition root can dispatch it asynchronously through the controller.
    pub fn install(window: &AppWindow) -> Result<Self, PlatformError> {
        let tray = AppTray::new()?;

        let window_weak = window.as_weak();
        tray.on_show_main_window(move || {
            let Some(window) = window_weak.upgrade() else {
                return;
            };
            super::restore_main_window(&window, "tray");
        });

        tray.on_quit_application(|| {
            if let Err(error) = slint::quit_event_loop() {
                tracing::error!(%error, "failed to request desktop shutdown from tray");
            }
        });

        let window_weak = window.as_weak();
        window.window().on_close_requested(move || {
            if let Some(window) = window_weak.upgrade() {
                super::close_window(&window);
            }
            CloseRequestResponse::HideWindow
        });
        tray.show()?;

        Ok(Self { tray })
    }

    /// Returns the generated tray component for connection-state presentation
    /// and asynchronous action binding in the desktop composition root.
    pub fn tray(&self) -> &AppTray {
        &self.tray
    }
}

impl fmt::Debug for TrayLifecycle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrayLifecycle")
            .finish_non_exhaustive()
    }
}
