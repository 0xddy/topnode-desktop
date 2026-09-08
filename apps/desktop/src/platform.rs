use std::io;

use copypasta::{ClipboardContext, ClipboardProvider};
use slint::ComponentHandle;

mod elevation;
mod tray;

// The UI/controller wiring will consume this platform API when TUN preference
// controls are connected. Keeping the export here avoids exposing Win32 details.
#[allow(unused_imports)]
pub use elevation::{
    TunElevationError, TunElevationOutcome, request_tun_elevation_restart, tun_permission_available,
};
pub(crate) use elevation::{
    TunElevationStartupMode, apply_tun_startup_policy, tun_elevation_startup_mode,
};
pub use tray::TrayLifecycle;

pub fn initialize_window_backend() -> Result<(), slint::PlatformError> {
    let mut backend = slint::BackendSelector::new();
    if cfg!(windows) && std::env::var_os("SLINT_BACKEND").is_none() {
        // Keep the desktop usable with remote sessions and screen capture, where
        // the OpenGL compositor may expose an empty or transparent surface.
        backend = backend
            .backend_name("winit".into())
            .renderer_name("software".into());
        tracing::info!("using the Windows software renderer");
    }
    backend.select()
}

pub fn restore_main_window(window: &(impl ComponentHandle + 'static), source: &'static str) {
    window.window().set_minimized(false);
    if let Err(error) = window.show() {
        tracing::warn!(%error, source, "failed to restore main window");
        return;
    }
    finish_window_frame(window);
    request_full_redraw(window.window());
}

/// Invalidate the native surface after restoring it from the tray.
fn request_full_redraw(window: &slint::Window) {
    // Slint 1.17.1 only invalidates the software renderer on Occluded, which
    // Windows doesn't reliably emit for hide/show. Its retained bitmap can be
    // intact while the native surface is cleared, so request_redraw() alone
    // presents only changed regions and leaves the rest of the window blank.
    // Keep this internal API workaround local to the platform boundary and
    // recheck it when upgrading the exact Slint version pinned in Cargo.toml.
    use slint::private_unstable_api::re_exports::{LogicalRect, WindowInner};

    let size = window.size().to_logical(window.scale_factor());
    let region = LogicalRect::from_size([size.width, size.height].into());
    WindowInner::from_pub(window)
        .window_adapter()
        .renderer()
        .mark_dirty_region(region.into());
    window.request_redraw();
}

/// Restore the native outer edge after removing the title bar, including after
/// a hidden window is recreated by the backend. Keep content fully opaque.
#[cfg(windows)]
pub fn finish_window_frame(window: &(impl ComponentHandle + 'static)) {
    use slint::winit_030::{
        WinitWindowAccessor,
        winit::platform::windows::{Color, CornerPreference, WindowExtWindows},
    };

    let weak = window.as_weak();
    if let Err(error) = slint::spawn_local(async move {
        let Some(window) = weak.upgrade() else { return };
        // show() can return before winit creates the native window. Await that
        // event so the very first launch gets the same frame as later restores.
        let Ok(native) = window.window().winit_window().await else {
            return;
        };
        let frameless = !native.is_decorated();
        native.set_undecorated_shadow(frameless);
        native.set_corner_preference(CornerPreference::Round);
        native.set_border_color(Some(if frameless {
            Color::from_rgb(0xd0, 0xde, 0xd7)
        } else {
            Color::SYSTEM_DEFAULT
        }));
    }) {
        tracing::warn!(%error, "failed to schedule native window frame styling");
    }
}

#[cfg(not(windows))]
pub fn finish_window_frame(_window: &(impl ComponentHandle + 'static)) {}

pub fn open_url(url: &str) -> io::Result<()> {
    webbrowser::open(url)
}

pub fn drag_window(window: &impl ComponentHandle) {
    use slint::winit_030::WinitWindowAccessor;

    window.window().with_winit_window(|native| {
        if let Err(error) = native.drag_window() {
            tracing::warn!(%error, "failed to drag the desktop window");
        }
    });
}

/// Match the custom close control and the OS close gesture. An authenticated
/// session keeps running in the tray; closing the login page exits the app.
pub fn close_window(window: &crate::AppWindow) {
    if window.get_app_phase() == crate::AppPhase::SignedIn {
        if let Err(error) = window.hide() {
            tracing::warn!(%error, "failed to hide the main window");
        }
    } else if let Err(error) = slint::quit_event_loop() {
        tracing::warn!(%error, "failed to close the login window");
    }
}

pub fn copy_text(value: &str) -> io::Result<()> {
    let mut clipboard = ClipboardContext::new().map_err(io::Error::other)?;
    clipboard
        .set_contents(value.to_owned())
        .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::open_url;

    #[test]
    fn browser_opener_rejects_non_web_targets() {
        let error = open_url("file:///C:/sensitive.txt").expect_err("file URL must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
