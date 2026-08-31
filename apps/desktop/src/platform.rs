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

pub fn restore_main_window(window: &impl ComponentHandle, source: &'static str) {
    window.window().set_minimized(false);
    if let Err(error) = window.show() {
        tracing::warn!(%error, source, "failed to restore main window");
    }
    window.window().request_redraw();
}

pub fn open_url(url: &str) -> io::Result<()> {
    webbrowser::open(url)
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
