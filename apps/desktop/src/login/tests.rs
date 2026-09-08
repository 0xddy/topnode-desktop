use std::{cell::Cell, rc::Rc, time::Duration};

use slint::platform::{
    Platform, PlatformError, WindowAdapter,
    software_renderer::{MinimalSoftwareWindow, RepaintBufferType},
    update_timers_and_animations,
};

use crate::{AppPhase, AppWindow};

struct TestPlatform(Rc<Cell<Duration>>);

impl Platform for TestPlatform {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        Ok(MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer))
    }

    fn duration_since_start(&self) -> Duration {
        self.0.get()
    }
}

fn advance(clock: &Cell<Duration>, millis: u64) {
    update_timers_and_animations();
    clock.set(clock.get() + Duration::from_millis(millis));
    update_timers_and_animations();
}

#[test]
fn auto_login_waits_two_seconds_and_respects_configuration_updates_and_edits() {
    let clock = Rc::new(Cell::new(Duration::ZERO));
    slint::platform::set_platform(Box::new(TestPlatform(clock.clone()))).unwrap();
    let ui = AppWindow::new().unwrap();
    let attempts = Rc::new(Cell::new(0));
    let count = attempts.clone();
    ui.on_submit_login(move |_, _| count.set(count.get() + 1));
    ui.set_login_email("preview@example.test".into());
    ui.set_login_password("preview-only".into());
    ui.set_login_auto(true);

    ui.invoke_arm_auto_login();
    ui.invoke_trigger_login();
    advance(&clock, 10_000);
    assert_eq!(attempts.get(), 0, "configuration must complete first");

    ui.set_login_config_ready(true);
    ui.invoke_arm_auto_login();
    advance(&clock, 1_999);
    assert_eq!(attempts.get(), 0, "wait the full two seconds");
    advance(&clock, 1);
    assert_eq!(attempts.get(), 1);
    advance(&clock, 10_000);
    assert_eq!(attempts.get(), 1, "automatic login is attempted only once");

    ui.invoke_arm_auto_login();
    advance(&clock, 500);
    ui.set_login_auto(false);
    advance(&clock, 2_000);
    assert_eq!(attempts.get(), 1, "unchecking cancels the timer");

    ui.set_login_auto(true);
    ui.invoke_arm_auto_login();
    advance(&clock, 500);
    ui.invoke_cancel_auto_login();
    advance(&clock, 2_000);
    assert_eq!(attempts.get(), 1, "editing cancels the timer");

    ui.set_login_edited(false);
    ui.invoke_arm_auto_login();
    advance(&clock, 500);
    ui.set_update_visible(true);
    advance(&clock, 2_000);
    ui.invoke_trigger_login();
    assert_eq!(attempts.get(), 1, "updates block both login paths");
    ui.set_update_visible(false);
    advance(&clock, 0);
    ui.invoke_arm_auto_login();
    advance(&clock, 2_000);
    assert_eq!(
        attempts.get(),
        1,
        "deferring an update must not rearm login"
    );
    ui.invoke_trigger_login();
    assert_eq!(attempts.get(), 2, "manual login works after deferring");
    ui.set_app_phase(AppPhase::SignedIn);
    ui.invoke_trigger_login();
    assert_eq!(attempts.get(), 2, "authenticated windows cannot resubmit");
}
