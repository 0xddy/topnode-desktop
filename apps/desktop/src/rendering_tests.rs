use std::{cell::Cell, rc::Rc, time::Duration};

use slint::{
    ComponentHandle, ModelRc, Rgb8Pixel, VecModel,
    platform::{
        Platform, PlatformError, WindowAdapter, WindowEvent,
        software_renderer::{MinimalSoftwareWindow, RepaintBufferType},
        update_timers_and_animations,
    },
};

use crate::{AppPhase, AppWindow, NodeItem, ResourceGroupItem, ResourcePhase};

struct RenderPlatform {
    window: Rc<MinimalSoftwareWindow>,
    clock: Rc<Cell<Duration>>,
}

impl Platform for RenderPlatform {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        Ok(self.window.clone())
    }

    fn duration_since_start(&self) -> Duration {
        self.clock.get()
    }
}

fn draw(window: &MinimalSoftwareWindow, pixels: &mut [Rgb8Pixel], stride: usize) {
    window.request_redraw();
    window.draw_if_needed(|renderer| {
        renderer.render(pixels, stride);
    });
}

fn advance(clock: &Cell<Duration>, millis: u64) {
    clock.set(clock.get() + Duration::from_millis(millis));
    update_timers_and_animations();
}

#[test]
fn node_modal_partial_repaints_match_full_frames_after_pointer_movement() {
    let clock = Rc::new(Cell::new(Duration::ZERO));
    let window = MinimalSoftwareWindow::new(RepaintBufferType::ReusedBuffer);
    slint::platform::set_platform(Box::new(RenderPlatform {
        window: window.clone(),
        clock: clock.clone(),
    }))
    .unwrap();
    let ui = AppWindow::new().unwrap();
    ui.set_app_phase(AppPhase::SignedIn);
    ui.set_core_available(true);
    ui.set_node_selection_enabled(true);
    ui.set_resource_phase(ResourcePhase::Ready);
    ui.set_resource_groups(ModelRc::new(VecModel::from(vec![ResourceGroupItem {
        id: "preview".into(),
        name: "Preview plan".into(),
        connectable: true,
        selected: true,
        ..Default::default()
    }])));
    ui.set_visible_nodes(ModelRc::new(VecModel::from(
        (0..9)
            .map(|index| NodeItem {
                id: index.to_string().into(),
                name: format!("Preview node {index}").into(),
                country_code: "US".into(),
                selectable: true,
                ..Default::default()
            })
            .collect::<Vec<_>>(),
    )));
    ui.show().unwrap();
    for (scale, width, height) in [(1., 1024, 720), (1.25, 1280, 900), (1.5, 1536, 1080)] {
        window.dispatch_event(WindowEvent::ScaleFactorChanged {
            scale_factor: scale,
        });
        window.set_size(slint::PhysicalSize::new(width, height));
        let stride = usize::try_from(width).unwrap();
        let mut partial = vec![Rgb8Pixel::default(); stride * usize::try_from(height).unwrap()];
        ui.set_node_selector_visible(false);
        draw(&window, &mut partial, stride);
        ui.set_node_selector_visible(true);
        draw(&window, &mut partial, stride);
        advance(&clock, 250);
        draw(&window, &mut partial, stride);

        // Hover rows across the home orb and then move to the modal header. Small
        // dirty regions must preserve icons and rounded outlines at fractional DPI.
        for (x, y) in [
            (700., 190.),
            (700., 270.),
            (700., 340.),
            (700., 420.),
            (450., 100.),
        ] {
            window.dispatch_event(WindowEvent::PointerMoved {
                position: slint::LogicalPosition::new(x, y),
            });
            draw(&window, &mut partial, stride);
            advance(&clock, 70);
            draw(&window, &mut partial, stride);
            advance(&clock, 180);
            draw(&window, &mut partial, stride);

            let mut full = vec![Rgb8Pixel::default(); partial.len()];
            window.request_redraw();
            window.draw_if_needed(|renderer| {
                renderer.set_repaint_buffer_type(RepaintBufferType::NewBuffer);
                renderer.render(&mut full, stride);
                renderer.set_repaint_buffer_type(RepaintBufferType::ReusedBuffer);
            });
            let changed = partial.iter().zip(&full).filter(|(a, b)| a != b).count();
            assert_eq!(
                changed, 0,
                "partial repaint differs from full frame at ({x}, {y}), scale {scale}"
            );
            partial = full;
        }
    }
}
