use std::{
    cell::{Cell, RefCell},
    collections::HashSet,
    rc::Rc,
    time::{Duration, Instant},
};

use slint::{
    ComponentHandle, Model, ModelRc, Rgb8Pixel, VecModel,
    platform::{
        Platform, PlatformError, WindowAdapter, WindowEvent,
        software_renderer::{MinimalSoftwareWindow, PhysicalRegion, RepaintBufferType},
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

fn signed_in_window() -> (AppWindow, Rc<MinimalSoftwareWindow>, Rc<Cell<Duration>>) {
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
    (ui, window, clock)
}

struct ObservedNodes {
    rows: VecModel<NodeItem>,
    requested: RefCell<HashSet<usize>>,
}

impl Model for ObservedNodes {
    type Data = NodeItem;

    fn row_count(&self) -> usize {
        self.rows.row_count()
    }

    fn row_data(&self, row: usize) -> Option<NodeItem> {
        self.requested.borrow_mut().insert(row);
        self.rows.row_data(row)
    }

    fn model_tracker(&self) -> &dyn slint::ModelTracker {
        self.rows.model_tracker()
    }
}

#[test]
fn node_selector_large_plan_switch_only_materializes_visible_rows() {
    let (ui, window, clock) = signed_in_window();
    window.set_size(slint::PhysicalSize::new(1024, 720));
    let mut pixels = vec![Rgb8Pixel::default(); 1024 * 720];
    ui.set_node_selector_visible(true);
    draw(&window, &mut pixels, 1024);
    advance(&clock, 250);
    draw(&window, &mut pixels, 1024);

    for count in [24, 1_000, 24] {
        let nodes = Rc::new(ObservedNodes {
            rows: VecModel::from(
                (0..count)
                    .map(|index| NodeItem {
                        id: index.to_string().into(),
                        name: format!("Plan {count} node {index}").into(),
                        country_code: "US".into(),
                        selectable: true,
                        measuring: true,
                        ..Default::default()
                    })
                    .collect::<Vec<_>>(),
            ),
            requested: RefCell::default(),
        });
        let start = Instant::now();
        ui.set_visible_nodes(ModelRc::from(nodes.clone()));
        draw(&window, &mut pixels, 1024);
        let switch_elapsed = start.elapsed();
        advance(&clock, 70);
        let start = Instant::now();
        draw(&window, &mut pixels, 1024);
        eprintln!(
            "nodes={count}, materialized={}, switch={switch_elapsed:?}, animation_frame={:?}",
            nodes.requested.borrow().len(),
            start.elapsed()
        );
        let requested = nodes.requested.borrow();
        assert!(
            requested.contains(&0),
            "a new plan must start at its first node"
        );
        assert!(
            requested.len() <= 16,
            "only viewport rows should be instantiated, got {} of {count}",
            requested.len()
        );
    }
}

#[test]
fn node_selector_scroll_and_plan_switch_keep_click_targets_current() {
    let (ui, window, clock) = signed_in_window();
    window.set_size(slint::PhysicalSize::new(1024, 720));
    let mut pixels = vec![Rgb8Pixel::default(); 1024 * 720];
    let selected = Rc::new(RefCell::new(String::new()));
    let selected_callback = selected.clone();
    ui.on_select_node(move |id| *selected_callback.borrow_mut() = id.to_string());

    for prefix in ["large", "small"] {
        let count = if prefix == "large" { 1_000 } else { 3 };
        let nodes = Rc::new(VecModel::from(
            (0..count)
                .map(|index| NodeItem {
                    id: format!("{prefix}-{index}").into(),
                    name: format!("Node {index}").into(),
                    selectable: true,
                    ..Default::default()
                })
                .collect::<Vec<_>>(),
        ));
        ui.set_visible_nodes(ModelRc::from(nodes.clone()));
        ui.set_node_selector_visible(true);
        advance(&clock, 250);
        draw(&window, &mut pixels, 1024);
        if prefix == "large" {
            window.dispatch_event(WindowEvent::PointerScrolled {
                position: slint::LogicalPosition::new(700., 190.),
                delta_x: 0.,
                delta_y: -780.,
            });
            advance(&clock, 250);
            draw(&window, &mut pixels, 1024);
            let mut node = nodes.row_data(10).unwrap();
            node.latency_label = "42ms".into();
            node.latency_available = true;
            nodes.set_row_data(10, node);
            draw(&window, &mut pixels, 1024);
        }
        for pressed in [true, false] {
            let position = slint::LogicalPosition::new(700., 190.);
            let button = slint::platform::PointerEventButton::Left;
            window.dispatch_event(if pressed {
                WindowEvent::PointerPressed { position, button }
            } else {
                WindowEvent::PointerReleased { position, button }
            });
        }
        assert_eq!(
            *selected.borrow(),
            if prefix == "large" {
                "large-10"
            } else {
                "small-0"
            },
            "scrolling must select the visible node; switching plans must reset the scroll offset"
        );
    }
}

#[test]
fn node_modal_partial_repaints_match_full_frames_after_pointer_movement() {
    let (ui, window, clock) = signed_in_window();
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

// Match winit's software backend: the retained bitmap can be intact while the
// native window has lost its displayed pixels. Only the damage bounding box is
// copied back to the window by softbuffer::present_with_damage().
fn present_damage(
    pixels: &[Rgb8Pixel],
    displayed: &mut [Rgb8Pixel],
    stride: usize,
    region: &PhysicalRegion,
) {
    let origin = region.bounding_box_origin();
    let size = region.bounding_box_size();
    let left = usize::try_from(origin.x).unwrap();
    let top = usize::try_from(origin.y).unwrap();
    let width = usize::try_from(size.width).unwrap();
    let height = usize::try_from(size.height).unwrap();
    for row in top..top + height {
        let start = row * stride + left;
        displayed[start..start + width].copy_from_slice(&pixels[start..start + width]);
    }
}

#[test]
fn tray_restores_repaint_the_entire_window_after_native_contents_are_lost() {
    let (ui, window, clock) = signed_in_window();
    for (scale, width, height) in [(1., 1024, 720), (1.25, 1280, 900), (1.5, 1536, 1080)] {
        window.dispatch_event(WindowEvent::ScaleFactorChanged {
            scale_factor: scale,
        });
        let size = slint::PhysicalSize::new(width, height);
        window.set_size(size);
        let stride = usize::try_from(width).unwrap();
        let mut pixels = vec![Rgb8Pixel::default(); stride * usize::try_from(height).unwrap()];

        for modal_visible in [false, true] {
            ui.set_node_selector_visible(modal_visible);
            draw(&window, &mut pixels, stride);
            advance(&clock, 500);
            draw(&window, &mut pixels, stride);
            let mut expected = vec![Rgb8Pixel::default(); pixels.len()];
            window.request_redraw();
            window.draw_if_needed(|renderer| {
                renderer.set_repaint_buffer_type(RepaintBufferType::NewBuffer);
                renderer.render(&mut expected, stride);
                renderer.set_repaint_buffer_type(RepaintBufferType::ReusedBuffer);
            });
            // Rebuild the ordinary partial rendering cache before hiding.
            draw(&window, &mut pixels, stride);

            for cycle in 0..3 {
                ui.hide().unwrap();
                let mut displayed = vec![
                    Rgb8Pixel {
                        r: 255,
                        g: 255,
                        b: 255
                    };
                    pixels.len()
                ];
                crate::platform::restore_main_window(&ui, "rendering-regression-test");
                if cycle == 2 {
                    // A tray double-click can queue another restore before painting.
                    crate::platform::restore_main_window(&ui, "rendering-regression-double-click");
                }
                assert!(window.draw_if_needed(|renderer| {
                    assert_eq!(
                        renderer.repaint_buffer_type(),
                        RepaintBufferType::ReusedBuffer
                    );
                    let region = renderer.render(&mut pixels, stride);
                    present_damage(&pixels, &mut displayed, stride, &region);
                }));
                let changed = displayed
                    .iter()
                    .zip(&expected)
                    .filter(|(a, b)| a != b)
                    .count();
                assert_eq!(
                    changed, 0,
                    "restored frame differs at scale {scale}, modal {modal_visible}, cycle {cycle}"
                );

                // Restoration must invalidate one frame only. A subsequent idle
                // frame should have no damage and retain normal partial repainting.
                window.request_redraw();
                assert!(window.draw_if_needed(|renderer| {
                    let region = renderer.render(&mut pixels, stride);
                    assert_eq!(region.bounding_box_size(), slint::PhysicalSize::default());
                }));
            }
        }
    }
}
