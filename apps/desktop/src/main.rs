#![allow(missing_debug_implementations)]
#![cfg_attr(windows, windows_subsystem = "windows")]

mod bootstrap;
mod build_info;
mod controller;
mod payment_qr;
mod platform;
mod presentation;

slint::include_modules!();

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if let Some(exit_code) = topnode_infrastructure::run_sidecar_guardian_if_requested().await? {
        std::process::exit(exit_code);
    }
    bootstrap::run().await
}
