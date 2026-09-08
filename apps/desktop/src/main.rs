#![allow(missing_debug_implementations)]
#![cfg_attr(windows, windows_subsystem = "windows")]

mod bootstrap;
mod build_info;
mod controller;
mod login;
mod payment_qr;
mod platform;
mod presentation;
#[cfg(test)]
mod rendering_tests;
mod startup;
mod updates;

slint::include_modules!();

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if let Some(exit_code) = topnode_infrastructure::run_sidecar_guardian_if_requested().await? {
        std::process::exit(exit_code);
    }
    bootstrap::run().await
}
