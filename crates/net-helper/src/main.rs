#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[cfg(target_os = "linux")]
mod linux;
mod policy;

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    if linux::run().await.is_err() {
        // Never include untrusted configuration or native error chains here.
        eprintln!(
            "TUN helper failed: service, authorization, installed core or configuration check failed"
        );
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This network helper requires Linux/systemd/polkit");
    std::process::exit(1);
}
