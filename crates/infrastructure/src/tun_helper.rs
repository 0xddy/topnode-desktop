/// Checks installation only; authorization is performed for each connection by
/// the privileged service. The GUI never inherits its privileges.
pub fn tun_helper_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf))
            .is_some_and(|directory| {
                directory == std::path::Path::new("/usr/lib/topnode")
                    && directory.join("topnode-net-helper").is_file()
                    && std::path::Path::new("/run/topnode/network.sock").exists()
                    && std::path::Path::new("/dev/net/tun").exists()
            })
    }
    #[cfg(target_os = "macos")]
    {
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf))
            .is_some_and(|directory| {
                directory
                    == std::path::Path::new("/Applications/TOPNODE Desktop.app/Contents/MacOS")
                    && std::process::Command::new(directory.join("topnode-network-bridge"))
                        .arg("status")
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .is_ok_and(|status| status.success())
            })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}
