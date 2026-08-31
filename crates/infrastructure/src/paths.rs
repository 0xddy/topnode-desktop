use std::{io, path::PathBuf};

use directories::ProjectDirs;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppPaths {
    pub runtime_dir: PathBuf,
    pub startup_configuration: PathBuf,
    pub core_dir: PathBuf,
    pub sidecar_binary: PathBuf,
    pub data_dir: PathBuf,
    pub auth_dir: PathBuf,
    pub session_vault_file: PathBuf,
    pub config_dir: PathBuf,
    pub log_dir: PathBuf,
    pub session_config: PathBuf,
    pub development_config: PathBuf,
    pub settings_file: PathBuf,
    pub system_proxy_journal: PathBuf,
    pub instance_lock: PathBuf,
    pub instance_handoff_lock: PathBuf,
    pub instance_activation: PathBuf,
}

impl AppPaths {
    /// Resolves the executable directory and platform application-data root.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the executable or OS data location is unavailable.
    pub fn discover() -> io::Result<Self> {
        let executable = std::env::current_exe()?;
        let project_dirs = ProjectDirs::from("cc", "TOPNODE", "TOPNODE Desktop")
            .ok_or_else(|| io::Error::other("无法确定应用数据目录"))?;
        Ok(Self::from_roots(
            &executable,
            project_dirs.data_local_dir().to_path_buf(),
        ))
    }

    pub fn from_roots(executable: &std::path::Path, data_dir: PathBuf) -> Self {
        let executable_dir = executable
            .parent()
            .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf);
        let runtime_dir = executable_dir.join("runtime");
        let core_dir = runtime_dir.join("core");
        let sidecar_name = if cfg!(windows) {
            "sing-box.exe"
        } else {
            "sing-box"
        };
        let config_dir = data_dir.join("runtime");
        let auth_dir = data_dir.join("auth");
        Self {
            sidecar_binary: core_dir.join(sidecar_name),
            core_dir,
            startup_configuration: runtime_dir.join("startup.json"),
            runtime_dir,
            log_dir: data_dir.join("logs"),
            session_vault_file: auth_dir.join("session.v1.bin"),
            auth_dir,
            session_config: config_dir.join("session.json"),
            development_config: config_dir.join("development-input.json"),
            settings_file: data_dir.join("settings.toml"),
            system_proxy_journal: data_dir.join("system-proxy-lease.v1.json"),
            instance_lock: data_dir.join("instance.lock"),
            instance_handoff_lock: data_dir.join("instance-handoff.lock"),
            instance_activation: data_dir.join("instance-activation.json"),
            config_dir,
            data_dir,
        }
    }

    /// Creates the writable configuration, log, and authentication directories.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when either directory cannot be created.
    pub async fn ensure_directories(&self) -> io::Result<()> {
        tokio::fs::create_dir_all(&self.config_dir).await?;
        tokio::fs::create_dir_all(&self.log_dir).await?;
        tokio::fs::create_dir_all(&self.auth_dir).await
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::AppPaths;

    #[test]
    fn sidecar_is_always_under_the_application_runtime_core_directory() {
        let executable = PathBuf::from("/opt/topnode/topnode-desktop");
        let paths = AppPaths::from_roots(&executable, PathBuf::from("/var/lib/topnode"));
        let expected_runtime_dir = executable
            .parent()
            .expect("fixture executable has a parent")
            .join("runtime");
        let expected_core_dir = expected_runtime_dir.join("core");
        let expected_sidecar_name = if cfg!(windows) {
            "sing-box.exe"
        } else {
            "sing-box"
        };

        assert_eq!(paths.runtime_dir, expected_runtime_dir);
        assert_eq!(
            paths.startup_configuration,
            expected_runtime_dir.join("startup.json")
        );
        assert_eq!(paths.core_dir, expected_core_dir);
        assert_eq!(
            paths.sidecar_binary,
            expected_core_dir.join(expected_sidecar_name)
        );
        assert_eq!(
            paths.session_config,
            PathBuf::from("/var/lib/topnode/runtime/session.json")
        );
        assert_eq!(
            paths.development_config,
            PathBuf::from("/var/lib/topnode/runtime/development-input.json")
        );
        assert_eq!(
            paths.session_vault_file,
            PathBuf::from("/var/lib/topnode/auth/session.v1.bin")
        );
        assert_eq!(
            paths.instance_activation,
            PathBuf::from("/var/lib/topnode/instance-activation.json")
        );
        assert_eq!(
            paths.instance_handoff_lock,
            PathBuf::from("/var/lib/topnode/instance-handoff.lock")
        );
        assert_eq!(
            paths.system_proxy_journal,
            PathBuf::from("/var/lib/topnode/system-proxy-lease.v1.json")
        );
    }
}
