use serde::{Deserialize, Serialize};
use topnode_domain::ConnectionPreferences;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default)]
pub struct DesktopSettings {
    pub device_id: String,
    pub selected_group_id: String,
    pub selected_entitlement_id: String,
    pub selected_endpoint_id: String,
    pub preferences: ConnectionPreferences,
}

#[derive(Clone, Debug)]
pub struct SettingsStore {
    path: std::path::PathBuf,
}

impl SettingsStore {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Loads settings or returns defaults when no file exists.
    ///
    /// # Errors
    ///
    /// Returns an I/O error for unreadable or invalid TOML content.
    pub async fn load(&self) -> Result<DesktopSettings, std::io::Error> {
        match tokio::fs::read_to_string(&self.path).await {
            Ok(content) => {
                let mut settings: DesktopSettings =
                    toml::from_str(&content).map_err(std::io::Error::other)?;
                settings.preferences = settings.preferences.normalized();
                Ok(settings)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(DesktopSettings::default())
            }
            Err(error) => Err(error),
        }
    }

    /// Persists a settings snapshot with an atomic, private file replacement.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when serialization or replacement fails.
    pub async fn save(&self, settings: &DesktopSettings) -> Result<(), std::io::Error> {
        let content = toml::to_string_pretty(settings).map_err(std::io::Error::other)?;
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        atomic_write_private(&self.path, content.into_bytes()).await
    }
}

impl DesktopSettings {
    /// Ensures this installation has a stable non-secret device identifier.
    pub fn ensure_device_id(&mut self) -> bool {
        if uuid::Uuid::parse_str(self.device_id.trim()).is_err() {
            self.device_id = uuid::Uuid::new_v4().to_string();
            true
        } else {
            false
        }
    }
}

async fn atomic_write_private(
    path: &std::path::Path,
    content: Vec<u8>,
) -> Result<(), std::io::Error> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        use std::io::Write;

        #[cfg(not(unix))]
        let options = atomic_write_file::OpenOptions::new();
        #[cfg(unix)]
        let mut options = atomic_write_file::OpenOptions::new();
        #[cfg(unix)]
        {
            atomic_write_file::unix::OpenOptionsExt::preserve_mode(&mut options, false);
            atomic_write_file::unix::OpenOptionsExt::try_preserve_owner(&mut options, false);
            use std::os::unix::fs::OpenOptionsExt;

            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(&content)?;
        file.commit()
    })
    .await
    .map_err(std::io::Error::other)?
}

#[cfg(test)]
mod tests {
    use topnode_domain::ConnectionPreferences;

    use super::{DesktopSettings, SettingsStore};

    #[test]
    fn installation_id_is_stable_and_repairs_invalid_values() {
        let mut settings = DesktopSettings {
            device_id: "not-a-uuid".to_owned(),
            ..DesktopSettings::default()
        };

        assert!(settings.ensure_device_id());
        let generated = settings.device_id.clone();
        assert!(uuid::Uuid::parse_str(&generated).is_ok());
        assert!(!settings.ensure_device_id());
        assert_eq!(settings.device_id, generated);
    }

    #[tokio::test]
    async fn save_atomically_replaces_existing_settings_and_round_trips() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let path = directory.path().join("nested").join("settings.toml");
        let store = SettingsStore::new(&path);
        let first = DesktopSettings {
            device_id: uuid::Uuid::new_v4().to_string(),
            selected_group_id: "group-old".to_owned(),
            selected_entitlement_id: "grant-old".to_owned(),
            selected_endpoint_id: "node-old".to_owned(),
            preferences: ConnectionPreferences::default(),
        };
        store.save(&first).await.expect("first save should succeed");

        let mut second = first;
        second.selected_group_id = "group-new".to_owned();
        second.selected_entitlement_id = "grant-new".to_owned();
        second.selected_endpoint_id = "node-new".to_owned();
        second.preferences.tun_enabled = true;
        store
            .save(&second)
            .await
            .expect("replacement save should succeed");

        assert_eq!(
            store.load().await.expect("saved settings should load"),
            second
        );
        assert!(path.is_file());
        assert!(!path.with_extension("toml.tmp").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn saved_settings_are_owner_only_after_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let path = directory.path().join("settings.toml");
        tokio::fs::write(&path, "legacy = true\n")
            .await
            .expect("legacy settings fixture should be written");
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .await
            .expect("legacy permissions should be set");

        SettingsStore::new(&path)
            .save(&DesktopSettings::default())
            .await
            .expect("settings replacement should succeed");

        let mode = tokio::fs::metadata(&path)
            .await
            .expect("settings metadata should be readable")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
