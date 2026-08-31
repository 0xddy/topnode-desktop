use serde::Deserialize;

/// Controls how a third-party payment session is presented by the desktop app.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentPresentation {
    /// Render the server-provided payment URL as a QR code inside the app.
    #[default]
    QrCode,
    /// Open the payment URL with the operating system's default browser.
    Browser,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
struct PaymentConfiguration {
    presentation: PaymentPresentation,
}

/// Read-only deployment configuration loaded before the desktop UI is created.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct StartupConfiguration {
    payment: PaymentConfiguration,
}

impl StartupConfiguration {
    pub fn payment_presentation(self) -> PaymentPresentation {
        self.payment.presentation
    }
}

#[derive(Clone, Debug)]
pub struct StartupConfigurationStore {
    path: std::path::PathBuf,
}

impl StartupConfigurationStore {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Loads the packaged JSON configuration, using safe defaults when it is absent.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the file is unreadable or contains invalid JSON.
    pub async fn load(&self) -> Result<StartupConfiguration, std::io::Error> {
        match tokio::fs::read_to_string(&self.path).await {
            Ok(content) => serde_json::from_str(&content)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(StartupConfiguration::default())
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PaymentPresentation, StartupConfiguration, StartupConfigurationStore};

    #[test]
    fn missing_payment_configuration_defaults_to_qr_code() {
        let configuration: StartupConfiguration =
            serde_json::from_str("{}").expect("empty startup configuration should decode");

        assert_eq!(
            configuration.payment_presentation(),
            PaymentPresentation::QrCode
        );
    }

    #[test]
    fn browser_presentation_decodes_from_nested_payment_configuration() {
        let configuration: StartupConfiguration =
            serde_json::from_str(r#"{"payment":{"presentation":"browser"},"futureField":true}"#)
                .expect("browser startup configuration should decode");

        assert_eq!(
            configuration.payment_presentation(),
            PaymentPresentation::Browser
        );
    }

    #[tokio::test]
    async fn missing_startup_file_uses_defaults() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let configuration = StartupConfigurationStore::new(directory.path().join("missing.json"))
            .load()
            .await
            .expect("missing startup configuration should use defaults");

        assert_eq!(
            configuration.payment_presentation(),
            PaymentPresentation::QrCode
        );
    }

    #[tokio::test]
    async fn malformed_startup_file_is_rejected() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let path = directory.path().join("startup.json");
        tokio::fs::write(&path, "not json")
            .await
            .expect("fixture should be written");

        let error = StartupConfigurationStore::new(path)
            .load()
            .await
            .expect_err("malformed startup configuration must fail closed");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
