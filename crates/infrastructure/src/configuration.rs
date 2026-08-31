use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use topnode_application::{ConfigurationRequest, ConfigurationSource, ConfigurationSourceError};
use topnode_domain::ClientConfiguration;

const DEVELOPMENT_SCHEMA: u32 = 1;

#[derive(Clone, Debug)]
pub struct DevelopmentConfigurationSource {
    path: std::path::PathBuf,
}

impl DevelopmentConfigurationSource {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[async_trait]
impl ConfigurationSource for DevelopmentConfigurationSource {
    async fn load(
        &self,
        request: &ConfigurationRequest,
    ) -> Result<ClientConfiguration, ConfigurationSourceError> {
        let payload = match tokio::fs::read_to_string(&self.path).await {
            Ok(payload) => payload,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ConfigurationSourceError::Unavailable(format!(
                    "请先将服务端下发的配置写入 {}",
                    self.path.display()
                )));
            }
            Err(error) => return Err(ConfigurationSourceError::Read(error.to_string())),
        };

        serde_json::from_str::<serde_json::Value>(&payload)
            .map_err(|error| ConfigurationSourceError::Invalid(error.to_string()))?;

        if !request
            .supported_schema_versions
            .contains(&DEVELOPMENT_SCHEMA)
        {
            return Err(ConfigurationSourceError::Invalid(
                "开发配置只支持 schema 1".to_owned(),
            ));
        }
        let revision = tokio::fs::metadata(&self.path)
            .await
            .ok()
            .and_then(|metadata| metadata.modified().ok())
            .unwrap_or_else(SystemTime::now)
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        ClientConfiguration::new(
            request.runtime_id.clone(),
            DEVELOPMENT_SCHEMA,
            format!("local-{revision}"),
            u64::MAX,
            request.selected_endpoint_id.clone(),
            payload,
        )
        .map_err(|error| ConfigurationSourceError::Invalid(error.to_string()))
    }
}
