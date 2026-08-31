use std::{fmt, path::PathBuf};

use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::watch;

use crate::{ConnectionPreferences, ConnectionState, RuntimeTelemetrySnapshot, StopReason};

/// Cloneable, edge-safe cancellation signal for one connection generation.
///
/// The application owns cancellation policy, while engine adapters await the
/// same signal around child-process work that must be interrupted promptly.
#[derive(Clone)]
pub struct ConnectionCancellation {
    cancelled: watch::Sender<bool>,
}

impl ConnectionCancellation {
    pub fn new() -> Self {
        let (cancelled, _) = watch::channel(false);
        Self { cancelled }
    }

    pub fn cancel(&self) {
        self.cancelled.send_replace(true);
    }

    pub fn is_cancelled(&self) -> bool {
        *self.cancelled.borrow()
    }

    pub async fn cancelled(&self) {
        let mut cancelled = self.cancelled.subscribe();
        if *cancelled.borrow_and_update() {
            return;
        }
        while cancelled.changed().await.is_ok() {
            if *cancelled.borrow_and_update() {
                return;
            }
        }
    }
}

impl Default for ConnectionCancellation {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ConnectionCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionCancellation")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RuntimeId(String);

impl RuntimeId {
    /// Creates a validated runtime identifier.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::UnsupportedRuntime`] when the identifier is empty,
    /// longer than 32 bytes, or contains unsupported characters.
    pub fn new(value: impl Into<String>) -> Result<Self, EngineError> {
        let value = value.into();
        let mut bytes = value.bytes();
        let valid_first = bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
        let valid_tail = bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        });
        if value.len() > 32 || !valid_first || !valid_tail {
            return Err(EngineError::UnsupportedRuntime(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineCapabilities {
    pub latency_test: bool,
    pub hot_network_update: bool,
    pub selector_switch: bool,
    pub ipv6: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeDescriptor {
    pub runtime_id: RuntimeId,
    pub version: String,
    pub supported_schemas: Vec<u32>,
    pub capabilities: EngineCapabilities,
}

/// Opaque server-provided runtime data. Its `Debug` output intentionally omits the payload.
#[derive(Clone)]
pub struct RuntimeConfiguration {
    runtime_id: RuntimeId,
    schema_version: u32,
    revision: String,
    expires_at_epoch_seconds: Option<u64>,
    payload: String,
    preferences: ConnectionPreferences,
}

/// Configuration response metadata retained until the application validates
/// expiry and the endpoint selected by the server.
pub struct ClientConfiguration {
    pub runtime_id: RuntimeId,
    pub schema_version: u32,
    pub revision: String,
    pub expires_at_epoch_seconds: u64,
    pub selected_endpoint_id: String,
    payload: String,
}

impl ClientConfiguration {
    /// Creates a client-configuration response while keeping its JSON opaque.
    ///
    /// # Errors
    ///
    /// Returns an error when the schema, selected endpoint, or payload is empty.
    pub fn new(
        runtime_id: RuntimeId,
        schema_version: u32,
        revision: impl Into<String>,
        expires_at_epoch_seconds: u64,
        selected_endpoint_id: impl Into<String>,
        payload: impl Into<String>,
    ) -> Result<Self, EngineError> {
        let selected_endpoint_id = selected_endpoint_id.into();
        let payload = payload.into();
        if schema_version == 0 {
            return Err(EngineError::UnsupportedSchema(schema_version));
        }
        if selected_endpoint_id.trim().is_empty() {
            return Err(EngineError::InvalidConfiguration(
                "服务端未返回所选节点".to_owned(),
            ));
        }
        if payload.trim().is_empty() {
            return Err(EngineError::InvalidConfiguration(
                "运行时配置不能为空".to_owned(),
            ));
        }
        Ok(Self {
            runtime_id,
            schema_version,
            revision: revision.into(),
            expires_at_epoch_seconds,
            selected_endpoint_id,
            payload,
        })
    }

    /// Validates response metadata and converts it to an engine-only envelope.
    ///
    /// # Errors
    ///
    /// Returns an error when the response expired or selected a different endpoint.
    pub fn into_runtime(
        self,
        expected_endpoint_id: &str,
        now_epoch_seconds: u64,
        preferences: ConnectionPreferences,
    ) -> Result<RuntimeConfiguration, EngineError> {
        if self.expires_at_epoch_seconds <= now_epoch_seconds {
            return Err(EngineError::InvalidConfiguration(
                "服务端配置已经过期".to_owned(),
            ));
        }
        if self.selected_endpoint_id != expected_endpoint_id {
            return Err(EngineError::InvalidConfiguration(format!(
                "服务端选择了非请求节点：{}",
                self.selected_endpoint_id
            )));
        }
        let mut configuration = RuntimeConfiguration::new(
            self.runtime_id,
            self.schema_version,
            self.revision,
            self.payload,
            preferences,
        )?;
        configuration.expires_at_epoch_seconds = Some(self.expires_at_epoch_seconds);
        Ok(configuration)
    }
}

impl fmt::Debug for ClientConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientConfiguration")
            .field("runtime_id", &self.runtime_id)
            .field("schema_version", &self.schema_version)
            .field("revision", &self.revision)
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .field("selected_endpoint_id", &self.selected_endpoint_id)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

impl RuntimeConfiguration {
    /// Creates an opaque runtime configuration envelope.
    ///
    /// # Errors
    ///
    /// Returns an error for schema version zero or an empty payload.
    pub fn new(
        runtime_id: RuntimeId,
        schema_version: u32,
        revision: impl Into<String>,
        payload: impl Into<String>,
        preferences: ConnectionPreferences,
    ) -> Result<Self, EngineError> {
        let payload = payload.into();
        if schema_version == 0 {
            return Err(EngineError::UnsupportedSchema(schema_version));
        }
        if payload.trim().is_empty() {
            return Err(EngineError::InvalidConfiguration(
                "运行时配置不能为空".to_owned(),
            ));
        }
        Ok(Self {
            runtime_id,
            schema_version,
            revision: revision.into(),
            expires_at_epoch_seconds: None,
            payload,
            preferences,
        })
    }

    pub fn runtime_id(&self) -> &RuntimeId {
        &self.runtime_id
    }

    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }

    pub const fn expires_at_epoch_seconds(&self) -> Option<u64> {
        self.expires_at_epoch_seconds
    }

    pub fn payload(&self) -> &str {
        &self.payload
    }

    pub const fn preferences(&self) -> &ConnectionPreferences {
        &self.preferences
    }
}

impl fmt::Debug for RuntimeConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeConfiguration")
            .field("runtime_id", &self.runtime_id)
            .field("schema_version", &self.schema_version)
            .field("revision", &self.revision)
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .field("payload", &"[REDACTED]")
            .field("preferences", &self.preferences)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigurationValidation {
    Valid,
    Invalid { reason: String },
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EngineError {
    #[error("未找到 sing-box 内核：{0}")]
    MissingBinary(PathBuf),
    #[error("运行时配置无效：{0}")]
    InvalidConfiguration(String),
    #[error("不支持的运行时：{0}")]
    UnsupportedRuntime(String),
    #[error("不支持的配置版本：{0}")]
    UnsupportedSchema(u32),
    #[error("运行时已启动")]
    AlreadyRunning,
    #[error("运行时未启动")]
    NotRunning,
    #[error("运行时 I/O 错误：{0}")]
    Io(String),
    #[error("运行时进程错误：{0}")]
    Process(String),
    #[error("系统代理错误：{0}")]
    SystemProxy(String),
    #[error("运行时操作超时：{0}")]
    Timeout(String),
    #[error("TUN 模式需要管理员权限")]
    InsufficientPrivileges,
    #[error("运行时操作已取消")]
    Cancelled,
}

#[async_trait]
pub trait ConnectionEngine: Send + Sync {
    fn descriptor(&self) -> RuntimeDescriptor;

    fn subscribe(&self) -> watch::Receiver<ConnectionState>;

    fn subscribe_telemetry(&self) -> watch::Receiver<RuntimeTelemetrySnapshot>;

    async fn validate(
        &self,
        configuration: &RuntimeConfiguration,
        cancellation: &ConnectionCancellation,
    ) -> Result<ConfigurationValidation, EngineError>;

    async fn start(
        &self,
        configuration: RuntimeConfiguration,
        cancellation: &ConnectionCancellation,
    ) -> Result<(), EngineError>;

    async fn stop(&self, reason: StopReason) -> Result<(), EngineError>;
}

#[cfg(test)]
mod tests {
    use crate::ConnectionPreferences;

    use super::{ClientConfiguration, RuntimeConfiguration, RuntimeId};

    #[test]
    fn runtime_configuration_debug_redacts_payload() {
        let config = RuntimeConfiguration::new(
            RuntimeId::new("rt1").expect("valid runtime"),
            1,
            "test",
            r#"{"password":"secret"}"#,
            ConnectionPreferences::default(),
        )
        .expect("valid configuration");

        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn runtime_id_is_restricted() {
        assert!(RuntimeId::new("rt1").is_ok());
        assert!(RuntimeId::new("RT 1").is_err());
        assert!(RuntimeId::new("").is_err());
    }

    #[test]
    fn client_configuration_rejects_expiry_and_endpoint_mismatch() {
        let runtime_id = RuntimeId::new("rt1").expect("valid runtime");
        let expired =
            ClientConfiguration::new(runtime_id.clone(), 1, "expired", 99, "node:1", "{}")
                .expect("valid envelope");
        assert!(
            expired
                .into_runtime("node:1", 100, ConnectionPreferences::default())
                .is_err()
        );

        let mismatched = ClientConfiguration::new(runtime_id, 1, "fresh", 200, "node:2", "{}")
            .expect("valid envelope");
        assert!(
            mismatched
                .into_runtime("node:1", 100, ConnectionPreferences::default())
                .is_err()
        );
    }
}
