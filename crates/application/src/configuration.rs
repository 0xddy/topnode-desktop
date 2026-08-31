use async_trait::async_trait;
use thiserror::Error;
use topnode_domain::{ClientConfiguration, ConnectionPreferences, RuntimeId};

#[derive(Clone, Debug)]
pub struct ConfigurationRequest {
    pub group_id: String,
    pub selected_endpoint_id: String,
    pub preferences: ConnectionPreferences,
    pub runtime_id: RuntimeId,
    pub supported_schema_versions: Vec<u32>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ConfigurationSourceError {
    #[error("尚未准备运行时配置：{0}")]
    Unavailable(String),
    #[error("登录状态已失效，请重新登录")]
    Unauthorized,
    #[error("服务端拒绝了连接请求：{0}")]
    Rejected(String),
    #[error("配置读取失败：{0}")]
    Read(String),
    #[error("服务端配置无效：{0}")]
    Invalid(String),
}

#[async_trait]
pub trait ConfigurationSource: Send + Sync {
    async fn load(
        &self,
        request: &ConfigurationRequest,
    ) -> Result<ClientConfiguration, ConfigurationSourceError>;
}
