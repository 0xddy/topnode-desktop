//! Authenticated loopback activation for a process that already owns the
//! single-instance lock.
//!
//! The composition root must acquire [`crate::InstanceGuard`] first. The lock
//! owner then calls [`InstanceActivation::bind`], while a process receiving
//! [`crate::InstanceLockError::AlreadyRunning`] calls
//! [`InstanceActivation::notify`]. This ordering prevents stale activation
//! metadata from deciding process ownership.

use std::{
    fmt,
    fs::File,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddrV4},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};
use uuid::Uuid;

const ACTIVATION_PROTOCOL_VERSION: u8 = 1;
const TOKEN_BYTES: usize = 32;
const ACK: u8 = 1;
const MAX_METADATA_BYTES: usize = 1_024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(5);
const NOTIFY_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(250);
const NOTIFY_RETRY_DELAY: Duration = Duration::from_millis(50);

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationRecord {
    version: u8,
    port: u16,
    token: String,
}

impl ActivationRecord {
    fn validate(&self) -> Result<(), InstanceActivationError> {
        if self.version != ACTIVATION_PROTOCOL_VERSION {
            return Err(InstanceActivationError::InvalidMetadata(
                "激活协议版本不受支持",
            ));
        }
        if self.port == 0 {
            return Err(InstanceActivationError::InvalidMetadata("激活端口不能为零"));
        }
        if self.token.len() != TOKEN_BYTES
            || !self.token.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(InstanceActivationError::InvalidMetadata("激活令牌格式无效"));
        }
        Ok(())
    }
}

/// Error raised while publishing or delivering a local instance activation.
#[derive(Debug, Error)]
pub enum InstanceActivationError {
    #[error("无法绑定本机实例激活端口: {0}")]
    Bind(#[source] io::Error),
    #[error("无法读取实例激活元数据 {path}: {source}")]
    ReadMetadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("无法写入实例激活元数据 {path}: {source}")]
    WriteMetadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("实例激活元数据无效: {0}")]
    InvalidMetadata(&'static str),
    #[error("实例激活元数据不是有效 JSON: {0}")]
    DecodeMetadata(#[source] serde_json::Error),
    #[error("无法接受本机实例激活连接: {0}")]
    Accept(#[source] io::Error),
    #[error("无法连接正在运行的实例: {0}")]
    Connect(#[source] io::Error),
    #[error("等待正在运行的实例响应超时")]
    Timeout,
    #[error("正在运行的实例拒绝了激活请求")]
    Rejected,
}

impl InstanceActivationError {
    fn is_startup_race(&self) -> bool {
        match self {
            Self::ReadMetadata { source, .. } => source.kind() == io::ErrorKind::NotFound,
            Self::Connect(source) => matches!(
                source.kind(),
                io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::NotConnected
            ),
            _ => false,
        }
    }
}

/// Authenticated loopback channel used to bring the primary window forward.
///
/// The primary instance owns this value and waits for notifications. A later
/// process calls [`Self::notify`] after its process lock reports that the
/// primary is already running.
pub struct InstanceActivation {
    listener: TcpListener,
    metadata_path: PathBuf,
    token: String,
    previous_record: Option<ActivationRecord>,
}

impl fmt::Debug for InstanceActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstanceActivation")
            .field("metadata_path", &self.metadata_path)
            .finish_non_exhaustive()
    }
}

impl InstanceActivation {
    /// Binds a random IPv4 loopback port without publishing its discovery
    /// record. This is used by replacement processes that must preflight the
    /// listener without overwriting the still-active primary instance.
    ///
    /// Call [`Self::publish`] only inside a commit protocol. If that protocol
    /// aborts after publication, call [`Self::rollback_publication`].
    ///
    /// # Errors
    ///
    /// Returns an error when the listener cannot bind.
    pub async fn prepare(metadata_path: &Path) -> Result<Self, InstanceActivationError> {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(InstanceActivationError::Bind)?;
        let token = Uuid::new_v4().simple().to_string();
        let previous_record = read_record_if_valid(metadata_path);
        Ok(Self {
            listener,
            metadata_path: metadata_path.to_path_buf(),
            token,
            previous_record,
        })
    }

    /// Binds a random IPv4 loopback port and atomically publishes its
    /// authenticated activation record.
    ///
    /// # Errors
    ///
    /// Returns an error when the listener cannot bind or the metadata cannot
    /// be published.
    pub async fn bind(metadata_path: &Path) -> Result<Self, InstanceActivationError> {
        let activation = Self::prepare(metadata_path).await?;
        activation.publish()?;
        Ok(activation)
    }

    /// Atomically publishes this prepared listener's authenticated discovery
    /// record.
    ///
    /// # Errors
    ///
    /// Returns an error when the listener address cannot be read or the record
    /// cannot be published.
    pub fn publish(&self) -> Result<(), InstanceActivationError> {
        let port = self
            .listener
            .local_addr()
            .map_err(InstanceActivationError::Bind)?
            .port();
        let record = ActivationRecord {
            version: ACTIVATION_PROTOCOL_VERSION,
            port,
            token: self.token.clone(),
        };
        publish_record(&self.metadata_path, &record)
    }

    /// Restores the discovery record that existed when this listener was
    /// prepared, but only while the current record still belongs to this
    /// listener. This makes a replacement handoff abort non-destructive.
    ///
    /// # Errors
    ///
    /// Returns an error when the previous record cannot be restored or this
    /// listener's record cannot be removed.
    pub fn rollback_publication(&self) -> Result<(), InstanceActivationError> {
        if !record_belongs_to(&self.metadata_path, &self.token) {
            return Ok(());
        }
        if let Some(previous_record) = &self.previous_record {
            return publish_record(&self.metadata_path, previous_record);
        }
        match std::fs::remove_file(&self.metadata_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(InstanceActivationError::WriteMetadata {
                path: self.metadata_path.clone(),
                source,
            }),
        }
    }

    /// Waits until a client proves knowledge of the random activation token.
    /// Invalid, non-loopback, and stalled connections are ignored.
    ///
    /// # Errors
    ///
    /// Returns an error when the listening socket can no longer accept.
    pub async fn wait_for_notification(&self) -> Result<(), InstanceActivationError> {
        loop {
            let (mut stream, peer) = self
                .listener
                .accept()
                .await
                .map_err(InstanceActivationError::Accept)?;
            if !peer.ip().is_loopback() {
                continue;
            }

            let authenticated = timeout(HANDSHAKE_TIMEOUT, async {
                let mut supplied_token = [0_u8; TOKEN_BYTES];
                stream.read_exact(&mut supplied_token).await?;
                if !tokens_match(self.token.as_bytes(), &supplied_token) {
                    return Ok::<_, io::Error>(false);
                }
                stream.write_all(&[ACK]).await?;
                stream.flush().await?;
                Ok(true)
            })
            .await;

            if matches!(authenticated, Ok(Ok(true))) {
                return Ok(());
            }
        }
    }

    /// Notifies the primary instance and waits for its acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns an error for missing or invalid metadata, connection failures,
    /// timeouts, or an invalid acknowledgement. A missing metadata file or a
    /// refused connection is retried for at most five seconds to cover the
    /// interval between the primary acquiring its lock and publishing the
    /// activation listener.
    pub async fn notify(metadata_path: &Path) -> Result<(), InstanceActivationError> {
        timeout(NOTIFY_TIMEOUT, async {
            loop {
                match timeout(NOTIFY_ATTEMPT_TIMEOUT, Self::notify_once(metadata_path)).await {
                    Ok(Ok(())) => return Ok(()),
                    Ok(Err(error)) if error.is_startup_race() => {}
                    Ok(Err(error)) => return Err(error),
                    Err(_) => {}
                }
                sleep(NOTIFY_RETRY_DELAY).await;
            }
        })
        .await
        .map_err(|_| InstanceActivationError::Timeout)?
    }

    async fn notify_once(metadata_path: &Path) -> Result<(), InstanceActivationError> {
        let record = read_record(metadata_path).await?;
        let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, record.port);
        let mut stream = TcpStream::connect(address)
            .await
            .map_err(InstanceActivationError::Connect)?;

        stream
            .write_all(record.token.as_bytes())
            .await
            .map_err(InstanceActivationError::Connect)?;
        stream
            .flush()
            .await
            .map_err(InstanceActivationError::Connect)?;
        let mut acknowledgement = [0_u8; 1];
        stream
            .read_exact(&mut acknowledgement)
            .await
            .map_err(InstanceActivationError::Connect)?;

        if acknowledgement[0] != ACK {
            return Err(InstanceActivationError::Rejected);
        }
        Ok(())
    }
}

impl Drop for InstanceActivation {
    fn drop(&mut self) {
        if record_belongs_to(&self.metadata_path, &self.token) {
            match std::fs::remove_file(&self.metadata_path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    tracing::warn!(
                        path = %self.metadata_path.display(),
                        %error,
                        "failed to remove instance activation metadata"
                    );
                }
            }
        }
    }
}

fn publish_record(
    metadata_path: &Path,
    record: &ActivationRecord,
) -> Result<(), InstanceActivationError> {
    let payload = serde_json::to_vec(record).map_err(InstanceActivationError::DecodeMetadata)?;
    let parent = metadata_path
        .parent()
        .ok_or(InstanceActivationError::InvalidMetadata(
            "激活元数据路径缺少父目录",
        ))?;
    std::fs::create_dir_all(parent).map_err(|source| InstanceActivationError::WriteMetadata {
        path: metadata_path.to_path_buf(),
        source,
    })?;

    #[cfg(not(unix))]
    let options = atomic_write_file::OpenOptions::new();
    #[cfg(unix)]
    let mut options = atomic_write_file::OpenOptions::new();
    #[cfg(unix)]
    {
        atomic_write_file::unix::OpenOptionsExt::preserve_mode(&mut options, false);
        atomic_write_file::unix::OpenOptionsExt::try_preserve_owner(&mut options, false);
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    }
    let mut file =
        options
            .open(metadata_path)
            .map_err(|source| InstanceActivationError::WriteMetadata {
                path: metadata_path.to_path_buf(),
                source,
            })?;
    file.write_all(&payload)
        .and_then(|()| file.commit())
        .map_err(|source| InstanceActivationError::WriteMetadata {
            path: metadata_path.to_path_buf(),
            source,
        })
}

async fn read_record(metadata_path: &Path) -> Result<ActivationRecord, InstanceActivationError> {
    let file = tokio::fs::File::open(metadata_path)
        .await
        .map_err(|source| InstanceActivationError::ReadMetadata {
            path: metadata_path.to_path_buf(),
            source,
        })?;
    let mut payload = Vec::new();
    file.take((MAX_METADATA_BYTES + 1) as u64)
        .read_to_end(&mut payload)
        .await
        .map_err(|source| InstanceActivationError::ReadMetadata {
            path: metadata_path.to_path_buf(),
            source,
        })?;
    if payload.len() > MAX_METADATA_BYTES {
        return Err(InstanceActivationError::InvalidMetadata(
            "激活元数据超过大小限制",
        ));
    }
    let record: ActivationRecord =
        serde_json::from_slice(&payload).map_err(InstanceActivationError::DecodeMetadata)?;
    record.validate()?;
    Ok(record)
}

fn read_record_if_valid(metadata_path: &Path) -> Option<ActivationRecord> {
    let Ok(file) = File::open(metadata_path) else {
        return None;
    };
    let mut payload = Vec::new();
    if file
        .take((MAX_METADATA_BYTES + 1) as u64)
        .read_to_end(&mut payload)
        .is_err()
        || payload.len() > MAX_METADATA_BYTES
    {
        return None;
    }
    let record = serde_json::from_slice::<ActivationRecord>(&payload).ok()?;
    record.validate().ok()?;
    Some(record)
}

fn record_belongs_to(metadata_path: &Path, expected_token: &str) -> bool {
    read_record_if_valid(metadata_path).is_some_and(|record| record.token == expected_token)
}

fn tokens_match(expected: &[u8], supplied: &[u8; TOKEN_BYTES]) -> bool {
    expected.len() == TOKEN_BYTES
        && expected
            .iter()
            .zip(supplied)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

#[cfg(test)]
mod tests {
    use tokio::time::timeout;

    use super::{HANDSHAKE_TIMEOUT, InstanceActivation, InstanceActivationError, NOTIFY_TIMEOUT};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticated_notification_round_trip_is_acknowledged() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let path = directory.path().join("instance-activation.json");
        let activation = InstanceActivation::bind(&path)
            .await
            .expect("activation listener should bind");

        let notification = async {
            let (received, notified) = tokio::join!(
                activation.wait_for_notification(),
                InstanceActivation::notify(&path)
            );
            received.expect("primary should receive notification");
            notified.expect("secondary should receive acknowledgement");
        };

        timeout(NOTIFY_TIMEOUT, notification)
            .await
            .expect("round trip should not stall");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn notification_retries_until_primary_publishes_metadata() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let path = directory.path().join("instance-activation.json");
        let primary_path = path.clone();
        let delayed_primary = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let activation = InstanceActivation::bind(&primary_path)
                .await
                .expect("activation listener should bind");
            activation.wait_for_notification().await
        });

        InstanceActivation::notify(&path)
            .await
            .expect("secondary should receive acknowledgement");
        let received = timeout(HANDSHAKE_TIMEOUT, delayed_primary)
            .await
            .expect("primary should not stall after acknowledging")
            .expect("primary task should not panic");
        received.expect("primary should receive retried notification");
    }

    #[tokio::test]
    async fn oversized_metadata_is_rejected_before_connecting() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let path = directory.path().join("instance-activation.json");
        tokio::fs::write(&path, vec![b'x'; 1_025])
            .await
            .expect("test metadata should be written");

        let result = InstanceActivation::notify(&path).await;

        assert!(matches!(
            result,
            Err(InstanceActivationError::InvalidMetadata(
                "激活元数据超过大小限制"
            ))
        ));
    }

    #[tokio::test]
    async fn dropping_listener_removes_its_metadata() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let path = directory.path().join("instance-activation.json");
        let activation = InstanceActivation::bind(&path)
            .await
            .expect("activation listener should bind");
        assert!(path.exists());

        drop(activation);

        assert!(!path.exists());
    }

    #[tokio::test]
    async fn prepared_replacement_preserves_primary_metadata_until_publish() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let path = directory.path().join("instance-activation.json");
        let primary = InstanceActivation::bind(&path)
            .await
            .expect("primary activation listener should bind");
        let original = tokio::fs::read(&path)
            .await
            .expect("primary metadata should be readable");

        let unpublished = InstanceActivation::prepare(&path)
            .await
            .expect("replacement activation listener should prepare");
        assert_eq!(
            tokio::fs::read(&path)
                .await
                .expect("metadata should remain"),
            original
        );
        drop(unpublished);
        assert_eq!(
            tokio::fs::read(&path)
                .await
                .expect("metadata should remain"),
            original
        );

        let replacement = InstanceActivation::prepare(&path)
            .await
            .expect("replacement activation listener should prepare");
        replacement
            .publish()
            .expect("committed replacement should publish");
        assert_ne!(
            tokio::fs::read(&path)
                .await
                .expect("replacement metadata should be readable"),
            original
        );
        replacement
            .rollback_publication()
            .expect("aborted replacement should restore primary metadata");
        assert_eq!(
            tokio::fs::read(&path)
                .await
                .expect("metadata should remain"),
            original
        );
        replacement
            .publish()
            .expect("replacement should publish again for commit");
        drop(primary);
        assert!(path.exists());
        drop(replacement);
        assert!(!path.exists());
    }
}
