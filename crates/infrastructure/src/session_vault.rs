use std::{
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;
use topnode_application::PanelError;
use topnode_domain::{SessionTokens, UserIdentity, UserSession};
use zeroize::Zeroizing;

use crate::paths::AppPaths;

const SERVICE_NAME: &str = "cc.topnode.desktop";
const ACCOUNT_NAME: &str = "session-envelope-key-v1";
const MAGIC: &[u8; 8] = b"TNSESS01";
const ENVELOPE_VERSION: u16 = 1;
const HEADER_LEN: usize = MAGIC.len() + size_of::<u16>();
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const MAX_PLAINTEXT_BYTES: usize = 60 * 1_024;
const MAX_ENVELOPE_BYTES: usize = 64 * 1_024;
const ASSOCIATED_DATA: &[u8] = b"cc.topnode.desktop/session-envelope/TNSESS01/v1";

/// Stores only a random data-encryption key in the platform credential vault;
/// the session itself lives in an authenticated, atomically replaced envelope.
#[derive(Clone)]
pub struct SessionVault {
    inner: Arc<SessionVaultInner>,
}

struct SessionVaultInner {
    envelope_path: PathBuf,
    key_store: Arc<dyn EnvelopeKeyStore>,
    operation_gate: Mutex<()>,
}

impl std::fmt::Debug for SessionVault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionVault")
            .field("envelope_path", &self.inner.envelope_path)
            .finish_non_exhaustive()
    }
}

impl SessionVault {
    pub fn new(envelope_path: impl Into<PathBuf>) -> Self {
        Self::with_key_store(envelope_path.into(), Arc::new(PlatformKeyStore))
    }

    pub fn from_paths(paths: &AppPaths) -> Self {
        Self::new(&paths.session_vault_file)
    }

    fn with_key_store(envelope_path: PathBuf, key_store: Arc<dyn EnvelopeKeyStore>) -> Self {
        Self {
            inner: Arc::new(SessionVaultInner {
                envelope_path,
                key_store,
                operation_gate: Mutex::new(()),
            }),
        }
    }

    /// Reads and authenticates the saved session.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the platform vault is unavailable or the
    /// encrypted envelope is unreadable, malformed, or fails authentication.
    pub async fn read(&self) -> Result<Option<UserSession>, PanelError> {
        let _guard = self.inner.operation_gate.lock().await;
        let envelope_path = self.inner.envelope_path.clone();
        let key_store = Arc::clone(&self.inner.key_store);
        run_blocking(move || read_session(&envelope_path, key_store.as_ref())).await
    }

    /// Atomically replaces the authenticated encrypted session envelope.
    ///
    /// # Errors
    ///
    /// Returns a serialization, cryptography, I/O, or platform-vault failure.
    pub async fn write(&self, session: &UserSession) -> Result<(), PanelError> {
        let _guard = self.inner.operation_gate.lock().await;
        let stored = StoredSession::from_domain(session);
        let envelope_path = self.inner.envelope_path.clone();
        let key_store = Arc::clone(&self.inner.key_store);
        run_blocking(move || write_session(&envelope_path, key_store.as_ref(), &stored)).await
    }

    /// Removes the data-encryption key before deleting the encrypted envelope.
    /// Missing credentials and files are treated as success.
    ///
    /// # Errors
    ///
    /// Returns a platform-vault or filesystem failure.
    pub async fn clear(&self) -> Result<(), PanelError> {
        let _guard = self.inner.operation_gate.lock().await;
        let envelope_path = self.inner.envelope_path.clone();
        let key_store = Arc::clone(&self.inner.key_store);
        run_blocking(move || clear_material(&envelope_path, key_store.as_ref())).await
    }
}

async fn run_blocking<T>(
    operation: impl FnOnce() -> Result<T, VaultError> + Send + 'static,
) -> Result<T, PanelError>
where
    T: Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| PanelError::Storage(format!("凭据存储任务异常结束：{error}")))?
        .map_err(|error| PanelError::Storage(error.to_string()))
}

fn read_session(
    envelope_path: &Path,
    key_store: &dyn EnvelopeKeyStore,
) -> Result<Option<UserSession>, VaultError> {
    let envelope = match read_envelope(envelope_path) {
        Ok(Some(envelope)) => envelope,
        Ok(None) => {
            key_store.clear()?;
            return Ok(None);
        }
        Err(error @ VaultError::Corrupt(_)) => {
            clear_material(envelope_path, key_store)?;
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    let Some(key) = key_store.read()? else {
        remove_envelope(envelope_path)?;
        return Ok(None);
    };

    if key.len() != KEY_LEN {
        clear_material(envelope_path, key_store)?;
        return Err(VaultError::Corrupt("凭据库中的会话密钥长度无效"));
    }

    match decrypt_session(&envelope, &key).and_then(StoredSession::into_domain) {
        Ok(session) => Ok(Some(session)),
        Err(error @ VaultError::Corrupt(_)) => {
            clear_material(envelope_path, key_store)?;
            Err(error)
        }
        Err(error) => Err(error),
    }
}

fn write_session(
    envelope_path: &Path,
    key_store: &dyn EnvelopeKeyStore,
    session: &StoredSession,
) -> Result<(), VaultError> {
    let key = match key_store.read()? {
        Some(key) if key.len() == KEY_LEN => key,
        Some(_) => {
            clear_material(envelope_path, key_store)?;
            create_and_store_key(key_store)?
        }
        None => create_and_store_key(key_store)?,
    };
    let envelope = encrypt_session(session, &key)?;
    atomic_write(envelope_path, &envelope)
}

fn create_and_store_key(
    key_store: &dyn EnvelopeKeyStore,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let generated = Zeroizing::new(
        <[u8; KEY_LEN]>::try_generate().map_err(|_| VaultError::Random("无法生成会话加密密钥"))?,
    );
    key_store.write(generated.as_slice())?;
    Ok(Zeroizing::new(generated.to_vec()))
}

fn encrypt_session(session: &StoredSession, key: &[u8]) -> Result<Vec<u8>, VaultError> {
    let plaintext = Zeroizing::new(
        serde_json::to_vec(session).map_err(|_| VaultError::Serialization("无法序列化会话"))?,
    );
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(VaultError::Serialization("会话数据超过安全大小限制"));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| VaultError::Corrupt("会话加密密钥长度无效"))?;
    let nonce = XNonce::try_generate().map_err(|_| VaultError::Random("无法生成会话加密随机数"))?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_slice(),
                aad: ASSOCIATED_DATA,
            },
        )
        .map_err(|_| VaultError::Crypto("无法加密会话"))?;

    let mut envelope = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(MAGIC);
    envelope.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    if envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(VaultError::Serialization("加密会话超过安全大小限制"));
    }
    Ok(envelope)
}

fn decrypt_session(envelope: &[u8], key: &[u8]) -> Result<StoredSession, VaultError> {
    if envelope.len() < HEADER_LEN + NONCE_LEN + TAG_LEN {
        return Err(VaultError::Corrupt("会话信封长度无效"));
    }
    if &envelope[..MAGIC.len()] != MAGIC {
        return Err(VaultError::Corrupt("会话信封标识无效"));
    }
    let version = u16::from_be_bytes([envelope[MAGIC.len()], envelope[MAGIC.len() + 1]]);
    if version != ENVELOPE_VERSION {
        return Err(VaultError::Corrupt("不支持的会话信封版本"));
    }

    let nonce_end = HEADER_LEN + NONCE_LEN;
    let nonce = XNonce::try_from(&envelope[HEADER_LEN..nonce_end])
        .map_err(|_| VaultError::Corrupt("会话随机数长度无效"))?;
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| VaultError::Corrupt("会话加密密钥长度无效"))?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &envelope[nonce_end..],
                    aad: ASSOCIATED_DATA,
                },
            )
            .map_err(|_| VaultError::Corrupt("会话信封身份验证失败"))?,
    );
    serde_json::from_slice(&plaintext).map_err(|_| VaultError::Corrupt("会话信封内容无效"))
}

fn read_envelope(path: &Path) -> Result<Option<Vec<u8>>, VaultError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut envelope = Vec::new();
    file.take((MAX_ENVELOPE_BYTES + 1) as u64)
        .read_to_end(&mut envelope)?;
    if envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(VaultError::Corrupt("会话信封超过安全大小限制"));
    }
    Ok(Some(envelope))
}

fn atomic_write(path: &Path, content: &[u8]) -> Result<(), VaultError> {
    let parent = path
        .parent()
        .ok_or(VaultError::Serialization("会话信封路径缺少父目录"))?;
    std::fs::create_dir_all(parent)?;
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
    let mut file = options.open(path)?;
    file.write_all(content)?;
    file.commit()?;
    Ok(())
}

fn clear_material(
    envelope_path: &Path,
    key_store: &dyn EnvelopeKeyStore,
) -> Result<(), VaultError> {
    let key_result = key_store.clear();
    let envelope_result = remove_envelope(envelope_path);
    match (key_result, envelope_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(key_error), Ok(())) => Err(key_error),
        (Ok(()), Err(envelope_error)) => Err(envelope_error),
        (Err(key_error), Err(envelope_error)) => {
            tracing::error!(%key_error, %envelope_error, "failed to clear both session key and envelope");
            Err(key_error)
        }
    }
}

fn remove_envelope(path: &Path) -> Result<(), VaultError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

trait EnvelopeKeyStore: Send + Sync {
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError>;
    fn write(&self, key: &[u8]) -> Result<(), VaultError>;
    fn clear(&self) -> Result<(), VaultError>;
}

#[derive(Debug)]
struct PlatformKeyStore;

impl EnvelopeKeyStore for PlatformKeyStore {
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        let entry = keyring::v1::Entry::new(SERVICE_NAME, ACCOUNT_NAME)
            .map_err(|error| keyring_storage_error(&error))?;
        match entry.get_secret() {
            Ok(key) => Ok(Some(Zeroizing::new(key))),
            Err(keyring::v1::Error::NoEntry) => Ok(None),
            Err(error) => Err(keyring_storage_error(&error)),
        }
    }

    fn write(&self, key: &[u8]) -> Result<(), VaultError> {
        keyring::v1::Entry::new(SERVICE_NAME, ACCOUNT_NAME)
            .and_then(|entry| entry.set_secret(key))
            .map_err(|error| keyring_storage_error(&error))
    }

    fn clear(&self) -> Result<(), VaultError> {
        let entry = keyring::v1::Entry::new(SERVICE_NAME, ACCOUNT_NAME)
            .map_err(|error| keyring_storage_error(&error))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::v1::Error::NoEntry) => Ok(()),
            Err(error) => Err(keyring_storage_error(&error)),
        }
    }
}

#[derive(Deserialize, Serialize)]
struct StoredSession {
    session_id: String,
    access_token: String,
    access_expires_at_epoch_seconds: u64,
    refresh_token: String,
    refresh_expires_at_epoch_seconds: u64,
    user_id: u64,
    user_uuid: String,
    username: String,
    email: String,
    #[serde(default)]
    balance_cents: i64,
}

impl StoredSession {
    fn from_domain(session: &UserSession) -> Self {
        Self {
            session_id: session.tokens.session_id().to_owned(),
            access_token: session.tokens.access_token().to_owned(),
            access_expires_at_epoch_seconds: session.tokens.access_expires_at_epoch_seconds(),
            refresh_token: session.tokens.refresh_token().to_owned(),
            refresh_expires_at_epoch_seconds: session.tokens.refresh_expires_at_epoch_seconds(),
            user_id: session.user.id,
            user_uuid: session.user.uuid.clone(),
            username: session.user.username.clone(),
            email: session.user.email.clone(),
            balance_cents: session.user.balance_cents,
        }
    }

    fn into_domain(self) -> Result<UserSession, VaultError> {
        let tokens = SessionTokens::new(
            self.session_id,
            self.access_token,
            self.access_expires_at_epoch_seconds,
            self.refresh_token,
            self.refresh_expires_at_epoch_seconds,
        )
        .map_err(|_| VaultError::Corrupt("会话令牌字段不完整"))?;
        Ok(UserSession {
            user: UserIdentity {
                id: self.user_id,
                uuid: self.user_uuid,
                username: self.username,
                email: self.email,
                balance_cents: self.balance_cents,
            },
            tokens,
        })
    }
}

#[derive(Debug, Error)]
enum VaultError {
    #[error("系统凭据库不可用：{0}")]
    Credential(&'static str),
    #[error("{0}")]
    Serialization(&'static str),
    #[error("{0}")]
    Random(&'static str),
    #[error("{0}")]
    Crypto(&'static str),
    #[error("加密会话已损坏：{0}")]
    Corrupt(&'static str),
    #[error("会话信封文件操作失败：{0}")]
    Io(#[from] io::Error),
}

fn keyring_storage_error(error: &keyring::v1::Error) -> VaultError {
    let description = match error {
        keyring::v1::Error::PlatformFailure(_) => "平台凭据库调用失败",
        keyring::v1::Error::NoStorageAccess(_) => "凭据库被锁定或拒绝访问",
        keyring::v1::Error::NoEntry => "凭据不存在",
        keyring::v1::Error::BadEncoding(_) => "凭据编码无效",
        keyring::v1::Error::BadDataFormat(_, _) => "凭据格式无效",
        keyring::v1::Error::BadStoreFormat(_) => "凭据库格式无效",
        keyring::v1::Error::TooLong(_, _) => "凭据超过平台大小限制",
        keyring::v1::Error::Invalid(_, _) => "凭据标识无效",
        keyring::v1::Error::Ambiguous(_) => "发现重复凭据",
        keyring::v1::Error::NoDefaultStore => "平台凭据库未初始化",
        keyring::v1::Error::NotSupportedByStore(_) => "平台凭据库不支持此操作",
        _ => "未知平台凭据库错误",
    };
    VaultError::Credential(description)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use tempfile::tempdir;

    use super::*;

    #[derive(Debug, Default)]
    struct MemoryKeyStore {
        key: StdMutex<Option<Vec<u8>>>,
    }

    impl MemoryKeyStore {
        fn saved_key(&self) -> Option<Vec<u8>> {
            self.key.lock().expect("key lock").clone()
        }
    }

    impl EnvelopeKeyStore for MemoryKeyStore {
        fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
            Ok(self.saved_key().map(Zeroizing::new))
        }

        fn write(&self, key: &[u8]) -> Result<(), VaultError> {
            *self.key.lock().expect("key lock") = Some(key.to_vec());
            Ok(())
        }

        fn clear(&self) -> Result<(), VaultError> {
            *self.key.lock().expect("key lock") = None;
            Ok(())
        }
    }

    #[derive(Debug)]
    struct ClearFailingKeyStore;

    impl EnvelopeKeyStore for ClearFailingKeyStore {
        fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
            Ok(None)
        }

        fn write(&self, _key: &[u8]) -> Result<(), VaultError> {
            Ok(())
        }

        fn clear(&self) -> Result<(), VaultError> {
            Err(VaultError::Credential("测试凭据库故障"))
        }
    }

    #[tokio::test]
    async fn round_trip_keeps_only_the_dek_in_the_key_store() {
        let directory = tempdir().expect("temp dir");
        let path = directory.path().join("auth/session.v1.bin");
        let keys = Arc::new(MemoryKeyStore::default());
        let vault = SessionVault::with_key_store(path.clone(), keys.clone());
        let session = sample_session("access-secret", "refresh-secret");

        vault.write(&session).await.expect("write session");

        assert_eq!(keys.saved_key().expect("saved key").len(), KEY_LEN);
        let envelope = std::fs::read(&path).expect("envelope");
        assert!(envelope.starts_with(MAGIC));
        assert!(!contains(&envelope, b"access-secret"));
        assert!(!contains(&envelope, b"refresh-secret"));
        assert_eq!(vault.read().await.expect("read session"), Some(session));
    }

    #[tokio::test]
    async fn every_replacement_uses_a_fresh_nonce() {
        let directory = tempdir().expect("temp dir");
        let path = directory.path().join("auth/session.v1.bin");
        let keys = Arc::new(MemoryKeyStore::default());
        let vault = SessionVault::with_key_store(path.clone(), keys);

        vault
            .write(&sample_session("access-one", "refresh-one"))
            .await
            .expect("first write");
        let first = std::fs::read(&path).expect("first envelope");
        vault
            .write(&sample_session("access-two", "refresh-two"))
            .await
            .expect("second write");
        let second = std::fs::read(&path).expect("second envelope");

        assert_ne!(
            &first[HEADER_LEN..HEADER_LEN + NONCE_LEN],
            &second[HEADER_LEN..HEADER_LEN + NONCE_LEN]
        );
    }

    #[tokio::test]
    async fn tampering_invalidates_both_key_and_envelope() {
        let directory = tempdir().expect("temp dir");
        let path = directory.path().join("auth/session.v1.bin");
        let keys = Arc::new(MemoryKeyStore::default());
        let vault = SessionVault::with_key_store(path.clone(), keys.clone());
        vault
            .write(&sample_session("access", "refresh"))
            .await
            .expect("write session");
        let mut envelope = std::fs::read(&path).expect("envelope");
        let last = envelope.last_mut().expect("ciphertext byte");
        *last ^= 0x01;
        std::fs::write(&path, envelope).expect("tamper envelope");

        let error = vault.read().await.expect_err("tampering must fail");

        assert!(error.to_string().contains("身份验证失败"));
        assert!(keys.saved_key().is_none());
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn clear_is_idempotent_and_removes_key_before_session_is_reusable() {
        let directory = tempdir().expect("temp dir");
        let path = directory.path().join("auth/session.v1.bin");
        let keys = Arc::new(MemoryKeyStore::default());
        let vault = SessionVault::with_key_store(path.clone(), keys.clone());
        vault
            .write(&sample_session("access", "refresh"))
            .await
            .expect("write session");

        vault.clear().await.expect("first clear");
        vault.clear().await.expect("second clear");

        assert!(keys.saved_key().is_none());
        assert!(!path.exists());
        assert_eq!(vault.read().await.expect("read cleared vault"), None);
    }

    #[test]
    fn envelope_removal_is_attempted_when_the_key_store_fails() {
        let directory = tempdir().expect("temp dir");
        let path = directory.path().join("session.v1.bin");
        std::fs::write(&path, b"encrypted envelope").expect("fixture");

        clear_material(&path, &ClearFailingKeyStore).expect_err("key clear must fail");

        assert!(!path.exists());
    }

    #[tokio::test]
    async fn missing_envelope_removes_an_orphaned_key() {
        let directory = tempdir().expect("temp dir");
        let path = directory.path().join("auth/session.v1.bin");
        let keys = Arc::new(MemoryKeyStore::default());
        keys.write(&[7; KEY_LEN]).expect("seed orphaned key");
        let vault = SessionVault::with_key_store(path, keys.clone());

        assert_eq!(vault.read().await.expect("read empty vault"), None);
        assert!(keys.saved_key().is_none());
    }

    fn sample_session(access_token: &str, refresh_token: &str) -> UserSession {
        UserSession {
            user: UserIdentity {
                id: 7,
                uuid: "user-uuid".to_owned(),
                username: "TOPNODE user".to_owned(),
                email: "user@example.com".to_owned(),
                balance_cents: 12_345,
            },
            tokens: SessionTokens::new(
                "session-id",
                access_token,
                2_000_000_000,
                refresh_token,
                2_100_000_000,
            )
            .expect("valid tokens"),
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}
