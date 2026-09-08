use std::{fmt, sync::Arc};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

const SERVICE: &str = "cc.topnode.desktop";
const ACCOUNT: &str = "auto-login-credentials-v1";
const MAX_SECRET_BYTES: usize = 2_500;

/// Explicitly opted-in login inputs; never include them in logs or settings.
#[derive(Clone, Serialize, Deserialize)]
pub struct SavedLogin {
    version: u8,
    email: String,
    password: String,
}

impl SavedLogin {
    pub fn new(email: String, password: String) -> Self {
        Self {
            version: 1,
            email,
            password,
        }
    }

    pub fn email(&self) -> &str {
        &self.email
    }
    pub fn password(&self) -> &str {
        &self.password
    }

    fn valid(&self) -> bool {
        self.version == 1 && !self.email.trim().is_empty() && !self.password.is_empty()
    }
}

impl fmt::Debug for SavedLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SavedLogin([REDACTED])")
    }
}

impl Drop for SavedLogin {
    fn drop(&mut self) {
        self.email.zeroize();
        self.password.zeroize();
    }
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct AutoLoginError(&'static str);

trait SecretStore: Send + Sync {
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, AutoLoginError>;
    fn write(&self, secret: &[u8]) -> Result<(), AutoLoginError>;
    fn clear(&self) -> Result<(), AutoLoginError>;
}

struct PlatformSecretStore;

fn credential_entry() -> Result<keyring::v1::Entry, AutoLoginError> {
    keyring::v1::Entry::new(SERVICE, ACCOUNT).map_err(|_| AutoLoginError("无法访问系统凭据库"))
}

impl SecretStore for PlatformSecretStore {
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, AutoLoginError> {
        match credential_entry()?.get_secret() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(keyring::v1::Error::NoEntry) => Ok(None),
            Err(_) => Err(AutoLoginError("无法读取自动登录信息，请手动登录")),
        }
    }

    fn write(&self, secret: &[u8]) -> Result<(), AutoLoginError> {
        credential_entry()?
            .set_secret(secret)
            .map_err(|_| AutoLoginError("无法保存自动登录信息，请检查系统凭据库"))
    }

    fn clear(&self) -> Result<(), AutoLoginError> {
        match credential_entry()?.delete_credential() {
            Ok(()) | Err(keyring::v1::Error::NoEntry) => Ok(()),
            Err(_) => Err(AutoLoginError("无法清除自动登录信息，请检查系统凭据库")),
        }
    }
}

/// One OS credential entry contains both inputs, so opt-in and credentials cannot diverge.
#[derive(Clone)]
pub struct AutoLoginStore {
    backend: Arc<dyn SecretStore>,
    gate: Arc<Mutex<()>>,
}

impl fmt::Debug for AutoLoginStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AutoLoginStore").finish_non_exhaustive()
    }
}

impl Default for AutoLoginStore {
    fn default() -> Self {
        Self {
            backend: Arc::new(PlatformSecretStore),
            gate: Arc::default(),
        }
    }
}

impl AutoLoginStore {
    /// Reads explicit auto-login consent and inputs from the OS credential store.
    ///
    /// # Errors
    /// Returns an error for unavailable storage or invalid saved data.
    pub async fn read(&self) -> Result<Option<SavedLogin>, AutoLoginError> {
        let guard = Arc::clone(&self.gate).lock_owned().await;
        let backend = Arc::clone(&self.backend);
        blocking(move || {
            // A timed-out caller cannot cancel spawn_blocking. Keep serialization
            // until the OS operation ends, including removal of invalid entries.
            let _guard = guard;
            let Some(secret) = backend.read()? else {
                return Ok(None);
            };
            let saved = (secret.len() <= MAX_SECRET_BYTES)
                .then(|| serde_json::from_slice::<SavedLogin>(&secret).ok())
                .flatten()
                .filter(SavedLogin::valid);
            if saved.is_none() {
                backend.clear()?;
                return Err(AutoLoginError("自动登录信息已失效，请重新输入"));
            }
            Ok(saved)
        })
        .await
    }

    /// Replaces the complete opted-in login inputs after successful authentication.
    ///
    /// # Errors
    /// Returns an error for invalid inputs or a failed OS credential write.
    pub async fn save(&self, saved: SavedLogin) -> Result<(), AutoLoginError> {
        let guard = Arc::clone(&self.gate).lock_owned().await;
        let backend = Arc::clone(&self.backend);
        blocking(move || {
            let _guard = guard;
            if !saved.valid() {
                return Err(AutoLoginError("自动登录信息不完整"));
            }
            let secret = Zeroizing::new(
                serde_json::to_vec(&saved).map_err(|_| AutoLoginError("无法保存自动登录信息"))?,
            );
            if secret.len() > MAX_SECRET_BYTES {
                return Err(AutoLoginError("自动登录信息超过系统凭据库大小限制"));
            }
            backend.write(&secret)
        })
        .await
    }

    /// Removes both saved inputs and auto-login consent.
    ///
    /// # Errors
    /// Returns an error if the OS credential cannot be deleted.
    pub async fn clear(&self) -> Result<(), AutoLoginError> {
        let guard = Arc::clone(&self.gate).lock_owned().await;
        let backend = Arc::clone(&self.backend);
        blocking(move || {
            let _guard = guard;
            backend.clear()
        })
        .await
    }
}

async fn blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, AutoLoginError> + Send + 'static,
) -> Result<T, AutoLoginError> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| AutoLoginError("系统凭据库任务未完成"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemoryStore(std::sync::Mutex<Option<Vec<u8>>>);
    impl SecretStore for MemoryStore {
        fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, AutoLoginError> {
            Ok(self.0.lock().unwrap().clone().map(Zeroizing::new))
        }
        fn write(&self, secret: &[u8]) -> Result<(), AutoLoginError> {
            *self.0.lock().unwrap() = Some(secret.to_vec());
            Ok(())
        }
        fn clear(&self) -> Result<(), AutoLoginError> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }

    fn fixture() -> (AutoLoginStore, Arc<MemoryStore>) {
        let backend = Arc::new(MemoryStore::default());
        (
            AutoLoginStore {
                backend: backend.clone(),
                gate: Arc::default(),
            },
            backend,
        )
    }

    #[tokio::test]
    async fn only_explicitly_saved_inputs_are_restored_and_clear_removes_both() {
        let (store, _) = fixture();
        assert!(store.read().await.unwrap().is_none());
        store
            .save(SavedLogin::new("a@example.test".into(), "secret".into()))
            .await
            .unwrap();
        let saved = store.read().await.unwrap().unwrap();
        assert_eq!(saved.email(), "a@example.test");
        assert_eq!(saved.password(), "secret");
        store.clear().await.unwrap();
        assert!(store.read().await.unwrap().is_none());
        store.clear().await.unwrap();
    }

    #[tokio::test]
    async fn malformed_or_incompatible_credentials_are_removed() {
        let (store, backend) = fixture();
        for value in [
            b"invalid".as_slice(),
            br#"{"version":2,"email":"a","password":"b"}"#,
            br#"{"version":1,"email":"a","password":""}"#,
        ] {
            backend.write(value).unwrap();
            assert!(store.read().await.is_err());
            assert!(backend.read().unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn failed_validation_does_not_replace_existing_credentials() {
        let (store, _) = fixture();
        store
            .save(SavedLogin::new("a".into(), "secret".into()))
            .await
            .unwrap();
        assert!(
            store
                .save(SavedLogin::new("b".into(), "x".repeat(MAX_SECRET_BYTES)))
                .await
                .is_err()
        );
        assert_eq!(store.read().await.unwrap().unwrap().email(), "a");
    }

    #[test]
    fn debug_never_contains_login_inputs() {
        let debug = format!(
            "{:?}",
            SavedLogin::new("private-email".into(), "secret".into())
        );
        assert!(!debug.contains("private-email"));
        assert!(!debug.contains("secret"));
    }

    #[derive(Default)]
    struct PausedStore {
        entered: tokio::sync::Notify,
        released: std::sync::Mutex<bool>,
        wake: std::sync::Condvar,
    }

    impl SecretStore for PausedStore {
        fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, AutoLoginError> {
            self.entered.notify_one();
            drop(
                self.wake
                    .wait_while(self.released.lock().unwrap(), |released| !*released)
                    .unwrap(),
            );
            Ok(None)
        }
        fn write(&self, _: &[u8]) -> Result<(), AutoLoginError> {
            Ok(())
        }
        fn clear(&self) -> Result<(), AutoLoginError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn cancelling_a_read_keeps_other_operations_serialized_until_os_completion() {
        let backend = Arc::new(PausedStore::default());
        let store = AutoLoginStore {
            backend: backend.clone(),
            gate: Arc::default(),
        };
        let reader = store.clone();
        let reading = tokio::spawn(async move { reader.read().await });
        backend.entered.notified().await;
        reading.abort();
        let _ = reading.await;
        let remained_locked = store.gate.try_lock().is_err();
        *backend.released.lock().unwrap() = true;
        backend.wake.notify_one();
        let _completed = store.gate.lock().await;
        assert!(
            remained_locked,
            "cancelled OS reads must not race later writes"
        );
    }
}
