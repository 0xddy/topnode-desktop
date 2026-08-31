use std::fmt;

use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserIdentity {
    pub id: u64,
    pub uuid: String,
    pub username: String,
    pub email: String,
    pub balance_cents: i64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SessionTokens {
    session_id: String,
    access_token: String,
    access_expires_at_epoch_seconds: u64,
    refresh_token: String,
    refresh_expires_at_epoch_seconds: u64,
}

impl SessionTokens {
    /// Creates a validated token envelope.
    ///
    /// # Errors
    ///
    /// Returns [`SessionValidationError`] when a token or its expiry is empty.
    pub fn new(
        session_id: impl Into<String>,
        access_token: impl Into<String>,
        access_expires_at_epoch_seconds: u64,
        refresh_token: impl Into<String>,
        refresh_expires_at_epoch_seconds: u64,
    ) -> Result<Self, SessionValidationError> {
        let value = Self {
            session_id: session_id.into(),
            access_token: access_token.into(),
            access_expires_at_epoch_seconds,
            refresh_token: refresh_token.into(),
            refresh_expires_at_epoch_seconds,
        };
        if value.session_id.trim().is_empty()
            || value.access_token.trim().is_empty()
            || value.refresh_token.trim().is_empty()
            || value.access_expires_at_epoch_seconds == 0
            || value.refresh_expires_at_epoch_seconds == 0
        {
            return Err(SessionValidationError);
        }
        Ok(value)
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    pub const fn access_expires_at_epoch_seconds(&self) -> u64 {
        self.access_expires_at_epoch_seconds
    }

    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    pub const fn refresh_expires_at_epoch_seconds(&self) -> u64 {
        self.refresh_expires_at_epoch_seconds
    }
}

impl fmt::Debug for SessionTokens {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionTokens")
            .field("session_id", &self.session_id)
            .field("access_token", &"[REDACTED]")
            .field(
                "access_expires_at_epoch_seconds",
                &self.access_expires_at_epoch_seconds,
            )
            .field("refresh_token", &"[REDACTED]")
            .field(
                "refresh_expires_at_epoch_seconds",
                &self.refresh_expires_at_epoch_seconds,
            )
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserSession {
    pub user: UserIdentity,
    pub tokens: SessionTokens,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("会话令牌字段不完整")]
pub struct SessionValidationError;

#[cfg(test)]
mod tests {
    use super::SessionTokens;

    #[test]
    fn token_debug_output_is_redacted() {
        let tokens = SessionTokens::new("session", "access-secret", 100, "refresh-secret", 200)
            .expect("valid tokens");

        let debug = format!("{tokens:?}");
        assert!(!debug.contains("access-secret"));
        assert!(!debug.contains("refresh-secret"));
    }
}
