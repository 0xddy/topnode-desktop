/// Observable lifecycle of the external connection runtime.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ConnectionState {
    #[default]
    Disconnected,
    Preparing,
    Validating,
    Starting,
    Connected {
        started_at_epoch_millis: u64,
    },
    Stopping,
    Failed {
        message: String,
    },
}

impl ConnectionState {
    pub const fn is_transitioning(&self) -> bool {
        matches!(
            self,
            Self::Preparing | Self::Validating | Self::Starting | Self::Stopping
        )
    }

    pub const fn is_connected(&self) -> bool {
        matches!(self, Self::Connected { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    User,
    PermissionRevoked,
    SessionInvalid,
    EntitlementExpired,
    NetworkRestart,
    ApplicationExit,
    RuntimeError,
}
