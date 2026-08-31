//! Application use-cases. This crate knows no Slint or operating-system APIs.

mod configuration;
mod connection;
mod panel;

pub use configuration::{ConfigurationRequest, ConfigurationSource, ConfigurationSourceError};
pub use connection::{ConnectError, ConnectionCoordinator};
pub use panel::{
    AccountPhase, AccountSnapshot, LoginCredentials, PanelCoordinator, PanelError, PanelRepository,
    PasswordChange, ShopPhase, ShopSnapshot,
};
