//! Operating-system adapters used by the desktop composition root.

mod activation;
mod api_endpoint;
mod auto_login;
mod configuration;
mod containment;
mod instance;
mod latency;
mod logging;
pub(crate) mod normalizer;
mod panel;
mod paths;
mod remote_startup;
mod session_vault;
mod settings;
mod sidecar;
mod sidecar_guardian;
mod startup;
mod system_proxy;
mod tls;

pub use activation::{InstanceActivation, InstanceActivationError};
pub use api_endpoint::PanelEndpoint;
pub use auto_login::{AutoLoginError, AutoLoginStore, SavedLogin};
pub use configuration::DevelopmentConfigurationSource;
pub use containment::ProcessContainmentGuard;
pub use instance::{InstanceGuard, InstanceLockError};
pub use latency::ping_latency;
pub use logging::{LogGuard, initialize_logging};
pub use panel::{HttpPanelClient, PanelClientOptions};
pub use paths::AppPaths;
pub use remote_startup::{
    DESKTOP_STARTUP_CONFIGURATION_URLS, PendingStartupConfiguration, RemoteDesktopVersion,
    RemoteStartupConfigurationLoader, RemoteStartupError, ResolvedStartupConfiguration,
};
pub use session_vault::SessionVault;
pub use settings::{DesktopSettings, SettingsStore};
pub use sidecar::{CoreProbe, SingBoxSidecar};
pub use sidecar_guardian::run_if_requested as run_sidecar_guardian_if_requested;
pub use startup::{PaymentPresentation, StartupConfiguration, StartupConfigurationStore};
pub use system_proxy::{
    ReconcileOutcome, RestoreOutcome, SystemProxyError, SystemProxyLease, SystemProxyManager,
};
