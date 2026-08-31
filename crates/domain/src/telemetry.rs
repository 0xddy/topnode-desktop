/// Bounded, aggregate-only runtime telemetry suitable for desktop status UI.
///
/// It deliberately excludes per-connection destinations and process metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuntimeTelemetrySnapshot {
    pub upload_total_bytes: u64,
    pub download_total_bytes: u64,
    pub upload_bytes_per_second: u64,
    pub download_bytes_per_second: u64,
    pub active_connections: u32,
    pub memory_bytes: Option<u64>,
    pub sampled_at_epoch_millis: u64,
}
