use std::time::Duration;

const MIN_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_TIMEOUT: Duration = Duration::from_secs(10);

/// Measures one ICMP echo round trip without launching a command-line process.
/// Invalid targets and failed or timed-out probes return `None`.
pub async fn ping_latency(target: &str, timeout: Duration) -> Option<u64> {
    let target = normalize_ping_target(target)?;
    let timeout = timeout.clamp(MIN_TIMEOUT, MAX_TIMEOUT);
    tokio::time::timeout(timeout, native_ping(&target, timeout))
        .await
        .ok()
        .flatten()
}

#[cfg(all(windows, not(target_arch = "aarch64")))]
async fn native_ping(target: &str, timeout: Duration) -> Option<u64> {
    let address = resolve_target(target).await?;
    let mut pinger = winping::AsyncPinger::new();
    pinger.set_timeout(u32::try_from(timeout.as_millis()).ok()?);
    let response = pinger.send(address, winping::Buffer::new()).await;
    response
        .result
        .ok()
        .map(|milliseconds| u64::from(milliseconds).max(1))
}

#[cfg(any(not(windows), all(windows, target_arch = "aarch64")))]
async fn native_ping(target: &str, _timeout: Duration) -> Option<u64> {
    let address = resolve_target(target).await?;
    let (_, elapsed) = surge_ping::ping(address, &[0; 8]).await.ok()?;
    u64::try_from(elapsed.as_millis())
        .ok()
        .map(|milliseconds| milliseconds.max(1))
}

async fn resolve_target(target: &str) -> Option<std::net::IpAddr> {
    let mut addresses = tokio::net::lookup_host((target, 0)).await.ok()?;
    addresses.next().map(|address| address.ip())
}

fn normalize_ping_target(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 253 || trimmed.starts_with('-') {
        return None;
    }
    let without_brackets = trimmed
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(trimmed);
    (!without_brackets.is_empty()
        && without_brackets
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._:-".contains(character)))
    .then(|| without_brackets.to_owned())
}

#[cfg(test)]
mod tests {
    use super::normalize_ping_target;
    #[cfg(windows)]
    use super::ping_latency;

    #[test]
    fn normalizes_the_same_targets_as_android() {
        assert_eq!(
            normalize_ping_target(" node.example ").as_deref(),
            Some("node.example")
        );
        assert_eq!(
            normalize_ping_target("[2001:db8::1]").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(normalize_ping_target("-invalid"), None);
        assert_eq!(normalize_ping_target("invalid target"), None);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn native_windows_icmp_reaches_loopback_without_a_child_process() {
        assert!(
            ping_latency("127.0.0.1", std::time::Duration::from_secs(1))
                .await
                .is_some()
        );
    }
}
