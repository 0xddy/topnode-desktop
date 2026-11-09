pub(crate) fn category(message: &str) -> &'static str {
    let text = message.to_ascii_lowercase();
    let has = |markers: &[&str]| markers.iter().any(|marker| text.contains(marker));
    if has(&[
        "not supported by this build",
        "unsupported runtime",
        "qualification",
    ]) {
        "capability"
    } else if has(&[
        "uot v2",
        "refresh the configuration",
        "invalid configuration",
    ]) {
        "configuration"
    } else if has(&["certificate", "x509", "err_cert_", "unknown authority"]) {
        "trust"
    } else if has(&[
        "407",
        "proxy_auth",
        "authentication",
        "unauthorized",
        "bad credentials",
    ]) {
        "authentication"
    } else if has(&["timed out", "timeout", "err_timed_out"]) {
        "network-timeout"
    } else if has(&[
        "network is unreachable",
        "network_unreachable",
        "quic_protocol_error",
        "quic handshake",
    ]) {
        "network-unreachable"
    } else if has(&["connection refused", "connection_refused"]) {
        "network-refused"
    } else if has(&[
        "protect native socket",
        "permission denied",
        "tun helper",
        "system proxy",
    ]) {
        "system-takeover"
    } else {
        "runtime"
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn cronet_errors_are_not_all_configuration_errors() {
        for (message, category) in [
            ("Cronet ERR_CERT_AUTHORITY_INVALID", "trust"),
            ("HTTPS 407 proxy authentication failed", "authentication"),
            (
                "QUIC handshake network is unreachable",
                "network-unreachable",
            ),
            ("connection timed out", "network-timeout"),
        ] {
            assert_eq!(super::category(message), category);
        }
    }
}
