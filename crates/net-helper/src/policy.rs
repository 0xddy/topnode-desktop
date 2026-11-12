use serde_json::Value;

pub const MAX_CONFIGURATION: usize = 8 * 1024 * 1024;

// Privileged configuration is data only. It cannot select a program, read a
// private file, create a service, serve a dashboard, or write persistent state.
pub fn validate(payload: &[u8]) -> Result<(), &'static str> {
    if payload.len() > MAX_CONFIGURATION {
        return Err("configuration too large");
    }
    let document: Value = serde_json::from_slice(payload).map_err(|_| "invalid configuration")?;
    let root = document.as_object().ok_or("invalid configuration root")?;
    if root.keys().any(|key| {
        ![
            "log",
            "dns",
            "inbounds",
            "outbounds",
            "route",
            "experimental",
        ]
        .contains(&key.as_str())
    }) {
        return Err("privileged configuration has unsupported sections");
    }
    check_fields(&document, FieldScope::Root)?;
    let inbounds = document["inbounds"]
        .as_array()
        .ok_or("missing TUN inbound")?;
    if inbounds
        .iter()
        .filter(|inbound| inbound["type"] == "tun")
        .count()
        != 1
    {
        return Err("exactly one TUN inbound is required");
    }
    for inbound in inbounds {
        match inbound["type"].as_str() {
            Some("tun") => {
                if inbound.get("interface_name").is_some_and(|name| {
                    !name.as_str().is_some_and(|name| {
                        name.starts_with("topnode")
                            && name.len() <= 15
                            && name.bytes().all(|c| c.is_ascii_alphanumeric())
                    })
                }) {
                    return Err("invalid TUN interface name");
                }
            }
            Some("mixed" | "socks" | "http")
                if inbound["listen"] == "127.0.0.1" || inbound["listen"] == "::1" => {}
            _ => return Err("privileged listener must be TUN or loopback proxy"),
        }
    }
    if let Some(outbounds) = document["outbounds"].as_array() {
        for outbound in outbounds {
            if !outbound["type"].as_str().is_some_and(|kind| {
                [
                    "direct",
                    "block",
                    "selector",
                    "urltest",
                    "naive",
                    "vless",
                    "anytls",
                    "hysteria2",
                    "juicity",
                    "mieru",
                ]
                .contains(&kind)
            }) {
                return Err("unsupported privileged outbound");
            }
        }
    }
    if let Some(controller) = document["experimental"]["clash_api"]["external_controller"].as_str()
    {
        let address: std::net::SocketAddr =
            controller.parse().map_err(|_| "invalid control address")?;
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err("control API must be loopback");
        }
    }
    if document["experimental"]["cache_file"]["enabled"].as_bool() == Some(true) {
        return Err("privileged cache is disabled");
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FieldScope {
    Root,
    Outbounds,
    Outbound,
    XhttpTransport,
    Nested,
}

fn check_fields(value: &Value, scope: FieldScope) -> Result<(), &'static str> {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                // This path selects a remote HTTP route on a VLESS XHTTP outbound.
                let invalid_path =
                    key == "path" && (scope != FieldScope::XhttpTransport || !value.is_string());
                if key.ends_with("_path")
                    || key.ends_with("_file") && key != "cache_file"
                    || invalid_path
                    || [
                        "external_ui",
                        "external_ui_download_url",
                        "command",
                        "script",
                        "working_directory",
                    ]
                    .contains(&key.as_str())
                    || key == "output" && value.as_str() != Some("")
                {
                    return Err("privileged file or command reference rejected");
                }
                let child_scope = match (scope, key.as_str()) {
                    (FieldScope::Root, "outbounds") => FieldScope::Outbounds,
                    (FieldScope::Outbound, "transport")
                        if fields.get("type").and_then(Value::as_str) == Some("vless")
                            && value.get("type").and_then(Value::as_str) == Some("xhttp") =>
                    {
                        FieldScope::XhttpTransport
                    }
                    _ => FieldScope::Nested,
                };
                check_fields(value, child_scope)?;
            }
        }
        Value::Array(values) => {
            let element_scope = if scope == FieldScope::Outbounds {
                FieldScope::Outbound
            } else {
                FieldScope::Nested
            };
            for value in values {
                check_fields(value, element_scope)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_privileged_file_service_and_listener_escape() {
        for config in [
            r#"{"services":[],"inbounds":[{"type":"tun"}]}"#,
            r#"{"inbounds":[{"type":"tun"}],"outbounds":[{"type":"naive","tls":{"certificate_path":"/etc/shadow"}}]}"#,
            r#"{"inbounds":[{"type":"tun"},{"type":"mixed","listen":"0.0.0.0"}]}"#,
            r#"{"inbounds":[{"type":"tun"}],"experimental":{"clash_api":{"external_controller":"0.0.0.0:9090"}}}"#,
            r#"{"log":{"output":"/etc/shadow"},"inbounds":[{"type":"tun"}]}"#,
        ] {
            assert!(validate(config.as_bytes()).is_err());
        }
    }
    #[test]
    fn accepts_in_memory_tun_with_uot() {
        assert!(validate(br#"{"log":{"output":""},"inbounds":[{"type":"tun","interface_name":"topnode0","auto_route":true}],"outbounds":[{"type":"naive","udp_over_tcp":{"enabled":true,"version":2},"tls":{"enabled":true,"certificate":["PEM"]}}],"experimental":{"clash_api":{"external_controller":"127.0.0.1:49152"}}}"#).is_ok());
    }

    #[test]
    fn accepts_xhttp_route_paths_but_rejects_filesystem_paths() {
        let fixture = include_bytes!("../../../scripts/tests/fixtures/sing-box-acp-protocols.json");
        assert!(validate(fixture).is_ok());
        let mut document: Value = serde_json::from_slice(fixture).unwrap();
        document["route"]["rule_set"] =
            serde_json::json!([{"tag":"local","type":"local","path":"/etc/shadow"}]);
        assert!(validate(&serde_json::to_vec(&document).unwrap()).is_err());
    }
}
