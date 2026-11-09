use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, SocketAddrV4},
};

use serde_json::{Map, Value};
use topnode_domain::{ConnectionPreferences, EngineError, RouteMode};

const DETOUR_FIELDS: [&str; 2] = ["detour", "download_detour"];
const SNIFF_ROUTING_ACTION: &str = "sniff";
const DNS_PROTOCOL: &str = "dns";
const LOCAL_DIRECT_OUTBOUND_TAG: &str = "__topnode_local_direct";
const LOCALHOST_DOMAIN: &str = "localhost";
const LOCAL_IPV4_CIDRS: [&str; 4] = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
];
const PRIVATE_RULE_SET_TAGS: [&str; 2] = ["geoip-private", "geosite-private"];
const DESTINATION_MATCHER_FIELDS: [&str; 9] = [
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "geosite",
    "geoip",
    "ip_cidr",
    "ip_is_private",
    "rule_set",
];
const VLESS_OUTBOUND_TYPE: &str = "vless";
const RUNTIME_NODE_TAG_PREFIX: &str = "tn-endpoint-";
const LOCAL_MIXED_INBOUND_TAG: &str = "__topnode_system_proxy";

const PRIVATE_RULE_SET_SPECS: [PrivateRuleSetSpec; 2] = [
    PrivateRuleSetSpec {
        tag: "geoip-private",
        url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/private.srs",
        update_interval: "720h",
    },
    PrivateRuleSetSpec {
        tag: "geosite-private",
        url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/private.srs",
        update_interval: "120h",
    },
];

#[derive(Clone, Copy)]
struct PrivateRuleSetSpec {
    tag: &'static str,
    url: &'static str,
    update_interval: &'static str,
}

/// Applies client-local policy transforms to an opaque rt1 payload.
///
/// This is deliberately an engine-boundary operation. The application and UI
/// continue to treat the server document as opaque.
///
/// # Errors
///
/// Returns [`EngineError::InvalidConfiguration`] when the payload is not a JSON
/// object or a targeted sing-box field has an incompatible shape.
pub(crate) fn normalize(
    payload: &str,
    preferences: &ConnectionPreferences,
) -> Result<String, EngineError> {
    let Value::Object(document) = serde_json::from_str::<Value>(payload)
        .map_err(|error| invalid_configuration(format!("JSON 解析失败：{error}")))?
    else {
        return Err(invalid_configuration("根节点必须是 JSON 对象"));
    };

    let original = document.clone();
    let empty_direct_tags = empty_direct_outbound_tags(&document)?;
    let mut normalized = if empty_direct_tags.is_empty() {
        document
    } else {
        let Value::Object(document) =
            remove_redundant_direct_detours(Value::Object(document), &empty_direct_tags)
        else {
            unreachable!("an object normalizes to an object");
        };
        document
    };

    normalized = apply_tun_policy(normalized, preferences.tun_enabled)?;
    normalized = apply_local_lan_rule_sets(normalized, preferences.bypass_lan)?;
    if preferences.bypass_lan || !preferences.udp_forwarding_enabled {
        normalized = add_local_direct_routes(
            normalized,
            preferences.bypass_lan,
            !preferences.udp_forwarding_enabled,
        )?;
    }
    normalized = apply_local_multiplex_policy(normalized, preferences.multiplex_enabled)?;
    use_tcp_dns_for_naive_detours(&mut normalized);

    if normalized == original {
        Ok(payload.to_owned())
    } else {
        serde_json::to_string(&Value::Object(normalized))
            .map_err(|error| invalid_configuration(format!("JSON 序列化失败：{error}")))
    }
}

fn use_tcp_dns_for_naive_detours(document: &mut Map<String, Value>) {
    let Some(outbounds) = document.get("outbounds").and_then(Value::as_array) else {
        return;
    };
    let mut parent_groups = HashMap::<&str, Vec<&str>>::new();
    let mut pending = Vec::new();
    for outbound in outbounds {
        let Some(tag) = outbound["tag"].as_str() else {
            continue;
        };
        match outbound["type"].as_str() {
            Some("naive") => {
                let uot = &outbound["udp_over_tcp"];
                if uot.as_bool() != Some(true) && uot["enabled"].as_bool() != Some(true) {
                    pending.push(tag);
                }
            }
            Some("selector" | "urltest") => {
                if let Some(members) = outbound["outbounds"].as_array() {
                    for member in members.iter().filter_map(Value::as_str) {
                        parent_groups.entry(member).or_default().push(tag);
                    }
                }
            }
            _ => {}
        }
    }

    // A selector can restore a cached choice, so account for any member
    // that can make UDP DNS fail. Preserve the configured resolver and detour.
    let mut tcp_dns_detours = HashSet::new();
    while let Some(tag) = pending.pop() {
        if tcp_dns_detours.insert(tag.to_owned())
            && let Some(parents) = parent_groups.get(tag)
        {
            pending.extend(parents);
        }
    }
    let Some(servers) = document
        .get_mut("dns")
        .and_then(|dns| dns.get_mut("servers"))
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    for server in servers {
        if server["type"] == "udp"
            && server["detour"]
                .as_str()
                .is_some_and(|tag| tcp_dns_detours.contains(tag))
        {
            server["type"] = Value::String("tcp".to_owned());
        }
    }
}

/// Adds the private Clash-compatible control plane used to prove sidecar
/// readiness. The server-provided Clash API object is replaced wholesale so it
/// cannot retain a public listener, external UI, or a server-selected secret.
///
/// This remains an engine-boundary transform: callers above the sidecar keep
/// treating the Panel payload as opaque.
pub(crate) fn normalize_with_local_clash_api(
    payload: &str,
    preferences: &ConnectionPreferences,
    controller: SocketAddrV4,
    secret: &str,
    system_proxy: Option<SocketAddrV4>,
) -> Result<String, EngineError> {
    if controller.ip() != &Ipv4Addr::LOCALHOST || controller.port() == 0 {
        return Err(invalid_configuration(
            "Clash API 必须使用 127.0.0.1 的非零端口",
        ));
    }
    if !(32..=128).contains(&secret.len())
        || !secret
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid_configuration("Clash API secret 格式无效"));
    }
    match (preferences.tun_enabled, system_proxy) {
        (true, Some(_)) => {
            return Err(invalid_configuration("TUN 模式不应同时配置系统代理入口"));
        }
        (false, None) => {
            return Err(invalid_configuration("普通代理模式缺少本机 Mixed 入口"));
        }
        (_, Some(endpoint)) if endpoint.ip() != &Ipv4Addr::LOCALHOST || endpoint.port() == 0 => {
            return Err(invalid_configuration(
                "系统代理入口必须使用 127.0.0.1 的非零端口",
            ));
        }
        _ => {}
    }

    let normalized = normalize(payload, preferences)?;
    let Value::Object(mut document) = serde_json::from_str::<Value>(&normalized)
        .map_err(|error| invalid_configuration(format!("JSON 解析失败：{error}")))?
    else {
        unreachable!("normalize only returns a JSON object");
    };
    document = replace_local_proxy_inbounds(document, system_proxy)?;

    // The Panel document must not choose a disk output path or inherit
    // sing-box's very verbose default trace level. Runtime streams are drained
    // separately and remain debug-only in the desktop logger.
    document.insert(
        "log".to_owned(),
        serde_json::json!({
            "disabled": false,
            "level": "warn",
            "output": "",
            "timestamp": true
        }),
    );

    let experimental = match document.get_mut("experimental") {
        Some(Value::Object(experimental)) => experimental,
        Some(_) => {
            return Err(invalid_configuration("experimental 必须是 JSON 对象"));
        }
        None => {
            document.insert("experimental".to_owned(), Value::Object(Map::new()));
            document
                .get_mut("experimental")
                .and_then(Value::as_object_mut)
                .expect("inserted experimental object")
        }
    };
    let origin = format!("http://{controller}");
    if cfg!(unix) && preferences.tun_enabled {
        // Privileged helpers must not create server-selected persistent files.
        experimental.insert(
            "cache_file".to_owned(),
            serde_json::json!({"enabled": false}),
        );
    }
    let default_mode = match preferences.route_mode {
        RouteMode::Rule => "Rule",
        RouteMode::Global => "Global",
    };
    experimental.insert(
        "clash_api".to_owned(),
        serde_json::json!({
            "external_controller": controller.to_string(),
            "secret": secret,
            "default_mode": default_mode,
            "access_control_allow_origin": [origin],
            "access_control_allow_private_network": false
        }),
    );

    serde_json::to_string(&Value::Object(document))
        .map_err(|error| invalid_configuration(format!("JSON 序列化失败：{error}")))
}

fn replace_local_proxy_inbounds(
    mut document: Map<String, Value>,
    endpoint: Option<SocketAddrV4>,
) -> Result<Map<String, Value>, EngineError> {
    let server_inbounds = array_field(&document, "inbounds")?
        .cloned()
        .unwrap_or_default();
    if server_inbounds
        .iter()
        .filter_map(inbound_tag)
        .any(|tag| tag == LOCAL_MIXED_INBOUND_TAG)
    {
        return Err(invalid_configuration(
            "服务端配置使用了客户端保留的入口标识",
        ));
    }

    let mut removed_inbounds = server_inbounds
        .iter()
        .filter(|inbound| matches!(inbound_type(inbound), Some("mixed" | "socks")))
        .cloned()
        .collect::<Vec<_>>();
    let mut retained_inbounds = server_inbounds
        .into_iter()
        .filter(|inbound| !matches!(inbound_type(inbound), Some("mixed" | "socks")))
        .collect::<Vec<_>>();

    loop {
        let unavailable_tags = unavailable_inbound_tags(&removed_inbounds, &retained_inbounds);
        let mut next_retained = Vec::with_capacity(retained_inbounds.len());
        let mut removed_dependency = false;
        for inbound in retained_inbounds {
            let depends_on_removed_inbound = inbound
                .as_object()
                .and_then(|inbound| inbound.get("detour"))
                .and_then(Value::as_str)
                .is_some_and(|detour| unavailable_tags.contains(detour));
            if depends_on_removed_inbound {
                removed_inbounds.push(inbound);
                removed_dependency = true;
            } else {
                next_retained.push(inbound);
            }
        }
        retained_inbounds = next_retained;
        if !removed_dependency {
            break;
        }
    }

    let unavailable_tags = unavailable_inbound_tags(&removed_inbounds, &retained_inbounds);
    remove_rule_inbound_references(&mut document, "route", &unavailable_tags)?;
    remove_rule_inbound_references(&mut document, "dns", &unavailable_tags)?;
    remove_v2ray_stats_inbound_references(&mut document, &unavailable_tags)?;

    if let Some(endpoint) = endpoint {
        retained_inbounds.push(serde_json::json!({
            "type": "mixed",
            "tag": LOCAL_MIXED_INBOUND_TAG,
            "listen": endpoint.ip().to_string(),
            "listen_port": endpoint.port()
        }));
    }
    document.insert("inbounds".to_owned(), Value::Array(retained_inbounds));
    Ok(document)
}

fn invalid_configuration(message: impl Into<String>) -> EngineError {
    EngineError::InvalidConfiguration(message.into())
}

fn array_field<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<Option<&'a Vec<Value>>, EngineError> {
    match object.get(field) {
        None => Ok(None),
        Some(Value::Array(values)) => Ok(Some(values)),
        Some(_) => Err(invalid_configuration(format!("{field} 必须是 JSON 数组"))),
    }
}

fn object_field<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<Option<&'a Map<String, Value>>, EngineError> {
    match object.get(field) {
        None => Ok(None),
        Some(Value::Object(value)) => Ok(Some(value)),
        Some(_) => Err(invalid_configuration(format!("{field} 必须是 JSON 对象"))),
    }
}

fn apply_tun_policy(
    mut document: Map<String, Value>,
    enabled: bool,
) -> Result<Map<String, Value>, EngineError> {
    if enabled {
        #[cfg(target_os = "linux")]
        let managed_name = "topnode0";
        #[cfg(target_os = "macos")]
        let managed_name = "utun";
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(inbounds) = document.get_mut("inbounds").and_then(Value::as_array_mut) {
            for inbound in inbounds
                .iter_mut()
                .filter(|item| inbound_type(item) == Some("tun"))
            {
                inbound["interface_name"] = Value::String(managed_name.to_owned());
            }
        }
        return Ok(document);
    }
    let Some(server_inbounds) = array_field(&document, "inbounds")?.cloned() else {
        return Ok(document);
    };

    let mut removed_inbounds = server_inbounds
        .iter()
        .filter(|inbound| inbound_type(inbound) == Some("tun"))
        .cloned()
        .collect::<Vec<_>>();
    if removed_inbounds.is_empty() {
        return Ok(document);
    }

    let mut retained_inbounds = server_inbounds
        .into_iter()
        .filter(|inbound| inbound_type(inbound) != Some("tun"))
        .collect::<Vec<_>>();
    loop {
        let unavailable_tags = unavailable_inbound_tags(&removed_inbounds, &retained_inbounds);
        let mut next_retained = Vec::with_capacity(retained_inbounds.len());
        let mut removed_dependency = false;
        for inbound in retained_inbounds {
            let depends_on_removed_inbound = inbound
                .as_object()
                .and_then(|inbound| inbound.get("detour"))
                .and_then(Value::as_str)
                .is_some_and(|detour| unavailable_tags.contains(detour));
            if depends_on_removed_inbound {
                removed_inbounds.push(inbound);
                removed_dependency = true;
            } else {
                next_retained.push(inbound);
            }
        }
        retained_inbounds = next_retained;
        if !removed_dependency {
            break;
        }
    }

    let unavailable_tags = unavailable_inbound_tags(&removed_inbounds, &retained_inbounds);
    document.insert("inbounds".to_owned(), Value::Array(retained_inbounds));
    remove_rule_inbound_references(&mut document, "route", &unavailable_tags)?;
    remove_rule_inbound_references(&mut document, "dns", &unavailable_tags)?;
    remove_v2ray_stats_inbound_references(&mut document, &unavailable_tags)?;
    Ok(document)
}

fn inbound_type(inbound: &Value) -> Option<&str> {
    inbound
        .as_object()
        .and_then(|inbound| inbound.get("type"))
        .and_then(Value::as_str)
}

fn inbound_tag(inbound: &Value) -> Option<&str> {
    inbound
        .as_object()
        .and_then(|inbound| inbound.get("tag"))
        .and_then(Value::as_str)
        .filter(|tag| !tag.trim().is_empty())
}

fn unavailable_inbound_tags(
    removed_inbounds: &[Value],
    retained_inbounds: &[Value],
) -> HashSet<String> {
    let retained_tags = retained_inbounds
        .iter()
        .filter_map(inbound_tag)
        .collect::<HashSet<_>>();
    removed_inbounds
        .iter()
        .filter_map(inbound_tag)
        .filter(|tag| !retained_tags.contains(tag))
        .map(str::to_owned)
        .collect()
}

fn remove_rule_inbound_references(
    document: &mut Map<String, Value>,
    section_name: &str,
    unavailable_tags: &HashSet<String>,
) -> Result<(), EngineError> {
    let Some(section) = document.get_mut(section_name) else {
        return Ok(());
    };
    let Value::Object(section) = section else {
        return Err(invalid_configuration(format!(
            "{section_name} 必须是 JSON 对象"
        )));
    };
    let Some(rules) = section.get_mut("rules") else {
        return Ok(());
    };
    let Value::Array(rules) = rules else {
        return Err(invalid_configuration(format!(
            "{section_name}.rules 必须是 JSON 数组"
        )));
    };
    *rules = rules
        .drain(..)
        .filter_map(|rule| remove_rule_inbound_reference(rule, unavailable_tags))
        .collect();
    Ok(())
}

fn remove_rule_inbound_reference(rule: Value, unavailable_tags: &HashSet<String>) -> Option<Value> {
    let Value::Object(mut rule) = rule else {
        return Some(rule);
    };

    if let Some(inbound) = rule.get("inbound").cloned() {
        match without_unavailable_inbound_tags(inbound, unavailable_tags) {
            InboundReference::Unchanged => {}
            InboundReference::Retained(inbound) => {
                rule.insert("inbound".to_owned(), inbound);
            }
            InboundReference::Unavailable => return None,
        }
    }

    if let Some(Value::Array(children)) = rule.get_mut("rules") {
        let original_length = children.len();
        let normalized = children
            .drain(..)
            .filter_map(|child| remove_rule_inbound_reference(child, unavailable_tags))
            .collect::<Vec<_>>();
        // Removing one branch can invert or broaden a logical matcher. Drop the
        // complete parent instead of guessing at server-authored rule semantics.
        if normalized.len() != original_length {
            return None;
        }
        *children = normalized;
    }
    Some(Value::Object(rule))
}

enum InboundReference {
    Unchanged,
    Retained(Value),
    Unavailable,
}

fn without_unavailable_inbound_tags(
    inbound: Value,
    unavailable_tags: &HashSet<String>,
) -> InboundReference {
    match inbound {
        Value::String(tag) if unavailable_tags.contains(&tag) => InboundReference::Unavailable,
        Value::Array(tags) => {
            let original_length = tags.len();
            let tags = tags
                .into_iter()
                .filter(|tag| {
                    !tag.as_str()
                        .is_some_and(|tag| unavailable_tags.contains(tag))
                })
                .collect::<Vec<_>>();
            if tags.len() == original_length {
                InboundReference::Unchanged
            } else if tags.is_empty() {
                InboundReference::Unavailable
            } else {
                InboundReference::Retained(Value::Array(tags))
            }
        }
        _ => InboundReference::Unchanged,
    }
}

fn remove_v2ray_stats_inbound_references(
    document: &mut Map<String, Value>,
    unavailable_tags: &HashSet<String>,
) -> Result<(), EngineError> {
    let Some(experimental) = document.get_mut("experimental") else {
        return Ok(());
    };
    let Value::Object(experimental) = experimental else {
        return Err(invalid_configuration("experimental 必须是 JSON 对象"));
    };
    let Some(v2ray_api) = experimental.get_mut("v2ray_api") else {
        return Ok(());
    };
    let Value::Object(v2ray_api) = v2ray_api else {
        return Err(invalid_configuration(
            "experimental.v2ray_api 必须是 JSON 对象",
        ));
    };
    let Some(stats) = v2ray_api.get_mut("stats") else {
        return Ok(());
    };
    let Value::Object(stats) = stats else {
        return Err(invalid_configuration(
            "experimental.v2ray_api.stats 必须是 JSON 对象",
        ));
    };
    let Some(inbounds) = stats.get_mut("inbounds") else {
        return Ok(());
    };
    let Value::Array(inbounds) = inbounds else {
        return Err(invalid_configuration(
            "experimental.v2ray_api.stats.inbounds 必须是 JSON 数组",
        ));
    };
    inbounds.retain(|tag| {
        !tag.as_str()
            .is_some_and(|tag| unavailable_tags.contains(tag))
    });
    Ok(())
}

fn empty_direct_outbound_tags(
    document: &Map<String, Value>,
) -> Result<HashSet<String>, EngineError> {
    Ok(array_field(document, "outbounds")?
        .into_iter()
        .flatten()
        .filter_map(empty_direct_outbound_tag)
        .collect())
}

fn empty_direct_outbound_tag(element: &Value) -> Option<String> {
    let Value::Object(outbound) = element else {
        return None;
    };
    if outbound.get("type").and_then(Value::as_str) != Some("direct")
        || outbound.keys().any(|key| key != "type" && key != "tag")
    {
        return None;
    }
    outbound
        .get("tag")
        .and_then(Value::as_str)
        .filter(|tag| !tag.trim().is_empty())
        .map(str::to_owned)
}

fn remove_redundant_direct_detours(element: Value, empty_direct_tags: &HashSet<String>) -> Value {
    match element {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .filter_map(|(key, value)| {
                    let redundant = DETOUR_FIELDS.contains(&key.as_str())
                        && value
                            .as_str()
                            .is_some_and(|tag| empty_direct_tags.contains(tag));
                    (!redundant).then(|| {
                        (
                            key,
                            remove_redundant_direct_detours(value, empty_direct_tags),
                        )
                    })
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(|value| remove_redundant_direct_detours(value, empty_direct_tags))
                .collect(),
        ),
        primitive => primitive,
    }
}

fn apply_local_multiplex_policy(
    mut document: Map<String, Value>,
    enabled: bool,
) -> Result<Map<String, Value>, EngineError> {
    let Some(outbounds) = array_field(&document, "outbounds")? else {
        return Ok(document);
    };
    let mut changed = false;
    let normalized = outbounds
        .iter()
        .map(|element| {
            let Value::Object(outbound) = element else {
                return element.clone();
            };
            if !is_runtime_vless_outbound(outbound) {
                return element.clone();
            }

            let mut outbound = outbound.clone();
            if enabled {
                let mut multiplex = outbound
                    .get("multiplex")
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                multiplex.insert("enabled".to_owned(), Value::Bool(true));
                outbound.insert("multiplex".to_owned(), Value::Object(multiplex));
            } else {
                outbound.remove("multiplex");
            }
            let next = Value::Object(outbound);
            changed |= next != *element;
            next
        })
        .collect();
    if changed {
        document.insert("outbounds".to_owned(), Value::Array(normalized));
    }
    Ok(document)
}

fn is_runtime_vless_outbound(outbound: &Map<String, Value>) -> bool {
    outbound.get("type").and_then(Value::as_str) == Some(VLESS_OUTBOUND_TYPE)
        && outbound
            .get("tag")
            .and_then(Value::as_str)
            .is_some_and(|tag| tag.starts_with(RUNTIME_NODE_TAG_PREFIX))
}

fn apply_local_lan_rule_sets(
    mut document: Map<String, Value>,
    enabled: bool,
) -> Result<Map<String, Value>, EngineError> {
    let original_route = object_field(&document, "route")?.cloned();
    if original_route.is_none() && !enabled {
        return Ok(document);
    }
    let mut route = original_route.clone().unwrap_or_default();
    let direct_outbound_tags = direct_outbound_tags(&document)?;
    let server_rules = array_field(&route, "rules")?
        .into_iter()
        .flatten()
        .filter_map(|rule| strip_private_direct_matchers(rule, &direct_outbound_tags))
        .collect();
    route.insert("rules".to_owned(), Value::Array(server_rules));

    route = if enabled {
        let fallback = private_rule_set_download_detour(&document, &route)?;
        upsert_private_rule_sets(route, fallback.as_ref())?
    } else {
        remove_unused_private_rule_sets(&document, route)?
    };

    if original_route.as_ref() != Some(&route) {
        document.insert("route".to_owned(), Value::Object(route));
    }
    Ok(document)
}

fn direct_outbound_tags(document: &Map<String, Value>) -> Result<HashSet<String>, EngineError> {
    Ok(array_field(document, "outbounds")?
        .into_iter()
        .flatten()
        .filter_map(|element| {
            let outbound = element.as_object()?;
            (outbound.get("type").and_then(Value::as_str) == Some("direct"))
                .then(|| {
                    outbound
                        .get("tag")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .flatten()
        })
        .collect())
}

fn strip_private_direct_matchers(
    element: &Value,
    direct_outbound_tags: &HashSet<String>,
) -> Option<Value> {
    let Some(rule) = element.as_object() else {
        return Some(element.clone());
    };
    let outbound = rule.get("outbound").and_then(Value::as_str);
    if !outbound.is_some_and(|tag| direct_outbound_tags.contains(tag)) {
        return Some(element.clone());
    }
    if outbound.is_some_and(is_local_direct_outbound_tag) && is_client_lan_fallback_rule(rule) {
        return None;
    }

    let mut normalized = rule.clone();
    let mut changed = false;
    if normalized
        .get("ip_is_private")
        .is_some_and(primitive_is_true)
    {
        normalized.remove("ip_is_private");
        changed = true;
    }
    if let Some(rule_set) = normalized.get("rule_set").cloned() {
        let next = without_private_rule_set_tags(rule_set);
        if normalized.get("rule_set") != next.as_ref() {
            changed = true;
            if let Some(next) = next {
                normalized.insert("rule_set".to_owned(), next);
            } else {
                normalized.remove("rule_set");
            }
        }
    }

    if !changed {
        Some(element.clone())
    } else if has_destination_matcher(&normalized) {
        Some(Value::Object(normalized))
    } else {
        None
    }
}

fn primitive_is_true(value: &Value) -> bool {
    matches!(value, Value::Bool(true)) || value.as_str() == Some("true")
}

fn is_client_lan_fallback_rule(rule: &Map<String, Value>) -> bool {
    contains_string(rule.get("domain"), LOCALHOST_DOMAIN)
        || PRIVATE_RULE_SET_TAGS
            .iter()
            .any(|tag| contains_string(rule.get("rule_set"), tag))
}

fn contains_string(value: Option<&Value>, expected: &str) -> bool {
    match value {
        Some(Value::String(value)) => value == expected,
        Some(Value::Array(values)) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

fn without_private_rule_set_tags(value: Value) -> Option<Value> {
    match value {
        Value::String(tag) if is_private_rule_set_tag(&tag) => None,
        Value::Array(tags) => {
            let tags: Vec<_> = tags
                .into_iter()
                .filter(|tag| !tag.as_str().is_some_and(is_private_rule_set_tag))
                .collect();
            (!tags.is_empty()).then_some(Value::Array(tags))
        }
        other => Some(other),
    }
}

fn is_private_rule_set_tag(tag: &str) -> bool {
    PRIVATE_RULE_SET_TAGS.contains(&tag)
}

fn has_destination_matcher(rule: &Map<String, Value>) -> bool {
    DESTINATION_MATCHER_FIELDS
        .iter()
        .filter_map(|field| rule.get(*field))
        .any(matcher_has_value)
}

fn matcher_has_value(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(_) | Value::Object(_) => true,
        Value::String(value) => !value.is_empty() && value != "false",
        Value::Array(values) => !values.is_empty(),
    }
}

fn upsert_private_rule_sets(
    mut route: Map<String, Value>,
    fallback_download_detour: Option<&Value>,
) -> Result<Map<String, Value>, EngineError> {
    let existing = array_field(&route, "rule_set")?
        .cloned()
        .unwrap_or_default();
    let mut existing_by_tag = HashMap::new();
    for element in &existing {
        let Some(definition) = element.as_object() else {
            continue;
        };
        let Some(tag) = definition.get("tag").and_then(Value::as_str) else {
            continue;
        };
        existing_by_tag.insert(tag.to_owned(), definition.clone());
    }

    let mut normalized: Vec<Value> = existing
        .into_iter()
        .filter(|element| {
            !element
                .as_object()
                .and_then(|definition| definition.get("tag"))
                .and_then(Value::as_str)
                .is_some_and(is_private_rule_set_tag)
        })
        .collect();
    normalized.extend(PRIVATE_RULE_SET_SPECS.map(|spec| {
        private_rule_set_definition(
            spec,
            existing_by_tag.get(spec.tag),
            fallback_download_detour,
        )
    }));
    route.insert("rule_set".to_owned(), Value::Array(normalized));
    Ok(route)
}

fn private_rule_set_definition(
    spec: PrivateRuleSetSpec,
    existing: Option<&Map<String, Value>>,
    fallback_download_detour: Option<&Value>,
) -> Value {
    let mut definition = Map::new();
    definition.insert("tag".to_owned(), Value::String(spec.tag.to_owned()));
    definition.insert("type".to_owned(), Value::String("remote".to_owned()));
    definition.insert("format".to_owned(), Value::String("binary".to_owned()));
    definition.insert("url".to_owned(), Value::String(spec.url.to_owned()));
    definition.insert(
        "update_interval".to_owned(),
        Value::String(spec.update_interval.to_owned()),
    );
    existing
        .and_then(|definition| definition.get("download_detour"))
        .or(fallback_download_detour)
        .cloned()
        .map(|detour| definition.insert("download_detour".to_owned(), detour));
    Value::Object(definition)
}

fn private_rule_set_download_detour(
    document: &Map<String, Value>,
    route: &Map<String, Value>,
) -> Result<Option<Value>, EngineError> {
    if let Some(detour) = array_field(route, "rule_set")?
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .find_map(|definition| definition.get("download_detour").cloned())
    {
        return Ok(Some(detour));
    }
    Ok(array_field(document, "outbounds")?
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .find(|outbound| outbound.get("type").and_then(Value::as_str) == Some("selector"))
        .and_then(|outbound| outbound.get("tag").cloned()))
}

fn remove_unused_private_rule_sets(
    document: &Map<String, Value>,
    mut route: Map<String, Value>,
) -> Result<Map<String, Value>, EngineError> {
    let Some(definitions) = array_field(&route, "rule_set")?.cloned() else {
        return Ok(route);
    };
    let mut document_without_definitions = document.clone();
    let mut route_without_definitions = route.clone();
    route_without_definitions.remove("rule_set");
    document_without_definitions
        .insert("route".to_owned(), Value::Object(route_without_definitions));

    let mut referenced_tags = HashSet::new();
    collect_rule_set_references(
        &Value::Object(document_without_definitions),
        &mut referenced_tags,
    );
    let normalized: Vec<_> = definitions
        .into_iter()
        .filter(|element| {
            let tag = element
                .as_object()
                .and_then(|definition| definition.get("tag"))
                .and_then(Value::as_str);
            !tag.is_some_and(|tag| is_private_rule_set_tag(tag) && !referenced_tags.contains(tag))
        })
        .collect();
    if normalized.is_empty() {
        route.remove("rule_set");
    } else {
        route.insert("rule_set".to_owned(), Value::Array(normalized));
    }
    Ok(route)
}

fn collect_rule_set_references(element: &Value, destination: &mut HashSet<String>) {
    match element {
        Value::Object(object) => {
            for (key, value) in object {
                if key == "rule_set" {
                    collect_strings(value, destination);
                } else {
                    collect_rule_set_references(value, destination);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_rule_set_references(value, destination);
            }
        }
        _ => {}
    }
}

fn collect_strings(element: &Value, destination: &mut HashSet<String>) {
    match element {
        Value::String(value) => {
            destination.insert(value.clone());
        }
        Value::Array(values) => {
            for value in values {
                collect_strings(value, destination);
            }
        }
        _ => {}
    }
}

fn add_local_direct_routes(
    mut document: Map<String, Value>,
    bypass_lan_enabled: bool,
    udp_direct_enabled: bool,
) -> Result<Map<String, Value>, EngineError> {
    let outbounds = array_field(&document, "outbounds")?
        .cloned()
        .unwrap_or_default();
    let endpoints = array_field(&document, "endpoints")?
        .cloned()
        .unwrap_or_default();
    let existing_local_direct_tag = outbounds.iter().find_map(local_direct_outbound_tag);
    let direct_tag = existing_local_direct_tag
        .clone()
        .unwrap_or_else(|| available_local_direct_tag(&outbounds, &endpoints));
    let normalized_outbounds = if existing_local_direct_tag.is_some() {
        outbounds
    } else {
        let mut normalized = outbounds;
        normalized.push(local_direct_outbound(&direct_tag));
        normalized
    };

    let mut local_rules = Vec::with_capacity(2);
    if bypass_lan_enabled {
        local_rules.push(local_lan_rule(&direct_tag));
    }
    if udp_direct_enabled {
        local_rules.push(local_udp_rule(&direct_tag));
    }

    let mut route = object_field(&document, "route")?
        .cloned()
        .unwrap_or_default();
    let server_rules: Vec<_> = array_field(&route, "rules")?
        .into_iter()
        .flatten()
        .filter(|rule| !local_rules.contains(rule))
        .cloned()
        .collect();
    let dns_prefix_length = server_rules
        .iter()
        .position(|rule| !is_dns_routing_prelude(rule))
        .unwrap_or(server_rules.len());
    let mut normalized_rules = Vec::with_capacity(server_rules.len() + local_rules.len());
    normalized_rules.extend_from_slice(&server_rules[..dns_prefix_length]);
    normalized_rules.extend(local_rules);
    normalized_rules.extend_from_slice(&server_rules[dns_prefix_length..]);
    route.insert("rules".to_owned(), Value::Array(normalized_rules));

    document.insert("outbounds".to_owned(), Value::Array(normalized_outbounds));
    document.insert("route".to_owned(), Value::Object(route));
    Ok(document)
}

fn local_direct_outbound(tag: &str) -> Value {
    let mut outbound = Map::new();
    outbound.insert("type".to_owned(), Value::String("direct".to_owned()));
    outbound.insert("tag".to_owned(), Value::String(tag.to_owned()));
    Value::Object(outbound)
}

fn local_lan_rule(direct_tag: &str) -> Value {
    let mut rule = Map::new();
    rule.insert(
        "domain".to_owned(),
        Value::Array(vec![Value::String(LOCALHOST_DOMAIN.to_owned())]),
    );
    rule.insert(
        "ip_cidr".to_owned(),
        Value::Array(
            LOCAL_IPV4_CIDRS
                .iter()
                .map(|cidr| Value::String((*cidr).to_owned()))
                .collect(),
        ),
    );
    rule.insert("ip_is_private".to_owned(), Value::Bool(true));
    rule.insert(
        "rule_set".to_owned(),
        Value::Array(
            PRIVATE_RULE_SET_TAGS
                .iter()
                .map(|tag| Value::String((*tag).to_owned()))
                .collect(),
        ),
    );
    rule.insert("action".to_owned(), Value::String("route".to_owned()));
    rule.insert("outbound".to_owned(), Value::String(direct_tag.to_owned()));
    Value::Object(rule)
}

fn local_udp_rule(direct_tag: &str) -> Value {
    let mut rule = Map::new();
    rule.insert("network".to_owned(), Value::String("udp".to_owned()));
    rule.insert("outbound".to_owned(), Value::String(direct_tag.to_owned()));
    Value::Object(rule)
}

fn local_direct_outbound_tag(element: &Value) -> Option<String> {
    let outbound = element.as_object()?;
    if outbound.get("type").and_then(Value::as_str) != Some("direct")
        || outbound.keys().any(|key| key != "type" && key != "tag")
    {
        return None;
    }
    outbound
        .get("tag")
        .and_then(Value::as_str)
        .filter(|tag| !tag.trim().is_empty() && is_local_direct_outbound_tag(tag))
        .map(str::to_owned)
}

fn is_local_direct_outbound_tag(tag: &str) -> bool {
    if tag == LOCAL_DIRECT_OUTBOUND_TAG {
        return true;
    }
    let Some(suffix) = tag.strip_prefix(&format!("{LOCAL_DIRECT_OUTBOUND_TAG}_")) else {
        return false;
    };
    if !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    match suffix.as_bytes() {
        [digit] => matches!(digit, b'2'..=b'9'),
        [first, ..] => matches!(first, b'1'..=b'9'),
        [] => false,
    }
}

fn available_local_direct_tag(outbounds: &[Value], endpoints: &[Value]) -> String {
    let existing_tags: HashSet<_> = outbounds
        .iter()
        .chain(endpoints)
        .filter_map(Value::as_object)
        .filter_map(|value| value.get("tag"))
        .filter_map(Value::as_str)
        .collect();
    if !existing_tags.contains(LOCAL_DIRECT_OUTBOUND_TAG) {
        return LOCAL_DIRECT_OUTBOUND_TAG.to_owned();
    }
    let mut suffix = 2_u64;
    loop {
        let candidate = format!("{LOCAL_DIRECT_OUTBOUND_TAG}_{suffix}");
        if !existing_tags.contains(candidate.as_str()) {
            return candidate;
        }
        suffix = suffix.saturating_add(1);
    }
}

fn is_dns_routing_prelude(element: &Value) -> bool {
    let Some(rule) = element.as_object() else {
        return false;
    };
    if rule.get("action").and_then(Value::as_str) == Some(SNIFF_ROUTING_ACTION) {
        return true;
    }
    if rule.get("invert").is_some_and(primitive_is_true) {
        return false;
    }
    match rule.get("protocol") {
        Some(Value::String(protocol)) => protocol == DNS_PROTOCOL,
        Some(Value::Array(protocols)) => {
            !protocols.is_empty()
                && protocols
                    .iter()
                    .all(|protocol| protocol.as_str() == Some(DNS_PROTOCOL))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use serde_json::{Value, json};
    use topnode_domain::ConnectionPreferences;

    use super::{LOCAL_MIXED_INBOUND_TAG, normalize, normalize_with_local_clash_api};

    fn preferences() -> ConnectionPreferences {
        ConnectionPreferences {
            bypass_lan: false,
            ..ConnectionPreferences::default()
        }
    }

    fn normalized(payload: &str, preferences: &ConnectionPreferences) -> Value {
        serde_json::from_str(&normalize(payload, preferences).expect("configuration normalizes"))
            .expect("normalized JSON parses")
    }

    #[test]
    fn disabled_tun_removes_inbounds_and_every_safe_tag_reference() {
        let payload = r#"{
            "inbounds":[
                {"type":"tun","tag":"tun-main","auto_route":true},
                {"type":"tun","tag":"tun-secondary"},
                {"type":"mixed","tag":"mixed"},
                {"type":"socks","tag":"tun-dependent","detour":"tun-main"},
                {"type":"http","tag":"dependent-chain","detour":"tun-dependent"}
            ],
            "route":{"rules":[
                {"inbound":"tun-main","outbound":"proxy"},
                {"inbound":["tun-secondary","mixed"],"outbound":"proxy"},
                {"inbound":"dependent-chain","outbound":"proxy"},
                {"inbound":"mixed","outbound":"direct"},
                {"type":"logical","mode":"or","rules":[
                    {"inbound":"tun-main"},
                    {"domain":"example.com"}
                ],"outbound":"proxy"}
            ]},
            "dns":{"rules":[
                {"inbound":["tun-main","mixed"],"server":"local"},
                {"inbound":"tun-secondary","server":"remote"}
            ]},
            "experimental":{"v2ray_api":{"stats":{
                "enabled":true,
                "inbounds":["tun-main","mixed","dependent-chain"]
            }}}
        }"#;

        let document = normalized(payload, &preferences());

        assert_eq!(
            document["inbounds"],
            json!([{"type":"mixed","tag":"mixed"}])
        );
        assert_eq!(
            document["route"]["rules"],
            json!([
                {"inbound":["mixed"],"outbound":"proxy"},
                {"inbound":"mixed","outbound":"direct"}
            ])
        );
        assert_eq!(
            document["dns"]["rules"],
            json!([{"inbound":["mixed"],"server":"local"}])
        );
        assert_eq!(
            document["experimental"]["v2ray_api"]["stats"]["inbounds"],
            json!(["mixed"])
        );
    }

    #[test]
    fn enabled_tun_preserves_server_inbounds_and_references() {
        let payload = r#"{"inbounds":[{"type":"tun","tag":"tun-in","auto_route":true}],"route":{"rules":[{"inbound":"tun-in","outbound":"proxy"}]}}"#;
        let mut preferences = preferences();
        preferences.tun_enabled = true;

        assert_eq!(
            normalize(payload, &preferences).expect("configuration normalizes"),
            payload
        );
    }

    #[test]
    fn removes_only_detours_to_empty_direct_outbounds() {
        let payload = r#"{
            "dns":{"servers":[
                {"tag":"empty","detour":"direct"},
                {"tag":"configured","detour":"bound-direct"}
            ]},
            "outbounds":[
                {"type":"direct","tag":"direct"},
                {"type":"direct","tag":"bound-direct","bind_interface":"wlan0"}
            ]
        }"#;

        let document = normalized(payload, &preferences());
        let servers = document["dns"]["servers"].as_array().expect("DNS servers");
        assert!(servers[0].get("detour").is_none());
        assert_eq!(servers[1]["detour"], "bound-direct");
    }

    #[test]
    fn enabled_udp_keeps_server_routing_unchanged() {
        let payload = r#"{"outbounds":[{"type":"selector","tag":"proxy"}],"route":{"rules":[{"network":"udp","outbound":"proxy"}]}}"#;

        assert_eq!(
            normalize(payload, &preferences()).expect("normalizes"),
            payload
        );
    }

    #[test]
    fn lan_fallback_is_inserted_after_dns_and_canonicalizes_rule_sets() {
        let payload = r#"{
            "outbounds":[
                {"type":"selector","tag":"proxy"},
                {"type":"direct","tag":"direct"}
            ],
            "route":{
                "rules":[
                    {"action":"sniff"},
                    {"action":"hijack-dns","protocol":"dns"},
                    {"domain":["example.org"],"outbound":"proxy"}
                ],
                "rule_set":[{
                    "tag":"geoip-private","type":"local","format":"source",
                    "url":"wrong","download_detour":"proxy"
                }]
            }
        }"#;
        let mut preferences = preferences();
        preferences.bypass_lan = true;

        let document = normalized(payload, &preferences);
        let rules = document["route"]["rules"].as_array().expect("route rules");
        assert_eq!(rules[0]["action"], "sniff");
        assert_eq!(rules[1]["action"], "hijack-dns");
        assert_eq!(rules[2]["domain"], json!(["localhost"]));
        assert_eq!(
            rules[2]["ip_cidr"],
            json!([
                "127.0.0.0/8",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16"
            ])
        );
        assert_eq!(
            rules[2]["rule_set"],
            json!(["geoip-private", "geosite-private"])
        );
        assert_eq!(rules[2]["outbound"], "__topnode_local_direct");
        assert_eq!(rules[3]["domain"], json!(["example.org"]));

        let definitions = document["route"]["rule_set"]
            .as_array()
            .expect("rule-set definitions");
        assert_eq!(definitions.len(), 2);
        assert_eq!(definitions[0]["type"], "remote");
        assert_eq!(definitions[0]["format"], "binary");
        assert_eq!(definitions[0]["update_interval"], "720h");
        assert_eq!(definitions[0]["download_detour"], "proxy");
        assert_eq!(definitions[1]["update_interval"], "120h");
    }

    #[test]
    fn disabled_lan_strips_private_matchers_but_keeps_mainland_rules() {
        let payload = r#"{
            "outbounds":[{"type":"direct","tag":"direct"}],
            "route":{
                "rules":[
                    {"ip_is_private":true,"outbound":"direct"},
                    {"rule_set":["geosite-cn","geoip-cn","geoip-private","geosite-private"],"outbound":"direct"}
                ],
                "rule_set":[
                    {"tag":"geosite-cn"},
                    {"tag":"geoip-cn"},
                    {"tag":"geoip-private"},
                    {"tag":"geosite-private"}
                ]
            }
        }"#;

        let document = normalized(payload, &preferences());
        let rules = document["route"]["rules"].as_array().expect("route rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["rule_set"], json!(["geosite-cn", "geoip-cn"]));
        assert_eq!(
            document["route"]["rule_set"],
            json!([{"tag":"geosite-cn"}, {"tag":"geoip-cn"}])
        );
    }

    #[test]
    fn disabled_udp_inserts_direct_rule_before_server_rules() {
        let payload = r#"{
            "outbounds":[{"type":"selector","tag":"proxy"}],
            "route":{"rules":[
                {"action":"sniff"},
                {"protocol":"dns","action":"hijack-dns"},
                {"network":"udp","outbound":"proxy"}
            ]}
        }"#;
        let mut preferences = preferences();
        preferences.udp_forwarding_enabled = false;

        let document = normalized(payload, &preferences);
        let rules = document["route"]["rules"].as_array().expect("route rules");
        assert_eq!(
            rules[2],
            json!({"network":"udp","outbound":"__topnode_local_direct"})
        );
        assert_eq!(rules[3], json!({"network":"udp","outbound":"proxy"}));
        assert!(document["outbounds"].as_array().is_some_and(|outbounds| {
            outbounds.iter().any(|outbound| {
                outbound == &json!({"type":"direct","tag":"__topnode_local_direct"})
            })
        }));
    }

    #[test]
    fn local_direct_tag_avoids_outbound_and_endpoint_collisions() {
        let payload = r#"{
            "outbounds":[
                {"type":"selector","tag":"__topnode_local_direct"},
                {"type":"direct","tag":"__topnode_local_direct_2","bind_interface":"wlan0"}
            ],
            "endpoints":[{"type":"wireguard","tag":"__topnode_local_direct_3"}]
        }"#;
        let mut preferences = preferences();
        preferences.udp_forwarding_enabled = false;

        let document = normalized(payload, &preferences);
        let direct = document["outbounds"]
            .as_array()
            .expect("outbounds")
            .iter()
            .find(|outbound| {
                outbound
                    == &&json!({
                        "type":"direct",
                        "tag":"__topnode_local_direct_4"
                    })
            });
        assert!(direct.is_some());
        assert_eq!(
            document["route"]["rules"][0]["outbound"],
            "__topnode_local_direct_4"
        );
    }

    #[test]
    fn multiplex_only_changes_runtime_vless_outbounds() {
        let payload = r#"{"outbounds":[
            {"type":"vless","tag":"tn-endpoint-node-1"},
            {"type":"vless","tag":"tn-endpoint-node-2","multiplex":{"enabled":false,"protocol":"h2mux"}},
            {"type":"vless","tag":"server-vless","multiplex":{"enabled":false}},
            {"type":"trojan","tag":"tn-endpoint-node-3","multiplex":{"enabled":false}}
        ]}"#;
        let mut preferences = preferences();
        preferences.multiplex_enabled = true;

        let document = normalized(payload, &preferences);
        let outbounds = document["outbounds"].as_array().expect("outbounds");
        assert_eq!(outbounds[0]["multiplex"], json!({"enabled":true}));
        assert_eq!(
            outbounds[1]["multiplex"],
            json!({"enabled":true,"protocol":"h2mux"})
        );
        assert_eq!(outbounds[2]["multiplex"], json!({"enabled":false}));
        assert_eq!(outbounds[3]["multiplex"], json!({"enabled":false}));

        preferences.multiplex_enabled = false;
        let document = normalized(payload, &preferences);
        let outbounds = document["outbounds"].as_array().expect("outbounds");
        assert!(outbounds[0].get("multiplex").is_none());
        assert!(outbounds[1].get("multiplex").is_none());
        assert!(outbounds[2].get("multiplex").is_some());
        assert!(outbounds[3].get("multiplex").is_some());
    }

    #[test]
    fn preserves_acp_outbound_options_in_both_desktop_modes() {
        let fixture = include_str!("../../../scripts/tests/fixtures/sing-box-acp-protocols.json");
        let original: Value = serde_json::from_str(fixture).expect("ACP test configuration");
        let controller = "127.0.0.1:9090".parse().expect("controller address");
        let mixed = "127.0.0.1:2080".parse().expect("mixed address");
        for (tun_enabled, system_proxy) in [(false, Some(mixed)), (true, None)] {
            let preferences = ConnectionPreferences {
                tun_enabled,
                ..preferences()
            };
            let normalized = normalize_with_local_clash_api(
                fixture,
                &preferences,
                controller,
                "0123456789abcdefghijklmnopqrstuv",
                system_proxy,
            )
            .expect("ACP fixture should normalize");
            let normalized: Value = serde_json::from_str(&normalized).expect("normalized JSON");
            assert_eq!(normalized["outbounds"], original["outbounds"]);
        }
    }

    #[test]
    fn dns_uses_tcp_when_a_detour_can_select_tcp_only_naive() {
        let payload = r#"{
            "outbounds":[
                {"type":"naive","tag":"naive","quic":true},
                {"type":"naive","tag":"naive-uot","udp_over_tcp":{"enabled":true}},
                {"type":"vless","tag":"vless"},
                {"type":"urltest","tag":"auto","outbounds":["vless","naive"]},
                {"type":"selector","tag":"selected","default":"vless","outbounds":["vless","auto"]}
            ],
            "dns":{"servers":[
                {"type":"udp","tag":"remote","server":"192.0.2.53","server_port":5353,"detour":"selected"},
                {"type":"udp","tag":"naive-dns","server":"192.0.2.53","detour":"naive"},
                {"type":"udp","tag":"local","server":"192.0.2.54"},
                {"type":"udp","tag":"uot","server":"192.0.2.53","detour":"naive-uot"},
                {"type":"https","tag":"doh","server":"192.0.2.53","detour":"naive"}
            ]}
        }"#;
        let mut expected: Value = serde_json::from_str(payload).expect("original JSON");
        expected["dns"]["servers"][0]["type"] = json!("tcp");
        expected["dns"]["servers"][1]["type"] = json!("tcp");
        assert_eq!(normalized(payload, &preferences()), expected);
    }

    #[test]
    fn normalization_is_idempotent_for_fixed_preferences() {
        let payload = r#"{
            "outbounds":[{"type":"vless","tag":"tn-endpoint-node-1"}],
            "route":{"rules":[{"action":"sniff"}]}
        }"#;
        let mut preferences = preferences();
        preferences.bypass_lan = true;
        preferences.udp_forwarding_enabled = false;
        preferences.multiplex_enabled = true;

        let first = normalize(payload, &preferences).expect("first normalization");
        let second = normalize(&first, &preferences).expect("second normalization");
        assert_eq!(
            serde_json::from_str::<Value>(&first).expect("first JSON"),
            serde_json::from_str::<Value>(&second).expect("second JSON")
        );
    }

    #[test]
    fn udp_preference_preserves_naive_transport_uot_and_internal_dns() {
        for quic in [false, true] {
            let payload = json!({"outbounds":[
                {"type":"naive","tag":"naive","quic":quic,"udp_over_tcp":{"enabled":true,"version":2}},
                {"type":"hysteria2","tag":"hy2"},
                {"type":"selector","tag":"proxy","outbounds":["auto","cycle"]},
                {"type":"urltest","tag":"auto","outbounds":["naive","hy2"]},
                {"type":"selector","tag":"cycle","outbounds":["proxy"]}
            ],"dns":{"servers":[{"type":"udp","tag":"remote","server":"192.0.2.53","detour":"proxy"}]}});
            let mut prefs = preferences();
            prefs.udp_forwarding_enabled = false;
            let first = normalized(&payload.to_string(), &prefs);
            assert_eq!(first["outbounds"][0], payload["outbounds"][0]);
            assert_eq!(first["outbounds"][1], payload["outbounds"][1]);
            assert_eq!(first["dns"], payload["dns"]);
            assert_eq!(normalized(&first.to_string(), &prefs), first);
        }
    }

    #[test]
    fn rejects_non_object_and_malformed_target_fields() {
        assert!(normalize("[]", &preferences()).is_err());
        assert!(normalize(r#"{"outbounds":{}}"#, &preferences()).is_err());
    }

    #[test]
    fn local_clash_api_replaces_untrusted_controller_configuration() {
        let payload = r#"{
            "log": {
                "level": "trace",
                "output": "server-selected.log"
            },
            "experimental": {
                "cache_file": {"enabled": true},
                "clash_api": {
                    "external_controller": "0.0.0.0:9090",
                    "external_ui": "remote-dashboard",
                    "secret": "server-selected"
                }
            }
        }"#;
        let controller = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 43_217);
        let system_proxy = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 43_218);
        let secret = "abcdefghijklmnopqrstuvwxyzABCDEF0123456789_-";

        let normalized = normalize_with_local_clash_api(
            payload,
            &preferences(),
            controller,
            secret,
            Some(system_proxy),
        )
        .expect("injects private local endpoints");
        let document: Value = serde_json::from_str(&normalized).expect("valid JSON");
        let clash_api = &document["experimental"]["clash_api"];

        assert_eq!(clash_api["external_controller"], "127.0.0.1:43217");
        assert_eq!(clash_api["secret"], secret);
        assert_eq!(clash_api["default_mode"], "Rule");
        assert_eq!(
            clash_api["access_control_allow_origin"],
            json!(["http://127.0.0.1:43217"])
        );
        assert_eq!(clash_api["access_control_allow_private_network"], false);
        assert!(clash_api.get("external_ui").is_none());
        assert_eq!(document["experimental"]["cache_file"]["enabled"], true);
        assert_eq!(document["log"]["level"], "warn");
        assert_eq!(document["log"]["output"], "");
        assert_eq!(document["log"]["timestamp"], true);
        assert_eq!(document["inbounds"][0]["type"], "mixed");
        assert_eq!(document["inbounds"][0]["tag"], LOCAL_MIXED_INBOUND_TAG);
        assert_eq!(document["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(document["inbounds"][0]["listen_port"], 43_218);
    }

    #[test]
    fn local_clash_api_rejects_non_loopback_or_weak_credentials() {
        let valid_secret = "abcdefghijklmnopqrstuvwxyzABCDEF0123456789_-";
        assert!(
            normalize_with_local_clash_api(
                "{}",
                &preferences(),
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 9_090),
                valid_secret,
                Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9_091)),
            )
            .is_err()
        );
        assert!(
            normalize_with_local_clash_api(
                "{}",
                &preferences(),
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9_090),
                "short",
                Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9_091)),
            )
            .is_err()
        );
    }

    #[test]
    fn local_runtime_replaces_server_proxy_listeners_with_one_private_mixed_inbound() {
        let payload = r#"{
            "inbounds":[
                {"type":"socks","tag":"server-socks","listen":"0.0.0.0","listen_port":1080},
                {"type":"mixed","tag":"server-mixed","listen":"0.0.0.0","listen_port":8080}
            ],
            "route":{"rules":[
                {"inbound":"server-socks","outbound":"direct"},
                {"domain":"example.com","outbound":"direct"}
            ]}
        }"#;
        let controller = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 43_217);
        let proxy = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 43_218);
        let secret = "abcdefghijklmnopqrstuvwxyzABCDEF0123456789_-";

        let normalized = normalize_with_local_clash_api(
            payload,
            &preferences(),
            controller,
            secret,
            Some(proxy),
        )
        .expect("normalizes local proxy listeners");
        let document: Value = serde_json::from_str(&normalized).expect("valid JSON");
        let inbounds = document["inbounds"].as_array().expect("inbounds");
        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0]["tag"], LOCAL_MIXED_INBOUND_TAG);
        assert_eq!(inbounds[0]["listen"], "127.0.0.1");
        assert_eq!(inbounds[0]["listen_port"], 43_218);
        let rules = document["route"]["rules"].as_array().expect("rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["domain"], "example.com");
    }

    #[test]
    fn tun_runtime_removes_unused_server_proxy_listeners() {
        let payload = r#"{"inbounds":[
            {"type":"tun","tag":"tun-in"},
            {"type":"mixed","tag":"server-mixed","listen":"0.0.0.0","listen_port":8080}
        ]}"#;
        let mut tun_preferences = preferences();
        tun_preferences.tun_enabled = true;
        let normalized = normalize_with_local_clash_api(
            payload,
            &tun_preferences,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 43_217),
            "abcdefghijklmnopqrstuvwxyzABCDEF0123456789_-",
            None,
        )
        .expect("normalizes TUN runtime listeners");
        let document: Value = serde_json::from_str(&normalized).expect("valid JSON");
        let inbounds = document["inbounds"].as_array().expect("inbounds");
        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0]["type"], "tun");
    }
}
