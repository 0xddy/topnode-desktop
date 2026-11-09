//! Native qualification is bound to the exact installed core and its dependencies.
use std::{collections::BTreeSet, io::Read, path::Path};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use topnode_domain::EngineError;

const CAPABILITIES: [&str; 4] = [
    "https-uot-v2",
    "quic-uot-v2",
    "https-custom-ca-uot-v2",
    "quic-custom-ca-uot-v2",
];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NaiveCapabilities(BTreeSet<String>);

impl NaiveCapabilities {
    pub fn protocol_offers(&self) -> Vec<String> {
        self.0
            .iter()
            .map(|capability| {
                let transport = capability.split('-').next().unwrap_or_default();
                let trust = if capability.contains("-custom-ca-") {
                    ";custom-ca"
                } else {
                    ""
                };
                format!("naive;transport={transport};security=tls{trust};uot-v2")
            })
            .collect()
    }
}

#[derive(Deserialize)]
struct Qualification {
    schema_version: u32,
    core_version: String,
    core_commit: String,
    target: String,
    core_sha256: String,
    libraries: Vec<Library>,
    capabilities: BTreeSet<String>,
    results: Vec<NativeResult>,
}

#[derive(Deserialize)]
struct Library {
    file: String,
    sha256: String,
}

#[derive(Deserialize)]
#[allow(clippy::struct_excessive_bools)] // Independent externally recorded test outcomes.
struct NativeResult {
    capability: String,
    tcp: bool,
    udp_echo: bool,
    udp_dns: bool,
    negative_trust: bool,
    negative_auth: bool,
}

fn digest(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0; 65536];
    loop {
        let count = file.read(&mut buffer).ok()?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Some(format!("{:x}", digest.finalize()))
}

pub(crate) fn verified_capabilities(binary: &Path, probe: &str) -> NaiveCapabilities {
    load_qualification(binary, probe).unwrap_or_default()
}

fn load_qualification(binary: &Path, probe: &str) -> Option<NaiveCapabilities> {
    let directory = binary.parent()?;
    let report_path = directory.join("naive-validation.json");
    if std::fs::metadata(&report_path).ok()?.len() > 1024 * 1024 {
        return None;
    }
    let report: Qualification = serde_json::from_slice(&std::fs::read(report_path).ok()?).ok()?;
    let version = env!("TOPNODE_SING_BOX_ACP_VERSION");
    let commit = env!("TOPNODE_SING_BOX_ACP_COMMIT");
    if report.schema_version != 2
        || report.core_version != version
        || report.core_commit != commit
        || report.target != env!("TOPNODE_BUILD_TARGET")
        || !probe
            .lines()
            .any(|line| line == format!("Revision: {commit}"))
        || !probe
            .lines()
            .any(|line| line == format!("sing-box version {version}"))
        || !probe
            .lines()
            .filter_map(|line| line.strip_prefix("Tags: "))
            .any(|tags| tags.split(',').any(|tag| tag == "with_naive_outbound"))
        || digest(binary).as_deref() != Some(report.core_sha256.as_str())
    {
        return None;
    }
    let required_library = match std::env::consts::OS {
        "windows" => Some("libcronet.dll"),
        "linux" => Some("libcronet.so"),
        _ => None,
    };
    if required_library
        .is_some_and(|required| !report.libraries.iter().any(|lib| lib.file == required))
    {
        return None;
    }
    for library in &report.libraries {
        if library.file.is_empty()
            || library.file.contains(['/', '\\', ':'])
            || library.file.starts_with('.')
            || digest(&directory.join(&library.file)).as_deref() != Some(library.sha256.as_str())
        {
            return None;
        }
    }
    for capability in &report.capabilities {
        if !CAPABILITIES.contains(&capability.as_str())
            || !report.results.iter().any(|result| {
                &result.capability == capability
                    && result.tcp
                    && result.udp_echo
                    && result.udp_dns
                    && result.negative_trust
                    && result.negative_auth
            })
        {
            return None;
        }
    }
    Some(NaiveCapabilities(report.capabilities))
}

pub(crate) fn require_configuration(
    payload: &str,
    capabilities: &NaiveCapabilities,
) -> Result<(), EngineError> {
    let document: Value = serde_json::from_str(payload).map_err(|_| {
        EngineError::InvalidConfiguration("无法解析运行配置，请刷新配置".to_owned())
    })?;
    for outbound in document["outbounds"].as_array().into_iter().flatten() {
        if outbound["type"].as_str() != Some("naive") {
            continue;
        }
        if outbound["udp_over_tcp"]["enabled"].as_bool() != Some(true)
            || outbound["udp_over_tcp"]["version"].as_u64() != Some(2)
        {
            return Err(EngineError::InvalidConfiguration(
                "Naive 配置缺少 UoT v2，请刷新配置".to_owned(),
            ));
        }
        let tls = &outbound["tls"];
        if tls["enabled"].as_bool() != Some(true)
            || (!tls["insecure"].is_null() && tls["insecure"].as_bool() != Some(false))
        {
            return Err(EngineError::InvalidConfiguration(
                "Naive 必须启用 TLS 证书验证".to_owned(),
            ));
        }
        if !outbound["quic"].is_null() && !outbound["quic"].is_boolean() {
            return Err(EngineError::InvalidConfiguration(
                "Naive 传输配置无效，请刷新配置".to_owned(),
            ));
        }
        let transport = if outbound["quic"].as_bool() == Some(true) {
            "quic"
        } else {
            "https"
        };
        let custom = tls.get("certificate").is_some() || tls.get("certificate_path").is_some();
        let capability = format!(
            "{transport}{}-uot-v2",
            if custom { "-custom-ca" } else { "" }
        );
        if !capabilities.0.contains(&capability) {
            return Err(EngineError::UnsupportedRuntime(format!(
                "当前构建未经 {capability} 验证或产物校验失败，请更新客户端"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_rejects_old_or_malformed_uot_without_exposing_credentials() {
        let caps = NaiveCapabilities(CAPABILITIES.into_iter().map(str::to_owned).collect());
        for value in [
            "null",
            "true",
            "{}",
            r#"{"enabled":true,"version":1}"#,
            r#"{"enabled":"true","version":2}"#,
            r#"{"enabled":true,"version":"2"}"#,
        ] {
            let payload = format!(
                r#"{{"outbounds":[{{"type":"naive","password":"secret-sentinel","udp_over_tcp":{value}}}]}}"#
            );
            let error = require_configuration(&payload, &caps)
                .unwrap_err()
                .to_string();
            assert!(error.contains("UoT v2"));
            assert!(!error.contains("secret-sentinel"));
        }
    }

    #[test]
    fn transports_and_trust_are_independent() {
        let caps = NaiveCapabilities(BTreeSet::from(["https-uot-v2".to_owned()]));
        let mut config = serde_json::json!({"outbounds":[{"type":"naive","quic":false,
            "udp_over_tcp":{"enabled":true,"version":2},"tls":{"enabled":true}}]});
        assert!(require_configuration(&config.to_string(), &caps).is_ok());
        config["outbounds"][0]["quic"] = Value::Bool(true);
        assert!(require_configuration(&config.to_string(), &caps).is_err());
        config["outbounds"][0]["quic"] = Value::Bool(false);
        config["outbounds"][0]["tls"]["certificate"] = serde_json::json!(["CA"]);
        assert!(require_configuration(&config.to_string(), &caps).is_err());
        assert_eq!(
            caps.protocol_offers(),
            ["naive;transport=https;security=tls;uot-v2"]
        );
    }

    #[test]
    fn report_is_bound_to_native_artifacts_and_udp_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("core");
        std::fs::write(&binary, b"unit-test-core").unwrap();
        let library = if cfg!(windows) {
            "libcronet.dll"
        } else {
            "libcronet.so"
        };
        std::fs::write(directory.path().join(library), b"unit-test-library").unwrap();
        let mut report = serde_json::json!({
            "schema_version":2,"core_version":env!("TOPNODE_SING_BOX_ACP_VERSION"),
            "core_commit":env!("TOPNODE_SING_BOX_ACP_COMMIT"),"target":env!("TOPNODE_BUILD_TARGET"),
            "core_sha256":super::digest(&binary).unwrap(),
            "libraries":[{"file":library,"sha256":super::digest(&directory.path().join(library)).unwrap()}],
            "capabilities":["https-uot-v2"],
            "results":[{"capability":"https-uot-v2","tcp":true,"udp_echo":true,"udp_dns":true,"negative_trust":true,"negative_auth":true}]
        });
        let path = directory.path().join("naive-validation.json");
        let probe = format!(
            "sing-box version {}\nRevision: {}\nTags: with_naive_outbound",
            env!("TOPNODE_SING_BOX_ACP_VERSION"),
            env!("TOPNODE_SING_BOX_ACP_COMMIT")
        );
        std::fs::write(&path, report.to_string()).unwrap();
        assert_eq!(
            super::verified_capabilities(&binary, &probe)
                .protocol_offers()
                .len(),
            1
        );
        report["results"][0]["udp_echo"] = Value::Bool(false);
        std::fs::write(&path, report.to_string()).unwrap();
        assert!(
            super::verified_capabilities(&binary, &probe)
                .protocol_offers()
                .is_empty()
        );
        report["results"][0]["udp_echo"] = Value::Bool(true);
        std::fs::write(&path, report.to_string()).unwrap();
        std::fs::write(directory.path().join(library), b"replacement").unwrap();
        assert!(
            super::verified_capabilities(&binary, &probe)
                .protocol_offers()
                .is_empty()
        );
    }
}
