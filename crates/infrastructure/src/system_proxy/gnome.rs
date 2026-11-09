//! GNOME `GSettings` snapshots with a single dconf changeset for atomic updates.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
use std::{
    collections::BTreeMap,
    io::{self, Write},
    net::SocketAddrV4,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

type Settings = BTreeMap<String, BTreeMap<String, String>>;
const SCHEMA: &str = "org.gnome.system.proxy";

fn run(program: &str, args: &[&str], input: Option<&[u8]>) -> io::Result<Vec<u8>> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("proxy input unavailable"))?
            .write_all(input)?;
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "GNOME proxy operation timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output()?;
    if !output.status.success() || output.stdout.len() > 65536 {
        return Err(io::Error::other("GNOME proxy operation failed"));
    }
    Ok(output.stdout)
}

pub(super) fn available() -> bool {
    std::env::var("XDG_CURRENT_DESKTOP").is_ok_and(|value| {
        value
            .split(':')
            .any(|name| name.eq_ignore_ascii_case("gnome"))
    })
}

pub(super) fn capture() -> io::Result<Vec<u8>> {
    let output = run("/usr/bin/gsettings", &["list-recursively", SCHEMA], None)?;
    let text = String::from_utf8(output).map_err(io::Error::other)?;
    let mut settings = Settings::new();
    for line in text.lines() {
        let mut fields = line.splitn(3, ' ');
        let schema = fields.next().unwrap_or_default();
        let key = fields.next().unwrap_or_default();
        let value = fields
            .next()
            .ok_or_else(|| io::Error::other("incomplete GSettings snapshot"))?;
        let group = if schema == SCHEMA {
            ""
        } else {
            schema
                .strip_prefix("org.gnome.system.proxy.")
                .ok_or_else(|| io::Error::other("unexpected proxy schema"))?
        };
        settings
            .entry(group.to_owned())
            .or_default()
            .insert(key.to_owned(), value.to_owned());
    }
    validate(&settings)?;
    serde_json::to_vec(&settings).map_err(io::Error::other)
}

fn validate(settings: &Settings) -> io::Result<()> {
    if !settings
        .get("")
        .is_some_and(|values| values.contains_key("mode"))
    {
        return Err(io::Error::other("missing GNOME proxy mode"));
    }
    for (group, values) in settings {
        if !["", "http", "https", "ftp", "socks"].contains(&group.as_str()) {
            return Err(io::Error::other("invalid proxy group"));
        }
        for (key, value) in values {
            if key.is_empty()
                || !key.bytes().all(|c| c.is_ascii_lowercase() || c == b'-')
                || value.contains(['\n', '\r'])
            {
                return Err(io::Error::other("invalid proxy snapshot"));
            }
        }
    }
    Ok(())
}

pub(super) fn local_proxy_snapshot(original: &[u8], endpoint: SocketAddrV4) -> io::Result<Vec<u8>> {
    let mut settings: Settings = serde_json::from_slice(original).map_err(io::Error::other)?;
    validate(&settings)?;
    let general = settings
        .get_mut("")
        .ok_or_else(|| io::Error::other("missing proxy settings"))?;
    general.insert("mode".to_owned(), "'manual'".to_owned());
    general.insert("use-same-proxy".to_owned(), "false".to_owned());
    for group in ["http", "https", "socks"] {
        let values = settings.entry(group.to_owned()).or_default();
        values.insert("host".to_owned(), format!("'{}'", endpoint.ip()));
        values.insert("port".to_owned(), endpoint.port().to_string());
    }
    settings
        .entry("http".to_owned())
        .or_default()
        .insert("use-authentication".to_owned(), "false".to_owned());
    serde_json::to_vec(&settings).map_err(io::Error::other)
}

pub(super) fn install(snapshot: &[u8]) -> io::Result<()> {
    let settings: Settings = serde_json::from_slice(snapshot).map_err(io::Error::other)?;
    validate(&settings)?;
    let mut changes = String::new();
    for (group, values) in settings {
        use std::fmt::Write as _;
        writeln!(changes, "[{}]", if group.is_empty() { "/" } else { &group })
            .map_err(io::Error::other)?;
        for (key, value) in values {
            writeln!(changes, "{key}={value}").map_err(io::Error::other)?;
        }
        changes.push('\n');
    }
    run(
        "/usr/bin/dconf",
        &["load", "/system/proxy/"],
        Some(changes.as_bytes()),
    )
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_pac_exceptions_and_credentials_for_restoration() {
        let settings = serde_json::json!({"":{"mode":"'auto'","autoconfig-url":"'https://example.test/pac'","ignore-hosts":"['localhost']","use-same-proxy":"true"},"http":{"host":"'old'","port":"8080","use-authentication":"true","authentication-password":"'secret'"},"https":{"host":"''","port":"0"},"socks":{"host":"''","port":"0"}});
        let desired = local_proxy_snapshot(
            &serde_json::to_vec(&settings).unwrap(),
            SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 1080),
        )
        .unwrap();
        let desired: serde_json::Value = serde_json::from_slice(&desired).unwrap();
        assert_eq!(desired[""]["mode"], "'manual'");
        assert_eq!(
            desired[""]["autoconfig-url"],
            settings[""]["autoconfig-url"]
        );
        assert_eq!(desired[""]["ignore-hosts"], settings[""]["ignore-hosts"]);
        assert_eq!(
            desired["http"]["authentication-password"],
            settings["http"]["authentication-password"]
        );
    }
}
