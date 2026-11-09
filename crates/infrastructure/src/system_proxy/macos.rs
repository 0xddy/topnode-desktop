#![cfg_attr(not(target_os = "macos"), allow(dead_code))]
use std::{
    io::{self, Write},
    net::SocketAddrV4,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

type Services = std::collections::BTreeMap<String, String>;
type ServiceUpdate = Option<(Vec<u8>, Vec<u8>, Vec<u8>)>;

pub(super) fn new_services(
    original: &[u8],
    applied: &[u8],
    observed: &[u8],
    endpoint: SocketAddrV4,
) -> io::Result<ServiceUpdate> {
    let mut original: Services = serde_json::from_slice(original).map_err(io::Error::other)?;
    let mut applied: Services = serde_json::from_slice(applied).map_err(io::Error::other)?;
    let observed: Services = serde_json::from_slice(observed).map_err(io::Error::other)?;
    let additions: Services = observed
        .into_iter()
        .filter(|(id, _)| !original.contains_key(id))
        .collect();
    if additions.is_empty() {
        return Ok(None);
    }
    let local = local_proxy_snapshot(
        &serde_json::to_vec(&additions).map_err(io::Error::other)?,
        endpoint,
    )?;
    original.extend(additions);
    applied.extend(serde_json::from_slice::<Services>(&local).map_err(io::Error::other)?);
    Ok(Some((
        serde_json::to_vec(&original).map_err(io::Error::other)?,
        serde_json::to_vec(&applied).map_err(io::Error::other)?,
        local,
    )))
}

pub(super) fn contains_services(snapshot: &[u8], expected: &[u8]) -> io::Result<bool> {
    let snapshot: Services = serde_json::from_slice(snapshot).map_err(io::Error::other)?;
    let expected: Services = serde_json::from_slice(expected).map_err(io::Error::other)?;
    Ok(expected
        .iter()
        .all(|(id, value)| snapshot.get(id) == Some(value)))
}

fn run(operation: &str, port: Option<u16>, snapshot: Option<&[u8]>) -> io::Result<Vec<u8>> {
    let executable = std::env::current_exe()?;
    let helper = executable
        .parent()
        .ok_or_else(|| io::Error::other("missing application directory"))?
        .join("topnode-proxy-settings");
    let mut command = Command::new(helper);
    command.arg(operation);
    if let Some(port) = port {
        command.arg(port.to_string());
    }
    command
        .stdin(if snapshot.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn()?;
    if let Some(snapshot) = snapshot {
        child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("missing proxy input"))?
            .write_all(snapshot)?;
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "macOS proxy authorization timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output()?;
    if !output.status.success() || output.stdout.len() > 65536 {
        return Err(io::Error::other(
            "macOS system proxy authorization or operation failed",
        ));
    }
    Ok(output.stdout)
}

pub(super) fn capture() -> io::Result<Vec<u8>> {
    run("capture", None, None)
}
pub(super) fn local_proxy_snapshot(original: &[u8], endpoint: SocketAddrV4) -> io::Result<Vec<u8>> {
    run("local", Some(endpoint.port()), Some(original))
}
pub(super) fn install(snapshot: &[u8]) -> io::Result<()> {
    run("install", None, Some(snapshot)).map(|_| ())
}

// Ownership is per network service, so changing Wi-Fi must not strand our
// proxy on an unchanged Ethernet service or overwrite the new Wi-Fi settings.
pub(super) fn restore_target(
    original: &[u8],
    applied: &[u8],
    observed: &[u8],
) -> io::Result<Option<Vec<u8>>> {
    let original: Services = serde_json::from_slice(original).map_err(io::Error::other)?;
    let applied: Services = serde_json::from_slice(applied).map_err(io::Error::other)?;
    let mut target: Services = serde_json::from_slice(observed).map_err(io::Error::other)?;
    let mut changed = false;
    for (service, value) in &mut target {
        if applied.get(service) == Some(value)
            && let Some(previous) = original.get(service)
            && previous != value
        {
            value.clone_from(previous);
            changed = true;
        }
    }
    if changed {
        serde_json::to_vec(&target)
            .map(Some)
            .map_err(io::Error::other)
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::{contains_services, restore_target};

    #[test]
    fn restores_owned_service_without_overwriting_external_or_new_services() {
        let restored = restore_target(
            br#"{"ethernet":"old-e","wifi":"old-w"}"#,
            br#"{"ethernet":"ours-e","wifi":"ours-w"}"#,
            br#"{"ethernet":"ours-e","wifi":"user-change","usb":"new"}"#,
        )
        .unwrap()
        .unwrap();
        assert!(
            contains_services(
                &restored,
                br#"{"ethernet":"old-e","wifi":"user-change","usb":"new"}"#
            )
            .unwrap()
        );
        assert!(
            restore_target(
                br#"{"wifi":"old"}"#,
                br#"{"wifi":"ours"}"#,
                br#"{"wifi":"external"}"#
            )
            .unwrap()
            .is_none()
        );
    }
}
