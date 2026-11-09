use crate::policy::{self, MAX_CONFIGURATION};
use sha2::{Digest, Sha256};
use std::{
    io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    process::Command,
    time::timeout,
};
use zeroize::Zeroizing;

const ROOT: &str = "/usr/lib/topnode";
const CORE: &str = "/usr/lib/topnode/runtime/core/sing-box-acp";
const HELPER: &str = "/usr/lib/topnode/topnode-net-helper";
const SOCKET: &str = "/run/topnode/network.sock";

fn failure() -> io::Error {
    io::Error::other("restricted network helper operation failed")
}

pub async fn run() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode] if mode == "serve" => serve().await,
        [mode] if mode == "connect" => connect().await,
        _ => Err(failure()),
    }
}

async fn connect() -> io::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut payload = Zeroizing::new(Vec::new());
    tokio::io::stdin()
        .take((MAX_CONFIGURATION + 1) as u64)
        .read_to_end(&mut payload)
        .await?;
    policy::validate(&payload).map_err(|_| failure())?;
    let mut stream = UnixStream::connect(SOCKET).await?;
    if stream.peer_cred()?.uid() != 0 {
        return Err(failure());
    }
    stream
        .write_u32(u32::try_from(payload.len()).map_err(|_| failure())?)
        .await?;
    stream.write_all(&payload).await?;
    drop(payload);
    // Keep the write half open: loss of this connection revokes its root core.
    let status = timeout(Duration::from_secs(120), stream.read_u8())
        .await
        .map_err(|_| failure())??;
    if status != 0 {
        return Err(failure());
    }
    tokio::select! {
        _=terminate.recv()=>{},
        _=stream.read_u8()=>return Err(failure()),
    }
    stream.write_u8(2).await?;
    match timeout(Duration::from_secs(3), stream.read_u8()).await {
        Ok(Ok(2)) => Ok(()),
        _ => Err(failure()),
    }
}

async fn serve() -> io::Result<()> {
    if std::fs::metadata("/proc/self")?.uid() != 0 {
        return Err(failure());
    }
    verify_core()?;
    // systemd owns this directory; no user-writable socket parent is accepted.
    protected(Path::new("/run/topnode"))?;
    if Path::new(SOCKET).exists() {
        std::fs::remove_file(SOCKET)?;
    }
    let listener = UnixListener::bind(SOCKET)?;
    std::fs::set_permissions(SOCKET, std::fs::Permissions::from_mode(0o666))?;
    let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    loop {
        tokio::select! {
            result=listener.accept()=> {
                let (mut stream,_)=result?;
                let Ok(permit)=gate.clone().try_acquire_owned() else {let _=stream.write_u8(1).await;continue;};
                tokio::spawn(async move {
                    let _permit=permit;
                    if session(&mut stream).await.is_err(){let _=stream.write_u8(1).await;}
                });
            }
            _=tokio::signal::ctrl_c()=>return Ok(()),
        }
    }
}

async fn session(stream: &mut UnixStream) -> io::Result<()> {
    let credentials = stream.peer_cred()?;
    let pid = credentials.pid().ok_or_else(failure)?;
    let uid = credentials.uid();
    if uid == 0 {
        return Err(failure());
    }
    let start = process_identity(pid)?;
    let length = timeout(Duration::from_secs(5), stream.read_u32())
        .await
        .map_err(|_| failure())?? as usize;
    if length > MAX_CONFIGURATION {
        return Err(failure());
    }
    let mut payload = Zeroizing::new(vec![0; length]);
    timeout(Duration::from_secs(10), stream.read_exact(&mut payload))
        .await
        .map_err(|_| failure())??;
    policy::validate(&payload).map_err(|_| failure())?;
    let status = timeout(
        Duration::from_secs(110),
        Command::new("/usr/bin/pkcheck")
            .args([
                "--action-id",
                "cc.topnode.network.tun",
                "--process",
                &format!("{pid},{start},{uid}"),
                "--allow-user-interaction",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await
    .map_err(|_| failure())??;
    if !status.success() || process_identity(pid)? != start {
        return Err(failure());
    }
    verify_core()?;
    let mut child = Command::new(CORE)
        .args(["run", "-c", "stdin"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .current_dir(ROOT)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or_else(failure)?;
    if timeout(Duration::from_secs(10), async {
        stdin.write_all(&payload).await?;
        stdin.shutdown().await
    })
    .await
    .map_err(|_| failure())?
    .is_err()
    {
        let _ = child.kill().await;
        return Err(failure());
    }
    drop(payload);
    drop(stdin);
    stream.write_u8(0).await?;
    let mut byte = [0];
    tokio::select! {
        _=stream.read(&mut byte)=>{},
        _=child.wait()=>{},
    }
    // SIGTERM lets sing-box restore routes and DNS. systemd kills the complete
    // cgroup on daemon exit; a disconnected GUI cannot retain a privileged core.
    if let Some(pid) = child.id() {
        let _ = Command::new("/usr/bin/kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .await;
    }
    if timeout(Duration::from_secs(2), child.wait()).await.is_err() {
        let _ = child.kill().await;
    }
    let _ = stream.write_u8(2).await;
    Ok(())
}

fn process_identity(pid: i32) -> io::Result<String> {
    if std::fs::read_link(format!("/proc/{pid}/exe"))? != Path::new(HELPER) {
        return Err(failure());
    }
    protected(Path::new(HELPER))?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let tail = stat.rsplit_once(')').ok_or_else(failure)?.1;
    tail.split_whitespace()
        .nth(19)
        .map(str::to_owned)
        .ok_or_else(failure)
}

fn protected(path: &Path) -> io::Result<()> {
    for component in path.ancestors() {
        let metadata = std::fs::symlink_metadata(component)?;
        if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        {
            return Err(failure());
        }
    }
    Ok(())
}

fn file_digest(path: &Path) -> io::Result<String> {
    use std::io::Read;
    protected(path)?;
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 8192];
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn verify_core() -> io::Result<()> {
    let directory = Path::new(CORE).parent().ok_or_else(failure)?;
    let manifest = directory.join("source.json");
    protected(&manifest)?;
    if std::fs::metadata(&manifest)?.len() > 65536 {
        return Err(failure());
    }
    let metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(manifest)?).map_err(|_| failure())?;
    let lock = include_str!("../../../config/sing-box-acp.lock");
    for key in ["commit", "version"] {
        let value = lock
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .ok_or_else(failure)?;
        if metadata[key].as_str() != Some(value) {
            return Err(failure());
        }
    }
    if metadata["binarySha256"].as_str() != Some(&file_digest(Path::new(CORE))?) {
        return Err(failure());
    }
    for library in metadata["libraries"].as_array().ok_or_else(failure)? {
        let name = library["file"].as_str().ok_or_else(failure)?;
        if name.is_empty() || name.starts_with('.') || name.contains(['/', '\\', ':']) {
            return Err(failure());
        }
        if library["sha256"].as_str() != Some(&file_digest(&directory.join(name))?) {
            return Err(failure());
        }
    }
    Ok(())
}
