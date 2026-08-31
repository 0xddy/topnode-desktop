//! Audited `WinINet` facade for the default LAN connection.
//!
//! All FFI is confined to this module. The rest of the workspace sees only an
//! opaque, versioned snapshot and cannot accidentally omit notification or
//! query-back from the ownership protocol.

#![allow(unsafe_code)]

use std::{
    ffi::c_void,
    io,
    mem::size_of,
    net::SocketAddrV4,
    ptr::{null, null_mut},
};

use windows_sys::Win32::{
    Foundation::GlobalFree,
    Networking::WinInet::{
        INTERNET_OPTION_PER_CONNECTION_OPTION, INTERNET_OPTION_REFRESH,
        INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_PER_CONN_AUTOCONFIG_URL,
        INTERNET_PER_CONN_AUTODISCOVERY_FLAGS, INTERNET_PER_CONN_FLAGS, INTERNET_PER_CONN_FLAGS_UI,
        INTERNET_PER_CONN_OPTION_LISTW, INTERNET_PER_CONN_OPTIONW, INTERNET_PER_CONN_OPTIONW_0,
        INTERNET_PER_CONN_PROXY_BYPASS, INTERNET_PER_CONN_PROXY_SERVER, InternetQueryOptionW,
        InternetSetOptionW, PROXY_TYPE_AUTO_DETECT, PROXY_TYPE_AUTO_PROXY_URL, PROXY_TYPE_DIRECT,
        PROXY_TYPE_PROXY,
    },
};

const SNAPSHOT_MAGIC: &[u8; 8] = b"TNPXYW01";
const OPTIONAL_NONE: u32 = u32::MAX;
const MAX_STRING_UNITS: usize = 16 * 1_024;

pub(super) fn capture() -> io::Result<Vec<u8>> {
    query(INTERNET_PER_CONN_FLAGS_UI)
        .or_else(|_| query(INTERNET_PER_CONN_FLAGS))
        .and_then(|snapshot| snapshot.encode())
}

pub(super) fn local_proxy_snapshot(original: &[u8], endpoint: SocketAddrV4) -> io::Result<Vec<u8>> {
    let mut snapshot = WinInetSnapshot::decode(original)?;
    snapshot.flags &= !(PROXY_TYPE_AUTO_PROXY_URL | PROXY_TYPE_AUTO_DETECT);
    snapshot.flags |= PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY;
    snapshot.proxy_server = Some(endpoint.to_string().encode_utf16().collect());
    // Route every proxy-aware request through the private Mixed listener. LAN
    // bypass is a sing-box routing preference; applying a WinINet `<local>`
    // bypass here would silently override the user's `bypass_lan = false`.
    snapshot.proxy_bypass = None;
    snapshot.encode()
}

pub(super) fn install(encoded: &[u8]) -> io::Result<()> {
    let snapshot = WinInetSnapshot::decode(encoded)?;
    apply(&snapshot)
}

struct WinInetSnapshot {
    flags: u32,
    auto_discovery_flags: u32,
    proxy_server: Option<Vec<u16>>,
    proxy_bypass: Option<Vec<u16>>,
    pac_url: Option<Vec<u16>>,
}

impl WinInetSnapshot {
    fn encode(&self) -> io::Result<Vec<u8>> {
        validate_wide(self.proxy_server.as_deref())?;
        validate_wide(self.proxy_bypass.as_deref())?;
        validate_wide(self.pac_url.as_deref())?;

        let mut encoded = Vec::with_capacity(64);
        encoded.extend_from_slice(SNAPSHOT_MAGIC);
        encoded.extend_from_slice(&self.flags.to_le_bytes());
        encoded.extend_from_slice(&self.auto_discovery_flags.to_le_bytes());
        encode_optional_wide(&mut encoded, self.proxy_server.as_deref())?;
        encode_optional_wide(&mut encoded, self.proxy_bypass.as_deref())?;
        encode_optional_wide(&mut encoded, self.pac_url.as_deref())?;
        Ok(encoded)
    }

    fn decode(encoded: &[u8]) -> io::Result<Self> {
        let mut reader = SnapshotReader::new(encoded);
        if reader.take(SNAPSHOT_MAGIC.len())? != SNAPSHOT_MAGIC {
            return Err(invalid_snapshot("快照标识无效"));
        }
        let flags = reader.read_u32()?;
        let auto_discovery_flags = reader.read_u32()?;
        let proxy_server = reader.read_optional_wide()?;
        let proxy_bypass = reader.read_optional_wide()?;
        let pac_url = reader.read_optional_wide()?;
        if !reader.is_finished() {
            return Err(invalid_snapshot("快照包含尾随数据"));
        }
        Ok(Self {
            flags,
            auto_discovery_flags,
            proxy_server,
            proxy_bypass,
            pac_url,
        })
    }
}

fn query(flags_option: u32) -> io::Result<WinInetSnapshot> {
    let mut options = [
        value_option(flags_option, 0),
        string_option(INTERNET_PER_CONN_PROXY_SERVER, null_mut()),
        string_option(INTERNET_PER_CONN_PROXY_BYPASS, null_mut()),
        string_option(INTERNET_PER_CONN_AUTOCONFIG_URL, null_mut()),
        value_option(INTERNET_PER_CONN_AUTODISCOVERY_FLAGS, 0),
    ];
    let mut list = option_list(&mut options)?;
    let mut list_size = list.dwSize;

    // SAFETY: `list` and `list_size` point to initialized, writable values for
    // the duration of the call. `list.pOptions` points to the live `options`
    // array, and a null connection selects the documented default LAN entry.
    let success = unsafe {
        InternetQueryOptionW(
            null(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            (&raw mut list).cast::<c_void>(),
            &raw mut list_size,
        )
    };
    let query_error = (success == 0).then(io::Error::last_os_error);

    let result = if let Some(error) = query_error {
        Err(error)
    } else {
        // SAFETY: On successful query WinINet initializes each requested union
        // member according to its `dwOption`. String pointers are either null or
        // GlobalAlloc-owned, NUL-terminated UTF-16 strings documented by
        // INTERNET_OPTION_PER_CONNECTION_OPTION.
        unsafe { snapshot_from_options(&options) }
    };
    let free_result = free_query_strings(&mut options);
    match (result, free_result) {
        (Ok(snapshot), Ok(())) => Ok(snapshot),
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

unsafe fn snapshot_from_options(
    options: &[INTERNET_PER_CONN_OPTIONW; 5],
) -> io::Result<WinInetSnapshot> {
    // SAFETY: The caller established that WinINet successfully initialized the
    // union members for exactly these option kinds.
    let flags = unsafe { options[0].Value.dwValue };
    // SAFETY: Same invariant as above; indices 1..=3 are string-valued options.
    let proxy_server = unsafe { copy_wide(options[1].Value.pszValue)? };
    // SAFETY: Same invariant as above.
    let proxy_bypass = unsafe { copy_wide(options[2].Value.pszValue)? };
    // SAFETY: Same invariant as above.
    let pac_url = unsafe { copy_wide(options[3].Value.pszValue)? };
    // SAFETY: Index 4 is the integer-valued auto-discovery option.
    let auto_discovery_flags = unsafe { options[4].Value.dwValue };
    Ok(WinInetSnapshot {
        flags,
        auto_discovery_flags,
        proxy_server,
        proxy_bypass,
        pac_url,
    })
}

unsafe fn copy_wide(pointer: *mut u16) -> io::Result<Option<Vec<u16>>> {
    if pointer.is_null() {
        return Ok(None);
    }
    let mut length = 0usize;
    loop {
        if length == MAX_STRING_UNITS {
            return Err(invalid_snapshot("WinINet 字符串超过安全大小限制"));
        }
        // SAFETY: WinINet promises a GlobalAlloc-owned, NUL-terminated UTF-16
        // string for this successful string query. The bounded scan prevents an
        // attacker-controlled unbounded allocation.
        if unsafe { *pointer.add(length) } == 0 {
            break;
        }
        length += 1;
    }
    if length == 0 {
        return Ok(None);
    }
    // SAFETY: The preceding scan found a terminator after `length` initialized
    // code units, so this exact prefix is readable.
    Ok(Some(unsafe {
        std::slice::from_raw_parts(pointer, length).to_vec()
    }))
}

fn free_query_strings(options: &mut [INTERNET_PER_CONN_OPTIONW; 5]) -> io::Result<()> {
    let mut first_error = None;
    for option in &mut options[1..=3] {
        // SAFETY: These are the string-valued union members initialized by the
        // query. Each non-null pointer is owned by WinINet via GlobalAlloc and
        // is freed exactly once here, regardless of query/copy success.
        let pointer = unsafe { option.Value.pszValue };
        if pointer.is_null() {
            continue;
        }
        // SAFETY: The pointer ownership invariant above is exactly GlobalFree's
        // contract. The returned non-null handle denotes failure.
        let failed_handle = unsafe { GlobalFree(pointer.cast::<c_void>()) };
        option.Value = INTERNET_PER_CONN_OPTIONW_0 {
            pszValue: null_mut(),
        };
        if !failed_handle.is_null() && first_error.is_none() {
            first_error = Some(io::Error::last_os_error());
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn apply(snapshot: &WinInetSnapshot) -> io::Result<()> {
    validate_wide(snapshot.proxy_server.as_deref())?;
    validate_wide(snapshot.proxy_bypass.as_deref())?;
    validate_wide(snapshot.pac_url.as_deref())?;

    let mut proxy_server = terminated(snapshot.proxy_server.as_deref());
    let mut proxy_bypass = terminated(snapshot.proxy_bypass.as_deref());
    let mut pac_url = terminated(snapshot.pac_url.as_deref());
    let mut options = [
        value_option(INTERNET_PER_CONN_FLAGS, snapshot.flags),
        string_option(
            INTERNET_PER_CONN_PROXY_SERVER,
            optional_pointer(&mut proxy_server),
        ),
        string_option(
            INTERNET_PER_CONN_PROXY_BYPASS,
            optional_pointer(&mut proxy_bypass),
        ),
        string_option(
            INTERNET_PER_CONN_AUTOCONFIG_URL,
            optional_pointer(&mut pac_url),
        ),
        value_option(
            INTERNET_PER_CONN_AUTODISCOVERY_FLAGS,
            snapshot.auto_discovery_flags,
        ),
    ];
    let list = option_list(&mut options)?;

    // SAFETY: `list` and its option array remain alive for the call, and each
    // string union points to a live NUL-terminated UTF-16 buffer or is null.
    let applied = unsafe {
        InternetSetOptionW(
            null(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            (&raw const list).cast::<c_void>(),
            list.dwSize,
        )
    };
    if applied == 0 {
        return Err(io::Error::last_os_error());
    }

    notify(INTERNET_OPTION_SETTINGS_CHANGED)?;
    notify(INTERNET_OPTION_REFRESH)
}

fn notify(option: u32) -> io::Result<()> {
    // SAFETY: These WinINet notification options are documented to use a null
    // internet handle and no option buffer.
    let success = unsafe { InternetSetOptionW(null(), option, null(), 0) };
    if success == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn value_option(option: u32, value: u32) -> INTERNET_PER_CONN_OPTIONW {
    INTERNET_PER_CONN_OPTIONW {
        dwOption: option,
        Value: INTERNET_PER_CONN_OPTIONW_0 { dwValue: value },
    }
}

fn string_option(option: u32, value: *mut u16) -> INTERNET_PER_CONN_OPTIONW {
    INTERNET_PER_CONN_OPTIONW {
        dwOption: option,
        Value: INTERNET_PER_CONN_OPTIONW_0 { pszValue: value },
    }
}

fn option_list(
    options: &mut [INTERNET_PER_CONN_OPTIONW],
) -> io::Result<INTERNET_PER_CONN_OPTION_LISTW> {
    Ok(INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: u32::try_from(size_of::<INTERNET_PER_CONN_OPTION_LISTW>())
            .map_err(|_| invalid_snapshot("WinINet 结构大小无效"))?,
        pszConnection: null_mut(),
        dwOptionCount: u32::try_from(options.len())
            .map_err(|_| invalid_snapshot("WinINet 选项数量无效"))?,
        dwOptionError: 0,
        pOptions: options.as_mut_ptr(),
    })
}

fn terminated(value: Option<&[u16]>) -> Option<Vec<u16>> {
    value.map(|value| {
        let mut terminated = Vec::with_capacity(value.len() + 1);
        terminated.extend_from_slice(value);
        terminated.push(0);
        terminated
    })
}

fn optional_pointer(value: &mut Option<Vec<u16>>) -> *mut u16 {
    value.as_mut().map_or(null_mut(), Vec::as_mut_ptr)
}

fn validate_wide(value: Option<&[u16]>) -> io::Result<()> {
    if let Some(value) = value {
        if value.len() > MAX_STRING_UNITS {
            return Err(invalid_snapshot("WinINet 字符串超过安全大小限制"));
        }
        if value.contains(&0) {
            return Err(invalid_snapshot("WinINet 字符串包含内部终止符"));
        }
    }
    Ok(())
}

fn encode_optional_wide(encoded: &mut Vec<u8>, value: Option<&[u16]>) -> io::Result<()> {
    let Some(value) = value else {
        encoded.extend_from_slice(&OPTIONAL_NONE.to_le_bytes());
        return Ok(());
    };
    let length = u32::try_from(value.len()).map_err(|_| invalid_snapshot("字符串长度无效"))?;
    encoded.extend_from_slice(&length.to_le_bytes());
    for unit in value {
        encoded.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(())
}

struct SnapshotReader<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> SnapshotReader<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn take(&mut self, length: usize) -> io::Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| invalid_snapshot("快照长度溢出"))?;
        let bytes = self
            .encoded
            .get(self.offset..end)
            .ok_or_else(|| invalid_snapshot("快照被截断"))?;
        self.offset = end;
        Ok(bytes)
    }

    fn read_u32(&mut self) -> io::Result<u32> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| invalid_snapshot("整数编码无效"))?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_optional_wide(&mut self) -> io::Result<Option<Vec<u16>>> {
        let length = self.read_u32()?;
        if length == OPTIONAL_NONE {
            return Ok(None);
        }
        let length = usize::try_from(length).map_err(|_| invalid_snapshot("字符串长度无效"))?;
        if length > MAX_STRING_UNITS {
            return Err(invalid_snapshot("WinINet 字符串超过安全大小限制"));
        }
        let bytes = self.take(
            length
                .checked_mul(2)
                .ok_or_else(|| invalid_snapshot("字符串长度溢出"))?,
        )?;
        let mut value = Vec::with_capacity(length);
        for pair in bytes.chunks_exact(2) {
            value.push(u16::from_le_bytes([pair[0], pair[1]]));
        }
        let value = Some(value);
        validate_wide(value.as_deref())?;
        Ok(value)
    }

    const fn is_finished(&self) -> bool {
        self.offset == self.encoded.len()
    }
}

fn invalid_snapshot(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::*;

    #[test]
    fn codec_round_trips_all_proxy_modes_and_dormant_values() {
        let original = WinInetSnapshot {
            flags: PROXY_TYPE_DIRECT
                | PROXY_TYPE_PROXY
                | PROXY_TYPE_AUTO_PROXY_URL
                | PROXY_TYPE_AUTO_DETECT
                | 0x8000_0000,
            auto_discovery_flags: 0x1234_5678,
            proxy_server: Some("old-proxy:8181".encode_utf16().collect()),
            proxy_bypass: Some("<local>;example.test".encode_utf16().collect()),
            pac_url: Some("https://private.test/proxy.pac".encode_utf16().collect()),
        };

        let encoded = original.encode().expect("encode snapshot");
        let decoded = WinInetSnapshot::decode(&encoded).expect("decode snapshot");

        assert_eq!(decoded.flags, original.flags);
        assert_eq!(decoded.auto_discovery_flags, original.auto_discovery_flags);
        assert!(decoded.proxy_server == original.proxy_server);
        assert!(decoded.proxy_bypass == original.proxy_bypass);
        assert!(decoded.pac_url == original.pac_url);
    }

    #[test]
    fn local_snapshot_clears_platform_bypass_and_preserves_other_dormant_state() {
        let original = WinInetSnapshot {
            flags: PROXY_TYPE_AUTO_PROXY_URL | PROXY_TYPE_AUTO_DETECT | 0x8000_0000,
            auto_discovery_flags: 42,
            proxy_server: Some("old-proxy:8181".encode_utf16().collect()),
            proxy_bypass: Some("private.test".encode_utf16().collect()),
            pac_url: Some("https://private.test/proxy.pac".encode_utf16().collect()),
        };
        let original = original.encode().expect("encode original");

        let desired =
            local_proxy_snapshot(&original, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2_334))
                .and_then(|encoded| WinInetSnapshot::decode(&encoded))
                .expect("build local snapshot");

        assert_eq!(
            desired.flags,
            PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY | 0x8000_0000
        );
        assert_eq!(desired.auto_discovery_flags, 42);
        assert!(desired.proxy_server == Some("127.0.0.1:2334".encode_utf16().collect()));
        assert!(desired.proxy_bypass.is_none());
        assert!(desired.pac_url == Some("https://private.test/proxy.pac".encode_utf16().collect()));

        let original = WinInetSnapshot::decode(&original).expect("original remains recoverable");
        assert!(original.proxy_bypass == Some("private.test".encode_utf16().collect()));
    }

    #[test]
    fn malformed_or_oversized_snapshots_are_rejected_without_ffi() {
        let mut truncated = SNAPSHOT_MAGIC.to_vec();
        truncated.extend_from_slice(&1_u32.to_le_bytes());
        assert!(WinInetSnapshot::decode(&truncated).is_err());

        let oversized = WinInetSnapshot {
            flags: 0,
            auto_discovery_flags: 0,
            proxy_server: Some(vec![u16::from(b'x'); MAX_STRING_UNITS + 1]),
            proxy_bypass: None,
            pac_url: None,
        };
        assert!(oversized.encode().is_err());
    }
}
