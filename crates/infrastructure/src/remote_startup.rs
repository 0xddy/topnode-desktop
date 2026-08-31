use std::{collections::BTreeMap, net::IpAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::{Client, Response, Url, header::CACHE_CONTROL};
use serde::Deserialize;
use thiserror::Error;
use tokio::task::JoinSet;

use crate::{PanelEndpoint, PaymentPresentation, api_endpoint::build_discovered_endpoint_client};

pub const DESKTOP_STARTUP_CONFIGURATION_URLS: [&str; 3] = [
    "https://0x10.topboot.top/desktop.config.json",
    "https://0x11.boot1.top/desktop.config.json",
    "https://0x12.boot2.top/desktop.config.json",
];

const MAX_CONFIGURATION_BYTES: usize = 1024 * 1024;
const MAX_API_SERVERS: usize = 16;
const MAX_FRONTED_ENDPOINTS: usize = 32;
const MAX_PLATFORM_DOWNLOADS: usize = 16;
const MAX_VERSION_CODE: u64 = 2_100_000_000;
const MAX_VERSION_NAME_LENGTH: usize = 64;
const MAX_TARGET_NAME_LENGTH: usize = 64;
const MAX_FILE_NAME_LENGTH: usize = 128;
const MAX_MIME_TYPE_LENGTH: usize = 128;
const MIN_TIMEOUT_MILLIS: u64 = 100;
const MAX_CONNECT_TIMEOUT_MILLIS: u64 = 10_000;
const MAX_REQUEST_TIMEOUT_MILLIS: u64 = 30_000;
const MAX_OVERALL_TIMEOUT_MILLIS: u64 = 60_000;

/// The remotely selected Panel route and desktop-only presentation policy.
#[derive(Clone, Debug)]
pub struct ResolvedStartupConfiguration {
    endpoint: PanelEndpoint,
    payment_presentation: PaymentPresentation,
    desktop_version: RemoteDesktopVersion,
    source_url: String,
    configuration_attempts: usize,
    probe_response_code: u16,
}

impl ResolvedStartupConfiguration {
    pub fn endpoint(&self) -> &PanelEndpoint {
        &self.endpoint
    }

    pub fn into_endpoint(self) -> PanelEndpoint {
        self.endpoint
    }

    pub const fn payment_presentation(&self) -> PaymentPresentation {
        self.payment_presentation
    }

    pub const fn desktop_version(&self) -> &RemoteDesktopVersion {
        &self.desktop_version
    }

    pub fn source_url(&self) -> &str {
        &self.source_url
    }

    pub const fn configuration_attempts(&self) -> usize {
        self.configuration_attempts
    }

    pub const fn probe_response_code(&self) -> u16 {
        self.probe_response_code
    }
}

/// Remote desktop release metadata selected for this exact build target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteDesktopVersion {
    version_code: u64,
    version_name: String,
    build_target: String,
    download_url: Option<Url>,
}

impl RemoteDesktopVersion {
    pub const fn version_code(&self) -> u64 {
        self.version_code
    }

    pub fn version_name(&self) -> &str {
        &self.version_name
    }

    pub fn build_target(&self) -> &str {
        &self.build_target
    }

    pub fn download_url(&self) -> Option<&str> {
        self.download_url.as_ref().map(Url::as_str)
    }

    /// Returns a target-specific HTTPS archive only for a strict upgrade.
    pub fn available_download_url(&self, current_version_code: u64) -> Option<&str> {
        (self.version_code > current_version_code)
            .then(|| self.download_url())
            .flatten()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RemoteStartupError {
    #[error("无法初始化桌面启动配置客户端")]
    Initialization,
    #[error("无法从 {attempts} 个地址取得有效的桌面启动配置")]
    Configuration { attempts: usize },
    #[error("启动配置已加载，但 {api_probe_attempts} 个 Panel API 候选均不可达")]
    ApiConnectivity {
        configuration_attempts: usize,
        api_probe_attempts: usize,
    },
}

/// Resolves the remote desktop startup contract on every cold process start.
#[derive(Clone)]
pub struct RemoteStartupConfigurationLoader {
    configuration_urls: Arc<[Url]>,
    fetcher: Arc<dyn ConfigurationFetcher>,
    selector: ApiServerSelector,
    fallback_payment_presentation: PaymentPresentation,
    desktop_target: Arc<str>,
}

impl std::fmt::Debug for RemoteStartupConfigurationLoader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteStartupConfigurationLoader")
            .field("configuration_urls", &self.configuration_urls)
            .field(
                "fallback_payment_presentation",
                &self.fallback_payment_presentation,
            )
            .field("desktop_target", &self.desktop_target)
            .finish_non_exhaustive()
    }
}

impl RemoteStartupConfigurationLoader {
    /// Creates the production loader with Android-compatible bootstrap HTTP
    /// timeouts and the fixed ordered desktop sources.
    ///
    /// # Errors
    ///
    /// Returns an initialization error if a compiled-in URL or the bootstrap
    /// HTTP client policy cannot be constructed.
    pub fn production(
        fallback_payment_presentation: PaymentPresentation,
        desktop_target: &str,
        desktop_version_name: &str,
    ) -> Result<Self, RemoteStartupError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let configuration_urls: Arc<[Url]> = DESKTOP_STARTUP_CONFIGURATION_URLS
            .iter()
            .map(|url| require_https_url(url, false))
            .collect::<Option<Vec<_>>>()
            .ok_or(RemoteStartupError::Initialization)?
            .into();
        let desktop_version_name = normalize_version_name(desktop_version_name)
            .ok_or(RemoteStartupError::Initialization)?;
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(6))
            .user_agent(format!("TOPNODE-Desktop-Bootstrap/{desktop_version_name}"))
            .tls_backend_rustls()
            .build()
            .map_err(|_| RemoteStartupError::Initialization)?;
        let desktop_target = normalize_target_name(desktop_target)
            .ok_or(RemoteStartupError::Initialization)?
            .into();
        Ok(Self {
            configuration_urls,
            fetcher: Arc::new(HttpConfigurationFetcher { client }),
            selector: ApiServerSelector::new(Arc::new(HttpEndpointProber {
                desktop_version_name: desktop_version_name.into(),
            })),
            fallback_payment_presentation,
            desktop_target,
        })
    }

    /// Loads the first valid source, then races all API candidates from that
    /// source. A probe failure never falls back to a later configuration file.
    ///
    /// # Errors
    ///
    /// Returns a stage-specific error when all configuration sources are
    /// invalid/unavailable or every selected configuration candidate is
    /// unreachable.
    pub async fn load(&self) -> Result<ResolvedStartupConfiguration, RemoteStartupError> {
        let mut resolved = None;
        let mut attempts = 0;
        for source_url in self.configuration_urls.iter() {
            attempts += 1;
            let configuration = match self.fetcher.fetch(source_url).await {
                Ok(bytes) => parse_and_validate_configuration(&bytes),
                Err(()) => None,
            };
            if let Some(configuration) = configuration {
                resolved = Some((source_url, configuration));
                break;
            }
        }
        let Some((source_url, configuration)) = resolved else {
            return Err(RemoteStartupError::Configuration { attempts });
        };
        let payment_presentation = configuration
            .payment_presentation
            .unwrap_or(self.fallback_payment_presentation);
        let desktop_version = configuration
            .version
            .into_remote_desktop_version(&self.desktop_target);
        let api_probe_attempts = configuration.candidates.len();
        match self
            .selector
            .select(configuration.candidates, &configuration.probe)
            .await
        {
            EndpointSelection::Success {
                endpoint,
                response_code,
            } => Ok(ResolvedStartupConfiguration {
                endpoint: *endpoint,
                payment_presentation,
                desktop_version,
                source_url: source_url.to_string(),
                configuration_attempts: attempts,
                probe_response_code: response_code,
            }),
            EndpointSelection::Failure => Err(RemoteStartupError::ApiConnectivity {
                configuration_attempts: attempts,
                api_probe_attempts,
            }),
        }
    }

    #[cfg(test)]
    fn with_adapters(
        configuration_urls: Vec<Url>,
        fetcher: Arc<dyn ConfigurationFetcher>,
        prober: Arc<dyn EndpointProber>,
        fallback_payment_presentation: PaymentPresentation,
    ) -> Self {
        Self {
            configuration_urls: configuration_urls.into(),
            fetcher,
            selector: ApiServerSelector::new(prober),
            fallback_payment_presentation,
            desktop_target: Arc::from("x86_64-pc-windows-msvc"),
        }
    }
}

#[async_trait]
trait ConfigurationFetcher: Send + Sync {
    async fn fetch(&self, url: &Url) -> Result<Vec<u8>, ()>;
}

struct HttpConfigurationFetcher {
    client: Client,
}

#[async_trait]
impl ConfigurationFetcher for HttpConfigurationFetcher {
    async fn fetch(&self, url: &Url) -> Result<Vec<u8>, ()> {
        let mut response = self
            .client
            .get(url.clone())
            .header(CACHE_CONTROL, "no-store")
            .send()
            .await
            .map_err(|_| ())?;
        if !response.status().is_success() {
            return Err(());
        }
        read_bounded(&mut response, MAX_CONFIGURATION_BYTES).await
    }
}

async fn read_bounded(response: &mut Response, maximum_bytes: usize) -> Result<Vec<u8>, ()> {
    if response
        .content_length()
        .is_some_and(|length| usize::try_from(length).map_or(true, |length| length > maximum_bytes))
    {
        return Err(());
    }
    let capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or_default();
    let mut bytes = Vec::with_capacity(capacity);
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if chunk.len() > maximum_bytes.saturating_sub(bytes.len()) {
            return Err(());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[derive(Clone)]
struct ApiServerSelector {
    prober: Arc<dyn EndpointProber>,
}

impl ApiServerSelector {
    fn new(prober: Arc<dyn EndpointProber>) -> Self {
        Self { prober }
    }

    async fn select(
        &self,
        candidates: Vec<PanelEndpoint>,
        configuration: &ValidatedProbe,
    ) -> EndpointSelection {
        if candidates.is_empty() {
            return EndpointSelection::Failure;
        }
        let mut tasks = JoinSet::new();
        for endpoint in candidates {
            let prober = Arc::clone(&self.prober);
            let configuration = configuration.clone();
            tasks.spawn(async move {
                let response_code = prober.probe(&endpoint, &configuration).await;
                (endpoint, response_code)
            });
        }
        let deadline = tokio::time::sleep(configuration.overall_timeout);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                () = &mut deadline => {
                    abort_and_drain(&mut tasks).await;
                    return EndpointSelection::Failure;
                }
                completed = tasks.join_next() => {
                    match completed {
                        Some(Ok((endpoint, Some(response_code)))) => {
                            abort_and_drain(&mut tasks).await;
                            return EndpointSelection::Success {
                                endpoint: Box::new(endpoint),
                                response_code,
                            };
                        }
                        Some(_) => {}
                        None => return EndpointSelection::Failure,
                    }
                }
            }
        }
    }
}

async fn abort_and_drain(tasks: &mut JoinSet<(PanelEndpoint, Option<u16>)>) {
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

enum EndpointSelection {
    Success {
        endpoint: Box<PanelEndpoint>,
        response_code: u16,
    },
    Failure,
}

#[async_trait]
trait EndpointProber: Send + Sync {
    async fn probe(&self, endpoint: &PanelEndpoint, configuration: &ValidatedProbe) -> Option<u16>;
}

struct HttpEndpointProber {
    desktop_version_name: Arc<str>,
}

#[async_trait]
impl EndpointProber for HttpEndpointProber {
    async fn probe(&self, endpoint: &PanelEndpoint, configuration: &ValidatedProbe) -> Option<u16> {
        let client = build_discovered_endpoint_client(
            endpoint,
            configuration.connect_timeout,
            configuration.request_timeout,
            &format!("TOPNODE-Desktop-Probe/{}", self.desktop_version_name),
        )
        .ok()?;
        let url = endpoint.probe_url(&configuration.path)?;
        let response = client
            .get(url)
            .header(CACHE_CONTROL, "no-store")
            .send()
            .await
            .ok()?;
        Some(response.status().as_u16())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteConfigurationWire {
    #[serde(rename = "baseApiServer")]
    base_api_servers: Vec<String>,
    api_probe: ApiProbeWire,
    version: VersionWire,
    #[serde(default)]
    fake: Option<FakeConfigurationWire>,
    #[serde(default)]
    payment: Option<RemotePaymentWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiProbeWire {
    method: String,
    path: String,
    strategy: String,
    connect_timeout_ms: u64,
    request_timeout_ms: u64,
    overall_timeout_ms: u64,
    cancel_remaining: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VersionWire {
    metadata: VersionMetadataWire,
    download: VersionDownloadWire,
    #[serde(default)]
    downloads: BTreeMap<String, VersionDownloadWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VersionMetadataWire {
    version_code: u64,
    version_name: String,
    #[serde(default, rename = "updateInfo")]
    _update_info: String,
    #[serde(default)]
    #[serde(rename = "forceUpdate")]
    _force_update: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VersionDownloadWire {
    down_type: String,
    url: String,
    file_name: String,
    mime_type: String,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct FakeConfigurationWire {
    enable: bool,
    #[serde(rename = "fakeSNI")]
    fake_sni: String,
    real: Vec<RealEndpointWire>,
}

#[derive(Deserialize)]
struct RealEndpointWire {
    ip: String,
    domain: String,
    pk: String,
}

#[derive(Deserialize)]
struct RemotePaymentWire {
    #[serde(default)]
    presentation: Option<PaymentPresentation>,
}

struct ValidatedRemoteConfiguration {
    candidates: Vec<PanelEndpoint>,
    probe: ValidatedProbe,
    version: ValidatedVersion,
    payment_presentation: Option<PaymentPresentation>,
}

struct ValidatedVersion {
    version_code: u64,
    version_name: String,
    downloads: BTreeMap<String, Url>,
}

impl ValidatedVersion {
    fn into_remote_desktop_version(self, desktop_target: &str) -> RemoteDesktopVersion {
        let download_url = self.downloads.get(desktop_target).cloned();
        RemoteDesktopVersion {
            version_code: self.version_code,
            version_name: self.version_name,
            build_target: desktop_target.to_owned(),
            download_url,
        }
    }
}

#[derive(Clone)]
struct ValidatedProbe {
    path: String,
    connect_timeout: Duration,
    request_timeout: Duration,
    overall_timeout: Duration,
}

#[derive(Clone, PartialEq, Eq)]
struct ValidatedRealEndpoint {
    ip: IpAddr,
    domain: String,
    spki_pin: [u8; 32],
}

struct ValidatedFakeConfiguration {
    fake_sni: String,
    real: Vec<ValidatedRealEndpoint>,
}

fn parse_and_validate_configuration(bytes: &[u8]) -> Option<ValidatedRemoteConfiguration> {
    let wire: RemoteConfigurationWire = serde_json::from_slice(bytes).ok()?;
    if wire.base_api_servers.len() > MAX_API_SERVERS || wire.base_api_servers.is_empty() {
        return None;
    }
    let mut base_api_servers = Vec::with_capacity(wire.base_api_servers.len());
    for value in wire.base_api_servers {
        let url = normalize_base_url(&value)?;
        if !base_api_servers.contains(&url) {
            base_api_servers.push(url);
        }
    }
    if base_api_servers.is_empty() {
        return None;
    }
    let probe = validate_probe(&wire.api_probe)?;
    let version = validate_version(wire.version)?;
    let fake = match wire.fake {
        Some(fake) if fake.enable => Some(validate_fake(fake)?),
        _ => None,
    };
    let candidates = build_candidates(&base_api_servers, fake.as_ref())?;
    Some(ValidatedRemoteConfiguration {
        candidates,
        probe,
        version,
        payment_presentation: wire.payment.and_then(|payment| payment.presentation),
    })
}

fn validate_probe(wire: &ApiProbeWire) -> Option<ValidatedProbe> {
    let path = wire.path.trim();
    if !wire.method.trim().eq_ignore_ascii_case("GET")
        || !wire.strategy.trim().eq_ignore_ascii_case("FirstSuccessful")
        || !wire.cancel_remaining
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains(['?', '#'])
        || !(MIN_TIMEOUT_MILLIS..=MAX_CONNECT_TIMEOUT_MILLIS).contains(&wire.connect_timeout_ms)
        || !(wire.connect_timeout_ms..=MAX_REQUEST_TIMEOUT_MILLIS)
            .contains(&wire.request_timeout_ms)
        || !(wire.request_timeout_ms..=MAX_OVERALL_TIMEOUT_MILLIS)
            .contains(&wire.overall_timeout_ms)
    {
        return None;
    }
    Some(ValidatedProbe {
        path: path.to_owned(),
        connect_timeout: Duration::from_millis(wire.connect_timeout_ms),
        request_timeout: Duration::from_millis(wire.request_timeout_ms),
        overall_timeout: Duration::from_millis(wire.overall_timeout_ms),
    })
}

fn validate_version(wire: VersionWire) -> Option<ValidatedVersion> {
    let metadata = wire.metadata;
    let version_name = metadata.version_name.trim();
    if metadata.version_code < 1
        || metadata.version_code > MAX_VERSION_CODE
        || version_name.is_empty()
        || version_name.len() > MAX_VERSION_NAME_LENGTH
    {
        return None;
    }
    validate_download(wire.download, None)?;
    if wire.downloads.len() > MAX_PLATFORM_DOWNLOADS {
        return None;
    }
    let mut downloads = BTreeMap::new();
    for (target, download) in wire.downloads {
        let target = normalize_target_name(&target)?;
        let archive_format = platform_archive_format(&target)?;
        let url = validate_download(download, Some(archive_format))?;
        downloads.insert(target, url);
    }
    Some(ValidatedVersion {
        version_code: metadata.version_code,
        version_name: version_name.to_owned(),
        downloads,
    })
}

fn validate_download(
    wire: VersionDownloadWire,
    platform_archive: Option<(&str, &str)>,
) -> Option<Url> {
    let download = wire;
    let down_type = download.down_type.trim();
    if !(down_type.eq_ignore_ascii_case("Native") || down_type.eq_ignore_ascii_case("Browser"))
        || (platform_archive.is_some() && !down_type.eq_ignore_ascii_case("Browser"))
    {
        return None;
    }
    let url = require_https_url(&download.url, true)?;
    let file_name = download.file_name.trim();
    let mime_type = download.mime_type.trim();
    if file_name.is_empty()
        || file_name.len() > MAX_FILE_NAME_LENGTH
        || file_name.contains(['/', '\\', '\0'])
        || mime_type.is_empty()
        || mime_type.len() > MAX_MIME_TYPE_LENGTH
        || mime_type.chars().any(char::is_control)
    {
        return None;
    }
    if let Some((extension, expected_mime_type)) = platform_archive
        && (!file_name.ends_with(extension)
            || !url.path().ends_with(extension)
            || !mime_type.eq_ignore_ascii_case(expected_mime_type))
    {
        return None;
    }
    Some(url)
}

fn platform_archive_format(target: &str) -> Option<(&'static str, &'static str)> {
    match target {
        "x86_64-pc-windows-msvc" | "aarch64-pc-windows-msvc" => Some((".zip", "application/zip")),
        "x86_64-unknown-linux-gnu"
        | "aarch64-unknown-linux-gnu"
        | "x86_64-apple-darwin"
        | "aarch64-apple-darwin" => Some((".tar.gz", "application/gzip")),
        _ => None,
    }
}

fn normalize_target_name(value: &str) -> Option<String> {
    let target = value.trim();
    if target.is_empty()
        || target.len() > MAX_TARGET_NAME_LENGTH
        || !target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return None;
    }
    Some(target.to_owned())
}

fn normalize_version_name(value: &str) -> Option<String> {
    let version_name = value.trim();
    let mut bytes = version_name.bytes();
    if version_name.len() > MAX_VERSION_NAME_LENGTH
        || !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return None;
    }
    Some(version_name.to_owned())
}

fn validate_fake(wire: FakeConfigurationWire) -> Option<ValidatedFakeConfiguration> {
    if wire.real.is_empty() || wire.real.len() > MAX_FRONTED_ENDPOINTS {
        return None;
    }
    let fake_sni = normalize_dns_name(&wire.fake_sni)?;
    let mut real = Vec::with_capacity(wire.real.len());
    for endpoint in wire.real {
        let endpoint = ValidatedRealEndpoint {
            ip: endpoint.ip.trim().parse().ok()?,
            domain: normalize_dns_name(&endpoint.domain)?,
            spki_pin: decode_spki_pin(&endpoint.pk)?,
        };
        if !real.contains(&endpoint) {
            real.push(endpoint);
        }
    }
    if real.is_empty() {
        return None;
    }
    Some(ValidatedFakeConfiguration { fake_sni, real })
}

fn build_candidates(
    base_api_servers: &[Url],
    fake: Option<&ValidatedFakeConfiguration>,
) -> Option<Vec<PanelEndpoint>> {
    let mut candidates = Vec::new();
    for logical_url in base_api_servers {
        let logical_host = logical_url.host_str()?;
        let matching_routes = fake
            .map(|fake| {
                fake.real
                    .iter()
                    .filter(|route| route.domain == logical_host)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if matching_routes.is_empty() {
            let endpoint = PanelEndpoint::direct(logical_url.clone());
            if !candidates.contains(&endpoint) {
                candidates.push(endpoint);
            }
            continue;
        }
        let fake = fake?;
        for route in matching_routes {
            let endpoint = PanelEndpoint::fronted(
                logical_url.clone(),
                fake.fake_sni.clone(),
                route.ip,
                route.spki_pin,
            )
            .ok()?;
            if !candidates.contains(&endpoint) {
                candidates.push(endpoint);
            }
        }
    }
    (!candidates.is_empty()).then_some(candidates)
}

fn normalize_base_url(value: &str) -> Option<Url> {
    let mut url = require_https_url(value, false)?;
    if url.cannot_be_a_base() || url.host_str().is_none() {
        return None;
    }
    if !url.path().ends_with('/') {
        url.path_segments_mut().ok()?.push("");
    }
    Some(url)
}

fn require_https_url(value: &str, allow_query: bool) -> Option<Url> {
    let url = Url::parse(value.trim()).ok()?;
    (url.scheme() == "https"
        && !url.cannot_be_a_base()
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && (allow_query || url.query().is_none())
        && url.fragment().is_none())
    .then_some(url)
}

fn normalize_dns_name(value: &str) -> Option<String> {
    let candidate = value.trim();
    if candidate.is_empty()
        || candidate.ends_with('.')
        || candidate.contains('*')
        || candidate.contains(['/', ':', '@', '[', ']'])
    {
        return None;
    }
    let url = Url::parse(&format!("https://{candidate}/")).ok()?;
    let host = url.host_str()?.to_owned();
    if host.len() > 253
        || !host.contains('.')
        || host.parse::<IpAddr>().is_ok()
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return None;
    }
    Some(host)
}

fn decode_spki_pin(value: &str) -> Option<[u8; 32]> {
    let encoded = value.trim().strip_prefix("sha256/")?;
    STANDARD.decode(encoded).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use reqwest::Url;

    use super::{
        ApiServerSelector, ConfigurationFetcher, DESKTOP_STARTUP_CONFIGURATION_URLS,
        EndpointProber, EndpointSelection, PaymentPresentation, RemoteStartupConfigurationLoader,
        RemoteStartupError, ValidatedProbe, parse_and_validate_configuration,
    };
    use crate::PanelEndpoint;

    const VALID_CONFIGURATION: &str = r#"{
      "baseApiServer": ["https://api.anyrelink.top"],
      "apiProbe": {
        "method": "GET",
        "path": "/",
        "strategy": "FirstSuccessful",
        "connectTimeoutMs": 100,
        "requestTimeoutMs": 200,
        "overallTimeoutMs": 1000,
        "cancelRemaining": true
      },
      "version": {
        "metadata": {
          "versionCode": 16,
          "versionName": "2026.08.29-7be466cb",
          "updateInfo": "版本说明",
          "forceUpdate": false
        },
        "download": {
          "downType": "Native",
          "url": "https://soft.example.test/topnode.apk",
          "fileName": "topnode.apk",
          "mimeType": "application/vnd.android.package-archive"
        },
        "downloads": {
          "x86_64-pc-windows-msvc": {
            "downType": "Browser",
            "url": "https://soft.example.test/topnode-desktop-windows-x86_64.zip",
            "fileName": "topnode-desktop-windows-x86_64.zip",
            "mimeType": "application/zip"
          }
        }
      },
      "payment": { "presentation": "browser" }
    }"#;

    #[test]
    fn desktop_sources_are_fixed_in_strict_order() {
        assert_eq!(
            DESKTOP_STARTUP_CONFIGURATION_URLS,
            [
                "https://0x10.topboot.top/desktop.config.json",
                "https://0x11.boot1.top/desktop.config.json",
                "https://0x12.boot2.top/desktop.config.json",
            ]
        );
    }

    #[test]
    fn live_android_style_desktop_document_is_accepted_with_payment_extension() {
        let configuration = parse_and_validate_configuration(VALID_CONFIGURATION.as_bytes())
            .expect("valid remote configuration");

        assert_eq!(configuration.candidates.len(), 1);
        assert_eq!(
            configuration.payment_presentation,
            Some(PaymentPresentation::Browser)
        );
    }

    #[test]
    fn checked_in_desktop_contract_example_remains_valid() {
        let configuration = parse_and_validate_configuration(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/desktop-config.json"
        )))
        .expect("checked-in desktop startup example");

        assert_eq!(configuration.candidates.len(), 1);
        assert_eq!(
            configuration.payment_presentation,
            Some(PaymentPresentation::QrCode)
        );
    }

    #[test]
    fn fake_routes_replace_matching_direct_candidates_and_redact_pins() {
        let configuration = VALID_CONFIGURATION.replace(
            "\"payment\": { \"presentation\": \"browser\" }",
            r#""fake": {
              "enable": true,
              "fakeSNI": "front.example.test",
              "real": [{
                "ip": "203.0.113.10",
                "domain": "api.anyrelink.top",
                "pk": "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
              }]
            }"#,
        );
        let configuration = parse_and_validate_configuration(configuration.as_bytes())
            .expect("valid fronted configuration");

        assert_eq!(configuration.candidates.len(), 1);
        let debug = format!("{:?}", configuration.candidates[0]);
        assert!(debug.contains("fronted"));
        assert!(!debug.contains("AAAA"));
    }

    #[tokio::test]
    async fn loader_advances_strictly_until_the_first_valid_configuration() {
        let fetcher = Arc::new(ScriptedFetcher::new(vec![
            Ok(b"not json".to_vec()),
            Ok(VALID_CONFIGURATION.as_bytes().to_vec()),
            Ok(VALID_CONFIGURATION.as_bytes().to_vec()),
        ]));
        let urls = test_urls();
        let loader = RemoteStartupConfigurationLoader::with_adapters(
            urls.clone(),
            fetcher.clone(),
            Arc::new(ImmediateProber(Some(404))),
            PaymentPresentation::QrCode,
        );

        let result = loader.load().await.expect("second source should resolve");

        assert_eq!(result.source_url(), urls[1].as_str());
        assert_eq!(result.configuration_attempts(), 2);
        assert_eq!(result.probe_response_code(), 404);
        assert_eq!(result.payment_presentation(), PaymentPresentation::Browser);
        assert_eq!(result.desktop_version().version_code(), 16);
        assert_eq!(
            result.desktop_version().available_download_url(15),
            Some("https://soft.example.test/topnode-desktop-windows-x86_64.zip")
        );
        assert_eq!(result.desktop_version().available_download_url(16), None);
        assert_eq!(
            fetcher.calls(),
            vec![urls[0].to_string(), urls[1].to_string()]
        );
    }

    #[tokio::test]
    async fn api_failure_does_not_return_to_a_later_configuration_source() {
        let fetcher = Arc::new(ScriptedFetcher::new(vec![
            Ok(VALID_CONFIGURATION.as_bytes().to_vec()),
            Ok(VALID_CONFIGURATION.as_bytes().to_vec()),
        ]));
        let urls = test_urls();
        let loader = RemoteStartupConfigurationLoader::with_adapters(
            urls.clone(),
            fetcher.clone(),
            Arc::new(ImmediateProber(None)),
            PaymentPresentation::QrCode,
        );

        let error = loader.load().await.expect_err("probe should fail");

        assert_eq!(
            error,
            RemoteStartupError::ApiConnectivity {
                configuration_attempts: 1,
                api_probe_attempts: 1,
            }
        );
        assert_eq!(fetcher.calls(), vec![urls[0].to_string()]);
    }

    #[tokio::test]
    async fn all_configuration_sources_fail_without_a_fixed_api_fallback() {
        let fetcher = Arc::new(ScriptedFetcher::new(vec![Err(()), Err(()), Err(())]));
        let urls = test_urls();
        let loader = RemoteStartupConfigurationLoader::with_adapters(
            urls.clone(),
            fetcher.clone(),
            Arc::new(ImmediateProber(Some(200))),
            PaymentPresentation::QrCode,
        );

        let error = loader
            .load()
            .await
            .expect_err("all sources should fail closed");

        assert_eq!(error, RemoteStartupError::Configuration { attempts: 3 });
        assert_eq!(
            fetcher.calls(),
            urls.iter().map(ToString::to_string).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn missing_remote_payment_policy_keeps_the_packaged_default() {
        let without_payment = VALID_CONFIGURATION.replace(
            ",\n      \"payment\": { \"presentation\": \"browser\" }",
            "",
        );
        let loader = RemoteStartupConfigurationLoader::with_adapters(
            vec![Url::parse("https://one.example/config").expect("test URL")],
            Arc::new(ScriptedFetcher::new(vec![Ok(without_payment.into_bytes())])),
            Arc::new(ImmediateProber(Some(200))),
            PaymentPresentation::Browser,
        );

        let resolved = loader.load().await.expect("configuration should resolve");

        assert_eq!(
            resolved.payment_presentation(),
            PaymentPresentation::Browser
        );
    }

    #[test]
    fn platform_downloads_require_browser_https_and_exact_target_selection() {
        let configuration = parse_and_validate_configuration(VALID_CONFIGURATION.as_bytes())
            .expect("valid platform download configuration");
        let windows = configuration
            .version
            .into_remote_desktop_version("x86_64-pc-windows-msvc");
        assert_eq!(
            windows.download_url(),
            Some("https://soft.example.test/topnode-desktop-windows-x86_64.zip")
        );

        let configuration = parse_and_validate_configuration(VALID_CONFIGURATION.as_bytes())
            .expect("valid platform download configuration");
        let linux = configuration
            .version
            .into_remote_desktop_version("x86_64-unknown-linux-gnu");
        assert_eq!(linux.download_url(), None);

        let native_platform_download = VALID_CONFIGURATION.replace(
            "\"downType\": \"Browser\",\n            \"url\": \"https://soft.example.test/topnode-desktop-windows-x86_64.zip\"",
            "\"downType\": \"Native\",\n            \"url\": \"https://soft.example.test/topnode-desktop-windows-x86_64.zip\"",
        );
        assert!(parse_and_validate_configuration(native_platform_download.as_bytes()).is_none());

        let apk_platform_download = VALID_CONFIGURATION
            .replace(
                "https://soft.example.test/topnode-desktop-windows-x86_64.zip",
                "https://soft.example.test/topnode.apk",
            )
            .replace("topnode-desktop-windows-x86_64.zip", "topnode.apk")
            .replace("application/zip", "application/vnd.android.package-archive");
        assert!(parse_and_validate_configuration(apk_platform_download.as_bytes()).is_none());

        let unknown_platform =
            VALID_CONFIGURATION.replace("x86_64-pc-windows-msvc", "x86_64-pc-windows-unknown");
        assert!(parse_and_validate_configuration(unknown_platform.as_bytes()).is_none());
    }

    #[tokio::test]
    async fn first_http_response_wins_and_cancels_slower_probes() {
        let slow_cancelled = Arc::new(AtomicBool::new(false));
        let selector = ApiServerSelector::new(Arc::new(RacingProber {
            slow_cancelled: Arc::clone(&slow_cancelled),
        }));
        let candidates = vec![
            PanelEndpoint::direct(Url::parse("https://slow.example.test/").expect("URL")),
            PanelEndpoint::direct(Url::parse("https://fast.example.test/").expect("URL")),
        ];
        let probe = ValidatedProbe {
            path: "/".to_owned(),
            connect_timeout: Duration::from_millis(100),
            request_timeout: Duration::from_millis(500),
            overall_timeout: Duration::from_secs(1),
        };

        let selected = selector.select(candidates, &probe).await;

        match selected {
            EndpointSelection::Success {
                endpoint,
                response_code,
            } => {
                assert_eq!(endpoint.logical_base_url(), "https://fast.example.test/");
                assert_eq!(response_code, 503);
            }
            EndpointSelection::Failure => panic!("fast response should win"),
        }
        assert!(slow_cancelled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    #[ignore = "requires the public production bootstrap and Panel network"]
    async fn production_bootstrap_smoke_test() {
        let loader = RemoteStartupConfigurationLoader::production(
            PaymentPresentation::QrCode,
            "x86_64-pc-windows-msvc",
            "2026.09.01-abcdef12",
        )
        .expect("production loader");

        let resolved = loader
            .load()
            .await
            .expect("production bootstrap should resolve");

        assert!(
            DESKTOP_STARTUP_CONFIGURATION_URLS.contains(&resolved.source_url()),
            "unexpected source: {}",
            resolved.source_url()
        );
        assert!(
            resolved
                .endpoint()
                .logical_base_url()
                .starts_with("https://")
        );
        eprintln!("resolved production startup: {resolved:?}");
    }

    fn test_urls() -> Vec<Url> {
        [
            "https://one.example/config",
            "https://two.example/config",
            "https://three.example/config",
        ]
        .into_iter()
        .map(|url| Url::parse(url).expect("test URL"))
        .collect()
    }

    struct ScriptedFetcher {
        responses: Mutex<VecDeque<Result<Vec<u8>, ()>>>,
        calls: Mutex<Vec<String>>,
    }

    impl ScriptedFetcher {
        fn new(responses: Vec<Result<Vec<u8>, ()>>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().expect("calls lock").clone()
        }
    }

    #[async_trait]
    impl ConfigurationFetcher for ScriptedFetcher {
        async fn fetch(&self, url: &Url) -> Result<Vec<u8>, ()> {
            self.calls.lock().expect("calls lock").push(url.to_string());
            self.responses
                .lock()
                .expect("responses lock")
                .pop_front()
                .unwrap_or(Err(()))
        }
    }

    struct ImmediateProber(Option<u16>);

    #[async_trait]
    impl EndpointProber for ImmediateProber {
        async fn probe(
            &self,
            _endpoint: &PanelEndpoint,
            _configuration: &ValidatedProbe,
        ) -> Option<u16> {
            self.0
        }
    }

    struct RacingProber {
        slow_cancelled: Arc<AtomicBool>,
    }

    #[async_trait]
    impl EndpointProber for RacingProber {
        async fn probe(
            &self,
            endpoint: &PanelEndpoint,
            _configuration: &ValidatedProbe,
        ) -> Option<u16> {
            if endpoint.logical_base_url().contains("fast") {
                tokio::time::sleep(Duration::from_millis(10)).await;
                return Some(503);
            }
            let _guard = CancellationGuard(Arc::clone(&self.slow_cancelled));
            tokio::time::sleep(Duration::from_secs(10)).await;
            None
        }
    }

    struct CancellationGuard(Arc<AtomicBool>);

    impl Drop for CancellationGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
}
