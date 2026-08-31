use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use reqwest::{
    Client, Url,
    header::{HOST, HeaderMap, HeaderValue},
};
use thiserror::Error;

use crate::tls::{fixed_panel_client_config, fronted_panel_client_config};

/// A logical Panel URL together with the route used to reach it.
///
/// The fronted route deliberately keeps its SPKI pin out of `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct PanelEndpoint {
    logical_base_url: Url,
    transport_base_url: Url,
    route: PanelRoute,
}

#[derive(Clone, PartialEq, Eq)]
enum PanelRoute {
    Direct,
    Fronted {
        fake_sni: String,
        connect_ip: IpAddr,
        authority: String,
        spki_pin: [u8; 32],
    },
}

impl PanelEndpoint {
    pub(crate) fn direct(logical_base_url: Url) -> Self {
        Self {
            transport_base_url: logical_base_url.clone(),
            logical_base_url,
            route: PanelRoute::Direct,
        }
    }

    pub(crate) fn fronted(
        logical_base_url: Url,
        fake_sni: String,
        connect_ip: IpAddr,
        spki_pin: [u8; 32],
    ) -> Result<Self, EndpointClientError> {
        let authority = logical_authority(&logical_base_url)?;
        let mut transport_base_url = logical_base_url.clone();
        transport_base_url
            .set_host(Some(&fake_sni))
            .map_err(|_| EndpointClientError::InvalidEndpoint)?;
        Ok(Self {
            logical_base_url,
            transport_base_url,
            route: PanelRoute::Fronted {
                fake_sni,
                connect_ip,
                authority,
                spki_pin,
            },
        })
    }

    pub fn logical_base_url(&self) -> &str {
        self.logical_base_url.as_str()
    }

    pub(crate) fn logical_url(&self) -> &Url {
        &self.logical_base_url
    }

    pub(crate) fn transport_url(&self) -> &Url {
        &self.transport_base_url
    }

    pub(crate) fn probe_url(&self, path: &str) -> Option<Url> {
        let url = self.transport_base_url.join(path).ok()?;
        (url.scheme() == "https"
            && url.host_str() == self.transport_base_url.host_str()
            && url.port_or_known_default() == self.transport_base_url.port_or_known_default())
        .then_some(url)
    }
}

impl fmt::Debug for PanelEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let logical_origin = self.logical_base_url.origin().ascii_serialization();
        let transport_origin = self.transport_base_url.origin().ascii_serialization();
        let mut debug = formatter.debug_struct("PanelEndpoint");
        debug
            .field("logical_base_url", &logical_origin)
            .field("transport_base_url", &transport_origin);
        match &self.route {
            PanelRoute::Direct => {
                debug.field("route", &"direct");
            }
            PanelRoute::Fronted {
                fake_sni,
                connect_ip,
                authority,
                spki_pin: _,
            } => {
                debug
                    .field("route", &"fronted")
                    .field("fake_sni", fake_sni)
                    .field("connect_ip", connect_ip)
                    .field("authority", authority);
            }
        }
        debug.finish()
    }
}

#[derive(Debug, Error)]
pub(crate) enum EndpointClientError {
    #[error("Panel endpoint is invalid")]
    InvalidEndpoint,
    #[error("Panel endpoint TLS policy is invalid")]
    InvalidTls,
    #[error("Panel endpoint HTTP client could not be created")]
    Client,
}

pub(crate) fn build_discovered_endpoint_client(
    endpoint: &PanelEndpoint,
    connect_timeout: Duration,
    request_timeout: Duration,
    user_agent: &str,
) -> Result<Client, EndpointClientError> {
    let builder = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(connect_timeout)
        .timeout(request_timeout)
        .user_agent(user_agent);

    let builder = match &endpoint.route {
        PanelRoute::Direct => builder.use_preconfigured_tls(
            fixed_panel_client_config().map_err(|_| EndpointClientError::InvalidTls)?,
        ),
        PanelRoute::Fronted {
            fake_sni,
            connect_ip,
            authority,
            spki_pin,
        } => {
            let logical_host = endpoint
                .logical_base_url
                .host_str()
                .ok_or(EndpointClientError::InvalidEndpoint)?;
            let port = endpoint
                .transport_base_url
                .port_or_known_default()
                .ok_or(EndpointClientError::InvalidEndpoint)?;
            let mut headers = HeaderMap::new();
            headers.insert(
                HOST,
                HeaderValue::from_str(authority)
                    .map_err(|_| EndpointClientError::InvalidEndpoint)?,
            );
            builder
                // A fronted request requires the HTTP authority to differ from
                // the transport URL's host. Keep this invariant explicit if
                // the workspace enables reqwest's HTTP/2 feature in the future.
                .http1_only()
                .default_headers(headers)
                .resolve(fake_sni, SocketAddr::new(*connect_ip, port))
                .use_preconfigured_tls(
                    fronted_panel_client_config(logical_host, fake_sni, *spki_pin)
                        .map_err(|_| EndpointClientError::InvalidTls)?,
                )
        }
    };

    builder.build().map_err(|_| EndpointClientError::Client)
}

fn logical_authority(url: &Url) -> Result<String, EndpointClientError> {
    let host = url.host_str().ok_or(EndpointClientError::InvalidEndpoint)?;
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    match url.port() {
        Some(port) => Ok(format!("{host}:{port}")),
        None => Ok(host),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use reqwest::Url;

    use super::PanelEndpoint;

    #[test]
    fn fronted_endpoint_separates_logical_and_transport_hosts() {
        let endpoint = PanelEndpoint::fronted(
            Url::parse("https://api.example.test/panel/").expect("logical URL"),
            "front.example.test".to_owned(),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            [7; 32],
        )
        .expect("fronted endpoint");

        assert_eq!(
            endpoint.logical_base_url(),
            "https://api.example.test/panel/"
        );
        assert_eq!(
            endpoint.transport_url().as_str(),
            "https://front.example.test/panel/"
        );
    }

    #[test]
    fn endpoint_debug_never_contains_the_spki_pin() {
        let endpoint = PanelEndpoint::fronted(
            Url::parse("https://api.example.test/").expect("logical URL"),
            "front.example.test".to_owned(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            [65; 32],
        )
        .expect("fronted endpoint");

        let debug = format!("{endpoint:?}");
        assert!(!debug.contains("spki"));
        assert!(!debug.contains("65"));
    }
}
