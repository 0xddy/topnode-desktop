use std::{iter, sync::Arc};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x509_parser::prelude::{FromDer, X509Certificate};

pub(crate) const FIXED_PANEL_HOST: &str = "api.anyrelink.top";

const FIXED_PANEL_SPKI_PINS: [&str; 4] = [
    "sha256/RPNLRtAKDYyIoJS+6ocH2s2eEA90HWVtmitZwo6ZE9I=",
    "sha256/s/tdAOmUzd8syaTuqfgGvFcn6DzA5Cmb+Vby1ST+U3Y=",
    "sha256/sCkq5UWXjg+7mKu9lMhhYF5bGLsy7VI/UNW3tccdR7w=",
    "sha256/diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=",
];

#[derive(Debug, Error)]
pub(crate) enum TlsConfigurationError {
    #[error("SPKI pin 列表不能为空")]
    EmptyPins,
    #[error("第 {index} 个 SPKI pin 不是有效的 sha256/<base64> 值")]
    InvalidPin { index: usize },
    #[error("无法构建 WebPKI 服务器证书验证器")]
    WebPkiVerifier,
    #[error("无法使用当前加密提供器启用默认 TLS 协议")]
    ProtocolVersions,
    #[error("TLS 服务器名称无效")]
    InvalidServerName,
}

/// Builds the production Panel TLS configuration.
///
/// The custom verifier always delegates to rustls' `WebPkiServerVerifier`
/// first. Pinning is an additional check and therefore cannot bypass trust
/// chain, hostname, validity period, or handshake-signature verification.
pub(crate) fn fixed_panel_client_config() -> Result<ClientConfig, TlsConfigurationError> {
    panel_client_config(&FIXED_PANEL_SPKI_PINS, None, None)
}

/// Builds the fronted Panel TLS policy.
///
/// TLS is routed with `expected_sni`, while `WebPKI` hostname verification uses
/// `logical_host`; the route pin remains an additional requirement.
pub(crate) fn fronted_panel_client_config(
    logical_host: &str,
    expected_sni: &str,
    spki_pin: [u8; 32],
) -> Result<ClientConfig, TlsConfigurationError> {
    let logical_host = ServerName::try_from(logical_host.to_owned())
        .map_err(|_| TlsConfigurationError::InvalidServerName)?;
    let expected_sni = ServerName::try_from(expected_sni.to_owned())
        .map_err(|_| TlsConfigurationError::InvalidServerName)?;
    panel_client_config(&[], Some(spki_pin), Some((logical_host, expected_sni)))
}

fn panel_client_config(
    encoded_pins: &[&str],
    decoded_pin: Option<[u8; 32]>,
    server_names: Option<(ServerName<'static>, ServerName<'static>)>,
) -> Result<ClientConfig, TlsConfigurationError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .cloned()
        .collect::<RootCertStore>();
    let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|_| TlsConfigurationError::WebPkiVerifier)?;
    let verifier = SpkiPinVerifier::new(webpki, encoded_pins, decoded_pin, server_names)?;

    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsConfigurationError::ProtocolVersions)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth())
}

struct SpkiPinVerifier {
    webpki: Arc<WebPkiServerVerifier>,
    pins: Vec<[u8; 32]>,
    verified_server_name: Option<ServerName<'static>>,
    expected_sni: Option<ServerName<'static>>,
}

impl std::fmt::Debug for SpkiPinVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SpkiPinVerifier")
            .field("webpki", &self.webpki)
            .field("pins", &"[REDACTED]")
            .field("verified_server_name", &self.verified_server_name)
            .field("expected_sni", &self.expected_sni)
            .finish()
    }
}

impl SpkiPinVerifier {
    fn new(
        webpki: Arc<WebPkiServerVerifier>,
        encoded_pins: &[&str],
        decoded_pin: Option<[u8; 32]>,
        server_names: Option<(ServerName<'static>, ServerName<'static>)>,
    ) -> Result<Self, TlsConfigurationError> {
        if encoded_pins.is_empty() && decoded_pin.is_none() {
            return Err(TlsConfigurationError::EmptyPins);
        }
        let mut pins: Vec<[u8; 32]> = encoded_pins
            .iter()
            .enumerate()
            .map(|(index, pin)| {
                parse_sha256_pin(pin).map_err(|()| TlsConfigurationError::InvalidPin { index })
            })
            .collect::<Result<_, _>>()?;
        pins.extend(decoded_pin);
        let (verified_server_name, expected_sni) =
            server_names.map_or((None, None), |names| (Some(names.0), Some(names.1)));
        Ok(Self {
            webpki,
            pins,
            verified_server_name,
            expected_sni,
        })
    }
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self
            .expected_sni
            .as_ref()
            .is_some_and(|expected| expected != server_name)
        {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        let verified_server_name = self.verified_server_name.as_ref().unwrap_or(server_name);
        let verified = self.webpki.verify_server_cert(
            end_entity,
            intermediates,
            verified_server_name,
            ocsp_response,
            now,
        )?;

        let matches = iter::once(end_entity)
            .chain(intermediates)
            .filter_map(certificate_spki_sha256)
            .any(|digest| self.pins.contains(&digest));
        if !matches {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

fn parse_sha256_pin(value: &str) -> Result<[u8; 32], ()> {
    let encoded = value.strip_prefix("sha256/").ok_or(())?;
    STANDARD
        .decode(encoded)
        .map_err(|_| ())?
        .try_into()
        .map_err(|_| ())
}

fn certificate_spki_sha256(certificate: &CertificateDer<'_>) -> Option<[u8; 32]> {
    let (_, certificate) = X509Certificate::from_der(certificate.as_ref()).ok()?;
    Some(spki_sha256(certificate.public_key().raw))
}

fn spki_sha256(subject_public_key_info_der: &[u8]) -> [u8; 32] {
    Sha256::digest(subject_public_key_info_der).into()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustls::{RootCertStore, client::WebPkiServerVerifier};

    use super::{
        FIXED_PANEL_SPKI_PINS, SpkiPinVerifier, fixed_panel_client_config,
        fronted_panel_client_config, parse_sha256_pin, spki_sha256,
    };

    #[test]
    fn fixed_tls_configuration_can_be_built() {
        fixed_panel_client_config().expect("valid fixed Panel TLS policy");
    }

    #[test]
    fn fronted_tls_configuration_separates_logical_identity_and_sni() {
        fronted_panel_client_config("api.example.test", "front.example.test", [7; 32])
            .expect("valid fronted Panel TLS policy");
    }

    #[test]
    fn verifier_debug_redacts_server_provided_pins() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let roots = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned()
            .collect::<RootCertStore>();
        let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .expect("WebPKI verifier");
        let verifier =
            SpkiPinVerifier::new(webpki, &[], Some([65; 32]), None).expect("pin verifier");

        let debug = format!("{verifier:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("65"));
    }

    #[test]
    fn fixed_pins_are_valid_sha256_digests() {
        for pin in FIXED_PANEL_SPKI_PINS {
            assert!(parse_sha256_pin(pin).is_ok());
        }
    }

    #[test]
    fn malformed_pins_are_rejected() {
        assert!(parse_sha256_pin("sha1/AAAAAAAAAAAAAAAAAAAAAAAAAAA=").is_err());
        assert!(parse_sha256_pin("sha256/not-base64").is_err());
        assert!(parse_sha256_pin("sha256/AAAA").is_err());
    }

    #[test]
    fn spki_digest_matches_any_configured_pin() {
        let first = spki_sha256(b"first subject public key info");
        let second = spki_sha256(b"second subject public key info");
        let other = spki_sha256(b"unrelated subject public key info");

        assert!([first, second].contains(&second));
        assert!(![first, second].contains(&other));
    }
}
