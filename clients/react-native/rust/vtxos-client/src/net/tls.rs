//! TLS to the enclave: no CA, no name, and the certificate taken on the attestation's word, but
//! the handshake checked.
//!
//! The runtime makes a self-signed certificate at every boot and binds its hash into each
//! attestation document. So a client accepts whatever leaf it is served, keeps it, and lets the
//! attestation decide whether it is the enclave's. What it must not skip is the handshake
//! signature: that is what proves the peer holds the key of the certificate it presented. A
//! verifier that waves it through accepts anyone who copied the certificate.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::error::{Error, Result};

/// Accepts any leaf, and checks the handshake signature against it.
#[derive(Debug)]
struct AnyLeafSignedHandshake {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AnyLeafSignedHandshake {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        // The attestation vouches for the certificate, not a CA: see the module docs.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A TLS connection to the enclave, and the certificate it served.
pub struct Connected {
    pub stream: TlsStream<TcpStream>,
    /// The leaf the peer presented, DER: what an attestation must name.
    pub certificate: Vec<u8>,
}

impl Connected {
    /// The SHA-256 of the served certificate: what approvals bind and attestations name.
    pub fn certificate_sha256(&self) -> [u8; 32] {
        Sha256::digest(&self.certificate).into()
    }
}

/// Connect to `host:port`, offering ALPN `h2`, with SNI `server_name`.
pub async fn connect(host: &str, port: u16, server_name: &str) -> Result<Connected> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Transport(format!("TLS versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyLeafSignedHandshake { provider }))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];

    let tcp = TcpStream::connect((host, port))
        .await
        .map_err(|e| Error::Transport(format!("connect {host}:{port}: {e}")))?;
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|e| Error::Transport(format!("server name {server_name:?}: {e}")))?;
    let stream = TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .map_err(|e| Error::Transport(format!("TLS with {host}:{port}: {e}")))?;
    let (_, session) = stream.get_ref();
    if session.alpn_protocol() != Some(b"h2") {
        return Err(Error::Transport(format!(
            "{host}:{port} does not speak HTTP/2"
        )));
    }
    let certificate = session
        .peer_certificates()
        .and_then(|chain| chain.first())
        .map(|leaf| leaf.to_vec())
        .ok_or_else(|| Error::Transport(format!("{host}:{port} served no certificate")))?;
    Ok(Connected {
        stream,
        certificate,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustls::pki_types::PrivateKeyDer;
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    /// Serves `certificate`, signing the handshake with `key`, which may not be its own.
    #[derive(Debug)]
    struct Serve(Arc<CertifiedKey>);

    impl ResolvesServerCert for Serve {
        fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    fn self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["enclave".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        (
            cert.der().clone(),
            PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
        )
    }

    /// A server presenting `certificate` and signing with `key`, on a local port.
    async fn serve(certificate: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> u16 {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let signing = provider.key_provider.load_private_key(key).unwrap();
        let certified = Arc::new(CertifiedKey::new(vec![certificate], signing));
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Serve(certified)));
        config.alpn_protocols = vec![b"h2".to_vec()];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _ = acceptor.accept(tcp).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn the_served_certificate_is_kept() {
        let (certificate, key) = self_signed();
        let port = serve(certificate.clone(), key).await;
        let connected = connect("127.0.0.1", port, "enclave").await.unwrap();
        assert_eq!(connected.certificate, certificate.to_vec());
    }

    /// The point of the verifier: the enclave's certificate, copied by someone without its key,
    /// is refused at the handshake.
    #[tokio::test]
    async fn a_copied_certificate_without_its_key_is_refused() {
        let (certificate, _) = self_signed();
        let (_, someone_elses_key) = self_signed();
        let port = serve(certificate, someone_elses_key).await;
        let err = connect("127.0.0.1", port, "enclave")
            .await
            .err()
            .expect("refused");
        assert!(matches!(err, Error::Transport(_)), "{err}");
    }
}
