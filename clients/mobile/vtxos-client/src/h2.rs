//! One HTTP/2 connection as a gRPC channel for tonic's generated clients: the enclave's attested
//! connection (with an interaction's token), or the ASP's.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::{header, HeaderValue, Uri};
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tonic::body::BoxBody;

use crate::error::{Error, Result};

/// A gRPC channel over one HTTP/2 connection, optionally carrying an `Authorization` header.
#[derive(Clone)]
pub struct Channel {
    send: SendRequest<BoxBody>,
    authorization: Option<HeaderValue>,
}

impl Channel {
    pub fn new(send: SendRequest<BoxBody>, authorization: Option<HeaderValue>) -> Self {
        Self {
            send,
            authorization,
        }
    }
}

impl tower_service::Service<http::Request<BoxBody>> for Channel {
    type Response = http::Response<hyper::body::Incoming>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.send.poll_ready(cx)
    }

    fn call(&mut self, mut request: http::Request<BoxBody>) -> Self::Future {
        if let Some(value) = &self.authorization {
            request
                .headers_mut()
                .insert(header::AUTHORIZATION, value.clone());
        }
        Box::pin(self.send.send_request(request))
    }
}

/// HTTP/2 over `io`, its connection driven in the background.
pub(crate) async fn handshake<IO>(io: IO, peer: &str) -> Result<SendRequest<BoxBody>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (send, driver) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
            .await
            .map_err(|e| Error::Transport(format!("HTTP/2 with {peer}: {e}")))?;
    tokio::spawn(driver);
    Ok(send)
}

/// A gRPC origin on the public network: `https://` with the web PKI's roots, or `http://` in the
/// clear, which only a regtest ASP on a developer's machine should be.
pub(crate) async fn connect_public(url: &str) -> Result<(SendRequest<BoxBody>, Uri)> {
    let origin: Uri = url
        .parse()
        .map_err(|e| Error::Transport(format!("URL {url:?}: {e}")))?;
    let host = origin
        .host()
        .ok_or_else(|| Error::Transport(format!("URL {url:?} has no host")))?
        .to_string();
    let tls = match origin.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        _ => {
            return Err(Error::Transport(format!(
                "URL {url:?} is neither https nor http"
            )))
        }
    };
    let port = origin.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| Error::Transport(format!("connect {host}:{port}: {e}")))?;
    let send = if tls {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Transport(format!("TLS versions: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|e| Error::Transport(format!("server name {host:?}: {e}")))?;
        let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
            .map_err(|e| Error::Transport(format!("TLS with {host}: {e}")))?;
        handshake(stream, &host).await?
    } else {
        handshake(tcp, &host).await?
    };
    Ok((send, origin))
}
