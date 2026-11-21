//! The enclave: one HTTP/2 connection over [`super::tls`], attested on every options call, and
//! the sign-in that precedes every call to what the enclave runs.
//!
//! The order is the protocol's. An options call carries a fresh `x-enclave-nonce` and comes back
//! with an attestation document, which must verify under the pins and name the certificate this
//! connection served. Only then does anything secret go out — a dealt share, an ECDH partial, a
//! signature — and only on that same connection. A guest call then spends the token on it too.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use bytes::Bytes;
use enclave_auth::client::{Client, Registering};
use enclave_auth::wire::{RegisterVerifyResponse, TokenResponse};
use http::{header, Method, Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http2::SendRequest;
use rand_core::{OsRng, RngCore};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::Mutex;

use super::h2::Body;
use crate::core::keys::{Polynomial, WalletRecord};
use crate::error::{Error, Result};
use crate::net::tls;

/// AWS Nitro's root, which a real enclave's documents chain to.
pub use enclave_client::AWS_NITRO_ROOT_G1_PEM;

/// What the app pins: the root the documents chain to, the runtime image and the guest.
#[derive(Debug, Clone)]
pub struct Pins {
    /// PEM or DER. [`enclave_client::AWS_NITRO_ROOT_G1_PEM`] for a real enclave; a dev enclave
    /// prints its own at each boot.
    pub trust_root: Vec<u8>,
    /// 48 bytes.
    pub pcr0: Vec<u8>,
    /// 48 bytes.
    pub pcr16: Vec<u8>,
    /// How old a document may be.
    pub max_age: Duration,
}

impl From<&Pins> for enclave_client::Pins {
    fn from(p: &Pins) -> Self {
        enclave_client::Pins {
            trust_root: p.trust_root.clone(),
            pcr0: p.pcr0.clone(),
            pcr16: p.pcr16.clone(),
            max_age: p.max_age,
        }
    }
}

/// An enclave runtime, by URL and pins. Connects lazily and reconnects when the connection drops;
/// every interaction re-attests the connection it runs on.
pub struct Enclave {
    origin: Uri,
    host: String,
    port: u16,
    pins: enclave_client::Pins,
    connection: Mutex<Option<Connection>>,
}

/// One HTTP/2 connection to the enclave, and the certificate it served.
#[derive(Clone)]
pub struct Connection {
    send: SendRequest<Body>,
    origin: Uri,
    certificate: Arc<Vec<u8>>,
}

impl Enclave {
    /// `url` is `https://host[:port]`.
    pub fn new(url: &str, pins: &Pins) -> Result<Self> {
        let origin: Uri = url
            .parse()
            .map_err(|e| Error::Transport(format!("the enclave's URL {url:?}: {e}")))?;
        if origin.scheme_str() != Some("https") {
            return Err(Error::Transport(format!(
                "the enclave's URL {url:?} is not https"
            )));
        }
        let host = origin
            .host()
            .ok_or_else(|| Error::Transport(format!("the enclave's URL {url:?} has no host")))?
            .to_string();
        let port = origin.port_u16().unwrap_or(443);
        Ok(Enclave {
            origin,
            host,
            port,
            pins: pins.into(),
            connection: Mutex::new(None),
        })
    }

    /// The open connection, or a new one.
    pub async fn connection(&self) -> Result<Connection> {
        let mut slot = self.connection.lock().await;
        if let Some(c) = slot.as_ref().filter(|c| !c.send.is_closed()) {
            return Ok(c.clone());
        }
        let connected = tls::connect(&self.host, self.port, &self.host).await?;
        let certificate = Arc::new(connected.certificate);
        let send = crate::net::h2::handshake(connected.stream, "the enclave").await?;
        let c = Connection {
            send,
            origin: self.origin.clone(),
            certificate,
        };
        *slot = Some(c.clone());
        Ok(c)
    }

    /// Register a new wallet whose polynomial comes from the passkey's PRF output: the DKG with
    /// the runtime, signed with the finished share. Returns what the app keeps.
    pub async fn register(&self, prf: &[u8; 32]) -> Result<WalletRecord> {
        let polynomial = Polynomial::from_prf(prf);
        let registering = Registering::new(&polynomial.a0, &polynomial.a1, &mut OsRng)
            .map_err(Error::Protocol)?;
        let connection = self.connection().await?;
        let (options, certificate) = connection
            .attested("/auth/register/options", &registering.options(), &self.pins)
            .await?;
        let (body, pending) = registering
            .verify(&options, &certificate, &mut OsRng)
            .map_err(Error::Protocol)?;
        let answer: RegisterVerifyResponse =
            connection.post("/auth/register/verify", &body).await?;
        let registered = pending.finish(&answer).map_err(Error::Protocol)?;
        if answer.tenant_id != hex::encode(registered.client.tenant()) {
            return Err(Error::Protocol("the runtime named another tenant".into()));
        }
        Ok(WalletRecord::new(
            &registered.client,
            &registered.dealt_share,
        ))
    }

    /// Sign in to one interaction, `POST path`: an attested options call, then the signature and
    /// the ECDH partial on the same connection, whose answer must carry a partial the runtime's
    /// share made. Returns that connection and the token to spend on it.
    pub async fn sign_in(&self, client: &Client, path: &str) -> Result<(Connection, String)> {
        let connection = self.connection().await?;
        let (options, certificate) = connection
            .attested(
                "/auth/request/options",
                &client.options("POST", path, None),
                &self.pins,
            )
            .await?;
        let (body, sign_in) = client
            .verify(&options, "POST", path, None, &certificate, &mut OsRng)
            .map_err(Error::Protocol)?;
        let answer: TokenResponse = connection.post("/auth/request/verify", &body).await?;
        sign_in.finish(&answer).map_err(Error::Protocol)?;
        Ok((connection, answer.token))
    }
}

impl Connection {
    /// The HTTP/2 handle and the origin, for a call on this connection.
    pub fn parts(&self) -> (SendRequest<Body>, Uri) {
        (self.send.clone(), self.origin.clone())
    }

    /// An options call: `body` with a fresh nonce, and its answer's attestation verified under
    /// `pins` against the certificate this connection served. Returns the answer and that
    /// certificate's SHA-256.
    async fn attested<B: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        pins: &enclave_client::Pins,
    ) -> Result<(R, [u8; 32])> {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let nonce_header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
        let (headers, bytes) = self.exchange(path, body, Some(&nonce_header)).await?;
        let document = headers
            .get("x-enclave-attestation")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Error::Attestation(format!("{path} answered without a document")))?;
        let cose = base64::engine::general_purpose::STANDARD
            .decode(document)
            .map_err(|e| Error::Attestation(format!("{path}'s document is not base64: {e}")))?;
        let attested = enclave_client::verify_connection(
            &cose,
            pins,
            &self.certificate,
            &nonce,
            SystemTime::now(),
        )
        .map_err(|e| Error::Attestation(e.to_string()))?;
        let answer = serde_json::from_slice(&bytes)
            .map_err(|e| Error::Protocol(format!("{path}'s answer: {e}")))?;
        Ok((answer, attested.certificate_sha256))
    }

    /// A call that is not attested: a verify call, on the connection an options call attested.
    async fn post<B: Serialize, R: DeserializeOwned>(&self, path: &str, body: &B) -> Result<R> {
        let (_, bytes) = self.exchange(path, body, None).await?;
        serde_json::from_slice(&bytes).map_err(|e| Error::Protocol(format!("{path}'s answer: {e}")))
    }

    async fn exchange<B: Serialize>(
        &self,
        path: &str,
        body: &B,
        nonce: Option<&str>,
    ) -> Result<(http::HeaderMap, Bytes)> {
        let json = serde_json::to_vec(body).expect("the wire types serialize");
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(self.uri(path)?)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(nonce) = nonce {
            request = request.header("x-enclave-nonce", nonce);
        }
        let request = request
            .body(boxed(json))
            .map_err(|e| Error::Protocol(format!("{path}: {e}")))?;
        let response = self
            .send
            .clone()
            .send_request(request)
            .await
            .map_err(|e| Error::Transport(format!("{path}: {e}")))?;
        let (parts, body) = response.into_parts();
        let bytes = body
            .collect()
            .await
            .map_err(|e| Error::Transport(format!("{path}'s answer: {e}")))?
            .to_bytes();
        if !parts.status.is_success() {
            return Err(Error::Auth {
                status: parts.status.as_u16(),
                message: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }
        Ok((parts.headers, bytes))
    }

    pub(super) fn uri(&self, path: &str) -> Result<Uri> {
        let mut parts = self.origin.clone().into_parts();
        parts.path_and_query = Some(
            path.parse()
                .map_err(|e| Error::Protocol(format!("path {path:?}: {e}")))?,
        );
        Uri::from_parts(parts).map_err(|e| Error::Protocol(format!("path {path:?}: {e}")))
    }
}

fn boxed(bytes: Vec<u8>) -> Body {
    Full::new(Bytes::from(bytes)).boxed_unsync()
}
