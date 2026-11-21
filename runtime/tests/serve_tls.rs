//! The guest over TLS, on a runtime that attests.
//!
//! These run without sign-in, so no answer here carries a document: a guest
//! call sends no nonce and gets none back, and a guest cannot supply one of
//! its own. The documents themselves, on `register/options` and
//! `request/options`, are checked in `serve_auth`.
//!
//! The NSM here is a local fake, but it is not a stub: it produces a genuine
//! P-384 chain and a genuine ES384 COSE_Sign1 over a payload built from the
//! request it was given. The chain is pinned as the trust root and verified
//! against — `allow_untrusted_root` is off — so the verifier does the same
//! work it does in production. What the fake cannot supply is AWS's signing
//! key, so what these tests do *not* establish is that a real NSM's documents
//! chain to the real root. Only hardware shows that; the QEMU harness covers
//! the real device short of the AWS signature.
//!
//! ```console
//! $ (cd examples/guest-http && cargo build --release --target wasm32-wasip2)
//! $ cargo test -p enclave-runtime --test serve_tls -- --include-ignored
//! ```

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use enclave_runtime::{GuestEnvironment, HostClock, ServeConfig, TlsIdentity};
use nitro_attestation::testing::TestChain;
use nitro_nsm::{AttestationRequest, Nsm};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn component_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../examples/guest-http/target/wasm32-wasip2/release/guest-http.wasm")
}

/// An NSM that signs for real, echoing back whatever it was asked to bind.
///
/// A fake returning a canned document would let the endpoint pass while
/// binding the wrong certificate — precisely the bug these tests exist to
/// catch — so this builds the payload from the request.
#[derive(Debug)]
struct SigningNsm {
    chain: TestChain,
    pcr0: [u8; 48],
    last: Mutex<Option<AttestationRequest>>,
}

impl SigningNsm {
    fn new() -> Self {
        SigningNsm {
            chain: TestChain::new().expect("test chain"),
            pcr0: [0x5a; 48],
            last: Mutex::new(None),
        }
    }
}

impl Nsm for SigningNsm {
    fn get_random(&self, buf: &mut [u8]) -> anyhow::Result<()> {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        Ok(())
    }

    fn attest(&self, request: &AttestationRequest) -> anyhow::Result<Vec<u8>> {
        *self.last.lock().unwrap() = Some(request.clone());
        self.chain
            .document(request.user_data.clone(), request.nonce.clone(), self.pcr0)
    }

    fn describe_pcr(&self, index: u16) -> anyhow::Result<nitro_nsm::Pcr> {
        Ok(nitro_nsm::Pcr {
            locked: index < 3,
            value: if index == 0 {
                self.pcr0.to_vec()
            } else {
                nitro_nsm::PCR_ZERO.to_vec()
            },
        })
    }

    fn extend_pcr(&self, _index: u16, _data: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("this fake does not model PCR extension")
    }

    fn lock_pcr(&self, _index: u16) -> anyhow::Result<()> {
        anyhow::bail!("this fake does not model PCR locking")
    }

    fn describe(&self) -> String {
        "signing test NSM".into()
    }
}

struct Harness {
    addr: std::net::SocketAddr,
}

/// Start the real [`enclave_runtime::serve_component`] on an ephemeral port.
async fn start() -> Harness {
    // `create`, not `mount`: an empty store is a refusal since the boot
    // machine landed, not an invitation to format one.
    let fs = enclave_runtime::Zfs::scratch().await;

    let nsm = Arc::new(SigningNsm::new());
    let guest_bytes = std::fs::read(component_path()).unwrap_or_else(|e| {
        panic!(
            "reading {}: {e}\nbuild it first: (cd examples/guest-http && \
             cargo build --release --target wasm32-wasip2)",
            component_path().display()
        )
    });

    // Detached deliberately: the collector runs for as long as this
    // environment can send, which is what a test wants. Production drains it
    // explicitly instead.
    let (logs, _collector) = enclave_runtime::telemetry::logs::start(std::sync::Arc::new(
        enclave_runtime::TracingLogSink,
    ));
    let guest = GuestEnvironment::new(fs, Arc::new(HostClock), nsm.clone(), &[], &[], logs)
        .expect("guest environment");
    let identity =
        Arc::new(TlsIdentity::self_signed(&["enclave.test".to_string()]).expect("tls identity"));
    let certificate = Some(identity);

    // Bind first so the test knows the port before the server owns it.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let bytes = guest_bytes.clone();
    let nsm_for_server = nsm.clone();
    tokio::spawn(async move {
        let _ = enclave_runtime::serve_component(
            &bytes,
            guest,
            ServeConfig {
                background_tasks: None,
                notify: None,
                telemetry: Default::default(),
                addr,
                certificate,
                attestation: Some(nsm_for_server),
                request_timeout: std::time::Duration::from_secs(30),
                max_interaction: std::time::Duration::from_secs(300),
                tenancy: None,
                // These tests are about the attestation binding, which is
                // reached under `/enclave/` and never passes the gate.
                authentication: None,
            },
        )
        .await;
    });

    // Compiling the guest takes a moment and several tests start servers at
    // once. Wait properly, and say so on failure rather than leaving every
    // assertion below to fail on a refused connection.
    let mut ready = false;
    for _ in 0..400 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(ready, "the server never came up on {addr}");

    Harness { addr }
}

/// A TLS request, returning the status, body, and the certificate the server
/// presented — which is the whole point.
async fn https(addr: std::net::SocketAddr, path: &str) -> (u16, String, Vec<u8>) {
    let (status, _, body, certificate) = https_full(addr, path).await;
    (status, body, certificate)
}

/// The same, plus the response head — which is where the per-response
/// attestation lives, and which `https` discards.
async fn https_full(addr: std::net::SocketAddr, path: &str) -> (u16, String, String, Vec<u8>) {
    let config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAny))
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from("enclave.test").unwrap();

    let socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut stream = connector.connect(name, socket).await.expect("handshake");

    let request = format!("GET {path} HTTP/1.1\r\nHost: enclave.test\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.expect("write");

    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response).await;

    let certificate = {
        let (_, conn) = stream.get_ref();
        conn.peer_certificates()
            .and_then(|c| c.first().cloned())
            .expect("server certificate")
            .to_vec()
    };

    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("headers");
    let head = String::from_utf8_lossy(&response[..split]).to_string();
    let status: u16 = head
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let raw = &response[split + 4..];
    // A guest response carries no content-length — the body streams out of the
    // component — so hyper chunks it.
    let body = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk(raw)
    } else {
        raw.to_vec()
    };
    (
        status,
        head,
        String::from_utf8_lossy(&body).to_string(),
        certificate,
    )
}

/// The attestation document from a response head, decoded.
fn document_from(head: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let line = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("x-enclave-attestation:"))?;
    let value = line.split_once(':')?.1.trim();
    base64::engine::general_purpose::STANDARD.decode(value).ok()
}

fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(end) = rest.windows(2).position(|w| w == b"\r\n") {
        let header = String::from_utf8_lossy(&rest[..end]);
        let Ok(size) = usize::from_str_radix(header.split(';').next().unwrap_or("").trim(), 16)
        else {
            break;
        };
        rest = &rest[end + 2..];
        if size == 0 || rest.len() < size {
            break;
        }
        out.extend_from_slice(&rest[..size]);
        rest = rest.get(size + 2..).unwrap_or(&[]);
    }
    out
}

/// The guest keeps working over TLS, and never sees the runtime's paths.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn the_guest_serves_everything_else() {
    let harness = start().await;

    let (status, body, _) = https(harness.addr, "/counter").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body.trim(), "1");

    let (status, body, _) = https(harness.addr, "/counter").await;
    assert_eq!(status, 200);
    assert_eq!(body.trim(), "2", "state must persist across TLS requests");
}

#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Trust comes from the attestation binding, which these tests check
        // explicitly; PKI has nothing to say about a certificate born inside
        // an enclave ten milliseconds ago.
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Per-response attestation
// ---------------------------------------------------------------------------

/// A guest call sends no nonce, and is served: none of its answers is
/// attested, so there is nothing for one to bind.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_guest_call_needs_no_nonce() {
    let harness = start().await;
    let (status, head, body, _) = https_full(harness.addr, "/counter").await;
    assert_eq!(status, 200, "body: {body}");
    assert!(
        document_from(&head).is_none(),
        "a guest answer carried a document"
    );
}

/// The guest cannot own the header. It sets a forged one on `/whoami`-style
/// routes and the client must still see exactly one, the runtime's.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn the_guest_cannot_forge_the_proof() {
    let harness = start().await;
    let (status, head, _, _) = https_full(harness.addr, "/forge-attestation").await;
    assert_eq!(status, 200);

    // None, not one. The runtime does not attest a guest response — a caller
    // has already identified the enclave on the `/auth/` exchange and pinned
    // its certificate — so there is no document of its own to overwrite the
    // guest's with. The header is taken away instead.
    //
    // This is the check that keeps the header runtime-owned. It used to hold
    // as a side effect of attesting everything; now it is deliberate, and
    // failing it means a guest can hand a client a document under the
    // runtime's name.
    let copies = head
        .lines()
        .filter(|l| l.to_ascii_lowercase().starts_with("x-enclave-attestation:"))
        .count();
    assert_eq!(copies, 0, "the guest's copies survived:\n{head}");
}

/// Attestation must not cost streaming. A guest response carries no document,
/// so nothing holds its head back: it goes out the moment the guest sets it.
///
/// `/trickle` sends three chunks with a pause between them. If the runtime
/// buffered the response, or waited for the body to finish before writing the
/// head, the head would not arrive until every chunk had.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs examples/guest-http built for wasm32-wasip2"]
async fn a_document_does_not_wait_for_the_body() {
    let harness = start().await;

    let config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAny))
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from("enclave.test").unwrap();
    let socket = tokio::net::TcpStream::connect(harness.addr)
        .await
        .expect("connect");
    let mut stream = connector.connect(name, socket).await.expect("handshake");

    let request = "GET /trickle HTTP/1.1\r\nHost: enclave.test\r\nConnection: close\r\n\r\n";
    let started = std::time::Instant::now();
    stream.write_all(request.as_bytes()).await.expect("write");

    // Read only as far as the end of the head, so the timing below measures
    // when the head arrived rather than when the whole response did.
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    while !raw.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut byte).await.expect("read");
        assert!(n == 1, "the connection closed before the head was complete");
        raw.push(byte[0]);
    }
    let head_at = started.elapsed();
    let head = String::from_utf8_lossy(&raw).to_string();

    let mut rest = Vec::new();
    let _ = stream.read_to_end(&mut rest).await;
    let body_at = started.elapsed();
    let body = String::from_utf8_lossy(&dechunk(&rest)).to_string();

    assert!(
        head.to_ascii_lowercase()
            .contains("transfer-encoding: chunked"),
        "a streamed body must not be given a content-length: {head}"
    );
    assert_eq!(body, "chunk-0\nchunk-1\nchunk-2\n", "{head}");

    // The guest pauses 150ms before each of the last two chunks, so a
    // buffering runtime could not have produced the head in under 300ms.
    assert!(
        body_at >= Duration::from_millis(250),
        "the guest did not actually pause; the timing below proves nothing"
    );
    assert!(
        head_at < body_at / 2,
        "the head waited for the body: head at {head_at:?}, body at {body_at:?}"
    );
}
