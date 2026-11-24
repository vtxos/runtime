//! `wallet-client` — drive the enclave's gate from a script, as a wallet would.
//!
//! ```console
//! $ wallet-client --url https://127.0.0.1:8443 enrol
//! $ wallet-client --url https://127.0.0.1:8443 get --path /counter
//! ```
//!
//! A phone cannot be driven from a shell script, so this is the client half in software: it
//! registers a wallet key with the runtime (the DKG, in two calls) and then signs each request
//! with its share, the same exchanges a real app makes, producing the same bytes
//! (`docs/CLIENT_INTEGRATION.md`).
//!
//! It is a *client*, not a bypass. Everything it sends goes through the same gate as anything
//! else, and the enclave cannot tell the difference — which is the point: if the harness can
//! reach the guest with this, the gate is wired up, and if it cannot without it, the gate is
//! doing its job.
//!
//! # Registration
//!
//! ```text
//!   1. POST /auth/register/options   the wallet's commitment: nothing secret
//!   2. check that answer's document against its connection   ◀── refuse here
//!      and pin the certificate it was served under
//!   3. POST /auth/register/verify    the share dealt to the runtime, a signature, the partial:
//!                                    only to the pinned certificate
//! ```
//!
//! # A signed request
//!
//! ```text
//!   1. POST /auth/request/options    a challenge for this exact interaction: nothing secret
//!   2. check that answer's document against its connection   ◀── refuse here
//!      and pin the certificate it was served under
//!   3. POST /auth/request/verify     the signature and the ECDH partial: only to the pinned
//!                                    certificate
//!   4. the interaction, to the pinned certificate
//! ```
//!
//! The partial is what this client must never send to an enclave it has not identified: with
//! the runtime's share it gives the tenant's pool key. So both operations start with an attested
//! options call, and nothing secret is sent until its answer has been checked.
//!
//! A pinned connection is checked after the handshake and before a byte is written, so a
//! changed far end means the request is never sent. TLS proves the peer holds the private key
//! of the certificate it shows, so "the same certificate" and "the same enclave" are one
//! statement. This rests on the runtime refusing session resumption — see `serve::tls`.
//!
//! The wallet's share is kept in a file between invocations, so a script can enrol once and
//! then make several signed requests, the way a session on a phone would.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use clap::{Parser, Subcommand};
use enclave_runtime::auth::client::{Client, Registering};
use enclave_runtime::auth::ATTESTED_CALLS;

#[derive(Parser, Debug)]
#[command(about = "Register a wallet key and make signed requests", version)]
struct Cli {
    /// Base URL, e.g. `https://127.0.0.1:8443`.
    #[arg(long)]
    url: String,

    /// Where the wallet's share is kept between invocations.
    #[arg(long, default_value = "/tmp/wallet-client.json")]
    state: PathBuf,

    /// The name to ask for in the handshake and the Host header.
    #[arg(long, default_value = "enclave.test")]
    domain: String,

    /// Write the attested answer's proof into this directory: `document.b64`, the
    /// `certificate.der` its connection was served, and the `nonce.hex` the request sent. Three
    /// files is what `nitro-attest --document --peer-certificate --nonce` needs to check the
    /// binding, for an exchange it cannot make itself: a POST of the client's own.
    #[arg(long)]
    dump_proof: Option<PathBuf>,

    /// Required PCR0, hex. Pins which runtime image is answering.
    ///
    /// The hypervisor measures this from the image and locks it, so nothing
    /// running inside can choose it — which is what makes it the measurement
    /// the other one rests on. It does not cover the guest, which is not in the
    /// image. Required unless `--unsigned-emulator`.
    #[arg(long)]
    pcr0: Option<String>,

    /// Required PCR16, hex. Pins which guest the runtime is running.
    ///
    /// The runtime extends this register with the guest's hash and locks it
    /// before it can obtain a key, so it is the measurement that says which
    /// application holds your data. It says that only beside `--pcr0`, because
    /// the runtime is what writes it. Required — or `--guest` — unless
    /// `--unsigned-emulator`.
    #[arg(long)]
    pcr16: Option<String>,

    /// The guest component itself. Computes the PCR16 to require, and checks
    /// the document's second hash as well.
    ///
    /// Never a substitute for `--pcr0`, for the same reason `--pcr16` is not:
    /// both halves of what it checks are written by the runtime being attested.
    #[arg(long)]
    guest: Option<PathBuf>,

    /// Trust root, PEM or DER. Defaults to the embedded AWS Nitro root.
    #[arg(long)]
    trust_root: Option<PathBuf>,

    /// Accept a document that does not chain to the AWS root.
    #[arg(long)]
    allow_untrusted_root: bool,

    /// Reject a document older than this many seconds.
    #[arg(long, default_value_t = 300)]
    max_age: u64,

    /// Check the document's contents without verifying any signature.
    ///
    /// Only one producer needs this and it is not a real enclave: QEMU's
    /// emulated NSM does not sign at all. With this on, **nothing establishes
    /// who produced the document** — the nonce and certificate binding are
    /// still checked, and they are this runtime's work, but the signature is
    /// AWS hardware's and there is none to check.
    ///
    /// Never use it against anything you are trusting with a key.
    #[arg(long)]
    unsigned_emulator: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Register a new wallet key, which creates a new tenant.
    Enrol,
    /// A signed GET.
    Get {
        #[arg(long)]
        path: String,
    },
    /// A signed POST.
    Post {
        #[arg(long)]
        path: String,
        #[arg(long, default_value = "")]
        body: String,
    },
    /// Spend a token issued for one route against a different one.
    ///
    /// The harness uses this to show that an approval names an interaction and
    /// cannot be moved off it — one no ordinary client can exercise, because a
    /// client has no reason to build a request its own approval does not match.
    ///
    /// Note what this deliberately does not demonstrate: a substituted *body*.
    /// A token commits to no bytes, so sending different ones at the approved
    /// route is not a refusal and there would be nothing to show.
    Substitute {
        /// The route the token is issued for.
        #[arg(long)]
        approved: String,
        /// The route it is actually spent on.
        #[arg(long)]
        sent: String,
        #[arg(long, default_value = "")]
        body: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Command::Enrol => {
            let client = enrol(&cli)?;
            save(&cli, &client)?;
            println!("enrolled {}", hex::encode(client.tenant()));
        }
        Command::Get { path } => {
            let client = load(&cli)?;
            let (status, body) = signed(&cli, &client, "GET", path, "", None)?;
            print!("{body}");
            std::process::exit(if (200..300).contains(&status) { 0 } else { 1 });
        }
        Command::Post { path, body } => {
            let client = load(&cli)?;
            let (status, response) = signed(&cli, &client, "POST", path, body, None)?;
            print!("{response}");
            std::process::exit(if (200..300).contains(&status) { 0 } else { 1 });
        }
        Command::Substitute {
            approved,
            sent,
            body,
        } => {
            let client = load(&cli)?;
            let (status, response) = signed(&cli, &client, "POST", sent, body, Some(approved))?;
            println!("{status}");
            print!("{response}");
        }
    }
    Ok(())
}

fn load(cli: &Cli) -> Result<Client> {
    let raw = std::fs::read(&cli.state)
        .with_context(|| format!("reading {} — run `enrol` first", cli.state.display()))?;
    let saved: serde_json::Value =
        serde_json::from_slice(&raw).context("parsing the saved wallet")?;
    Client::load(&saved).map_err(anyhow::Error::msg)
}

fn save(cli: &Cli, client: &Client) -> Result<()> {
    std::fs::write(&cli.state, serde_json::to_vec(&client.save())?)
        .with_context(|| format!("writing {}", cli.state.display()))
}

/// Registration: the wallet's commitment to an enclave nobody has vouched for yet, whose
/// attested answer is checked before anything secret goes to it.
fn enrol(cli: &Cli) -> Result<Client> {
    let registering = Registering::new();
    let options =
        connect(cli, None)?.post(cli, "/auth/register/options", &registering.options_body())?;
    anyhow::ensure!(
        options.status == 200,
        "registration was refused: {}",
        options.body
    );
    let pin = attested(cli, &options)?.certificate;

    let connection = connect(cli, Some(&pin))?;
    let (body, pending) = registering
        .verify_body(&options.json()?, &connection.served())
        .map_err(anyhow::Error::msg)?;
    let answer = connection.post(cli, "/auth/register/verify", &body)?;
    anyhow::ensure!(
        answer.status == 200,
        "registration was refused: {}",
        answer.body
    );
    let (client, _) = pending
        .finish(&answer.json()?)
        .map_err(anyhow::Error::msg)?;
    Ok(client)
}

/// Sign in for one interaction and make it.
///
/// `approved_route` exists only so the harness can take a token for one route and spend it on
/// another.
fn signed(
    cli: &Cli,
    client: &Client,
    method: &str,
    path: &str,
    body: &str,
    approved_route: Option<&str>,
) -> Result<(u16, String)> {
    let approved = approved_route.unwrap_or(path);
    let (approved_path, query) = match approved.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (approved, None),
    };

    // The challenge's answer is attested, and checked, before anything is signed: the signature
    // and the partial go only to the certificate it named.
    let (options, pin) = challenge(cli, client, method, approved_path, query)?;
    let connection = connect(cli, Some(&pin))?;
    let (verify, sign_in) = client
        .verify_body(&options, method, approved_path, query, &connection.served())
        .map_err(anyhow::Error::msg)?;
    let answer = connection.post(cli, "/auth/request/verify", &verify)?;
    anyhow::ensure!(
        answer.status == 200,
        "the sign-in was refused: {} {}",
        answer.status,
        answer.body
    );
    sign_in
        .finish(&answer.json()?)
        .map_err(anyhow::Error::msg)?;
    let token = token_of(&answer)?;

    // The interaction, pinned to the certificate the challenge's answer named. Nothing is retried
    // on a fresh connection: the token is good once.
    let response = connect(cli, Some(&pin))?.send(
        cli,
        method,
        path,
        &[("authorization", format!("Bearer {token}"))],
        body,
    )?;
    Ok((response.status, response.body))
}

/// A challenge for one interaction, from an enclave nobody has vouched for yet. The request
/// carries nothing secret, and the answer is attested: checked against its connection before
/// anything is signed. Back: the challenge, and the certificate to pin.
fn challenge(
    cli: &Cli,
    client: &Client,
    method: &str,
    path: &str,
    query: Option<&str>,
) -> Result<(serde_json::Value, Vec<u8>)> {
    let options = connect(cli, None)?.post(
        cli,
        "/auth/request/options",
        &client.options_body(method, path, query),
    )?;
    anyhow::ensure!(
        options.status == 200,
        "no challenge was issued: {}",
        options.body
    );
    let pin = attested(cli, &options)?.certificate;
    Ok((options.json()?, pin))
}

fn token_of(answer: &Exchange) -> Result<String> {
    answer.json()?["token"]
        .as_str()
        .map(str::to_string)
        .context("the runtime issued no token")
}

/// One TLS connection with its handshake finished: what the far end presented is known before
/// anything is sent to it.
struct Connection {
    tls: rustls::ClientConnection,
    socket: TcpStream,
    presented: Vec<u8>,
}

/// One request and its whole response.
struct Exchange {
    status: u16,
    head: String,
    body: String,
    /// The nonce sent, on an options call.
    nonce: Option<[u8; 20]>,
    presented: Vec<u8>,
}

impl Exchange {
    fn json(&self) -> Result<serde_json::Value> {
        serde_json::from_str(&self.body).with_context(|| format!("not JSON: {}", self.body))
    }
}

/// Open a connection, accepting whatever certificate is presented, and refuse it unless it is
/// `pinned` when one is given.
///
/// The certificate is not what establishes trust — nothing vouches for it, and nothing needs to.
/// An attestation does, by naming the certificate a connection presented ([`attested`]). After
/// that the certificate is pinned, and checked here, after the handshake and before a byte is
/// written.
fn connect(cli: &Cli, pinned: Option<&[u8]>) -> Result<Connection> {
    let authority = cli
        .url
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_string();
    let config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAny))
    .with_no_client_auth();

    let name = rustls::pki_types::ServerName::try_from(cli.domain.clone())?;
    let mut tls = rustls::ClientConnection::new(Arc::new(config), name)?;
    let mut socket =
        TcpStream::connect(&authority).with_context(|| format!("connecting to {authority}"))?;
    while tls.is_handshaking() {
        tls.complete_io(&mut socket)
            .context("completing the TLS handshake")?;
    }
    let presented = tls
        .peer_certificates()
        .and_then(|c| c.first())
        .context("the server presented no certificate")?
        .to_vec();
    if let Some(expected) = pinned {
        anyhow::ensure!(
            presented == expected,
            "this connection presents a different certificate than the enclave this client \
             identified; nothing was sent"
        );
    }
    Ok(Connection {
        tls,
        socket,
        presented,
    })
}

impl Connection {
    /// The SHA-256 of the certificate this connection was served: what a signature binds.
    fn served(&self) -> [u8; 32] {
        nitro_attestation::sha256(&self.presented)
    }

    fn post(self, cli: &Cli, path: &str, body: &serde_json::Value) -> Result<Exchange> {
        self.send(
            cli,
            "POST",
            path,
            &[("content-type", "application/json".to_string())],
            &body.to_string(),
        )
    }

    fn send(
        mut self,
        cli: &Cli,
        method: &str,
        path: &str,
        headers: &[(&str, String)],
        body: &str,
    ) -> Result<Exchange> {
        let mut tls = rustls::Stream::new(&mut self.tls, &mut self.socket);

        // A nonce on the options calls, whose answers carry a document that must quote it. The
        // runtime refuses one without it. No other answer carries one, so no other call sends it.
        let nonce = ATTESTED_CALLS.contains(&path).then(fresh_nonce);
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
            cli.domain,
            body.len()
        );
        if let Some(nonce) = &nonce {
            request.push_str(&format!("x-enclave-nonce: {}\r\n", encode_nonce(nonce)));
        }
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        request.push_str(body);
        tls.write_all(request.as_bytes())?;

        let mut raw = Vec::new();
        let _ = tls.read_to_end(&mut raw);
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .context("no response headers")?;
        let head = String::from_utf8_lossy(&raw[..split]).to_string();
        let status: u16 = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .context("no status line")?
            .parse()?;

        // A response counts only once it is complete. The runtime streams a body as the guest
        // writes it and holds back only its end until the guest's writes are anchored, so a body
        // that stops short reports an operation that may be rolled back.
        let rest = &raw[split + 4..];
        let lower = head.to_ascii_lowercase();
        let cut_off = || {
            anyhow::anyhow!(
                "{method} {path}: the response was cut off before it ended, so what it reports \
                 may not have happened"
            )
        };
        let body = if lower.contains("transfer-encoding: chunked") {
            dechunk(rest).ok_or_else(cut_off)?
        } else if let Some(length) = lower
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse::<usize>().ok())
        {
            rest.get(..length).ok_or_else(cut_off)?.to_vec()
        } else {
            rest.to_vec()
        };
        Ok(Exchange {
            status,
            head,
            body: String::from_utf8_lossy(&body).to_string(),
            nonce,
            presented: self.presented,
        })
    }
}

/// Check an attested answer against the connection it arrived on, before acting on it.
/// Refused if it carries no document: a deployment that does not attest is one this client will
/// not talk to. The proof is kept first, when asked for, so an answer that is refused can still
/// be examined.
fn attested(cli: &Cli, exchange: &Exchange) -> Result<ConnectionProof> {
    let nonce = exchange
        .nonce
        .context("only an options call sends a nonce, so only its answer can be attested")?;
    if let Some(dir) = &cli.dump_proof {
        dump_proof(dir, &exchange.head, &nonce, &exchange.presented)?;
    }
    connection_proof(
        &exchange.head,
        &nonce,
        &exchange.presented,
        &TrustConfig::from(cli)?,
    )
    .context("the answer could not be tied to its connection")
}

/// A fresh nonce for one request.
///
/// From the OS, because a nonce a third party can predict is not a nonce — and this one is
/// checked: the document that comes back must quote it, or the answer is refused before its
/// body is read.
fn fresh_nonce() -> [u8; 20] {
    let mut nonce = [0u8; 20];
    getrandom::fill(&mut nonce).expect("the OS has entropy");
    nonce
}

fn encode_nonce(nonce: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce)
}

/// The three things a verifier needs and cannot recover after the fact: what
/// the enclave signed, which certificate this connection was actually served,
/// and which nonce was asked for.
/// What one response proves about the connection it arrived on.
///
/// The document is generated before the request is routed, so it says nothing
/// about the body below it and nothing about whether the guest ran. What it
/// does say is that *this* enclave terminated *this* connection, just now —
/// and that is the claim the operation depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectionProof {
    /// The leaf this connection presented, which the document was checked to
    /// name. Kept whole rather than hashed because the next connection is
    /// pinned against it, and TLS compares certificates rather than digests.
    certificate: Vec<u8>,
    guest: [u8; 32],
}

/// Verify a response's attestation against the connection it arrived on.
///
/// Everything, in the order it has to happen:
///
/// - the **signature and certificate chain**, so the document came from a real
///   Nitro enclave and not from whoever answered the socket;
/// - its **age**, so it was made now rather than captured earlier;
/// - the **nonce**, so it was made for this caller and not replayed from
///   somebody else's exchange;
/// - the **certificate** it binds, against the one this connection actually
///   presented, so the enclave that signed it is the party on the other end
///   rather than one being relayed by something in between;
/// - and, when given, **PCR0** and the guest hash — *which* enclave and *which*
///   application, not merely that it is some enclave.
///
/// The chain check is what the other four rest on. Without it a party that
/// terminated TLS could mint a document naming its own certificate and quoting
/// the nonce, and every remaining check would pass.
fn connection_proof(
    head: &str,
    nonce: &[u8],
    presented: &[u8],
    trust: &TrustConfig,
) -> Result<ConnectionProof> {
    let encoded = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("x-enclave-attestation:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim())
        .context("the response carried no x-enclave-attestation header")?;
    let cose = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("the attestation header is not base64")?;

    let now = std::time::SystemTime::now();
    let verified = if trust.unsigned_emulator {
        nitro_attestation::Verified {
            document: nitro_attestation::parse(&cose).context("parsing the document")?,
            trust: nitro_attestation::Trust::Unsigned,
        }
    } else {
        nitro_attestation::verify(
            &cose,
            &nitro_attestation::VerifyOptions {
                trust_root: trust.root.clone(),
                now,
                allow_untrusted_root: trust.allow_untrusted_root,
            },
        )
        .context("the document did not verify")?
    };

    // What the runtime binds: the leaf this connection was served, and the
    // guest component behind it. The certificate half is checked always; the
    // guest half only when the caller supplied the component to check against.
    let hashes = nitro_attestation::AttestationHashes::parse(
        verified
            .document
            .user_data
            .as_deref()
            .context("the document binds no user_data")?,
    )
    .context("the document's user_data is not the runtime's binding")?;
    anyhow::ensure!(
        hashes.tls_certificate == nitro_attestation::sha256(presented),
        "the document binds a certificate this connection was never served: \
         the enclave that signed it is not the party answering here"
    );

    let mut expectations = nitro_attestation::Expectations {
        nonce: Some(nonce.to_vec()),
        max_age: Some(trust.max_age),
        ..Default::default()
    };
    if let Some(pcr0) = &trust.pcr0 {
        expectations = expectations.pcr0(pcr0.clone());
    }
    // Missing from the document is a refusal, not a skipped check: a runtime
    // that never locked the register attests no guest at all.
    if let Some(pcr16) = &trust.pcr16 {
        expectations = expectations.pcr(nitro_attestation::PCR_GUEST, pcr16.clone());
    }
    if let Some(guest) = &trust.guest {
        expectations.user_data =
            Some(nitro_attestation::AttestationHashes::new(presented, guest).serialize());
    }
    verified
        .expect(&expectations, now)
        .context("the document did not meet expectations")?;

    Ok(ConnectionProof {
        certificate: presented.to_vec(),
        guest: hashes.guest,
    })
}

/// What the client requires of a document before it acts on the response.
struct TrustConfig {
    root: Vec<u8>,
    allow_untrusted_root: bool,
    unsigned_emulator: bool,
    max_age: std::time::Duration,
    pcr0: Option<Vec<u8>>,
    /// The guest register to require, from `--pcr16` or computed from
    /// `--guest`.
    pcr16: Option<Vec<u8>>,
    guest: Option<Vec<u8>>,
}

impl TrustConfig {
    fn from(cli: &Cli) -> Result<Self> {
        // A verified chain says "a genuine Nitro enclave". It does not say
        // *which* one, and an attacker who can run their own gets a document
        // that passes every other check here.
        //
        // **Two measurements close that, and neither stands in for the other.**
        // PCR0 is measured by the hypervisor from the image and locked, so no
        // software inside the enclave can choose it — but the image no longer
        // contains the guest. PCR16 is the guest, extended and locked by the
        // runtime before it could obtain a key — but because the runtime writes
        // it, an enclave running an attacker's runtime can claim your guest's
        // value while running nothing of the kind. PCR0 says the runtime that
        // wrote PCR16 is yours; PCR16 says which application it loaded.
        //
        // `--guest` is how most callers supply PCR16, and it checks the
        // document's guest hash as well. Both halves of that come from the
        // runtime, so it is never a substitute for `--pcr0`.
        //
        // `--unsigned-emulator` is the one exception, and an explicit one: QEMU
        // has no stable PCR0 to pin, and nothing there is signed anyway.
        let guest = match &cli.guest {
            Some(path) => {
                Some(std::fs::read(path).with_context(|| format!("reading {}", path.display()))?)
            }
            None => None,
        };
        let measured = guest
            .as_deref()
            .map(|component| nitro_attestation::guest_pcr(component).to_vec());
        let pcr16 = match (&cli.pcr16, measured) {
            (Some(pinned), measured) => {
                let pinned = hex::decode(pinned.trim()).context("--pcr16 is not hex")?;
                if let Some(measured) = measured {
                    anyhow::ensure!(
                        measured == pinned,
                        "--pcr16 and --guest name different guests: the component measures \
                         to {}",
                        hex::encode(&measured)
                    );
                }
                Some(pinned)
            }
            (None, measured) => measured,
        };

        if !cli.unsigned_emulator {
            if cli.pcr0.is_none() {
                bail!(
                    "refusing to talk to an unidentified enclave: pass --pcr0, which is the \
                     measurement the hypervisor takes of the image and the only one an \
                     attacker's own enclave cannot claim. --guest and --pcr16 are required \
                     alongside it, not instead of it: the runtime being attested is what \
                     writes them. Against QEMU, pass --unsigned-emulator."
                );
            }
            if pcr16.is_none() {
                bail!(
                    "refusing to talk to an enclave whose guest is unidentified: pass --pcr16, \
                     or --guest with the component itself. PCR0 measures the runtime image, \
                     and the guest is not in it — the runtime loads it at boot, measures it \
                     into PCR16 and locks that register before it can obtain a key. PCR16 is \
                     the measurement that says which application holds your data."
                );
            }
        }
        Ok(TrustConfig {
            root: match &cli.trust_root {
                Some(path) => {
                    std::fs::read(path).with_context(|| format!("reading {}", path.display()))?
                }
                None => nitro_attestation::AWS_NITRO_ROOT_G1_PEM.as_bytes().to_vec(),
            },
            allow_untrusted_root: cli.allow_untrusted_root,
            unsigned_emulator: cli.unsigned_emulator,
            max_age: std::time::Duration::from_secs(cli.max_age),
            pcr0: match &cli.pcr0 {
                Some(hex) => Some(hex::decode(hex.trim()).context("--pcr0 is not hex")?),
                None => None,
            },
            pcr16,
            guest,
        })
    }
}

fn dump_proof(dir: &Path, head: &str, nonce: &[u8], certificate: &[u8]) -> Result<()> {
    let document = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("x-enclave-attestation:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim())
        .context("the response carried no x-enclave-attestation header")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::write(dir.join("document.b64"), document)?;
    std::fs::write(dir.join("certificate.der"), certificate)?;
    std::fs::write(dir.join("nonce.hex"), hex::encode(nonce))?;
    Ok(())
}

/// The body of a chunked response, or `None` if it never reached its last,
/// zero-length chunk: a body cut off part-way is not a short body.
fn dechunk(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = body;
    loop {
        let end = rest.windows(2).position(|w| w == b"\r\n")?;
        let header = String::from_utf8_lossy(&rest[..end]);
        let size = usize::from_str_radix(header.split(';').next().unwrap_or("").trim(), 16).ok()?;
        rest = &rest[end + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(rest.get(..size)?);
        rest = rest.get(size + 2..)?;
    }
}

/// Accepts any certificate, because the attestation vouches for it, but only
/// from the holder of its key: a certificate is public, and without the
/// handshake signatures anyone relaying a copy of the enclave's would pass.
#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _e: &rustls::pki_types::CertificateDer<'_>,
        _i: &[rustls::pki_types::CertificateDer<'_>],
        _s: &rustls::pki_types::ServerName<'_>,
        _o: &[u8],
        _n: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &signature_algorithms())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &signature_algorithms())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        signature_algorithms().supported_schemes()
    }
}

fn signature_algorithms() -> rustls::crypto::WebPkiSupportedAlgorithms {
    rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A response is complete or it is not acted on: the runtime holds back
    /// only a body's end until its writes are anchored.
    #[test]
    fn a_chunked_body_must_reach_its_last_chunk() {
        assert_eq!(
            dechunk(b"5\r\nhello\r\n0\r\n\r\n").as_deref(),
            Some(&b"hello"[..])
        );
        assert_eq!(
            dechunk(b"5\r\nhello\r\n"),
            None,
            "cut off before the last chunk"
        );
        assert_eq!(dechunk(b"5\r\nhel"), None, "cut off inside a chunk");
        assert_eq!(dechunk(b""), None);
    }
    use nitro_attestation::testing::TestChain;
    use nitro_attestation::AttestationHashes;

    /// What a client requires, pointed at a test chain rather than AWS.
    ///
    /// `allow_untrusted_root` stays **false**: it does not mean "this root is
    /// not AWS", it means "accept a document that chains to nothing I pinned",
    /// which would make every test below vacuous. Pinning the test chain's own
    /// root is what keeps the chain check real.
    fn trust(chain: &TestChain) -> TrustConfig {
        TrustConfig {
            root: chain.root_der().to_vec(),
            allow_untrusted_root: false,
            unsigned_emulator: false,
            max_age: std::time::Duration::from_secs(300),
            pcr0: None,
            pcr16: None,
            guest: None,
        }
    }

    const GUEST: &[u8] = b"a-guest";

    /// The registers an enclave running [`GUEST`] has locked: its image, and
    /// the guest it measured.
    fn registers() -> std::collections::BTreeMap<u32, Vec<u8>> {
        [
            (0u32, vec![0x5a; 48]),
            (
                nitro_attestation::PCR_GUEST,
                nitro_attestation::guest_pcr(GUEST).to_vec(),
            ),
        ]
        .into()
    }

    /// A response head carrying a document built for `cert` and `nonce`.
    fn head_for(chain: &TestChain, cert: &[u8], nonce: &[u8]) -> String {
        head_with(chain, cert, nonce, registers())
    }

    /// The same, listing exactly the registers given.
    fn head_with(
        chain: &TestChain,
        cert: &[u8],
        nonce: &[u8],
        pcrs: std::collections::BTreeMap<u32, Vec<u8>>,
    ) -> String {
        let user_data = AttestationHashes::new(cert, GUEST).serialize();
        let cose = chain
            .document_with_pcrs(Some(user_data), Some(nonce.to_vec()), pcrs)
            .expect("a document");
        format!(
            "HTTP/1.1 200 OK\r\nx-enclave-attestation: {}\r\n",
            base64::engine::general_purpose::STANDARD.encode(cose)
        )
    }

    #[test]
    fn a_document_for_this_connection_and_this_nonce_is_accepted() {
        let chain = TestChain::new().expect("chain");
        let cert = b"the-leaf-this-connection-presented";
        let nonce = [7u8; 20];
        let proof = connection_proof(
            &head_for(&chain, cert, &nonce),
            &nonce,
            cert,
            &trust(&chain),
        )
        .expect("the document names this certificate and quotes this nonce");
        assert_eq!(proof.certificate, cert.to_vec());
    }

    /// **The forgery.** A document nobody signed, naming the forger's own
    /// certificate and quoting the nonce it was just sent.
    ///
    /// Every check except the chain passes: the nonce matches, and the
    /// certificate it binds really is the one this connection presented —
    /// because the forger chose both. Only verifying the signature and the
    /// chain catches it, which is why parsing the document was never enough.
    #[test]
    fn a_document_that_nobody_signed_is_refused() {
        let forger = TestChain::new().expect("the forger's own chain");
        let honest = TestChain::new().expect("the enclave's chain");
        let cert = b"the-forgers-leaf";
        let nonce = [7u8; 20];

        // Signed by a chain the client does not trust.
        let err = connection_proof(
            &head_for(&forger, cert, &nonce),
            &nonce,
            cert,
            &trust(&honest),
        )
        .expect_err("a document from an untrusted chain was accepted");
        assert!(
            format!("{err:#}").contains("did not verify"),
            "the refusal did not name the reason: {err:#}"
        );
    }

    /// **The relay.** A genuine document from the real enclave, replayed by
    /// something that terminated TLS itself.
    #[test]
    fn a_document_naming_another_certificate_is_refused() {
        let chain = TestChain::new().expect("chain");
        let nonce = [7u8; 20];
        let head = head_for(&chain, b"the-real-enclaves-leaf", &nonce);
        let err = connection_proof(&head, &nonce, b"the-interceptors-leaf", &trust(&chain))
            .expect_err("a relayed document was accepted");
        assert!(
            format!("{err:#}").contains("never served"),
            "the refusal did not name the reason: {err:#}"
        );
    }

    /// **The replay.** A document made earlier, for an earlier request.
    #[test]
    fn a_document_quoting_another_nonce_is_refused() {
        let chain = TestChain::new().expect("chain");
        let cert = b"the-leaf";
        let head = head_for(&chain, cert, &[1u8; 20]);
        assert!(
            connection_proof(&head, &[2u8; 20], cert, &trust(&chain)).is_err(),
            "a document made for another request was accepted"
        );
    }

    /// A document older than the client will accept.
    #[test]
    fn a_stale_document_is_refused() {
        let chain = TestChain::new().expect("chain");
        let cert = b"the-leaf";
        let nonce = [4u8; 20];
        let mut trust = trust(&chain);
        trust.max_age = std::time::Duration::from_nanos(1);
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(
            connection_proof(&head_for(&chain, cert, &nonce), &nonce, cert, &trust).is_err(),
            "a document older than the client's window was accepted"
        );
    }

    /// The wrong image, caught by PCR0 when the caller pins one.
    #[test]
    fn a_document_from_another_image_is_refused() {
        let chain = TestChain::new().expect("chain");
        let cert = b"the-leaf";
        let nonce = [5u8; 20];
        let mut trust = trust(&chain);
        trust.pcr0 = Some(vec![0xff; 48]);
        assert!(
            connection_proof(&head_for(&chain, cert, &nonce), &nonce, cert, &trust).is_err(),
            "a document from an unexpected image was accepted"
        );
    }

    /// Fail closed: a deployment that does not attest is one this client will
    /// not act on, because there is nothing for it to check.
    #[test]
    fn a_response_without_a_document_is_refused() {
        let chain = TestChain::new().expect("chain");
        let err = connection_proof("HTTP/1.1 200 OK\r\n", &[0u8; 20], b"leaf", &trust(&chain))
            .expect_err("an unattested response was accepted");
        assert!(
            format!("{err:#}").contains("no x-enclave-attestation"),
            "{err:#}"
        );
    }

    /// The continuity check, which is what pins the interaction's connection.
    #[test]
    fn two_exchanges_on_different_certificates_do_not_match() {
        let chain = TestChain::new().expect("chain");
        let nonce = [3u8; 20];
        let t = trust(&chain);

        let opened = connection_proof(
            &head_for(&chain, b"leaf-one", &nonce),
            &nonce,
            b"leaf-one",
            &t,
        )
        .expect("the first exchange");
        let answered = connection_proof(
            &head_for(&chain, b"leaf-two", &nonce),
            &nonce,
            b"leaf-two",
            &t,
        )
        .expect("the second exchange");
        assert_ne!(
            opened.certificate, answered.certificate,
            "a changed certificate must be visible, or the pin cannot fire"
        );

        let again = connection_proof(
            &head_for(&chain, b"leaf-one", &nonce),
            &nonce,
            b"leaf-one",
            &t,
        )
        .expect("the same enclave again");
        assert_eq!(opened.certificate, again.certificate);
    }

    /// **A chain alone is not an identity.**
    ///
    /// Verifying the signature says a genuine Nitro enclave answered. It does
    /// not say whose. Refusing to run without measurements is what stops the
    /// default from reading as more safety than it gives.
    #[test]
    fn a_client_refuses_to_run_without_expected_measurements() {
        let cli = Cli::parse_from([
            "wallet-client",
            "--url",
            "https://e.test",
            "get",
            "--path",
            "/",
        ]);
        let err = match TrustConfig::from(&cli) {
            Err(e) => e,
            Ok(_) => panic!("an unidentified enclave was accepted"),
        };
        assert!(
            format!("{err:#}").contains("unidentified enclave"),
            "{err:#}"
        );
    }

    fn cli_with(flags: &[&str]) -> Cli {
        let mut args = vec!["wallet-client", "--url", "https://e.test"];
        args.extend_from_slice(flags);
        args.extend_from_slice(&["get", "--path", "/"]);
        Cli::parse_from(args)
    }

    fn guest_file(name: &str, bytes: &[u8]) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("wallet-client-{}-{name}.wasm", std::process::id()));
        std::fs::write(&path, bytes).expect("writing a guest file");
        path
    }

    fn refusal(cli: &Cli) -> String {
        match TrustConfig::from(cli) {
            Err(e) => format!("{e:#}"),
            Ok(_) => panic!("an unidentified enclave was accepted"),
        }
    }

    /// **`--guest` alone is not an identity.**
    ///
    /// It yields a PCR16 and a `user_data` guest hash, and the runtime being
    /// attested writes both — so an attacker running their own runtime signs a
    /// genuine document claiming whatever guest you asked for. Only PCR0,
    /// measured by the hypervisor and locked, says whose runtime wrote them.
    #[test]
    fn a_guest_alone_is_not_an_identity() {
        let text = refusal(&cli_with(&["--guest", "/dev/null"]));
        assert!(text.contains("--pcr0"), "{text}");
    }

    /// **PCR0 alone no longer identifies the guest.** The image does not
    /// contain it, so a client pinning only the runtime would accept that
    /// runtime serving any application at all.
    #[test]
    fn pinning_the_runtime_alone_does_not_identify_the_guest() {
        let text = refusal(&cli_with(&["--pcr0", &"ab".repeat(48)]));
        assert!(text.contains("PCR16"), "{text}");
    }

    #[test]
    fn pinning_both_measurements_identifies_the_enclave() {
        let trust = TrustConfig::from(&cli_with(&[
            "--pcr0",
            &"ab".repeat(48),
            "--pcr16",
            &"cd".repeat(48),
        ]))
        .expect("both measurements were not accepted");
        assert_eq!(trust.pcr16, Some(vec![0xcd; 48]));
    }

    /// The component itself is the usual way to supply PCR16, and it becomes
    /// exactly the value the runtime would have locked.
    #[test]
    fn a_guest_file_becomes_the_register_it_measures_to() {
        let path = guest_file("measured", GUEST);
        let trust = TrustConfig::from(&cli_with(&[
            "--pcr0",
            &"ab".repeat(48),
            "--guest",
            path.to_str().unwrap(),
        ]));
        let _ = std::fs::remove_file(&path);

        let trust = trust.expect("a guest file was not accepted");
        assert_eq!(
            trust.pcr16,
            Some(nitro_attestation::guest_pcr(GUEST).to_vec())
        );
        assert_eq!(trust.guest.as_deref(), Some(GUEST));
    }

    #[test]
    fn a_pcr16_and_a_guest_file_that_disagree_are_refused() {
        let path = guest_file("disagreeing", GUEST);
        let cli = cli_with(&[
            "--pcr0",
            &"ab".repeat(48),
            "--pcr16",
            &"00".repeat(48),
            "--guest",
            path.to_str().unwrap(),
        ]);
        let text = refusal(&cli);
        let _ = std::fs::remove_file(&path);
        assert!(text.contains("different guests"), "{text}");
    }

    /// **Another guest**, behind the right runtime.
    #[test]
    fn a_document_from_another_guest_is_refused() {
        let chain = TestChain::new().expect("chain");
        let cert = b"the-leaf";
        let nonce = [6u8; 20];
        let mut trust = trust(&chain);
        trust.pcr0 = Some(vec![0x5a; 48]);
        trust.pcr16 = Some(nitro_attestation::guest_pcr(b"the approved guest").to_vec());
        let err = connection_proof(&head_for(&chain, cert, &nonce), &nonce, cert, &trust)
            .expect_err("a document for another guest was accepted");
        assert!(format!("{err:#}").contains("PCR16 mismatch"), "{err:#}");
    }

    /// **No guest at all.** A runtime that never locked the register attests
    /// documents without it, and a client pinning a guest refuses that rather
    /// than skipping the check.
    #[test]
    fn a_document_that_measured_no_guest_is_refused() {
        let chain = TestChain::new().expect("chain");
        let cert = b"the-leaf";
        let nonce = [7u8; 20];
        let mut trust = trust(&chain);
        trust.pcr16 = Some(nitro_attestation::guest_pcr(GUEST).to_vec());
        let head = head_with(&chain, cert, &nonce, [(0u32, vec![0x5a; 48])].into());
        let err = connection_proof(&head, &nonce, cert, &trust)
            .expect_err("a document with no guest register was accepted");
        assert!(format!("{err:#}").contains("no PCR16"), "{err:#}");
    }

    #[test]
    fn a_document_for_the_pinned_runtime_and_guest_is_accepted() {
        let chain = TestChain::new().expect("chain");
        let cert = b"the-leaf";
        let nonce = [8u8; 20];
        let mut trust = trust(&chain);
        trust.pcr0 = Some(vec![0x5a; 48]);
        trust.pcr16 = Some(nitro_attestation::guest_pcr(GUEST).to_vec());
        trust.guest = Some(GUEST.to_vec());
        connection_proof(&head_for(&chain, cert, &nonce), &nonce, cert, &trust)
            .expect("the pinned runtime and guest were refused");
    }

    /// The exception is explicit, and only for the one producer that needs it.
    #[test]
    fn the_emulator_exception_must_be_asked_for_by_name() {
        let trust =
            TrustConfig::from(&cli_with(&["--unsigned-emulator"])).expect("the emulator exception");
        assert!(trust.unsigned_emulator);
        assert!(
            trust.pcr0.is_none() && trust.pcr16.is_none(),
            "the exception should not invent a measurement"
        );
    }
}
