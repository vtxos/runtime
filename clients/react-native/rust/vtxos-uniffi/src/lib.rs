//! vtxos for React Native: [`vtxos_client`], exported through UniFFI.
//!
//! Two things, and nothing about what an enclave's policy says:
//!
//! - **The key.** The app holds a passkey, whose PRF output it passes in at each use, and a
//!   [`WalletRecord`], which [`Enclave::register`] returns and is useless without the passkey.
//!   From them [`Enclave::open`] rebuilds the phone's share, which lives in an open [`Session`]
//!   until [`Session::close`], and [`Session::sign_round`] makes the phone's half of a signature
//!   with it.
//! - **Calls.** A [`Session`] calls any method the enclave serves, with bytes it does not look
//!   inside, one message each way or as a [`Stream`].
//!
//! The messages are the app's: whoever writes the policy an enclave runs knows them, and writes
//! and reads them itself.
//!
//! Every call runs on this library's own tokio runtime, so the connection it keeps open outlives
//! any one call, whatever runtime the foreign side has.

use std::future::Future;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use vtxos_client::core::{frost, keys};
use vtxos_client::net;

uniffi::setup_scaffolding!();

static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("vtxos")
        .build()
        .expect("a tokio runtime")
});

/// Run `work` on the library's runtime.
async fn run<T: Send + 'static>(
    work: impl Future<Output = Result<T, VtxosError>> + Send + 'static,
) -> Result<T, VtxosError> {
    RUNTIME
        .spawn(work)
        .await
        .map_err(|e| VtxosError::Protocol {
            message: format!("the call did not finish: {e}"),
        })?
}

/// What went wrong, by whose fault.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VtxosError {
    /// The enclave's attestation does not verify under the pins: it is not the enclave pinned.
    #[error("{message}")]
    Attestation { message: String },
    /// The enclave served a certificate it did not attest.
    #[error("{message}")]
    Pinning { message: String },
    /// A sign-in or registration was refused.
    #[error("refused ({status}): {message}")]
    Auth { status: u16, message: String },
    /// A call the enclave ended with an error: gRPC's status code, and what the policy said.
    #[error("the enclave answered {code}: {message}")]
    Status { code: u32, message: String },
    /// This passkey does not open this wallet.
    #[error("this passkey does not open this wallet")]
    WrongPasskey,
    /// A message that does not follow the protocol, or an argument that is not valid.
    #[error("{message}")]
    Protocol { message: String },
    /// The network.
    #[error("{message}")]
    Transport { message: String },
}

impl From<vtxos_client::Error> for VtxosError {
    fn from(e: vtxos_client::Error) -> Self {
        use vtxos_client::Error as E;
        let message = e.to_string();
        match e {
            E::Attestation(_) => VtxosError::Attestation { message },
            E::Pinning(_) => VtxosError::Pinning { message },
            E::Auth { status, message } => VtxosError::Auth { status, message },
            E::Status { code, message } => VtxosError::Status { code, message },
            E::WrongPasskey => VtxosError::WrongPasskey,
            E::Protocol(_) => VtxosError::Protocol { message },
            E::Transport(_) => VtxosError::Transport { message },
        }
    }
}

fn invalid(message: impl Into<String>) -> VtxosError {
    VtxosError::Protocol {
        message: message.into(),
    }
}

/// What the app pins about the enclave. Hex for the PCRs.
#[derive(uniffi::Record)]
pub struct Pins {
    /// PEM of the root the attestation chain must reach; none for AWS Nitro's own root. A dev
    /// enclave prints its own at each boot.
    pub trust_root_pem: Option<String>,
    /// The runtime image, 48 bytes as hex.
    pub pcr0: String,
    /// The policy guest, 48 bytes as hex.
    pub pcr16: String,
    /// How old an attestation document may be.
    pub max_age_secs: u64,
}

/// What the app keeps for a wallet: not secret without the passkey, and needed with it. A cache:
/// registering again with the same passkey returns it.
#[derive(uniffi::Record, Clone)]
pub struct WalletRecord {
    pub group_key: String,
    pub tenant_id: String,
    pub identifier: String,
    pub verifying_share: String,
    pub runtime_identifier: String,
    pub runtime_verifying_share: String,
    pub dealt_share: String,
}

impl From<keys::WalletRecord> for WalletRecord {
    fn from(r: keys::WalletRecord) -> Self {
        WalletRecord {
            group_key: r.group_key,
            tenant_id: r.tenant_id,
            identifier: r.identifier,
            verifying_share: r.verifying_share,
            runtime_identifier: r.runtime_identifier,
            runtime_verifying_share: r.runtime_verifying_share,
            dealt_share: r.dealt_share,
        }
    }
}

impl From<WalletRecord> for keys::WalletRecord {
    fn from(r: WalletRecord) -> Self {
        keys::WalletRecord {
            group_key: r.group_key,
            tenant_id: r.tenant_id,
            identifier: r.identifier,
            verifying_share: r.verifying_share,
            runtime_identifier: r.runtime_identifier,
            runtime_verifying_share: r.runtime_verifying_share,
            dealt_share: r.dealt_share,
        }
    }
}

/// What the app asks its passkey's PRF to evaluate.
#[uniffi::export]
pub fn prf_salt() -> Vec<u8> {
    keys::prf_salt().to_vec()
}

/// A record as JSON, to store.
#[uniffi::export]
pub fn encode_record(record: WalletRecord) -> String {
    serde_json::to_string(&keys::WalletRecord::from(record)).expect("a record serializes")
}

/// A record from the JSON [`encode_record`] made.
#[uniffi::export]
pub fn decode_record(json: String) -> Result<WalletRecord, VtxosError> {
    serde_json::from_str::<keys::WalletRecord>(&json)
        .map(Into::into)
        .map_err(|e| invalid(format!("not a wallet record: {e}")))
}

fn prf(output: &[u8]) -> Result<[u8; 32], VtxosError> {
    output
        .try_into()
        .map_err(|_| invalid(format!("a PRF output is 32 bytes, not {}", output.len())))
}

/// The app's pins, checked and in the client's own form.
fn checked(pins: Pins) -> Result<net::Pins, VtxosError> {
    let decode = |hex_pcr: &str, which: &str| {
        hex::decode(hex_pcr)
            .ok()
            .filter(|b| b.len() == 48)
            .ok_or_else(|| invalid(format!("{which} is not 48 bytes of hex")))
    };
    Ok(net::Pins {
        trust_root: pins
            .trust_root_pem
            .unwrap_or_else(|| enclave_client_root().to_string())
            .into_bytes(),
        pcr0: decode(&pins.pcr0, "PCR0")?,
        pcr16: decode(&pins.pcr16, "PCR16")?,
        max_age: Duration::from_secs(pins.max_age_secs),
    })
}

fn enclave_client_root() -> &'static str {
    vtxos_client::net::enclave::AWS_NITRO_ROOT_G1_PEM
}

/// An enclave, by its address and what the app pins: where a key is made and a [`Session`] opened.
#[derive(uniffi::Object)]
pub struct Enclave {
    inner: Arc<net::Enclave>,
}

#[uniffi::export(async_runtime = "tokio")]
impl Enclave {
    /// `enclave_url` is `https://…`. Nothing connects until a call needs to.
    #[uniffi::constructor]
    pub fn new(enclave_url: String, pins: Pins) -> Result<Arc<Self>, VtxosError> {
        Ok(Arc::new(Enclave {
            inner: Arc::new(net::Enclave::new(&enclave_url, &checked(pins)?)?),
        }))
    }

    /// Make a new key with the enclave, from the passkey's PRF output. The record is what the app
    /// keeps.
    pub async fn register(&self, prf_output: Vec<u8>) -> Result<WalletRecord, VtxosError> {
        let (enclave, prf) = (self.inner.clone(), prf(&prf_output)?);
        run(async move { Ok(enclave.register(&prf).await?.into()) }).await
    }

    /// Open a session: the share, rebuilt from the passkey's PRF output and the record. No network.
    pub fn open(
        &self,
        record: WalletRecord,
        prf_output: Vec<u8>,
    ) -> Result<Arc<Session>, VtxosError> {
        let client = keys::WalletRecord::from(record).open(&prf(&prf_output)?)?;
        Ok(Arc::new(Session {
            inner: Mutex::new(Some(Arc::new(net::Session::new(
                self.inner.clone(),
                client,
            )))),
        }))
    }
}

/// An open key on an enclave: calls to any method the enclave serves, as bytes. One call at a
/// time: a second waits for the first to end.
#[derive(uniffi::Object)]
pub struct Session {
    inner: Mutex<Option<Arc<net::Session>>>,
}

impl Session {
    fn get(&self) -> Result<Arc<net::Session>, VtxosError> {
        self.inner
            .lock()
            .expect("the session's lock")
            .clone()
            .ok_or_else(|| invalid("the session is closed"))
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl Session {
    /// One message each way: `request` to `method`, and its one reply. `method` is the call's
    /// path, by gRPC's habit `/package.Service/Method`.
    pub async fn call(&self, method: String, request: Vec<u8>) -> Result<Vec<u8>, VtxosError> {
        let session = self.get()?;
        run(async move { Ok(session.call(&method, &request).await?) }).await
    }

    /// Open `method` for messages both ways.
    pub async fn stream(&self, method: String) -> Result<Arc<Stream>, VtxosError> {
        let session = self.get()?;
        run(async move {
            Ok(Arc::new(Stream {
                inner: Arc::new(session.stream(&method).await?),
            }))
        })
        .await
    }

    /// The phone's half of a signing round, for each of `messages`: the enclave commits first and
    /// sends `commitments`, one per message and in their order, and what this returns goes back to
    /// it, in whatever message the policy carries a round in. The enclave then finishes the
    /// signatures.
    ///
    /// The share stays here. A half is no signature: without the enclave's, which its policy
    /// decides, it signs nothing.
    pub fn sign_round(
        &self,
        messages: Vec<Vec<u8>>,
        commitments: Vec<Commitment>,
    ) -> Result<Vec<Round>, VtxosError> {
        let session = self.get()?;
        let key = session.key();
        let commitments: Vec<frost::Commitment> = commitments
            .into_iter()
            .map(|c| frost::Commitment {
                hiding: c.hiding,
                binding: c.binding,
            })
            .collect();
        // The enclave is the runtime this key was made with, or the round does not complete.
        let runtime = hex::encode(key.runtime().serialize());
        let rounds = frost::answer(
            key.key_package(),
            key.runtime(),
            &runtime,
            &messages,
            &commitments,
        )?;
        Ok(rounds
            .into_iter()
            .map(|r| Round {
                hiding: r.hiding,
                binding: r.binding,
                share: r.share,
            })
            .collect())
    }

    /// Drop the share. Calls already running finish with it; no new call can start.
    pub fn close(&self) {
        self.inner.lock().expect("the session's lock").take();
    }
}

/// The enclave's commitment for one message of a signing round: two compressed points, 33 bytes
/// each.
#[derive(uniffi::Record)]
pub struct Commitment {
    pub hiding: Vec<u8>,
    pub binding: Vec<u8>,
}

/// The phone's half of one message's round: its own commitment, and its share over both, 32 bytes.
#[derive(uniffi::Record)]
pub struct Round {
    pub hiding: Vec<u8>,
    pub binding: Vec<u8>,
    pub share: Vec<u8>,
}

/// One call, open.
#[derive(uniffi::Object)]
pub struct Stream {
    inner: Arc<net::Stream>,
}

#[uniffi::export(async_runtime = "tokio")]
impl Stream {
    /// Send one message.
    pub async fn send(&self, message: Vec<u8>) -> Result<(), VtxosError> {
        let stream = self.inner.clone();
        run(async move { Ok(stream.send(&message).await?) }).await
    }

    /// The next reply, or none once the enclave has ended the call well. A call it ended with an
    /// error is [`VtxosError::Status`].
    pub async fn next(&self) -> Result<Option<Vec<u8>>, VtxosError> {
        let stream = self.inner.clone();
        run(async move { Ok(stream.next().await?) }).await
    }

    /// No more messages from this side. The enclave may still reply.
    pub fn finish(&self) {
        self.inner.finish();
    }

    /// Abandon the call, and free the session for the next one.
    pub fn cancel(&self) {
        self.inner.cancel();
    }
}
