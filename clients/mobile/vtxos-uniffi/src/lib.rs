//! vtxos for Kotlin, Swift and React Native: [`vtxos_client`], exported through UniFFI.
//!
//! The app holds two things for a wallet: a passkey, whose PRF output it passes in at each use, and
//! a [`WalletRecord`], which [`Vtxos::register`] returns and is useless without the passkey. From
//! them [`Vtxos::open`] rebuilds the wallet's share, which lives in an open [`Wallet`] until
//! [`Wallet::close`].
//!
//! Every call runs on this library's own tokio runtime, so the connections it keeps open outlive
//! any one call, whatever runtime the foreign side has.

use std::future::Future;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use vtxos_client::asp::Asp;
use vtxos_client::enclave::Enclave;
use vtxos_client::keys;
use vtxos_client::wallet as client;

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
    /// The enclave or its guest answered with an error.
    #[error("{message}")]
    Enclave { message: String },
    /// The ASP refused or could not be reached.
    #[error("{message}")]
    Asp { message: String },
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
            E::Enclave(_) => VtxosError::Enclave { message },
            E::Asp(_) => VtxosError::Asp { message },
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

/// What the app keeps for a wallet: not secret without the passkey, and needed with it. Keep it
/// backed up; losing it loses the wallet even with the passkey.
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

/// A VTXO the wallet holds.
#[derive(uniffi::Record)]
pub struct Vtxo {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    pub exit_delay: u32,
    /// Unix seconds.
    pub expires_at: i64,
}

/// An on-chain output paid to the wallet's boarding address.
#[derive(uniffi::Record)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
}

/// What renewing the delegate should arrange alongside it.
#[derive(uniffi::Record, Default)]
pub struct Renewal {
    /// An on-chain address the user controls: each VTXO gets a signed exit paying it.
    #[uniffi(default = None)]
    pub exit_address: Option<String>,
    /// A push token, so background renewal can wake this phone.
    #[uniffi(default = None)]
    pub device_token: Option<String>,
}

/// A signed exit, with everything needed to leave without the ASP. Keep it.
///
/// To leave: put each of `unroll` on chain in order, then, once the last has confirmed and
/// `sequence` has passed, `raw_tx`. Each pays no fee and carries a P2A anchor, so each goes in a
/// package with a child that spends the anchor and pays for both, from the app's own wallet; one
/// per block, since TRUC lets a transaction have only one unconfirmed parent.
///
/// It holds until the VTXO is spent or refreshed, or its batch expires and the ASP sweeps it. A
/// newer exit replaces it.
#[derive(uniffi::Record)]
pub struct Exit {
    /// The VTXO it spends, `txid:vout`.
    pub outpoint: String,
    pub raw_tx: Vec<u8>,
    /// The relative timelock `raw_tx` waits for, as its input's nSequence.
    pub sequence: u32,
    pub amount_sats: u64,
    /// The virtual transactions from the batch down to the VTXO, in the order they go on chain.
    pub unroll: Vec<Vec<u8>>,
}

/// A delegate renewed: the guest refreshes these VTXOs itself from `valid_at_secs`.
#[derive(uniffi::Record)]
pub struct Renewed {
    pub valid_at_secs: u64,
    pub margin_secs: u64,
    pub covered: Vec<String>,
    pub device_enrolled: bool,
    pub exits: Vec<Exit>,
}

/// A send the ASP accepted.
#[derive(uniffi::Record)]
pub struct Sent {
    pub ark_txid: String,
    pub renewed: Option<Renewed>,
}

/// A round settled: boarding, or a refresh.
#[derive(uniffi::Record)]
pub struct Settled {
    pub commitment_txid: String,
    pub vtxo_txid: String,
    pub vtxo_vout: u32,
    pub amount_sats: u64,
    pub exit_delay: u32,
    pub renewed: Option<Renewed>,
}

impl From<client::Vtxo> for Vtxo {
    fn from(v: client::Vtxo) -> Self {
        Vtxo {
            txid: v.txid,
            vout: v.vout,
            amount_sats: v.amount_sats,
            exit_delay: v.exit_delay,
            expires_at: v.expires_at,
        }
    }
}

impl From<Renewal> for client::Renewal {
    fn from(r: Renewal) -> Self {
        client::Renewal {
            exit_address: r.exit_address,
            device_token: r.device_token,
        }
    }
}

impl From<client::Renewed> for Renewed {
    fn from(r: client::Renewed) -> Self {
        Renewed {
            valid_at_secs: r.valid_at_secs,
            margin_secs: r.margin_secs,
            covered: r.covered,
            device_enrolled: r.device_enrolled,
            exits: r
                .exits
                .into_iter()
                .map(|e| Exit {
                    outpoint: e.outpoint,
                    raw_tx: e.raw_tx,
                    sequence: e.sequence,
                    amount_sats: e.amount_sats,
                    unroll: e.unroll,
                })
                .collect(),
        }
    }
}

impl From<client::Settled> for Settled {
    fn from(s: client::Settled) -> Self {
        Settled {
            commitment_txid: s.commitment_txid,
            vtxo_txid: s.vtxo_txid,
            vtxo_vout: s.vtxo_vout,
            amount_sats: s.amount_sats,
            exit_delay: s.exit_delay,
            renewed: s.renewed.map(Into::into),
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

/// An enclave runtime and an ASP: where wallets are made and opened.
#[derive(uniffi::Object)]
pub struct Vtxos {
    enclave: Arc<Enclave>,
    asp: Arc<Asp>,
}

#[uniffi::export(async_runtime = "tokio")]
impl Vtxos {
    /// `enclave_url` is `https://…`; `asp_url` is `https://…`, or `http://…` for a regtest ASP.
    /// Nothing connects until a call needs to.
    #[uniffi::constructor]
    pub fn new(enclave_url: String, asp_url: String, pins: Pins) -> Result<Arc<Self>, VtxosError> {
        let decode = |hex_pcr: &str, which: &str| {
            hex::decode(hex_pcr)
                .ok()
                .filter(|b| b.len() == 48)
                .ok_or_else(|| invalid(format!("{which} is not 48 bytes of hex")))
        };
        let pins = vtxos_client::enclave::Pins {
            trust_root: pins
                .trust_root_pem
                .unwrap_or_else(|| enclave_client_root().to_string())
                .into_bytes(),
            pcr0: decode(&pins.pcr0, "PCR0")?,
            pcr16: decode(&pins.pcr16, "PCR16")?,
            max_age: Duration::from_secs(pins.max_age_secs),
        };
        Ok(Arc::new(Vtxos {
            enclave: Arc::new(Enclave::new(&enclave_url, &pins)?),
            asp: Arc::new(Asp::new(&asp_url)),
        }))
    }

    /// Register a new wallet whose key the passkey's PRF output makes, with the enclave.
    pub async fn register(&self, prf_output: Vec<u8>) -> Result<WalletRecord, VtxosError> {
        let (enclave, prf) = (self.enclave.clone(), prf(&prf_output)?);
        run(async move { Ok(enclave.register(&prf).await?.into()) }).await
    }

    /// Open a wallet: its share, rebuilt from the passkey's PRF output and its record.
    pub fn open(
        &self,
        record: WalletRecord,
        prf_output: Vec<u8>,
    ) -> Result<Arc<Wallet>, VtxosError> {
        let client = keys::WalletRecord::from(record).open(&prf(&prf_output)?)?;
        let wallet = client::Wallet::new(self.enclave.clone(), self.asp.clone(), client);
        Ok(Arc::new(Wallet {
            inner: Mutex::new(Some(Arc::new(wallet))),
        }))
    }
}

fn enclave_client_root() -> &'static str {
    vtxos_client::enclave::AWS_NITRO_ROOT_G1_PEM
}

/// An open wallet, its share in memory until [`Wallet::close`].
#[derive(uniffi::Object)]
pub struct Wallet {
    inner: Mutex<Option<Arc<client::Wallet>>>,
}

impl Wallet {
    fn get(&self) -> Result<Arc<client::Wallet>, VtxosError> {
        self.inner
            .lock()
            .expect("the wallet's lock")
            .clone()
            .ok_or_else(|| invalid("the wallet is closed"))
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl Wallet {
    /// Where to receive off-chain.
    pub async fn ark_address(&self) -> Result<String, VtxosError> {
        let w = self.get()?;
        run(async move { Ok(w.ark_address().await?) }).await
    }

    /// Where to send on-chain funds, to bring them in with [`Wallet::board`].
    pub async fn boarding_address(&self) -> Result<String, VtxosError> {
        let w = self.get()?;
        run(async move { Ok(w.boarding_address().await?) }).await
    }

    pub async fn vtxos(&self) -> Result<Vec<Vtxo>, VtxosError> {
        let w = self.get()?;
        run(async move { Ok(w.vtxos().await?.into_iter().map(Into::into).collect()) }).await
    }

    pub async fn balance(&self) -> Result<u64, VtxosError> {
        let w = self.get()?;
        run(async move { Ok(w.balance().await?) }).await
    }

    /// Send `amount_sats` off-chain to the Ark address `address`; with `renewal`, renew the
    /// delegate over what is left.
    pub async fn send(
        &self,
        address: String,
        amount_sats: u64,
        renewal: Option<Renewal>,
    ) -> Result<Sent, VtxosError> {
        let w = self.get()?;
        run(async move {
            let sent = w
                .send(&address, amount_sats, renewal.map(Into::into))
                .await?;
            Ok(Sent {
                ark_txid: sent.ark_txid,
                renewed: sent.renewed.map(Into::into),
            })
        })
        .await
    }

    /// Bring an on-chain output paid to the boarding address into Ark.
    pub async fn board(&self, utxo: Utxo, renewal: Option<Renewal>) -> Result<Settled, VtxosError> {
        let w = self.get()?;
        run(async move {
            let utxo = (utxo.txid, utxo.vout, utxo.amount_sats);
            Ok(w.board(utxo, renewal.map(Into::into)).await?.into())
        })
        .await
    }

    /// Refresh everything held into a new VTXO, in the next round.
    pub async fn refresh(&self, renewal: Option<Renewal>) -> Result<Settled, VtxosError> {
        let w = self.get()?;
        run(async move { Ok(w.refresh(renewal.map(Into::into)).await?.into()) }).await
    }

    /// Renew the delegate over what is held, and its exits: the guest then refreshes these VTXOs
    /// itself before they expire, with nobody connected.
    pub async fn protect(&self, renewal: Renewal) -> Result<Renewed, VtxosError> {
        let w = self.get()?;
        run(async move { Ok(w.protect(renewal.into()).await?.into()) }).await
    }

    pub async fn register_device(&self, token: String) -> Result<(), VtxosError> {
        let w = self.get()?;
        run(async move { Ok(w.register_device(&token).await?) }).await
    }

    pub async fn forget_device(&self, token: String) -> Result<(), VtxosError> {
        let w = self.get()?;
        run(async move { Ok(w.forget_device(&token).await?) }).await
    }

    pub async fn device_count(&self) -> Result<u32, VtxosError> {
        let w = self.get()?;
        run(async move { Ok(w.device_count().await?) }).await
    }

    /// Drop the share. Calls already running finish with it; no new call can start.
    pub fn close(&self) {
        self.inner.lock().expect("the wallet's lock").take();
    }
}
