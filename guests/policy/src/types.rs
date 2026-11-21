//! Durable, non-secret domain types. Plain data, no crypto material — the sealed snapshot is built
//! from these.

use serde::{Deserialize, Serialize};

/// One VTXO this policy holds. `created_at`/`expires_at` come from the ASP and feed the
/// delegate's renewal deadline; rows lacking them deserialize to 0 — unknown expiry, treated
/// conservatively.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtxoEntry {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub exit_delay: u32,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub expires_at: i64,
}



#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArkTxEntry {
    /// "board", "send", "receive", "settle".
    pub tx_type: String,
    /// Positive for inflows, negative for outflows.
    pub amount_sats: i64,
    pub txid: String,
    /// Seconds since the Unix epoch.
    pub timestamp: i64,
}

/// A spendable VTXO the actor can use as a send input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtxoInput {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    pub exit_delay: u32,
    /// Unix seconds, as the ASP's indexer reports it; 0 when not known. Schedules a wake, nothing
    /// more.
    #[serde(default)]
    pub expires_at: i64,
}



/// The actor's durable state, serialized into the sealed snapshot blob. Excludes in-flight
/// sessions (MuSig2 secret nonces must never persist) and the wallet key, which the runtime keeps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotState {
    /// The owned set, with expiry. `VtxoInput` before — a shape that dropped the expiry a
    /// delegate's renewal deadline needs, which is why a second set existed alongside it.
    pub vtxos: Vec<VtxoEntry>,
    /// A `ReadyToSettle` delegate session serialized via ark `PersistedDelegate` (JSON), if
    /// one is pending. Lets durable auto-settle survive actor eviction. Only ever
    /// `ReadyToSettle` (never a `Settling`-phase session — MuSig2 nonces must not persist).
    pub delegate_json: Option<String>,
    /// Where older seals kept the delegate's registration id, which the delegate now carries.
    /// Read only to restore a delegate sealed before it did, and never written.
    #[serde(default, skip_serializing)]
    pub delegate_intent_id: Option<String>,
}

// ===========================================================================
// Actor method inputs. Plain-data request structs passed to the `Policy` signing/session
// methods the registry calls (`sign_step1`, `send_vtxo_step1`, `generate_delegate`, …).
// ===========================================================================

/// SendVtxo phase 1 — build the Ark tx and get sighashes to sign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendVtxoStep1 {
    pub recipient_ark_address: String,
    pub amount: u64,
    /// The current spendable VTXO set, supplied by the host from its persisted projection. The
    /// actor selects from these + checks the balance itself (no separate `SetVtxos` push).
    pub vtxos: Vec<VtxoInput>,
}

/// One participant's signing commitments, keyed by FROST identifier (hex).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitment {
    pub identifier_hex: String,
    pub hiding: Vec<u8>,
    pub binding: Vec<u8>,
}

// ===========================================================================
// Actor method outputs. Typed return values for the `Policy` methods the registry
// calls directly. Plain in-process data — no serde needed (never crosses a boundary).
// ===========================================================================





/// Output of `settle_delegate`: the finalized commitment txid, the settled VTXO outpoint if
/// produced, and the `unilateral_exit_delay` the output was built with.
#[derive(Debug)]
pub struct SettleSubmitted {
    pub commitment_txid: String,
    pub vtxo_outpoint: Option<(String, u32)>,
    pub exit_delay: u32,
}

/// Output of a completed boarding settle: the finalized settle's new VTXO.
#[derive(Debug)]
pub struct BoardingSettleSubmitted {
    pub commitment_txid: String,
    pub vtxo_txid: String,
    pub vtxo_vout: u32,
    pub amount_sats: u64,
    pub exit_delay: u32,
}

/// Result of a `boarding_session` step: either more sighashes to FROST-sign (mid-flight) or the
/// finalized VTXO (completion).
#[derive(Debug)]
pub enum BoardingSettleOutcome {
    Sighashes(Vec<Vec<u8>>),
    Submitted(BoardingSettleSubmitted),
}

