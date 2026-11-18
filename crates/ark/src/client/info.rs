//! The ASP's parameters, in ark-core's own type.
//!
//! arkd publishes them as strings and integers (`GetInfoResponse`), and that is how they travel:
//! the wallet relays them, and the guest reads them from arkd's REST gateway. ark-core's builders
//! take a typed [`Info`]. [`server_info`] is the one place the first becomes the second.

use std::str::FromStr;

use ark_core::server;
use bitcoin::address::NetworkUnchecked;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{relative, Address, Amount, ScriptBuf, Sequence};

use crate::client::address::parse_network;
use crate::client::proto;

pub use ark_core::server::Info;

/// arkd's `GetInfo` answer as an [`Info`].
///
/// Only what arkd's answer carries is filled in; `fees`, `scheduled_session` and
/// `deprecated_signers` are left empty, and none of the ark-core builders this crate calls reads
/// them. A delay that [`exit_delay_value`] would not give back unchanged is refused, so the raw
/// delays the wire and the guest's state carry always match the sequences here.
pub fn server_info(i: proto::GetInfoResponse) -> Result<Info, String> {
    let network = parse_network(&i.network)?;
    let key = |hex: &str, what: &str| {
        // arkd publishes keys compressed; an x-only one is lifted with even y, as BIP-340 does.
        let compressed = if hex.len() == 64 { format!("02{hex}") } else { hex.to_string() };
        PublicKey::from_str(&compressed).map_err(|e| format!("invalid {what} {hex:?}: {e}"))
    };
    let delay = |raw: i64, what: &str| {
        let sequence = server::parse_sequence_number(raw)
            .map_err(|e| format!("invalid {what} {raw}: {e}"))?;
        if i64::from(exit_delay_value(sequence)?) != raw {
            return Err(format!("{what} {raw} is not a whole number of 512-second units"));
        }
        Ok::<_, String>(sequence)
    };
    // arkd sends 0 for "none" and -1 for "no limit".
    let limit = |sats: i64| u64::try_from(sats).ok().filter(|s| *s > 0).map(Amount::from_sat);

    Ok(Info {
        version: i.version,
        signer_pk: key(&i.signer_pubkey, "signer_pubkey")?,
        forfeit_pk: key(&i.forfeit_pubkey, "forfeit_pubkey")?,
        forfeit_address: i
            .forfeit_address
            .parse::<Address<NetworkUnchecked>>()
            .map_err(|e| format!("invalid forfeit_address {:?}: {e}", i.forfeit_address))?
            .require_network(network)
            .map_err(|e| format!("forfeit_address is for another network: {e}"))?,
        checkpoint_tapscript: ScriptBuf::from_hex(&i.checkpoint_tapscript)
            .map_err(|e| format!("invalid checkpoint_tapscript: {e}"))?,
        network,
        session_duration: u64::try_from(i.session_duration)
            .map_err(|_| format!("negative session_duration {}", i.session_duration))?,
        unilateral_exit_delay: delay(i.unilateral_exit_delay, "unilateral_exit_delay")?,
        boarding_exit_delay: delay(i.boarding_exit_delay, "boarding_exit_delay")?,
        utxo_min_amount: limit(i.utxo_min_amount),
        utxo_max_amount: limit(i.utxo_max_amount),
        vtxo_min_amount: limit(i.vtxo_min_amount),
        vtxo_max_amount: limit(i.vtxo_max_amount),
        dust: Amount::from_sat(
            u64::try_from(i.dust).map_err(|_| format!("negative dust {}", i.dust))?,
        ),
        fees: None,
        scheduled_session: None,
        deprecated_signers: Vec::new(),
        service_status: i.service_status,
        digest: i.digest,
        max_tx_weight: i.max_tx_weight,
        // Not in the arkd protos this crate vendors.
        max_op_return_outputs: 0,
    })
}

/// The delay a BIP-68 sequence encodes, as the wire and the guest's state carry it: blocks, or
/// seconds when 512 or more. The inverse of `parse_sequence_number` for every delay
/// [`server_info`] accepts.
pub fn exit_delay_value(sequence: Sequence) -> Result<u32, String> {
    match sequence.to_relative_lock_time() {
        Some(relative::LockTime::Blocks(height)) => Ok(height.value().into()),
        Some(relative::LockTime::Time(time)) => Ok(u32::from(time.value()) * 512),
        None => Err(format!("{sequence} is not a relative lock time")),
    }
}
