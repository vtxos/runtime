//! Exits the phone signs with a delegate: the escape hatch, checked on both sides.
//!
//! With a renewed delegate the guest also asks the phone to sign one exit per VTXO, paying the
//! address the user gave. The phone builds the same transactions with the same code
//! (`ark::exit`), in the guest's order and with its rule for dust, and signs only if the sighashes
//! it is asked for are exactly those. When the signed exits come back, each must be that
//! transaction with a signature that verifies over its own exit leaf.

use ark::client::Info;
use ark::exit::{build_exit_tx, ExitInput, ExitSpend};
use bitcoin::consensus::deserialize;
use bitcoin::secp256k1::{schnorr, Message, Secp256k1};
use bitcoin::{ScriptBuf, Transaction, XOnlyPublicKey};

use crate::error::{Error, Result};
use crate::proto::guest::{ExitTx, VtxoInput};

/// One exit, signed and ready to broadcast once its delay has passed.
#[derive(Debug, Clone)]
pub struct Exit {
    /// The VTXO it spends, `txid:vout`.
    pub outpoint: String,
    /// The whole transaction, consensus-serialized.
    pub raw_tx: Vec<u8>,
    /// The relative timelock it waits for, as the input's nSequence.
    pub sequence: u32,
    pub amount_sats: u64,
}

/// The exits the guest is expected to ask for.
pub(crate) struct Plan {
    owner: XOnlyPublicKey,
    spends: Vec<(String, ExitSpend)>,
}

impl Plan {
    /// One exit per VTXO in `vtxos`, in order, paying `destination`. A VTXO whose exit could not
    /// be built, as one below the dust floor, gets none: the guest's rule.
    pub(crate) fn new(
        info: &Info,
        owner: XOnlyPublicKey,
        vtxos: &[VtxoInput],
        destination: &ScriptBuf,
    ) -> Self {
        let asp = info.signer_pk.x_only_public_key().0;
        let spends = vtxos
            .iter()
            .filter_map(|v| {
                let input = ExitInput {
                    txid: v.txid.parse().ok()?,
                    vout: v.vout,
                    amount_sats: v.amount_sats,
                    exit_delay: v.exit_delay,
                };
                let spend = build_exit_tx(asp, owner, info.network, &input, destination).ok()?;
                Some((format!("{}:{}", v.txid, v.vout), spend))
            })
            .collect();
        Plan { owner, spends }
    }

    /// Refuse to sign exits other than the ones built here.
    pub(crate) fn check(&self, offered: &[Vec<u8>]) -> Result<()> {
        let expected: Vec<&[u8]> = self
            .spends
            .iter()
            .map(|(_, s)| s.sighash.as_slice())
            .collect();
        let offered: Vec<&[u8]> = offered.iter().map(Vec::as_slice).collect();
        if expected != offered {
            return Err(Error::Protocol(format!(
                "the guest asked to sign {} exits that are not the {} this wallet would build",
                offered.len(),
                expected.len()
            )));
        }
        Ok(())
    }

    /// The signed exits, each checked: the transaction built here, and a signature by the wallet
    /// key over its exit leaf.
    pub(crate) fn verify(&self, returned: &[ExitTx]) -> Result<Vec<Exit>> {
        if returned.len() != self.spends.len() {
            return Err(Error::Protocol(format!(
                "{} exits came back for the {} signed",
                returned.len(),
                self.spends.len()
            )));
        }
        let secp = Secp256k1::verification_only();
        self.spends
            .iter()
            .zip(returned)
            .map(|((outpoint, spend), exit)| {
                let tx: Transaction = deserialize(&exit.raw_tx)
                    .map_err(|e| Error::Protocol(format!("the exit of {outpoint}: {e}")))?;
                let mut unsigned = tx.clone();
                unsigned.input.iter_mut().for_each(|i| i.witness.clear());
                let witness = &tx.input.first().ok_or_else(|| bad(outpoint))?.witness;
                let signature = witness
                    .nth(0)
                    .and_then(|s| schnorr::Signature::from_slice(s).ok())
                    .ok_or_else(|| bad(outpoint))?;
                let valid = unsigned == spend.tx
                    && exit.outpoint == *outpoint
                    && witness.len() == 3
                    && witness.nth(1) == Some(spend.script.as_bytes())
                    && witness.nth(2) == Some(spend.control_block.serialize().as_slice())
                    && secp
                        .verify_schnorr(
                            &signature,
                            &Message::from_digest(spend.sighash),
                            &self.owner,
                        )
                        .is_ok();
                if !valid {
                    return Err(bad(outpoint));
                }
                Ok(Exit {
                    outpoint: outpoint.clone(),
                    raw_tx: exit.raw_tx.clone(),
                    sequence: spend.sequence,
                    amount_sats: exit.amount_sats,
                })
            })
            .collect()
    }
}

fn bad(outpoint: &str) -> Error {
    Error::Protocol(format!(
        "the exit of {outpoint} is not the transaction signed"
    ))
}
