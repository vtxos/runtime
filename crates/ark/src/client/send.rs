//! Off-chain VTXO send — build, sign, and submit Ark transactions.
//!
//! 1. **Build** (`SendSession::build`) — ark-core's `build_offchain_transactions` makes the ark
//!    tx and its checkpoints, and its signing helpers name the sighashes to FROST-sign.
//! 2. **Sign** (`sign_with_frost`) — take the FROST signatures back.
//! 3. **Submit** (`prepare_submit`, then `finalize_checkpoints`) — the same helpers put the
//!    signatures in; the caller submits and finalizes with the ASP.

use std::collections::HashMap;

use ark_core::send::{self, OffchainTransactions, VtxoInput};
use ark_core::server;

use bitcoin::base64::{self, Engine};
use bitcoin::key::Secp256k1;
use bitcoin::{Amount, OutPoint, Psbt, XOnlyPublicKey};

use crate::client::sighashes::{Collect, Replay};
use crate::client::Info;
use crate::keys::parse_xonly;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// VTXO input descriptor for off-chain send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendVtxoInput {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    /// This VTXO's OWN unilateral-exit delay, which is part of its taproot tree
    /// and therefore of its scriptPubKey. A wallet legitimately holds a mix: a
    /// boarding-settled VTXO carries `boarding_exit_delay` while a received one
    /// carries `unilateral_exit_delay`, so one delay cannot stand in for all.
    pub exit_delay: u32,
}

enum SendPhase {
    AwaitingSignatures,
    ReadyToSubmit,
    Done,
}

/// A session for sending VTXOs off-chain to an Ark address.
///
/// The flow splits into phases so FROST signing can happen externally:
/// 1. `build()` → the sighashes
/// 2. `sign_with_frost()` → the signatures
/// 3. `prepare_submit()` / `finalize_checkpoints()` → what the caller sends the ASP
pub struct SendSession {
    phase: SendPhase,

    owner_pk: XOnlyPublicKey,

    // Transactions built by ark_core::send
    ark_tx: Psbt,
    checkpoint_txs: Vec<Psbt>,

    // What ark-core asked to have signed, ark tx inputs first, then each checkpoint.
    sighashes: Vec<[u8; 32]>,

    // FROST signatures (stored after sign_with_frost, applied during submit)
    frost_signatures: Option<Vec<[u8; 64]>>,
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

impl SendSession {
    /// Build off-chain transactions and compute all sighashes.
    ///
    /// Returns `(session, sighashes)` where sighashes need FROST signing.
    /// Sighash order: all ark tx inputs first, then all checkpoint inputs.
    pub fn build(
        owner_pk_hex: &str,
        vtxo_inputs: &[SendVtxoInput],
        recipient_ark_address: &str,
        amount_sats: u64,
        change_ark_address: Option<&str>,
        info: &Info,
    ) -> Result<(Self, Vec<[u8; 32]>), String> {
        let secp = Secp256k1::new();
        let network = info.network;

        let owner_pk = parse_xonly(owner_pk_hex)?;
        let asp_pk = info.signer_pk.x_only_public_key().0;

        // Derive the spend info from EACH input's own exit delay, not from one
        // shared value. The delay is part of the VTXO's taproot tree, so reusing
        // one input's script/control block for the rest yields a wrong
        // scriptPubKey and a sighash computed over the wrong prevout — the ASP
        // rejects such a send. `generate_delegate` already builds one Vtxo per
        // distinct delay; this is the same treatment for the send path.
        //
        // Cached by delay: a mixed set is usually just two distinct values
        // (boarding vs unilateral), and Vtxo::new_default does real taproot work.
        let mut spend_info_by_delay: HashMap<u32, _> = HashMap::new();
        for vi in vtxo_inputs {
            if spend_info_by_delay.contains_key(&vi.exit_delay) {
                continue;
            }
            let exit_seq = server::parse_sequence_number(vi.exit_delay as i64)
                .map_err(|e| format!("invalid exit_delay {}: {e}", vi.exit_delay))?;
            let vtxo = ark_core::Vtxo::new_default(&secp, asp_pk, owner_pk, exit_seq, network)
                .map_err(|e| format!("Vtxo::new_default: {e}"))?;
            let (spend_script, control_block) = vtxo
                .forfeit_spend_info()
                .map_err(|e| format!("forfeit_spend_info: {e}"))?;
            spend_info_by_delay.insert(
                vi.exit_delay,
                (
                    spend_script,
                    control_block,
                    vtxo.tapscripts(),
                    vtxo.script_pubkey(),
                ),
            );
        }

        // Build VtxoInput for each input VTXO.
        let send_inputs: Vec<VtxoInput> = vtxo_inputs
            .iter()
            .map(|vi| {
                let outpoint = OutPoint {
                    txid: vi.txid.parse().map_err(|e| format!("invalid txid: {e}"))?,
                    vout: vi.vout,
                };
                let (spend_script, control_block, tapscripts, vtxo_script_pubkey) =
                    spend_info_by_delay
                        .get(&vi.exit_delay)
                        .ok_or("missing spend info for exit delay")?;
                Ok(VtxoInput::new(
                    spend_script.clone(),
                    None, // no locktime for default VTXOs
                    control_block.clone(),
                    tapscripts.clone(),
                    vtxo_script_pubkey.clone(),
                    Amount::from_sat(vi.amount_sats),
                    outpoint,
                    Vec::new(), // assets — none (ark-core 0.9)
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;

        // Parse recipient address.
        let recipient: ark_core::ArkAddress = recipient_ark_address
            .parse()
            .map_err(|e| format!("invalid recipient ark address: {e}"))?;

        // ark-core 0.9 takes `SendReceiver`s instead of (&addr, amount) tuples.
        let receivers = vec![send::SendReceiver::bitcoin(
            recipient,
            Amount::from_sat(amount_sats),
        )];

        // 0.9 requires a change address (it only emits a change output when
        // there is leftover value). Default to the sender's own ark address
        // when the caller didn't pass one.
        let change_addr: ark_core::ArkAddress = match change_ark_address {
            Some(a) => a
                .parse()
                .map_err(|e| format!("invalid change ark address: {e}"))?,
            None => ark_core::Vtxo::new_default(
                &secp,
                asp_pk,
                owner_pk,
                info.unilateral_exit_delay,
                network,
            )
            .map_err(|e| format!("Vtxo::new_default: {e}"))?
            .to_ark_address(),
        };

        // Build the off-chain transactions.
        let OffchainTransactions {
            ark_tx,
            checkpoint_txs,
        } = send::build_offchain_transactions(&receivers, &change_addr, &send_inputs, info)
            .map_err(|e| format!("build_offchain_transactions: {e}"))?;

        // The sighashes are whatever ark-core's signing helpers ask to have signed, run over
        // copies: see `sighashes`.
        let collect = Collect::default();
        sign(&collect.any(), &mut ark_tx.clone(), &mut checkpoint_txs.clone())?;
        let sighashes = collect.into_messages();

        let session = SendSession {
            phase: SendPhase::AwaitingSignatures,
            owner_pk,
            ark_tx,
            checkpoint_txs,
            sighashes: sighashes.clone(),
            frost_signatures: None,
        };

        Ok((session, sighashes))
    }
}

// ---------------------------------------------------------------------------
// FROST signature insertion
// ---------------------------------------------------------------------------

impl SendSession {
    /// Store FROST signatures for later insertion during submit.
    pub fn sign_with_frost(&mut self, signatures: Vec<[u8; 64]>) -> Result<(), String> {
        if !matches!(self.phase, SendPhase::AwaitingSignatures) {
            return Err("sign_with_frost called in wrong phase".into());
        }
        if signatures.len() != self.sighashes.len() {
            return Err(format!(
                "expected {} signatures, got {}",
                self.sighashes.len(),
                signatures.len()
            ));
        }
        self.frost_signatures = Some(signatures);
        self.phase = SendPhase::ReadyToSubmit;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ASP submission
// ---------------------------------------------------------------------------

impl SendSession {
    /// Insert the stored FROST signatures into the PSBTs and produce the base64 payloads
    /// to submit: `(signed_ark_tx, unsigned_checkpoint_txs)`. Pure signing-side prep — no
    /// ASP. Callable from the wasm guest (the guest drives submission via host imports).
    pub fn prepare_submit(&mut self) -> Result<(String, Vec<String>), String> {
        if !matches!(self.phase, SendPhase::ReadyToSubmit) {
            return Err("submit called in wrong phase".into());
        }

        let signatures = self
            .frost_signatures
            .take()
            .ok_or("missing FROST signatures")?;

        // The same helpers that named the sighashes put the signatures in.
        let replay = Replay::new(&self.sighashes, &signatures, self.owner_pk)?;
        sign(&replay.any(), &mut self.ark_tx, &mut self.checkpoint_txs)?;
        replay.finish()?;

        // Signed ark tx + checkpoints WITHOUT our sigs (the ASP adds its own first).
        let signed_ark_b64 = encode_psbt_b64(&self.ark_tx);
        let unsigned_checkpoint_b64s: Vec<String> = self
            .checkpoint_txs
            .iter()
            .map(|cp| {
                let mut unsigned = cp.clone();
                for input in &mut unsigned.inputs {
                    input.tap_script_sigs.clear();
                }
                encode_psbt_b64(&unsigned)
            })
            .collect();

        Ok((signed_ark_b64, unsigned_checkpoint_b64s))
    }

    /// Counter-sign the ASP-returned checkpoints with our FROST signatures, returning the
    /// fully-signed checkpoint PSBTs (base64) to finalize. Pure PSBT math — guest-callable.
    pub fn finalize_checkpoints(
        &self,
        signed_checkpoint_txs_b64: &[String],
    ) -> Result<Vec<String>, String> {
        let mut final_checkpoints = Vec::new();
        for asp_cp_b64 in signed_checkpoint_txs_b64 {
            let mut asp_cp = decode_psbt_b64(asp_cp_b64)?;

            // Find matching original checkpoint by unsigned_tx txid.
            let cp_txid = asp_cp.unsigned_tx.compute_txid();
            let original = self
                .checkpoint_txs
                .iter()
                .find(|cp| cp.unsigned_tx.compute_txid() == cp_txid)
                .ok_or_else(|| format!("ASP returned unknown checkpoint txid: {cp_txid}"))?;

            // Restore witness_script / tap_scripts (may be stripped by ASP).
            if let Some(ws) = &original.inputs[0].witness_script {
                asp_cp.inputs[0].witness_script = Some(ws.clone());
            }
            if asp_cp.inputs[0].tap_scripts.is_empty() {
                asp_cp.inputs[0].tap_scripts = original.inputs[0].tap_scripts.clone();
            }

            // Our signatures, as ark-core put them into our checkpoint in `prepare_submit`.
            for ((pk, lh), sig) in &original.inputs[0].tap_script_sigs {
                asp_cp.inputs[0]
                    .tap_script_sigs
                    .insert((*pk, *lh), sig.clone());
            }

            final_checkpoints.push(encode_psbt_b64(&asp_cp));
        }
        Ok(final_checkpoints)
    }

    /// The transactions as built, before anybody has signed: the ark tx and one checkpoint per
    /// input, base64 PSBTs.
    ///
    /// For a counterparty that has to submit *exactly* what was approved rather than rebuild it.
    /// `build` is deterministic, so a party running it over the same inputs gets the same bytes —
    /// but "the same, we checked" is a weaker thing to rest a release on than "these, verbatim",
    /// and a signature is only valid over the transaction whose sighashes it covers anyway.
    pub fn unsigned(&self) -> (String, Vec<String>) {
        (
            encode_psbt_b64(&self.ark_tx),
            self.checkpoint_txs.iter().map(encode_psbt_b64).collect(),
        )
    }

    /// The ark transaction's id, known as soon as it is built.
    ///
    /// Fixed before anything is signed: these are taproot script-path spends, so the signatures go
    /// in the witness and the txid does not move. That is what lets a caller write down what it is
    /// about to submit, and afterwards ask the chain whether it landed.
    pub fn ark_txid(&self) -> String {
        self.ark_tx.unsigned_tx.compute_txid().to_string()
    }

    /// The ark transaction's outputs — where the money actually goes — for a policy to judge.
    pub fn outputs(&self) -> &[bitcoin::TxOut] {
        &self.ark_tx.unsigned_tx.output
    }

    /// Mark the session complete after finalization succeeds.
    pub fn mark_done(&mut self) {
        self.phase = SendPhase::Done;
    }

    /// Returns the change VTXO outpoint `(txid, vout, amount_sats)` if the
    /// ark tx has a change output.
    /// Output order: [recipient(s)..., change, anchor]. The anchor output
    /// (0-value) is always last, so change is second-to-last when present.
    /// Call after `submit()`.
    pub fn change_vtxo(&self) -> Option<(String, u32, u64)> {
        let outputs = &self.ark_tx.unsigned_tx.output;
        // At minimum: 1 recipient + 1 anchor = 2 outputs (no change).
        // With change: 1 recipient + 1 change + 1 anchor = 3+ outputs.
        if outputs.len() < 3 {
            return None;
        }
        let txid = self.ark_tx.unsigned_tx.compute_txid().to_string();
        // Change is second-to-last (before anchor)
        let change_idx = outputs.len() - 2;
        let amount = outputs[change_idx].value.to_sat();
        if amount == 0 {
            return None;
        }
        Some((txid, change_idx as u32, amount))
    }
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Run ark-core's signing helpers over the ark tx's inputs, then each checkpoint's: the order the
/// sighashes are handed out in.
fn sign<F>(f: &F, ark_tx: &mut Psbt, checkpoint_txs: &mut [Psbt]) -> Result<(), String>
where
    F: Fn(
        &mut bitcoin::psbt::Input,
        bitcoin::secp256k1::Message,
    ) -> Result<Vec<(bitcoin::secp256k1::schnorr::Signature, XOnlyPublicKey)>, ark_core::Error>,
{
    for i in 0..ark_tx.inputs.len() {
        send::sign_ark_transaction(f, ark_tx, i)
            .map_err(|e| format!("ark tx input {i}: {e}"))?;
    }
    for (i, checkpoint) in checkpoint_txs.iter_mut().enumerate() {
        send::sign_checkpoint_transaction(f, checkpoint)
            .map_err(|e| format!("checkpoint {i}: {e}"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn decode_psbt_b64(b64: &str) -> Result<Psbt, String> {
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new(),
    );
    let bytes = engine
        .decode(b64)
        .map_err(|e| format!("base64 decode: {e}"))?;
    Psbt::deserialize(&bytes).map_err(|e| format!("PSBT deserialize: {e}"))
}

fn encode_psbt_b64(psbt: &Psbt) -> String {
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new(),
    );
    engine.encode(psbt.serialize())
}
