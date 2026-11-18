//! The way down to a VTXO: the virtual transactions that must be on chain before its exit can be.
//!
//! A VTXO is an output of a transaction that exists only off chain. That transaction spends others
//! like it, back to the commitment transactions the ASP put on chain. To leave without the ASP,
//! every one of them must confirm first, and only the ASP's indexer knows them: once it is gone,
//! nobody does. So the wallet fetches a VTXO's branch when it signs the VTXO's exit, and keeps it
//! with the exit.
//!
//! Each of them is TRUC and pays no fee, with a P2A anchor, as the exit is: whoever unrolls
//! attaches a child to each that pays for both. One per block, since TRUC lets a transaction have
//! only one unconfirmed parent.

use std::collections::{HashMap, HashSet};

use ark::client::proto::{IndexerChain, IndexerChainedTxType};
use ark_core::server::{ChainedTxType, VtxoChain, VtxoChains};
use ark_core::unilateral_exit::{
    build_unilateral_exit_tree_txids, finalize_taproot_script_spend_witness,
};
use base64::Engine as _;
use bitcoin::{Psbt, Transaction, Txid, Witness};

use crate::asp::Asp;
use crate::error::{Error, Result};

/// The virtual transactions from the commitment transactions down to the VTXO `txid:vout`,
/// finalized, in the order they go on chain: each after every transaction it spends, the VTXO's
/// own last.
pub(crate) async fn branch(asp: &Asp, txid: &str, vout: u32) -> Result<Vec<Transaction>> {
    let vtxo: Txid = txid
        .parse()
        .map_err(|e| Error::Protocol(format!("VTXO txid {txid}: {e}")))?;
    let chains = vtxo_chains(&asp.vtxo_chain(txid, vout).await?)?;
    let commitments: HashSet<Txid> = chains
        .inner
        .iter()
        .filter(|c| matches!(c.tx_type, ChainedTxType::Commitment))
        .map(|c| c.txid)
        .collect();
    let order = build_unilateral_exit_tree_txids(&chains, vtxo)
        .map_err(|e| Error::Asp(format!("the chain of {txid}:{vout}: {e}")))?
        .concat();

    let wanted: Vec<String> = order.iter().map(Txid::to_string).collect();
    let mut psbts: HashMap<Txid, Psbt> = HashMap::new();
    for encoded in asp.virtual_txs(&wanted).await? {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .map_err(|e| Error::Asp(format!("a virtual transaction's base64: {e}")))?;
        let psbt = Psbt::deserialize(&bytes)
            .map_err(|e| Error::Asp(format!("a virtual transaction's PSBT: {e}")))?;
        psbts.insert(psbt.unsigned_tx.compute_txid(), psbt);
    }
    let branch = order
        .iter()
        .map(|t| {
            psbts
                .remove(t)
                .ok_or_else(|| Error::Asp(format!("no virtual transaction {t}")))
                .and_then(finalize)
        })
        .collect::<Result<Vec<_>>>()?;
    check(&branch, commitments, vtxo, vout)?;
    Ok(branch)
}

/// The indexer's chain, as ark-core takes it.
fn vtxo_chains(chain: &[IndexerChain]) -> Result<VtxoChains> {
    let txid = |t: &str| {
        t.parse::<Txid>()
            .map_err(|e| Error::Asp(format!("txid {t} in a VTXO's chain: {e}")))
    };
    let inner = chain
        .iter()
        .map(|c| {
            Ok(VtxoChain {
                txid: txid(&c.txid)?,
                tx_type: match IndexerChainedTxType::try_from(c.r#type) {
                    Ok(IndexerChainedTxType::Commitment) => ChainedTxType::Commitment,
                    Ok(IndexerChainedTxType::Tree) => ChainedTxType::Tree,
                    Ok(IndexerChainedTxType::Checkpoint) => ChainedTxType::Checkpoint,
                    Ok(IndexerChainedTxType::Ark) => ChainedTxType::Ark,
                    Ok(IndexerChainedTxType::Unspecified) | Err(_) => ChainedTxType::Unspecified,
                },
                // arkd names a checkpoint's parent by outpoint, every other by txid.
                spends: c
                    .spends
                    .iter()
                    .map(|s| txid(s.split_once(':').map_or(s.as_str(), |(t, _)| t)))
                    .collect::<Result<_>>()?,
                expires_at: c.expires_at,
            })
        })
        .collect::<Result<_>>()?;
    Ok(VtxoChains { inner })
}

/// The transaction, its witnesses made from the signatures its PSBT carries: a key-path signature
/// for a tree's nodes, the tapscript and its signatures for a checkpoint's or an Ark
/// transaction's inputs, as ark-core assembles them.
///
/// Not ark-core's `finalize_virtual_tx_input`: that wants each input's prevout, to check the fee as
/// it extracts, and a tree's root spends the commitment transaction, which the indexer does not
/// serve and a key-path witness does not need. It also finalizes only the first input, and an Ark
/// transaction may have more.
fn finalize(mut psbt: Psbt) -> Result<Transaction> {
    let txid = psbt.unsigned_tx.compute_txid();
    for (i, input) in psbt.inputs.iter_mut().enumerate() {
        let witness = match input.tap_key_sig {
            Some(signature) => Witness::p2tr_key_spend(&signature),
            None => finalize_taproot_script_spend_witness(input)
                .map_err(|e| Error::Asp(format!("virtual transaction {txid}, input {i}: {e}")))?,
        };
        input.final_script_witness = Some(witness);
    }
    Ok(psbt.extract_tx_unchecked_fee_rate())
}

/// What an exit can rely on: every transaction TRUC with an anchor to pay for it by, each spending
/// only commitment transactions and the ones before it, and the last the VTXO's own.
fn check(
    branch: &[Transaction],
    mut confirmed_before: HashSet<Txid>,
    vtxo: Txid,
    vout: u32,
) -> Result<()> {
    let anchor = ark_core::anchor_output();
    for tx in branch {
        let txid = tx.compute_txid();
        if tx.version.0 != 3 || !tx.output.contains(&anchor) {
            return Err(Error::Asp(format!(
                "virtual transaction {txid} is not TRUC with an anchor"
            )));
        }
        if let Some(input) = tx
            .input
            .iter()
            .find(|i| !confirmed_before.contains(&i.previous_output.txid))
        {
            return Err(Error::Asp(format!(
                "virtual transaction {txid} spends {}, which does not come before it",
                input.previous_output
            )));
        }
        confirmed_before.insert(txid);
    }
    match branch.last() {
        Some(last) if last.compute_txid() == vtxo && (vout as usize) < last.output.len() => Ok(()),
        _ => Err(Error::Asp(format!(
            "the branch does not end at the VTXO {vtxo}:{vout}"
        ))),
    }
}
