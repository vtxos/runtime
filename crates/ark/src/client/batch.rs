//! Ark batch rounds: boarding an on-chain output ([`SettleSession`]), and renewing VTXOs through a
//! delegate signed in advance ([`DelegateSettleSession`]).
//!
//! Both are split into steps so the FROST signatures can be made elsewhere between them, and both
//! are transport-free: the caller relays each ASP event in and sends what comes back out.
//!
//! Boarding signs twice:
//!
//! 1. [`SettleSession::new_boarding`] builds the intent proof and hands out its sighashes;
//!    [`SettleSession::insert_intent_signatures`] takes the signatures back, and
//!    [`SettleSession::register_payload`] is what to register.
//! 2. The relayed events drive the round; at `BatchFinalization`,
//!    [`SettleSession::handle_batch_finalization`] hands out the commitment's sighashes and
//!    [`SettleSession::insert_commitment_signatures`] returns the signed commitment to submit.

use std::collections::HashMap;
use std::str::FromStr;

use ark_core::batch::{NonceKps, OnChainInput};
use ark_core::batch::{aggregate_nonces, generate_nonce_tree, sign_batch_tree_tx};
use ark_core::intent::{self, Intent, IntentMessage};
use ark_core::server::PartialSigTree;
use ark_core::{BoardingOutput, TxGraph, TxGraphChunk};

use bitcoin::base64::{self, Engine};
use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::{Amount, Network, OutPoint, Psbt, Sequence, TxOut, Txid, XOnlyPublicKey};

use crate::client::address::parse_network;
use crate::client::proto;
use crate::client::sighashes::{Collect, Replay};
use crate::keys::parse_xonly;

/// Whether `event`'s batch actually contains our intent.
///
/// A public ASP batches many clients together, and `BatchStarted` is broadcast
/// regardless of whose intents made it into that batch. Confirming
/// unconditionally makes us join a batch we were never registered in, and the
/// ASP then aborts it with "not enough intent confirmations received" — its
/// real participants never confirmed. On a single-tenant regtest ASP every
/// batch is ours, which is why this only ever fails against a shared server.
///
/// The hash is `sha256(intent_id)` lowercase-hex, matching arkd and the
/// reference client in `third_party/rust-sdk/ark-client/src/batch.rs`.
/// The batch id of a batch-scoped `event` that `is_ours` rejects, or `None` when
/// the event is ours or carries no batch id at all.
///
/// Central so every settle loop gates on the same set. `BatchStarted` is
/// deliberately excluded — it is filtered by intent hash instead
/// (see [`batch_includes_intent`]), and it is what establishes the batch id
/// everything else is matched against. Heartbeat/StreamStarted are not
/// batch-scoped.
pub fn foreign_batch_id<F>(event: &Event, is_ours: F) -> Option<String>
where
    F: Fn(&str) -> bool,
{
    let id = match event {
        Event::BatchStarted(_) | Event::Heartbeat(_) | Event::StreamStarted(_) => return None,
        Event::TreeSigningStarted(e) => &e.id,
        Event::TreeNoncesAggregated(e) => &e.id,
        Event::TreeTx(e) => &e.id,
        Event::TreeNonces(e) => &e.id,
        Event::TreeSignature(e) => &e.id,
        Event::BatchFinalization(e) => &e.id,
        Event::BatchFinalized(e) => &e.id,
        Event::BatchFailed(e) => &e.id,
    };
    if is_ours(id) {
        None
    } else {
        Some(id.clone())
    }
}

pub fn batch_includes_intent(event: &proto::BatchStartedEvent, intent_id: &str) -> bool {
    let hash = sha256::Hash::hash(intent_id.as_bytes());
    let hash_hex: String = hash.as_byte_array().iter().map(|b| format!("{b:02x}")).collect();
    event.intent_id_hashes.iter().any(|h| h == &hash_hex)
}
// A prost message type, not transport: classifying an event needs no ASP connection, and the guest
// that drives a settle from relayed events needs exactly this.
use crate::client::proto::get_event_stream_response::Event;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The tree-signing work a boarding round's events call for. The MuSig2 tree-signing secret is
/// the [`BoardingTreeSigner`]'s, not the session's, so the session hands the public data out.
pub enum SettleAction {
    /// Pass these (public) tree chunks and the commitment PSBT to
    /// [`BoardingTreeSigner::gen_nonces`], and submit the nonces it returns.
    NeedTreeNonces {
        tree_tx_chunks: Vec<(String, String, Vec<(u32, String)>)>,
        commitment_psbt_b64: String,
    },
    /// Pass every node's aggregated nonces to [`BoardingTreeSigner::sign`], and submit the
    /// signatures it returns.
    NeedTreeSign {
        pending_nonces: Vec<(String, Vec<(String, String)>)>,
        batch_expiry: u32,
        forfeit_pk_hex: String,
    },
}

/// Internal phase of the settle session state machine.
enum Phase {
    /// Intent prepared, waiting for FROST signatures on intent proof.
    AwaitingIntentSignatures,
    /// Intent registered, driving the event stream.
    Driving,
    /// Commitment PSBT received, waiting for FROST signatures.
    AwaitingCommitmentSignatures,
    /// Settlement complete.
    Done,
}

/// A session for settling boarding UTXOs into Ark VTXOs.
///
/// Splits the batch protocol into phases so that FROST signing can happen
/// externally between each phase.
pub struct SettleSession {
    phase: Phase,

    // -- identity --
    owner_pk: XOnlyPublicKey,
    #[allow(dead_code)]
    asp_pk: XOnlyPublicKey,
    /// ASP's forfeit x-only public key (used for tree signing sweep scripts).
    forfeit_pk: XOnlyPublicKey,
    #[allow(dead_code)]
    network: Network,
    #[allow(dead_code)]
    exit_delay: Sequence,

    // -- boarding input --
    onchain_input: OnChainInput,

    // -- intent: what `make_intent` is given, the messages it asked to have signed, and the signed
    //    intent once the signatures are back --
    intent_inputs: Vec<intent::Input>,
    intent_outputs: Vec<intent::Output>,
    intent_message: IntentMessage,
    intent_sighashes: Vec<[u8; 32]>,
    intent: Option<Intent>,

    // -- cosigner identity (PUBLIC only) --
    // Plan A Phase 2: the MuSig2 cosigner keypair + secret per-node nonces live in the cosigner
    // guest, NOT here. This session keeps only the PUBLIC cosigner key (for the intent + event-
    // stream topic); tree-signing is delegated out via `SettleAction::NeedTreeNonces`/`NeedTreeSign`.
    cosigner_pk: bitcoin::secp256k1::PublicKey,

    // -- batch state --
    batch_id: Option<String>,
    batch_expiry: Option<Sequence>,
    tx_graph_chunks: Vec<TxGraphChunk>,
    tx_graph: Option<TxGraph>,
    commitment_psbt: Option<Psbt>,
    /// Accumulated raw nonces per tree txid (from TreeNonces events).
    /// We only sign + submit once ALL nonces for every node in the graph
    /// have been collected (matching the reference ark-client).
    pending_nonces: HashMap<Txid, HashMap<String, String>>,

    // -- commitment signing: what `sign_commitment_psbt` asked to have signed --
    commitment_sighashes: Vec<[u8; 32]>,
}

/// Standalone boarding tree-signer (Plan A Phase 2). Does ONLY the secret MuSig2 tree-signing of a
/// boarding settle — so it can run inside the cosigner guest while the host keeps the batch state
/// machine, the event stream, and the FROST rounds. It holds the secret per-node nonces between
/// `gen_nonces` and `sign`. All inputs/outputs are wire-friendly (hex / base64 / strings), so the
/// guest needs no `ark_core` types: the host passes the public tree graph; the secret stays here.
pub struct BoardingTreeSigner {
    cosigner_kp: Keypair,
    tx_graph: Option<TxGraph>,
    commitment_psbt: Option<Psbt>,
    nonce_kps: Option<NonceKps>,
}

impl BoardingTreeSigner {
    /// A signer with a tree-signing key of its own, drawn for this one round. Once the round is
    /// over the tree is presigned and nothing needs the key again; one key across rounds would only
    /// let the ASP link them.
    pub fn generate() -> Self {
        Self {
            cosigner_kp: Keypair::new(&Secp256k1::new(), &mut rand::thread_rng()),
            tx_graph: None,
            commitment_psbt: None,
            nonce_kps: None,
        }
    }

    /// The cosigner's MuSig2 public key (33-byte compressed, hex) — the host needs it for the
    /// boarding intent's `own_cosigner_pks` and never has to derive it from the secret.
    pub fn cosigner_pubkey_hex(&self) -> String {
        self.cosigner_kp.public_key().to_string()
    }

    /// Rebuild the tx graph from the (public) tree chunks, generate the secret nonce tree, and
    /// return the cosigner pubkey + per-node public nonce points to submit. Holds the secret nonces
    /// + graph for the matching `sign`. `tree_tx_chunks` = `(txid_or_empty, psbt_b64, [(vout, child_txid)])`.
    pub fn gen_nonces(
        &mut self,
        tree_tx_chunks: &[(String, String, Vec<(u32, String)>)],
        commitment_psbt_b64: &str,
    ) -> Result<(String, Vec<(String, String)>), String> {
        let commitment_psbt = decode_psbt_b64(commitment_psbt_b64)?;
        let mut chunks = Vec::with_capacity(tree_tx_chunks.len());
        for (txid_str, psbt_b64, children_wire) in tree_tx_chunks {
            let tx = decode_psbt_b64(psbt_b64)?;
            let txid = if txid_str.is_empty() {
                None
            } else {
                Some(txid_str.parse().map_err(|e| format!("bad chunk txid: {e}"))?)
            };
            let children = children_wire
                .iter()
                .map(|(vout, ctxid)| {
                    Ok::<_, String>((
                        *vout,
                        ctxid.parse().map_err(|e| format!("bad child txid: {e}"))?,
                    ))
                })
                .collect::<Result<HashMap<_, _>, String>>()?;
            chunks.push(TxGraphChunk { txid, tx, children });
        }
        let tx_graph = TxGraph::new(chunks).map_err(|e| format!("TxGraph::new: {e}"))?;

        let cosigner_pk = self.cosigner_kp.public_key();
        let nonce_kps = {
            let mut rng = rand::thread_rng();
            generate_nonce_tree(&mut rng, &tx_graph, cosigner_pk, &commitment_psbt)
                .map_err(|e| format!("generate_nonce_tree: {e}"))?
        };
        let nonce_map: Vec<(String, String)> =
            nonce_kps.to_nonce_pks().encode().into_iter().collect();

        self.nonce_kps = Some(nonce_kps);
        self.tx_graph = Some(tx_graph);
        self.commitment_psbt = Some(commitment_psbt);
        Ok((cosigner_pk.to_string(), nonce_map))
    }

    /// MuSig2-sign every tree tx with the in-guest cosigner key + held nonces. `pending_nonces` =
    /// `(tree_txid, [(cosigner_pk_hex, nonce_pk_hex)])` for every node. Returns the cosigner pubkey
    /// + per-node partial signatures, and consumes the held session.
    pub fn sign(
        &mut self,
        pending_nonces: &[(String, Vec<(String, String)>)],
        batch_expiry: u32,
        forfeit_pk_hex: &str,
    ) -> Result<(String, Vec<(String, String)>), String> {
        let tx_graph = self
            .tx_graph
            .as_ref()
            .ok_or("no tx_graph (call gen_nonces first)")?;
        let commitment_psbt = self.commitment_psbt.as_ref().ok_or("no commitment_psbt")?;
        let nonce_kps = self.nonce_kps.as_mut().ok_or("no nonce_kps")?;
        let batch_expiry = Sequence::from_consensus(batch_expiry);
        let forfeit_pk = bitcoin::XOnlyPublicKey::from_str(forfeit_pk_hex)
            .map_err(|e| format!("bad forfeit_pk: {e}"))?;

        let mut nonces_by_txid: HashMap<Txid, HashMap<String, String>> = HashMap::new();
        for (txid_str, nonces) in pending_nonces {
            let txid: Txid = txid_str.parse().map_err(|e| format!("bad txid: {e}"))?;
            nonces_by_txid.insert(txid, nonces.iter().cloned().collect());
        }

        let mut combined = PartialSigTree::default();
        for (tree_txid, _) in tx_graph.as_map() {
            let raw = nonces_by_txid
                .get(&tree_txid)
                .ok_or_else(|| format!("missing nonces for {tree_txid}"))?;
            let nonce_pks = ark_core::server::TreeTxNoncePks::decode(raw.clone())
                .map_err(|e| format!("decode TreeTxNoncePks: {e}"))?;
            let agg = aggregate_nonces(nonce_pks);
            let partial = sign_batch_tree_tx(
                tree_txid,
                batch_expiry,
                forfeit_pk,
                &self.cosigner_kp,
                agg,
                tx_graph,
                commitment_psbt,
                nonce_kps,
            )
            .map_err(|e| format!("sign_batch_tree_tx {tree_txid}: {e}"))?;
            combined.0.extend(partial.0);
        }
        let sig_map: Vec<(String, String)> = combined.encode().into_iter().collect();
        let cosigner_pk_hex = self.cosigner_kp.public_key().to_string();
        self.tx_graph = None;
        self.commitment_psbt = None;
        self.nonce_kps = None;
        Ok((cosigner_pk_hex, sig_map))
    }
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

impl SettleSession {
    /// Create a new settle session for boarding UTXOs.
    ///
    /// Returns `(session, sighashes)` where `sighashes` are the taproot
    /// script-path sighashes that need FROST signing for the intent proof.
    pub fn new_boarding(
        owner_pk_hex: &str,
        asp_pk_hex: &str,
        forfeit_pk_hex: &str,
        boarding_address: &str,
        boarding_utxo_txid: &str,
        boarding_utxo_vout: u32,
        boarding_utxo_amount_sat: u64,
        exit_delay: u32,
        network: &str,
        cosigner_pk_hex: &str,
    ) -> Result<(Self, Vec<[u8; 32]>), String> {
        let secp = Secp256k1::new();
        let network = parse_network(network)?;

        let owner_pk = parse_xonly(owner_pk_hex)?;
        let asp_pk = parse_xonly(asp_pk_hex)?;
        let forfeit_pk = parse_xonly(forfeit_pk_hex)?;

        let exit_seq = ark_core::server::parse_sequence_number(exit_delay as i64)
            .map_err(|e| format!("invalid exit_delay: {e}"))?;

        let boarding_output =
            BoardingOutput::new(&secp, asp_pk, owner_pk, exit_seq, network)
                .map_err(|e| format!("BoardingOutput::new: {e}"))?;

        // Verify the address matches what the caller expects.
        let derived_addr = boarding_output.address().to_string();
        if derived_addr != boarding_address {
            return Err(format!(
                "derived boarding address {derived_addr} != expected {boarding_address}"
            ));
        }

        let outpoint = OutPoint {
            txid: boarding_utxo_txid
                .parse()
                .map_err(|e| format!("invalid txid: {e}"))?,
            vout: boarding_utxo_vout,
        };

        let amount = Amount::from_sat(boarding_utxo_amount_sat);

        let onchain_input = OnChainInput::new(boarding_output.clone(), amount, outpoint);

        // Plan A Phase 2: the MuSig2 cosigner SECRET lives in the cosigner guest. Here we only need
        // its PUBLIC key, supplied by the caller (fetched from the guest), to declare the cosigner
        // in the intent. The actual tree-signing is delegated out during `drive`.
        let cosigner_pk = bitcoin::secp256k1::PublicKey::from_str(cosigner_pk_hex)
            .map_err(|e| format!("invalid cosigner pubkey: {e}"))?;

        // Build the intent message.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("time error: {e}"))?
            .as_secs();
        let expire_at = now + 120; // 2 minutes

        let intent_message = IntentMessage::Register {
            onchain_output_indexes: vec![],
            valid_at: now,
            expire_at,
            own_cosigner_pks: vec![cosigner_pk],
        };

        // The input as ark-client 0.9.1 builds a boarding input (`prepare_intent`), with the
        // boarding exit delay as its sequence, and one output: the boarded VTXO.
        let intent_inputs = vec![intent::Input::new(
            outpoint,
            boarding_output.exit_delay(),
            None,
            TxOut {
                value: amount,
                script_pubkey: boarding_output.script_pubkey(),
            },
            boarding_output.tapscripts(),
            boarding_output.forfeit_spend_info(),
            true,  // is_onchain
            false, // is_swept
            Vec::new(),
        )];
        let intent_outputs = vec![intent::Output::Offchain(TxOut {
            value: amount,
            script_pubkey: boarding_output
                .to_ark_address(network, asp_pk)
                .to_p2tr_script_pubkey(),
        })];

        // The sighashes are whatever `make_intent` asks to have signed: see `sighashes`.
        let collect = Collect::default();
        intent::make_intent(
            collect.any(),
            collect.one(owner_pk),
            intent_inputs.clone(),
            intent_outputs.clone(),
            intent_message.clone(),
        )
        .map_err(|e| format!("make_intent: {e}"))?;
        let sighashes = collect.into_messages();

        let session = SettleSession {
            phase: Phase::AwaitingIntentSignatures,
            owner_pk,
            asp_pk,
            forfeit_pk,
            network,
            exit_delay: exit_seq,
            onchain_input,
            intent_inputs,
            intent_outputs,
            intent_message,
            intent_sighashes: sighashes.clone(),
            intent: None,
            cosigner_pk,
            batch_id: None,
            batch_expiry: None,
            tx_graph_chunks: Vec::new(),
            tx_graph: None,
            commitment_psbt: None,
            pending_nonces: HashMap::new(),
            commitment_sighashes: Vec::new(),
        };

        Ok((session, sighashes))
    }
}

// ---------------------------------------------------------------------------
// Event handlers: each takes one relayed event and returns what to send, without any I/O.
// ---------------------------------------------------------------------------

impl SettleSession {
    /// TreeSigningStarted (Plan A Phase 2): build + store the tx graph from collected chunks, and
    /// return the (public) tree data the caller must dispatch to the guest's `BoardingGenNonces`.
    /// No secret is touched here — nonce generation happens in the guest.
    pub fn on_tree_signing_started(
        &mut self,
        event: proto::TreeSigningStartedEvent,
    ) -> Result<SettleAction, String> {
        // Use batch_id from BatchStarted if available, else the event id (public ASPs may skip it).
        if self.batch_id.is_none() {
            self.batch_id = Some(event.id.clone());
        }
        let commitment_psbt = decode_psbt_b64(&event.unsigned_commitment_tx)?;
        if self.tx_graph_chunks.is_empty() {
            return Err("no tree tx chunks collected yet".into());
        }
        let chunks: Vec<TxGraphChunk> = self.tx_graph_chunks.drain(..).collect();

        // Serialize the (public) chunks for the guest, then build our own graph for tracking.
        let tree_tx_chunks: Vec<(String, String, Vec<(u32, String)>)> = chunks
            .iter()
            .map(|c| {
                let txid = c.txid.map(|t| t.to_string()).unwrap_or_default();
                let psbt_b64 = encode_psbt_b64(&c.tx);
                let children = c.children.iter().map(|(v, t)| (*v, t.to_string())).collect();
                (txid, psbt_b64, children)
            })
            .collect();
        let commitment_psbt_b64 = encode_psbt_b64(&commitment_psbt);

        let tx_graph = TxGraph::new(chunks).map_err(|e| format!("TxGraph::new: {e}"))?;
        self.tx_graph = Some(tx_graph);
        self.commitment_psbt = Some(commitment_psbt);

        Ok(SettleAction::NeedTreeNonces {
            tree_tx_chunks,
            commitment_psbt_b64,
        })
    }

    /// TreeNonces (Plan A Phase 2): accumulate; once every node has nonces, return them (+ batch
    /// expiry + forfeit key) for the caller to dispatch tree-signing to the guest. `None` while
    /// still waiting. No secret is touched here — signing happens in the guest.
    pub fn on_tree_nonces(
        &mut self,
        event: proto::TreeNoncesEvent,
    ) -> Result<Option<SettleAction>, String> {
        let txid: Txid = event
            .txid
            .parse()
            .map_err(|e| format!("invalid txid {}: {e}", event.txid))?;
        self.pending_nonces.insert(txid, event.nonces);

        let tx_graph = self.tx_graph.as_ref().ok_or("no tx_graph built")?;
        let expected = tx_graph.nb_of_nodes();
        eprintln!(
            "  accumulated nonces for txid={txid}, {}/{} collected",
            self.pending_nonces.len(),
            expected
        );
        if self.pending_nonces.len() < expected {
            return Ok(None);
        }

        let batch_expiry = self.batch_expiry.ok_or("no batch_expiry")?.to_consensus_u32();
        let forfeit_pk_hex = self.forfeit_pk.to_string();
        let pending_nonces: Vec<(String, Vec<(String, String)>)> = self
            .pending_nonces
            .iter()
            .map(|(txid, nonces)| {
                (
                    txid.to_string(),
                    nonces.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                )
            })
            .collect();

        Ok(Some(SettleAction::NeedTreeSign {
            pending_nonces,
            batch_expiry,
            forfeit_pk_hex,
        }))
    }

    pub fn handle_tree_tx(&mut self, event: proto::TreeTxEvent) -> Result<(), String> {
        let psbt = decode_psbt_b64(&event.tx)?;

        let children: HashMap<u32, Txid> = event
            .children
            .into_iter()
            .map(|(vout, txid_str)| {
                let txid: Txid = txid_str
                    .parse()
                    .map_err(|e| format!("invalid child txid: {e}"))?;
                Ok((vout, txid))
            })
            .collect::<Result<_, String>>()?;

        let txid = if event.txid.is_empty() {
            None
        } else {
            Some(
                event
                    .txid
                    .parse()
                    .map_err(|e| format!("invalid txid: {e}"))?,
            )
        };

        self.tx_graph_chunks.push(TxGraphChunk {
            txid,
            tx: psbt,
            children,
        });

        Ok(())
    }

    /// BatchFinalization: the commitment's sighashes for our boarding input, as ark-core's
    /// `sign_commitment_psbt` asks for them.
    pub fn handle_batch_finalization(
        &mut self,
        event: proto::BatchFinalizationEvent,
    ) -> Result<Vec<[u8; 32]>, String> {
        let commitment_psbt = decode_psbt_b64(&event.commitment_tx)?;

        // `sign_commitment_psbt` verifies each signature it is handed, so `Collect` stops it at
        // the first message, which is the only one: this session boards one output. Run on a copy,
        // like every first pass (see `sighashes`).
        let collect = Collect::default();
        let collected = ark_core::batch::sign_commitment_psbt(
            collect.checked(),
            &mut commitment_psbt.clone(),
            std::slice::from_ref(&self.onchain_input),
        );
        match collected {
            Ok(()) => return Err("boarding input not found in commitment PSBT".into()),
            Err(e) if collect.len() == 0 => return Err(format!("sign_commitment_psbt: {e}")),
            Err(_) => {}
        }

        self.commitment_psbt = Some(commitment_psbt);
        self.commitment_sighashes = collect.into_messages();
        self.phase = Phase::AwaitingCommitmentSignatures;

        Ok(self.commitment_sighashes.clone())
    }

    // ----- guest-driveable step API (Plan A: the GUEST drives the boarding settle itself,
    // mirroring DelegateSettleSession; the host relays the two FROST rounds) -----

    /// Insert the FROST signatures over the intent-proof sighashes (from `new_boarding`), through
    /// the same `make_intent` that named them, so the proof is ready to register.
    pub fn insert_intent_signatures(&mut self, signatures: Vec<[u8; 64]>) -> Result<(), String> {
        if !matches!(self.phase, Phase::AwaitingIntentSignatures) {
            return Err("insert_intent_signatures called in wrong phase".into());
        }
        let replay = Replay::new(&self.intent_sighashes, &signatures, self.owner_pk)?;
        let intent = intent::make_intent(
            replay.any(),
            replay.one(),
            self.intent_inputs.clone(),
            self.intent_outputs.clone(),
            self.intent_message.clone(),
        )
        .map_err(|e| format!("make_intent: {e}"))?;
        replay.finish()?;
        self.intent = Some(intent);
        self.phase = Phase::Driving;
        Ok(())
    }

    /// The registration payload `(proof_b64, message_json, topics)` for `RegisterIntent` +
    /// `GetEventStream` — topics are the boarding outpoint + the cosigner pubkey hex.
    pub fn register_payload(&self) -> Result<(String, String, Vec<String>), String> {
        let intent = self.intent.as_ref().ok_or("the intent is not signed yet")?;
        let message_json = intent
            .serialize_message()
            .map_err(|e| format!("encode intent message: {e}"))?;
        let outpoint_topic = self.onchain_input.outpoint().to_string();
        let cosigner_topic: String = self
            .cosigner_pk
            .serialize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Ok((intent.serialize_proof(), message_json, vec![outpoint_topic, cosigner_topic]))
    }

    /// BatchStarted: record batch id + expiry. (The guest then sends ConfirmRegistration itself.)
    pub fn on_batch_started(&mut self, event: proto::BatchStartedEvent) -> Result<(), String> {
        self.batch_id = Some(event.id.clone());
        if event.batch_expiry > 0 {
            self.batch_expiry = Some(
                ark_core::server::parse_sequence_number(event.batch_expiry)
                    .map_err(|e| format!("parse batch_expiry: {e}"))?,
            );
        }
        Ok(())
    }

    /// Insert the FROST signatures over the commitment sighashes (from `handle_batch_finalization`)
    /// through `sign_commitment_psbt`, which also checks each one against the boarding key, and
    /// return the signed commitment PSBT b64 to submit (`SubmitSignedForfeitTxs`, no forfeits).
    pub fn insert_commitment_signatures(
        &mut self,
        signatures: Vec<[u8; 64]>,
    ) -> Result<String, String> {
        if !matches!(self.phase, Phase::AwaitingCommitmentSignatures) {
            return Err("insert_commitment_signatures called in wrong phase".into());
        }
        let commitment_psbt = self
            .commitment_psbt
            .as_mut()
            .ok_or("missing commitment PSBT")?;
        let replay = Replay::new(&self.commitment_sighashes, &signatures, self.owner_pk)?;
        ark_core::batch::sign_commitment_psbt(
            replay.checked(),
            commitment_psbt,
            std::slice::from_ref(&self.onchain_input),
        )
        .map_err(|e| format!("sign_commitment_psbt: {e}"))?;
        replay.finish()?;
        let signed_commitment_b64 = encode_psbt_b64(commitment_psbt);
        self.phase = Phase::Driving;
        Ok(signed_commitment_b64)
    }

    /// The current batch id (for the guest's `SubmitTreeNonces`/`SubmitTreeSignatures`).
    pub fn batch_id(&self) -> String {
        self.batch_id.clone().unwrap_or_default()
    }

    /// After submitting the signed commitment, return the new VTXO WITHOUT waiting for a
    /// BatchFinalized event — the commitment txid is the commitment-PSBT txid (witness-independent)
    /// and the VTXO is the first tree leaf. Lets the guest finalize boarding without resuming the
    /// (now mid-batch) event stream across the commitment-FROST pause.
    pub fn finalize_optimistic(&self) -> Result<(String, Option<(String, u32)>), String> {
        let commitment_psbt = self.commitment_psbt.as_ref().ok_or("no commitment PSBT")?;
        let commitment_txid = commitment_psbt.unsigned_tx.compute_txid().to_string();
        let vtxo = self.tx_graph.as_ref().map(|g| {
            let leaf = first_tree_leaf(g);
            (leaf.unsigned_tx.compute_txid().to_string(), 0u32)
        });
        Ok((commitment_txid, vtxo))
    }

    /// BatchFinalized: mark done and return `(commitment_txid, vtxo_outpoint)`.
    pub fn on_batch_finalized(
        &mut self,
        event: proto::BatchFinalizedEvent,
    ) -> (String, Option<(String, u32)>) {
        self.phase = Phase::Done;
        let vtxo_outpoint = self.tx_graph.as_ref().map(|g| {
            let leaf = first_tree_leaf(g);
            (leaf.unsigned_tx.compute_txid().to_string(), 0u32)
        });
        (event.commitment_txid, vtxo_outpoint)
    }
}

// ===========================================================================
// DelegateSettleSession — settle existing VTXOs via the delegate pattern.
//
// The delegate pattern cleanly separates FROST (owner key) from MuSig2
// (tree signing):
//   Phase 1: generate_delegate() → build intent + forfeit PSBTs, return sighashes
//   Phase 2: sign_with_frost() → insert FROST signatures
//   Phase 3: register_payload() + the on_* step methods → the caller drives the round
// ===========================================================================

/// Input VTXO descriptor for delegate settle. The server passes these from
/// its VTXO store; the `DelegateSettleSession` reconstructs the `ark_core`
/// types needed for `prepare_delegate_psbts`.
pub struct DelegateVtxoInput {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    /// Whether this VTXO was already swept by the ASP.
    pub is_swept: bool,
    /// This VTXO's unilateral-exit delay (consensus sequence value). Per-input
    /// because a wallet naturally holds a mix: a boarded VTXO keeps the
    /// boarding delay while received/refreshed ones use the unilateral delay.
    pub exit_delay: u32,
}

/// Output descriptor for delegate settle.
pub struct DelegateOutput {
    /// Where it goes. An Ark address (bech32m) stays in Ark, as a fresh VTXO. A bitcoin address
    /// leaves Ark: a collaborative exit, paid on chain by the batch's commitment transaction.
    pub address: String,
    pub amount_sats: u64,
}

/// One destination as an intent carries it.
///
/// An Ark address stays off-chain. A bitcoin address is an on-chain output — a collaborative
/// exit — which `prepare_delegate_psbts_at` then lists in the intent's `onchain_output_indexes`,
/// so the server pays it in the commitment transaction.
fn intent_output(
    address: &str,
    amount_sats: u64,
    network: bitcoin::Network,
) -> Result<ark_core::intent::Output, String> {
    let value = Amount::from_sat(amount_sats);
    if let Ok(ark_addr) = address.parse::<ark_core::ArkAddress>() {
        return Ok(ark_core::intent::Output::Offchain(TxOut {
            value,
            script_pubkey: ark_addr.to_p2tr_script_pubkey(),
        }));
    }
    let onchain: bitcoin::Address<bitcoin::address::NetworkUnchecked> = address
        .parse()
        .map_err(|e| format!("{address:?} is neither an Ark nor a bitcoin address: {e}"))?;
    let onchain = onchain
        .require_network(network)
        .map_err(|e| format!("{address:?} is for another network: {e}"))?;
    Ok(ark_core::intent::Output::Onchain(TxOut {
        value,
        script_pubkey: onchain.script_pubkey(),
    }))
}

/// Phase of the delegate session state machine.
enum DelegatePhase {
    AwaitingSignatures,
    ReadyToSettle,
    Done,
}

/// A session for settling existing VTXOs using the delegate pattern.
///
/// Unlike `SettleSession` (boarding), this requires only a single round of
/// FROST signatures upfront.  The server then drives the batch autonomously
/// using its DKG private key for MuSig2 tree signing.
pub struct DelegateSettleSession {
    phase: DelegatePhase,

    // -- identity --
    owner_pk: XOnlyPublicKey,
    #[allow(dead_code)]
    asp_pk: XOnlyPublicKey,
    /// ASP's forfeit x-only public key (used for tree signing sweep scripts).
    forfeit_pk: XOnlyPublicKey,
    #[allow(dead_code)]
    network: Network,
    #[allow(dead_code)]
    exit_delay: Sequence,

    // -- delegate data --
    delegate: ark_core::batch::Delegate,
    delegate_cosigner_kp: Keypair,
    /// The ASP's id for this delegate's registration, once it is registered: a run that stops
    /// mid-round follows it rather than registering the same intent twice.
    pub intent_id: Option<String>,

    // -- what ark-core asked to have signed: the intent's inputs, then each forfeit --
    sighashes: Vec<[u8; 32]>,

    // -- batch state --
    batch_id: Option<String>,
    batch_expiry: Option<Sequence>,
    vtxo_graph_chunks: Vec<TxGraphChunk>,
    connector_graph_chunks: Vec<TxGraphChunk>,
    vtxo_graph: Option<TxGraph>,
    nonce_kps: Option<NonceKps>,
    commitment_psbt: Option<Psbt>,
    /// Accumulated raw nonces per tree txid (from TreeNonces events).
    pending_nonces: HashMap<Txid, HashMap<String, String>>,
}

// ---------------------------------------------------------------------------
// Persistence — only valid while in `ReadyToSettle` phase.
//
// The live batch-state fields (`batch_id`, `nonce_kps`, `vtxo_graph_chunks`,
// `connector_graph_chunks`, `commitment_psbt`, `pending_nonces`) are all
// `None`/empty at `ReadyToSettle` time, so we don't persist them — they'd
// either be wrong or absent on rehydration. `nonce_kps` specifically is
// MuSig2 secret-nonce material that MUST NEVER be persisted: rehydrating
// a partially-settled session would risk nonce re-use.
//
// `delegate_cosigner_kp` is the delegate's own MuSig2 tree-signing key, drawn
// when the delegate is built. It IS persisted, in the record: the round the
// delegate joins runs later, with nobody connected, and signs with it then.
// It lives as long as the delegate and no longer. It used to be the server's
// DKG secret, one key for the wallet's whole life and every round.
// ---------------------------------------------------------------------------

/// Part of the sealed format, so it stays: records are written with none, and what an older record
/// carries is ignored — nothing signs a delegate once it is persisted.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedSighashEntry {
    pub psbt_type: usize,
    pub input_idx: usize,
    /// Hex of `TapLeafHash::to_byte_array()` (32 bytes).
    pub leaf_hash_hex: String,
}

/// Serializable snapshot of a `DelegateSettleSession` in `ReadyToSettle`
/// phase, its tree-signing key included — see the note above.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedDelegate {
    pub owner_pk_hex: String,
    pub asp_pk_hex: String,
    pub forfeit_pk_hex: String,
    /// Network string as understood by `ark::client::parse_network` —
    /// "bitcoin", "testnet", "signet", "regtest", "mutinynet".
    pub network: String,
    /// `Sequence` consensus value for unilateral exit.
    pub exit_delay: u32,
    /// Base64-encoded PSBT.
    pub intent_proof_psbt_b64: String,
    /// JSON-encoded `IntentMessage`.
    pub intent_message_json: String,
    /// Base64-encoded forfeit PSBTs.
    pub forfeit_psbts_b64: Vec<String>,
    /// Hex of the cosigner public key (33-byte compressed).
    pub delegate_cosigner_pk_hex: String,
    /// Hex of this delegate's tree-signing secret. Empty in a record persisted before a delegate
    /// carried its own; `from_persisted` refuses that until its caller supplies the key.
    #[serde(default)]
    pub delegate_cosigner_secret_hex: String,
    /// See [`DelegateSettleSession::intent_id`].
    #[serde(default)]
    pub intent_id: Option<String>,
    pub sighash_meta: Vec<PersistedSighashEntry>,
}

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("base64 decode: {e}"))
}

// ---------------------------------------------------------------------------
// DelegateSettleSession – construction
// ---------------------------------------------------------------------------

impl DelegateSettleSession {
    /// Generate a delegate for existing VTXOs.
    ///
    /// Reconstructs `ark_core::Vtxo` objects from the provided metadata,
    /// calls `prepare_delegate_psbts`, and returns sighashes that need
    /// FROST signing (intent proof + all forfeit PSBTs). The round's tree-signing key is drawn
    /// here, for this delegate alone.
    pub fn generate_delegate(
        owner_pk_hex: &str,
        asp_pk_hex: &str,
        forfeit_pk_hex: &str,
        vtxo_inputs: &[DelegateVtxoInput],
        outputs: &[DelegateOutput],
        forfeit_address: &str,
        dust_sats: u64,
        network_str: &str,
        // When set, the renewal time (Unix secs) the delegate becomes valid;
        // arkd rejects settling before it, and the intent never expires
        // (expire_at = 0). `None` keeps the legacy 2-minute window.
        intent_valid_at: Option<u64>,
    ) -> Result<(Self, Vec<[u8; 32]>), String> {
        let secp = Secp256k1::new();
        let network = parse_network(network_str)?;

        let owner_pk = parse_xonly(owner_pk_hex)?;
        let asp_pk = parse_xonly(asp_pk_hex)?;
        let forfeit_pk = parse_xonly(forfeit_pk_hex)?;

        if vtxo_inputs.is_empty() {
            return Err("no VTXO inputs".to_string());
        }

        let delegate_cosigner_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let delegate_cosigner_pk = delegate_cosigner_kp.public_key();

        // Reconstruct default VTXOs for spend info — one per DISTINCT exit
        // delay, since each input's script embeds its own delay.
        let mut vtxo_by_delay: HashMap<u32, (Sequence, ark_core::Vtxo)> = HashMap::new();
        for vi in vtxo_inputs {
            if let std::collections::hash_map::Entry::Vacant(slot) =
                vtxo_by_delay.entry(vi.exit_delay)
            {
                let exit_seq = ark_core::server::parse_sequence_number(vi.exit_delay as i64)
                    .map_err(|e| format!("invalid exit_delay: {e}"))?;
                let vtxo =
                    ark_core::Vtxo::new_default(&secp, asp_pk, owner_pk, exit_seq, network)
                        .map_err(|e| format!("Vtxo::new_default: {e}"))?;
                slot.insert((exit_seq, vtxo));
            }
        }

        // Build intent::Input for each VTXO with its own delay's spend info.
        let intent_inputs: Vec<ark_core::intent::Input> = vtxo_inputs
            .iter()
            .map(|vi| {
                let outpoint = OutPoint {
                    txid: vi.txid.parse().map_err(|e| format!("invalid txid: {e}"))?,
                    vout: vi.vout,
                };
                let (exit_seq, vtxo) = &vtxo_by_delay[&vi.exit_delay];
                let forfeit_spend_info = vtxo
                    .forfeit_spend_info()
                    .map_err(|e| format!("forfeit_spend_info: {e}"))?;
                Ok(ark_core::intent::Input::new(
                    outpoint,
                    *exit_seq,
                    None,
                    TxOut {
                        value: Amount::from_sat(vi.amount_sats),
                        script_pubkey: vtxo.script_pubkey(),
                    },
                    vtxo.tapscripts(),
                    forfeit_spend_info,
                    false, // is_onchain = false (existing VTXOs)
                    vi.is_swept,
                    Vec::new(), // assets — none (ark-core 0.9)
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;

        // Build intent::Output for each destination.
        let intent_outputs: Vec<ark_core::intent::Output> = outputs
            .iter()
            .map(|o| intent_output(&o.address, o.amount_sats, network))
            .collect::<Result<Vec<_>, String>>()?;

        // Parse forfeit address.
        let forfeit_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
            forfeit_address.parse()
                .map_err(|e| format!("invalid forfeit address: {e}"))?;
        let forfeit_addr = forfeit_addr.require_network(network)
            .map_err(|e| format!("forfeit address network mismatch: {e}"))?;

        // Prepare delegate PSBTs (intent proof + forfeit PSBTs).
        let delegate = ark_core::batch::prepare_delegate_psbts_at(
            intent_inputs,
            intent_outputs,
            delegate_cosigner_pk,
            &forfeit_addr,
            Amount::from_sat(dust_sats),
            intent_valid_at,
        ).map_err(|e| format!("prepare_delegate_psbts_at: {e}"))?;

        // The sighashes are whatever ark-core's `sign_delegate_psbts` asks to have signed, run
        // over copies: see `sighashes`.
        let collect = Collect::default();
        ark_core::batch::sign_delegate_psbts(
            collect.any(),
            &mut delegate.intent.proof.clone(),
            &mut delegate.forfeit_psbts.clone(),
        )
        .map_err(|e| format!("sign_delegate_psbts: {e}"))?;
        let sighashes = collect.into_messages();

        let session = DelegateSettleSession {
            phase: DelegatePhase::AwaitingSignatures,
            owner_pk,
            asp_pk,
            forfeit_pk,
            network,
            // Unused downstream (the PSBTs embed per-input spend info); kept
            // for the persisted-snapshot shape. First input's delay.
            exit_delay: vtxo_by_delay[&vtxo_inputs[0].exit_delay].0,
            delegate,
            delegate_cosigner_kp,
            intent_id: None,
            sighashes: sighashes.clone(),
            batch_id: None,
            batch_expiry: None,
            vtxo_graph_chunks: Vec::new(),
            connector_graph_chunks: Vec::new(),
            vtxo_graph: None,
            nonce_kps: None,
            commitment_psbt: None,
            pending_nonces: HashMap::new(),
        };

        Ok((session, sighashes))
    }
}

// ---------------------------------------------------------------------------
// DelegateSettleSession – FROST signature insertion
// ---------------------------------------------------------------------------

impl DelegateSettleSession {
    /// The batch this session joined, or `None` before a matching `BatchStarted`.
    /// Callers driving the event stream gate batch-scoped events on this — see
    /// [`foreign_batch_id`].
    pub fn joined_batch_id(&self) -> Option<&str> {
        self.batch_id.as_deref()
    }

    /// Insert FROST signatures into the intent proof and forfeit PSBTs, through the same
    /// `sign_delegate_psbts` that named the sighashes; it sets the forfeits' `ALL|ANYONECANPAY`.
    ///
    /// `signatures` must match the sighashes returned by `generate_delegate`.
    pub fn sign_with_frost(
        &mut self,
        signatures: Vec<[u8; 64]>,
    ) -> Result<(), String> {
        if !matches!(self.phase, DelegatePhase::AwaitingSignatures) {
            return Err("sign_with_frost called in wrong phase".into());
        }
        let replay = Replay::new(&self.sighashes, &signatures, self.owner_pk)?;
        ark_core::batch::sign_delegate_psbts(
            replay.any(),
            &mut self.delegate.intent.proof,
            &mut self.delegate.forfeit_psbts,
        )
        .map_err(|e| format!("sign_delegate_psbts: {e}"))?;
        replay.finish()?;

        self.phase = DelegatePhase::ReadyToSettle;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DelegateSettleSession – persistence (ReadyToSettle phase only)
// ---------------------------------------------------------------------------

impl DelegateSettleSession {
    /// Serialize a session in `ReadyToSettle` phase for sled storage.
    ///
    /// Refuses for any other phase: persisting `AwaitingSignatures` would
    /// drop FROST sigs the client paid to compute, and persisting a round in
    /// progress would expose MuSig2 secret nonces in `nonce_kps`. Called after
    /// `sign_with_frost` has moved the session to `ReadyToSettle`.
    pub fn to_persisted(&self) -> Result<PersistedDelegate, String> {
        if !matches!(self.phase, DelegatePhase::ReadyToSettle) {
            return Err(format!(
                "to_persisted requires ReadyToSettle phase, got {:?}",
                std::mem::discriminant(&self.phase)
            ));
        }

        let intent_proof_b64 = self.delegate.intent.serialize_proof();
        let intent_message_json = self
            .delegate
            .intent
            .serialize_message()
            .map_err(|e| format!("serialize intent message: {e}"))?;

        let forfeit_psbts_b64 = self
            .delegate
            .forfeit_psbts
            .iter()
            .map(|p| b64_encode(&p.serialize()))
            .collect();

        let delegate_cosigner_pk_hex = hex::encode(
            self.delegate
                .delegate_cosigner_pk
                .serialize(),
        );

        Ok(PersistedDelegate {
            owner_pk_hex: self.owner_pk.to_string(),
            asp_pk_hex: self.asp_pk.to_string(),
            forfeit_pk_hex: self.forfeit_pk.to_string(),
            network: self.network.to_string(),
            exit_delay: self.exit_delay.to_consensus_u32(),
            intent_proof_psbt_b64: intent_proof_b64,
            intent_message_json,
            forfeit_psbts_b64,
            delegate_cosigner_pk_hex,
            delegate_cosigner_secret_hex: hex::encode(self.delegate_cosigner_kp.secret_bytes()),
            intent_id: self.intent_id.clone(),
            sighash_meta: Vec::new(),
        })
    }

    /// Reconstruct a `ReadyToSettle` session from a `PersistedDelegate`,
    /// with the tree-signing key it carries.
    pub fn from_persisted(p: &PersistedDelegate) -> Result<Self, String> {
        let owner_pk = XOnlyPublicKey::from_str(&p.owner_pk_hex)
            .map_err(|e| format!("parse owner_pk: {e}"))?;
        let asp_pk = XOnlyPublicKey::from_str(&p.asp_pk_hex)
            .map_err(|e| format!("parse asp_pk: {e}"))?;
        let forfeit_pk = XOnlyPublicKey::from_str(&p.forfeit_pk_hex)
            .map_err(|e| format!("parse forfeit_pk: {e}"))?;
        let network =
            Network::from_str(&p.network).map_err(|e| format!("parse network: {e}"))?;
        let exit_delay = Sequence::from_consensus(p.exit_delay);

        let intent_proof_bytes = b64_decode(&p.intent_proof_psbt_b64)?;
        let intent_proof = Psbt::deserialize(&intent_proof_bytes)
            .map_err(|e| format!("deserialize intent proof PSBT: {e}"))?;
        let intent_message: IntentMessage = serde_json::from_str(&p.intent_message_json)
            .map_err(|e| format!("parse intent message JSON: {e}"))?;
        let intent = ark_core::intent::Intent::new(intent_proof, intent_message);

        let forfeit_psbts: Result<Vec<Psbt>, String> = p
            .forfeit_psbts_b64
            .iter()
            .map(|s| {
                let bytes = b64_decode(s)?;
                Psbt::deserialize(&bytes)
                    .map_err(|e| format!("deserialize forfeit PSBT: {e}"))
            })
            .collect();
        let forfeit_psbts = forfeit_psbts?;

        let delegate_cosigner_pk_bytes = hex::decode(&p.delegate_cosigner_pk_hex)
            .map_err(|e| format!("decode cosigner pk hex: {e}"))?;
        let delegate_cosigner_pk =
            bitcoin::secp256k1::PublicKey::from_slice(&delegate_cosigner_pk_bytes)
                .map_err(|e| format!("parse cosigner pk: {e}"))?;

        if p.delegate_cosigner_secret_hex.is_empty() {
            return Err("this delegate was persisted without its tree-signing key".into());
        }
        let cosigner_secret_bytes = hex_decode_32(&p.delegate_cosigner_secret_hex)?;
        let secp = Secp256k1::new();
        let cosigner_secret = bitcoin::secp256k1::SecretKey::from_slice(&cosigner_secret_bytes)
            .map_err(|e| format!("parse cosigner secret: {e}"))?;
        let delegate_cosigner_kp = Keypair::from_secret_key(&secp, &cosigner_secret);
        // The key must be the one the intent registered. If they diverge the
        // record is corrupt, or was given a key that is not its own: refuse
        // rather than sign with the wrong one.
        if delegate_cosigner_kp.public_key() != delegate_cosigner_pk {
            return Err(
                "delegate cosigner secret does not match persisted pubkey".into(),
            );
        }

        Ok(Self {
            phase: DelegatePhase::ReadyToSettle,
            owner_pk,
            asp_pk,
            forfeit_pk,
            network,
            exit_delay,
            delegate: ark_core::batch::Delegate {
                intent,
                forfeit_psbts,
                delegate_cosigner_pk,
            },
            delegate_cosigner_kp,
            intent_id: p.intent_id.clone(),
            sighashes: Vec::new(),
            batch_id: None,
            batch_expiry: None,
            vtxo_graph_chunks: Vec::new(),
            connector_graph_chunks: Vec::new(),
            vtxo_graph: None,
            nonce_kps: None,
            commitment_psbt: None,
            pending_nonces: HashMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// DelegateSettleSession – batch driving, transport-free step methods.
//
// Each consumes one decoded batch event, runs the MuSig2 / forfeit math (using
// the secret cosigner key + nonces), mutates session state, and RETURNS the
// unary gRPC payload to submit (if any) — without doing any I/O. The caller
// drives the event loop over these.
// ---------------------------------------------------------------------------
impl DelegateSettleSession {
    /// Pre-loop: the registration payload `(proof_b64, message_json)` and the
    /// event-stream topics (VTXO input outpoints + cosigner pubkey hex).
    pub fn register_payload(&self) -> Result<(String, String, Vec<String>), String> {
        let proof_b64 = encode_psbt_b64(&self.delegate.intent.proof);
        let message_json = self
            .delegate
            .intent
            .serialize_message()
            .map_err(|e| format!("serialize intent message: {e}"))?;

        let mut topics = Vec::new();
        for input in &self.delegate.intent.proof.unsigned_tx.input {
            topics.push(input.previous_output.to_string());
        }
        let cosigner_bytes = self.delegate_cosigner_kp.public_key().serialize();
        let cosigner_topic: String = cosigner_bytes.iter().map(|b| format!("{b:02x}")).collect();
        topics.push(cosigner_topic);

        Ok((proof_b64, message_json, topics))
    }

    /// BatchStarted: record batch id + expiry. The guest then submits
    /// ConfirmRegistration with the intent id from RegisterIntent.
    pub fn on_batch_started(&mut self, event: proto::BatchStartedEvent) -> Result<(), String> {
        self.batch_id = Some(event.id.clone());
        if event.batch_expiry > 0 {
            self.batch_expiry = Some(
                ark_core::server::parse_sequence_number(event.batch_expiry)
                    .map_err(|e| format!("parse batch_expiry: {e}"))?,
            );
        }
        Ok(())
    }

    /// TreeTx: accumulate a tree chunk into the vtxo (0) or connector (1) graph.
    pub fn on_tree_tx(&mut self, event: proto::TreeTxEvent) -> Result<(), String> {
        let psbt = decode_psbt_b64(&event.tx)?;
        let children: HashMap<u32, Txid> = event
            .children
            .into_iter()
            .map(|(vout, txid_str)| {
                let txid: Txid = txid_str
                    .parse()
                    .map_err(|e| format!("invalid child txid: {e}"))?;
                Ok((vout, txid))
            })
            .collect::<Result<_, String>>()?;
        let txid = if event.txid.is_empty() {
            None
        } else {
            Some(
                event
                    .txid
                    .parse()
                    .map_err(|e| format!("invalid txid: {e}"))?,
            )
        };
        let chunk = TxGraphChunk {
            txid,
            tx: psbt,
            children,
        };
        match event.batch_index {
            0 => self.vtxo_graph_chunks.push(chunk),
            1 => self.connector_graph_chunks.push(chunk),
            n => return Err(format!("unsupported TreeTx batch_index: {n}")),
        }
        Ok(())
    }

    /// TreeSigningStarted: build the VTXO graph, generate ephemeral nonces, and
    /// return `(batch_id, cosigner_pk_hex, nonce_map)` to submit.
    pub fn on_tree_signing_started(
        &mut self,
        event: proto::TreeSigningStartedEvent,
    ) -> Result<(String, String, HashMap<String, String>), String> {
        let commitment_psbt = decode_psbt_b64(&event.unsigned_commitment_tx)?;
        if self.vtxo_graph_chunks.is_empty() {
            return Err("no VTXO tree tx chunks collected".into());
        }
        let vtxo_graph = TxGraph::new(self.vtxo_graph_chunks.drain(..).collect())
            .map_err(|e| format!("TxGraph::new: {e}"))?;

        let cosigner_pk = self.delegate_cosigner_kp.public_key();
        let nonce_kps = {
            let mut rng = rand::thread_rng();
            generate_nonce_tree(&mut rng, &vtxo_graph, cosigner_pk, &commitment_psbt)
                .map_err(|e| format!("generate_nonce_tree: {e}"))?
        };
        let nonce_map = nonce_kps.to_nonce_pks().encode();
        let batch_id = self.batch_id.as_ref().ok_or("no batch_id")?.clone();
        let cosigner_pk_hex = cosigner_pk.to_string();

        self.nonce_kps = Some(nonce_kps);
        self.vtxo_graph = Some(vtxo_graph);
        self.commitment_psbt = Some(commitment_psbt);

        Ok((batch_id, cosigner_pk_hex, nonce_map))
    }

    /// TreeNonces: accumulate; once every tree node has nonces, MuSig2-sign all
    /// tree txs and return `(batch_id, cosigner_pk_hex, sig_map)`. Returns `None`
    /// while still waiting for more nonces.
    pub fn on_tree_nonces(
        &mut self,
        event: proto::TreeNoncesEvent,
    ) -> Result<Option<(String, String, HashMap<String, String>)>, String> {
        let txid: Txid = event
            .txid
            .parse()
            .map_err(|e| format!("invalid txid: {e}"))?;
        self.pending_nonces.insert(txid, event.nonces);

        let vtxo_graph = self.vtxo_graph.as_ref().ok_or("no vtxo_graph")?;
        let expected = vtxo_graph.nb_of_nodes();
        if self.pending_nonces.len() < expected {
            return Ok(None);
        }

        let batch_id = self.batch_id.as_ref().ok_or("no batch_id")?.clone();
        let commitment_psbt = self.commitment_psbt.as_ref().ok_or("no commitment_psbt")?;
        let nonce_kps = self.nonce_kps.as_mut().ok_or("no nonce_kps")?;
        let batch_expiry = self.batch_expiry.ok_or("no batch_expiry")?;

        let mut combined_sigs = PartialSigTree::default();
        for (tree_txid, _) in vtxo_graph.as_map() {
            let raw_nonces = self
                .pending_nonces
                .get(&tree_txid)
                .ok_or_else(|| format!("missing nonces for {tree_txid}"))?;
            let tree_tx_nonce_pks = ark_core::server::TreeTxNoncePks::decode(raw_nonces.clone())
                .map_err(|e| format!("decode TreeTxNoncePks: {e}"))?;
            let agg_nonce = aggregate_nonces(tree_tx_nonce_pks);
            let partial_sig = sign_batch_tree_tx(
                tree_txid,
                batch_expiry,
                self.forfeit_pk,
                &self.delegate_cosigner_kp,
                agg_nonce,
                vtxo_graph,
                commitment_psbt,
                nonce_kps,
            )
            .map_err(|e| format!("sign_batch_tree_tx: {e}"))?;
            combined_sigs.0.extend(partial_sig.0);
        }

        let sig_map = combined_sigs.encode();
        let cosigner_pk_hex = self.delegate_cosigner_kp.public_key().to_string();
        self.pending_nonces.clear();
        Ok(Some((batch_id, cosigner_pk_hex, sig_map)))
    }

    /// BatchFinalization: complete the delegated forfeit txs from the connector
    /// graph leaves. Returns the signed forfeit b64s to submit, or `None` when
    /// there are no connectors (nothing to forfeit).
    pub fn on_batch_finalization(
        &mut self,
        _event: proto::BatchFinalizationEvent,
    ) -> Result<Option<Vec<String>>, String> {
        if self.connector_graph_chunks.is_empty() {
            return Ok(None);
        }
        let connectors_graph = TxGraph::new(self.connector_graph_chunks.drain(..).collect())
            .map_err(|e| format!("TxGraph::new (connectors): {e}"))?;
        let connector_leaves = connectors_graph.leaves();
        let completed_forfeits = ark_core::batch::complete_delegate_forfeit_txs(
            &self.delegate.forfeit_psbts,
            &connector_leaves,
        )
        .map_err(|e| format!("complete_delegate_forfeit_txs: {e}"))?;
        let signed_forfeits: Vec<String> =
            completed_forfeits.iter().map(encode_psbt_b64).collect();
        Ok(Some(signed_forfeits))
    }

    /// BatchFinalized: mark done and return `(commitment_txid, vtxo_outpoint)`.
    pub fn on_batch_finalized(
        &mut self,
        event: proto::BatchFinalizedEvent,
    ) -> (String, Option<(String, u32)>) {
        self.phase = DelegatePhase::Done;
        let vtxo_outpoint = self.vtxo_graph.as_ref().map(|g| {
            let leaf = first_tree_leaf(g);
            (leaf.unsigned_tx.compute_txid().to_string(), 0u32)
        });
        (event.commitment_txid, vtxo_outpoint)
    }
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

/// Get the first leaf PSBT from a TxGraph.
fn first_tree_leaf(graph: &TxGraph) -> &Psbt {
    let leaves = graph.leaves();
    leaves.into_iter().next().unwrap_or_else(|| graph.root())
}

/// Decode a 64-char hex string into a 32-byte array.
fn hex_decode_32(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("hex decode error at byte {i}: {e}"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod batch_intent_tests {
    use super::*;

    fn event(hashes: &[&str]) -> proto::BatchStartedEvent {
        proto::BatchStartedEvent {
            id: "batch-1".to_string(),
            intent_id_hashes: hashes.iter().map(|s| s.to_string()).collect(),
            batch_expiry: 0,
        }
    }

    /// Pinned against `sha256sum`, so a change in hashing shows up here rather
    /// than as an aborted batch on a live ASP.
    const TEST_INTENT: &str = "test-intent";
    const TEST_INTENT_HASH: &str =
        "c65c50e6ddaf679c703ebc2705b82498136a5e9e5fcc2ebd50376b1935689768";


    fn started(id: &str) -> Event {
        Event::BatchStarted(proto::BatchStartedEvent {
            id: id.into(),
            intent_id_hashes: vec![],
            batch_expiry: 0,
        })
    }
    fn failed(id: &str) -> Event {
        Event::BatchFailed(proto::BatchFailedEvent { id: id.into(), reason: "x".into() })
    }
    fn finalized(id: &str) -> Event {
        Event::BatchFinalized(proto::BatchFinalizedEvent {
            id: id.into(),
            commitment_txid: "deadbeef".into(),
        })
    }
    fn tree_tx(id: &str) -> Event {
        Event::TreeTx(proto::TreeTxEvent {
            id: id.into(),
            topic: vec![],
            batch_index: 0,
            txid: String::new(),
            tx: String::new(),
            children: Default::default(),
        })
    }

    /// The bug this guards: a stranger's batch failing used to abort our settle,
    /// and a stranger's batch finalizing used to be recorded as our settlement.
    /// Each boarding round draws its own tree-signing key, so no two rounds share one.
    #[test]
    fn every_boarding_signer_has_a_key_of_its_own() {
        assert_ne!(
            BoardingTreeSigner::generate().cosigner_pubkey_hex(),
            BoardingTreeSigner::generate().cosigner_pubkey_hex()
        );
    }

    #[test]
    fn foreign_batch_events_are_rejected() {
        let ours = |id: &str| id == "ours";
        assert_eq!(foreign_batch_id(&failed("theirs"), ours).as_deref(), Some("theirs"));
        assert_eq!(foreign_batch_id(&finalized("theirs"), ours).as_deref(), Some("theirs"));
        assert_eq!(foreign_batch_id(&tree_tx("theirs"), ours).as_deref(), Some("theirs"));
    }

    #[test]
    fn our_own_batch_events_pass_through() {
        let ours = |id: &str| id == "ours";
        assert!(foreign_batch_id(&failed("ours"), ours).is_none());
        assert!(foreign_batch_id(&finalized("ours"), ours).is_none());
        assert!(foreign_batch_id(&tree_tx("ours"), ours).is_none());
    }

    /// BatchStarted is filtered by intent hash instead, and establishes the id
    /// everything else is matched against, so it must never be gated here.
    #[test]
    fn batch_started_is_never_gated() {
        assert!(foreign_batch_id(&started("theirs"), |_| false).is_none());
    }

    /// Before joining a batch nothing is ours — matching the reference client,
    /// which ignores every batch event until its Step leaves Start.
    #[test]
    fn nothing_is_ours_before_joining() {
        let none = |_: &str| false;
        assert_eq!(foreign_batch_id(&finalized("any"), none).as_deref(), Some("any"));
    }

    #[test]
    fn matches_sha256_hex_of_the_intent_id() {
        assert!(batch_includes_intent(&event(&[TEST_INTENT_HASH]), TEST_INTENT));
    }

    #[test]
    fn finds_our_intent_among_other_participants() {
        let e = event(&["00".repeat(32).as_str(), TEST_INTENT_HASH, "ff".repeat(32).as_str()]);
        assert!(batch_includes_intent(&e, TEST_INTENT));
    }

    #[test]
    fn rejects_a_batch_we_are_not_in() {
        // The case that aborted boarding on mutinynet: a batch of other people's
        // intents, which we used to confirm into unconditionally.
        assert!(!batch_includes_intent(&event(&["00".repeat(32).as_str()]), TEST_INTENT));
    }

    #[test]
    fn rejects_an_empty_batch() {
        assert!(!batch_includes_intent(&event(&[]), TEST_INTENT));
    }

    #[test]
    fn does_not_match_the_raw_intent_id() {
        // arkd sends hashes, never the ids themselves.
        assert!(!batch_includes_intent(&event(&[TEST_INTENT]), TEST_INTENT));
    }

    /// A bitcoin address in a delegate is a collaborative exit, an on-chain output; an Ark
    /// address stays in Ark.
    #[test]
    fn a_bitcoin_address_leaves_ark_and_an_ark_address_stays() {
        use bitcoin::key::TweakedPublicKey;
        use bitcoin::Network;
        let owner = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let asp = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
        let ark = crate::client::ark_address(owner, asp, 512, Network::Regtest).unwrap();
        let xonly: bitcoin::XOnlyPublicKey = owner.parse().unwrap();
        let onchain = bitcoin::Address::p2tr_tweaked(
            TweakedPublicKey::dangerous_assume_tweaked(xonly),
            Network::Regtest,
        )
        .to_string();

        assert!(matches!(
            intent_output(&ark, 1_000, Network::Regtest),
            Ok(ark_core::intent::Output::Offchain(_))
        ));
        assert!(matches!(
            intent_output(&onchain, 1_000, Network::Regtest),
            Ok(ark_core::intent::Output::Onchain(o)) if o.value.to_sat() == 1_000
        ));
        // Another network's address, and something that is no address, are refused.
        assert!(intent_output(&onchain, 1_000, Network::Bitcoin).is_err());
        assert!(intent_output("not an address", 1_000, Network::Regtest).is_err());
    }
}
