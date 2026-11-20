//! The unilateral exits a renewal hands back.
//!
//! What matters here is that the exit is *complete* when the wallet gets it: a real 2-of-2
//! signature over the VTXO's exit leaf, in a transaction anybody can broadcast. That is the only
//! thing the wallet cannot obtain later, because obtaining it needs this cosigner.

mod common;

use bitcoin::consensus::deserialize;
use bitcoin::Transaction;
use policy::sign::WalletHalf;
use policy::renew::DelegateRenew;
use policy::session::proto;
use std::sync::{Arc, Mutex};
use policy::types::{Commitment, VtxoInput};
use std::collections::BTreeMap;

use rand::rngs::OsRng;
use threshold::identifier::Identifier;
use threshold::keys::KeyPackage;
use threshold::nonce::{self, SigningCommitments};
use threshold::point;
use threshold::scalar::scalar_to_bytes;
use threshold::commitment::SigningPackage;
use threshold::signing;

/// A P2TR output somewhere else entirely — an exit pays a wallet this one does not control.
fn destination() -> Vec<u8> {
    let mut spk = vec![0x51, 0x20];
    spk.extend_from_slice(&[0xab; 32]);
    spk
}

/// The ASP's parameters as the wallet relays them.
fn ark_info() -> policy::wallet_proto::ArkInfo {
    policy::wallet_proto::ArkInfo {
        signer_pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
        forfeit_pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
        forfeit_address: "bcrt1qq5rjlmqartxjyh6vnmjrhrqnc58q2hqr5asln0".into(),
        network: "regtest".into(),
        unilateral_exit_delay: 512,
        boarding_exit_delay: 144,
        dust: 330,
        ..Default::default()
    }
}

fn vtxo(txid: char, amount_sats: u64) -> VtxoInput {
    VtxoInput {
        txid: std::iter::repeat(txid).take(64).collect(),
        vout: 0,
        amount_sats,
        exit_delay: 512,
        // A delegate needs a deadline to be scheduled against.
        expires_at: 4_102_444_800,
    }
}

/// The wallet's half of the round, over every message the cosigner committed to.
fn wallet_answers(
    kp_user: &KeyPackage,
    messages: &[Vec<u8>],
    cosigner_commitments: &[Commitment],
) -> Vec<WalletHalf> {
    let mut rng = OsRng;
    messages
        .iter()
        .zip(cosigner_commitments)
        .map(|(message, theirs)| {
            let ours = nonce::new_nonce(&mut rng, &kp_user.secret_share);
            let mut commitments: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
            let id: [u8; 32] = hex::decode(&theirs.identifier_hex).unwrap().try_into().unwrap();
            commitments.insert(
                Identifier::deserialize(&id).unwrap(),
                SigningCommitments {
                    hiding: point::deserialize_compressed(
                        &theirs.hiding.clone().try_into().unwrap(),
                    )
                    .unwrap(),
                    binding: point::deserialize_compressed(
                        &theirs.binding.clone().try_into().unwrap(),
                    )
                    .unwrap(),
                },
            );
            commitments.insert(kp_user.identifier.clone(), ours.commitments.clone());
            let package = SigningPackage::new(commitments, message.clone());
            let share = signing::sign(&package, &ours, kp_user).expect("wallet share");
            WalletHalf {
                hiding: point::serialize_compressed(&ours.commitments.hiding).to_vec(),
                binding: point::serialize_compressed(&ours.commitments.binding).to_vec(),
                share: scalar_to_bytes(&share.s).to_vec(),
            }
        })
        .collect()
}

struct Renewed {
    exits: Vec<proto::ExitTx>,
}

/// A wallet as DKG leaves it, on a host that accepts whatever its renewals schedule.
struct Wallet {
    cosigner: Arc<Mutex<policy::Cosigner>>,
    test: common::TestWallet,
    store: std::sync::Arc<policy::store::Store>,
}

fn wallet() -> Option<Wallet> {
    let store = common::try_store()?;
    let test = common::wallet();
    let cosigner = Arc::new(Mutex::new(reopen_at(&store, &test)));
    Some(Wallet { cosigner, test, store })
}

/// A new instance over the store: what the runtime does on every request.
fn reopen_at(
    store: &std::sync::Arc<policy::store::Store>,
    test: &common::TestWallet,
) -> policy::Cosigner {
    // Renewing arms the settle watch, so the runtime must hold the key and take the task.
    common::Recorder::holding(test);
    policy::Cosigner::open(store.clone(), test.group_key()).expect("open")
}

/// Run a whole renewal on [w]: open it, answer its round as the wallet would, and finish.
fn renew_on(w: &mut Wallet, vtxos: Vec<VtxoInput>, exit_script: &[u8]) -> Renewed {
    let request = proto::RenewDelegate {
        vtxos: vtxos.into_iter().map(proto_vtxo).collect(),
        ark_info: Some(ark_info()),
        exit_script_pubkey: exit_script.to_vec(),
        device_token: String::new(),
    };
    let (renew, to_sign) = match DelegateRenew::build(&w.cosigner, request) {
        Ok(opened) => opened,
        Err(e) => panic!("the renewal must work offline: {e}"),
    };
    let all: Vec<Vec<u8>> = to_sign.delegate.iter().chain(&to_sign.exits).cloned().collect();
    assert_eq!(to_sign.commitments.len(), all.len(), "one commitment per message");

    let rounds = wallet_answers(&w.test.user, &all, &to_sign.commitments)
        .into_iter()
        .map(|h| proto::WalletRound { hiding: h.hiding, binding: h.binding, share: h.share })
        .collect();
    let renewed = renew.finalise(&w.cosigner, rounds, "").expect("renew");
    Renewed { exits: renewed.exit_txs }
}

fn proto_vtxo(v: VtxoInput) -> proto::VtxoInput {
    proto::VtxoInput {
        txid: v.txid,
        vout: v.vout,
        amount_sats: v.amount_sats,
        exit_delay: v.exit_delay,
        expires_at: v.expires_at,
    }
}

/// Run a whole renewal on a wallet of its own.
fn renew(vtxos: Vec<VtxoInput>, exit_script: &[u8]) -> Option<Renewed> {
    Some(renew_on(&mut wallet()?, vtxos, exit_script))
}

/// What [c] would seal now, parsed.
fn snapshot(c: &policy::Cosigner) -> serde_json::Value {
    serde_json::from_slice(&c.to_snapshot().expect("snapshot")).expect("json")
}

/// The delegate inside a snapshot, as `to_persisted` wrote it.
fn delegate_in(snapshot: &serde_json::Value) -> serde_json::Value {
    serde_json::from_str(snapshot["delegate_json"].as_str().expect("a delegate")).expect("json")
}

/// One exit per VTXO, each spending its own outpoint and paying the whole amount to the address
/// the wallet named. Signed: the witness is complete, so nothing else is needed to broadcast it.
#[test]
fn a_renewal_returns_one_signed_exit_per_vtxo() {
    let Some(renewed) = renew(vec![vtxo('a', 100_000), vtxo('b', 50_000)], &destination()) else {
        return;
    };
    assert_eq!(renewed.exits.len(), 2);

    for (exit, amount) in renewed.exits.iter().zip([100_000u64, 50_000]) {
        assert_eq!(exit.amount_sats, amount);
        let tx: Transaction = deserialize(&exit.raw_tx).expect("an exit must be a transaction");
        assert_eq!(tx.input.len(), 1);
        assert_eq!(
            format!("{}:{}", tx.input[0].previous_output.txid, tx.input[0].previous_output.vout),
            exit.outpoint,
        );
        assert_eq!(tx.input[0].sequence.to_consensus_u32(), exit.sequence);
        assert_eq!(tx.input[0].witness.len(), 3, "signature, leaf, control block");
        // Everything to the wallet's own address, and an anchor for whoever pays the fee.
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[0].value.to_sat(), amount);
        assert_eq!(tx.output[0].script_pubkey.as_bytes(), destination());
        assert_eq!(tx.output[1].value.to_sat(), 0);
    }
}

/// A wallet with no exit address yet still renews its delegate — it just gets no exits.
#[test]
fn without_an_exit_address_a_renewal_still_works() {
    let Some(renewed) = renew(vec![vtxo('a', 100_000)], &[]) else { return };
    assert!(renewed.exits.is_empty());
}

/// Too small to leave a non-dust output: no exit for that VTXO, and the renewal still happens. The
/// delegate protects it; an exit could not be relayed.
#[test]
fn dust_gets_no_exit_but_does_not_fail_the_renewal() {
    let Some(renewed) = renew(vec![vtxo('a', 100_000), vtxo('b', 200)], &destination()) else {
        return;
    };
    assert_eq!(renewed.exits.len(), 1);
    assert_eq!(renewed.exits[0].amount_sats, 100_000);
}

/// Each delegate signs its round with a tree-signing key of its own, drawn when it is built. It
/// used to be one key for the wallet's life — the cosigner's own DKG secret — which every round
/// showed the ASP, and which joined to the wallet's half of the DKG would have been the whole key.
#[test]
fn every_delegate_has_a_tree_signing_key_of_its_own() {
    let Some(mut w) = wallet() else { return };
    renew_on(&mut w, vec![vtxo('a', 100_000)], &destination());
    let first = delegate_in(&snapshot(&w.cosigner.lock().unwrap()));
    renew_on(&mut w, vec![vtxo('a', 100_000)], &destination());
    let second = delegate_in(&snapshot(&w.cosigner.lock().unwrap()));
    assert_ne!(first["delegate_cosigner_pk_hex"], second["delegate_cosigner_pk_hex"]);
    assert!(
        snapshot(&w.cosigner.lock().unwrap()).get("ark_cosigner_secret_hex").is_none(),
        "no wallet-wide key is sealed beside the delegate"
    );
}

/// The watch runs a delegate long after the request that built it, from the seal alone, so the
/// delegate's key has to come back with it.
#[test]
fn a_delegate_comes_back_from_the_seal_with_its_key() {
    let Some(mut w) = wallet() else { return };
    renew_on(&mut w, vec![vtxo('a', 100_000)], &destination());
    w.cosigner.lock().unwrap().seal();
    let sealed = delegate_in(&snapshot(&w.cosigner.lock().unwrap()));
    let reopened = reopen_at(&w.store, &w.test);
    assert_eq!(delegate_in(&snapshot(&reopened)), sealed, "the delegate came back, key and all");
}

/// A seal from before: its registration's id sat beside the delegate. It still restores, and the
/// next seal moves the id into the delegate.
#[test]
fn a_delegate_whose_id_was_sealed_beside_it_still_restores() {
    let Some(mut w) = wallet() else { return };
    renew_on(&mut w, vec![vtxo('a', 100_000)], &destination());

    // The seal as the old cosigner wrote it.
    let mut old = snapshot(&w.cosigner.lock().unwrap());
    let mut delegate = delegate_in(&old);
    delegate.as_object_mut().unwrap().remove("intent_id");
    old["delegate_json"] = delegate.to_string().into();
    old["delegate_intent_id"] = "intent-1".into();
    w.store
        .put("sealed_state", &w.test.group_key(), &hex::encode(old.to_string()))
        .expect("put");

    let mut reopened = reopen_at(&w.store, &w.test);
    let now = snapshot(&reopened);
    assert_eq!(delegate_in(&now)["intent_id"], "intent-1");
    assert!(now.get("delegate_intent_id").is_none(), "the id is not kept beside the delegate");

    // And from the seal it writes now.
    reopened.seal();
    let again = delegate_in(&snapshot(&reopen_at(&w.store, &w.test)));
    assert_eq!(again["intent_id"], "intent-1");
}
