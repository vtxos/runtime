//! Each session against ark-core's own signing helpers, run the way ark-client runs them.
//!
//! The sessions hand out sighashes and take FROST signatures back, because the wallet key is a
//! 2-of-2 whose signature comes from a network round, not from a closure. What reaches the ASP
//! must still be exactly what ark-core would have produced. So each test drives a session to its
//! signed PSBTs, signs the same unsigned PSBTs with ark-core directly, and expects the same bytes,
//! and the same messages in the same order.
//!
//! One key stands in for the wallet key X: the ASP only ever sees a BIP-340 signature under X,
//! however it was made, and signing without auxiliary randomness makes both sides' bytes equal.
#![cfg(feature = "signing")]

use std::cell::RefCell;

use ark::client::batch::{DelegateOutput, DelegateSettleSession, DelegateVtxoInput, SettleSession};
use ark::client::proto;
use ark::client::send::{SendSession, SendVtxoInput};
use ark::client::{exit_delay_value, server_info, Info};
use ark::exit::ExitInput;
use ark_core::batch::OnChainInput;
use ark_core::intent::{self, IntentMessage};
use ark_core::server::parse_sequence_number;
use ark_core::{BoardingOutput, Vtxo};
use bitcoin::base64::{engine::general_purpose::STANDARD, Engine};
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::secp256k1::{schnorr, Message, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::LeafVersion;
use bitcoin::transaction::Version;
use bitcoin::{
    absolute, Address, Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, TapLeafHash,
    TapSighashType, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey,
};

const UNILATERAL: u32 = 86016;
const BOARDING: u32 = 172032;
const BOARDED: u64 = 100_000;

fn keypair(byte: u8) -> Keypair {
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[byte; 32]).unwrap())
}
fn owner() -> Keypair {
    keypair(9)
}
fn asp() -> Keypair {
    keypair(7)
}
fn forfeit() -> Keypair {
    keypair(5)
}
fn xonly(kp: &Keypair) -> XOnlyPublicKey {
    kp.x_only_public_key().0
}
fn hex_of(kp: &Keypair) -> String {
    xonly(kp).to_string()
}
fn txid(byte: u8) -> Txid {
    Txid::from_byte_array([byte; 32])
}

fn sign(msg: &[u8; 32]) -> schnorr::Signature {
    Secp256k1::new().sign_schnorr_no_aux_rand(&Message::from_digest(*msg), &owner())
}
fn sign_all(sighashes: &[[u8; 32]]) -> Vec<[u8; 64]> {
    sighashes.iter().map(|m| sign(m).serialize()).collect()
}

/// What ark-client hands ark-core's signing helpers: sign for the owner, and here also note
/// each message in the order the helper asks.
fn signer(
    seen: &RefCell<Vec<[u8; 32]>>,
) -> impl Fn(
    &mut bitcoin::psbt::Input,
    Message,
) -> Result<Vec<(schnorr::Signature, XOnlyPublicKey)>, ark_core::Error>
       + '_ {
    move |_, msg| {
        let m: [u8; 32] = *msg.as_ref();
        seen.borrow_mut().push(m);
        Ok(vec![(sign(&m), xonly(&owner()))])
    }
}

fn psbt(b64: &String) -> Psbt {
    Psbt::deserialize(&STANDARD.decode(b64).unwrap()).unwrap()
}
fn b64(psbt: &Psbt) -> String {
    STANDARD.encode(psbt.serialize())
}

fn forfeit_address() -> Address {
    Address::p2tr(&Secp256k1::new(), xonly(&forfeit()), None, Network::Regtest)
}

/// The ASP's parameters as arkd sends them.
fn get_info() -> proto::GetInfoResponse {
    let checkpoint = ark_core::script::csv_sig_script(
        parse_sequence_number(10).unwrap(),
        xonly(&asp()),
    );
    proto::GetInfoResponse {
        signer_pubkey: asp().public_key().to_string(),
        forfeit_pubkey: forfeit().public_key().to_string(),
        forfeit_address: forfeit_address().to_string(),
        checkpoint_tapscript: hex::encode(checkpoint.as_bytes()),
        network: "regtest".into(),
        session_duration: 10,
        unilateral_exit_delay: UNILATERAL as i64,
        boarding_exit_delay: BOARDING as i64,
        vtxo_min_amount: 1,
        dust: 330,
        ..Default::default()
    }
}

fn info() -> Info {
    server_info(get_info()).unwrap()
}

fn ark_address(kp: &Keypair, delay: u32) -> String {
    ark::client::ark_address(&hex_of(kp), &hex_of(&asp()), delay, Network::Regtest).unwrap()
}

#[test]
fn a_send_signs_what_ark_core_signs() {
    let inputs = [
        SendVtxoInput { txid: txid(1).to_string(), vout: 0, amount_sats: 50_000, exit_delay: BOARDING },
        SendVtxoInput { txid: txid(2).to_string(), vout: 1, amount_sats: 30_000, exit_delay: UNILATERAL },
    ];
    let recipient = ark_address(&keypair(11), UNILATERAL);
    let (mut session, sighashes) =
        SendSession::build(&hex_of(&owner()), &inputs, &recipient, 60_000, None, &info()).unwrap();
    let (ark_tx_b64, checkpoints_b64) = session.unsigned();
    session.sign_with_frost(sign_all(&sighashes)).unwrap();
    let (signed_ark_tx_b64, _) = session.prepare_submit().unwrap();

    let seen = RefCell::new(Vec::new());
    let mut ark_tx = psbt(&ark_tx_b64);
    for i in 0..ark_tx.inputs.len() {
        ark_core::send::sign_ark_transaction(signer(&seen), &mut ark_tx, i).unwrap();
    }
    let mut checkpoints: Vec<Psbt> = checkpoints_b64.iter().map(psbt).collect();
    for checkpoint in &mut checkpoints {
        ark_core::send::sign_checkpoint_transaction(signer(&seen), checkpoint).unwrap();
    }

    assert_eq!(sighashes, seen.into_inner(), "the messages, in ark-core's order");
    assert_eq!(psbt(&signed_ark_tx_b64), ark_tx);
    // Our checkpoint signatures, laid on checkpoints as the ASP returns them.
    let finals = session.finalize_checkpoints(&checkpoints_b64).unwrap();
    assert_eq!(finals.iter().map(psbt).collect::<Vec<_>>(), checkpoints);
}

#[test]
fn a_delegate_signs_what_ark_core_signs() {
    let inputs = [
        DelegateVtxoInput { txid: txid(3).to_string(), vout: 0, amount_sats: 40_000, is_swept: false, exit_delay: UNILATERAL },
        DelegateVtxoInput { txid: txid(4).to_string(), vout: 2, amount_sats: 20_000, is_swept: false, exit_delay: BOARDING },
    ];
    let outputs = [DelegateOutput { address: ark_address(&owner(), UNILATERAL), amount_sats: 60_000 }];
    let (mut session, sighashes) = DelegateSettleSession::generate_delegate(
        &hex_of(&owner()),
        &hex_of(&asp()),
        &hex_of(&forfeit()),
        &inputs,
        &outputs,
        &forfeit_address().to_string(),
        330,
        "regtest",
        Some(1_800_000_000),
    )
    .unwrap();
    session.sign_with_frost(sign_all(&sighashes)).unwrap();
    let persisted = session.to_persisted().unwrap();
    let signed_intent = psbt(&persisted.intent_proof_psbt_b64);
    let signed_forfeits: Vec<Psbt> = persisted.forfeit_psbts_b64.iter().map(psbt).collect();

    // Signing only adds signatures, so these less the signatures are what ark-core signs.
    let unsigned = |p: &Psbt| {
        let mut p = p.clone();
        p.inputs.iter_mut().for_each(|i| i.tap_script_sigs.clear());
        p
    };
    let mut intent = unsigned(&signed_intent);
    let mut forfeits: Vec<Psbt> = signed_forfeits.iter().map(unsigned).collect();
    let seen = RefCell::new(Vec::new());
    ark_core::batch::sign_delegate_psbts(signer(&seen), &mut intent, &mut forfeits).unwrap();

    assert_eq!(sighashes, seen.into_inner(), "the messages, in ark-core's order");
    assert_eq!(signed_intent, intent);
    assert_eq!(signed_forfeits, forfeits);
}

/// A boarding session over one confirmed output, the intent sighashes it hands out, and what it
/// spends.
fn boarding() -> (SettleSession, Vec<[u8; 32]>, BoardingOutput, OutPoint) {
    let boarding_output = BoardingOutput::new(
        &Secp256k1::new(),
        xonly(&asp()),
        xonly(&owner()),
        parse_sequence_number(BOARDING as i64).unwrap(),
        Network::Regtest,
    )
    .unwrap();
    let outpoint = OutPoint { txid: txid(6), vout: 1 };
    let (session, sighashes) = SettleSession::new_boarding(
        &hex_of(&owner()),
        &hex_of(&asp()),
        &hex_of(&forfeit()),
        &boarding_output.address().to_string(),
        &outpoint.txid.to_string(),
        outpoint.vout,
        BOARDED,
        BOARDING,
        "regtest",
        &keypair(12).public_key().to_string(),
    )
    .unwrap();
    (session, sighashes, boarding_output, outpoint)
}

#[test]
fn a_boarding_intent_is_the_one_ark_client_makes() {
    let (mut session, sighashes, boarding_output, outpoint) = boarding();
    session.insert_intent_signatures(sign_all(&sighashes)).unwrap();
    let (proof_b64, message_json, _) = session.register_payload().unwrap();
    let message: IntentMessage = serde_json::from_str(&message_json).unwrap();

    // ark-client 0.9.1's boarding input (`prepare_intent`), signed through `make_intent`.
    let input = intent::Input::new(
        outpoint,
        boarding_output.exit_delay(),
        None,
        TxOut { value: Amount::from_sat(BOARDED), script_pubkey: boarding_output.script_pubkey() },
        boarding_output.tapscripts(),
        boarding_output.forfeit_spend_info(),
        true,
        false,
        Vec::new(),
    );
    let output = intent::Output::Offchain(TxOut {
        value: Amount::from_sat(BOARDED),
        script_pubkey: boarding_output
            .to_ark_address(Network::Regtest, xonly(&asp()))
            .to_p2tr_script_pubkey(),
    });
    let seen = RefCell::new(Vec::new());
    let onchain = |_: &mut bitcoin::psbt::Input, msg: Message| {
        let m: [u8; 32] = *msg.as_ref();
        seen.borrow_mut().push(m);
        Ok((sign(&m), xonly(&owner())))
    };
    let reference =
        intent::make_intent(signer(&seen), onchain, vec![input], vec![output], message).unwrap();

    assert_eq!(sighashes, seen.into_inner(), "the messages, in ark-core's order");
    assert_eq!(psbt(&proof_b64), reference.proof);
}

#[test]
fn a_boarding_commitment_signs_what_ark_core_signs() {
    let (mut session, sighashes, boarding_output, outpoint) = boarding();
    session.insert_intent_signatures(sign_all(&sighashes)).unwrap();

    // A commitment transaction as the ASP sends it: someone else's input, then ours.
    let theirs = TxOut {
        value: Amount::from_sat(250_000),
        script_pubkey: Address::p2tr(&Secp256k1::new(), xonly(&keypair(14)), None, Network::Regtest)
            .script_pubkey(),
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: [OutPoint { txid: txid(8), vout: 0 }, outpoint]
            .into_iter()
            .map(|previous_output| TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(340_000),
            script_pubkey: forfeit_address().script_pubkey(),
        }],
    };
    let mut commitment = Psbt::from_unsigned_tx(tx).unwrap();
    commitment.inputs[0].witness_utxo = Some(theirs);
    commitment.inputs[1].witness_utxo =
        Some(TxOut { value: Amount::from_sat(BOARDED), script_pubkey: boarding_output.script_pubkey() });

    let sighashes = session
        .handle_batch_finalization(proto::BatchFinalizationEvent {
            id: "batch".into(),
            commitment_tx: b64(&commitment),
        })
        .unwrap();
    let signed = psbt(&session.insert_commitment_signatures(sign_all(&sighashes)).unwrap());

    let seen = RefCell::new(Vec::new());
    let mut reference = commitment.clone();
    ark_core::batch::sign_commitment_psbt(
        |_, msg| {
            let m: [u8; 32] = *msg.as_ref();
            seen.borrow_mut().push(m);
            Ok(sign(&m))
        },
        &mut reference,
        &[OnChainInput::new(boarding_output, Amount::from_sat(BOARDED), outpoint)],
    )
    .unwrap();

    assert_eq!(sighashes, seen.into_inner(), "the messages, in ark-core's order");
    assert_eq!(signed, reference);
}

/// The exit is the one transaction ark-core has no builder for, so it is checked against its own
/// leaf instead: rebuilt from ark-core's VTXO, not from anything `build_exit_tx` returned.
#[test]
fn an_exit_signature_verifies_over_ark_cores_exit_leaf() {
    let secp = Secp256k1::new();
    let input = ExitInput { txid: txid(5), vout: 1, amount_sats: 70_000, exit_delay: UNILATERAL };
    let destination =
        Address::p2tr(&secp, xonly(&keypair(13)), None, Network::Regtest).script_pubkey();
    let spend =
        ark::exit::build_exit_tx(xonly(&asp()), xonly(&owner()), Network::Regtest, &input, &destination)
            .unwrap();
    let raw = ark::exit::finalize_exit_tx(&spend, sign(&spend.sighash).as_ref()).unwrap();
    let tx: Transaction = bitcoin::consensus::deserialize(&raw).unwrap();

    let vtxo = Vtxo::new_default(
        &secp,
        xonly(&asp()),
        xonly(&owner()),
        parse_sequence_number(UNILATERAL as i64).unwrap(),
        Network::Regtest,
    )
    .unwrap();
    let (script, control_block) = vtxo.exit_spend_info().unwrap();
    assert_eq!(tx.input[0].sequence, vtxo.exit_delay());
    let prevout = TxOut { value: Amount::from_sat(70_000), script_pubkey: vtxo.script_pubkey() };
    let sighash = SighashCache::new(&tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout]),
            TapLeafHash::from_script(&script, LeafVersion::TapScript),
            TapSighashType::Default,
        )
        .unwrap();

    let witness = &tx.input[0].witness;
    assert_eq!(witness.len(), 3);
    let signature = schnorr::Signature::from_slice(witness.nth(0).unwrap()).unwrap();
    secp.verify_schnorr(&signature, &Message::from_digest(sighash.to_byte_array()), &xonly(&owner()))
        .expect("the exit's signature verifies over the exit leaf of ark-core's VTXO");
    assert_eq!(witness.nth(1).unwrap(), script.as_bytes());
    assert_eq!(witness.nth(2).unwrap(), control_block.serialize());
}

/// The wire and the guest's state carry raw delays; `Info` carries the sequences. Each must give
/// back the other exactly, or a VTXO's delay would stop matching the ASP's.
#[test]
fn a_delay_survives_the_trip_through_its_sequence() {
    for raw in [0, 144, 511, 512, 86016, 172032] {
        let sequence = parse_sequence_number(raw as i64).unwrap();
        assert_eq!(exit_delay_value(sequence).unwrap(), raw, "{raw}");
    }
    let info = info();
    assert_eq!(exit_delay_value(info.unilateral_exit_delay).unwrap(), UNILATERAL);
    assert_eq!(exit_delay_value(info.boarding_exit_delay).unwrap(), BOARDING);
}

/// A delay in seconds that is not a whole number of 512-second units would come back rounded up,
/// so it is refused where the parameters arrive rather than mismatched later.
#[test]
fn a_delay_that_would_not_survive_the_trip_is_refused() {
    let mut get_info = get_info();
    get_info.unilateral_exit_delay = 86017;
    assert!(server_info(get_info).unwrap_err().contains("512-second"));
}

/// What arkd's REST gateway answered on regtest, through the same conversion.
#[test]
fn arkds_own_answer_converts() {
    let info = server_info(proto::GetInfoResponse {
        version: "v0.9.2".into(),
        signer_pubkey: "02e35799157be4b37565bb5afe4d04e6a0fa0a4b6a4f4e48b0d904685d253cdbdb".into(),
        forfeit_pubkey: "03dd8bd6d61d7a4c25eeda780b749923aa62ec5dabe1deb76f11cd5ae1067b698f".into(),
        forfeit_address: "bcrt1qq5rjlmqartxjyh6vnmjrhrqnc58q2hqr5asln0".into(),
        checkpoint_tapscript:
            "5ab27520dd8bd6d61d7a4c25eeda780b749923aa62ec5dabe1deb76f11cd5ae1067b698fac".into(),
        network: "regtest".into(),
        session_duration: 10,
        unilateral_exit_delay: 86016,
        boarding_exit_delay: 172032,
        utxo_min_amount: 330,
        utxo_max_amount: -1,
        vtxo_min_amount: 1,
        vtxo_max_amount: -1,
        dust: 330,
        max_tx_weight: 40000,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(info.network, Network::Regtest);
    assert_eq!(info.dust, Amount::from_sat(330));
    assert_eq!(info.utxo_min_amount, Some(Amount::from_sat(330)));
    assert_eq!(info.utxo_max_amount, None, "-1 is no limit");
    assert_eq!(exit_delay_value(info.unilateral_exit_delay).unwrap(), 86016);
}
