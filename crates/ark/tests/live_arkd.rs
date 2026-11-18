//! The sessions against a real arkd, on regtest: board, send, and renew through a delegate, driven
//! event by event the way the policy guest drives them (`guests/policy/src/{boarding,renew}.rs`).
//!
//! What the offline parity tests cannot show is that arkd accepts the result. This does, for
//! `crates/ark`; the guest's own REST/JSON layer is not under test here.
//!
//! One key stands in for the wallet key X — arkd only ever sees a BIP-340 signature under X — and
//! a fresh one is drawn each run, so earlier runs' funds never get in the way.
//!
//! Needs the wallet repository's regtest stack, unchanged:
//!
//! ```console
//! $ cd ~/MerlinWallet && make arkd-up bitcoin-init arkd-init
//! $ cargo test -p ark --all-features --test live_arkd -- --ignored --test-threads=1
//! ```
//!
//! `ARK_LIVE_ASP` overrides arkd's address (default `http://127.0.0.1:7070`), and
//! `ARK_LIVE_BITCOIND` the bitcoind container `bitcoin-cli` runs in (default `mpc_bitcoind`).
#![cfg(feature = "signing")]

// tonic's generated client stubs, not ours to lint.
#[allow(clippy::all)]
mod grpc {
    include!(concat!(env!("OUT_DIR"), "/grpc/ark.v1.rs"));
}

use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ark::client::batch::{
    batch_includes_intent, foreign_batch_id, BoardingTreeSigner, DelegateOutput,
    DelegateSettleSession, DelegateVtxoInput, SettleAction, SettleSession,
};
use ark::client::proto::{self, get_event_stream_response::Event};
use ark::client::send::{SendSession, SendVtxoInput};
use ark::client::{exit_delay_value, Info};
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::secp256k1::Message;
use tokio_stream::StreamExt;
use tonic::transport::Channel;
use tonic::Streaming;

type Ark = grpc::ark_service_client::ArkServiceClient<Channel>;
type Indexer = grpc::indexer_service_client::IndexerServiceClient<Channel>;

const BOARDED: u64 = 100_000;
const SENT: u64 = 30_000;
/// A round on regtest arkd takes seconds; this is how long any one wait may take before the test
/// gives up rather than hang.
const PATIENCE: Duration = Duration::from_secs(300);

#[tokio::test]
#[ignore = "needs regtest arkd: cd ~/MerlinWallet && make arkd-up bitcoin-init arkd-init"]
async fn board_send_and_renew_against_arkd() {
    let url = std::env::var("ARK_LIVE_ASP").unwrap_or_else(|_| "http://127.0.0.1:7070".into());
    let mut ark = Ark::connect(url.clone()).await.expect("connect to arkd");
    let mut indexer = Indexer::connect(url).await.expect("connect to arkd's indexer");
    let answer = ark.get_info(proto::GetInfoRequest {}).await.unwrap().into_inner();
    let info = ark::client::server_info(answer).expect("arkd's parameters convert");
    let network = info.network;
    let asp = info.signer_pk.to_string();
    let wallet = Keypair::new(&Secp256k1::new(), &mut rand::thread_rng());
    let owner = wallet.x_only_public_key().0.to_string();
    let boarding_delay = exit_delay_value(info.boarding_exit_delay).unwrap();
    let unilateral_delay = exit_delay_value(info.unilateral_exit_delay).unwrap();

    // 1. Board: fund the boarding address, then settle it into a VTXO.
    let boarded = board(&mut ark, &info, &wallet).await;
    let boarded_script =
        ark::client::vtxo_script_pubkey_hex(&owner, &asp, boarding_delay, network)
            .unwrap();
    let vtxo = wait_for_vtxo(&mut indexer, &boarded_script, |v| v.amount == BOARDED).await;
    assert_eq!(boarded, outpoint_of(&vtxo), "the boarded VTXO is the one the session reports");

    // 2. Send part of it off-chain, keeping the change.
    let recipient = Keypair::new(&Secp256k1::new(), &mut rand::thread_rng());
    let recipient_hex = recipient.x_only_public_key().0.to_string();
    let recipient_address =
        ark::client::ark_address(&recipient_hex, &asp, unilateral_delay, network)
            .unwrap();
    let (mut send, sighashes) = SendSession::build(
        &owner,
        &[SendVtxoInput {
            txid: boarded.0.clone(),
            vout: boarded.1,
            amount_sats: BOARDED,
            exit_delay: boarding_delay,
        }],
        &recipient_address,
        SENT,
        None,
        &info,
    )
    .unwrap();
    send.sign_with_frost(sign_all(&wallet, &sighashes)).unwrap();
    let (signed_ark_tx, checkpoint_txs) = send.prepare_submit().unwrap();
    let submitted = ark
        .submit_tx(proto::SubmitTxRequest { signed_ark_tx, checkpoint_txs })
        .await
        .expect("arkd accepts the send")
        .into_inner();
    let final_checkpoint_txs = send.finalize_checkpoints(&submitted.signed_checkpoint_txs).unwrap();
    ark.finalize_tx(proto::FinalizeTxRequest {
        ark_txid: submitted.ark_txid.clone(),
        final_checkpoint_txs,
    })
    .await
    .expect("arkd finalizes the send");
    send.mark_done();
    let (change_txid, change_vout, change_amount) = send.change_vtxo().expect("a change output");
    assert_eq!(change_amount, BOARDED - SENT);

    let recipient_script = ark::client::vtxo_script_pubkey_hex(
        &recipient_hex,
        &asp,
        unilateral_delay,
        network,
    )
    .unwrap();
    wait_for_vtxo(&mut indexer, &recipient_script, |v| v.amount == SENT).await;
    let own_script =
        ark::client::vtxo_script_pubkey_hex(&owner, &asp, unilateral_delay, network)
            .unwrap();
    wait_for_vtxo(&mut indexer, &own_script, |v| {
        outpoint_of(v) == (change_txid.clone(), change_vout)
    })
    .await;

    // 3. Renew the change through a delegate, valid now, through its sealed form, as the guest's
    //    watch runs it.
    let (delegate, sighashes) = DelegateSettleSession::generate_delegate(
        &owner,
        &asp,
        &info.forfeit_pk.to_string(),
        &[DelegateVtxoInput {
            txid: change_txid.clone(),
            vout: change_vout,
            amount_sats: change_amount,
            is_swept: false,
            exit_delay: unilateral_delay,
        }],
        &[DelegateOutput {
            address: ark::client::ark_address(
                &owner,
                &asp,
                unilateral_delay,
                network,
            )
            .unwrap(),
            amount_sats: change_amount,
        }],
        &info.forfeit_address.to_string(),
        info.dust.to_sat(),
        &info.network.to_string(),
        Some(now_secs()),
    )
    .unwrap();
    let mut delegate = delegate;
    delegate.sign_with_frost(sign_all(&wallet, &sighashes)).unwrap();
    let mut delegate = DelegateSettleSession::from_persisted(&delegate.to_persisted().unwrap())
        .expect("a sealed delegate reopens");
    renew(&mut ark, &mut delegate).await;
    wait_for_vtxo(&mut indexer, &own_script, |v| {
        v.amount == change_amount && outpoint_of(v) != (change_txid.clone(), change_vout)
    })
    .await;
}

/// The boarding round, as `guests/policy/src/boarding.rs` drives it. Returns the new VTXO.
async fn board(ark: &mut Ark, info: &Info, wallet: &Keypair) -> (String, u32) {
    let owner = wallet.x_only_public_key().0.to_string();
    let asp = info.signer_pk.to_string();
    let delay = exit_delay_value(info.boarding_exit_delay).unwrap();
    let address = ark::client::boarding_address(&owner, &asp, delay, info.network).unwrap();
    let (txid, vout) = fund(&address, BOARDED);

    let mut signer = BoardingTreeSigner::generate();
    let (mut session, sighashes) = SettleSession::new_boarding(
        &owner,
        &asp,
        &info.forfeit_pk.to_string(),
        &address,
        &txid,
        vout,
        BOARDED,
        delay,
        &info.network.to_string(),
        &signer.cosigner_pubkey_hex(),
    )
    .unwrap();
    session.insert_intent_signatures(sign_all(wallet, &sighashes)).unwrap();
    let (proof, message, topics) = session.register_payload().unwrap();
    let mut events = events(ark, topics).await;
    let intent_id = register(ark, proof, message).await;

    loop {
        let event = next(&mut events).await;
        let joined = session.batch_id();
        if foreign_batch_id(&event, |id| id == joined).is_some() {
            continue;
        }
        match event {
            Event::BatchStarted(e) => {
                if batch_includes_intent(&e, &intent_id) {
                    session.on_batch_started(e).unwrap();
                    confirm(ark, &intent_id).await;
                }
            }
            Event::TreeTx(e) => session.handle_tree_tx(e).unwrap(),
            Event::TreeSigningStarted(e) => {
                if let SettleAction::NeedTreeNonces { tree_tx_chunks, commitment_psbt_b64 } =
                    session.on_tree_signing_started(e).unwrap()
                {
                    let (pubkey, nonces) =
                        signer.gen_nonces(&tree_tx_chunks, &commitment_psbt_b64).unwrap();
                    ark.submit_tree_nonces(proto::SubmitTreeNoncesRequest {
                        batch_id: session.batch_id(),
                        pubkey,
                        tree_nonces: nonces.into_iter().collect(),
                    })
                    .await
                    .expect("arkd takes the tree nonces");
                }
            }
            Event::TreeNonces(e) => {
                if let Some(SettleAction::NeedTreeSign {
                    pending_nonces,
                    batch_expiry,
                    forfeit_pk_hex,
                }) = session.on_tree_nonces(e).unwrap()
                {
                    let (pubkey, signatures) =
                        signer.sign(&pending_nonces, batch_expiry, &forfeit_pk_hex).unwrap();
                    ark.submit_tree_signatures(proto::SubmitTreeSignaturesRequest {
                        batch_id: session.batch_id(),
                        pubkey,
                        tree_signatures: signatures.into_iter().collect(),
                    })
                    .await
                    .expect("arkd takes the tree signatures");
                }
            }
            Event::BatchFinalization(e) => {
                let sighashes = session.handle_batch_finalization(e).unwrap();
                let signed_commitment_tx = session
                    .insert_commitment_signatures(sign_all(wallet, &sighashes))
                    .unwrap();
                ark.submit_signed_forfeit_txs(proto::SubmitSignedForfeitTxsRequest {
                    signed_forfeit_txs: Vec::new(),
                    signed_commitment_tx,
                })
                .await
                .expect("arkd takes the signed commitment");
            }
            Event::BatchFinalized(e) => {
                let (_, vtxo) = session.on_batch_finalized(e);
                mine(1);
                return vtxo.expect("the batch's VTXO");
            }
            Event::BatchFailed(e) => panic!("boarding batch failed: {}", e.reason),
            _ => {}
        }
    }
}

/// The delegate's round, as `guests/policy/src/renew.rs` drives it.
async fn renew(ark: &mut Ark, session: &mut DelegateSettleSession) {
    let (proof, message, topics) = session.register_payload().unwrap();
    let mut events = events(ark, topics).await;
    let intent_id = register(ark, proof, message).await;
    session.intent_id = Some(intent_id.clone());

    loop {
        let event = next(&mut events).await;
        let joined = session.joined_batch_id().map(str::to_string);
        if foreign_batch_id(&event, |id| joined.as_deref() == Some(id)).is_some() {
            continue;
        }
        match event {
            Event::BatchStarted(e) => {
                if batch_includes_intent(&e, &intent_id) {
                    session.on_batch_started(e).unwrap();
                    confirm(ark, &intent_id).await;
                }
            }
            Event::TreeTx(e) => session.on_tree_tx(e).unwrap(),
            Event::TreeSigningStarted(e) => {
                let (batch_id, pubkey, nonces) = session.on_tree_signing_started(e).unwrap();
                ark.submit_tree_nonces(proto::SubmitTreeNoncesRequest {
                    batch_id,
                    pubkey,
                    tree_nonces: nonces,
                })
                .await
                .expect("arkd takes the delegate's tree nonces");
            }
            Event::TreeNonces(e) => {
                if let Some((batch_id, pubkey, signatures)) = session.on_tree_nonces(e).unwrap() {
                    ark.submit_tree_signatures(proto::SubmitTreeSignaturesRequest {
                        batch_id,
                        pubkey,
                        tree_signatures: signatures,
                    })
                    .await
                    .expect("arkd takes the delegate's tree signatures");
                }
            }
            Event::BatchFinalization(e) => {
                if let Some(signed_forfeit_txs) = session.on_batch_finalization(e).unwrap() {
                    ark.submit_signed_forfeit_txs(proto::SubmitSignedForfeitTxsRequest {
                        signed_forfeit_txs,
                        signed_commitment_tx: String::new(),
                    })
                    .await
                    .expect("arkd takes the delegated forfeits");
                }
            }
            Event::BatchFinalized(e) => {
                session.on_batch_finalized(e);
                mine(1);
                return;
            }
            Event::BatchFailed(e) => panic!("delegate batch failed: {}", e.reason),
            _ => {}
        }
    }
}

fn sign_all(wallet: &Keypair, sighashes: &[[u8; 32]]) -> Vec<[u8; 64]> {
    let secp = Secp256k1::new();
    sighashes
        .iter()
        .map(|m| secp.sign_schnorr_no_aux_rand(&Message::from_digest(*m), wallet).serialize())
        .collect()
}

/// Open the event stream before registering, so no event of the round can be missed.
async fn events(ark: &mut Ark, topics: Vec<String>) -> Streaming<proto::GetEventStreamResponse> {
    ark.get_event_stream(proto::GetEventStreamRequest { topics })
        .await
        .expect("open arkd's event stream")
        .into_inner()
}

async fn next(events: &mut Streaming<proto::GetEventStreamResponse>) -> Event {
    loop {
        let message = tokio::time::timeout(PATIENCE, events.next())
            .await
            .expect("no event from arkd in time")
            .expect("arkd closed the event stream")
            .expect("arkd's event stream failed");
        if let Some(event) = message.event {
            return event;
        }
    }
}

/// Register an intent, retrying while arkd has yet to see a just-confirmed boarding output.
async fn register(ark: &mut Ark, proof: String, message: String) -> String {
    let started = Instant::now();
    loop {
        let request = proto::RegisterIntentRequest {
            intent: Some(proto::Intent { proof: proof.clone(), message: message.clone() }),
        };
        match ark.register_intent(request).await {
            Ok(response) => return response.into_inner().intent_id,
            Err(e) if started.elapsed() < Duration::from_secs(60) => {
                eprintln!("register_intent: {e}; retrying");
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            Err(e) => panic!("arkd refused the intent: {e}"),
        }
    }
}

async fn confirm(ark: &mut Ark, intent_id: &str) {
    ark.confirm_registration(proto::ConfirmRegistrationRequest { intent_id: intent_id.into() })
        .await
        .expect("arkd takes the confirmation");
}

/// Wait for a spendable VTXO under `script` that `wanted` picks out.
async fn wait_for_vtxo(
    indexer: &mut Indexer,
    script: &str,
    wanted: impl Fn(&proto::IndexerVtxo) -> bool,
) -> proto::IndexerVtxo {
    let started = Instant::now();
    loop {
        let found = indexer
            .get_vtxos(proto::GetVtxosRequest {
                scripts: vec![script.to_string()],
                spendable_only: true,
                ..Default::default()
            })
            .await
            .expect("arkd's indexer answers")
            .into_inner()
            .vtxos
            .into_iter()
            .find(|v| wanted(v));
        if let Some(vtxo) = found {
            return vtxo;
        }
        assert!(started.elapsed() < PATIENCE, "no matching VTXO under {script} in time");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn outpoint_of(vtxo: &proto::IndexerVtxo) -> (String, u32) {
    let outpoint = vtxo.outpoint.as_ref().expect("a VTXO has an outpoint");
    (outpoint.txid.clone(), outpoint.vout)
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// `bitcoin-cli` in the regtest bitcoind container, as the wallet's `scripts/bitcoin.sh` runs it.
fn bitcoin_cli(args: &[&str]) -> String {
    let container =
        std::env::var("ARK_LIVE_BITCOIND").unwrap_or_else(|_| "mpc_bitcoind".to_string());
    let output = Command::new("docker")
        .args(["exec", &container, "bitcoin-cli", "-regtest", "-rpcuser=admin1"])
        .args(["-rpcpassword=123", "-rpcwallet=default"])
        .args(args)
        .output()
        .expect("run docker");
    assert!(
        output.status.success(),
        "bitcoin-cli {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn mine(blocks: u32) {
    let address = bitcoin_cli(&["getnewaddress", "", "bech32m"]);
    bitcoin_cli(&["generatetoaddress", &blocks.to_string(), &address]);
}

/// Pay `sats` to `address` and confirm it; the output's outpoint.
fn fund(address: &str, sats: u64) -> (String, u32) {
    let btc = format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000);
    let txid = bitcoin_cli(&["sendtoaddress", address, &btc]);
    mine(1);
    let tx: serde_json::Value =
        serde_json::from_str(&bitcoin_cli(&["gettransaction", &txid])).unwrap();
    let vout = tx["details"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["address"] == address && d["category"] == "send")
        .and_then(|d| d["vout"].as_u64())
        .expect("the funding output");
    (txid, vout as u32)
}
