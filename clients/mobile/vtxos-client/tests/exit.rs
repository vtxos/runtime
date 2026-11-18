//! Leaving without the ASP, on regtest: a VTXO's exit put on chain after the virtual transactions
//! above it, each package paid for by a child from another wallet — bitcoind's, standing in for
//! the app's.
//!
//! It moves the regtest chain's clock past arkd's exit delay, about a day, for good. arkd then
//! sweeps every batch on that stack, and bitcoind refuses to mine on its own clock
//! (`time-too-new`) until that clock is within two hours of the chain's again. So it is a suite of
//! its own, run alone, on a chain that can spare it, and only with `ARK_LIVE_EXIT=1`:
//!
//! ```console
//! $ ARK_LIVE_EXIT=1 POLICY_WASM=<path to policy.wasm> cargo test --test exit -- --ignored
//! ```

mod common;

use std::sync::Arc;

use ark_core::unilateral_exit::{build_anchor_tx, SelectedUtxo, UtxoCoinSelection};
use base64::Engine as _;
use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{relative, Address, Amount, OutPoint, Psbt, Sequence, Transaction, Witness};
use common::{
    bitcoin_cli, fund, harness, mine, pins, recipient_address, settled_balance, try_bitcoin_cli,
};
use vtxos_client::asp::Asp;
use vtxos_client::enclave::Enclave;
use vtxos_client::wallet::{Renewal, Wallet};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs POLICY_WASM and a regtest arkd; moves the regtest clock past the exit delay"]
async fn an_exit_goes_on_chain_after_its_unroll_each_paid_for_by_a_child() {
    assert_eq!(
        std::env::var("ARK_LIVE_EXIT").as_deref(),
        Ok("1"),
        "this moves the regtest chain's clock a day ahead for good: arkd sweeps every batch on \
         it, and bitcoind cannot mine until its own clock catches up. Set ARK_LIVE_EXIT=1 to run \
         it on a chain that can spare that"
    );
    let h = harness().await;
    let enclave = Arc::new(Enclave::new(&h.url(), &pins(&h)).unwrap());
    let asp_url = std::env::var("ARK_LIVE_ASP").unwrap_or_else(|_| "http://127.0.0.1:7070".into());
    let asp = Arc::new(Asp::new(&asp_url));
    let mut prf = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut prf);
    let record = enclave.register(&prf).await.expect("registered");
    let wallet = Wallet::new(enclave.clone(), asp.clone(), record.open(&prf).unwrap());

    let boarding = wallet.boarding_address().await.unwrap();
    let (txid, vout) = fund(&boarding, 100_000);
    wallet
        .board((txid, vout, 100_000), None)
        .await
        .expect("boarded");
    mine(1);
    assert_eq!(settled_balance(&wallet, 100_000).await, 100_000);

    // The change of a send: its way down is a tree's key-path spend, then a checkpoint's and an
    // Ark transaction's script spends.
    let exit_address = bitcoin_cli(&["getnewaddress", "", "bech32m"]);
    let sent = wallet
        .send(
            &recipient_address(&asp).await,
            30_000,
            Some(Renewal {
                exit_address: Some(exit_address.clone()),
                device_token: None,
            }),
        )
        .await
        .expect("sent");
    let exit = sent
        .renewed
        .expect("the delegate renewed")
        .exits
        .into_iter()
        .next()
        .expect("an exit, for the change");
    let unroll: Vec<Transaction> = exit
        .unroll
        .iter()
        .map(|tx| deserialize(tx).unwrap())
        .collect();
    assert!(unroll.len() >= 3, "tree, checkpoint, Ark transaction");
    let vtxo_txid = exit.outpoint.split_once(':').unwrap().0;
    assert_eq!(unroll.last().unwrap().compute_txid().to_string(), vtxo_txid);

    // Each on chain in turn, a block apiece: TRUC lets a child have one unconfirmed parent.
    for tx in &unroll {
        submit_with_child(tx).expect("a virtual transaction and the child paying for it");
        mine(1);
    }

    // The exit is refused until its delay has passed on the chain's clock, then goes in.
    let exit_tx: Transaction = deserialize(&exit.raw_tx).unwrap();
    let early = submit_with_child(&exit_tx).expect_err("too early");
    assert!(early.contains("non-BIP68-final"), "{early}");
    let _clock = pass(exit.sequence);
    submit_with_child(&exit_tx).expect("the exit and the child paying for it");
    mine(1);

    let paid: serde_json::Value = serde_json::from_str(&bitcoin_cli(&[
        "gettxout",
        &exit_tx.compute_txid().to_string(),
        "0",
    ]))
    .expect("the exit's output, unspent");
    assert_eq!(paid["scriptPubKey"]["address"], exit_address.as_str());
    assert_eq!(
        Amount::from_btc(paid["value"].as_f64().unwrap()).unwrap(),
        Amount::from_sat(exit.amount_sats),
        "the whole VTXO: the child paid the fee"
    );
}

/// Submit `parent` with a child that spends its anchor and a coin of bitcoind's wallet, paying
/// for both: what the package relay says, `Err` if it did not take both.
fn submit_with_child(parent: &Transaction) -> Result<(), String> {
    let child = child_of(parent);
    let package = format!(
        "[\"{}\",\"{}\"]",
        serialize_hex(parent),
        serialize_hex(&child)
    );
    let answer = try_bitcoin_cli(&["submitpackage", &package])?;
    let result: serde_json::Value = serde_json::from_str(&answer).unwrap();
    if result["package_msg"] == "success" {
        Ok(())
    } else {
        Err(answer)
    }
}

/// The child: ark-core's anchor transaction from one confirmed coin of bitcoind's wallet, at
/// 2 sat/vB over the package, its change back to the wallet; bitcoind signs its coin, and the
/// anchor, which P2A lets anyone spend, takes an empty witness.
fn child_of(parent: &Transaction) -> Transaction {
    let coins: serde_json::Value =
        serde_json::from_str(&bitcoin_cli(&["listunspent", "1"])).unwrap();
    let coin = coins
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["spendable"] == true && c["amount"].as_f64().unwrap() >= 0.001)
        .expect("a confirmed coin to pay fees with");
    let address = |a: &str| {
        a.parse::<Address<NetworkUnchecked>>()
            .unwrap()
            .assume_checked()
    };
    let selected = SelectedUtxo {
        outpoint: OutPoint {
            txid: coin["txid"].as_str().unwrap().parse().unwrap(),
            vout: coin["vout"].as_u64().unwrap() as u32,
        },
        amount: Amount::from_btc(coin["amount"].as_f64().unwrap()).unwrap(),
        address: address(coin["address"].as_str().unwrap()),
    };
    let change = address(&bitcoin_cli(&["getnewaddress", "", "bech32m"]));
    let psbt = build_anchor_tx(parent, change, 2.0, |fee| {
        Ok(UtxoCoinSelection {
            selected_utxos: vec![selected.clone()],
            total_selected: selected.amount,
            change_amount: selected.amount - fee,
        })
    })
    .unwrap();

    let b64 = base64::engine::general_purpose::STANDARD;
    let processed: serde_json::Value = serde_json::from_str(&bitcoin_cli(&[
        "walletprocesspsbt",
        &b64.encode(psbt.serialize()),
    ]))
    .unwrap();
    let mut signed =
        Psbt::deserialize(&b64.decode(processed["psbt"].as_str().unwrap()).unwrap()).unwrap();
    signed.inputs[0].final_script_witness = Some(Witness::new());
    assert!(
        signed.inputs[1].final_script_witness.is_some(),
        "bitcoind signed its coin"
    );
    signed.extract_tx_unchecked_fee_rate()
}

/// Move the chain's clock past the relative timelock `sequence` asks for, counted from the tip:
/// eleven blocks at the new time put the median time past there too. bitcoind keeps its own clock
/// again once what this returns is dropped.
fn pass(sequence: u32) -> MockTime {
    let seconds = match Sequence::from_consensus(sequence).to_relative_lock_time() {
        Some(relative::LockTime::Time(t)) => u64::from(t.value()) * 512,
        other => panic!("the exit waits for {other:?}, not a time"),
    };
    let tip: serde_json::Value =
        serde_json::from_str(&bitcoin_cli(&["getblockchaininfo"])).unwrap();
    let now = tip["time"].as_u64().unwrap() + seconds + 3_600;
    bitcoin_cli(&["setmocktime", &now.to_string()]);
    let clock = MockTime;
    mine(11);
    clock
}

/// bitcoind's clock set by hand, until this is dropped, pass or panic.
struct MockTime;

impl Drop for MockTime {
    fn drop(&mut self) {
        let _ = try_bitcoin_cli(&["setmocktime", "0"]);
    }
}
