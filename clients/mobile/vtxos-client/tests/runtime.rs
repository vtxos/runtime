//! Against the runtime itself, in process (`enclave_runtime::testing`), serving the real policy
//! guest: a real TLS handshake, real attestation documents under the harness's root, the real
//! sign-in gate, and the guest's own gRPC service.
//!
//! ```console
//! $ nix build .#policy
//! $ POLICY_WASM=<path to policy.wasm> cargo test --test runtime -- --ignored
//! ```

use std::time::Duration;

use std::process::Command;
use std::sync::Arc;

use enclave_runtime::testing::Enclave as Harness;
use vtxos_client::asp::Asp;
use vtxos_client::enclave::{Enclave, Pins};
use vtxos_client::wallet::{Renewal, Wallet};
use vtxos_client::{guest, Error};

/// A push token as FCM issues them: the guest takes 32 to 512 characters.
const TOKEN: &str = "fcm-token-for-a-phone-that-holds-this-wallet:0123456789";

async fn harness() -> Harness {
    let path = std::env::var_os("POLICY_WASM").expect("POLICY_WASM: the policy guest to serve");
    Harness::builder(std::fs::read(path).expect("read POLICY_WASM"))
        .notify()
        .background_tasks()
        .start()
        .await
        .expect("the runtime starts")
}

fn pins(h: &Harness) -> Pins {
    Pins {
        trust_root: h.trust_root(),
        pcr0: h.pcr0().to_vec(),
        pcr16: h.pcr16().to_vec(),
        max_age: Duration::from_secs(300),
    }
}

/// A passkey registers a wallet; the record and the same passkey open it again; the opened wallet
/// signs in to the guest's own calls.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs POLICY_WASM: nix build .#policy"]
async fn a_passkey_registers_a_wallet_that_signs_in_to_the_guest() {
    let h = harness().await;
    let enclave = Enclave::new(&h.url(), &pins(&h)).unwrap();
    let prf = [0x42; 32];
    let record = enclave.register(&prf).await.expect("registered");

    let client = record.open(&prf).expect("the passkey opens its wallet");
    assert_eq!(guest::device_count(&enclave, &client).await.unwrap(), 0);
    guest::register_device(&enclave, &client, TOKEN)
        .await
        .unwrap();
    assert_eq!(guest::device_count(&enclave, &client).await.unwrap(), 1);
    guest::forget_device(&enclave, &client, TOKEN)
        .await
        .unwrap();
    assert_eq!(guest::device_count(&enclave, &client).await.unwrap(), 0);

    assert!(matches!(record.open(&[0x43; 32]), Err(Error::WrongPasskey)));
}

/// An enclave running another guest is refused before anything secret goes out.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs POLICY_WASM: nix build .#policy"]
async fn another_guest_is_refused_at_registration() {
    let h = harness().await;
    let mut pins = pins(&h);
    pins.pcr16 = vec![0; 48];
    let enclave = Enclave::new(&h.url(), &pins).unwrap();
    let err = enclave.register(&[0x42; 32]).await.unwrap_err();
    assert!(matches!(err, Error::Attestation(_)), "{err}");
}

/// A document under a root the app does not pin is refused the same way.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs POLICY_WASM: nix build .#policy"]
async fn another_root_is_refused() {
    let h = harness().await;
    let mut pins = pins(&h);
    pins.trust_root = enclave_client::AWS_NITRO_ROOT_G1_PEM.as_bytes().to_vec();
    let enclave = Enclave::new(&h.url(), &pins).unwrap();
    let err = enclave.register(&[0x42; 32]).await.unwrap_err();
    assert!(matches!(err, Error::Attestation(_)), "{err}");
}

/// The whole wallet against a real arkd: board, send with the delegate renewed and its exits
/// checked, refresh in a round, and protect. Needs the wallet repository's regtest stack too:
/// `cd ~/MerlinWallet && make arkd-up bitcoin-init arkd-init`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs POLICY_WASM and a regtest arkd"]
async fn a_wallet_boards_sends_refreshes_and_protects_against_arkd() {
    let h = harness().await;
    let enclave = Arc::new(Enclave::new(&h.url(), &pins(&h)).unwrap());
    let asp_url = std::env::var("ARK_LIVE_ASP").unwrap_or_else(|_| "http://127.0.0.1:7070".into());
    let asp = Arc::new(Asp::new(&asp_url));
    // A passkey of its own: the harness's enclave makes the same wallet key from the same
    // passkey, and arkd keeps what earlier runs left under it.
    let mut prf = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut prf);
    let record = enclave.register(&prf).await.expect("registered");
    let wallet = Wallet::new(enclave.clone(), asp.clone(), record.open(&prf).unwrap());

    // Board.
    let boarding = wallet.boarding_address().await.unwrap();
    let (txid, vout) = fund(&boarding, 100_000);
    let settled = wallet
        .board((txid, vout, 100_000), None)
        .await
        .expect("boarded");
    assert_eq!(settled.amount_sats, 100_000);
    mine(1);
    assert_eq!(settled_balance(&wallet, 100_000).await, 100_000);

    // Send part of it, renewing the delegate over the change with an exit to an address of ours.
    let exit_address = bitcoin_cli(&["getnewaddress", "", "bech32m"]);
    let renewal = Renewal {
        exit_address: Some(exit_address.clone()),
        device_token: None,
    };
    let recipient = recipient_address(&asp).await;
    let sent = wallet
        .send(&recipient, 30_000, Some(renewal.clone()))
        .await
        .expect("sent");
    let renewed = sent.renewed.expect("the delegate renewed");
    assert_eq!(renewed.exits.len(), 1, "one exit, for the change");
    assert_eq!(renewed.exits[0].amount_sats, 70_000);
    assert_eq!(settled_balance(&wallet, 70_000).await, 70_000);

    // Refresh the change in a round.
    let refreshed = wallet.refresh(None).await.expect("refreshed");
    assert_eq!(
        refreshed.amount_sats, 70_000,
        "the new VTXO's amount, from the indexer"
    );
    let held = wallet.vtxos().await.unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(
        (held[0].txid.clone(), held[0].vout),
        (refreshed.vtxo_txid.clone(), refreshed.vtxo_vout)
    );
    mine(1);

    // Protect what is held now, with a device to wake.
    let protected = wallet
        .protect(Renewal {
            exit_address: Some(exit_address),
            device_token: Some(TOKEN.into()),
        })
        .await
        .expect("protected");
    assert_eq!(protected.exits.len(), 1);
    assert!(protected.device_enrolled);
}

/// The balance once the indexer shows `expected`.
async fn settled_balance(wallet: &Wallet, expected: u64) -> u64 {
    for _ in 0..30 {
        let balance = wallet.balance().await.unwrap();
        if balance == expected {
            return balance;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    wallet.balance().await.unwrap()
}

/// Someone else's Ark address on this ASP.
async fn recipient_address(asp: &Asp) -> String {
    let info = ark::client::server_info(asp.info().await.unwrap()).unwrap();
    let someone = bitcoin::secp256k1::Keypair::new(
        &bitcoin::secp256k1::Secp256k1::new(),
        &mut rand_core::OsRng,
    );
    ark::client::ark_address(
        &someone.x_only_public_key().0.to_string(),
        &info.signer_pk.to_string(),
        ark::client::exit_delay_value(info.unilateral_exit_delay).unwrap(),
        info.network,
    )
    .unwrap()
}

/// `bitcoin-cli` in the regtest bitcoind container, as the wallet's `scripts/bitcoin.sh` runs it.
fn bitcoin_cli(args: &[&str]) -> String {
    let container =
        std::env::var("ARK_LIVE_BITCOIND").unwrap_or_else(|_| "mpc_bitcoind".to_string());
    let output = Command::new("docker")
        .args([
            "exec",
            &container,
            "bitcoin-cli",
            "-regtest",
            "-rpcuser=admin1",
        ])
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
