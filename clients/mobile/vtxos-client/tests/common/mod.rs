//! What the live suites share: the runtime in process, serving the policy guest, and the regtest
//! stack's bitcoind.

use std::process::Command;
use std::time::Duration;

use enclave_runtime::testing::Enclave as Harness;
use vtxos_client::asp::Asp;
use vtxos_client::enclave::Pins;
use vtxos_client::wallet::Wallet;

pub async fn harness() -> Harness {
    let path = std::env::var_os("POLICY_WASM").expect("POLICY_WASM: the policy guest to serve");
    Harness::builder(std::fs::read(path).expect("read POLICY_WASM"))
        .notify()
        .background_tasks()
        .start()
        .await
        .expect("the runtime starts")
}

pub fn pins(h: &Harness) -> Pins {
    Pins {
        trust_root: h.trust_root(),
        pcr0: h.pcr0().to_vec(),
        pcr16: h.pcr16().to_vec(),
        max_age: Duration::from_secs(300),
    }
}

/// The balance once the indexer shows `expected`.
pub async fn settled_balance(wallet: &Wallet, expected: u64) -> u64 {
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
pub async fn recipient_address(asp: &Asp) -> String {
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

/// `bitcoin-cli` in the regtest bitcoind container, as the wallet's `scripts/bitcoin.sh` runs it:
/// its output, or what it said on failing.
pub fn try_bitcoin_cli(args: &[&str]) -> Result<String, String> {
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
    if output.status.success() {
        Ok(String::from_utf8(output.stdout).unwrap().trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

/// `bitcoin-cli`, which must succeed.
pub fn bitcoin_cli(args: &[&str]) -> String {
    try_bitcoin_cli(args).unwrap_or_else(|e| panic!("bitcoin-cli {args:?}: {e}"))
}

pub fn mine(blocks: u32) {
    let address = bitcoin_cli(&["getnewaddress", "", "bech32m"]);
    bitcoin_cli(&["generatetoaddress", &blocks.to_string(), &address]);
}

/// Pay `sats` to `address` and confirm it; the output's outpoint.
pub fn fund(address: &str, sats: u64) -> (String, u32) {
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
