//! The runtime in process, serving the policy guest, for the React Native example app to talk to
//! from an emulator. It prints one line: the app's connection settings (URLs and pins), JSON in
//! base64url, to paste into the app.
//!
//! ```console
//! $ POLICY_WASM=<path to policy.wasm> cargo run -p vtxos-uniffi --example dev_enclave
//! ```
//!
//! The ASP is the regtest arkd on 127.0.0.1:7070. An emulator reaches both through `adb reverse`,
//! which the printed command sets up.

use base64::Engine as _;
use enclave_runtime::testing::Enclave as Harness;

#[tokio::main]
async fn main() {
    let path = std::env::var_os("POLICY_WASM").expect("POLICY_WASM: the policy guest to serve");
    let enclave = Harness::builder(std::fs::read(path).expect("read POLICY_WASM"))
        .notify()
        .background_tasks()
        .start()
        .await
        .expect("the runtime starts");

    let root = base64::engine::general_purpose::STANDARD.encode(enclave.trust_root());
    let lines: Vec<&str> = root
        .as_bytes()
        .chunks(64)
        .map(|l| std::str::from_utf8(l).unwrap())
        .collect();
    let settings = serde_json::json!({
        "enclaveUrl": enclave.url(),
        "aspUrl": "http://127.0.0.1:7070",
        "pins": {
            "trustRootPem": format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                lines.join("\n")
            ),
            "pcr0": hex::encode(enclave.pcr0()),
            "pcr16": hex::encode(enclave.pcr16()),
            "maxAgeSecs": 300,
        },
    });
    let port = enclave.addr().port();
    println!("adb reverse tcp:{port} tcp:{port} && adb reverse tcp:7070 tcp:7070");
    println!(
        "{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(settings.to_string())
    );
    std::future::pending::<()>().await;
}
