//! The exported API itself, against the runtime in process serving the real policy guest: what a
//! Kotlin, Swift or React Native caller gets, short of the generated glue.
//!
//! ```console
//! $ POLICY_WASM=<path to policy.wasm> cargo test -p vtxos-uniffi --test exports -- --ignored
//! ```

use base64::Engine as _;
use enclave_runtime::testing::Enclave as Harness;
use vtxos_uniffi::{decode_record, encode_record, prf_salt, Pins, Vtxos, VtxosError};

const TOKEN: &str = "fcm-token-for-a-phone-that-holds-this-wallet:0123456789";

async fn harness() -> Harness {
    let path = std::env::var_os("POLICY_WASM").expect("POLICY_WASM: the policy guest to serve");
    Harness::builder(std::fs::read(path).expect("read POLICY_WASM"))
        .notify()
        .start()
        .await
        .expect("the runtime starts")
}

fn pem(der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|l| std::str::from_utf8(l).unwrap())
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs POLICY_WASM: nix build .#policy"]
async fn register_store_reopen_and_close() {
    let h = harness().await;
    let vtxos = Vtxos::new(
        h.url(),
        "http://127.0.0.1:7070".into(),
        Pins {
            trust_root_pem: Some(pem(&h.trust_root())),
            pcr0: hex::encode(h.pcr0()),
            pcr16: hex::encode(h.pcr16()),
            max_age_secs: 300,
        },
    )
    .unwrap();
    let prf = vec![0x61; 32];
    let record = vtxos.register(prf.clone()).await.expect("registered");

    // What the app stores, and reads back.
    let stored = decode_record(encode_record(record.clone())).unwrap();
    assert_eq!(stored.group_key, record.group_key);

    let wallet = vtxos
        .open(stored.clone(), prf)
        .expect("the passkey opens it");
    wallet.register_device(TOKEN.into()).await.unwrap();
    assert_eq!(wallet.device_count().await.unwrap(), 1);

    wallet.close();
    assert!(matches!(
        wallet.device_count().await,
        Err(VtxosError::Protocol { .. })
    ));
    assert!(matches!(
        vtxos.open(stored, vec![0x62; 32]),
        Err(VtxosError::WrongPasskey)
    ));
}

#[test]
fn arguments_are_checked() {
    assert_eq!(prf_salt().len(), 32);
    let bad_pins = Pins {
        trust_root_pem: None,
        pcr0: "00".into(),
        pcr16: "00".into(),
        max_age_secs: 300,
    };
    assert!(Vtxos::new("https://enclave".into(), "https://asp".into(), bad_pins).is_err());
    assert!(decode_record("{}".into()).is_err());
}
