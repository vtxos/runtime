//! The exported API itself, against the runtime in process serving the echo guest
//! (`examples/guest-grpc`): what a React Native caller gets, short of the generated glue.
//!
//! ```console
//! $ scripts/build-guest.sh grpc
//! $ cargo test -p vtxos-uniffi --test exports -- --ignored
//! ```

use base64::Engine as _;
use enclave_runtime::testing::Enclave as Harness;
use vtxos_uniffi::{decode_record, encode_record, prf_salt, Enclave, Pins, VtxosError};

/// The runtime serving the echo guest: `GUEST_GRPC_WASM`, or where `scripts/build-guest.sh grpc`
/// leaves it.
async fn harness() -> Harness {
    let path = std::env::var_os("GUEST_GRPC_WASM")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
                "../../../../examples/guest-grpc/target/wasm32-wasip2/release/guest-grpc.wasm",
            )
        });
    Harness::builder(std::fs::read(path).expect("the echo guest"))
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
#[ignore = "needs the echo guest: scripts/build-guest.sh grpc"]
async fn register_store_reopen_and_close() {
    let h = harness().await;
    let enclave = Enclave::new(
        h.url(),
        Pins {
            trust_root_pem: Some(pem(&h.trust_root())),
            pcr0: hex::encode(h.pcr0()),
            pcr16: hex::encode(h.pcr16()),
            max_age_secs: 300,
        },
    )
    .unwrap();
    let prf = vec![0x61; 32];
    let record = enclave.register(prf.clone()).await.expect("registered");

    // What the app stores, and reads back.
    let stored = decode_record(encode_record(record.clone())).unwrap();
    assert_eq!(stored.group_key, record.group_key);

    // The reopened key signs in to a call of the guest's own. The echo guest's message with only
    // its payload, field 4, set: `0x22`, a length, the bytes.
    let echo = "/enclave.cosign.v1.SigningSession/Sign".to_string();
    let message = vec![0x22, 2, b'h', b'i'];
    let session = enclave
        .open(stored.clone(), prf)
        .expect("the passkey opens it");
    assert!(session
        .call(echo.clone(), message.clone())
        .await
        .unwrap()
        .ends_with(b"hi"));

    session.close();
    assert!(matches!(
        session.call(echo, message).await,
        Err(VtxosError::Protocol { .. })
    ));
    assert!(matches!(
        enclave.open(stored, vec![0x62; 32]),
        Err(VtxosError::WrongPasskey)
    ));
}

/// The exported session against the echo guest (`scripts/build-guest.sh grpc`): a guest with a
/// wire of its own, reached as bytes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the echo guest: scripts/build-guest.sh grpc"]
async fn a_session_calls_as_bytes() {
    let h = harness().await;
    let enclave = Enclave::new(
        h.url(),
        Pins {
            trust_root_pem: Some(pem(&h.trust_root())),
            pcr0: hex::encode(h.pcr0()),
            pcr16: hex::encode(h.pcr16()),
            max_age_secs: 300,
        },
    )
    .unwrap();
    let prf = vec![0x61; 32];
    let record = enclave.register(prf.clone()).await.expect("registered");
    let session = enclave.open(record, prf).expect("the passkey opens it");

    // The echo guest's message with only its payload, field 4, set: `0x22`, a length, the bytes.
    let echo = "/enclave.cosign.v1.SigningSession/Sign".to_string();
    let message = vec![0x22, 2, b'h', b'i'];
    let reply = session
        .call(echo.clone(), message.clone())
        .await
        .expect("call");
    assert!(reply.ends_with(b"hi"), "{reply:?}");

    let stream = session.stream(echo.clone()).await.expect("stream");
    stream.send(message.clone()).await.unwrap();
    assert!(stream.next().await.unwrap().is_some());
    stream.finish();
    assert_eq!(stream.next().await.unwrap(), None);

    // The guest's own refusal, with its code.
    let refused = session
        .call("/nobody.Home/Knock".into(), vec![])
        .await
        .unwrap_err();
    assert!(
        matches!(refused, VtxosError::Status { code: 12, .. }),
        "{refused}"
    );

    // The phone's half of a round is refused when the commitments do not match the messages.
    assert!(matches!(
        session.sign_round(vec![vec![0x5a; 32]], vec![]),
        Err(VtxosError::Protocol { .. })
    ));

    session.close();
    assert!(matches!(
        session.call(echo, message).await,
        Err(VtxosError::Protocol { .. })
    ));
    assert!(session.sign_round(vec![], vec![]).is_err());
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
    assert!(Enclave::new("https://enclave".into(), bad_pins).is_err());
    assert!(decode_record("{}".into()).is_err());
}
