//! Against the runtime itself, in process (`enclave_runtime::testing`), serving the echo guest
//! (`examples/guest-grpc`): a real TLS handshake, real attestation documents under the harness's
//! root, and the real sign-in gate.
//!
//! ```console
//! $ scripts/build-guest.sh grpc
//! $ cargo test -p vtxos-client --test runtime -- --ignored --test-threads=1
//! ```

mod common;

use std::sync::Arc;

use common::{harness, pins};
use vtxos_client::net::{Enclave, Session};
use vtxos_client::Error;

/// A passkey registers a key; the record and the same passkey open it again; the opened key signs
/// in to a call of the guest's own.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the echo guest: scripts/build-guest.sh grpc"]
async fn a_passkey_registers_a_key_that_signs_in_to_the_guest() {
    let h = harness("grpc").await;
    let enclave = Arc::new(Enclave::new(&h.url(), &pins(&h)).unwrap());
    let prf = [0x42; 32];
    let record = enclave.register(&prf).await.expect("registered");

    let session = Session::new(
        enclave,
        record.open(&prf).expect("the passkey opens its key"),
    );
    // The echo guest's message with only its payload, field 4, set: `0x22`, a length, the bytes.
    let reply = session
        .call(
            "/enclave.cosign.v1.SigningSession/Sign",
            &[0x22, 2, b'h', b'i'],
        )
        .await
        .expect("signed in, and answered");
    assert!(reply.ends_with(b"hi"), "{reply:?}");

    assert!(matches!(record.open(&[0x43; 32]), Err(Error::WrongPasskey)));
}

/// An enclave running another guest is refused before anything secret goes out.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the echo guest: scripts/build-guest.sh grpc"]
async fn another_guest_is_refused_at_registration() {
    let h = harness("grpc").await;
    let mut pins = pins(&h);
    pins.pcr16 = vec![0; 48];
    let enclave = Enclave::new(&h.url(), &pins).unwrap();
    let err = enclave.register(&[0x42; 32]).await.unwrap_err();
    assert!(matches!(err, Error::Attestation(_)), "{err}");
}

/// A document under a root the app does not pin is refused the same way.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the echo guest: scripts/build-guest.sh grpc"]
async fn another_root_is_refused() {
    let h = harness("grpc").await;
    let mut pins = pins(&h);
    pins.trust_root = enclave_client::AWS_NITRO_ROOT_G1_PEM.as_bytes().to_vec();
    let enclave = Enclave::new(&h.url(), &pins).unwrap();
    let err = enclave.register(&[0x42; 32]).await.unwrap_err();
    assert!(matches!(err, Error::Attestation(_)), "{err}");
}
