//! A signature made with a guest through `net` and `core` alone.
//!
//! This is what an app does when it runs a guest's conversation itself: open the call as a
//! stream, read the enclave's commitments, answer with the phone's half, and get the signature.
//! The guest is `examples/guest-signer`, whose messages are the bytes themselves.
//!
//! ```sh
//! scripts/build-guest.sh signer
//! cargo test -p vtxos-client --test sign -- --ignored
//! ```

mod common;

use std::sync::Arc;

use bitcoin::secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};
use common::{harness, pins};
use vtxos_client::core::frost::{answer, Commitment};
use vtxos_client::net::{Enclave, Session};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the signer guest: scripts/build-guest.sh signer"]
async fn a_stream_and_the_phones_half_make_a_signature_with_a_guest() {
    let h = harness("signer").await;
    let enclave = Arc::new(Enclave::new(&h.url(), &pins(&h)).unwrap());
    let prf = [0x42; 32];
    let record = enclave.register(&prf).await.expect("registered");
    let session = Session::new(enclave, record.open(&prf).expect("the passkey opens it"));
    let message = vec![0x5a; 32];

    let stream = session
        .stream("/enclave.signer.v1.Signer/Sign")
        .await
        .expect("stream");
    let next = || async { stream.next().await.unwrap().expect("a message") };

    // What to sign. The enclave commits first: who it is, then its two commitments.
    stream.send(&message).await.unwrap();
    let cosigner = hex::encode(next().await);
    let theirs = Commitment {
        hiding: next().await,
        binding: next().await,
    };

    // The phone's half, from `core`, sent back a part at a time.
    let key = session.key();
    let round = answer(
        key.key_package(),
        key.runtime(),
        &cosigner,
        std::slice::from_ref(&message),
        &[theirs],
    )
    .expect("the phone's half")
    .remove(0);
    for part in [round.hiding, round.binding, round.share] {
        stream.send(&part).await.unwrap();
    }

    let signature = next().await;
    stream.finish();
    assert_eq!(stream.next().await.unwrap(), None);

    // It is a BIP-340 signature over the message, under the wallet's key.
    let group_key = hex::decode(&record.group_key).unwrap();
    Secp256k1::verification_only()
        .verify_schnorr(
            &schnorr::Signature::from_slice(&signature).expect("64 bytes"),
            &Message::from_digest(message.try_into().unwrap()),
            &XOnlyPublicKey::from_slice(&group_key[1..]).expect("the group key, x-only"),
        )
        .expect("the wallet's key signed the message");
}
