//! The 2-of-2 cooperative sign, driven the way the `Sign` stream drives it: the policy commits
//! first, the wallet answers with its commitments and its share together, the policy aggregates.
//! It is the signing session `Send` and `Renew` run, over one message — the wallet cannot commit
//! first any more, because it holds no share until the stream's first answer brings the half the
//! policy dealt it. The user/client half is simulated host-side.
//!
//! The policy's half is the runtime's, played here by `common::Recorder` over `threshold`: the
//! guest asks for a round and hands back the wallet's answer.
//!
//! Persistence is in-process SQLite. The ASP channel is lazy and never used on the signing path.

mod common;

use policy::sign::SigningSession;
use threshold::point;
use threshold::scalar::scalar_from_bytes;
use threshold::signature::Signature;

/// A full round, through the runtime's key, verifies under the group key.
#[test]
fn a_sign_session_verifies_under_the_group_key() {
    let Some(store) = common::try_store() else {
        return;
    };
    let wallet = common::wallet();
    let message = vec![0x42u8; 32];
    let _policy = common::open_holding(&store, &wallet);

    // Round 1. The round leaves the policy with the reply; nothing is parked behind it.
    let (round, theirs) =
        SigningSession::begin(std::slice::from_ref(&message)).expect("round one");
    assert_eq!(theirs.len(), 1, "one message, one commitment");

    // The client's round-trip, with no lock held on the policy.
    let ours = common::wallet_answers(&wallet.user, std::slice::from_ref(&message), &theirs);

    // Round 2. The round goes back in by value and is consumed.
    let signature = round
        .finish(ours)
        .expect("finish")
        .pop()
        .expect("one signature");

    // As the `Sign` stream reports it, and as the wallet's `frostFinish` reads it: R compressed
    // under an even prefix — `aggregate` normalizes it — and z.
    let mut r = [0x02u8; 33];
    r[1..].copy_from_slice(&signature[..32]);
    let z: [u8; 32] = signature[32..].try_into().expect("z is 32 bytes");
    Signature::new(
        point::deserialize_compressed(&r).unwrap(),
        scalar_from_bytes(&z).unwrap(),
    )
    .verify(&wallet.key.public_key_package.verifying_key, &message)
    .expect("aggregated 2-of-2 signature must verify under the group key");
}

/// The property the design rests on: an abandoned ceremony leaves nothing reusable behind.
///
/// A FROST nonce may be used once — signing twice under one nonce leaks the secret share. The round
/// is a value: drop it and the nonce is gone, and a second round on the same policy gets fresh
/// commitments.
#[test]
fn abandoned_ceremony_leaves_no_reusable_nonce() {
    let Some(store) = common::try_store() else {
        return;
    };

    let wallet = common::wallet();
    let message = vec![0x42u8; 32];
    let _policy = common::open_holding(&store, &wallet);

    // Open a round and abandon it, as an interrupted stream does.
    let (_, first) = SigningSession::begin(std::slice::from_ref(&message)).unwrap();
    // Same policy, same message: a second round must not reuse the first one's nonce.
    let (_, second) = SigningSession::begin(std::slice::from_ref(&message)).unwrap();

    assert_ne!(first[0].hiding, second[0].hiding, "hiding commitment must not repeat");
    assert_ne!(first[0].binding, second[0].binding, "binding commitment must not repeat");
}
