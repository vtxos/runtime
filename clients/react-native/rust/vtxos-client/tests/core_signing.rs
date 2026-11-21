//! `core`'s half of a signing round, against the runtime's own signer: the two halves make a
//! signature the runtime accepts, with nothing in between but the plain values `core` trades in.

use enclave_runtime::signer::signing::{Signing, WalletRound};
use enclave_runtime::signer::testing::enrol;
use vtxos_client::core::frost::{answer, Commitment};

#[test]
fn the_phones_half_and_the_runtimes_make_a_signature() {
    // A registration's DKG, both sides: what the runtime keeps, and the phone's key package.
    let (_, registered, phone) = enrol(&[7; 32], &[1; 16]);
    let runtime = registered.key.signer();
    let cosigner = hex::encode(runtime.serialize());
    let messages = vec![vec![0xaa; 32], vec![0xbb; 32]];

    // The runtime commits first.
    let (signing, commitments) = Signing::begin(&registered.key, &messages);
    let commitments: Vec<Commitment> = commitments
        .iter()
        .map(|c| Commitment {
            hiding: c.hiding.to_vec(),
            binding: c.binding.to_vec(),
        })
        .collect();

    // The phone answers, and the runtime checks each share before it aggregates.
    let rounds =
        answer(&phone, runtime, &cosigner, &messages, &commitments).expect("the phone's half");
    let rounds: Vec<WalletRound> = rounds
        .into_iter()
        .map(|r| WalletRound {
            hiding: r.hiding,
            binding: r.binding,
            share: r.share,
        })
        .collect();
    let signatures = signing.finish(&rounds).expect("the runtime aggregates");
    assert_eq!(signatures.len(), messages.len());

    // A round the enclave signs under another identifier is not answered.
    assert!(answer(&phone, runtime, "00", &messages, &commitments).is_err());
    // Nor one whose commitments do not match its messages.
    assert!(answer(&phone, runtime, &cosigner, &messages, &commitments[..1]).is_err());
}
