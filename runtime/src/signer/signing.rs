//! One FROST round with a tenant's wallet key, the signer's half.

use std::collections::BTreeMap;

use crate::random::Rng;
use zeroize::Zeroize;

use threshold::commitment::SigningPackage;
use threshold::nonce::{self, SigningCommitments, SigningNonce};
use threshold::point;
use threshold::scalar::scalar_from_bytes;
use threshold::signing::{self, SignatureShare};

use super::key::WalletKey;

/// The signer's commitment for one message, as two compressed points.
pub struct Commitment {
    pub hiding: [u8; 33],
    pub binding: [u8; 33],
}

/// The wallet's half of one message's round: its commitment, and its share over both
/// commitments.
pub struct WalletRound {
    pub hiding: Vec<u8>,
    pub binding: Vec<u8>,
    pub share: Vec<u8>,
}

/// One FROST round over a batch of messages, halfway through.
///
/// One round trip for the whole batch: the signer commits, the wallet answers with its
/// commitment and its share together, and the signer signs and aggregates. Script-path only:
/// the signer signs untweaked, and a key-path tweak is the wallet's to compensate.
///
/// Not `Clone`, and [`Signing::finish`] takes it by value: each message owns a single-use nonce.
pub struct Signing {
    key: WalletKey,
    rounds: Vec<(Vec<u8>, SigningNonce)>,
}

impl Signing {
    /// A fresh nonce for each message, hedged with the signer's share, and its commitment.
    pub fn begin(key: &WalletKey, messages: &[Vec<u8>]) -> (Self, Vec<Commitment>) {
        let rounds: Vec<_> = messages
            .iter()
            .map(|m| {
                (
                    m.clone(),
                    nonce::new_nonce(&mut Rng, &key.key_package().secret_share),
                )
            })
            .collect();
        let commitments = rounds
            .iter()
            .map(|(_, n)| Commitment {
                hiding: point::serialize_compressed(&n.commitments.hiding),
                binding: point::serialize_compressed(&n.commitments.binding),
            })
            .collect();
        (
            Self {
                key: key.clone(),
                rounds,
            },
            commitments,
        )
    }

    /// The wallet's half for each message in, BIP-340 signatures out, in the order the messages
    /// were given.
    ///
    /// `aggregate` checks the wallet's share against its verifying share, so a share that does not
    /// belong to this message and these commitments is refused here.
    pub fn finish(self, wallet: &[WalletRound]) -> Result<Vec<[u8; 64]>, String> {
        if wallet.len() != self.rounds.len() {
            return Err(format!(
                "the wallet answered {} of {} messages",
                wallet.len(),
                self.rounds.len()
            ));
        }
        let ours = self.key.signer().clone();
        let theirs = self.key.wallet().clone();
        self.rounds
            .iter()
            .zip(wallet)
            .enumerate()
            .map(|(i, ((message, nonce), half))| {
                let at = |e: String| format!("message {i}: {e}");
                let commitments = BTreeMap::from([
                    (ours.clone(), nonce.commitments.clone()),
                    (
                        theirs.clone(),
                        SigningCommitments::from_bytes(&half.hiding, &half.binding)
                            .map_err(|e| at(e.to_string()))?,
                    ),
                ]);
                let share: [u8; 32] = half
                    .share
                    .as_slice()
                    .try_into()
                    .map_err(|_| at("the wallet's share must be 32 bytes".into()))?;
                let share = scalar_from_bytes(&share).map_err(|e| at(e.to_string()))?;
                let package = SigningPackage::new(commitments, message.clone());
                let mine = signing::sign(&package, nonce, self.key.key_package())
                    .map_err(|e| at(format!("frost sign: {e}")))?;
                let shares = BTreeMap::from([
                    (ours.clone(), mine),
                    (theirs.clone(), SignatureShare { s: share }),
                ]);
                let signature =
                    signing::aggregate(&package, &shares, self.key.public_key_package())
                        .map_err(|e| at(format!("frost aggregate: {e}")))?;
                Ok(signature.serialize())
            })
            .collect()
    }
}

impl Drop for Signing {
    fn drop(&mut self) {
        for (_, nonce) in &mut self.rounds {
            nonce.hiding.zeroize();
            nonce.binding.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::{answer, enrol};
    use super::*;
    use k256::schnorr::signature::hazmat::PrehashVerifier;

    fn verify(key: &WalletKey, message: &[u8], signature: &[u8; 64]) {
        let vk = k256::schnorr::VerifyingKey::from_bytes(&key.group_key()[1..]).unwrap();
        let sig = k256::schnorr::Signature::try_from(&signature[..]).unwrap();
        vk.verify_prehash(message, &sig)
            .expect("a BIP-340 signature under V");
    }

    #[test]
    fn a_batch_signs_under_the_group_key() {
        let (_, registered, wallet) = enrol(&[7; 32], &[9; 16]);
        let key = registered.key;
        let messages = vec![vec![1u8; 32], vec![2u8; 32]];
        let (signing, commitments) = Signing::begin(&key, &messages);
        let rounds = answer(&wallet, key.signer(), &messages, &commitments);
        for (m, s) in messages.iter().zip(&signing.finish(&rounds).unwrap()) {
            verify(&key, m, s);
        }
    }

    #[test]
    fn every_round_takes_a_fresh_nonce() {
        let (_, registered, _) = enrol(&[7; 32], &[9; 16]);
        let messages = vec![vec![1u8; 32]];
        let (_, a) = Signing::begin(&registered.key, &messages);
        let (_, b) = Signing::begin(&registered.key, &messages);
        assert_ne!(a[0].hiding, b[0].hiding);
    }

    #[test]
    fn a_tampered_wallet_share_is_refused() {
        let (_, registered, wallet) = enrol(&[7; 32], &[9; 16]);
        let key = registered.key;
        let messages = vec![vec![1u8; 32]];
        let (signing, commitments) = Signing::begin(&key, &messages);
        let mut rounds = answer(&wallet, key.signer(), &messages, &commitments);
        rounds[0].share[31] ^= 1;
        assert!(signing.finish(&rounds).is_err());
    }

    #[test]
    fn a_short_answer_is_refused() {
        let (_, registered, wallet) = enrol(&[7; 32], &[9; 16]);
        let key = registered.key;
        let messages = vec![vec![1u8; 32], vec![2u8; 32]];
        let (signing, commitments) = Signing::begin(&key, &messages);
        let rounds = answer(&wallet, key.signer(), &messages[..1], &commitments[..1]);
        assert!(signing.finish(&rounds).is_err());
    }
}
