//! The phone's half of a FROST round.
//!
//! The enclave commits first and sends its commitment for each message; the phone answers each
//! with its own commitment and its signature share over both, and the enclave aggregates. Shares
//! are script-path and untweaked: the key is the group key as the DKG made it.
//!
//! Plain types in and out. Whatever carries them to the enclave, a policy's messages or the
//! wallet's, is the caller's.

use std::collections::BTreeMap;

use rand_core::OsRng;
use threshold::commitment::SigningPackage;
use threshold::identifier::Identifier;
use threshold::keys::KeyPackage;
use threshold::nonce::{self, SigningCommitments};
use threshold::point;
use threshold::scalar::scalar_to_bytes;
use threshold::signing;

use crate::error::{Error, Result};

/// One side's commitment for one message: two compressed points, 33 bytes each.
#[derive(Debug, Clone)]
pub struct Commitment {
    pub hiding: Vec<u8>,
    pub binding: Vec<u8>,
}

/// The phone's half of one message's round: its commitment, and its share over both commitments,
/// 32 bytes big-endian.
#[derive(Debug, Clone)]
pub struct Round {
    pub hiding: Vec<u8>,
    pub binding: Vec<u8>,
    pub share: Vec<u8>,
}

/// Answer the enclave's commitments over `messages`, in order. `cosigner` is the identifier the
/// enclave signs as, which must be the runtime's this wallet was made with.
pub fn answer(
    key: &KeyPackage,
    runtime: &Identifier,
    cosigner: &str,
    messages: &[Vec<u8>],
    commitments: &[Commitment],
) -> Result<Vec<Round>> {
    if cosigner != hex::encode(runtime.serialize()) {
        return Err(Error::Protocol(format!(
            "the enclave signs as {cosigner}, not as the runtime this wallet was made with"
        )));
    }
    if messages.len() != commitments.len() {
        return Err(Error::Protocol(format!(
            "{} messages but {} commitments",
            messages.len(),
            commitments.len()
        )));
    }
    messages
        .iter()
        .zip(commitments)
        .map(|(message, theirs)| {
            let theirs = SigningCommitments::from_bytes(&theirs.hiding, &theirs.binding)
                .map_err(|e| Error::Protocol(format!("the enclave's commitment: {e}")))?;
            let ours = nonce::new_nonce(&mut OsRng, &key.secret_share);
            let package = SigningPackage::new(
                BTreeMap::from([
                    (runtime.clone(), theirs),
                    (key.identifier.clone(), ours.commitments.clone()),
                ]),
                message.clone(),
            );
            let share = signing::sign(&package, &ours, key)
                .map_err(|e| Error::Protocol(format!("signing share: {e}")))?;
            Ok(Round {
                hiding: point::serialize_compressed(&ours.commitments.hiding).to_vec(),
                binding: point::serialize_compressed(&ours.commitments.binding).to_vec(),
                share: scalar_to_bytes(&share.s).to_vec(),
            })
        })
        .collect()
}
