//! The phone's half of a FROST round, carried inside the stream that needs the signatures.
//!
//! The guest commits first and sends its commitment for each message; the phone answers each with
//! its own commitment and its signature share over both, and the runtime aggregates. Shares are
//! script-path and untweaked: the key is the group key as the DKG made it.

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
use crate::proto::guest::{Commitment, WalletRound};

/// Answer the guest's commitments over `messages`, in order. `cosigner` is the identifier the
/// guest named, which must be the runtime's this wallet was made with.
pub(crate) fn answer(
    key: &KeyPackage,
    runtime: &Identifier,
    cosigner: &str,
    messages: &[Vec<u8>],
    commitments: &[Commitment],
) -> Result<Vec<WalletRound>> {
    if cosigner != hex::encode(runtime.serialize()) {
        return Err(Error::Protocol(format!(
            "the guest signs as {cosigner}, not as the runtime this wallet was made with"
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
                .map_err(|e| Error::Protocol(format!("the guest's commitment: {e}")))?;
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
            Ok(WalletRound {
                hiding: point::serialize_compressed(&ours.commitments.hiding).to_vec(),
                binding: point::serialize_compressed(&ours.commitments.binding).to_vec(),
                share: scalar_to_bytes(&share.s).to_vec(),
            })
        })
        .collect()
}
