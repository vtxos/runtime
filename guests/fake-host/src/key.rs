//! The runtime's half of the wallet key, as this host plays it.
//!
//! A stand-in, not the runtime's code: a plain 2-of-2 made with `threshold`, the cosigner's
//! polynomial random where the runtime derives it from the operator master, and the DKG in two
//! calls where the runtime runs it inside the passkey's registration. The component sees only the
//! public package, the dealt share and the signing rounds, so it cannot tell; how the runtime
//! derives its half is the runtime's to test.

use std::collections::BTreeMap;

use rand_core::OsRng;
use threshold::commitment::SigningPackage;
use threshold::dkg::{self, Round1Package, Round1SecretPackage, Round2Package, Round2SecretPackage};
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::nonce::{self, SigningCommitments, SigningNonce};
use threshold::random::mod_n_random;
use threshold::scalar::{scalar_from_bytes, scalar_to_bytes};
use threshold::signing::{self, SignatureShare};

/// The cosigner's reply to the wallet's round one.
pub struct Round1 {
    pub cosigner: Identifier,
    pub package: Round1Package,
    /// `f_c(id_w)`.
    pub dealt: Round2Package,
}

/// The cosigner's state between its two calls.
pub(crate) struct Pending {
    round1: Round1SecretPackage,
    round2: Round2SecretPackage,
    wallet: Identifier,
    dealt: Vec<u8>,
}

/// The cosigner's share of the wallet key, with the key's public package.
#[derive(Clone)]
pub struct WalletKey {
    pub(crate) key_package: KeyPackage,
    pub public_key_package: PublicKeyPackage,
    pub wallet: Identifier,
    /// `f_c(id_w)`, as dealt.
    pub dealt: Vec<u8>,
}

impl WalletKey {
    pub fn group_key(&self) -> [u8; 33] {
        self.public_key_package.verifying_key.serialize()
    }

    pub fn cosigner(&self) -> &Identifier {
        &self.key_package.identifier
    }
}

/// Round one, the cosigner's half: a random polynomial, checked against the wallet's proof.
pub(crate) fn round1(wallet: &Round1Package) -> Result<(Round1, Pending), String> {
    let (secret, slope) = (mod_n_random(&mut OsRng), mod_n_random(&mut OsRng));
    let (round1, package) =
        dkg::dkg_part1(2, 2, &secret, &[slope], &mut OsRng).map_err(|e| e.to_string())?;
    let id = Identifier::derive(&wallet.commitment.to_verifying_key().serialize())
        .map_err(|e| e.to_string())?;
    let (round2, mut shares) =
        dkg::dkg_part2(&round1, &BTreeMap::from([(id.clone(), wallet.clone())]), &[])
            .map_err(|e| e.to_string())?;
    let dealt = shares.remove(&id).ok_or("no share for the wallet")?;
    let reply = Round1 {
        cosigner: round1.identifier.clone(),
        package,
        dealt: dealt.clone(),
    };
    let pending = Pending {
        round1,
        round2,
        wallet: id,
        dealt: scalar_to_bytes(&dealt.secret_share).to_vec(),
    };
    Ok((reply, pending))
}

/// Round two, the cosigner's half: the wallet's share in, the key out.
pub(crate) fn finish(
    pending: Pending,
    wallet: &Round1Package,
    from_wallet: &Round2Package,
) -> Result<WalletKey, String> {
    let (key_package, public_key_package) = dkg::dkg_part3(
        &pending.round1,
        &pending.round2,
        &BTreeMap::from([(pending.wallet.clone(), wallet.clone())]),
        &BTreeMap::from([(pending.wallet.clone(), from_wallet.clone())]),
        &[],
    )
    .map_err(|e| e.to_string())?;
    Ok(WalletKey {
        key_package,
        public_key_package,
        wallet: pending.wallet,
        dealt: pending.dealt,
    })
}

/// The wallet's half of one message's round: its hiding and binding commitments, and its share.
pub(crate) type Half = (Vec<u8>, Vec<u8>, Vec<u8>);

/// The cosigner's commitment for one message: hiding and binding, compressed.
pub(crate) type Commitment = ([u8; 33], [u8; 33]);

/// A round halfway through: one nonce per message, until `finish`.
pub(crate) struct Signing {
    key: WalletKey,
    rounds: Vec<(Vec<u8>, SigningNonce)>,
}

impl Signing {
    /// The cosigner's commitment for each message, as two compressed points.
    pub(crate) fn begin(key: &WalletKey, messages: &[Vec<u8>]) -> (Self, Vec<Commitment>) {
        let rounds: Vec<_> = messages
            .iter()
            .map(|m| (m.clone(), nonce::new_nonce(&mut OsRng, &key.key_package.secret_share)))
            .collect();
        let commitments = rounds
            .iter()
            .map(|(_, n)| {
                (
                    threshold::point::serialize_compressed(&n.commitments.hiding),
                    threshold::point::serialize_compressed(&n.commitments.binding),
                )
            })
            .collect();
        (Self { key: key.clone(), rounds }, commitments)
    }

    /// The wallet's commitment and share for each message in, BIP-340 signatures out.
    pub(crate) fn finish(self, wallet: &[Half]) -> Result<Vec<Vec<u8>>, String> {
        if wallet.len() != self.rounds.len() {
            return Err(format!("the wallet answered {} of {} messages", wallet.len(), self.rounds.len()));
        }
        let ours = self.key.key_package.identifier.clone();
        let theirs = self.key.wallet.clone();
        self.rounds
            .iter()
            .zip(wallet)
            .enumerate()
            .map(|(i, ((message, nonce), (hiding, binding, share)))| {
                let at = |e: String| format!("message {i}: {e}");
                let commitments = BTreeMap::from([
                    (ours.clone(), nonce.commitments.clone()),
                    (
                        theirs.clone(),
                        SigningCommitments::from_bytes(hiding, binding).map_err(|e| at(e.to_string()))?,
                    ),
                ]);
                let share: [u8; 32] =
                    share.as_slice().try_into().map_err(|_| at("share must be 32 bytes".into()))?;
                let share = scalar_from_bytes(&share).map_err(|e| at(e.to_string()))?;
                let package = SigningPackage::new(commitments, message.clone());
                let mine = signing::sign(&package, nonce, &self.key.key_package)
                    .map_err(|e| at(format!("frost sign: {e}")))?;
                let shares =
                    BTreeMap::from([(ours.clone(), mine), (theirs.clone(), SignatureShare { s: share })]);
                signing::aggregate(&package, &shares, &self.key.public_key_package)
                    .map(|s| s.serialize().to_vec())
                    .map_err(|e| at(format!("frost aggregate: {e}")))
            })
            .collect()
    }
}
