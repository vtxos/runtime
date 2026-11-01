//! A wallet's side of the DKG and of signing, as the app runs it, for the tests here and in the
//! auth routes. Random, where a device derives it from the passkey's PRF: nothing on this side can
//! tell the two apart.

use std::collections::BTreeMap;

use rand_core::OsRng;

use threshold::commitment::SigningPackage;
use threshold::dkg::{
    self, Round1Package, Round1SecretPackage, Round2Package, Round2SecretPackage,
};
use threshold::identifier::Identifier;
use threshold::keys::KeyPackage;
use threshold::nonce::{self, SigningCommitments};
use threshold::point;
use threshold::random::mod_n_random;
use threshold::scalar::scalar_to_bytes;
use threshold::signing;

use super::dkg::{opening, register, Opening, Registered};
use super::signing::{Commitment, WalletRound};

pub struct Wallet {
    pub(crate) round1: Round1SecretPackage,
    /// Round one: what the wallet sends with `register/verify`.
    pub package: Round1Package,
    /// The signer the wallet dealt to, and its part two, kept for part three.
    dealt: Option<(Identifier, [u8; 33], Round2SecretPackage)>,
}

impl Wallet {
    pub fn random() -> Self {
        let secret = mod_n_random(&mut OsRng);
        let slope = mod_n_random(&mut OsRng);
        let (round1, package) =
            dkg::dkg_part1(2, 2, &secret, &[slope], &mut OsRng).expect("dkg_part1");
        Self {
            round1,
            package,
            dealt: None,
        }
    }

    pub fn id(&self) -> &Identifier {
        &self.round1.identifier
    }

    /// Part two against the signer's opening, before its round one exists: its proof checked,
    /// then the share for it.
    pub fn deal(&mut self, opening: &Opening) -> Result<Round2Package, String> {
        let vk = opening.verifying_key.serialize();
        if Identifier::derive(&vk).map_err(|e| e.to_string())? != opening.identifier {
            return Err("the opening's identifier is not its key's".into());
        }
        dkg::verify_proof_of_knowledge(&opening.identifier, &opening.verifying_key, &opening.proof)
            .map_err(|e| e.to_string())?;
        let (round2, mut out) = dkg::dkg_part2(
            &self.round1,
            &BTreeMap::new(),
            std::slice::from_ref(&opening.identifier),
        )
        .map_err(|e| e.to_string())?;
        let share = out
            .remove(&opening.identifier)
            .ok_or("no share for the signer")?;
        self.dealt = Some((opening.identifier.clone(), vk, round2));
        Ok(share)
    }

    /// Part three with the signer's round one and the share it dealt: the wallet's key package.
    /// Its round one must open with the key the opening committed to.
    pub fn finish(
        &self,
        signer: &Round1Package,
        dealt: &Round2Package,
    ) -> Result<KeyPackage, String> {
        let (id, vk, round2) = self.dealt.as_ref().ok_or("no opening dealt to")?;
        if signer.commitment.coeffs.len() != 2 || signer.verifying_key.serialize() != *vk {
            return Err("the signer's round one is not what it opened with".into());
        }
        let (key, _) = dkg::dkg_part3(
            &self.round1,
            round2,
            &BTreeMap::from([(id.clone(), signer.clone())]),
            &BTreeMap::from([(id.clone(), dealt.clone())]),
            &[],
        )
        .map_err(|e| e.to_string())?;
        Ok(key)
    }
}

/// The whole registration DKG, both sides: the wallet, what the signer keeps, and the wallet's
/// key package.
pub fn enrol(master: &[u8; 32], handle: &[u8; 16]) -> (Wallet, Registered, KeyPackage) {
    let mut wallet = Wallet::random();
    let to_signer = wallet
        .deal(&opening(master, handle).expect("opening"))
        .expect("deal");
    let registered = register(master, handle, &wallet.package, &to_signer).expect("register");
    let key = wallet
        .finish(&registered.package, &registered.dealt)
        .expect("finish");
    (wallet, registered, key)
}

/// The wallet's half of a signing round, over the signer's commitments.
pub fn answer(
    wallet: &KeyPackage,
    signer: &Identifier,
    messages: &[Vec<u8>],
    commitments: &[Commitment],
) -> Vec<WalletRound> {
    messages
        .iter()
        .zip(commitments)
        .map(|(m, c)| {
            let n = nonce::new_nonce(&mut OsRng, &wallet.secret_share);
            let package = SigningPackage::new(
                BTreeMap::from([
                    (
                        signer.clone(),
                        SigningCommitments::from_bytes(&c.hiding, &c.binding)
                            .expect("the signer's commitment"),
                    ),
                    (wallet.identifier.clone(), n.commitments.clone()),
                ]),
                m.clone(),
            );
            let share = signing::sign(&package, &n, wallet).expect("the wallet's share");
            WalletRound {
                hiding: point::serialize_compressed(&n.commitments.hiding).to_vec(),
                binding: point::serialize_compressed(&n.commitments.binding).to_vec(),
                share: scalar_to_bytes(&share.s).to_vec(),
            }
        })
        .collect()
}
