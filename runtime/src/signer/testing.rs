//! A wallet's side of the DKG and of signing, as the app runs it, for the tests here, the auth
//! routes' and the harness's. Random, where a device may derive it from a PRF instead: nothing on
//! this side can tell the two apart.

use std::collections::BTreeMap;

use threshold::commitment::SigningPackage;
use threshold::dkg::{self, Round1Package, Round1SecretPackage, Round2Package};
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::nonce::{self, SigningCommitments};
use threshold::point;
use threshold::random::mod_n_random;
use threshold::scalar::scalar_to_bytes;
use threshold::signing;

use crate::random::Rng;

use super::dkg::{deal, register, Registered};
use super::signing::{Commitment, WalletRound};

pub struct Wallet {
    pub(crate) round1: Round1SecretPackage,
    /// Round one: what the wallet commits to with `register/options`.
    pub package: Round1Package,
}

impl Wallet {
    pub fn random() -> Self {
        let secret = mod_n_random(&mut Rng);
        let slope = mod_n_random(&mut Rng);
        let (round1, package) =
            dkg::dkg_part1(2, 2, &secret, &[slope], &mut Rng).expect("dkg_part1");
        Self { round1, package }
    }

    pub fn id(&self) -> &Identifier {
        &self.round1.identifier
    }

    /// Parts two and three against what `register/options` answered: the runtime's round one,
    /// its proof checked, and the share it dealt. Returns the share for the runtime, which
    /// `register/verify` carries, the wallet's own key package, and the key's public package.
    pub fn respond(
        &self,
        runtime: &Round1Package,
        dealt: &Round2Package,
    ) -> Result<(Round2Package, KeyPackage, PublicKeyPackage), String> {
        enclave_auth::client::finish_dkg(&self.round1, runtime, dealt)
    }
}

/// The whole registration DKG, both sides: the wallet, what the runtime keeps, and the wallet's
/// key package.
pub fn enrol(master: &[u8; 32], handle: &[u8; 16]) -> (Wallet, Registered, KeyPackage) {
    let wallet = Wallet::random();
    let answer = deal(master, handle, &wallet.package).expect("deal");
    let (to_runtime, key, _) = wallet
        .respond(&answer.package, &answer.dealt)
        .expect("respond");
    let registered = register(master, handle, &wallet.package, &to_runtime).expect("register");
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
            let n = nonce::new_nonce(&mut Rng, &wallet.secret_share);
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
