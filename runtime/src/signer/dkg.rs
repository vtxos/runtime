//! The signer's half of the wallet key's DKG, run inside registration.
//!
//! A wallet key is a 2-of-2 FROST key between the owner's wallet and the signer, made by a
//! Pedersen DKG. The signer's polynomial is not random: it is derived from the operator master
//! and a handle the registration mints, so it is never stored, only its handle. The master alone
//! signs nothing: the signer's share is `f_c(id_c) + f_w(id_c)`, and `f_w` is the wallet's.
//!
//! The ceremony is two messages, and the wallet commits first:
//!
//! - `register/options` brings the wallet's round one: its commitment and a proof of knowledge of
//!   its secret, nothing secret. [`deal`] answers with the signer's round one and the share it
//!   deals the wallet, so the wallet can finish its share before the second message.
//! - `register/verify` brings the share the wallet dealt `id_c`, and [`register`] finishes the
//!   key. The wallet's signature and ECDH partial ride with it, made with the share it just
//!   finished, so registration ends with the tenant's pool created.
//!
//! The signer reveals its commitment only after the wallet has committed to its own, and its
//! polynomial is derived inside attested code from a fresh handle: it cannot steer the key.

use std::collections::BTreeMap;

use crate::random::Rng;
use hkdf::Hkdf;
use k256::elliptic_curve::bigint::U512;
use k256::elliptic_curve::ops::Reduce;
use k256::Scalar;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use threshold::dkg::{
    self, Round1Package, Round1SecretPackage, Round2Package, Round2SecretPackage,
};
use threshold::identifier::Identifier;
use threshold::polynomial;
use threshold::scalar::scalar_to_bytes;

use super::key::WalletKey;

/// The HKDF salt for the signer's polynomial.
pub const SALT: &[u8] = b"aegira/cosigner-dkg/v1";

/// What [`deal`] answers the wallet's round one with.
pub struct Deal {
    /// The signer's round-one package: its commitment and proof of knowledge.
    pub package: Round1Package,
    /// `f_c(id_w)`: the share the signer deals the wallet.
    pub dealt: Round2Package,
}

/// The signer's answer to a wallet's round one: its own round one, and the share it deals the
/// wallet. Nothing is kept: [`register`] derives the same polynomial again from the handle.
///
/// Fails if the wallet's proof of knowledge does not verify.
pub fn deal(master: &[u8; 32], handle: &[u8; 16], wallet: &Round1Package) -> Result<Deal, String> {
    let dealer = Dealer::new(master, handle, wallet)?;
    let dealt = dealer
        .shares
        .get(&dealer.wallet)
        .cloned()
        .ok_or("dkg_part2 dealt the wallet nothing")?;
    Ok(Deal {
        package: dealer.package.clone(),
        dealt,
    })
}

/// What [`register`] leaves.
pub struct Registered {
    /// The signer's round-one package, for the wallet's part three.
    pub package: Round1Package,
    /// `f_c(id_w)`: the share the signer deals the wallet.
    pub dealt: Round2Package,
    pub key: WalletKey,
}

/// The signer's whole DKG: the wallet's round one and the share it dealt the signer in; the
/// signer's round one, the share it deals the wallet, and the key out.
///
/// Fails if the wallet's proof of knowledge does not verify, or its share does not match its
/// commitment.
pub fn register(
    master: &[u8; 32],
    handle: &[u8; 16],
    wallet: &Round1Package,
    from_wallet: &Round2Package,
) -> Result<Registered, String> {
    let dealer = Dealer::new(master, handle, wallet)?;
    let id = dealer.wallet.clone();
    let dealt = dealer
        .shares
        .get(&id)
        .cloned()
        .ok_or("dkg_part2 dealt the wallet nothing")?;
    let (key_package, public_key_package) = dkg::dkg_part3(
        &dealer.round1,
        &dealer.round2,
        &BTreeMap::from([(id.clone(), wallet.clone())]),
        &BTreeMap::from([(id, from_wallet.clone())]),
        &[],
    )
    .map_err(|e| format!("dkg_part3: {e}"))?;
    Ok(Registered {
        package: dealer.package.clone(),
        dealt,
        key: WalletKey::new(key_package, public_key_package, *handle),
    })
}

/// `f_c(id_w)`, the share the signer dealt the wallet that is `wallet`, recomputed.
///
/// Raw, as dealt: `dkg_part3` may negate the wallet's share for even Y, and the wallet resolves
/// that against its own verifying share.
pub fn dealt_share(
    master: &[u8; 32],
    handle: &[u8; 16],
    wallet: &Identifier,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let coefficients = coefficients(master, handle, wallet)?;
    let share = polynomial::evaluate_polynomial(wallet, &coefficients[..]);
    Ok(Zeroizing::new(scalar_to_bytes(&share)))
}

/// The signer's polynomial for the wallet that is `wallet`: `a0_c` from the handle, and `a1_c`
/// from the handle and the wallet.
///
/// `id_w` is in the slope's seed because a degree-1 polynomial is recovered from any two of its
/// points: two wallets dealt to under one handle get points on two different lines through
/// `a0_c`, which do not combine.
fn coefficients(
    master: &[u8; 32],
    handle: &[u8; 16],
    wallet: &Identifier,
) -> Result<Zeroizing<[Scalar; 2]>, String> {
    let a0 = derive(master, &[&handle[..], &[0]])?;
    let a1 = derive(master, &[&handle[..], &wallet.serialize()[..], &[1]])?;
    Ok(Zeroizing::new([*a0, *a1]))
}

/// One coefficient: `HKDF-SHA256(master, SALT, info)`, 64 bytes reduced mod n, zero refused.
fn derive(master: &[u8; 32], info: &[&[u8]]) -> Result<Zeroizing<Scalar>, String> {
    let mut okm = Zeroizing::new([0u8; 64]);
    Hkdf::<Sha256>::new(Some(SALT), master)
        .expand_multi_info(info, &mut okm[..])
        .map_err(|e| format!("hkdf: {e}"))?;
    let a = <Scalar as Reduce<U512>>::reduce(U512::from_be_slice(&okm[..]));
    if bool::from(a.is_zero()) {
        return Err("the signer's polynomial has a zero coefficient".into());
    }
    Ok(Zeroizing::new(a))
}

/// The signer's DKG against one wallet's round one, with its secrets scrubbed on drop.
struct Dealer {
    wallet: Identifier,
    round1: Round1SecretPackage,
    package: Round1Package,
    round2: Round2SecretPackage,
    shares: BTreeMap<Identifier, Round2Package>,
}

impl Dealer {
    fn new(master: &[u8; 32], handle: &[u8; 16], wallet: &Round1Package) -> Result<Self, String> {
        // What the wallet's `dkg_part1` derived its identifier from, and what `dkg_part2` checks
        // its proof of knowledge against.
        let id = Identifier::derive(&wallet.commitment.to_verifying_key().serialize())
            .map_err(|e| format!("the wallet's identifier: {e}"))?;
        let a = coefficients(master, handle, &id)?;
        // Derives `id_c` from `a0_c·G`.
        let (round1, package) = dkg::dkg_part1(2, 2, &a[0], &a[1..], &mut Rng)
            .map_err(|e| format!("dkg_part1: {e}"))?;
        let (round2, shares) = dkg::dkg_part2(
            &round1,
            &BTreeMap::from([(id.clone(), wallet.clone())]),
            &[],
        )
        .map_err(|e| format!("dkg_part2: {e}"))?;
        Ok(Self {
            wallet: id,
            round1,
            package,
            round2,
            shares,
        })
    }
}

impl Drop for Dealer {
    fn drop(&mut self) {
        self.round1.coefficients.zeroize();
        self.round2.secret_share.zeroize();
        for share in self.shares.values_mut() {
            share.secret_share.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::{enrol, Wallet};
    use super::*;
    use threshold::scalar::scalar_from_bytes;

    const MASTER: [u8; 32] = [7; 32];
    const HANDLE: [u8; 16] = [9; 16];

    /// What `register/options` answers with is what `register/verify` finishes: the polynomial
    /// is derived again, not kept.
    #[test]
    fn the_deal_is_the_round_one_registration_finishes_with() {
        let w = Wallet::random();
        let d = deal(&MASTER, &HANDLE, &w.package).unwrap();
        let (to_signer, _, _) = w.respond(&d.package, &d.dealt).unwrap();
        let registered = register(&MASTER, &HANDLE, &w.package, &to_signer).unwrap();
        assert_eq!(
            registered.package.verifying_key.serialize(),
            d.package.verifying_key.serialize()
        );
        assert_eq!(registered.dealt.secret_share, d.dealt.secret_share);
    }

    #[test]
    fn both_sides_end_with_the_same_key() {
        let (wallet, registered, kp) = enrol(&MASTER, &HANDLE);
        assert_eq!(registered.key.group_key(), kp.verifying_key.serialize());
        assert_eq!(registered.key.wallet(), wallet.id());
        assert_eq!(registered.key.handle(), &HANDLE);
    }

    #[test]
    fn the_same_handle_rebuilds_the_same_key() {
        let w = Wallet::random();
        let d = deal(&MASTER, &HANDLE, &w.package).unwrap();
        let (to_signer, _, _) = w.respond(&d.package, &d.dealt).unwrap();
        let first = register(&MASTER, &HANDLE, &w.package, &to_signer).unwrap();
        let again = register(&MASTER, &HANDLE, &w.package, &to_signer).unwrap();
        assert_eq!(first.key.group_key(), again.key.group_key());
        assert_eq!(first.key.secret_share(), again.key.secret_share());
    }

    #[test]
    fn each_handle_and_master_gets_its_own_signer() {
        let w = Wallet::random();
        let id = |master, handle| {
            deal(master, handle, &w.package)
                .unwrap()
                .package
                .verifying_key
                .serialize()
        };
        assert_ne!(id(&MASTER, &HANDLE), id(&MASTER, &[8; 16]));
        assert_ne!(id(&MASTER, &HANDLE), id(&[6; 32], &HANDLE));
    }

    #[test]
    fn two_wallets_under_one_handle_share_only_the_secret() {
        let (a, b) = (Wallet::random(), Wallet::random());
        let ca = coefficients(&MASTER, &HANDLE, a.id()).unwrap();
        let cb = coefficients(&MASTER, &HANDLE, b.id()).unwrap();
        assert_eq!(ca[0], cb[0], "one opening per handle");
        assert_ne!(ca[1], cb[1], "two lines through it, which do not combine");
    }

    #[test]
    fn the_dealt_share_completes_the_wallets_share() {
        let (wallet, registered, kp) = enrol(&MASTER, &HANDLE);
        let dealt = dealt_share(&MASTER, &HANDLE, wallet.id()).unwrap();
        assert_eq!(*dealt, scalar_to_bytes(&registered.dealt.secret_share));
        let own = polynomial::evaluate_polynomial(wallet.id(), &wallet.round1.coefficients);
        let rebuilt = own + scalar_from_bytes(&dealt).unwrap();
        assert!(rebuilt == kp.secret_share || -rebuilt == kp.secret_share);
    }

    #[test]
    fn a_share_off_the_wallets_commitment_is_refused() {
        let w = Wallet::random();
        let d = deal(&MASTER, &HANDLE, &w.package).unwrap();
        let (mut forged, _, _) = w.respond(&d.package, &d.dealt).unwrap();
        forged.secret_share += Scalar::ONE;
        assert!(register(&MASTER, &HANDLE, &w.package, &forged).is_err());
    }

    #[test]
    fn a_bad_proof_of_knowledge_is_refused() {
        let mut w = Wallet::random();
        w.package.proof_of_knowledge.z += Scalar::ONE;
        assert!(deal(&MASTER, &HANDLE, &w.package).is_err());
    }
}
