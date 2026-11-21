//! The phone's share of the wallet key, from a passkey.
//!
//! The wallet key is made at registration by a 2-of-2 DKG with the runtime. The phone's share is
//! `x_w = ±(f_w(id_w) + f_c(id_w))`: its own polynomial at its own identifier, plus the share the
//! runtime dealt it, negated when `dkg_part3` normalised the key to even Y.
//!
//! - `f_w` comes from the passkey: its PRF output, at [`prf_salt`], through HKDF, gives the two
//!   coefficients, and with them `id_w`. Nothing of it is stored.
//! - Everything else is in the [`WalletRecord`], which the app keeps: the runtime's dealt share
//!   `f_c(id_w)` and the public parts of the key. Without the passkey none of it rebuilds the
//!   share, so the record may live in ordinary, backed-up storage. Without the record, the
//!   passkey alone rebuilds nothing either: keep both.

use hkdf::Hkdf;
use k256::elliptic_curve::bigint::U512;
use k256::elliptic_curve::ops::Reduce;
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, VerifyingKey};
use threshold::point;
use threshold::polynomial::evaluate_polynomial;
use threshold::scalar::scalar_from_bytes_allow_zero;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};

/// What the app asks its passkey's PRF to evaluate: `sha256("vtxos/wallet/prf/v1")`.
pub fn prf_salt() -> [u8; 32] {
    Sha256::digest(b"vtxos/wallet/prf/v1").into()
}

const HKDF_SALT: &[u8] = b"vtxos/wallet/v1";

/// The phone's DKG polynomial, `f_w(z) = a0 + a1·z`. Scrubbed on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Polynomial {
    pub a0: Scalar,
    pub a1: Scalar,
}

impl Polynomial {
    /// From the passkey's PRF output: each coefficient is 64 bytes of HKDF-SHA256, reduced mod n.
    pub fn from_prf(prf: &[u8; 32]) -> Self {
        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), prf);
        let coefficient = |info: &[u8]| {
            let mut wide = Zeroizing::new([0u8; 64]);
            hkdf.expand(info, wide.as_mut())
                .expect("64 bytes is a valid HKDF length");
            <Scalar as Reduce<U512>>::reduce(U512::from_be_slice(wide.as_ref()))
        };
        Polynomial {
            a0: coefficient(b"dkg/a0"),
            a1: coefficient(b"dkg/a1"),
        }
    }

    /// `id_w = SHA256(a0·G) mod n`, as `dkg_part1` derives it.
    pub fn identifier(&self) -> Result<Identifier> {
        Identifier::derive(&point::serialize_compressed(&point::base_mul(&self.a0)))
            .map_err(|e| Error::Protocol(format!("the wallet's identifier: {e}")))
    }

    fn at(&self, id: &Identifier) -> Scalar {
        evaluate_polynomial(id, &[self.a0, self.a1])
    }
}

/// What the app keeps for a wallet. None of it is secret on its own: with the passkey it rebuilds
/// the phone's share, and without the passkey it rebuilds nothing. Hex throughout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletRecord {
    /// `X`, compressed and even-Y: the wallet key.
    pub group_key: String,
    /// The tenant the runtime keeps this wallet under, `sha256("aegira/tenant/v1" ‖ X)[..16]`.
    pub tenant_id: String,
    /// `id_w`, the phone's FROST identifier.
    pub identifier: String,
    /// `Y_w = x_w·G`: what a rebuilt share must match.
    pub verifying_share: String,
    /// `id_c`, the runtime's FROST identifier.
    pub runtime_identifier: String,
    /// `Y_c`, the runtime's verifying share: its ECDH partials are checked against it.
    pub runtime_verifying_share: String,
    /// `f_c(id_w)`, the share the runtime dealt the phone at registration.
    pub dealt_share: String,
}

impl WalletRecord {
    /// The record for a wallet just registered.
    pub fn new(client: &enclave_auth::client::Client, dealt_share: &[u8; 32]) -> Self {
        let key = client.key_package();
        WalletRecord {
            group_key: hex::encode(client.group_key()),
            tenant_id: hex::encode(client.tenant()),
            identifier: hex::encode(key.identifier.serialize()),
            verifying_share: hex::encode(point::serialize_compressed(&key.verifying_share)),
            runtime_identifier: hex::encode(client.runtime().serialize()),
            runtime_verifying_share: hex::encode(point::serialize_compressed(
                client.runtime_share(),
            )),
            dealt_share: hex::encode(dealt_share),
        }
    }

    /// The phone's share, rebuilt from the passkey's PRF output, as a signing client. Refused,
    /// as [`Error::WrongPasskey`], when the passkey is not the one the wallet was made with.
    pub fn open(&self, prf: &[u8; 32]) -> Result<enclave_auth::client::Client> {
        let polynomial = Polynomial::from_prf(prf);
        let identifier = Identifier::deserialize(&hex_array(&self.identifier, "identifier")?)
            .map_err(|e| Error::Protocol(format!("the record's identifier: {e}")))?;
        if polynomial.identifier()? != identifier {
            return Err(Error::WrongPasskey);
        }
        let dealt = Zeroizing::new(hex_array::<32>(&self.dealt_share, "dealt_share")?);
        let dealt = scalar_from_bytes_allow_zero(&dealt)
            .map_err(|e| Error::Protocol(format!("the record's dealt share: {e}")))?;
        let verifying_share = point_of(&self.verifying_share, "verifying_share")?;

        let sum = polynomial.at(&identifier) + dealt;
        let secret_share = [sum, -sum]
            .into_iter()
            .find(|s| point::base_mul(s) == verifying_share)
            .ok_or(Error::WrongPasskey)?;

        let key = KeyPackage {
            identifier,
            secret_share,
            verifying_share,
            verifying_key: VerifyingKey::deserialize(&hex_array(&self.group_key, "group_key")?)
                .map_err(|e| Error::Protocol(format!("the record's group key: {e}")))?,
            min_signers: 2,
        };
        let runtime =
            Identifier::deserialize(&hex_array(&self.runtime_identifier, "runtime_identifier")?)
                .map_err(|e| Error::Protocol(format!("the record's runtime identifier: {e}")))?;
        let runtime_share = point_of(&self.runtime_verifying_share, "runtime_verifying_share")?;
        Ok(enclave_auth::client::Client::new(
            key,
            runtime,
            runtime_share,
        ))
    }
}

fn point_of(text: &str, field: &str) -> Result<ProjectivePoint> {
    point::deserialize_compressed(&hex_array(text, field)?)
        .map_err(|e| Error::Protocol(format!("the record's {field}: {e}")))
}

fn hex_array<const N: usize>(text: &str, field: &str) -> Result<[u8; N]> {
    hex::decode(text)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| Error::Protocol(format!("the record's {field} is not {N} bytes of hex")))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rand_core::OsRng;
    use threshold::dkg;
    use threshold::keys::KeyPackage;
    use threshold::random::mod_n_random;
    use threshold::scalar::scalar_to_bytes;

    use super::*;

    fn share_bytes(client: &enclave_auth::client::Client) -> [u8; 32] {
        scalar_to_bytes(&client.key_package().secret_share)
    }

    /// One registration's DKG, both sides in process: the phone from `prf`, the runtime random.
    /// Returns the phone's key package, the runtime's identifier and verifying share, and the
    /// share the runtime dealt the phone.
    fn register(prf: &[u8; 32]) -> (KeyPackage, Identifier, ProjectivePoint, [u8; 32]) {
        let ours = Polynomial::from_prf(prf);
        let (w1, w_pkg) = dkg::dkg_part1(2, 2, &ours.a0, &[ours.a1], &mut OsRng).unwrap();
        let (a0, a1) = (mod_n_random(&mut OsRng), mod_n_random(&mut OsRng));
        let (c1, c_pkg) = dkg::dkg_part1(2, 2, &a0, &[a1], &mut OsRng).unwrap();
        let (w_id, c_id) = (w1.identifier.clone(), c1.identifier.clone());

        let (w2, mut to_runtime) =
            dkg::dkg_part2(&w1, &BTreeMap::from([(c_id.clone(), c_pkg.clone())]), &[]).unwrap();
        let (c2, mut to_wallet) =
            dkg::dkg_part2(&c1, &BTreeMap::from([(w_id.clone(), w_pkg.clone())]), &[]).unwrap();
        let dealt = to_wallet.remove(&w_id).unwrap();
        let (key, public) = dkg::dkg_part3(
            &w1,
            &w2,
            &BTreeMap::from([(c_id.clone(), c_pkg)]),
            &BTreeMap::from([(c_id.clone(), dealt.clone())]),
            &[],
        )
        .unwrap();
        let _ = (c2, to_runtime.remove(&c_id));
        let runtime_share = public.verifying_shares[&c_id];
        (
            key,
            c_id,
            runtime_share,
            scalar_to_bytes(&dealt.secret_share),
        )
    }

    fn record(
        key: &KeyPackage,
        runtime: &Identifier,
        share: &ProjectivePoint,
        dealt: &[u8; 32],
    ) -> WalletRecord {
        let client = enclave_auth::client::Client::new(key.clone(), runtime.clone(), *share);
        WalletRecord::new(&client, dealt)
    }

    /// The share comes back from the passkey and the record alone, whichever way `dkg_part3`
    /// normalised the key: over enough registrations both signs occur.
    #[test]
    fn the_passkey_and_the_record_rebuild_the_share() {
        let mut negated = [false, false];
        for seed in 0u8..16 {
            let prf = [seed; 32];
            let (key, runtime, share, dealt) = register(&prf);
            let opened = record(&key, &runtime, &share, &dealt).open(&prf).unwrap();
            assert_eq!(share_bytes(&opened), scalar_to_bytes(&key.secret_share));
            let sum = Polynomial::from_prf(&prf).at(&key.identifier)
                + scalar_from_bytes_allow_zero(&dealt).unwrap();
            negated[usize::from(sum != key.secret_share)] = true;
        }
        assert_eq!(negated, [true, true], "both normalisations were exercised");
    }

    #[test]
    fn another_passkey_opens_nothing() {
        let (key, runtime, share, dealt) = register(&[1; 32]);
        let err = record(&key, &runtime, &share, &dealt)
            .open(&[2; 32])
            .unwrap_err();
        assert!(matches!(err, Error::WrongPasskey), "{err}");
    }

    /// The right passkey with someone else's dealt share is refused, not turned into a key.
    #[test]
    fn a_tampered_record_opens_nothing() {
        let (key, runtime, share, _) = register(&[3; 32]);
        let err = record(&key, &runtime, &share, &[7; 32])
            .open(&[3; 32])
            .unwrap_err();
        assert!(matches!(err, Error::WrongPasskey), "{err}");
    }

    /// The derivation is part of every wallet's identity: changing it strands them all. The salt
    /// and both coefficients were recomputed independently (Python's hashlib and hmac: HKDF-SHA256,
    /// then the 64 bytes mod n), and the identifier is `dkg_part1`'s for that `a0`.
    #[test]
    fn the_derivation_is_pinned() {
        assert_eq!(
            hex::encode(prf_salt()),
            "15dbba7f13ac94f1d554a5de01e3fc0a056e0c405ea0cdc71fcf135f58755fa3"
        );
        let p = Polynomial::from_prf(&[0x11; 32]);
        assert_eq!(
            hex::encode(scalar_to_bytes(&p.a0)),
            "9c89fcda317108d164e9814671bdc76823ebc3f0e078de7d47bfc697edae308a"
        );
        assert_eq!(
            hex::encode(scalar_to_bytes(&p.a1)),
            "4710a70ef5ce4c6b9e2faa9d70ca69eafda14e1e08234d3bff8c151b502716e4"
        );
        assert_eq!(
            hex::encode(p.identifier().unwrap().serialize()),
            "83f60fa4a17f3f221f039dbcb31613e46fc2f829e686f4f205e4b08fd92b9bec"
        );
    }
}
