//! Two-party threshold ECDH: both holders of a 2-of-2 key derive the same
//! symmetric key, and neither ever reconstructs the group secret `x`.
//!
//! ```text
//!   R   = hash_to_curve(compressed(X))      suite secp256k1_XMD:SHA-256_SSWU_RO_ (RFC 9380)
//!   D_i = x_i·R                              each holder, with a Chaum-Pedersen proof
//!                                            that log_G(Y_i) = log_R(D_i)
//!   Z   = λ_i·D_i + λ_j·D_j  (= x·R)         Lagrange over the two identifiers
//!   k   = HKDF-SHA256(ikm = compressed(Z), info = KEY_INFO ‖ compressed(X))
//! ```
//!
//! `R` depends only on `X`, so every qualifying pair of shares derives the same
//! `k`: today the wallet's and the runtime's, later a recovery share's.
//! Repeating the protocol gives the same `k`; another `X` gives another.
//!
//! **The proof.** A holder sends `(D_i, A, B, s)`:
//! - `n` is fresh;
//! - `A = n·G` and `B = n·R`;
//! - `c = H(G, Y_i, R, D_i, A, B, transcript)`;
//! - `s = n + c·x_i`.
//!
//! The other holder checks `s·G == A + c·Y_i` and `s·R == B + c·D_i`, and
//! aborts if either fails. It never falls back to an unverified `D`. The
//! transcript binds a proof to its session.
//!
//! **What is kept.** Nothing. `R` is recomputed each time. A [`Session`] holds
//! its own `D_i` only until [`Session::finish`] consumes it, and zeroizes it on
//! drop. The proof nonce, `Z` and the HKDF input are zeroized as soon as they
//! are used. [`Partial`] and [`Session`] print redacted.
//!
//! **Limits.**
//! - A holder that keeps `Z` or `k` can derive `k` again without the other.
//! - Both shares together expose it.
//! - Both holders must be online.

use alloc::vec::Vec;

use hkdf::Hkdf;
use k256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use k256::elliptic_curve::zeroize::{Zeroize, Zeroizing};
use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, ProjectivePoint, Scalar, Secp256k1};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;

use crate::error::Error;
use crate::hash::tagged_hash;
use crate::identifier::Identifier;
use crate::lagrange::lagrange_coeff_at_zero;
use crate::point;
use crate::scalar::scalar_to_bytes;

/// The hash-to-curve domain separation tag. RFC 9380's form is
/// `<application>-V<xx>-CS<yy>-<suite id>`. Changing it changes every `R`,
/// and so every key derived here.
pub const HASH_TO_CURVE_DST: &[u8] = b"aegira-v1-secp256k1_XMD:SHA-256_SSWU_RO_";

/// The HKDF info prefix. The group key follows it, so two group keys never
/// share a derivation.
pub const KEY_INFO: &[u8] = b"aegira-v1-session-key";

/// Tags the proof's challenge, as a BIP-340 tagged hash.
const DLEQ_TAG: &str = "aegira/ecdh/dleq/v1";
/// Tags the proof nonce's derivation.
const NONCE_TAG: &str = "aegira/ecdh/nonce/v1";

/// `hash_to_curve(msg)` under the suite `secp256k1_XMD:SHA-256_SSWU_RO_`, with
/// the caller's domain separation tag. [`base_point`] is this with
/// [`HASH_TO_CURVE_DST`].
pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> Result<ProjectivePoint, Error> {
    let point = Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[msg], &[dst])
        .map_err(|_| Error::InvalidPoint)?;
    if point::is_identity(&point) {
        return Err(Error::InvalidPoint);
    }
    Ok(point)
}

/// `R = hash_to_curve(compressed(X))`: the point each holder multiplies its
/// share into. Recomputed every time, never stored.
pub fn base_point(group_key: &ProjectivePoint) -> Result<ProjectivePoint, Error> {
    if point::is_identity(group_key) {
        return Err(Error::InvalidPoint);
    }
    hash_to_curve(&point::serialize_compressed(group_key), HASH_TO_CURVE_DST)
}

/// The last step: `k = HKDF-SHA256(ikm = compressed(Z), info = KEY_INFO ‖
/// compressed(X))`, with no salt. Public so that the derivation can be checked
/// and published as vectors; a session calls it with the `Z` it combined.
pub fn derive_key(
    z: &ProjectivePoint,
    group_key: &ProjectivePoint,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    if point::is_identity(z) || point::is_identity(group_key) {
        return Err(Error::InvalidPoint);
    }
    let ikm = Zeroizing::new(point::serialize_compressed(z));
    let mut info = Vec::with_capacity(KEY_INFO.len() + 33);
    info.extend_from_slice(KEY_INFO);
    info.extend_from_slice(&point::serialize_compressed(group_key));

    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, ikm.as_slice())
        .expand(&info, key.as_mut_slice())
        .map_err(|_| Error::SerializationError)?;
    Ok(key)
}

/// What one holder sends the other: its partial `D_i` and the proof that it
/// was made with the share behind `Y_i`.
///
/// `D_i` is half of `Z`, so it is zeroized on drop and never printed. Send it
/// only over a channel to a holder you have authenticated.
#[derive(Clone)]
pub struct Partial {
    share: ProjectivePoint,
    a: ProjectivePoint,
    b: ProjectivePoint,
    s: Scalar,
}

/// A [`Partial`] on the wire: compressed points and a big-endian scalar.
#[derive(Clone)]
pub struct PartialBytes {
    pub share: [u8; 33],
    pub a: [u8; 33],
    pub b: [u8; 33],
    pub s: [u8; 32],
}

impl Partial {
    /// The wire form.
    pub fn to_bytes(&self) -> PartialBytes {
        PartialBytes {
            share: point::serialize_compressed(&self.share),
            a: point::serialize_compressed(&self.a),
            b: point::serialize_compressed(&self.b),
            s: scalar_to_bytes(&self.s),
        }
    }

    /// From the wire form. Refuses any point that is not on the curve or is
    /// the identity, and an `s` that is not below the group order. A value
    /// reduced mod n would be another encoding of the same proof.
    pub fn from_bytes(bytes: &PartialBytes) -> Result<Self, Error> {
        let share = decode_point(&bytes.share)?;
        let a = decode_point(&bytes.a)?;
        let b = decode_point(&bytes.b)?;
        let s = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::clone_from_slice(&bytes.s)))
            .ok_or(Error::InvalidScalar)?;
        Ok(Partial { share, a, b, s })
    }

    /// Check the proof against `Y_i`, the verifying share of the holder that
    /// sent it, under `X` and this session's transcript. [`Session::finish`]
    /// does this itself. It is public so that a caller can refuse a bad
    /// partial before it fetches its own share.
    pub fn verify(
        &self,
        group_key: &ProjectivePoint,
        verifying_share: &ProjectivePoint,
        transcript: &[u8],
    ) -> Result<(), Error> {
        self.verify_on(&base_point(group_key)?, verifying_share, transcript)
    }

    fn verify_on(
        &self,
        base: &ProjectivePoint,
        verifying_share: &ProjectivePoint,
        transcript: &[u8],
    ) -> Result<(), Error> {
        for p in [verifying_share, &self.share, &self.a, &self.b] {
            if point::is_identity(p) {
                return Err(Error::InvalidPoint);
            }
        }
        let c = challenge(
            verifying_share,
            base,
            &self.share,
            &self.a,
            &self.b,
            transcript,
        );
        let on_g = point::points_equal(&point::base_mul(&self.s), &(self.a + verifying_share * &c));
        let on_r = point::points_equal(&(base * &self.s), &(self.b + self.share * c));
        if on_g && on_r {
            Ok(())
        } else {
            Err(Error::InvalidProof)
        }
    }
}

impl Drop for Partial {
    fn drop(&mut self) {
        self.share.zeroize();
    }
}

impl core::fmt::Debug for Partial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Partial { <redacted> }")
    }
}

impl Drop for PartialBytes {
    fn drop(&mut self) {
        self.share.zeroize();
    }
}

impl core::fmt::Debug for PartialBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PartialBytes { <redacted> }")
    }
}

/// One holder's side of a session. [`Session::start`] makes it along with the
/// partial to send, and [`Session::finish`] consumes it once the other
/// holder's partial arrives. Until then it holds this holder's `D_i`, which it
/// zeroizes when dropped, finished or not.
pub struct Session {
    group_key: ProjectivePoint,
    base: ProjectivePoint,
    identifier: Identifier,
    share: ProjectivePoint,
    transcript: Vec<u8>,
}

impl Session {
    /// Start a session as the holder of `secret_share` under `identifier`.
    ///
    /// `secret_share` is the share exactly as the key package holds it, after
    /// the DKG's even-Y normalisation; its verifying share is what the other
    /// holder checks the proof against. `transcript` must be the same on both
    /// sides, and should be unique to the session.
    pub fn start(
        group_key: &ProjectivePoint,
        identifier: &Identifier,
        secret_share: &Scalar,
        transcript: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Session, Partial), Error> {
        if bool::from(secret_share.is_zero()) {
            return Err(Error::InvalidZeroScalar);
        }
        let base = base_point(group_key)?;
        let verifying_share = point::base_mul(secret_share);
        let share = base * secret_share;

        let n = Zeroizing::new(proof_nonce(secret_share, &share, transcript, rng));
        let a = point::base_mul(&n);
        let b = base * *n;
        let c = challenge(&verifying_share, &base, &share, &a, &b, transcript);
        let s = *n + c * secret_share;

        let session = Session {
            group_key: *group_key,
            base,
            identifier: identifier.clone(),
            share,
            transcript: transcript.to_vec(),
        };
        Ok((session, Partial { share, a, b, s }))
    }

    /// Finish with the other holder's partial and its verifying share:
    /// verify its proof, combine `Z`, derive `k`.
    ///
    /// Aborts with [`Error::InvalidProof`] if the proof fails,
    /// [`Error::DuplicateIdentifier`] if the other holder claims this one's
    /// identifier, and [`Error::InvalidPoint`] for an identity point or `Z`.
    pub fn finish(
        self,
        peer: &Identifier,
        peer_verifying_share: &ProjectivePoint,
        partial: &Partial,
    ) -> Result<Zeroizing<[u8; 32]>, Error> {
        if *peer == self.identifier {
            return Err(Error::DuplicateIdentifier);
        }
        partial.verify_on(&self.base, peer_verifying_share, &self.transcript)?;

        let set = [self.identifier.clone(), peer.clone()];
        let mut z = self.share * lagrange_coeff_at_zero(&self.identifier, &set)
            + partial.share * lagrange_coeff_at_zero(peer, &set);
        let key = derive_key(&z, &self.group_key);
        z.zeroize();
        key
    }
}

impl Zeroize for Session {
    fn zeroize(&mut self) {
        self.share.zeroize();
        self.transcript.zeroize();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Session { <redacted> }")
    }
}

/// A compressed point, and nothing else. The SEC1 decoder also takes the
/// 33-byte compact form (tag `0x05`), which would give one point two encodings.
fn decode_point(bytes: &[u8; 33]) -> Result<ProjectivePoint, Error> {
    if !matches!(bytes[0], 0x02 | 0x03) {
        return Err(Error::InvalidPoint);
    }
    let p = point::deserialize_compressed(bytes)?;
    if point::is_identity(&p) {
        return Err(Error::InvalidPoint);
    }
    Ok(p)
}

/// `c = H(G, Y, R, D, A, B, transcript)`: a BIP-340 tagged hash, reduced mod n,
/// over the compressed points and then the transcript. The points are fixed
/// width, so the transcript needs no length prefix.
fn challenge(
    verifying_share: &ProjectivePoint,
    base: &ProjectivePoint,
    share: &ProjectivePoint,
    a: &ProjectivePoint,
    b: &ProjectivePoint,
    transcript: &[u8],
) -> Scalar {
    let mut msg = Zeroizing::new(Vec::with_capacity(6 * 33 + transcript.len()));
    for p in [
        &ProjectivePoint::GENERATOR,
        verifying_share,
        base,
        share,
        a,
        b,
    ] {
        msg.extend_from_slice(&point::serialize_compressed(p));
    }
    msg.extend_from_slice(transcript);
    tagged_hash(DLEQ_TAG, &msg)
}

/// A fresh nonce for every proof. It is hedged: a tagged hash over the share,
/// the partial, the transcript and 32 random bytes. A broken RNG then still
/// gives a different nonce for a different transcript, and a repeated nonce
/// across two transcripts would hand the other holder this one's share.
fn proof_nonce(
    secret_share: &Scalar,
    share: &ProjectivePoint,
    transcript: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> Scalar {
    let secret = Zeroizing::new(scalar_to_bytes(secret_share));
    let partial = Zeroizing::new(point::serialize_compressed(share));
    loop {
        let mut random = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(random.as_mut_slice());

        let mut input = Zeroizing::new(Vec::with_capacity(32 + 33 + transcript.len() + 32));
        input.extend_from_slice(secret.as_slice());
        input.extend_from_slice(partial.as_slice());
        input.extend_from_slice(transcript);
        input.extend_from_slice(random.as_slice());

        let n = tagged_hash(NONCE_TAG, &input);
        if !bool::from(n.is_zero()) {
            return n;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Counter(u8);
    impl RngCore for Counter {
        fn next_u32(&mut self) -> u32 {
            self.0 = self.0.wrapping_add(1);
            u32::from(self.0)
        }
        fn next_u64(&mut self) -> u64 {
            u64::from(self.next_u32())
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0 = self.0.wrapping_add(1);
            dest.fill(self.0);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for Counter {}

    /// After a session ends, nothing secret is left in its state.
    #[test]
    fn a_session_keeps_nothing_once_it_ends() {
        let x = Scalar::from(11u64);
        let group_key = point::base_mul(&x);
        let id = Identifier::from_u16(1).unwrap();
        let (mut session, _partial) =
            Session::start(&group_key, &id, &x, b"transcript", &mut Counter(0)).unwrap();
        assert!(!point::is_identity(&session.share));

        session.zeroize();
        assert!(
            point::is_identity(&session.share),
            "D_i survived the session"
        );
        assert!(session.transcript.is_empty());
    }

    /// Two proofs over two transcripts never share a nonce, even from an RNG
    /// that returns the same bytes every time.
    #[test]
    fn a_stuck_rng_still_gives_each_transcript_its_own_nonce() {
        struct Stuck;
        impl RngCore for Stuck {
            fn next_u32(&mut self) -> u32 {
                0
            }
            fn next_u64(&mut self) -> u64 {
                0
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                dest.fill(0);
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
                dest.fill(0);
                Ok(())
            }
        }
        impl CryptoRng for Stuck {}

        let x = Scalar::from(5u64);
        let share = point::base_mul(&x);
        let one = proof_nonce(&x, &share, b"one", &mut Stuck);
        let two = proof_nonce(&x, &share, b"two", &mut Stuck);
        assert_ne!(one, two);
    }
}
