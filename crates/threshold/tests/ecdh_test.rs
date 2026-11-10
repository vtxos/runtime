//! Threshold ECDH: the acceptance criteria, and vectors a client can check
//! itself against.
#![cfg(feature = "ecdh")]

use hex_conservative::{DisplayHex, FromHex};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use threshold::ecdh::{self, Partial, PartialBytes, Session};
use threshold::error::Error;
use threshold::identifier::Identifier;
use threshold::point;

/// `f(z) = a0 + a1·z`: the group secret is `f(0) = a0`, and `X = a0·G`.
struct Poly {
    a0: Scalar,
    a1: Scalar,
}

impl Poly {
    fn new(a0: u64, a1: u64) -> Self {
        Poly {
            a0: Scalar::from(a0),
            a1: Scalar::from(a1),
        }
    }

    fn share(&self, id: &Identifier) -> Scalar {
        self.a0 + self.a1 * id.to_scalar()
    }

    fn group_key(&self) -> ProjectivePoint {
        point::base_mul(&self.a0)
    }

    /// What every pair of holders should derive: HKDF over `x·R`, computed
    /// here with the secret no holder ever has.
    fn expected_key(&self) -> [u8; 32] {
        let x = self.group_key();
        let z = ecdh::base_point(&x).unwrap() * self.a0;
        *ecdh::derive_key(&z, &x).unwrap()
    }
}

fn id(n: u16) -> Identifier {
    Identifier::from_u16(n).unwrap()
}

/// Both holders' sides of one session, each finishing with the other's
/// partial. Returns each holder's key.
fn exchange(
    poly: &Poly,
    i: &Identifier,
    j: &Identifier,
    transcript: &[u8],
) -> ([u8; 32], [u8; 32]) {
    let x = poly.group_key();
    let (x_i, x_j) = (poly.share(i), poly.share(j));
    let mut rng = rand::thread_rng();
    let (session_i, partial_i) = Session::start(&x, i, &x_i, transcript, &mut rng).unwrap();
    let (session_j, partial_j) = Session::start(&x, j, &x_j, transcript, &mut rng).unwrap();
    let k_i = session_i
        .finish(j, &point::base_mul(&x_j), &partial_j)
        .unwrap();
    let k_j = session_j
        .finish(i, &point::base_mul(&x_i), &partial_i)
        .unwrap();
    (*k_i, *k_j)
}

/// The same bytes on every call: makes the hedged nonce, and so the whole
/// partial, reproducible for the vectors below.
struct FixedRng(u8);

impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([self.0; 4])
    }
    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes([self.0; 8])
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(self.0);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        dest.fill(self.0);
        Ok(())
    }
}

impl CryptoRng for FixedRng {}

/// RFC 9380, appendix J.8.1: `secp256k1_XMD:SHA-256_SSWU_RO_`.
#[test]
fn hash_to_curve_matches_rfc_9380() {
    const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_";
    let q128 = format!("q128_{}", "q".repeat(128));
    let a512 = format!("a512_{}", "a".repeat(512));
    let vectors: [(&[u8], &str, &str); 5] = [
        (
            b"",
            "c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346",
            "64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e51067",
        ),
        (
            b"abc",
            "3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b",
            "7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6",
        ),
        (
            b"abcdef0123456789",
            "bac54083f293f1fe08e4a70137260aa90783a5cb84d3f35848b324d0674b0e3a",
            "4436476085d4c3c4508b60fcf4389c40176adce756b398bdee27bca19758d828",
        ),
        (
            q128.as_bytes(),
            "e2167bc785333a37aa562f021f1e881defb853839babf52a7f72b102e41890e9",
            "f2401dd95cc35867ffed4f367cd564763719fbc6a53e969fb8496a1e6685d873",
        ),
        (
            a512.as_bytes(),
            "e3c8d35aaaf0b9b647e88a0a0a7ee5d5bed5ad38238152e4e6fd8c1f8cb7c998",
            "8446eeb6181bf12f56a9d24e262221cc2f0c4725c7e3803024b5888ee5823aa6",
        ),
    ];
    for (msg, x, y) in vectors {
        let p = ecdh::hash_to_curve(msg, DST).unwrap();
        let encoded = p.to_affine().to_encoded_point(false);
        assert_eq!(
            encoded.x().unwrap().to_lower_hex_string(),
            x,
            "P.x for {msg:?}"
        );
        assert_eq!(
            encoded.y().unwrap().to_lower_hex_string(),
            y,
            "P.y for {msg:?}"
        );
    }
}

/// With a known polynomial, the key both holders derive is the one over `x·R`.
#[test]
fn the_combined_point_is_x_times_r() {
    let poly = Poly::new(7, 3);
    let (k_1, k_2) = exchange(&poly, &id(1), &id(2), b"session");
    assert_eq!(k_1, poly.expected_key());
    assert_eq!(k_2, poly.expected_key());
}

#[test]
fn both_holders_derive_the_same_key() {
    let poly = Poly::new(123_456_789, 987_654_321);
    let (k_1, k_2) = exchange(&poly, &id(1), &id(2), b"session");
    assert_eq!(k_1, k_2);
}

#[test]
fn a_new_session_derives_the_same_key() {
    let poly = Poly::new(42, 17);
    let (first, _) = exchange(&poly, &id(1), &id(2), b"monday");
    let (second, _) = exchange(&poly, &id(1), &id(2), b"tuesday");
    assert_eq!(first, second);
}

#[test]
fn another_group_key_derives_another_key() {
    let (one, _) = exchange(&Poly::new(42, 17), &id(1), &id(2), b"session");
    let (two, _) = exchange(&Poly::new(43, 17), &id(1), &id(2), b"session");
    assert_ne!(one, two);
}

/// Identifiers here are hash-derived scalars, and a recovery share would sit at
/// another index. Every pair derives the one key.
#[test]
fn any_two_identifiers_derive_the_same_key() {
    let poly = Poly::new(1_000_003, 77);
    let wallet = Identifier::derive(b"wallet").unwrap();
    let runtime = Identifier::derive(b"runtime").unwrap();
    for (i, j) in [
        (wallet.clone(), runtime.clone()),
        (runtime, wallet),
        (id(1), id(3)),
        (id(2), id(3)),
        (id(3), id(1)),
    ] {
        let (k_i, k_j) = exchange(&poly, &i, &j, b"session");
        assert_eq!(k_i, poly.expected_key());
        assert_eq!(k_j, poly.expected_key());
    }
}

#[test]
fn a_holder_claiming_the_other_identifier_is_refused() {
    let poly = Poly::new(42, 17);
    let x = poly.group_key();
    let mut rng = rand::thread_rng();
    let (session, _) = Session::start(&x, &id(1), &poly.share(&id(1)), b"s", &mut rng).unwrap();
    let (_, partial) = Session::start(&x, &id(2), &poly.share(&id(2)), b"s", &mut rng).unwrap();
    let err = session
        .finish(&id(1), &point::base_mul(&poly.share(&id(2))), &partial)
        .unwrap_err();
    assert!(matches!(err, Error::DuplicateIdentifier), "{err:?}");
}

/// Each field of the partial, changed: the session aborts, and never falls
/// back to the unverified point.
#[test]
fn a_tampered_partial_aborts() {
    let poly = Poly::new(42, 17);
    let x = poly.group_key();
    let (x_1, x_2) = (poly.share(&id(1)), poly.share(&id(2)));
    let mut rng = rand::thread_rng();

    let tamperings: [fn(&mut PartialBytes); 4] = [
        |p| {
            p.share = point::serialize_compressed(
                &(point::deserialize_compressed(&p.share).unwrap() + ProjectivePoint::GENERATOR),
            )
        },
        |p| {
            p.a = point::serialize_compressed(
                &(point::deserialize_compressed(&p.a).unwrap() + ProjectivePoint::GENERATOR),
            )
        },
        |p| {
            p.b = point::serialize_compressed(
                &(point::deserialize_compressed(&p.b).unwrap() + ProjectivePoint::GENERATOR),
            )
        },
        |p| p.s[31] ^= 1,
    ];
    for tamper in tamperings {
        let (session, _) = Session::start(&x, &id(1), &x_1, b"s", &mut rng).unwrap();
        let (_, partial) = Session::start(&x, &id(2), &x_2, b"s", &mut rng).unwrap();
        let mut bytes = partial.to_bytes();
        tamper(&mut bytes);
        let tampered = Partial::from_bytes(&bytes).unwrap();
        let err = session
            .finish(&id(2), &point::base_mul(&x_2), &tampered)
            .unwrap_err();
        assert!(matches!(err, Error::InvalidProof), "{err:?}");
    }
}

/// A proof is bound to its session: replayed into another, it fails.
#[test]
fn a_partial_from_another_session_aborts() {
    let poly = Poly::new(42, 17);
    let x = poly.group_key();
    let (x_1, x_2) = (poly.share(&id(1)), poly.share(&id(2)));
    let mut rng = rand::thread_rng();
    let (session, _) = Session::start(&x, &id(1), &x_1, b"today", &mut rng).unwrap();
    let (_, yesterday) = Session::start(&x, &id(2), &x_2, b"yesterday", &mut rng).unwrap();
    let err = session
        .finish(&id(2), &point::base_mul(&x_2), &yesterday)
        .unwrap_err();
    assert!(matches!(err, Error::InvalidProof), "{err:?}");
}

/// A partial made with a share other than the one behind the verifying share
/// it is checked against.
#[test]
fn a_partial_from_the_wrong_share_aborts() {
    let poly = Poly::new(42, 17);
    let x = poly.group_key();
    let mut rng = rand::thread_rng();
    let (session, _) = Session::start(&x, &id(1), &poly.share(&id(1)), b"s", &mut rng).unwrap();
    let impostor = Scalar::from(999u64);
    let (_, partial) = Session::start(&x, &id(2), &impostor, b"s", &mut rng).unwrap();
    let err = session
        .finish(&id(2), &point::base_mul(&poly.share(&id(2))), &partial)
        .unwrap_err();
    assert!(matches!(err, Error::InvalidProof), "{err:?}");
}

#[test]
fn invalid_and_identity_points_are_refused() {
    let poly = Poly::new(42, 17);
    let x = poly.group_key();
    let mut rng = rand::thread_rng();
    let (_, partial) = Session::start(&x, &id(2), &poly.share(&id(2)), b"s", &mut rng).unwrap();
    let good = partial.to_bytes();

    // Not a compressed encoding.
    let mut bad = good.clone();
    bad.share[0] = 0x05;
    assert!(Partial::from_bytes(&bad).is_err());

    // An x with no point on the curve: x = 5 has none on secp256k1.
    let mut off_curve = [0u8; 33];
    off_curve[0] = 0x02;
    off_curve[32] = 5;
    let mut bad = good.clone();
    bad.a = off_curve;
    assert!(Partial::from_bytes(&bad).is_err());

    // The identity has no 33-byte encoding at all.
    let mut bad = good.clone();
    bad.b = [0u8; 33];
    assert!(Partial::from_bytes(&bad).is_err());

    // s at the group order: not canonical.
    let mut bad = good.clone();
    bad.s =
        <[u8; 32]>::from_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .unwrap();
    assert!(matches!(
        Partial::from_bytes(&bad),
        Err(Error::InvalidScalar)
    ));

    // An identity group key or verifying share.
    assert!(ecdh::base_point(&ProjectivePoint::IDENTITY).is_err());
    let (session, _) = Session::start(&x, &id(1), &poly.share(&id(1)), b"s", &mut rng).unwrap();
    let err = session
        .finish(&id(2), &ProjectivePoint::IDENTITY, &partial)
        .unwrap_err();
    assert!(matches!(err, Error::InvalidPoint), "{err:?}");

    // A zero share.
    assert!(Session::start(&x, &id(1), &Scalar::ZERO, b"s", &mut rng).is_err());
}

/// A DKG negates every share when the raw group key has odd Y. Raw or
/// normalised, the shares and group key that belong together derive the key
/// over their own `x·R`. The two keys differ, because `X` differs.
#[test]
fn an_odd_group_key_and_its_normalised_form_each_work() {
    let raw = (1u64..)
        .map(|a0| Poly::new(a0, 5))
        .find(|p| !point::has_even_y(&p.group_key()))
        .unwrap();
    let normalised = Poly {
        a0: -raw.a0,
        a1: -raw.a1,
    };
    assert!(point::has_even_y(&normalised.group_key()));

    let (k_raw, _) = exchange(&raw, &id(1), &id(2), b"s");
    let (k_normalised, _) = exchange(&normalised, &id(1), &id(2), b"s");
    assert_eq!(k_raw, raw.expected_key());
    assert_eq!(k_normalised, normalised.expected_key());
    assert_ne!(k_raw, k_normalised);
}

/// Pinned values a client implementation can check itself against:
/// - `f(z) = 7 + 3z`, so `X = 7·G`;
/// - holders 1 and 2, so λ = (2, −1);
/// - transcript `"aegira-kat"`;
/// - every random byte `0x42`.
///
/// A change here changes every tenant's key.
#[test]
fn known_answers() {
    let poly = Poly::new(7, 3);
    let x = poly.group_key();
    let (x_1, x_2) = (poly.share(&id(1)), poly.share(&id(2)));
    let transcript = b"aegira-kat";

    let r = ecdh::base_point(&x).unwrap();
    let (session_1, partial_1) =
        Session::start(&x, &id(1), &x_1, transcript, &mut FixedRng(0x42)).unwrap();
    let (session_2, partial_2) =
        Session::start(&x, &id(2), &x_2, transcript, &mut FixedRng(0x42)).unwrap();
    let k_1 = session_1
        .finish(&id(2), &point::base_mul(&x_2), &partial_2)
        .unwrap();
    let k_2 = session_2
        .finish(&id(1), &point::base_mul(&x_1), &partial_1)
        .unwrap();
    assert_eq!(*k_1, *k_2);

    let p = partial_1.to_bytes();
    let got = [
        point::serialize_compressed(&r).to_lower_hex_string(),
        p.share.to_lower_hex_string(),
        p.a.to_lower_hex_string(),
        p.b.to_lower_hex_string(),
        p.s.to_lower_hex_string(),
        k_1.to_lower_hex_string(),
    ];
    // Checked against an independent implementation (pure-Python secp256k1
    // and HKDF), not only against this one.
    let want = [
        "0251cc89eb233cc5484ff14079783c9233cc1b85a0ef144fee8f29f0c814caea14",
        "03b1e4e988c0c04c6ae50e4b902e93f3c7a4d459762e91a3230828279fc9b41aa2",
        "038e0e5d08c1e8e798d63acebf9bfacfbe90d43922be4636a6fde90e65ecc5822d",
        "038b25cab42a1c8eeeb3a16bd087a6d28850e26bb34d040f06ef174b29e1e8efde",
        "99b106c9e89440265ce98e4bade3eefb978085b0bbb69235593ed8bafce582a5",
        "c607455d21237800381d7a93b72a0eab6fa842abf15b8cd85688eb5c2460ce74",
    ];
    for (name, (got, want)) in ["R", "D_1", "A_1", "B_1", "s_1", "k"]
        .iter()
        .zip(got.iter().zip(want))
    {
        assert_eq!(got, want, "{name}");
    }
}
