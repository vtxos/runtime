//! Key hierarchy.
//!
//! Two roots, because two parties hold the state.
//!
//! A tenant's pool is keyed from its [`TenantKey`], which the owner's app
//! derives from its passkey's PRF output and sends with each assertion. It is
//! the same on every release, so a tenant's data survives every release, and
//! nothing the enclave or its operator holds can produce it.
//!
//! What belongs to one release — its TLS certificate, its cache of tenant keys
//! for background work — hangs off a [`MasterSecret`] that KMS releases only
//! to that release's PCR0 and PCR16, through [`VersionKeys`]. A new release
//! gets a new one and inherits none of it.
//!
//! ```text
//!   TenantKey (client)                       MasterSecret (KMS, one release)
//!        │                                         │
//!   HKDF-SHA384(salt = fs_uuid,              HKDF-SHA384(salt = fs_uuid ‖ vid,
//!               info = purpose ‖ pool_id)                info = purpose)
//!     ┌──┴───────────────┐               ┌─────────┼──────────────┐
//!     ▼                  ▼               ▼         ▼              ▼
//!  Ed25519 seed     pool dm-crypt     ACME seal  tenant-key   anonymous
//!  (the pool's      key (AES-XTS)     key        cache key    tenant key
//!   anchors)
//! ```
//!
//! Separate keys per purpose so that a weakness in one use cannot be pivoted
//! into another.

use aws_lc_rs::aead::{LessSafeKey, UnboundKey, AES_256_GCM};
use aws_lc_rs::hkdf::{KeyType, Salt, HKDF_SHA384};
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::store::error::{StoreError, StoreResult};

/// HKDF info strings. Versioned so a future format revision can rotate
/// derived keys without changing the secret they come from.
const INFO_POOL_SIGN: &[u8] = b"aegira/pool/anchor-sign/v1";
const INFO_POOL_DMCRYPT: &[u8] = b"aegira/pool/dmcrypt/v1";
/// Seals the runtime's own secrets — the ACME account key and the TLS
/// certificate's private key — which live in the roots bucket.
///
/// In the bucket rather than on a pool, because a certificate has to be
/// served before anything else is, and a separate label keeps it
/// cryptographically distinct from everything else derived here.
const INFO_RUNTIME_SEAL: &[u8] = b"enclave/runtime-seal/v1";
/// Seals each tenant key this release keeps for background work.
const INFO_TENANT_CACHE: &[u8] = b"aegira/version/tenant-key-cache/v1";
/// The key of the anonymous tenant a deployment with no gate serves.
const INFO_ANONYMOUS: &[u8] = b"aegira/version/anonymous-tenant/v1";

/// Length of an Ed25519 public key and of a raw signing seed.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// The root of the key hierarchy. Scrubbed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterSecret([u8; 32]);

impl MasterSecret {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        MasterSecret(bytes)
    }

    /// The raw bytes.
    ///
    /// Named to be conspicuous at the call site. There is exactly one
    /// legitimate reason to reach in here — sealing the secret so it can be
    /// stored — and everything else should take a `&MasterSecret` and derive
    /// what it needs through [`KeyMaterial`], which is why no plain `as_bytes`
    /// exists.
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parse a 64-character hex string, as supplied by `--data-key` or an
    /// environment variable in development.
    pub fn from_hex(s: &str) -> StoreResult<Self> {
        let s = s.trim();
        if s.len() != 64 {
            return Err(StoreError::Invalid("master key must be 64 hex characters"));
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| StoreError::Invalid("master key is not valid hex"))?;
        }
        Ok(MasterSecret(out))
    }

    /// Generate a fresh random secret. Used when formatting a new filesystem
    /// in development; production keys come from KMS.
    pub fn generate() -> StoreResult<Self> {
        let mut out = [0u8; 32];
        aws_lc_rs::rand::fill(&mut out)
            .map_err(|_| StoreError::Io("system RNG unavailable".to_string()))?;
        Ok(MasterSecret(out))
    }
}

/// Deliberately opaque: a `Debug` that printed the bytes would leak the key
/// into any log line that formats a struct containing one.
impl std::fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterSecret(<redacted>)")
    }
}

/// Arbitrary-length HKDF output.
struct OkmLen(usize);
impl KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-SHA384 over raw input key material.
pub fn hkdf_raw(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> StoreResult<()> {
    let prk = Salt::new(HKDF_SHA384, salt).extract(ikm);
    prk.expand(&[info], OkmLen(out.len()))
        .and_then(|okm| okm.fill(out))
        .map_err(|_| StoreError::Io("HKDF expansion failed".to_string()))
}

/// HKDF-SHA384 from the master secret.
pub fn hkdf(secret: &MasterSecret, salt: &[u8], info: &[u8], out: &mut [u8]) -> StoreResult<()> {
    hkdf_raw(&secret.0, salt, info, out)
}

/// One tenant's key: the root of its pool, and of nothing else. Scrubbed on
/// drop, never printed.
///
/// The owner's app derives it from its passkey's PRF output
/// ([`crate::auth::tenant_key`]) and sends it with an assertion, and only
/// after checking this enclave's PCR0 and PCR16. A release the app does not
/// approve is never sent it, and so can open none of that tenant's data.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TenantKey([u8; 32]);

impl TenantKey {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        TenantKey(bytes)
    }

    /// The raw bytes, for sealing the key into this release's cache.
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constant-time equality, for checking a presented key against the one
    /// a tenant's pool was attached with.
    pub fn ct_eq(&self, other: &TenantKey) -> bool {
        aws_lc_rs::constant_time::verify_slices_are_equal(&self.0, &other.0).is_ok()
    }
}

impl std::fmt::Debug for TenantKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TenantKey(<redacted>)")
    }
}

/// A pool's dm-crypt key: two AES-256 keys, for XTS.
pub fn pool_dmcrypt_key(
    key: &TenantKey,
    fs_uuid: &[u8; 16],
    pool_id: &[u8; 16],
) -> StoreResult<zeroize::Zeroizing<[u8; 64]>> {
    let mut out = zeroize::Zeroizing::new([0u8; 64]);
    hkdf_raw(
        &key.0,
        fs_uuid,
        &[INFO_POOL_DMCRYPT, pool_id.as_slice()].concat(),
        out.as_mut(),
    )?;
    Ok(out)
}

fn aes_key(bytes: &[u8; 32]) -> StoreResult<LessSafeKey> {
    Ok(LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, bytes)
            .map_err(|_| StoreError::Io("AES key setup failed".to_string()))?,
    ))
}

/// What one release keeps for itself, from the master secret KMS releases to
/// it alone.
pub struct VersionKeys {
    runtime_seal_key: LessSafeKey,
    tenant_cache_key: LessSafeKey,
    anonymous: TenantKey,
}

impl VersionKeys {
    /// `salt` names the release: the filesystem id and the release's id, so two
    /// releases under one master secret (a static development key) still keep
    /// apart.
    pub fn derive(master: &MasterSecret, salt: &[u8]) -> StoreResult<Self> {
        let mut bytes = [0u8; 32];
        hkdf(master, salt, INFO_RUNTIME_SEAL, &mut bytes)?;
        let runtime_seal_key = aes_key(&bytes)?;
        hkdf(master, salt, INFO_TENANT_CACHE, &mut bytes)?;
        let tenant_cache_key = aes_key(&bytes)?;
        hkdf(master, salt, INFO_ANONYMOUS, &mut bytes)?;
        let anonymous = TenantKey(bytes);
        bytes.zeroize();
        Ok(VersionKeys {
            runtime_seal_key,
            tenant_cache_key,
            anonymous,
        })
    }

    /// Seals runtime secrets stored outside every pool. See
    /// [`INFO_RUNTIME_SEAL`].
    pub fn runtime_seal_key(&self) -> &LessSafeKey {
        &self.runtime_seal_key
    }

    /// Seals the tenant keys this release keeps for background work.
    pub fn tenant_cache_key(&self) -> &LessSafeKey {
        &self.tenant_cache_key
    }

    /// The anonymous tenant's key, when no gate is configured. A release's
    /// own, so its data lasts only as long as the release.
    pub fn anonymous(&self) -> &TenantKey {
        &self.anonymous
    }
}

impl std::fmt::Debug for VersionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VersionKeys(<redacted>)")
    }
}

/// One pool's anchor-signing key.
pub struct KeyMaterial {
    signing_key: Ed25519KeyPair,
    public_key: [u8; ED25519_PUBLIC_KEY_LEN],
    fs_uuid: [u8; 16],
}

impl KeyMaterial {
    /// The signing key of one tenant's pool, from that tenant's key.
    ///
    /// `fs_uuid` is the HKDF salt and the pool id is in the info, so one
    /// tenant key never signs for two pools or two filesystems. Both are in
    /// every anchor, and neither is a secret.
    pub fn for_pool(key: &TenantKey, fs_uuid: [u8; 16], pool_id: &[u8; 16]) -> StoreResult<Self> {
        let mut seed = [0u8; 32];
        hkdf_raw(
            &key.0,
            &fs_uuid,
            &[INFO_POOL_SIGN, pool_id.as_slice()].concat(),
            &mut seed,
        )?;
        let signing_key = Ed25519KeyPair::from_seed_unchecked(&seed)
            .map_err(|_| StoreError::Io("Ed25519 key derivation failed".to_string()))?;
        seed.zeroize();

        let mut public_key = [0u8; ED25519_PUBLIC_KEY_LEN];
        public_key.copy_from_slice(signing_key.public_key().as_ref());

        Ok(KeyMaterial {
            signing_key,
            public_key,
            fs_uuid,
        })
    }

    pub fn signing_key(&self) -> &Ed25519KeyPair {
        &self.signing_key
    }

    /// Public half of the anchor-signing key. Written into each anchor so an
    /// external auditor can verify the chain without the master secret.
    pub fn public_key(&self) -> &[u8; ED25519_PUBLIC_KEY_LEN] {
        &self.public_key
    }

    pub fn fs_uuid(&self) -> &[u8; 16] {
        &self.fs_uuid
    }
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("fs_uuid", &hex16(&self.fs_uuid))
            .field("public_key", &hex16(&self.public_key[..8]))
            .finish_non_exhaustive()
    }
}

fn hex16(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> TenantKey {
        TenantKey::from_bytes([0x5a; 32])
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = KeyMaterial::for_pool(&tenant(), [1u8; 16], &[3u8; 16]).unwrap();
        let b = KeyMaterial::for_pool(&tenant(), [1u8; 16], &[3u8; 16]).unwrap();
        assert_eq!(a.public_key(), b.public_key());
    }

    /// The salt is what keeps two filesystems apart under one tenant key.
    #[test]
    fn different_fs_uuid_gives_different_keys() {
        let a = KeyMaterial::for_pool(&tenant(), [1u8; 16], &[3u8; 16]).unwrap();
        let b = KeyMaterial::for_pool(&tenant(), [2u8; 16], &[3u8; 16]).unwrap();
        assert_ne!(a.public_key(), b.public_key());
    }

    /// And the pool id two pools, so a tenant key never signs for another pool.
    #[test]
    fn different_pools_get_different_keys() {
        let a = KeyMaterial::for_pool(&tenant(), [1u8; 16], &[3u8; 16]).unwrap();
        let b = KeyMaterial::for_pool(&tenant(), [1u8; 16], &[4u8; 16]).unwrap();
        assert_ne!(a.public_key(), b.public_key());
        let (x, y) = (
            pool_dmcrypt_key(&tenant(), &[1u8; 16], &[3u8; 16]).unwrap(),
            pool_dmcrypt_key(&tenant(), &[1u8; 16], &[4u8; 16]).unwrap(),
        );
        assert_ne!(*x, *y);
    }

    #[test]
    fn different_tenant_keys_give_different_keys() {
        let a = KeyMaterial::for_pool(&TenantKey::from_bytes([1; 32]), [0; 16], &[3; 16]).unwrap();
        let b = KeyMaterial::for_pool(&TenantKey::from_bytes([2; 32]), [0; 16], &[3; 16]).unwrap();
        assert_ne!(a.public_key(), b.public_key());
    }

    /// Purpose separation: the signing seed and the dm-crypt key of one pool,
    /// from one tenant key, must not overlap.
    #[test]
    fn purposes_are_separated() {
        let mut seed = [0u8; 32];
        hkdf_raw(
            &tenant().0,
            &[0u8; 16],
            &[INFO_POOL_SIGN, &[3u8; 16]].concat(),
            &mut seed,
        )
        .unwrap();
        let dm = pool_dmcrypt_key(&tenant(), &[0u8; 16], &[3u8; 16]).unwrap();
        assert_ne!(seed[..], dm[..32]);
    }

    /// Two releases under one master secret — a static development key — must
    /// not share a cache key or an anonymous tenant.
    #[test]
    fn releases_are_separated_by_their_salt() {
        let master = MasterSecret::from_bytes([9; 32]);
        let a = VersionKeys::derive(&master, b"release-a").unwrap();
        let b = VersionKeys::derive(&master, b"release-b").unwrap();
        assert!(!a.anonymous().ct_eq(b.anonymous()));
    }

    #[test]
    fn tenant_keys_compare_by_value() {
        assert!(tenant().ct_eq(&tenant()));
        assert!(!tenant().ct_eq(&TenantKey::from_bytes([0x5b; 32])));
    }

    #[test]
    fn hex_parsing_round_trips() {
        let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let m = MasterSecret::from_hex(hex).unwrap();
        assert_eq!(m.0[0], 0x01);
        assert_eq!(m.0[31], 0x20);
        // Whitespace from a config file or shell is tolerated.
        assert!(MasterSecret::from_hex(&format!("  {hex}\n")).is_ok());
    }

    #[test]
    fn hex_parsing_rejects_bad_input() {
        assert!(MasterSecret::from_hex("abcd").is_err());
        assert!(MasterSecret::from_hex(&"z".repeat(64)).is_err());
        assert!(MasterSecret::from_hex("").is_err());
    }

    #[test]
    fn generate_produces_distinct_secrets() {
        let a = MasterSecret::generate().unwrap();
        let b = MasterSecret::generate().unwrap();
        assert_ne!(a.0, b.0);
        assert_ne!(a.0, [0u8; 32], "RNG returned all zeros");
    }

    /// A key that prints itself is a key in the logs.
    #[test]
    fn secrets_are_redacted_in_debug_output() {
        let m = MasterSecret::from_bytes([0xab; 32]);
        let s = format!("{m:?}");
        assert_eq!(s, "MasterSecret(<redacted>)");
        assert!(!s.contains("ab"));

        let t = TenantKey::from_bytes([0xab; 32]);
        assert_eq!(format!("{t:?}"), "TenantKey(<redacted>)");

        let v = VersionKeys::derive(&m, b"salt").unwrap();
        assert!(!format!("{v:?}").contains("abab"));

        let km = KeyMaterial::for_pool(&t, [0u8; 16], &[0u8; 16]).unwrap();
        let s = format!("{km:?}");
        assert!(!s.contains("abab"));
    }
}
