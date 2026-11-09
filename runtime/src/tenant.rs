//! A tenant: one user, the passkey they registered, and every key their data is opened with.
//!
//! ```text
//!   passkey credential id ──sha256("enclave/tenant/v1" ‖ id)[..16]──► tenant id
//!   passkey PRF output ──HKDF-SHA256(salt "aegira/tenant-key/v1", info tenant id)──► K_t
//!                                     (in the owner's app, never here)
//!   K_t ──HKDF-SHA384(salt fs_uuid, info purpose ‖ pool id)──┬─ signing:    pool anchor key
//!                                                            │              task signing key
//!                                                            └─ encryption: pool disk key
//!                                                                           task seal key
//! ```
//!
//! **The tenant id** is derived from the credential id ([`tenant_of`]): nothing to mint and
//! nothing to store. A credential id is registered once and kept when revoked, so it names one
//! tenant forever. A replacement passkey is a new tenant with an empty pool; a synced passkey is
//! the same credential on every device.
//!
//! **K_t** ([`TenantKey`]) is the root of everything the tenant owns. The owner's app derives it
//! from its passkey's PRF output during the same ceremony that produces the assertion, at
//! registration and at every sign-in, and sends it only after checking this enclave's PCR0 and
//! PCR16 on that connection. It never sends the PRF output itself, which also seeds the wallet's
//! half of the wallet key. A release the app does not approve is never sent K_t, and so can open
//! none of the tenant's data. It is the same on every release, so the data outlives every release,
//! and nothing the enclave or its operator holds can produce it.
//!
//! **What K_t derives** is per pool: `fs_uuid` is the HKDF salt and the pool id is in the info, so
//! one K_t never keys two pools or two filesystems. One key per purpose, so a weakness in one use
//! cannot be pivoted into another:
//! - signing — the pool's anchor key ([`KeyMaterial`]) and its task signing key ([`TaskKeys`]);
//! - encryption — the pool's disk key ([`pool_dmcrypt_key`]) and its task seal key ([`TaskKeys`]).
//!
//! What belongs to a release rather than a tenant — its certificate, its cache of tenant keys —
//! hangs off the release's master secret instead ([`crate::store::crypto::keys`]).

use aws_lc_rs::aead::LessSafeKey;
use aws_lc_rs::hkdf::{KeyType, Salt, HKDF_SHA256};
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::store::crypto::keys::{aes_key, hkdf_raw};
use crate::store::crypto::ED25519_PUBLIC_KEY_LEN;
use crate::store::error::{StoreError, StoreResult};

/// The tenant of a deployment with no gate.
pub const ANONYMOUS: [u8; 16] = [0; 16];

/// The HKDF salt K_t is derived under. Changing it changes every tenant's key, and strands every
/// pool.
pub const KEY_SALT: &[u8] = b"aegira/tenant-key/v1";

/// HKDF info strings for what K_t derives. Versioned so a future format revision can rotate a
/// derived key without changing K_t.
const INFO_POOL_SIGN: &[u8] = b"aegira/pool/anchor-sign/v1";
const INFO_POOL_DMCRYPT: &[u8] = b"aegira/pool/dmcrypt/v1";
/// Sign and seal a tenant's scheduled tasks, which live outside the enclave.
const INFO_TASK_SIGN: &[u8] = b"aegira/pool/task-sign/v1";
const INFO_TASK_SEAL: &[u8] = b"aegira/pool/task-seal/v1";

/// The tenant a credential speaks for: the first sixteen bytes of
/// `sha256("enclave/tenant/v1" || credential_id)`.
///
/// Every tenant's record and pool is named by this, so changing it strands them all;
/// `tenant_of_is_pinned` is what notices.
pub fn tenant_of(credential_id: &[u8]) -> [u8; 16] {
    let digest =
        nitro_attestation::sha256(&[b"enclave/tenant/v1".as_slice(), credential_id].concat());
    digest[..16].try_into().expect("16 bytes")
}

/// One tenant's key, K_t: the root of its pool, and of nothing else. Scrubbed on drop, never
/// printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TenantKey([u8; 32]);

impl TenantKey {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        TenantKey(bytes)
    }

    /// K_t for the tenant `tenant_id`, from its passkey's PRF output: what every client computes.
    ///
    /// SHA-256 rather than the SHA-384 the enclave's own derivations use, because this one is
    /// computed on phones, and every platform has it. The enclave never has a PRF output to call
    /// this with; it is here so the derivation and its pinned vector live beside the key.
    pub fn derive(prf: &[u8], tenant_id: &[u8; 16]) -> Self {
        struct Len32;
        impl KeyType for Len32 {
            fn len(&self) -> usize {
                32
            }
        }
        let mut out = [0u8; 32];
        Salt::new(HKDF_SHA256, KEY_SALT)
            .extract(prf)
            .expand(&[tenant_id], Len32)
            .and_then(|okm| okm.fill(&mut out))
            .expect("32 bytes is within HKDF-SHA256's output limit");
        TenantKey(out)
    }

    /// The raw bytes, for sealing the key into this release's cache.
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constant-time equality, for checking a presented key against the one a tenant's pool was
    /// attached with.
    pub fn ct_eq(&self, other: &TenantKey) -> bool {
        aws_lc_rs::constant_time::verify_slices_are_equal(&self.0, &other.0).is_ok()
    }
}

impl std::fmt::Debug for TenantKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TenantKey(<redacted>)")
    }
}

/// One pool's anchor-signing key.
pub struct KeyMaterial {
    signing_key: Ed25519KeyPair,
    public_key: [u8; ED25519_PUBLIC_KEY_LEN],
    fs_uuid: [u8; 16],
}

impl KeyMaterial {
    /// The signing key of one tenant's pool, from that tenant's key. `fs_uuid` and the pool id
    /// are in every anchor, and neither is a secret.
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

    /// Public half of the anchor-signing key. Written into each anchor so an external auditor
    /// can verify the chain without the master secret.
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
            .field("fs_uuid", &hex::encode(self.fs_uuid))
            .field("public_key", &hex::encode(&self.public_key[..8]))
            .finish_non_exhaustive()
    }
}

/// A pool's disk key: two AES-256 keys, for dm-crypt's XTS.
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

/// What a tenant's scheduled tasks are signed and sealed with.
///
/// Tasks are kept where the host can write — a table, a scheduler, a queue — so each one carries
/// a signature only its tenant's key could make, and its payload is sealed to the same key. The
/// same on every release, as the pool is: a task survives a restart and an upgrade, and is opened
/// by whichever release its owner has approved.
pub struct TaskKeys {
    signing_key: Ed25519KeyPair,
    public_key: [u8; ED25519_PUBLIC_KEY_LEN],
    seal_key: LessSafeKey,
}

impl TaskKeys {
    /// One pool's task keys, from its tenant's key.
    pub fn for_pool(key: &TenantKey, fs_uuid: [u8; 16], pool_id: &[u8; 16]) -> StoreResult<Self> {
        let mut bytes = [0u8; 32];
        hkdf_raw(
            &key.0,
            &fs_uuid,
            &[INFO_TASK_SIGN, pool_id.as_slice()].concat(),
            &mut bytes,
        )?;
        let signing_key = Ed25519KeyPair::from_seed_unchecked(&bytes)
            .map_err(|_| StoreError::Io("Ed25519 key derivation failed".to_string()))?;
        hkdf_raw(
            &key.0,
            &fs_uuid,
            &[INFO_TASK_SEAL, pool_id.as_slice()].concat(),
            &mut bytes,
        )?;
        let seal_key = aes_key(&bytes)?;
        bytes.zeroize();
        let mut public_key = [0u8; ED25519_PUBLIC_KEY_LEN];
        public_key.copy_from_slice(signing_key.public_key().as_ref());
        Ok(TaskKeys {
            signing_key,
            public_key,
            seal_key,
        })
    }

    pub fn signing_key(&self) -> &Ed25519KeyPair {
        &self.signing_key
    }

    pub fn public_key(&self) -> &[u8; ED25519_PUBLIC_KEY_LEN] {
        &self.public_key
    }

    pub fn seal_key(&self) -> &LessSafeKey {
        &self.seal_key
    }
}

impl std::fmt::Debug for TaskKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TaskKeys(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> TenantKey {
        TenantKey::from_bytes([0x5a; 32])
    }

    /// Every tenant's record and pool is named by this value. A change here is every tenant
    /// waking up to an empty pool, so it has to be deliberate.
    #[test]
    fn tenant_of_is_pinned() {
        assert_eq!(
            hex::encode(tenant_of(b"credential")),
            "a0e215ab9e6d4fc553fe89c4d78b844f"
        );
    }

    /// Byte for byte, what every client computes. A change here strands every tenant's pool; the
    /// vector is the one `docs/CLIENT_INTEGRATION.md` publishes.
    #[test]
    fn the_key_derivation_is_pinned() {
        let key = TenantKey::derive(&[0x11; 32], &[0x22; 16]);
        assert_eq!(
            hex::encode(key.expose_secret()),
            "57c4b615bf5da47923a682fed599cc34355bf19467ea46c482f244d13bebde6c"
        );
    }

    /// One PRF output, two tenants: two keys.
    #[test]
    fn the_tenant_id_separates_keys() {
        let a = TenantKey::derive(&[0x11; 32], &[1; 16]);
        let b = TenantKey::derive(&[0x11; 32], &[2; 16]);
        assert!(!a.ct_eq(&b));
    }

    #[test]
    fn tenant_keys_compare_by_value() {
        assert!(tenant().ct_eq(&tenant()));
        assert!(!tenant().ct_eq(&TenantKey::from_bytes([0x5b; 32])));
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

    /// Purpose separation: the signing seed and the dm-crypt key of one pool, from one tenant
    /// key, must not overlap.
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

    /// A task key is its own: not the pool's anchor key, and pinned, because a change strands
    /// every scheduled task's signature.
    #[test]
    fn task_keys_are_their_own_and_pinned() {
        let task = TaskKeys::for_pool(&tenant(), [1u8; 16], &[3u8; 16]).unwrap();
        let anchor = KeyMaterial::for_pool(&tenant(), [1u8; 16], &[3u8; 16]).unwrap();
        assert_ne!(task.public_key(), anchor.public_key());
        assert_eq!(
            hex::encode(task.public_key()),
            "cda19132c27ec714854b5a7bc38d452f845733f01300c6f6678e6e49d16b923d"
        );
        let other = TaskKeys::for_pool(&tenant(), [1u8; 16], &[4u8; 16]).unwrap();
        assert_ne!(task.public_key(), other.public_key());
    }

    /// A key that prints itself is a key in the logs.
    #[test]
    fn secrets_are_redacted_in_debug_output() {
        let t = TenantKey::from_bytes([0xab; 32]);
        assert_eq!(format!("{t:?}"), "TenantKey(<redacted>)");
        let km = KeyMaterial::for_pool(&t, [0u8; 16], &[0u8; 16]).unwrap();
        assert!(!format!("{km:?}").contains("abab"));
        let tk = TaskKeys::for_pool(&t, [0u8; 16], &[0u8; 16]).unwrap();
        assert_eq!(format!("{tk:?}"), "TaskKeys(<redacted>)");
    }
}
