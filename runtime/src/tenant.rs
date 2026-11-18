//! A tenant: one user, the wallet key they share with the runtime, and every key their data is
//! opened with.
//!
//! ```text
//!   group key X ──sha256("aegira/tenant/v1" ‖ X)[..16]──► tenant id
//!   the client's share + the runtime's share ──threshold ECDH on X──► k
//!   k ──HKDF-SHA384(salt fs_uuid, info purpose ‖ pool id)──┬─ signing:    pool anchor key
//!                                                          │              task signing key
//!                                                          └─ encryption: pool disk key
//!                                                                         task seal key
//! ```
//!
//! **The tenant id** is derived from the wallet's group public key ([`tenant_of`]): nothing to
//! mint and nothing to store. Every share of that key, today's or a later recovery share, belongs
//! to the same `X`, so losing one share never changes who the tenant is.
//!
//! **k** ([`TenantKey`]) is the root of everything the tenant owns. Neither side holds it: each
//! sign-in that needs it derives it by threshold ECDH ([`threshold::ecdh`]) between the client's
//! share, which never leaves the client, and the runtime's ([`crate::signer`]). Any qualifying
//! pair of shares derives the same `k`, so the data outlives every release and every device. The
//! client sends its half only to a release whose attestation it has checked, so a release it does
//! not approve can open none of the tenant's data.
//!
//! **What k derives** is per pool: `fs_uuid` is the HKDF salt and the pool id is in the info, so
//! one `k` never keys two pools or two filesystems. One key per purpose, so a weakness in one use
//! cannot be pivoted into another:
//! - signing — the pool's anchor key ([`KeyMaterial`]) and its task signing key ([`TaskKeys`]);
//! - encryption — the pool's disk key ([`pool_dmcrypt_key`]) and its task seal key ([`TaskKeys`]).
//!
//! What belongs to a release rather than a tenant — its certificate, its cache of tenant keys —
//! hangs off the release's master secret instead ([`crate::store::crypto::keys`]).

use aws_lc_rs::aead::LessSafeKey;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::store::crypto::keys::{aes_key, hkdf_raw};
use crate::store::crypto::ED25519_PUBLIC_KEY_LEN;
use crate::store::error::{StoreError, StoreResult};

/// The tenant of a deployment with no gate.
pub const ANONYMOUS: [u8; 16] = [0; 16];

/// HKDF info strings for what `k` derives. Versioned so a future format revision can rotate a
/// derived key without changing `k`.
const INFO_POOL_SIGN: &[u8] = b"aegira/pool/anchor-sign/v1";
const INFO_POOL_DMCRYPT: &[u8] = b"aegira/pool/dmcrypt/v1";
/// Sign and seal a tenant's scheduled tasks, which live outside the enclave.
const INFO_TASK_SIGN: &[u8] = b"aegira/pool/task-sign/v1";
const INFO_TASK_SEAL: &[u8] = b"aegira/pool/task-seal/v1";

/// The tenant a wallet key belongs to: the first sixteen bytes of
/// `sha256("aegira/tenant/v1" ‖ X)`, with `X` the group key compressed.
///
/// Every tenant's record and pool is named by this, so changing it strands them all;
/// `tenant_of_is_pinned` is what notices.
pub fn tenant_of(group_key: &[u8; 33]) -> [u8; 16] {
    enclave_auth::tenant::tenant_of(group_key)
}

/// One tenant's key, `k`: the root of its pool, and of nothing else. Scrubbed on drop, never
/// printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TenantKey([u8; 32]);

impl TenantKey {
    /// `k` as threshold ECDH derived it, or as this release's cache kept it.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        TenantKey(bytes)
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
    /// waking up to an empty pool, so it has to be deliberate. `X = 7·G`; the vector is the one
    /// `docs/CLIENT_INTEGRATION.md` publishes, checked against an independent SHA-256.
    #[test]
    fn tenant_of_is_pinned() {
        let x = hex::decode("025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc")
            .unwrap();
        assert_eq!(
            hex::encode(tenant_of(&x.try_into().unwrap())),
            "ecf80fb854cd261687d9881a8b6498ec"
        );
    }

    /// From a pair of shares to the pool's anchor key, end to end: what a client's sign-in and
    /// the runtime's half of it make together. A change here strands every pool. `f(z) = 7 + 3z`,
    /// holders 1 and 2, and `k` as `threshold`'s known answers pin it.
    #[test]
    fn shares_to_anchor_key_is_pinned() {
        use k256::Scalar;
        use threshold::ecdh::Session;
        use threshold::identifier::Identifier;
        use threshold::point;

        let x = point::base_mul(&Scalar::from(7u64));
        let (one, two) = (
            Identifier::from_u16(1).unwrap(),
            Identifier::from_u16(2).unwrap(),
        );
        let (x_1, x_2) = (Scalar::from(10u64), Scalar::from(13u64));
        let mut rng = crate::random::Rng;
        let (s_1, _) = Session::start(&x, &one, &x_1, b"t", &mut rng).unwrap();
        let (_, p_2) = Session::start(&x, &two, &x_2, b"t", &mut rng).unwrap();
        let k = s_1.finish(&two, &point::base_mul(&x_2), &p_2).unwrap();
        assert_eq!(
            hex::encode(*k),
            "c607455d21237800381d7a93b72a0eab6fa842abf15b8cd85688eb5c2460ce74"
        );
        let anchor =
            KeyMaterial::for_pool(&TenantKey::from_bytes(*k), [1u8; 16], &[3u8; 16]).unwrap();
        assert_eq!(hex::encode(anchor.public_key()), ANCHOR_KEY);
    }

    /// What [`shares_to_anchor_key_is_pinned`] derives, checked against an independent HKDF-SHA384
    /// and Ed25519.
    const ANCHOR_KEY: &str = "71dd455cc3611f79767d98ceedd82238cec63ff19173b2eb0230fe3575790d8f";

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
