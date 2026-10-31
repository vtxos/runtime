//! Cryptographic primitives.
//!
//! - [`hash`] — BLAKE3 digests.
//! - [`sign`] — Ed25519, so an anchor cannot be minted or re-pointed by anyone
//!   holding only bucket write access.
//! - [`keys`] — a tenant key per pool, a master secret per release, each
//!   HKDF-separated per purpose.
//! - [`seal`] — AES-256-GCM bound to where the blob is stored.
//!
//! Primitives come from `aws-lc-rs` (the same stack KMS speaks, FIPS-capable)
//! except BLAKE3, which has no aws-lc equivalent.

pub mod hash;
pub mod keys;
pub mod seal;
pub mod sign;

pub use hash::{Hash256, HASH_LEN};
pub use keys::{
    KeyMaterial, MasterSecret, TenantKey, VersionKeys, ED25519_PUBLIC_KEY_LEN,
    ED25519_SIGNATURE_LEN,
};
