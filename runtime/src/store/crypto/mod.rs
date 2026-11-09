//! Cryptographic primitives.
//!
//! - [`hash`] — BLAKE3 digests.
//! - [`sign`] — Ed25519, so an anchor cannot be minted or re-pointed by anyone
//!   holding only bucket write access.
//! - [`keys`] — a master secret per release, HKDF-separated per purpose. A
//!   tenant's keys are its own ([`crate::tenant`]).
//! - [`seal`] — AES-256-GCM bound to where the blob is stored.
//!
//! Primitives come from `aws-lc-rs` (the same stack KMS speaks, FIPS-capable)
//! except BLAKE3, which has no aws-lc equivalent.

pub mod hash;
pub mod keys;
pub mod seal;
pub mod sign;

pub use hash::{Hash256, HASH_LEN};
pub use keys::{MasterSecret, VersionKeys, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN};
