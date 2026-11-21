//! Where state lives: the tenants' pools, and the bucket and keys around them.
//!
//! - [`zfs`] — the disk, each tenant's pool on its region, and the anchors
//!   that pin it.
//! - [`registry`] — who the tenants are and where their pools are, in the
//!   roots bucket.
//! - [`mount`] — configuration in, a connection to the roots bucket out.
//! - [`backend`] — S3 (and S3-compatible) object storage, plus an in-memory
//!   fake, with the Object Lock and retained-version reads the anchor chain
//!   and the boot records depend on.
//! - [`crypto`] — the key hierarchy off one master secret, Ed25519 signing,
//!   and BLAKE3.
//! - [`error`] — the error type `backend` and `crypto` speak.

pub mod backend;
pub mod crypto;
pub mod error;
pub mod mount;
pub mod registry;
pub mod zfs;

pub use crypto::MasterSecret;
pub use error::{StoreError, StoreResult};
