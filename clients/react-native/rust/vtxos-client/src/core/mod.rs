//! The phone's half of the wallet key: what it is made from, what the app keeps, and what it signs.
//!
//! No network and no wire format. The key comes from a passkey's PRF output ([`keys`]); the app
//! keeps a [`keys::WalletRecord`], which rebuilds the share only together with that output; and
//! [`frost`] is the phone's half of a signing round. The FROST arithmetic itself is the
//! `threshold` crate, which the enclave's half uses too.

pub mod frost;
pub mod keys;
