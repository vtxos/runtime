//! The phone's side of an enclave: its half of a key, and calls to whatever the enclave runs.
//!
//! The key is a 2-of-2 between the phone and the enclave runtime. This crate is two parts and
//! nothing else:
//!
//! - [`core`]: the phone's half of the key. What it is made from, the record the app keeps, and
//!   its half of a signing round. No network and no wire format.
//! - [`net`]: the attested connection to the enclave, sign-in, and calls on it as bytes
//!   ([`net::Session`]).
//!
//! It knows nothing of what a call's messages mean. Those belong to whoever wrote the policy the
//! enclave runs, and so to the app that talks to it: the app writes and reads them, and asks
//! [`core`] for the phone's half when the policy opens a signing round.
//!
//! The phone's share is never stored: it is rebuilt at each use from a passkey's PRF output and a
//! [`core::keys::WalletRecord`] that is useless without it.

pub mod core;
mod error;
pub mod net;

pub use error::{Error, Result};
