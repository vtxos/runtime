//! A vtxos wallet's client.
//!
//! The wallet key is a 2-of-2 between the phone and the enclave runtime. This crate is the phone's
//! side of everything that needs the key: the attested connection to the runtime, sign-in, the
//! policy guest's ceremonies with their FROST rounds, and the ASP calls those ceremonies relay.
//!
//! The phone's share is never stored: it is rebuilt at each use from a passkey's PRF output and a
//! [`keys::WalletRecord`] that is useless without it.

pub mod asp;
pub mod enclave;
mod error;
pub mod exits;
mod frost;
pub mod guest;
pub mod h2;
pub mod keys;
pub mod proto;
pub mod tls;
mod unroll;
pub mod wallet;

pub use error::{Error, Result};
