//! The network: the attested connection to an enclave, sign-in, and calls on it as bytes.
//!
//! Nothing here knows what a call's messages mean. [`enclave::Enclave`] connects, proves the
//! enclave is the one pinned, registers a key and signs in; [`Session`] makes a call or opens a
//! stream to any method the enclave serves. [`h2`] and [`tls`] are the connection underneath.

pub mod enclave;
pub mod h2;
mod session;
pub mod tls;

pub use enclave::{Enclave, Pins};
pub use session::{Session, Stream, MAX_MESSAGE_BYTES};
