//! The Ark protocol as the policy guest uses it, on top of ark-core.
//!
//! ark-core builds every transaction and computes every sighash. What is here is what it cannot do
//! for a wallet whose key is a 2-of-2 signed over a network round: hand the sighashes out and take
//! the signatures back ([`client`]), and an exit signed long before it is broadcast ([`exit`]).

#[cfg(feature = "signing")]
pub mod client;

#[cfg(feature = "exit")]
pub mod exit;

#[cfg(feature = "exit")]
pub mod keys;
