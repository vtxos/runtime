//! The runtime's sign-in protocol, in one place for the runtime and for every client.
//!
//! A wallet registers by running a 2-of-2 DKG with the runtime, and signs in to each interaction
//! with a BIP-340 signature by its share over an approval ([`approval`]), carrying a threshold
//! ECDH partial over the same message. [`wire`] is what travels; [`client`] is a client's side,
//! without I/O: it builds each request and checks each answer, and the caller owns the network,
//! the attestation check and the certificate pin.

pub mod approval;
pub mod client;
pub mod tenant;
pub mod wire;
