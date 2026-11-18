//! What a client signs to approve something, in one place for both sides.
//!
//! A client signs with its share of the wallet key (BIP-340), and the runtime checks the signature
//! against that share's verifying share in the tenant's write-once record. The same 32 bytes are
//! the transcript of the ECDH partial that rides with the signature, so that proof is bound to
//! this approval and no other.
//!
//! ```text
//! m = SHA-256("aegira/approval/v1" ‖ for each field: u32-be length ‖ bytes)
//!   register: "register", registration_id, X, id_w, certificate
//!   request:  "request",  challenge_id, X, id_w, certificate, method, path, query
//! ```
//!
//! Both ids are single use and issued by the runtime, so each approval is good once: the
//! registration or challenge it names is consumed whether or not it verifies.
//!
//! - `X` is the group key, compressed (33 bytes).
//! - `id_w` is the wallet's FROST identifier (32 bytes).
//! - `certificate` is the SHA-256 of the TLS certificate the client was served: the value its
//!   attestation document binds. It is 32 zero bytes over plain HTTP, which only tests use. This
//!   binds the approval to this enclave: a signature made on a connection to anyone else names
//!   their certificate, and is refused here, so a client may send it before it has checked
//!   anything.
//! - A query is `0x00` when there is none, and `0x01 ‖ query` when there is, so a bare `?` is not
//!   the same request as no query at all.

use sha2::{Digest, Sha256};

/// The domain tag every approval starts with.
pub const TAG: &[u8] = b"aegira/approval/v1";

/// The certificate field of an approval made over plain HTTP: tests only.
pub const NO_CERTIFICATE: [u8; 32] = [0; 32];

/// One sign-in, as the client signs it.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub challenge_id: &'a [u8; 16],
    pub group_key: &'a [u8; 33],
    pub wallet: &'a [u8; 32],
    pub certificate: &'a [u8; 32],
    pub method: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
}

/// The message a sign-in signs, and its ECDH partial's transcript.
pub fn request(r: &Request<'_>) -> [u8; 32] {
    let query = match r.query {
        None => vec![0u8],
        Some(q) => [&[1u8][..], q.as_bytes()].concat(),
    };
    message(&[
        b"request",
        r.challenge_id,
        r.group_key,
        r.wallet,
        r.certificate,
        r.method.as_bytes(),
        r.path.as_bytes(),
        &query,
    ])
}

/// The message `register/verify` signs, and its ECDH partial's transcript. `registration_id` is
/// single use and was issued by the runtime, so it needs no timestamp or nonce.
pub fn register(
    registration_id: &[u8; 16],
    group_key: &[u8; 33],
    wallet: &[u8; 32],
    certificate: &[u8; 32],
) -> [u8; 32] {
    message(&[b"register", registration_id, group_key, wallet, certificate])
}

fn message(fields: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(TAG);
    for field in fields {
        hash.update((field.len() as u32).to_be_bytes());
        hash.update(field);
    }
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign_in<'a>(query: Option<&'a str>) -> Request<'a> {
        Request {
            challenge_id: &[9; 16],
            group_key: &[2; 33],
            wallet: &[1; 32],
            certificate: &NO_CERTIFICATE,
            method: "POST",
            path: "/sign",
            query,
        }
    }

    /// What a client must compute byte for byte; the vector `docs/CLIENT_INTEGRATION.md`
    /// publishes, checked against an independent SHA-256.
    #[test]
    fn the_messages_are_pinned() {
        assert_eq!(hex::encode(request(&sign_in(None))), REQUEST);
        assert_eq!(
            hex::encode(register(&[7; 16], &[2; 33], &[1; 32], &NO_CERTIFICATE)),
            REGISTER
        );
    }

    const REQUEST: &str = "8478b9e19a9acda3141924f43138ad7e96d6250eadffc5b8067d9b0957a846d4";
    const REGISTER: &str = "8df647a0fa17dbe593f73e94b149eb02d11b896c7e68c53c9e5458a6dd1a6325";

    /// No query, an empty one and a real one are three different requests.
    #[test]
    fn a_query_is_part_of_what_is_signed() {
        let (none, empty, some) = (
            request(&sign_in(None)),
            request(&sign_in(Some(""))),
            request(&sign_in(Some("a=1"))),
        );
        assert_ne!(none, empty);
        assert_ne!(empty, some);
        assert_ne!(none, some);
    }

    /// Fields are length-prefixed, so moving bytes from one field into its neighbour changes
    /// the message.
    #[test]
    fn fields_cannot_bleed_into_each_other() {
        let a = Request {
            method: "POS",
            path: "T/sign",
            ..sign_in(None)
        };
        assert_ne!(request(&a), request(&sign_in(None)));
    }
}
