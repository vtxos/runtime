//! Who is allowed to reach the guest, and for which request.
//!
//! **No fresh, single-use approval signed with the tenant's share of its wallet key, for this
//! exact interaction, means the guest is never called.** No session, no cookie and no
//! certificate authorizes a guest request by itself.
//!
//! ## The division of labour
//!
//! [`routes`] verifies a sign-in ([`approval`]): a BIP-340 signature by the wallet's share,
//! checked against its verifying share in the tenant's write-once record, over a single-use
//! challenge ([`challenge`]), the method, path and query it was issued for, and the certificate
//! this enclave served. What it buys is a token ([`token`]) for that one interaction, which
//! [`gate`] spends when the interaction arrives, comparing the request against what was signed.
//!
//! ## What a signature does and does not prove
//!
//! It proves the holder of the wallet's share approved *this interaction at this route*, not
//! these bytes: the body is not part of it, because an interaction may be a stream whose body
//! does not exist yet. A client compromised between signing and sending can change the payload.

pub use enclave_auth::approval;
pub mod challenge;
/// A client in software, for tests, the in-process harness and `wallet-client`.
///
/// Behind a feature because it *mints approvals*. Nothing that can sign for a tenant should be
/// reachable in a production image, however carefully it is otherwise unused.
#[cfg(any(test, feature = "testing"))]
pub mod client;
pub mod gate;
pub mod routes;
mod token;

pub use challenge::{ChallengeError, ChallengeStore, DEFAULT_CAPACITY, DEFAULT_TTL};
pub use gate::{Denied, Gate, Verified, AUTHORIZATION_HEADER, AUTH_HEADERS};
pub use routes::{AuthEndpoints, AuthResponse, ATTESTED_CALLS, AUTH_PREFIX};
pub use token::{
    InteractionScope, TokenError, TokenStore, DEFAULT_CAPACITY as DEFAULT_TOKEN_CAPACITY,
    DEFAULT_TTL as DEFAULT_TOKEN_TTL,
};
