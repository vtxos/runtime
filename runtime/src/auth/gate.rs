//! The gate: no unspent interaction token, no guest.
//!
//! A token is what a verified sign-in buys ([`super::routes`]): one interaction, at the method,
//! path and query the client signed for, once. [`Gate::redeem`] is the only way past, and it
//! either returns a [`Verified`] tenant or a [`Denied`]. There is no third outcome and no
//! caller-supplied way to skip it.
//!
//! The scope is rebuilt from the request that actually arrived and compared with the one the
//! client signed, so a token cannot be moved to another route. The body is never part of it: an
//! interaction may be a stream, whose body does not exist when the approval is given.

use super::challenge::ChallengeError;
use super::token::{InteractionScope, TokenError, TokenStore};

/// Carries the interaction token: `Authorization: Bearer <token>`.
///
/// An ordinary HTTP header rather than an `x-enclave-*` one, deliberately: a
/// gRPC stream's opening metadata *is* an HTTP/2 HEADERS frame, so one header
/// covers a request and a stream alike, and every client library already knows
/// how to set this one.
pub const AUTHORIZATION_HEADER: &str = "authorization";

/// Every header the gate consumes. Stripped before the guest sees a request, so
/// a guest can neither read a client's token nor forge one.
pub const AUTH_HEADERS: [&str; 1] = [AUTHORIZATION_HEADER];

/// Ceiling on a bearer token, in characters.
///
/// The runtime mints 32 bytes as base64url, so anything much longer is not one
/// of ours; the bound exists so a header cannot make the runtime hash an
/// arbitrary amount of input before deciding it was never valid.
const MAX_TOKEN_CHARS: usize = 128;

/// What a client is known as, once it has proved it.
#[derive(Debug, Clone)]
pub struct Verified {
    /// Sixteen bytes, derived from the wallet's group key by [`crate::tenant::tenant_of`] and
    /// naming the tenant's pool. It is not a secret and nothing derives a key from it.
    pub tenant_id: [u8; 16],
}

/// Why a client did not get past the gate, or did not get a token.
///
/// The variants exist for the runtime's log. **Clients are told one thing.** An
/// attacker distinguishing "unknown tenant" from "bad signature" learns which
/// guesses to keep making; a legitimate client learns nothing it can act on,
/// because the remedy for all of them is to sign again.
#[derive(Debug)]
pub enum Denied {
    /// No token at all.
    Missing,
    /// Present but not parseable, or over the size limit.
    Malformed(String),
    Token(TokenError),
    /// No such tenant, or it has been revoked.
    UnknownTenant,
    /// The signature did not verify against the tenant's verifying share: a wrong share, a
    /// changed request, or one signed for another enclave's certificate.
    Signature,
    /// The ECDH partial's proof did not verify.
    Proof,
    Challenge(ChallengeError),
}

impl Denied {
    /// What the client is told. Deliberately the same for every variant.
    pub fn public_message(&self) -> &'static str {
        "a fresh signature bound to this request is required"
    }

    pub fn status(&self) -> hyper::StatusCode {
        hyper::StatusCode::UNAUTHORIZED
    }
}

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Denied::Missing => write!(f, "no token presented"),
            Denied::Malformed(e) => write!(f, "malformed: {e}"),
            Denied::Token(e) => write!(f, "{e}"),
            Denied::UnknownTenant => write!(f, "unknown or revoked tenant"),
            Denied::Signature => write!(f, "the signature did not verify"),
            Denied::Proof => write!(f, "the ECDH partial's proof did not verify"),
            Denied::Challenge(e) => write!(f, "{e}"),
        }
    }
}

impl std::fmt::Debug for Gate {
    /// Names what it holds, never what is in it: a `Debug` that printed tokens
    /// would put the only thing between a caller and a tenant's guest into any
    /// log line that formatted a struct containing one.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gate")
            .field("outstanding_tokens", &self.tokens.outstanding())
            .finish_non_exhaustive()
    }
}

pub struct Gate {
    tokens: TokenStore,
}

impl Gate {
    pub fn new(tokens: TokenStore) -> Self {
        Gate { tokens }
    }

    pub fn tokens(&self) -> &TokenStore {
        &self.tokens
    }

    /// Record a verified sign-in as a token for one interaction. The caller minted the token's
    /// bytes; the store keeps a hash, so the only copy is the one going to the client.
    pub fn grant(
        &self,
        token: &[u8],
        tenant_id: [u8; 16],
        scope: InteractionScope,
    ) -> Result<std::time::Duration, Denied> {
        self.tokens
            .issue(token, tenant_id, scope)
            .map_err(Denied::Token)?;
        Ok(self.tokens.ttl())
    }

    /// Spend one approval on one interaction.
    ///
    /// The scope is rebuilt from the request that actually arrived and compared
    /// with the one the client signed, so a token cannot be moved to another
    /// route. It says nothing about the body, and deliberately: an interaction
    /// may be a stream, whose body does not exist when the approval is given.
    pub fn redeem<B>(&self, req: &hyper::Request<B>) -> Result<Verified, Denied> {
        let offered = req
            .headers()
            .get(AUTHORIZATION_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .ok_or(Denied::Missing)?;
        if offered.is_empty() || offered.len() > MAX_TOKEN_CHARS {
            return Err(Denied::Malformed("token is not a plausible length".into()));
        }

        let arrived_as =
            InteractionScope::new(req.method().as_str(), req.uri().path(), req.uri().query());
        let tenant_id = self
            .tokens
            .redeem(offered.as_bytes(), &arrived_as)
            .map_err(Denied::Token)?;

        Ok(Verified { tenant_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    const TENANT: [u8; 16] = [7; 16];

    fn gate_with(token: &[u8], method: &str, path: &str) -> Gate {
        let gate = Gate::new(TokenStore::new(
            super::super::token::DEFAULT_TTL,
            super::super::token::DEFAULT_CAPACITY,
        ));
        let (path, query) = match path.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (path, None),
        };
        gate.grant(token, TENANT, InteractionScope::new(method, path, query))
            .unwrap();
        gate
    }

    fn bearer(
        method: &str,
        path: &str,
        body: &'static [u8],
        token: &[u8],
    ) -> hyper::Request<http_body_util::Full<Bytes>> {
        hyper::Request::builder()
            .method(method)
            .uri(format!("https://enclave.test{path}"))
            .header(
                AUTHORIZATION_HEADER,
                format!("Bearer {}", std::str::from_utf8(token).unwrap()),
            )
            .body(http_body_util::Full::new(Bytes::from_static(body)))
            .expect("well-formed request")
    }

    /// A token identifies its tenant, and spends itself doing it.
    #[test]
    fn a_token_admits_one_interaction() {
        let gate = gate_with(b"a-token", "POST", "/sign");
        let req = bearer("POST", "/sign", b"pay alice", b"a-token");
        assert_eq!(gate.redeem(&req).unwrap().tenant_id, TENANT);

        let again = bearer("POST", "/sign", b"pay alice", b"a-token");
        assert!(
            matches!(gate.redeem(&again), Err(Denied::Token(_))),
            "a token admitted a second interaction"
        );
    }

    /// **What the token still refuses.** It names a route, and cannot be moved.
    #[test]
    fn a_token_cannot_be_moved_to_another_interaction() {
        for (method, path) in [
            ("POST", "/withdraw"),
            ("GET", "/sign"),
            ("POST", "/sign?all=1"),
        ] {
            let gate = gate_with(b"a-token", "POST", "/sign");
            let req = bearer(method, path, b"", b"a-token");
            assert!(
                matches!(gate.redeem(&req), Err(Denied::Token(_))),
                "an approval for POST /sign was spent on {method} {path}"
            );
        }
    }

    /// **What it deliberately does not refuse, and this is the trade.**
    ///
    /// The approval names the interaction, not the payload. A different body at
    /// the same route is the same interaction as far as the runtime is
    /// concerned. This test exists so the property is written down rather than
    /// discovered.
    #[test]
    fn a_token_does_not_bind_the_body() {
        let gate = gate_with(b"a-token", "POST", "/sign");
        let req = bearer("POST", "/sign", b"pay mallory 1000", b"a-token");
        assert!(
            gate.redeem(&req).is_ok(),
            "the token bound a body it was never given"
        );
    }

    /// The whole rule: nothing gets through without one.
    #[test]
    fn a_request_without_a_token_is_refused() {
        let gate = gate_with(b"a-token", "POST", "/sign");
        let req = hyper::Request::builder()
            .method("POST")
            .uri("https://enclave.test/sign")
            .body(http_body_util::Full::new(Bytes::new()))
            .expect("well-formed request");
        assert!(matches!(gate.redeem(&req), Err(Denied::Missing)));
    }

    #[test]
    fn a_malformed_authorization_header_is_refused_rather_than_panicking() {
        let gate = gate_with(b"a-token", "POST", "/sign");
        for value in [
            "",
            "Bearer ",
            "Basic abc",
            "bearer lowercase-scheme",
            &"x".repeat(4096),
        ] {
            let req = hyper::Request::builder()
                .method("POST")
                .uri("https://enclave.test/sign")
                .header(AUTHORIZATION_HEADER, value)
                .body(http_body_util::Full::new(Bytes::new()))
                .expect("well-formed request");
            assert!(
                gate.redeem(&req).is_err(),
                "{value:?} was accepted as a token"
            );
        }
    }

    /// **The uniformity guarantee.** Every refusal says the same thing.
    #[test]
    fn refusals_are_indistinguishable_to_the_client() {
        let all = [
            Denied::Missing,
            Denied::Malformed("x".into()),
            Denied::Token(TokenError::WrongInteraction),
            Denied::Token(TokenError::Expired),
            Denied::UnknownTenant,
            Denied::Signature,
            Denied::Proof,
            Denied::Challenge(ChallengeError::Unknown),
            Denied::Challenge(ChallengeError::Expired),
        ];
        for denied in &all {
            assert_eq!(
                denied.public_message(),
                all[0].public_message(),
                "{denied} tells a client something the others do not"
            );
            assert_eq!(denied.status(), hyper::StatusCode::UNAUTHORIZED);
            let public = denied.public_message();
            assert!(!public.contains("tenant"), "{public}");
            assert!(!public.contains("expired"), "{public}");
            assert!(!public.contains("proof"), "{public}");
        }
    }
}
