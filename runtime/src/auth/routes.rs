//! `/auth/*` — the only routes that answer without a token.
//!
//! They are runtime-owned in the same sense `/enclave/*` is: refused before
//! dispatch, never forwarded, and unreachable by any guest. That is not a
//! convenience. A guest able to answer under `/auth/` could hand out its own
//! tokens, which is the same as having none.
//!
//! ## Registration: two calls, the whole DKG
//!
//! Registration is open: what it grants is a new, empty tenant and nothing else.
//! It makes the tenant's wallet key, a 2-of-2 between the client and the runtime
//! ([`crate::signer::dkg`]), and the wallet commits first:
//!
//! 1. `register/options` takes the wallet's round one (a commitment and a proof
//!    of knowledge: nothing secret) and answers with the runtime's round one and
//!    the share it deals the wallet. The answer carries this enclave's
//!    attestation, which the client checks, pinning the certificate, before it
//!    sends anything secret.
//! 2. `register/verify` takes the share the wallet deals the runtime, a
//!    signature with the wallet's finished share, and its ECDH partial. Only when
//!    all three verify is anything kept: the runtime's share sealed into the
//!    tenant's record, a region claimed, and the pool created under `k`. A
//!    registration that is abandoned or refused leaves nothing behind.
//!
//! ## Sign-in: a challenge, then a signature
//!
//! `request/options` names the tenant by its group key and the interaction it
//! wants, and gets a single-use challenge ([`super::challenge`]). It is issued
//! whatever key it names, so it cannot be used to learn which keys are tenants.
//! The answer carries this enclave's attestation, which the client checks,
//! pinning the certificate, before it signs anything. `request/verify` carries
//! a signature by the wallet's share over that challenge and the interaction
//! ([`super::approval`]), and the wallet's ECDH partial, from which the runtime
//! derives `k` and opens the pool if it is not open already. A client cannot
//! know whether it is, and is not told, so every sign-in carries the partial.
//!
//! So both operations have the same shape: an options call whose answer is
//! attested ([`ATTESTED_CALLS`]), then a verify call that does the work, on the
//! certificate that answer named.
//!
//! Every refusal of who is asking is the same `401`, carries no attestation,
//! and costs the runtime no unsealing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use threshold::dkg::{Round1Package, Round2Package};
use threshold::ecdh::{Partial, PartialBytes};
use threshold::point;

use super::approval;
use super::challenge::ChallengeStore;
use super::gate::{Denied, Gate};
use super::token::InteractionScope;
use crate::signer::{seal_share, Keys};
use crate::store::registry::Place;
use crate::store::zfs::{Arrival, AttachError, Zfs};
use crate::tenant::{tenant_of, TenantKey};

/// The prefix the guest can never see.
pub const AUTH_PREFIX: &str = "/auth/";

/// The calls whose answers carry this enclave's attestation, and so the only ones that take
/// `x-enclave-nonce`: the first call of a registration and of a sign-in. A client checks the
/// document, and pins the certificate, before it sends anything secret on the verify call that
/// follows.
pub const ATTESTED_CALLS: [&str; 2] = ["/auth/register/options", "/auth/request/options"];

/// How long a half-finished registration is held.
const REGISTRATION_TTL: Duration = Duration::from_secs(300);
/// Half-finished registrations allowed at once.
const MAX_REGISTRATIONS: usize = 64;
/// Ceiling on an `/auth/*` request body.
const MAX_BODY: usize = 16 * 1024;

type Body = wasmtime_wasi_http::p2::body::HyperOutgoingBody;

/// An `/auth/*` answer, and whether this enclave attests it.
///
/// Only the options calls' answers are attested ([`ATTESTED_CALLS`]), and only when they succeed:
/// no refusal carries a document.
pub struct AuthResponse {
    pub response: hyper::Response<Body>,
    pub attest: bool,
}

/// The wallet's round one: its commitment and proof of knowledge, nothing secret.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterOptionsRequest {
    dkg: WalletCommitment,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletCommitment {
    /// threshold's JSON.
    round1_package: String,
}

#[derive(Serialize)]
struct RegisterOptionsResponse {
    registration_id: String,
    dkg: RuntimeDeal,
}

/// The runtime's round one, and the share it deals the wallet, as threshold's JSON.
#[derive(Serialize)]
struct RuntimeDeal {
    round1_package: String,
    /// `f_c(id_w)`.
    round2_package: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterVerifyRequest {
    registration_id: String,
    dkg: WalletDeal,
    /// Hex, 64 bytes: BIP-340 by the wallet's finished share over
    /// [`approval::register`].
    signature: String,
    ecdh: WirePartial,
}

/// The share the wallet deals the runtime, `f_w(id_c)`, as threshold's JSON.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletDeal {
    round2_package: String,
}

#[derive(Serialize)]
struct RegisterVerifyResponse {
    tenant_id: String,
    /// `X`, compressed, hex.
    group_key: String,
    /// The runtime's ECDH partial: with it the wallet derives the same `k`.
    ecdh: WirePartial,
}

/// What a sign-in will approve: one interaction, for the tenant whose group key this is.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestOptionsRequest {
    /// `X`, compressed and even-Y, hex: names the tenant.
    group_key: String,
    method: String,
    path: String,
    #[serde(default)]
    query: Option<String>,
}

#[derive(Serialize)]
struct RequestOptionsResponse {
    /// Base64url, 16 bytes: single use, good for a minute.
    challenge_id: String,
}

/// One sign-in, answering one challenge.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestVerifyRequest {
    challenge_id: String,
    /// Hex, 64 bytes: BIP-340 by the wallet's share over [`approval::request`].
    signature: String,
    /// The wallet's ECDH partial, over the same message.
    ecdh: WirePartial,
}

/// The token, and how long it has to be spent.
#[derive(Serialize)]
struct TokenResponse {
    token: String,
    /// Seconds. This bounds the time to *start* an interaction, and is not how
    /// long one may run once started.
    expires_in_secs: u64,
    /// The runtime's ECDH partial: with it the wallet derives the same `k`.
    ecdh: WirePartial,
}

/// An ECDH partial on the wire ([`threshold::ecdh`]): compressed points and a scalar, hex.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePartial {
    share: String,
    a: String,
    b: String,
    s: String,
}

impl WirePartial {
    fn encode(partial: &Partial) -> Self {
        let bytes = partial.to_bytes();
        WirePartial {
            share: hex::encode(bytes.share),
            a: hex::encode(bytes.a),
            b: hex::encode(bytes.b),
            s: hex::encode(bytes.s),
        }
    }

    fn decode(&self) -> Option<Partial> {
        Partial::from_bytes(&PartialBytes {
            share: hex_array(&self.share)?,
            a: hex_array(&self.a)?,
            b: hex_array(&self.b)?,
            s: hex_array(&self.s)?,
        })
        .ok()
    }
}

struct PendingRegistration {
    /// What the runtime's polynomial for this registration is derived from.
    handle: [u8; 16],
    /// The wallet's round one, which `register/verify` finishes against.
    wallet: Round1Package,
    expires: Instant,
}

impl std::fmt::Debug for AuthEndpoints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthEndpoints")
            .field(
                "pending_registrations",
                &self.registrations.lock().map(|r| r.len()).unwrap_or(0),
            )
            .finish_non_exhaustive()
    }
}

pub struct AuthEndpoints {
    gate: Arc<Gate>,
    /// Each tenant's wallet key, and the operator master the runtime's half is
    /// derived from and sealed under.
    keys: Arc<Keys>,
    zfs: Arc<Zfs>,
    entropy: Arc<dyn nitro_nsm::Nsm>,
    challenges: ChallengeStore,
    registrations: Mutex<HashMap<[u8; 16], PendingRegistration>>,
}

impl AuthEndpoints {
    pub fn new(
        gate: Arc<Gate>,
        keys: Arc<Keys>,
        zfs: Arc<Zfs>,
        entropy: Arc<dyn nitro_nsm::Nsm>,
        challenges: ChallengeStore,
    ) -> Self {
        AuthEndpoints {
            gate,
            keys,
            zfs,
            entropy,
            challenges,
            registrations: Mutex::new(HashMap::new()),
        }
    }

    /// Each tenant's wallet key, for the guest's signing to read.
    pub fn keys(&self) -> &Arc<Keys> {
        &self.keys
    }

    fn random_id(&self) -> anyhow::Result<[u8; 16]> {
        let mut id = [0u8; 16];
        self.entropy.get_random(&mut id)?;
        Ok(id)
    }

    /// Answer an `/auth/*` request, or `None` if this is not one. `certificate`
    /// is the SHA-256 of the certificate this connection was served, or
    /// [`approval::NO_CERTIFICATE`] over plain HTTP.
    pub async fn handle(
        &self,
        method: &hyper::Method,
        path: &str,
        body: &[u8],
        certificate: &[u8; 32],
    ) -> Option<AuthResponse> {
        if !path.starts_with(AUTH_PREFIX) {
            return None;
        }
        if method != hyper::Method::POST {
            return Some(refuse(
                hyper::StatusCode::METHOD_NOT_ALLOWED,
                "auth routes are POST",
            ));
        }
        if body.len() > MAX_BODY {
            return Some(refuse(
                hyper::StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large",
            ));
        }

        Some(match &path[AUTH_PREFIX.len()..] {
            "register/options" => self.register_options(body).await,
            "register/verify" => self.register_verify(body, certificate).await,
            "request/options" => self.request_options(body).await,
            "request/verify" => self.request_verify(body, certificate).await,
            other => refuse(
                hyper::StatusCode::NOT_FOUND,
                &format!("no auth endpoint {other:?}"),
            ),
        })
    }

    async fn register_options(&self, body: &[u8]) -> AuthResponse {
        let Ok(request) = serde_json::from_slice::<RegisterOptionsRequest>(body) else {
            return refuse(hyper::StatusCode::BAD_REQUEST, "malformed request");
        };
        let Ok(wallet) = Round1Package::from_json(&request.dkg.round1_package) else {
            return refuse(hyper::StatusCode::BAD_REQUEST, "malformed DKG package");
        };
        let master = match self.master().await {
            Ok(master) => master,
            Err((status, message)) => return refuse(status, message),
        };
        let Ok(handle) = self.random_id() else {
            return refuse(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
        };
        // The wallet has committed; the runtime answers with its commitment and the share it
        // deals, and keeps nothing secret: `register/verify` derives the same polynomial again.
        let deal = match crate::signer::dkg::deal(master, &handle, &wallet) {
            Ok(deal) => deal,
            Err(e) => {
                tracing::info!(reason = %e, "refused a DKG package");
                return refuse(
                    hyper::StatusCode::BAD_REQUEST,
                    "the DKG package did not verify",
                );
            }
        };

        let Ok(id) = self.random_id() else {
            return refuse(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
        };
        {
            let now = Instant::now();
            let mut pending = self.registrations.lock().expect("registrations poisoned");
            pending.retain(|_, p| p.expires > now);
            if pending.len() >= MAX_REGISTRATIONS {
                return refuse(hyper::StatusCode::SERVICE_UNAVAILABLE, "try again");
            }
            pending.insert(
                id,
                PendingRegistration {
                    handle,
                    wallet,
                    expires: now + REGISTRATION_TTL,
                },
            );
        }

        AuthResponse {
            response: json(
                hyper::StatusCode::OK,
                &RegisterOptionsResponse {
                    registration_id: b64(&id),
                    dkg: RuntimeDeal {
                        round1_package: deal.package.to_json(),
                        round2_package: deal.dealt.to_json(),
                    },
                },
            ),
            attest: true,
        }
    }

    async fn register_verify(&self, body: &[u8], certificate: &[u8; 32]) -> AuthResponse {
        let Ok(request) = serde_json::from_slice::<RegisterVerifyRequest>(body) else {
            return refuse(hyper::StatusCode::BAD_REQUEST, "malformed request");
        };
        let Some(id) = decode_id(&request.registration_id) else {
            return refuse(hyper::StatusCode::BAD_REQUEST, "malformed registration id");
        };
        let Ok(from_wallet) = Round2Package::from_json(&request.dkg.round2_package) else {
            return refuse(hyper::StatusCode::BAD_REQUEST, "malformed DKG package");
        };
        let Some(signature) = hex_array::<64>(&request.signature) else {
            return refuse(hyper::StatusCode::BAD_REQUEST, "malformed signature");
        };
        let Some(partial) = request.ecdh.decode() else {
            return refuse(hyper::StatusCode::BAD_REQUEST, "malformed ECDH partial");
        };

        // Taken, not borrowed: an attempt that fails must not leave the registration open for
        // another try.
        let pending = {
            let mut registrations = self.registrations.lock().expect("registrations poisoned");
            registrations.remove(&id)
        };
        let Some(pending) = pending.filter(|p| p.expires > Instant::now()) else {
            return refuse(hyper::StatusCode::FORBIDDEN, "registration expired");
        };
        let master = match self.master().await {
            Ok(master) => master,
            Err((status, message)) => return refuse(status, message),
        };

        // The key, in memory: nothing is kept until the wallet has shown it holds its half.
        let key = match crate::signer::dkg::register(
            master,
            &pending.handle,
            &pending.wallet,
            &from_wallet,
        ) {
            Ok(registered) => registered.key,
            Err(e) => {
                tracing::info!(reason = %e, "refused a DKG package");
                return refuse(
                    hyper::StatusCode::BAD_REQUEST,
                    "the DKG package did not verify",
                );
            }
        };
        let group_key = key.group_key();
        let tenant = tenant_of(&group_key);
        let message = approval::register(&id, &group_key, &key.wallet().serialize(), certificate);

        // The wallet finished its share: it signs with it, and makes its partial with it.
        if !threshold::auth::verify_schnorr_signature(
            &point::serialize_compressed(key.wallet_share()),
            &message,
            &signature,
        ) {
            return self.denied(Denied::Signature);
        }
        let (tenant_key, mine) = match crate::signer::tenant_key(&key, &partial, &message) {
            Ok(pair) => pair,
            Err(_) => return self.denied(Denied::Proof),
        };

        // Everything verified. Kept now, in this order: the record with the sealed share and its
        // region, then the pool under `k`.
        let sealed = match seal_share(master, &tenant, key.secret_share()) {
            Ok(sealed) => sealed,
            Err(e) => {
                tracing::error!(error = format!("{e:#}"), "sealing a wallet key");
                return refuse(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
            }
        };
        let record = match self
            .zfs
            .registry()
            .register(tenant, key.record(sealed))
            .await
        {
            Ok(record) => record,
            Err(e) => {
                tracing::error!(error = format!("{e:#}"), "registering a tenant");
                return refuse(hyper::StatusCode::CONFLICT, "could not register");
            }
        };
        if let Err((status, message)) = self.attach(tenant, record.place, &tenant_key).await {
            return refuse(status, message);
        }
        self.keys.insert(tenant, key);

        tracing::info!(tenant = %hex::encode(tenant), "registered a tenant");
        AuthResponse {
            response: json(
                hyper::StatusCode::OK,
                &RegisterVerifyResponse {
                    tenant_id: hex::encode(tenant),
                    group_key: hex::encode(group_key),
                    ecdh: WirePartial::encode(&mine),
                },
            ),
            attest: false,
        }
    }

    /// A challenge for one interaction of one tenant, with this enclave's attestation.
    /// Unauthenticated by necessity: a client cannot sign until it has one, and checks the
    /// attestation before it does. Issued whatever key it names, so an answer here says nothing
    /// about which keys are tenants; a key that is not one fails at `request/verify`, like any
    /// other refusal.
    async fn request_options(&self, body: &[u8]) -> AuthResponse {
        let Ok(request) = serde_json::from_slice::<RequestOptionsRequest>(body) else {
            return refuse(hyper::StatusCode::BAD_REQUEST, "malformed request");
        };
        let Some(group_key) = hex_array::<33>(&request.group_key).filter(|k| k[0] == 0x02) else {
            return refuse(hyper::StatusCode::BAD_REQUEST, "malformed group key");
        };
        let Ok(id) = self.random_id() else {
            return refuse(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
        };
        let scope = InteractionScope::new(&request.method, &request.path, request.query.as_deref());
        match self.challenges.issue(id, tenant_of(&group_key), scope) {
            Ok(()) => AuthResponse {
                response: json(
                    hyper::StatusCode::OK,
                    &RequestOptionsResponse {
                        challenge_id: b64(&id),
                    },
                ),
                attest: true,
            },
            Err(e) => {
                tracing::warn!(error = %e, "issuing a challenge");
                refuse(hyper::StatusCode::SERVICE_UNAVAILABLE, "try again")
            }
        }
    }

    /// Turn a signed approval into a token for one interaction.
    ///
    /// **What the token authorizes: one interaction at the method, path and
    /// query the client signed.** It commits to no bytes. The client approved
    /// *doing this thing*, not *sending these bytes*, and nothing here should
    /// be described as approval of a payload.
    async fn request_verify(&self, body: &[u8], certificate: &[u8; 32]) -> AuthResponse {
        let Ok(request) = serde_json::from_slice::<RequestVerifyRequest>(body) else {
            return refuse(hyper::StatusCode::BAD_REQUEST, "malformed request");
        };
        let Some(challenge_id) = decode_id(&request.challenge_id) else {
            return refuse(hyper::StatusCode::BAD_REQUEST, "malformed challenge id");
        };
        let Some(signature) = hex_array::<64>(&request.signature) else {
            return refuse(hyper::StatusCode::BAD_REQUEST, "malformed signature");
        };
        let Some(partial) = request.ecdh.decode() else {
            return refuse(hyper::StatusCode::BAD_REQUEST, "malformed ECDH partial");
        };

        // Consumed whatever happens next: a challenge answered badly has been seen by whoever
        // answered it, and a second attempt at the same one buys them only attempts.
        let (tenant, scope) = match self.challenges.consume(&challenge_id) {
            Ok(issued) => issued,
            Err(e) => return self.denied(Denied::Challenge(e)),
        };

        // Who is asking: a tenant on record, not revoked, whose wallet signed exactly this.
        let record = match self.zfs.registry().tenant(tenant).await {
            Ok(Some(record)) => record,
            Ok(None) => return self.denied(Denied::UnknownTenant),
            Err(e) => {
                tracing::error!(error = format!("{e:#}"), "reading a tenant record");
                return refuse(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
            }
        };
        match self.zfs.registry().revoked(tenant).await {
            Ok(false) => {}
            Ok(true) => return self.denied(Denied::UnknownTenant),
            Err(e) => {
                tracing::error!(error = format!("{e:#}"), "reading a revocation");
                return refuse(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
            }
        }
        let group_key = record.key.group_key;
        let message = approval::request(&approval::Request {
            challenge_id: &challenge_id,
            group_key: &group_key,
            wallet: &record.key.wallet.identifier,
            certificate,
            method: &scope.method,
            path: &scope.path,
            query: scope.query.as_deref(),
        });
        if !threshold::auth::verify_schnorr_signature(
            &record.key.wallet.verifying_share,
            &message,
            &signature,
        ) {
            return self.denied(Denied::Signature);
        }

        // The pool: opened with `k`, which the wallet's partial and the runtime's share make. The
        // proof first, so a bad partial costs no unsealing.
        let (Ok(x), Ok(wallet)) = (
            point::deserialize_compressed(&group_key),
            point::deserialize_compressed(&record.key.wallet.verifying_share),
        ) else {
            return refuse(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
        };
        if partial.verify(&x, &wallet, &message).is_err() {
            return self.denied(Denied::Proof);
        }
        let key = match self.keys.get(tenant).await {
            Ok(key) => key,
            Err(e) => {
                tracing::error!(error = format!("{e:#}"), "reading a wallet key");
                return refuse(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
            }
        };
        let (tenant_key, mine) = match crate::signer::tenant_key(&key, &partial, &message) {
            Ok(pair) => pair,
            Err(_) => return self.denied(Denied::Proof),
        };
        if let Err((status, message)) = self.attach(tenant, record.place, &tenant_key).await {
            return refuse(status, message);
        }

        // Minted here, from the enclave's entropy, and held in exactly two places: this
        // response, and a hash in the store.
        let mut token = [0u8; 32];
        if self.entropy.get_random(&mut token).is_err() {
            return refuse(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
        }
        let token = b64(&token);
        let (method, path) = (scope.method.clone(), scope.path.clone());
        let ttl = match self.gate.grant(token.as_bytes(), tenant, scope) {
            Ok(ttl) => ttl,
            Err(denied) => {
                tracing::warn!(reason = %denied, "could not record an approval");
                return refuse(hyper::StatusCode::SERVICE_UNAVAILABLE, "try again");
            }
        };

        // The token itself is never logged. What identifies this event is the tenant it belongs
        // to and the interaction it is good for.
        tracing::info!(
            tenant = %hex::encode(tenant),
            %method,
            %path,
            "issued an interaction token"
        );
        AuthResponse {
            response: json(
                hyper::StatusCode::OK,
                &TokenResponse {
                    token,
                    expires_in_secs: ttl.as_secs(),
                    ecdh: WirePartial::encode(&mine),
                },
            ),
            attest: false,
        }
    }

    /// Logged in full, answered in one sentence: which check failed is the runtime's business,
    /// and telling a caller would tell them which guess to refine.
    fn denied(&self, denied: Denied) -> AuthResponse {
        tracing::info!(reason = %denied, "refused a sign-in");
        refuse(denied.status(), denied.public_message())
    }

    /// Attach a verified tenant's pool with `k`, creating it the first time.
    async fn attach(
        &self,
        tenant: [u8; 16],
        place: Place,
        key: &TenantKey,
    ) -> Result<(), (hyper::StatusCode, &'static str)> {
        match self.zfs.attach(tenant, place, key).await {
            Ok(Arrival::New) => {
                tracing::info!(tenant = %hex::encode(tenant), "created a tenant's pool");
                Ok(())
            }
            Ok(Arrival::Returning) => Ok(()),
            Err(AttachError::WrongKey) => {
                // `k` came from proofs that verified, so the pool, not the client, is wrong:
                // its anchors were written under some other key.
                tracing::error!(
                    tenant = %hex::encode(tenant),
                    "a tenant's pool does not open with the key its shares derive"
                );
                Err((hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable"))
            }
            Err(e @ AttachError::Superseded(_)) => {
                tracing::error!(tenant = %hex::encode(tenant), error = %e, "refusing a tenant");
                Err((
                    hyper::StatusCode::CONFLICT,
                    "this tenant was last served by a newer release",
                ))
            }
            Err(e) => {
                tracing::error!(tenant = %hex::encode(tenant), error = %e, "attaching a tenant");
                Err((hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable"))
            }
        }
    }

    /// The operator master, or why it cannot be read yet.
    async fn master(&self) -> Result<&[u8; 32], (hyper::StatusCode, &'static str)> {
        self.keys.master().get().await.map_err(|e| {
            tracing::warn!(error = format!("{e:#}"), "reading the operator master");
            (
                hyper::StatusCode::SERVICE_UNAVAILABLE,
                "the operator master is not provisioned yet",
            )
        })
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn decode(text: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text.trim())
        .ok()
}

fn decode_id(text: &str) -> Option<[u8; 16]> {
    decode(text).and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
}

fn hex_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    hex::decode(text.trim())
        .ok()
        .and_then(|b| <[u8; N]>::try_from(b).ok())
}

fn body_of(bytes: Vec<u8>) -> Body {
    use http_body_util::BodyExt;
    http_body_util::Full::new(Bytes::from(bytes))
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed_unsync()
}

fn json<T: Serialize>(status: hyper::StatusCode, value: &T) -> hyper::Response<Body> {
    let bytes = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    hyper::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        // Tokens and registrations are single-use and short-lived; a cache that replayed one
        // would be handing out a used one.
        .header("cache-control", "no-store")
        .body(body_of(bytes))
        .expect("response is well formed")
}

/// An unattested refusal.
fn refuse(status: hyper::StatusCode, detail: &str) -> AuthResponse {
    AuthResponse {
        response: json(status, &serde_json::json!({ "error": detail })),
        attest: false,
    }
}

#[cfg(test)]
mod tests;
