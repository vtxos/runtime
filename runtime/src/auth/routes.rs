//! `/auth/*` — the only routes that answer without an assertion.
//!
//! They are runtime-owned in the same sense `/enclave/*` is: refused before
//! dispatch, never forwarded, and unreachable by any guest. That is not a
//! convenience. A guest able to answer under `/auth/` could hand out its own
//! challenges and verify its own assertions, which is the same as having none.
//!
//! Registration creates a new tenant, which anyone may do: it is open, and what
//! it grants is an empty tenant and nothing else. A tenant's pool is attached
//! only with the tenant key the app sends: created with it at registration,
//! and opened with it beside every assertion after — the only way a release
//! ever opens a tenant's data.
//!
//! Registration also carries the whole of the wallet key's DKG
//! ([`crate::signer::dkg`]): `register/options` answers with the cosigner's
//! opening, and `register/verify` completes the ceremony and keeps the key on
//! the pool it creates. The cosigner's half is derived from the operator master
//! and the registration's user handle.
//!
//! ## Why registration is two calls
//!
//! WebAuthn registration is a challenge and a response, and the runtime has to
//! remember which challenge it issued while the user holds their thumb to a
//! phone. The state is kept here, keyed by an id the client quotes back, for
//! the same reasons the assertion challenges are: single use, short lived, and
//! bounded, because issuing one is necessarily unauthenticated.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

use super::credential::RegistryCredentials;
use super::gate::Gate;
use super::token::InteractionScope;
use crate::keys::OperatorMaster;
use crate::tenant::tenant_of;

/// The prefix the guest can never see.
pub const AUTH_PREFIX: &str = "/auth/";

/// How long a half-finished registration is held.
const REGISTRATION_TTL: Duration = Duration::from_secs(300);
/// Half-finished registrations allowed at once.
const MAX_REGISTRATIONS: usize = 64;
/// Ceiling on an `/auth/*` request body.
const MAX_BODY: usize = 16 * 1024;

/// Registration is open, so nothing here is required. The only thing a caller
/// may supply is what to call the credential.
///
/// `deny_unknown_fields` for the same reason `RequestOptionsRequest` has it: an
/// older client still sending `enrollment_token` is told that it means nothing
/// now, rather than having it quietly ignored and believing it was admitted on
/// the strength of one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterOptionsRequest {
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Serialize)]
struct RegisterOptionsResponse {
    registration_id: String,
    options: CreationChallengeResponse,
    /// The cosigner's opening, on an enclave that makes wallet keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    dkg: Option<DkgOpening>,
}

/// The cosigner's opening: its commitment to its secret, before the wallet has
/// made anything.
#[derive(Serialize)]
struct DkgOpening {
    /// `id_c`, hex: the identifier the wallet deals its share to.
    identifier: String,
    /// `a0_c·G`, compressed, hex.
    verifying_key: String,
    /// The proof of knowledge of `a0_c` under `identifier`, as a round-one
    /// package carries it: `{"R": hex, "Z": hex}`.
    proof_of_knowledge: serde_json::Value,
}

#[derive(Deserialize)]
struct RegisterVerifyRequest {
    registration_id: String,
    /// The new credential, **with its PRF results removed**.
    credential: RegisterPublicKeyCredential,
    /// Base64url of the tenant key, 32 bytes: the new tenant's pool is created
    /// with it.
    #[serde(default)]
    tenant_key: Option<String>,
    /// The wallet's half of the DKG.
    #[serde(default)]
    dkg: Option<DkgRequest>,
}

#[derive(Serialize)]
struct RegisterVerifyResponse {
    tenant_id: String,
    credential_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    dkg: Option<DkgAnswer>,
}

/// The wallet's half of the DKG, its packages as threshold's JSON.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DkgRequest {
    /// The wallet's round-one package.
    round1_package: String,
    /// The share the wallet dealt the cosigner, `f_w(id_c)`, as a round-two
    /// package.
    round2_package: String,
}

/// The cosigner's half of the DKG, finished.
#[derive(Serialize)]
struct DkgAnswer {
    /// The cosigner's round-one package, for the wallet's part three.
    round1_package: String,
    /// The share the cosigner dealt the wallet, `f_c(id_w)`, as a round-two
    /// package.
    round2_package: String,
    /// The group key, compressed, hex.
    group_key: String,
}

/// What an interaction challenge is issued for.
///
/// `deny_unknown_fields` is load-bearing: this route used to take a
/// `body_sha256`, and a client still sending one must be told that it means
/// nothing now rather than have it quietly ignored. An approval that names a
/// body it does not bind would be worse than one that never claimed to.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestOptionsRequest {
    /// Which passkey the client intends to use. The runtime allows exactly
    /// that one, so an assertion from any other credential fails even before
    /// the credential lookup.
    credential_id: String,
    method: String,
    path: String,
    #[serde(default)]
    query: Option<String>,
}

/// The assertion, coming back to be turned into a token.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestVerifyRequest {
    challenge_id: String,
    /// Base64url of the `PublicKeyCredential` JSON `navigator.credentials.get()`
    /// produced, **with its PRF results removed**.
    assertion: String,
    /// Base64url of the tenant key, 32 bytes ([`crate::tenant::TenantKey`]): what
    /// opens this tenant's pool. Required: a release opens a tenant's data
    /// only with the key its owner sends it.
    tenant_key: String,
}

/// Whether a credential or an assertion carries the output of a PRF — the
/// WebAuthn `prf` extension, or the CTAP `hmac-secret` it is built on.
///
/// The one thing a client must never send. The tenant key is derived from
/// that output, and so is the wallet's DKG polynomial: with it and the share
/// the cosigner dealt, an enclave would hold the whole of a 2-of-2 key.
/// `webauthn-rs` ignores fields it does not know, so this is checked on the
/// raw JSON, before it is parsed.
fn carries_prf(assertion: &serde_json::Value) -> bool {
    ["extensions", "clientExtensionResults"]
        .iter()
        .filter_map(|k| assertion.get(k))
        .any(|ext| {
            ["prf", "hmac_get_secret", "hmacGetSecret"]
                .iter()
                .any(|name| ext.get(name).is_some_and(|v| !v.is_null()))
        })
}

/// A tenant key as the app sends it: base64url of 32 bytes.
fn tenant_key_of(encoded: &str) -> Option<crate::tenant::TenantKey> {
    decode(encoded)
        .and_then(|k| <[u8; 32]>::try_from(k).ok())
        .map(crate::tenant::TenantKey::from_bytes)
}

/// The token, and how long it has to be spent.
#[derive(Serialize)]
struct TokenResponse {
    token: String,
    /// Seconds. This bounds the time to *start* an interaction, and is not how
    /// long one may run once started.
    expires_in_secs: u64,
}

#[derive(Serialize)]
struct RequestOptionsResponse {
    challenge_id: String,
    options: RequestChallengeResponse,
}

struct PendingRegistration {
    state: PasskeyRegistration,
    /// The WebAuthn user handle this registration was started with: what the
    /// cosigner's polynomial is derived from.
    handle: [u8; 16],
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
    credentials: Arc<RegistryCredentials>,
    entropy: Arc<dyn nitro_nsm::Nsm>,
    zfs: Arc<crate::store::zfs::Zfs>,
    /// What the cosigner's DKG polynomials are derived from. `None`, and this
    /// enclave makes no wallet keys.
    operator_master: Option<Arc<OperatorMaster>>,
    registrations: Mutex<HashMap<[u8; 16], PendingRegistration>>,
}

impl AuthEndpoints {
    pub fn new(
        gate: Arc<Gate>,
        credentials: Arc<RegistryCredentials>,
        zfs: Arc<crate::store::zfs::Zfs>,
        entropy: Arc<dyn nitro_nsm::Nsm>,
        operator_master: Option<Arc<OperatorMaster>>,
    ) -> Self {
        AuthEndpoints {
            gate,
            credentials,
            entropy,
            zfs,
            operator_master,
            registrations: Mutex::new(HashMap::new()),
        }
    }

    /// What the DKG derives from, for the guest's signing to recompute dealt
    /// shares with.
    pub fn operator_master(&self) -> Option<&Arc<OperatorMaster>> {
        self.operator_master.as_ref()
    }

    fn random_id(&self) -> anyhow::Result<[u8; 16]> {
        let mut id = [0u8; 16];
        self.entropy.get_random(&mut id)?;
        Ok(id)
    }

    /// Answer an `/auth/*` request, or `None` if this is not one.
    pub async fn handle(
        &self,
        method: &hyper::Method,
        path: &str,
        body: &[u8],
    ) -> Option<hyper::Response<wasmtime_wasi_http::p2::body::HyperOutgoingBody>> {
        if !path.starts_with(AUTH_PREFIX) {
            return None;
        }
        if method != hyper::Method::POST {
            return Some(problem(
                hyper::StatusCode::METHOD_NOT_ALLOWED,
                "auth routes are POST",
            ));
        }
        if body.len() > MAX_BODY {
            return Some(problem(
                hyper::StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large",
            ));
        }

        Some(match &path[AUTH_PREFIX.len()..] {
            "register/options" => self.register_options(body).await,
            "register/verify" => self.register_verify(body).await,
            "request/options" => self.request_options(body).await,
            "request/verify" => self.request_verify(body).await,
            other => problem(
                hyper::StatusCode::NOT_FOUND,
                &format!("no auth endpoint {other:?}"),
            ),
        })
    }

    async fn register_options(
        &self,
        body: &[u8],
    ) -> hyper::Response<wasmtime_wasi_http::p2::body::HyperOutgoingBody> {
        let Ok(request) = serde_json::from_slice::<RegisterOptionsRequest>(body) else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed request");
        };

        // Registration is open: anyone who can reach this route may create a
        // tenant. What that grants is deliberately narrow — a *new*, empty
        // tenant and nothing else. It cannot reach an existing tenant's data,
        // approve anything, or add a passkey to somebody else's account, all of
        // which still need an assertion from a credential already registered
        // there. Admission control over resource creation is what was given up
        // here; access control was not.
        let name = request.display_name.as_deref().unwrap_or("cosigner");
        let Ok(handle) = self.random_id() else {
            return problem(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
        };
        let handle = Uuid::from_bytes(handle);

        // The cosigner commits first: its opening goes out with the challenge,
        // before the wallet has made anything. It is derived from the handle
        // alone, so nothing about the passkey is needed yet.
        let dkg = match &self.operator_master {
            None => None,
            Some(_) => match self.opening(handle.as_bytes()).await {
                Ok(opening) => Some(opening),
                Err((status, message)) => return problem(status, message),
            },
        };

        // A discoverable platform passkey (`residentKey: required`,
        // `authenticatorAttachment: platform`), not webauthn-rs's default of
        // `residentKey: discouraged` with no attachment. Android below 14 takes
        // the default literally and makes a non-discoverable security-key
        // credential outside Password Manager, which sign-in then cannot find.
        // Clients are native apps, never a browser, so nothing is given up by
        // ruling out roaming security keys and cross-device registration. It
        // also drops credProtect, which Android does not support and a platform
        // passkey does not need.
        let (options, state) = match self
            .gate
            .webauthn()
            .start_google_passkey_in_google_password_manager_only_registration(
                handle, name, name, None,
            ) {
            Ok(pair) => pair,
            Err(e) => {
                tracing::error!(error = %e, "starting registration");
                return problem(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
            }
        };

        let Ok(id) = self.random_id() else {
            return problem(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
        };
        {
            let now = Instant::now();
            let mut pending = self.registrations.lock().expect("registrations poisoned");
            pending.retain(|_, p| p.expires > now);
            if pending.len() >= MAX_REGISTRATIONS {
                return problem(hyper::StatusCode::SERVICE_UNAVAILABLE, "try again");
            }
            pending.insert(
                id,
                PendingRegistration {
                    state,
                    handle: *handle.as_bytes(),
                    expires: now + REGISTRATION_TTL,
                },
            );
        }

        json(
            hyper::StatusCode::OK,
            &RegisterOptionsResponse {
                registration_id: b64(&id),
                options,
                dkg,
            },
        )
    }

    async fn register_verify(
        &self,
        body: &[u8],
    ) -> hyper::Response<wasmtime_wasi_http::p2::body::HyperOutgoingBody> {
        let Ok(raw) = serde_json::from_slice::<serde_json::Value>(body) else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed request");
        };
        if raw.get("credential").is_some_and(carries_prf) {
            return problem(
                hyper::StatusCode::BAD_REQUEST,
                "the credential carries a PRF result; send the tenant key, never the PRF output",
            );
        }
        let Ok(request) = serde_json::from_value::<RegisterVerifyRequest>(raw) else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed request");
        };
        let tenant_key = match request.tenant_key.as_deref().map(tenant_key_of) {
            None => None,
            Some(Some(key)) => Some(key),
            Some(None) => return problem(hyper::StatusCode::BAD_REQUEST, "malformed tenant key"),
        };
        let Some(id) = decode_id(&request.registration_id) else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed registration id");
        };

        // Taken, not borrowed: an attempt that fails must not leave the
        // registration open for another try at the same challenge.
        let pending = {
            let mut registrations = self.registrations.lock().expect("registrations poisoned");
            registrations.remove(&id)
        };
        let Some(pending) = pending.filter(|p| p.expires > Instant::now()) else {
            return problem(hyper::StatusCode::FORBIDDEN, "registration expired");
        };

        let passkey = match self
            .gate
            .webauthn()
            .finish_passkey_registration(&request.credential, &pending.state)
        {
            Ok(passkey) => passkey,
            Err(e) => {
                tracing::warn!(error = %e, "registration did not verify");
                return problem(hyper::StatusCode::FORBIDDEN, "registration did not verify");
            }
        };

        let credential_id = request.credential.raw_id.as_ref().to_vec();
        let tenant_id = tenant_of(&credential_id);

        // The whole DKG, in memory, before anything is kept: a registration
        // whose wallet key cannot be made is refused whole. On an enclave that
        // makes wallet keys this is the only place one is made, so it is not
        // optional there.
        let registered = match (&self.operator_master, &request.dkg) {
            (None, None) => None,
            (Some(_), None) => {
                return problem(
                    hyper::StatusCode::BAD_REQUEST,
                    "the wallet key is made at registration: send the DKG",
                );
            }
            (_, Some(_)) if tenant_key.is_none() => {
                return problem(
                    hyper::StatusCode::BAD_REQUEST,
                    "the wallet key is kept on the tenant's pool: send the tenant key",
                );
            }
            (_, Some(dkg)) => match self.register_dkg(tenant_id, &pending.handle, dkg).await {
                Ok(registered) => Some(registered),
                Err((status, message)) => return problem(status, message),
            },
        };

        // A record and a place for the tenant's pool, durable before this
        // returns.
        if let Err(e) = self.credentials.register(passkey).await {
            tracing::error!(error = format!("{e:#}"), "storing a credential");
            return problem(hyper::StatusCode::CONFLICT, "could not register");
        }
        // The pool, created with the key the new passkey's PRF gave. Failing
        // from here leaves a passkey without a wallet key, which nothing makes
        // later: its app registers another.
        if let Some(key) = &tenant_key {
            if let Err((status, message)) = self.attach(tenant_id, key).await {
                return problem(status, message);
            }
        }
        let dkg = match registered {
            None => None,
            Some(registered) => {
                if let Err((status, message)) = self.keep(tenant_id, &registered.key).await {
                    return problem(status, message);
                }
                Some(DkgAnswer {
                    round1_package: registered.package.to_json(),
                    round2_package: registered.dealt.to_json(),
                    group_key: hex::encode(registered.key.group_key()),
                })
            }
        };

        tracing::info!(
            tenant = %hex::encode(tenant_id),
            credential = %hex::encode(&credential_id[..8.min(credential_id.len())]),
            "registered a passkey"
        );
        json(
            hyper::StatusCode::OK,
            &RegisterVerifyResponse {
                tenant_id: hex::encode(tenant_id),
                credential_id: b64(&credential_id),
                dkg,
            },
        )
    }

    /// Turn a verified assertion into a token for one interaction.
    ///
    /// The second of the three trips a signed interaction takes, and it has to
    /// be its own exchange: a passkey is a challenge-response, so the assertion
    /// cannot exist until `request/options` has already answered. Named to
    /// match `register/options` → `register/verify`, which is the same shape.
    ///
    /// **What the token authorizes: one interaction at the method, path and
    /// query the challenge was issued for.** It commits to no bytes. A person
    /// approved *doing this thing*, not *sending these bytes*, and nothing here
    /// should be described as approval of a payload.
    async fn request_verify(
        &self,
        body: &[u8],
    ) -> hyper::Response<wasmtime_wasi_http::p2::body::HyperOutgoingBody> {
        let Ok(request) = serde_json::from_slice::<RequestVerifyRequest>(body) else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed request");
        };
        let Some(challenge_id) = decode_id(&request.challenge_id) else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed challenge id");
        };
        let Some(tenant_key) = tenant_key_of(&request.tenant_key) else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed tenant key");
        };
        let Some(assertion_json) = decode(&request.assertion) else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed assertion");
        };
        let Ok(raw) = serde_json::from_slice::<serde_json::Value>(&assertion_json) else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed assertion");
        };
        if carries_prf(&raw) {
            return problem(
                hyper::StatusCode::BAD_REQUEST,
                "the assertion carries a PRF result; send the tenant key, never the PRF output",
            );
        }
        let Ok(assertion) = serde_json::from_value::<PublicKeyCredential>(raw) else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed assertion");
        };

        let who = match self.gate.authenticate(&challenge_id, &assertion).await {
            Ok(who) => who,
            Err(denied) => {
                // Logged in full, answered in one sentence — the same rule the
                // gate has always followed.
                tracing::info!(reason = %denied, "refused an assertion");
                return problem(denied.status(), denied.public_message());
            }
        };

        // The tenant's pool, opened with its key — or the key checked against
        // the one it is already open with. A key that does not open it is
        // refused like a bad assertion, and earns no token.
        if let Err((status, message)) = self.attach(who.tenant_id, &tenant_key).await {
            return problem(status, message);
        }

        // Minted here, from the enclave's entropy, and held in exactly two
        // places: this response, and a hash in the store.
        let mut token = [0u8; 32];
        if self.entropy.get_random(&mut token).is_err() {
            return problem(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
        }
        let token = b64(&token);

        let ttl = match self.gate.grant(token.as_bytes(), &who) {
            Ok(ttl) => ttl,
            Err(denied) => {
                tracing::warn!(reason = %denied, "could not record an approval");
                return problem(denied.status(), denied.public_message());
            }
        };

        // The token itself is never logged. What identifies this event is the
        // tenant it belongs to and the interaction it is good for.
        tracing::info!(
            tenant = %hex::encode(who.tenant_id),
            method = %who.scope.method,
            path = %who.scope.path,
            "issued an interaction token"
        );

        json(
            hyper::StatusCode::OK,
            &TokenResponse {
                token,
                expires_in_secs: ttl.as_secs(),
            },
        )
    }

    async fn request_options(
        &self,
        body: &[u8],
    ) -> hyper::Response<wasmtime_wasi_http::p2::body::HyperOutgoingBody> {
        let Ok(request) = serde_json::from_slice::<RequestOptionsRequest>(body) else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed request");
        };
        let Some(credential_id) = decode(&request.credential_id) else {
            return problem(hyper::StatusCode::BAD_REQUEST, "malformed credential id");
        };

        let record = match self.credentials_lookup(&credential_id).await {
            Ok(Some(record)) if record.active => record,
            Ok(_) => {
                // Deliberately the same answer as a credential that exists but
                // is revoked, and the same as one that never did.
                return problem(
                    hyper::StatusCode::FORBIDDEN,
                    "no challenge for that credential",
                );
            }
            Err(e) => {
                tracing::error!(error = format!("{e:#}"), "looking up a credential");
                return problem(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
            }
        };

        let Ok(id) = self.random_id() else {
            return problem(hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
        };
        let scope = InteractionScope::new(&request.method, &request.path, request.query.as_deref());
        match self
            .gate
            .issue(id, scope, std::slice::from_ref(&record.passkey))
        {
            Ok(options) => json(
                hyper::StatusCode::OK,
                &RequestOptionsResponse {
                    challenge_id: b64(&id),
                    options,
                },
            ),
            Err(e) => {
                tracing::warn!(error = %e, "issuing a challenge");
                problem(hyper::StatusCode::SERVICE_UNAVAILABLE, "try again")
            }
        }
    }

    /// Attach a verified tenant's pool with the key it sent.
    async fn attach(
        &self,
        tenant: [u8; 16],
        key: &crate::tenant::TenantKey,
    ) -> Result<(), (hyper::StatusCode, &'static str)> {
        let place = match self.zfs.registry().tenant(tenant).await {
            Ok(Some(record)) => record.place,
            Ok(None) => {
                tracing::error!(tenant = %hex::encode(tenant), "a verified tenant has no record");
                return Err((hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable"));
            }
            Err(e) => {
                tracing::error!(error = format!("{e:#}"), "reading a tenant record");
                return Err((hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable"));
            }
        };
        match self.zfs.attach(tenant, place, key).await {
            Ok(crate::store::zfs::Arrival::New) => {
                tracing::info!(tenant = %hex::encode(tenant), "created a tenant's pool");
                Ok(())
            }
            Ok(crate::store::zfs::Arrival::Returning) => Ok(()),
            Err(crate::store::zfs::AttachError::WrongKey) => {
                tracing::warn!(
                    tenant = %hex::encode(tenant),
                    "a verified assertion came with a tenant key that does not open its pool"
                );
                Err((hyper::StatusCode::UNAUTHORIZED, "not approved"))
            }
            Err(e @ crate::store::zfs::AttachError::Superseded(_)) => {
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

    /// The cosigner's opening for the registration whose user handle is
    /// `handle`.
    async fn opening(
        &self,
        handle: &[u8; 16],
    ) -> Result<DkgOpening, (hyper::StatusCode, &'static str)> {
        let master = self.master().await?;
        let opening = crate::signer::dkg::opening(master, handle).map_err(|e| {
            tracing::error!(error = %e, "making the cosigner's opening");
            (hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable")
        })?;
        Ok(DkgOpening {
            identifier: hex::encode(opening.identifier.serialize()),
            verifying_key: hex::encode(opening.verifying_key.serialize()),
            proof_of_knowledge: opening.proof.to_json_value(),
        })
    }

    /// The cosigner's whole DKG for a registration, in memory: nothing is kept.
    async fn register_dkg(
        &self,
        tenant: [u8; 16],
        handle: &[u8; 16],
        dkg: &DkgRequest,
    ) -> Result<crate::signer::dkg::Registered, (hyper::StatusCode, &'static str)> {
        use threshold::dkg::{Round1Package, Round2Package};
        let malformed = (hyper::StatusCode::BAD_REQUEST, "malformed DKG package");
        let wallet = Round1Package::from_json(&dkg.round1_package).map_err(|_| malformed)?;
        let from_wallet = Round2Package::from_json(&dkg.round2_package).map_err(|_| malformed)?;
        let master = self.master().await?;
        crate::signer::dkg::register(master, handle, &wallet, &from_wallet).map_err(|e| {
            tracing::info!(tenant = %hex::encode(tenant), reason = %e, "refused a DKG package");
            (
                hyper::StatusCode::BAD_REQUEST,
                "the DKG package did not verify",
            )
        })
    }

    /// Keep a tenant's wallet key on its pool, which must be attached.
    async fn keep(
        &self,
        tenant: [u8; 16],
        key: &crate::signer::WalletKey,
    ) -> Result<(), (hyper::StatusCode, &'static str)> {
        match crate::signer::store(&self.zfs, tenant, key).await {
            Ok(crate::signer::Stored::New) => {
                tracing::info!(tenant = %hex::encode(tenant), "kept a wallet key");
                Ok(())
            }
            Ok(crate::signer::Stored::Same) => Ok(()),
            Ok(crate::signer::Stored::Different) => {
                tracing::warn!(tenant = %hex::encode(tenant), "refused a second wallet key");
                Err((
                    hyper::StatusCode::CONFLICT,
                    "this tenant already has another wallet key",
                ))
            }
            Err(e) => {
                tracing::error!(error = format!("{e:#}"), "keeping a wallet key");
                Err((hyper::StatusCode::INTERNAL_SERVER_ERROR, "unavailable"))
            }
        }
    }

    /// The operator master, or why there is none to derive from.
    async fn master(&self) -> Result<&[u8; 32], (hyper::StatusCode, &'static str)> {
        let Some(master) = &self.operator_master else {
            return Err((
                hyper::StatusCode::SERVICE_UNAVAILABLE,
                "this enclave makes no wallet keys",
            ));
        };
        master.get().await.map_err(|e| {
            tracing::warn!(error = format!("{e:#}"), "reading the operator master");
            (
                hyper::StatusCode::SERVICE_UNAVAILABLE,
                "the operator master is not provisioned yet",
            )
        })
    }

    async fn credentials_lookup(
        &self,
        credential_id: &[u8],
    ) -> anyhow::Result<Option<super::gate::CredentialRecord>> {
        use super::gate::CredentialStore;
        self.credentials.lookup(credential_id).await
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

fn body_of(bytes: Vec<u8>) -> wasmtime_wasi_http::p2::body::HyperOutgoingBody {
    use http_body_util::BodyExt;
    http_body_util::Full::new(Bytes::from(bytes))
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed_unsync()
}

fn json<T: Serialize>(
    status: hyper::StatusCode,
    value: &T,
) -> hyper::Response<wasmtime_wasi_http::p2::body::HyperOutgoingBody> {
    let bytes = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    hyper::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        // Challenges and options are single-use and short-lived; a cache that
        // replayed one would be handing out a used challenge.
        .header("cache-control", "no-store")
        .body(body_of(bytes))
        .expect("response is well formed")
}

fn problem(
    status: hyper::StatusCode,
    detail: &str,
) -> hyper::Response<wasmtime_wasi_http::p2::body::HyperOutgoingBody> {
    json(status, &serde_json::json!({ "error": detail }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::challenge::{ChallengeStore, DEFAULT_CAPACITY, DEFAULT_TTL};
    use crate::auth::testing::{Relying, ORIGIN, RP_ID};
    use crate::auth::SoftwareAuthenticator;
    use crate::store::zfs::Zfs;
    use http_body_util::BodyExt;

    const MASTER: [u8; 32] = [7; 32];

    struct Fixture {
        endpoints: AuthEndpoints,
        fs: Arc<Zfs>,
        credentials: Arc<RegistryCredentials>,
    }

    async fn fixture() -> Fixture {
        let fs = Zfs::scratch().await;
        let credentials = Arc::new(RegistryCredentials::new(fs.registry().clone()));
        let gate = Arc::new(Gate::new(
            Relying::new().webauthn,
            ChallengeStore::new(DEFAULT_TTL, DEFAULT_CAPACITY),
            credentials.clone(),
            super::super::TokenStore::new(
                std::time::Duration::from_secs(60),
                super::super::token::DEFAULT_CAPACITY,
            ),
        ));
        let entropy: Arc<dyn nitro_nsm::Nsm> = Arc::new(nitro_nsm::fake::FakeNsm::new());
        let endpoints = AuthEndpoints::new(
            gate,
            credentials.clone(),
            fs.clone(),
            entropy,
            Some(Arc::new(OperatorMaster::fixed(MASTER))),
        );
        Fixture {
            endpoints,
            fs,
            credentials,
        }
    }

    async fn post(f: &Fixture, path: &str, body: serde_json::Value) -> (u16, serde_json::Value) {
        let response = f
            .endpoints
            .handle(&hyper::Method::POST, path, body.to_string().as_bytes())
            .await
            .expect("an auth route");
        let status = response.status().as_u16();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    /// Register a passkey the way the app does, and get its tenant back.
    async fn register(f: &Fixture, auth: &SoftwareAuthenticator) -> (u16, serde_json::Value) {
        let (status, body, _) = register_with(f, auth, |_| {}).await;
        (status, body)
    }

    /// Register as the app does: on an enclave that makes wallet keys, the
    /// cosigner's opening is checked and dealt to, and the wallet's round one
    /// and share go with the credential and the tenant key. `edit` changes the
    /// request first. Back: the answer, and the wallet when it dealt.
    async fn register_with(
        f: &Fixture,
        auth: &SoftwareAuthenticator,
        edit: impl FnOnce(&mut serde_json::Value),
    ) -> (
        u16,
        serde_json::Value,
        Option<crate::signer::testing::Wallet>,
    ) {
        let (status, options) = post(f, "/auth/register/options", serde_json::json!({})).await;
        if status != 200 {
            return (status, options, None);
        }
        let challenge = options["options"]["publicKey"]["challenge"]
            .as_str()
            .expect("a challenge")
            .to_string();
        let mut body = serde_json::json!({
            "registration_id": options["registration_id"],
            "credential": auth.register(&challenge, ORIGIN),
            "tenant_key": key_of(auth),
        });
        let mut wallet = None;
        if let Some(opening) = options.get("dkg") {
            let mut w = crate::signer::testing::Wallet::random();
            let to_cosigner = w.deal(&opening_of(opening)).expect("the opening verifies");
            body["dkg"] = serde_json::json!({
                "round1_package": w.package.to_json(),
                "round2_package": to_cosigner.to_json(),
            });
            wallet = Some(w);
        }
        edit(&mut body);
        let (status, answer) = post(f, "/auth/register/verify", body).await;
        (status, answer, wallet)
    }

    /// The cosigner's opening, off the wire.
    fn opening_of(json: &serde_json::Value) -> crate::signer::dkg::Opening {
        let mut vk = [0u8; 33];
        hex::decode_to_slice(json["verifying_key"].as_str().unwrap(), &mut vk).unwrap();
        crate::signer::dkg::Opening {
            identifier: json["identifier"].as_str().unwrap().parse().unwrap(),
            verifying_key: threshold::keys::VerifyingKey::deserialize(&vk).unwrap(),
            proof: threshold::dkg::DkgSignature::from_json_value(&json["proof_of_knowledge"])
                .unwrap(),
        }
    }

    /// Options ask for a passkey sign-in can find. With webauthn-rs's defaults,
    /// Android below 14 made a credential One Tap reports as "Cannot find a
    /// matching credential".
    #[tokio::test]
    async fn registration_asks_for_a_discoverable_platform_passkey() {
        let f = fixture().await;
        let (status, body) = post(&f, "/auth/register/options", serde_json::json!({})).await;
        assert_eq!(status, 200, "{body}");
        let selection = &body["options"]["publicKey"]["authenticatorSelection"];
        assert_eq!(selection["residentKey"], "required", "{selection}");
        assert_eq!(selection["requireResidentKey"], true, "{selection}");
        assert_eq!(
            selection["authenticatorAttachment"], "platform",
            "{selection}"
        );
        assert_eq!(selection["userVerification"], "required", "{selection}");
    }

    /// The whole registration path: options, response, a tenant, and its pool
    /// created with the key the passkey's PRF gave.
    #[tokio::test]
    async fn registration_creates_a_tenant_and_its_pool() {
        let f = fixture().await;
        let auth = SoftwareAuthenticator::new(RP_ID);
        let (status, body) = register(&f, &auth).await;
        assert_eq!(status, 200, "{body}");

        let tenant_hex = body["tenant_id"].as_str().expect("a tenant id");
        assert_eq!(
            tenant_hex,
            hex::encode(tenant_of(auth.credential_id())),
            "the tenant is the one the credential derives"
        );

        // The credential is stored and points at that tenant.
        use crate::auth::gate::CredentialStore;
        let record = f
            .credentials
            .lookup(auth.credential_id())
            .await
            .unwrap()
            .expect("the credential was stored");
        assert_eq!(hex::encode(record.tenant_id), tenant_hex);

        let mut tenant = [0u8; 16];
        hex::decode_to_slice(tenant_hex, &mut tenant).unwrap();
        assert!(f
            .credentials
            .place(auth.credential_id())
            .await
            .unwrap()
            .is_some());
        assert!(f.fs.is_attached(tenant));
        assert!(f.fs.attached_dir(tenant).unwrap().is_dir());

        // Approvals find it open with the same key.
        for _ in 0..2 {
            let (status, body) = verify(&f, &auth, key_of(&auth), |_| {}).await;
            assert_eq!(status, 200, "{body}");
            assert!(body["token"].is_string());
        }
    }

    /// One interaction's approval: options, an assertion, and verify with
    /// `tenant_key` (left out when `None`). `tamper` edits the assertion first.
    async fn verify(
        f: &Fixture,
        auth: &SoftwareAuthenticator,
        tenant_key: Option<String>,
        tamper: impl FnOnce(&mut serde_json::Value),
    ) -> (u16, serde_json::Value) {
        approve(f, auth, tenant_key, tamper, None).await
    }

    /// The same, carrying `dkg` when given.
    async fn approve(
        f: &Fixture,
        auth: &SoftwareAuthenticator,
        tenant_key: Option<String>,
        tamper: impl FnOnce(&mut serde_json::Value),
        dkg: Option<serde_json::Value>,
    ) -> (u16, serde_json::Value) {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let (status, options) = post(
            f,
            "/auth/request/options",
            serde_json::json!({
                "credential_id": b64.encode(auth.credential_id()),
                "method": "GET",
                "path": "/counter",
            }),
        )
        .await;
        assert_eq!(status, 200, "{options}");
        let challenge = options["options"]["publicKey"]["challenge"]
            .as_str()
            .unwrap();
        let mut assertion = auth.assert(challenge, ORIGIN);
        tamper(&mut assertion);
        let mut body = serde_json::json!({
            "challenge_id": options["challenge_id"],
            "assertion": b64.encode(assertion.to_string()),
        });
        if let Some(key) = tenant_key {
            body["tenant_key"] = key.into();
        }
        if let Some(dkg) = dkg {
            body["dkg"] = dkg;
        }
        post(f, "/auth/request/verify", body).await
    }

    /// The whole DKG rides registration: the wallet finishes against the
    /// cosigner's round one, which opens with what the opening committed to,
    /// both sides agree on the key, and it is kept on the new pool with the
    /// handle its dealt share is recomputed from.
    #[tokio::test]
    async fn the_whole_dkg_rides_registration() {
        use threshold::dkg::{Round1Package, Round2Package};
        let f = fixture().await;
        let auth = SoftwareAuthenticator::new(RP_ID);
        let tenant = tenant_of(auth.credential_id());
        let (status, body, wallet) = register_with(&f, &auth, |_| {}).await;
        assert_eq!(status, 200, "{body}");
        let wallet = wallet.expect("this enclave makes wallet keys");

        let dkg = &body["dkg"];
        let cosigner = Round1Package::from_json(dkg["round1_package"].as_str().unwrap()).unwrap();
        let dealt = Round2Package::from_json(dkg["round2_package"].as_str().unwrap()).unwrap();
        let key = wallet
            .finish(&cosigner, &dealt)
            .expect("the cosigner's round one is the one it opened with");
        assert_eq!(dkg["group_key"], hex::encode(key.verifying_key.serialize()));

        let kept = crate::signer::load(&f.fs, tenant)
            .await
            .unwrap()
            .expect("a key");
        assert_eq!(kept.group_key(), key.verifying_key.serialize());
        assert_eq!(
            *crate::signer::dkg::dealt_share(&MASTER, kept.handle(), wallet.id()).unwrap(),
            threshold::scalar::scalar_to_bytes(&dealt.secret_share)
        );
    }

    /// A registration whose wallet key cannot be made is refused whole: no
    /// passkey is kept and no pool is made.
    #[tokio::test]
    async fn a_registration_whose_dkg_fails_is_refused_whole() {
        use threshold::dkg::{Round1Package, Round2Package};
        fn edit_package(
            b: &mut serde_json::Value,
            which: &str,
            forge: impl FnOnce(&str) -> String,
        ) {
            let edited = forge(b["dkg"][which].as_str().unwrap());
            b["dkg"][which] = edited.into();
        }
        type Edit = Box<dyn FnOnce(&mut serde_json::Value)>;
        let f = fixture().await;
        let edits: Vec<Edit> = vec![
            Box::new(|b| {
                b.as_object_mut().unwrap().remove("dkg");
            }),
            Box::new(|b| {
                b.as_object_mut().unwrap().remove("tenant_key");
            }),
            Box::new(|b| b["dkg"]["round1_package"] = "not a package".into()),
            Box::new(|b| {
                edit_package(b, "round2_package", |json| {
                    let mut forged = Round2Package::from_json(json).unwrap();
                    forged.secret_share += k256::Scalar::ONE;
                    forged.to_json()
                })
            }),
            Box::new(|b| {
                edit_package(b, "round1_package", |json| {
                    let mut forged = Round1Package::from_json(json).unwrap();
                    forged.proof_of_knowledge.z += k256::Scalar::ONE;
                    forged.to_json()
                })
            }),
        ];
        for (i, edit) in edits.into_iter().enumerate() {
            let auth = SoftwareAuthenticator::new(RP_ID);
            let (status, body, _) = register_with(&f, &auth, edit).await;
            assert_eq!(status, 400, "case {i}: {body}");
            use crate::auth::gate::CredentialStore;
            assert!(f
                .credentials
                .lookup(auth.credential_id())
                .await
                .unwrap()
                .is_none());
            assert!(!f.fs.is_attached(tenant_of(auth.credential_id())));
        }
    }

    /// With no operator master there is nothing to derive from: registration
    /// offers no opening and makes no wallet key, and one that brings a DKG
    /// anyway is refused.
    #[tokio::test]
    async fn without_an_operator_master_registration_makes_no_wallet_key() {
        let mut f = fixture().await;
        f.endpoints.operator_master = None;
        let (_, options) = post(&f, "/auth/register/options", serde_json::json!({})).await;
        assert!(options.get("dkg").is_none(), "{options}");

        let auth = SoftwareAuthenticator::new(RP_ID);
        let (status, body, wallet) = register_with(&f, &auth, |_| {}).await;
        assert_eq!(status, 200, "{body}");
        assert!(wallet.is_none() && body.get("dkg").is_none());

        let mut w = crate::signer::testing::Wallet::random();
        let share = w
            .deal(&crate::signer::dkg::opening(&MASTER, &[0; 16]).unwrap())
            .unwrap();
        let dkg = serde_json::json!({
            "round1_package": w.package.to_json(),
            "round2_package": share.to_json(),
        });
        let auth = SoftwareAuthenticator::new(RP_ID);
        let (status, body, _) = register_with(&f, &auth, |b| b["dkg"] = dkg).await;
        assert_eq!(status, 503, "{body}");
    }

    /// The PRF output is refused at registration too: with it and the share
    /// the cosigner deals, an enclave would hold the whole wallet key.
    #[tokio::test]
    async fn a_credential_carrying_a_prf_result_is_refused() {
        let f = fixture().await;
        let auth = SoftwareAuthenticator::new(RP_ID);
        let (status, body, _) = register_with(&f, &auth, |b| {
            b["credential"]["clientExtensionResults"] =
                serde_json::json!({ "prf": { "results": { "first": "AAAA" } } });
        })
        .await;
        assert_eq!(status, 400, "{body}");
        assert!(!f.fs.is_attached(tenant_of(auth.credential_id())));
    }

    /// An approval makes no wallet key: a `dkg` field there means nothing now,
    /// and is refused rather than ignored.
    #[tokio::test]
    async fn an_approval_carries_no_dkg() {
        let f = fixture().await;
        let auth = SoftwareAuthenticator::new(RP_ID);
        assert_eq!(register(&f, &auth).await.0, 200);
        let dkg = serde_json::json!({ "round1_package": "{}", "round2_package": "{}" });
        let (status, body) = approve(&f, &auth, key_of(&auth), |_| {}, Some(dkg)).await;
        assert_eq!(status, 400, "{body}");
        assert!(body.get("token").is_none());
    }

    fn key_of(auth: &SoftwareAuthenticator) -> Option<String> {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        Some(b64.encode(auth.tenant_key().expose_secret()))
    }

    /// A key that does not open the pool earns no token, though the assertion
    /// was good.
    #[tokio::test]
    async fn a_wrong_tenant_key_earns_no_token() {
        let f = fixture().await;
        let auth = SoftwareAuthenticator::new(RP_ID);
        assert_eq!(register(&f, &auth).await.0, 200);
        assert_eq!(verify(&f, &auth, key_of(&auth), |_| {}).await.0, 200);

        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let wrong = Some(b64.encode([0x42; 32]));
        let (status, body) = verify(&f, &auth, wrong, |_| {}).await;
        assert_eq!(status, 401, "{body}");
        assert!(body.get("token").is_none());
    }

    /// No key, or one that is not 32 bytes, is a malformed request.
    #[tokio::test]
    async fn a_missing_or_short_tenant_key_is_malformed() {
        let f = fixture().await;
        let auth = SoftwareAuthenticator::new(RP_ID);
        assert_eq!(register(&f, &auth).await.0, 200);
        assert_eq!(verify(&f, &auth, None, |_| {}).await.0, 400);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        assert_eq!(
            verify(&f, &auth, Some(b64.encode([1; 16])), |_| {}).await.0,
            400
        );
    }

    /// The PRF output itself is refused wherever an assertion carries it, so a
    /// careless client cannot hand over the root of the wallet's key.
    #[tokio::test]
    async fn an_assertion_carrying_a_prf_result_is_refused() {
        let f = fixture().await;
        let auth = SoftwareAuthenticator::new(RP_ID);
        assert_eq!(register(&f, &auth).await.0, 200);
        for (field, ext) in [
            (
                "clientExtensionResults",
                serde_json::json!({ "prf": { "results": { "first": "AAAA" } } }),
            ),
            (
                "extensions",
                serde_json::json!({ "prf": { "results": { "first": "AAAA" } } }),
            ),
            (
                "extensions",
                serde_json::json!({ "hmac_get_secret": { "output1": "AAAA" } }),
            ),
        ] {
            let (status, body) = verify(&f, &auth, key_of(&auth), |a| {
                a[field] = ext.clone();
            })
            .await;
            assert_eq!(status, 400, "{field}: {body}");
        }
    }

    /// Registration is open, and each one stands alone: a second, unrelated
    /// passkey registers too and lands in a tenant of its own rather than
    /// joining the first.
    #[tokio::test]
    async fn registration_is_open_and_each_one_is_a_new_tenant() {
        let f = fixture().await;
        let (first_status, first) = register(&f, &SoftwareAuthenticator::new(RP_ID)).await;
        assert_eq!(first_status, 200, "{first}");
        let (second_status, second) = register(&f, &SoftwareAuthenticator::new(RP_ID)).await;
        assert_eq!(second_status, 200, "{second}");
        assert_ne!(
            first["tenant_id"], second["tenant_id"],
            "a second registration joined the first one's tenant"
        );
    }

    /// An older client still sending an enrollment token is told the field
    /// means nothing now, rather than being quietly admitted as though one had
    /// been checked.
    #[tokio::test]
    async fn a_registration_still_carrying_an_enrollment_token_is_refused() {
        let f = fixture().await;
        let (status, _) = post(
            &f,
            "/auth/register/options",
            serde_json::json!({ "enrollment_token": "not-a-real-token-but-long" }),
        )
        .await;
        assert_eq!(status, 400);
    }

    /// A registration response for a challenge that was never issued.
    #[tokio::test]
    async fn an_unknown_registration_id_is_refused() {
        let f = fixture().await;
        let auth = SoftwareAuthenticator::new(RP_ID);
        let (status, _) = post(
            &f,
            "/auth/register/verify",
            serde_json::json!({
                "registration_id": "AAAAAAAAAAAAAAAAAAAAAA",
                "credential": auth.register("Y2hhbGxlbmdl", ORIGIN),
            }),
        )
        .await;
        assert_eq!(status, 403);
    }

    /// A failed attempt must not leave the registration open for another try.
    #[tokio::test]
    async fn a_registration_id_cannot_be_retried() {
        let f = fixture().await;
        let (_, options) = post(&f, "/auth/register/options", serde_json::json!({})).await;
        let auth = SoftwareAuthenticator::new(RP_ID);

        // Wrong challenge: fails.
        let (first, _) = post(
            &f,
            "/auth/register/verify",
            serde_json::json!({
                "registration_id": options["registration_id"],
                "credential": auth.register("d3JvbmctY2hhbGxlbmdl", ORIGIN),
            }),
        )
        .await;
        assert_eq!(first, 403);

        // The right one now also fails: the id was consumed by the attempt.
        let challenge = options["options"]["publicKey"]["challenge"]
            .as_str()
            .unwrap();
        let (second, _) = post(
            &f,
            "/auth/register/verify",
            serde_json::json!({
                "registration_id": options["registration_id"],
                "credential": auth.register(challenge, ORIGIN),
            }),
        )
        .await;
        assert_eq!(second, 403, "a failed registration could be retried");
    }

    /// A challenge is issued only for a credential this runtime knows.
    #[tokio::test]
    async fn a_challenge_is_issued_for_a_registered_credential() {
        let f = fixture().await;
        let auth = SoftwareAuthenticator::new(RP_ID);
        assert_eq!(register(&f, &auth).await.0, 200);

        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let (status, body) = post(
            &f,
            "/auth/request/options",
            serde_json::json!({
                "credential_id": b64.encode(auth.credential_id()),
                "method": "POST",
                "path": "/sign",
            }),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert!(body["challenge_id"].is_string());
        assert!(body["options"]["publicKey"]["challenge"].is_string());
    }

    /// Unknown and revoked credentials are refused identically, so the route
    /// cannot be used to learn which passkeys exist.
    #[tokio::test]
    async fn unknown_and_revoked_credentials_are_indistinguishable() {
        let f = fixture().await;
        let auth = SoftwareAuthenticator::new(RP_ID);
        assert_eq!(register(&f, &auth).await.0, 200);
        f.credentials.revoke(auth.credential_id()).await.unwrap();

        async fn ask(f: &Fixture, id: &[u8]) -> (u16, serde_json::Value) {
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            post(
                f,
                "/auth/request/options",
                serde_json::json!({
                    "credential_id": b64.encode(id),
                    "method": "POST",
                    "path": "/sign",
                }),
            )
            .await
        }
        let revoked = ask(&f, auth.credential_id()).await;
        let unknown = ask(&f, &[0xff; 32]).await;
        assert_eq!(revoked.0, 403);
        assert_eq!(revoked, unknown, "the refusals differ and leak existence");
    }

    /// Everything outside `/auth/` is somebody else's business.
    #[tokio::test]
    async fn other_paths_are_not_claimed() {
        let f = fixture().await;
        assert!(f
            .endpoints
            .handle(&hyper::Method::POST, "/sign", b"{}")
            .await
            .is_none());
        assert!(f
            .endpoints
            .handle(&hyper::Method::GET, "/counter", b"")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn an_unknown_auth_route_is_a_404() {
        let f = fixture().await;
        let (status, _) = post(&f, "/auth/nonsense", serde_json::json!({})).await;
        assert_eq!(status, 404);
    }
}
