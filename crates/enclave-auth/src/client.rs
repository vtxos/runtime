//! A client's side of `/auth/*`, without I/O: its half of registration's DKG, and signed
//! sign-ins with their ECDH partial. What it sends is exactly what a client sends, field for
//! field (`docs/CLIENT_INTEGRATION.md`).
//!
//! The caller owns the network. Before anything this builds is sent, the caller must have checked
//! the options call's attestation and pinned the certificate it names: the verify calls carry a
//! dealt share or an ECDH partial, which belong only to that certificate.

use std::collections::BTreeMap;

use base64::Engine as _;
use k256::{ProjectivePoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use threshold::auth::AuthSigner;
use threshold::dkg::{self, Round1Package, Round1SecretPackage, Round2Package};
use threshold::ecdh::{Partial, Session};
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::random::mod_n_random;
use threshold::scalar::scalar_to_bytes;
use zeroize::{Zeroize, Zeroizing};

use crate::approval;
use crate::wire::{
    RegisterOptionsRequest, RegisterOptionsResponse, RegisterVerifyRequest, RegisterVerifyResponse,
    RequestOptionsRequest, RequestOptionsResponse, RequestVerifyRequest, TokenResponse,
    WalletCommitment, WalletDeal, WirePartial,
};

/// A registration under way: the wallet, committed and not yet dealt.
pub struct Registering {
    round1: Round1SecretPackage,
    package: Round1Package,
}

impl Registering {
    /// The wallet's polynomial `f_w(z) = a0 + a1·z`, from wherever the app keeps it: a passkey's
    /// PRF, or [`Self::random`]. The runtime cannot tell the two apart.
    pub fn new(
        a0: &Scalar,
        a1: &Scalar,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, String> {
        let (round1, package) =
            dkg::dkg_part1(2, 2, a0, &[*a1], rng).map_err(|e| format!("dkg_part1: {e}"))?;
        Ok(Self { round1, package })
    }

    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let (a0, a1) = (mod_n_random(rng), mod_n_random(rng));
        Self::new(&a0, &a1, rng).expect("a random polynomial")
    }

    /// The wallet's FROST identifier, `SHA256(a0·G) mod n`.
    pub fn identifier(&self) -> &Identifier {
        &self.round1.identifier
    }

    /// `register/options`' body: the wallet's round one.
    pub fn options(&self) -> RegisterOptionsRequest {
        RegisterOptionsRequest {
            dkg: WalletCommitment {
                round1_package: self.package.to_json(),
            },
        }
    }

    /// From `register/options`' answer to `register/verify`'s body: the wallet finishes its
    /// share, deals the runtime its own, signs and makes its partial. `certificate` is the
    /// SHA-256 of the certificate the connection was served.
    pub fn verify(
        self,
        options: &RegisterOptionsResponse,
        certificate: &[u8; 32],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(RegisterVerifyRequest, PendingRegistration), String> {
        let id = decode_b64::<16>(&options.registration_id)?;
        let runtime = Round1Package::from_json(&options.dkg.round1_package)
            .map_err(|e| format!("the runtime's round one: {e}"))?;
        let dealt = Round2Package::from_json(&options.dkg.round2_package)
            .map_err(|e| format!("the runtime's dealt share: {e}"))?;
        let (to_runtime, key, public) = finish_dkg(&self.round1, &runtime, &dealt)?;
        let client = Client::from_public(key, &public)?;

        let message = approval::register(
            &id,
            &client.group_key(),
            &client.key.identifier.serialize(),
            certificate,
        );
        let signature = client.sign(&message);
        let (session, partial) = client.partial(&message, rng)?;
        let body = RegisterVerifyRequest {
            registration_id: b64(&id),
            dkg: WalletDeal {
                round2_package: to_runtime.to_json(),
            },
            signature: hex::encode(signature),
            ecdh: WirePartial::encode(&partial),
        };
        let dealt = Zeroizing::new(scalar_to_bytes(&dealt.secret_share));
        Ok((
            body,
            PendingRegistration {
                client,
                session,
                dealt,
            },
        ))
    }
}

/// The wallet's DKG parts two and three, against the runtime's round one, its proof checked, and
/// the share it dealt. Returns the share for the runtime, which `register/verify` carries, the
/// wallet's own key package, and the key's public package.
pub fn finish_dkg(
    round1: &Round1SecretPackage,
    runtime: &Round1Package,
    dealt: &Round2Package,
) -> Result<(Round2Package, KeyPackage, PublicKeyPackage), String> {
    if runtime.commitment.coeffs.len() != 2 {
        return Err("the runtime's round one is not of a 2-of-2".into());
    }
    let id = Identifier::derive(&runtime.commitment.to_verifying_key().serialize())
        .map_err(|e| e.to_string())?;
    let theirs = BTreeMap::from([(id.clone(), runtime.clone())]);
    let (round2, mut out) = dkg::dkg_part2(round1, &theirs, &[]).map_err(|e| e.to_string())?;
    let to_runtime = out.remove(&id).ok_or("no share for the runtime")?;
    let (key, public) = dkg::dkg_part3(
        round1,
        &round2,
        &theirs,
        &BTreeMap::from([(id, dealt.clone())]),
        &[],
    )
    .map_err(|e| e.to_string())?;
    Ok((to_runtime, key, public))
}

/// A registration sent, waiting for `register/verify`'s answer.
pub struct PendingRegistration {
    client: Client,
    session: Session,
    dealt: Zeroizing<[u8; 32]>,
}

impl PendingRegistration {
    /// The registered client, once the answer names its key and carries a partial the runtime's
    /// share made.
    pub fn finish(self, answer: &RegisterVerifyResponse) -> Result<Registered, String> {
        if answer.group_key != hex::encode(self.client.group_key()) {
            return Err("the runtime made another key".into());
        }
        let tenant_key = self.client.finish(self.session, &answer.ecdh)?;
        Ok(Registered {
            client: self.client,
            tenant_key,
            dealt_share: self.dealt,
        })
    }
}

/// What registering leaves the wallet with.
pub struct Registered {
    pub client: Client,
    /// `k`, the tenant key both sides derived.
    pub tenant_key: Zeroizing<[u8; 32]>,
    /// `f_c(id_w)`, the share the runtime dealt, as it was dealt (before `dkg_part3`'s even-Y
    /// normalisation). With the wallet's own polynomial it rebuilds the wallet's share, and
    /// without that polynomial it rebuilds nothing.
    pub dealt_share: Zeroizing<[u8; 32]>,
}

/// A registered client: its share of the wallet key, and what it knows of the runtime's half.
#[derive(Clone)]
pub struct Client {
    key: KeyPackage,
    runtime: Identifier,
    runtime_share: ProjectivePoint,
}

impl Client {
    /// A client from its key package and the runtime's identifier and verifying share, as a
    /// wallet that rebuilds its share at each use assembles it.
    pub fn new(key: KeyPackage, runtime: Identifier, runtime_share: ProjectivePoint) -> Self {
        Self {
            key,
            runtime,
            runtime_share,
        }
    }

    fn from_public(key: KeyPackage, public: &PublicKeyPackage) -> Result<Self, String> {
        let (runtime, runtime_share) = public
            .verifying_shares
            .iter()
            .find(|(id, _)| **id != key.identifier)
            .map(|(id, share)| (id.clone(), *share))
            .ok_or("no runtime in the public package")?;
        Ok(Self::new(key, runtime, runtime_share))
    }

    /// `X`, compressed and even-Y.
    pub fn group_key(&self) -> [u8; 33] {
        self.key.verifying_key.serialize()
    }

    pub fn tenant(&self) -> [u8; 16] {
        crate::tenant::tenant_of(&self.group_key())
    }

    /// The wallet's key package, for signing alongside the runtime.
    pub fn key_package(&self) -> &KeyPackage {
        &self.key
    }

    /// The runtime's FROST identifier.
    pub fn runtime(&self) -> &Identifier {
        &self.runtime
    }

    /// The runtime's verifying share, which its ECDH partials are checked against.
    pub fn runtime_share(&self) -> &ProjectivePoint {
        &self.runtime_share
    }

    /// `request/options`' body: the interaction a sign-in will approve.
    pub fn options(&self, method: &str, path: &str, query: Option<&str>) -> RequestOptionsRequest {
        RequestOptionsRequest {
            group_key: hex::encode(self.group_key()),
            method: method.to_string(),
            path: path.to_string(),
            query: query.map(str::to_string),
        }
    }

    /// `request/verify`'s body, answering the challenge in `options`, `request/options`' answer
    /// for the same interaction. `certificate` is the SHA-256 of the certificate the connection
    /// was served. It carries the wallet's partial, and the [`SignIn`] waits for the runtime's.
    pub fn verify(
        &self,
        options: &RequestOptionsResponse,
        method: &str,
        path: &str,
        query: Option<&str>,
        certificate: &[u8; 32],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(RequestVerifyRequest, SignIn), String> {
        let challenge_id = decode_b64::<16>(&options.challenge_id)?;
        let message = approval::request(&approval::Request {
            challenge_id: &challenge_id,
            group_key: &self.group_key(),
            wallet: &self.key.identifier.serialize(),
            certificate,
            // As the runtime records the challenge's interaction: the method in upper case.
            method: &method.to_ascii_uppercase(),
            path,
            query,
        });
        let (session, partial) = self.partial(&message, rng)?;
        let body = RequestVerifyRequest {
            challenge_id: b64(&challenge_id),
            signature: hex::encode(self.sign(&message)),
            ecdh: WirePartial::encode(&partial),
        };
        Ok((
            body,
            SignIn {
                client: self.clone(),
                session,
            },
        ))
    }

    /// BIP-340 with the wallet's share.
    fn sign(&self, message: &[u8; 32]) -> [u8; 64] {
        let secret = Zeroizing::new(scalar_to_bytes(&self.key.secret_share));
        AuthSigner::from_secret_bytes(&secret)
            .expect("a share is never zero")
            .sign(message)
    }

    fn partial(
        &self,
        transcript: &[u8; 32],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Session, Partial), String> {
        Session::start(
            &self.key.verifying_key.point,
            &self.key.identifier,
            &self.key.secret_share,
            transcript,
            rng,
        )
        .map_err(|e| e.to_string())
    }

    fn finish(
        &self,
        session: Session,
        runtime: &WirePartial,
    ) -> Result<Zeroizing<[u8; 32]>, String> {
        let partial = runtime
            .decode()
            .ok_or("the runtime's partial is malformed")?;
        session
            .finish(&self.runtime, &self.runtime_share, &partial)
            .map_err(|e| format!("the runtime's partial: {e}"))
    }
}

impl Drop for Client {
    /// The share goes with the client: a closed wallet leaves no copy of it in memory.
    fn drop(&mut self) {
        self.key.secret_share.zeroize();
    }
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("group_key", &hex::encode(self.group_key()))
            .finish_non_exhaustive()
    }
}

/// A sign-in sent, waiting for the runtime's partial.
pub struct SignIn {
    client: Client,
    session: Session,
}

impl SignIn {
    /// The tenant key, from the runtime's partial in `request/verify`'s answer: what the runtime
    /// opened the pool with.
    pub fn finish(self, answer: &TokenResponse) -> Result<Zeroizing<[u8; 32]>, String> {
        self.client.finish(self.session, &answer.ecdh)
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_b64<const N: usize>(text: &str) -> Result<[u8; N], String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .ok()
        .and_then(|b| <[u8; N]>::try_from(b).ok())
        .ok_or_else(|| format!("not {N} bytes of base64url"))
}
