//! A client's side of `/auth/*`, in software: its half of registration's DKG, and signed sign-ins
//! with their ECDH partial. For the tests, the in-process harness and `wallet-client`.
//!
//! Behind the `testing` feature: it holds a wallet share and signs approvals with it, and nothing
//! that mints approvals should be reachable in a production image. What it sends is exactly what a real client sends, field for field
//! (`docs/CLIENT_INTEGRATION.md`).

use base64::Engine as _;
use k256::ProjectivePoint;
use serde_json::{json, Value};
use threshold::auth::AuthSigner;
use threshold::dkg::{Round1Package, Round2Package};
use threshold::ecdh::{Partial, PartialBytes, Session};
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::point;
use threshold::scalar::{scalar_from_bytes, scalar_to_bytes};
use zeroize::Zeroizing;

use super::approval;
use crate::random::Rng;
use crate::signer::testing::Wallet;

/// A registration under way: the wallet, committed and not yet dealt.
pub struct Registering {
    wallet: Wallet,
}

impl Default for Registering {
    fn default() -> Self {
        Self::new()
    }
}

impl Registering {
    pub fn new() -> Self {
        Registering {
            wallet: Wallet::random(),
        }
    }

    /// The body of `register/options`: the wallet's round one.
    pub fn options_body(&self) -> Value {
        json!({ "dkg": { "round1_package": self.wallet.package.to_json() } })
    }

    /// From `register/options`' answer to `register/verify`'s body: the wallet finishes its
    /// share, deals the runtime its own, signs and makes its partial. `certificate` is the
    /// SHA-256 of the certificate the connection was served. Its attestation is the caller's
    /// to have checked by now.
    pub fn verify_body(
        self,
        options: &Value,
        certificate: &[u8; 32],
    ) -> Result<(Value, PendingRegistration), String> {
        let id = decode_b64::<16>(text(options, "registration_id")?)?;
        let runtime = Round1Package::from_json(text(&options["dkg"], "round1_package")?)
            .map_err(|e| format!("the runtime's round one: {e}"))?;
        let dealt = Round2Package::from_json(text(&options["dkg"], "round2_package")?)
            .map_err(|e| format!("the runtime's dealt share: {e}"))?;
        let (to_runtime, key, public) = self.wallet.respond(&runtime, &dealt)?;
        let client = Client::new(key, &public)?;

        let message = approval::register(
            &id,
            &client.group_key(),
            &client.key.identifier.serialize(),
            certificate,
        );
        let signature = client.sign(&message);
        let (session, partial) = client.partial(&message)?;
        let body = json!({
            "registration_id": b64(&id),
            "dkg": { "round2_package": to_runtime.to_json() },
            "signature": hex::encode(signature),
            "ecdh": wire(&partial),
        });
        Ok((body, PendingRegistration { client, session }))
    }
}

/// A registration sent, waiting for `register/verify`'s answer.
pub struct PendingRegistration {
    client: Client,
    session: Session,
}

impl PendingRegistration {
    /// The client, once the answer names its key and carries a partial the runtime's share
    /// made; with the tenant key both derived.
    pub fn finish(self, answer: &Value) -> Result<(Client, [u8; 32]), String> {
        if text(answer, "group_key")? != hex::encode(self.client.group_key()) {
            return Err("the runtime made another key".into());
        }
        let k = self.client.finish(self.session, &answer["ecdh"])?;
        Ok((self.client, k))
    }
}

/// A registered client: its share of the wallet key, and what it knows of the runtime's half.
#[derive(Clone)]
pub struct Client {
    key: KeyPackage,
    runtime: Identifier,
    runtime_share: ProjectivePoint,
}

impl Client {
    fn new(key: KeyPackage, public: &PublicKeyPackage) -> Result<Self, String> {
        let (runtime, runtime_share) = public
            .verifying_shares
            .iter()
            .find(|(id, _)| **id != key.identifier)
            .map(|(id, share)| (id.clone(), *share))
            .ok_or("no runtime in the public package")?;
        Ok(Client {
            key,
            runtime,
            runtime_share,
        })
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

    /// `request/options`' body: the interaction a sign-in will approve.
    pub fn options_body(&self, method: &str, path: &str, query: Option<&str>) -> Value {
        json!({
            "group_key": hex::encode(self.group_key()),
            "method": method,
            "path": path,
            "query": query,
        })
    }

    /// `request/verify`'s body, answering the challenge in `options`, `request/options`' answer
    /// for the same interaction. `certificate` is the SHA-256 of the certificate the connection
    /// was served. It carries the wallet's partial, and the [`SignIn`] waits for the runtime's:
    /// send it only to the certificate `request/options`' attestation named.
    pub fn verify_body(
        &self,
        options: &Value,
        method: &str,
        path: &str,
        query: Option<&str>,
        certificate: &[u8; 32],
    ) -> Result<(Value, SignIn), String> {
        let challenge_id = decode_b64::<16>(text(options, "challenge_id")?)?;
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
        let (session, partial) = self.partial(&message)?;
        let body = json!({
            "challenge_id": b64(&challenge_id),
            "signature": hex::encode(self.sign(&message)),
            "ecdh": wire(&partial),
        });
        Ok((
            body,
            SignIn {
                client: self.clone(),
                session,
            },
        ))
    }

    /// The client, as `wallet-client` keeps it between runs.
    pub fn save(&self) -> Value {
        json!({
            "secret_share": hex::encode(scalar_to_bytes(&self.key.secret_share)),
            "identifier": hex::encode(self.key.identifier.serialize()),
            "group_key": hex::encode(self.group_key()),
            "runtime": hex::encode(self.runtime.serialize()),
            "runtime_share": hex::encode(point::serialize_compressed(&self.runtime_share)),
        })
    }

    pub fn load(saved: &Value) -> Result<Self, String> {
        let secret: Zeroizing<[u8; 32]> = Zeroizing::new(hex_array(text(saved, "secret_share")?)?);
        let secret_share = scalar_from_bytes(&secret).map_err(|e| e.to_string())?;
        let identifier = Identifier::deserialize(&hex_array(text(saved, "identifier")?)?)
            .map_err(|e| e.to_string())?;
        let group =
            threshold::keys::VerifyingKey::deserialize(&hex_array(text(saved, "group_key")?)?)
                .map_err(|e| e.to_string())?;
        let runtime = Identifier::deserialize(&hex_array(text(saved, "runtime")?)?)
            .map_err(|e| e.to_string())?;
        let runtime_share =
            point::deserialize_compressed(&hex_array(text(saved, "runtime_share")?)?)
                .map_err(|e| e.to_string())?;
        Ok(Client {
            key: KeyPackage {
                verifying_share: point::base_mul(&secret_share),
                identifier,
                secret_share,
                verifying_key: group,
                min_signers: 2,
            },
            runtime,
            runtime_share,
        })
    }

    /// BIP-340 with the wallet's share.
    fn sign(&self, message: &[u8; 32]) -> [u8; 64] {
        let secret = Zeroizing::new(scalar_to_bytes(&self.key.secret_share));
        AuthSigner::from_secret_bytes(&secret)
            .expect("a share is never zero")
            .sign(message)
    }

    fn partial(&self, transcript: &[u8; 32]) -> Result<(Session, Partial), String> {
        Session::start(
            &self.key.verifying_key.point,
            &self.key.identifier,
            &self.key.secret_share,
            transcript,
            &mut Rng,
        )
        .map_err(|e| e.to_string())
    }

    fn finish(&self, session: Session, runtime: &Value) -> Result<[u8; 32], String> {
        let partial = unwire(runtime)?;
        let k = session
            .finish(&self.runtime, &self.runtime_share, &partial)
            .map_err(|e| format!("the runtime's partial: {e}"))?;
        Ok(*k)
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
    /// The tenant key, from the runtime's partial in `request/verify`'s answer: what the
    /// runtime opened the pool with.
    pub fn finish(self, answer: &Value) -> Result<[u8; 32], String> {
        self.client.finish(self.session, &answer["ecdh"])
    }
}

fn wire(partial: &Partial) -> Value {
    let p = partial.to_bytes();
    json!({
        "share": hex::encode(p.share),
        "a": hex::encode(p.a),
        "b": hex::encode(p.b),
        "s": hex::encode(p.s),
    })
}

fn unwire(value: &Value) -> Result<Partial, String> {
    Partial::from_bytes(&PartialBytes {
        share: hex_array(text(value, "share")?)?,
        a: hex_array(text(value, "a")?)?,
        b: hex_array(text(value, "b")?)?,
        s: hex_array(text(value, "s")?)?,
    })
    .map_err(|e| format!("a partial: {e}"))
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("no {field} in {value}"))
}

fn hex_array<const N: usize>(text: &str) -> Result<[u8; N], String> {
    hex::decode(text)
        .ok()
        .and_then(|b| <[u8; N]>::try_from(b).ok())
        .ok_or_else(|| format!("not {N} bytes of hex"))
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
