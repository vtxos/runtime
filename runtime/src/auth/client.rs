//! A client's side of `/auth/*`, in software: [`enclave_auth::client`] with a random wallet and
//! the NSM's randomness, in the JSON the tests, the in-process harness and `wallet-client` pass
//! around. What it sends is exactly what a real client sends, field for field
//! (`docs/CLIENT_INTEGRATION.md`).
//!
//! Behind the `testing` feature: it holds a wallet share and signs approvals with it, and nothing
//! that mints approvals should be reachable in a production image.

use enclave_auth::client as auth;
use serde_json::Value;
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, VerifyingKey};
use threshold::point;
use threshold::scalar::{scalar_from_bytes, scalar_to_bytes};
use zeroize::Zeroizing;

use crate::random::Rng;

/// A registration under way: the wallet, committed and not yet dealt.
pub struct Registering(auth::Registering);

impl Default for Registering {
    fn default() -> Self {
        Self::new()
    }
}

impl Registering {
    pub fn new() -> Self {
        Registering(auth::Registering::random(&mut Rng))
    }

    /// The body of `register/options`: the wallet's round one.
    pub fn options_body(&self) -> Value {
        to_json(&self.0.options())
    }

    /// From `register/options`' answer to `register/verify`'s body. `certificate` is the
    /// SHA-256 of the certificate the connection was served. Its attestation is the caller's
    /// to have checked by now.
    pub fn verify_body(
        self,
        options: &Value,
        certificate: &[u8; 32],
    ) -> Result<(Value, PendingRegistration), String> {
        let (body, pending) = self.0.verify(&from_json(options)?, certificate, &mut Rng)?;
        Ok((to_json(&body), PendingRegistration(pending)))
    }
}

/// A registration sent, waiting for `register/verify`'s answer.
pub struct PendingRegistration(auth::PendingRegistration);

impl PendingRegistration {
    /// The client, once the answer names its key and carries a partial the runtime's share
    /// made; with the tenant key both derived.
    pub fn finish(self, answer: &Value) -> Result<(Client, [u8; 32]), String> {
        let registered = self.0.finish(&from_json(answer)?)?;
        Ok((Client(registered.client), *registered.tenant_key))
    }
}

/// A registered client: its share of the wallet key, and what it knows of the runtime's half.
#[derive(Clone, Debug)]
pub struct Client(auth::Client);

impl Client {
    /// `X`, compressed and even-Y.
    pub fn group_key(&self) -> [u8; 33] {
        self.0.group_key()
    }

    pub fn tenant(&self) -> [u8; 16] {
        self.0.tenant()
    }

    /// The wallet's key package, for signing alongside the runtime.
    pub fn key_package(&self) -> &KeyPackage {
        self.0.key_package()
    }

    /// The runtime's FROST identifier.
    pub fn runtime(&self) -> &Identifier {
        self.0.runtime()
    }

    /// `request/options`' body: the interaction a sign-in will approve.
    pub fn options_body(&self, method: &str, path: &str, query: Option<&str>) -> Value {
        to_json(&self.0.options(method, path, query))
    }

    /// `request/verify`'s body, answering the challenge in `options`. Send it only to the
    /// certificate `request/options`' attestation named.
    pub fn verify_body(
        &self,
        options: &Value,
        method: &str,
        path: &str,
        query: Option<&str>,
        certificate: &[u8; 32],
    ) -> Result<(Value, SignIn), String> {
        let (body, sign_in) = self.0.verify(
            &from_json(options)?,
            method,
            path,
            query,
            certificate,
            &mut Rng,
        )?;
        Ok((to_json(&body), SignIn(sign_in)))
    }

    /// The client, as `wallet-client` keeps it between runs.
    pub fn save(&self) -> Value {
        let key = self.0.key_package();
        serde_json::json!({
            "secret_share": hex::encode(scalar_to_bytes(&key.secret_share)),
            "identifier": hex::encode(key.identifier.serialize()),
            "group_key": hex::encode(self.group_key()),
            "runtime": hex::encode(self.runtime().serialize()),
            "runtime_share": hex::encode(point::serialize_compressed(self.0.runtime_share())),
        })
    }

    pub fn load(saved: &Value) -> Result<Self, String> {
        let secret: Zeroizing<[u8; 32]> = Zeroizing::new(hex_array(text(saved, "secret_share")?)?);
        let secret_share = scalar_from_bytes(&secret).map_err(|e| e.to_string())?;
        let identifier = Identifier::deserialize(&hex_array(text(saved, "identifier")?)?)
            .map_err(|e| e.to_string())?;
        let group = VerifyingKey::deserialize(&hex_array(text(saved, "group_key")?)?)
            .map_err(|e| e.to_string())?;
        let runtime = Identifier::deserialize(&hex_array(text(saved, "runtime")?)?)
            .map_err(|e| e.to_string())?;
        let runtime_share =
            point::deserialize_compressed(&hex_array(text(saved, "runtime_share")?)?)
                .map_err(|e| e.to_string())?;
        let key = KeyPackage {
            verifying_share: point::base_mul(&secret_share),
            identifier,
            secret_share,
            verifying_key: group,
            min_signers: 2,
        };
        Ok(Client(auth::Client::new(key, runtime, runtime_share)))
    }
}

/// A sign-in sent, waiting for the runtime's partial.
pub struct SignIn(auth::SignIn);

impl SignIn {
    /// The tenant key, from the runtime's partial in `request/verify`'s answer: what the
    /// runtime opened the pool with.
    pub fn finish(self, answer: &Value) -> Result<[u8; 32], String> {
        Ok(*self.0.finish(&from_json(answer)?)?)
    }
}

fn to_json(value: &impl serde::Serialize) -> Value {
    serde_json::to_value(value).expect("the wire types serialize")
}

fn from_json<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, String> {
    serde_json::from_value(value.clone()).map_err(|e| format!("{e} in {value}"))
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
