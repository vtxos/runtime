//! What `/auth/*` carries, as JSON. The runtime reads the requests and writes the answers; a
//! client does the reverse, so both share these.
//!
//! Requests reject unknown fields: an extra field is a 400 rather than ignored. Binary values are
//! hex, except the two single-use ids, which are unpadded base64url. DKG packages are JSON strings
//! in `threshold`'s format.

use serde::{Deserialize, Serialize};
use threshold::ecdh::{Partial, PartialBytes};

/// `register/options`: the wallet's round one, its commitment and proof of knowledge, nothing
/// secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterOptionsRequest {
    pub dkg: WalletCommitment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletCommitment {
    /// threshold's JSON.
    pub round1_package: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterOptionsResponse {
    /// Base64url, 16 bytes: single use, good for five minutes.
    pub registration_id: String,
    pub dkg: RuntimeDeal,
}

/// The runtime's round one, and the share it deals the wallet, as threshold's JSON.
#[derive(Clone, Serialize, Deserialize)]
pub struct RuntimeDeal {
    pub round1_package: String,
    /// `f_c(id_w)`.
    pub round2_package: String,
}

// Redacting Debug: `round2_package` is a dealt share.
impl std::fmt::Debug for RuntimeDeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeDeal")
            .field("round1_package", &self.round1_package)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterVerifyRequest {
    pub registration_id: String,
    pub dkg: WalletDeal,
    /// Hex, 64 bytes: BIP-340 by the wallet's finished share over
    /// [`crate::approval::register`].
    pub signature: String,
    pub ecdh: WirePartial,
}

/// The share the wallet deals the runtime, `f_w(id_c)`, as threshold's JSON.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletDeal {
    pub round2_package: String,
}

// Redacting Debug: `round2_package` is a dealt share.
impl std::fmt::Debug for WalletDeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletDeal").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterVerifyResponse {
    pub tenant_id: String,
    /// `X`, compressed, hex.
    pub group_key: String,
    /// The runtime's ECDH partial: with it the wallet derives the same `k`.
    pub ecdh: WirePartial,
}

/// What a sign-in will approve: one interaction, for the tenant whose group key this is.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestOptionsRequest {
    /// `X`, compressed and even-Y, hex: names the tenant.
    pub group_key: String,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub query: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestOptionsResponse {
    /// Base64url, 16 bytes: single use, good for a minute.
    pub challenge_id: String,
}

/// One sign-in, answering one challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestVerifyRequest {
    pub challenge_id: String,
    /// Hex, 64 bytes: BIP-340 by the wallet's share over [`crate::approval::request`].
    pub signature: String,
    /// The wallet's ECDH partial, over the same message.
    pub ecdh: WirePartial,
}

/// The token, and how long it has to be spent.
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub token: String,
    /// Seconds. This bounds the time to *start* an interaction, and is not how
    /// long one may run once started.
    pub expires_in_secs: u64,
    /// The runtime's ECDH partial: with it the wallet derives the same `k`.
    pub ecdh: WirePartial,
}

// Redacting Debug: `token` admits an interaction.
impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("expires_in_secs", &self.expires_in_secs)
            .finish_non_exhaustive()
    }
}

/// An ECDH partial on the wire ([`threshold::ecdh`]): compressed points and a scalar, hex.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WirePartial {
    pub share: String,
    pub a: String,
    pub b: String,
    pub s: String,
}

impl WirePartial {
    pub fn encode(partial: &Partial) -> Self {
        let bytes = partial.to_bytes();
        WirePartial {
            share: hex::encode(bytes.share),
            a: hex::encode(bytes.a),
            b: hex::encode(bytes.b),
            s: hex::encode(bytes.s),
        }
    }

    /// `None` for anything that is not three points and a scalar of the right sizes.
    pub fn decode(&self) -> Option<Partial> {
        Partial::from_bytes(&PartialBytes {
            share: hex_array(&self.share)?,
            a: hex_array(&self.a)?,
            b: hex_array(&self.b)?,
            s: hex_array(&self.s)?,
        })
        .ok()
    }
}

pub(crate) fn hex_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    hex::decode(text.trim()).ok()?.try_into().ok()
}
