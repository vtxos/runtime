//! The release's key hierarchy: what one release keeps for itself.
//!
//! Two roots, because two parties hold the state. A tenant's data is keyed from its own key,
//! which only its owner's app holds ([`crate::tenant`]). What belongs to one release — its TLS
//! certificate, its cache of tenant keys for background work — hangs off a [`MasterSecret`] that
//! KMS releases only to that release's PCR0 and PCR16, through [`VersionKeys`]. A new release gets
//! a new one and inherits none of it.
//!
//! ```text
//!   MasterSecret (KMS, one release)
//!        │
//!   HKDF-SHA384(salt = fs_uuid ‖ vid, info = purpose)
//!   ┌────┼──────────────┐
//!   ▼    ▼              ▼
//!  ACME  tenant-key     anonymous
//!  seal  cache key      tenant key
//! ```
//!
//! Separate keys per purpose so that a weakness in one use cannot be pivoted into another.

use aws_lc_rs::aead::{LessSafeKey, UnboundKey, AES_256_GCM};
use aws_lc_rs::hkdf::{KeyType, Salt, HKDF_SHA384};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::tenant::TenantKey;

use crate::store::error::{StoreError, StoreResult};

/// HKDF info strings. Versioned so a future format revision can rotate
/// derived keys without changing the secret they come from.
/// Seals the runtime's own secrets — the ACME account key and the TLS
/// certificate's private key — which live in the roots bucket.
///
/// In the bucket rather than on a pool, because a certificate has to be
/// served before anything else is, and a separate label keeps it
/// cryptographically distinct from everything else derived here.
const INFO_RUNTIME_SEAL: &[u8] = b"enclave/runtime-seal/v1";
/// Seals each tenant key this release keeps for background work.
const INFO_TENANT_CACHE: &[u8] = b"aegira/version/tenant-key-cache/v1";
/// The key of the anonymous tenant a deployment with no gate serves.
const INFO_ANONYMOUS: &[u8] = b"aegira/version/anonymous-tenant/v1";

/// Length of an Ed25519 public key and of a raw signing seed.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// The root of the key hierarchy. Scrubbed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterSecret([u8; 32]);

impl MasterSecret {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        MasterSecret(bytes)
    }

    /// The raw bytes.
    ///
    /// Named to be conspicuous at the call site. There is exactly one
    /// legitimate reason to reach in here — sealing the secret so it can be
    /// stored — and everything else should take a `&MasterSecret` and derive
    /// what it needs through [`VersionKeys`], which is why no plain `as_bytes`
    /// exists.
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parse a 64-character hex string, as supplied by `--data-key` or an
    /// environment variable in development.
    pub fn from_hex(s: &str) -> StoreResult<Self> {
        let s = s.trim();
        if s.len() != 64 {
            return Err(StoreError::Invalid("master key must be 64 hex characters"));
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| StoreError::Invalid("master key is not valid hex"))?;
        }
        Ok(MasterSecret(out))
    }

    /// Generate a fresh random secret. Used when formatting a new filesystem
    /// in development; production keys come from KMS.
    pub fn generate() -> StoreResult<Self> {
        let mut out = [0u8; 32];
        aws_lc_rs::rand::fill(&mut out)
            .map_err(|_| StoreError::Io("system RNG unavailable".to_string()))?;
        Ok(MasterSecret(out))
    }
}

/// Deliberately opaque: a `Debug` that printed the bytes would leak the key
/// into any log line that formats a struct containing one.
impl std::fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterSecret(<redacted>)")
    }
}

/// Arbitrary-length HKDF output.
struct OkmLen(usize);
impl KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-SHA384 over raw input key material.
pub fn hkdf_raw(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> StoreResult<()> {
    let prk = Salt::new(HKDF_SHA384, salt).extract(ikm);
    prk.expand(&[info], OkmLen(out.len()))
        .and_then(|okm| okm.fill(out))
        .map_err(|_| StoreError::Io("HKDF expansion failed".to_string()))
}

/// HKDF-SHA384 from the master secret.
pub fn hkdf(secret: &MasterSecret, salt: &[u8], info: &[u8], out: &mut [u8]) -> StoreResult<()> {
    hkdf_raw(&secret.0, salt, info, out)
}

pub(crate) fn aes_key(bytes: &[u8; 32]) -> StoreResult<LessSafeKey> {
    Ok(LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, bytes)
            .map_err(|_| StoreError::Io("AES key setup failed".to_string()))?,
    ))
}

/// What one release keeps for itself, from the master secret KMS releases to
/// it alone.
pub struct VersionKeys {
    runtime_seal_key: LessSafeKey,
    tenant_cache_key: LessSafeKey,
    anonymous: TenantKey,
}

impl VersionKeys {
    /// `salt` names the release: the filesystem id and the release's id, so two
    /// releases under one master secret (a static development key) still keep
    /// apart.
    pub fn derive(master: &MasterSecret, salt: &[u8]) -> StoreResult<Self> {
        let mut bytes = [0u8; 32];
        hkdf(master, salt, INFO_RUNTIME_SEAL, &mut bytes)?;
        let runtime_seal_key = aes_key(&bytes)?;
        hkdf(master, salt, INFO_TENANT_CACHE, &mut bytes)?;
        let tenant_cache_key = aes_key(&bytes)?;
        hkdf(master, salt, INFO_ANONYMOUS, &mut bytes)?;
        let anonymous = TenantKey::from_bytes(bytes);
        bytes.zeroize();
        Ok(VersionKeys {
            runtime_seal_key,
            tenant_cache_key,
            anonymous,
        })
    }

    /// Seals runtime secrets stored outside every pool. See
    /// [`INFO_RUNTIME_SEAL`].
    pub fn runtime_seal_key(&self) -> &LessSafeKey {
        &self.runtime_seal_key
    }

    /// Seals the tenant keys this release keeps for background work.
    pub fn tenant_cache_key(&self) -> &LessSafeKey {
        &self.tenant_cache_key
    }

    /// The anonymous tenant's key, when no gate is configured. A release's
    /// own, so its data lasts only as long as the release.
    pub fn anonymous(&self) -> &TenantKey {
        &self.anonymous
    }
}

impl std::fmt::Debug for VersionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VersionKeys(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two releases under one master secret — a static development key — must
    /// not share a cache key or an anonymous tenant.
    #[test]
    fn releases_are_separated_by_their_salt() {
        let master = MasterSecret::from_bytes([9; 32]);
        let a = VersionKeys::derive(&master, b"release-a").unwrap();
        let b = VersionKeys::derive(&master, b"release-b").unwrap();
        assert!(!a.anonymous().ct_eq(b.anonymous()));
    }

    #[test]
    fn hex_parsing_round_trips() {
        let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let m = MasterSecret::from_hex(hex).unwrap();
        assert_eq!(m.0[0], 0x01);
        assert_eq!(m.0[31], 0x20);
        // Whitespace from a config file or shell is tolerated.
        assert!(MasterSecret::from_hex(&format!("  {hex}\n")).is_ok());
    }

    #[test]
    fn hex_parsing_rejects_bad_input() {
        assert!(MasterSecret::from_hex("abcd").is_err());
        assert!(MasterSecret::from_hex(&"z".repeat(64)).is_err());
        assert!(MasterSecret::from_hex("").is_err());
    }

    #[test]
    fn generate_produces_distinct_secrets() {
        let a = MasterSecret::generate().unwrap();
        let b = MasterSecret::generate().unwrap();
        assert_ne!(a.0, b.0);
        assert_ne!(a.0, [0u8; 32], "RNG returned all zeros");
    }

    /// A key that prints itself is a key in the logs.
    #[test]
    fn secrets_are_redacted_in_debug_output() {
        let m = MasterSecret::from_bytes([0xab; 32]);
        let s = format!("{m:?}");
        assert_eq!(s, "MasterSecret(<redacted>)");
        assert!(!s.contains("ab"));

        let v = VersionKeys::derive(&m, b"salt").unwrap();
        assert!(!format!("{v:?}").contains("abab"));
    }
}
