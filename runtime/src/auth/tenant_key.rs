//! The tenant key: how a client turns its passkey into the key of its pool.
//!
//! ```text
//! K_t = HKDF-SHA256(ikm = PRF output, salt = "aegira/tenant-key/v1", info = tenant id)
//! ```
//!
//! The PRF output is what the passkey's WebAuthn `prf` extension returns
//! during the same `get()` that produces the assertion, so deriving it costs
//! no prompt. The wallet also seeds its DKG polynomial from that output, with
//! HKDF under the salt `merlin/frost/v1`; this salt keeps the two apart.
//!
//! The client sends `K_t` in `POST /auth/request/verify`, **never the PRF
//! output itself** — with that and the share the cosigner dealt it, the
//! enclave would hold the wallet's whole key — and only after it has checked
//! this enclave's PCR0 and PCR16 on the same connection. Whatever release it
//! does not approve is never sent the key, and can open none of its data.
//!
//! SHA-256 rather than the SHA-384 the enclave's own derivations use, because
//! this one is computed on phones, and every platform has it.

use aws_lc_rs::hkdf::{KeyType, Salt, HKDF_SHA256};

use crate::store::crypto::TenantKey;

/// The HKDF salt. Changing it changes every tenant's key, and strands every
/// pool.
pub const SALT: &[u8] = b"aegira/tenant-key/v1";

struct Len32;
impl KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

/// `K_t` for the tenant `tenant_id`, from its passkey's PRF output.
pub fn derive(prf: &[u8], tenant_id: &[u8; 16]) -> TenantKey {
    let mut out = [0u8; 32];
    Salt::new(HKDF_SHA256, SALT)
        .extract(prf)
        .expand(&[tenant_id], Len32)
        .and_then(|okm| okm.fill(&mut out))
        .expect("32 bytes is within HKDF-SHA256's output limit");
    TenantKey::from_bytes(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte for byte, what every client computes. A change here strands every
    /// tenant's pool; the vector is the one `docs/CLIENT_INTEGRATION.md`
    /// publishes.
    #[test]
    fn the_derivation_is_pinned() {
        let key = derive(&[0x11; 32], &[0x22; 16]);
        assert_eq!(
            hex::encode(key.expose_secret()),
            "57c4b615bf5da47923a682fed599cc34355bf19467ea46c482f244d13bebde6c"
        );
    }

    /// One PRF output, two tenants: two keys.
    #[test]
    fn the_tenant_id_separates_keys() {
        let a = derive(&[0x11; 32], &[1; 16]);
        let b = derive(&[0x11; 32], &[2; 16]);
        assert!(!a.ct_eq(&b));
    }
}
