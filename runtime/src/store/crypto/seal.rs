//! AES-256-GCM with associated data, for what is stored outside every pool.
//!
//! The object key goes in as associated data, so a sealed blob cannot be moved
//! to another key — an account blob over a certificate, one tenant's cached
//! key over another's — by anyone who can write to the bucket.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, NONCE_LEN};

use crate::store::error::{StoreError, StoreResult};

/// `nonce ‖ ciphertext ‖ tag`, under a fresh random nonce.
pub fn seal(key: &LessSafeKey, aad: &[u8], plaintext: &[u8]) -> StoreResult<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    crate::random::fill(&mut nonce);
    let mut buffer = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        &mut buffer,
    )
    .map_err(|_| StoreError::Io("sealing".to_string()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + buffer.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buffer);
    Ok(out)
}

/// The plaintext of what [`seal`] wrote under the same key and `aad`, or an
/// integrity error for anything else.
pub fn unseal(key: &LessSafeKey, aad: &[u8], sealed: &[u8]) -> StoreResult<Vec<u8>> {
    if sealed.len() <= NONCE_LEN {
        return Err(StoreError::Integrity(
            "sealed blob is too short to hold a nonce",
        ));
    }
    let (nonce, body) = sealed.split_at(NONCE_LEN);
    let mut buffer = body.to_vec();
    let plaintext = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce.try_into().expect("NONCE_LEN bytes")),
            Aad::from(aad),
            &mut buffer,
        )
        .map_err(|_| {
            StoreError::Integrity(
                "sealed blob did not authenticate: another key, another place, or tampered",
            )
        })?;
    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::aead::{UnboundKey, AES_256_GCM};

    fn key(b: u8) -> LessSafeKey {
        LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[b; 32]).unwrap())
    }

    #[test]
    fn round_trips() {
        let sealed = seal(&key(1), b"here", b"secret").unwrap();
        assert_eq!(unseal(&key(1), b"here", &sealed).unwrap(), b"secret");
    }

    /// Moved to another object, or opened under another release's key.
    #[test]
    fn another_place_or_key_is_refused() {
        let sealed = seal(&key(1), b"here", b"secret").unwrap();
        assert!(unseal(&key(1), b"there", &sealed).is_err());
        assert!(unseal(&key(2), b"here", &sealed).is_err());
        assert!(unseal(&key(1), b"here", &sealed[..8]).is_err());
    }
}
