//! The record of a tenant's wallet key: the signer's share of it, the key's public package, and
//! the user handle the signer's polynomial was derived from.

use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use zeroize::{Zeroize, Zeroizing};

/// The signer's share of one wallet key, with the key's public package.
#[derive(Clone)]
pub struct WalletKey {
    key_package: KeyPackage,
    public_key_package: PublicKeyPackage,
    /// The registration's WebAuthn user handle: what the dealt share is recomputed from.
    handle: [u8; 16],
}

impl WalletKey {
    pub(super) fn new(
        key_package: KeyPackage,
        public_key_package: PublicKeyPackage,
        handle: [u8; 16],
    ) -> Self {
        Self {
            key_package,
            public_key_package,
            handle,
        }
    }

    /// The group key `V`, compressed and even-Y.
    pub fn group_key(&self) -> [u8; 33] {
        self.public_key_package.verifying_key.serialize()
    }

    /// The signer's FROST identifier.
    pub fn signer(&self) -> &Identifier {
        &self.key_package.identifier
    }

    /// The wallet's FROST identifier: the other signer in the public package.
    pub fn wallet(&self) -> &Identifier {
        self.public_key_package
            .verifying_shares
            .keys()
            .find(|id| **id != self.key_package.identifier)
            .expect("decode and register both hold two signers")
    }

    pub fn public_key_package(&self) -> &PublicKeyPackage {
        &self.public_key_package
    }

    /// The signer's key package: its identifier, its signing share and the group key.
    pub(super) fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }

    pub fn handle(&self) -> &[u8; 16] {
        &self.handle
    }

    /// The record the runtime stores: versioned JSON, holding the signer's share.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let key_package = Zeroizing::new(self.key_package.to_json());
        Zeroizing::new(
            format!(
                r#"{{"v":1,"keyPackage":{},"publicKeyPackage":{},"handle":"{}"}}"#,
                *key_package,
                self.public_key_package.to_json(),
                hex::encode(self.handle)
            )
            .into_bytes(),
        )
    }

    pub fn decode(record: &[u8]) -> Result<Self, String> {
        let v: serde_json::Value =
            serde_json::from_slice(record).map_err(|e| format!("wallet key record: {e}"))?;
        if v["v"] != 1 {
            return Err(format!("wallet key record version {}", v["v"]));
        }
        let key_package = KeyPackage::from_json_value(&v["keyPackage"])
            .map_err(|e| format!("wallet key record: {e}"))?;
        let public_key_package = PublicKeyPackage::from_json_value(&v["publicKeyPackage"])
            .map_err(|e| format!("wallet key record: {e}"))?;
        let shares = &public_key_package.verifying_shares;
        if shares.len() != 2 || !shares.contains_key(&key_package.identifier) {
            return Err("wallet key record: not a 2-of-2 holding the signer".into());
        }
        let handle = v["handle"]
            .as_str()
            .and_then(|h| hex::decode(h).ok())
            .and_then(|h| <[u8; 16]>::try_from(h).ok())
            .ok_or("wallet key record: no handle")?;
        Ok(Self {
            key_package,
            public_key_package,
            handle,
        })
    }
}

impl Drop for WalletKey {
    fn drop(&mut self) {
        self.key_package.secret_share.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing;

    #[test]
    fn the_record_round_trips() {
        let (_, registered, _) = testing::enrol(&[7; 32], &[9; 16]);
        let key = registered.key;
        let back = super::WalletKey::decode(&key.encode()).unwrap();
        assert_eq!(back.group_key(), key.group_key());
        assert_eq!(back.wallet(), key.wallet());
        assert_eq!(back.handle(), key.handle());
        assert_eq!(back.key_package().to_json(), key.key_package().to_json());
    }
}
