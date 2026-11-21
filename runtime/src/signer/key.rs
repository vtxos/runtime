//! A tenant's wallet key as the runtime holds it: its own share, the key's public package, and
//! the handle its polynomial was derived from.
//!
//! It lives in the tenant's registry record ([`TenantKeyRecord`]), with the share sealed under
//! the operator master, rather than on the tenant's pool: the pool's key is derived with this
//! share, so the share has to be readable before the pool is.

use std::collections::BTreeMap;

use k256::{ProjectivePoint, Scalar};
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage, VerifyingKey};
use threshold::point;
use zeroize::Zeroize;

use crate::store::registry::{Member, TenantKeyRecord, SEALED_SHARE_LEN};

/// The runtime's share of one wallet key, with the key's public package.
#[derive(Clone)]
pub struct WalletKey {
    key_package: KeyPackage,
    public_key_package: PublicKeyPackage,
    /// What the runtime's polynomial was derived from, with the operator master: what the dealt
    /// share is recomputed from.
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

    /// The key from its registry record and the runtime's share, unsealed. Refused unless the
    /// share is the one behind the record's verifying share: a record is write-once, and a share
    /// that does not match it is a share somebody substituted.
    pub fn from_record(record: &TenantKeyRecord, secret_share: Scalar) -> Result<Self, String> {
        let member = |m: &Member| -> Result<(Identifier, ProjectivePoint), String> {
            let id = Identifier::deserialize(&m.identifier).map_err(|e| e.to_string())?;
            let share =
                point::deserialize_compressed(&m.verifying_share).map_err(|e| e.to_string())?;
            Ok((id, share))
        };
        let (signer, signer_share) = member(&record.signer)?;
        let (wallet, wallet_share) = member(&record.wallet)?;
        let group = VerifyingKey::deserialize(&record.group_key).map_err(|e| e.to_string())?;
        if !point::points_equal(&point::base_mul(&secret_share), &signer_share) {
            return Err("the runtime's share is not the one its record names".into());
        }
        Ok(Self {
            key_package: KeyPackage {
                identifier: signer.clone(),
                secret_share,
                verifying_share: signer_share,
                verifying_key: group.clone(),
                min_signers: 2,
            },
            public_key_package: PublicKeyPackage {
                verifying_shares: BTreeMap::from([(signer, signer_share), (wallet, wallet_share)]),
                verifying_key: group,
            },
            handle: record.handle,
        })
    }

    /// The registry record of this key, with the runtime's share already sealed.
    pub fn record(&self, share: [u8; SEALED_SHARE_LEN]) -> TenantKeyRecord {
        TenantKeyRecord {
            group_key: self.group_key(),
            signer: Member {
                identifier: self.signer().serialize(),
                verifying_share: point::serialize_compressed(&self.key_package.verifying_share),
            },
            wallet: Member {
                identifier: self.wallet().serialize(),
                verifying_share: point::serialize_compressed(self.wallet_share()),
            },
            handle: self.handle,
            share,
        }
    }

    /// The group key `X`, compressed and even-Y.
    pub fn group_key(&self) -> [u8; 33] {
        self.public_key_package.verifying_key.serialize()
    }

    /// The runtime's FROST identifier.
    pub fn signer(&self) -> &Identifier {
        &self.key_package.identifier
    }

    /// The wallet's FROST identifier: the other holder in the public package.
    pub fn wallet(&self) -> &Identifier {
        self.public_key_package
            .verifying_shares
            .keys()
            .find(|id| **id != self.key_package.identifier)
            .expect("from_record and register both hold two signers")
    }

    /// The wallet's verifying share: what its sign-ins are checked against.
    pub fn wallet_share(&self) -> &ProjectivePoint {
        &self.public_key_package.verifying_shares[self.wallet()]
    }

    pub fn public_key_package(&self) -> &PublicKeyPackage {
        &self.public_key_package
    }

    /// The runtime's key package: its identifier, its share and the group key.
    pub(super) fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }

    /// The runtime's share, for sealing it into the record and for its half of threshold ECDH.
    /// It never leaves the enclave.
    pub(crate) fn secret_share(&self) -> &Scalar {
        &self.key_package.secret_share
    }

    pub fn handle(&self) -> &[u8; 16] {
        &self.handle
    }
}

impl Drop for WalletKey {
    fn drop(&mut self) {
        self.key_package.secret_share.zeroize();
    }
}

impl std::fmt::Debug for WalletKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletKey")
            .field("group_key", &hex::encode(self.group_key()))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing;
    use super::*;

    #[test]
    fn the_record_round_trips_with_its_share() {
        let (_, registered, _) = testing::enrol(&[7; 32], &[9; 16]);
        let key = registered.key;
        let record = key.record([0; SEALED_SHARE_LEN]);
        let back = WalletKey::from_record(&record, *key.secret_share()).unwrap();
        assert_eq!(back.group_key(), key.group_key());
        assert_eq!(back.wallet(), key.wallet());
        assert_eq!(back.signer(), key.signer());
        assert_eq!(back.handle(), key.handle());
        assert_eq!(back.key_package().to_json(), key.key_package().to_json());
    }

    /// The record is write-once; the share beside it is not, so one that does not match is
    /// refused rather than signed with.
    #[test]
    fn a_share_its_record_does_not_name_is_refused() {
        let (_, registered, _) = testing::enrol(&[7; 32], &[9; 16]);
        let record = registered.key.record([0; SEALED_SHARE_LEN]);
        let other = *registered.key.secret_share() + Scalar::ONE;
        assert!(WalletKey::from_record(&record, other).is_err());
    }
}
