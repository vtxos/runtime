//! Registered passkeys, and the tenants they speak for.
//!
//! Each tenant's record is in the roots bucket ([`crate::catalog`]), written
//! once under Object Lock and read back as the version that write created —
//! outside every pool and every release, so a new release recognises every
//! passkey the last one did. No guest can name it.
//!
//! A record is not what opens a tenant's data, and need not be secret: that
//! takes the tenant's key, which only its owner's app has
//! ([`crate::auth::tenant_key`]). A host that substituted a passkey would
//! earn a token, and then be refused when it presented a key that does not
//! open the pool.
//!
//! ## The tenant id is derived from the credential id
//!
//! [`tenant_of`]: nothing to mint and nothing to store. A credential id is
//! registered once and kept when revoked, so it names one tenant forever. The
//! cost is that a passkey *is* its tenant: a replacement passkey starts with
//! an empty pool. A synced passkey is the same credential on every device, so
//! a new phone is not a new passkey.
//!
//! ## Why the sign counter is not persisted
//!
//! The counter exists to spot a cloned authenticator. Persisting it on every
//! request would put a write in the path of every signature, to record a
//! number that platform passkeys synced through iCloud or Google report as
//! zero forever.
//!
//! So it is held in memory, checked for regression while the process lives,
//! and logged when it moves backwards. A restart forgets it, which loses the
//! ability to detect a clone *across* restarts and costs nothing else.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use webauthn_rs::prelude::Passkey;

use crate::auth::gate::{CredentialRecord, CredentialStore};
use crate::catalog::{Catalog, TenantRecord};

/// Credentials in the catalog, with the counters in memory.
pub struct CatalogCredentials {
    catalog: Arc<Catalog>,
    counters: Mutex<HashMap<Vec<u8>, u32>>,
}

impl CatalogCredentials {
    pub fn new(catalog: Arc<Catalog>) -> Self {
        CatalogCredentials {
            catalog,
            counters: Mutex::new(HashMap::new()),
        }
    }

    /// Register a passkey as a new tenant, refusing one that exists: a second
    /// registration of the same credential id is an error rather than a
    /// silent repointing, which is what taking over somebody else's tenant
    /// would look like. Durable before it returns.
    pub async fn register(&self, passkey: Passkey) -> Result<TenantRecord> {
        let tenant = tenant_of(passkey.cred_id().as_ref());
        self.catalog
            .register(tenant, passkey)
            .await
            .context("registering a passkey")
    }

    /// Mark a credential unusable, for good.
    pub async fn revoke(&self, credential_id: &[u8]) -> Result<()> {
        self.catalog.revoke(tenant_of(credential_id)).await
    }

    /// Where the credential's tenant's pool is.
    pub async fn place(&self, credential_id: &[u8]) -> Result<Option<crate::catalog::Place>> {
        Ok(self
            .catalog
            .tenant(tenant_of(credential_id))
            .await?
            .map(|r| r.place))
    }
}

#[async_trait::async_trait]
impl CredentialStore for CatalogCredentials {
    async fn lookup(&self, credential_id: &[u8]) -> Result<Option<CredentialRecord>> {
        let tenant = tenant_of(credential_id);
        let Some(record) = self.catalog.tenant(tenant).await? else {
            return Ok(None);
        };
        // A different credential whose id happens to hash to this tenant is
        // not this one.
        if record.passkey.cred_id().as_ref() != credential_id {
            return Ok(None);
        }
        let active = !self.catalog.revoked(tenant).await?;
        let counter = self
            .counters
            .lock()
            .expect("credentials poisoned")
            .get(credential_id)
            .copied()
            .unwrap_or(0);
        Ok(Some(CredentialRecord {
            tenant_id: tenant,
            passkey: record.passkey,
            active,
            counter,
        }))
    }

    async fn record_use(&self, credential_id: &[u8], counter: u32) -> Result<()> {
        let mut counters = self.counters.lock().expect("credentials poisoned");
        let stored = counters.entry(credential_id.to_vec()).or_insert(0);
        // Zero means the authenticator does not keep one — which is what a
        // synced platform passkey reports — so it says nothing either way and
        // is not a regression.
        if counter != 0 && counter <= *stored {
            tracing::warn!(
                credential = %hex::encode(&credential_id[..8.min(credential_id.len())]),
                stored = *stored,
                presented = counter,
                "authenticator sign counter did not advance; this can mean a cloned \
                 credential and is recorded rather than acted on, because the policy for \
                 it has to be a deliberate decision"
            );
        }
        *stored = (*stored).max(counter);
        Ok(())
    }
}

/// The tenant a credential speaks for: the first sixteen bytes of
/// `sha256("enclave/tenant/v1" || credential_id)`.
///
/// Every tenant's record and pool is named by this, so changing it strands
/// them all; `tenant_of_is_pinned` is what notices.
pub fn tenant_of(credential_id: &[u8]) -> [u8; 16] {
    let digest =
        nitro_attestation::sha256(&[b"enclave/tenant/v1".as_slice(), credential_id].concat());
    digest[..16].try_into().expect("16 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::testing::{Relying, RP_ID};
    use crate::auth::SoftwareAuthenticator;
    use crate::store::backend::memory::MemoryBackend;
    use crate::store::backend::Backend;
    use crate::zfs::{Disk, Zfs};

    async fn registered() -> (
        Arc<dyn Backend>,
        CatalogCredentials,
        SoftwareAuthenticator,
        [u8; 16],
    ) {
        let roots: Arc<dyn Backend> = Arc::new(MemoryBackend::new());
        let fs = Zfs::scratch_on(&Disk::scratch().unwrap(), roots.clone()).await;
        let store = CatalogCredentials::new(fs.catalog().clone());
        let auth = SoftwareAuthenticator::new(RP_ID);
        store
            .register(Relying::new().register(&auth))
            .await
            .expect("registering");
        let tenant_id = tenant_of(auth.credential_id());
        (roots, store, auth, tenant_id)
    }

    /// A fresh enclave over the same bucket — a restart, or a new release.
    async fn after(roots: Arc<dyn Backend>) -> CatalogCredentials {
        let fs = Zfs::scratch_on(&Disk::scratch().unwrap(), roots).await;
        CatalogCredentials::new(fs.catalog().clone())
    }

    /// A record written by one enclave is readable by the next: the point of
    /// putting it in the bucket rather than in memory or on a pool.
    #[tokio::test]
    async fn a_credential_survives_a_restart() {
        let (roots, _store, auth, tenant_id) = registered().await;
        let found = after(roots)
            .await
            .lookup(auth.credential_id())
            .await
            .unwrap()
            .expect("the credential is still there");
        assert_eq!(found.tenant_id, tenant_id);
        assert!(found.active);
    }

    #[tokio::test]
    async fn an_unregistered_credential_is_absent_rather_than_an_error() {
        let (roots, _, _, _) = registered().await;
        assert!(after(roots)
            .await
            .lookup(&[0xff; 32])
            .await
            .unwrap()
            .is_none());
    }

    /// Registering the same credential twice must not silently repoint it —
    /// that is what taking over somebody else's tenant would look like.
    #[tokio::test]
    async fn a_credential_cannot_be_registered_over() {
        let (_roots, store, auth, _) = registered().await;
        let again = Relying::new().register(
            &SoftwareAuthenticator::restore(
                RP_ID,
                auth.credential_id(),
                auth.private_key_pkcs8(),
                0,
            )
            .unwrap(),
        );
        assert!(store.register(again).await.is_err());
    }

    /// Revocation must be visible immediately, and to every later enclave.
    #[tokio::test]
    async fn revocation_takes_effect_at_once_and_survives_a_restart() {
        let (roots, store, auth, _) = registered().await;
        assert!(
            store
                .lookup(auth.credential_id())
                .await
                .unwrap()
                .unwrap()
                .active
        );

        store.revoke(auth.credential_id()).await.unwrap();
        assert!(
            !store
                .lookup(auth.credential_id())
                .await
                .unwrap()
                .unwrap()
                .active
        );
        assert!(
            !after(roots)
                .await
                .lookup(auth.credential_id())
                .await
                .unwrap()
                .unwrap()
                .active
        );
    }

    /// Every tenant's record and pool is named by this value. A change here is
    /// every tenant waking up to an empty pool, so it has to be deliberate.
    #[test]
    fn tenant_of_is_pinned() {
        assert_eq!(
            hex::encode(tenant_of(b"credential")),
            "a0e215ab9e6d4fc553fe89c4d78b844f"
        );
    }

    /// A counter that does not advance is recorded, not fatal — a synced
    /// passkey reports zero forever and must keep working.
    #[tokio::test]
    async fn a_zero_counter_is_not_treated_as_a_regression() {
        let (_roots, store, auth, _) = registered().await;
        store.record_use(auth.credential_id(), 5).await.unwrap();
        store.record_use(auth.credential_id(), 0).await.unwrap();
        // Never moves backwards, and the credential stays usable.
        let found = store.lookup(auth.credential_id()).await.unwrap().unwrap();
        assert_eq!(found.counter, 5);
        assert!(found.active);
    }

    /// Registering places the tenant's pool without creating it: that needs
    /// the tenant's key, which comes with its first assertion.
    #[tokio::test]
    async fn registering_places_a_pool_without_creating_it() {
        let (_roots, store, auth, _) = registered().await;
        let place = store.place(auth.credential_id()).await.unwrap().unwrap();
        assert!(store.place(&[0xee; 32]).await.unwrap().is_none());
        let _ = place;
    }
}
