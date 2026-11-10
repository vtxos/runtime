//! The tenant registry: what must outlive every release, in the roots bucket.
//!
//! ```text
//!   tenants/<tid>                        the tenant's wallet key and place         once
//!   revoked/<tid>                        a marker                                  once
//!   regions/<r>                          which tenant and pool hold region r       once
//!   versions/<vid>/tenant-keys/<tid>     the tenant's key, sealed to this release  rewritable
//!   versions/<vid>/anonymous             the anonymous tenant's place              once
//! ```
//!
//! Nothing here is signed: no key outlives a release to sign it with. What
//! makes the records trustworthy is that each is written once, under Object
//! Lock, and read back as its **retained** version — the one the conditional
//! PUT created — so a host can neither rewrite one nor hide one and write
//! another. A forged newer version is simply not what is read.
//!
//! A tenant's record holds the public half of its wallet key, the handle the
//! runtime's polynomial was derived from, and the runtime's share of the key,
//! sealed under a key from the operator master (`crate::signer`). That share
//! has to be here rather than on the pool, because the pool's key is derived
//! with it. It is the operator's, and opens nothing alone: a tenant's pool
//! opens only with `k`, which takes the client's share too, and a host that
//! pointed a tenant at another's place would still have to present a key that
//! verifies against that pool's anchors.
//!
//! The cache is the one rewritable thing, and the one thing that is secret:
//! each tenant key this release keeps so its background work can run with
//! nobody connected. Sealed under a key only this release's PCR0 and PCR16 are
//! released, it is useless to every other release — a new release starts with
//! an empty cache and opens each tenant as its owner next signs in.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::clock::TrustedClock;
use crate::store::backend::{get_once, put_once, Backend, ListBlobsInput, Once};
use crate::store::crypto::seal::{seal, unseal};
use crate::store::crypto::VersionKeys;
use crate::tenant::{TenantKey, ANONYMOUS};

const TENANT_VERSION: u32 = 4;
const CLAIM_VERSION: u32 = 1;
const CACHE_VERSION: u32 = 1;

/// Ceiling on any one record read back. A tenant's is a few hundred bytes.
const MAX_RECORD: usize = 8 * 1024;

/// How long an unknown tenant id is remembered as unknown. A sign-in names its
/// tenant by a public key anyone can send, and each miss would otherwise be a
/// version listing and a GET against the bucket.
const ABSENT_TTL: Duration = Duration::from_secs(60);
const MAX_ABSENT: usize = 4096;

/// Where a tenant's pool is: its id, and the region of the disk it sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Place {
    #[serde(with = "hex_bytes")]
    pub pool_id: [u8; 16],
    pub region: u64,
}

/// The runtime's share of a wallet key, sealed: `nonce ‖ ciphertext ‖ tag`.
pub const SEALED_SHARE_LEN: usize = 12 + 32 + 16;

/// One holder of a tenant's wallet key: its FROST identifier and verifying
/// share, as the DKG's even-Y-normalised public package has them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    #[serde(with = "hex_bytes")]
    pub identifier: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub verifying_share: [u8; 33],
}

/// A tenant's wallet key as the registry keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantKeyRecord {
    /// `X`, compressed and even-Y. The tenant id is derived from it.
    #[serde(with = "hex_bytes")]
    pub group_key: [u8; 33],
    /// The runtime: its share is [`TenantKeyRecord::share`].
    pub signer: Member,
    /// The client: a sign-in is checked against its verifying share.
    pub wallet: Member,
    /// What the runtime's DKG polynomial was derived from, with the operator
    /// master.
    #[serde(with = "hex_bytes")]
    pub handle: [u8; 16],
    /// The runtime's share, sealed under a key from the operator master.
    #[serde(with = "hex_bytes")]
    pub share: [u8; SEALED_SHARE_LEN],
}

/// A registered tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantRecord {
    pub version: u32,
    #[serde(flatten)]
    pub place: Place,
    #[serde(flatten)]
    pub key: TenantKeyRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RegionClaim {
    version: u32,
    #[serde(with = "hex_bytes")]
    tenant: [u8; 16],
    #[serde(with = "hex_bytes")]
    pool_id: [u8; 16],
}

#[derive(Serialize, Deserialize)]
struct CachedKey {
    version: u32,
    #[serde(flatten)]
    place: Place,
    #[serde(with = "hex_bytes")]
    key: [u8; 32],
}

/// A tenant key this release kept, with where its pool is.
pub struct Cached {
    pub tenant: [u8; 16],
    pub place: Place,
    pub key: TenantKey,
}

pub struct Registry {
    roots: Arc<dyn Backend>,
    prefix: String,
    retention: Duration,
    clock: Arc<dyn TrustedClock>,
    /// Regions the disk holds, the cap on tenants.
    regions: u64,
    /// This release: `sha256(pcr0 ‖ pcr16)`.
    vid: [u8; 32],
    version_keys: Arc<VersionKeys>,
    tenants: Mutex<HashMap<[u8; 16], TenantRecord>>,
    absent: Mutex<HashMap<[u8; 16], Instant>>,
    /// Every answer, both ways: only this enclave writes a revocation, so one
    /// read per tenant per boot is enough.
    revoked: Mutex<HashMap<[u8; 16], bool>>,
    /// Serialises this enclave's own region claims, so two registrations do not
    /// race each other for the same region. Other enclaves are raced by the
    /// write-once PUT.
    claiming: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("regions", &self.regions)
            .field("vid", &hex::encode(&self.vid[..8]))
            .finish_non_exhaustive()
    }
}

impl Registry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        roots: Arc<dyn Backend>,
        prefix: &str,
        retention: Duration,
        clock: Arc<dyn TrustedClock>,
        regions: u64,
        vid: [u8; 32],
        version_keys: Arc<VersionKeys>,
    ) -> Self {
        Registry {
            roots,
            prefix: prefix.to_string(),
            retention,
            clock,
            regions,
            vid,
            version_keys,
            tenants: Mutex::new(HashMap::new()),
            absent: Mutex::new(HashMap::new()),
            revoked: Mutex::new(HashMap::new()),
            claiming: tokio::sync::Mutex::new(()),
        }
    }

    pub fn regions(&self) -> u64 {
        self.regions
    }

    pub fn version_keys(&self) -> &Arc<VersionKeys> {
        &self.version_keys
    }

    fn retain_until(&self) -> Result<std::time::SystemTime> {
        Ok(std::time::UNIX_EPOCH + self.clock.now()? + self.retention)
    }

    fn tenant_key(&self, tenant: &[u8; 16]) -> String {
        format!("{}tenants/{}", self.prefix, hex::encode(tenant))
    }

    fn revoked_key(&self, tenant: &[u8; 16]) -> String {
        format!("{}revoked/{}", self.prefix, hex::encode(tenant))
    }

    fn region_key(&self, region: u64) -> String {
        format!("{}regions/{region:08x}", self.prefix)
    }

    fn version_prefix(&self) -> String {
        format!("{}versions/{}/", self.prefix, hex::encode(self.vid))
    }

    fn cache_key(&self, tenant: &[u8; 16]) -> String {
        format!(
            "{}tenant-keys/{}",
            self.version_prefix(),
            hex::encode(tenant)
        )
    }

    async fn read(&self, key: &str) -> Result<Option<Bytes>> {
        let body = get_once(&self.roots, key)
            .await
            .with_context(|| format!("reading {key}"))?;
        if let Some(b) = &body {
            ensure!(b.len() <= MAX_RECORD, "{key} is over the record limit");
        }
        Ok(body)
    }

    async fn write_once(&self, key: &str, body: Vec<u8>) -> Result<Once> {
        ensure!(body.len() <= MAX_RECORD, "{key} is over the record limit");
        put_once(&self.roots, key, body.into(), self.retain_until()?)
            .await
            .with_context(|| format!("writing {key}"))
    }

    // ---- tenants -----------------------------------------------------------

    /// A registered tenant, or `None`.
    ///
    /// The record must hold a wallet key whose tenant is this one, and whose
    /// public package adds up. A host can write any bytes under any name, but
    /// the retained version is the first that was written, and these checks
    /// mean even that one cannot speak for a tenant its key does not derive.
    pub async fn tenant(&self, tenant: [u8; 16]) -> Result<Option<TenantRecord>> {
        if let Some(hit) = self.tenants.lock().expect("registry poisoned").get(&tenant) {
            return Ok(Some(hit.clone()));
        }
        {
            let mut absent = self.absent.lock().expect("registry poisoned");
            match absent.get(&tenant) {
                Some(at) if at.elapsed() < ABSENT_TTL => return Ok(None),
                Some(_) => {
                    absent.remove(&tenant);
                }
                None => {}
            }
        }
        let Some(bytes) = self.read(&self.tenant_key(&tenant)).await? else {
            let mut absent = self.absent.lock().expect("registry poisoned");
            if absent.len() >= MAX_ABSENT {
                absent.clear();
            }
            absent.insert(tenant, Instant::now());
            return Ok(None);
        };
        let record: TenantRecord =
            ciborium::from_reader(bytes.as_ref()).context("decoding a tenant record")?;
        ensure!(
            record.version == TENANT_VERSION,
            "tenant record is version {}, this build understands {TENANT_VERSION}",
            record.version
        );
        check_key(tenant, &record.key)?;
        ensure!(
            record.place.region < self.regions,
            "tenant {} is placed in region {}, past the disk's {}",
            hex::encode(tenant),
            record.place.region,
            self.regions
        );
        self.tenants
            .lock()
            .expect("registry poisoned")
            .insert(tenant, record.clone());
        Ok(Some(record))
    }

    /// Register a tenant: a place for its pool, then its record. Refused if
    /// the tenant exists.
    ///
    /// The region is claimed first, so a crash between the two leaves a region
    /// claimed by nobody's record — a leak, never two tenants on one region.
    /// No pool is created here: the caller creates it with `k`.
    pub async fn register(&self, tenant: [u8; 16], key: TenantKeyRecord) -> Result<TenantRecord> {
        check_key(tenant, &key)?;
        if self.tenant(tenant).await?.is_some() {
            bail!("tenant {} is already registered", hex::encode(tenant));
        }
        let place = self.claim_place(tenant).await?;
        let record = TenantRecord {
            version: TENANT_VERSION,
            place,
            key,
        };
        let mut body = Vec::new();
        ciborium::into_writer(&record, &mut body).context("encoding a tenant record")?;
        match self.write_once(&self.tenant_key(&tenant), body).await? {
            Once::Won => {}
            Once::Lost => bail!(
                "tenant {} was registered first by another writer",
                hex::encode(tenant)
            ),
        }
        self.absent
            .lock()
            .expect("registry poisoned")
            .remove(&tenant);
        self.tenants
            .lock()
            .expect("registry poisoned")
            .insert(tenant, record.clone());
        Ok(record)
    }

    /// Mark a tenant unusable for good. Written once and never removed, so no
    /// rewind un-revokes it.
    pub async fn revoke(&self, tenant: [u8; 16]) -> Result<()> {
        // Won or lost, a marker is there: revoked either way.
        self.write_once(&self.revoked_key(&tenant), b"revoked".to_vec())
            .await?;
        self.revoked
            .lock()
            .expect("registry poisoned")
            .insert(tenant, true);
        Ok(())
    }

    pub async fn revoked(&self, tenant: [u8; 16]) -> Result<bool> {
        if let Some(known) = self.revoked.lock().expect("registry poisoned").get(&tenant) {
            return Ok(*known);
        }
        let revoked = self.read(&self.revoked_key(&tenant)).await?.is_some();
        self.revoked
            .lock()
            .expect("registry poisoned")
            .insert(tenant, revoked);
        Ok(revoked)
    }

    // ---- regions -----------------------------------------------------------

    /// Claim the lowest free region for a new pool, with a fresh random pool
    /// id. A region another writer won, or whose claim is hidden, is skipped.
    pub async fn claim_place(&self, tenant: [u8; 16]) -> Result<Place> {
        let _claiming = self.claiming.lock().await;
        let taken = self.claimed_regions().await?;
        let mut pool_id = [0u8; 16];
        crate::random::fill(&mut pool_id);
        let claim = RegionClaim {
            version: CLAIM_VERSION,
            tenant,
            pool_id,
        };
        let mut body = Vec::new();
        ciborium::into_writer(&claim, &mut body).context("encoding a region claim")?;
        for region in (0..self.regions).filter(|r| !taken.contains(r)) {
            if self
                .write_once(&self.region_key(region), body.clone())
                .await?
                == Once::Won
            {
                tracing::info!(tenant = %hex::encode(tenant), region, "claimed a pool region");
                return Ok(Place { pool_id, region });
            }
        }
        bail!(
            "no free pool region: the disk holds {} and all are claimed",
            self.regions
        )
    }

    /// Regions with a current claim. A hidden claim reads as free here, and
    /// loses its write-once PUT to the claim beneath it.
    async fn claimed_regions(&self) -> Result<BTreeSet<u64>> {
        let prefix = format!("{}regions/", self.prefix);
        let mut taken = BTreeSet::new();
        let mut token: Option<String> = None;
        loop {
            let page = self
                .roots
                .list_blobs(ListBlobsInput {
                    prefix: &prefix,
                    continuation_token: token.as_deref(),
                    ..Default::default()
                })
                .await
                .context("listing region claims")?;
            for item in &page.items {
                if let Ok(r) = u64::from_str_radix(&item.key[prefix.len()..], 16) {
                    taken.insert(r);
                }
            }
            match page.next_continuation_token {
                Some(t) if page.is_truncated => token = Some(t),
                _ => return Ok(taken),
            }
        }
    }

    /// Refuse a place whose region is not claimed for this tenant and pool.
    /// Checked before a region is mapped, so no tenant's pool is ever opened
    /// on another's region.
    pub async fn check_place(&self, tenant: [u8; 16], place: &Place) -> Result<()> {
        ensure!(
            place.region < self.regions,
            "region {} is past the disk's {}",
            place.region,
            self.regions
        );
        let bytes = self
            .read(&self.region_key(place.region))
            .await?
            .with_context(|| format!("region {} has no claim", place.region))?;
        let claim: RegionClaim =
            ciborium::from_reader(bytes.as_ref()).context("decoding a region claim")?;
        ensure!(
            claim.version == CLAIM_VERSION
                && claim.tenant == tenant
                && claim.pool_id == place.pool_id,
            "region {} is claimed for another tenant or pool",
            place.region
        );
        Ok(())
    }

    /// The place of a tenant that claimed a region but has no record: the
    /// tests' tenants, made without a wallet key. Walks every claim.
    #[cfg(any(test, feature = "testing"))]
    pub async fn place_claimed_by(&self, tenant: [u8; 16]) -> Result<Option<Place>> {
        for region in self.claimed_regions().await? {
            if let Some(bytes) = self.read(&self.region_key(region)).await? {
                let claim: RegionClaim = ciborium::from_reader(bytes.as_ref())?;
                if claim.tenant == tenant {
                    return Ok(Some(Place {
                        pool_id: claim.pool_id,
                        region,
                    }));
                }
            }
        }
        Ok(None)
    }

    /// The anonymous tenant's place for this release, claimed on first use.
    /// Per release, because its key is: a deployment with no gate keeps
    /// nothing across releases.
    pub async fn anonymous_place(&self) -> Result<Place> {
        let key = format!("{}anonymous", self.version_prefix());
        if let Some(bytes) = self.read(&key).await? {
            return ciborium::from_reader(bytes.as_ref()).context("decoding the anonymous place");
        }
        let place = self.claim_place(ANONYMOUS).await?;
        let mut body = Vec::new();
        ciborium::into_writer(&place, &mut body)?;
        match self.write_once(&key, body).await? {
            Once::Won => Ok(place),
            // Another boot of this release placed it first; theirs stands.
            Once::Lost => {
                let bytes = self
                    .read(&key)
                    .await?
                    .context("the anonymous place vanished")?;
                ciborium::from_reader(bytes.as_ref()).context("decoding the anonymous place")
            }
        }
    }

    // ---- this release's tenant keys -----------------------------------------

    /// Keep a tenant's key for this release's background work.
    pub async fn put_cached(&self, tenant: [u8; 16], place: Place, key: &TenantKey) -> Result<()> {
        let record = CachedKey {
            version: CACHE_VERSION,
            place,
            key: *key.expose_secret(),
        };
        let mut plain = zeroize::Zeroizing::new(Vec::new());
        ciborium::into_writer(&record, &mut *plain).context("encoding a cached key")?;
        let object = self.cache_key(&tenant);
        let sealed = seal(
            self.version_keys.tenant_cache_key(),
            object.as_bytes(),
            &plain,
        )?;
        self.roots
            .put_blob(crate::store::backend::PutBlobInput::new(
                object.clone(),
                sealed.into(),
            ))
            .await
            .with_context(|| format!("writing {object}"))?;
        Ok(())
    }

    /// Every tenant key this release kept. One that will not open is logged
    /// and skipped: it costs that tenant its background work until its owner
    /// signs in, and nobody else anything.
    pub async fn cached(&self) -> Result<Vec<Cached>> {
        let prefix = format!("{}tenant-keys/", self.version_prefix());
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let page = self
                .roots
                .list_blobs(ListBlobsInput {
                    prefix: &prefix,
                    continuation_token: token.as_deref(),
                    ..Default::default()
                })
                .await
                .context("listing this release's tenant keys")?;
            for item in &page.items {
                match self.open_cached(&prefix, &item.key).await {
                    Ok(cached) => out.push(cached),
                    Err(e) => tracing::warn!(
                        object = %item.key,
                        error = format!("{e:#}"),
                        "a cached tenant key would not open; that tenant waits for its owner"
                    ),
                }
            }
            match page.next_continuation_token {
                Some(t) if page.is_truncated => token = Some(t),
                _ => return Ok(out),
            }
        }
    }

    async fn open_cached(&self, prefix: &str, object: &str) -> Result<Cached> {
        let mut tenant = [0u8; 16];
        hex::decode_to_slice(&object[prefix.len()..], &mut tenant)
            .context("a cached key's name is not a tenant id")?;
        let sealed = self
            .roots
            .get_blob(object, None)
            .await
            .with_context(|| format!("reading {object}"))?
            .body;
        let plain = zeroize::Zeroizing::new(unseal(
            self.version_keys.tenant_cache_key(),
            object.as_bytes(),
            &sealed,
        )?);
        let record: CachedKey =
            ciborium::from_reader(plain.as_slice()).context("decoding a cached key")?;
        ensure!(
            record.version == CACHE_VERSION,
            "unknown cached key version"
        );
        Ok(Cached {
            tenant,
            place: record.place,
            key: TenantKey::from_bytes(record.key),
        })
    }
}

/// Refuse a wallet key that does not name `tenant`, or whose public package
/// does not add up: `X` must be even-Y, its tenant must be this one, the two
/// holders distinct, and `X` what their verifying shares interpolate to.
fn check_key(tenant: [u8; 16], key: &TenantKeyRecord) -> Result<()> {
    use threshold::identifier::Identifier;
    use threshold::lagrange::lagrange_coeff_at_zero;
    use threshold::point;

    ensure!(
        key.group_key[0] == 0x02,
        "the wallet key of tenant {} is not even-Y",
        hex::encode(tenant)
    );
    ensure!(
        crate::tenant::tenant_of(&key.group_key) == tenant,
        "the record for tenant {} holds the wallet key of another tenant",
        hex::encode(tenant)
    );
    let decode = |m: &Member| -> Result<_> {
        let id = Identifier::deserialize(&m.identifier)
            .map_err(|e| anyhow::anyhow!("an identifier: {e}"))?;
        let share = point::deserialize_compressed(&m.verifying_share)
            .map_err(|e| anyhow::anyhow!("a verifying share: {e}"))?;
        Ok((id, share))
    };
    let (signer, signer_share) = decode(&key.signer)?;
    let (wallet, wallet_share) = decode(&key.wallet)?;
    ensure!(signer != wallet, "the two holders are one identifier");
    let group = point::deserialize_compressed(&key.group_key)
        .map_err(|e| anyhow::anyhow!("the group key: {e}"))?;
    let set = [signer.clone(), wallet.clone()];
    let interpolated = signer_share * lagrange_coeff_at_zero(&signer, &set)
        + wallet_share * lagrange_coeff_at_zero(&wallet, &set);
    ensure!(
        point::points_equal(&interpolated, &group),
        "the verifying shares of tenant {} are not shares of its group key",
        hex::encode(tenant)
    );
    Ok(())
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("wrong length"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::backend::memory::MemoryBackend;
    use crate::store::backend::PutBlobInput;
    use crate::store::MasterSecret;

    fn registry_on(roots: Arc<dyn Backend>, vid: u8, regions: u64) -> Registry {
        let keys = VersionKeys::derive(&MasterSecret::from_bytes([1; 32]), &[vid; 32]).unwrap();
        Registry::new(
            roots,
            "p/",
            Duration::from_secs(3600),
            Arc::new(crate::clock::HostClock),
            regions,
            [vid; 32],
            Arc::new(keys),
        )
    }

    fn roots() -> Arc<dyn Backend> {
        Arc::new(MemoryBackend::new())
    }

    #[tokio::test]
    async fn places_are_distinct_and_checked() {
        let c = registry_on(roots(), 1, 4);
        let a = c.claim_place([1; 16]).await.unwrap();
        let b = c.claim_place([2; 16]).await.unwrap();
        assert_ne!(a.region, b.region);
        assert_ne!(a.pool_id, b.pool_id);
        c.check_place([1; 16], &a).await.unwrap();
        assert!(c.check_place([2; 16], &a).await.is_err(), "another tenant");
        let mut wrong_pool = a;
        wrong_pool.pool_id = [9; 16];
        assert!(
            c.check_place([1; 16], &wrong_pool).await.is_err(),
            "another pool"
        );
    }

    #[tokio::test]
    async fn a_full_disk_refuses_a_new_place() {
        let c = registry_on(roots(), 1, 1);
        c.claim_place([1; 16]).await.unwrap();
        assert!(c.claim_place([2; 16]).await.is_err());
    }

    /// A hidden claim looks free to the listing, and its owner keeps it.
    #[tokio::test]
    async fn a_hidden_claim_is_not_handed_to_another_tenant() {
        let r = roots();
        let c = registry_on(r.clone(), 1, 3);
        let a = c.claim_place([1; 16]).await.unwrap();
        r.delete_blob(&c.region_key(a.region)).await.unwrap();
        let b = c.claim_place([2; 16]).await.unwrap();
        assert_ne!(a.region, b.region);
        c.check_place([1; 16], &a).await.unwrap();
    }

    /// A newer version over a claim, as a host could write, is not what is
    /// read.
    #[tokio::test]
    async fn a_forged_claim_is_ignored() {
        let r = roots();
        let c = registry_on(r.clone(), 1, 3);
        let a = c.claim_place([1; 16]).await.unwrap();
        let mut forged = Vec::new();
        ciborium::into_writer(
            &RegionClaim {
                version: CLAIM_VERSION,
                tenant: [2; 16],
                pool_id: a.pool_id,
            },
            &mut forged,
        )
        .unwrap();
        r.put_blob(PutBlobInput::new(c.region_key(a.region), forged.into()))
            .await
            .unwrap();
        c.check_place([1; 16], &a).await.unwrap();
        assert!(c.check_place([2; 16], &a).await.is_err());
    }

    #[tokio::test]
    async fn an_unknown_tenant_is_absent_and_remembered() {
        let c = registry_on(roots(), 1, 3);
        assert!(c.tenant([5; 16]).await.unwrap().is_none());
        assert!(c.absent.lock().unwrap().contains_key(&[5; 16]));
    }

    #[tokio::test]
    async fn revocation_is_for_good() {
        let r = roots();
        let c = registry_on(r.clone(), 1, 3);
        assert!(!c.revoked([1; 16]).await.unwrap());
        c.revoke([1; 16]).await.unwrap();
        assert!(c.revoked([1; 16]).await.unwrap());
        // A fresh enclave reads it from the bucket, hidden or not.
        r.delete_blob("p/revoked/01010101010101010101010101010101")
            .await
            .unwrap();
        assert!(registry_on(r, 1, 3).revoked([1; 16]).await.unwrap());
    }

    #[tokio::test]
    async fn a_release_reads_back_only_its_own_cached_keys() {
        let r = roots();
        let v1 = registry_on(r.clone(), 1, 3);
        let place = v1.claim_place([1; 16]).await.unwrap();
        v1.put_cached([1; 16], place, &TenantKey::from_bytes([7; 32]))
            .await
            .unwrap();

        let back = v1.cached().await.unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].tenant, [1; 16]);
        assert_eq!(back[0].place, place);
        assert!(back[0].key.ct_eq(&TenantKey::from_bytes([7; 32])));

        let v2 = registry_on(r, 2, 3);
        assert!(
            v2.cached().await.unwrap().is_empty(),
            "a new release starts empty"
        );
    }

    /// One tenant's sealed key moved under another's name does not open.
    #[tokio::test]
    async fn a_cached_key_moved_to_another_tenant_is_refused() {
        let r = roots();
        let c = registry_on(r.clone(), 1, 3);
        let place = c.claim_place([1; 16]).await.unwrap();
        c.put_cached([1; 16], place, &TenantKey::from_bytes([7; 32]))
            .await
            .unwrap();
        let sealed = r.get_blob(&c.cache_key(&[1; 16]), None).await.unwrap().body;
        r.delete_blob(&c.cache_key(&[1; 16])).await.unwrap();
        r.put_blob(PutBlobInput::new(c.cache_key(&[2; 16]), sealed))
            .await
            .unwrap();
        assert!(c.cached().await.unwrap().is_empty());
    }

    /// A real wallet key's record, and the tenant it names.
    fn wallet_record() -> ([u8; 16], TenantKeyRecord) {
        let (_, registered, _) = crate::signer::testing::enrol(&[7; 32], &[9; 16]);
        let record = registered.key.record([0; SEALED_SHARE_LEN]);
        (crate::tenant::tenant_of(&record.group_key), record)
    }

    #[tokio::test]
    async fn a_tenant_is_read_back_as_registered() {
        let r = roots();
        let c = registry_on(r.clone(), 1, 4);
        let (tenant, key) = wallet_record();
        let registered = c.register(tenant, key.clone()).await.unwrap();
        assert_eq!(registered.key, key);
        c.check_place(tenant, &registered.place).await.unwrap();
        // A fresh enclave reads the same record from the bucket.
        let back = registry_on(r, 1, 4).tenant(tenant).await.unwrap().unwrap();
        assert_eq!(back.key, key);
        assert_eq!(back.place, registered.place);
        assert!(c.register(tenant, key).await.is_err(), "registered twice");
    }

    /// A record names its tenant by its key, and its verifying shares must be shares of that
    /// key: a host writing records of its own cannot make one speak for someone else.
    #[tokio::test]
    async fn a_record_that_does_not_add_up_is_refused() {
        let c = registry_on(roots(), 1, 4);
        let (tenant, key) = wallet_record();
        assert!(
            c.register([3; 16], key.clone()).await.is_err(),
            "another tenant's name"
        );

        let mut forged = key.clone();
        forged.wallet.verifying_share = forged.signer.verifying_share;
        assert!(
            c.register(tenant, forged).await.is_err(),
            "shares of another key"
        );

        let mut odd = key.clone();
        odd.group_key[0] = 0x03;
        assert!(c.register(tenant, odd).await.is_err(), "an odd group key");

        let mut one = key;
        one.wallet.identifier = one.signer.identifier;
        assert!(c.register(tenant, one).await.is_err(), "one holder twice");
    }

    #[tokio::test]
    async fn the_anonymous_place_is_claimed_once_per_release() {
        let r = roots();
        let c = registry_on(r.clone(), 1, 4);
        let a = c.anonymous_place().await.unwrap();
        assert_eq!(c.anonymous_place().await.unwrap(), a);
        assert_eq!(
            registry_on(r.clone(), 1, 4)
                .anonymous_place()
                .await
                .unwrap(),
            a
        );
        assert_ne!(registry_on(r, 2, 4).anonymous_place().await.unwrap(), a);
    }
}
