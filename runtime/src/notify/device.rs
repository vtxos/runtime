//! Which devices a tenant can be woken on.
//!
//! A registration token is a capability: whoever holds one can wake that device
//! from anywhere, through the Firebase project it was issued for. So tokens live
//! in `runtime/devices/` on the tenant's own pool, beside its tasks and streams
//! and outside the `data` dataset that is the guest's only preopen. A guest
//! enrols one and asks for a count; it never reads one back.
//!
//! On the tenant's pool, a tenant's devices are loaded when its pool is
//! attached and not before — so a release cannot wake a tenant it has not yet
//! been given the key to, and a host that reads the disk reads no tokens.
//!
//! ## Why the filename is a hash
//!
//! A token's character set is Google's business and may widen. Naming the file
//! after the token would make path safety depend on a validator agreeing with
//! FCM forever; naming it `sha256(token)` makes the name safe by construction
//! and keeps the check that the record matches its own filename.
//!
//! ## Why the cap evicts instead of refusing
//!
//! At [`MAX_DEVICES_PER_TENANT`] a new enrolment drops the oldest rather than
//! failing. This is a cache of places a person can be reached, not a list of
//! credentials: somebody on their ninth phone must still be able to enrol it,
//! and the entry evicted is the one least likely to still be live. That is the
//! deliberate opposite of [`crate::auth::credential`], where a revoked passkey
//! is kept for ever so it can never be silently reinstated.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::zfs::{TenantLoader, Zfs};

/// Where a tenant's devices live on its pool.
pub const DEVICES_DIR: &str = "devices";

/// Devices one tenant may have enrolled at once.
pub const MAX_DEVICES_PER_TENANT: usize = 8;
/// Devices across every attached tenant, bounding what is held in memory.
pub const MAX_DEVICES: usize = 4096;
/// An FCM registration token is ~160 characters today; these bound the shape
/// without pretending to know the format.
const MIN_TOKEN_LEN: usize = 32;
const MAX_TOKEN_LEN: usize = 512;
const MAX_RECORD: usize = 4 * 1024;
const RECORD_VERSION: u32 = 1;

/// One enrolled device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredDevice {
    /// An unknown version is a refusal, never a misparse.
    pub version: u32,
    /// Repeated inside the record so it can be checked against the directory
    /// the record was found in. Neither check is sufficient alone: the filename
    /// proves the token, the directory proves the owner.
    pub tenant: [u8; 16],
    pub token: String,
    pub created_ms: u64,
}

/// What the registry will hold. Injectable for the same reason `TaskLimits` is:
/// the caps are the interesting behaviour, and a test that had to write four
/// thousand records to reach one would not be written.
#[derive(Debug, Clone, Copy)]
pub struct DeviceLimits {
    pub max_devices: usize,
    pub per_tenant: usize,
}

impl Default for DeviceLimits {
    fn default() -> Self {
        DeviceLimits {
            max_devices: MAX_DEVICES,
            per_tenant: MAX_DEVICES_PER_TENANT,
        }
    }
}

/// Every attached tenant's devices, held in memory and backed by its pool.
///
/// Held in memory because the forwarder needs a tenant's tokens on every wake,
/// and a `read_dir` per wake would be disk I/O over vsock in the path of a
/// signal whose only value is being prompt.
pub struct DeviceRegistry {
    zfs: Arc<Zfs>,
    limits: DeviceLimits,
    devices: Mutex<Devices>,
}

#[derive(Default)]
struct Devices {
    by_tenant: BTreeMap<[u8; 16], Vec<StoredDevice>>,
    loaded: BTreeSet<[u8; 16]>,
}

impl Devices {
    fn total(&self) -> usize {
        self.by_tenant.values().map(Vec::len).sum()
    }
}

impl std::fmt::Debug for DeviceRegistry {
    /// Counts, never tokens. A token in a log line is a token in whatever reads
    /// that log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRegistry").finish_non_exhaustive()
    }
}

fn valid_token(token: &str) -> bool {
    (MIN_TOKEN_LEN..=MAX_TOKEN_LEN).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.'))
}

fn record_name(token: &str) -> String {
    hex::encode(nitro_attestation::sha256(token.as_bytes()))
}

impl DeviceRegistry {
    pub async fn open(zfs: Arc<Zfs>) -> Result<Arc<Self>> {
        Self::open_with_limits(zfs, DeviceLimits::default()).await
    }

    pub async fn open_with_limits(zfs: Arc<Zfs>, limits: DeviceLimits) -> Result<Arc<Self>> {
        anyhow::ensure!(
            limits.max_devices > 0 && limits.per_tenant > 0,
            "device limits must be positive"
        );
        let registry = Arc::new(DeviceRegistry {
            zfs: zfs.clone(),
            limits,
            devices: Mutex::new(Devices::default()),
        });
        let loader: Arc<dyn TenantLoader> = registry.clone();
        zfs.register_loader(Arc::downgrade(&loader)).await?;
        Ok(registry)
    }

    async fn dir(&self, tenant: [u8; 16]) -> Result<PathBuf> {
        self.zfs.tenant_runtime_dir(tenant, DEVICES_DIR).await
    }

    /// Read a tenant's published records back, refusing anything that does not
    /// account for itself.
    async fn scan(&self, tenant: [u8; 16]) -> Result<Vec<StoredDevice>> {
        let dir = self.dir(tenant).await?;
        let mut list = Vec::new();
        let mut entries = tokio::fs::read_dir(&dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name().into_string().unwrap_or_default();
            // A write interrupted before its rename. Nothing published it,
            // so nothing may read it.
            if name.ends_with(".tmp") {
                tokio::fs::remove_file(entry.path()).await?;
                continue;
            }
            let path = entry.path();
            let bytes = tokio::fs::read(&path).await?;
            ensure!(bytes.len() <= MAX_RECORD, "oversized device record");
            let device: StoredDevice =
                serde_json::from_slice(&bytes).context("decoding a device record")?;
            ensure!(
                device.version == RECORD_VERSION
                    && device.tenant == tenant
                    && valid_token(&device.token)
                    && record_name(&device.token) == name,
                "invalid device record at {}",
                path.display()
            );
            list.push(device);
        }
        // Oldest first, so eviction and reporting have one order to rely on.
        list.sort_by_key(|d| (d.created_ms, d.token.clone()));
        Ok(list)
    }

    /// Publish a record: temp file, then renamed into place.
    ///
    /// The rename is what makes the record visible, so a crash leaves either
    /// the old state or the new one and never a half-written record.
    async fn write(&self, device: &StoredDevice) -> Result<()> {
        let bytes = serde_json::to_vec(device)?;
        ensure!(bytes.len() <= MAX_RECORD, "device record exceeds its limit");

        let dir = self.dir(device.tenant).await?;
        let name = record_name(&device.token);
        // Truncates an unpublished write left by a cancelled host call.
        let temp = dir.join(format!("{name}.tmp"));
        tokio::fs::write(&temp, &bytes).await?;
        tokio::fs::rename(&temp, dir.join(name)).await?;
        Ok(())
    }

    async fn remove(&self, tenant: [u8; 16], token: &str) -> Result<()> {
        let path = self.dir(tenant).await?.join(record_name(token));
        match tokio::fs::remove_file(path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).context("removing a device record"),
        }
    }

    /// Load a tenant's devices, trimmed to what the caps allow.
    ///
    /// Over a cap, drop the oldest rather than refuse. A device record is a
    /// cache of where somebody can be reached, not work that must not be lost
    /// — so unlike a task record, the right answer to too many is to keep the
    /// newest and serve. A store can be over-full legitimately: a lowered cap
    /// in a new image, or records written before the cap was enforced.
    async fn load(&self, devices: &mut Devices, tenant: [u8; 16]) -> Result<()> {
        if devices.loaded.contains(&tenant) {
            return Ok(());
        }
        let mut list = self.scan(tenant).await?;
        let room = self
            .limits
            .max_devices
            .saturating_sub(devices.total())
            .min(self.limits.per_tenant);
        if list.len() > room {
            let excess = list.len() - room;
            tracing::warn!(
                tenant = %hex::encode(tenant),
                held = list.len(),
                dropping = excess,
                "a tenant's devices are over a cap; dropping the oldest"
            );
            for evicted in list.drain(..excess) {
                self.remove(tenant, &evicted.token).await?;
            }
        }
        if !list.is_empty() {
            devices.by_tenant.insert(tenant, list);
        }
        devices.loaded.insert(tenant);
        Ok(())
    }

    /// Enrol a token for this tenant.
    ///
    /// Enrolling a token the tenant already has is success and changes nothing,
    /// including its `created_ms`: a client that re-registers on every launch —
    /// which is what the FCM SDKs encourage — must not thereby keep itself at
    /// the front of the eviction queue for ever.
    pub async fn register(&self, tenant: [u8; 16], token: &str, now_ms: u64) -> Result<()> {
        ensure!(
            valid_token(token),
            "a registration token must be {MIN_TOKEN_LEN}-{MAX_TOKEN_LEN} characters of \
             letters, digits, '-', '_', ':' or '.'"
        );
        let mut devices = self.devices.lock().await;
        self.load(&mut devices, tenant).await?;
        if devices
            .by_tenant
            .get(&tenant)
            .is_some_and(|list| list.iter().any(|d| d.token == token))
        {
            return Ok(());
        }

        // The global cap, enforced where the write happens — the same place
        // `tasks::enqueue` enforces `max_records`.
        ensure!(
            devices.total() < self.limits.max_devices,
            "the device store is full ({} records); devices must be forgotten \
             before another can enrol",
            self.limits.max_devices
        );

        let device = StoredDevice {
            version: RECORD_VERSION,
            tenant,
            token: token.to_string(),
            created_ms: now_ms,
        };
        self.write(&device).await?;

        let list = devices.by_tenant.entry(tenant).or_default();
        list.push(device);
        list.sort_by_key(|d| (d.created_ms, d.token.clone()));
        // Published first, evicted second: a crash between the two leaves one
        // device too many, which the next enrolment trims. The other order
        // could leave the tenant with nothing enrolled at all.
        while list.len() > self.limits.per_tenant {
            let evicted = list.remove(0);
            self.remove(tenant, &evicted.token).await?;
        }
        Ok(())
    }

    /// Forgetting a token this tenant does not have is success.
    ///
    /// A client that was pruned while it was offline is not wrong to ask.
    pub async fn forget(&self, tenant: [u8; 16], token: &str) -> Result<()> {
        let mut devices = self.devices.lock().await;
        self.load(&mut devices, tenant).await?;
        self.remove(tenant, token).await?;
        if let Some(list) = devices.by_tenant.get_mut(&tenant) {
            list.retain(|d| d.token != token);
        }
        Ok(())
    }

    /// Remove a token only if it is still the record we failed to reach.
    ///
    /// The forwarder decides to prune and applies it later, and in between an
    /// interactive call may have re-enrolled the same token. Comparing
    /// `created_ms` makes that a no-op rather than deleting a live enrolment.
    pub async fn forget_if_unchanged(
        &self,
        tenant: [u8; 16],
        token: &str,
        created_ms: u64,
    ) -> Result<bool> {
        let mut devices = self.devices.lock().await;
        let Some(list) = devices.by_tenant.get_mut(&tenant) else {
            return Ok(false);
        };
        if !list
            .iter()
            .any(|d| d.token == token && d.created_ms == created_ms)
        {
            return Ok(false);
        }
        self.remove(tenant, token).await?;
        list.retain(|d| d.token != token);
        Ok(true)
    }

    /// What this tenant can be woken on, oldest first. Nothing, for a tenant
    /// whose pool is not attached.
    pub async fn devices(&self, tenant: [u8; 16]) -> Vec<StoredDevice> {
        self.devices
            .lock()
            .await
            .by_tenant
            .get(&tenant)
            .cloned()
            .unwrap_or_default()
    }

    /// How many devices this tenant has enrolled. Never the tokens.
    pub async fn count(&self, tenant: [u8; 16]) -> u32 {
        self.devices
            .lock()
            .await
            .by_tenant
            .get(&tenant)
            .map(|l| l.len() as u32)
            .unwrap_or(0)
    }
}

#[async_trait::async_trait]
impl TenantLoader for DeviceRegistry {
    /// Devices are not background work: a tenant with only devices enrolled
    /// is not re-attached at boot for them.
    async fn load_tenant(&self, tenant: [u8; 16]) -> Result<bool> {
        let mut devices = self.devices.lock().await;
        self.load(&mut devices, tenant).await?;
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::backend::memory::MemoryBackend;
    use crate::store::backend::Backend;
    use crate::zfs::{Disk, Zfs};

    const ALICE: [u8; 16] = [1; 16];
    const BOB: [u8; 16] = [2; 16];

    fn token(seed: &str) -> String {
        format!("{seed}{}", "x".repeat(MIN_TOKEN_LEN))
    }

    /// Storage with Alice and Bob attached, as their sign-ins would leave it.
    async fn memory() -> Arc<Zfs> {
        let fs = Zfs::scratch().await;
        fs.tenant_dir(ALICE).await.unwrap();
        fs.tenant_dir(BOB).await.unwrap();
        fs
    }

    /// Alice's directory of device records.
    async fn alice_dir(fs: &Zfs) -> PathBuf {
        fs.tenant_runtime_dir(ALICE, DEVICES_DIR).await.unwrap()
    }

    async fn registry() -> Arc<DeviceRegistry> {
        DeviceRegistry::open(memory().await).await.unwrap()
    }

    #[tokio::test]
    async fn a_device_registered_by_one_tenant_is_invisible_to_another() {
        let r = registry().await;
        r.register(ALICE, &token("alice"), 1000).await.unwrap();
        assert_eq!(r.count(ALICE).await, 1);
        assert_eq!(r.count(BOB).await, 0);
        assert!(r.devices(BOB).await.is_empty());
    }

    #[tokio::test]
    async fn registering_a_token_a_tenant_already_has_changes_nothing() {
        let r = registry().await;
        r.register(ALICE, &token("a"), 1000).await.unwrap();
        r.register(ALICE, &token("a"), 9999).await.unwrap();
        let devices = r.devices(ALICE).await;
        assert_eq!(devices.len(), 1);
        assert_eq!(
            devices[0].created_ms, 1000,
            "re-registering moved the device to the back of the eviction queue"
        );
    }

    #[tokio::test]
    async fn the_device_cap_evicts_the_oldest_rather_than_refusing_the_newest() {
        let r = registry().await;
        for i in 0..MAX_DEVICES_PER_TENANT {
            r.register(ALICE, &token(&format!("d{i}")), 1000 + i as u64)
                .await
                .unwrap();
        }
        r.register(ALICE, &token("newest"), 9000).await.unwrap();

        let devices = r.devices(ALICE).await;
        assert_eq!(devices.len(), MAX_DEVICES_PER_TENANT);
        assert!(
            devices.iter().any(|d| d.token == token("newest")),
            "the newest device was refused instead of admitted"
        );
        assert!(
            !devices.iter().any(|d| d.token == token("d0")),
            "the oldest device survived the cap"
        );
    }

    /// Accepting an enrolment past the cap would write a store that the next
    /// restart refuses to load — an enclave made unbootable by ordinary use.
    #[tokio::test]
    async fn an_enrolment_past_the_global_cap_is_refused_rather_than_written() {
        let r = DeviceRegistry::open_with_limits(
            memory().await,
            DeviceLimits {
                max_devices: 3,
                per_tenant: 8,
            },
        )
        .await
        .unwrap();
        r.register(ALICE, &token("a"), 1).await.unwrap();
        r.register(BOB, &token("b"), 2).await.unwrap();
        r.register(BOB, &token("c"), 3).await.unwrap();

        let err = r
            .register(ALICE, &token("d"), 4)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("full"), "unhelpful refusal: {err}");
        assert_eq!(
            r.count(ALICE).await,
            1,
            "a refused enrolment was still stored"
        );

        // Forgetting one makes room again.
        r.forget(BOB, &token("c")).await.unwrap();
        r.register(ALICE, &token("d"), 5).await.unwrap();
        assert_eq!(r.count(ALICE).await, 2);
    }

    /// A store can be over the cap legitimately — a lowered cap in a new image,
    /// or records written before the cap was enforced on the way in. Booting is
    /// what matters; these are cached addresses, not work.
    #[tokio::test]
    async fn a_store_over_its_cap_still_opens_and_drops_the_oldest() {
        let fs = memory().await;
        let roomy = DeviceRegistry::open_with_limits(
            fs.clone(),
            DeviceLimits {
                max_devices: 8,
                per_tenant: 8,
            },
        )
        .await
        .unwrap();
        for i in 0..6 {
            roomy
                .register(ALICE, &token(&format!("d{i}")), 1000 + i as u64)
                .await
                .unwrap();
        }
        drop(roomy);

        // The same store, reopened under a tighter cap.
        let tight = DeviceRegistry::open_with_limits(
            fs,
            DeviceLimits {
                max_devices: 2,
                per_tenant: 8,
            },
        )
        .await
        .expect("an over-full store must still open");
        let left = tight.devices(ALICE).await;
        assert_eq!(left.len(), 2, "the store was not trimmed to its cap");
        assert_eq!(
            left.iter().map(|d| d.created_ms).collect::<Vec<_>>(),
            vec![1004, 1005],
            "trimming kept the wrong records"
        );
    }

    #[tokio::test]
    async fn forgetting_a_token_that_is_not_there_is_success_not_an_error() {
        let r = registry().await;
        r.forget(ALICE, &token("never")).await.unwrap();
        r.register(ALICE, &token("a"), 1).await.unwrap();
        r.forget(ALICE, &token("other")).await.unwrap();
        assert_eq!(r.count(ALICE).await, 1);
    }

    #[tokio::test]
    async fn a_token_that_is_not_a_plausible_registration_token_is_refused() {
        let r = registry().await;
        assert!(r.register(ALICE, "short", 1).await.is_err());
        assert!(r
            .register(ALICE, &"x".repeat(MAX_TOKEN_LEN + 1), 1)
            .await
            .is_err());
        assert!(
            r.register(ALICE, &format!("has spaces{}", "x".repeat(40)), 1)
                .await
                .is_err(),
            "a token with a path-hostile character was accepted"
        );
        assert_eq!(r.count(ALICE).await, 0);
    }

    #[tokio::test]
    async fn a_token_reregistered_while_a_prune_was_in_flight_survives_it() {
        let r = registry().await;
        r.register(ALICE, &token("a"), 1000).await.unwrap();
        // The forwarder failed against the record created at 1000; by the time
        // it prunes, the client has re-enrolled and the record is newer.
        r.forget(ALICE, &token("a")).await.unwrap();
        r.register(ALICE, &token("a"), 5000).await.unwrap();

        assert!(!r
            .forget_if_unchanged(ALICE, &token("a"), 1000)
            .await
            .unwrap());
        assert_eq!(r.count(ALICE).await, 1, "a live re-enrolment was pruned");

        assert!(r
            .forget_if_unchanged(ALICE, &token("a"), 5000)
            .await
            .unwrap());
        assert_eq!(r.count(ALICE).await, 0);
    }

    /// Records are on the tenants' pools: a restart finds them once each
    /// tenant is attached again, and not before.
    #[tokio::test]
    async fn a_published_device_record_survives_a_restart_once_its_tenant_is_back() {
        let disk = Disk::scratch().unwrap();
        let roots: Arc<dyn Backend> = Arc::new(MemoryBackend::new());
        let fs = Zfs::scratch_on(&disk, roots.clone()).await;
        fs.tenant_dir(ALICE).await.unwrap();
        fs.tenant_dir(BOB).await.unwrap();
        let r = DeviceRegistry::open(fs.clone()).await.unwrap();
        r.register(ALICE, &token("a"), 1000).await.unwrap();
        r.register(BOB, &token("b"), 2000).await.unwrap();
        drop(r);
        drop(fs);

        let fs = Zfs::scratch_on(&disk, roots).await;
        let reopened = DeviceRegistry::open(fs.clone()).await.unwrap();
        assert_eq!(reopened.count(ALICE).await, 0, "not attached, not loaded");
        fs.tenant_dir(ALICE).await.unwrap();
        assert_eq!(reopened.count(ALICE).await, 1);
        assert_eq!(reopened.devices(ALICE).await[0].token, token("a"));
        assert_eq!(reopened.count(BOB).await, 0);
    }

    #[tokio::test]
    async fn an_unpublished_temporary_file_is_discarded_but_a_corrupt_record_stops_startup() {
        let fs = memory().await;
        let r = DeviceRegistry::open(fs.clone()).await.unwrap();
        r.register(ALICE, &token("a"), 1000).await.unwrap();

        let dir = alice_dir(&fs).await;
        std::fs::write(dir.join("orphan.tmp"), b"").unwrap();
        assert_eq!(
            DeviceRegistry::open(fs.clone())
                .await
                .unwrap()
                .count(ALICE)
                .await,
            1,
            "an unpublished temporary file was treated as a record"
        );

        // A published record that will not decode is a different matter: it is
        // storage this runtime does not understand, and guessing is worse than
        // refusing to start.
        std::fs::write(dir.join(record_name(&token("bad"))), b"not json").unwrap();
        assert!(DeviceRegistry::open(fs).await.is_err());
    }

    #[tokio::test]
    async fn a_record_that_names_a_tenant_other_than_its_directory_is_refused() {
        let fs = memory().await;
        let r = DeviceRegistry::open(fs.clone()).await.unwrap();
        r.register(ALICE, &token("a"), 1000).await.unwrap();

        // Alice's directory, a record claiming to be Bob's: the filename still
        // matches its token, so only the directory check catches this.
        let forged = StoredDevice {
            version: RECORD_VERSION,
            tenant: BOB,
            token: token("forged"),
            created_ms: 1,
        };
        let path = alice_dir(&fs).await.join(record_name(&forged.token));
        std::fs::write(path, serde_json::to_vec(&forged).unwrap()).unwrap();

        assert!(DeviceRegistry::open(fs).await.is_err());
    }

    #[tokio::test]
    async fn a_record_whose_hash_does_not_match_its_token_is_refused() {
        let fs = memory().await;
        let r = DeviceRegistry::open(fs.clone()).await.unwrap();
        r.register(ALICE, &token("a"), 1000).await.unwrap();

        // The right owner, but filed under another token's name — so only the
        // filename check catches this one.
        let device = StoredDevice {
            version: RECORD_VERSION,
            tenant: ALICE,
            token: token("real"),
            created_ms: 1,
        };
        let path = alice_dir(&fs)
            .await
            .join(record_name(&token("someone-else")));
        std::fs::write(path, serde_json::to_vec(&device).unwrap()).unwrap();

        assert!(DeviceRegistry::open(fs).await.is_err());
    }

    #[tokio::test]
    async fn a_record_from_an_unknown_version_is_refused_rather_than_misparsed() {
        let fs = memory().await;
        DeviceRegistry::open(fs.clone()).await.unwrap();

        let device = StoredDevice {
            version: RECORD_VERSION + 1,
            tenant: ALICE,
            token: token("a"),
            created_ms: 1,
        };
        let path = alice_dir(&fs).await.join(record_name(&device.token));
        std::fs::write(path, serde_json::to_vec(&device).unwrap()).unwrap();

        assert!(DeviceRegistry::open(fs).await.is_err());
    }

    /// The records sit beside the tenant's data, not in it, so no guest
    /// preopen reaches them.
    #[tokio::test]
    async fn device_records_live_outside_every_tenant_directory() {
        let fs = memory().await;
        let r = DeviceRegistry::open(fs.clone()).await.unwrap();
        r.register(ALICE, &token("a"), 1).await.unwrap();

        let records = alice_dir(&fs).await;
        assert!(records.join(record_name(&token("a"))).exists());
        let (tenant, _) = fs.tenant_dir(ALICE).await.unwrap();
        assert!(
            !records.starts_with(&tenant),
            "a tenant's directory contains its device records"
        );
    }
}
