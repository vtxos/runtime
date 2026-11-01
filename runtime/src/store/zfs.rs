//! Storage: a ZFS pool per tenant, on one disk, each opened by its tenant's key.
//!
//! ```text
//!   /pools/<id>/data       a tenant's pool, mounted here: the guest's preopen
//!   /pools/<id>/runtime    the tenant's tasks and devices
//!   pool "p<id>"           region N: a tenant's pool
//!   /dev/mapper/zcrypt-*   plain dm-crypt per region, a key per pool
//!   /dev/nbd0              the parent's disk, cut into equal regions, over vsock
//! ```
//!
//! Each pool sits on its own region of the one disk and anchors on its own
//! chain. A tenant's data is theirs alone, so one tenant's anchor can never
//! cover another's write. Which region is whose is the registry's
//! ([`crate::store::registry`]), in the roots bucket, written once.
//!
//! ## Opened by the tenant's key
//!
//! A pool's dm-crypt key and its anchor-signing key both derive from its
//! tenant's [`TenantKey`], which the owner's app sends with an assertion. So
//! a pool is opened — **attached** — the first time its owner signs in to a
//! release, and not before; and anchor 0, written once and locked, pins that
//! key for good. A wrong key fails the chain before anything is mapped. Any
//! release opens the pool with the right one, which is why nothing has to be
//! migrated when the runtime or the guest changes.
//!
//! A release keeps the keys of tenants with background work, sealed to itself
//! ([`crate::store::registry::Registry::put_cached`]), and re-attaches them at boot.
//!
//! dm-crypt is what makes the host's disk safe to read. Without the key the
//! host can only replay sectors it once saw or scramble them, and to ZFS both
//! look like the ordinary corruption its checksums exist to catch. No header
//! is parsed from the disk: plain mode has none.
//!
//! ## The anchor
//!
//! Every ZFS block pointer carries its child's checksum, so a pool state is
//! pinned by its uberblock. But a txg number does not name one: forks reuse
//! numbers, and every uberblock the disk ever held may still be on it for the
//! host to serve.
//!
//! So each anchor writes a fresh random value into the pool itself, the marker
//! `zfs set enclave:anchor=<seq>-<nonce>-<previous anchor's hash>`, which also
//! syncs everything written before it. A second sync follows, and the txg that
//! reached is the one the anchor names. Signed with the nonce, chained to the
//! anchor before, it is published to the roots bucket under Object Lock.
//! Nothing is acknowledged — a response, a finished task — until the anchor
//! covering it exists.
//!
//! The marker's txg is older than the anchored one, and a write that lands
//! between the two is acknowledged by the anchor, so the nonce alone does not
//! pin the state. Attaching imports the newest state on the disk and asks the
//! kernel which txg it loaded. It refuses one older than the anchored txg, and
//! one whose marker is neither the newest anchor's nor that of an unpublished
//! successor naming it ([`admit`]). A rolled-back disk, an abandoned fork and
//! the disk as of the marker are all refused.
//!
//! There is no rewind. What an enclave synced and died before anchoring stays,
//! unacknowledged: rewinding even three txgs can find the anchored state's
//! blocks reused, and ZFS would then quietly load an older one.
//!
//! Anchors cannot be hidden either: they are found by their retained version,
//! beneath any delete marker, and Object Lock keeps every one.
//!
//! ## Releases
//!
//! Every anchor carries the release that wrote it — the runtime's and the
//! guest's, each a number measured into its PCR. A pool last written by a newer
//! release is refused, so an operator cannot boot an old approved release onto
//! state a newer one has moved on, and attaching from an older release stamps
//! the pool as soon as it is opened.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use crate::store::backend::{put_once, Backend, Once};
use crate::store::crypto::keys::pool_dmcrypt_key;
use crate::store::crypto::{
    sign, Hash256, KeyMaterial, TenantKey, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN,
};
use crate::store::error::{StoreError, StoreResult};
use crate::store::registry::{Place, Registry, ANONYMOUS};
use anyhow::{anyhow, bail, ensure, Context, Result};
use bytes::Bytes;
use rustix::ioctl::{self, opcode, IntegerSetter, NoArg};
use rustix::net::addr::{SocketAddrArg, SocketAddrLen, SocketAddrOpaque};
use rustix::net::{AddressFamily, SocketType};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Mutex;
use zeroize::Zeroize;

use crate::clock::TrustedClock;

/// The absolute time an Object Lock should hold until: the enclave's *trusted*
/// time (PTP on Nitro), never the host's system clock — a host that wound its
/// clock back could otherwise shorten the lock and make an anchor or a
/// generation record deletable early.
fn retain_until(
    clock: &Arc<dyn TrustedClock>,
    retention: Duration,
) -> Result<std::time::SystemTime> {
    Ok(std::time::UNIX_EPOCH + clock.now()? + retention)
}

const NBD_DEVICE: &str = "/dev/nbd0";
/// The parent, as every enclave sees it.
const PARENT_CID: u32 = 3;
/// Where the parent serves the disk: NBD's registered port, on vsock.
const NBD_PORT: u32 = 10809;
const PROPERTY: &str = "enclave:anchor";
/// No txg starts on a timer, a request's writes fit in one txg, and the txg
/// history reaches back further than the gap between two anchors.
/// The debug log records which uberblock an import loaded.
const ZFS_PARAMS: &str = "zfs_txg_timeout=3600 zfs_txg_history=4096 \
    zfs_arc_max=268435456 zfs_dirty_data_max=268435456 zfs_dirty_data_sync_percent=90 \
    spa_load_verify_data=0 zfs_dbgmsg_enable=1";

const ANCHOR_MAGIC: &[u8; 8] = b"ZFSANCH3";

// magic | seq | prev | fs_uuid | pool_id | tenant_id | pool_guid | txg | nonce
//       | runtime release | guest release | pubkey | sig
const OFF_SEQ: usize = 8;
const OFF_PREV: usize = OFF_SEQ + 8;
const OFF_FS_UUID: usize = OFF_PREV + 32;
const OFF_POOL_ID: usize = OFF_FS_UUID + 16;
const OFF_TENANT_ID: usize = OFF_POOL_ID + 16;
const OFF_POOL_GUID: usize = OFF_TENANT_ID + 16;
const OFF_TXG: usize = OFF_POOL_GUID + 8;
const OFF_NONCE: usize = OFF_TXG + 8;
const OFF_RUNTIME_RELEASE: usize = OFF_NONCE + 32;
const OFF_GUEST_RELEASE: usize = OFF_RUNTIME_RELEASE + 8;
const OFF_PUBKEY: usize = OFF_GUEST_RELEASE + 8;
const SIGNED_LEN: usize = OFF_PUBKEY + ED25519_PUBLIC_KEY_LEN;
pub const ANCHOR_LEN: usize = SIGNED_LEN + ED25519_SIGNATURE_LEN;

fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_be_bytes(b[off..off + 8].try_into().expect("8 bytes"))
}

fn id_at(b: &[u8], off: usize) -> [u8; 16] {
    b[off..off + 16].try_into().expect("16 bytes")
}

/// Which release wrote a state: the runtime's number, measured into PCR0 with
/// the image's configuration, and the guest's, measured into PCR16 with its
/// settings. Each only ever goes up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Release {
    pub runtime: u64,
    pub guest: u64,
}

impl Release {
    /// Whether a state written by `other` may be opened by this release: not
    /// if either number is ahead of ours.
    fn may_open(&self, other: &Release) -> bool {
        other.runtime <= self.runtime && other.guest <= self.guest
    }
}

impl std::fmt::Display for Release {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "runtime {} guest {}", self.runtime, self.guest)
    }
}

/// The disk is cut into equal regions, one pool each. 512-byte sectors; a
/// region is 4 KiB-aligned so its dm-crypt mapping starts on a block boundary.
const SECTORS_PER_MIB: u64 = (1024 * 1024) / 512;

/// The default region size until a deployment sets one with `--region-mib`. A
/// ZFS pool needs only tens of MiB, so this is deliberately small.
const DEFAULT_REGION_MIB: u64 = 200;

/// A nominal disk size, in regions, for a directory-backed manager: enough for
/// the tests' tenants without a real disk behind it.
#[cfg(any(test, feature = "testing"))]
const SCRATCH_REGIONS: u64 = 64;

/// The region an index occupies, as `(offset_sectors, length_sectors)`, or
/// `None` if it does not fit. Regions never overlap and never run past the
/// disk: region `i` is `[i*len, (i+1)*len)`, and a trailing partial region is
/// unused.
fn region_bounds(index: u64, region_sectors: u64, disk_sectors: u64) -> Option<(u64, u64)> {
    let offset = index.checked_mul(region_sectors)?;
    (offset.checked_add(region_sectors)? <= disk_sectors).then_some((offset, region_sectors))
}

/// How many whole regions a disk holds: the cap on pools.
fn region_count(region_sectors: u64, disk_sectors: u64) -> u64 {
    disk_sectors / region_sectors.max(1)
}

/// What a pool needs once the manager has mapped its device.
struct PoolSpec {
    name: String,
    mapped: String,
    pool_id: [u8; 16],
    tenant_id: [u8; 16],
    anchor_prefix: String,
    root: PathBuf,
    is_pool: bool,
}

/// The names and paths each pool uses, derived from its id so two tenants
/// never collide.
fn tenant_pool_name(pool_id: &[u8; 16]) -> String {
    // zpool names must start with a letter.
    format!("p{}", hex::encode(pool_id))
}
fn tenant_dev_name(pool_id: &[u8; 16]) -> String {
    format!("zcrypt-{}", hex::encode(pool_id))
}

/// One anchored pool state, chained to the one before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub seq: u64,
    pub prev: Hash256,
    /// Which pool this anchor speaks for. Signed in, and checked on load, so
    /// the host cannot serve one pool's anchor as another's.
    pub pool_id: [u8; 16],
    /// The tenant the pool belongs to.
    pub tenant_id: [u8; 16],
    pub pool_guid: u64,
    pub txg: u64,
    /// Also in the pool, as `enclave:anchor`: what tells this state apart
    /// from another that reached the same txg.
    pub nonce: [u8; 32],
    /// The release that wrote this state.
    pub release: Release,
    encoded: Bytes,
}

impl Anchor {
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        keys: &KeyMaterial,
        prev: Option<&Anchor>,
        pool_id: [u8; 16],
        tenant_id: [u8; 16],
        pool_guid: u64,
        txg: u64,
        nonce: [u8; 32],
        release: Release,
    ) -> Anchor {
        let seq = prev.map_or(0, |p| p.seq + 1);
        let prev_hash = prev.map_or(Hash256::ZERO, Anchor::hash);
        let mut b = Vec::with_capacity(ANCHOR_LEN);
        b.extend_from_slice(ANCHOR_MAGIC);
        b.extend_from_slice(&seq.to_be_bytes());
        b.extend_from_slice(prev_hash.as_bytes());
        b.extend_from_slice(keys.fs_uuid());
        b.extend_from_slice(&pool_id);
        b.extend_from_slice(&tenant_id);
        b.extend_from_slice(&pool_guid.to_be_bytes());
        b.extend_from_slice(&txg.to_be_bytes());
        b.extend_from_slice(&nonce);
        b.extend_from_slice(&release.runtime.to_be_bytes());
        b.extend_from_slice(&release.guest.to_be_bytes());
        b.extend_from_slice(keys.public_key());
        let sig = sign::sign(keys.signing_key(), &b);
        b.extend_from_slice(&sig);
        Anchor {
            seq,
            prev: prev_hash,
            pool_id,
            tenant_id,
            pool_guid,
            txg,
            nonce,
            release,
            encoded: Bytes::from(b),
        }
    }

    /// Identity for chaining: the full encoding, signature included.
    pub fn hash(&self) -> Hash256 {
        Hash256::of(&self.encoded)
    }

    pub fn encoded(&self) -> Bytes {
        self.encoded.clone()
    }

    /// The value written to the pool's `enclave:anchor` property.
    pub fn property(&self) -> String {
        marker(self.seq, &self.nonce, &self.prev)
    }

    /// Our key and not the one the record names, our filesystem and pool, and
    /// a sequence that matches the key it was read from.
    ///
    /// "Signed by an unexpected key" is what a wrong tenant key comes to, since
    /// the pool's signing key derives from it.
    pub fn decode_and_verify(
        bytes: &[u8],
        keys: &KeyMaterial,
        expected_seq: u64,
        expected_pool_id: [u8; 16],
    ) -> StoreResult<Anchor> {
        if bytes.len() != ANCHOR_LEN || &bytes[..8] != ANCHOR_MAGIC {
            return Err(StoreError::Integrity("zfs anchor: not an anchor"));
        }
        if &bytes[OFF_PUBKEY..SIGNED_LEN] != keys.public_key() {
            return Err(StoreError::Integrity(
                "zfs anchor: signed by an unexpected key",
            ));
        }
        let sig: [u8; ED25519_SIGNATURE_LEN] = bytes[SIGNED_LEN..].try_into().expect("64 bytes");
        sign::verify(keys.public_key(), &bytes[..SIGNED_LEN], &sig)?;
        if &bytes[OFF_FS_UUID..OFF_POOL_ID] != keys.fs_uuid() {
            return Err(StoreError::Integrity(
                "zfs anchor: belongs to another filesystem",
            ));
        }
        if id_at(bytes, OFF_POOL_ID) != expected_pool_id {
            return Err(StoreError::Integrity("zfs anchor: belongs to another pool"));
        }
        let seq = u64_at(bytes, OFF_SEQ);
        if seq != expected_seq {
            return Err(StoreError::Integrity(
                "zfs anchor: sequence does not match its key",
            ));
        }
        let prev = Hash256::from_bytes(bytes[OFF_PREV..OFF_FS_UUID].try_into().expect("32 bytes"));
        if seq == 0 && !prev.is_zero() {
            return Err(StoreError::Integrity(
                "zfs anchor: genesis has a predecessor",
            ));
        }
        Ok(Anchor {
            seq,
            prev,
            pool_id: id_at(bytes, OFF_POOL_ID),
            tenant_id: id_at(bytes, OFF_TENANT_ID),
            pool_guid: u64_at(bytes, OFF_POOL_GUID),
            txg: u64_at(bytes, OFF_TXG),
            nonce: bytes[OFF_NONCE..OFF_RUNTIME_RELEASE]
                .try_into()
                .expect("32 bytes"),
            release: Release {
                runtime: u64_at(bytes, OFF_RUNTIME_RELEASE),
                guest: u64_at(bytes, OFF_GUEST_RELEASE),
            },
            encoded: Bytes::copy_from_slice(bytes),
        })
    }
}

const GEN_MAGIC: &[u8; 8] = b"ZFSGEN02";
// magic | generation | fs_uuid | pool_id | pubkey | sig
const GEN_OFF_G: usize = 8;
const GEN_OFF_FS_UUID: usize = GEN_OFF_G + 8;
const GEN_OFF_POOL_ID: usize = GEN_OFF_FS_UUID + 16;
const GEN_OFF_PUBKEY: usize = GEN_OFF_POOL_ID + 16;
const GEN_SIGNED_LEN: usize = GEN_OFF_PUBKEY + ED25519_PUBLIC_KEY_LEN;
const GEN_LEN: usize = GEN_SIGNED_LEN + ED25519_SIGNATURE_LEN;

/// An attach's generation claim on one pool. One per attach, chained only by
/// its number: a running enclave stops anchoring a pool for good once a higher
/// one exists, so a second enclave the host starts — a new release included —
/// cannot let the first acknowledge a write the second has forked away from.
/// Signed by the pool's key and Object-Locked like an anchor, so the host can
/// neither forge one for this pool nor hide the newest.
fn seal_generation(keys: &KeyMaterial, pool_id: &[u8; 16], generation: u64) -> Bytes {
    let mut b = Vec::with_capacity(GEN_LEN);
    b.extend_from_slice(GEN_MAGIC);
    b.extend_from_slice(&generation.to_be_bytes());
    b.extend_from_slice(keys.fs_uuid());
    b.extend_from_slice(pool_id);
    b.extend_from_slice(keys.public_key());
    let sig = sign::sign(keys.signing_key(), &b);
    b.extend_from_slice(&sig);
    Bytes::from(b)
}

fn generation_key(anchor_prefix: &str, generation: u64) -> String {
    format!("{anchor_prefix}generations/{generation:016x}")
}

/// Does a retained object exist at `key`? A delete marker reads as absent.
async fn exists_raw(roots: &Arc<dyn Backend>, key: &str) -> Result<bool> {
    match roots.get_retained_blob(key).await {
        Ok(_) => Ok(true),
        Err(StoreError::NotFound) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// The newest number of a contiguous, never-deleted chain: existence is
/// monotone, so gallop then bisect.
async fn chain_tip(roots: &Arc<dyn Backend>, key: impl Fn(u64) -> String) -> Result<Option<u64>> {
    if !exists_raw(roots, &key(0)).await? {
        return Ok(None);
    }
    let (mut lo, mut step) = (0u64, 1u64);
    while let Some(next) = lo.checked_add(step) {
        if !exists_raw(roots, &key(next)).await? {
            break;
        }
        lo = next;
        step = step.saturating_mul(2);
    }
    let mut hi = lo.saturating_add(step);
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if exists_raw(roots, &key(mid)).await? {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Ok(Some(lo))
}

/// Whether a generation of this pool exists, verifying it so a host cannot
/// fence this enclave out with a record it forged.
async fn generation_exists(
    roots: &Arc<dyn Backend>,
    keys: &KeyMaterial,
    anchor_prefix: &str,
    pool_id: &[u8; 16],
    generation: u64,
) -> Result<bool> {
    let key = generation_key(anchor_prefix, generation);
    if exists_raw(roots, &key).await? {
        verify_generation(
            &roots.get_retained_blob(&key).await?.body,
            keys,
            pool_id,
            generation,
        )?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Claim the first unused generation of this pool, racing other enclaves for
/// it.
async fn claim_generation(
    roots: &Arc<dyn Backend>,
    keys: &KeyMaterial,
    anchor_prefix: &str,
    pool_id: &[u8; 16],
    retention: Duration,
    clock: &Arc<dyn TrustedClock>,
) -> Result<u64> {
    for _ in 0..1024 {
        let generation = chain_tip(roots, |g| generation_key(anchor_prefix, g))
            .await?
            .map_or(0, |t| t + 1);
        let key = generation_key(anchor_prefix, generation);
        let body = seal_generation(keys, pool_id, generation);
        match put_once(roots, &key, body, retain_until(clock, retention)?).await? {
            Once::Won => {
                tracing::debug!(generation, pool = %hex::encode(pool_id), "claimed a pool generation");
                return Ok(generation);
            }
            Once::Lost => continue, // try the next
        }
    }
    bail!("could not claim a pool generation after 1024 tries; the pool is being raced")
}

fn verify_generation(
    bytes: &[u8],
    keys: &KeyMaterial,
    pool_id: &[u8; 16],
    expected: u64,
) -> StoreResult<()> {
    if bytes.len() != GEN_LEN || &bytes[..8] != GEN_MAGIC {
        return Err(StoreError::Integrity("zfs generation: not a generation"));
    }
    if &bytes[GEN_OFF_PUBKEY..GEN_SIGNED_LEN] != keys.public_key() {
        return Err(StoreError::Integrity(
            "zfs generation: signed by an unexpected key",
        ));
    }
    let sig: [u8; ED25519_SIGNATURE_LEN] = bytes[GEN_SIGNED_LEN..].try_into().expect("64 bytes");
    sign::verify(keys.public_key(), &bytes[..GEN_SIGNED_LEN], &sig)?;
    if &bytes[GEN_OFF_FS_UUID..GEN_OFF_POOL_ID] != keys.fs_uuid() {
        return Err(StoreError::Integrity(
            "zfs generation: belongs to another filesystem",
        ));
    }
    if id_at(bytes, GEN_OFF_POOL_ID) != *pool_id {
        return Err(StoreError::Integrity(
            "zfs generation: belongs to another pool",
        ));
    }
    if u64_at(bytes, GEN_OFF_G) != expected {
        return Err(StoreError::Integrity(
            "zfs generation: number does not match its key",
        ));
    }
    Ok(())
}

/// Where the pools live.
#[derive(Debug, Clone)]
pub enum Disk {
    /// The parent's disk, over vsock: the only one an enclave has.
    Parent,
    /// A temporary directory standing in for the disk, for tests that cannot
    /// load ZFS. Anchors are still published (at txg 0); nothing is synced,
    /// so `anchor` does nothing. Clones share the directory, so a test can
    /// "restart" onto the same disk.
    #[cfg(any(test, feature = "testing"))]
    Directory(Arc<tempfile::TempDir>),
}

impl Disk {
    /// A fresh [`Disk::Directory`].
    #[cfg(any(test, feature = "testing"))]
    pub fn scratch() -> Result<Disk> {
        Ok(Disk::Directory(Arc::new(tempfile::tempdir()?)))
    }
}

/// One ZFS pool: its device, its anchor chain, its last-anchor lock.
struct Pool {
    /// Held so a [`Disk::Directory`] lives as long as the pool on it.
    #[allow(dead_code)]
    disk: Disk,
    keys: Arc<KeyMaterial>,
    roots: Arc<dyn Backend>,
    /// This pool's prefix in the bucket, `{prefix}zfs/pools/<id>/`. Its anchors
    /// and its generations hang off it.
    anchor_prefix: String,
    retention: Duration,
    /// Trusted time, for Object Lock retain-until (see [`retain_until`]).
    clock: Arc<dyn TrustedClock>,
    /// The zpool's name, `p<id>`.
    name: String,
    /// The dm-crypt device the pool sits on.
    mapped: String,
    /// The pool's identity, signed into every anchor.
    pool_id: [u8; 16],
    tenant_id: [u8; 16],
    /// `/pools/<id>`; a directory for [`Disk::Directory`].
    root: PathBuf,
    pool: bool,
    pool_guid: u64,
    /// This attach's generation. An anchor refuses to publish once generation
    /// `+ 1` exists, so a superseded enclave cannot acknowledge anything.
    generation: u64,
    /// The release this enclave is, written into every anchor.
    release: Release,
    /// The newest published anchor, or why anchoring stopped. Held for the
    /// whole of an anchor, so they run one at a time.
    last: Mutex<std::result::Result<Anchor, String>>,
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("root", &self.root)
            .field("pool_guid", &self.pool_guid)
            .finish()
    }
}

/// The datasets every pool holds, each mounted at `root`/`name`: `data` (the
/// guest's only preopen) and `runtime` (the tenant's tasks and
/// devices, out of the guest's reach).
const DATASETS: &[&str] = &["data", "runtime"];

impl Pool {
    /// A pool's handle, before it is created or opened.
    #[allow(clippy::too_many_arguments)]
    fn new(
        disk: &Disk,
        roots: Arc<dyn Backend>,
        keys: Arc<KeyMaterial>,
        retention: Duration,
        clock: Arc<dyn TrustedClock>,
        spec: PoolSpec,
        release: Release,
    ) -> Pool {
        Pool {
            disk: disk.clone(),
            keys,
            roots,
            anchor_prefix: spec.anchor_prefix,
            retention,
            clock,
            name: spec.name,
            mapped: spec.mapped,
            pool_id: spec.pool_id,
            tenant_id: spec.tenant_id,
            root: spec.root,
            pool: spec.is_pool,
            pool_guid: 0,
            generation: 0,
            release,
            last: Mutex::new(Err("not opened".into())),
        }
    }

    /// Genesis for one pool: create it on its device and publish anchor 0,
    /// which pins the tenant key for good.
    ///
    /// Only ever over a chain with no anchors, and so over a device on which
    /// nothing was ever acknowledged: whatever an interrupted genesis left
    /// there is overwritten rather than refused, or a dropped first request
    /// would leave the tenant with a pool it can never open.
    async fn create(mut self) -> Result<Pool> {
        if self.pool {
            run(
                "zpool",
                &[
                    "create",
                    "-f",
                    "-o",
                    "ashift=12",
                    "-o",
                    "cachefile=none",
                    "-o",
                    "failmode=panic",
                    "-O",
                    "checksum=sha256",
                    "-O",
                    "atime=off",
                    "-O",
                    "sync=disabled",
                    "-O",
                    "mountpoint=none",
                    &self.name,
                    &self.mapped,
                ],
            )
            .await?;
            for ds in DATASETS {
                let mount = self.root.join(ds);
                run(
                    "zfs",
                    &[
                        "create",
                        "-o",
                        &format!("mountpoint={}", mount.display()),
                        &format!("{}/{ds}", self.name),
                    ],
                )
                .await?;
                // Keep a little space for records a guest cannot fill: a full
                // `data` dataset must not stop a task being recorded.
                if *ds == "runtime" {
                    run(
                        "zfs",
                        &["set", "reservation=16M", &format!("{}/{ds}", self.name)],
                    )
                    .await?;
                }
            }
            self.pool_guid = pool_guid(&self.name).await?;
        } else {
            for ds in DATASETS {
                tokio::fs::create_dir_all(self.root.join(ds)).await?;
            }
        }
        let genesis = self.seal_and_publish(None).await?;
        tracing::info!(
            name = %self.name,
            pool_guid = self.pool_guid,
            txg = genesis.txg,
            "zfs genesis: created a pool"
        );
        self.last = Mutex::new(Ok(genesis));
        Ok(self)
    }

    /// Resume one pool at `tip`, the newest anchor, already verified: import it
    /// as it is, and refuse it unless that anchor vouches for what ZFS loaded
    /// (see [`admit`]).
    async fn open(mut self, tip: Anchor) -> Result<Pool> {
        if self.pool {
            // The newest state on the disk, not `-T` the anchored txg: that
            // takes the newest uberblock at or below it with no exact match,
            // and falls back further when one fails to load. Which txg it got
            // comes from the kernel's own notes on this import, so the log is
            // emptied first. Unmounted until it is admitted.
            tokio::fs::write(DBGMSG, "0")
                .await
                .context("clearing the ZFS debug log")?;
            run(
                "zpool",
                &[
                    "import",
                    "-f",
                    "-N",
                    "-d",
                    &self.mapped,
                    "-o",
                    "cachefile=none",
                    &tip.pool_guid.to_string(),
                    &self.name,
                ],
            )
            .await
            .context("importing the pool")?;
            #[cfg(feature = "testing")]
            log_loaded_state(&self.name).await;
            let loaded = loaded_txg(&tokio::fs::read_to_string(DBGMSG).await?, &self.name);
            let marker = run("zfs", &["get", "-Hp", "-o", "value", PROPERTY, &self.name]).await?;
            let guid = pool_guid(&self.name).await?;
            if let Err(why) = admit(&tip, loaded, marker.trim(), guid) {
                let _ = run("zpool", &["export", &self.name]).await;
                bail!("refusing the pool: {why}");
            }
            run("zfs", &["mount", "-a"]).await?;
            tracing::info!(
                name = %self.name,
                loaded_txg = loaded,
                marker = marker.trim(),
                "zfs pool admitted"
            );
        }
        self.pool_guid = tip.pool_guid;
        tracing::info!(
            name = %self.name,
            seq = tip.seq,
            txg = tip.txg,
            pool_guid = self.pool_guid,
            "zfs pool resumed at its anchor"
        );
        self.last = Mutex::new(Ok(tip));
        Ok(self)
    }

    /// The newest anchor, checked against the one before it: `None` for a
    /// chain with none.
    async fn verified_tip(&self) -> Result<Option<Anchor>> {
        let Some(seq) = self.find_tip().await? else {
            return Ok(None);
        };
        let tip = self.load(seq).await?;
        if seq > 0 && self.load(seq - 1).await?.hash() != tip.prev {
            bail!("the anchor chain is broken at seq {seq}");
        }
        Ok(Some(tip))
    }

    /// Make everything written so far survive the host. Call before telling
    /// anyone a write happened, and tell nobody if it fails.
    ///
    /// It runs in a task of its own, so a caller that is dropped — a deadline,
    /// an abort, a client that went away — cannot stop it between writing the
    /// marker and publishing the anchor, and leave the next one to collide
    /// with an anchor it does not know was published.
    ///
    /// Before the marker is written a failure changes nothing and is only
    /// returned. From the marker on it stops anchoring for good, an uncertain
    /// publish included: retrying could publish over a lost race, or past a
    /// state the host has since rewritten.
    pub async fn anchor(self: &Arc<Self>) -> Result<()> {
        if !self.pool {
            return Ok(());
        }
        let zfs = self.clone();
        tokio::spawn(async move { zfs.anchor_now(false).await })
            .await
            .context("the anchor's task died")?
    }

    /// Anchor even with nothing new on the disk, so the chain names this
    /// release: what makes "a newer release has opened this pool" a fact about
    /// the bucket rather than about whether its owner happened to write.
    async fn stamp(self: &Arc<Self>) -> Result<()> {
        let zfs = self.clone();
        tokio::spawn(async move { zfs.anchor_now(true).await })
            .await
            .context("the stamp's task died")?
    }

    async fn anchor_now(&self, force: bool) -> Result<()> {
        #[cfg(feature = "testing")]
        if self.last.try_lock().is_err() {
            hook("anchor-wait", String::new()).await;
        }
        let mut last = self.last.lock().await;
        let prev = last
            .as_ref()
            .map_err(|e| anyhow!("zfs anchoring stopped after a failure: {e}"))?
            .clone();
        let start = Instant::now();
        let synced = if self.pool {
            run("zpool", &["sync", &self.name]).await?;
            let synced = synced_txg(&self.name).await?;
            if synced == prev.txg && !force {
                return Ok(()); // nothing has reached the disk since
            }
            synced
        } else {
            prev.txg
        };
        let sync_ms = start.elapsed().as_millis();
        match self.seal_and_publish(Some(&prev)).await {
            Ok(anchor) => {
                tracing::info!(
                    seq = anchor.seq,
                    txg = anchor.txg,
                    written_txgs_since = synced - prev.txg,
                    sync_ms,
                    total_ms = start.elapsed().as_millis(),
                    "zfs anchored"
                );
                *last = Ok(anchor);
                Ok(())
            }
            Err(e) => {
                *last = Err(format!("{e:#}"));
                Err(e)
            }
        }
    }

    async fn seal_and_publish(&self, prev: Option<&Anchor>) -> Result<Anchor> {
        let seq = prev.map_or(0, |p| p.seq + 1);
        let mut nonce = [0u8; 32];
        crate::random::fill(&mut nonce);
        let txg = if self.pool {
            // Anchor::property, before there is an anchor. A sync task: back
            // once the txg holding it, and everything written before it, is
            // on the disk.
            let value = marker(seq, &nonce, &prev.map_or(Hash256::ZERO, Anchor::hash));
            run("zfs", &["set", &format!("{PROPERTY}={value}"), &self.name]).await?;
            #[cfg(feature = "testing")]
            hook("after-marker", format!("seq={seq}")).await;
            // Its frees are deferred two txgs, and would otherwise reach the
            // disk on the next sync: every later call would see a write and
            // anchor again, read-only ones included.
            run("zpool", &["sync", &self.name]).await?;
            let txg = synced_txg(&self.name).await?;
            if let Some(p) = prev {
                ensure!(
                    txg > p.txg,
                    "zfs set reached txg {txg}, not past the anchor at {}",
                    p.txg
                );
            }
            txg
        } else {
            0
        };
        #[cfg(feature = "testing")]
        hook("after-sync", format!("seq={seq} txg={txg}")).await;
        // The fence, checked as late as possible before the publish that would
        // acknowledge these writes: if a newer enclave has attached this pool,
        // this one is superseded and must not publish. The marker is already on
        // the disk, which is harmless — nothing was acknowledged, and the next
        // attach's admission handles an unpublished marker.
        if generation_exists(
            &self.roots,
            &self.keys,
            &self.anchor_prefix,
            &self.pool_id,
            self.generation + 1,
        )
        .await?
        {
            bail!(
                "a newer generation ({}) of this pool exists; this enclave is superseded \
                 and will not anchor it",
                self.generation + 1
            );
        }
        let anchor = Anchor::seal(
            &self.keys,
            prev,
            self.pool_id,
            self.tenant_id,
            self.pool_guid,
            txg,
            nonce,
            self.release,
        );
        self.publish(seq, anchor.encoded()).await?;
        #[cfg(feature = "testing")]
        hook("after-publish", format!("seq={seq} txg={txg}")).await;
        Ok(anchor)
    }

    /// Where the guest's files live: the `data` dataset. The only thing a
    /// guest ever sees.
    fn data_dir(&self) -> PathBuf {
        self.root.join("data")
    }

    /// A directory of the tenant's runtime records, out of the guest's reach —
    /// no preopen names anything above `data`.
    async fn runtime_dir(&self, name: &str) -> Result<PathBuf> {
        let dir = self.root.join("runtime").join(name);
        tokio::fs::create_dir_all(&dir).await?;
        Ok(dir)
    }

    // ---- the anchor chain, in the roots bucket -----------------------------

    fn anchor_key(&self, seq: u64) -> String {
        format!("{}anchors/{seq:016x}", self.anchor_prefix)
    }

    /// The retained version of a key: a delete marker hides an Object-Locked
    /// object from a plain GET while leaving it there, so a plain GET would let
    /// the host roll a chain back with one legal call.
    async fn retained(&self, key: &str) -> StoreResult<Bytes> {
        Ok(self.roots.get_retained_blob(key).await?.body)
    }

    async fn load(&self, seq: u64) -> Result<Anchor> {
        Ok(Anchor::decode_and_verify(
            &self.retained(&self.anchor_key(seq)).await?,
            &self.keys,
            seq,
            self.pool_id,
        )?)
    }

    /// The newest anchor of this pool's chain, or `None` if it has none.
    async fn find_tip(&self) -> Result<Option<u64>> {
        chain_tip(&self.roots, |seq| self.anchor_key(seq)).await
    }

    /// Publish `seq`, winning or losing the race for it.
    async fn publish(&self, seq: u64, body: Bytes) -> Result<()> {
        let key = self.anchor_key(seq);
        let until = retain_until(&self.clock, self.retention)?;
        match put_once(&self.roots, &key, body, until).await? {
            Once::Won => Ok(()),
            Once::Lost => bail!("another writer published anchor {seq} first"),
        }
    }
}

/// What [`Zfs::attach`] found: a pool already attached, or one it attached now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arrival {
    /// Their directory was already there.
    Returning,
    /// First contact: it was created.
    New,
}

/// Why a tenant could not be attached.
#[derive(Debug)]
pub enum AttachError {
    /// The key does not open this tenant's pool: not the key anchor 0 pinned,
    /// or not the key the pool was attached with this boot.
    WrongKey,
    /// The pool was last written by a newer release than this one.
    Superseded(Release),
    /// Anything else: the store, the disk, the registry.
    Other(anyhow::Error),
}

impl std::fmt::Display for AttachError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttachError::WrongKey => f.write_str("the tenant key does not open this pool"),
            AttachError::Superseded(by) => {
                write!(f, "the pool was last written by a newer release ({by})")
            }
            AttachError::Other(e) => write!(f, "{e:#}"),
        }
    }
}

impl std::error::Error for AttachError {}

impl From<anyhow::Error> for AttachError {
    fn from(e: anyhow::Error) -> Self {
        AttachError::Other(e)
    }
}

/// Something that keeps per-tenant records in memory — tasks and devices
/// — and loads a tenant's when its pool is attached.
#[async_trait::async_trait]
pub trait TenantLoader: Send + Sync {
    /// Load the tenant's records from its pool. Idempotent. Returns whether
    /// the tenant has background work, so its key is kept for the next boot.
    async fn load_tenant(&self, tenant: [u8; 16]) -> Result<bool>;
}

/// An attached tenant: its pool, and the key it was opened with.
struct Attached {
    pool: Arc<Pool>,
    key: TenantKey,
    place: Place,
    /// Whether the loaders have run for this attach.
    loaded: std::sync::atomic::AtomicBool,
}

/// A tenant's pool, attached once per boot behind its slot.
type Slot = Arc<tokio::sync::OnceCell<Arc<Attached>>>;

/// The enclave's storage: a pool per tenant, each attached with its tenant's
/// key. One disk underneath, cut into equal regions (see [`region_bounds`]),
/// each its own dm-crypt device and its own pool with its own anchor chain.
pub struct Zfs {
    disk: Disk,
    roots: Arc<dyn Backend>,
    registry: Arc<Registry>,
    fs_uuid: [u8; 16],
    prefix: String,
    retention: Duration,
    clock: Arc<dyn TrustedClock>,
    release: Release,
    /// Real ZFS, or a directory stand-in for tests.
    is_pool: bool,
    region_sectors: u64,
    disk_sectors: u64,
    /// Attached tenants. The slot (a `OnceCell`) serialises a tenant's attach
    /// without serialising everyone; steady state is a map read.
    tenants: std::sync::Mutex<HashMap<[u8; 16], Slot>>,
    /// A tenant's data directory once its pool is attached, for the sync
    /// `tenant_path`.
    tenant_roots: std::sync::Mutex<HashMap<[u8; 16], PathBuf>>,
    /// Tenants whose key this release has kept for background work.
    background: std::sync::Mutex<HashSet<[u8; 16]>>,
    loaders: std::sync::Mutex<Vec<Weak<dyn TenantLoader>>>,
    root_base: PathBuf,
}

impl std::fmt::Debug for Zfs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Zfs")
            .field("regions", &self.registry.regions())
            .field("release", &self.release)
            .finish_non_exhaustive()
    }
}

/// What a release needs to keep its storage: its id and keys, and its number.
pub struct ReleaseContext {
    pub vid: [u8; 32],
    pub keys: Arc<crate::store::crypto::VersionKeys>,
    pub release: Release,
}

impl Zfs {
    /// Bring up the disk. No pool is attached: each waits for its tenant's key,
    /// from an assertion or from this release's cache
    /// ([`Zfs::resume_from_cache`]).
    #[allow(clippy::too_many_arguments)]
    pub async fn open(
        disk: &Disk,
        roots: Arc<dyn Backend>,
        fs_uuid: [u8; 16],
        prefix: &str,
        retention: Duration,
        clock: Arc<dyn TrustedClock>,
        release: ReleaseContext,
    ) -> Result<Arc<Zfs>> {
        let (root_base, is_pool, disk_sectors) = bring_up(disk)?;
        let region_sectors = DEFAULT_REGION_MIB * SECTORS_PER_MIB;
        let registry = Arc::new(Registry::new(
            roots.clone(),
            prefix,
            retention,
            clock.clone(),
            region_count(region_sectors, disk_sectors),
            release.vid,
            release.keys,
        ));
        Ok(Arc::new(Zfs {
            disk: disk.clone(),
            roots,
            registry,
            fs_uuid,
            prefix: prefix.to_string(),
            retention,
            clock,
            release: release.release,
            is_pool,
            region_sectors,
            disk_sectors,
            tenants: std::sync::Mutex::new(HashMap::new()),
            tenant_roots: std::sync::Mutex::new(HashMap::new()),
            background: std::sync::Mutex::new(HashSet::new()),
            loaders: std::sync::Mutex::new(Vec::new()),
            root_base,
        }))
    }

    /// In-process test storage in a temporary directory, over an in-memory
    /// bucket.
    #[cfg(any(test, feature = "testing"))]
    pub async fn scratch() -> Arc<Zfs> {
        Zfs::scratch_on(
            &Disk::scratch().expect("a temporary directory"),
            Arc::new(crate::store::backend::memory::MemoryBackend::new()),
        )
        .await
    }

    /// Test storage on a given disk and bucket, as one fixed release: open it
    /// twice on the same two and it is a restart.
    #[cfg(any(test, feature = "testing"))]
    pub async fn scratch_on(disk: &Disk, roots: Arc<dyn Backend>) -> Arc<Zfs> {
        let master = crate::store::MasterSecret::from_bytes([7u8; 32]);
        let keys = crate::store::crypto::VersionKeys::derive(&master, b"scratch release")
            .expect("deriving keys");
        Zfs::open(
            disk,
            roots,
            [0u8; 16],
            "",
            Duration::from_secs(3600),
            Arc::new(crate::clock::HostClock),
            ReleaseContext {
                vid: [0x5c; 32],
                keys: Arc::new(keys),
                release: Release::default(),
            },
        )
        .await
        .expect("a scratch store")
    }

    pub fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }

    /// Have `loader` load each tenant's records as its pool is attached, and
    /// those already attached now.
    pub async fn register_loader(&self, loader: Weak<dyn TenantLoader>) -> Result<()> {
        self.loaders
            .lock()
            .expect("loaders mutex")
            .push(loader.clone());
        if let Some(loader) = loader.upgrade() {
            for tenant in self.attached_tenants() {
                if loader.load_tenant(tenant).await? {
                    self.mark_background(tenant).await?;
                }
            }
        }
        Ok(())
    }

    /// Attach a tenant's pool with its key: create it if it has never been, or
    /// open it if the key verifies against its anchors. A tenant already
    /// attached is checked against the key it was attached with.
    ///
    /// Runs in a task of its own, so a caller that goes away cannot leave a
    /// half-created pool or a mapped region behind it.
    pub async fn attach(
        self: &Arc<Self>,
        tenant: [u8; 16],
        place: Place,
        key: &TenantKey,
    ) -> std::result::Result<Arrival, AttachError> {
        let cell = self.slot(tenant)?;
        if let Some(attached) = cell.get() {
            return if attached.key.ct_eq(key) && attached.place == place {
                Ok(Arrival::Returning)
            } else {
                Err(AttachError::WrongKey)
            };
        }
        let zfs = self.clone();
        let key = key.clone();
        let (attached, arrival) = tokio::spawn(async move {
            let mut arrival = Arrival::Returning;
            let attached = cell
                .get_or_try_init(|| async {
                    let (pool, fresh) = zfs.open_tenant(tenant, place, &key).await?;
                    if fresh {
                        arrival = Arrival::New;
                    }
                    Ok::<_, AttachError>(Arc::new(Attached {
                        pool,
                        key: key.clone(),
                        place,
                        loaded: std::sync::atomic::AtomicBool::new(false),
                    }))
                })
                .await?
                .clone();
            if !attached.key.ct_eq(&key) || attached.place != place {
                return Err(AttachError::WrongKey);
            }
            Ok((attached, arrival))
        })
        .await
        .map_err(|e| AttachError::Other(anyhow!("the attach's task died: {e}")))??;

        self.tenant_roots
            .lock()
            .expect("tenant_roots mutex")
            .insert(tenant, attached.pool.data_dir());
        if !attached
            .loaded
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            self.run_loaders(tenant).await?;
        }
        Ok(arrival)
    }

    fn slot(&self, tenant: [u8; 16]) -> Result<Slot> {
        let mut map = self.tenants.lock().expect("tenants mutex");
        if !map.contains_key(&tenant) {
            ensure!(
                (map.len() as u64) < self.registry.regions(),
                "no free pool region: the disk holds {} pools and all are attached",
                self.registry.regions()
            );
            map.insert(tenant, Slot::default());
        }
        Ok(map.get(&tenant).expect("just inserted").clone())
    }

    async fn run_loaders(&self, tenant: [u8; 16]) -> Result<()> {
        let loaders: Vec<_> = self
            .loaders
            .lock()
            .expect("loaders mutex")
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        let mut background = false;
        for loader in loaders {
            background |= loader.load_tenant(tenant).await?;
        }
        if background {
            self.mark_background(tenant).await?;
        }
        Ok(())
    }

    /// Open (or create) one tenant's pool. Returns the pool and whether it was
    /// created.
    async fn open_tenant(
        &self,
        tenant: [u8; 16],
        place: Place,
        key: &TenantKey,
    ) -> std::result::Result<(Arc<Pool>, bool), AttachError> {
        self.registry.check_place(tenant, &place).await?;
        let keys = Arc::new(
            KeyMaterial::for_pool(key, self.fs_uuid, &place.pool_id)
                .map_err(|e| anyhow!("deriving the pool's keys: {e}"))?,
        );
        let mut pool = Pool::new(
            &self.disk,
            self.roots.clone(),
            keys.clone(),
            self.retention,
            self.clock.clone(),
            PoolSpec {
                name: tenant_pool_name(&place.pool_id),
                mapped: if self.is_pool {
                    format!("/dev/mapper/{}", tenant_dev_name(&place.pool_id))
                } else {
                    String::new()
                },
                pool_id: place.pool_id,
                tenant_id: tenant,
                anchor_prefix: format!("{}zfs/pools/{}/", self.prefix, hex::encode(place.pool_id)),
                root: self.pool_root(&place.pool_id),
                is_pool: self.is_pool,
            },
            self.release,
        );
        // The key first, against the chain in the bucket: nothing is claimed
        // or mapped for a key that does not open this pool.
        let tip = match pool.verified_tip().await {
            Ok(tip) => tip,
            Err(e)
                if e.downcast_ref::<StoreError>().is_some_and(|e| {
                    matches!(
                        e,
                        StoreError::Integrity("zfs anchor: signed by an unexpected key")
                    )
                }) =>
            {
                return Err(AttachError::WrongKey)
            }
            Err(e) => return Err(e.into()),
        };
        if let Some(tip) = &tip {
            if !self.release.may_open(&tip.release) {
                return Err(AttachError::Superseded(tip.release));
            }
        }
        pool.generation = claim_generation(
            &self.roots,
            &keys,
            &pool.anchor_prefix,
            &place.pool_id,
            self.retention,
            &self.clock,
        )
        .await?;

        let mapped = Mapped::new(self, &place, key).await?;
        let (pool, fresh) = match tip {
            Some(tip) => {
                let older = tip.release != self.release;
                let pool = Arc::new(pool.open(tip).await?);
                if older {
                    // Last written by an older release: say so in the bucket
                    // now, so that release can no longer open it.
                    pool.stamp().await?;
                }
                (pool, false)
            }
            None => (Arc::new(pool.create().await?), true),
        };
        mapped.keep();
        tracing::info!(
            tenant = %hex::encode(tenant),
            region = place.region,
            pool = %tenant_pool_name(&place.pool_id),
            created = fresh,
            "attached a tenant pool"
        );
        Ok((pool, fresh))
    }

    fn pool_root(&self, pool_id: &[u8; 16]) -> PathBuf {
        self.root_base.join("pools").join(hex::encode(pool_id))
    }

    /// The tenant's attached pool.
    fn attached(&self, tenant: [u8; 16]) -> Option<Arc<Attached>> {
        self.tenants
            .lock()
            .expect("tenants mutex")
            .get(&tenant)
            .and_then(|cell| cell.get().cloned())
    }

    pub fn is_attached(&self, tenant: [u8; 16]) -> bool {
        self.attached(tenant).is_some()
    }

    /// Every tenant attached this boot.
    pub fn attached_tenants(&self) -> Vec<[u8; 16]> {
        self.tenants
            .lock()
            .expect("tenants mutex")
            .iter()
            .filter(|(_, cell)| cell.get().is_some())
            .map(|(t, _)| *t)
            .collect()
    }

    /// A tenant's data directory. Refused for a tenant whose owner has not
    /// signed in to this release and whose key it did not keep.
    pub fn attached_dir(&self, tenant: [u8; 16]) -> Result<PathBuf> {
        Ok(self.require(tenant)?.pool.data_dir())
    }

    fn require(&self, tenant: [u8; 16]) -> Result<Arc<Attached>> {
        self.attached(tenant).with_context(|| {
            format!(
                "tenant {} is not attached: its owner has not signed in to this release",
                hex::encode(tenant)
            )
        })
    }

    /// Where a tenant's data directory is. Known exactly once the pool has been
    /// attached; otherwise a path under the disk that does not exist, enough
    /// for callers only asking whether a tenant's files are there.
    pub fn tenant_path(&self, tenant_id: [u8; 16]) -> PathBuf {
        self.tenant_roots
            .lock()
            .expect("tenant_roots mutex")
            .get(&tenant_id)
            .cloned()
            .unwrap_or_else(|| {
                self.root_base
                    .join("pools")
                    .join(format!("absent-{}", hex::encode(tenant_id)))
                    .join("data")
            })
    }

    /// A directory for a tenant's own runtime records (its tasks and
    /// devices), on the tenant's pool, out of the guest's reach.
    pub async fn tenant_runtime_dir(&self, tenant_id: [u8; 16], name: &str) -> Result<PathBuf> {
        self.require(tenant_id)?.pool.runtime_dir(name).await
    }

    /// Anchor a tenant's writes before anyone is told of them.
    pub async fn anchor_tenant(&self, tenant_id: [u8; 16]) -> Result<()> {
        match self.attached(tenant_id) {
            Some(attached) => attached.pool.anchor().await,
            None => Ok(()),
        }
    }

    /// Keep this tenant's key for this release, so its background work runs
    /// after a restart with nobody connected. Durable before the record that
    /// needs it, so a crash never leaves work the boot would miss. A no-op once
    /// kept.
    pub async fn mark_background(&self, tenant: [u8; 16]) -> Result<()> {
        if self
            .background
            .lock()
            .expect("background mutex")
            .contains(&tenant)
        {
            return Ok(());
        }
        let attached = self.require(tenant)?;
        if tenant != ANONYMOUS {
            self.registry
                .put_cached(tenant, attached.place, &attached.key)
                .await?;
        }
        self.background
            .lock()
            .expect("background mutex")
            .insert(tenant);
        Ok(())
    }

    /// At boot: attach every tenant whose key this release kept. One that
    /// fails is logged and left waiting for its owner; it does not stop the
    /// boot.
    pub async fn resume_from_cache(self: &Arc<Self>) -> Result<usize> {
        use futures::StreamExt;
        let cached = self.registry.cached().await?;
        let resumed = futures::stream::iter(cached)
            .map(|c| async move {
                match self.attach(c.tenant, c.place, &c.key).await {
                    Ok(_) => {
                        self.background
                            .lock()
                            .expect("background mutex")
                            .insert(c.tenant);
                        true
                    }
                    Err(e) => {
                        tracing::warn!(
                            tenant = %hex::encode(c.tenant),
                            error = %e,
                            "could not re-attach a tenant from this release's cache; it waits \
                             for its owner"
                        );
                        false
                    }
                }
            })
            .buffer_unordered(8)
            .filter(|ok| std::future::ready(*ok))
            .count()
            .await;
        Ok(resumed)
    }

    /// The anonymous tenant's data directory, for a deployment with no gate:
    /// one shared pool, keyed by this release and kept only as long as it is.
    pub async fn anonymous_dir(self: &Arc<Self>) -> Result<PathBuf> {
        if let Some(attached) = self.attached(ANONYMOUS) {
            return Ok(attached.pool.data_dir());
        }
        let place = self.registry.anonymous_place().await?;
        let key = self.registry.version_keys().anonymous().clone();
        self.attach(ANONYMOUS, place, &key)
            .await
            .map_err(|e| anyhow!("attaching the anonymous tenant: {e}"))?;
        self.attached_dir(ANONYMOUS)
    }

    /// Tests: a tenant's data directory, its pool attached with a key derived
    /// from its id and placed on first use.
    #[cfg(any(test, feature = "testing"))]
    pub async fn tenant_dir(self: &Arc<Self>, tenant: [u8; 16]) -> Result<(PathBuf, Arrival)> {
        let place = match self.registry.place_claimed_by(tenant).await? {
            Some(place) => place,
            None => self.registry.claim_place(tenant).await?,
        };
        let arrival = self
            .attach(tenant, place, &test_key(tenant))
            .await
            .map_err(|e| anyhow!("attaching a test tenant: {e}"))?;
        Ok((self.attached_dir(tenant)?, arrival))
    }
}

/// Tests: the key [`Zfs::tenant_dir`] attaches a tenant with.
#[cfg(any(test, feature = "testing"))]
pub fn test_key(tenant: [u8; 16]) -> TenantKey {
    crate::auth::tenant_key::derive(b"a test tenant's PRF output", &tenant)
}

/// A region mapped as a dm-crypt device, unmapped again if the attach that
/// mapped it does not finish: a retry with the right key must not find the
/// device name taken.
struct Mapped {
    dev_name: Option<String>,
}

impl Mapped {
    async fn new(zfs: &Zfs, place: &Place, key: &TenantKey) -> Result<Mapped> {
        if !zfs.is_pool {
            return Ok(Mapped { dev_name: None });
        }
        let (offset, len) = region_bounds(place.region, zfs.region_sectors, zfs.disk_sectors)
            .with_context(|| format!("region {} does not fit the disk", place.region))?;
        let dev_name = tenant_dev_name(&place.pool_id);
        let dm_key = pool_dmcrypt_key(key, &zfs.fs_uuid, &place.pool_id)
            .map_err(|e| anyhow!("deriving the pool's dm-crypt key: {e}"))?;
        map_region(&dm_key, &dev_name, offset, len).await?;
        Ok(Mapped {
            dev_name: Some(dev_name),
        })
    }

    fn keep(mut self) {
        self.dev_name = None;
    }
}

impl Drop for Mapped {
    fn drop(&mut self) {
        if let Some(name) = self.dev_name.take() {
            // Synchronous on purpose: this runs while an attach unwinds, and
            // the next attempt must find the name free.
            let _ = std::process::Command::new("dmsetup")
                .args(["remove", "--noudevsync", &name])
                .env("DM_DISABLE_UDEV", "1")
                .status();
        }
    }
}

/// Bring up the disk once: the modules and `/dev/nbd0` for a real enclave, or a
/// directory for tests. Returns `(disk root, real?, disk sectors)`.
fn bring_up(disk: &Disk) -> Result<(PathBuf, bool, u64)> {
    match disk {
        Disk::Parent => {
            let sectors = bring_up_disk()?;
            Ok((PathBuf::from("/"), true, sectors))
        }
        #[cfg(any(test, feature = "testing"))]
        Disk::Directory(dir) => Ok((
            dir.path().to_path_buf(),
            false,
            DEFAULT_REGION_MIB * SECTORS_PER_MIB * SCRATCH_REGIONS,
        )),
    }
}

/// `<seq>-<nonce>-<previous anchor's hash>`, as the pool's `enclave:anchor`.
/// The hash is what lets a boot recognise the marker of an anchor that was
/// never published as the successor of the one that was.
fn marker(seq: u64, nonce: &[u8; 32], prev: &Hash256) -> String {
    format!(
        "{seq}-{}-{}",
        hex::encode(nonce),
        hex::encode(prev.as_bytes())
    )
}

/// Whether the newest anchor vouches for a loaded pool state: the txg ZFS
/// loaded, the marker it holds and its guid.
///
/// The marker's nonce first reaches the disk a txg or more before the txg the
/// anchor names, and a write that lands between the two is acknowledged by the
/// anchor. So holding the anchor's marker is not enough; the state must also be
/// no older than the anchored txg. One that is newer descends from it: nothing
/// but the enclave writes the marker, and a nonce is written once.
///
/// A state may also hold the marker of the next anchor, one the enclave wrote
/// and died before publishing, naming this one as its predecessor. Either way
/// everything the anchor covered is there, and anything after it was never
/// acknowledged, so the boot goes on from it rather than rewinding: a rewind
/// to a txg some way back can find its blocks already reused.
fn admit(
    tip: &Anchor,
    loaded_txg: Option<u64>,
    marker: &str,
    guid: u64,
) -> std::result::Result<(), String> {
    let loaded = loaded_txg.ok_or("the kernel did not say which txg it loaded")?;
    if guid != tip.pool_guid {
        return Err(format!(
            "it is pool {guid}, not the anchored pool {}",
            tip.pool_guid
        ));
    }
    if loaded < tip.txg {
        return Err(format!(
            "it loaded txg {loaded}, older than the anchored txg {}",
            tip.txg
        ));
    }
    if marker == tip.property() {
        return Ok(());
    }
    if let [seq, nonce, prev] = marker.split('-').collect::<Vec<_>>()[..] {
        if seq == (tip.seq + 1).to_string()
            && nonce.len() == 64
            && prev == hex::encode(tip.hash().as_bytes())
        {
            return Ok(());
        }
    }
    Err(format!(
        "it holds anchor {marker:?}, but the newest anchor is {:?}",
        tip.property()
    ))
}

/// Where the kernel keeps its debug log, `zfs_dbgmsg`.
const DBGMSG: &str = "/proc/spl/kstat/zfs/dbgmsg";

/// The txg of the uberblock an import of `pool` loaded, from the kernel's own
/// notes on it in the debug log: the `using uberblock with txg=` of the load
/// that ended `LOADED` with nothing after it. `zpool import` loads the pool
/// more than once — a trial load, a reload with the trusted config, a retry
/// at an older txg — and only the last is the pool as imported.
fn loaded_txg(dbgmsg: &str, pool: &str) -> Option<u64> {
    let tag = format!("spa_load({pool}, config ");
    let (mut using, mut loaded) = (None, None);
    for line in dbgmsg.lines() {
        let Some((_, rest)) = line.split_once(&tag) else {
            continue;
        };
        let Some((_, note)) = rest.split_once("): ") else {
            continue;
        };
        let note = note.trim();
        if let Some(txg) = note.strip_prefix("using uberblock with txg=") {
            using = txg.parse().ok();
        } else if note == "LOADED" {
            loaded = using;
        } else if note == "LOADING" || note == "UNLOADING" || note.starts_with("FAILED") {
            using = None;
            loaded = None;
        }
    }
    loaded
}

/// The newest txg that reached the disk: the last committed row of the pool's
/// txg history that wrote anything. A txg that changes nothing writes no
/// uberblock, so "last committed" alone can name one the disk never held.
fn witness(kstat: &str) -> Option<u64> {
    let mut lines = kstat.lines().skip_while(|l| !l.starts_with("txg"));
    let cols: Vec<&str> = lines.next()?.split_whitespace().collect();
    let col = |name| cols.iter().position(|c| *c == name);
    let (txg, state, written) = (col("txg")?, col("state")?, col("nwritten")?);
    lines
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let wrote = f.get(written)?.parse::<u64>().ok()? > 0;
            (*f.get(state)? == "C" && wrote).then(|| f.get(txg)?.parse().ok())?
        })
        .max()
}

async fn synced_txg(pool: &str) -> Result<u64> {
    let kstat = tokio::fs::read_to_string(format!("/proc/spl/kstat/zfs/{pool}/txgs")).await?;
    witness(&kstat).context("the pool's txg history shows nothing written")
}

/// Testing only: what the kernel says it loaded, as evidence for the rollback
/// legs of `run-zfs-spike.sh` — the import's own notes from the debug log, and
/// the first txgs the pool opened after it.
#[cfg(feature = "testing")]
async fn log_loaded_state(pool: &str) {
    let dbgmsg = tokio::fs::read_to_string("/proc/spl/kstat/zfs/dbgmsg")
        .await
        .unwrap_or_default();
    for line in dbgmsg.lines().filter(|l| l.contains("spa_load(")) {
        tracing::info!(line, "zfs import: dbgmsg");
    }
    let txgs = tokio::fs::read_to_string(format!("/proc/spl/kstat/zfs/{pool}/txgs"))
        .await
        .unwrap_or_default();
    for line in txgs.lines().skip(1).take(4) {
        tracing::info!(line, "zfs import: txgs");
    }
}

/// Testing only: the vsock port `deploy/qemu-nitro/test-hooks.py` answers on.
#[cfg(feature = "testing")]
const TEST_HOOK_PORT: u32 = 9101;

/// Testing only: stop at a named point in an anchor until the host says to go
/// on, or die there, so a test can copy the disk at an exact moment or kill the
/// enclave between two steps. With nothing listening on the port it returns at
/// once.
#[cfg(feature = "testing")]
async fn hook(point: &'static str, detail: String) {
    let line = format!("{point} {detail}\n");
    let reply = tokio::task::spawn_blocking(move || -> io::Result<String> {
        let mut v = vsock_connect(PARENT_CID, TEST_HOOK_PORT)?;
        v.write_all(line.as_bytes())?;
        let mut reply = String::new();
        io::BufRead::read_line(&mut io::BufReader::new(v), &mut reply)?;
        Ok(reply)
    })
    .await;
    if let Ok(Ok(reply)) = reply {
        if reply.trim() == "abort" {
            tracing::error!(point, detail, "test hook: dying here");
            std::process::abort();
        }
    }
}

async fn pool_guid(pool: &str) -> Result<u64> {
    let out = run("zpool", &["get", "-Hp", "-o", "value", "guid", pool]).await?;
    out.trim().parse().context("parsing the pool guid")
}

async fn run(program: &str, args: &[&str]) -> Result<String> {
    run_with_input(program, args, None).await
}

/// Runs a ZFS or device-mapper tool. `input` goes on stdin, never argv, which
/// any process can read from /proc.
async fn run_with_input(program: &str, args: &[&str], input: Option<&str>) -> Result<String> {
    let mut child = Command::new(program)
        .args(args)
        // No udev in an enclave: libdevmapper makes its own /dev/mapper node.
        .env("DM_DISABLE_UDEV", "1")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {program}"))?;
    if let Some(input) = input {
        let mut stdin = child.stdin.take().expect("piped");
        stdin.write_all(input.as_bytes()).await?;
    }
    let out = child.wait_with_output().await?;
    ensure!(
        out.status.success(),
        "{program} {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn insmod(path: &str, params: &str) -> Result<()> {
    let module = File::open(path).with_context(|| format!("opening {path}"))?;
    match rustix::system::finit_module(&module, &std::ffi::CString::new(params)?, 0) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("loading {path}")),
    }
}

/// Load the ZFS modules and attach the parent's disk as `/dev/nbd0`, once per
/// boot. Returns the disk's size in 512-byte sectors.
fn bring_up_disk() -> Result<u64> {
    insmod("/lib/zfs/spl.ko", "")?;
    insmod("/lib/zfs/zfs.ko", ZFS_PARAMS)?;
    Ok(nbd_attach(NBD_PORT)? / 512)
}

/// Map one region of `/dev/nbd0` as its own dm-crypt device under `key`, two
/// AES-256 keys for XTS. Offset and length are the region's, in 512-byte
/// sectors.
async fn map_region(
    key: &[u8; 64],
    dev_name: &str,
    offset_sectors: u64,
    len_sectors: u64,
) -> Result<String> {
    let mapped = format!("/dev/mapper/{dev_name}");
    let mut table = format!(
        "0 {len_sectors} crypt aes-xts-plain64 {} 0 {NBD_DEVICE} {offset_sectors} 1 sector_size:4096\n",
        hex::encode(key)
    );
    let r = run_with_input(
        "dmsetup",
        &["create", dev_name, "--noudevsync"],
        Some(&table),
    )
    .await;
    table.zeroize();
    r.map(|_| mapped)
}

const NBDMAGIC: u64 = 0x4e42_444d_4147_4943;
const IHAVEOPT: u64 = 0x4948_4156_454f_5054;

/// Attach `/dev/nbd0` to the parent's NBD export on vsock `port`.
///
/// The kernel takes only TCP and UNIX sockets for NBD ("Unsupported socket:
/// should be TCP or UNIX"), so it is given one end of a socketpair and two
/// threads copy between the other end and the vsock connection.
// ponytail: those copies go through userspace; splice(2) them if disk
// throughput is ever what limits a request.
fn nbd_attach(port: u32) -> Result<u64> {
    let mut v = vsock_connect(PARENT_CID, port)
        .with_context(|| format!("connecting to the parent's NBD server on vsock port {port}"))?;

    // Fixed-newstyle handshake, default export.
    let mut hello = [0u8; 18];
    v.read_exact(&mut hello)?;
    ensure!(
        hello[..8] == NBDMAGIC.to_be_bytes() && hello[8..16] == IHAVEOPT.to_be_bytes(),
        "the parent's NBD server does not speak fixed-newstyle"
    );
    let no_zeroes = u16::from_be_bytes([hello[16], hello[17]]) & 2;
    v.write_all(&(1 | u32::from(no_zeroes)).to_be_bytes())?;
    let mut export_name = IHAVEOPT.to_be_bytes().to_vec();
    export_name.extend(1u32.to_be_bytes()); // NBD_OPT_EXPORT_NAME
    export_name.extend(0u32.to_be_bytes()); // "", the default
    v.write_all(&export_name)?;
    let mut reply = [0u8; 10];
    v.read_exact(&mut reply)?;
    let size = u64::from_be_bytes(reply[..8].try_into().expect("8 bytes"));
    let flags = u16::from_be_bytes([reply[8], reply[9]]);
    if no_zeroes == 0 {
        v.read_exact(&mut [0u8; 124])?;
    }

    let (kernel_end, bridge) = UnixStream::pair()?;
    pump(bridge.try_clone()?, v.try_clone()?, "enclave to parent");
    pump(v, bridge, "parent to enclave");

    let dev = File::options().read(true).write(true).open(NBD_DEVICE)?;
    // SAFETY: the NBD ioctls are _IO(0xab, n), each taking the integer below.
    unsafe {
        ioctl::ioctl(
            &dev,
            IntegerSetter::<{ opcode::none(0xab, 1) }>::new_usize(4096),
        )?; // SET_BLKSIZE
        ioctl::ioctl(
            &dev,
            IntegerSetter::<{ opcode::none(0xab, 7) }>::new_usize((size / 4096) as usize),
        )?; // SET_SIZE_BLOCKS
            // Without the server's flags the kernel never sends FLUSH, and nothing
            // written would be asked to reach the parent's disk.
        ioctl::ioctl(
            &dev,
            IntegerSetter::<{ opcode::none(0xab, 10) }>::new_usize(flags.into()),
        )?; // SET_FLAGS
        ioctl::ioctl(
            &dev,
            IntegerSetter::<{ opcode::none(0xab, 0) }>::new_usize(kernel_end.as_raw_fd() as usize),
        )?; // SET_SOCK
    }
    std::thread::spawn(move || {
        let _socket = kernel_end;
        // SAFETY: NBD_DO_IT takes no argument; it serves until the device goes.
        let r = unsafe { ioctl::ioctl(&dev, NoArg::<{ opcode::none(0xab, 3) }>::new()) };
        tracing::error!(?r, "the NBD device stopped; the pool has no disk");
        std::process::exit(71);
    });
    // The device starts inside NBD_DO_IT, on that thread. Until then it has
    // no size and dm-crypt would map nothing. Started is when this appears.
    for _ in 0..100 {
        if Path::new("/sys/block/nbd0/pid").exists() {
            return Ok(size);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    bail!("/dev/nbd0 did not start within 5s of NBD_DO_IT")
}

fn pump(
    mut from: impl Read + Send + 'static,
    mut to: impl Write + Send + 'static,
    way: &'static str,
) {
    std::thread::spawn(move || {
        let r = io::copy(&mut from, &mut to);
        tracing::error!(way, ?r, "the NBD bridge closed; the pool has no disk");
        std::process::exit(71);
    });
}

/// `struct sockaddr_vm`, which rustix has no type for.
#[repr(C)]
struct VsockAddr {
    family: u16,
    reserved: u16,
    port: u32,
    cid: u32,
    zero: [u8; 4],
}

// SAFETY: a complete sockaddr_vm, readable for its whole size for the call.
unsafe impl SocketAddrArg for VsockAddr {
    unsafe fn with_sockaddr<R>(
        &self,
        f: impl FnOnce(*const SocketAddrOpaque, SocketAddrLen) -> R,
    ) -> R {
        f(
            (self as *const Self).cast(),
            std::mem::size_of::<Self>() as SocketAddrLen,
        )
    }
}

fn vsock_connect(cid: u32, port: u32) -> io::Result<File> {
    let fd = rustix::net::socket(AddressFamily::VSOCK, SocketType::STREAM, None)?;
    let addr = VsockAddr {
        family: AddressFamily::VSOCK.as_raw(),
        reserved: 0,
        port,
        cid,
        zero: [0; 4],
    };
    rustix::net::connect(&fd, &addr)?;
    Ok(File::from(fd))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::backend::memory::MemoryBackend;

    /// A pool's keys, from a tenant key of `b`s.
    fn keys(b: u8) -> KeyMaterial {
        KeyMaterial::for_pool(&TenantKey::from_bytes([b; 32]), [1u8; 16], &TEST_POOL_ID).unwrap()
    }

    /// A tenant-pool anchor, for the codec and admission tests. `guid` stands
    /// in for the pool guid; the pool id is fixed so chaining can be checked.
    const TEST_POOL_ID: [u8; 16] = [0x7c; 16];
    fn tseal(
        k: &KeyMaterial,
        prev: Option<&Anchor>,
        guid: u64,
        txg: u64,
        nonce: [u8; 32],
    ) -> Anchor {
        Anchor::seal(
            k,
            prev,
            TEST_POOL_ID,
            [0x7a; 16],
            guid,
            txg,
            nonce,
            Release {
                runtime: 3,
                guest: 5,
            },
        )
    }

    #[test]
    fn witness_is_the_newest_committed_txg_that_wrote() {
        // As /proc/spl/kstat/zfs/<pool>/txgs prints it: a raw kstat header,
        // the column names, then one row per txg.
        let kstat = "\
13 0 0x01 6 672 1234 5678
txg      birth            state ndirty       nread        nwritten     reads    writes   otime        qtime        wtime        stime
26       100              C     0            0            90112        0        12       10           10           10           10
27       200              C     0            0            0            0        0        10           10           10           10
28       300              C     0            0            0            0        0        10           10           10           10
29       400              C     4096         0            86016        0        11       10           10           10           10
30       500              S     4096         0            0            0        0        10           10           0            0
31       600              O     0            0            0            0        0        0            0            0            0
";
        assert_eq!(witness(kstat), Some(29));
        assert_eq!(witness("txg birth state ndirty nread nwritten\n"), None);
    }

    /// Shaped as the emulator's kernel logged a boot: a trial load, then the
    /// load with the trusted config. The two name different txgs here, which
    /// a host serving two reads differently could make happen; the last is
    /// the pool as imported. `$import` is a trial under its own name.
    const PLAIN_IMPORT: &str = "\
timestamp    message
1791607760   ffff8880052b5140 spa_misc.c:431:spa_load_note(): spa_load($import, config untrusted): using uberblock with txg=900
1791607760   ffff8880052b5140 spa_misc.c:431:spa_load_note(): spa_load(enclave, config trusted): LOADING
1791607760   ffff8880052b5140 spa_misc.c:431:spa_load_note(): spa_load(enclave, config untrusted): using uberblock with txg=845
1791607760   ffff8880052b5140 spa_misc.c:431:spa_load_note(): spa_load(enclave, config trusted): LOADED
1791607760   ffff8880052b5140 spa_misc.c:431:spa_load_note(): spa_load(enclave, config trusted): UNLOADING
1791607760   ffff8880052b5140 spa_misc.c:431:spa_load_note(): spa_load(enclave, config trusted): LOADING
1791607760   ffff8880052b5140 spa_misc.c:431:spa_load_note(): spa_load(enclave, config untrusted): using uberblock with txg=846
1791607760   ffff8880052b5140 spa_misc.c:431:spa_load_note(): spa_load(enclave, config trusted): Read 9 log space maps (9 total blocks - blksz = 131072 bytes) in 1 ms
1791607760   ffff8880052b5140 spa_misc.c:431:spa_load_note(): spa_load(enclave, config trusted): LOADED
";

    /// And a load that failed at one txg and was retried at an older one.
    const RETRIED_IMPORT: &str = "\
1791607707   ffff888003fe2080 spa_misc.c:431:spa_load_note(): spa_load(enclave, config trusted): LOADING
1791607707   ffff888003fe2080 spa_misc.c:431:spa_load_note(): spa_load(enclave, config untrusted): using uberblock with txg=810
1791607707   ffff888003fe2080 spa_misc.c:417:spa_load_failed(): spa_load(enclave, config untrusted): FAILED: couldn't get 'config' value in MOS directory [error=5]
1791607707   ffff888003fe2080 spa_misc.c:431:spa_load_note(): spa_load(enclave, config untrusted): UNLOADING
1791607707   ffff888003fe2080 spa_misc.c:431:spa_load_note(): spa_load(enclave, config untrusted): spa_load_retry: rewind, max txg: 809
1791607707   ffff888003fe2080 spa_misc.c:431:spa_load_note(): spa_load(enclave, config untrusted): LOADING
1791607707   ffff888003fe2080 spa_misc.c:431:spa_load_note(): spa_load(enclave, config untrusted): using uberblock with txg=809
1791607707   ffff888003fe2080 spa_misc.c:431:spa_load_note(): spa_load(enclave, config trusted): LOADED
";

    #[test]
    fn the_loaded_txg_is_the_last_load_that_finished() {
        assert_eq!(loaded_txg(PLAIN_IMPORT, "enclave"), Some(846));
        assert_eq!(loaded_txg(RETRIED_IMPORT, "enclave"), Some(809));
        assert_eq!(
            loaded_txg(PLAIN_IMPORT, "encl"),
            None,
            "another pool's name"
        );
        // Anything after the last LOADED means it is not the pool as imported.
        for after in ["UNLOADING", "FAILED: no valid uberblock found", "LOADING"] {
            let later = format!("{PLAIN_IMPORT}1 x spa_load(enclave, config trusted): {after}\n");
            assert_eq!(loaded_txg(&later, "enclave"), None, "{after} after LOADED");
        }
        // LOADED with no uberblock named since the load began.
        let unnamed = "1 x spa_load(enclave, config trusted): LOADING\n\
                       1 x spa_load(enclave, config trusted): LOADED\n";
        assert_eq!(loaded_txg(unnamed, "enclave"), None);
        assert_eq!(loaded_txg("", "enclave"), None);
    }

    #[test]
    fn only_the_anchored_state_and_its_descendants_are_admitted() {
        let k = keys(7);
        let a0 = tseal(&k, None, 42, 100, [9u8; 32]);
        let tip = tseal(&k, Some(&a0), 42, 846, [8u8; 32]);
        let mine = tip.property();
        assert!(
            admit(&tip, Some(846), &mine, 42).is_ok(),
            "the anchored txg"
        );
        assert!(admit(&tip, Some(900), &mine, 42).is_ok(), "synced past it");
        // The leg-7 disk: the marker's txg, holding the right nonce.
        let early = admit(&tip, Some(845), &mine, 42).unwrap_err();
        assert!(early.contains("older than the anchored txg"), "{early}");
        assert!(
            admit(&tip, None, &mine, 42).is_err(),
            "no word from the kernel"
        );
        assert!(admit(&tip, Some(846), &mine, 43).is_err(), "another pool");
        // Rolled back: the anchor before, at an older txg or not.
        assert!(admit(&tip, Some(846), &a0.property(), 42).is_err());
        // The marker of an anchor that died unpublished, naming this one.
        let next = marker(tip.seq + 1, &[5u8; 32], &tip.hash());
        assert!(admit(&tip, Some(860), &next, 42).is_ok());
        // ... but not one naming another predecessor, or two seqs on.
        assert!(admit(
            &tip,
            Some(860),
            &marker(tip.seq + 1, &[5u8; 32], &a0.hash()),
            42
        )
        .is_err());
        assert!(admit(
            &tip,
            Some(860),
            &marker(tip.seq + 2, &[5u8; 32], &tip.hash()),
            42
        )
        .is_err());
        // The 2-field marker shape is not a successor and is refused.
        assert!(admit(
            &tip,
            Some(846),
            &format!("{}-{}", tip.seq, hex::encode(tip.nonce)),
            42
        )
        .is_err());
    }

    #[test]
    fn regions_tile_the_disk_without_overlap_or_overrun() {
        let (region, disk) = (400, 1000); // 2 whole regions, 200 sectors spare
        assert_eq!(region_count(region, disk), 2);
        assert_eq!(region_bounds(0, region, disk), Some((0, 400)));
        assert_eq!(region_bounds(1, region, disk), Some((400, 400)));
        assert_eq!(region_bounds(2, region, disk), None, "the third overruns");
        let (o0, l0) = region_bounds(0, region, disk).unwrap();
        assert_eq!(
            o0 + l0,
            region_bounds(1, region, disk).unwrap().0,
            "abut, not overlap"
        );
    }

    /// Two tenants get two pools, in two regions, with two ids; each returns to
    /// its own; a tenant never attached is refused.
    #[tokio::test]
    async fn tenants_get_independent_pools() {
        let fs = Zfs::scratch().await;
        let (a, first) = fs.tenant_dir([1; 16]).await.unwrap();
        assert_eq!(first, Arrival::New);
        let (b, _) = fs.tenant_dir([2; 16]).await.unwrap();
        assert_ne!(a, b, "two tenants shared a data directory");
        let (again, arrival) = fs.tenant_dir([1; 16]).await.unwrap();
        assert_eq!((again, arrival), (a.clone(), Arrival::Returning));

        let pa = fs
            .registry()
            .place_claimed_by([1; 16])
            .await
            .unwrap()
            .unwrap();
        let pb = fs
            .registry()
            .place_claimed_by([2; 16])
            .await
            .unwrap()
            .unwrap();
        assert_ne!(pa.region, pb.region);
        assert_ne!(pa.pool_id, pb.pool_id);

        assert!(fs.attached_dir([3; 16]).is_err(), "never attached");
        assert_eq!(fs.attached_dir([1; 16]).unwrap(), a);
    }

    /// The key that created a pool is the only one that opens it — on this
    /// boot, and on any later one.
    #[tokio::test]
    async fn only_the_tenant_key_opens_its_pool() {
        let disk = Disk::scratch().unwrap();
        let roots: Arc<dyn Backend> = Arc::new(MemoryBackend::new());
        let fs = Zfs::scratch_on(&disk, roots.clone()).await;
        let place = fs.registry().claim_place([1; 16]).await.unwrap();
        let right = TenantKey::from_bytes([1; 32]);
        let wrong = TenantKey::from_bytes([2; 32]);
        assert_eq!(
            fs.attach([1; 16], place, &right).await.unwrap(),
            Arrival::New
        );
        assert!(matches!(
            fs.attach([1; 16], place, &wrong).await,
            Err(AttachError::WrongKey)
        ));

        // A restart: nothing attached, and the wrong key still opens nothing.
        let fs = Zfs::scratch_on(&disk, roots).await;
        assert!(matches!(
            fs.attach([1; 16], place, &wrong).await,
            Err(AttachError::WrongKey)
        ));
        assert!(
            !fs.is_attached([1; 16]),
            "a refused key leaves nothing attached"
        );
        assert_eq!(
            fs.attach([1; 16], place, &right).await.unwrap(),
            Arrival::Returning
        );
    }

    /// A place another tenant claimed is never opened as this tenant's.
    #[tokio::test]
    async fn a_tenant_is_never_attached_on_another_tenants_place() {
        let fs = Zfs::scratch().await;
        let theirs = fs.registry().claim_place([1; 16]).await.unwrap();
        let err = fs
            .attach([2; 16], theirs, &TenantKey::from_bytes([2; 32]))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("claimed for another"), "{err}");
    }

    /// Each attach claims the next generation of its pool, and the fence it
    /// leaves behind is verifiable. Directory-backed, so this is the claim
    /// logic, not the pool.
    #[tokio::test]
    async fn attaches_claim_generations_in_order() {
        let disk = Disk::scratch().unwrap();
        let roots: Arc<dyn Backend> = Arc::new(MemoryBackend::new());
        let place = Zfs::scratch_on(&disk, roots.clone())
            .await
            .registry()
            .claim_place([1; 16])
            .await
            .unwrap();
        let key = TenantKey::from_bytes([1; 32]);
        for expected in 0..=2 {
            let fs = Zfs::scratch_on(&disk, roots.clone()).await;
            fs.attach([1; 16], place, &key).await.unwrap();
            let pool = fs.attached([1; 16]).unwrap().pool.clone();
            assert_eq!(pool.generation, expected);
            assert!(generation_exists(
                &pool.roots,
                &pool.keys,
                &pool.anchor_prefix,
                &pool.pool_id,
                expected
            )
            .await
            .unwrap());
            assert!(!generation_exists(
                &pool.roots,
                &pool.keys,
                &pool.anchor_prefix,
                &pool.pool_id,
                expected + 1
            )
            .await
            .unwrap());
        }
    }

    /// An enclave superseded on a pool — a newer one attached it — anchors it
    /// no more.
    #[tokio::test]
    async fn a_superseded_enclave_stops_anchoring() {
        let disk = Disk::scratch().unwrap();
        let roots: Arc<dyn Backend> = Arc::new(MemoryBackend::new());
        let old = Zfs::scratch_on(&disk, roots.clone()).await;
        let place = old.registry().claim_place([1; 16]).await.unwrap();
        let key = TenantKey::from_bytes([1; 32]);
        old.attach([1; 16], place, &key).await.unwrap();
        let new = Zfs::scratch_on(&disk, roots).await;
        new.attach([1; 16], place, &key).await.unwrap();

        let err = old
            .attached([1; 16])
            .unwrap()
            .pool
            .stamp()
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("superseded"), "{err:#}");
        new.attached([1; 16]).unwrap().pool.stamp().await.unwrap();
    }

    /// A store opened only by releases at or past the one that last wrote it;
    /// an older release stamps it as it opens it.
    #[tokio::test]
    async fn a_pool_is_refused_to_an_older_release_and_stamped_by_a_newer_one() {
        let disk = Disk::scratch().unwrap();
        let roots: Arc<dyn Backend> = Arc::new(MemoryBackend::new());
        let at = |runtime, guest| {
            let (disk, roots) = (disk.clone(), roots.clone());
            async move {
                let master = crate::store::MasterSecret::from_bytes([7u8; 32]);
                let keys = crate::store::crypto::VersionKeys::derive(&master, b"r").unwrap();
                Zfs::open(
                    &disk,
                    roots,
                    [0u8; 16],
                    "",
                    Duration::from_secs(3600),
                    Arc::new(crate::clock::HostClock),
                    ReleaseContext {
                        vid: [runtime as u8 ^ (guest as u8) << 4; 32],
                        keys: Arc::new(keys),
                        release: Release { runtime, guest },
                    },
                )
                .await
                .unwrap()
            }
        };
        let key = TenantKey::from_bytes([1; 32]);
        let v2 = at(2, 2).await;
        let place = v2.registry().claim_place([1; 16]).await.unwrap();
        v2.attach([1; 16], place, &key).await.unwrap();

        for (runtime, guest) in [(1, 2), (2, 1)] {
            assert!(
                matches!(
                    at(runtime, guest).await.attach([1; 16], place, &key).await,
                    Err(AttachError::Superseded(r)) if r == Release { runtime: 2, guest: 2 }
                ),
                "release {runtime}/{guest} opened a pool release 2/2 wrote"
            );
        }

        // A newer guest opens it, and stamps it at once.
        at(2, 3).await.attach([1; 16], place, &key).await.unwrap();
        assert!(matches!(
            at(2, 2).await.attach([1; 16], place, &key).await,
            Err(AttachError::Superseded(_))
        ));
    }

    /// A tenant with background work is re-attached by the next boot of the
    /// same release, and by no other release.
    #[tokio::test]
    async fn a_release_resumes_the_tenants_it_kept() {
        let disk = Disk::scratch().unwrap();
        let roots: Arc<dyn Backend> = Arc::new(MemoryBackend::new());
        let fs = Zfs::scratch_on(&disk, roots.clone()).await;
        fs.tenant_dir([1; 16]).await.unwrap();
        fs.tenant_dir([2; 16]).await.unwrap();
        fs.mark_background([1; 16]).await.unwrap();

        let again = Zfs::scratch_on(&disk, roots.clone()).await;
        assert_eq!(again.resume_from_cache().await.unwrap(), 1);
        assert!(again.is_attached([1; 16]));
        assert!(!again.is_attached([2; 16]), "no background work, not kept");

        let master = crate::store::MasterSecret::from_bytes([7u8; 32]);
        let other = Zfs::open(
            &disk,
            roots,
            [0u8; 16],
            "",
            Duration::from_secs(3600),
            Arc::new(crate::clock::HostClock),
            ReleaseContext {
                vid: [0x77; 32],
                keys: Arc::new(
                    crate::store::crypto::VersionKeys::derive(&master, b"another release").unwrap(),
                ),
                release: Release::default(),
            },
        )
        .await
        .unwrap();
        assert_eq!(other.resume_from_cache().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn the_anonymous_tenant_has_one_pool_per_release() {
        let fs = Zfs::scratch().await;
        let a = fs.anonymous_dir().await.unwrap();
        assert_eq!(fs.anonymous_dir().await.unwrap(), a);
        assert!(a.is_dir());
    }

    #[test]
    fn a_generation_round_trips_and_refuses_tampering_and_strangers() {
        let k = keys(7);
        let g = seal_generation(&k, &TEST_POOL_ID, 5);
        assert_eq!(g.len(), GEN_LEN);
        assert!(verify_generation(&g, &k, &TEST_POOL_ID, 5).is_ok());
        assert!(
            verify_generation(&g, &k, &TEST_POOL_ID, 6).is_err(),
            "number from another key"
        );
        assert!(
            verify_generation(&g, &keys(8), &TEST_POOL_ID, 5).is_err(),
            "another tenant key"
        );
        assert!(
            verify_generation(&g, &k, &[0x99; 16], 5).is_err(),
            "another pool"
        );
        let mut flipped = g.to_vec();
        flipped[GEN_OFF_G + 7] ^= 1;
        assert!(verify_generation(&flipped, &k, &TEST_POOL_ID, 5).is_err());
        assert!(
            verify_generation(&g[..GEN_LEN - 1], &k, &TEST_POOL_ID, 5).is_err(),
            "truncated"
        );
    }

    #[test]
    fn anchor_round_trips_and_chains() {
        let k = keys(7);
        let a0 = tseal(&k, None, 42, 4, [9u8; 32]);
        let a1 = tseal(&k, Some(&a0), 42, 9, [8u8; 32]);
        assert_eq!(a1.encoded().len(), ANCHOR_LEN);
        assert_eq!(
            Anchor::decode_and_verify(&a0.encoded(), &k, 0, TEST_POOL_ID).unwrap(),
            a0
        );
        let back = Anchor::decode_and_verify(&a1.encoded(), &k, 1, TEST_POOL_ID).unwrap();
        assert_eq!((back.seq, back.txg, back.prev), (1, 9, a0.hash()));
        assert_eq!((back.pool_id, back.tenant_id), (TEST_POOL_ID, [0x7a; 16]));
        assert_eq!(
            back.release,
            Release {
                runtime: 3,
                guest: 5
            }
        );
    }

    #[test]
    fn anchor_refuses_tampering_replay_and_strangers() {
        let k = keys(7);
        let a = tseal(&k, None, 42, 4, [9u8; 32]);
        let mut flipped = a.encoded().to_vec();
        flipped[OFF_TXG + 7] ^= 1;
        assert!(Anchor::decode_and_verify(&flipped, &k, 0, TEST_POOL_ID).is_err());
        assert!(
            Anchor::decode_and_verify(&a.encoded(), &k, 1, TEST_POOL_ID).is_err(),
            "replayed at another seq"
        );
        assert!(
            Anchor::decode_and_verify(&a.encoded(), &keys(8), 0, TEST_POOL_ID).is_err(),
            "another tenant key"
        );
        assert!(
            Anchor::decode_and_verify(&a.encoded(), &k, 0, [0x99; 16]).is_err(),
            "another pool's id"
        );
    }
}
