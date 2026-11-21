//! Which release this enclave is, and what that release keeps.
//!
//! A **release** is a runtime image and a guest: the pair of PCR0 and PCR16 a
//! KMS key policy names. Each release has a master secret of its own, minted by
//! its first boot and released by KMS to that pair alone, and with it keeps the
//! keys of the tenants whose background work it runs ([`crate::store::registry`]).
//! That is no other release's business.
//!
//! What every release shares is the tenants' data, and that is not keyed by any
//! release. Each tenant's pool opens with the key its owner's share and the
//! runtime's derive together at sign-in — the owner's half sent only to a release
//! whose PCR0 and PCR16 its app approves — and is pinned to that key by its own
//! anchor 0 ([`crate::store::zfs`]). So a new release reads every tenant's data
//! exactly as the last one did, from the moment that tenant's owner signs in to
//! it, and **nothing is migrated**.
//!
//! Booting is therefore small:
//!
//! 1. Read PCR0 and PCR16, refusing an unmeasured guest, before anything is
//!    read from the store or asked of KMS.
//! 2. Find this release's sealed master secret, `versions/<vid>/sealed-key`,
//!    and open it; or, on the release's first boot, mint one and write it
//!    once, under Object Lock. That write is the release's lease: two first
//!    boots race it and one wins.
//! 3. Bring up the disk, and attach the tenants whose keys this release kept.
//!
//! A tenant this release never saw waits, attached by nothing, until its owner
//! signs in. Its tasks do not run and its connections are not held until then;
//! that is the cost of a release being unable to read what its owners have not
//! given it.

use std::sync::Arc;
use std::time::SystemTime;

use crate::store::backend::{get_once, put_once, Backend, Once};
use anyhow::{bail, Context, Result};
use nitro_nsm::{Nsm, PCR_GUEST, PCR_ZERO};

use crate::keys::{MasterKeySource, SealedKey};
use crate::store::crypto::VersionKeys;
use crate::store::mount::MountConfig;
use crate::store::zfs::{Disk, Release, ReleaseContext, Zfs};

/// Which boot of this release this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMode {
    /// This release's first boot on this store: it minted its master secret.
    VersionGenesis,
    /// This release has booted here before, and opened the secret it minted.
    VersionResume,
}

/// The two measurements that say what an enclave is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pair {
    /// The runtime image, measured by the hypervisor.
    pub pcr0: [u8; 48],
    /// The guest component, measured by that runtime into [`PCR_GUEST`] and
    /// locked before it asked for a key.
    pub pcr16: [u8; 48],
}

impl Pair {
    /// Read both from the device, refusing if the guest was never measured.
    ///
    /// The first thing [`boot`] does, before anything is read from the store or
    /// asked of KMS. An enclave that reached KMS with PCR16 unlocked would
    /// present an attestation with no guest in it, and could still extend the
    /// register after being released a key.
    pub fn read(nsm: &dyn Nsm) -> Result<Self> {
        let pcr0 = nsm
            .describe_pcr(0)
            .context("reading PCR0; a release is named by it")?;
        let guest = nsm
            .describe_pcr(PCR_GUEST)
            .context("reading PCR16, where the guest is measured")?;
        if !guest.locked {
            bail!(
                "PCR16 is not locked, so this enclave has not measured its guest. It must be \
                 measured and locked before any key is asked for: an attestation carries only \
                 locked registers, so a key policy pinning the guest would see none. Refusing \
                 to boot."
            );
        }
        if guest.value == PCR_ZERO {
            bail!(
                "PCR16 is locked but was never extended, so it names no guest. Refusing to boot."
            );
        }
        Ok(Pair {
            pcr0: register(&pcr0.value, 0)?,
            pcr16: register(&guest.value, PCR_GUEST)?,
        })
    }

    /// The release's id, `sha256(pcr0 ‖ pcr16)`: what names everything it
    /// keeps. Both registers are SHA-384 and so always 48 bytes, which keeps
    /// the concatenation unambiguous.
    pub fn vid(&self) -> [u8; 32] {
        let mut both = [0u8; 96];
        both[..48].copy_from_slice(&self.pcr0);
        both[48..].copy_from_slice(&self.pcr16);
        nitro_attestation::sha256(&both)
    }
}

fn register(value: &[u8], index: u16) -> Result<[u8; 48]> {
    value.try_into().with_context(|| {
        format!(
            "PCR{index} is {} bytes; a SHA-384 register is 48",
            value.len()
        )
    })
}

/// What a boot established, for logging and for serving.
#[derive(Debug)]
pub struct Booted {
    pub mode: BootMode,
    /// The disk, with the tenants this release kept attached.
    pub zfs: Arc<Zfs>,
    /// What this release keeps for itself.
    pub version_keys: Arc<VersionKeys>,
    /// The runtime image and guest this enclave is running.
    pub pair: Pair,
    /// `sha256(pcr0 ‖ pcr16)`.
    pub vid: [u8; 32],
    /// How many tenants were attached from this release's cache.
    pub resumed: usize,
}

/// Everything the boot needs that is not already in [`MountConfig`].
pub struct BootConfig {
    /// Where the pools live: the parent's disk, or a directory in tests.
    pub disk: Disk,
    /// This release's numbers, written into every anchor.
    pub release: Release,
}

/// Where a release's sealed master secret lives.
pub fn sealed_key_key(prefix: &str, vid: &[u8; 32]) -> String {
    format!("{prefix}versions/{}/sealed-key", hex::encode(vid))
}

/// Decide the mode, resolve this release's key, bring up the disk and attach
/// what this release kept.
pub async fn boot(
    roots: &Arc<dyn Backend>,
    mount_config: &MountConfig,
    boot_config: &BootConfig,
    nsm: &Arc<dyn Nsm>,
    key_source: &dyn MasterKeySource,
    clock: &Arc<dyn crate::clock::TrustedClock>,
) -> Result<Booted> {
    let prefix = &mount_config.bucket_prefix;
    let fs_uuid = mount_config.fs_id;

    // Before anything is read from the store or asked of KMS.
    let pair = Pair::read(nsm.as_ref())?;
    let vid = pair.vid();

    let key_object = sealed_key_key(prefix, &vid);
    let existing = get_once(roots, &key_object)
        .await
        .with_context(|| format!("reading {key_object}"))?;
    let (mode, master) = match existing {
        // Under `kms` this is where the key policy decides: a pair it does not
        // name gets no key and goes no further.
        Some(sealed) => (
            BootMode::VersionResume,
            key_source
                .open(&SealedKey::from_bytes(sealed.to_vec()))
                .await
                .context("opening this release's master key")?,
        ),
        None => {
            tracing::info!(
                pcr0 = %hex::encode(pair.pcr0),
                pcr16 = %hex::encode(pair.pcr16),
                "this release's first boot on this store: minting its master key"
            );
            let (master, sealed) = key_source.mint().await.context("minting a master key")?;
            let until = SystemTime::UNIX_EPOCH + clock.now()? + mount_config.root_retention;
            match put_once(roots, &key_object, sealed.as_bytes().to_vec().into(), until)
                .await
                .with_context(|| format!("writing {key_object}"))?
            {
                Once::Won => (BootMode::VersionGenesis, master),
                Once::Lost => bail!(
                    "another enclave of this release minted its key first. Restart: the next \
                     boot opens that one."
                ),
            }
        }
    };

    let salt = [fs_uuid.as_slice(), vid.as_slice()].concat();
    let version_keys = Arc::new(
        VersionKeys::derive(&master, &salt).map_err(|e| anyhow::anyhow!("deriving keys: {e}"))?,
    );
    drop(master);

    let zfs = Zfs::open(
        &boot_config.disk,
        roots.clone(),
        fs_uuid,
        prefix,
        mount_config.root_retention,
        clock.clone(),
        ReleaseContext {
            vid,
            keys: version_keys.clone(),
            release: boot_config.release,
        },
    )
    .await
    .context("bringing up the disk")?;
    let resumed = zfs
        .resume_from_cache()
        .await
        .context("re-attaching the tenants this release kept")?;

    Ok(Booted {
        mode,
        zfs,
        version_keys,
        pair,
        vid,
        resumed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nitro_nsm::fake::FakeNsm;

    fn pair(pcr0: u8, pcr16: u8) -> Pair {
        Pair {
            pcr0: [pcr0; 48],
            pcr16: [pcr16; 48],
        }
    }

    /// One id per release, so the id has to change with either register — and
    /// with which register holds which value.
    #[test]
    fn a_release_id_names_both_measurements() {
        let base = pair(1, 2).vid();
        assert_eq!(pair(1, 2).vid(), base, "must be deterministic");
        assert_ne!(pair(9, 2).vid(), base, "another runtime");
        assert_ne!(pair(1, 9).vid(), base, "another guest");
        assert_ne!(pair(2, 1).vid(), base, "registers swapped");
    }

    #[test]
    fn a_releases_key_lives_under_its_id() {
        let k = sealed_key_key("p/", &pair(1, 2).vid());
        assert!(k.starts_with("p/versions/"));
        assert_ne!(k, sealed_key_key("p/", &pair(1, 3).vid()));
    }

    #[test]
    fn a_measured_guest_is_read_back_as_the_pair() {
        let nsm = FakeNsm::new();
        let pcr16 = crate::guest::measure_guest(&nsm, b"a guest").unwrap();
        let read = Pair::read(&nsm).unwrap();
        assert_eq!(read.pcr16, pcr16);
        assert_eq!(read.pcr0, [0x10; 48], "the fake's PCR0");
    }

    /// Boot's first refusal, and the one that keeps an unmeasured guest from
    /// ever reaching KMS.
    #[test]
    fn an_unmeasured_guest_is_not_a_pair() {
        let err = Pair::read(&FakeNsm::new()).unwrap_err();
        assert!(
            format!("{err:#}").contains("PCR16 is not locked"),
            "{err:#}"
        );
    }

    #[test]
    fn a_locked_but_empty_guest_register_is_not_a_pair() {
        let nsm = FakeNsm::new();
        nsm.lock_pcr(PCR_GUEST).unwrap();
        let err = Pair::read(&nsm).unwrap_err();
        assert!(format!("{err:#}").contains("never extended"), "{err:#}");
    }
}
