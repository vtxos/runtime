//! Booting a release: its own key, minted once and opened after, and the
//! tenants it kept.
//!
//! Everything runs over `MemoryBackend` and a directory disk, with the static
//! key source, so there is no Docker, no network and no KMS: what is under test
//! is the decision, not S3. The NSM keeps registers the way the device does —
//! 0–15 locked from the start, 16 free until the guest is measured.

use std::sync::{Arc, Mutex};

use enclave_runtime::boot::{sealed_key_key, BootConfig, BootMode, Pair};
use enclave_runtime::store::backend::{
    memory::MemoryBackend, Backend, ListBlobsInput, PutBlobInput,
};
use enclave_runtime::store::MasterSecret;
use enclave_runtime::tenant::TenantKey;
use enclave_runtime::{AttachError, Disk, MountConfig, Release, StaticKey};
use nitro_nsm::{AttestationRequest, Nsm, Pcr, PCR_ZERO};

const GUEST_A: &[u8] = b"guest component A";
const GUEST_B: &[u8] = b"guest component B";
const FS_ID: [u8; 16] = [3u8; 16];
const ALICE: [u8; 16] = [0xa1; 16];

/// An NSM that keeps registers like the device. Boot asks it for nothing but
/// registers.
struct TestNsm {
    pcrs: Mutex<Vec<Pcr>>,
}

impl std::fmt::Debug for TestNsm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestNsm")
    }
}

impl TestNsm {
    fn unmeasured(pcr0: u8) -> Arc<dyn Nsm> {
        Arc::new(TestNsm {
            pcrs: Mutex::new(
                (0..32)
                    .map(|i| Pcr {
                        locked: i < 16,
                        value: if i == 0 {
                            vec![pcr0; 48]
                        } else {
                            PCR_ZERO.to_vec()
                        },
                    })
                    .collect(),
            ),
        })
    }

    /// A fresh enclave running image `pcr0` with `guest` measured, as the
    /// runtime does before it boots.
    fn running(pcr0: u8, guest: &[u8]) -> Arc<dyn Nsm> {
        let nsm = Self::unmeasured(pcr0);
        enclave_runtime::measure_guest(nsm.as_ref(), guest).expect("measuring the guest");
        nsm
    }
}

impl Nsm for TestNsm {
    fn get_random(&self, buf: &mut [u8]) -> anyhow::Result<()> {
        buf.fill(0x5a);
        Ok(())
    }

    fn attest(&self, _: &AttestationRequest) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("boot attests nothing")
    }

    fn describe_pcr(&self, index: u16) -> anyhow::Result<Pcr> {
        self.pcrs
            .lock()
            .unwrap()
            .get(index as usize)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no PCR{index}"))
    }

    fn extend_pcr(&self, index: u16, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut pcrs = self.pcrs.lock().unwrap();
        let pcr = pcrs
            .get_mut(index as usize)
            .ok_or_else(|| anyhow::anyhow!("no PCR{index}"))?;
        anyhow::ensure!(!pcr.locked, "PCR{index} is read-only");
        pcr.value = nitro_nsm::pcr_extend(&pcr.value, data);
        Ok(pcr.value.clone())
    }

    fn lock_pcr(&self, index: u16) -> anyhow::Result<()> {
        let mut pcrs = self.pcrs.lock().unwrap();
        let pcr = pcrs
            .get_mut(index as usize)
            .ok_or_else(|| anyhow::anyhow!("no PCR{index}"))?;
        anyhow::ensure!(!pcr.locked, "PCR{index} is read-only");
        pcr.locked = true;
        Ok(())
    }

    fn describe(&self) -> String {
        "test NSM".into()
    }
}

/// One bucket and one disk, reused across boots, so a restart and a new
/// release are both what they say.
struct Store {
    roots: Arc<dyn Backend>,
    disk: Disk,
}

impl Store {
    fn new() -> Self {
        Store {
            roots: Arc::new(MemoryBackend::new()),
            disk: Disk::scratch().expect("a scratch disk"),
        }
    }

    async fn keys(&self) -> Vec<String> {
        let listed = self
            .roots
            .list_blobs(ListBlobsInput {
                prefix: "",
                ..Default::default()
            })
            .await
            .expect("list");
        listed.items.into_iter().map(|i| i.key).collect()
    }

    async fn boot(&self, nsm: &Arc<dyn Nsm>) -> anyhow::Result<enclave_runtime::Booted> {
        enclave_runtime::boot(
            &self.roots,
            &config(),
            &BootConfig {
                disk: self.disk.clone(),
                release: Release::default(),
            },
            nsm,
            &StaticKey::new(MasterSecret::from_bytes([8u8; 32])),
            &(Arc::new(enclave_runtime::HostClock) as Arc<dyn enclave_runtime::TrustedClock>),
        )
        .await
    }
}

fn config() -> MountConfig {
    MountConfig {
        roots_bucket: "roots".into(),
        region: "us-east-1".into(),
        endpoint: None,
        access_key_id: None,
        secret_access_key: None,
        session_token: None,
        force_path_style: false,
        bucket_prefix: String::new(),
        fs_id: FS_ID,
        skip_bucket_probe: true,
        request_timeout: std::time::Duration::from_secs(30),
        root_retention: enclave_runtime::DEFAULT_ROOT_RETENTION,
    }
}

fn vid(pcr0: u8, guest: &[u8]) -> [u8; 32] {
    Pair {
        pcr0: [pcr0; 48],
        pcr16: nitro_attestation::guest_pcr(guest),
    }
    .vid()
}

#[tokio::test]
async fn a_releases_first_boot_mints_its_key_and_a_restart_opens_it() {
    let store = Store::new();
    let first = store
        .boot(&TestNsm::running(0xaa, GUEST_A))
        .await
        .expect("first boot");
    assert_eq!(first.mode, BootMode::VersionGenesis);
    assert_eq!(first.vid, vid(0xaa, GUEST_A));
    assert_eq!(first.resumed, 0);
    assert_eq!(
        store.keys().await,
        vec![sealed_key_key("", &vid(0xaa, GUEST_A))],
        "a first boot writes its key and nothing else"
    );
    drop(first);

    let again = store
        .boot(&TestNsm::running(0xaa, GUEST_A))
        .await
        .expect("restart");
    assert_eq!(again.mode, BootMode::VersionResume);
    assert_eq!(store.keys().await.len(), 1, "a restart writes nothing");
}

/// A hidden key is still the key: the retained version is read, so a restart
/// does not mint a second one beside it.
#[tokio::test]
async fn hiding_a_releases_key_does_not_get_it_reminted() {
    let store = Store::new();
    store.boot(&TestNsm::running(0xaa, GUEST_A)).await.unwrap();
    store
        .roots
        .delete_blob(&sealed_key_key("", &vid(0xaa, GUEST_A)))
        .await
        .unwrap();
    let again = store.boot(&TestNsm::running(0xaa, GUEST_A)).await.unwrap();
    assert_eq!(again.mode, BootMode::VersionResume);
}

/// Bytes at a release's key that it did not write open as nothing: refused,
/// not replaced.
#[tokio::test]
async fn junk_at_a_releases_key_is_refused() {
    let store = Store::new();
    store
        .roots
        .put_blob(PutBlobInput::new(
            sealed_key_key("", &vid(0xaa, GUEST_A)),
            b"not a key".to_vec().into(),
        ))
        .await
        .unwrap();
    let err = store
        .boot(&TestNsm::running(0xaa, GUEST_A))
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("opening this release's master key"),
        "{err:#}"
    );
}

/// The guest is measured before any key is asked for; an enclave that skipped
/// it reads nothing and writes nothing.
#[tokio::test]
async fn an_unmeasured_guest_is_refused_before_anything_is_touched() {
    let store = Store::new();
    let err = store.boot(&TestNsm::unmeasured(0xaa)).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("PCR16 is not locked"),
        "{err:#}"
    );
    assert!(store.keys().await.is_empty());
}

/// The point of it all. A tenant's data, written under release A, is read by
/// release B as soon as its owner sends B the key — with nothing migrated, and
/// nothing B could have opened without it.
#[tokio::test]
async fn a_new_release_reads_a_tenants_data_once_its_owner_sends_the_key() {
    let store = Store::new();
    let key = TenantKey::from_bytes([0x4b; 32]);

    // Release A: the tenant signs in, writes, and has background work.
    let a = store.boot(&TestNsm::running(0xaa, GUEST_A)).await.unwrap();
    let place = a.zfs.registry().claim_place(ALICE).await.unwrap();
    a.zfs.attach(ALICE, place, &key).await.unwrap();
    std::fs::write(a.zfs.attached_dir(ALICE).unwrap().join("ledger"), b"42").unwrap();
    a.zfs.anchor_tenant(ALICE).await.unwrap();
    a.zfs.mark_background(ALICE).await.unwrap();

    // A restart of A picks the tenant straight back up.
    let a_again = store.boot(&TestNsm::running(0xaa, GUEST_A)).await.unwrap();
    assert_eq!(a_again.resumed, 1);
    assert!(a_again.zfs.is_attached(ALICE));
    drop(a_again);

    // Release B, a new guest: its own key, and none of A's tenants.
    let b = store.boot(&TestNsm::running(0xaa, GUEST_B)).await.unwrap();
    assert_eq!(b.mode, BootMode::VersionGenesis);
    assert_ne!(b.vid, a.vid);
    assert_eq!(
        b.resumed, 0,
        "B can open no tenant its owner has not sent it"
    );
    assert!(b.zfs.attached_dir(ALICE).is_err());

    // A key that is not the tenant's opens nothing.
    assert!(matches!(
        b.zfs
            .attach(ALICE, place, &TenantKey::from_bytes([0x4c; 32]))
            .await,
        Err(AttachError::WrongKey)
    ));

    // The owner signs in to B: the same pool, intact.
    b.zfs.attach(ALICE, place, &key).await.unwrap();
    assert_eq!(
        std::fs::read(b.zfs.attached_dir(ALICE).unwrap().join("ledger")).unwrap(),
        b"42"
    );
    b.zfs.anchor_tenant(ALICE).await.unwrap();
}

/// A new runtime image is a new release in exactly the same way.
#[tokio::test]
async fn a_new_runtime_image_is_a_new_release_too() {
    let store = Store::new();
    let a = store.boot(&TestNsm::running(0xaa, GUEST_A)).await.unwrap();
    let b = store.boot(&TestNsm::running(0xbb, GUEST_A)).await.unwrap();
    assert_eq!(b.mode, BootMode::VersionGenesis);
    assert_ne!(a.vid, b.vid);
    assert_eq!(store.keys().await.len(), 2, "a key per release");
}
