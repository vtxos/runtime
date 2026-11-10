//! Each tenant's wallet key: the runtime's half of its 2-of-2, and `enclave:signer`, the guest's
//! way to sign with it.
//!
//! Made by the DKG registration carries ([`dkg`]). The runtime's share is the operator's. It is
//! kept in the tenant's write-once registry record, sealed under a key derived from the operator
//! master ([`seal_share`]), and not on the tenant's pool: the pool is keyed with this share
//! ([`tenant_key`]), so the share has to be readable first. Every release reads the same master,
//! so nothing moves between releases.
//!
//! The ABI is defined in wit/signer/signer.wit. No function accepts a tenant id, none returns the
//! runtime's share, and every one is interactive only: the context is set on an authenticated
//! request and on nothing else.

pub mod dkg;
mod key;
pub mod signing;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use key::WalletKey;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, ensure, Context, Result};
use aws_lc_rs::aead::LessSafeKey;
use hkdf::Hkdf;
use k256::Scalar;
use sha2::Sha256;
use threshold::ecdh::{Partial, Session};
use threshold::identifier::Identifier;
use threshold::scalar::{scalar_from_bytes, scalar_to_bytes};
use wasmtime::component::{ComponentType, Lift, Linker, Lower, Resource, ResourceType};
use zeroize::Zeroizing;

use signing::Signing;

use crate::keys::OperatorMaster;
use crate::random::Rng;
use crate::state::State;
use crate::store::crypto::seal::{seal, unseal};
use crate::store::registry::{Registry, SEALED_SHARE_LEN};
use crate::tenant::TenantKey;

/// The HKDF salt of the key each tenant's share is sealed under.
const SHARE_SALT: &[u8] = b"aegira/signer/share-seal/v1";

/// `HKDF-SHA256(operator master, SHARE_SALT, tenant id)`: one key per tenant, so a sealed share
/// opens only under the name it was sealed for.
fn share_key(master: &[u8; 32], tenant: &[u8; 16]) -> Result<LessSafeKey> {
    let mut okm = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(SHARE_SALT), master)
        .expand(tenant, &mut okm[..])
        .map_err(|e| anyhow!("hkdf: {e}"))?;
    Ok(crate::store::crypto::keys::aes_key(&okm)?)
}

/// The runtime's share of `tenant`'s wallet key, sealed for its registry record: AES-256-GCM
/// under [`share_key`], with the tenant id as associated data.
pub fn seal_share(
    master: &[u8; 32],
    tenant: &[u8; 16],
    share: &Scalar,
) -> Result<[u8; SEALED_SHARE_LEN]> {
    let plain = Zeroizing::new(scalar_to_bytes(share));
    let sealed = seal(&share_key(master, tenant)?, tenant, plain.as_slice())?;
    sealed
        .try_into()
        .map_err(|_| anyhow!("a sealed share is {SEALED_SHARE_LEN} bytes"))
}

/// What [`seal_share`] sealed, or an error for anything sealed under another master or for
/// another tenant.
pub fn unseal_share(
    master: &[u8; 32],
    tenant: &[u8; 16],
    sealed: &[u8; SEALED_SHARE_LEN],
) -> Result<Scalar> {
    let plain = Zeroizing::new(unseal(&share_key(master, tenant)?, tenant, sealed)?);
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
        plain
            .as_slice()
            .try_into()
            .context("a sealed share holds 32 bytes")?,
    );
    scalar_from_bytes(&bytes).map_err(|e| anyhow!("the runtime's share: {e}"))
}

/// `k` for the tenant whose wallet key this is: the runtime's half of threshold ECDH, finished
/// with the wallet's partial under `transcript`. Returns `k` and the runtime's own partial, from
/// which the wallet derives the same `k`.
///
/// Fails if the wallet's proof does not verify against its verifying share: a partial that was
/// not made with the wallet's share is never combined.
pub fn tenant_key(
    key: &WalletKey,
    wallet: &Partial,
    transcript: &[u8],
) -> std::result::Result<(TenantKey, Partial), threshold::error::Error> {
    let group = key.public_key_package().verifying_key.point;
    let (session, mine) = Session::start(
        &group,
        key.signer(),
        key.secret_share(),
        transcript,
        &mut Rng,
    )?;
    let k = session.finish(key.wallet(), key.wallet_share(), wallet)?;
    Ok((TenantKey::from_bytes(*k), mine))
}

/// Each tenant's wallet key with its share unsealed, kept in memory from the first time a
/// registration, a sign-in or the signer needs it in a boot. Never written anywhere.
pub struct Keys {
    registry: Arc<Registry>,
    master: Arc<OperatorMaster>,
    cache: Mutex<HashMap<[u8; 16], Arc<WalletKey>>>,
}

impl Keys {
    pub fn new(registry: Arc<Registry>, master: Arc<OperatorMaster>) -> Self {
        Keys {
            registry,
            master,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// What the runtime's polynomials are derived from, and its shares sealed under.
    pub fn master(&self) -> &Arc<OperatorMaster> {
        &self.master
    }

    /// Keep a key a registration just made.
    pub fn insert(&self, tenant: [u8; 16], key: WalletKey) -> Arc<WalletKey> {
        let key = Arc::new(key);
        self.cache
            .lock()
            .expect("signer keys poisoned")
            .insert(tenant, key.clone());
        key
    }

    /// `tenant`'s wallet key, from memory or from its record.
    pub async fn get(&self, tenant: [u8; 16]) -> Result<Arc<WalletKey>> {
        if let Some(key) = self
            .cache
            .lock()
            .expect("signer keys poisoned")
            .get(&tenant)
        {
            return Ok(key.clone());
        }
        let record = self
            .registry
            .tenant(tenant)
            .await?
            .context("this tenant has no wallet key")?;
        let master = self.master.get().await?;
        let share = unseal_share(master, &tenant, &record.key.share)?;
        let key = WalletKey::from_record(&record.key, share).map_err(anyhow::Error::msg)?;
        Ok(self.insert(tenant, key))
    }
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field(
                "held",
                &self.cache.lock().map(|c| c.len()).unwrap_or_default(),
            )
            .finish_non_exhaustive()
    }
}

/// What a guest's `enclave:signer` calls reach: the tenant of one interactive call, and the keys
/// its wallet key is read from.
#[derive(Clone)]
pub struct SignerContext {
    pub keys: Arc<Keys>,
    pub tenant: [u8; 16],
}

impl SignerContext {
    async fn key(&self) -> Result<Arc<WalletKey>> {
        self.keys.get(self.tenant).await
    }

    /// `f_c(id_w)` for the key's wallet, if that is the wallet `identifier` names.
    async fn dealt_share(&self, identifier: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let key = self.key().await?;
        let asked = Identifier::try_from(identifier).map_err(|e| anyhow!("bad identifier: {e}"))?;
        ensure!(
            &asked == key.wallet(),
            "that identifier is not this wallet's: the share it rebuilt would not sign"
        );
        let master = self.keys.master().get().await?;
        dkg::dealt_share(master, key.handle(), key.wallet()).map_err(anyhow::Error::msg)
    }
}

/// The WIT `commitment`.
#[derive(ComponentType, Lower, Clone, Debug)]
#[component(record)]
struct Commitment {
    #[component(name = "hiding")]
    hiding: Vec<u8>,
    #[component(name = "binding")]
    binding: Vec<u8>,
}

/// The WIT `wallet-round`.
#[derive(ComponentType, Lift, Clone, Debug)]
#[component(record)]
struct WalletRound {
    #[component(name = "hiding")]
    hiding: Vec<u8>,
    #[component(name = "binding")]
    binding: Vec<u8>,
    #[component(name = "share")]
    share: Vec<u8>,
}

/// The WIT `key`.
#[derive(ComponentType, Lower, Clone, Debug)]
#[component(record)]
struct PublicWalletKey {
    #[component(name = "group-key")]
    group_key: Vec<u8>,
    #[component(name = "public-key-package")]
    public_key_package: String,
    #[component(name = "signer-identifier")]
    signer_identifier: Vec<u8>,
    #[component(name = "wallet-identifier")]
    wallet_identifier: Vec<u8>,
}

/// What a guest's `signing` handle refers to: a round halfway through, until `finish` spends it.
pub struct SigningHandle(Option<Signing>);

fn context(state: &State) -> Result<SignerContext> {
    state
        .signer
        .clone()
        .context("the wallet key needs its owner connected: interactive, authenticated calls only")
}

pub fn add_to_linker(linker: &mut Linker<State>) -> wasmtime::Result<()> {
    let mut wallet = linker.instance("enclave:signer/wallet@0.1.0")?;

    // Dropping the handle drops the round, and its nonces with it.
    wallet.resource(
        "signing",
        ResourceType::host::<SigningHandle>(),
        |mut store, rep| {
            store
                .data_mut()
                .table()
                .delete(Resource::<SigningHandle>::new_own(rep))?;
            Ok(())
        },
    )?;

    wallet.func_wrap_async("wallet-key", |store, (): ()| {
        Box::new(async move {
            let result = async move {
                let key = context(store.data())?.key().await?;
                Ok::<_, anyhow::Error>(PublicWalletKey {
                    group_key: key.group_key().to_vec(),
                    public_key_package: key.public_key_package().to_json(),
                    signer_identifier: key.signer().serialize().to_vec(),
                    wallet_identifier: key.wallet().serialize().to_vec(),
                })
            }
            .await;
            Ok((result.map_err(|e| e.to_string()),))
        })
    })?;

    wallet.func_wrap_async("dealt-share", |store, (identifier,): (Vec<u8>,)| {
        Box::new(async move {
            let result = async move {
                let share = context(store.data())?.dealt_share(&identifier).await?;
                Ok::<_, anyhow::Error>(share.to_vec())
            }
            .await;
            Ok((result.map_err(|e| e.to_string()),))
        })
    })?;

    wallet.func_wrap_async(
        "[static]signing.begin",
        |mut store, (messages,): (Vec<Vec<u8>>,)| {
            Box::new(async move {
                // Owned before the await: the store is not to be borrowed across one.
                let begun = match context(store.data()) {
                    Ok(ctx) => ctx.key().await.map(|key| Signing::begin(&key, &messages)),
                    Err(e) => Err(e),
                };
                let (signing, commitments) = match begun {
                    Ok(begun) => begun,
                    Err(e) => return Ok((Err(e.to_string()),)),
                };
                let handle = store
                    .data_mut()
                    .table()
                    .push(SigningHandle(Some(signing)))?;
                let commitments = commitments
                    .into_iter()
                    .map(|c| Commitment {
                        hiding: c.hiding.to_vec(),
                        binding: c.binding.to_vec(),
                    })
                    .collect::<Vec<_>>();
                Ok((Ok((handle, commitments)),))
            })
        },
    )?;

    wallet.func_wrap(
        "[method]signing.finish",
        |mut store, (handle, rounds): (Resource<SigningHandle>, Vec<WalletRound>)| {
            let signing = store.data_mut().table().get_mut(&handle)?.0.take();
            let result = match signing {
                None => Err("this round is already finished".to_string()),
                Some(signing) => signing
                    .finish(
                        &rounds
                            .into_iter()
                            .map(|r| signing::WalletRound {
                                hiding: r.hiding,
                                binding: r.binding,
                                share: r.share,
                            })
                            .collect::<Vec<_>>(),
                    )
                    .map(|signatures| {
                        signatures
                            .into_iter()
                            .map(|s| s.to_vec())
                            .collect::<Vec<_>>()
                    }),
            };
            Ok((result,))
        },
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::testing::{enrol, Wallet};
    use super::*;
    use crate::tenant::tenant_of;

    const MASTER: [u8; 32] = [7; 32];
    const HANDLE: [u8; 16] = [9; 16];

    #[test]
    fn a_sealed_share_opens_only_for_its_tenant_under_its_master() {
        let share = Scalar::from(12345u64);
        let sealed = seal_share(&MASTER, &[1; 16], &share).unwrap();
        assert_eq!(unseal_share(&MASTER, &[1; 16], &sealed).unwrap(), share);
        assert!(
            unseal_share(&MASTER, &[2; 16], &sealed).is_err(),
            "another tenant"
        );
        assert!(
            unseal_share(&[8; 32], &[1; 16], &sealed).is_err(),
            "another master"
        );
    }

    /// Registered once; read back from the record by a boot that never saw the registration.
    #[tokio::test]
    async fn a_key_is_read_back_from_its_record() {
        let fs = crate::store::zfs::Zfs::scratch().await;
        let (_, registered, _) = enrol(&MASTER, &HANDLE);
        let tenant = tenant_of(&registered.key.group_key());
        let sealed = seal_share(&MASTER, &tenant, registered.key.secret_share()).unwrap();
        fs.registry()
            .register(tenant, registered.key.record(sealed))
            .await
            .unwrap();

        let keys = Keys::new(
            fs.registry().clone(),
            Arc::new(OperatorMaster::fixed(MASTER)),
        );
        let back = keys.get(tenant).await.unwrap();
        assert_eq!(back.group_key(), registered.key.group_key());
        assert_eq!(back.secret_share(), registered.key.secret_share());
        assert!(keys.get([3; 16]).await.is_err(), "a tenant with no record");
    }

    /// The dealt share goes to the key's own wallet and to nobody else, and it is the one the DKG
    /// dealt, recomputed from the handle the record keeps.
    #[tokio::test]
    async fn the_dealt_share_goes_only_to_the_keys_wallet() {
        let fs = crate::store::zfs::Zfs::scratch().await;
        let (wallet, registered, _) = enrol(&MASTER, &HANDLE);
        let tenant = tenant_of(&registered.key.group_key());
        let ctx = SignerContext {
            keys: Arc::new(Keys::new(
                fs.registry().clone(),
                Arc::new(OperatorMaster::fixed(MASTER)),
            )),
            tenant,
        };
        assert!(ctx.dealt_share(&wallet.id().serialize()).await.is_err());

        let sealed = seal_share(&MASTER, &tenant, registered.key.secret_share()).unwrap();
        fs.registry()
            .register(tenant, registered.key.record(sealed))
            .await
            .unwrap();
        let share = ctx.dealt_share(&wallet.id().serialize()).await.unwrap();
        assert_eq!(
            *share,
            threshold::scalar::scalar_to_bytes(&registered.dealt.secret_share)
        );
        let stranger = Wallet::random();
        assert!(ctx.dealt_share(&stranger.id().serialize()).await.is_err());
        assert!(ctx.dealt_share(&[0; 31]).await.is_err());
    }

    /// The wallet and the runtime, each with its own share, derive one `k`; the wallet's partial
    /// made with any other share is refused.
    #[test]
    fn both_halves_of_the_ecdh_derive_one_key() {
        let (_, registered, wallet_key) = enrol(&MASTER, &HANDLE);
        let key = registered.key;
        let group = key.public_key_package().verifying_key.point;
        let (session, partial) = Session::start(
            &group,
            &wallet_key.identifier,
            &wallet_key.secret_share,
            b"transcript",
            &mut Rng,
        )
        .unwrap();
        let (k, runtime) = tenant_key(&key, &partial, b"transcript").unwrap();
        let k_wallet = session
            .finish(key.signer(), &key.key_package().verifying_share, &runtime)
            .unwrap();
        assert!(k.ct_eq(&TenantKey::from_bytes(*k_wallet)));

        let (_, impostor) = Session::start(
            &group,
            &wallet_key.identifier,
            &(wallet_key.secret_share + Scalar::ONE),
            b"transcript",
            &mut Rng,
        )
        .unwrap();
        assert!(tenant_key(&key, &impostor, b"transcript").is_err());
    }
}
