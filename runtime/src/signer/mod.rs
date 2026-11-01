//! Each tenant's wallet key: the signer's half of its 2-of-2, kept on the tenant's own pool,
//! and `enclave:signer`, the guest's way to sign with it.
//!
//! Made by the DKG that rides the passkey's registration ([`dkg`]), written once, and read by
//! every signing round after it. On the pool, so it is under the tenant's key like the rest of its
//! data, and a release opens it only when its owner sends that key.
//!
//! The ABI is defined in wit/signer/signer.wit. No function accepts a tenant id, none returns the
//! signer's share, and every one is interactive only: the context is set on an authenticated
//! request and on nothing else.

pub mod dkg;
mod key;
pub mod signing;
#[cfg(test)]
pub(crate) mod testing;

pub use key::WalletKey;

use std::sync::Arc;

use anyhow::{anyhow, ensure, Context, Result};
use threshold::identifier::Identifier;
use wasmtime::component::{ComponentType, Lift, Linker, Lower, Resource, ResourceType};
use zeroize::Zeroizing;

use signing::Signing;

use crate::keys::OperatorMaster;
use crate::state::State;
use crate::store::zfs::Zfs;

const DIR: &str = "keys";
const FILE: &str = "wallet";

/// What [`store`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum Stored {
    /// The key is kept, and anchored.
    New,
    /// The tenant already had this key: a DKG run again with the same passkey rebuilds it.
    Same,
    /// The tenant already has a different key, which is kept.
    Different,
}

/// The tenant's wallet key, if it has one. The tenant must be attached.
pub async fn load(zfs: &Zfs, tenant: [u8; 16]) -> Result<Option<WalletKey>> {
    let path = zfs.tenant_runtime_dir(tenant, DIR).await?.join(FILE);
    match tokio::fs::read(&path).await {
        Ok(bytes) => WalletKey::decode(&Zeroizing::new(bytes))
            .map(Some)
            .map_err(anyhow::Error::msg),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Keep a tenant's wallet key, anchored before this returns.
///
/// Never replaces one: everything held under a wallet key is spendable only with it, so a second
/// DKG that made another key is answered with [`Stored::Different`] and changes nothing.
pub async fn store(zfs: &Zfs, tenant: [u8; 16], key: &WalletKey) -> Result<Stored> {
    if let Some(existing) = load(zfs, tenant).await? {
        return Ok(if existing.group_key() == key.group_key() {
            Stored::Same
        } else {
            Stored::Different
        });
    }
    let dir = zfs.tenant_runtime_dir(tenant, DIR).await?;
    // Temp file, then renamed into place, so a crash leaves no half-written key.
    let temp = dir.join(format!("{FILE}.tmp"));
    tokio::fs::write(&temp, &*key.encode()).await?;
    tokio::fs::rename(&temp, dir.join(FILE)).await?;
    zfs.anchor_tenant(tenant).await?;
    Ok(Stored::New)
}

/// What a guest's `enclave:signer` calls reach: the tenant of one interactive call, and the master
/// its dealt share is recomputed from.
#[derive(Clone)]
pub struct SignerContext {
    pub zfs: Arc<Zfs>,
    pub master: Option<Arc<OperatorMaster>>,
    pub tenant: [u8; 16],
}

impl SignerContext {
    async fn key(&self) -> Result<WalletKey> {
        load(&self.zfs, self.tenant)
            .await?
            .context("this tenant has no wallet key yet")
    }

    /// `f_c(id_w)` for the key's wallet, if that is the wallet `identifier` names.
    async fn dealt_share(&self, identifier: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let key = self.key().await?;
        let asked = Identifier::try_from(identifier).map_err(|e| anyhow!("bad identifier: {e}"))?;
        ensure!(
            &asked == key.wallet(),
            "that passkey does not derive this wallet's identifier: the share it rebuilt would \
             not sign"
        );
        let master = self
            .master
            .as_ref()
            .context("this enclave has no operator master")?
            .get()
            .await?;
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

    const ALICE: [u8; 16] = [1; 16];
    const MASTER: [u8; 32] = [7; 32];
    const HANDLE: [u8; 16] = [9; 16];

    fn key(wallet: &mut Wallet) -> WalletKey {
        let to_signer = wallet
            .deal(&dkg::opening(&MASTER, &HANDLE).unwrap())
            .unwrap();
        dkg::register(&MASTER, &HANDLE, &wallet.package, &to_signer)
            .unwrap()
            .key
    }

    #[tokio::test]
    async fn a_key_is_kept_once_and_never_replaced() {
        let fs = Zfs::scratch().await;
        fs.tenant_dir(ALICE).await.unwrap();
        assert!(load(&fs, ALICE).await.unwrap().is_none());

        let mut wallet = Wallet::random();
        assert_eq!(
            store(&fs, ALICE, &key(&mut wallet)).await.unwrap(),
            Stored::New
        );
        assert_eq!(
            store(&fs, ALICE, &key(&mut wallet)).await.unwrap(),
            Stored::Same
        );
        let other = key(&mut Wallet::random());
        assert_eq!(store(&fs, ALICE, &other).await.unwrap(), Stored::Different);

        let kept = load(&fs, ALICE).await.unwrap().expect("a key");
        assert_eq!(kept.group_key(), key(&mut wallet).group_key());
        assert_eq!(kept.handle(), &HANDLE);
    }

    /// The dealt share goes to the key's own wallet and to nobody else, and it is the one the DKG
    /// dealt, recomputed from the handle the record keeps.
    #[tokio::test]
    async fn the_dealt_share_goes_only_to_the_keys_wallet() {
        let fs = Zfs::scratch().await;
        fs.tenant_dir(ALICE).await.unwrap();
        let ctx = SignerContext {
            zfs: fs.clone(),
            master: Some(Arc::new(OperatorMaster::fixed(MASTER))),
            tenant: ALICE,
        };
        let (wallet, registered, _) = enrol(&MASTER, &HANDLE);
        assert!(ctx.dealt_share(&wallet.id().serialize()).await.is_err());

        store(&fs, ALICE, &registered.key).await.unwrap();
        let share = ctx.dealt_share(&wallet.id().serialize()).await.unwrap();
        assert_eq!(
            *share,
            threshold::scalar::scalar_to_bytes(&registered.dealt.secret_share)
        );
        let stranger = Wallet::random();
        assert!(ctx.dealt_share(&stranger.id().serialize()).await.is_err());
        assert!(ctx.dealt_share(&[0; 31]).await.is_err());
    }
}
