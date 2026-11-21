//! `Recover`: the half of a wallet's key the runtime recomputes, and the ways the policy refuses
//! to hand it over.
//!
//! The arithmetic — that this share plus the wallet's own rebuilds the wallet's share — is the
//! runtime's to prove (`runtime/src/signer/dkg.rs`). What is checked here is the gate around it: it answers only once the
//! runtime holds a key, only for the identifier that key records, and it installs nothing.

mod common;

use policy::session::proto::RecoverRequest;

use threshold::identifier::Identifier;

fn asking_as(id: &Identifier) -> RecoverRequest {
    RecoverRequest {
        identifier: id.serialize().to_vec(),
    }
}

#[test]
fn recover_returns_the_dealt_share_to_the_wallets_own_identifier() {
    let Some(store) = common::try_store() else {
        return;
    };
    let wallet = common::wallet();
    let policy = common::open_holding(&store, &wallet);

    let resp = policy.lock().unwrap().recover(asking_as(&wallet.user.identifier))
        .expect("the owner's own identifier must be answered");

    assert_eq!(resp.dealt_share, wallet.dealt_share(), "the share the runtime recomputes");
    assert_eq!(resp.group_key, wallet.group_key());
    assert!(
        resp.public_key_package_json.contains(&wallet.group_key()),
        "the package the caller checks its rebuilt share against must come back with it"
    );

    // Nothing was installed: it answers again the same way.
    let again = policy.lock().unwrap().recover(asking_as(&wallet.user.identifier))
        .expect("recovering must not consume or re-key the wallet");
    assert_eq!(again.group_key, resp.group_key);
    assert_eq!(again.dealt_share, resp.dealt_share);
}

#[test]
fn recover_refuses_before_there_is_a_wallet() {
    let Some(store) = common::try_store() else {
        return;
    };
    let wallet = common::wallet();
    // A runtime holding no key for this tenant.
    let policy = common::open_policy(&store, &wallet.group_key());

    let err = policy.lock().unwrap().recover(asking_as(&wallet.user.identifier))
        .expect_err("there is nothing to recover before a DKG");
    assert!(format!("{err:?}").contains("has no key"), "unexpected refusal: {err:?}");
}

#[test]
fn recover_refuses_an_identifier_the_key_does_not_record() {
    let Some(store) = common::try_store() else {
        return;
    };
    let wallet = common::wallet();
    let policy = common::open_holding(&store, &wallet);

    // A passkey whose PRF answered differently derives a different identifier. It would rebuild a
    // share that cannot sign, so it is refused rather than served.
    let other = common::wallet();
    let err = policy.lock().unwrap().recover(asking_as(&other.user.identifier))
        .expect_err("a stranger's identifier must not be answered");
    assert!(
        format!("{err:?}").contains("does not derive this wallet"),
        "unexpected refusal: {err:?}"
    );
}
