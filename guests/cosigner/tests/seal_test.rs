//! What opening from the seal does when the seal is not what it should be.
//!
//! The cosigner's seal is the only copy of its VTXOs and its delegate. So "there is no seal" and
//! "there is a seal and it cannot be read" are different situations with different right answers:
//! the first is a new wallet; the second is a read fault, and opening it as the first would forget
//! what the seal holds.

mod common;

/// Open from the seal, with no runtime around it.
fn open(
    store: std::sync::Arc<cosigner::store::Store>,
    group_key: String,
) -> Result<cosigner::Cosigner, cosigner::grpc::Status> {
    cosigner::Cosigner::open(store, group_key, std::sync::Arc::new(cosigner::host::Detached))
}

/// A seal that is there and cannot be read refuses to open as an empty wallet.
#[test]
fn a_present_but_unreadable_seal_refuses_to_open_as_a_fresh_wallet() {
    let Some(store) = common::try_store() else {
        return;
    };
    let group_key = "wallet".to_string();
    let cosigner = common::open_cosigner(&store, &group_key);
    cosigner.lock().unwrap().try_seal().expect("seal");
    drop(cosigner);

    // Not hex at all.
    store.put("sealed_state", &group_key, "not-hex").expect("put");
    let err = open(store.clone(), group_key.clone())
        .err()
        .expect("a corrupt seal must not open as a fresh wallet");
    assert!(format!("{err:?}").contains("unreadable"), "{err:?}");

    // Hex, and JSON, and not a snapshot.
    store
        .put("sealed_state", &group_key, &hex::encode(b"{}"))
        .expect("put");
    assert!(open(store.clone(), group_key.clone()).is_err());

    // No seal at all is a new wallet, and opens.
    store.delete("sealed_state", &group_key).expect("delete");
    open(store, group_key).expect("no seal is a fresh wallet");
}
