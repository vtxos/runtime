use super::*;
use crate::auth::client::{Client, Registering};
use crate::keys::OperatorMaster;
use crate::store::backend::Backend;
use crate::store::zfs::Disk;
use http_body_util::BodyExt;
use serde_json::Value;

const MASTER: [u8; 32] = [7; 32];
/// The certificate this test enclave "served".
const CERTIFICATE: [u8; 32] = [0xce; 32];

/// One boot: endpoints over a store. Two on the same disk and bucket are a restart.
async fn boot(disk: &Disk, roots: Arc<dyn Backend>) -> (AuthEndpoints, Arc<Zfs>) {
    let fs = Zfs::scratch_on(disk, roots).await;
    let keys = Arc::new(Keys::new(
        fs.registry().clone(),
        Arc::new(OperatorMaster::fixed(MASTER)),
    ));
    let gate = Arc::new(Gate::new(crate::auth::TokenStore::new(
        crate::auth::DEFAULT_TOKEN_TTL,
        crate::auth::DEFAULT_TOKEN_CAPACITY,
    )));
    let entropy: Arc<dyn nitro_nsm::Nsm> = Arc::new(nitro_nsm::fake::FakeNsm::new());
    let endpoints = AuthEndpoints::new(
        gate,
        keys,
        fs.clone(),
        entropy,
        ChallengeStore::new(
            crate::auth::challenge::DEFAULT_TTL,
            crate::auth::challenge::DEFAULT_CAPACITY,
        ),
    );
    (endpoints, fs)
}

async fn fresh() -> (AuthEndpoints, Arc<Zfs>) {
    boot(
        &Disk::scratch().unwrap(),
        Arc::new(crate::store::backend::memory::MemoryBackend::new()),
    )
    .await
}

async fn post(endpoints: &AuthEndpoints, path: &str, body: &Value) -> (u16, Value, bool) {
    let answer = endpoints
        .handle(
            &hyper::Method::POST,
            path,
            body.to_string().as_bytes(),
            &CERTIFICATE,
        )
        .await
        .expect("an auth route");
    let status = answer.response.status().as_u16();
    let bytes = answer
        .response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        answer.attest,
    )
}

/// Register as the app does; `edit` changes `register/verify`'s body first. Back: the answer,
/// and the client with the key its own partial derived, when it worked.
async fn register_with(
    endpoints: &AuthEndpoints,
    registering: Registering,
    edit: impl FnOnce(&mut Value),
) -> (u16, Value, Option<(Client, [u8; 32])>) {
    let (status, options, attested) = post(
        endpoints,
        "/auth/register/options",
        &registering.options_body(),
    )
    .await;
    assert_eq!(status, 200, "{options}");
    assert!(attested, "register/options carries the attestation");
    let (mut body, pending) = registering.verify_body(&options, &CERTIFICATE).unwrap();
    edit(&mut body);
    let (status, answer, attested) = post(endpoints, "/auth/register/verify", &body).await;
    assert!(
        !attested,
        "register/verify answers on a connection already checked"
    );
    let finished = (status == 200).then(|| pending.finish(&answer).unwrap());
    (status, answer, finished)
}

async fn register(endpoints: &AuthEndpoints) -> (Client, [u8; 32]) {
    register_as(endpoints, Registering::new()).await
}

async fn register_as(endpoints: &AuthEndpoints, wallet: Registering) -> (Client, [u8; 32]) {
    let (status, answer, finished) = register_with(endpoints, wallet, |_| {}).await;
    assert_eq!(status, 200, "{answer}");
    finished.unwrap()
}

/// One wallet, the same every time: a passkey's PRF, on any phone.
fn the_wallet() -> Registering {
    Registering::from_coefficients(&[3; 32], &[4; 32]).unwrap()
}

/// A challenge for `POST /sign`, as `request/options` issues it.
async fn challenge(endpoints: &AuthEndpoints, client: &Client) -> Value {
    let (status, options, attested) = post(
        endpoints,
        "/auth/request/options",
        &client.options_body("POST", "/sign", None),
    )
    .await;
    assert_eq!(status, 200, "{options}");
    assert!(attested, "request/options carries the attestation");
    options
}

/// A sign-in for `POST /sign`: a challenge, then `edit` changes the signed body before it is
/// sent. Back: status, answer, whether it was attested, and the key the client derived from the
/// runtime's partial.
async fn sign_in_with(
    endpoints: &AuthEndpoints,
    client: &Client,
    edit: impl FnOnce(&mut Value),
) -> (u16, Value, bool, Option<[u8; 32]>) {
    let options = challenge(endpoints, client).await;
    let (mut body, pending) = client
        .verify_body(&options, "POST", "/sign", None, &CERTIFICATE)
        .unwrap();
    edit(&mut body);
    let (status, answer, attested) = post(endpoints, "/auth/request/verify", &body).await;
    let k = (status == 200).then(|| pending.finish(&answer).unwrap());
    (status, answer, attested, k)
}

// ---- registration ---------------------------------------------------------

/// Both calls, and at the end of the second a record and a pool: the whole registration.
#[tokio::test]
async fn registration_ends_with_the_tenants_pool() {
    let (endpoints, fs) = fresh().await;
    let (client, _) = register(&endpoints).await;
    let record = fs
        .registry()
        .tenant(client.tenant())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.key.group_key, client.group_key());
    assert!(fs.is_attached(client.tenant()), "the pool was not created");
}

/// `register/options` keeps nothing durable: no record, no region, no pool.
#[tokio::test]
async fn register_options_writes_nothing() {
    let (endpoints, fs) = fresh().await;
    let registering = Registering::new();
    let (status, _, _) = post(
        &endpoints,
        "/auth/register/options",
        &registering.options_body(),
    )
    .await;
    assert_eq!(status, 200);
    assert!(fs.attached_tenants().is_empty());
    // No region was claimed: the next claim is the first region.
    let place = fs.registry().claim_place([9; 16]).await.unwrap();
    assert_eq!(place.region, 0);
}

/// A registration the wallet cannot sign for, or whose partial was not made with its share, is
/// refused with no record and no pool, and cannot be retried.
#[tokio::test]
async fn a_registration_that_does_not_verify_keeps_nothing() {
    for edit in [
        (|b: &mut Value| b["signature"] = Value::String("00".repeat(64))) as fn(&mut Value),
        |b: &mut Value| {
            let s = b["ecdh"]["s"].as_str().unwrap().to_string();
            let flipped = if s.ends_with('0') { "1" } else { "0" };
            b["ecdh"]["s"] = Value::String(format!("{}{flipped}", &s[..s.len() - 1]));
        },
    ] {
        let (endpoints, fs) = fresh().await;
        let (status, answer, _) = register_with(&endpoints, Registering::new(), edit).await;
        assert_eq!(status, 401, "{answer}");
        assert!(fs.attached_tenants().is_empty());
    }
}

/// The wallet's dealt share is checked against the commitment it made in `register/options`.
#[tokio::test]
async fn a_dealt_share_off_the_wallets_commitment_is_refused() {
    let (endpoints, fs) = fresh().await;
    let (status, _, _) = register_with(&endpoints, Registering::new(), |b| {
        let mut package: Value =
            serde_json::from_str(b["dkg"]["round2_package"].as_str().unwrap()).unwrap();
        let share = package["secretShare"].as_str().unwrap().to_string();
        let flipped = if share.ends_with('0') { "1" } else { "0" };
        package["secretShare"] = Value::String(format!("{}{flipped}", &share[..share.len() - 1]));
        b["dkg"]["round2_package"] = Value::String(package.to_string());
    })
    .await;
    assert_eq!(status, 400);
    assert!(fs.attached_tenants().is_empty());
}

#[tokio::test]
async fn a_registration_id_is_good_once() {
    let (endpoints, _) = fresh().await;
    let registering = Registering::new();
    let (_, options, _) = post(
        &endpoints,
        "/auth/register/options",
        &registering.options_body(),
    )
    .await;
    let (body, _) = registering.verify_body(&options, &CERTIFICATE).unwrap();
    let (first, _, _) = post(&endpoints, "/auth/register/verify", &body).await;
    let (second, _, _) = post(&endpoints, "/auth/register/verify", &body).await;
    assert_eq!((first, second), (200, 403));
}

/// Registering again is recovering: the same wallet gets the same key, the same `k`, the same
/// pool, and no second region.
#[tokio::test]
async fn registering_again_is_recovering() {
    let (endpoints, fs) = fresh().await;
    let (client, k) = register_as(&endpoints, the_wallet()).await;
    let (again, k_again) = register_as(&endpoints, the_wallet()).await;
    assert_eq!((again.save(), k_again), (client.save(), k));
    // One region claimed, the tenant's: the next claim is the second.
    assert_eq!(fs.registry().claim_place([9; 16]).await.unwrap().region, 1);
    let (status, answer, _, k_signed_in) = sign_in_with(&endpoints, &client, |_| {}).await;
    assert_eq!(status, 200, "{answer}");
    assert_eq!(k_signed_in.unwrap(), k);
}

/// As on a new phone after a restart: a fresh boot on the same disk and bucket.
#[tokio::test]
async fn after_a_restart_registering_again_opens_the_same_pool() {
    let disk = Disk::scratch().unwrap();
    let roots: Arc<dyn Backend> = Arc::new(crate::store::backend::memory::MemoryBackend::new());
    let (first, _) = boot(&disk, roots.clone()).await;
    let (client, k) = register_as(&first, the_wallet()).await;
    drop(first);

    let (second, fs) = boot(&disk, roots).await;
    let (again, k_again) = register_as(&second, the_wallet()).await;
    assert_eq!((again.save(), k_again), (client.save(), k));
    assert!(fs.is_attached(client.tenant()));
}

/// Revocation is for good: the wallet registering again is refused, and claims nothing.
#[tokio::test]
async fn a_revoked_wallet_cannot_register_again() {
    let (endpoints, fs) = fresh().await;
    let (client, _) = register_as(&endpoints, the_wallet()).await;
    fs.registry().revoke(client.tenant()).await.unwrap();
    let (status, answer, finished) = register_with(&endpoints, the_wallet(), |_| {}).await;
    assert_eq!(status, 401, "{answer}");
    assert!(finished.is_none());
    assert_eq!(fs.registry().claim_place([9; 16]).await.unwrap().region, 1);
}

/// The same `a0` with another slope makes the same tenant with other shares: refused, with no
/// partial for the tenant's `k`.
#[tokio::test]
async fn another_key_for_a_tenant_on_record_is_refused() {
    let (endpoints, _) = fresh().await;
    register_as(&endpoints, the_wallet()).await;
    let other = Registering::from_coefficients(&[3; 32], &[5; 32]).unwrap();
    let (status, answer, finished) = register_with(&endpoints, other, |_| {}).await;
    assert_eq!(status, 409, "{answer}");
    assert!(finished.is_none());
}

/// The same wallet registering twice at once is one tenant.
#[tokio::test]
async fn one_wallet_registering_twice_at_once_is_one_tenant() {
    let (endpoints, _) = fresh().await;
    let ((a, k_a), (b, k_b)) = tokio::join!(
        register_as(&endpoints, the_wallet()),
        register_as(&endpoints, the_wallet())
    );
    assert_eq!((a.save(), k_a), (b.save(), k_b));
}

/// A body the route does not know — here the old `display_name` — is refused, with no document.
#[tokio::test]
async fn an_old_registration_body_is_refused() {
    let (endpoints, _) = fresh().await;
    let (status, _, attested) = post(
        &endpoints,
        "/auth/register/options",
        &serde_json::json!({ "display_name": "cosigner" }),
    )
    .await;
    assert_eq!(status, 400);
    assert!(!attested);
}

// ---- sign-in --------------------------------------------------------------

/// The key a sign-in derives is the one registration made: the same pool opens.
#[tokio::test]
async fn every_sign_in_derives_the_registrations_key() {
    let (endpoints, _) = fresh().await;
    let (client, registered) = register(&endpoints).await;
    for _ in 0..2 {
        let (status, answer, attested, k) = sign_in_with(&endpoints, &client, |_| {}).await;
        assert_eq!(status, 200, "{answer}");
        assert!(
            !attested,
            "request/verify answers on a connection already checked"
        );
        assert_eq!(k.unwrap(), registered);
    }
}

/// Every sign-in carries the partial, open pool or not: the client cannot know which, and is
/// not told.
#[tokio::test]
async fn a_sign_in_without_its_partial_is_malformed() {
    let (endpoints, _) = fresh().await;
    let (client, _) = register(&endpoints).await;
    let (status, answer, attested, _) = sign_in_with(&endpoints, &client, |b| {
        b.as_object_mut().unwrap().remove("ecdh");
    })
    .await;
    assert_eq!(status, 400, "{answer}");
    assert!(!attested);
}

/// After a restart the pool is closed, and a sign-in opens the pool registration created.
#[tokio::test]
async fn after_a_restart_a_sign_in_opens_the_pool() {
    let disk = Disk::scratch().unwrap();
    let roots: Arc<dyn Backend> = Arc::new(crate::store::backend::memory::MemoryBackend::new());
    let (first, _) = boot(&disk, roots.clone()).await;
    let (client, registered) = register(&first).await;
    drop(first);

    let (second, fs) = boot(&disk, roots).await;
    assert!(!fs.is_attached(client.tenant()));
    let (status, answer, _, k) = sign_in_with(&second, &client, |_| {}).await;
    assert_eq!(status, 200, "{answer}");
    assert_eq!(k.unwrap(), registered);
    assert!(fs.is_attached(client.tenant()));
}

/// Every refusal of who is asking is the same 401, unattested.
#[tokio::test]
async fn refused_sign_ins_are_indistinguishable() {
    let (endpoints, _) = fresh().await;
    let (client, _) = register(&endpoints).await;
    let stranger = {
        let (other, _) = fresh().await;
        register(&other).await.0
    };
    type Edit = Box<dyn FnOnce(&mut Value)>;
    let edits: [(&str, Edit); 4] = [
        (
            "a bad signature",
            Box::new(|b| b["signature"] = Value::String("00".repeat(64))),
        ),
        (
            "a challenge that was never issued",
            Box::new(|b| b["challenge_id"] = Value::String("A".repeat(22))),
        ),
        (
            "a partial with a broken proof",
            Box::new(|b| {
                let s = b["ecdh"]["s"].as_str().unwrap().to_string();
                let flipped = if s.ends_with('0') { "1" } else { "0" };
                b["ecdh"]["s"] = Value::String(format!("{}{flipped}", &s[..s.len() - 1]));
            }),
        ),
        (
            "another partial than its own",
            Box::new(|b| {
                b["ecdh"]["share"] = b["ecdh"]["a"].clone();
            }),
        ),
    ];
    let mut messages = Vec::new();
    for (what, edit) in edits {
        let (status, answer, attested, _) = sign_in_with(&endpoints, &client, edit).await;
        assert_eq!(status, 401, "{what}: {answer}");
        assert!(!attested, "{what} was attested");
        messages.push(answer["error"].clone());
    }

    // A tenant this enclave never registered: its challenge is issued all the same, and it is
    // refused like the rest.
    let options = challenge(&endpoints, &stranger).await;
    let (body, _) = stranger
        .verify_body(&options, "POST", "/sign", None, &CERTIFICATE)
        .unwrap();
    let (status, answer, attested) = post(&endpoints, "/auth/request/verify", &body).await;
    assert_eq!(status, 401, "{answer}");
    assert!(!attested);
    messages.push(answer["error"].clone());

    // Signed for another interaction than the challenge was issued for.
    let options = challenge(&endpoints, &client).await;
    let (body, _) = client
        .verify_body(&options, "POST", "/withdraw", None, &CERTIFICATE)
        .unwrap();
    let (status, answer, _) = post(&endpoints, "/auth/request/verify", &body).await;
    assert_eq!(status, 401, "{answer}");
    messages.push(answer["error"].clone());

    assert!(messages.windows(2).all(|w| w[0] == w[1]), "{messages:?}");
}

/// A challenge is issued for any key, attested like any other, so an answer says nothing about
/// which keys are tenants.
#[tokio::test]
async fn a_challenge_says_nothing_about_who_is_a_tenant() {
    let (endpoints, _) = fresh().await;
    let stranger = {
        let (other, _) = fresh().await;
        register(&other).await.0
    };
    let (status, answer, attested) = post(
        &endpoints,
        "/auth/request/options",
        &stranger.options_body("POST", "/sign", None),
    )
    .await;
    assert_eq!(status, 200, "{answer}");
    assert!(attested);
}

/// A signature made for another enclave's certificate: what a server the parent ran with its
/// own certificate would have to relay.
#[tokio::test]
async fn a_sign_in_for_another_certificate_is_refused() {
    let (endpoints, _) = fresh().await;
    let (client, _) = register(&endpoints).await;
    let options = challenge(&endpoints, &client).await;
    let (body, _) = client
        .verify_body(&options, "POST", "/sign", None, &[0xab; 32])
        .unwrap();
    let (status, _, _) = post(&endpoints, "/auth/request/verify", &body).await;
    assert_eq!(status, 401);
}

/// One challenge, one signature, once: what stops a captured sign-in being replayed.
#[tokio::test]
async fn a_challenge_is_good_once() {
    let (endpoints, _) = fresh().await;
    let (client, _) = register(&endpoints).await;
    let options = challenge(&endpoints, &client).await;
    let (body, _) = client
        .verify_body(&options, "POST", "/sign", None, &CERTIFICATE)
        .unwrap();
    let (first, _, _) = post(&endpoints, "/auth/request/verify", &body).await;
    let (again, _, _) = post(&endpoints, "/auth/request/verify", &body).await;
    assert_eq!((first, again), (200, 401));
}

/// A challenge answered badly is gone all the same: no second attempt at it.
#[tokio::test]
async fn a_challenge_answered_badly_is_spent() {
    let (endpoints, _) = fresh().await;
    let (client, _) = register(&endpoints).await;
    let options = challenge(&endpoints, &client).await;
    let (good, _) = client
        .verify_body(&options, "POST", "/sign", None, &CERTIFICATE)
        .unwrap();
    let mut bad = good.clone();
    bad["signature"] = Value::String("00".repeat(64));
    let (first, _, _) = post(&endpoints, "/auth/request/verify", &bad).await;
    let (second, _, _) = post(&endpoints, "/auth/request/verify", &good).await;
    assert_eq!((first, second), (401, 401));
}

#[tokio::test]
async fn a_revoked_tenant_is_refused() {
    let (endpoints, fs) = fresh().await;
    let (client, _) = register(&endpoints).await;
    fs.registry().revoke(client.tenant()).await.unwrap();
    let (status, _, attested, _) = sign_in_with(&endpoints, &client, |_| {}).await;
    assert_eq!(status, 401);
    assert!(!attested);
}

/// The token is good for what was signed, once, and for nothing else.
#[tokio::test]
async fn the_token_is_for_the_signed_interaction() {
    let (endpoints, _) = fresh().await;
    let (client, _) = register(&endpoints).await;
    let token = |answer: &Value| answer["token"].as_str().unwrap().to_string();
    let request = |method: &str, path: &str, token: &str| {
        hyper::Request::builder()
            .method(method)
            .uri(format!("https://enclave.test{path}"))
            .header("authorization", format!("Bearer {token}"))
            .body(())
            .unwrap()
    };

    let (_, answer, _, _) = sign_in_with(&endpoints, &client, |_| {}).await;
    let t = token(&answer);
    assert!(endpoints
        .gate
        .redeem(&request("POST", "/withdraw", &t))
        .is_err());

    let (_, answer, _, _) = sign_in_with(&endpoints, &client, |_| {}).await;
    let t = token(&answer);
    let verified = endpoints
        .gate
        .redeem(&request("POST", "/sign", &t))
        .unwrap();
    assert_eq!(verified.tenant_id, client.tenant());
    assert!(endpoints
        .gate
        .redeem(&request("POST", "/sign", &t))
        .is_err());
}

/// An odd group key is malformed: every key a registration makes is even-Y.
#[tokio::test]
async fn an_odd_group_key_is_malformed() {
    let (endpoints, _) = fresh().await;
    let (client, _) = register(&endpoints).await;
    let mut body = client.options_body("POST", "/sign", None);
    let key = body["group_key"].as_str().unwrap().to_string();
    body["group_key"] = Value::String(format!("03{}", &key[2..]));
    let (status, _, _) = post(&endpoints, "/auth/request/options", &body).await;
    assert_eq!(status, 400);
}

// ---- the routes themselves --------------------------------------------------

#[tokio::test]
async fn only_posts_to_known_routes_are_answered_and_none_of_the_refusals_is_attested() {
    let (endpoints, _) = fresh().await;
    for (method, path, status) in [
        (hyper::Method::GET, "/auth/", 405),
        (hyper::Method::GET, "/auth/request/verify", 405),
        (hyper::Method::POST, "/auth/request/options", 400),
        (hyper::Method::POST, "/auth/request/challenge", 404),
        (hyper::Method::POST, "/auth/nothing", 404),
    ] {
        let answer = endpoints
            .handle(&method, path, b"{}", &CERTIFICATE)
            .await
            .unwrap();
        assert_eq!(answer.response.status().as_u16(), status, "{method} {path}");
        assert!(!answer.attest, "{method} {path} was attested");
    }
    let big = vec![b' '; MAX_BODY + 1];
    let answer = endpoints
        .handle(
            &hyper::Method::POST,
            "/auth/request/verify",
            &big,
            &CERTIFICATE,
        )
        .await
        .unwrap();
    assert_eq!(answer.response.status().as_u16(), 413);
    assert!(endpoints
        .handle(&hyper::Method::POST, "/sign", b"", &CERTIFICATE)
        .await
        .is_none());
}
