// Shared test helpers: each integration binary compiles this module and uses only part of it.
#![allow(dead_code)]

//! Shared setup for the integration tests. Builds `Store` against the local dev stack.
//!
//! Persistence is an in-process SQLite store, so there is no external dependency to reach and each
//! `try_store` call gets its own isolated database.
//!
//! These tests run as wasm inside `guests/fake-host` (`fake-host-run`, cargo's runner here), so
//! the policy calls the runtime's interfaces exactly as a release does and the fake host
//! answers. The wallet key is the runtime's, so a test that signs deals it itself and hands the
//! runtime's half to the fake host ([`Recorder::hold`]): a plain 2-of-2 with both polynomials
//! random, because the guest sees only the public package, the dealt share and the rounds, and
//! how the runtime derives its half is the runtime's to test.

use policy::Policy;
use std::collections::BTreeMap;
use std::sync::Arc;

use rand::rngs::OsRng;

use policy::store::Store;

use enclave_wit::fake_host::enclave::fake_host::control;
use threshold::dkg;
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::random::mod_n_random;
use threshold::scalar::scalar_to_bytes;

use std::sync::Mutex;

pub fn try_store() -> Option<Arc<Store>> {
    // `:memory:` — a fresh, private store per caller. Tests no longer share one namespace, so a
    // leftover key from a failed run can't leak into the next one.
    Some(Arc::new(
        Store::open(":memory:", 1800).expect("open in-memory store"),
    ))
}

/// A wallet that has run its DKG with the runtime: the app's key package, and the policy's half
/// the runtime keeps.
pub struct TestWallet {
    pub user: KeyPackage,
    pub key: RuntimeKey,
}

impl TestWallet {
    /// The group key, compressed, hex — what the policy's seal is filed under in these tests.
    pub fn group_key(&self) -> String {
        hex::encode(self.key.group_key())
    }

    /// The share the policy dealt this wallet, as the runtime recomputes it.
    pub fn dealt_share(&self) -> Vec<u8> {
        self.key.dealt.clone()
    }
}

/// The runtime's half of a wallet key, as these tests play it.
#[derive(Clone)]
pub struct RuntimeKey {
    pub key_package: KeyPackage,
    pub public_key_package: PublicKeyPackage,
    pub wallet: Identifier,
    /// `f_c(id_w)`, as dealt.
    pub dealt: Vec<u8>,
}

impl RuntimeKey {
    pub fn group_key(&self) -> [u8; 33] {
        self.public_key_package.verifying_key.serialize()
    }
}

/// A 2-of-2 DKG between a wallet and the runtime, both polynomials random.
pub fn wallet() -> TestWallet {
    let mut rng = OsRng;
    let mut part1 = || {
        let (secret, slope) = (mod_n_random(&mut rng), mod_n_random(&mut rng));
        dkg::dkg_part1(2, 2, &secret, &[slope], &mut OsRng).expect("dkg_part1")
    };
    let (w1, w_pkg) = part1();
    let (c1, c_pkg) = part1();
    let (w_id, c_id) = (w1.identifier.clone(), c1.identifier.clone());
    let (w2, mut from_w) =
        dkg::dkg_part2(&w1, &BTreeMap::from([(c_id.clone(), c_pkg.clone())]), &[]).unwrap();
    let (c2, mut from_c) =
        dkg::dkg_part2(&c1, &BTreeMap::from([(w_id.clone(), w_pkg.clone())]), &[]).unwrap();
    let to_w = from_c.remove(&w_id).unwrap();
    let to_c = from_w.remove(&c_id).unwrap();
    let dealt = scalar_to_bytes(&to_w.secret_share).to_vec();
    let (user, _) = dkg::dkg_part3(
        &w1,
        &w2,
        &BTreeMap::from([(c_id.clone(), c_pkg)]),
        &BTreeMap::from([(c_id, to_w)]),
        &[],
    )
    .unwrap();
    let (key_package, public_key_package) = dkg::dkg_part3(
        &c1,
        &c2,
        &BTreeMap::from([(w_id.clone(), w_pkg)]),
        &BTreeMap::from([(w_id.clone(), to_c)]),
        &[],
    )
    .unwrap();
    TestWallet {
        user,
        key: RuntimeKey { key_package, public_key_package, wallet: w_id, dealt },
    }
}

/// Open the policy this process serves, in a runtime that holds no wallet key and no tasks.
pub fn open_policy(store: &Arc<Store>, group_key: &str) -> Mutex<Policy> {
    Recorder::default();
    let policy = Policy::open(store.clone(), group_key.to_string());
    Mutex::new(policy.expect("open policy"))
}

/// Open it inside a runtime that holds [wallet]'s key.
pub fn open_holding(store: &Arc<Store>, wallet: &TestWallet) -> Mutex<Policy> {
    Recorder::holding(wallet);
    let policy = Policy::open(store.clone(), wallet.group_key());
    Mutex::new(policy.expect("open policy"))
}

/// The wallet's half of a signing session over [messages]: a fresh nonce for each, then a share
/// over both commitments. What `answerRound` does in the app.
pub fn wallet_answers(
    kp_user: &KeyPackage,
    messages: &[Vec<u8>],
    cosigner_commitments: &[policy::types::Commitment],
) -> Vec<policy::sign::WalletHalf> {
    use threshold::commitment::SigningPackage;
    use threshold::nonce::{self, SigningCommitments};
    use threshold::point;
    use threshold::scalar::scalar_to_bytes;
    use threshold::signing;

    let mut rng = OsRng;
    messages
        .iter()
        .zip(cosigner_commitments)
        .map(|(message, theirs)| {
            let ours = nonce::new_nonce(&mut rng, &kp_user.secret_share);
            let mut commitments: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
            let id: [u8; 32] = hex::decode(&theirs.identifier_hex).unwrap().try_into().unwrap();
            commitments.insert(
                Identifier::deserialize(&id).unwrap(),
                SigningCommitments::from_bytes(&theirs.hiding, &theirs.binding).unwrap(),
            );
            commitments.insert(kp_user.identifier.clone(), ours.commitments.clone());
            let package = SigningPackage::new(commitments, message.clone());
            let share = signing::sign(&package, &ours, kp_user).expect("wallet share");
            policy::sign::WalletHalf {
                hiding: point::serialize_compressed(&ours.commitments.hiding).to_vec(),
                binding: point::serialize_compressed(&ours.commitments.binding).to_vec(),
                share: scalar_to_bytes(&share.s).to_vec(),
            }
        })
        .collect()
}

/// Make the next seal filed under [name] in the file store at [dir] fail to write: a directory
/// sits where its temporary goes, which to the code writing it looks like a full or failing disk.
pub fn block_seal(dir: &std::path::Path, name: &str) {
    let tree = dir.join(hex::encode("sealed_state"));
    std::fs::create_dir_all(tree.join(format!("{}.writing", hex::encode(name)))).unwrap();
}

/// Driving `Session::route` with messages, as the runtime delivers them.
///
/// A request from [request] is every message the client sends, then its close, so a test can open
/// a stream and read what the policy says first, but cannot answer it: a stream opened and left
/// is cut off mid-ceremony, and ends `Cancelled`.
pub mod wire {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::future::Future;
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    use policy::session::Session;
    use policy::status::Status;
    use policy::wallet_proto::GetServerInfoResponse;
    use policy::wire::{Wire, WireFuture};
    use policy::Policy;

    /// Drive a future to completion on this thread.
    ///
    /// Every message here is already in memory and the runtime's calls return at once, so nothing
    /// genuinely parks and a busy poll is enough. The cap is what turns "this future never
    /// finishes" into a failed test rather than a hung one.
    pub fn block_on<F: Future>(fut: F) -> F::Output {
        let mut fut = Box::pin(fut);
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..100_000 {
            if let Poll::Ready(value) = fut.as_mut().poll(&mut cx) {
                return value;
            }
        }
        panic!("the future never completed");
    }

    /// One call: its path, and every message the client sends before it closes.
    pub struct Request {
        method: String,
        messages: Vec<Vec<u8>>,
    }

    /// A call to `method` carrying `messages`, as the runtime would deliver it.
    pub fn request<M: prost::Message>(method: &str, messages: &[M]) -> Request {
        Request {
            method: format!("/cosigner.v1.Cosigner/{method}"),
            messages: messages.iter().map(|m| m.encode_to_vec()).collect(),
        }
    }

    /// What the policy said, and how the call ended.
    pub struct Response {
        messages: Vec<Vec<u8>>,
        outcome: Result<(), Status>,
    }

    /// What came back: the decoded messages, and the status a client reads from the trailers.
    pub struct Answer<M> {
        pub messages: Vec<M>,
        pub code: u32,
        pub message: String,
    }

    pub fn collect<M: prost::Message + Default>(resp: Response) -> Answer<M> {
        let (code, message) = match resp.outcome {
            Ok(()) => (0, String::new()),
            Err(s) => (s.code() as u32, s.message().to_string()),
        };
        let messages = resp
            .messages
            .iter()
            .map(|bytes| M::decode(bytes.as_slice()).expect("decodable response"))
            .collect();
        Answer { messages, code, message }
    }

    /// The router, over a policy, as the runtime calls it.
    pub struct Service(Session);

    impl Service {
        pub async fn route(&self, req: Request) -> Response {
            let replies = Rc::new(RefCell::new(Vec::new()));
            let wire = Scripted { requests: req.messages.into(), replies: replies.clone() };
            let outcome = self.0.route(&req.method, Box::new(wire)).await;
            let messages = replies.borrow_mut().drain(..).collect();
            Response { messages, outcome }
        }
    }

    pub fn service(policy: Policy) -> Service {
        Service(Session::new(
            Arc::new(Mutex::new(policy)),
            GetServerInfoResponse { bitcoin_network: "regtest".into() },
        ))
    }

    /// The client's messages, then its close; and what the policy said back.
    struct Scripted {
        requests: VecDeque<Vec<u8>>,
        replies: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl Wire for Scripted {
        fn recv(&mut self) -> WireFuture<'_, Option<Vec<u8>>> {
            let next = self.requests.pop_front();
            Box::pin(async move { next })
        }

        fn send(&mut self, message: Vec<u8>) -> WireFuture<'_, ()> {
            self.replies.borrow_mut().push(message);
            Box::pin(async {})
        }
    }
}

/// The runtime these tests run against: the fake host's fakes, set up and read back through
/// `enclave:fake-host/control`.
///
/// One fake host runs a whole test binary, so making a `Recorder` starts the tenant over: no
/// key, no tasks, nothing recorded. It holds the runtime to its rule for task ids (an id is an
/// idempotency key, refused with different input until its record is forgotten) and, holding a
/// wallet key, answers `enclave:signer` as the runtime does.
pub struct Recorder(());

impl Default for Recorder {
    fn default() -> Self {
        control::reset();
        Recorder(())
    }
}

impl Recorder {
    /// A runtime holding [wallet]'s key.
    pub fn holding(wallet: &TestWallet) -> Self {
        let recorder = Self::default();
        recorder.hold(wallet);
        recorder
    }

    /// Hold [wallet]'s key from now on, as a DKG leaves the runtime.
    pub fn hold(&self, wallet: &TestWallet) {
        let key = &wallet.key;
        control::hold(
            &key.key_package.to_json(),
            &key.public_key_package.to_json(),
            &key.wallet.serialize(),
            &key.dealt,
        );
    }

    /// Everything the policy asked to have enqueued, as `(id, payload, run_at_ms, interval_ms)`.
    pub fn enqueued(&self) -> Vec<(String, Vec<u8>, u64, Option<u64>)> {
        control::enqueued()
            .into_iter()
            .map(|t| (t.id, t.payload, t.run_at, t.interval_ms))
            .collect()
    }

    pub fn woken(&self) -> Vec<(String, Option<String>)> {
        control::woken()
    }

    pub fn cancelled(&self) -> Vec<String> {
        control::cancelled()
    }
}
