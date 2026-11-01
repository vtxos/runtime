// Shared test helpers: each integration binary compiles this module and uses only part of it.
#![allow(dead_code)]

//! Shared setup for the integration tests. Builds `Store` against the local dev stack.
//!
//! Persistence is an in-process SQLite store, so there is no external dependency to reach and each
//! `try_store` call gets its own isolated database. The wallet key is the runtime's, so a test that
//! signs plays the runtime too: a [`Recorder`] holding a [`TestWallet`]'s key does what
//! `enclave:signer` does, over `threshold`. It is a stand-in, not the runtime's code: a plain 2-of-2
//! with both polynomials random, because the guest sees only the public package, the dealt share and
//! the rounds, and how the runtime derives its half is the runtime's to test.

use cosigner::Cosigner;
use std::collections::BTreeMap;
use std::sync::Arc;

use rand::rngs::OsRng;

use cosigner::host::{Commitment, Host, SigningHandle, WalletKey};
use cosigner::sign::WalletHalf;
use cosigner::store::Store;

use threshold::commitment::SigningPackage;
use threshold::dkg;
use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};
use threshold::nonce::{self, SigningCommitments, SigningNonce};
use threshold::random::mod_n_random;
use threshold::scalar::{scalar_from_bytes, scalar_to_bytes};
use threshold::signing::{self, SignatureShare};

use std::sync::Mutex;

pub fn try_store() -> Option<Arc<Store>> {
    // `:memory:` — a fresh, private store per caller. Tests no longer share one namespace, so a
    // leftover key from a failed run can't leak into the next one.
    Some(Arc::new(
        Store::open(":memory:", 1800).expect("open in-memory store"),
    ))
}

/// A wallet that has run its DKG with the runtime: the app's key package, and the cosigner's half
/// the runtime keeps.
pub struct TestWallet {
    pub user: KeyPackage,
    pub key: RuntimeKey,
}

impl TestWallet {
    /// The group key, compressed, hex — what the cosigner's seal is filed under in these tests.
    pub fn group_key(&self) -> String {
        hex::encode(self.key.group_key())
    }

    /// The share the cosigner dealt this wallet, as the runtime recomputes it.
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

/// A round the runtime is halfway through: one nonce per message, until `finish`.
pub struct Round {
    key: RuntimeKey,
    rounds: Vec<(Vec<u8>, SigningNonce)>,
}

impl Round {
    fn begin(key: RuntimeKey, messages: &[Vec<u8>]) -> (Self, Vec<Commitment>) {
        let rounds: Vec<_> = messages
            .iter()
            .map(|m| (m.clone(), nonce::new_nonce(&mut OsRng, &key.key_package.secret_share)))
            .collect();
        let commitments = rounds
            .iter()
            .map(|(_, n)| Commitment {
                hiding: threshold::point::serialize_compressed(&n.commitments.hiding).to_vec(),
                binding: threshold::point::serialize_compressed(&n.commitments.binding).to_vec(),
            })
            .collect();
        (Self { key, rounds }, commitments)
    }

    fn finish(self, halves: &[WalletHalf]) -> Result<Vec<Vec<u8>>, String> {
        if halves.len() != self.rounds.len() {
            return Err(format!("the wallet answered {} of {} messages", halves.len(), self.rounds.len()));
        }
        let ours = self.key.key_package.identifier.clone();
        let theirs = self.key.wallet.clone();
        self.rounds
            .iter()
            .zip(halves)
            .enumerate()
            .map(|(i, ((message, nonce), half))| {
                let at = |e: String| format!("message {i}: {e}");
                let commitments = BTreeMap::from([
                    (ours.clone(), nonce.commitments.clone()),
                    (
                        theirs.clone(),
                        SigningCommitments::from_bytes(&half.hiding, &half.binding)
                            .map_err(|e| at(e.to_string()))?,
                    ),
                ]);
                let share: [u8; 32] =
                    half.share.as_slice().try_into().map_err(|_| at("share must be 32 bytes".into()))?;
                let share = scalar_from_bytes(&share).map_err(|e| at(e.to_string()))?;
                let package = SigningPackage::new(commitments, message.clone());
                let mine = signing::sign(&package, nonce, &self.key.key_package)
                    .map_err(|e| at(format!("frost sign: {e}")))?;
                let shares =
                    BTreeMap::from([(ours.clone(), mine), (theirs.clone(), SignatureShare { s: share })]);
                signing::aggregate(&package, &shares, &self.key.public_key_package)
                    .map(|s| s.serialize().to_vec())
                    .map_err(|e| at(format!("frost aggregate: {e}")))
            })
            .collect()
    }
}

/// Open the cosigner this process serves, with no runtime around it: no wallet key, no queue.
pub fn open_cosigner(store: &Arc<Store>, group_key: &str) -> Mutex<Cosigner> {
    let detached = std::sync::Arc::new(cosigner::host::Detached);
    let cosigner = Cosigner::open(store.clone(), group_key.to_string(), detached);
    Mutex::new(cosigner.expect("open cosigner"))
}

/// Open it inside a runtime that holds [wallet]'s key.
pub fn open_holding(store: &Arc<Store>, wallet: &TestWallet) -> Mutex<Cosigner> {
    let host = Arc::new(Recorder::holding(wallet));
    let cosigner = Cosigner::open(store.clone(), wallet.group_key(), host);
    Mutex::new(cosigner.expect("open cosigner"))
}

/// The wallet's half of a signing session over [messages]: a fresh nonce for each, then a share
/// over both commitments. What `answerRound` does in the app.
pub fn wallet_answers(
    kp_user: &KeyPackage,
    messages: &[Vec<u8>],
    cosigner_commitments: &[cosigner::types::Commitment],
) -> Vec<cosigner::sign::WalletHalf> {
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
            cosigner::sign::WalletHalf {
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

/// Driving `Session::route` with real framed bodies, as the runtime delivers them.
///
/// A body from [request] is written whole before the handler runs, so a test can open a stream and
/// read what the cosigner says first — but cannot answer it; a stream opened and left is cut off
/// mid-ceremony, and ends `Cancelled`. A [Wire] is fed as the test goes, for a ceremony whose
/// rounds depend on the cosigner's.
pub mod wire {
    use std::future::Future;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    use bytes::Bytes;
    use http_body_util::BodyExt;

    use cosigner::grpc::framing::{frame, Deframer};
    use cosigner::session::Session;
    use cosigner::wallet_proto::GetServerInfoResponse;
    use cosigner::Cosigner;
    use wstd::http::{Body, Request, Response};

    /// Drive a future to completion on this thread.
    ///
    /// Every body here is already in memory, so nothing genuinely parks and a busy poll is enough.
    /// The cap is what turns "this future never finishes" into a failed test rather than a hung
    /// one — which matters, because a duplex that stops making progress is exactly the bug these
    /// tests would catch.
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

    /// A gRPC request carrying `messages`, addressed at `method`, as the runtime would deliver it.
    pub fn request<M: prost::Message>(method: &str, messages: &[M]) -> Request<Body> {
        let mut buf = Vec::new();
        for message in messages {
            buf.extend_from_slice(&frame(&message.encode_to_vec()));
        }
        Request::builder()
            .method("POST")
            .uri(format!("http://cosigner/cosigner.v1.Cosigner/{method}"))
            .header("content-type", "application/grpc+proto")
            .body(Body::from_http_body(
                http_body_util::Full::new(Bytes::from(buf))
                    .map_err(|e: std::convert::Infallible| -> wstd::http::Error { match e {} }),
            ))
            .expect("request is well formed")
    }

    /// What came back: the decoded messages, and the status a client reads from the trailers.
    pub struct Answer<M> {
        pub messages: Vec<M>,
        pub code: u32,
        pub message: String,
    }

    pub fn collect<M: prost::Message + Default>(resp: Response<Body>) -> Answer<M> {
        let collected =
            block_on(resp.into_body().into_boxed_body().collect()).expect("collect body");
        let trailers = collected.trailers().cloned().unwrap_or_default();
        let code = trailers
            .get("grpc-status")
            .expect("every gRPC response carries a grpc-status trailer")
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let message = trailers
            .get("grpc-message")
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();

        let mut deframer = Deframer::default();
        deframer.push(&collected.to_bytes());
        let mut messages = Vec::new();
        while let Some(bytes) = deframer.next().expect("well-framed response") {
            messages.push(M::decode(bytes).expect("decodable response"));
        }
        Answer { messages, code, message }
    }

    pub fn service(cosigner: Cosigner) -> Session {
        Session::new(
            Arc::new(Mutex::new(cosigner)),
            GetServerInfoResponse { bitcoin_network: "regtest".into() },
        )
    }

    /// The client's end of a stream: frames handed over as the test decides them. Empty is
    /// `Pending`, as a connection with nothing in flight is — which is what makes a stream a
    /// conversation rather than a batch, and lets a client answer what the cosigner said — until
    /// the client ends its side.
    #[derive(Clone, Default)]
    pub struct Wire(Arc<Mutex<(std::collections::VecDeque<Bytes>, bool)>>);

    impl Wire {
        pub fn send<M: prost::Message>(&self, message: &M) {
            self.0.lock().unwrap().0.push_back(frame(&message.encode_to_vec()));
        }

        /// The client's side, ended: it has nothing more to say.
        pub fn close(&self) {
            self.0.lock().unwrap().1 = true;
        }
    }

    impl http_body::Body for Wire {
        type Data = Bytes;
        type Error = wstd::http::Error;

        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
            let mut wire = self.0.lock().unwrap();
            match wire.0.pop_front() {
                Some(bytes) => Poll::Ready(Some(Ok(http_body::Frame::data(bytes)))),
                None if wire.1 => Poll::Ready(None),
                None => Poll::Pending,
            }
        }
    }

    /// The cosigner's end of a stream, read one message at a time.
    pub struct Reply {
        body: http_body_util::combinators::UnsyncBoxBody<Bytes, wstd::http::Error>,
        deframer: Deframer,
    }

    impl Reply {
        /// Open the stream [method], with [wire] as its request body.
        pub fn open(cosigner: Cosigner, method: &str, wire: &Wire) -> Self {
            let request = Request::builder()
                .method("POST")
                .uri(format!("http://cosigner/cosigner.v1.Cosigner/{method}"))
                .header("content-type", "application/grpc+proto")
                .body(Body::from_http_body(wire.clone()))
                .expect("request is well formed");
            let response = block_on(service(cosigner).route(request));
            Self { body: response.into_body().into_boxed_body(), deframer: Deframer::default() }
        }

        /// The cosigner's next message. It has been sent everything it asked for, so it has
        /// something to say: waiting is a test that forgot to answer, and trailers are a stream
        /// that failed.
        pub fn next<M: prost::Message + Default>(&mut self) -> M {
            use http_body::Body as _;
            let mut cx = Context::from_waker(Waker::noop());
            loop {
                if let Some(bytes) = self.deframer.next().expect("well framed") {
                    return M::decode(bytes).expect("decodable");
                }
                match std::pin::Pin::new(&mut self.body).poll_frame(&mut cx) {
                    Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                        Ok(data) => self.deframer.push(&data),
                        Err(frame) => panic!("the stream ended early: {:?}", frame.trailers_ref()),
                    },
                    Poll::Ready(Some(Err(e))) => panic!("the stream failed: {e}"),
                    Poll::Ready(None) => panic!("the stream ended before its next message"),
                    Poll::Pending => panic!("the cosigner is waiting for a message never sent"),
                }
            }
        }

        /// How the stream ended, as a client reads it from the trailers: status code and message.
        pub fn finish(mut self) -> (String, String) {
            use http_body::Body as _;
            let mut cx = Context::from_waker(Waker::noop());
            let Poll::Ready(Some(Ok(frame))) =
                std::pin::Pin::new(&mut self.body).poll_frame(&mut cx)
            else {
                panic!("expected the trailers after the last message");
            };
            let trailers = frame.into_trailers().expect("trailers, and nothing more said");
            let read =
                |name: &str| trailers.get(name).map_or("", |v| v.to_str().unwrap()).to_string();
            (read("grpc-status"), read("grpc-message"))
        }
    }
}

/// Records what the cosigner asked of the runtime, and holds it to the runtime's rule for task ids:
/// an id is an idempotency key, refused with different input until its record is forgotten. When
/// it holds a wallet key it answers `enclave:signer` as the runtime does.
#[derive(Default)]
pub struct Recorder {
    pub enqueued: Mutex<Vec<(String, Vec<u8>, u64, Option<u64>)>>,
    live: Mutex<std::collections::HashMap<String, (Vec<u8>, u64, bool)>>,
    pub cancelled: Mutex<Vec<String>>,
    pub woken: Mutex<Vec<(String, Option<String>)>>,
    registered: Mutex<Vec<String>>,
    key: Mutex<Option<RuntimeKey>>,
}

impl Host for Recorder {
    fn enqueue(
        &self,
        id: &str,
        payload: &[u8],
        run_at_ms: u64,
        interval_ms: Option<u64>,
    ) -> Result<(), String> {
        let mut live = self.live.lock().unwrap();
        if let Some((old, old_run_at, _)) = live.get(id) {
            if old != payload || *old_run_at != run_at_ms {
                return Err("task id already used with different input".into());
            }
            return Ok(());
        }
        live.insert(id.into(), (payload.to_vec(), run_at_ms, false));
        self.enqueued
            .lock()
            .unwrap()
            .push((id.into(), payload.to_vec(), run_at_ms, interval_ms));
        Ok(())
    }
    fn status(&self, _: &str) -> Result<String, String> {
        Ok("{}".into())
    }
    fn cancel(&self, id: &str) -> Result<(), String> {
        if let Some(record) = self.live.lock().unwrap().get_mut(id) {
            record.2 = true;
        }
        self.cancelled.lock().unwrap().push(id.into());
        Ok(())
    }
    fn forget(&self, id: &str) -> Result<(), String> {
        let mut live = self.live.lock().unwrap();
        match live.get(id) {
            Some((_, _, true)) => {
                live.remove(id);
                Ok(())
            }
            Some(_) => Err("task is still active".into()),
            None => Err("no such task".into()),
        }
    }
    fn register_device(&self, token: &str) -> Result<(), String> {
        self.registered.lock().unwrap().push(token.into());
        Ok(())
    }
    fn forget_device(&self, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn devices(&self) -> Result<u32, String> {
        Ok(self.registered.lock().unwrap().len() as u32)
    }
    fn wake(&self, category: &str, reference: Option<&str>) -> Result<(), String> {
        self.woken
            .lock()
            .unwrap()
            .push((category.into(), reference.map(Into::into)));
        Ok(())
    }
    fn wallet_key(&self) -> Result<WalletKey, String> {
        let key = self.key()?;
        Ok(WalletKey {
            group_key: key.group_key().to_vec(),
            public_key_package: key.public_key_package.to_json(),
            signer_identifier: key.key_package.identifier.serialize().to_vec(),
            wallet_identifier: key.wallet.serialize().to_vec(),
        })
    }
    fn dealt_share(&self, identifier: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.key()?;
        if identifier != key.wallet.serialize() {
            return Err("not this wallet's identifier".into());
        }
        Ok(key.dealt)
    }
    fn signing_begin(&self, messages: &[Vec<u8>]) -> Result<(SigningHandle, Vec<Commitment>), String> {
        let (round, commitments) = Round::begin(self.key()?, messages);
        Ok((SigningHandle(Box::new(round)), commitments))
    }
    fn signing_finish(&self, signing: SigningHandle, rounds: &[WalletHalf]) -> Result<Vec<Vec<u8>>, String> {
        signing.0.downcast::<Round>().map_err(|_| "not our round")?.finish(rounds)
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
        *self.key.lock().unwrap() = Some(wallet.key.clone());
    }

    fn key(&self) -> Result<RuntimeKey, String> {
        self.key.lock().unwrap().clone().ok_or_else(|| "this tenant has no wallet key yet".into())
    }

    /// Everything the cosigner asked to have enqueued, as `(id, payload, run_at_ms, interval_ms)`.
    pub fn enqueued(&self) -> Vec<(String, Vec<u8>, u64, Option<u64>)> {
        self.enqueued.lock().unwrap().clone()
    }

    pub fn woken(&self) -> Vec<(String, Option<String>)> {
        self.woken.lock().unwrap().clone()
    }

    pub fn cancelled(&self) -> Vec<String> {
        self.cancelled.lock().unwrap().clone()
    }
}
