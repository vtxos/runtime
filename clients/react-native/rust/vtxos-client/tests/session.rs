//! [`Session`]: calls as bytes, against a guest this crate knows nothing about.
//!
//! The guest is `examples/guest-grpc`, an echo with a wire of its own and nothing of the wallet's.
//! That is the point: the session reaches it with no change, so it reaches any policy. Its
//! messages are spelled out here by hand, as an app would spell out its own.
//!
//! ```sh
//! scripts/build-guest.sh grpc
//! cargo test -p vtxos-client --test session -- --ignored --test-threads=1
//! ```

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{harness, pins};
use enclave_runtime::testing::Enclave as Harness;
use prost::Message as _;
use vtxos_client::net::{Enclave, Session};
use vtxos_client::Error;

const ECHO: &str = "/enclave.cosign.v1.SigningSession/Sign";
const REFUSE: &str = "/enclave.cosign.v1.SigningSession/Refuse";

/// The echo guest's one message shape, both ways.
#[derive(Clone, PartialEq, prost::Message)]
struct Msg {
    #[prost(string, tag = "1")]
    session_id: String,
    #[prost(uint64, tag = "2")]
    seq: u64,
    #[prost(int32, tag = "3")]
    kind: i32,
    #[prost(bytes = "vec", tag = "4")]
    payload: Vec<u8>,
}

fn msg(seq: u64, payload: &[u8]) -> Vec<u8> {
    Msg {
        session_id: "s".into(),
        seq,
        kind: 2,
        payload: payload.to_vec(),
    }
    .encode_to_vec()
}

fn decode(bytes: &[u8]) -> Msg {
    Msg::decode(bytes).expect("the echo guest's message")
}

/// The runtime in process, serving the echo guest, and a session a fresh wallet opened on it.
async fn session() -> (Harness, Arc<Session>) {
    let h = harness("grpc").await;
    let enclave = Arc::new(Enclave::new(&h.url(), &pins(&h)).unwrap());
    let prf = [0x42; 32];
    let record = enclave.register(&prf).await.expect("registered");
    let client = record.open(&prf).expect("the passkey opens its wallet");
    (h, Arc::new(Session::new(enclave, client)))
}

/// One message each way, messages both ways, and a call the guest ends with an error: each as the
/// guest sent it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the echo guest: scripts/build-guest.sh grpc"]
async fn a_session_calls_a_guest_it_knows_nothing_about() {
    let (_h, session) = session().await;

    // One message each way.
    let reply = session.call(ECHO, &msg(1, b"hello")).await.expect("call");
    assert_eq!(decode(&reply).payload, b"hello");
    assert_eq!(decode(&reply).seq, 1);

    // Both ways, in order, each answered before the next is sent.
    let stream = session.stream(ECHO).await.expect("stream");
    for seq in 1..=3u64 {
        stream.send(&msg(seq, &[seq as u8; 4])).await.expect("send");
        let reply = decode(&stream.next().await.expect("reply").expect("a message"));
        assert_eq!((reply.seq, reply.payload), (seq, vec![seq as u8; 4]));
    }
    stream.finish();
    assert_eq!(stream.next().await.expect("an orderly end"), None);
    // Ended, and it stays ended.
    assert_eq!(stream.next().await.expect("still ended"), None);
    assert!(stream.send(&msg(4, b"late")).await.is_err());

    // A reply, and then the guest's own status, with its code and its words.
    let stream = session.stream(REFUSE).await.expect("stream");
    stream.send(&msg(1, b"please")).await.expect("send");
    assert_eq!(
        decode(&stream.next().await.unwrap().unwrap()).payload,
        b"please"
    );
    match stream.next().await {
        Err(Error::Status { code: 7, message }) => {
            assert!(message.contains("not authorized"), "{message}")
        }
        other => panic!("expected the guest's refusal, got {other:?}"),
    }

    // A method the guest does not have is the guest's to refuse, and the session is usable after.
    match session.call("/nobody.Home/Knock", b"").await {
        Err(Error::Status { code: 12, .. }) => {}
        other => panic!("expected UNIMPLEMENTED, got {other:?}"),
    }
    assert_eq!(
        decode(&session.call(ECHO, &msg(9, b"again")).await.unwrap()).seq,
        9
    );

    // A method is a path.
    assert!(matches!(
        session.call("no-slash", b"").await,
        Err(Error::Protocol(_))
    ));
}

/// One call at a time: a second waits for the first to end, and a cancelled one gives its turn
/// back.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the echo guest: scripts/build-guest.sh grpc"]
async fn calls_take_turns_and_a_cancelled_one_gives_its_back() {
    let (_h, session) = session().await;

    let open = session.stream(ECHO).await.expect("stream");
    open.send(&msg(1, b"first")).await.unwrap();
    assert_eq!(decode(&open.next().await.unwrap().unwrap()).seq, 1);

    // While that stream is open, another call does not start.
    let waiting = {
        let session = session.clone();
        tokio::spawn(async move { session.call(ECHO, &msg(2, b"second")).await })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !waiting.is_finished(),
        "a second call ran while the first was open"
    );

    // It ends, and the second one runs.
    open.finish();
    assert_eq!(open.next().await.unwrap(), None);
    let reply = tokio::time::timeout(Duration::from_secs(20), waiting)
        .await
        .expect("the second call got its turn")
        .unwrap()
        .expect("call");
    assert_eq!(decode(&reply).seq, 2);

    // A stream abandoned mid-way gives its turn back too, here and in the enclave.
    let abandoned = session.stream(ECHO).await.expect("stream");
    abandoned.send(&msg(3, b"third")).await.unwrap();
    abandoned.cancel();
    assert!(abandoned.next().await.is_err());
    let reply = tokio::time::timeout(
        Duration::from_secs(20),
        session.call(ECHO, &msg(4, b"fourth")),
    )
    .await
    .expect("the turn came back after a cancel")
    .expect("call");
    assert_eq!(decode(&reply).seq, 4);
}
