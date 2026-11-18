//! The router, over real frames: routing, the five-byte frames, and the `grpc-status` trailer a
//! client actually reads a failure from.
//!
//! Driven through `route` with real framed bodies rather than handlers directly: only the wire
//! shows what a client actually reads.

mod common;

use policy::grpc::Code;
use policy::session::proto;
use policy::wallet_proto::{GetServerInfoRequest, GetServerInfoResponse};
use policy::Cosigner;

use threshold::keys::KeyPackage;

use common::wire::{block_on, collect, request, service};

/// A `SignOpen` from the wallet that owns [kp_user]. No commitments: the wallet has no share to
/// hedge a nonce with until the cosigner's first answer brings the half it dealt.
fn sign_open(kp_user: &KeyPackage) -> proto::SignClientMsg {
    proto::SignClientMsg {
        session_id: "s1".into(),
        seq: 0,
        body: Some(proto::sign_client_msg::Body::Open(proto::SignOpen {
            message_to_sign: vec![0x42; 32],
            full_transaction: Vec::new(),
            script_path_spend: true,
            identifier: kp_user.identifier.serialize().to_vec(),
        })),
    }
}

/// A cosigner whose runtime holds a wallet's key, and that wallet.
fn seeded() -> Option<(Cosigner, common::TestWallet)> {
    let store = common::try_store()?;
    let wallet = common::wallet();
    let cosigner = common::open_holding(&store, &wallet);
    Some((cosigner.into_inner().unwrap(), wallet))
}

/// A ceremony that is cut off mid-round ends as a cancellation, not as a success.
///
/// The client half-closes after opening, so the handler parks waiting for a share that never comes.
/// The trailers are the only place that difference can be said, and reporting OK here would tell a
/// client its round completed.
#[test]
fn a_stream_that_ends_mid_ceremony_is_a_cancellation() {
    let Some((cosigner, wallet)) = seeded() else { return };
    let answer = collect::<proto::SignServerMsg>(block_on(
        service(cosigner).route(request("Sign", &[sign_open(&wallet.user)])),
    ));
    assert_eq!(answer.code, Code::Cancelled as u32, "got {}", answer.message);
    assert_eq!(answer.messages.len(), 1, "the commitments round went out before the client vanished");
}

/// An unknown method is a gRPC status and not an HTTP one — a client reading
/// only the head would otherwise see a perfectly successful call.
#[test]
fn an_unknown_method_is_unimplemented_in_the_trailers() {
    let Some((cosigner, _)) = seeded() else { return };
    let resp = block_on(
        service(cosigner).route(request::<GetServerInfoRequest>("Nope", &[])),
    );
    assert_eq!(resp.status(), 200, "gRPC reports failure in the trailers");
    assert_eq!(collect::<GetServerInfoResponse>(resp).code, Code::Unimplemented as u32);
}

#[test]
fn get_server_info_answers_a_single_framed_message() {
    let Some((cosigner, _)) = seeded() else { return };
    let answer = collect::<GetServerInfoResponse>(block_on(service(cosigner).route(request(
        "GetServerInfo",
        &[GetServerInfoRequest::default()],
    ))));
    assert_eq!(answer.code, Code::Ok as u32, "got {}", answer.message);
    assert_eq!(answer.messages.len(), 1);
    assert_eq!(answer.messages[0].bitcoin_network, "regtest");
}
