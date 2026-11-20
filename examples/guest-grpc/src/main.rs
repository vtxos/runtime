//! A gRPC service with a bidirectional streaming method, in a Wasm guest.
//!
//! ```text
//!   client ──frame──▶ runtime ──message──▶ ┌───────┐
//!   client ◀─frame─── runtime ◀─message─── │ guest │
//!                                          └───────┘
//! ```
//!
//! The runtime ends gRPC: it reads the frames, hands this guest each message's protobuf over
//! `enclave:rpc/service`'s request stream, frames whatever comes back on the reply stream, and
//! turns the status into trailers. What is left here is the service.
//!
//! # What this is not
//!
//! There is no cryptography here. The messages are shaped like signing-session traffic so the
//! transport and the authorization can be settled before a key depends on either, and `Sign`
//! echoes rather than signs.

use prost::Message as _;

mod bindings {
    wit_bindgen::generate!({ path: "../../wit/rpc", world: "enclave:rpc/server" });
}

use bindings::exports::enclave::rpc::service::{Guest, Status};
use bindings::{wit_future, wit_stream};
use wit_bindgen::{FutureReader, StreamReader, StreamWriter};

// --- the wire format, mirroring proto/enclave/cosign/v1/session.proto -------

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum Kind {
    Unspecified = 0,
    Hello = 1,
    Round = 2,
    Finish = 3,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ClientMsg {
    #[prost(string, tag = "1")]
    pub session_id: String,
    #[prost(uint64, tag = "2")]
    pub seq: u64,
    #[prost(enumeration = "Kind", tag = "3")]
    pub kind: i32,
    #[prost(bytes = "vec", tag = "4")]
    pub payload: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ServerMsg {
    #[prost(string, tag = "1")]
    pub session_id: String,
    #[prost(uint64, tag = "2")]
    pub seq: u64,
    #[prost(enumeration = "Kind", tag = "3")]
    pub kind: i32,
    #[prost(bytes = "vec", tag = "4")]
    pub payload: Vec<u8>,
}

// --- gRPC status codes this service uses ------------------------------------

const GRPC_INVALID_ARGUMENT: u32 = 3;
const GRPC_PERMISSION_DENIED: u32 = 7;
const GRPC_UNIMPLEMENTED: u32 = 12;
const GRPC_INTERNAL: u32 = 13;

fn status(code: u32, message: impl Into<String>) -> Status {
    Status {
        code,
        message: message.into(),
    }
}

/// What the guest does with each message it receives.
///
/// The variants past `Echo` exist to be tested against, the way `/hang` and `/trickle` do in
/// `examples/guest-http`: they are behaviours a host cannot provoke from outside, so the guest has
/// to offer them deliberately.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Answer every message as it arrives. The real shape.
    Echo,
    /// Answer once, then end with a non-zero status, so a test can read a failure out of the
    /// trailers rather than out of the head.
    Refuse,
    /// Answer once, then burn CPU forever. The runtime's epoch watchdog must still stop this,
    /// which is what keeps "a stream may run long" from becoming "anything may run forever".
    Spin,
    /// Write 64 messages without ever reading, so a client that does not drain finds out that the
    /// guest waits rather than buffering.
    Firehose,
}

/// One answer for one message.
fn answer(msg: ClientMsg) -> ServerMsg {
    ServerMsg {
        session_id: msg.session_id,
        seq: msg.seq,
        kind: match msg.kind {
            k if k == Kind::Hello as i32 => Kind::Hello as i32,
            k if k == Kind::Finish as i32 => Kind::Finish as i32,
            _ => Kind::Round as i32,
        },
        // Echoed, not signed. See the `.proto` beside this file.
        payload: msg.payload,
    }
}

async fn serve(
    method: &str,
    requests: &mut StreamReader<Vec<u8>>,
    replies: &mut StreamWriter<Vec<u8>>,
) -> Result<(), Status> {
    let mode = match method {
        "/enclave.cosign.v1.SigningSession/Sign" => Mode::Echo,
        "/enclave.cosign.v1.SigningSession/Refuse" => Mode::Refuse,
        "/enclave.cosign.v1.SigningSession/Spin" => Mode::Spin,
        "/enclave.cosign.v1.SigningSession/Firehose" => Mode::Firehose,
        _ => return Err(status(GRPC_UNIMPLEMENTED, "no such method")),
    };

    if mode == Mode::Firehose {
        for seq in 0..64 {
            let msg = ServerMsg {
                session_id: "firehose".into(),
                seq,
                kind: Kind::Round as i32,
                payload: vec![0xab; 1024],
            };
            // Each write waits for the runtime to take it, and the runtime takes one only once
            // the client has room: nothing regulates this but whether anybody is draining it.
            if replies.write_one(msg.encode_to_vec()).await.is_some() {
                return Ok(());
            }
        }
        return Ok(());
    }

    while let Some(message) = requests.next().await {
        let msg = ClientMsg::decode(message.as_slice())
            .map_err(|e| status(GRPC_INVALID_ARGUMENT, format!("undecodable ClientMsg: {e}")))?;
        replies.write_one(answer(msg).encode_to_vec()).await;
        match mode {
            Mode::Refuse => {
                return Err(status(
                    GRPC_PERMISSION_DENIED,
                    "this session is not authorized to sign",
                ))
            }
            Mode::Spin => {
                // No await point, no I/O, forever. Only the epoch can end this.
                #[allow(clippy::empty_loop)]
                loop {
                    std::hint::spin_loop();
                }
            }
            Mode::Echo | Mode::Firehose => {}
        }
    }
    // The client half-closed between messages: an orderly end.
    Ok(())
}

struct Service;

impl Guest for Service {
    async fn call(
        method: String,
        mut requests: StreamReader<Vec<u8>>,
    ) -> (StreamReader<Vec<u8>>, FutureReader<Result<(), Status>>) {
        let (mut replies, out) = wit_stream::new::<Vec<u8>>();
        let (done, status_out) = wit_future::new::<Result<(), Status>>(|| {
            Err(status(GRPC_INTERNAL, "the call ended without a status"))
        });
        // Returned at once, so the runtime can send the head; the conversation runs after.
        wit_bindgen::spawn(async move {
            let outcome = serve(&method, &mut requests, &mut replies).await;
            // Replies first, then the status: the runtime sends trailers once both are in.
            drop(replies);
            let _ = done.write(outcome).await;
        });
        (out, status_out)
    }
}

bindings::export!(Service with_types_in bindings);

fn main() {}
