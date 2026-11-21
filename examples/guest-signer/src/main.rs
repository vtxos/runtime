//! A guest that signs: the smallest use of `enclave:signer`.
//!
//! The wallet's key is two shares, one on the phone and one the runtime keeps. This guest never
//! sees either. It asks the runtime to begin a round, relays what the phone needs to answer it,
//! and asks the runtime to finish:
//!
//! ```text
//!   phone ── message ─────────────────────▶ guest ── begin ──▶ runtime
//!   phone ◀─ identifier, hiding, binding ── guest
//!   phone ── hiding, binding, share ──────▶ guest ── finish ─▶ runtime
//!   phone ◀─ signature ──────────────────── guest
//! ```
//!
//! Each arrow is one message on the stream, and each message is the bytes themselves: no
//! protobuf, no lengths. The runtime ends gRPC and does not read what a message holds.
//!
//! # What this is not
//!
//! A policy. It signs whatever it is sent. A real guest decides here, between reading the message
//! and calling `begin`, whether the message is one it will sign.

use enclave_wit::enclave::signer::wallet;
use enclave_wit::exports::enclave::rpc::service::{Guest, Status};
use enclave_wit::{wit_future, wit_stream};
use wit_bindgen::{FutureReader, StreamReader, StreamWriter};

const SIGN: &str = "/enclave.signer.v1.Signer/Sign";

const GRPC_FAILED_PRECONDITION: u32 = 9;
const GRPC_UNIMPLEMENTED: u32 = 12;
const GRPC_INTERNAL: u32 = 13;

async fn read(requests: &mut StreamReader<Vec<u8>>) -> Result<Vec<u8>, String> {
    requests.next().await.ok_or_else(|| "the stream ended before the round did".to_string())
}

async fn sign(
    requests: &mut StreamReader<Vec<u8>>,
    replies: &mut StreamWriter<Vec<u8>>,
) -> Result<(), String> {
    let message = read(requests).await?;
    let (signing, commitments) = wallet::Signing::begin(&[message])?;
    let ours = commitments.into_iter().next().ok_or("the runtime made no commitment")?;
    for part in [wallet::wallet_key()?.signer_identifier, ours.hiding, ours.binding] {
        replies.write_one(part).await;
    }

    let round = wallet::WalletRound {
        hiding: read(requests).await?,
        binding: read(requests).await?,
        share: read(requests).await?,
    };
    let signature =
        signing.finish(&[round])?.into_iter().next().ok_or("the runtime made no signature")?;
    replies.write_one(signature).await;
    Ok(())
}

struct Signer;

impl Guest for Signer {
    async fn call(
        method: String,
        mut requests: StreamReader<Vec<u8>>,
    ) -> (StreamReader<Vec<u8>>, FutureReader<Result<(), Status>>) {
        let (mut replies, out) = wit_stream::new::<Vec<u8>>();
        let (done, status) = wit_future::new::<Result<(), Status>>(|| {
            Err(Status { code: GRPC_INTERNAL, message: "the call ended without a status".into() })
        });
        // Returned at once, so the runtime can send the head; the round runs after.
        wit_bindgen::spawn(async move {
            let outcome = if method == SIGN {
                sign(&mut requests, &mut replies)
                    .await
                    .map_err(|message| Status { code: GRPC_FAILED_PRECONDITION, message })
            } else {
                Err(Status { code: GRPC_UNIMPLEMENTED, message: "no such method".into() })
            };
            // Replies first, then the status: the runtime sends trailers once both are in.
            drop(replies);
            let _ = done.write(outcome).await;
        });
        (out, status)
    }
}

/// The world's other export. This guest arms no task, so the runtime never calls it.
impl enclave_wit::Guest for Signer {
    fn run_task(_task_id: String, _payload: Vec<u8>) -> Result<Vec<u8>, String> {
        Err("this guest arms no tasks".into())
    }
}

enclave_wit::export!(Signer);

fn main() {}
