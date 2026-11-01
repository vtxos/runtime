//! Ceremonies as bidirectional gRPC sessions.
//!
//! The unary API makes a ceremony a sequence of requests, so the server has to park state between
//! them: a FROST nonce for signing, round-1 and round-2 secrets for DKG. Under a per-request
//! runtime there is no "between" — that state would have to be persisted, and a reused nonce leaks
//! a secret share.
//!
//! One stream removes the problem rather than managing it. The ceremony is one session, its secrets
//! live on this handler's stack, and a stream that dies takes them with it. A reconnect is a new
//! session with new secrets, so there is nothing to replay and no ledger to keep.
//!
//! Authentication is once, at open, for the session — matching the runtime this is heading for,
//! where one passkey assertion authorizes one interaction and the messages inside it are not
//! individually approved. See `cosign_session.proto` for why there is no per-message approval field.
//!
//! # Why these are plain `async fn`s
//!
//! They were `async_stream::try_stream!` blocks behind a tonic service trait. tonic does not build
//! for `wasm32-wasip2` at all, so the guest port replaced it with [`crate::grpc`] — 250 lines that
//! do the framing, the trailers and the duplex. What did *not* change is these bodies: `yield x`
//! became `duplex.send(x)`, `inbound.next().await` became `duplex.recv().await`, and the ceremonies
//! are otherwise the same code. That was the test of whether the transport had been kept at arm's
//! length, and it passed.

use std::sync::{Arc, Mutex, MutexGuard};

use wstd::http::{Body, Request, Response};

use crate::cosigner::Cosigner;
use crate::renew::{DelegateRenew, DelegateStream};
use crate::sign::SigningSession;
use crate::grpc::{self, Duplex, HasBody, SessionBody, Status};
use crate::wallet_proto as wp;

pub mod proto {
    #![allow(clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/cosigner.v1.rs"));
}

use proto::{
    sign_client_msg, sign_server_msg, SignClientMsg, SignCommitments, SignComplete, SignServerMsg,
};

/// Every RPC this service answers, under the package and service names in `cosign_session.proto`.
const PREFIX: &str = "/cosigner.v1.Cosigner/";

pub struct Session {
    cosigner: Arc<Mutex<Cosigner>>,
    server_info: wp::GetServerInfoResponse,
}

impl Session {
    pub fn new(cosigner: Arc<Mutex<Cosigner>>, server_info: wp::GetServerInfoResponse) -> Self {
        Self {
            cosigner,
            server_info,
        }
    }

    /// One request, routed.
    ///
    /// This is what the generated service trait was for. Matching `:path` by hand is a table of
    /// fifteen names — clearer than a code generator, and the only part of tonic still in use once
    /// the framing and the status had their own modules.
    pub async fn route(&self, req: Request<Body>) -> Response<Body> {
        // Authentication is the runtime's: it lets a request through only once a passkey approved
        // it. Run it without a gate and anyone can call this.
        let path = req.uri().path().to_string();
        let Some(method) = path.strip_prefix(PREFIX) else {
            eprintln!("request to unknown service: {path}");
            return grpc::failed(Status::unimplemented(format!("no such service: {path}")));
        };
        println!("{method}: request");

        // --- The ceremonies ---------------------------------------------------------------------
        //
        // Each holds the request body for the life of the response, so the head goes out before the
        // first round does.
        macro_rules! ceremony {
            ($handler:path) => {{
                let cosigner = Arc::clone(&self.cosigner);
                let inbound = req.into_body().into_boxed_body();
                // The handler runs as the response streams, so its outcome is known later than the
                // `request` line above. Logging the end here, with the method, leaves every ceremony
                // a start/end pair; the handler itself adds the ids beyond the method name.
                let op = method.to_string();
                return grpc::streaming(SessionBody::new(inbound, move |duplex| async move {
                    match $handler(cosigner, duplex).await {
                        Ok(()) => {
                            println!("{op}: done");
                            Ok(())
                        }
                        Err(status) => {
                            eprintln!("{op}: failed: {status}");
                            Err(status)
                        }
                    }
                }));
            }};
        }
        match method {
            "Sign" => ceremony!(sign),
            "Send" => ceremony!(send),
            "Renew" => ceremony!(renew),
            "Board" => ceremony!(board),
            _ => {}
        }

        // --- The single-round calls ---------------------------------------------------------------
        //
        // Nothing is held between messages, so a stream would buy nothing.
        macro_rules! unary {
            ($body:expr) => {
                match $body.await {
                    Ok(resp) => {
                        println!("{method}: done");
                        grpc::unary(resp)
                    }
                    Err(status) => {
                        eprintln!("{method}: failed: {status}");
                        grpc::failed(status)
                    }
                }
            };
        }
        let body = req.into_body();
        match method {
            "GetServerInfo" => unary!(self.get_server_info(body)),
            "RegisterDevice" => unary!(self.register_device(body)),
            "ForgetDevice" => unary!(self.forget_device(body)),
            "DeviceCount" => unary!(self.device_count(body)),
            "Recover" => unary!(self.recover(body)),
            other => {
                eprintln!("{other}: no such method");
                grpc::failed(Status::unimplemented(format!("no such method: {other}")))
            }
        }
    }

    // -------------------------------------------------------------------------------------------
    // The single-round calls.
    // -------------------------------------------------------------------------------------------

    async fn get_server_info(&self, body: Body) -> Result<wp::GetServerInfoResponse, Status> {
        let _: wp::GetServerInfoRequest = grpc::one_message(body).await?;
        Ok(self.server_info.clone())
    }

    // --- Devices -------------------------------------------------------------------------------
    //
    // Forwarded to the runtime and not stored here. The cosigner has no push channel of its own and
    // never sees a token twice; `device_count` returns a number because it is not meant to be able
    // to enumerate a tenant's devices.

    async fn register_device(&self, body: Body) -> Result<proto::RegisterDeviceResponse, Status> {
        let req: proto::RegisterDeviceRequest = grpc::one_message(body).await?;
        lock(&self.cosigner)
            .host
            .register_device(&req.token)
            .map_err(Status::unavailable)?;
        Ok(proto::RegisterDeviceResponse {})
    }

    async fn forget_device(&self, body: Body) -> Result<proto::ForgetDeviceResponse, Status> {
        let req: proto::ForgetDeviceRequest = grpc::one_message(body).await?;
        lock(&self.cosigner)
            .host
            .forget_device(&req.token)
            .map_err(Status::unavailable)?;
        Ok(proto::ForgetDeviceResponse {})
    }

    async fn device_count(&self, body: Body) -> Result<proto::DeviceCountResponse, Status> {
        let _: proto::DeviceCountRequest = grpc::one_message(body).await?;
        let devices = lock(&self.cosigner).host.devices().map_err(Status::unavailable)?;
        Ok(proto::DeviceCountResponse { devices })
    }

    /// See [`Cosigner::recover`]. Reads the seal; installs nothing.
    async fn recover(&self, body: Body) -> Result<proto::RecoverResponse, Status> {
        let req: proto::RecoverRequest = grpc::one_message(body).await?;
        lock(&self.cosigner).recover(req)
    }

}

/// The cosigner, with a poisoned lock recovered rather than propagated.
///
/// A panic mid-ceremony leaves the wallet's in-memory state as it was — its authority comes from
/// the seal, not from this guard — and taking down every later call because one caller panicked
/// would turn a single failed request into a dead instance.
pub(crate) fn lock(cosigner: &Arc<Mutex<Cosigner>>) -> MutexGuard<'_, Cosigner> {
    cosigner.lock().unwrap_or_else(|e| e.into_inner())
}

// ===============================================================================================
// The ceremonies
// ===============================================================================================

/// One signature, as one signing session.
///
/// The wallet used to commit first, in `SignOpen`. It cannot: its nonce is hedged with its share,
/// and it holds no share until this stream's first answer brings the half the cosigner dealt it.
/// So this is the round `Send` and `Renew` already run — the cosigner commits first, the wallet
/// answers with its commitments and its share together — over a single message.
///
/// Script-path only, like every signing session: the cosigner signs untweaked and `aggregate`
/// checks each share, so a key-path share could never have aggregated here. It is refused by name
/// rather than left to fail as a bad share.
async fn sign(
    cosigner: Arc<Mutex<Cosigner>>,
    duplex: Duplex<SignClientMsg, SignServerMsg>,
) -> Result<(), Status> {
    // --- Round 1: open --------------------------------------------------------------------
    let first = duplex.expect("it opened").await?;
    let session_id = first.session_id.clone();
    let open = match first.body {
        Some(sign_client_msg::Body::Open(o)) => o,
        _ => return Err(Status::invalid_argument("a session must open with SignOpen")),
    };
    // Authenticated before it got here: the runtime approved this stream with a passkey assertion,
    // once, at open, and `route` refuses anything that arrives without the tenant it resolved.

    if !open.script_path_spend {
        return Err(Status::invalid_argument(
            "Sign is script-path only: the cosigner signs untweaked, so a key-path share cannot \
             aggregate",
        ));
    }

    // NOTHING ABOUT THE MESSAGE IS CHECKED HERE. The contract gate that once stood between an
    // authorized caller and a signature over arbitrary bytes went with the contract layer; the
    // policy IR is what has to take its place before this is exposed for real signing.
    // `full_transaction` is what that policy will read, and is why it still travels.

    // The wallet's half of its own share, before any nonce exists: a caller that is not this
    // wallet is refused with nothing to abandon.
    let dealt = lock(&cosigner).dealt_share_for(&open.identifier)?;

    // The round is OURS, as an ordinary local. The lock is released before we wait on the client —
    // a slow client blocks nobody.
    let messages = vec![open.message_to_sign.clone()];
    let host = lock(&cosigner).host();
    let (signing, commitments) =
        SigningSession::begin(host, &messages).map_err(Status::unavailable)?;

    println!("Sign: returned the dealt share to the wallet's own identifier");
    duplex.send(SignServerMsg {
        session_id: session_id.clone(),
        seq: 1,
        body: Some(sign_server_msg::Body::Commitments(SignCommitments {
            commitments: commitments
                .into_iter()
                .map(|c| (c.identifier_hex.clone(), c.into()))
                .collect(),
            message_to_sign: open.message_to_sign,
            wallet_dealt_share: dealt,
        })),
    });

    // --- Round 2: the wallet's commitments and share ----------------------------------------
    //
    // If the client never sends it, or the stream dies here, `signing` drops with this task and the
    // nonce is gone. That is the safe failure: an abandoned round leaves nothing reusable.
    let share = match duplex.next_body("the share arrived").await? {
        sign_client_msg::Body::Share(s) => s,
        _ => return Err(Status::invalid_argument("expected SignShare")),
    };

    // A bad share is the caller's fault, and is reported as such rather than as ours.
    let signature = signing
        .finish(vec![share.into()])
        .map_err(Status::invalid_argument)?
        .pop()
        .ok_or_else(|| Status::internal("the round produced no signature"))?;
    if signature.len() != 64 {
        return Err(Status::internal("the round produced a signature that is not 64 bytes"));
    }

    // BIP-340: `R.x ‖ z`, and `aggregate` normalizes R to even Y — so the compressed point the
    // wallet verifies against is that x under an even prefix.
    let mut r_point = vec![0x02];
    r_point.extend_from_slice(&signature[..32]);
    duplex.send(SignServerMsg {
        session_id,
        seq: 2,
        body: Some(sign_server_msg::Body::Complete(SignComplete {
            r_point,
            z_scalar: signature[32..].to_vec(),
        })),
    });
    Ok(())
}

/// A send as one session, with the caller submitting.
///
/// The unary form parked the half-built transactions on the actor between "build it" and "submit
/// it", and called the ASP itself for both `SubmitTx` and `FinalizeTx`. Here the session is a local
/// on this handler and the caller makes those two calls: the cosigner hands over what to send and
/// seals only once the ASP has accepted it, so an interrupted send leaves neither a half-signed
/// transaction addressable by the next request nor a recorded spend that never happened.
async fn send(
    cosigner: Arc<Mutex<Cosigner>>,
    duplex: Duplex<proto::SendClientMsg, proto::SendServerMsg>,
) -> Result<(), Status> {
    let first = duplex.expect("it opened").await?;
    let session_id = first.session_id.clone();
    let open = match first.body {
        Some(proto::send_client_msg::Body::Open(o)) => o,
        _ => return Err(Status::invalid_argument("a session must open with SendOpen")),
    };
    // Authenticated by the runtime at open — see `sign` above.

    // The wallet's half of its own share, before anything is built — see `dealt_share_for`. It
    // rides the first sighashes and nothing after: a trailing delegate renewal reuses what the
    // wallet rebuilt.
    let dealt = lock(&cosigner).dealt_share_for(&open.identifier)?;

    let info = open
        .ark_info
        .map(ark::client::types::ArkInfo::from)
        .ok_or_else(|| Status::invalid_argument("SendOpen carried no ark_info"))?;

    // The caller names its inputs, and the cosigner validates every one against the scriptPubKey it
    // derives from its own owner key before selecting — so naming a VTXO here cannot widen what the
    // wallet owns.
    let (session, change_exit_delay, sighashes) = {
        let step1 = crate::types::SendVtxoStep1 {
            recipient_ark_address: open.recipient_ark_address.clone(),
            amount: open.amount,
            vtxos: open.vtxos.iter().cloned().map(Into::into).collect(),
        };
        lock(&cosigner).create_send_session(step1, &info).map_err(Status::internal)?
    };

    drive_send(&cosigner, &duplex, &session_id, session, change_exit_delay, sighashes, dealt).await
}

/// A send's rounds, from its sighashes to its change recorded and an optional delegate renewal —
/// on whichever stream carries them ([`SendStream`]). [dealt] rides the first sighashes: the wallet's dealt share when this is the
/// stream's first reconstruction of it, empty when the wallet has already rebuilt its share.
async fn drive_send<S: SendStream>(
    cosigner: &Arc<Mutex<Cosigner>>,
    duplex: &Duplex<S::In, S>,
    session_id: &str,
    mut session: ark::client::send::SendSession,
    change_exit_delay: u32,
    sighashes: Vec<Vec<u8>>,
    dealt: Vec<u8>,
) -> Result<(), Status> {
    let say = |seq, body| {
        duplex.send(S::carry(proto::SendServerMsg {
            session_id: session_id.to_string(),
            seq,
            body: Some(body),
        }))
    };

    // Round one of the FROST signature, on this stream. It used to be a nested `Sign` stream per
    // sighash, which deadlocks inside enclave-runtime — see `crate::sign`.
    let host = lock(cosigner).host();
    let (signing, commitments) =
        SigningSession::begin(host, &sighashes).map_err(Status::unavailable)?;

    say(1, proto::send_server_msg::Body::Sighashes(proto::SendSighashes {
        wallet_dealt_share: dealt,
        ..proto::SendSighashes::round(sighashes, commitments)
    }));

    // --- The wallet's half of the round, then what it must submit --------------------------
    let signed = match next_send(duplex).await? {
        proto::send_client_msg::Body::Signed(s) => s,
        _ => return Err(Status::invalid_argument("expected SendSigned")),
    };
    // A bad share is the caller's fault, and is reported as such rather than as ours.
    let signatures = signing
        .finish(signed.rounds.into_iter().map(Into::into).collect())
        .map_err(Status::invalid_argument)?;
    let (ark_tx_b64, checkpoint_txs) =
        crate::cosigner::sign_and_prepare(&mut session, &signatures).map_err(Status::internal)?;

    say(2, proto::send_server_msg::Body::Submit(proto::SendSubmit {
        ark_tx_b64,
        checkpoint_txs,
    }));

    // --- What the ASP returned, turned into the finalize call ------------------------------
    let submitted = match next_send(duplex).await? {
        proto::send_client_msg::Body::Submitted(s) => s,
        _ => return Err(Status::invalid_argument("expected SendSubmitted")),
    };
    let final_checkpoint_txs = session
        .finalize_checkpoints(&submitted.signed_checkpoint_txs)
        .map_err(|e| Status::internal(format!("finalize checkpoints: {e}")))?;

    say(3, proto::send_server_msg::Body::Finalize(proto::SendFinalize {
        ark_txid: submitted.ark_txid.clone(),
        final_checkpoint_txs,
    }));

    // --- Accepted. Only now is it ours to record -------------------------------------------
    match next_send(duplex).await? {
        proto::send_client_msg::Body::Finalized(_) => {}
        _ => return Err(Status::invalid_argument("expected SendFinalized")),
    }
    {
        let mut c = lock(cosigner);
        c.finalise_send_session(session, change_exit_delay);
        c.seal();
    }

    say(4, proto::send_server_msg::Body::Complete(proto::SendComplete {
        ark_txid: submitted.ark_txid,
        change: None,
    }));

    // --- Optionally, renew the delegate over what the wallet holds now ---------------------
    //
    // On this stream so it rides the approval — and the passkey seed — the send already had. A
    // caller that closes instead has simply not asked for it.
    if let Some(msg) = duplex.recv().await {
        let request = match msg.into_body().and_then(S::uncarry) {
            Some(proto::send_client_msg::Body::RenewDelegate(r)) => r,
            _ => {
                return Err(Status::invalid_argument(
                    "after SendComplete only the delegate's renewal may follow",
                ))
            }
        };
        DelegateRenew::run(cosigner, duplex, request, session_id, 5, vec![]).await?;
    }
    Ok(())
}

/// The next step of a send, out of whatever its stream carries.
async fn next_send<S: SendStream>(
    duplex: &Duplex<S::In, S>,
) -> Result<proto::send_client_msg::Body, Status> {
    S::uncarry(duplex.next_body("mid-send").await?)
        .ok_or_else(|| Status::invalid_argument("expected the send's next step"))
}

/// A stream a send's rounds can ride, and how it carries a `Send` stream's messages: as they are,
/// or inside its own. Every one that does also carries the delegate renewal that may follow.
pub(crate) trait SendStream: DelegateStream {
    fn carry(msg: proto::SendServerMsg) -> Self;

    /// The `Send` stream's message in [body], or None if [body] is something else.
    fn uncarry(body: <Self::In as HasBody>::Body) -> Option<proto::send_client_msg::Body>;
}

impl SendStream for proto::SendServerMsg {
    fn carry(msg: proto::SendServerMsg) -> Self {
        msg
    }

    fn uncarry(body: proto::send_client_msg::Body) -> Option<proto::send_client_msg::Body> {
        Some(body)
    }
}

/// Renewing the VTXOs held, with the caller driving the ASP round.
///
/// The cosigner answers each relayed event with what to send the ASP next and never opens a socket
/// of its own. `ark_info` arrives from the caller for the same reason: it is the one talking to the
/// ASP. See `Cosigner::renew_begin` for why that cannot redirect funds.
async fn renew(
    cosigner: Arc<Mutex<Cosigner>>,
    duplex: Duplex<proto::RenewClientMsg, proto::RenewServerMsg>,
) -> Result<(), Status> {
    let first = duplex.expect("it opened").await?;
    let session_id = first.session_id.clone();
    let open = match first.body {
        Some(proto::renew_client_msg::Body::Open(o)) => o,
        _ => return Err(Status::invalid_argument("a session must open with RenewOpen")),
    };
    // Authenticated by the runtime at open — see `sign` above.

    // The wallet's half of its own share — see `dealt_share_for`. Taken by the FIRST sighashes this
    // stream sends, whichever path sends them, and gone after: a renewal signs two or three rounds
    // and the wallet rebuilds its share once.
    let mut dealt = Some(lock(&cosigner).dealt_share_for(&open.identifier)?);
    println!("Renew: returning the dealt share to the wallet's own identifier");

    let info = open
        .ark_info
        .map(ark::client::types::ArkInfo::from)
        .ok_or_else(|| Status::invalid_argument("RenewOpen carried no ark_info"))?;
    if open.delegate_only {
        // Nothing to refresh now; renew the delegate over the set and close.
        let request = proto::RenewDelegate {
            vtxos: open.vtxos,
            ark_info: Some(wp::ArkInfo::from(&info)),
            device_token: open.device_token,
            exit_script_pubkey: open.exit_script_pubkey,
        };
        let dealt = dealt.take().unwrap_or_default();
        return DelegateRenew::run(&cosigner, &duplex, request, &session_id, 1, dealt).await;
    }
    let vtxos = open.vtxos.into_iter().map(Into::into).collect();
    let sighashes = lock(&cosigner).renew_begin(vtxos, info).map_err(Status::internal)?;
    drive_round(&cosigner, &duplex, &session_id, dealt, sighashes).await
}

/// Boarding one on-chain output into Ark: the round `renew` drives, opened with `BoardOpen` on a
/// stream of its own.
async fn board(
    cosigner: Arc<Mutex<Cosigner>>,
    duplex: Duplex<proto::RenewClientMsg, proto::RenewServerMsg>,
) -> Result<(), Status> {
    let first = duplex.expect("it opened").await?;
    let session_id = first.session_id.clone();
    let open = match first.body {
        Some(proto::renew_client_msg::Body::Board(o)) => o,
        _ => return Err(Status::invalid_argument("a session must open with BoardOpen")),
    };
    // Authenticated by the runtime at open — see `sign` above.

    // The wallet's half of its own share, as `renew` hands it out: with the first sighashes.
    let dealt = lock(&cosigner).dealt_share_for(&open.identifier)?;
    println!("Board: returning the dealt share to the wallet's own identifier");

    let info = open
        .ark_info
        .map(ark::client::types::ArkInfo::from)
        .ok_or_else(|| Status::invalid_argument("BoardOpen carried no ark_info"))?;
    let utxo = open
        .utxo
        .map(|u| (u.txid, u.vout, u.amount_sats))
        .ok_or_else(|| Status::invalid_argument("BoardOpen carried no utxo"))?;
    let sighashes = lock(&cosigner).board_begin(utxo, &info).map_err(Status::internal)?;
    drive_round(&cosigner, &duplex, &session_id, Some(dealt), sighashes).await
}

/// The round `renew` and `board` share: from the first sighashes to `RenewComplete`, and the
/// delegate's renewal the caller may ask for after it. [dealt] goes out with the first sighashes,
/// unless the stream already spent it.
async fn drive_round(
    cosigner: &Arc<Mutex<Cosigner>>,
    duplex: &Duplex<proto::RenewClientMsg, proto::RenewServerMsg>,
    session_id: &str,
    mut dealt: Option<Vec<u8>>,
    sighashes: Vec<Vec<u8>>,
) -> Result<(), Status> {
    use crate::renew::RenewStep;

    let mut seq = 1u64;
    let mut step = RenewStep::Sighashes(sighashes);

    // The FROST round that is waiting for the wallet's half. A renewal signs twice — the intent
    // proof, and for a boarding settle the commitment transaction later — so this is set each time
    // sighashes go out and taken when the matching `Signed` comes back. Holding it here rather than
    // on the cosigner is what keeps the nonces on this stream's stack, where a dropped stream takes
    // them with it.
    let mut pending_round: Option<SigningSession> = None;

    loop {
        // Say what we need, then read what the caller did about it.
        let body = match step {
            RenewStep::Sighashes(messages_to_sign) => {
                // Round one, on this stream — see `crate::sign` for why it cannot be a nested
                // `Sign` any more.
                let host = lock(cosigner).host();
                let (signing, commitments) = SigningSession::begin(host, &messages_to_sign)
                    .map_err(Status::unavailable)?;
                pending_round = Some(signing);
                Some(proto::renew_server_msg::Body::Sighashes(proto::RenewSighashes {
                    wallet_dealt_share: dealt.take().unwrap_or_default(),
                    ..proto::RenewSighashes::round(messages_to_sign, commitments)
                }))
            }
            RenewStep::Register { proof, message, topics } => Some(
                proto::renew_server_msg::Body::Register(proto::RegisterIntent {
                    proof,
                    message,
                    topics,
                }),
            ),
            RenewStep::Submit(call) => {
                Some(proto::renew_server_msg::Body::Submit(call.into()))
            }
            RenewStep::Idle => Some(proto::renew_server_msg::Body::Idle(proto::RenewIdle {})),
            RenewStep::Complete(sub) => {
                let complete = proto::RenewComplete {
                    commitment_txid: sub.commitment_txid.clone(),
                    vtxo_txid: sub.vtxo_txid.clone(),
                    vtxo_vout: sub.vtxo_vout,
                    amount_sats: sub.amount_sats,
                    exit_delay: sub.exit_delay,
                };
                {
                    let mut c = lock(cosigner);
                    c.apply_boarding_settle(sub);
                    c.seal();
                }
                duplex.send(proto::RenewServerMsg {
                    session_id: session_id.to_string(),
                    seq,
                    body: Some(proto::renew_server_msg::Body::Complete(complete)),
                });
                // Optionally, renew the delegate over what the wallet holds now — on this stream,
                // so it rides the approval and the passkey seed the renewal already had.
                if let Some(msg) = duplex.recv().await {
                    let request = match msg.body {
                        Some(proto::renew_client_msg::Body::RenewDelegate(r)) => r,
                        _ => {
                            return Err(Status::invalid_argument(
                                "after RenewComplete only the delegate's renewal may follow",
                            ))
                        }
                    };
                    // No share with it: the renewal's first round already carried one.
                    let next = seq + 1;
                    DelegateRenew::run(cosigner, duplex, request, session_id, next, vec![])
                        .await?;
                }
                return Ok(());
            }
        };

        duplex.send(proto::RenewServerMsg {
            session_id: session_id.to_string(),
            seq,
            body,
        });
        seq += 1;

        let body = duplex.next_body("the next renewal step").await?;

        // Scoped to this iteration, and released before the loop comes back around to
        // `recv().await`. That used to matter because the caller opened a nested `Sign` on its own
        // connection while this stream was parked; signing rides this stream now, so nothing else
        // takes this lock mid-renewal — but holding a guard across an await is still the wrong
        // habit.
        let mut c = lock(cosigner);
        step = match body {
            proto::renew_client_msg::Body::Signed(s) => {
                let round = pending_round.take().ok_or_else(|| {
                    Status::invalid_argument("signatures arrived with no round waiting for them")
                })?;
                let signatures = round
                    .finish(s.rounds.into_iter().map(Into::into).collect())
                    .map_err(Status::invalid_argument)?;
                c.renew_signed(signatures).map_err(Status::internal)?
            }
            proto::renew_client_msg::Body::Registered(r) => {
                c.renew_registered(r.intent_id).map_err(Status::internal)?;
                RenewStep::Idle
            }
            proto::renew_client_msg::Body::Event(e) => match Option::try_from(e)? {
                Some(ev) => c.renew_on_event(ev).map_err(Status::internal)?,
                None => RenewStep::Idle,
            },
            proto::renew_client_msg::Body::Open(_) | proto::renew_client_msg::Body::Board(_) => {
                return Err(Status::invalid_argument("the session is already open"))
            }
            proto::renew_client_msg::Body::RenewDelegate(_) => {
                return Err(Status::invalid_argument(
                    "the delegate's renewal follows RenewComplete, not the round",
                ))
            }
        };
        drop(c);
    }
}

/// Enrol a device token carried in-band, if there is one. Whether it was, rather than an error: the
/// operation it rode on is what the caller asked for, and must not fail because a wake could not be
/// arranged — the wallet sends the token again next time.
pub(crate) fn enrol_device(cosigner: &Arc<Mutex<Cosigner>>, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    lock(cosigner).host.register_device(token).is_ok()
}

