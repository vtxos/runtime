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
//! They were `async_stream::try_stream!` blocks behind a tonic service trait, then bodies driven by
//! the guest's own gRPC framing. The runtime ends gRPC now and hands over messages, and these
//! bodies still did not change: `yield x` became `duplex.send(x)`, `inbound.next().await` became
//! `duplex.recv().await`, and the ceremonies are otherwise the same code. That was the test of
//! whether the transport had been kept at arm's length, and it passed twice.

use std::sync::{Arc, Mutex, MutexGuard};

use enclave_wit::enclave::notify::notify;

use crate::policy::Policy;
use crate::renew::{DelegateRenew, DelegateStream};
use crate::sign::SigningSession;
use crate::status::Status;
use crate::wallet_proto as wp;
use crate::wire::{Duplex, HasBody, Wire};

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
    policy: Arc<Mutex<Policy>>,
    server_info: wp::GetServerInfoResponse,
}

impl Session {
    pub fn new(policy: Arc<Mutex<Policy>>, server_info: wp::GetServerInfoResponse) -> Self {
        Self {
            policy,
            server_info,
        }
    }

    /// One call, routed: `method` is its path, and `wire` carries its messages.
    ///
    /// This is what a generated service trait would be for. Matching the path by hand is a table
    /// of nine names, clearer than a code generator. Whatever a ceremony queued goes out before
    /// its status does, however it ends.
    pub async fn route(&self, method: &str, wire: Box<dyn Wire>) -> Result<(), Status> {
        // Authentication is the runtime's: it lets a call through only once its owner signed in.
        // Run it without a gate and anyone can call this.
        let Some(name) = method.strip_prefix(PREFIX) else {
            eprintln!("request to unknown service: {method}");
            return Err(Status::unimplemented(format!("no such service: {method}")));
        };
        println!("{name}: request");

        // --- The ceremonies ---------------------------------------------------------------------
        macro_rules! ceremony {
            ($handler:path) => {{
                let duplex = Duplex::new(wire);
                let outcome = $handler(Arc::clone(&self.policy), &duplex).await;
                duplex.flush().await;
                outcome
            }};
        }
        let outcome = match name {
            "Sign" => ceremony!(sign),
            "Send" => ceremony!(send),
            "Renew" => ceremony!(renew),
            "Board" => ceremony!(board),

            // --- The single-round calls -----------------------------------------------------------
            //
            // Nothing is held between messages, so a stream would buy nothing.
            "GetServerInfo" => unary(wire, |_: wp::GetServerInfoRequest| Ok(self.server_info.clone())).await,
            "RegisterDevice" => unary(wire, register_device).await,
            "ForgetDevice" => unary(wire, forget_device).await,
            "DeviceCount" => unary(wire, device_count).await,
            "Recover" => unary(wire, |req| lock(&self.policy).recover(req)).await,
            other => {
                eprintln!("{other}: no such method");
                return Err(Status::unimplemented(format!("no such method: {other}")));
            }
        };
        match &outcome {
            Ok(()) => println!("{name}: done"),
            Err(status) => eprintln!("{name}: failed: {status}"),
        }
        outcome
    }
}

/// A single-round call: one request in, one answer out.
async fn unary<Req, Resp>(
    wire: Box<dyn Wire>,
    answer: impl FnOnce(Req) -> Result<Resp, Status>,
) -> Result<(), Status>
where
    Req: prost::Message + Default,
    Resp: prost::Message,
{
    let duplex = Duplex::<Req, Resp>::new(wire);
    duplex.send(answer(duplex.only().await?)?);
    duplex.flush().await;
    Ok(())
}

// --- Devices -----------------------------------------------------------------------------------
//
// Forwarded to the runtime and not stored here. The policy has no push channel of its own and
// never sees a token twice; `device_count` returns a number because it is not meant to be able to
// enumerate a tenant's devices.

fn register_device(req: proto::RegisterDeviceRequest) -> Result<proto::RegisterDeviceResponse, Status> {
    notify::register_device(&req.token).map_err(Status::unavailable)?;
    Ok(proto::RegisterDeviceResponse {})
}

fn forget_device(req: proto::ForgetDeviceRequest) -> Result<proto::ForgetDeviceResponse, Status> {
    notify::forget_device(&req.token).map_err(Status::unavailable)?;
    Ok(proto::ForgetDeviceResponse {})
}

fn device_count(_: proto::DeviceCountRequest) -> Result<proto::DeviceCountResponse, Status> {
    let devices = notify::devices().map_err(Status::unavailable)?;
    Ok(proto::DeviceCountResponse { devices })
}

/// The policy, with a poisoned lock recovered rather than propagated.
///
/// A panic mid-ceremony leaves the wallet's in-memory state as it was — its authority comes from
/// the seal, not from this guard — and taking down every later call because one caller panicked
/// would turn a single failed request into a dead instance.
pub(crate) fn lock(policy: &Arc<Mutex<Policy>>) -> MutexGuard<'_, Policy> {
    policy.lock().unwrap_or_else(|e| e.into_inner())
}

// ===============================================================================================
// The ceremonies
// ===============================================================================================

/// One signature, as one signing session.
///
/// The wallet used to commit first, in `SignOpen`. It cannot: its nonce is hedged with its share,
/// and it holds no share until this stream's first answer brings the half the policy dealt it.
/// So this is the round `Send` and `Renew` already run — the policy commits first, the wallet
/// answers with its commitments and its share together — over a single message.
///
/// Script-path only, like every signing session: the policy signs untweaked and `aggregate`
/// checks each share, so a key-path share could never have aggregated here. It is refused by name
/// rather than left to fail as a bad share.
async fn sign(
    policy: Arc<Mutex<Policy>>,
    duplex: &Duplex<SignClientMsg, SignServerMsg>,
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
            "Sign is script-path only: the policy signs untweaked, so a key-path share cannot \
             aggregate",
        ));
    }

    // NOTHING ABOUT THE MESSAGE IS CHECKED HERE. The contract gate that once stood between an
    // authorized caller and a signature over arbitrary bytes went with the contract layer; the
    // policy IR is what has to take its place before this is exposed for real signing.
    // `full_transaction` is what that policy will read, and is why it still travels.

    // The wallet's half of its own share, before any nonce exists: a caller that is not this
    // wallet is refused with nothing to abandon.
    let dealt = lock(&policy).dealt_share_for(&open.identifier)?;

    // The round is OURS, as an ordinary local. The lock is released before we wait on the client —
    // a slow client blocks nobody.
    let messages = vec![open.message_to_sign.clone()];
    let (signing, commitments) =
        SigningSession::begin(&messages).map_err(Status::unavailable)?;

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
/// on this handler and the caller makes those two calls: the policy hands over what to send and
/// seals only once the ASP has accepted it, so an interrupted send leaves neither a half-signed
/// transaction addressable by the next request nor a recorded spend that never happened.
async fn send(
    policy: Arc<Mutex<Policy>>,
    duplex: &Duplex<proto::SendClientMsg, proto::SendServerMsg>,
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
    let dealt = lock(&policy).dealt_share_for(&open.identifier)?;

    let info = open
        .ark_info
        .ok_or_else(|| Status::invalid_argument("SendOpen carried no ark_info"))
        .and_then(|i| crate::util::server_info(i).map_err(Status::invalid_argument))?;

    // The caller names its inputs, and the policy validates every one against the scriptPubKey it
    // derives from its own owner key before selecting — so naming a VTXO here cannot widen what the
    // wallet owns.
    let (session, change_exit_delay, sighashes) = {
        let step1 = crate::types::SendVtxoStep1 {
            recipient_ark_address: open.recipient_ark_address.clone(),
            amount: open.amount,
            vtxos: open.vtxos.iter().cloned().map(Into::into).collect(),
        };
        lock(&policy).create_send_session(step1, &info).map_err(Status::internal)?
    };

    drive_send(&policy, duplex, &session_id, session, change_exit_delay, sighashes, dealt).await
}

/// A send's rounds, from its sighashes to its change recorded and an optional delegate renewal —
/// on whichever stream carries them ([`SendStream`]). [dealt] rides the first sighashes: the wallet's dealt share when this is the
/// stream's first reconstruction of it, empty when the wallet has already rebuilt its share.
async fn drive_send<S: SendStream>(
    policy: &Arc<Mutex<Policy>>,
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
    let (signing, commitments) =
        SigningSession::begin(&sighashes).map_err(Status::unavailable)?;

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
        crate::policy::sign_and_prepare(&mut session, &signatures).map_err(Status::internal)?;

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
        let mut c = lock(policy);
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
    if let Some(msg) = duplex.recv().await? {
        let request = match msg.into_body().and_then(S::uncarry) {
            Some(proto::send_client_msg::Body::RenewDelegate(r)) => r,
            _ => {
                return Err(Status::invalid_argument(
                    "after SendComplete only the delegate's renewal may follow",
                ))
            }
        };
        DelegateRenew::run(policy, duplex, request, session_id, 5, vec![]).await?;
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
/// The policy answers each relayed event with what to send the ASP next and never opens a socket
/// of its own. `ark_info` arrives from the caller for the same reason: it is the one talking to the
/// ASP. See `Policy::renew_begin` for why that cannot redirect funds.
async fn renew(
    policy: Arc<Mutex<Policy>>,
    duplex: &Duplex<proto::RenewClientMsg, proto::RenewServerMsg>,
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
    let mut dealt = Some(lock(&policy).dealt_share_for(&open.identifier)?);
    println!("Renew: returning the dealt share to the wallet's own identifier");

    let wire_info = open
        .ark_info
        .ok_or_else(|| Status::invalid_argument("RenewOpen carried no ark_info"))?;
    let info = crate::util::server_info(wire_info.clone()).map_err(Status::invalid_argument)?;
    if open.delegate_only {
        // Nothing to refresh now; renew the delegate over the set and close.
        let request = proto::RenewDelegate {
            vtxos: open.vtxos,
            ark_info: Some(wire_info),
            device_token: open.device_token,
            exit_script_pubkey: open.exit_script_pubkey,
        };
        let dealt = dealt.take().unwrap_or_default();
        return DelegateRenew::run(&policy, duplex, request, &session_id, 1, dealt).await;
    }
    let vtxos = open.vtxos.into_iter().map(Into::into).collect();
    let sighashes = lock(&policy).renew_begin(vtxos, info).map_err(Status::internal)?;
    drive_round(&policy, duplex, &session_id, dealt, sighashes).await
}

/// Boarding one on-chain output into Ark: the round `renew` drives, opened with `BoardOpen` on a
/// stream of its own.
async fn board(
    policy: Arc<Mutex<Policy>>,
    duplex: &Duplex<proto::RenewClientMsg, proto::RenewServerMsg>,
) -> Result<(), Status> {
    let first = duplex.expect("it opened").await?;
    let session_id = first.session_id.clone();
    let open = match first.body {
        Some(proto::renew_client_msg::Body::Board(o)) => o,
        _ => return Err(Status::invalid_argument("a session must open with BoardOpen")),
    };
    // Authenticated by the runtime at open — see `sign` above.

    // The wallet's half of its own share, as `renew` hands it out: with the first sighashes.
    let dealt = lock(&policy).dealt_share_for(&open.identifier)?;
    println!("Board: returning the dealt share to the wallet's own identifier");

    let info = open
        .ark_info
        .ok_or_else(|| Status::invalid_argument("BoardOpen carried no ark_info"))
        .and_then(|i| crate::util::server_info(i).map_err(Status::invalid_argument))?;
    let utxo = open
        .utxo
        .map(|u| (u.txid, u.vout, u.amount_sats))
        .ok_or_else(|| Status::invalid_argument("BoardOpen carried no utxo"))?;
    let sighashes = lock(&policy).board_begin(utxo, &info).map_err(Status::internal)?;
    drive_round(&policy, duplex, &session_id, Some(dealt), sighashes).await
}

/// The round `renew` and `board` share: from the first sighashes to `RenewComplete`, and the
/// delegate's renewal the caller may ask for after it. [dealt] goes out with the first sighashes,
/// unless the stream already spent it.
async fn drive_round(
    policy: &Arc<Mutex<Policy>>,
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
    // on the policy is what keeps the nonces on this stream's stack, where a dropped stream takes
    // them with it.
    let mut pending_round: Option<SigningSession> = None;

    loop {
        // Say what we need, then read what the caller did about it.
        let body = match step {
            RenewStep::Sighashes(messages_to_sign) => {
                // Round one, on this stream — see `crate::sign` for why it cannot be a nested
                // `Sign` any more.
                let (signing, commitments) = SigningSession::begin(&messages_to_sign)
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
                    let mut c = lock(policy);
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
                if let Some(msg) = duplex.recv().await? {
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
                    DelegateRenew::run(policy, duplex, request, session_id, next, vec![])
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
        let mut c = lock(policy);
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
pub(crate) fn enrol_device(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    notify::register_device(token).is_ok()
}

