//! gRPC, ended here for a guest that exports `enclave:rpc/service`.
//!
//! ```text
//!   client ──frames──▶ Deframe ──messages──▶ ┌───────┐
//!   client ◀─frames─── GrpcBody ◀─messages── │ guest │ ── status ──▶ trailers
//!                                            └───────┘
//! ```
//!
//! The guest sees protobuf messages and nothing of HTTP: no framing, no trailers, no headers. What
//! goes on the wire is exactly what a guest serving gRPC itself used to send: HTTP 200,
//! `content-type: application/grpc+proto`, a `trailer` header for HTTP/1.1, the 5-byte prefix on
//! every message, and `grpc-status` with `grpc-message` at the end. So a client cannot tell which
//! kind of guest it reached.
//!
//! The call runs inside [`wasmtime::Store::run_concurrent`] for as long as the guest talks: the
//! streams move only while the store's event loop does. It ends with the guest's status, and the
//! store, its instance and every stream end drop with the task that ran it.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::{BufMut, Bytes, BytesMut};
use futures::channel::mpsc;
use futures::Stream;
use hyper::body::{Body, Frame};
use wasmtime::component::{
    Destination, FutureConsumer, Source, StreamConsumer, StreamProducer, StreamReader, StreamResult,
};
use wasmtime::{Store, StoreContextMut};
use wasmtime_wasi_http::p2::bindings::http::types::ErrorCode;
use wasmtime_wasi_http::p2::body::HyperOutgoingBody;

use crate::state::State;

wasmtime::component::bindgen!({ path: "../wit/rpc", world: "enclave:rpc/server" });

pub(crate) use exports::enclave::rpc::service::Status;

/// The largest message either side may send, framed or not. A frame claiming more is refused
/// before it is buffered.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

const OK: u32 = 0;
const INVALID_ARGUMENT: u32 = 3;
const UNAVAILABLE: u32 = 14;

fn status(code: u32, message: impl Into<String>) -> Status {
    Status {
        code,
        message: message.into(),
    }
}

/// What the transport itself concluded, which outranks whatever the guest says after it.
///
/// A frame the runtime could not read ends the guest's request stream early, and the guest, seeing
/// only an early end, would report that. The real reason is here.
type Verdict = Arc<Mutex<Option<Status>>>;

/// Run one call to `guest`'s `enclave:rpc/service` in `store`.
///
/// The response head goes to `head` as soon as the guest has taken the call, so the client hears
/// back before the conversation starts. The body streams the guest's replies, and ends with its
/// status as trailers. Returns once that status is known.
pub(crate) async fn serve<B>(
    store: &mut Store<State>,
    pre: &ServerPre<State>,
    req: hyper::Request<B>,
    head: tokio::sync::oneshot::Sender<Result<hyper::Response<HyperOutgoingBody>, ErrorCode>>,
) -> wasmtime::Result<()>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<ErrorCode>,
{
    let guest = pre.instantiate_async(&mut *store).await?;
    let method = req.uri().path().to_string();
    let verdict = Verdict::default();
    let body = req.into_body();

    store
        .run_concurrent(async move |a| -> wasmtime::Result<()> {
            let requests =
                a.with(|mut s| StreamReader::new(&mut s, Deframe::new(body, verdict.clone())))?;
            let (replies, outcome) = guest
                .enclave_rpc_service()
                .call_call(a, method, requests)
                .await?;

            // Capacity of one, plus one in flight: a client that stops reading stops the guest's
            // next write, rather than the runtime buffering for it.
            let (replies_tx, replies_rx) = mpsc::channel(0);
            let (outcome_tx, outcome_rx) = tokio::sync::oneshot::channel();
            let (status_tx, status_rx) = tokio::sync::oneshot::channel();
            a.with(|mut s| -> wasmtime::Result<()> {
                replies.pipe(&mut s, Replies(replies_tx))?;
                outcome.pipe(&mut s, Outcome(Some(outcome_tx)))?;
                Ok(())
            })?;

            let _ = head.send(Ok(response(GrpcBody {
                replies: replies_rx,
                status: Some(status_rx),
                verdict,
            })));

            // Waiting here is what keeps the event loop, and so the streams, running.
            if let Ok(outcome) = outcome_rx.await {
                let _ = status_tx.send(outcome);
            }
            Ok(())
        })
        .await?
}

fn response(body: GrpcBody) -> hyper::Response<HyperOutgoingBody> {
    use http_body_util::BodyExt;
    hyper::Response::builder()
        .status(hyper::StatusCode::OK)
        .header("content-type", "application/grpc+proto")
        // Load-bearing on HTTP/1.1, where hyper's encoder drops trailers it was not told to
        // expect. Harmless on HTTP/2.
        .header("trailer", "grpc-status, grpc-message")
        .body(body.boxed_unsync())
        .expect("response is well formed")
}

/// The request body, as the guest's stream of messages.
struct Deframe<B> {
    body: B,
    buffer: BytesMut,
    ended: bool,
    verdict: Verdict,
}

impl<B> Deframe<B> {
    fn new(body: B, verdict: Verdict) -> Self {
        Deframe {
            body,
            buffer: BytesMut::new(),
            ended: false,
            verdict,
        }
    }

    fn refuse(&self, code: u32, why: impl Into<String>) -> Poll<wasmtime::Result<StreamResult>> {
        *self.verdict.lock().unwrap() = Some(status(code, why));
        Poll::Ready(Ok(StreamResult::Dropped))
    }
}

impl<B, D> StreamProducer<D> for Deframe<B>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<ErrorCode>,
{
    type Item = Vec<u8>;
    type Buffer = Option<Vec<u8>>;

    fn poll_produce<'a>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut store: StoreContextMut<'a, D>,
        mut destination: Destination<'a, Vec<u8>, Option<Vec<u8>>>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        let this = self.get_mut();
        loop {
            match next_message(&this.buffer) {
                // A guest asking only whether a message is ready is told yes without being handed
                // one it might never read.
                Ok(Some(_)) if destination.remaining(&mut store) == Some(0) => {
                    return Poll::Ready(Ok(StreamResult::Completed))
                }
                Ok(Some(message)) => {
                    // Split off only now, so a zero-length read leaves it where it was.
                    let _ = this.buffer.split_to(5);
                    let message = this.buffer.split_to(message).to_vec();
                    destination.set_buffer(Some(message));
                    return Poll::Ready(Ok(StreamResult::Completed));
                }
                Ok(None) => {}
                Err(malformed) => return this.refuse(INVALID_ARGUMENT, malformed),
            }
            if this.ended {
                // An end between messages is a half-close. An end with bytes stranded is a
                // message cut off, and reporting OK for it would tell the client its last message
                // arrived when it did not.
                if !this.buffer.is_empty() {
                    return this.refuse(
                        INVALID_ARGUMENT,
                        "the stream ended part-way through a message",
                    );
                }
                return Poll::Ready(Ok(StreamResult::Dropped));
            }
            match Pin::new(&mut this.body).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    // Request trailers: gRPC clients send none, and nothing here would use them.
                    if let Ok(data) = frame.into_data() {
                        this.buffer.extend_from_slice(&data);
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    let e: ErrorCode = e.into();
                    return this.refuse(UNAVAILABLE, format!("reading the request body: {e:?}"));
                }
                Poll::Ready(None) => this.ended = true,
                Poll::Pending if finish => return Poll::Ready(Ok(StreamResult::Cancelled)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// The length of the next complete message at the front of `buffer`, if one has fully arrived.
/// `None` means "not yet", not "never".
fn next_message(buffer: &BytesMut) -> Result<Option<usize>, String> {
    if buffer.len() < 5 {
        return Ok(None);
    }
    if buffer[0] != 0 {
        return Err("compressed frames are not accepted".into());
    }
    let len = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
    if len > MAX_MESSAGE_BYTES {
        return Err(format!(
            "a {len} byte message exceeds the {MAX_MESSAGE_BYTES} byte limit"
        ));
    }
    if buffer.len() < 5 + len {
        return Ok(None);
    }
    Ok(Some(len))
}

/// One message, framed.
fn frame(message: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(5 + message.len());
    out.put_u8(0);
    out.put_u32(message.len() as u32);
    out.put_slice(message);
    out.freeze()
}

/// The guest's replies, handed to the response body one at a time.
struct Replies(mpsc::Sender<Vec<u8>>);

impl<D> StreamConsumer<D> for Replies {
    type Item = Vec<u8>;

    fn poll_consume(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut store: StoreContextMut<D>,
        mut source: Source<'_, Vec<u8>>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        match self.0.poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let mut one = None;
                source.read(&mut store, &mut one)?;
                if let Some(message) = one {
                    // Room was just reserved, so this only fails if the client went away.
                    let _ = self.0.start_send(message);
                }
                Poll::Ready(Ok(StreamResult::Completed))
            }
            // The client went away: the guest's next write learns the stream is gone.
            Poll::Ready(Err(_)) => Poll::Ready(Ok(StreamResult::Dropped)),
            Poll::Pending if finish => Poll::Ready(Ok(StreamResult::Cancelled)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// The guest's status, once it writes one.
struct Outcome(Option<tokio::sync::oneshot::Sender<Result<(), Status>>>);

impl<D> FutureConsumer<D> for Outcome {
    type Item = Result<(), Status>;

    fn poll_consume(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        mut store: StoreContextMut<D>,
        mut source: Source<'_, Self::Item>,
        _: bool,
    ) -> Poll<wasmtime::Result<()>> {
        let mut value = None;
        source.read(&mut store, &mut value)?;
        if let (Some(tx), Some(value)) = (self.0.take(), value) {
            let _ = tx.send(value);
        }
        Poll::Ready(Ok(()))
    }
}

/// The response body: every reply framed, then the status as trailers.
struct GrpcBody {
    replies: mpsc::Receiver<Vec<u8>>,
    /// `None` once the trailers have gone out.
    status: Option<tokio::sync::oneshot::Receiver<Result<(), Status>>>,
    verdict: Verdict,
}

impl Body for GrpcBody {
    type Data = Bytes;
    type Error = ErrorCode;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, ErrorCode>>> {
        use std::future::Future;
        let this = self.get_mut();
        let Some(status) = &mut this.status else {
            return Poll::Ready(None);
        };
        // Every reply goes out before the status does.
        match Pin::new(&mut this.replies).poll_next(cx) {
            Poll::Ready(Some(message)) => {
                return Poll::Ready(Some(Ok(Frame::data(frame(&message)))))
            }
            Poll::Ready(None) => {}
            Poll::Pending => return Poll::Pending,
        }
        let outcome = match Pin::new(status).poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(outcome) => outcome,
        };
        this.status = None;
        match outcome {
            Ok(guest) => {
                let outcome = match this.verdict.lock().unwrap().take() {
                    Some(transport) => Err(transport),
                    None => guest,
                };
                Poll::Ready(Some(Ok(Frame::trailers(trailers(&outcome)))))
            }
            // The guest trapped or was abandoned before saying how the call went. Ending the body
            // cleanly would read as a success, so it is cut off instead.
            Err(_) => Poll::Ready(Some(Err(ErrorCode::InternalError(Some(
                "the guest ended the call without a status".into(),
            ))))),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.status.is_none()
    }
}

/// gRPC reports its real outcome here, never in the HTTP status.
fn trailers(outcome: &Result<(), Status>) -> hyper::HeaderMap {
    let (code, message) = match outcome {
        Ok(()) => (OK, ""),
        Err(s) => (s.code, s.message.as_str()),
    };
    let mut trailers = hyper::HeaderMap::new();
    trailers.insert("grpc-status", code.into());
    if !message.is_empty() {
        // The one field here carrying anything dynamic, and a stray newline would end the header
        // early.
        let sanitized: String = message
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        if let Ok(value) = sanitized.parse() {
            trailers.insert("grpc-message", value);
        }
    }
    trailers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn take(buffer: &mut BytesMut) -> Option<Vec<u8>> {
        let len = next_message(buffer).unwrap()?;
        let _ = buffer.split_to(5);
        Some(buffer.split_to(len).to_vec())
    }

    #[test]
    fn a_message_split_across_reads_is_reassembled() {
        let whole = frame(b"hello world");
        let mut buffer = BytesMut::new();
        // Three reads, none of them on a frame boundary.
        buffer.extend_from_slice(&whole[..3]);
        assert_eq!(take(&mut buffer), None);
        buffer.extend_from_slice(&whole[3..9]);
        assert_eq!(take(&mut buffer), None);
        buffer.extend_from_slice(&whole[9..]);
        assert_eq!(take(&mut buffer).as_deref(), Some(&b"hello world"[..]));
        assert_eq!(take(&mut buffer), None);
        assert!(buffer.is_empty());
    }

    #[test]
    fn several_messages_in_one_read_all_come_out() {
        let mut buffer = BytesMut::new();
        for m in [&b"one"[..], b"two", b"three"] {
            buffer.extend_from_slice(&frame(m));
        }
        assert_eq!(take(&mut buffer).as_deref(), Some(&b"one"[..]));
        assert_eq!(take(&mut buffer).as_deref(), Some(&b"two"[..]));
        assert_eq!(take(&mut buffer).as_deref(), Some(&b"three"[..]));
        assert_eq!(take(&mut buffer), None);
    }

    /// A truncated frame stays in the buffer rather than being reported as absent: the difference
    /// is what tells a half-close from a cut-off message.
    #[test]
    fn a_truncated_frame_is_held_not_dropped() {
        let mut buffer = BytesMut::from(&frame(b"hello")[..7]);
        assert_eq!(take(&mut buffer), None);
        assert!(!buffer.is_empty());
    }

    #[test]
    fn compression_and_oversize_are_refused() {
        assert!(next_message(&BytesMut::from(&[1u8, 0, 0, 0, 1, 0xff][..])).is_err());
        let mut head = BytesMut::from(&[0u8][..]);
        head.extend_from_slice(&((MAX_MESSAGE_BYTES + 1) as u32).to_be_bytes());
        assert!(next_message(&head).is_err());
    }

    #[test]
    fn the_message_is_sanitised_and_a_status_always_sent() {
        let ok = trailers(&Ok(()));
        assert_eq!(ok.get("grpc-status").unwrap(), "0");
        assert!(ok.get("grpc-message").is_none());
        let refused = trailers(&Err(status(7, "no\nsigning")));
        assert_eq!(refused.get("grpc-status").unwrap(), "7");
        assert_eq!(refused.get("grpc-message").unwrap(), "no signing");
    }
}
