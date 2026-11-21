//! Calls to whatever the enclave runs, as bytes.
//!
//! A [`Session`] is an enclave and an open key. [`Session::call`] and [`Session::stream`] each make
//! the whole trip: the attested connection, a sign-in for exactly that method, and the gRPC call
//! with the token the sign-in returned. What the messages mean is the caller's: nothing here looks
//! inside one, so any policy can be called, whatever it speaks.
//!
//! One call at a time. The enclave holds a wallet's lock for a call's whole life, so a second call
//! would only wait there; it waits here instead, and a stream holds its turn until it ends.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bytes::{BufMut, Bytes, BytesMut};
use enclave_auth::client::Client;
use http::{header, Method, Request};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use tokio::sync::{mpsc, watch, OwnedMutexGuard};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;

use super::enclave::Enclave;
use crate::error::{Error, Result};

/// The largest message either side may send: the enclave's own limit.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

type Head = Pin<Box<dyn Future<Output = hyper::Result<http::Response<Incoming>>> + Send>>;

/// An enclave and an open key: what a call is made with.
pub struct Session {
    enclave: Arc<Enclave>,
    client: Client,
    turn: Arc<tokio::sync::Mutex<()>>,
}

impl Session {
    pub fn new(enclave: Arc<Enclave>, client: Client) -> Self {
        Session {
            enclave,
            client,
            turn: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// The open key: what [`crate::core::frost::answer`] signs a round with.
    pub fn key(&self) -> &Client {
        &self.client
    }

    /// One message each way: `request` to `method`, and its one reply.
    pub async fn call(&self, method: &str, request: &[u8]) -> Result<Vec<u8>> {
        let stream = self.stream(method).await?;
        stream.send(request).await?;
        stream.finish();
        let reply = stream
            .next()
            .await?
            .ok_or_else(|| Error::Protocol(format!("{method} answered with no message")))?;
        match stream.next().await? {
            None => Ok(reply),
            Some(_) => {
                stream.cancel();
                Err(Error::Protocol(format!(
                    "{method} answered with more than one message: open it as a stream"
                )))
            }
        }
    }

    /// Open `method` for messages both ways. `method` is the call's path, by gRPC's habit
    /// `/package.Service/Method`.
    pub async fn stream(&self, method: &str) -> Result<Stream> {
        if !method.starts_with('/') {
            return Err(Error::Protocol(format!(
                "a method is a path, and {method:?} does not start with /"
            )));
        }
        // The turn before the sign-in: a token lasts a minute, and must not spend it waiting.
        let turn = self.turn.clone().lock_owned().await;
        let (connection, token) = self.enclave.sign_in(&self.client, method).await?;

        let (outbound, frames) = mpsc::channel::<Bytes>(1);
        let body = StreamBody::new(
            ReceiverStream::new(frames)
                .map(Frame::data)
                .map(Ok::<_, std::convert::Infallible>),
        )
        .boxed_unsync();
        let request = Request::builder()
            .method(Method::POST)
            .uri(connection.uri(method)?)
            .header(header::CONTENT_TYPE, "application/grpc")
            .header(header::TE, "trailers")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(body)
            .map_err(|e| Error::Protocol(format!("{method}: {e}")))?;
        // Sent now, answered whenever the enclave answers: the head is not waited for here, so a
        // policy that reads before it replies is not kept waiting for a message nobody could send.
        let (mut send, _) = connection.parts();
        let head: Head = Box::pin(send.send_request(request));

        let (cancel, _) = watch::channel(false);
        Ok(Stream {
            outbound: Mutex::new(Some(outbound)),
            inbound: tokio::sync::Mutex::new(Inbound {
                method: method.to_string(),
                head: Some(head),
                body: None,
                buffer: BytesMut::new(),
                over: false,
            }),
            turn: Mutex::new(Some(turn)),
            cancel,
        })
    }
}

/// One call, open: messages out with [`Stream::send`], replies in with [`Stream::next`].
pub struct Stream {
    /// The request body's other end. `None` once the caller has finished or the call is over.
    outbound: Mutex<Option<mpsc::Sender<Bytes>>>,
    inbound: tokio::sync::Mutex<Inbound>,
    /// This call's turn, given back when the call is over.
    turn: Mutex<Option<OwnedMutexGuard<()>>>,
    cancel: watch::Sender<bool>,
}

struct Inbound {
    method: String,
    /// The response, until its head has arrived.
    head: Option<Head>,
    body: Option<Incoming>,
    buffer: BytesMut,
    /// The status has been read, or the call was dropped: nothing more will come.
    over: bool,
}

impl Stream {
    /// Send one message. Waits until the connection has taken it.
    pub async fn send(&self, message: &[u8]) -> Result<()> {
        if message.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Protocol(format!(
                "a {} byte message exceeds the {MAX_MESSAGE_BYTES} byte limit",
                message.len()
            )));
        }
        let outbound = self.outbound.lock().unwrap().clone();
        let outbound = outbound.ok_or_else(|| {
            Error::Protocol("the call is finished: nothing more can be sent".into())
        })?;
        let mut frame = BytesMut::with_capacity(5 + message.len());
        frame.put_u8(0);
        frame.put_u32(message.len() as u32);
        frame.put_slice(message);
        outbound
            .send(frame.freeze())
            .await
            .map_err(|_| Error::Transport("the enclave closed the call".into()))
    }

    /// No more messages from this side. The enclave may still reply.
    pub fn finish(&self) {
        self.outbound.lock().unwrap().take();
    }

    /// The next reply, or `None` once the enclave has ended the call well. A call the enclave
    /// ended with an error is [`Error::Status`].
    pub async fn next(&self) -> Result<Option<Vec<u8>>> {
        let mut cancelled = self.cancel.subscribe();
        let mut inbound = self.inbound.lock().await;
        if *cancelled.borrow() {
            return Err(Error::Transport("the call was cancelled".into()));
        }
        let next = tokio::select! {
            next = inbound.next() => next,
            _ = cancelled.changed() => {
                inbound.close();
                Err(Error::Transport("the call was cancelled".into()))
            }
        };
        if !matches!(next, Ok(Some(_))) {
            inbound.close();
            drop(inbound);
            self.over();
        }
        next
    }

    /// Abandon the call. The enclave sees it go, and frees the wallet for the next one.
    pub fn cancel(&self) {
        // `send_replace`: `send` stores nothing when no read is subscribed, and a read that starts
        // after this must still find the call cancelled.
        self.cancel.send_replace(true);
        // If no read is waiting, the response is dropped here; one that is waiting drops it.
        if let Ok(mut inbound) = self.inbound.try_lock() {
            inbound.close();
        }
        self.over();
    }

    fn over(&self) {
        self.outbound.lock().unwrap().take();
        self.turn.lock().unwrap().take();
    }
}

impl Inbound {
    fn close(&mut self) {
        self.over = true;
        self.head = None;
        self.body = None;
        self.buffer.clear();
    }

    async fn next(&mut self) -> Result<Option<Vec<u8>>> {
        if self.over {
            return Ok(None);
        }
        if let Some(head) = self.head.as_mut() {
            let response = head
                .await
                .map_err(|e| Error::Transport(format!("{}: {e}", self.method)))?;
            self.head = None;
            let (parts, body) = response.into_parts();
            if !parts.status.is_success() {
                // Not gRPC's answer but the gate's: no token, a spent one, or one for another
                // method.
                let message = body
                    .collect()
                    .await
                    .map(|b| b.to_bytes())
                    .unwrap_or_default();
                return Err(Error::Auth {
                    status: parts.status.as_u16(),
                    message: String::from_utf8_lossy(&message).into_owned(),
                });
            }
            // A call refused outright carries its status in the head and has no body.
            if let Some(status) = status(&parts.headers) {
                self.over = true;
                return status.map(|()| None);
            }
            self.body = Some(body);
        }
        loop {
            if let Some(message) = self.take_message()? {
                return Ok(Some(message));
            }
            let body = self
                .body
                .as_mut()
                .ok_or_else(|| Error::Protocol("the call is over".into()))?;
            match body.frame().await {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => self.buffer.extend_from_slice(&data),
                    Err(frame) => {
                        if let Ok(trailers) = frame.into_trailers() {
                            self.over = true;
                            return match status(&trailers) {
                                Some(status) => status.map(|()| None),
                                None => Err(Error::Protocol(format!(
                                    "{} ended without a status",
                                    self.method
                                ))),
                            };
                        }
                    }
                },
                Some(Err(e)) => return Err(Error::Transport(format!("{}: {e}", self.method))),
                None => {
                    return Err(Error::Protocol(format!(
                        "{} ended without a status",
                        self.method
                    )))
                }
            }
        }
    }

    /// One whole message off the front of the buffer, if one has arrived.
    fn take_message(&mut self) -> Result<Option<Vec<u8>>> {
        if self.buffer.len() < 5 {
            return Ok(None);
        }
        if self.buffer[0] != 0 {
            return Err(Error::Protocol(format!(
                "{} sent a compressed message, which is not accepted",
                self.method
            )));
        }
        let len = u32::from_be_bytes([
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
            self.buffer[4],
        ]) as usize;
        if len > MAX_MESSAGE_BYTES {
            return Err(Error::Protocol(format!(
                "{} sent a {len} byte message, over the {MAX_MESSAGE_BYTES} byte limit",
                self.method
            )));
        }
        if self.buffer.len() < 5 + len {
            return Ok(None);
        }
        let _ = self.buffer.split_to(5);
        Ok(Some(self.buffer.split_to(len).to_vec()))
    }
}

/// The call's status, if these headers carry one: `Ok` for 0, [`Error::Status`] for anything else.
fn status(headers: &http::HeaderMap) -> Option<Result<()>> {
    let code: u32 = headers
        .get("grpc-status")?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()?;
    if code == 0 {
        return Some(Ok(()));
    }
    let message = headers
        .get("grpc-message")
        .map(|m| percent_decode(m.as_bytes()))
        .unwrap_or_default();
    Some(Err(Error::Status { code, message }))
}

/// gRPC percent-encodes `grpc-message`. Anything that is not a valid escape is kept as it is.
fn percent_decode(raw: &[u8]) -> String {
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match (
            raw[i],
            raw.get(i + 1).copied().and_then(hex),
            raw.get(i + 2).copied().and_then(hex),
        ) {
            (b'%', Some(high), Some(low)) => {
                out.push(high << 4 | low);
                i += 3;
            }
            (byte, _, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inbound(bytes: &[u8]) -> Inbound {
        Inbound {
            method: "/t.T/M".into(),
            head: None,
            body: None,
            buffer: BytesMut::from(bytes),
            over: false,
        }
    }

    #[test]
    fn messages_come_off_the_buffer_whole_and_in_order() {
        let mut i = inbound(&[
            0, 0, 0, 0, 2, b'h', b'i', 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, b'x',
        ]);
        assert_eq!(i.take_message().unwrap().as_deref(), Some(&b"hi"[..]));
        assert_eq!(i.take_message().unwrap().as_deref(), Some(&b""[..]));
        // The third is cut short: not yet, rather than an error.
        assert_eq!(i.take_message().unwrap(), None);
    }

    #[test]
    fn a_compressed_or_oversized_message_is_refused() {
        assert!(inbound(&[1, 0, 0, 0, 0]).take_message().is_err());
        assert!(inbound(&[0, 0xff, 0xff, 0xff, 0xff])
            .take_message()
            .is_err());
    }

    #[test]
    fn a_status_is_read_from_headers_with_its_message_decoded() {
        let mut headers = http::HeaderMap::new();
        assert!(status(&headers).is_none());
        headers.insert("grpc-status", "0".parse().unwrap());
        assert!(matches!(status(&headers), Some(Ok(()))));
        headers.insert("grpc-status", "7".parse().unwrap());
        headers.insert("grpc-message", "over%20the limit 100%".parse().unwrap());
        match status(&headers) {
            Some(Err(Error::Status { code: 7, message })) => {
                assert_eq!(message, "over the limit 100%")
            }
            other => panic!("{other:?}"),
        }
    }
}
