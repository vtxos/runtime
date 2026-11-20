//! A call's messages, as `async fn`s the ceremonies read like a script.
//!
//! The runtime ends gRPC (`enclave:rpc/service`), so what reaches the cosigner is already one
//! protobuf message at a time, in order, and what it hands back is framed by the runtime. A
//! [`Wire`] is that pair of streams. In a release it is the export's own two; in tests it is a
//! queue, which is the only reason this is a trait.
//!
//! [`Duplex`] is what a ceremony holds: typed messages over a wire. `send` queues and returns, and
//! the queue goes out before the next read and when the ceremony ends, whichever way it ends, so a
//! reply is never lost behind an error.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;

use prost::Message as ProstMessage;

use crate::status::Status;

/// A future borrowed from the wire it reads or writes.
pub type WireFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// One call's messages, already deframed.
pub trait Wire {
    /// The next message, or `None` once the client has half-closed.
    fn recv(&mut self) -> WireFuture<'_, Option<Vec<u8>>>;

    /// Hand one message on. A client that has gone away is found out at the next `recv`.
    fn send(&mut self, message: Vec<u8>) -> WireFuture<'_, ()>;
}

/// A ceremony's end of a call: `Req`s in, `Resp`s out.
pub struct Duplex<Req, Resp> {
    /// Taken while a read or write is in flight, so no borrow is held across an await.
    wire: Cell<Option<Box<dyn Wire>>>,
    outbound: RefCell<VecDeque<Vec<u8>>>,
    _messages: PhantomData<fn(Req) -> Resp>,
}

impl<Req: ProstMessage + Default, Resp: ProstMessage> Duplex<Req, Resp> {
    pub fn new(wire: Box<dyn Wire>) -> Self {
        Self {
            wire: Cell::new(Some(wire)),
            outbound: RefCell::new(VecDeque::new()),
            _messages: PhantomData,
        }
    }

    /// Queue one message. Not async: a ceremony never blocks on a slow reader mid-round, and the
    /// queue is sent before the next read.
    pub fn send(&self, msg: Resp) {
        self.outbound.borrow_mut().push_back(msg.encode_to_vec());
    }

    /// Send everything queued.
    pub async fn flush(&self) {
        let mut wire = self.take();
        loop {
            let next = self.outbound.borrow_mut().pop_front();
            match next {
                Some(message) => wire.send(message).await,
                None => break,
            }
        }
        self.wire.set(Some(wire));
    }

    /// The next message, or `None` if the client half-closed. What was queued goes out first.
    pub async fn recv(&self) -> Result<Option<Req>, Status> {
        self.flush().await;
        let mut wire = self.take();
        let next = wire.recv().await;
        self.wire.set(Some(wire));
        next.map(|bytes| {
            Req::decode(bytes.as_slice())
                .map_err(|e| Status::invalid_argument(format!("undecodable message: {e}")))
        })
        .transpose()
    }

    /// The next message, or a `cancelled` status naming what the ceremony was waiting for.
    ///
    /// Every round in every ceremony needs this, and the message matters: "stream closed before
    /// the share arrived" tells an operator which round died, where a bare cancellation does not.
    pub async fn expect(&self, what: &str) -> Result<Req, Status> {
        self.recv()
            .await?
            .ok_or_else(|| Status::cancelled(format!("stream closed before {what}")))
    }

    /// A unary call's one message: exactly one, then the client's close.
    pub async fn only(&self) -> Result<Req, Status> {
        let req = self
            .recv()
            .await?
            .ok_or_else(|| Status::invalid_argument("the request carried no message"))?;
        match self.recv().await? {
            None => Ok(req),
            Some(_) => Err(Status::invalid_argument(
                "a unary call carried more than one message",
            )),
        }
    }

    fn take(&self) -> Box<dyn Wire> {
        self.wire
            .take()
            .expect("a ceremony reads and writes one message at a time")
    }
}

/// A stream message whose payload is a `oneof body`, as every client message here is.
pub trait HasBody {
    type Body;

    fn into_body(self) -> Option<Self::Body>;
}

impl<Req: ProstMessage + Default + HasBody, Resp: ProstMessage> Duplex<Req, Resp> {
    /// The next message's body: [`expect`](Self::expect), and refused if the message is empty.
    pub async fn next_body(&self, what: &str) -> Result<Req::Body, Status> {
        let empty = || Status::invalid_argument(format!("an empty message where {what} belonged"));
        self.expect(what).await?.into_body().ok_or_else(empty)
    }
}
