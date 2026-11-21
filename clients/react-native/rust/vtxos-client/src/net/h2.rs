//! HTTP/2 to the enclave, over the connection [`super::tls`] made.

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{Error, Result};

/// A request's body on this connection. It cannot fail: what is sent is already in memory.
pub type Body = UnsyncBoxBody<Bytes, std::convert::Infallible>;

/// HTTP/2 over `io`, its connection driven in the background.
pub(crate) async fn handshake<IO>(io: IO, peer: &str) -> Result<SendRequest<Body>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (send, driver) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
            .await
            .map_err(|e| Error::Transport(format!("HTTP/2 with {peer}: {e}")))?;
    tokio::spawn(driver);
    Ok(send)
}
