//! What can go wrong, by whose fault: the enclave's proof, the connection, the sign-in, the
//! enclave's answer, the passkey, or a message that does not follow the protocol.

/// One error type for every call, so the bindings carry one.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The attestation document does not verify under the pins.
    #[error("the enclave's attestation does not check out: {0}")]
    Attestation(String),
    /// The connection served a certificate other than the one the attestation named.
    #[error("the enclave served a certificate it did not attest: {0}")]
    Pinning(String),
    /// A sign-in or registration was refused.
    #[error("refused ({status}): {message}")]
    Auth { status: u16, message: String },
    /// A call the enclave ended with an error: gRPC's status code, and what the policy said.
    #[error("the enclave answered {code}: {message}")]
    Status { code: u32, message: String },
    /// The passkey's PRF output does not rebuild this wallet's share.
    #[error("this passkey does not open this wallet")]
    WrongPasskey,
    /// A message that does not follow the protocol, from either side.
    #[error("{0}")]
    Protocol(String),
    /// The network: connecting, TLS, HTTP/2.
    #[error("connection: {0}")]
    Transport(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
