//! The policy guest's service, `cosigner.v1.Cosigner`, over the enclave's attested connection.
//!
//! Every call is its own interaction: [`Enclave::sign_in`] for exactly `POST
//! /cosigner.v1.Cosigner/<Method>`, then the call on the connection that sign-in ran on, with its
//! token. A token is single use, so a client is made for one call and dropped.

use enclave_auth::client::Client;
use http::HeaderValue;

use crate::enclave::Enclave;
use crate::error::{Error, Result};
use crate::h2::Channel;
use crate::proto::guest::cosigner_client::CosignerClient;
use crate::proto::guest::{DeviceCountRequest, ForgetDeviceRequest, RegisterDeviceRequest};
use crate::proto::wallet::{GetServerInfoRequest, GetServerInfoResponse};

/// The guest's service, for one call: every request on it spends the same token, which the
/// runtime accepts once.
pub type Guest = CosignerClient<Channel>;

/// Signed in to `method` and ready to call it.
pub async fn guest(enclave: &Enclave, client: &Client, method: &str) -> Result<Guest> {
    let path = format!("/cosigner.v1.Cosigner/{method}");
    let (connection, token) = enclave.sign_in(client, &path).await?;
    let token = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|e| Error::Protocol(format!("a token that is not a header value: {e}")))?;
    let (send, origin) = connection.parts();
    Ok(CosignerClient::with_origin(
        Channel::new(send, Some(token)),
        origin,
    ))
}

/// A gRPC status from the guest, as an error.
pub(crate) fn status(call: &str, status: tonic::Status) -> Error {
    Error::Enclave(format!(
        "{call}: {} ({:?})",
        status.message(),
        status.code()
    ))
}

/// How many devices this wallet has enrolled for wakes.
pub async fn device_count(enclave: &Enclave, client: &Client) -> Result<u32> {
    let mut guest = guest(enclave, client, "DeviceCount").await?;
    let answer = guest
        .device_count(DeviceCountRequest {})
        .await
        .map_err(|s| status("DeviceCount", s))?;
    Ok(answer.into_inner().devices)
}

/// Enrol a push token, so background work can wake this phone.
pub async fn register_device(enclave: &Enclave, client: &Client, token: &str) -> Result<()> {
    let mut guest = guest(enclave, client, "RegisterDevice").await?;
    guest
        .register_device(RegisterDeviceRequest {
            token: token.to_string(),
        })
        .await
        .map_err(|s| status("RegisterDevice", s))?;
    Ok(())
}

/// Stop waking the phone that holds `token`.
pub async fn forget_device(enclave: &Enclave, client: &Client, token: &str) -> Result<()> {
    let mut guest = guest(enclave, client, "ForgetDevice").await?;
    guest
        .forget_device(ForgetDeviceRequest {
            token: token.to_string(),
        })
        .await
        .map_err(|s| status("ForgetDevice", s))?;
    Ok(())
}

/// What the guest says about itself.
pub async fn server_info(enclave: &Enclave, client: &Client) -> Result<GetServerInfoResponse> {
    let mut guest = guest(enclave, client, "GetServerInfo").await?;
    Ok(guest
        .get_server_info(GetServerInfoRequest {})
        .await
        .map_err(|s| status("GetServerInfo", s))?
        .into_inner())
}
