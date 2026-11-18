//! The generated wire: the policy guest's service and arkd's, client stubs only.

/// `mpc_wallet.proto`: the shapes the guest's single-round calls and opens carry.
pub mod wallet {
    #![allow(clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/mpc_wallet.rs"));
}

/// `cosign_session.proto`, package `cosigner.v1`: the guest's service.
pub mod guest {
    #![allow(clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/cosigner.v1.rs"));
}

/// arkd's `ArkService` and `IndexerService` clients, over `ark::client::proto`'s messages.
pub mod arkd {
    #![allow(clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/arkd/ark.v1.rs"));
}
