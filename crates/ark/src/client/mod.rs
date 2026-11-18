//! The sessions the policy guest drives — board, send, renew through a delegate — and the wire
//! types it relays. Transport-free and wasm-buildable: the caller talks to the ASP.

pub mod address;
pub mod batch;
mod info;
pub mod send;
mod sighashes;

/// arkd's ArkService and IndexerService messages (both `package ark.v1`, so one file). Prost
/// messages only: there is no transport here.
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/ark.v1.rs"));
}

// Re-exports for convenience.
pub use address::{
    ark_address, ark_address_script_pubkey_hex, boarding_address, parse_network,
    vtxo_script_pubkey_hex,
};
pub use info::{exit_delay_value, server_info, Info};
