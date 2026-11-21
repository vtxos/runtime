//! A guest's bindings to the runtime, generated from the WIT beside this file.
//!
//! The world is `enclave:guest/guest`: export `enclave:rpc/service` and `run-task`, import
//! anything the runtime offers. An import the guest never calls is not an import of its
//! component.
//!
//! A guest implements the exports and hands them over with [`export!`]:
//!
//! ```ignore
//! struct Guest;
//! impl enclave_wit::exports::enclave::rpc::service::Guest for Guest { /* call */ }
//! impl enclave_wit::Guest for Guest { /* run_task */ }
//! enclave_wit::export!(Guest);
//! ```

pub use bindings::*;

/// In a module of its own: generated at the crate root, the public export macro collides with the
/// re-export wit-bindgen also emits for it.
pub mod bindings {
    wit_bindgen::generate!({
        // Dependencies first: each package resolves against the ones already read.
        path: ["tasks", "notify", "signer", "telemetry", "rpc", "guest"],
        world: "enclave:guest/guest",
        generate_all,
        pub_export_macro: true,
        default_bindings_module: "enclave_wit::bindings",
    });
}
