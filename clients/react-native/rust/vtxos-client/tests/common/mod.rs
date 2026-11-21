//! What the suites against a guest share: the runtime in process, serving one of the example
//! guests, and the pins it gives a client.

use std::path::{Path, PathBuf};
use std::time::Duration;

use enclave_runtime::testing::Enclave as Harness;
use vtxos_client::net::Pins;

/// The runtime serving `examples/guest-<name>`: `GUEST_<NAME>_WASM`, or where
/// `scripts/build-guest.sh <name>` leaves it.
pub async fn harness(name: &str) -> Harness {
    let path = std::env::var_os(format!("GUEST_{}_WASM", name.to_uppercase()))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
                "../../../../examples/guest-{name}/target/wasm32-wasip2/release/guest-{name}.wasm"
            ))
        });
    let guest = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("{}: {e}; scripts/build-guest.sh {name}", path.display()));
    Harness::builder(guest)
        .start()
        .await
        .expect("the runtime starts")
}

pub fn pins(h: &Harness) -> Pins {
    Pins {
        trust_root: h.trust_root(),
        pcr0: h.pcr0().to_vec(),
        pcr16: h.pcr16().to_vec(),
        max_age: Duration::from_secs(300),
    }
}
