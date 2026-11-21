//! The runtime's own random bytes come from the source boot installs. A file of its own, because
//! the source is installed once per process.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use nitro_nsm::fake::FakeNsm;
use rand_core::RngCore;

#[test]
fn the_runtimes_bytes_come_from_the_installed_source() {
    let nsm = Arc::new(FakeNsm::new());
    enclave_runtime::random::install(nsm.clone()).unwrap();

    let mut buf = [0u8; 32];
    enclave_runtime::random::fill(&mut buf);
    assert_eq!(nsm.calls.load(Ordering::SeqCst), 1);
    enclave_runtime::random::Rng.fill_bytes(&mut buf);
    assert_eq!(nsm.calls.load(Ordering::SeqCst), 2);

    assert!(
        enclave_runtime::random::install(Arc::new(FakeNsm::new())).is_err(),
        "a second source must not replace the first"
    );

    nsm.empty.store(true, Ordering::SeqCst);
    assert!(enclave_runtime::random::try_fill(&mut buf).is_err());
}
