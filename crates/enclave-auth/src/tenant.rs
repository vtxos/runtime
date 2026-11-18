//! A tenant's id: `sha256("aegira/tenant/v1" ‖ X)[..16]`.
//!
//! From the group key `X` rather than either share, so it survives a change of shares. Every
//! tenant's record and pool is named by it, so changing it strands them all.

use sha2::{Digest, Sha256};

/// The tenant whose wallet key is `group_key` (compressed, even-Y).
pub fn tenant_of(group_key: &[u8; 33]) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(b"aegira/tenant/v1")
        .chain_update(group_key)
        .finalize();
    digest[..16].try_into().expect("16 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vector `docs/CLIENT_INTEGRATION.md` publishes: `X = 7·G`.
    #[test]
    fn the_id_is_pinned() {
        let seven_g =
            hex::decode("025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc")
                .unwrap();
        assert_eq!(
            hex::encode(tenant_of(&seven_g.try_into().unwrap())),
            "ecf80fb854cd261687d9881a8b6498ec"
        );
    }
}
