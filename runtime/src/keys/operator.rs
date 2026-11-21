//! The operator master: the 32 bytes each tenant's cosigner polynomial is derived from, and the
//! runtime's share of each wallet key is sealed under.
//!
//! The operator writes it as an SSM `SecureString` once the enclave is up, and the runtime reads
//! it the first time a registration or a sign-in needs it, then keeps it in memory. Until it is
//! there, those are answered as unavailable and the read is tried again on the next one.
//!
//! What holding it gives, with the roots bucket: the runtime's share of every wallet key
//! ([`crate::signer`]). That share is the operator's, and it signs nothing and opens no pool
//! alone — both need the owner's share too. Every release reads the same master, so nothing
//! moves between releases; and it must never be lost or changed, since every runtime share is
//! sealed under it.

use anyhow::{Context, Result};
use tokio::sync::OnceCell;
use zeroize::Zeroizing;

pub struct OperatorMaster {
    /// Where it is read from. `None` for a master fixed by configuration.
    ssm: Option<(aws_sdk_ssm::Client, String)>,
    value: OnceCell<Zeroizing<[u8; 32]>>,
}

impl OperatorMaster {
    pub(super) fn ssm(client: aws_sdk_ssm::Client, parameter: String) -> Self {
        OperatorMaster {
            ssm: Some((client, parameter)),
            value: OnceCell::new(),
        }
    }

    /// A master from configuration, for the emulator and the tests.
    #[cfg(any(test, feature = "testing"))]
    pub fn fixed(master: [u8; 32]) -> Self {
        OperatorMaster {
            ssm: None,
            value: OnceCell::new_with(Some(Zeroizing::new(master))),
        }
    }

    /// The master, read on first use and kept. An error means it is not there yet, or could not
    /// be read; the next call tries again.
    pub async fn get(&self) -> Result<&[u8; 32]> {
        let value = self
            .value
            .get_or_try_init(|| async {
                let (client, parameter) = self
                    .ssm
                    .as_ref()
                    .context("a fixed operator master is always set")?;
                let out = client
                    .get_parameter()
                    .name(parameter)
                    .with_decryption(true)
                    .send()
                    .await
                    .with_context(|| format!("reading SSM parameter {parameter}"))?;
                let text = Zeroizing::new(
                    out.parameter()
                        .and_then(|p| p.value())
                        .with_context(|| format!("SSM parameter {parameter} has no value"))?
                        .to_string(),
                );
                parse(&text)
            })
            .await?;
        Ok(value)
    }
}

/// 64 hex characters.
pub(super) fn parse(hex: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(hex.trim(), &mut out[..])
        .context("the operator master must be 64 hex characters")?;
    Ok(out)
}

impl std::fmt::Debug for OperatorMaster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorMaster")
            .field("parameter", &self.ssm.as_ref().map(|(_, p)| p))
            .field("read", &self.value.initialized())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_master_is_64_hex_characters() {
        assert_eq!(*parse(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        assert_eq!(*parse(&format!(" {}\n", "01".repeat(32))).unwrap(), [1; 32]);
        assert!(parse(&"ab".repeat(31)).is_err());
        assert!(parse(&"zz".repeat(32)).is_err());
    }

    #[tokio::test]
    async fn a_fixed_master_needs_no_read() {
        let master = OperatorMaster::fixed([7; 32]);
        assert_eq!(master.get().await.unwrap(), &[7; 32]);
    }
}
