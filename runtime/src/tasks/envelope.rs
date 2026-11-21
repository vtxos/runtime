//! A task as it is kept outside the enclave: signed with its tenant's task key, its payload sealed
//! to it.
//!
//! The table, the scheduler and the queue are all writable by the parent instance, whose role the
//! enclave borrows. So nothing read back from them is believed until it verifies here: a task is
//! run only if its tenant's key signed it, and only that key opens what it carries. The keys are
//! the pool's, from the tenant's key ([`crate::tenant::TaskKeys`]), so a task outlives a
//! restart and a new release, and is opened by whichever release its owner has approved.

use anyhow::{anyhow, ensure, Context, Result};
use aws_lc_rs::signature::{KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

use crate::store::crypto::seal::{seal, unseal};
use crate::store::crypto::ED25519_SIGNATURE_LEN;
use crate::tenant::TaskKeys;

/// Everything the enclave relies on when it runs a task. Signed whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u32,
    pub tenant: [u8; 16],
    pub id: String,
    pub generation: [u8; 16],
    pub run_at: u64,
    pub interval_ms: Option<u64>,
    pub created_at: u64,
    /// The guest's payload, sealed to the tenant's task key.
    pub payload: Vec<u8>,
}

/// What a task is, without its payload: what [`Envelope::seal`] signs over.
pub struct Draft<'a> {
    pub tenant: [u8; 16],
    pub id: &'a str,
    pub generation: [u8; 16],
    pub run_at: u64,
    pub interval_ms: Option<u64>,
    pub created_at: u64,
}

impl Envelope {
    /// Seal `payload` and sign the whole: the bytes to store, `body ‖ signature`.
    pub fn seal(keys: &TaskKeys, draft: Draft<'_>, payload: &[u8]) -> Result<Vec<u8>> {
        let aad = payload_aad(draft.tenant, draft.id, draft.generation);
        let envelope = Envelope {
            v: 1,
            tenant: draft.tenant,
            id: draft.id.to_string(),
            generation: draft.generation,
            run_at: draft.run_at,
            interval_ms: draft.interval_ms,
            created_at: draft.created_at,
            payload: seal(keys.seal_key(), &aad, payload)?,
        };
        let mut stored = Vec::new();
        ciborium::into_writer(&envelope, &mut stored).context("encoding a task")?;
        let signature = keys.signing_key().sign(&stored);
        stored.extend_from_slice(signature.as_ref());
        Ok(stored)
    }

    /// The task in `stored`, with its payload opened, if these keys made it. Anything else —
    /// forged, altered, another tenant's — is refused.
    pub fn open(keys: &TaskKeys, stored: &[u8]) -> Result<(Envelope, Vec<u8>)> {
        ensure!(
            stored.len() > ED25519_SIGNATURE_LEN,
            "a task too short to be signed"
        );
        let (body, signature) = stored.split_at(stored.len() - ED25519_SIGNATURE_LEN);
        UnparsedPublicKey::new(&ED25519, keys.signing_key().public_key().as_ref())
            .verify(body, signature)
            .map_err(|_| anyhow!("a task whose signature is not its tenant's"))?;
        let envelope: Envelope = ciborium::from_reader(body).context("decoding a task")?;
        ensure!(envelope.v == 1, "a task of unknown version {}", envelope.v);
        let payload = unseal(
            keys.seal_key(),
            &payload_aad(envelope.tenant, &envelope.id, envelope.generation),
            &envelope.payload,
        )?;
        Ok((envelope, payload))
    }
}

/// Seal one occurrence's result, which is kept beside the task.
pub fn seal_result(
    keys: &TaskKeys,
    tenant: [u8; 16],
    id: &str,
    generation: [u8; 16],
    occurrence: u64,
    result: &[u8],
) -> Result<Vec<u8>> {
    Ok(seal(
        keys.seal_key(),
        &result_aad(tenant, id, generation, occurrence),
        result,
    )?)
}

/// The result [`seal_result`] sealed, for the same occurrence.
pub fn open_result(
    keys: &TaskKeys,
    tenant: [u8; 16],
    id: &str,
    generation: [u8; 16],
    occurrence: u64,
    sealed: &[u8],
) -> Result<Vec<u8>> {
    Ok(unseal(
        keys.seal_key(),
        &result_aad(tenant, id, generation, occurrence),
        sealed,
    )?)
}

fn payload_aad(tenant: [u8; 16], id: &str, generation: [u8; 16]) -> Vec<u8> {
    [
        b"aegira/task/payload\0".as_slice(),
        &tenant,
        &generation,
        id.as_bytes(),
    ]
    .concat()
}

fn result_aad(tenant: [u8; 16], id: &str, generation: [u8; 16], occurrence: u64) -> Vec<u8> {
    [
        b"aegira/task/result\0".as_slice(),
        &tenant,
        &generation,
        &occurrence.to_be_bytes(),
        id.as_bytes(),
    ]
    .concat()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenant::TenantKey;

    fn keys(b: u8) -> TaskKeys {
        TaskKeys::for_pool(&TenantKey::from_bytes([b; 32]), [1; 16], &[2; 16]).unwrap()
    }

    fn draft(id: &str) -> Draft<'_> {
        Draft {
            tenant: [7; 16],
            id,
            generation: [9; 16],
            run_at: 5_000,
            interval_ms: Some(60_000),
            created_at: 1_000,
        }
    }

    #[test]
    fn a_task_opens_with_its_own_keys() {
        let stored = Envelope::seal(&keys(1), draft("job"), b"top secret").unwrap();
        let (envelope, payload) = Envelope::open(&keys(1), &stored).unwrap();
        assert_eq!(payload, b"top secret");
        assert_eq!(envelope.id, "job");
        assert_eq!(envelope.run_at, 5_000);
        assert_eq!(envelope.interval_ms, Some(60_000));
        assert!(
            !stored.windows(10).any(|w| w == b"top secret"),
            "the payload is sealed"
        );
    }

    /// The host can write the table: a task it made, or one it changed, is refused.
    #[test]
    fn a_forged_or_altered_task_is_refused() {
        let stored = Envelope::seal(&keys(1), draft("job"), b"payload").unwrap();
        assert!(
            Envelope::open(&keys(2), &stored).is_err(),
            "another tenant's key"
        );
        for at in [0, stored.len() / 2, stored.len() - 1] {
            let mut altered = stored.clone();
            altered[at] ^= 1;
            assert!(Envelope::open(&keys(1), &altered).is_err(), "byte {at}");
        }
        assert!(Envelope::open(&keys(1), &stored[..10]).is_err());
    }

    #[test]
    fn a_result_opens_only_for_its_occurrence() {
        let k = keys(1);
        let sealed = seal_result(&k, [7; 16], "job", [9; 16], 3, b"done").unwrap();
        assert_eq!(
            open_result(&k, [7; 16], "job", [9; 16], 3, &sealed).unwrap(),
            b"done"
        );
        assert!(open_result(&k, [7; 16], "job", [9; 16], 4, &sealed).is_err());
        assert!(open_result(&k, [7; 16], "other", [9; 16], 3, &sealed).is_err());
    }
}
