//! FROST signing inside the stream that needs it: the policy's half of one round, for every
//! message in a batch.
//!
//! A send and a renewal both stop for the wallet to sign sighashes the policy built. They used to
//! do it by opening a *second* stream — a nested `Sign` per sighash, while the outer stream sat
//! parked waiting for the result. That worked against a native server running many streams at
//! once, and cannot work inside enclave-runtime, which runs **one request per tenant for the whole
//! life of a stream**: the outer stream holds the tenant, the nested one waits for it, and nothing
//! moves until the interaction deadline kills both. That was measured, not inferred — a second call
//! blocks on a separate TCP connection just the same, so a second channel does not help either.
//!
//! So the round rides the stream it belongs to, and it gets cheaper for it. The nested form cost
//! two round trips per signature; this is one round trip for the whole batch, because the order
//! FROST needs is "both commitments before either share", not "the wallet commits first":
//!
//! ```text
//!   policy → sighashes + its commitment for each
//!   wallet   → its commitment + its share for each      (it has both commitments by now)
//!   policy → computes its shares, aggregates, carries on
//! ```
//!
//! What the wallet gives up is seeing the finished signature, which it used to verify. That was
//! never the protection it looked like: a share is bound to one message and one pair of
//! commitments, so the policy cannot aggregate it over anything else — it would simply not
//! verify. And the runtime checks every share against its verifying share before summing, so a bad
//! wallet share is refused there rather than by the ASP.
//!
//! **The policy's half is the runtime's.** Its share, its nonces and the aggregation live behind
//! `enclave:signer/wallet`: this guest asks for a round and hands it the wallet's answer, and holds
//! no FROST secret at any point.
//!
//! **Script-path only, by construction.** The taproot key-path tweak is compensated entirely on
//! the wallet's share, and the policy signs untweaked; a tweaked share would fail the share
//! check. The policy only ever offers script-path sighashes on these streams, so that is the
//! right trade — but it is a property, not an accident.

use enclave_wit::enclave::signer::wallet;

use crate::types::Commitment;

/// A FROST round the runtime is halfway through, for every message in one batch.
///
/// Held by the `Sign`, `Send` or `Renew` handler across a single round trip, never by the
/// policy, so a dropped stream drops the runtime's round with it. Not `Clone`: each message's
/// nonce is single-use, and [`SigningSession::finish`] takes the session by value.
pub struct SigningSession {
    signing: wallet::Signing,
}

/// The wallet's half of one message's round: its commitment, and its share over both commitments.
pub struct WalletHalf {
    pub hiding: Vec<u8>,
    pub binding: Vec<u8>,
    pub share: Vec<u8>,
}

impl SigningSession {
    /// Round one, the policy's half: the runtime's commitment for each message.
    pub fn begin(messages: &[Vec<u8>]) -> Result<(Self, Vec<Commitment>), String> {
        let identifier_hex = hex::encode(wallet::wallet_key()?.signer_identifier);
        let (signing, commitments) = wallet::Signing::begin(messages)?;
        let commitments = commitments
            .into_iter()
            .map(|c| Commitment { identifier_hex: identifier_hex.clone(), hiding: c.hiding, binding: c.binding })
            .collect();
        Ok((Self { signing }, commitments))
    }

    /// Round two: the wallet's commitment and share for each message in, BIP-340 signatures out.
    ///
    /// [`WalletHalf`]s must be in the order the messages were: index `i` is a statement about
    /// message `i`, and nothing else ties them together. The runtime refuses a count that does not
    /// match, and a share that does not verify.
    pub fn finish(self, halves: Vec<WalletHalf>) -> Result<Vec<Vec<u8>>, String> {
        let rounds: Vec<_> = halves
            .into_iter()
            .map(|h| wallet::WalletRound { hiding: h.hiding, binding: h.binding, share: h.share })
            .collect();
        self.signing.finish(&rounds)
    }
}
