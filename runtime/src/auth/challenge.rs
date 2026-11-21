//! Challenges: what makes a sign-in single use, and what each one is *for*.
//!
//! `request/options` issues a challenge for one interaction of one tenant, and the client signs
//! its id ([`super::approval`]). `request/verify` consumes it and hands back the record: the
//! tenant and the method, path and query it was issued for. A signature moved to another
//! interaction names a challenge whose record does not match it, and fails.
//!
//! Three properties make that hold, and all three are enforced here rather than left to a caller
//! to remember:
//!
//! - **Single use.** [`ChallengeStore::consume`] removes the entry as it returns it, under one
//!   lock, so two copies of one signature cannot both find it.
//! - **Short lived.** An unconsumed challenge expires, so a signature captured and held is
//!   worthless within the minute.
//! - **Bounded.** The table is capped and swept, because issuing a challenge is unauthenticated
//!   by necessity and memory in an enclave is finite.
//!
//! Nothing here survives a restart, and nothing should: the client asks for a new challenge, and
//! every signature in flight becomes worthless. That is the safe direction to fail in.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::token::InteractionScope;

/// How long a challenge is good for: long enough to sign, short enough that a captured signature
/// is stale before it could be used.
pub const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// Outstanding challenges allowed at once: the bound on what an anonymous caller can make the
/// runtime hold.
pub const DEFAULT_CAPACITY: usize = 1024;

/// A challenge issued and not yet used.
struct Pending {
    tenant: [u8; 16],
    scope: InteractionScope,
    expires: Instant,
}

/// Why a challenge could not be used. Distinguished for the log, never for the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeError {
    Unknown,
    Expired,
    Full,
}

impl std::fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ChallengeError::Unknown => "no such challenge, or it has already been used",
            ChallengeError::Expired => "the challenge expired",
            ChallengeError::Full => "too many outstanding challenges",
        })
    }
}

pub struct ChallengeStore {
    pending: Mutex<HashMap<[u8; 16], Pending>>,
    ttl: Duration,
    capacity: usize,
}

impl ChallengeStore {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        ChallengeStore {
            pending: Mutex::new(HashMap::new()),
            ttl,
            capacity: capacity.max(1),
        }
    }

    /// Record a challenge: the tenant it was asked for, and the interaction.
    ///
    /// `id` comes from the enclave's entropy, so the id a client quotes back is unguessable:
    /// otherwise an attacker could name somebody else's outstanding challenge and race them for
    /// it.
    pub fn issue(
        &self,
        id: [u8; 16],
        tenant: [u8; 16],
        scope: InteractionScope,
    ) -> Result<(), ChallengeError> {
        let now = Instant::now();
        let mut pending = self.pending.lock().expect("challenge store poisoned");
        pending.retain(|_, p| p.expires > now);
        if pending.len() >= self.capacity {
            return Err(ChallengeError::Full);
        }
        pending.insert(
            id,
            Pending {
                tenant,
                scope,
                expires: now + self.ttl,
            },
        );
        Ok(())
    }

    /// Take a challenge, if it is there and still good: the tenant and the interaction it was
    /// issued for.
    ///
    /// Removed whether or not what it is offered with verifies. A challenge that was answered
    /// badly has been seen by whoever answered it, and a second attempt at the same one buys
    /// them only attempts.
    pub fn consume(&self, id: &[u8; 16]) -> Result<([u8; 16], InteractionScope), ChallengeError> {
        let mut pending = self.pending.lock().expect("challenge store poisoned");
        let entry = pending.remove(id).ok_or(ChallengeError::Unknown)?;
        if entry.expires <= Instant::now() {
            return Err(ChallengeError::Expired);
        }
        Ok((entry.tenant, entry.scope))
    }

    pub fn outstanding(&self) -> usize {
        let now = Instant::now();
        let mut pending = self.pending.lock().expect("challenge store poisoned");
        pending.retain(|_, p| p.expires > now);
        pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> InteractionScope {
        InteractionScope::new("POST", "/sign", None)
    }

    /// Issued, then used once, and the second attempt finds nothing. This is what stops a
    /// captured approval being replayed.
    #[test]
    fn a_challenge_can_be_consumed_exactly_once() {
        let store = ChallengeStore::new(DEFAULT_TTL, DEFAULT_CAPACITY);
        store.issue([1; 16], [7; 16], scope()).unwrap();
        assert_eq!(store.consume(&[1; 16]).unwrap(), ([7; 16], scope()));
        assert_eq!(
            store.consume(&[1; 16]).unwrap_err(),
            ChallengeError::Unknown
        );
    }

    #[test]
    fn an_expired_challenge_is_refused() {
        let store = ChallengeStore::new(Duration::from_millis(1), DEFAULT_CAPACITY);
        store.issue([2; 16], [7; 16], scope()).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(
            store.consume(&[2; 16]).unwrap_err(),
            ChallengeError::Expired
        );
    }

    #[test]
    fn an_unknown_challenge_is_refused() {
        let store = ChallengeStore::new(DEFAULT_TTL, DEFAULT_CAPACITY);
        assert_eq!(
            store.consume(&[9; 16]).unwrap_err(),
            ChallengeError::Unknown
        );
    }

    /// Issuing is unauthenticated by necessity, so the table is bounded against whoever can
    /// reach the port, and refuses rather than evicting live challenges.
    #[test]
    fn the_store_refuses_to_grow_without_bound() {
        let store = ChallengeStore::new(DEFAULT_TTL, 4);
        for i in 0..4u8 {
            store.issue([i; 16], [7; 16], scope()).unwrap();
        }
        assert_eq!(
            store.issue([99; 16], [7; 16], scope()).unwrap_err(),
            ChallengeError::Full
        );
        assert_eq!(store.outstanding(), 4);
    }

    /// Expired entries are swept, so a burst does not wedge the store.
    #[test]
    fn expiry_makes_room() {
        let store = ChallengeStore::new(Duration::from_millis(1), 2);
        store.issue([0; 16], [7; 16], scope()).unwrap();
        store.issue([1; 16], [7; 16], scope()).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(store.outstanding(), 0);
        store.issue([2; 16], [7; 16], scope()).unwrap();
    }
}
