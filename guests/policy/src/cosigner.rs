//! The cosigner: the Ark sessions and the ASP connection for the one wallet this process serves.
//! Its FROST rounds are `crate::sign`'s, and the wallet key behind them is the runtime's.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::grpc::Status;

use crate::types::{BoardingSettleSubmitted, SendVtxoStep1, SnapshotState, VtxoEntry, VtxoInput};

use ark::client::batch::{DelegateSettleSession, PersistedDelegate};
use ark::client::send::{SendSession, SendVtxoInput};
use ark::client::types::ArkInfo;

use crate::asp::{AspApi, EventSource};
use crate::boarding::BoardingSettleSession;
use crate::host::valid_task_id;
use crate::renew::{AspCall, RenewSession, RenewStep};
use crate::store::Store;

// --- The settle watch --------------------------------------------------------------------------
//
// When a sealed delegate comes due, the cosigner runs it. A VTXO expires. The wallet signs a
// delegate to refresh it while it is here — see `crate::renew` — and the cosigner seals it and
// enqueues this watch for the moment it becomes valid. Then, with no request in flight and nobody
// connected, the task opens the wallet, registers the sealed intent with the ASP its settings name,
// follows the round, and signs the tree with the cosigner's own key. See
// [`Cosigner::run_task_with`].
//
// Waking the owner is the fallback, for when it cannot: the settings name no ASP, or the round
// failed. A failure is a conclusion of this run, not an error — an error is retried five times and
// then the task is dead, and a watch that died would renew nothing ever again. So it reports,
// wakes, and the next interval tries again.

/// The id the watch is enqueued under. Tenant-local, and an idempotency key: re-arming replaces
/// rather than accumulating, so a wallet has one watch however many times it prepares a delegate.
pub const WATCH_TASK_ID: &str = "settle-watch";

/// How often the watch runs again after its first run at the deadline — the retry cadence for a
/// round that did not complete. `enclave:tasks` requires at least 1000ms.
pub const WATCH_INTERVAL_MS: u64 = 30 * 60 * 1000;

/// The wake category the app matches on. Opaque by contract — see `notify.wit`. Raised when a due
/// delegate could not be run here, so the owner can refresh in person.
pub const CATEGORY_SETTLE_DUE: &str = "settle-due";

/// Raised after the cosigner refreshed the funds itself: the refreshed VTXO has no delegate yet, and
/// the next time the owner is here the wallet renews the delegate.
pub const CATEGORY_DELEGATE_SETTLED: &str = "delegate-settled";

/// What the watch carries. Small and self-describing so the runtime's stored payload stays
/// readable, and so a future second task kind does not need a new queue id.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Task {
    /// Wake the owner once the sealed delegate's intent becomes valid.
    SettleDue {
        /// Unix seconds: earliest covered VTXO expiry minus the safety margin.
        deadline_secs: u64,
    },
}

/// What a run of the watch concluded. Returned to the caller so a test can assert on it, and
/// encoded as the task's result so the runtime persists something meaningful.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum Outcome {
    /// Nothing is owed yet.
    NotDue { deadline_secs: u64, now_secs: u64 },
    /// The cosigner ran the delegate: the funds are refreshed.
    Settled { commitment_txid: String },
    /// Due, and not run here — no ASP, or the round failed. The devices were woken.
    Woke { deadline_secs: u64 },
    /// There is no delegate to settle any more — the watch cancels itself.
    NothingToSettle,
}

pub struct Cosigner {
    /// The wallet's delegate, and whether its round is running.
    pub(crate) renew_session: Option<RenewSession>,
    /// In-flight boarding settle, held across the commitment-FROST pause. Transient — never
    /// snapshotted.
    pub(crate) boarding_session: Option<BoardingSettleSession>,
    /// Where the seal lives.
    pub(crate) store: Arc<Store>,
    /// The runtime this cosigner runs inside: its task queue, its push channel and the wallet key.
    /// `Detached` when it runs as a plain process, where every call fails rather than quietly doing
    /// nothing.
    pub(crate) host: Arc<dyn crate::host::Host>,
    /// The name the seal is filed under — configuration, and not the wallet's group key, which is
    /// the runtime's. See `main.rs`.
    pub(crate) group_key: String,
    /// The owned VTXO set. `VtxoEntry` carries the expiry a delegate's renewal deadline is
    /// computed from; callers wanting the ark-facing shape go through [`Self::vtxos()`].
    pub(crate) vtxos: Vec<VtxoEntry>,
}

impl Cosigner {
    /// Load this cosigner's state, then hand back something callable, running inside [host] —
    /// `crate::host::Detached` when there is no runtime.
    ///
    /// Eagerly, not on first use: per-request there is no later use to amortise a lazy restore
    /// into. Storage is the whole of the state — read on entry, sealed on mutation.
    ///
    /// No seal yet is not an error: a new wallet has nothing to read.
    pub fn open(
        store: Arc<Store>,
        group_key: String,
        host: Arc<dyn crate::host::Host>,
    ) -> Result<Self, Status> {
        let mut cosigner = Self::new(store.clone(), group_key.clone(), host);
        // A seal that is there and cannot be read is not the same as no seal: opening as an empty
        // wallet would forget its VTXOs and its delegate, and the seal is the only copy of them.
        crate::store::restore_snapshot(&mut cosigner, &store, &group_key).map_err(|e| {
            Status::failed_precondition(format!(
                "this wallet's sealed state is present but unreadable ({e}); refusing to open it \
                 as an empty wallet"
            ))
        })?;
        Ok(cosigner)
    }

    pub fn group_key(&self) -> &str {
        &self.group_key
    }

    fn new(store: Arc<Store>, group_key: String, host: Arc<dyn crate::host::Host>) -> Self {
        Self {
            renew_session: None,
            boarding_session: None,
            store,
            host,
            group_key,
            vtxos: Vec::new(),
        }
    }

    /// Serialize durable state (VTXOs, delegate) into the sealed-snapshot blob. In-flight sessions
    /// are excluded (transient; MuSig2 nonces must never persist), and so is the wallet key, which
    /// the runtime keeps.
    pub fn to_snapshot(&self) -> Result<Vec<u8>, String> {
        let snap = SnapshotState {
            vtxos: self.vtxos.clone(),
            // Persist a ReadyToSettle delegate (to_persisted errors for other phases → None).
            delegate_json: self
                .renew_session
                .as_ref()
                .and_then(|d| d.session().to_persisted().ok())
                .and_then(|p| serde_json::to_string(&p).ok()),
            delegate_intent_id: None,
        };
        serde_json::to_vec(&snap).map_err(|e| format!("snapshot serialize: {e}"))
    }

    /// Restore durable state from a snapshot blob, on open.
    pub fn restore_snapshot(&mut self, blob: &[u8]) -> Result<(), String> {
        let snap: SnapshotState =
            serde_json::from_slice(blob).map_err(|e| format!("snapshot deserialize: {e}"))?;
        self.vtxos = snap.vtxos;
        // A delegate carries its own tree-signing key and its registration's id. Older seals kept
        // the id beside it, as `delegate_intent_id`, which is read here for that and nothing else:
        // the next seal writes it inside the delegate, and not beside it.
        self.renew_session = match snap.delegate_json {
            Some(dj) => {
                let mut persisted: PersistedDelegate = serde_json::from_str(&dj)
                    .map_err(|e| format!("parse persisted delegate: {e}"))?;
                if persisted.intent_id.is_none() {
                    persisted.intent_id = snap.delegate_intent_id;
                }
                Some(RenewSession::Awaiting(DelegateSettleSession::from_persisted(&persisted)?))
            }
            None => None,
        };
        Ok(())
    }

    /// Take the caller's account of what this wallet holds, which means saying exactly what is and
    /// is not trusted here.
    ///
    /// NOT trusted: ownership. Every VTXO this wallet can spend sits under a scriptPubKey derived
    /// from the cosigner's OWN owner key and one of the two exit delays the ASP published — so an
    /// `exit_delay` outside that pair names a script this wallet does not control, and is refused
    /// outright. A caller cannot widen what it owns by asserting it.
    ///
    /// Trusted: existence. Whether `(txid, vout)` is really unspent is the ASP's to know, and a
    /// caller inventing one gets a transaction the ASP rejects — it wastes a round and nothing
    /// else. Existence is not a secret, so taking it on trust costs nothing.
    pub fn accept_vtxos(&mut self, supplied: Vec<VtxoInput>, info: &ArkInfo) -> Result<(), String> {
        let (unilateral, boarding) = (
            info.unilateral_exit_delay as u32,
            info.boarding_exit_delay as u32,
        );
        let now = crate::store::now_secs();
        let mut accepted: Vec<VtxoEntry> = Vec::with_capacity(supplied.len());
        for v in supplied {
            if v.exit_delay != unilateral && v.exit_delay != boarding {
                return Err(format!(
                    "vtxo {}:{} has exit delay {} — this wallet's are {unilateral} (received) or \
                     {boarding} (boarded); it is not ours to spend",
                    v.txid, v.vout, v.exit_delay
                ));
            }
            if v.amount_sats == 0 {
                return Err(format!("vtxo {}:{} has no amount", v.txid, v.vout));
            }
            if accepted.iter().any(|e| e.txid == v.txid && e.vout == v.vout) {
                return Err(format!("vtxo {}:{} named twice", v.txid, v.vout));
            }
            // Expiry is the indexer's, relayed by the caller; 0 reads as "unknown" downstream, which
            // `settle_deadline` skips conservatively rather than scheduling against a guess.
            accepted.push(VtxoEntry {
                txid: v.txid,
                vout: v.vout,
                amount: v.amount_sats,
                exit_delay: v.exit_delay,
                created_at: now,
                expires_at: v.expires_at.max(0),
            });
        }
        self.vtxos = accepted;
        Ok(())
    }

    /// The owned set in the shape ark's session builders take.
    pub fn vtxos(&self) -> Vec<VtxoInput> {
        self.vtxos
            .iter()
            .map(|e| VtxoInput {
                txid: e.txid.clone(),
                vout: e.vout,
                amount_sats: e.amount,
                exit_delay: e.exit_delay,
                expires_at: e.expires_at,
            })
            .collect()
    }

    /// When a delegate over the held set becomes valid: the earliest known expiry minus the safety
    /// margin. `None` when nothing is held, or no held VTXO has a known expiry — the ASP had not
    /// indexed them yet.
    pub(crate) fn settle_deadline(&self) -> Option<u64> {
        if self.vtxos.is_empty() {
            return None;
        }
        let earliest = self
            .vtxos
            .iter()
            .filter_map(|e| (e.expires_at > 0).then_some(e.expires_at))
            .min()
            .unwrap_or(0);
        let margin = self.store.auto_settle_safety_margin_secs;
        (earliest > margin).then(|| (earliest - margin) as u64)
    }

    /// Build a delegate over everything held and keep it as this wallet's [`RenewSession`], handing
    /// back the sighashes the wallet must FROST-sign. `deferred`: valid from
    /// [`Self::settle_deadline`] (a sealed delegate), or from now (a refresh the owner is asking
    /// for in person — the ASP refuses an intent valid in the future until then).
    pub fn generate_delegate(
        &mut self,
        info: &ArkInfo,
        deferred: bool,
    ) -> Result<Vec<Vec<u8>>, String> {
        let valid_at = if deferred { self.settle_deadline() } else { None };
        let (session, sighashes) =
            RenewSession::generate(&self.owner_pk_hex()?, &self.vtxos(), info, valid_at)?;
        self.renew_session = Some(session);
        Ok(sighashes)
    }

    /// The body of the guest's exported `run-task`.
    ///
    /// `task_id` is the runtime's *run* id, `<id>:<generation>:<occurrence>` — stable across retries
    /// of one occurrence, distinct across occurrences — not the id it was enqueued under. Only the
    /// id is ours to check; the rest identifies the run.
    ///
    /// Errors are retried by the runtime and successes are persisted, so anything recoverable must
    /// return `Err` and anything concluded must return `Ok` — including "not due" and "could not
    /// run it", which are conclusions and not failures.
    pub async fn run_task_with<A: AspApi>(
        &mut self,
        task_id: &str,
        payload: &[u8],
        asp: Option<&mut A>,
    ) -> Result<Vec<u8>, String> {
        let id = task_id.split(':').next().unwrap_or_default();
        if !valid_task_id(id) {
            return Err(format!("task id {task_id:?} is not a tenant-local key"));
        }
        let task: Task = serde_json::from_slice(payload)
            .map_err(|e| format!("undecodable task payload: {e}"))?;
        let outcome = match task {
            Task::SettleDue { deadline_secs } => self.settle_due(deadline_secs, asp).await?,
        };
        let encoded = serde_json::to_vec(&outcome).map_err(|e| format!("encode outcome: {e}"))?;
        // The watch runs unattended, so its outcome (NothingToSettle / NotDue / Settled / Woke, with
        // its ids) is the one line that says what a background wake-up did. It names no secret.
        println!("settle-due: {}", String::from_utf8_lossy(&encoded));
        Ok(encoded)
    }

    async fn settle_due<A: AspApi>(
        &mut self,
        deadline_secs: u64,
        asp: Option<&mut A>,
    ) -> Result<Outcome, String> {
        // No sealed delegate: it was run, or spent by a send, or replaced — nothing is owed. The
        // cancel is best-effort (a background run may not mutate the queue); the next renewal
        // re-arms.
        if self.renew_session.is_none() {
            self.host.cancel(WATCH_TASK_ID).ok();
            return Ok(Outcome::NothingToSettle);
        }

        let now = crate::store::now_secs().max(0) as u64;
        if now < deadline_secs {
            return Ok(Outcome::NotDue {
                deadline_secs,
                now_secs: now,
            });
        }

        if let Some(asp) = asp {
            // Run the sealed delegate's round against the ASP, for its commitment txid. Safe to
            // run again after a failure: the registered intent's id is sealed as soon as the ASP
            // assigns it, so a retry follows the same registration rather than making a second
            // one, and a failed batch clears it so the next attempt registers afresh.
            let run: Result<String, String> = async {
                let delegate =
                    self.renew_session.as_ref().ok_or("no sealed delegate")?.session();
                let (proof, message, topics) = delegate.register_payload()?;
                let registered = delegate.intent_id.is_some();
                let info = asp.get_info().await?;

                if !registered {
                    let id = asp.register_intent(&proof, &message).await?;
                    if let Some(delegate) = self.renew_session.as_mut() {
                        delegate.session_mut().intent_id = Some(id);
                    }
                    self.seal();
                }

                let mut events = asp.events(&topics).await?;
                let held: u64 = self.vtxos.iter().map(|v| v.amount).sum();
                let exit_delay = info.unilateral_exit_delay as u32;
                self.renew_session =
                    self.renew_session.take().map(|d| d.in_flight(exit_delay));

                let outcome: Result<crate::types::BoardingSettleSubmitted, String> = async {
                    loop {
                        let event = events
                            .next()
                            .await?
                            .ok_or("the ASP's event stream ended before the batch finalized")?;
                        match self.renew_on_event(event)? {
                            RenewStep::Idle => {}
                            RenewStep::Submit(AspCall::ConfirmRegistration { intent_id }) => {
                                asp.confirm_registration(&intent_id).await?
                            }
                            RenewStep::Submit(AspCall::TreeNonces { batch_id, pubkey, nonces }) => {
                                asp.submit_tree_nonces(&batch_id, &pubkey, &nonces).await?
                            }
                            RenewStep::Submit(AspCall::TreeSignatures {
                                batch_id,
                                pubkey,
                                signatures,
                            }) => {
                                asp.submit_tree_signatures(&batch_id, &pubkey, &signatures).await?
                            }
                            RenewStep::Submit(AspCall::ForfeitTxs {
                                signed_txs,
                                signed_commitment_b64,
                            }) => asp.submit_forfeits(&signed_txs, &signed_commitment_b64).await?,
                            RenewStep::Complete(sub) => return Ok(sub),
                            RenewStep::Sighashes(_) | RenewStep::Register { .. } => {
                                return Err(
                                    "a delegate round asked for a signature it should not need"
                                        .into(),
                                )
                            }
                        }
                    }
                }
                .await;

                // A round that stopped short leaves the delegate waiting again; a finished one took
                // it.
                self.renew_session =
                    self.renew_session.take().map(RenewSession::awaiting);
                match outcome {
                    Ok(sub) => {
                        // Everything the delegate covered was spent into the one VTXO it produced,
                        // and the delegate went with its round.
                        self.vtxos = vec![VtxoEntry {
                            txid: sub.vtxo_txid,
                            vout: sub.vtxo_vout,
                            amount: held,
                            exit_delay: sub.exit_delay,
                            created_at: crate::store::now_secs(),
                            expires_at: 0,
                        }];
                        self.seal();
                        Ok(sub.commitment_txid)
                    }
                    Err(e) => {
                        if e.contains("batch failed") {
                            // The ASP dropped the registration with the batch; register again next
                            // time.
                            if let Some(delegate) = self.renew_session.as_mut() {
                                delegate.session_mut().intent_id = None;
                            }
                            self.seal();
                        }
                        Err(e)
                    }
                }
            }
            .await;
            match run {
                Ok(commitment_txid) => {
                    // Best-effort: the refresh happened either way.
                    self.host.wake(CATEGORY_DELEGATE_SETTLED, None).ok();
                    return Ok(Outcome::Settled { commitment_txid });
                }
                Err(e) => eprintln!("the sealed delegate could not be run: {e}"),
            }
        }

        // The one call a task may make that an interactive call had to earn first. It spends the
        // enrolment; it authorizes nothing.
        self.host
            .wake(CATEGORY_SETTLE_DUE, None)
            .map_err(|e| format!("wake: {e}"))?;
        Ok(Outcome::Woke { deadline_secs })
    }

    /// Seal this cosigner's state, logging a failure rather than returning it.
    pub fn seal(&mut self) {
        if let Err(e) = self.try_seal() {
            eprintln!("{e}");
        }
    }

    /// Seal, and say whether it took. For a change that must not be acted on unless it is durable:
    /// a release signed but not written down is a payment that can be asked for again, and a key
    /// announced but not written down is one a wallet funds and the cosigner then forgets.
    pub fn try_seal(&mut self) -> Result<(), String> {
        let store = self.store.clone();
        let group_key = self.group_key.clone();
        crate::store::seal_snapshot(self, &store, &group_key)
    }

    /// Record a settled boarding output: replace it in the owned set with the VTXO it became, and
    /// hand back the commitment txid.
    pub fn apply_boarding_settle(&mut self, sub: BoardingSettleSubmitted) -> String {
        let now = crate::store::now_secs();
        self.vtxos
            .retain(|e| !(e.txid == sub.vtxo_txid && e.vout == sub.vtxo_vout));
        self.vtxos.push(VtxoEntry {
            txid: sub.vtxo_txid.clone(),
            vout: sub.vtxo_vout,
            amount: sub.amount_sats,
            exit_delay: sub.exit_delay,
            created_at: now,
            expires_at: 0,
        });
        sub.commitment_txid
    }

    /// The wallet's group x-only pubkey (hex) — the VTXO owner key, from the runtime's wallet key.
    pub fn owner_pk_hex(&self) -> Result<String, String> {
        let key = self.host.wallet_key()?;
        match key.group_key.as_slice() {
            [_, x @ ..] if x.len() == 32 => Ok(hex::encode(x)),
            _ => Err("the runtime's group key is not 33 bytes".into()),
        }
    }

    /// Rebuild a wallet on a new device, from nothing but its passkey: hand back the half of its
    /// share this cosigner dealt, with the public material to check it against.
    ///
    /// # Why half a key is sitting here
    ///
    /// A FROST share is the sum of every dealer's polynomial evaluated at the participant's
    /// identifier. For this 2-of-2 that is two terms:
    ///
    /// ```text
    ///   s_wallet = f_wallet(id_wallet) + f_cosigner(id_wallet)
    /// ```
    ///
    /// The wallet's own dealer is derived from the passkey's PRF output, which the platform syncs
    /// with the passkey, so a new phone that can use the passkey can reproduce `f_wallet` exactly —
    /// and with it `id_wallet`, which is derived from `a0·G`. The second term it cannot reproduce:
    /// the cosigner's polynomial is derived from the operator master, which only the runtime holds.
    /// So the runtime recomputes the one scalar the cosigner dealt out, and it is handed back here.
    ///
    /// # What this is not
    ///
    /// It is not a key escrow. The scalar returned is one term of a sum whose other term exists
    /// only behind the owner's biometric; alone it signs nothing and identifies nothing. And it is
    /// not a ceremony: nothing is installed, no key is written, no share is re-keyed.
    ///
    /// # Who may call it
    ///
    /// The runtime resolved the tenant from the caller's passkey before this was reached; there is
    /// no second authentication to do here and none is invented. What is checked instead is that
    /// the passkey used is the *right* one: the caller sends the identifier it derived, and a
    /// mismatch is refused rather than answered. A wallet whose PRF output changed is a wallet that
    /// can no longer sign, and it is far better to say so than to hand back a share that will not
    /// add up.
    pub fn recover(
        &self,
        req: crate::session::proto::RecoverRequest,
    ) -> Result<crate::session::proto::RecoverResponse, Status> {
        let dealt_share = self.dealt_share_for(&req.identifier)?;
        let key = self.host.wallet_key().map_err(Status::failed_precondition)?;
        println!("Recover: returning the dealt share to the wallet's own identifier");
        Ok(crate::session::proto::RecoverResponse {
            dealt_share,
            public_key_package_json: key.public_key_package,
            group_key: hex::encode(&key.group_key),
        })
    }

    /// The half of the wallet's share the cosigner dealt at DKG, for the wallet that is
    /// [identifier], recomputed by the runtime.
    ///
    /// `Recover` hands it to a device that has nothing. `Sign`, `Send` and `Renew` hand it back on
    /// their first round, every time, because the wallet keeps no share between operations: it
    /// re-derives its own half from the passkey and adds this one, under the approval the stream
    /// already has. One rule for all four, so there is one place it can be wrong.
    ///
    /// The identifier is public, so matching it proves nothing about who is asking — the runtime
    /// authenticated that. It proves the wallet asking is *this* wallet: a wrong passkey, or a PRF
    /// that answers differently, derives another identifier and is told so instead of being handed
    /// a share that would not add up.
    pub(crate) fn dealt_share_for(&self, identifier: &[u8]) -> Result<Vec<u8>, Status> {
        let key = self.host.wallet_key().map_err(|e| {
            Status::failed_precondition(format!(
                "this wallet has no key ({e}): there is nothing to recover, create one instead"
            ))
        })?;
        if identifier.len() != 32 {
            return Err(Status::invalid_argument("identifier must be 32 bytes"));
        }
        if identifier != key.wallet_identifier.as_slice() {
            // Not "wrong passkey" necessarily — a PRF that answers differently on this device
            // looks exactly the same from here. Either way the share would not add up, so say so
            // now.
            return Err(Status::permission_denied(
                "that passkey does not derive this wallet's owner key: the share it rebuilt would \
                 not be able to sign",
            ));
        }
        self.host.dealt_share(identifier).map_err(Status::unavailable)
    }

    /// The runtime this instance is running inside.
    ///
    /// Cloned out rather than borrowed so a caller can hold it across an await without holding the
    /// wallet's lock.
    pub fn host(&self) -> Arc<dyn crate::host::Host> {
        self.host.clone()
    }
}

impl Cosigner {
    /// Open a send: build the off-chain send tx (after `GetInfo`) and hand back the session
    /// alongside the sighashes the client must FROST-sign. Nothing about it is stored here.
    pub fn create_send_session(
        &mut self,
        req: SendVtxoStep1,
        info: &ArkInfo,
    ) -> Result<(SendSession, u32, Vec<Vec<u8>>), String> {
        // `req.vtxos` is the caller's account of the set; `accept_vtxos` decides what of it this
        // wallet could actually own before any of it is selected from.
        self.accept_vtxos(req.vtxos.clone(), info)?;
        let total: u64 = req.vtxos.iter().map(|v| v.amount_sats).sum();
        if total < req.amount {
            return Err(format!(
                "insufficient balance: have {} sats, need {} sats",
                total, req.amount
            ));
        }
        let owner_pk_hex = self.owner_pk_hex()?;
        build_send(&owner_pk_hex, &req.vtxos, &req, info).map_err(|e| format!("build send: {e}"))
    }

    /// Close the send once the ASP has accepted it: the owned set becomes its change, and the
    /// delegate goes.
    ///
    /// Takes the session by value: it holds the half-signed transactions, so consuming it is what
    /// stops a second submit from reaching the same session. Only called after `FinalizeTx`
    /// succeeded, so nothing is recorded for a send the ASP never took.
    pub fn finalise_send_session(&mut self, mut session: SendSession, change_exit_delay: u32) {
        let change = session
            .change_vtxo()
            .map(|(txid, vout, amount)| (txid, vout, amount, change_exit_delay));
        session.mark_done();
        // The send spent all current VTXOs; re-add the change VTXO to the owned set, if any.
        // Expiry is unknown until the ASP indexes it, so 0 — `settle_deadline` reads that as
        // "unknown" and skips it conservatively rather than settling against a made-up deadline.
        let now = crate::store::now_secs();
        self.vtxos.clear();
        if let Some((txid, vout, amount, exit_delay)) = change {
            self.vtxos.push(VtxoEntry {
                txid,
                vout,
                amount,
                exit_delay,
                created_at: now,
                expires_at: 0,
            });
        }
        // The send spent what the sealed delegate was signed over, so it can never settle now.
        // Dropping it makes the settle watch find nothing on its next run and cancel itself.
        self.renew_session = None;
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the off-chain send transactions (SendVtxoStep1): derive change address, run
/// `SendSession::build`, and return `(session, change_exit_delay, sighashes)`. Pure ark signing math
/// (no I/O); `info` comes from a prior gRPC `GetInfo`.
pub(crate) fn build_send(
    owner_pk_hex: &str,
    vtxos: &[VtxoInput],
    req: &SendVtxoStep1,
    info: &ArkInfo,
) -> Result<(SendSession, u32, Vec<Vec<u8>>), String> {
    if vtxos.is_empty() {
        return Err("no VTXOs to send".into());
    }
    let vtxo_inputs: Vec<SendVtxoInput> = vtxos
        .iter()
        .map(|v| SendVtxoInput {
            txid: v.txid.clone(),
            vout: v.vout,
            amount_sats: v.amount_sats,
            // Each input keeps its OWN delay; a boarding-settled VTXO and a
            // received one genuinely differ.
            exit_delay: v.exit_delay,
        })
        .collect();

    let total: u64 = vtxos.iter().map(|v| v.amount_sats).sum();
    if total < req.amount {
        return Err(format!(
            "insufficient balance: have {total}, need {}",
            req.amount
        ));
    }

    let network = ark::client::parse_network(&info.network)?;
    let change_exit_delay = info.unilateral_exit_delay as u32;
    let change_addr = if total > req.amount {
        Some(ark::client::ark_address(
            owner_pk_hex,
            &info.signer_pubkey,
            change_exit_delay,
            network,
        )?)
    } else {
        None
    };

    let (session, sighashes) = SendSession::build(
        owner_pk_hex,
        &vtxo_inputs,
        &req.recipient_ark_address,
        req.amount,
        change_addr.as_deref(),
        info,
    )?;
    Ok((
        session,
        change_exit_delay,
        sighashes.iter().map(|s| s.to_vec()).collect(),
    ))
}

/// Put the wallet's signatures, as the wire carried them, into [session], and hand back what the
/// caller submits: the ark tx and its checkpoints. The cosigner signs; the caller submits.
pub(crate) fn sign_and_prepare(
    session: &mut SendSession,
    signatures: &[Vec<u8>],
) -> Result<(String, Vec<String>), String> {
    session.sign_with_frost(crate::util::sigs_from_wire(signatures)?)?;
    session.prepare_submit().map_err(|e| format!("prepare submit: {e}"))
}
