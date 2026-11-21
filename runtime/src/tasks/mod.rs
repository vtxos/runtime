//! Durable, tenant-bound background work, scheduled outside the enclave and run inside it.
//!
//! ```text
//!   guest: enqueue ──► table (DynamoDB): the task, signed   ──► scheduler (EventBridge)
//!                                                                    │ at its time
//!   guest: run-task ◄── consumer: verify, claim, run ◄── queue (SQS) ◄┘
//! ```
//!
//! The runtime keeps no clock for tasks. It records each one where an operator can see it, makes
//! a schedule for it, and runs whatever the queue delivers — once it has checked it. Everything
//! outside the enclave is writable by the parent, whose role the enclave borrows, so:
//!
//! - **A task is signed** with its tenant's task key ([`envelope`]), so the host cannot make one,
//!   change one, or read its payload. A delivery names a task; the task itself comes from the table
//!   and is run only if it verifies.
//! - **A delivery is checked against the clock**: one before its time is dropped.
//! - **An occurrence is claimed** with a conditional write before it runs, and its outcome is
//!   recorded the same way after, so a second delivery of one that finished is dropped. The host
//!   can roll the table back, so execution is at least once whatever the table says: a handler
//!   must deduplicate its effects by run id, and check its own sealed state before acting.
//! - **The guest's writes reach the tenant's anchor** before its outcome is recorded or anyone is
//!   woken.
//!
//! What the host can still do is delete or delay — denial of service, which it can always do.
//!
//! A task can be checked and run only once its tenant is attached: its keys come from the
//! tenant's key. One that comes due before then — a new release its owner has not signed in to —
//! waits, and runs when they do ([`TaskQueue::catch_up`]).

pub mod aws;
pub mod deliveries;
pub mod envelope;
pub mod schedules;
pub mod table;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use serde::Serialize;
use wasmtime_wasi::HostWallClock;

use crate::clock::WallClockAdapter;
use crate::state::State;
use crate::store::zfs::{TenantLoader, Zfs};
use crate::tenant::TaskKeys;

use deliveries::{Deliveries, Delivery};
use envelope::{open_result, seal_result, Draft, Envelope};
use schedules::{schedule_name, Message, Schedule, Schedules, When};
use table::{RunRecord, RunState, TaskRecord, TaskState, TaskTable};

pub use aws::TasksConfig;

const MAX_PAYLOAD: usize = 64 * 1024;
const MAX_ATTEMPTS: u32 = 5;
/// Recurring tasks repeat in whole minutes: the smallest rate EventBridge Scheduler has.
const MINUTE_MS: u64 = 60_000;

/// How long one attempt at a background task may run. Fixed, not a setting: a task that drives a
/// round with an outside service waits on that service's schedule, which is minutes, and a limit
/// a deployment can lower is one more way for that work to fail somewhere other than here.
pub const TASK_TIMEOUT: Duration = Duration::from_secs(600);
/// How long a delivery stays hidden while its attempt runs: past the timeout, and the anchor and
/// the record after it.
const VISIBILITY: Duration = Duration::from_secs(900);
/// How far a delivery may be ahead of the enclave's clock and still run.
const SKEW_MS: u64 = 60_000;
/// A one-time task due this soon goes straight on the queue, delayed, rather than through a
/// schedule: SQS delays a message up to fifteen minutes.
const IMMEDIATE_MS: u64 = 15 * 60_000;
/// How often the reconciler looks for work left half done.
const RECONCILE_EVERY: Duration = Duration::from_secs(300);
/// How old a half-done create or cancel is before the reconciler finishes it.
const STALE_MS: u64 = 60_000;
/// How long a one-time task's firing may be missing before it is sent again.
const LOST_MS: u64 = 60 * 60_000;

#[derive(Debug, Clone)]
pub struct TaskLimits {
    /// Attempts running at once, across tenants. One tenant's attempts never overlap each other or
    /// its requests: each holds the tenant's turn.
    pub concurrency: usize,
    pub per_tenant: usize,
    pub timeout: Duration,
}
impl Default for TaskLimits {
    fn default() -> Self {
        Self {
            concurrency: 8,
            per_tenant: 64,
            timeout: TASK_TIMEOUT,
        }
    }
}

/// Background tasks, as a deployment sets them up.
#[derive(Debug)]
pub struct BackgroundTasks {
    pub limits: TaskLimits,
    pub backend: TaskBackend,
}

#[derive(Debug)]
pub enum TaskBackend {
    Aws(TasksConfig),
    /// Everything in memory, lost on restart: the emulator's stand-in for AWS.
    #[cfg(any(test, feature = "testing"))]
    Memory,
}

#[cfg(any(test, feature = "testing"))]
impl Default for BackgroundTasks {
    fn default() -> Self {
        BackgroundTasks {
            limits: TaskLimits::default(),
            backend: TaskBackend::Memory,
        }
    }
}

impl BackgroundTasks {
    pub async fn open(self, zfs: Arc<Zfs>, clock: Arc<WallClockAdapter>) -> Result<Arc<TaskQueue>> {
        let backend = match self.backend {
            TaskBackend::Aws(config) => Backend::aws(&config).await?,
            #[cfg(any(test, feature = "testing"))]
            TaskBackend::Memory => Backend::memory(clock.clone(), Duration::from_secs(20)),
        };
        TaskQueue::open(zfs, clock, self.limits, backend).await
    }
}

/// Where tasks are kept, scheduled and delivered.
pub struct Backend {
    pub table: Arc<dyn TaskTable>,
    pub schedules: Arc<dyn Schedules>,
    pub deliveries: Arc<dyn Deliveries>,
    /// The in-memory scheduler's clockwork, which [`TaskQueue::run`] turns.
    #[cfg(any(test, feature = "testing"))]
    clockwork: Option<Arc<schedules::MemorySchedules>>,
}

impl Backend {
    pub async fn aws(config: &TasksConfig) -> Result<Self> {
        let (table, schedules, deliveries) = aws::connect(config).await?;
        Ok(Backend {
            table: Arc::new(table),
            schedules: Arc::new(schedules),
            deliveries: Arc::new(deliveries),
            #[cfg(any(test, feature = "testing"))]
            clockwork: None,
        })
    }

    /// Everything in memory: the emulator's and the tests' stand-in for AWS. Lost on restart.
    #[cfg(any(test, feature = "testing"))]
    pub fn memory(clock: Arc<WallClockAdapter>, wait: Duration) -> Self {
        let deliveries = Arc::new(deliveries::MemoryDeliveries::new(wait));
        let schedules = Arc::new(schedules::MemorySchedules::new(deliveries.clone(), clock));
        Backend {
            table: Arc::new(table::MemoryTable::default()),
            schedules: schedules.clone(),
            deliveries,
            clockwork: Some(schedules),
        }
    }
}

/// How a background task is run: what [`crate::serve::ServeHandle`] does, behind a trait so the
/// queue can be tested without a guest.
#[async_trait::async_trait]
pub trait Runner: Send + Sync {
    /// The tenant's turn, if nobody holds it: held for the whole attempt, so it never overlaps the
    /// tenant's requests or its other tasks.
    fn turn(&self, tenant: [u8; 16]) -> Option<Box<dyn Send>>;
    /// One attempt: the guest's `run-task`, bounded by `limits.timeout`, and then its writes
    /// anchored, whatever it returned.
    async fn run(&self, queue: &Arc<TaskQueue>, job: &Job) -> Result<Vec<u8>>;
    /// Send the wakes the attempt staged, or drop them.
    fn wakes(&self, tenant: [u8; 16], deliver: bool);
}

/// One occurrence of a task, verified and ready to run.
#[derive(Debug, Clone)]
pub struct Job {
    pub tenant: [u8; 16],
    pub id: String,
    pub generation: [u8; 16],
    pub occurrence: u64,
    pub interval_ms: Option<u64>,
    pub payload: Vec<u8>,
}

impl Job {
    /// `<id>:<generation>:<occurrence>`: the same across retries of one occurrence, another for the
    /// next occurrence, or for the task enqueued again after `forget`.
    pub fn run_id(&self) -> String {
        format!(
            "{}:{}:{}",
            self.id,
            hex::encode(self.generation),
            self.occurrence
        )
    }
}

/// What `status` answers: a task, as the guest sees it.
#[derive(Debug, Clone, Serialize)]
pub struct TaskStatus {
    pub id: String,
    /// `pending`, `running`, `completed`, `failed` or `cancelled`.
    pub status: &'static str,
    pub run_at: u64,
    pub interval_ms: Option<u64>,
    /// The latest occurrence's run id, once one has fired.
    pub run_id: Option<String>,
    pub attempts: u32,
    /// The latest occurrence's result, once it completed.
    pub result: Vec<u8>,
    pub error: Option<String>,
}

enum Claim {
    Run(RunRecord),
    /// Already finished: a second delivery.
    Finished,
    /// Another attempt holds it, for this many more milliseconds.
    Leased(u64),
}

struct Verified {
    keys: TaskKeys,
    job: Job,
    run_at: u64,
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub struct TaskQueue {
    zfs: Arc<Zfs>,
    clock: Arc<WallClockAdapter>,
    pub limits: TaskLimits,
    table: Arc<dyn TaskTable>,
    schedules: Arc<dyn Schedules>,
    deliveries: Arc<dyn Deliveries>,
    #[cfg(any(test, feature = "testing"))]
    clockwork: Option<Arc<schedules::MemorySchedules>>,
}

#[async_trait::async_trait]
impl TenantLoader for TaskQueue {
    /// A tenant just attached: run what came due while it could not be, and say whether it has
    /// tasks, so its key is kept for the next boot. A failure here must not fail the sign-in, so it
    /// is logged; the occurrences wait for the next attach.
    async fn load_tenant(&self, tenant: [u8; 16]) -> Result<bool> {
        match self.catch_up(tenant).await {
            Ok(background) => Ok(background),
            Err(e) => {
                tracing::warn!(tenant = %hex::encode(tenant), error = format!("{e:#}"),
                    "could not catch up a tenant's tasks; they wait for its next attach");
                Ok(false)
            }
        }
    }
}

impl TaskQueue {
    pub async fn open(
        zfs: Arc<Zfs>,
        clock: Arc<WallClockAdapter>,
        limits: TaskLimits,
        backend: Backend,
    ) -> Result<Arc<Self>> {
        ensure!(
            limits.concurrency > 0 && limits.per_tenant > 0 && !limits.timeout.is_zero(),
            "task limits must be positive"
        );
        let queue = Arc::new(Self {
            zfs: zfs.clone(),
            clock,
            limits,
            table: backend.table,
            schedules: backend.schedules,
            deliveries: backend.deliveries,
            #[cfg(any(test, feature = "testing"))]
            clockwork: backend.clockwork,
        });
        // Catch up each tenant as its pool is attached: now, for the tenants this release kept,
        // and as each other tenant's owner signs in.
        let loader: Arc<dyn TenantLoader> = queue.clone();
        zfs.register_loader(Arc::downgrade(&loader)).await?;
        Ok(queue)
    }

    pub fn now(&self) -> u64 {
        self.clock.now().as_millis().min(u64::MAX as u128) as u64
    }

    pub async fn enqueue(
        &self,
        tenant: [u8; 16],
        id: String,
        payload: Vec<u8>,
        run_at: u64,
        interval_ms: Option<u64>,
    ) -> Result<()> {
        ensure!(valid_id(&id), "invalid task id");
        ensure!(payload.len() <= MAX_PAYLOAD, "task payload exceeds 64 KiB");
        ensure!(
            interval_ms.is_none_or(|i| i >= MINUTE_MS && i % MINUTE_MS == 0),
            "interval must be a whole number of minutes, at least one"
        );
        let keys = self.zfs.task_keys(tenant)?;
        // The tenant's pool must be re-attached on the next boot, or its tasks wait for its owner
        // there: keep its key before the task exists.
        self.zfs.mark_background(tenant).await?;
        let record = match self.table.task(tenant, &id).await? {
            Some(existing) => {
                let (envelope, stored) = Envelope::open(&keys, &existing.envelope)?;
                ensure!(
                    stored == payload
                        && envelope.run_at == run_at
                        && envelope.interval_ms == interval_ms,
                    "task id already used with different input"
                );
                if existing.state != TaskState::Scheduling {
                    return Ok(());
                }
                // Recorded by an enqueue that stopped before its schedule: finish it.
                existing
            }
            None => {
                ensure!(
                    self.table.tasks(tenant).await?.len() < self.limits.per_tenant,
                    "task quota reached; forget terminal tasks"
                );
                let mut generation = [0; 16];
                crate::random::fill(&mut generation);
                let now = self.now();
                let draft = Draft {
                    tenant,
                    id: &id,
                    generation,
                    run_at,
                    interval_ms,
                    created_at: now,
                };
                let record = TaskRecord {
                    envelope: Envelope::seal(&keys, draft, &payload)?,
                    schedule: schedule_name(tenant, &id, generation),
                    tenant,
                    id,
                    generation,
                    state: TaskState::Scheduling,
                    run_at,
                    interval_ms,
                    updated_at: now,
                    version: 1,
                };
                ensure!(
                    self.table.put_task(&record, None).await?,
                    "task id already used"
                );
                record
            }
        };
        self.schedule(record).await
    }

    /// Give a recorded task its trigger, and mark it scheduled.
    async fn schedule(&self, mut record: TaskRecord) -> Result<()> {
        self.trigger(&record).await?;
        let expected = record.version;
        record.state = TaskState::Scheduled;
        record.version += 1;
        record.updated_at = self.now();
        // Lost only to a cancel in between, whose own path removes the schedule.
        self.table.put_task(&record, Some(expected)).await?;
        Ok(())
    }

    /// What makes a task fire: a schedule, or, for a one-time task due soon, a delayed message.
    async fn trigger(&self, record: &TaskRecord) -> Result<()> {
        let now = self.now();
        let message = Message::template(record.tenant, &record.id, record.generation);
        let when = match record.interval_ms {
            None if record.run_at <= now.saturating_add(IMMEDIATE_MS) => {
                let delay = Duration::from_millis(record.run_at.saturating_sub(now));
                let due = Message::due(record.tenant, &record.id, record.generation, record.run_at);
                return self.deliveries.send(&due, delay).await;
            }
            None => When::At(record.run_at),
            Some(interval_ms) => When::Every {
                interval_ms,
                from: (record.run_at > now).then_some(record.run_at),
            },
        };
        self.schedules
            .create(&Schedule {
                name: record.schedule.clone(),
                when,
                message,
            })
            .await
    }

    pub async fn status(&self, tenant: [u8; 16], id: &str) -> Result<TaskStatus> {
        let record = self.table.task(tenant, id).await?.context("no such task")?;
        let keys = self.zfs.task_keys(tenant)?;
        Envelope::open(&keys, &record.envelope)?;
        let run = self.table.latest_run(tenant, id, record.generation).await?;
        let running = run
            .as_ref()
            .is_some_and(|r| r.state == RunState::Running && r.lease_until > self.now());
        let status = match record.state {
            TaskState::Scheduling | TaskState::Scheduled if running => "running",
            TaskState::Scheduling | TaskState::Scheduled => "pending",
            TaskState::Cancelling | TaskState::Cancelled => "cancelled",
            TaskState::Done => "completed",
            TaskState::Failed => "failed",
        };
        let result = match &run {
            Some(r) if r.state == RunState::Completed => open_result(
                &keys,
                tenant,
                id,
                record.generation,
                r.occurrence,
                &r.result,
            )?,
            _ => Vec::new(),
        };
        Ok(TaskStatus {
            id: record.id,
            status,
            run_at: record.run_at,
            interval_ms: record.interval_ms,
            run_id: run.as_ref().map(|r| {
                Job {
                    tenant,
                    id: id.to_string(),
                    generation: record.generation,
                    occurrence: r.occurrence,
                    interval_ms: record.interval_ms,
                    payload: Vec::new(),
                }
                .run_id()
            }),
            attempts: run.as_ref().map_or(0, |r| r.attempts),
            result,
            error: run.and_then(|r| r.error),
        })
    }

    /// Stop a task's future runs. A task already finished has none, and is left as it is. An
    /// attempt already running is not interrupted, but its outcome no longer finishes the task.
    pub async fn cancel(&self, tenant: [u8; 16], id: &str) -> Result<()> {
        let mut record = self.table.task(tenant, id).await?.context("no such task")?;
        if record.state.terminal() {
            return Ok(());
        }
        if record.state != TaskState::Cancelling {
            let expected = record.version;
            record.state = TaskState::Cancelling;
            record.version += 1;
            record.updated_at = self.now();
            ensure!(
                self.table.put_task(&record, Some(expected)).await?,
                "the task changed while it was being cancelled; try again"
            );
        }
        self.finish_cancel(record).await
    }

    async fn finish_cancel(&self, mut record: TaskRecord) -> Result<()> {
        self.schedules.delete(&record.schedule).await?;
        let expected = record.version;
        record.state = TaskState::Cancelled;
        record.version += 1;
        record.updated_at = self.now();
        // Lost only to another cancel finishing first.
        self.table.put_task(&record, Some(expected)).await?;
        Ok(())
    }

    /// Remove a finished task to free its id and its quota. Never one still running.
    pub async fn forget(&self, tenant: [u8; 16], id: &str) -> Result<()> {
        let record = self.table.task(tenant, id).await?.context("no such task")?;
        let running = self
            .table
            .latest_run(tenant, id, record.generation)
            .await?
            .is_some_and(|r| r.state == RunState::Running && r.lease_until > self.now());
        ensure!(record.state.terminal() && !running, "task is still active");
        ensure!(
            self.table.delete_task(tenant, id, record.version).await?,
            "the task changed while it was being forgotten; try again"
        );
        Ok(())
    }

    /// Receive and run deliveries until the process stops. A backend that cannot be reached is
    /// logged and tried again: its messages wait in the queue.
    pub async fn run(self: Arc<Self>, runner: Arc<dyn Runner>) -> Result<()> {
        // Owned here, so dropping the consumer stops the in-memory scheduler with it.
        #[cfg(any(test, feature = "testing"))]
        let _clockwork = {
            let mut clockwork = tokio::task::JoinSet::new();
            if let Some(schedules) = self.clockwork.clone() {
                clockwork.spawn(schedules.run());
            }
            clockwork
        };
        let mut workers = tokio::task::JoinSet::new();
        let mut reconcile_at = tokio::time::Instant::now();
        loop {
            if tokio::time::Instant::now() >= reconcile_at {
                if let Err(e) = self.reconcile().await {
                    tracing::warn!(error = format!("{e:#}"), "reconciling background tasks");
                }
                reconcile_at = tokio::time::Instant::now() + RECONCILE_EVERY;
            }
            while let Some(done) = workers.try_join_next() {
                if let Err(e) = done {
                    tracing::error!(error = %e, "a background task worker died");
                }
            }
            if workers.len() >= self.limits.concurrency {
                workers.join_next().await;
                continue;
            }
            let free = self.limits.concurrency - workers.len();
            match self.deliveries.receive(free.min(10), VISIBILITY).await {
                Ok(batch) => {
                    for delivery in batch {
                        let (queue, runner) = (self.clone(), runner.clone());
                        workers.spawn(async move { queue.handle(&runner, delivery).await });
                    }
                }
                Err(e) => {
                    tracing::warn!(error = format!("{e:#}"), "receiving background tasks");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    /// One delivery. Whatever goes wrong comes back later: the message is released, not lost.
    async fn handle(self: &Arc<Self>, runner: &Arc<dyn Runner>, delivery: Delivery) {
        if let Err(e) = self.try_handle(runner, &delivery).await {
            tracing::warn!(
                error = format!("{e:#}"),
                "a background task delivery could not be handled; it comes back"
            );
            if let Err(e) = self
                .deliveries
                .release(&delivery.receipt, Duration::from_secs(30))
                .await
            {
                tracing::warn!(error = format!("{e:#}"), "releasing a task delivery");
            }
        }
    }

    async fn try_handle(
        self: &Arc<Self>,
        runner: &Arc<dyn Runner>,
        delivery: &Delivery,
    ) -> Result<()> {
        let message = match Message::parse(&delivery.body) {
            Ok(message) => message,
            Err(e) => {
                tracing::warn!(
                    error = format!("{e:#}"),
                    "an undecodable task message was dropped"
                );
                return self.deliveries.delete(&delivery.receipt).await;
            }
        };
        if !self.zfs.is_attached(message.tenant) {
            self.park(&message, &delivery.body).await?;
            return self.deliveries.delete(&delivery.receipt).await;
        }
        let Some(verified) = self.verify(&message).await? else {
            return self.deliveries.delete(&delivery.receipt).await;
        };
        let now = self.now();
        if message.scheduled > now.saturating_add(SKEW_MS)
            || message.scheduled.saturating_add(SKEW_MS) < verified.run_at
        {
            tracing::warn!(tenant = %hex::encode(message.tenant), task = %message.id,
                scheduled = message.scheduled, now, "a task delivered before its time was dropped");
            return self.deliveries.delete(&delivery.receipt).await;
        }
        let job = verified.job;
        let Some(turn) = runner.turn(job.tenant) else {
            // A busy tenant never spends an attempt.
            let after = Duration::from_secs((5 * u64::from(delivery.receives)).min(60));
            return self.deliveries.release(&delivery.receipt, after).await;
        };
        let run = match self.claim(&job, &delivery.body).await? {
            Claim::Run(run) => run,
            Claim::Finished => return self.deliveries.delete(&delivery.receipt).await,
            Claim::Leased(ms) => {
                return self
                    .deliveries
                    .release(&delivery.receipt, Duration::from_millis(ms))
                    .await
            }
        };
        let outcome = runner.run(self, &job).await;
        let recorded = self
            .finish(&job, delivery, run, outcome, &verified.keys)
            .await;
        drop(turn);
        // A wake announces an outcome, so it goes once the outcome is recorded, and not otherwise.
        runner.wakes(job.tenant, recorded.is_ok());
        recorded
    }

    /// The task a message names, if it is one its tenant scheduled and it is still live.
    async fn verify(&self, message: &Message) -> Result<Option<Verified>> {
        let keys = self.zfs.task_keys(message.tenant)?;
        let record = self
            .table
            .task(message.tenant, &message.id)
            .await?
            .filter(|r| r.generation == message.generation);
        let Some(record) = record else {
            // Its task was forgotten or replaced, and its schedule left behind.
            self.schedules
                .delete(&schedule_name(
                    message.tenant,
                    &message.id,
                    message.generation,
                ))
                .await?;
            return Ok(None);
        };
        if matches!(
            record.state,
            TaskState::Cancelling | TaskState::Cancelled | TaskState::Done | TaskState::Failed
        ) {
            return Ok(None);
        }
        let (envelope, payload) = match Envelope::open(&keys, &record.envelope) {
            Ok(opened) => opened,
            Err(e) => {
                tracing::warn!(tenant = %hex::encode(message.tenant), task = %message.id,
                    error = format!("{e:#}"), "a task that does not verify was dropped");
                return Ok(None);
            }
        };
        if envelope.tenant != message.tenant
            || envelope.id != message.id
            || envelope.generation != message.generation
        {
            tracing::warn!(tenant = %hex::encode(message.tenant), task = %message.id,
                "a task signed for another task was dropped");
            return Ok(None);
        }
        Ok(Some(Verified {
            keys,
            run_at: envelope.run_at,
            job: Job {
                tenant: envelope.tenant,
                id: envelope.id,
                generation: envelope.generation,
                occurrence: message.scheduled,
                interval_ms: envelope.interval_ms,
                payload,
            },
        }))
    }

    /// Take an occurrence for one attempt, with a conditional write.
    async fn claim(&self, job: &Job, message: &str) -> Result<Claim> {
        let now = self.now();
        let prev = self
            .table
            .run(job.tenant, &job.id, job.generation, job.occurrence)
            .await?;
        if let Some(r) = &prev {
            if r.state.finished() {
                return Ok(Claim::Finished);
            }
            if r.state == RunState::Running && r.lease_until > now {
                return Ok(Claim::Leased(r.lease_until - now));
            }
        }
        let expected = prev.as_ref().map(|r| r.version);
        let attempts = prev.as_ref().map_or(0, |r| r.attempts) + 1;
        let mut run = RunRecord {
            tenant: job.tenant,
            id: job.id.clone(),
            generation: job.generation,
            occurrence: job.occurrence,
            state: RunState::Running,
            attempts,
            lease_until: now + VISIBILITY.as_millis() as u64,
            result: Vec::new(),
            error: prev.as_ref().and_then(|r| r.error.clone()),
            message: message.to_string(),
            updated_at: now,
            version: expected.map_or(1, |v| v + 1),
        };
        if attempts > MAX_ATTEMPTS {
            // Every attempt so far ended with the enclave, or its worker, before it recorded an
            // outcome: one that brings the enclave down must not loop on it for ever.
            run.state = RunState::Failed;
            run.lease_until = 0;
            run.error = Some("every attempt ended before it could record an outcome".into());
            if self.table.put_run(&run, expected).await? {
                self.settle(job, TaskState::Failed).await?;
            }
            return Ok(Claim::Finished);
        }
        if !self.table.put_run(&run, expected).await? {
            return Ok(Claim::Leased(5_000));
        }
        Ok(Claim::Run(run))
    }

    /// Record an attempt's outcome, then finish its delivery: delete it, or release it for the
    /// next attempt.
    async fn finish(
        &self,
        job: &Job,
        delivery: &Delivery,
        mut run: RunRecord,
        outcome: Result<Vec<u8>>,
        keys: &TaskKeys,
    ) -> Result<()> {
        let expected = run.version;
        run.version += 1;
        run.updated_at = self.now();
        run.lease_until = 0;
        let mut again = None;
        match outcome {
            Ok(result) => {
                run.state = RunState::Completed;
                run.result = seal_result(
                    keys,
                    job.tenant,
                    &job.id,
                    job.generation,
                    job.occurrence,
                    &result,
                )?;
                run.error = None;
            }
            Err(e) => {
                // `{:#}` keeps the causes: a trap or a deadline is otherwise recorded as its
                // outermost context and nothing of why.
                run.error = Some(format!("{e:#}").chars().take(512).collect());
                if run.attempts >= MAX_ATTEMPTS {
                    run.state = RunState::Failed;
                } else {
                    run.state = RunState::Retry;
                    again = Some(Duration::from_secs(1u64 << run.attempts.min(8)));
                }
            }
        }
        ensure!(
            self.table.put_run(&run, Some(expected)).await?,
            "the occurrence changed while its attempt ran"
        );
        // The error is what the guest could already print to its own log; `?` escapes it so it
        // cannot forge lines of its own.
        match &run.error {
            Some(error) => tracing::warn!(tenant = %hex::encode(job.tenant), task = %job.id,
                run = %job.run_id(), state = run.state.as_str(), attempts = run.attempts,
                error = ?error, "background task attempt failed"),
            None => tracing::info!(tenant = %hex::encode(job.tenant), task = %job.id,
                run = %job.run_id(), attempts = run.attempts, "background task recorded"),
        }
        if job.interval_ms.is_none() {
            match run.state {
                RunState::Completed => self.settle(job, TaskState::Done).await?,
                RunState::Failed => self.settle(job, TaskState::Failed).await?,
                _ => {}
            }
        }
        match again {
            Some(after) => self.deliveries.release(&delivery.receipt, after).await,
            None => self.deliveries.delete(&delivery.receipt).await,
        }
    }

    /// A one-time task's only occurrence ended, and with it the task — unless a cancel got there
    /// first.
    async fn settle(&self, job: &Job, state: TaskState) -> Result<()> {
        let record = self.table.task(job.tenant, &job.id).await?.filter(|r| {
            r.generation == job.generation
                && matches!(r.state, TaskState::Scheduling | TaskState::Scheduled)
        });
        if let Some(mut record) = record {
            let expected = record.version;
            record.state = state;
            record.version += 1;
            record.updated_at = self.now();
            self.table.put_task(&record, Some(expected)).await?;
        }
        Ok(())
    }

    /// An occurrence came due while its tenant could not be opened: keep it until it can.
    async fn park(&self, message: &Message, body: &str) -> Result<()> {
        if self
            .table
            .run(
                message.tenant,
                &message.id,
                message.generation,
                message.scheduled,
            )
            .await?
            .is_some()
        {
            return Ok(());
        }
        let run = RunRecord {
            tenant: message.tenant,
            id: message.id.clone(),
            generation: message.generation,
            occurrence: message.scheduled,
            state: RunState::WaitingForOwner,
            attempts: 0,
            lease_until: 0,
            result: Vec::new(),
            error: None,
            message: body.to_string(),
            updated_at: self.now(),
            version: 1,
        };
        if self.table.put_run(&run, None).await? {
            tracing::info!(tenant = %hex::encode(message.tenant), task = %message.id,
                "a task came due before its owner signed in to this release; it waits for them");
        }
        Ok(())
    }

    /// Send again what waited for this tenant, each recurring task's latest occurrence standing in
    /// for its missed ones. Whether the tenant has tasks.
    async fn catch_up(&self, tenant: [u8; 16]) -> Result<bool> {
        let mut latest: BTreeMap<(String, [u8; 16]), RunRecord> = BTreeMap::new();
        for run in self.table.waiting_runs(tenant).await? {
            let key = (run.id.clone(), run.generation);
            let older = match latest.remove(&key) {
                Some(kept) if kept.occurrence >= run.occurrence => {
                    latest.insert(key, kept);
                    run
                }
                Some(kept) => {
                    latest.insert(key, run);
                    kept
                }
                None => {
                    latest.insert(key, run);
                    continue;
                }
            };
            self.skip(older).await?;
        }
        for run in latest.values() {
            self.deliveries.send(&run.message, Duration::ZERO).await?;
        }
        Ok(self
            .table
            .tasks(tenant)
            .await?
            .iter()
            .any(|t| !t.state.terminal()))
    }

    async fn skip(&self, mut run: RunRecord) -> Result<()> {
        let expected = run.version;
        run.state = RunState::Skipped;
        run.error = Some("folded into a later occurrence while its owner was away".into());
        run.version += 1;
        run.updated_at = self.now();
        self.table.put_run(&run, Some(expected)).await?;
        Ok(())
    }

    /// Finish what was left half done, and restore a trigger the host removed. Only for tenants
    /// attached here: a task is acted on only once it verifies.
    async fn reconcile(&self) -> Result<()> {
        let now = self.now();
        for record in self.table.tasks_in(TaskState::Scheduling).await? {
            if record.updated_at.saturating_add(STALE_MS) > now || !self.verifies(&record) {
                continue;
            }
            if let Err(e) = self.schedule(record).await {
                tracing::warn!(error = format!("{e:#}"), "finishing a task's schedule");
            }
        }
        for record in self.table.tasks_in(TaskState::Cancelling).await? {
            if record.updated_at.saturating_add(STALE_MS) > now {
                continue;
            }
            if let Err(e) = self.finish_cancel(record).await {
                tracing::warn!(error = format!("{e:#}"), "finishing a task's cancel");
            }
        }
        for record in self.table.tasks_in(TaskState::Scheduled).await? {
            if !self.verifies(&record) {
                continue;
            }
            if let Err(e) = self.restore(&record, now).await {
                tracing::warn!(error = format!("{e:#}"), "restoring a task's trigger");
            }
        }
        Ok(())
    }

    fn verifies(&self, record: &TaskRecord) -> bool {
        self.zfs
            .task_keys(record.tenant)
            .is_ok_and(|keys| Envelope::open(&keys, &record.envelope).is_ok())
    }

    /// A scheduled task whose trigger is gone: make it again. A one-time task's schedule deletes
    /// itself once it fires, so for one already due, only a firing that never arrived is replaced.
    async fn restore(&self, record: &TaskRecord, now: u64) -> Result<()> {
        let future = record.run_at > now.saturating_add(IMMEDIATE_MS);
        if record.interval_ms.is_some() || future {
            if !self.schedules.exists(&record.schedule).await? {
                tracing::warn!(tenant = %hex::encode(record.tenant), task = %record.id,
                    "a task's schedule was missing; made again");
                self.trigger(record).await?;
            }
            return Ok(());
        }
        let fired = self
            .table
            .latest_run(record.tenant, &record.id, record.generation)
            .await?
            .is_some();
        // From when it was scheduled, not when it was due: one enqueued to run at once was due
        // before it existed.
        let since = record.run_at.max(record.updated_at);
        if !fired && since.saturating_add(LOST_MS) < now {
            tracing::warn!(tenant = %hex::encode(record.tenant), task = %record.id,
                "a task's firing never arrived; sent again");
            let due = Message::due(record.tenant, &record.id, record.generation, record.run_at);
            self.deliveries.send(&due, Duration::ZERO).await?;
        }
        Ok(())
    }

    /// Handle what is on the queue now, one at a time, for tests.
    #[cfg(test)]
    async fn drain(self: &Arc<Self>, runner: &Arc<dyn Runner>) -> usize {
        let batch = self.deliveries.receive(10, VISIBILITY).await.unwrap();
        let n = batch.len();
        for delivery in batch {
            self.handle(runner, delivery).await;
        }
        n
    }
}

#[derive(Clone)]
pub struct TaskContext {
    pub queue: Arc<TaskQueue>,
    pub tenant: [u8; 16],
    pub interactive: bool,
}
fn context(state: &State, mutation: bool) -> Result<TaskContext> {
    let ctx = state
        .tasks
        .clone()
        .context("tasks require an authenticated tenant and enabled scheduler")?;
    ensure!(
        !mutation || ctx.interactive,
        "background work cannot authorize more work"
    );
    Ok(ctx)
}
/// The ABI is defined in wit/tasks/tasks.wit. No tenant ID is accepted.
pub fn add_to_linker(linker: &mut wasmtime::component::Linker<State>) -> wasmtime::Result<()> {
    let mut queue = linker.instance("enclave:tasks/queue@0.1.0")?;
    queue.func_wrap_async(
        "enqueue",
        |store, (id, payload, at, interval): (String, Vec<u8>, u64, Option<u64>)| {
            Box::new(async move {
                let result = async move {
                    let ctx = context(store.data(), true)?;
                    ctx.queue
                        .enqueue(ctx.tenant, id, payload, at, interval)
                        .await
                }
                .await;
                Ok((result.map_err(|e| e.to_string()),))
            })
        },
    )?;
    queue.func_wrap_async("status", |store, (id,): (String,)| {
        Box::new(async move {
            let result: Result<String> = async move {
                let ctx = context(store.data(), false)?;
                Ok(serde_json::to_string(
                    &ctx.queue.status(ctx.tenant, &id).await?,
                )?)
            }
            .await;
            Ok((result.map_err(|e| e.to_string()),))
        })
    })?;
    queue.func_wrap_async("cancel", |store, (id,): (String,)| {
        Box::new(async move {
            let result = async move {
                let ctx = context(store.data(), true)?;
                ctx.queue.cancel(ctx.tenant, &id).await
            }
            .await;
            Ok((result.map_err(|e| e.to_string()),))
        })
    })?;
    queue.func_wrap_async("forget", |store, (id,): (String,)| {
        Box::new(async move {
            let result = async move {
                let ctx = context(store.data(), true)?;
                ctx.queue.forget(ctx.tenant, &id).await
            }
            .await;
            Ok((result.map_err(|e| e.to_string()),))
        })
    })?;
    Ok(())
}

#[cfg(test)]
mod tests;
