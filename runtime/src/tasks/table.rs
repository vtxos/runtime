//! Where tasks are recorded: one record per task, and one per occurrence of it.
//!
//! DynamoDB in production ([`super::aws::DynamoTable`]), so an operator can see every scheduled
//! task, its state and how its last run went. Every write is conditional on the version it read,
//! so two writers never overwrite each other unseen. Nothing read back is trusted on its own: a
//! task runs only once its envelope verifies ([`super::envelope`]).

use anyhow::Result;

/// Where a task stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Recorded; its schedule is being made.
    Scheduling,
    Scheduled,
    /// Cancelled; its schedule is being removed.
    Cancelling,
    Cancelled,
    /// A one-time task whose run completed.
    Done,
    /// A one-time task whose run failed for good.
    Failed,
}

impl TaskState {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Cancelled | Self::Done | Self::Failed)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduling => "scheduling",
            Self::Scheduled => "scheduled",
            Self::Cancelling => "cancelling",
            Self::Cancelled => "cancelled",
            Self::Done => "done",
            Self::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [
            Self::Scheduling,
            Self::Scheduled,
            Self::Cancelling,
            Self::Cancelled,
            Self::Done,
            Self::Failed,
        ]
        .into_iter()
        .find(|state| state.as_str() == s)
    }
}

/// Where one occurrence stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    Running,
    /// Its last attempt failed; another is coming.
    Retry,
    Completed,
    Failed,
    /// It came due while its tenant's owner had not signed in to this release.
    WaitingForOwner,
    /// Folded into a later occurrence of the same task.
    Skipped,
}

impl RunState {
    pub fn finished(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Skipped)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Retry => "retry",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::WaitingForOwner => "waiting-for-owner",
            Self::Skipped => "skipped",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [
            Self::Running,
            Self::Retry,
            Self::Completed,
            Self::Failed,
            Self::WaitingForOwner,
            Self::Skipped,
        ]
        .into_iter()
        .find(|state| state.as_str() == s)
    }
}

/// One task: what it is (signed, in `envelope`) and where it stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRecord {
    pub tenant: [u8; 16],
    pub id: String,
    pub generation: [u8; 16],
    pub state: TaskState,
    pub run_at: u64,
    pub interval_ms: Option<u64>,
    /// The scheduler's name for it.
    pub schedule: String,
    /// The signed task ([`super::envelope::Envelope`]).
    pub envelope: Vec<u8>,
    pub updated_at: u64,
    pub version: u64,
}

/// One occurrence of a task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRecord {
    pub tenant: [u8; 16],
    pub id: String,
    pub generation: [u8; 16],
    /// When it was due, in Unix milliseconds: the occurrence's identity.
    pub occurrence: u64,
    pub state: RunState,
    pub attempts: u32,
    /// Until when the attempt running now owns it.
    pub lease_until: u64,
    /// The guest's result, sealed ([`super::envelope::seal_result`]).
    pub result: Vec<u8>,
    pub error: Option<String>,
    /// The delivery that fired it, so one waiting for its owner can be sent again.
    pub message: String,
    pub updated_at: u64,
    pub version: u64,
}

/// The table. `expected` is the version a write is conditional on, `None` meaning nothing is
/// stored yet; a write whose condition fails returns `false`.
#[async_trait::async_trait]
pub trait TaskTable: Send + Sync {
    async fn task(&self, tenant: [u8; 16], id: &str) -> Result<Option<TaskRecord>>;
    async fn put_task(&self, task: &TaskRecord, expected: Option<u64>) -> Result<bool>;
    async fn delete_task(&self, tenant: [u8; 16], id: &str, expected: u64) -> Result<bool>;
    async fn tasks(&self, tenant: [u8; 16]) -> Result<Vec<TaskRecord>>;
    async fn tasks_in(&self, state: TaskState) -> Result<Vec<TaskRecord>>;
    async fn run(
        &self,
        tenant: [u8; 16],
        id: &str,
        generation: [u8; 16],
        occurrence: u64,
    ) -> Result<Option<RunRecord>>;
    async fn latest_run(
        &self,
        tenant: [u8; 16],
        id: &str,
        generation: [u8; 16],
    ) -> Result<Option<RunRecord>>;
    async fn put_run(&self, run: &RunRecord, expected: Option<u64>) -> Result<bool>;
    async fn waiting_runs(&self, tenant: [u8; 16]) -> Result<Vec<RunRecord>>;
}

/// The table in memory: the emulator's and the tests' stand-in for DynamoDB.
#[cfg(any(test, feature = "testing"))]
#[derive(Default)]
pub struct MemoryTable {
    inner: std::sync::Mutex<Inner>,
}

#[cfg(any(test, feature = "testing"))]
type RunKey = ([u8; 16], String, [u8; 16], u64);

#[cfg(any(test, feature = "testing"))]
#[derive(Default)]
struct Inner {
    tasks: std::collections::BTreeMap<([u8; 16], String), TaskRecord>,
    runs: std::collections::BTreeMap<RunKey, RunRecord>,
}

#[cfg(any(test, feature = "testing"))]
impl MemoryTable {
    /// Change a stored task as the host could, for tests.
    pub fn tamper(&self, tenant: [u8; 16], id: &str, edit: impl FnOnce(&mut TaskRecord)) {
        let mut inner = self.inner.lock().expect("table mutex");
        if let Some(task) = inner.tasks.get_mut(&(tenant, id.to_string())) {
            edit(task);
        }
    }

    /// Change a stored run as the host could, for tests.
    pub fn tamper_run(&self, tenant: [u8; 16], id: &str, edit: impl Fn(&mut RunRecord)) {
        let mut inner = self.inner.lock().expect("table mutex");
        for (key, run) in inner.runs.iter_mut() {
            if key.0 == tenant && key.1 == id {
                edit(run);
            }
        }
    }
}

#[cfg(any(test, feature = "testing"))]
#[async_trait::async_trait]
impl TaskTable for MemoryTable {
    async fn task(&self, tenant: [u8; 16], id: &str) -> Result<Option<TaskRecord>> {
        let inner = self.inner.lock().expect("table mutex");
        Ok(inner.tasks.get(&(tenant, id.to_string())).cloned())
    }

    async fn put_task(&self, task: &TaskRecord, expected: Option<u64>) -> Result<bool> {
        let mut inner = self.inner.lock().expect("table mutex");
        let key = (task.tenant, task.id.clone());
        if inner.tasks.get(&key).map(|t| t.version) != expected {
            return Ok(false);
        }
        inner.tasks.insert(key, task.clone());
        Ok(true)
    }

    async fn delete_task(&self, tenant: [u8; 16], id: &str, expected: u64) -> Result<bool> {
        let mut inner = self.inner.lock().expect("table mutex");
        let key = (tenant, id.to_string());
        if inner.tasks.get(&key).map(|t| t.version) != Some(expected) {
            return Ok(false);
        }
        inner.tasks.remove(&key);
        Ok(true)
    }

    async fn tasks(&self, tenant: [u8; 16]) -> Result<Vec<TaskRecord>> {
        let inner = self.inner.lock().expect("table mutex");
        Ok(inner
            .tasks
            .values()
            .filter(|t| t.tenant == tenant)
            .cloned()
            .collect())
    }

    async fn tasks_in(&self, state: TaskState) -> Result<Vec<TaskRecord>> {
        let inner = self.inner.lock().expect("table mutex");
        Ok(inner
            .tasks
            .values()
            .filter(|t| t.state == state)
            .cloned()
            .collect())
    }

    async fn run(
        &self,
        tenant: [u8; 16],
        id: &str,
        generation: [u8; 16],
        occurrence: u64,
    ) -> Result<Option<RunRecord>> {
        let inner = self.inner.lock().expect("table mutex");
        Ok(inner
            .runs
            .get(&(tenant, id.to_string(), generation, occurrence))
            .cloned())
    }

    async fn latest_run(
        &self,
        tenant: [u8; 16],
        id: &str,
        generation: [u8; 16],
    ) -> Result<Option<RunRecord>> {
        let inner = self.inner.lock().expect("table mutex");
        Ok(inner
            .runs
            .values()
            .filter(|r| r.tenant == tenant && r.id == id && r.generation == generation)
            .max_by_key(|r| r.occurrence)
            .cloned())
    }

    async fn put_run(&self, run: &RunRecord, expected: Option<u64>) -> Result<bool> {
        let mut inner = self.inner.lock().expect("table mutex");
        let key = (run.tenant, run.id.clone(), run.generation, run.occurrence);
        if inner.runs.get(&key).map(|r| r.version) != expected {
            return Ok(false);
        }
        inner.runs.insert(key, run.clone());
        Ok(true)
    }

    async fn waiting_runs(&self, tenant: [u8; 16]) -> Result<Vec<RunRecord>> {
        let inner = self.inner.lock().expect("table mutex");
        Ok(inner
            .runs
            .values()
            .filter(|r| r.tenant == tenant && r.state == RunState::WaitingForOwner)
            .cloned()
            .collect())
    }
}
