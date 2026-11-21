use super::*;
use crate::clock::{HostClock, TrustedClock};
use crate::store::backend::memory::MemoryBackend;
use crate::store::zfs::{Disk, Zfs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

#[derive(Debug, Clone)]
struct Clock(Arc<AtomicU64>);
impl TrustedClock for Clock {
    fn now(&self) -> Result<Duration> {
        Ok(Duration::from_millis(self.0.load(Ordering::Relaxed)))
    }
    fn resolution(&self) -> Duration {
        Duration::from_millis(1)
    }
    fn describe(&self) -> String {
        "test".into()
    }
}
impl Clock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
    fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::Relaxed);
    }
}

/// The backend in memory, with its parts kept by type so a test can play the host.
struct Aws {
    table: Arc<table::MemoryTable>,
    deliveries: Arc<deliveries::MemoryDeliveries>,
    schedules: Arc<schedules::MemorySchedules>,
}
impl Aws {
    fn new(wall: Arc<WallClockAdapter>) -> Self {
        let deliveries = Arc::new(deliveries::MemoryDeliveries::new(Duration::from_millis(50)));
        Aws {
            table: Arc::new(table::MemoryTable::default()),
            schedules: Arc::new(schedules::MemorySchedules::new(deliveries.clone(), wall)),
            deliveries,
        }
    }
    fn backend(&self) -> Backend {
        Backend {
            table: self.table.clone(),
            schedules: self.schedules.clone(),
            deliveries: self.deliveries.clone(),
            clockwork: Some(self.schedules.clone()),
        }
    }
}

struct Setup {
    q: Arc<TaskQueue>,
    clock: Clock,
    aws: Aws,
}

async fn setup(limits: TaskLimits) -> Setup {
    let fs = Zfs::scratch().await;
    for tenant in [[1; 16], [2; 16]] {
        fs.tenant_dir(tenant).await.unwrap();
    }
    let clock = Clock(Arc::new(AtomicU64::new(1_800_000_000_000)));
    let wall = Arc::new(WallClockAdapter::new(Arc::new(clock.clone())).unwrap());
    let aws = Aws::new(wall.clone());
    let q = TaskQueue::open(fs, wall, limits, aws.backend())
        .await
        .unwrap();
    Setup { q, clock, aws }
}

/// A runner without a guest: it records what it ran, echoes the payload, and fails or is busy on
/// request.
#[derive(Default)]
struct Fake {
    runs: Mutex<Vec<Job>>,
    fail: AtomicBool,
    busy: AtomicBool,
    wakes: Mutex<Vec<([u8; 16], bool)>>,
    hold: Option<Duration>,
    running: AtomicUsize,
    most: AtomicUsize,
}
#[async_trait::async_trait]
impl Runner for Fake {
    fn turn(&self, _tenant: [u8; 16]) -> Option<Box<dyn Send>> {
        (!self.busy.load(Ordering::SeqCst)).then(|| Box::new(()) as Box<dyn Send>)
    }
    async fn run(&self, _queue: &Arc<TaskQueue>, job: &Job) -> Result<Vec<u8>> {
        let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.most.fetch_max(now, Ordering::SeqCst);
        if let Some(hold) = self.hold {
            tokio::time::sleep(hold).await;
        }
        self.running.fetch_sub(1, Ordering::SeqCst);
        self.runs.lock().unwrap().push(job.clone());
        if self.fail.load(Ordering::SeqCst) {
            anyhow::bail!("co-signer refused the run id");
        }
        Ok(job.payload.clone())
    }
    fn wakes(&self, tenant: [u8; 16], deliver: bool) {
        self.wakes.lock().unwrap().push((tenant, deliver));
    }
}
impl Fake {
    fn runs(&self) -> Vec<Job> {
        self.runs.lock().unwrap().clone()
    }
}

fn runner(fake: &Arc<Fake>) -> Arc<dyn Runner> {
    fake.clone()
}

async fn add(q: &TaskQueue, tenant: u8, id: &str, at: u64) {
    q.enqueue([tenant; 16], id.into(), vec![tenant], at, None)
        .await
        .unwrap();
}

#[tokio::test]
async fn identity_quota_and_idempotency_are_tenant_scoped() {
    let Setup { q, .. } = setup(TaskLimits {
        per_tenant: 1,
        ..Default::default()
    })
    .await;
    add(&q, 1, "same", 0).await;
    add(&q, 1, "same", 0).await;
    add(&q, 2, "same", 0).await;
    assert!(q
        .enqueue([1; 16], "same".into(), vec![2], 0, None)
        .await
        .is_err());
    assert!(q
        .enqueue([1; 16], "same".into(), vec![1], 5, None)
        .await
        .is_err());
    assert!(q
        .enqueue([1; 16], "other".into(), vec![], 0, None)
        .await
        .is_err());
    assert_eq!(q.status([2; 16], "same").await.unwrap().status, "pending");
    assert!(q.cancel([3; 16], "same").await.is_err());
    assert!(q
        .enqueue([3; 16], "new".into(), vec![], 0, None)
        .await
        .is_err());
    q.cancel([1; 16], "same").await.unwrap();
    q.forget([1; 16], "same").await.unwrap();
    add(&q, 1, "other", 0).await;
    assert!(q
        .enqueue([2; 16], "../escape".into(), vec![], 0, None)
        .await
        .is_err());
    assert!(
        q.enqueue([2; 16], "beat".into(), vec![], 0, Some(1_000))
            .await
            .is_err(),
        "an interval is whole minutes"
    );
}

#[tokio::test]
async fn a_due_task_runs_once_and_its_result_is_kept() {
    let Setup { q, aws, .. } = setup(Default::default()).await;
    let fake = Arc::new(Fake::default());
    q.enqueue([1; 16], "job".into(), b"work".to_vec(), 0, None)
        .await
        .unwrap();
    let body = aws.deliveries.bodies().remove(0);
    assert_eq!(q.drain(&runner(&fake)).await, 1);
    let runs = fake.runs();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].payload, b"work");
    let status = q.status([1; 16], "job").await.unwrap();
    assert_eq!(status.status, "completed");
    assert_eq!(status.result, b"work");
    assert_eq!(status.run_id.as_deref(), Some(runs[0].run_id().as_str()));
    assert!(aws.deliveries.is_empty());
    assert_eq!(*fake.wakes.lock().unwrap(), vec![([1; 16], true)]);

    // The host delivers it again: the finished occurrence absorbs it.
    aws.deliveries.send(&body, Duration::ZERO).await.unwrap();
    q.drain(&runner(&fake)).await;
    assert_eq!(fake.runs().len(), 1, "a second delivery ran again");
    assert!(aws.deliveries.is_empty());
}

/// The host can write the table: a task it changed, or one signed by another tenant, never runs.
#[tokio::test]
async fn a_forged_or_altered_task_is_dropped() {
    let Setup { q, aws, .. } = setup(Default::default()).await;
    let fake = Arc::new(Fake::default());
    add(&q, 1, "job", 0).await;
    aws.table.tamper([1; 16], "job", |task| {
        let at = task.envelope.len() / 2;
        task.envelope[at] ^= 1;
    });
    q.drain(&runner(&fake)).await;
    assert!(fake.runs().is_empty(), "an altered task ran");
    assert!(aws.deliveries.is_empty());

    // Tenant 2's task, copied under tenant 1's name.
    add(&q, 2, "theirs", 0).await;
    let theirs = aws_task(&aws, [2; 16], "theirs").await;
    add(&q, 1, "mine", 0).await;
    aws.table.tamper([1; 16], "mine", |task| {
        task.envelope = theirs.envelope.clone()
    });
    q.drain(&runner(&fake)).await;
    assert_eq!(
        fake.runs().iter().map(|j| j.tenant).collect::<Vec<_>>(),
        vec![[2; 16]],
        "only tenant 2's own task ran"
    );
}

async fn aws_task(aws: &Aws, tenant: [u8; 16], id: &str) -> TaskRecord {
    aws.table.task(tenant, id).await.unwrap().unwrap()
}

#[tokio::test]
async fn a_delivery_before_its_time_is_dropped() {
    let Setup { q, aws, clock } = setup(Default::default()).await;
    let fake = Arc::new(Fake::default());
    let later = clock.now() + 2 * 60 * 60_000;
    add(&q, 1, "later", later).await;
    let task = aws_task(&aws, [1; 16], "later").await;
    assert_eq!(task.state, TaskState::Scheduled);
    assert!(aws.schedules.exists(&task.schedule).await.unwrap());
    let early = Message::due([1; 16], "later", task.generation, later);
    aws.deliveries.send(&early, Duration::ZERO).await.unwrap();
    q.drain(&runner(&fake)).await;
    assert!(fake.runs().is_empty(), "a task ran two hours early");

    clock.advance(2 * 60 * 60_000);
    assert_eq!(aws.schedules.fire_due().await, 1);
    q.drain(&runner(&fake)).await;
    assert_eq!(fake.runs().len(), 1, "it runs at its time");
    assert_eq!(fake.runs()[0].occurrence, later);
}

#[tokio::test]
async fn a_cancelled_task_does_not_run_and_a_finished_one_stays_finished() {
    let Setup { q, aws, .. } = setup(Default::default()).await;
    let fake = Arc::new(Fake::default());
    add(&q, 1, "job", 0).await;
    q.cancel([1; 16], "job").await.unwrap();
    q.drain(&runner(&fake)).await;
    assert!(fake.runs().is_empty());
    assert_eq!(q.status([1; 16], "job").await.unwrap().status, "cancelled");
    assert!(aws.deliveries.is_empty());

    add(&q, 2, "done", 0).await;
    q.drain(&runner(&fake)).await;
    q.cancel([2; 16], "done").await.unwrap();
    assert_eq!(
        q.status([2; 16], "done").await.unwrap().status,
        "completed",
        "cancel overwrote a finished task"
    );
}

#[tokio::test]
async fn forget_frees_the_id_and_the_next_generation_has_its_own_run_id() {
    let Setup { q, .. } = setup(Default::default()).await;
    let fake = Arc::new(Fake::default());
    add(&q, 1, "job", 0).await;
    assert!(
        q.forget([1; 16], "job").await.is_err(),
        "forgot a live task"
    );
    q.drain(&runner(&fake)).await;
    q.forget([1; 16], "job").await.unwrap();
    assert!(q.status([1; 16], "job").await.is_err());
    add(&q, 1, "job", 0).await;
    q.drain(&runner(&fake)).await;
    let runs = fake.runs();
    assert_eq!(runs.len(), 2);
    assert_ne!(runs[0].run_id(), runs[1].run_id());
}

#[tokio::test]
async fn retries_back_off_keep_their_run_id_and_eventually_stop() {
    let Setup { q, aws, .. } = setup(Default::default()).await;
    let fake = Arc::new(Fake::default());
    fake.fail.store(true, Ordering::SeqCst);
    add(&q, 1, "job", 0).await;
    for attempt in 1..=MAX_ATTEMPTS {
        aws.deliveries.reveal();
        assert_eq!(q.drain(&runner(&fake)).await, 1, "attempt {attempt}");
        let status = q.status([1; 16], "job").await.unwrap();
        assert_eq!(status.attempts, attempt);
        assert_eq!(
            status.error.as_deref(),
            Some("co-signer refused the run id"),
            "the recorded error names why"
        );
    }
    assert_eq!(q.status([1; 16], "job").await.unwrap().status, "failed");
    assert!(aws.deliveries.is_empty());
    let runs = fake.runs();
    assert_eq!(runs.len(), MAX_ATTEMPTS as usize);
    assert!(runs.iter().all(|j| j.run_id() == runs[0].run_id()));
}

/// Each occurrence is its own: one that fails for good does not stop the next.
#[tokio::test]
async fn a_recurring_task_survives_a_failed_occurrence() {
    let Setup { q, aws, clock } = setup(Default::default()).await;
    let fake = Arc::new(Fake::default());
    q.enqueue([1; 16], "beat".into(), b"tick".to_vec(), 0, Some(MINUTE_MS))
        .await
        .unwrap();
    assert_eq!(aws.schedules.fire_due().await, 1);
    fake.fail.store(true, Ordering::SeqCst);
    for _ in 1..=MAX_ATTEMPTS {
        aws.deliveries.reveal();
        q.drain(&runner(&fake)).await;
    }
    assert!(aws.deliveries.is_empty());
    assert_eq!(q.status([1; 16], "beat").await.unwrap().status, "pending");

    fake.fail.store(false, Ordering::SeqCst);
    clock.advance(MINUTE_MS);
    assert_eq!(aws.schedules.fire_due().await, 1);
    q.drain(&runner(&fake)).await;
    let runs = fake.runs();
    assert_eq!(runs.len(), MAX_ATTEMPTS as usize + 1);
    assert_ne!(runs.last().unwrap().run_id(), runs[0].run_id());
    let status = q.status([1; 16], "beat").await.unwrap();
    assert_eq!(
        (status.status, status.result.as_slice()),
        ("pending", b"tick".as_slice())
    );

    // Missed minutes fold into one firing.
    clock.advance(10 * MINUTE_MS);
    assert_eq!(aws.schedules.fire_due().await, 1);
}

#[tokio::test]
async fn a_busy_tenant_never_spends_an_attempt() {
    let Setup { q, aws, .. } = setup(Default::default()).await;
    let fake = Arc::new(Fake::default());
    fake.busy.store(true, Ordering::SeqCst);
    add(&q, 1, "job", 0).await;
    q.drain(&runner(&fake)).await;
    assert!(fake.runs().is_empty());
    assert_eq!(aws.deliveries.len(), 1, "released, not dropped");
    assert_eq!(q.status([1; 16], "job").await.unwrap().attempts, 0);
    fake.busy.store(false, Ordering::SeqCst);
    aws.deliveries.reveal();
    q.drain(&runner(&fake)).await;
    assert_eq!(q.status([1; 16], "job").await.unwrap().attempts, 1);
}

/// An attempt the enclave died in comes back once its lease runs out, and counts.
#[tokio::test]
async fn an_interrupted_attempt_is_claimed_again_with_the_same_run_id() {
    let Setup { q, aws, clock } = setup(Default::default()).await;
    let fake = Arc::new(Fake::default());
    add(&q, 1, "job", 0).await;
    let delivery = aws
        .deliveries
        .receive(1, VISIBILITY)
        .await
        .unwrap()
        .remove(0);
    let message = Message::parse(&delivery.body).unwrap();
    let verified = q.verify(&message).await.unwrap().unwrap();
    let Claim::Run(_) = q.claim(&verified.job, &delivery.body).await.unwrap() else {
        panic!("the first claim should take it");
    };
    // The enclave dies here. Its delivery comes back; while the lease holds, nobody runs it.
    aws.deliveries.reveal();
    q.drain(&runner(&fake)).await;
    assert!(fake.runs().is_empty(), "ran under another attempt's lease");
    clock.advance(VISIBILITY.as_millis() as u64 + 1);
    aws.deliveries.reveal();
    q.drain(&runner(&fake)).await;
    let runs = fake.runs();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id(), verified.job.run_id());
    let status = q.status([1; 16], "job").await.unwrap();
    assert_eq!((status.status, status.attempts), ("completed", 2));
}

/// A new release has no tenant key until its owner signs in. A task due before then waits, and
/// runs when they do.
#[tokio::test]
async fn a_task_due_before_its_owner_signs_in_waits_for_them() {
    let backend: Arc<dyn crate::store::backend::Backend> = Arc::new(MemoryBackend::new());
    let disk = Disk::scratch().unwrap();
    let clock = Clock(Arc::new(AtomicU64::new(1_800_000_000_000)));
    let wall = Arc::new(WallClockAdapter::new(Arc::new(clock.clone())).unwrap());
    let aws = Aws::new(wall.clone());

    let fs = Zfs::scratch_on(&disk, backend.clone()).await;
    fs.tenant_dir([1; 16]).await.unwrap();
    let q = TaskQueue::open(fs.clone(), wall.clone(), Default::default(), aws.backend())
        .await
        .unwrap();
    add(&q, 1, "job", 0).await;
    drop(q);
    drop(fs);

    // Restarted, and nobody has signed in.
    let fs = Zfs::scratch_on(&disk, backend).await;
    let q = TaskQueue::open(fs.clone(), wall, Default::default(), aws.backend())
        .await
        .unwrap();
    let fake = Arc::new(Fake::default());
    q.drain(&runner(&fake)).await;
    assert!(fake.runs().is_empty());
    assert!(aws.deliveries.is_empty());
    assert_eq!(aws.table.waiting_runs([1; 16]).await.unwrap().len(), 1);

    // The owner signs in.
    fs.tenant_dir([1; 16]).await.unwrap();
    q.drain(&runner(&fake)).await;
    assert_eq!(fake.runs().len(), 1);
    assert_eq!(q.status([1; 16], "job").await.unwrap().status, "completed");
    assert!(aws.table.waiting_runs([1; 16]).await.unwrap().is_empty());
}

#[tokio::test]
async fn the_reconciler_finishes_half_done_work_and_restores_a_missing_schedule() {
    let Setup { q, aws, clock } = setup(Default::default()).await;
    let later = clock.now() + 2 * 60 * 60_000;

    // A create that stopped after its record.
    add(&q, 1, "half-made", later).await;
    let task = aws_task(&aws, [1; 16], "half-made").await;
    aws.schedules.delete(&task.schedule).await.unwrap();
    aws.table
        .tamper([1; 16], "half-made", |t| t.state = TaskState::Scheduling);
    // A cancel that stopped before removing its schedule.
    add(&q, 1, "half-cancelled", later).await;
    aws.table.tamper([1; 16], "half-cancelled", |t| {
        t.state = TaskState::Cancelling
    });
    // A recurring task whose schedule the host deleted.
    q.enqueue([2; 16], "beat".into(), vec![], later, Some(MINUTE_MS))
        .await
        .unwrap();
    let beat = aws_task(&aws, [2; 16], "beat").await;
    aws.schedules.delete(&beat.schedule).await.unwrap();

    clock.advance(STALE_MS + 1);
    q.reconcile().await.unwrap();

    let made = aws_task(&aws, [1; 16], "half-made").await;
    assert_eq!(made.state, TaskState::Scheduled);
    assert!(aws.schedules.exists(&made.schedule).await.unwrap());
    let cancelled = aws_task(&aws, [1; 16], "half-cancelled").await;
    assert_eq!(cancelled.state, TaskState::Cancelled);
    assert!(!aws.schedules.exists(&cancelled.schedule).await.unwrap());
    assert!(aws.schedules.exists(&beat.schedule).await.unwrap());
}

/// A task enqueued to run at once was due before it existed: the reconciler must not take its
/// pending delivery for a lost one and send a second.
#[tokio::test]
async fn the_reconciler_leaves_a_task_that_is_only_waiting_its_turn() {
    let Setup { q, aws, clock } = setup(Default::default()).await;
    add(&q, 1, "now", 0).await;
    q.reconcile().await.unwrap();
    assert_eq!(aws.deliveries.len(), 1);
    // An hour after it was scheduled, with nothing having run it, it is lost.
    clock.advance(LOST_MS + 1);
    q.reconcile().await.unwrap();
    assert_eq!(aws.deliveries.len(), 2);
}

/// A schedule left behind by a forgotten task fires into nothing, and removes itself.
#[tokio::test]
async fn an_orphan_schedule_is_removed_when_it_fires() {
    let Setup { q, aws, clock } = setup(Default::default()).await;
    let fake = Arc::new(Fake::default());
    q.enqueue([1; 16], "beat".into(), vec![], 0, Some(MINUTE_MS))
        .await
        .unwrap();
    let beat = aws_task(&aws, [1; 16], "beat").await;
    // Forgotten behind the scheduler's back: the record goes, the schedule stays.
    aws.table
        .tamper([1; 16], "beat", |t| t.state = TaskState::Cancelled);
    q.forget([1; 16], "beat").await.unwrap();
    assert!(aws.schedules.exists(&beat.schedule).await.unwrap());
    clock.advance(MINUTE_MS);
    aws.schedules.fire_due().await;
    q.drain(&runner(&fake)).await;
    assert!(fake.runs().is_empty());
    assert!(!aws.schedules.exists(&beat.schedule).await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn tenants_run_at_once_within_the_limit() {
    let Setup { q, aws, .. } = setup(TaskLimits {
        concurrency: 3,
        ..Default::default()
    })
    .await;
    let fake = Arc::new(Fake {
        hold: Some(Duration::from_millis(100)),
        ..Default::default()
    });
    for job in 0..4 {
        add(&q, 1, &format!("a-{job}"), 0).await;
        add(&q, 2, &format!("b-{job}"), 0).await;
    }
    let worker = tokio::spawn(q.clone().run(runner(&fake)));
    tokio::time::timeout(Duration::from_secs(10), async {
        while fake.runs().len() < 8 || !aws.deliveries.is_empty() {
            assert!(!worker.is_finished(), "the consumer stopped");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the due tasks did not drain");
    worker.abort();
    let most = fake.most.load(Ordering::SeqCst);
    assert!(most <= 3, "{most} ran at once");
    assert!(most > 1, "nothing ran at once");
}

// ---- against a real guest ----------------------------------------------------------------

async fn guest(q: &Arc<TaskQueue>) -> Arc<crate::serve::ServeHandle> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../examples/guest-http/target/wasm32-wasip2/release/guest-http.wasm");
    let bytes = std::fs::read(path).expect("build examples/guest-http for wasm32-wasip2");
    let (logs, _collector) = crate::telemetry::logs::start(Arc::new(crate::TracingLogSink));
    let env = crate::GuestEnvironment::new(
        q.zfs.clone(),
        Arc::new(HostClock),
        Arc::new(nitro_nsm::fake::FakeNsm::new()),
        &[],
        &[],
        logs,
    )
    .unwrap();
    let engine = crate::ServeHandle::engine_with_watchdog().unwrap();
    let handle = crate::ServeHandle::new(&engine, &bytes, env)
        .unwrap()
        .with_tenancy(Arc::new(crate::Tenancy::new(Default::default())))
        .with_tasks(q.clone())
        .unwrap();
    handle.verify_instantiates().await.unwrap();
    Arc::new(handle)
}

async fn request(
    handle: &crate::ServeHandle,
    tenant: u8,
    method: &str,
    path: &str,
    payload: &[u8],
) -> (u16, Vec<u8>) {
    use http_body_util::BodyExt;
    let body = http_body_util::Full::new(bytes::Bytes::copy_from_slice(payload))
        .map_err(|e: std::convert::Infallible| -> wasmtime_wasi_http::p2::bindings::http::types::ErrorCode { match e {} })
        .boxed_unsync();
    let req = hyper::Request::builder()
        .method(method)
        .header("host", "enclave.test")
        .uri(path)
        .body(body)
        .unwrap();
    let response = handle
        .handle(
            wasmtime_wasi_http::p2::bindings::http::types::Scheme::Https,
            req,
            Some(&[tenant; 16]),
        )
        .await
        .unwrap();
    (
        response.status().as_u16(),
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
}

#[tokio::test]
#[ignore = "requires built guest-http component"]
async fn a_client_schedules_and_only_its_tenant_runs_it() {
    let Setup { q, .. } = setup(Default::default()).await;
    let handle = guest(&q).await;
    let runner: Arc<dyn Runner> = handle.clone();
    assert_eq!(
        request(&handle, 1, "POST", "/tasks/job", b"alice").await.0,
        202
    );
    assert_eq!(request(&handle, 2, "GET", "/tasks/job", b"").await.0, 404);
    q.drain(&runner).await;
    let status = q.status([1; 16], "job").await.unwrap();
    assert_eq!(
        (status.status, status.result.as_slice()),
        ("completed", b"alice".as_slice())
    );
    assert!(!q.zfs.tenant_path([2; 16]).join("http-example").exists());
    assert_eq!(request(&handle, 1, "GET", "/tasks/job", b"").await.0, 200);
}

/// The backoff, driven by a guest that really fails: its message survives the host round trip,
/// and every retry keeps the occurrence's run id.
#[tokio::test]
#[ignore = "requires built guest-http component"]
async fn a_guest_that_returns_an_error_retries_until_the_occurrence_is_failed() {
    let Setup { q, aws, .. } = setup(Default::default()).await;
    let handle = guest(&q).await;
    let runner: Arc<dyn Runner> = handle.clone();
    q.enqueue([1; 16], "job".into(), b"fail".to_vec(), 0, None)
        .await
        .unwrap();
    let mut run_ids = Vec::new();
    for attempt in 1..=MAX_ATTEMPTS {
        aws.deliveries.reveal();
        q.drain(&runner).await;
        let status = q.status([1; 16], "job").await.unwrap();
        assert_eq!(status.attempts, attempt);
        assert!(
            status
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("example task failure"),
            "the guest's own message did not survive: {status:?}"
        );
        run_ids.push(status.run_id.unwrap());
    }
    assert_eq!(q.status([1; 16], "job").await.unwrap().status, "failed");
    assert!(run_ids.iter().all(|id| *id == run_ids[0]));
    // The guest writes one file per run id, and only on success.
    let tasks = q.zfs.tenant_path([1; 16]).join("http-example/tasks");
    let names: Vec<String> = std::fs::read_dir(tasks)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(
        !names.iter().any(|n| n.starts_with("job")),
        "a task that only ever failed still wrote a result: {names:?}"
    );
}

#[tokio::test]
#[ignore = "requires built guest-http component"]
async fn background_cannot_enqueue_and_a_cpu_loop_releases_the_tenant() {
    let Setup { q, aws, .. } = setup(TaskLimits {
        timeout: Duration::from_millis(500),
        ..Default::default()
    })
    .await;
    let handle = guest(&q).await;
    let runner: Arc<dyn Runner> = handle.clone();
    q.enqueue(
        [1; 16],
        "authority".into(),
        b"check-authority".to_vec(),
        0,
        None,
    )
    .await
    .unwrap();
    q.drain(&runner).await;
    assert_eq!(
        q.status([1; 16], "authority").await.unwrap().status,
        "completed"
    );
    assert!(q.status([1; 16], "unauthorized").await.is_err());
    q.enqueue([1; 16], "loop".into(), b"spin".to_vec(), 0, None)
        .await
        .unwrap();
    q.drain(&runner).await;
    let status = q.status([1; 16], "loop").await.unwrap();
    assert!(status.error.unwrap().contains("deadline"));
    assert_eq!(aws.deliveries.len(), 1, "the timed-out attempt is retried");
    assert_eq!(request(&handle, 1, "GET", "/memory", b"").await.0, 200);
}

#[tokio::test]
#[ignore = "requires built guest-http component"]
async fn a_missing_tenant_is_never_recreated_by_a_worker() {
    let Setup { q, .. } = setup(Default::default()).await;
    let handle = guest(&q).await;
    let runner: Arc<dyn Runner> = handle.clone();
    add(&q, 1, "job", 0).await;
    std::fs::remove_dir_all(q.zfs.tenant_path([1; 16])).unwrap();
    q.drain(&runner).await;
    assert!(!q.zfs.tenant_path([1; 16]).exists());
    assert_ne!(q.status([1; 16], "job").await.unwrap().status, "completed");
}
