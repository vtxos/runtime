//! The background-task clients against LocalEmu, which serves DynamoDB, EventBridge Scheduler and
//! SQS on one endpoint: an open-source fork of LocalStack's community edition.
//!
//! Every test is `#[ignore]`d so default `cargo test` skips them. Run with Docker present:
//!
//! ```bash
//! scripts/localemu-image.sh
//! cargo test -p enclave-runtime --test tasks_aws -- --ignored --test-threads=1
//! ```
//!
//! Each test starts its own LocalEmu, so tests never share state.
//!
//! One difference from AWS shapes the tests: LocalEmu fires a schedule into the queue with its
//! input unchanged, as AWS does, but leaves `<aws.scheduler.scheduled-time>` unfilled, where AWS
//! puts the firing's time. So a schedule's firing is checked for arriving with the task's message,
//! and the consumer is driven by the occurrence as AWS would deliver it.

use std::sync::Arc;
use std::time::Duration;

use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage};

use enclave_runtime::clock::WallClockAdapter;
use enclave_runtime::store::zfs::Zfs;
use enclave_runtime::tasks::aws::{connect, TasksConfig};
use enclave_runtime::tasks::deliveries::Deliveries;
use enclave_runtime::tasks::schedules::{Message, Schedule, Schedules, When, SCHEDULED_TIME};
use enclave_runtime::tasks::table::{RunRecord, RunState, TaskRecord, TaskState, TaskTable};
use enclave_runtime::tasks::{Backend, Job, Runner, TaskLimits, TaskQueue};
use enclave_runtime::HostClock;

/// Built by `scripts/localemu-image.sh`.
const IMAGE: (&str, &str) = ("enclave-runtime/localemu", "1.3.2");
const REGION: &str = "us-east-1";
const TABLE: &str = "tasks";
const GROUP: &str = "tasks";

struct LocalEmu {
    /// Killed when dropped.
    _container: ContainerAsync<GenericImage>,
    endpoint: String,
}

async fn localemu() -> LocalEmu {
    // The runtime's clients take the default credential chain, which reads these first. Set once,
    // before any client exists; LocalEmu accepts any.
    static CREDENTIALS: std::sync::Once = std::sync::Once::new();
    CREDENTIALS.call_once(|| {
        std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
    });
    let container = GenericImage::new(IMAGE.0, IMAGE.1)
        .with_exposed_port(4566.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Ready."))
        .start()
        .await
        .expect("LocalEmu container start; is the image there? scripts/localemu-image.sh");
    let port = container
        .get_host_port_ipv4(4566)
        .await
        .expect("LocalEmu's port");
    LocalEmu {
        _container: container,
        endpoint: format!("http://127.0.0.1:{port}"),
    }
}

fn credentials() -> aws_credential_types::Credentials {
    aws_credential_types::Credentials::new("test", "test", None, None, "localemu")
}

/// Make what a deployment makes for background tasks — the table with its index and TTL, the queue, the schedule
/// group — and the runtime's settings for them.
async fn provision(emu: &LocalEmu) -> TasksConfig {
    use aws_sdk_dynamodb::types::{
        AttributeDefinition, BillingMode, GlobalSecondaryIndex, KeySchemaElement, KeyType,
        Projection, ProjectionType, ScalarAttributeType, TimeToLiveSpecification,
    };
    let region = aws_config::Region::new(REGION);
    let dynamo = aws_sdk_dynamodb::Client::from_conf(
        aws_sdk_dynamodb::Config::builder()
            .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
            .region(region.clone())
            .credentials_provider(credentials())
            .endpoint_url(&emu.endpoint)
            .build(),
    );
    let attribute = |name: &str, kind: ScalarAttributeType| {
        AttributeDefinition::builder()
            .attribute_name(name)
            .attribute_type(kind)
            .build()
            .unwrap()
    };
    let key = |name: &str, kind: KeyType| {
        KeySchemaElement::builder()
            .attribute_name(name)
            .key_type(kind)
            .build()
            .unwrap()
    };
    dynamo
        .create_table()
        .table_name(TABLE)
        .billing_mode(BillingMode::PayPerRequest)
        .attribute_definitions(attribute("pk", ScalarAttributeType::S))
        .attribute_definitions(attribute("sk", ScalarAttributeType::S))
        .attribute_definitions(attribute("state_key", ScalarAttributeType::S))
        .attribute_definitions(attribute("updated_at", ScalarAttributeType::N))
        .key_schema(key("pk", KeyType::Hash))
        .key_schema(key("sk", KeyType::Range))
        .global_secondary_indexes(
            GlobalSecondaryIndex::builder()
                .index_name("by-state")
                .key_schema(key("state_key", KeyType::Hash))
                .key_schema(key("updated_at", KeyType::Range))
                .projection(
                    Projection::builder()
                        .projection_type(ProjectionType::All)
                        .build(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("create the table");
    dynamo
        .update_time_to_live()
        .table_name(TABLE)
        .time_to_live_specification(
            TimeToLiveSpecification::builder()
                .attribute_name("expires_at")
                .enabled(true)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("turn on the table's TTL");

    let sqs = aws_sdk_sqs::Client::from_conf(
        aws_sdk_sqs::Config::builder()
            .behavior_version(aws_sdk_sqs::config::BehaviorVersion::latest())
            .region(region.clone())
            .credentials_provider(credentials())
            .endpoint_url(&emu.endpoint)
            .build(),
    );
    let queue_url = sqs
        .create_queue()
        .queue_name("tasks")
        .send()
        .await
        .expect("create the queue")
        .queue_url
        .expect("a queue URL");

    scheduler(emu)
        .create_schedule_group()
        .name(GROUP)
        .send()
        .await
        .expect("create the schedule group");

    TasksConfig {
        table: TABLE.into(),
        queue_url,
        schedule_group: GROUP.into(),
        scheduler_role_arn: "arn:aws:iam::000000000000:role/scheduler".into(),
        region: REGION.into(),
        endpoint: Some(emu.endpoint.clone()),
    }
}

fn scheduler(emu: &LocalEmu) -> aws_sdk_scheduler::Client {
    aws_sdk_scheduler::Client::from_conf(
        aws_sdk_scheduler::Config::builder()
            .behavior_version(aws_sdk_scheduler::config::BehaviorVersion::latest())
            .region(aws_config::Region::new(REGION))
            .credentials_provider(credentials())
            .endpoint_url(&emu.endpoint)
            .build(),
    )
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn task(id: &str, state: TaskState, version: u64) -> TaskRecord {
    TaskRecord {
        tenant: [1; 16],
        id: id.into(),
        generation: [2; 16],
        state,
        run_at: 5_000,
        interval_ms: Some(60_000),
        schedule: format!("t-{id}"),
        envelope: vec![1, 2, 3],
        updated_at: now_ms(),
        version,
    }
}

fn run(occurrence: u64, state: RunState, version: u64) -> RunRecord {
    RunRecord {
        tenant: [1; 16],
        id: "job".into(),
        generation: [2; 16],
        occurrence,
        state,
        attempts: 1,
        lease_until: 0,
        result: vec![9],
        error: None,
        message: "{}".into(),
        updated_at: now_ms(),
        version,
    }
}

/// Every write conditional on the version read, and the reads the queue relies on: by key, the
/// latest occurrence, by state through the index, and what waits for its owner.
#[tokio::test]
#[ignore = "requires Docker and scripts/localemu-image.sh"]
async fn the_table_takes_conditional_writes_and_answers_by_state() {
    let emu = localemu().await;
    let (table, _, _) = connect(&provision(&emu).await).await.unwrap();

    let first = task("job", TaskState::Scheduling, 1);
    assert!(table.put_task(&first, None).await.unwrap());
    assert!(
        !table.put_task(&first, None).await.unwrap(),
        "created twice"
    );
    let scheduled = task("job", TaskState::Scheduled, 2);
    assert!(table.put_task(&scheduled, Some(1)).await.unwrap());
    assert!(
        !table.put_task(&scheduled, Some(1)).await.unwrap(),
        "a write on a stale version went through"
    );
    assert_eq!(
        table.task([1; 16], "job").await.unwrap(),
        Some(scheduled.clone())
    );
    assert!(table.task([2; 16], "job").await.unwrap().is_none());

    table
        .put_task(&task("other", TaskState::Cancelling, 1), None)
        .await
        .unwrap();
    assert_eq!(table.tasks([1; 16]).await.unwrap().len(), 2);
    let ids = |records: Vec<TaskRecord>| records.into_iter().map(|t| t.id).collect::<Vec<_>>();
    assert_eq!(
        ids(table.tasks_in(TaskState::Scheduled).await.unwrap()),
        ["job"]
    );
    assert_eq!(
        ids(table.tasks_in(TaskState::Cancelling).await.unwrap()),
        ["other"]
    );
    assert!(table.tasks_in(TaskState::Done).await.unwrap().is_empty());

    let completed = run(9, RunState::Completed, 1);
    assert!(table.put_run(&completed, None).await.unwrap());
    for (occurrence, state) in [(10, RunState::WaitingForOwner), (100, RunState::Retry)] {
        assert!(table
            .put_run(&run(occurrence, state, 1), None)
            .await
            .unwrap());
    }
    assert!(!table
        .put_run(&run(9, RunState::Running, 1), None)
        .await
        .unwrap());
    assert_eq!(
        table
            .latest_run([1; 16], "job", [2; 16])
            .await
            .unwrap()
            .unwrap()
            .occurrence,
        100,
        "the latest occurrence sorts last"
    );
    assert_eq!(
        table.run([1; 16], "job", [2; 16], 9).await.unwrap(),
        Some(completed)
    );
    let waiting = table.waiting_runs([1; 16]).await.unwrap();
    assert_eq!(
        waiting.iter().map(|r| r.occurrence).collect::<Vec<_>>(),
        [10]
    );

    assert!(
        !table.delete_task([1; 16], "job", 1).await.unwrap(),
        "deleted on a stale version"
    );
    assert!(table.delete_task([1; 16], "job", 2).await.unwrap());
    assert!(table.task([1; 16], "job").await.unwrap().is_none());
}

/// A message is hidden while it is worked on, comes back when released, and can be delayed.
#[tokio::test]
#[ignore = "requires Docker and scripts/localemu-image.sh"]
async fn the_queue_hides_releases_delays_and_deletes() {
    let emu = localemu().await;
    let (_, _, queue) = connect(&provision(&emu).await).await.unwrap();

    queue.send("first", Duration::ZERO).await.unwrap();
    let got = queue.receive(10, Duration::from_secs(2)).await.unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].body.as_str(), got[0].receives), ("first", 1));
    // Hidden for two seconds, then received again.
    let again = queue.receive(10, Duration::from_secs(60)).await.unwrap();
    assert_eq!((again[0].body.as_str(), again[0].receives), ("first", 2));
    queue
        .release(&again[0].receipt, Duration::ZERO)
        .await
        .unwrap();
    let released = queue.receive(10, Duration::from_secs(60)).await.unwrap();
    assert_eq!(released[0].receives, 3);
    queue.delete(&released[0].receipt).await.unwrap();

    let sent = std::time::Instant::now();
    queue.send("later", Duration::from_secs(3)).await.unwrap();
    let later = queue.receive(10, Duration::from_secs(60)).await.unwrap();
    assert_eq!(later[0].body, "later", "the deleted message came back");
    assert!(
        sent.elapsed() >= Duration::from_secs(2),
        "the delay was not kept"
    );
}

/// A schedule fires into the queue with the task's message, once, and is gone after. Making it
/// twice is harmless, and so is removing one that is not there.
#[tokio::test]
#[ignore = "requires Docker and scripts/localemu-image.sh"]
async fn a_schedule_fires_into_the_queue_with_the_tasks_message() {
    let emu = localemu().await;
    let (_, schedules, queue) = connect(&provision(&emu).await).await.unwrap();

    let message = Message::template([1; 16], "job", [2; 16]);
    let schedule = Schedule {
        name: "t-job".into(),
        when: When::At(now_ms() + 3_000),
        message: message.clone(),
    };
    schedules.create(&schedule).await.unwrap();
    schedules.create(&schedule).await.unwrap();
    assert!(schedules.exists("t-job").await.unwrap());

    let fired = queue.receive(10, Duration::from_secs(60)).await.unwrap();
    assert_eq!(fired.len(), 1, "fired once");
    // AWS puts the firing's time in place of the placeholder; LocalEmu leaves it.
    assert_eq!(fired[0].body, message);
    assert!(fired[0].body.contains(SCHEDULED_TIME));
    assert!(
        !schedules.exists("t-job").await.unwrap(),
        "a one-time schedule outlived its firing"
    );

    schedules.delete("t-job").await.unwrap();
    schedules
        .create(&Schedule {
            name: "t-beat".into(),
            when: When::Every {
                interval_ms: 60_000,
                from: Some(now_ms() + 60 * 60_000),
            },
            message,
        })
        .await
        .unwrap();
    assert!(schedules.exists("t-beat").await.unwrap());
    schedules.delete("t-beat").await.unwrap();
    assert!(!schedules.exists("t-beat").await.unwrap());
}

/// The runner the queue is driven with: it echoes the payload back as the result.
struct Echo;

#[async_trait::async_trait]
impl Runner for Echo {
    fn turn(&self, _tenant: [u8; 16]) -> Option<Box<dyn Send>> {
        Some(Box::new(()))
    }
    async fn run(&self, _queue: &Arc<TaskQueue>, job: &Job) -> anyhow::Result<Vec<u8>> {
        Ok(job.payload.clone())
    }
    fn wakes(&self, _tenant: [u8; 16], _deliver: bool) {}
}

/// A whole task, through the table and the queue: enqueued, delivered, verified, claimed, run
/// and recorded. And one for later, through the scheduler: scheduled, then cancelled.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker and scripts/localemu-image.sh"]
async fn a_task_runs_through_the_table_and_the_queue() {
    let emu = localemu().await;
    let config = provision(&emu).await;
    let fs = Zfs::scratch().await;
    fs.tenant_dir([1; 16]).await.unwrap();
    let clock = Arc::new(WallClockAdapter::new(Arc::new(HostClock)).unwrap());
    let queue = TaskQueue::open(
        fs,
        clock,
        TaskLimits::default(),
        Backend::aws(&config).await.unwrap(),
    )
    .await
    .unwrap();

    // Due now: straight on the queue, with its time, as the scheduler would have put it.
    queue
        .enqueue([1; 16], "job".into(), b"work".to_vec(), 0, None)
        .await
        .unwrap();
    let runner: Arc<dyn Runner> = Arc::new(Echo);
    let worker = tokio::spawn(queue.clone().run(runner));
    let status = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let status = queue.status([1; 16], "job").await.unwrap();
            if status.status == "completed" {
                return status;
            }
            assert!(!worker.is_finished(), "the consumer stopped");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("the task never completed");
    assert_eq!(status.result, b"work");
    assert_eq!(status.attempts, 1);

    // Due in two hours: a schedule in the group, until it is cancelled.
    queue
        .enqueue(
            [1; 16],
            "later".into(),
            vec![],
            now_ms() + 2 * 60 * 60_000,
            None,
        )
        .await
        .unwrap();
    let schedules_in_group = || async {
        scheduler(&emu)
            .list_schedules()
            .group_name(GROUP)
            .send()
            .await
            .unwrap()
            .schedules
            .len()
    };
    assert_eq!(schedules_in_group().await, 1);
    assert_eq!(
        queue.status([1; 16], "later").await.unwrap().status,
        "pending"
    );
    queue.cancel([1; 16], "later").await.unwrap();
    assert_eq!(schedules_in_group().await, 0);
    assert_eq!(
        queue.status([1; 16], "later").await.unwrap().status,
        "cancelled"
    );
    worker.abort();
}
