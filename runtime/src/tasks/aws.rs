//! The production backends: DynamoDB records tasks, EventBridge Scheduler fires them, SQS delivers
//! them.
//!
//! Called as the instance's role, through gvproxy, over TLS that ends in here — the same way every
//! other AWS client in the runtime is. The parent holds that role too, so it can read, write and
//! delete anything here. That is why nothing here is believed without a check: a task runs only if
//! its tenant's key signed it ([`super::envelope`]), and what the host can still do — delete,
//! delay, replay — is denial of service, or a second delivery the occurrence's record absorbs.
//!
//! **The table** holds two kinds of item under the tenant's partition, `T#<tenant>`: the task,
//! `TASK#<id>`, and each occurrence, `RUN#<id>#<generation>#<occurrence>`, the occurrence padded so
//! the latest sorts last. A secondary index, `by-state`, on `state_key` and `updated_at`, answers
//! "which tasks are scheduling, cancelling, scheduled" for the reconciler, and for an operator.
//! Occurrences expire through the table's TTL on `expires_at`.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use aws_sdk_dynamodb::types::AttributeValue;
use aws_smithy_types::error::display::DisplayErrorContext;

use super::deliveries::{Deliveries, Delivery};
use super::schedules::{Schedule, Schedules, When};
use super::table::{RunRecord, RunState, TaskRecord, TaskState, TaskTable};

/// Where the backends are.
#[derive(Debug, Clone)]
pub struct TasksConfig {
    pub table: String,
    pub queue_url: String,
    pub schedule_group: String,
    /// The role EventBridge Scheduler takes to send to the queue.
    pub scheduler_role_arn: String,
    pub region: String,
    /// For tests and local endpoints. A downgrade path, like the guest log client's: pointed at
    /// an `http://` endpoint it sends task metadata in clear. PCR0 records which was built.
    pub endpoint: Option<String>,
}

/// How long an occurrence's record outlives its last write.
const RUN_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const INDEX: &str = "by-state";

/// The three clients, built the way the guest log client is: the default credential chain, which
/// resolves through gvproxy to the instance's role, and the region given to the chain as well as
/// to the client.
pub async fn connect(
    config: &TasksConfig,
) -> Result<(DynamoTable, EventBridgeSchedules, SqsDeliveries)> {
    let region = aws_config::Region::new(config.region.clone());
    let credentials = aws_credential_types::provider::SharedCredentialsProvider::new(
        aws_config::default_provider::credentials::DefaultCredentialsChain::builder()
            .region(region.clone())
            .build()
            .await,
    );
    // Longer than SQS's 20-second long poll, which is the longest call here.
    let timeouts = aws_smithy_types::timeout::TimeoutConfig::builder()
        .operation_timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(5))
        .build();
    let queue_arn = queue_arn(&config.queue_url, &config.region)?;

    let mut dynamo = aws_sdk_dynamodb::Config::builder()
        .behavior_version(aws_sdk_dynamodb::config::BehaviorVersion::latest())
        .region(region.clone())
        .credentials_provider(credentials.clone())
        .timeout_config(timeouts.clone());
    let mut scheduler = aws_sdk_scheduler::Config::builder()
        .behavior_version(aws_sdk_scheduler::config::BehaviorVersion::latest())
        .region(region.clone())
        .credentials_provider(credentials.clone())
        .timeout_config(timeouts.clone());
    let mut sqs = aws_sdk_sqs::Config::builder()
        .behavior_version(aws_sdk_sqs::config::BehaviorVersion::latest())
        .region(region)
        .credentials_provider(credentials)
        .timeout_config(timeouts);
    if let Some(endpoint) = &config.endpoint {
        dynamo = dynamo.endpoint_url(endpoint);
        scheduler = scheduler.endpoint_url(endpoint);
        sqs = sqs.endpoint_url(endpoint);
    }
    Ok((
        DynamoTable {
            client: aws_sdk_dynamodb::Client::from_conf(dynamo.build()),
            table: config.table.clone(),
        },
        EventBridgeSchedules {
            client: aws_sdk_scheduler::Client::from_conf(scheduler.build()),
            group: config.schedule_group.clone(),
            queue_arn,
            role_arn: config.scheduler_role_arn.clone(),
        },
        SqsDeliveries {
            client: aws_sdk_sqs::Client::from_conf(sqs.build()),
            url: config.queue_url.clone(),
        },
    ))
}

/// `https://sqs.<region>.amazonaws.com/<account>/<name>` → `arn:aws:sqs:<region>:<account>:<name>`.
/// The last two path segments, so a local endpoint's URL works too.
fn queue_arn(url: &str, region: &str) -> Result<String> {
    let mut segments = url.trim_end_matches('/').rsplit('/');
    let name = segments.next().filter(|s| !s.is_empty());
    let account = segments.next().filter(|s| !s.is_empty());
    match (account, name) {
        (Some(account), Some(name)) => Ok(format!("arn:aws:sqs:{region}:{account}:{name}")),
        _ => Err(anyhow!(
            "the task queue URL {url:?} does not end in <account>/<name>"
        )),
    }
}

fn aws_error(e: impl std::error::Error + Send + Sync + 'static) -> anyhow::Error {
    anyhow!("{}", DisplayErrorContext(e))
}

// ---- DynamoDB ------------------------------------------------------------------------------

pub struct DynamoTable {
    client: aws_sdk_dynamodb::Client,
    table: String,
}

type Item = HashMap<String, AttributeValue>;

fn pk(tenant: [u8; 16]) -> String {
    format!("T#{}", hex::encode(tenant))
}

fn task_sk(id: &str) -> String {
    format!("TASK#{id}")
}

fn run_prefix(id: &str, generation: [u8; 16]) -> String {
    format!("RUN#{id}#{}#", hex::encode(generation))
}

fn run_sk(id: &str, generation: [u8; 16], occurrence: u64) -> String {
    format!("{}{occurrence:020}", run_prefix(id, generation))
}

fn s(v: impl Into<String>) -> AttributeValue {
    AttributeValue::S(v.into())
}

fn n(v: u64) -> AttributeValue {
    AttributeValue::N(v.to_string())
}

fn b(v: &[u8]) -> AttributeValue {
    AttributeValue::B(aws_smithy_types::Blob::new(v))
}

fn get_s(item: &Item, key: &str) -> Result<String> {
    item.get(key)
        .and_then(|v| v.as_s().ok())
        .cloned()
        .with_context(|| format!("a task item without {key}"))
}

fn get_n(item: &Item, key: &str) -> Result<u64> {
    item.get(key)
        .and_then(|v| v.as_n().ok())
        .with_context(|| format!("a task item without {key}"))?
        .parse()
        .with_context(|| format!("a task item's {key}"))
}

fn get_b(item: &Item, key: &str) -> Result<Vec<u8>> {
    Ok(item
        .get(key)
        .and_then(|v| v.as_b().ok())
        .with_context(|| format!("a task item without {key}"))?
        .as_ref()
        .to_vec())
}

fn get_16(item: &Item, key: &str) -> Result<[u8; 16]> {
    let mut out = [0u8; 16];
    hex::decode_to_slice(get_s(item, key)?, &mut out)
        .with_context(|| format!("a task item's {key}"))?;
    Ok(out)
}

fn task_item(task: &TaskRecord) -> Item {
    let mut item = HashMap::from([
        ("pk".to_string(), s(pk(task.tenant))),
        ("sk".to_string(), s(task_sk(&task.id))),
        ("tenant".to_string(), s(hex::encode(task.tenant))),
        ("id".to_string(), s(&task.id)),
        ("generation".to_string(), s(hex::encode(task.generation))),
        ("state".to_string(), s(task.state.as_str())),
        (
            "state_key".to_string(),
            s(format!("task#{}", task.state.as_str())),
        ),
        ("run_at".to_string(), n(task.run_at)),
        ("schedule".to_string(), s(&task.schedule)),
        ("envelope".to_string(), b(&task.envelope)),
        ("updated_at".to_string(), n(task.updated_at)),
        ("version".to_string(), n(task.version)),
    ]);
    if let Some(interval) = task.interval_ms {
        item.insert("interval_ms".to_string(), n(interval));
    }
    item
}

fn task_record(item: &Item) -> Result<TaskRecord> {
    Ok(TaskRecord {
        tenant: get_16(item, "tenant")?,
        id: get_s(item, "id")?,
        generation: get_16(item, "generation")?,
        state: TaskState::parse(&get_s(item, "state")?).context("a task item's state")?,
        run_at: get_n(item, "run_at")?,
        interval_ms: item
            .contains_key("interval_ms")
            .then(|| get_n(item, "interval_ms"))
            .transpose()?,
        schedule: get_s(item, "schedule")?,
        envelope: get_b(item, "envelope")?,
        updated_at: get_n(item, "updated_at")?,
        version: get_n(item, "version")?,
    })
}

fn run_item(run: &RunRecord) -> Item {
    let mut item = HashMap::from([
        ("pk".to_string(), s(pk(run.tenant))),
        (
            "sk".to_string(),
            s(run_sk(&run.id, run.generation, run.occurrence)),
        ),
        ("tenant".to_string(), s(hex::encode(run.tenant))),
        ("id".to_string(), s(&run.id)),
        ("generation".to_string(), s(hex::encode(run.generation))),
        ("occurrence".to_string(), n(run.occurrence)),
        ("state".to_string(), s(run.state.as_str())),
        (
            "state_key".to_string(),
            s(format!("run#{}", run.state.as_str())),
        ),
        ("attempts".to_string(), n(u64::from(run.attempts))),
        ("lease_until".to_string(), n(run.lease_until)),
        ("result".to_string(), b(&run.result)),
        ("message".to_string(), s(&run.message)),
        ("updated_at".to_string(), n(run.updated_at)),
        ("version".to_string(), n(run.version)),
        (
            "expires_at".to_string(),
            n(run.updated_at / 1000 + RUN_TTL.as_secs()),
        ),
    ]);
    if let Some(error) = &run.error {
        item.insert("error".to_string(), s(error));
    }
    item
}

fn run_record(item: &Item) -> Result<RunRecord> {
    Ok(RunRecord {
        tenant: get_16(item, "tenant")?,
        id: get_s(item, "id")?,
        generation: get_16(item, "generation")?,
        occurrence: get_n(item, "occurrence")?,
        state: RunState::parse(&get_s(item, "state")?).context("a run item's state")?,
        attempts: u32::try_from(get_n(item, "attempts")?).context("a run item's attempts")?,
        lease_until: get_n(item, "lease_until")?,
        result: get_b(item, "result")?,
        error: item
            .contains_key("error")
            .then(|| get_s(item, "error"))
            .transpose()?,
        message: get_s(item, "message")?,
        updated_at: get_n(item, "updated_at")?,
        version: get_n(item, "version")?,
    })
}

impl DynamoTable {
    async fn get(&self, tenant: [u8; 16], sk: String) -> Result<Option<Item>> {
        let out = self
            .client
            .get_item()
            .table_name(&self.table)
            .key("pk", s(pk(tenant)))
            .key("sk", s(sk))
            .consistent_read(true)
            .send()
            .await
            .map_err(aws_error)?;
        Ok(out.item)
    }

    /// Put `item` if the stored version is `expected`.
    async fn put(&self, item: Item, expected: Option<u64>) -> Result<bool> {
        let mut put = self
            .client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item));
        put = match expected {
            None => put.condition_expression("attribute_not_exists(pk)"),
            Some(v) => put
                .condition_expression("#v = :expected")
                .expression_attribute_names("#v", "version")
                .expression_attribute_values(":expected", n(v)),
        };
        match put.send().await {
            Ok(_) => Ok(true),
            Err(e)
                if e.as_service_error()
                    .is_some_and(|e| e.is_conditional_check_failed_exception()) =>
            {
                Ok(false)
            }
            Err(e) => Err(aws_error(e)),
        }
    }

    /// Every item under the tenant whose sort key starts with `prefix`, latest first if `reverse`,
    /// at most `limit` of them.
    async fn query(
        &self,
        tenant: [u8; 16],
        prefix: String,
        reverse: bool,
        limit: Option<i32>,
    ) -> Result<Vec<Item>> {
        let mut out = Vec::new();
        let mut start = None;
        loop {
            let page = self
                .client
                .query()
                .table_name(&self.table)
                .key_condition_expression("pk = :pk AND begins_with(sk, :prefix)")
                .expression_attribute_values(":pk", s(pk(tenant)))
                .expression_attribute_values(":prefix", s(&prefix))
                .scan_index_forward(!reverse)
                .consistent_read(true)
                .set_limit(limit)
                .set_exclusive_start_key(start)
                .send()
                .await
                .map_err(aws_error)?;
            out.extend(page.items.unwrap_or_default());
            start = page.last_evaluated_key;
            if start.is_none() || limit.is_some() {
                return Ok(out);
            }
        }
    }
}

#[async_trait::async_trait]
impl TaskTable for DynamoTable {
    async fn task(&self, tenant: [u8; 16], id: &str) -> Result<Option<TaskRecord>> {
        self.get(tenant, task_sk(id))
            .await?
            .as_ref()
            .map(task_record)
            .transpose()
    }

    async fn put_task(&self, task: &TaskRecord, expected: Option<u64>) -> Result<bool> {
        self.put(task_item(task), expected).await
    }

    async fn delete_task(&self, tenant: [u8; 16], id: &str, expected: u64) -> Result<bool> {
        let delete = self
            .client
            .delete_item()
            .table_name(&self.table)
            .key("pk", s(pk(tenant)))
            .key("sk", s(task_sk(id)))
            .condition_expression("#v = :expected")
            .expression_attribute_names("#v", "version")
            .expression_attribute_values(":expected", n(expected));
        match delete.send().await {
            Ok(_) => Ok(true),
            Err(e)
                if e.as_service_error()
                    .is_some_and(|e| e.is_conditional_check_failed_exception()) =>
            {
                Ok(false)
            }
            Err(e) => Err(aws_error(e)),
        }
    }

    async fn tasks(&self, tenant: [u8; 16]) -> Result<Vec<TaskRecord>> {
        self.query(tenant, "TASK#".into(), false, None)
            .await?
            .iter()
            .map(task_record)
            .collect()
    }

    async fn tasks_in(&self, state: TaskState) -> Result<Vec<TaskRecord>> {
        let mut out = Vec::new();
        let mut start = None;
        loop {
            let page = self
                .client
                .query()
                .table_name(&self.table)
                .index_name(INDEX)
                .key_condition_expression("state_key = :state")
                .expression_attribute_values(":state", s(format!("task#{}", state.as_str())))
                .set_exclusive_start_key(start)
                .send()
                .await
                .map_err(aws_error)?;
            for item in page.items.unwrap_or_default() {
                out.push(task_record(&item)?);
            }
            start = page.last_evaluated_key;
            if start.is_none() {
                return Ok(out);
            }
        }
    }

    async fn run(
        &self,
        tenant: [u8; 16],
        id: &str,
        generation: [u8; 16],
        occurrence: u64,
    ) -> Result<Option<RunRecord>> {
        self.get(tenant, run_sk(id, generation, occurrence))
            .await?
            .as_ref()
            .map(run_record)
            .transpose()
    }

    async fn latest_run(
        &self,
        tenant: [u8; 16],
        id: &str,
        generation: [u8; 16],
    ) -> Result<Option<RunRecord>> {
        self.query(tenant, run_prefix(id, generation), true, Some(1))
            .await?
            .first()
            .map(run_record)
            .transpose()
    }

    async fn put_run(&self, run: &RunRecord, expected: Option<u64>) -> Result<bool> {
        self.put(run_item(run), expected).await
    }

    async fn waiting_runs(&self, tenant: [u8; 16]) -> Result<Vec<RunRecord>> {
        Ok(self
            .query(tenant, "RUN#".into(), false, None)
            .await?
            .iter()
            .map(run_record)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .filter(|r| r.state == RunState::WaitingForOwner)
            .collect())
    }
}

// ---- EventBridge Scheduler -----------------------------------------------------------------

pub struct EventBridgeSchedules {
    client: aws_sdk_scheduler::Client,
    group: String,
    queue_arn: String,
    role_arn: String,
}

/// `at(2026-11-01T12:00:00)`: whole seconds, rounded up so it never fires early.
fn at_expression(ms: u64) -> String {
    let secs = ms.div_ceil(1000);
    let time = super::schedules::format_time(secs * 1000);
    format!("at({})", time.trim_end_matches('Z'))
}

/// `rate(30 minutes)`. The queue only accepts whole minutes, the smallest rate EventBridge has.
fn rate_expression(interval_ms: u64) -> String {
    match interval_ms / 60_000 {
        1 => "rate(1 minute)".to_string(),
        minutes => format!("rate({minutes} minutes)"),
    }
}

#[async_trait::async_trait]
impl Schedules for EventBridgeSchedules {
    async fn create(&self, schedule: &Schedule) -> Result<()> {
        use aws_sdk_scheduler::types::{
            ActionAfterCompletion, FlexibleTimeWindow, FlexibleTimeWindowMode, RetryPolicy, Target,
        };
        let target = Target::builder()
            .arn(&self.queue_arn)
            .role_arn(&self.role_arn)
            .input(&schedule.message)
            // EventBridge's own retries, for when it cannot reach the queue: for a day.
            .retry_policy(
                RetryPolicy::builder()
                    .maximum_event_age_in_seconds(86_400)
                    .maximum_retry_attempts(185)
                    .build(),
            )
            .build()
            .map_err(aws_error)?;
        let mut create = self
            .client
            .create_schedule()
            .name(&schedule.name)
            .group_name(&self.group)
            .schedule_expression_timezone("UTC")
            .flexible_time_window(
                FlexibleTimeWindow::builder()
                    .mode(FlexibleTimeWindowMode::Off)
                    .build()
                    .map_err(aws_error)?,
            )
            .target(target);
        create = match schedule.when {
            When::At(at) => create
                .schedule_expression(at_expression(at))
                .action_after_completion(ActionAfterCompletion::Delete),
            When::Every { interval_ms, from } => {
                let create = create.schedule_expression(rate_expression(interval_ms));
                match from {
                    Some(from) => {
                        create.start_date(aws_smithy_types::DateTime::from_millis(from as i64))
                    }
                    None => create,
                }
            }
        };
        match create.send().await {
            Ok(_) => Ok(()),
            // Made before, under the same deterministic name.
            Err(e)
                if e.as_service_error()
                    .is_some_and(|e| e.is_conflict_exception()) =>
            {
                Ok(())
            }
            Err(e) => Err(aws_error(e)),
        }
    }

    async fn delete(&self, name: &str) -> Result<()> {
        let delete = self
            .client
            .delete_schedule()
            .name(name)
            .group_name(&self.group);
        match delete.send().await {
            Ok(_) => Ok(()),
            Err(e)
                if e.as_service_error()
                    .is_some_and(|e| e.is_resource_not_found_exception()) =>
            {
                Ok(())
            }
            Err(e) => Err(aws_error(e)),
        }
    }

    async fn exists(&self, name: &str) -> Result<bool> {
        let get = self
            .client
            .get_schedule()
            .name(name)
            .group_name(&self.group);
        match get.send().await {
            Ok(_) => Ok(true),
            Err(e)
                if e.as_service_error()
                    .is_some_and(|e| e.is_resource_not_found_exception()) =>
            {
                Ok(false)
            }
            Err(e) => Err(aws_error(e)),
        }
    }
}

// ---- SQS -----------------------------------------------------------------------------------

pub struct SqsDeliveries {
    client: aws_sdk_sqs::Client,
    url: String,
}

#[async_trait::async_trait]
impl Deliveries for SqsDeliveries {
    async fn receive(&self, max: usize, visibility: Duration) -> Result<Vec<Delivery>> {
        use aws_sdk_sqs::types::MessageSystemAttributeName;
        let out = self
            .client
            .receive_message()
            .queue_url(&self.url)
            .max_number_of_messages(max.clamp(1, 10) as i32)
            .wait_time_seconds(20)
            .visibility_timeout(visibility.as_secs().min(43_200) as i32)
            .message_system_attribute_names(MessageSystemAttributeName::ApproximateReceiveCount)
            .send()
            .await
            .map_err(aws_error)?;
        Ok(out
            .messages
            .unwrap_or_default()
            .into_iter()
            .filter_map(|m| {
                let receives = m
                    .attributes
                    .as_ref()
                    .and_then(|a| a.get(&MessageSystemAttributeName::ApproximateReceiveCount))
                    .and_then(|c| c.parse().ok())
                    .unwrap_or(1);
                Some(Delivery {
                    body: m.body?,
                    receipt: m.receipt_handle?,
                    receives,
                })
            })
            .collect())
    }

    async fn delete(&self, receipt: &str) -> Result<()> {
        self.client
            .delete_message()
            .queue_url(&self.url)
            .receipt_handle(receipt)
            .send()
            .await
            .map_err(aws_error)?;
        Ok(())
    }

    async fn release(&self, receipt: &str, after: Duration) -> Result<()> {
        self.client
            .change_message_visibility()
            .queue_url(&self.url)
            .receipt_handle(receipt)
            .visibility_timeout(after.as_secs().min(43_200) as i32)
            .send()
            .await
            .map_err(aws_error)?;
        Ok(())
    }

    async fn send(&self, body: &str, delay: Duration) -> Result<()> {
        self.client
            .send_message()
            .queue_url(&self.url)
            .message_body(body)
            .delay_seconds(delay.as_secs().min(900) as i32)
            .send()
            .await
            .map_err(aws_error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_queue_arn_comes_from_its_url() {
        assert_eq!(
            queue_arn(
                "https://sqs.eu-west-2.amazonaws.com/123456789012/tasks",
                "eu-west-2"
            )
            .unwrap(),
            "arn:aws:sqs:eu-west-2:123456789012:tasks"
        );
        assert_eq!(
            queue_arn("http://localhost:4566/000000000000/tasks/", "us-east-1").unwrap(),
            "arn:aws:sqs:us-east-1:000000000000:tasks"
        );
        assert!(queue_arn("tasks", "us-east-1").is_err());
    }

    #[test]
    fn expressions_are_what_eventbridge_takes() {
        assert_eq!(at_expression(1_793_534_400_000), "at(2026-11-01T12:00:00)");
        assert_eq!(
            at_expression(1_793_534_400_001),
            "at(2026-11-01T12:00:01)",
            "never early"
        );
        assert_eq!(rate_expression(60_000), "rate(1 minute)");
        assert_eq!(rate_expression(1_800_000), "rate(30 minutes)");
    }

    /// Items round-trip, the occurrence's sort key sorting by time.
    #[test]
    fn items_round_trip() {
        let task = TaskRecord {
            tenant: [1; 16],
            id: "job".into(),
            generation: [2; 16],
            state: TaskState::Scheduled,
            run_at: 5,
            interval_ms: Some(60_000),
            schedule: "t-x".into(),
            envelope: vec![1, 2, 3],
            updated_at: 6,
            version: 7,
        };
        assert_eq!(task_record(&task_item(&task)).unwrap(), task);
        let run = RunRecord {
            tenant: [1; 16],
            id: "job".into(),
            generation: [2; 16],
            occurrence: 9,
            state: RunState::WaitingForOwner,
            attempts: 2,
            lease_until: 0,
            result: vec![],
            error: Some("why".into()),
            message: "{}".into(),
            updated_at: 10,
            version: 1,
        };
        assert_eq!(run_record(&run_item(&run)).unwrap(), run);
        assert!(run_sk("job", [2; 16], 9) < run_sk("job", [2; 16], 10));
    }
}
