//! When a task fires: a schedule that puts a message naming it on the queue at its time.
//!
//! EventBridge Scheduler in production ([`super::aws::EventBridgeSchedules`]). The runtime keeps no
//! clock of its own for tasks: it makes a schedule when a task is enqueued, removes it when one is
//! cancelled, and otherwise only receives what fires. A schedule's message carries no secret and
//! no authority — only which task is due and when — so the host, which can make schedules of its
//! own, can at most ask for a task the tenant really scheduled to be looked at.

use anyhow::{bail, Context, Result};
use aws_smithy_types::date_time::Format;
use aws_smithy_types::DateTime;
use serde::{Deserialize, Serialize};

/// What EventBridge Scheduler replaces with each firing's scheduled time.
pub const SCHEDULED_TIME: &str = "<aws.scheduler.scheduled-time>";

/// When a schedule fires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum When {
    /// Once, at this time (Unix milliseconds).
    At(u64),
    /// Every `interval_ms`, from `from` if given and otherwise from now.
    Every { interval_ms: u64, from: Option<u64> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schedule {
    pub name: String,
    pub when: When,
    /// The message each firing sends, with [`SCHEDULED_TIME`] in it.
    pub message: String,
}

#[async_trait::async_trait]
pub trait Schedules: Send + Sync {
    /// Make `schedule`. One that already exists under its name is left as it is.
    async fn create(&self, schedule: &Schedule) -> Result<()>;
    /// Remove a schedule. One that does not exist is fine.
    async fn delete(&self, name: &str) -> Result<()>;
    async fn exists(&self, name: &str) -> Result<bool>;
}

/// The scheduler's name for a task: deterministic, so making it twice makes it once.
pub fn schedule_name(tenant: [u8; 16], id: &str, generation: [u8; 16]) -> String {
    let digest = nitro_attestation::sha256(
        &[
            b"aegira/task/schedule\0".as_slice(),
            &tenant,
            &generation,
            id.as_bytes(),
        ]
        .concat(),
    );
    format!("t-{}", hex::encode(&digest[..20]))
}

/// The message a firing delivers: which task, and when it was due.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub tenant: [u8; 16],
    pub id: String,
    pub generation: [u8; 16],
    /// When it was due, in Unix milliseconds.
    pub scheduled: u64,
}

#[derive(Serialize, Deserialize)]
struct Wire {
    v: u32,
    tenant: String,
    task: String,
    generation: String,
    scheduled: String,
}

impl Message {
    /// The message a schedule sends, its time left for the scheduler to fill in.
    pub fn template(tenant: [u8; 16], id: &str, generation: [u8; 16]) -> String {
        Self::encode(tenant, id, generation, SCHEDULED_TIME.to_string())
    }

    /// The message for an occurrence due at `scheduled`.
    pub fn due(tenant: [u8; 16], id: &str, generation: [u8; 16], scheduled: u64) -> String {
        Self::encode(tenant, id, generation, format_time(scheduled))
    }

    fn encode(tenant: [u8; 16], id: &str, generation: [u8; 16], scheduled: String) -> String {
        serde_json::to_string(&Wire {
            v: 1,
            tenant: hex::encode(tenant),
            task: id.to_string(),
            generation: hex::encode(generation),
            scheduled,
        })
        .expect("a message encodes")
    }

    pub fn parse(body: &str) -> Result<Message> {
        let wire: Wire = serde_json::from_str(body).context("decoding a task message")?;
        if wire.v != 1 {
            bail!("a task message of unknown version {}", wire.v);
        }
        let mut tenant = [0u8; 16];
        let mut generation = [0u8; 16];
        hex::decode_to_slice(&wire.tenant, &mut tenant).context("a task message's tenant")?;
        hex::decode_to_slice(&wire.generation, &mut generation)
            .context("a task message's generation")?;
        Ok(Message {
            tenant,
            id: wire.task,
            generation,
            scheduled: parse_time(&wire.scheduled)?,
        })
    }
}

/// `2026-11-01T12:00:00Z`, as the scheduler writes a scheduled time.
pub fn format_time(ms: u64) -> String {
    DateTime::from_millis(ms as i64)
        .fmt(Format::DateTime)
        .expect("a time in range formats")
}

fn parse_time(s: &str) -> Result<u64> {
    let time = DateTime::from_str(s, Format::DateTime).context("a task message's time")?;
    u64::try_from(time.to_millis().context("a task message's time")?)
        .context("a task message's time is before 1970")
}

/// The scheduler in memory: the emulator's and the tests' stand-in for EventBridge. Fires into a
/// [`super::deliveries::MemoryDeliveries`], as EventBridge fires into SQS.
#[cfg(any(test, feature = "testing"))]
pub struct MemorySchedules {
    schedules: std::sync::Mutex<std::collections::BTreeMap<String, (Schedule, u64)>>,
    deliveries: std::sync::Arc<super::deliveries::MemoryDeliveries>,
    clock: std::sync::Arc<crate::clock::WallClockAdapter>,
}

#[cfg(any(test, feature = "testing"))]
impl MemorySchedules {
    pub fn new(
        deliveries: std::sync::Arc<super::deliveries::MemoryDeliveries>,
        clock: std::sync::Arc<crate::clock::WallClockAdapter>,
    ) -> Self {
        MemorySchedules {
            schedules: Default::default(),
            deliveries,
            clock,
        }
    }

    fn now(&self) -> u64 {
        use wasmtime_wasi::HostWallClock;
        self.clock.now().as_millis().min(u64::MAX as u128) as u64
    }

    /// Fire every schedule due now: a one-time one once, a recurring one once however many of its
    /// times have passed. How many fired.
    pub async fn fire_due(&self) -> usize {
        use super::deliveries::Deliveries;
        let now = self.now();
        let due: Vec<(String, u64)> = {
            let mut schedules = self.schedules.lock().expect("schedules mutex");
            let mut due = Vec::new();
            schedules.retain(|_, (schedule, next)| {
                if *next > now {
                    return true;
                }
                due.push((schedule.message.clone(), *next));
                match schedule.when {
                    When::At(_) => false,
                    When::Every { interval_ms, .. } => {
                        while *next <= now {
                            *next += interval_ms;
                        }
                        true
                    }
                }
            });
            due
        };
        for (message, at) in &due {
            let body = message.replace(SCHEDULED_TIME, &format_time(*at));
            self.deliveries
                .send(&body, std::time::Duration::ZERO)
                .await
                .expect("the memory queue accepts");
        }
        due.len()
    }

    /// Fire schedules as they come due, until dropped.
    pub async fn run(self: std::sync::Arc<Self>) {
        loop {
            self.fire_due().await;
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }
}

#[cfg(any(test, feature = "testing"))]
#[async_trait::async_trait]
impl Schedules for MemorySchedules {
    async fn create(&self, schedule: &Schedule) -> Result<()> {
        let first = match schedule.when {
            When::At(at) => at,
            When::Every { from, .. } => from.unwrap_or_else(|| self.now()),
        };
        self.schedules
            .lock()
            .expect("schedules mutex")
            .entry(schedule.name.clone())
            .or_insert_with(|| (schedule.clone(), first));
        Ok(())
    }

    async fn delete(&self, name: &str) -> Result<()> {
        self.schedules.lock().expect("schedules mutex").remove(name);
        Ok(())
    }

    async fn exists(&self, name: &str) -> Result<bool> {
        Ok(self
            .schedules
            .lock()
            .expect("schedules mutex")
            .contains_key(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_round_trips_through_the_scheduler_s_time_format() {
        let body = Message::template([1; 16], "job", [2; 16]);
        assert!(body.contains(SCHEDULED_TIME));
        let fired = body.replace(SCHEDULED_TIME, "2026-11-01T12:00:00Z");
        let message = Message::parse(&fired).unwrap();
        assert_eq!(message.tenant, [1; 16]);
        assert_eq!(message.id, "job");
        assert_eq!(message.generation, [2; 16]);
        assert_eq!(message.scheduled, 1_793_534_400_000);
        assert_eq!(
            Message::parse(&Message::due([1; 16], "job", [2; 16], 1_793_534_400_000)).unwrap(),
            message
        );
    }

    #[test]
    fn garbage_is_refused() {
        assert!(Message::parse("{}").is_err());
        assert!(Message::parse("not json").is_err());
        let unfilled = Message::template([1; 16], "job", [2; 16]);
        assert!(
            Message::parse(&unfilled).is_err(),
            "a template never filled in"
        );
    }

    #[test]
    fn schedule_names_are_stable_and_distinct() {
        let a = schedule_name([1; 16], "job", [2; 16]);
        assert_eq!(a, schedule_name([1; 16], "job", [2; 16]));
        assert_ne!(a, schedule_name([1; 16], "job", [3; 16]));
        assert_ne!(a, schedule_name([1; 16], "other", [2; 16]));
        assert!(a.len() <= 64 && a.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    }
}
