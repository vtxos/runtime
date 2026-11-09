//! How a due task reaches the enclave: a queue of small messages naming it.
//!
//! SQS in production ([`super::aws::SqsDeliveries`]). A message is hidden from other receivers
//! while its attempt runs, and comes back if the attempt never says it is done — so a worker, or
//! the whole enclave, that dies mid-run leaves the task to be delivered again. Delivery is at least
//! once; what makes a second delivery harmless is the occurrence's record
//! ([`super::table::RunRecord`]), not the queue.

use std::time::Duration;

use anyhow::Result;

/// One message, as received.
#[derive(Debug, Clone)]
pub struct Delivery {
    pub body: String,
    /// What names this receipt of the message to `delete` and `release`.
    pub receipt: String,
    /// How many times it has been received, this one included.
    pub receives: u32,
}

#[async_trait::async_trait]
pub trait Deliveries: Send + Sync {
    /// Up to `max` messages, waiting a while for the first; each hidden for `visibility`.
    async fn receive(&self, max: usize, visibility: Duration) -> Result<Vec<Delivery>>;
    /// Done with: never delivered again.
    async fn delete(&self, receipt: &str) -> Result<()>;
    /// Deliverable again after `after`.
    async fn release(&self, receipt: &str, after: Duration) -> Result<()>;
    /// A new message, deliverable after `delay`.
    async fn send(&self, body: &str, delay: Duration) -> Result<()>;
}

/// The queue in memory: the emulator's and the tests' stand-in for SQS.
#[cfg(any(test, feature = "testing"))]
pub struct MemoryDeliveries {
    inner: std::sync::Mutex<Queue>,
    arrived: tokio::sync::Notify,
    /// How long `receive` waits for a message before returning none.
    wait: Duration,
}

#[cfg(any(test, feature = "testing"))]
#[derive(Default)]
struct Queue {
    next: u64,
    messages: Vec<Message>,
}

#[cfg(any(test, feature = "testing"))]
struct Message {
    id: u64,
    body: String,
    visible_at: tokio::time::Instant,
    receives: u32,
}

#[cfg(any(test, feature = "testing"))]
impl MemoryDeliveries {
    pub fn new(wait: Duration) -> Self {
        MemoryDeliveries {
            inner: std::sync::Mutex::new(Queue::default()),
            arrived: tokio::sync::Notify::new(),
            wait,
        }
    }

    /// Messages not yet deleted, visible or not.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("queue mutex").messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Make every message visible now, as if its delay had passed, for tests.
    pub fn reveal(&self) {
        let now = tokio::time::Instant::now();
        let mut inner = self.inner.lock().expect("queue mutex");
        for m in inner.messages.iter_mut() {
            m.visible_at = now;
        }
    }

    /// Every message body, for tests.
    pub fn bodies(&self) -> Vec<String> {
        let inner = self.inner.lock().expect("queue mutex");
        inner.messages.iter().map(|m| m.body.clone()).collect()
    }

    fn find(queue: &mut Queue, receipt: &str) -> Option<usize> {
        let (id, receives) = receipt.split_once('/')?;
        let (id, receives): (u64, u32) = (id.parse().ok()?, receives.parse().ok()?);
        queue
            .messages
            .iter()
            .position(|m| m.id == id && m.receives == receives)
    }
}

#[cfg(any(test, feature = "testing"))]
#[async_trait::async_trait]
impl Deliveries for MemoryDeliveries {
    async fn receive(&self, max: usize, visibility: Duration) -> Result<Vec<Delivery>> {
        let deadline = tokio::time::Instant::now() + self.wait;
        loop {
            let arrived = self.arrived.notified();
            let next = {
                let now = tokio::time::Instant::now();
                let mut inner = self.inner.lock().expect("queue mutex");
                let mut out = Vec::new();
                for m in inner.messages.iter_mut() {
                    if out.len() == max {
                        break;
                    }
                    if m.visible_at <= now {
                        m.visible_at = now + visibility;
                        m.receives += 1;
                        out.push(Delivery {
                            body: m.body.clone(),
                            receipt: format!("{}/{}", m.id, m.receives),
                            receives: m.receives,
                        });
                    }
                }
                if !out.is_empty() {
                    return Ok(out);
                }
                inner.messages.iter().map(|m| m.visible_at).min()
            };
            let until = next.map_or(deadline, |at| at.min(deadline));
            if tokio::time::Instant::now() >= deadline {
                return Ok(Vec::new());
            }
            tokio::select! {
                _ = arrived => {}
                _ = tokio::time::sleep_until(until) => {}
            }
        }
    }

    async fn delete(&self, receipt: &str) -> Result<()> {
        let mut inner = self.inner.lock().expect("queue mutex");
        if let Some(at) = Self::find(&mut inner, receipt) {
            inner.messages.remove(at);
        }
        Ok(())
    }

    async fn release(&self, receipt: &str, after: Duration) -> Result<()> {
        let mut inner = self.inner.lock().expect("queue mutex");
        if let Some(at) = Self::find(&mut inner, receipt) {
            inner.messages[at].visible_at = tokio::time::Instant::now() + after;
        }
        drop(inner);
        self.arrived.notify_waiters();
        Ok(())
    }

    async fn send(&self, body: &str, delay: Duration) -> Result<()> {
        let mut inner = self.inner.lock().expect("queue mutex");
        inner.next += 1;
        let id = inner.next;
        inner.messages.push(Message {
            id,
            body: body.to_string(),
            visible_at: tokio::time::Instant::now() + delay,
            receives: 0,
        });
        drop(inner);
        self.arrived.notify_waiters();
        Ok(())
    }
}
