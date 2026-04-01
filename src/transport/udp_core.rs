//! Core infrastructure for UDP response correlation.
//!
//! Provides a sharded pending request map with per-request wakeup.

use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

use crate::error::{Error, Result};

const SHARDS: usize = 64;

/// Sharded pending request tracking with per-request wakeup.
///
/// Uses 64 shards to reduce lock contention under high load.
/// Each pending request has its own [`Notify`], so delivering a
/// response wakes only the task waiting for that specific request.
pub struct UdpCore {
    shards: Box<[Shard; SHARDS]>,
}

struct Shard {
    pending: Mutex<HashMap<i32, ResponseSlot>>,
}

struct ResponseSlot {
    response: Option<(Bytes, SocketAddr)>,
    deadline: Instant,
    notify: Arc<Notify>,
}

impl UdpCore {
    /// Create a new `UdpCore` with empty shards.
    pub fn new() -> Self {
        let shards: Vec<Shard> = (0..SHARDS)
            .map(|_| Shard {
                pending: Mutex::new(HashMap::new()),
            })
            .collect();

        Self {
            shards: shards
                .try_into()
                .unwrap_or_else(|_| unreachable!("Vec has exactly SHARDS elements")),
        }
    }

    /// Get the shard for a given request ID.
    fn shard(&self, request_id: i32) -> &Shard {
        &self.shards[request_id as usize % SHARDS]
    }

    /// Register a pending request with a timeout.
    ///
    /// Creates a slot that will accept the response when it arrives.
    pub fn register(&self, request_id: i32, timeout: Duration) {
        let shard = self.shard(request_id);
        let slot = ResponseSlot {
            response: None,
            deadline: Instant::now() + timeout,
            notify: Arc::new(Notify::new()),
        };
        shard.pending.lock().unwrap().insert(request_id, slot);
    }

    /// Deliver a response to its waiting request.
    ///
    /// Returns `true` if the slot existed and the response was stored,
    /// `false` if there was no matching pending request.
    pub fn deliver(&self, request_id: i32, data: Bytes, source: SocketAddr) -> bool {
        let shard = self.shard(request_id);
        let mut pending = shard.pending.lock().unwrap();

        if let Some(slot) = pending.get_mut(&request_id) {
            slot.response = Some((data, source));
            let notify = slot.notify.clone();
            drop(pending);
            notify.notify_one();
            return true;
        }
        false
    }

    /// Wait for a response to arrive for the given request.
    ///
    /// Returns the response data and source address, or an error on timeout
    /// or if the slot was already cancelled/expired.
    pub async fn wait_for_response(
        &self,
        request_id: i32,
        target: SocketAddr,
    ) -> Result<(Bytes, SocketAddr)> {
        let shard = self.shard(request_id);

        loop {
            // Single lock: check for response, or grab notify + deadline for waiting.
            let (notify, deadline) = {
                let mut pending = shard.pending.lock().unwrap();
                if let Some(slot) = pending.get_mut(&request_id) {
                    if let Some(response) = slot.response.take() {
                        pending.remove(&request_id);
                        return Ok(response);
                    }
                    (slot.notify.clone(), slot.deadline)
                } else {
                    tracing::debug!(target: "async_snmp::transport::udp", { request_id, %target, elapsed = ?Duration::ZERO }, "transport timeout (slot missing)");
                    return Err(Error::Timeout {
                        target,
                        elapsed: Duration::ZERO,
                        retries: 0,
                    }
                    .boxed());
                }
            };

            let now = Instant::now();
            if now >= deadline {
                self.unregister(request_id);
                let elapsed = now.saturating_duration_since(deadline - Duration::from_secs(1));
                tracing::debug!(target: "async_snmp::transport::udp", { request_id, %target, ?elapsed }, "transport timeout");
                return Err(Error::Timeout {
                    target,
                    elapsed,
                    retries: 0,
                }
                .boxed());
            }

            tokio::select! {
                _ = notify.notified() => {
                    // Response delivered, loop back to retrieve it
                }
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                    // Timeout reached, loop will detect and return error
                }
            }
        }
    }

    /// Remove a pending request slot.
    ///
    /// Called for cancellation or cleanup.
    pub fn unregister(&self, request_id: i32) {
        let shard = self.shard(request_id);
        shard.pending.lock().unwrap().remove(&request_id);
    }

    /// Remove all expired request slots.
    ///
    /// Should be called periodically to clean up slots that timed out
    /// but were never waited on.
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        for shard in self.shards.iter() {
            let mut pending = shard.pending.lock().unwrap();
            pending.retain(|_, slot| slot.deadline > now);
        }
    }
}

impl Default for UdpCore {
    fn default() -> Self {
        Self::new()
    }
}
