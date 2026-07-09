//! SNMP client implementation.

mod auth;
mod builder;
mod retry;
mod v3;
mod walk;

pub use auth::{Auth, CommunityVersion, UsmAuth, UsmBuilder};
pub use builder::{ClientBuilder, Target};
pub use retry::{Backoff, Retry, RetryBuilder};

// New unified entry point
impl Client<UdpHandle> {
    /// Create a new SNMP client builder.
    ///
    /// This is the single entry point for client construction, supporting all
    /// SNMP versions (v1, v2c, v3) through the [`Auth`] enum.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::{Auth, Client, Retry};
    /// use std::time::Duration;
    ///
    /// # async fn example() -> async_snmp::Result<()> {
    /// // (host, port) tuple - convenient when host and port are separate
    /// let client = Client::builder(("192.168.1.1", 161), Auth::v2c("public"))
    ///     .connect().await?;
    ///
    /// // Combined address string (port defaults to 161 if omitted)
    /// let client = Client::builder("switch.local", Auth::v2c("public"))
    ///     .connect().await?;
    ///
    /// // SocketAddr works too
    /// let addr: std::net::SocketAddr = "192.168.1.1:161".parse().unwrap();
    /// let client = Client::builder(addr, Auth::v2c("public"))
    ///     .connect().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder(target: impl Into<Target>, auth: impl Into<Auth>) -> ClientBuilder {
        ClientBuilder::new(target, auth)
    }
}
use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, ErrorStatus, Result};
use crate::message::{CommunityMessage, Message};
use crate::oid::Oid;
use crate::pdu::{GetBulkPdu, Pdu, PduType, TrapV1Pdu};
use crate::transport::Transport;
use crate::transport::UdpHandle;
use crate::v3::{EngineCache, EngineState, SaltCounter};
use crate::value::Value;
use crate::varbind::VarBind;
use crate::version::Version;
use bytes::Bytes;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{Span, instrument};

pub use crate::notification::{DerivedKeys, UsmConfig};
pub use walk::{BulkWalk, OidOrdering, Walk, WalkMode, WalkStream};

// ============================================================================
// Shared helpers
// ============================================================================

/// Convert a configured `u32` `max_repetitions` to the `i32` GETBULK wire
/// field, saturating instead of wrapping.
///
/// RFC 3416 Section 4.2.3 specifies `max-repetitions` as `INTEGER
/// (0..2147483647)`. `ClientBuilder::max_repetitions` takes a `u32`, so a
/// configured value above `i32::MAX` would wrap to a negative number under a
/// plain `as i32` cast; this saturates to `i32::MAX` instead, which
/// `GetBulkPdu::encode`'s own clamp (`.max(0)`) would otherwise silently turn
/// into `0` (disabling repetitions).
pub(crate) fn max_repetitions_to_wire(max_repetitions: u32) -> i32 {
    i32::try_from(max_repetitions).unwrap_or(i32::MAX)
}

/// Extract an SNMP-level error from a PDU and convert it to an `Error::Snmp`.
///
/// Returns `Some(err)` if the PDU carries an SNMP error status, `None` otherwise.
/// The `error_index` field is 1-based; 0 means the error applies to the whole PDU.
pub(crate) fn pdu_to_snmp_error(pdu: &Pdu, target: SocketAddr) -> Option<Box<Error>> {
    if !pdu.is_error() {
        return None;
    }
    let status = pdu.error_status_enum();
    let oid = (pdu.error_index as usize)
        .checked_sub(1)
        .and_then(|idx| pdu.varbinds.get(idx))
        .map(|vb| vb.oid.clone());
    Some(
        Error::Snmp {
            target,
            status,
            index: pdu.error_index.try_into().unwrap_or(0),
            oid,
        }
        .boxed(),
    )
}

// ============================================================================
// Default configuration constants
// ============================================================================

/// Default timeout for SNMP requests.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default maximum OIDs per request.
///
/// Requests with more OIDs than this limit are automatically split into
/// multiple batches.
pub const DEFAULT_MAX_OIDS_PER_REQUEST: usize = 10;

/// Default max-repetitions for GETBULK operations.
///
/// Controls how many values are requested per GETBULK PDU during walks.
pub const DEFAULT_MAX_REPETITIONS: u32 = 25;

/// SNMP client.
///
/// Generic over transport type, with `UdpHandle` as default.
pub struct Client<T: Transport = UdpHandle> {
    inner: Arc<ClientInner<T>>,
}

impl<T: Transport> Clone for Client<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

struct ClientInner<T: Transport> {
    transport: T,
    config: ClientConfig,
    /// Cached engine state (V3)
    engine_state: RwLock<Option<EngineState>>,
    /// Derived keys for this engine (V3)
    derived_keys: RwLock<Option<DerivedKeys>>,
    /// Salt counter for privacy (V3)
    salt_counter: SaltCounter,
    /// Shared engine cache (V3, optional)
    engine_cache: Option<Arc<EngineCache>>,
    /// Serializes concurrent discovery attempts so only one runs at a time.
    discovery_lock: AsyncMutex<()>,
    /// Local engine start time for computing engine time in V3 traps.
    local_engine_start: Instant,
    /// Keys derived against `local_engine_id` for V3 trap sending.
    local_derived_keys: RwLock<Option<DerivedKeys>>,
}

/// Client configuration.
///
/// Most users should use [`ClientBuilder`] rather than constructing this directly.
#[derive(Clone)]
pub struct ClientConfig {
    /// SNMP version (default: V2c)
    pub version: Version,
    /// Community string for v1/v2c (default: "public")
    pub community: Bytes,
    /// Request timeout (default: 5 seconds)
    pub timeout: Duration,
    /// Retry configuration (default: 3 retries, 1-second delay)
    pub retry: Retry,
    /// Maximum OIDs per request (default: 10)
    pub max_oids_per_request: usize,
    /// `SNMPv3` security configuration (default: None)
    pub v3_security: Option<UsmConfig>,
    /// Walk operation mode (default: Auto)
    pub walk_mode: WalkMode,
    /// OID ordering behavior during walk operations (default: Strict)
    pub oid_ordering: OidOrdering,
    /// Maximum results from a single walk operation (default: None/unlimited)
    pub max_walk_results: Option<usize>,
    /// Max-repetitions for GETBULK operations (default: 25)
    pub max_repetitions: u32,
    /// Local engine ID for V3 trap sending (default: None).
    ///
    /// Per RFC 3412 Section 6.4, the sender is the authoritative engine for
    /// trap PDUs. This engine ID is used to localize keys for outbound V3 traps.
    pub local_engine_id: Option<Bytes>,
    /// Local engine boots base value for V3 trap sending (default: 1).
    pub local_engine_boots: u32,
}

impl Default for ClientConfig {
    /// Returns configuration for `SNMPv2c` with community "public".
    ///
    /// See field documentation for all default values.
    fn default() -> Self {
        Self {
            version: Version::V2c,
            community: Bytes::from_static(b"public"),
            timeout: DEFAULT_TIMEOUT,
            retry: Retry::default(),
            max_oids_per_request: DEFAULT_MAX_OIDS_PER_REQUEST,
            v3_security: None,
            walk_mode: WalkMode::Auto,
            oid_ordering: OidOrdering::Strict,
            max_walk_results: None,
            max_repetitions: DEFAULT_MAX_REPETITIONS,
            local_engine_id: None,
            local_engine_boots: 1,
        }
    }
}

impl<T: Transport> Client<T> {
    /// Create a new client with the given transport and config.
    ///
    /// For most use cases, prefer [`Client::builder()`] which provides a more
    /// ergonomic API. Use this constructor when you need fine-grained control
    /// over transport configuration (e.g., TCP connection timeout, keepalive
    /// settings) or when using a custom [`Transport`] implementation.
    pub fn new(transport: T, config: ClientConfig) -> Self {
        Self {
            inner: Arc::new(ClientInner {
                transport,
                config,
                engine_state: RwLock::new(None),
                derived_keys: RwLock::new(None),
                salt_counter: SaltCounter::new(),
                engine_cache: None,
                discovery_lock: AsyncMutex::new(()),
                local_engine_start: Instant::now(),
                local_derived_keys: RwLock::new(None),
            }),
        }
    }

    /// Create a new V3 client with a shared engine cache.
    pub fn with_engine_cache(
        transport: T,
        config: ClientConfig,
        engine_cache: Arc<EngineCache>,
    ) -> Self {
        Self {
            inner: Arc::new(ClientInner {
                transport,
                config,
                engine_state: RwLock::new(None),
                derived_keys: RwLock::new(None),
                salt_counter: SaltCounter::new(),
                engine_cache: Some(engine_cache),
                discovery_lock: AsyncMutex::new(()),
                local_engine_start: Instant::now(),
                local_derived_keys: RwLock::new(None),
            }),
        }
    }

    /// Get the peer (target) address.
    ///
    /// Returns the remote address that this client sends requests to.
    /// Named to match [`std::net::TcpStream::peer_addr()`].
    #[must_use]
    pub fn peer_addr(&self) -> SocketAddr {
        self.inner.transport.peer_addr()
    }

    /// Generate next request ID.
    ///
    /// Uses the transport's allocator (backed by a global counter).
    fn next_request_id(&self) -> i32 {
        self.inner.transport.alloc_request_id()
    }

    /// Check if using V3 with authentication/encryption configured.
    fn is_v3(&self) -> bool {
        self.inner.config.version == Version::V3 && self.inner.config.v3_security.is_some()
    }

    /// Send a request and wait for response (internal helper with pre-encoded data).
    #[instrument(
        level = "debug",
        skip(self, data),
        fields(
            snmp.target = %self.peer_addr(),
            snmp.request_id = request_id,
            snmp.attempt = tracing::field::Empty,
            snmp.elapsed_ms = tracing::field::Empty,
        )
    )]
    async fn send_and_recv(&self, request_id: i32, data: &[u8]) -> Result<Pdu> {
        let start = Instant::now();
        let mut last_error: Option<Box<Error>> = None;
        let max_attempts = if self.inner.transport.is_reliable() {
            0
        } else {
            self.inner.config.retry.max_attempts
        };

        for attempt in 0..=max_attempts {
            Span::current().record("snmp.attempt", attempt);
            if attempt > 0 {
                tracing::debug!(target: "async_snmp::client", "retrying request");
            }

            // Register (or re-register) with fresh deadline before sending
            self.inner
                .transport
                .register_request(request_id, self.inner.config.timeout);

            // Send request
            tracing::trace!(target: "async_snmp::client", { snmp.bytes = data.len() }, "sending request");
            self.inner.transport.send(data).await?;

            // Wait for response (deadline was set by register_request)
            match self.inner.transport.recv(request_id).await {
                Ok((response_data, _source)) => {
                    tracing::trace!(target: "async_snmp::client", { snmp.bytes = response_data.len() }, "received response");

                    // Decode response and extract PDU
                    let response = Message::decode(response_data)?;

                    // Validate response version matches request version
                    let response_version = response.version();
                    let expected_version = self.inner.config.version;
                    if response_version != expected_version {
                        tracing::warn!(target: "async_snmp::client", { ?expected_version, ?response_version, peer = %self.peer_addr() }, "version mismatch in response");
                        return Err(Error::MalformedResponse {
                            target: self.peer_addr(),
                        }
                        .boxed());
                    }

                    // Warn when the community does not echo the one we sent.
                    // net-snmp accepts such responses (proxies and some
                    // agents rewrite the community), so this is not a reject.
                    if let Message::Community(ref m) = response
                        && m.community != self.inner.config.community
                    {
                        tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr() }, "community mismatch in response");
                    }

                    let Some(response_pdu) = response.into_pdu() else {
                        tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr() }, "received TrapV1 in response to request");
                        return Err(Error::MalformedResponse {
                            target: self.peer_addr(),
                        }
                        .boxed());
                    };

                    // RFC 3416 Section 4.2: only a Response-PDU may answer a
                    // request; reject echoed request-type PDUs
                    if response_pdu.pdu_type != PduType::Response {
                        tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr(), pdu_type = ?response_pdu.pdu_type }, "non-Response PDU in response");
                        return Err(Error::MalformedResponse {
                            target: self.peer_addr(),
                        }
                        .boxed());
                    }

                    // Validate request ID
                    if response_pdu.request_id != request_id {
                        tracing::warn!(target: "async_snmp::client", { expected_request_id = request_id, actual_request_id = response_pdu.request_id, peer = %self.peer_addr() }, "request ID mismatch in response");
                        return Err(Error::MalformedResponse {
                            target: self.peer_addr(),
                        }
                        .boxed());
                    }

                    // Check for SNMP error
                    if let Some(err) = pdu_to_snmp_error(&response_pdu, self.peer_addr()) {
                        Span::current()
                            .record("snmp.elapsed_ms", start.elapsed().as_millis() as u64);
                        return Err(err);
                    }

                    Span::current().record("snmp.elapsed_ms", start.elapsed().as_millis() as u64);
                    return Ok(response_pdu);
                }
                Err(e) if matches!(*e, Error::Timeout { .. }) => {
                    last_error = Some(e);
                    // Apply backoff delay before next retry (if not last attempt)
                    if attempt < max_attempts {
                        let delay = self.inner.config.retry.compute_delay(attempt);
                        if !delay.is_zero() {
                            tracing::debug!(target: "async_snmp::client", { delay_ms = delay.as_millis() as u64 }, "backing off");
                            tokio::time::sleep(delay).await;
                        }
                    }
                    // fall thru to next loop iteration
                }
                Err(e) => {
                    Span::current().record("snmp.elapsed_ms", start.elapsed().as_millis() as u64);
                    return Err(e);
                }
            }
        }

        // All retries exhausted
        let elapsed = start.elapsed();
        Span::current().record("snmp.elapsed_ms", elapsed.as_millis() as u64);
        tracing::debug!(target: "async_snmp::client", { request_id, peer = %self.peer_addr(), ?elapsed, retries = max_attempts }, "request timed out");
        Err(last_error.unwrap_or_else(|| {
            Error::Timeout {
                target: self.peer_addr(),
                elapsed,
                retries: max_attempts,
            }
            .boxed()
        }))
    }

    /// Send a standard request (GET, GETNEXT, SET) and wait for response.
    async fn send_request(&self, pdu: Pdu) -> Result<Pdu> {
        // Dispatch to V3 handler if configured
        if self.is_v3() {
            return self.send_v3_and_recv(pdu).await;
        }

        tracing::debug!(target: "async_snmp::client", { snmp.pdu_type = ?pdu.pdu_type, snmp.varbind_count = pdu.varbinds.len() }, "sending {} request", pdu.pdu_type);

        let request_id = pdu.request_id;
        let message = CommunityMessage::new(
            self.inner.config.version,
            self.inner.config.community.clone(),
            pdu,
        );
        let data = message.encode();
        let response = self.send_and_recv(request_id, &data).await?;

        tracing::debug!(target: "async_snmp::client", { snmp.pdu_type = ?response.pdu_type, snmp.varbind_count = response.varbinds.len(), snmp.error_status = response.error_status, snmp.error_index = response.error_index }, "received {} response", response.pdu_type);

        Ok(response)
    }

    /// Send a GETBULK request and wait for response.
    async fn send_bulk_request(&self, pdu: GetBulkPdu) -> Result<Pdu> {
        // Dispatch to V3 handler if configured
        if self.is_v3() {
            // Convert GetBulkPdu to Pdu for V3 encoding
            let pdu = Pdu::get_bulk(
                pdu.request_id,
                pdu.non_repeaters,
                pdu.max_repetitions,
                pdu.varbinds,
            );
            return self.send_v3_and_recv(pdu).await;
        }

        tracing::debug!(target: "async_snmp::client", { snmp.non_repeaters = pdu.non_repeaters, snmp.max_repetitions = pdu.max_repetitions, snmp.varbind_count = pdu.varbinds.len() }, "sending GetBulkRequest");

        let request_id = pdu.request_id;
        let data = CommunityMessage::encode_bulk(
            self.inner.config.version,
            self.inner.config.community.clone(),
            &pdu,
        );
        let response = self.send_and_recv(request_id, &data).await?;

        tracing::debug!(target: "async_snmp::client", { snmp.pdu_type = ?response.pdu_type, snmp.varbind_count = response.varbinds.len(), snmp.error_status = response.error_status, snmp.error_index = response.error_index }, "received {} response", response.pdu_type);

        Ok(response)
    }

    /// GET a single OID.
    #[instrument(skip(self), err, fields(snmp.target = %self.peer_addr(), snmp.oid = %oid))]
    pub async fn get(&self, oid: &Oid) -> Result<VarBind> {
        let request_id = self.next_request_id();
        let pdu = Pdu::get_request(request_id, std::slice::from_ref(oid));
        let response = self.send_request(pdu).await?;

        response.varbinds.into_iter().next().ok_or_else(|| {
            tracing::debug!(target: "async_snmp::client", { peer = %self.peer_addr(), kind = %DecodeErrorKind::EmptyResponse }, "empty GET response");
            Error::MalformedResponse {
                target: self.peer_addr(),
            }
            .boxed()
        })
    }

    /// GET multiple OIDs.
    ///
    /// If the OID list exceeds `max_oids_per_request`, the request is
    /// automatically split into multiple batches. Results are returned
    /// in the same order as the input OIDs.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use async_snmp::{Auth, Client, oid};
    /// # async fn example() -> async_snmp::Result<()> {
    /// # let client = Client::builder("127.0.0.1:161", Auth::v2c("public")).connect().await?;
    /// let results = client.get_many(&[
    ///     oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),  // sysDescr
    ///     oid!(1, 3, 6, 1, 2, 1, 1, 3, 0),  // sysUpTime
    ///     oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),  // sysName
    /// ]).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self, oids), err, fields(snmp.target = %self.peer_addr(), snmp.oid_count = oids.len()))]
    pub async fn get_many(&self, oids: &[Oid]) -> Result<Vec<VarBind>> {
        self.get_or_getnext_many(oids, "GET", Pdu::get_request)
            .await
    }

    /// GETNEXT for a single OID.
    #[instrument(skip(self), err, fields(snmp.target = %self.peer_addr(), snmp.oid = %oid))]
    pub async fn get_next(&self, oid: &Oid) -> Result<VarBind> {
        let request_id = self.next_request_id();
        let pdu = Pdu::get_next_request(request_id, std::slice::from_ref(oid));
        let response = self.send_request(pdu).await?;

        response.varbinds.into_iter().next().ok_or_else(|| {
            tracing::debug!(target: "async_snmp::client", { peer = %self.peer_addr(), kind = %DecodeErrorKind::EmptyResponse }, "empty GETNEXT response");
            Error::MalformedResponse {
                target: self.peer_addr(),
            }
            .boxed()
        })
    }

    /// GETNEXT for multiple OIDs.
    ///
    /// If the OID list exceeds `max_oids_per_request`, the request is
    /// automatically split into multiple batches. Results are returned
    /// in the same order as the input OIDs.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use async_snmp::{Auth, Client, oid};
    /// # async fn example() -> async_snmp::Result<()> {
    /// # let client = Client::builder("127.0.0.1:161", Auth::v2c("public")).connect().await?;
    /// let results = client.get_next_many(&[
    ///     oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2),  // ifDescr
    ///     oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 3),  // ifType
    /// ]).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self, oids), err, fields(snmp.target = %self.peer_addr(), snmp.oid_count = oids.len()))]
    pub async fn get_next_many(&self, oids: &[Oid]) -> Result<Vec<VarBind>> {
        self.get_or_getnext_many(oids, "GETNEXT", Pdu::get_next_request)
            .await
    }

    /// Shared implementation for GET-many and GETNEXT-many.
    ///
    /// `op` is the PDU constructor (`Pdu::get_request` or `Pdu::get_next_request`).
    /// `op_name` is used only for log messages.
    async fn get_or_getnext_many(
        &self,
        oids: &[Oid],
        op_name: &'static str,
        op: fn(i32, &[Oid]) -> Pdu,
    ) -> Result<Vec<VarBind>> {
        if oids.is_empty() {
            return Ok(Vec::new());
        }

        let max_per_request = self.inner.config.max_oids_per_request;
        let mut all_results = Vec::with_capacity(oids.len());

        for chunk in oids.chunks(max_per_request) {
            self.send_batch_with_bisect(chunk, op_name, op, &mut all_results)
                .await?;
        }

        Ok(all_results)
    }

    /// Send a batch of OIDs, automatically bisecting on tooBig errors.
    ///
    /// If the agent returns tooBig for a batch with more than one OID, the batch
    /// is split in half and each half is retried. This repeats recursively until
    /// batches succeed or a single-OID request fails (which is unrecoverable).
    fn send_batch_with_bisect<'a>(
        &'a self,
        oids: &'a [Oid],
        op_name: &'static str,
        op: fn(i32, &[Oid]) -> Pdu,
        results: &'a mut Vec<VarBind>,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let request_id = self.next_request_id();
            let pdu = op(request_id, oids);
            match self.send_request(pdu).await {
                Ok(response) => {
                    if response.varbinds.len() > oids.len() {
                        tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr(), expected = oids.len(), actual = response.varbinds.len(), snmp.op = op_name }, "response has more varbinds than requested");
                        return Err(Error::MalformedResponse {
                            target: self.peer_addr(),
                        }
                        .boxed());
                    } else if response.varbinds.len() < oids.len() {
                        tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr(), expected = oids.len(), actual = response.varbinds.len(), snmp.op = op_name }, "response has fewer varbinds than requested");
                    }
                    results.extend(response.varbinds);
                    Ok(())
                }
                Err(e)
                    if oids.len() > 1
                        && matches!(
                            &*e,
                            Error::Snmp {
                                status: ErrorStatus::TooBig,
                                ..
                            }
                        ) =>
                {
                    let mid = oids.len() / 2;
                    tracing::debug!(target: "async_snmp::client", { peer = %self.peer_addr(), snmp.batch_size = oids.len(), snmp.split_at = mid, snmp.op = op_name }, "tooBig response, bisecting batch");
                    self.send_batch_with_bisect(&oids[..mid], op_name, op, results)
                        .await?;
                    self.send_batch_with_bisect(&oids[mid..], op_name, op, results)
                        .await?;
                    Ok(())
                }
                Err(e) => Err(e),
            }
        })
    }

    /// SET a single OID.
    #[instrument(skip(self, value), err, fields(snmp.target = %self.peer_addr(), snmp.oid = %oid))]
    pub async fn set(&self, oid: &Oid, value: Value) -> Result<VarBind> {
        let request_id = self.next_request_id();
        let varbind = VarBind::new(oid.clone(), value);
        let pdu = Pdu::set_request(request_id, vec![varbind]);
        let response = self.send_request(pdu).await?;

        response.varbinds.into_iter().next().ok_or_else(|| {
            tracing::debug!(target: "async_snmp::client", { peer = %self.peer_addr(), kind = %DecodeErrorKind::EmptyResponse }, "empty SET response");
            Error::MalformedResponse {
                target: self.peer_addr(),
            }
            .boxed()
        })
    }

    /// SET multiple OIDs in a single atomic PDU.
    ///
    /// RFC 3416 requires that a SET request be atomic: either all variables
    /// in the request are set, or none are. To preserve this guarantee,
    /// `set_many` refuses to split the varbind list across multiple PDUs.
    ///
    /// If `varbinds.len()` exceeds `max_oids_per_request`, this method
    /// returns `Error::Config` rather than silently batching the request.
    /// Callers that need to set more variables than the per-request limit
    /// must issue multiple explicit `set_many` calls and handle partial
    /// failure themselves.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use async_snmp::{Auth, Client, oid, Value};
    /// # async fn example() -> async_snmp::Result<()> {
    /// # let client = Client::builder("127.0.0.1:161", Auth::v2c("private")).connect().await?;
    /// let results = client.set_many(&[
    ///     (oid!(1, 3, 6, 1, 2, 1, 1, 5, 0), Value::from("new-hostname")),
    ///     (oid!(1, 3, 6, 1, 2, 1, 1, 6, 0), Value::from("new-location")),
    /// ]).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self, varbinds), err, fields(snmp.target = %self.peer_addr(), snmp.oid_count = varbinds.len()))]
    pub async fn set_many(&self, varbinds: &[(Oid, Value)]) -> Result<Vec<VarBind>> {
        if varbinds.is_empty() {
            return Ok(Vec::new());
        }

        let max_per_request = self.inner.config.max_oids_per_request;

        if varbinds.len() > max_per_request {
            return Err(Error::Config(
                format!(
                    "set_many: {} varbinds exceeds max_oids_per_request ({}); \
                     SET must be atomic and cannot be split across PDUs",
                    varbinds.len(),
                    max_per_request,
                )
                .into(),
            )
            .boxed());
        }

        let request_id = self.next_request_id();
        let vbs: Vec<VarBind> = varbinds
            .iter()
            .map(|(oid, value)| VarBind::new(oid.clone(), value.clone()))
            .collect();
        let expected_count = vbs.len();
        let pdu = Pdu::set_request(request_id, vbs);
        let response = self.send_request(pdu).await?;
        if response.varbinds.len() > expected_count {
            tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr(), expected = expected_count, actual = response.varbinds.len() }, "SET response has more varbinds than requested");
            return Err(Error::MalformedResponse {
                target: self.peer_addr(),
            }
            .boxed());
        } else if response.varbinds.len() < expected_count {
            tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr(), expected = expected_count, actual = response.varbinds.len() }, "SET response has fewer varbinds than requested");
        }
        Ok(response.varbinds)
    }

    /// Send a trap (fire-and-forget).
    ///
    /// For V1 clients: constructs a `TrapV1` PDU. The `trap_oid` is reverse-mapped
    /// to v1 `generic_trap/specific_trap/enterprise` fields per RFC 3584 Section 3.2.
    /// The `agent_addr` is set from the transport's local IPv4 address, or `[0,0,0,0]`
    /// if the local address is IPv6. Use [`send_v1_trap`](Self::send_v1_trap) for
    /// explicit control over v1 fields.
    ///
    /// For V2c/V3 clients: constructs a `TrapV2` PDU with the mandatory sysUpTime.0
    /// and snmpTrapOID.0 prefix.
    ///
    /// For V3: uses the local engine ID (set via `ClientBuilder::local_engine_id`).
    ///
    /// # Arguments
    ///
    /// * `trap_oid` - The trap OID (snmpTrapOID.0 value)
    /// * `uptime` - sysUpTime.0 value in hundredths of seconds
    /// * `varbinds` - Additional variable bindings (appended after the prefix)
    #[instrument(skip(self, varbinds), err, fields(snmp.target = %self.peer_addr(), snmp.trap_oid = %trap_oid))]
    pub async fn send_trap(
        &self,
        trap_oid: &Oid,
        uptime: u32,
        varbinds: Vec<VarBind>,
    ) -> Result<()> {
        if self.inner.config.version == Version::V1 {
            // Build a v2-style PDU and convert to v1.
            // Per RFC 3584 Section 3, use the local IPv4 address as agent_addr.
            let local_ip = match self.inner.transport.local_addr().ip() {
                std::net::IpAddr::V4(v4) => v4.octets(),
                std::net::IpAddr::V6(_) => [0, 0, 0, 0],
            };
            // request_id is unused in the v1 wire format, use 0 to avoid
            // wasting a slot in the request_id sequence.
            let pdu = Pdu::trap_v2(0, uptime, trap_oid, varbinds);
            let trap = pdu.to_v1_trap(local_ip).ok_or_else(|| {
                Error::Config("cannot convert trap to v1 (Counter64 varbind?)".into()).boxed()
            })?;
            return self.send_v1_trap(trap).await;
        }

        let request_id = self.next_request_id();
        let pdu = Pdu::trap_v2(request_id, uptime, trap_oid, varbinds);

        if self.is_v3() {
            self.ensure_local_keys_derived()?;
            let msg_id = self.next_request_id();
            let data = self.build_v3_trap_message(&pdu, msg_id)?;
            tracing::debug!(target: "async_snmp::client", { snmp.pdu_type = "TrapV2", snmp.varbind_count = pdu.varbinds.len(), snmp.bytes = data.len() }, "sending V3 trap");
            self.inner.transport.send(&data).await?;
        } else {
            let message = CommunityMessage::new(
                self.inner.config.version,
                self.inner.config.community.clone(),
                pdu,
            );
            let data = message.encode();
            tracing::debug!(target: "async_snmp::client", { snmp.pdu_type = "TrapV2", snmp.bytes = data.len() }, "sending v2c trap");
            self.inner.transport.send(&data).await?;
        }

        Ok(())
    }

    /// Send an `SNMPv1` trap with explicit v1 PDU fields.
    ///
    /// This is a lower-level method that accepts a pre-built [`TrapV1Pdu`],
    /// giving full control over enterprise OID, `agent_addr`, `generic_trap`,
    /// `specific_trap`, and `time_stamp` fields.
    ///
    /// The client must be configured for V1 (`Auth::v1()`). Returns an error
    /// if the client version is not V1.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use async_snmp::{Auth, Client, TrapV1Pdu, GenericTrap, oid};
    /// # async fn example() -> async_snmp::Result<()> {
    /// let client = Client::builder("192.168.1.100:162", Auth::v1("public"))
    ///     .connect().await?;
    ///
    /// let trap = TrapV1Pdu::new(
    ///     oid!(1, 3, 6, 1, 4, 1, 9999),  // enterprise
    ///     [192, 168, 1, 1],               // agent address
    ///     GenericTrap::ColdStart,
    ///     0,
    ///     12345,                          // uptime in centiseconds
    ///     vec![],
    /// );
    /// client.send_v1_trap(trap).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self, trap), err, fields(snmp.target = %self.peer_addr(), snmp.generic_trap = %trap.generic_trap))]
    pub async fn send_v1_trap(&self, trap: TrapV1Pdu) -> Result<()> {
        if self.inner.config.version != Version::V1 {
            return Err(Error::Config("send_v1_trap requires a V1 client".into()).boxed());
        }

        let message = CommunityMessage::v1_trap(self.inner.config.community.clone(), trap);
        let data = message.encode();
        tracing::debug!(target: "async_snmp::client", { snmp.pdu_type = "TrapV1", snmp.bytes = data.len() }, "sending v1 trap");
        self.inner.transport.send(&data).await?;

        Ok(())
    }

    /// Send a v2c/v3 inform and wait for acknowledgement.
    ///
    /// Constructs an `InformRequest` PDU with the mandatory sysUpTime.0 and
    /// snmpTrapOID.0 prefix, sends it to the target, and waits for a Response
    /// PDU. Uses the same retry and timeout logic as other request types.
    ///
    /// For V3: uses engine discovery against the receiver (same as GET/SET).
    /// V1 is not supported and returns an error.
    ///
    /// # Arguments
    ///
    /// * `trap_oid` - The trap OID (snmpTrapOID.0 value)
    /// * `uptime` - sysUpTime.0 value in hundredths of seconds
    /// * `varbinds` - Additional variable bindings (appended after the prefix)
    #[instrument(skip(self, varbinds), err, fields(snmp.target = %self.peer_addr(), snmp.trap_oid = %trap_oid))]
    pub async fn send_inform(
        &self,
        trap_oid: &Oid,
        uptime: u32,
        varbinds: Vec<VarBind>,
    ) -> Result<()> {
        if self.inner.config.version == Version::V1 {
            return Err(Error::Config("v1 inform sending not supported".into()).boxed());
        }

        let request_id = self.next_request_id();
        let pdu = Pdu::inform_request(request_id, uptime, trap_oid, varbinds);
        let _response = self.send_request(pdu).await?;
        Ok(())
    }

    /// GETBULK request (SNMPv2c/v3 only).
    ///
    /// Efficiently retrieves multiple variable bindings in a single request.
    /// GETBULK splits the requested OIDs into two groups:
    ///
    /// - **Non-repeaters** (first N OIDs): Each gets a single GETNEXT, returning
    ///   one value per OID. Use for scalar values like `sysUpTime.0`.
    /// - **Repeaters** (remaining OIDs): Each gets up to `max_repetitions` GETNEXTs,
    ///   returning multiple values per OID. Use for walking table columns.
    ///
    /// # Arguments
    ///
    /// * `oids` - OIDs to retrieve
    /// * `non_repeaters` - How many OIDs (from the start) are non-repeating
    /// * `max_repetitions` - Maximum rows to return for each repeating OID
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use async_snmp::{Auth, Client, oid};
    /// # async fn example() -> async_snmp::Result<()> {
    /// # let client = Client::builder("127.0.0.1:161", Auth::v2c("public")).connect().await?;
    /// // Get sysUpTime (non-repeater) plus 10 interface descriptions (repeater)
    /// let results = client.get_bulk(
    ///     &[oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2)],
    ///     1,  // first OID is non-repeating
    ///     10, // get up to 10 values for the second OID
    /// ).await?;
    /// // Results: [sysUpTime value, ifDescr.1, ifDescr.2, ..., ifDescr.10]
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self, oids), err, fields(
        snmp.target = %self.peer_addr(),
        snmp.oid_count = oids.len(),
        snmp.non_repeaters = non_repeaters,
        snmp.max_repetitions = max_repetitions
    ))]
    pub async fn get_bulk(
        &self,
        oids: &[Oid],
        non_repeaters: i32,
        max_repetitions: i32,
    ) -> Result<Vec<VarBind>> {
        let request_id = self.next_request_id();
        let pdu = GetBulkPdu::new(request_id, non_repeaters, max_repetitions, oids);
        let response = self.send_bulk_request(pdu).await?;
        Ok(response.varbinds)
    }

    /// Walk an OID subtree.
    ///
    /// Auto-selects the optimal walk method based on SNMP version and `WalkMode`:
    /// - `WalkMode::Auto` (default): Uses GETNEXT for V1, GETBULK for V2c/V3
    /// - `WalkMode::GetNext`: Always uses GETNEXT
    /// - `WalkMode::GetBulk`: Always uses GETBULK (fails on V1)
    ///
    /// Returns an async stream that yields each variable binding in the subtree.
    /// The walk terminates when an OID outside the subtree is encountered or
    /// when `EndOfMibView` is returned.
    ///
    /// Uses the client's configured `oid_ordering`, `max_walk_results`, and
    /// `max_repetitions` (for GETBULK) settings.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use async_snmp::{Auth, Client, oid};
    /// # async fn example() -> async_snmp::Result<()> {
    /// # let client = Client::builder("127.0.0.1:161", Auth::v2c("public")).connect().await?;
    /// // Auto-selects GETBULK for V2c/V3, GETNEXT for V1
    /// let results = client.walk(oid!(1, 3, 6, 1, 2, 1, 1))?.collect().await?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self), fields(snmp.target = %self.peer_addr(), snmp.oid = %oid))]
    pub fn walk(&self, oid: Oid) -> Result<WalkStream<T>>
    where
        T: 'static,
    {
        let ordering = self.inner.config.oid_ordering;
        let max_results = self.inner.config.max_walk_results;
        let walk_mode = self.inner.config.walk_mode;
        let max_repetitions = max_repetitions_to_wire(self.inner.config.max_repetitions);
        let version = self.inner.config.version;

        WalkStream::new(
            self.clone(),
            oid,
            version,
            walk_mode,
            ordering,
            max_results,
            max_repetitions,
        )
    }

    /// Walk an OID subtree using GETNEXT.
    ///
    /// This method always uses GETNEXT regardless of the client's `WalkMode` configuration.
    /// For auto-selection based on version and mode, use [`walk()`](Self::walk) instead.
    ///
    /// Returns an async stream that yields each variable binding in the subtree.
    /// The walk terminates when an OID outside the subtree is encountered or
    /// when `EndOfMibView` is returned.
    ///
    /// Uses the client's configured `oid_ordering` and `max_walk_results` settings.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use async_snmp::{Auth, Client, oid};
    /// # async fn example() -> async_snmp::Result<()> {
    /// # let client = Client::builder("127.0.0.1:161", Auth::v2c("public")).connect().await?;
    /// // Force GETNEXT even for V2c/V3 clients
    /// let results = client.walk_getnext(oid!(1, 3, 6, 1, 2, 1, 1)).collect().await?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self), fields(snmp.target = %self.peer_addr(), snmp.oid = %oid))]
    pub fn walk_getnext(&self, oid: Oid) -> Walk<T>
    where
        T: 'static,
    {
        let ordering = self.inner.config.oid_ordering;
        let max_results = self.inner.config.max_walk_results;
        Walk::new(self.clone(), oid, ordering, max_results)
    }

    /// Walk an OID subtree using GETBULK (more efficient than GETNEXT).
    ///
    /// Returns an async stream that yields each variable binding in the subtree.
    /// Uses GETBULK internally with `non_repeaters=0`, fetching `max_repetitions`
    /// values per request for efficient table traversal.
    ///
    /// Uses the client's configured `oid_ordering` and `max_walk_results` settings.
    ///
    /// # Arguments
    ///
    /// * `oid` - The base OID of the subtree to walk
    /// * `max_repetitions` - How many OIDs to fetch per request
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use async_snmp::{Auth, Client, oid};
    /// # async fn example() -> async_snmp::Result<()> {
    /// # let client = Client::builder("127.0.0.1:161", Auth::v2c("public")).connect().await?;
    /// // Walk the interfaces table efficiently
    /// let walk = client.bulk_walk(oid!(1, 3, 6, 1, 2, 1, 2, 2), 25);
    /// // Process with futures StreamExt
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self), fields(snmp.target = %self.peer_addr(), snmp.oid = %oid, snmp.max_repetitions = max_repetitions))]
    pub fn bulk_walk(&self, oid: Oid, max_repetitions: i32) -> BulkWalk<T>
    where
        T: 'static,
    {
        let ordering = self.inner.config.oid_ordering;
        let max_results = self.inner.config.max_walk_results;
        BulkWalk::new(self.clone(), oid, max_repetitions, ordering, max_results)
    }

    /// Walk an OID subtree using the client's configured `max_repetitions`.
    ///
    /// This is a convenience method that uses the client's `max_repetitions` setting
    /// (default: 25) instead of requiring it as a parameter.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use async_snmp::{Auth, Client, oid};
    /// # async fn example() -> async_snmp::Result<()> {
    /// # let client = Client::builder("127.0.0.1:161", Auth::v2c("public")).connect().await?;
    /// // Walk using configured max_repetitions
    /// let walk = client.bulk_walk_default(oid!(1, 3, 6, 1, 2, 1, 2, 2));
    /// // Process with futures StreamExt
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self), fields(snmp.target = %self.peer_addr(), snmp.oid = %oid))]
    pub fn bulk_walk_default(&self, oid: Oid) -> BulkWalk<T>
    where
        T: 'static,
    {
        let ordering = self.inner.config.oid_ordering;
        let max_results = self.inner.config.max_walk_results;
        let max_repetitions = max_repetitions_to_wire(self.inner.config.max_repetitions);
        BulkWalk::new(self.clone(), oid, max_repetitions, ordering, max_results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::CommunityMessage;
    use crate::oid::Oid;
    use crate::pdu::{Pdu, PduType};
    use crate::varbind::VarBind;
    use crate::version::Version;
    use bytes::Bytes;
    use std::collections::VecDeque;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    // -------------------------------------------------------------------------
    // max_repetitions_to_wire: saturating u32 -> i32 conversion used by
    // `walk()` and `bulk_walk_default()` so a configured `max_repetitions`
    // above `i32::MAX` cannot wrap to a negative GETBULK field (C7).
    // -------------------------------------------------------------------------

    #[test]
    fn test_max_repetitions_to_wire_saturates_above_i32_max() {
        // A plain `as i32` cast would wrap this to a negative number.
        assert_eq!(max_repetitions_to_wire(u32::MAX), i32::MAX);
        assert_eq!(
            max_repetitions_to_wire(i32::MAX as u32 + 1),
            i32::MAX,
            "one past i32::MAX must saturate, not wrap negative"
        );
    }

    #[test]
    fn test_max_repetitions_to_wire_passes_through_in_range_values() {
        assert_eq!(max_repetitions_to_wire(0), 0);
        assert_eq!(max_repetitions_to_wire(25), 25);
        assert_eq!(max_repetitions_to_wire(i32::MAX as u32), i32::MAX);
    }

    // -------------------------------------------------------------------------
    // Mock transport that returns a response with a configurable number of
    // varbinds, regardless of how many were requested.
    // -------------------------------------------------------------------------

    #[derive(Clone)]
    struct TruncatingTransport {
        /// Number of varbinds to include in each response.
        response_varbind_count: usize,
        /// Captured (`request_id`) values from sent requests, stored for building
        /// responses.
        pending: Arc<Mutex<VecDeque<i32>>>,
    }

    impl TruncatingTransport {
        fn new(response_varbind_count: usize) -> Self {
            Self {
                response_varbind_count,
                pending: Arc::new(Mutex::new(VecDeque::new())),
            }
        }
    }

    impl Transport for TruncatingTransport {
        fn send(&self, data: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send {
            // Decode the sent request to extract the request_id.
            let request_id = crate::transport::extract_request_id(data).unwrap_or(1);
            {
                let mut q = self.pending.lock().unwrap();
                q.push_back(request_id);
            }
            async { Ok(()) }
        }

        fn recv(
            &self,
            _request_id: i32,
        ) -> impl std::future::Future<Output = Result<(Bytes, SocketAddr)>> + Send {
            let request_id = {
                let mut q = self.pending.lock().unwrap();
                q.pop_front().unwrap_or(1)
            };
            let n = self.response_varbind_count;
            let peer: SocketAddr = "127.0.0.1:161".parse().unwrap();

            async move {
                // Build a response PDU with n varbinds (NULL values).
                let varbinds: Vec<VarBind> = (0..n)
                    .map(|i| {
                        VarBind::new(
                            Oid::from_slice(&[1, 3, 6, 1, i as u32]),
                            crate::value::Value::Null,
                        )
                    })
                    .collect();

                let pdu = Pdu {
                    pdu_type: PduType::Response,
                    request_id,
                    error_status: 0,
                    error_index: 0,
                    varbinds,
                };

                let msg = CommunityMessage::v2c(Bytes::from_static(b"public"), pdu);
                let encoded = msg.encode();
                Ok((encoded, peer))
            }
        }

        fn peer_addr(&self) -> SocketAddr {
            "127.0.0.1:161".parse().unwrap()
        }

        fn local_addr(&self) -> SocketAddr {
            "127.0.0.1:0".parse().unwrap()
        }

        fn is_reliable(&self) -> bool {
            true
        }
    }

    fn make_client(response_varbind_count: usize) -> Client<TruncatingTransport> {
        let transport = TruncatingTransport::new(response_varbind_count);
        let config = ClientConfig {
            version: Version::V2c,
            max_oids_per_request: 10,
            retry: crate::client::retry::Retry::none(),
            ..Default::default()
        };
        Client::new(transport, config)
    }

    #[tokio::test]
    async fn get_many_warns_on_truncated_response() {
        // Request 3 OIDs but the mock returns only 1 varbind - should warn and return what we got.
        let client = make_client(1);
        let oids = [
            Oid::from_slice(&[1, 3, 6, 1, 1]),
            Oid::from_slice(&[1, 3, 6, 1, 2]),
            Oid::from_slice(&[1, 3, 6, 1, 3]),
        ];

        let result = client.get_many(&oids).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn get_many_rejects_inflated_response() {
        // Request 3 OIDs but the mock returns 5 varbinds.
        let client = make_client(5);
        let oids = [
            Oid::from_slice(&[1, 3, 6, 1, 1]),
            Oid::from_slice(&[1, 3, 6, 1, 2]),
            Oid::from_slice(&[1, 3, 6, 1, 3]),
        ];

        let err = client.get_many(&oids).await.unwrap_err();
        assert!(
            matches!(*err, Error::MalformedResponse { .. }),
            "expected MalformedResponse, got: {err}"
        );
    }

    #[tokio::test]
    async fn get_many_accepts_correct_response_count() {
        // Request 3 OIDs and the mock returns exactly 3 varbinds.
        let client = make_client(3);
        let oids = [
            Oid::from_slice(&[1, 3, 6, 1, 1]),
            Oid::from_slice(&[1, 3, 6, 1, 2]),
            Oid::from_slice(&[1, 3, 6, 1, 3]),
        ];

        let result = client.get_many(&oids).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
        assert_eq!(result.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn get_next_many_warns_on_truncated_response() {
        // Request 3 OIDs but the mock returns only 1 varbind - should warn and return what we got.
        let client = make_client(1);
        let oids = [
            Oid::from_slice(&[1, 3, 6, 1, 1]),
            Oid::from_slice(&[1, 3, 6, 1, 2]),
            Oid::from_slice(&[1, 3, 6, 1, 3]),
        ];

        let result = client.get_next_many(&oids).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn get_next_many_rejects_inflated_response() {
        // Request 3 OIDs but the mock returns 5 varbinds.
        let client = make_client(5);
        let oids = [
            Oid::from_slice(&[1, 3, 6, 1, 1]),
            Oid::from_slice(&[1, 3, 6, 1, 2]),
            Oid::from_slice(&[1, 3, 6, 1, 3]),
        ];

        let err = client.get_next_many(&oids).await.unwrap_err();
        assert!(
            matches!(*err, Error::MalformedResponse { .. }),
            "expected MalformedResponse, got: {err}"
        );
    }

    #[tokio::test]
    async fn get_next_many_accepts_correct_response_count() {
        // Request 3 OIDs and the mock returns exactly 3 varbinds.
        let client = make_client(3);
        let oids = [
            Oid::from_slice(&[1, 3, 6, 1, 1]),
            Oid::from_slice(&[1, 3, 6, 1, 2]),
            Oid::from_slice(&[1, 3, 6, 1, 3]),
        ];

        let result = client.get_next_many(&oids).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
        assert_eq!(result.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn set_many_warns_on_truncated_response() {
        // Request 3 varbinds but the mock returns only 1 - should warn and return what we got.
        let client = make_client(1);
        let varbinds = [
            (
                Oid::from_slice(&[1, 3, 6, 1, 1]),
                crate::value::Value::Integer(1),
            ),
            (
                Oid::from_slice(&[1, 3, 6, 1, 2]),
                crate::value::Value::Integer(2),
            ),
            (
                Oid::from_slice(&[1, 3, 6, 1, 3]),
                crate::value::Value::Integer(3),
            ),
        ];

        let result = client.set_many(&varbinds).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn set_many_rejects_inflated_response() {
        // Request 3 varbinds but the mock returns 5.
        let client = make_client(5);
        let varbinds = [
            (
                Oid::from_slice(&[1, 3, 6, 1, 1]),
                crate::value::Value::Integer(1),
            ),
            (
                Oid::from_slice(&[1, 3, 6, 1, 2]),
                crate::value::Value::Integer(2),
            ),
            (
                Oid::from_slice(&[1, 3, 6, 1, 3]),
                crate::value::Value::Integer(3),
            ),
        ];

        let err = client.set_many(&varbinds).await.unwrap_err();
        assert!(
            matches!(*err, Error::MalformedResponse { .. }),
            "expected MalformedResponse, got: {err}"
        );
    }

    #[tokio::test]
    async fn set_many_accepts_correct_response_count() {
        // Request 3 varbinds and the mock returns exactly 3.
        let client = make_client(3);
        let varbinds = [
            (
                Oid::from_slice(&[1, 3, 6, 1, 1]),
                crate::value::Value::Integer(1),
            ),
            (
                Oid::from_slice(&[1, 3, 6, 1, 2]),
                crate::value::Value::Integer(2),
            ),
            (
                Oid::from_slice(&[1, 3, 6, 1, 3]),
                crate::value::Value::Integer(3),
            ),
        ];

        let result = client.set_many(&varbinds).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
        assert_eq!(result.unwrap().len(), 3);
    }

    // -------------------------------------------------------------------------
    // Mock transport that returns tooBig when request exceeds a varbind threshold.
    // -------------------------------------------------------------------------

    #[derive(Clone)]
    struct TooBigTransport {
        /// Max varbinds per request before returning tooBig.
        max_varbinds: usize,
        pending: Arc<Mutex<VecDeque<(i32, usize)>>>,
    }

    impl TooBigTransport {
        fn new(max_varbinds: usize) -> Self {
            Self {
                max_varbinds,
                pending: Arc::new(Mutex::new(VecDeque::new())),
            }
        }
    }

    impl Transport for TooBigTransport {
        fn send(&self, data: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send {
            let request_id = crate::transport::extract_request_id(data).unwrap_or(1);
            // Decode the message to count varbinds
            let msg = CommunityMessage::decode(Bytes::copy_from_slice(data)).unwrap();
            let varbind_count = msg.pdu.standard().unwrap().varbinds.len();
            {
                let mut q = self.pending.lock().unwrap();
                q.push_back((request_id, varbind_count));
            }
            async { Ok(()) }
        }

        fn recv(
            &self,
            _request_id: i32,
        ) -> impl std::future::Future<Output = Result<(Bytes, SocketAddr)>> + Send {
            let (request_id, varbind_count) = {
                let mut q = self.pending.lock().unwrap();
                q.pop_front().unwrap_or((1, 0))
            };
            let max = self.max_varbinds;
            let peer: SocketAddr = "127.0.0.1:161".parse().unwrap();

            async move {
                let pdu = if varbind_count > max {
                    // Return tooBig with empty varbinds (per RFC 3416)
                    Pdu {
                        pdu_type: PduType::Response,
                        request_id,
                        error_status: ErrorStatus::TooBig.as_i32(),
                        error_index: 0,
                        varbinds: vec![],
                    }
                } else {
                    // Echo back one varbind per requested OID
                    let varbinds: Vec<VarBind> = (0..varbind_count)
                        .map(|i| {
                            VarBind::new(
                                Oid::from_slice(&[1, 3, 6, 1, i as u32]),
                                crate::value::Value::Integer(i as i32),
                            )
                        })
                        .collect();
                    Pdu {
                        pdu_type: PduType::Response,
                        request_id,
                        error_status: 0,
                        error_index: 0,
                        varbinds,
                    }
                };

                let msg = CommunityMessage::v2c(Bytes::from_static(b"public"), pdu);
                Ok((msg.encode(), peer))
            }
        }

        fn peer_addr(&self) -> SocketAddr {
            "127.0.0.1:161".parse().unwrap()
        }

        fn local_addr(&self) -> SocketAddr {
            "127.0.0.1:0".parse().unwrap()
        }

        fn is_reliable(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn get_many_bisects_on_too_big() {
        // Agent can handle at most 3 varbinds per request. We ask for 8.
        // With max_oids_per_request=10, the initial batch is all 8 OIDs.
        // That triggers tooBig, so it bisects to 4+4, each of which still
        // triggers tooBig, then bisects to 2+2+2+2 which all succeed.
        let transport = TooBigTransport::new(3);
        let config = ClientConfig {
            version: Version::V2c,
            max_oids_per_request: 10,
            retry: crate::client::retry::Retry::none(),
            ..Default::default()
        };
        let client = Client::new(transport, config);

        let oids: Vec<Oid> = (0..8u32)
            .map(|i| Oid::from_slice(&[1, 3, 6, 1, i]))
            .collect();

        let result = client.get_many(&oids).await.unwrap();
        assert_eq!(result.len(), 8);
    }

    #[tokio::test]
    async fn get_many_single_oid_too_big_is_unrecoverable() {
        // Agent returns tooBig even for a single OID - can't bisect further.
        let transport = TooBigTransport::new(0);
        let config = ClientConfig {
            version: Version::V2c,
            max_oids_per_request: 10,
            retry: crate::client::retry::Retry::none(),
            ..Default::default()
        };
        let client = Client::new(transport, config);

        let oids = [Oid::from_slice(&[1, 3, 6, 1, 1])];
        let err = client.get_many(&oids).await.unwrap_err();
        assert!(
            matches!(
                &*err,
                Error::Snmp {
                    status: ErrorStatus::TooBig,
                    ..
                }
            ),
            "expected TooBig, got: {err}"
        );
    }

    #[tokio::test]
    async fn get_next_many_bisects_on_too_big() {
        // Same as get_many test but for GETNEXT.
        let transport = TooBigTransport::new(3);
        let config = ClientConfig {
            version: Version::V2c,
            max_oids_per_request: 10,
            retry: crate::client::retry::Retry::none(),
            ..Default::default()
        };
        let client = Client::new(transport, config);

        let oids: Vec<Oid> = (0..8u32)
            .map(|i| Oid::from_slice(&[1, 3, 6, 1, i]))
            .collect();

        let result = client.get_next_many(&oids).await.unwrap();
        assert_eq!(result.len(), 8);
    }

    // Batched path: get_many with more OIDs than max_per_request.
    #[tokio::test]
    async fn get_many_batched_warns_on_truncated_response() {
        // max_oids_per_request = 10, request 12 OIDs, mock returns 1 per batch.
        // Should warn and return 2 varbinds (1 per batch).
        let transport = TruncatingTransport::new(1);
        let config = ClientConfig {
            version: Version::V2c,
            max_oids_per_request: 10,
            retry: crate::client::retry::Retry::none(),
            ..Default::default()
        };
        let client = Client::new(transport, config);

        let oids: Vec<Oid> = (0..12u32)
            .map(|i| Oid::from_slice(&[1, 3, 6, 1, i]))
            .collect();

        let result = client.get_many(&oids).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
        assert_eq!(result.unwrap().len(), 2); // 1 varbind per batch, 2 batches
    }

    #[tokio::test]
    async fn get_many_batched_rejects_inflated_response() {
        // max_oids_per_request = 10, request 12 OIDs, mock returns 12 per batch.
        let transport = TruncatingTransport::new(12);
        let config = ClientConfig {
            version: Version::V2c,
            max_oids_per_request: 10,
            retry: crate::client::retry::Retry::none(),
            ..Default::default()
        };
        let client = Client::new(transport, config);

        let oids: Vec<Oid> = (0..12u32)
            .map(|i| Oid::from_slice(&[1, 3, 6, 1, i]))
            .collect();

        let err = client.get_many(&oids).await.unwrap_err();
        assert!(
            matches!(*err, Error::MalformedResponse { .. }),
            "expected MalformedResponse, got: {err}"
        );
    }

    // -------------------------------------------------------------------------
    // Mock transport returning a response with a configurable PDU type,
    // community, and message version, for response-validation tests.
    // -------------------------------------------------------------------------

    #[derive(Clone)]
    struct AdversarialTransport {
        pdu_type: PduType,
        community: &'static [u8],
        respond_as_v1: bool,
        pending: Arc<Mutex<VecDeque<i32>>>,
    }

    impl AdversarialTransport {
        fn new(pdu_type: PduType, community: &'static [u8], respond_as_v1: bool) -> Self {
            Self {
                pdu_type,
                community,
                respond_as_v1,
                pending: Arc::new(Mutex::new(VecDeque::new())),
            }
        }
    }

    impl Transport for AdversarialTransport {
        fn send(&self, data: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send {
            let request_id = crate::transport::extract_request_id(data).unwrap_or(1);
            self.pending.lock().unwrap().push_back(request_id);
            async { Ok(()) }
        }

        fn recv(
            &self,
            _request_id: i32,
        ) -> impl std::future::Future<Output = Result<(Bytes, SocketAddr)>> + Send {
            let request_id = self.pending.lock().unwrap().pop_front().unwrap_or(1);
            let peer: SocketAddr = "127.0.0.1:161".parse().unwrap();
            let pdu = Pdu {
                pdu_type: self.pdu_type,
                request_id,
                error_status: 0,
                error_index: 0,
                varbinds: vec![VarBind::new(
                    Oid::from_slice(&[1, 3, 6, 1, 1]),
                    crate::value::Value::Null,
                )],
            };
            let community = Bytes::from_static(self.community);
            let msg = if self.respond_as_v1 {
                CommunityMessage::v1(community, pdu)
            } else {
                CommunityMessage::v2c(community, pdu)
            };
            let encoded = msg.encode();
            async move { Ok((encoded, peer)) }
        }

        fn peer_addr(&self) -> SocketAddr {
            "127.0.0.1:161".parse().unwrap()
        }

        fn local_addr(&self) -> SocketAddr {
            "127.0.0.1:0".parse().unwrap()
        }

        fn is_reliable(&self) -> bool {
            true
        }
    }

    fn adversarial_client(
        pdu_type: PduType,
        community: &'static [u8],
        respond_as_v1: bool,
    ) -> Client<AdversarialTransport> {
        let transport = AdversarialTransport::new(pdu_type, community, respond_as_v1);
        let config = ClientConfig {
            version: Version::V2c,
            retry: crate::client::retry::Retry::none(),
            ..Default::default()
        };
        Client::new(transport, config)
    }

    /// Control: the adversarial transport is otherwise well-formed, so a
    /// Response PDU with the sent community passes validation.
    #[tokio::test]
    async fn response_validation_accepts_well_formed_response() {
        let client = adversarial_client(PduType::Response, b"public", false);
        let result = client.get(&Oid::from_slice(&[1, 3, 6, 1, 1])).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
    }

    /// RFC 3416 Section 4.2: an echoed request-type PDU with a matching
    /// request-id is not a Response and must be rejected.
    #[tokio::test]
    async fn response_validation_rejects_echoed_request_pdu() {
        let client = adversarial_client(PduType::GetRequest, b"public", false);
        let err = client
            .get(&Oid::from_slice(&[1, 3, 6, 1, 1]))
            .await
            .unwrap_err();
        assert!(
            matches!(*err, Error::MalformedResponse { .. }),
            "expected MalformedResponse, got: {err}"
        );
    }

    /// A response whose community differs from the one sent is rejected.
    #[tokio::test]
    async fn response_validation_accepts_community_mismatch() {
        let client = adversarial_client(PduType::Response, b"other", false);
        let result = client.get(&Oid::from_slice(&[1, 3, 6, 1, 1])).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
    }

    /// A v1 response to a v2c request is rejected (version mismatch).
    #[tokio::test]
    async fn response_validation_rejects_version_mismatch() {
        let client = adversarial_client(PduType::Response, b"public", true);
        let err = client
            .get(&Oid::from_slice(&[1, 3, 6, 1, 1]))
            .await
            .unwrap_err();
        assert!(
            matches!(*err, Error::MalformedResponse { .. }),
            "expected MalformedResponse, got: {err}"
        );
    }
}
