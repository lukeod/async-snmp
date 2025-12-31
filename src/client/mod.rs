//! SNMP client implementation.

mod auth;
mod builder;
mod v3;
mod walk;

pub use auth::{Auth, CommunityVersion, UsmAuth, UsmBuilder};
pub use builder::ClientBuilder;

// New unified entry point
impl Client<UdpTransport> {
    /// Create a new SNMP client builder.
    ///
    /// This is the single entry point for client construction, supporting all
    /// SNMP versions (v1, v2c, v3) through the [`Auth`] enum.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::{Auth, Client};
    /// use std::time::Duration;
    ///
    /// # async fn example() -> async_snmp::Result<()> {
    /// // Simple v2c client with default settings
    /// let client = Client::builder("192.168.1.1:161", Auth::v2c("public"))
    ///     .connect().await?;
    ///
    /// // v3 client with authentication
    /// let client = Client::builder("192.168.1.1:161",
    ///     Auth::usm("admin").auth(async_snmp::v3::AuthProtocol::Sha256, "password"))
    ///     .timeout(Duration::from_secs(10))
    ///     .retries(5)
    ///     .connect().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder(target: impl Into<String>, auth: impl Into<Auth>) -> ClientBuilder {
        ClientBuilder::new(target, auth)
    }
}
use crate::error::{DecodeErrorKind, Error, Result};
use crate::message::{CommunityMessage, Message};
use crate::oid::Oid;
use crate::pdu::{GetBulkPdu, Pdu};
use crate::transport::Transport;
use crate::transport::UdpTransport;
use crate::v3::{EngineCache, EngineState, SaltCounter};
use crate::value::Value;
use crate::varbind::VarBind;
use crate::version::Version;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};
use tracing::{Span, instrument};

pub use v3::{V3DerivedKeys, V3SecurityConfig};
pub use walk::{BulkWalk, OidOrdering, Walk, WalkMode, WalkStream};

/// SNMP client.
///
/// Generic over transport type, with `UdpTransport` as default.
#[derive(Clone)]
pub struct Client<T: Transport = UdpTransport> {
    inner: Arc<ClientInner<T>>,
}

struct ClientInner<T: Transport> {
    transport: T,
    config: ClientConfig,
    request_id: AtomicI32,
    /// Cached engine state (V3)
    engine_state: RwLock<Option<EngineState>>,
    /// Derived keys for this engine (V3)
    derived_keys: RwLock<Option<V3DerivedKeys>>,
    /// Salt counter for privacy (V3)
    salt_counter: SaltCounter,
    /// Shared engine cache (V3, optional)
    engine_cache: Option<Arc<EngineCache>>,
}

/// Client configuration.
#[derive(Clone)]
pub struct ClientConfig {
    /// SNMP version
    pub version: Version,
    /// Community string (v1/v2c)
    pub community: Bytes,
    /// Request timeout
    pub timeout: Duration,
    /// Number of retries
    pub retries: u32,
    /// Maximum OIDs per request
    pub max_oids_per_request: usize,
    /// SNMPv3 security configuration
    pub v3_security: Option<V3SecurityConfig>,
    /// Walk operation mode (Auto, GetNext, or GetBulk)
    pub walk_mode: WalkMode,
    /// OID ordering behavior during walk operations
    pub oid_ordering: OidOrdering,
    /// Maximum results from a single walk operation (None = unlimited)
    pub max_walk_results: Option<usize>,
    /// Max-repetitions for GETBULK operations (default: 25)
    pub max_repetitions: u32,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            version: Version::V2c,
            community: Bytes::from_static(b"public"),
            timeout: Duration::from_secs(5),
            retries: 3,
            max_oids_per_request: 10,
            v3_security: None,
            walk_mode: WalkMode::Auto,
            oid_ordering: OidOrdering::Strict,
            max_walk_results: None,
            max_repetitions: 25,
        }
    }
}

impl<T: Transport> Client<T> {
    /// Create a new client with the given transport and config.
    pub fn new(transport: T, config: ClientConfig) -> Self {
        Self {
            inner: Arc::new(ClientInner {
                transport,
                config,
                request_id: AtomicI32::new(1),
                engine_state: RwLock::new(None),
                derived_keys: RwLock::new(None),
                salt_counter: SaltCounter::new(),
                engine_cache: None,
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
                request_id: AtomicI32::new(1),
                engine_state: RwLock::new(None),
                derived_keys: RwLock::new(None),
                salt_counter: SaltCounter::new(),
                engine_cache: Some(engine_cache),
            }),
        }
    }

    /// Get the peer (target) address.
    ///
    /// Returns the remote address that this client sends requests to.
    /// Named to match [`std::net::TcpStream::peer_addr()`].
    pub fn peer_addr(&self) -> SocketAddr {
        self.inner.transport.peer_addr()
    }

    /// Generate next request ID.
    ///
    /// Uses the transport's shared counter if available (for shared transports),
    /// otherwise uses the client's own counter.
    fn next_request_id(&self) -> i32 {
        self.inner
            .transport
            .alloc_request_id()
            .unwrap_or_else(|| self.inner.request_id.fetch_add(1, Ordering::Relaxed))
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
            snmp.retries = tracing::field::Empty,
            snmp.elapsed_ms = tracing::field::Empty,
        )
    )]
    async fn send_and_recv(&self, request_id: i32, data: &[u8]) -> Result<Pdu> {
        let start = Instant::now();
        let mut last_error = None;
        let retries = if self.inner.transport.is_stream() {
            0
        } else {
            self.inner.config.retries
        };

        for attempt in 0..=retries {
            Span::current().record("snmp.retries", attempt);
            if attempt > 0 {
                tracing::debug!("retrying request");
            }

            // Send request
            tracing::trace!(snmp.bytes = data.len(), "sending request");
            self.inner.transport.send(data).await?;

            // Wait for response
            match self
                .inner
                .transport
                .recv(request_id, self.inner.config.timeout)
                .await
            {
                Ok((response_data, _source)) => {
                    tracing::trace!(snmp.bytes = response_data.len(), "received response");

                    // Decode response and extract PDU
                    let response = Message::decode(response_data)?;

                    // Validate response version matches request version
                    let response_version = response.version();
                    let expected_version = self.inner.config.version;
                    if response_version != expected_version {
                        return Err(Error::VersionMismatch {
                            expected: expected_version,
                            actual: response_version,
                        });
                    }

                    let response_pdu = response.into_pdu();

                    // Validate request ID
                    if response_pdu.request_id != request_id {
                        return Err(Error::RequestIdMismatch {
                            expected: request_id,
                            actual: response_pdu.request_id,
                        });
                    }

                    // Check for SNMP error
                    if response_pdu.is_error() {
                        let status = response_pdu.error_status_enum();
                        // error_index is 1-based; 0 means error applies to PDU, not a specific varbind
                        let oid = (response_pdu.error_index as usize)
                            .checked_sub(1)
                            .and_then(|idx| response_pdu.varbinds.get(idx))
                            .map(|vb| vb.oid.clone());

                        Span::current()
                            .record("snmp.elapsed_ms", start.elapsed().as_millis() as u64);
                        return Err(Error::Snmp {
                            target: Some(self.peer_addr()),
                            status,
                            index: response_pdu.error_index as u32,
                            oid,
                        });
                    }

                    Span::current().record("snmp.elapsed_ms", start.elapsed().as_millis() as u64);
                    return Ok(response_pdu);
                }
                Err(e @ Error::Timeout { .. }) => {
                    last_error = Some(e);
                    continue;
                }
                Err(e) => {
                    Span::current().record("snmp.elapsed_ms", start.elapsed().as_millis() as u64);
                    return Err(e);
                }
            }
        }

        // All retries exhausted
        Span::current().record("snmp.elapsed_ms", start.elapsed().as_millis() as u64);
        Err(last_error.unwrap_or(Error::Timeout {
            target: Some(self.peer_addr()),
            elapsed: self.inner.config.timeout * (retries + 1),
            request_id,
            retries,
        }))
    }

    /// Send a standard request (GET, GETNEXT, SET) and wait for response.
    async fn send_request(&self, pdu: Pdu) -> Result<Pdu> {
        // Dispatch to V3 handler if configured
        if self.is_v3() {
            return self.send_v3_and_recv(pdu).await;
        }

        tracing::debug!(
            snmp.pdu_type = ?pdu.pdu_type,
            snmp.varbind_count = pdu.varbinds.len(),
            "sending {} request",
            pdu.pdu_type
        );

        let request_id = pdu.request_id;
        let message = CommunityMessage::new(
            self.inner.config.version,
            self.inner.config.community.clone(),
            pdu,
        );
        let data = message.encode();
        let response = self.send_and_recv(request_id, &data).await?;

        tracing::debug!(
            snmp.pdu_type = ?response.pdu_type,
            snmp.varbind_count = response.varbinds.len(),
            snmp.error_status = response.error_status,
            snmp.error_index = response.error_index,
            "received {} response",
            response.pdu_type
        );

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

        tracing::debug!(
            snmp.non_repeaters = pdu.non_repeaters,
            snmp.max_repetitions = pdu.max_repetitions,
            snmp.varbind_count = pdu.varbinds.len(),
            "sending GetBulkRequest"
        );

        let request_id = pdu.request_id;
        let data = CommunityMessage::encode_bulk(
            self.inner.config.version,
            self.inner.config.community.clone(),
            &pdu,
        );
        let response = self.send_and_recv(request_id, &data).await?;

        tracing::debug!(
            snmp.pdu_type = ?response.pdu_type,
            snmp.varbind_count = response.varbinds.len(),
            snmp.error_status = response.error_status,
            snmp.error_index = response.error_index,
            "received {} response",
            response.pdu_type
        );

        Ok(response)
    }

    /// GET a single OID.
    #[instrument(skip(self), err, fields(snmp.target = %self.peer_addr(), snmp.oid = %oid))]
    pub async fn get(&self, oid: &Oid) -> Result<VarBind> {
        let request_id = self.next_request_id();
        let pdu = Pdu::get_request(request_id, std::slice::from_ref(oid));
        let response = self.send_request(pdu).await?;

        response
            .varbinds
            .into_iter()
            .next()
            .ok_or_else(|| Error::decode(0, DecodeErrorKind::EmptyResponse))
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
        if oids.is_empty() {
            return Ok(Vec::new());
        }

        let max_per_request = self.inner.config.max_oids_per_request;

        // Fast path: single request if within limit
        if oids.len() <= max_per_request {
            let request_id = self.next_request_id();
            let pdu = Pdu::get_request(request_id, oids);
            let response = self.send_request(pdu).await?;
            return Ok(response.varbinds);
        }

        // Batched path: split into chunks
        let num_batches = oids.len().div_ceil(max_per_request);
        tracing::debug!(
            snmp.oid_count = oids.len(),
            snmp.max_per_request = max_per_request,
            snmp.batch_count = num_batches,
            "splitting GET request into batches"
        );

        let mut all_results = Vec::with_capacity(oids.len());

        for (batch_idx, chunk) in oids.chunks(max_per_request).enumerate() {
            tracing::debug!(
                snmp.batch = batch_idx + 1,
                snmp.batch_total = num_batches,
                snmp.batch_oid_count = chunk.len(),
                "sending GET batch"
            );
            let request_id = self.next_request_id();
            let pdu = Pdu::get_request(request_id, chunk);
            let response = self.send_request(pdu).await?;
            all_results.extend(response.varbinds);
        }

        Ok(all_results)
    }

    /// GETNEXT for a single OID.
    #[instrument(skip(self), err, fields(snmp.target = %self.peer_addr(), snmp.oid = %oid))]
    pub async fn get_next(&self, oid: &Oid) -> Result<VarBind> {
        let request_id = self.next_request_id();
        let pdu = Pdu::get_next_request(request_id, std::slice::from_ref(oid));
        let response = self.send_request(pdu).await?;

        response
            .varbinds
            .into_iter()
            .next()
            .ok_or_else(|| Error::decode(0, DecodeErrorKind::EmptyResponse))
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
        if oids.is_empty() {
            return Ok(Vec::new());
        }

        let max_per_request = self.inner.config.max_oids_per_request;

        // Fast path: single request if within limit
        if oids.len() <= max_per_request {
            let request_id = self.next_request_id();
            let pdu = Pdu::get_next_request(request_id, oids);
            let response = self.send_request(pdu).await?;
            return Ok(response.varbinds);
        }

        // Batched path: split into chunks
        let num_batches = oids.len().div_ceil(max_per_request);
        tracing::debug!(
            snmp.oid_count = oids.len(),
            snmp.max_per_request = max_per_request,
            snmp.batch_count = num_batches,
            "splitting GETNEXT request into batches"
        );

        let mut all_results = Vec::with_capacity(oids.len());

        for (batch_idx, chunk) in oids.chunks(max_per_request).enumerate() {
            tracing::debug!(
                snmp.batch = batch_idx + 1,
                snmp.batch_total = num_batches,
                snmp.batch_oid_count = chunk.len(),
                "sending GETNEXT batch"
            );
            let request_id = self.next_request_id();
            let pdu = Pdu::get_next_request(request_id, chunk);
            let response = self.send_request(pdu).await?;
            all_results.extend(response.varbinds);
        }

        Ok(all_results)
    }

    /// SET a single OID.
    #[instrument(skip(self, value), err, fields(snmp.target = %self.peer_addr(), snmp.oid = %oid))]
    pub async fn set(&self, oid: &Oid, value: Value) -> Result<VarBind> {
        let request_id = self.next_request_id();
        let varbind = VarBind::new(oid.clone(), value);
        let pdu = Pdu::set_request(request_id, vec![varbind]);
        let response = self.send_request(pdu).await?;

        response
            .varbinds
            .into_iter()
            .next()
            .ok_or_else(|| Error::decode(0, DecodeErrorKind::EmptyResponse))
    }

    /// SET multiple OIDs.
    ///
    /// If the varbind list exceeds `max_oids_per_request`, the request is
    /// automatically split into multiple batches. Results are returned
    /// in the same order as the input varbinds.
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

        // Fast path: single request if within limit
        if varbinds.len() <= max_per_request {
            let request_id = self.next_request_id();
            let vbs: Vec<VarBind> = varbinds
                .iter()
                .map(|(oid, value)| VarBind::new(oid.clone(), value.clone()))
                .collect();
            let pdu = Pdu::set_request(request_id, vbs);
            let response = self.send_request(pdu).await?;
            return Ok(response.varbinds);
        }

        // Batched path: split into chunks
        let num_batches = varbinds.len().div_ceil(max_per_request);
        tracing::debug!(
            snmp.oid_count = varbinds.len(),
            snmp.max_per_request = max_per_request,
            snmp.batch_count = num_batches,
            "splitting SET request into batches"
        );

        let mut all_results = Vec::with_capacity(varbinds.len());

        for (batch_idx, chunk) in varbinds.chunks(max_per_request).enumerate() {
            tracing::debug!(
                snmp.batch = batch_idx + 1,
                snmp.batch_total = num_batches,
                snmp.batch_oid_count = chunk.len(),
                "sending SET batch"
            );
            let request_id = self.next_request_id();
            let vbs: Vec<VarBind> = chunk
                .iter()
                .map(|(oid, value)| VarBind::new(oid.clone(), value.clone()))
                .collect();
            let pdu = Pdu::set_request(request_id, vbs);
            let response = self.send_request(pdu).await?;
            all_results.extend(response.varbinds);
        }

        Ok(all_results)
    }

    /// GETBULK request (SNMPv2c/v3 only).
    ///
    /// Retrieves multiple variable bindings in a single request.
    ///
    /// # Arguments
    ///
    /// * `oids` - OIDs to retrieve
    /// * `non_repeaters` - Number of OIDs to treat as non-repeating
    /// * `max_repetitions` - Maximum iterations for repeating OIDs
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use async_snmp::{Auth, Client, oid};
    /// # async fn example() -> async_snmp::Result<()> {
    /// # let client = Client::builder("127.0.0.1:161", Auth::v2c("public")).connect().await?;
    /// // Get next 10 entries starting from ifDescr
    /// let results = client.get_bulk(&[oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2)], 0, 10).await?;
    /// for vb in results {
    ///     println!("{}: {:?}", vb.oid, vb.value);
    /// }
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
        let max_repetitions = self.inner.config.max_repetitions as i32;
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
    /// Uses GETBULK internally for better performance when walking large tables.
    ///
    /// Uses the client's configured `oid_ordering` and `max_walk_results` settings.
    /// If `max_repetitions` is not specified, uses the client's configured `max_repetitions`.
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
        let max_repetitions = self.inner.config.max_repetitions as i32;
        BulkWalk::new(self.clone(), oid, max_repetitions, ordering, max_results)
    }
}
