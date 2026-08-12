//! SNMP client implementation.

mod auth;
mod builder;
mod chunks;
mod response_shape;
mod retry;
mod v3;
mod walk;

pub use auth::{Auth, CommunityVersion};
pub use builder::{ClientBuilder, DEFAULT_CONSTRUCTION_TIMEOUT, Target};
pub use chunks::{FixedCardinalityChunk, FixedCardinalityChunkError, FixedCardinalityChunkStream};
pub use response_shape::{
    BulkResponse, FixedCardinalityOperation, FixedCardinalityResponse, ResponseMetadata,
    ResponseShapeAnomaly, ResponseShapePolicy,
};
pub use retry::{Retry, RetryBuilder, RetryConfigError};

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
    ///
    /// UDP clients expose endpoint observation but not lifecycle authority:
    ///
    /// ```compile_fail
    /// async fn invalid(client: async_snmp::UdpClient) {
    ///     let _control = client.control();
    ///     client.shutdown().await;
    /// }
    /// ```
    pub fn builder(target: impl Into<Target>, auth: impl Into<Auth>) -> ClientBuilder {
        ClientBuilder::new(target, auth)
    }

    /// Snapshot cumulative statistics for this client's UDP endpoint.
    ///
    /// Dedicated clients observe their private endpoint. Clients built from a
    /// shared [`UdpTransport`](crate::UdpTransport) observe the same counters as
    /// every other client and handle using that endpoint.
    #[must_use]
    pub fn stats(&self) -> UdpStats {
        self.inner.transport.stats()
    }
}
#[cfg(test)]
use crate::error::ErrorStatus;
use crate::error::{Error, Result};
use crate::message::{CommunityMessage, Message, SecurityLevel};
use crate::oid::Oid;
use crate::pdu::{Pdu, PduType, TrapV1Pdu};
use crate::transport::{Candidate, Transport, UdpHandle, UdpStats};
use crate::v3::{EngineCache, EngineState, SaltCounter};
use crate::value::Value;
use crate::varbind::VarBind;
use crate::version::Version;
use response_shape::{RequestShape, classify};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{Span, instrument};

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
pub use crate::v3::DerivedKeys;
#[cfg(not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
use crate::v3::DerivedKeys;
pub use crate::v3::UsmConfig;
pub use walk::{
    BulkWalk, BulkWalkWithMetadata, OidOrdering, Walk, WalkCollection, WalkError, WalkItem,
    WalkMode, WalkStream, WalkStreamWithMetadata, WalkWithMetadata,
};

// ============================================================================
// Shared helpers
// ============================================================================

/// Extract an SNMP-level error from a PDU and convert it to an `Error::Snmp`.
///
/// Returns `Some(err)` if the PDU carries an SNMP error status, `None` otherwise.
/// The `error_index` field is 1-based; 0 means the error applies to the whole PDU.
pub(crate) fn pdu_to_snmp_error(
    pdu: &Pdu,
    target: SocketAddr,
    metadata: ResponseMetadata,
) -> Option<Box<Error>> {
    if !pdu.is_error() {
        return None;
    }
    let status = pdu.error_status_enum();
    let oid = (pdu.error_index() as usize)
        .checked_sub(1)
        .and_then(|idx| pdu.varbinds.get(idx))
        .map(|vb| Box::new(vb.oid.clone()));
    Some(
        Error::Snmp {
            target,
            status,
            index: pdu.error_index().try_into().unwrap_or(0),
            oid,
            metadata: Box::new(metadata),
        }
        .boxed(),
    )
}

// ============================================================================
// Default configuration constants
// ============================================================================

/// Default timeout for SNMP requests.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Default timeout for unconfirmed notification sends.
pub const DEFAULT_SEND_TIMEOUT: Duration = Duration::from_secs(5);

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

#[derive(Debug)]
pub(super) struct DecodedResponse {
    pub(super) pdu: Pdu,
    pub(super) decode_anomalies: Vec<crate::DecodeAnomaly>,
}

impl<T: Transport> Clone for Client<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

struct ClientEngine {
    state: EngineState,
    derived_keys: DerivedKeys,
    /// Unique identity for this installed live engine generation.
    generation: Arc<()>,
}

impl ClientEngine {
    fn new(state: EngineState, derived_keys: DerivedKeys) -> Self {
        Self {
            state,
            derived_keys,
            generation: Arc::new(()),
        }
    }
}

struct ClientInner<T: Transport> {
    transport: T,
    config: ClientConfig,
    /// Coherent V3 identity, trusted time, and identity-localized keys.
    engine: RwLock<Option<ClientEngine>>,
    /// Salt counter for privacy (V3)
    salt_counter: Option<SaltCounter>,
    /// Shared engine cache (V3, optional)
    engine_cache: Option<Arc<EngineCache>>,
    /// Serializes concurrent discovery attempts so only one runs at a time.
    discovery_lock: AsyncMutex<()>,
    /// Keys derived against the local authoritative engine ID for V3 traps.
    local_derived_keys: RwLock<Option<DerivedKeys>>,
    #[cfg(test)]
    authenticated_response_validated_hook: RwLock<Option<Arc<dyn Fn() + Send + Sync>>>,
}

/// Client configuration.
///
/// Most users should use [`ClientBuilder`] rather than constructing this directly.
/// Authentication selects the protocol version, so contradictory configurations
/// such as an SNMPv3 version without USM credentials are not representable.
///
/// ```compile_fail
/// use async_snmp::{ClientConfig, Version};
///
/// let _ = ClientConfig {
///     version: Version::V3,
///     v3_security: None,
///     ..ClientConfig::default()
/// };
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct ClientConfig {
    /// Authentication and corresponding SNMP version (default: V2c "public").
    pub auth: Auth,
    /// Top-level response-envelope consumption policy (default: compatible).
    ///
    /// Compatible mode accepts bounded bytes after one complete declared SNMP
    /// message in a UDP datagram despite RFC 3417's one-message-per-datagram
    /// mapping. Strict mode rejects such datagrams. TCP still treats each
    /// declared message TLV as one stream frame.
    pub decode_policy: crate::message::DecodePolicy,
    /// BER/value malformed-input compatibility policy (default: established
    /// permissive receive behavior).
    pub compatibility_policy: crate::CompatibilityPolicy,
    /// Policy for correlating v1/v2c response communities (default: exact).
    pub community_response_policy: crate::transport::CommunityResponsePolicy,
    /// Request timeout (default: 5 seconds)
    pub request_timeout: Duration,
    /// Standalone send timeout (default: 5 seconds).
    ///
    /// This bounds unconfirmed notifications across transport queueing and
    /// write I/O. Confirmed requests continue to use [`Self::request_timeout`].
    pub send_timeout: Duration,
    /// Retry configuration (default: 3 retries, 1-second delay)
    pub retry: Retry,
    /// Maximum OIDs per request (default: 10)
    pub max_oids_per_request: usize,
    /// Fixed-cardinality response-shape policy (default: compatible).
    pub response_shape_policy: ResponseShapePolicy,
    /// Permit one packet-local correction from an unauthenticated
    /// `usmStatsNotInTimeWindows` Report on an authenticated V3 operation.
    ///
    /// This is disabled by default because the Report's boots/time tuple is
    /// unauthenticated and can cause one authenticated packet to be sent with
    /// attacker-selected time fields. The tuple is never stored as trusted
    /// engine state; only a subsequent authenticated, fully matched Response
    /// may advance that state.
    pub allow_unauthenticated_v3_time_correction: bool,
    /// Walk operation mode (default: Auto)
    pub walk_mode: WalkMode,
    /// OID ordering behavior during walk operations (default: Strict)
    pub oid_ordering: OidOrdering,
    /// Maximum results from a single walk operation (default: None/unlimited)
    pub max_walk_results: Option<usize>,
    /// Max-repetitions for GETBULK operations (default: 25).
    ///
    /// Values above `i32::MAX` are rejected during client construction.
    pub max_repetitions: u32,
    /// Local authoritative engine state for V3 trap sending (default: None).
    ///
    /// Per RFC 3412 Section 6.4, the sender is authoritative for trap PDUs.
    /// Construct this through the persistence-enforcing
    /// [`AuthoritativeEngine`](crate::v3::AuthoritativeEngine) API.
    pub local_authoritative_engine: Option<crate::v3::AuthoritativeEngine>,
}

impl Default for ClientConfig {
    /// Returns configuration for `SNMPv2c` with community "public".
    ///
    /// See field documentation for all default values.
    fn default() -> Self {
        Self {
            auth: Auth::default(),
            decode_policy: crate::message::DecodePolicy::Compatible,
            compatibility_policy: crate::CompatibilityPolicy::default(),
            community_response_policy: crate::transport::CommunityResponsePolicy::Exact,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            send_timeout: DEFAULT_SEND_TIMEOUT,
            retry: Retry::default(),
            max_oids_per_request: DEFAULT_MAX_OIDS_PER_REQUEST,
            response_shape_policy: ResponseShapePolicy::Compatible,
            allow_unauthenticated_v3_time_correction: false,
            walk_mode: WalkMode::Auto,
            oid_ordering: OidOrdering::Strict,
            max_walk_results: None,
            max_repetitions: DEFAULT_MAX_REPETITIONS,
            local_authoritative_engine: None,
        }
    }
}

impl ClientConfig {
    fn version(&self) -> Version {
        self.auth.version()
    }

    fn community(&self) -> Result<crate::Community> {
        self.auth
            .community()
            .cloned()
            .ok_or_else(|| Error::Config("community authentication required".into()).boxed())
    }

    fn usm_config(&self) -> Option<&UsmConfig> {
        self.auth.usm_config()
    }

    pub(super) fn validate(&self) -> Result<()> {
        crate::transport::checked_deadline(self.request_timeout, "request timeout")?;
        crate::transport::checked_deadline(self.send_timeout, "send timeout")?;

        if self.max_oids_per_request == 0 {
            return Err(
                Error::Config("max_oids_per_request must be greater than 0".into()).boxed(),
            );
        }

        if self.max_repetitions > crate::pdu::MAX_GET_BULK_VALUE {
            return Err(Error::Config("max_repetitions exceeds i32::MAX".into()).boxed());
        }

        if self.version() == Version::V1 && self.walk_mode == WalkMode::GetBulk {
            return Err(Error::Config("GETBULK not supported in SNMPv1".into()).boxed());
        }

        if self.oid_ordering == OidOrdering::AllowNonIncreasing && self.max_walk_results.is_none() {
            return Err(Error::Config(
                "AllowNonIncreasing requires max_walk_results to bound memory usage".into(),
            )
            .boxed());
        }

        Ok(())
    }

    fn validate_and_precompute(&mut self) -> Result<()> {
        self.validate()?;
        if let Auth::Usm(config) = &mut self.auth {
            config.validate_and_precompute().map_err(|error| {
                Error::Config(format!("invalid USM configuration: {error}").into()).boxed()
            })?;
        }
        Ok(())
    }
}

impl<T: Transport> Client<T> {
    /// Create a new client with the given transport and config.
    ///
    /// For most use cases, prefer [`Client::builder()`] which provides a more
    /// ergonomic API. Use this constructor when you need fine-grained control
    /// over transport configuration (e.g., TCP connection timeout, keepalive
    /// settings) or when using a custom [`Transport`] implementation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the configuration violates a client
    /// invariant, or [`Error::RandomSource`] when an `authPriv` client cannot
    /// initialize its privacy salt.
    pub fn new(transport: T, config: ClientConfig) -> Result<Self> {
        Self::with_optional_engine_cache(transport, config, None)
    }

    /// Create a new V3 client with a shared engine cache.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the configuration violates a client
    /// invariant, or [`Error::RandomSource`] when an `authPriv` client cannot
    /// initialize its privacy salt.
    pub fn with_engine_cache(
        transport: T,
        config: ClientConfig,
        engine_cache: Arc<EngineCache>,
    ) -> Result<Self> {
        Self::with_optional_engine_cache(transport, config, Some(engine_cache))
    }

    fn with_optional_engine_cache(
        transport: T,
        mut config: ClientConfig,
        engine_cache: Option<Arc<EngineCache>>,
    ) -> Result<Self> {
        config.validate_and_precompute()?;
        let salt_counter = config
            .usm_config()
            .filter(|security| security.security_level().requires_priv())
            .map(|_| SaltCounter::new())
            .transpose()?;
        Ok(Self {
            inner: Arc::new(ClientInner {
                transport,
                config,
                engine: RwLock::new(None),
                salt_counter,
                engine_cache,
                discovery_lock: AsyncMutex::new(()),
                local_derived_keys: RwLock::new(None),
                #[cfg(test)]
                authenticated_response_validated_hook: RwLock::new(None),
            }),
        })
    }

    /// Get the peer (target) address.
    ///
    /// Returns the remote address that this client sends requests to.
    /// Named to match [`std::net::TcpStream::peer_addr()`].
    #[must_use]
    pub fn peer_addr(&self) -> SocketAddr {
        self.inner.transport.peer_addr()
    }

    /// Returns the SNMP version configured for this client.
    ///
    /// The version is selected by the client's authentication configuration and
    /// does not expose community or USM identity data.
    #[must_use]
    pub fn version(&self) -> Version {
        self.inner.config.version()
    }

    /// Return the configured top-level response-envelope policy.
    #[must_use]
    pub fn decode_policy(&self) -> crate::message::DecodePolicy {
        self.inner.config.decode_policy
    }

    /// Return the configured BER/value compatibility policy.
    #[must_use]
    pub fn compatibility_policy(&self) -> crate::CompatibilityPolicy {
        self.inner.config.compatibility_policy
    }

    /// Returns the configured SNMPv3 USM security level.
    ///
    /// Returns `None` for SNMPv1 and SNMPv2c clients. For SNMPv3 clients, the
    /// value describes the configured security level and does not expose the
    /// USM identity or credentials.
    #[must_use]
    pub fn security_level(&self) -> Option<SecurityLevel> {
        self.inner
            .config
            .usm_config()
            .map(UsmConfig::security_level)
    }

    /// Generate next request ID.
    ///
    /// Uses the transport's allocator (backed by a global counter).
    fn next_request_id(&self) -> i32 {
        self.inner.transport.alloc_request_id()
    }

    /// Check if using V3 with authentication/encryption configured.
    fn is_v3(&self) -> bool {
        matches!(self.inner.config.auth, Auth::Usm(_))
    }

    /// Enforce the exact encoded size before transport I/O.
    ///
    /// SNMPv3 request/response exchanges additionally honor the remote
    /// engine's learned receive capacity. Local receive advertisement is not
    /// an outbound constraint.
    pub(super) fn enforce_outbound_size(
        &self,
        encoded_size: usize,
        remote_receive_capacity: Option<crate::MessageSize>,
    ) -> Result<()> {
        let transport_capacity = self.inner.transport.send_capacity();
        let effective_limit = remote_receive_capacity
            .map(crate::MessageSize::as_usize)
            .map_or(transport_capacity, |remote| transport_capacity.min(remote));
        crate::message_size::enforce_outbound_size(encoded_size, effective_limit)
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
    async fn send_and_recv(&self, request_id: i32, data: &[u8]) -> Result<DecodedResponse> {
        self.enforce_outbound_size(data.len(), None)?;
        let start = Instant::now();
        let mut last_error: Option<Box<Error>> = None;
        let max_attempts = if self.inner.transport.is_reliable() {
            0
        } else {
            self.inner.config.retry.max_attempts()
        };

        for attempt in 0..=max_attempts {
            Span::current().record("snmp.attempt", attempt);
            if attempt > 0 {
                tracing::debug!(target: "async_snmp::client", "retrying request");
            }

            // Register (or re-register) with fresh deadline before sending
            let version = self.inner.config.version();
            let community_version = match version {
                Version::V1 => CommunityVersion::V1,
                Version::V2c => CommunityVersion::V2c,
                Version::V3 => unreachable!("community request path cannot use SNMPv3"),
            };
            let community = self.inner.config.community()?;
            let registration = crate::transport::RequestRegistration::community(
                request_id,
                self.inner.config.request_timeout,
                community_version,
                community.clone(),
                self.inner.config.community_response_policy,
            )
            .with_decode_policy(self.inner.config.decode_policy);

            // Send request and wait for response as a single unit. Combining the
            // two lets reliable transports (TCP) own their stream lock for the
            // whole exchange, so a cancelled request cannot leak the lock and
            // wedge later requests.
            tracing::trace!(target: "async_snmp::client", { snmp.bytes = data.len() }, "sending request");
            match self
                .inner
                .transport
                .request_with(data, registration, |response_data, source| {
                    tracing::trace!(target: "async_snmp::client", { snmp.bytes = response_data.len() }, "received response candidate");
                    let Ok(decoded) = Message::decode_bounded_with_target_and_compatibility(
                        response_data,
                        self.inner.transport.receive_limits().accepted(),
                        Some(source),
                        self.inner.config.decode_policy,
                        self.inner.config.compatibility_policy,
                    ) else {
                        return Ok(Candidate::Reject);
                    };
                    let response = decoded.value;
                    if response.version() != version {
                        return Ok(Candidate::Reject);
                    }
                    if let Message::Community(ref message) = response
                        && community.as_bytes() != message.community().as_bytes()
                    {
                        let accepted = match self.inner.config.community_response_policy {
                            crate::transport::CommunityResponsePolicy::Exact => false,
                            crate::transport::CommunityResponsePolicy::AllowMismatchFromTarget => {
                                source == self.peer_addr()
                            }
                            crate::transport::CommunityResponsePolicy::AllowMismatchFromAnySource => true,
                        };
                        if !accepted {
                            return Ok(Candidate::Reject);
                        }
                    }
                    let Some(response_pdu) = response.into_pdu() else {
                        return Ok(Candidate::Reject);
                    };
                    if response_pdu.pdu_type() != PduType::Response
                        || response_pdu.request_id != request_id
                    {
                        return Ok(Candidate::Reject);
                    }
                    Ok(Candidate::Accept(DecodedResponse {
                        pdu: response_pdu,
                        decode_anomalies: decoded.anomalies,
                    }))
                })
                .await
            {
                Ok(response) => {
                    if let Some(err) = pdu_to_snmp_error(
                        &response.pdu,
                        self.peer_addr(),
                        ResponseMetadata::from_decode_anomalies(response.decode_anomalies.clone()),
                    ) {
                        Span::current()
                            .record("snmp.elapsed_ms", start.elapsed().as_millis() as u64);
                        return Err(err);
                    }
                    Span::current().record("snmp.elapsed_ms", start.elapsed().as_millis() as u64);
                    return Ok(response);
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

        // All retries exhausted. Every failing attempt was a timeout (other
        // errors return early), so build the final error here with the true
        // total elapsed time and retry count rather than propagating the
        // per-attempt transport timeout, whose elapsed/retries are not
        // meaningful at this layer.
        let _ = last_error;
        let elapsed = start.elapsed();
        Span::current().record("snmp.elapsed_ms", elapsed.as_millis() as u64);
        tracing::debug!(target: "async_snmp::client", { request_id, peer = %self.peer_addr(), ?elapsed, retries = max_attempts }, "request timed out");
        Err(Error::Timeout {
            target: self.peer_addr(),
            elapsed,
            retries: max_attempts,
        }
        .boxed())
    }

    /// Send a standard request (GET, GETNEXT, SET) and wait for response.
    async fn send_request(&self, pdu: Pdu) -> Result<DecodedResponse> {
        // Dispatch to V3 handler if configured
        if self.is_v3() {
            return self.send_v3_and_recv(pdu).await;
        }

        tracing::debug!(target: "async_snmp::client", { snmp.pdu_type = ?pdu.pdu_type(), snmp.varbind_count = pdu.varbinds.len() }, "sending {} request", pdu.pdu_type());

        let request_id = pdu.request_id;
        let message = CommunityMessage::new(
            self.inner.config.version(),
            self.inner.config.community()?,
            pdu,
        )?;
        let data = message.encode()?;
        let response = self.send_and_recv(request_id, &data).await?;

        tracing::debug!(target: "async_snmp::client", { snmp.pdu_type = ?response.pdu.pdu_type(), snmp.varbind_count = response.pdu.varbinds.len(), snmp.error_status = response.pdu.error_status(), snmp.error_index = response.pdu.error_index() }, "received {} response", response.pdu.pdu_type());

        Ok(response)
    }

    fn apply_response_shape_policy(
        &self,
        response: FixedCardinalityResponse,
    ) -> Result<FixedCardinalityResponse> {
        if self.inner.config.response_shape_policy == ResponseShapePolicy::Strict
            && !response.anomalies.is_empty()
        {
            return Err(Error::ResponseShape {
                target: self.peer_addr(),
                response,
            }
            .boxed());
        }
        Ok(response)
    }

    /// GET a single OID.
    ///
    /// Compatible mode preserves every returned binding and describes empty,
    /// excess, or renamed responses in `anomalies`.
    #[instrument(skip(self), err, fields(snmp.target = %self.peer_addr(), snmp.oid = %oid))]
    pub async fn get(&self, oid: &Oid) -> Result<FixedCardinalityResponse> {
        let request_id = self.next_request_id();
        let pdu = Pdu::get_request(request_id, std::slice::from_ref(oid));
        let response = self.send_request(pdu).await?;
        let mut classified = classify(
            RequestShape::Get(std::slice::from_ref(oid)),
            response.pdu.varbinds,
            0,
            0,
        );
        classified.metadata.decode_anomalies = response.decode_anomalies;
        self.apply_response_shape_policy(classified)
    }

    /// GET multiple OIDs.
    ///
    /// If the OID list exceeds `max_oids_per_request`, the request is
    /// automatically split into multiple batches. Response bindings are retained
    /// in received batch order; consult `anomalies` before assuming positional
    /// correspondence with the input OIDs. If any batch fails, this aggregate
    /// convenience method returns the error without returning earlier results;
    /// use [`get_many_chunks()`](Self::get_many_chunks) to retain partial work.
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
    pub async fn get_many(&self, oids: &[Oid]) -> Result<FixedCardinalityResponse> {
        self.get_many_chunks(oids)?.collect_response().await
    }

    /// Lazily GET multiple OIDs as sequential wire-level response chunks.
    ///
    /// All OIDs are validated when this method is called. No request is sent
    /// until the returned stream is polled, and after each item the next request
    /// waits for another poll. An agent `tooBig` response or a local
    /// [`Error::OutboundMessageTooLarge`] bisects a multi-OID request range and
    /// exposes successful child leaves independently. Either error on a
    /// single-OID range is terminal and is returned in
    /// [`FixedCardinalityChunkError::source`].
    ///
    /// The stream emits one [`FixedCardinalityChunkError`] for a terminal
    /// failure, then remains fused. Dropping a chunk stream while a TCP request
    /// is in flight follows [`TcpTransport`](crate::TcpTransport)'s cancellation
    /// contract: cancellation after acquiring the connection lock poisons that
    /// connection, and later operations fail with [`Error::Closed`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidOid`] before any I/O if any input OID cannot be
    /// represented on the wire.
    pub fn get_many_chunks(&self, oids: &[Oid]) -> Result<FixedCardinalityChunkStream<'_, T>> {
        FixedCardinalityChunkStream::new(self, oids, FixedCardinalityOperation::Get)
    }

    /// GETNEXT for a single OID.
    #[instrument(skip(self), err, fields(snmp.target = %self.peer_addr(), snmp.oid = %oid))]
    pub async fn get_next(&self, oid: &Oid) -> Result<FixedCardinalityResponse> {
        let request_id = self.next_request_id();
        let pdu = Pdu::get_next_request(request_id, std::slice::from_ref(oid));
        let response = self.send_request(pdu).await?;
        let mut classified = classify(
            RequestShape::GetNext(std::slice::from_ref(oid)),
            response.pdu.varbinds,
            0,
            0,
        );
        classified.metadata.decode_anomalies = response.decode_anomalies;
        self.apply_response_shape_policy(classified)
    }

    /// GETNEXT for multiple OIDs.
    ///
    /// If the OID list exceeds `max_oids_per_request`, the request is
    /// automatically split into multiple batches. Response bindings are retained
    /// in received batch order; consult `anomalies` before assuming positional
    /// correspondence with the input OIDs. If any batch fails, this aggregate
    /// convenience method returns the error without returning earlier results;
    /// use [`get_next_many_chunks()`](Self::get_next_many_chunks) to retain
    /// partial work.
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
    pub async fn get_next_many(&self, oids: &[Oid]) -> Result<FixedCardinalityResponse> {
        self.get_next_many_chunks(oids)?.collect_response().await
    }

    /// Lazily GETNEXT multiple OIDs as sequential wire-level response chunks.
    ///
    /// This has the same validation, backpressure, bisection, terminal-error,
    /// and TCP cancellation behavior as [`get_many_chunks()`](Self::get_many_chunks).
    pub fn get_next_many_chunks(&self, oids: &[Oid]) -> Result<FixedCardinalityChunkStream<'_, T>> {
        FixedCardinalityChunkStream::new(self, oids, FixedCardinalityOperation::GetNext)
    }

    /// SET a single OID.
    #[instrument(skip(self, value), err, fields(snmp.target = %self.peer_addr(), snmp.oid = %oid))]
    pub async fn set(&self, oid: &Oid, value: Value) -> Result<FixedCardinalityResponse> {
        let request_id = self.next_request_id();
        let requested = [(oid.clone(), value)];
        let pdu = Pdu::set_request(
            request_id,
            vec![VarBind::new(requested[0].0.clone(), requested[0].1.clone())],
        );
        let response = self.send_request(pdu).await?;
        let mut classified = classify(RequestShape::Set(&requested), response.pdu.varbinds, 0, 0);
        classified.metadata.decode_anomalies = response.decode_anomalies;
        self.apply_response_shape_policy(classified)
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
    pub async fn set_many(&self, varbinds: &[(Oid, Value)]) -> Result<FixedCardinalityResponse> {
        if varbinds.is_empty() {
            return Ok(FixedCardinalityResponse::empty(
                FixedCardinalityOperation::Set,
            ));
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
        let pdu = Pdu::set_request(request_id, vbs);
        let response = self.send_request(pdu).await?;
        let mut classified = classify(RequestShape::Set(varbinds), response.pdu.varbinds, 0, 0);
        classified.metadata.decode_anomalies = response.decode_anomalies;
        self.apply_response_shape_policy(classified)
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
    /// For V3: uses the persisted local authoritative engine state configured
    /// through `ClientBuilder::local_authoritative_engine`.
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
        if self.inner.config.version() == Version::V1 {
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
            self.enforce_outbound_size(data.len(), None)?;
            tracing::debug!(target: "async_snmp::client", { snmp.pdu_type = "TrapV2", snmp.varbind_count = pdu.varbinds.len(), snmp.bytes = data.len() }, "sending V3 trap");
            self.inner
                .transport
                .send_with_timeout(&data, self.inner.config.send_timeout)
                .await?;
        } else {
            let message = CommunityMessage::new(
                self.inner.config.version(),
                self.inner.config.community()?,
                pdu,
            )?;
            let data = message.encode()?;
            self.enforce_outbound_size(data.len(), None)?;
            tracing::debug!(target: "async_snmp::client", { snmp.pdu_type = "TrapV2", snmp.bytes = data.len() }, "sending v2c trap");
            self.inner
                .transport
                .send_with_timeout(&data, self.inner.config.send_timeout)
                .await?;
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
        if self.inner.config.version() != Version::V1 {
            return Err(Error::Config("send_v1_trap requires a V1 client".into()).boxed());
        }

        let message = CommunityMessage::v1_trap(self.inner.config.community()?, trap)?;
        let data = message.encode()?;
        self.enforce_outbound_size(data.len(), None)?;
        tracing::debug!(target: "async_snmp::client", { snmp.pdu_type = "TrapV1", snmp.bytes = data.len() }, "sending v1 trap");
        self.inner
            .transport
            .send_with_timeout(&data, self.inner.config.send_timeout)
            .await?;

        Ok(())
    }

    /// Send a v2c/v3 inform and wait for acknowledgement.
    ///
    /// Constructs an `InformRequest` PDU with the mandatory sysUpTime.0 and
    /// snmpTrapOID.0 prefix, sends it to the target, and waits for a Response
    /// PDU that echoes the request variable bindings. Uses the same retry and
    /// timeout logic as other request types.
    ///
    /// For V3: uses engine discovery against the receiver (same as GET/SET).
    /// V1 is not supported and returns an error.
    ///
    /// # Arguments
    ///
    /// * `trap_oid` - The trap OID (snmpTrapOID.0 value)
    /// * `uptime` - sysUpTime.0 value in hundredths of seconds
    /// * `varbinds` - Additional variable bindings (appended after the prefix)
    ///
    /// This convenience method intentionally discards accepted wire-deviation
    /// metadata. Use [`Self::send_inform_with_metadata`] when it is needed.
    #[instrument(skip(self, varbinds), err, fields(snmp.target = %self.peer_addr(), snmp.trap_oid = %trap_oid))]
    pub async fn send_inform(
        &self,
        trap_oid: &Oid,
        uptime: u32,
        varbinds: Vec<VarBind>,
    ) -> Result<()> {
        self.send_inform_with_metadata(trap_oid, uptime, varbinds)
            .await
            .map(|_| ())
    }

    /// Send an Inform and retain metadata from discovery, correction Reports,
    /// and the acknowledgement in exchange order.
    #[instrument(skip(self, varbinds), err, fields(snmp.target = %self.peer_addr(), snmp.trap_oid = %trap_oid))]
    pub async fn send_inform_with_metadata(
        &self,
        trap_oid: &Oid,
        uptime: u32,
        varbinds: Vec<VarBind>,
    ) -> Result<ResponseMetadata> {
        if self.inner.config.version() == Version::V1 {
            return Err(Error::Config("v1 inform sending not supported".into()).boxed());
        }

        let request_id = self.next_request_id();
        let pdu = Pdu::inform_request(request_id, uptime, trap_oid, varbinds);
        let expected_varbinds = pdu.varbinds.clone();
        let response = self.send_request(pdu).await?;
        if response.pdu.varbinds != expected_varbinds {
            let metadata = ResponseMetadata::from_decode_anomalies(response.decode_anomalies);
            return Err(Error::MalformedResponse {
                target: self.peer_addr(),
            }
            .boxed()
            .with_prior_response_metadata(&metadata));
        }
        Ok(ResponseMetadata::from_decode_anomalies(
            response.decode_anomalies,
        ))
    }

    /// GETBULK request (SNMPv2c/v3 only).
    ///
    /// Efficiently retrieves multiple variable bindings in a single request.
    /// GETBULK splits the requested OIDs into two groups:
    ///
    /// - **Non-repeaters** (first N OIDs): Each gets a single GETNEXT, returning
    ///   the first lexicographic successor of the requested OID. To retrieve a
    ///   scalar instance such as `sysUpTime.0`, request its object OID without
    ///   the `.0` instance suffix.
    /// - **Repeaters** (remaining OIDs): Each gets up to `max_repetitions` GETNEXTs,
    ///   returning multiple values per OID. Use for walking table columns.
    ///
    /// # Arguments
    ///
    /// * `oids` - OIDs to retrieve
    /// * `non_repeaters` - How many OIDs (from the start) are non-repeating
    /// * `max_repetitions` - Maximum rows to return for each repeating OID
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMessage`] when either GETBULK parameter exceeds
    /// `i32::MAX`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use async_snmp::{Auth, Client, oid};
    /// # async fn example() -> async_snmp::Result<()> {
    /// # let client = Client::builder("127.0.0.1:161", Auth::v2c("public")).connect().await?;
    /// // Get sysUpTime.0 (non-repeater) plus 10 interface descriptions (repeater).
    /// // Both inputs are object OIDs; GETBULK returns their instance successors.
    /// let results = client.get_bulk(
    ///     &[oid!(1, 3, 6, 1, 2, 1, 1, 3), oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2)],
    ///     1,  // first OID is non-repeating
    ///     10, // get up to 10 values for the second OID
    /// ).await?;
    /// // Results: [sysUpTime value, ifDescr.1, ifDescr.2, ..., ifDescr.10]
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// This convenience method discards accepted response metadata. Use
    /// [`Self::get_bulk_with_metadata`] when compatibility deviations must be
    /// retained.
    #[instrument(skip(self, oids), err, fields(
        snmp.target = %self.peer_addr(),
        snmp.oid_count = oids.len(),
        snmp.non_repeaters = non_repeaters,
        snmp.max_repetitions = max_repetitions
    ))]
    pub async fn get_bulk(
        &self,
        oids: &[Oid],
        non_repeaters: u32,
        max_repetitions: u32,
    ) -> Result<Vec<VarBind>> {
        Ok(self
            .get_bulk_with_metadata(oids, non_repeaters, max_repetitions)
            .await?
            .varbinds)
    }

    /// GETBULK with accepted wire deviations retained as response metadata.
    pub async fn get_bulk_with_metadata(
        &self,
        oids: &[Oid],
        non_repeaters: u32,
        max_repetitions: u32,
    ) -> Result<BulkResponse> {
        Pdu::checked_get_bulk_fields(non_repeaters, max_repetitions)?;
        let request_id = self.next_request_id();
        let pdu = Pdu::get_bulk(
            request_id,
            non_repeaters,
            max_repetitions,
            oids.iter().map(|oid| VarBind::null(oid.clone())).collect(),
        )?;
        let response = self.send_request(pdu).await?;
        Ok(BulkResponse {
            varbinds: response.pdu.varbinds,
            metadata: ResponseMetadata {
                decode_anomalies: response.decode_anomalies,
            },
        })
    }

    /// Walk an OID subtree.
    ///
    /// Auto-selects the optimal walk method based on SNMP version and `WalkMode`:
    /// - `WalkMode::Auto` (default): Uses GETNEXT for V1, GETBULK for V2c/V3
    /// - `WalkMode::GetNext`: Always uses GETNEXT
    /// - `WalkMode::GetBulk`: Always uses GETBULK (fails on V1)
    ///
    /// Returns an async stream that yields each variable binding in the subtree.
    /// This convenience stream intentionally discards decode metadata; use
    /// [`Self::walk_with_metadata`] to retain it.
    /// The walk terminates when an OID outside the subtree is encountered or
    /// when `EndOfMibView` is returned. All consumption methods observe this same
    /// GETNEXT/GETBULK sequence. A scalar instance OID is not retrieved as a
    /// fallback; use [`get()`](Self::get) to retrieve a scalar value.
    ///
    /// Uses the client's configured `oid_ordering`, `max_walk_results`, and
    /// `max_repetitions` (for GETBULK) settings. At a configured result limit,
    /// the stream inspects one look-ahead candidate and may make one extra
    /// request. Definite truncation is emitted as
    /// [`WalkAbortReason::ResultLimitExceeded`](crate::WalkAbortReason::ResultLimitExceeded).
    /// A walk is not an atomic MIB snapshot; values can change between the main
    /// sequence and the look-ahead.
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
        let max_repetitions = self.inner.config.max_repetitions;
        let version = self.inner.config.version();

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

    /// Auto-selected walk retaining per-item and aggregate decode metadata.
    pub fn walk_with_metadata(&self, oid: Oid) -> Result<WalkStreamWithMetadata<T>>
    where
        T: 'static,
    {
        self.walk(oid).map(WalkStreamWithMetadata::new)
    }

    /// Walk an OID subtree using GETNEXT.
    ///
    /// This method always uses GETNEXT regardless of the client's `WalkMode` configuration.
    /// For auto-selection based on version and mode, use [`walk()`](Self::walk) instead.
    ///
    /// Returns an async stream that yields each variable binding in the subtree.
    /// This convenience stream intentionally discards decode metadata; use
    /// [`Self::walk_getnext_with_metadata`] to retain it.
    /// The walk terminates when an OID outside the subtree is encountered or
    /// when `EndOfMibView` is returned. All consumption methods observe this same
    /// GETNEXT sequence. A scalar instance OID is not retrieved as a fallback;
    /// use [`get()`](Self::get) to retrieve a scalar value.
    ///
    /// Uses the client's configured `oid_ordering` and `max_walk_results` settings.
    /// At a configured result limit, the stream sends GETNEXT for one look-ahead
    /// candidate if needed. Definite truncation is emitted as
    /// [`WalkAbortReason::ResultLimitExceeded`](crate::WalkAbortReason::ResultLimitExceeded).
    /// A walk is not an atomic MIB snapshot; values can change before the probe.
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

    /// GETNEXT walk retaining per-item and aggregate decode metadata.
    pub fn walk_getnext_with_metadata(&self, oid: Oid) -> WalkWithMetadata<T>
    where
        T: 'static,
    {
        WalkWithMetadata::new(self.walk_getnext(oid))
    }

    /// Walk an OID subtree using GETBULK (more efficient than GETNEXT).
    ///
    /// Returns an async stream that yields each variable binding in the subtree.
    /// This convenience stream intentionally discards decode metadata; use
    /// [`Self::bulk_walk_with_metadata`] to retain it.
    /// Uses GETBULK internally with `non_repeaters=0`, fetching `max_repetitions`
    /// values per request for efficient table traversal. All consumption methods
    /// observe this same GETBULK sequence. A scalar instance OID is not retrieved
    /// as a fallback; use [`get()`](Self::get) to retrieve a scalar value.
    ///
    /// Uses the client's configured `oid_ordering` and `max_walk_results` settings.
    /// At a configured result limit, the stream first inspects one buffered
    /// binding, or sends GETBULK with `max_repetitions = 1` when none is buffered.
    /// Definite truncation is emitted as
    /// [`WalkAbortReason::ResultLimitExceeded`](crate::WalkAbortReason::ResultLimitExceeded).
    /// A walk is not an atomic MIB snapshot; values can change before the probe.
    ///
    /// # Arguments
    ///
    /// * `oid` - The base OID of the subtree to walk
    /// * `max_repetitions` - How many OIDs to fetch per request
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMessage`] when `max_repetitions` exceeds
    /// `i32::MAX`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use async_snmp::{Auth, Client, oid};
    /// # async fn example() -> async_snmp::Result<()> {
    /// # let client = Client::builder("127.0.0.1:161", Auth::v2c("public")).connect().await?;
    /// // Walk the interfaces table efficiently
    /// let walk = client.bulk_walk(oid!(1, 3, 6, 1, 2, 1, 2, 2), 25)?;
    /// // Process with futures StreamExt
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self), fields(snmp.target = %self.peer_addr(), snmp.oid = %oid, snmp.max_repetitions = max_repetitions))]
    pub fn bulk_walk(&self, oid: Oid, max_repetitions: u32) -> Result<BulkWalk<T>>
    where
        T: 'static,
    {
        Pdu::checked_get_bulk_fields(0, max_repetitions)?;
        let ordering = self.inner.config.oid_ordering;
        let max_results = self.inner.config.max_walk_results;
        BulkWalk::new(self.clone(), oid, max_repetitions, ordering, max_results)
    }

    /// GETBULK walk retaining per-item and aggregate decode metadata.
    pub fn bulk_walk_with_metadata(
        &self,
        oid: Oid,
        max_repetitions: u32,
    ) -> Result<BulkWalkWithMetadata<T>>
    where
        T: 'static,
    {
        self.bulk_walk(oid, max_repetitions)
            .map(BulkWalkWithMetadata::new)
    }

    /// Walk an OID subtree using the client's configured `max_repetitions`.
    ///
    /// Like [`bulk_walk()`](Self::bulk_walk), this yields only GETBULK walk results
    /// and does not retrieve a scalar instance OID with a fallback GET.
    ///
    /// This is a convenience method that uses the client's `max_repetitions` setting
    /// (default: 25) instead of requiring it as a parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMessage`] if the configured value cannot be
    /// represented as an RFC 3416 GETBULK field. Client construction validates
    /// this invariant, so this can occur only if an invalid client is introduced
    /// through future internal changes.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use async_snmp::{Auth, Client, oid};
    /// # async fn example() -> async_snmp::Result<()> {
    /// # let client = Client::builder("127.0.0.1:161", Auth::v2c("public")).connect().await?;
    /// // Walk using configured max_repetitions
    /// let walk = client.bulk_walk_default(oid!(1, 3, 6, 1, 2, 1, 2, 2))?;
    /// // Process with futures StreamExt
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self), fields(snmp.target = %self.peer_addr(), snmp.oid = %oid))]
    pub fn bulk_walk_default(&self, oid: Oid) -> Result<BulkWalk<T>>
    where
        T: 'static,
    {
        let ordering = self.inner.config.oid_ordering;
        let max_results = self.inner.config.max_walk_results;
        BulkWalk::new(
            self.clone(),
            oid,
            self.inner.config.max_repetitions,
            ordering,
            max_results,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::CommunityMessage;
    use crate::oid::Oid;
    use crate::pdu::{Pdu, PduType};
    use crate::varbind::VarBind;
    use bytes::Bytes;
    use std::collections::VecDeque;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

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
            _registration: crate::transport::RequestRegistration,
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

                let pdu = Pdu::response(request_id, 0, 0, varbinds);

                let msg = CommunityMessage::v2c(Bytes::from_static(b"public"), pdu).unwrap();
                let encoded = msg.encode().unwrap();
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

    fn metadata_client(auth: Auth) -> Client<TruncatingTransport> {
        Client::new(
            TruncatingTransport::new(0),
            ClientConfig {
                auth,
                retry: Retry::none(),
                ..Default::default()
            },
        )
        .expect("valid client config")
    }

    #[test]
    fn client_protocol_metadata_covers_versions_and_security_levels() {
        let v1 = metadata_client(Auth::v1("private"));
        assert_eq!(v1.version(), Version::V1);
        assert_eq!(v1.security_level(), None);
        assert!(v1.inner.salt_counter.is_none());

        let v2c = metadata_client(Auth::v2c("public"));
        assert_eq!(v2c.version(), Version::V2c);
        assert_eq!(v2c.security_level(), None);
        assert!(v2c.inner.salt_counter.is_none());

        let no_auth = metadata_client(Auth::usm("no-auth-user").into());
        assert_eq!(no_auth.version(), Version::V3);
        assert_eq!(no_auth.security_level(), Some(SecurityLevel::NoAuthNoPriv));
        assert!(no_auth.inner.salt_counter.is_none());

        #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
        {
            let auth = metadata_client(
                Auth::usm("auth-user")
                    .auth(crate::AuthProtocol::Sha256, "authpassword")
                    .into(),
            );
            assert_eq!(auth.version(), Version::V3);
            assert_eq!(auth.security_level(), Some(SecurityLevel::AuthNoPriv));
            assert!(auth.inner.salt_counter.is_none());

            let auth_priv = metadata_client(
                Auth::usm("private-user")
                    .auth_priv(
                        crate::AuthProtocol::Sha256,
                        "authpassword",
                        crate::PrivProtocol::Aes128,
                        "privpassword",
                    )
                    .into(),
            );
            assert_eq!(auth_priv.version(), Version::V3);
            assert_eq!(auth_priv.security_level(), Some(SecurityLevel::AuthPriv));
            assert!(auth_priv.inner.salt_counter.is_some());
        }
    }

    #[tokio::test]
    async fn client_protocol_metadata_is_transport_independent() {
        let udp_transport = crate::UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let udp_handle = udp_transport
            .handle("127.0.0.1:161".parse().unwrap())
            .unwrap();
        let udp_client = Client::new(
            udp_handle,
            ClientConfig {
                auth: Auth::v1("private"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(udp_client.version(), Version::V1);
        assert_eq!(udp_client.security_level(), None);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_transport = crate::TcpTransport::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let tcp_client = Client::new(
            tcp_transport,
            ClientConfig {
                auth: Auth::usm("no-auth-user").into(),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(tcp_client.version(), Version::V3);
        assert_eq!(
            tcp_client.security_level(),
            Some(SecurityLevel::NoAuthNoPriv)
        );
    }

    fn make_client(response_varbind_count: usize) -> Client<TruncatingTransport> {
        make_client_with_policy(response_varbind_count, ResponseShapePolicy::Compatible)
    }

    fn make_client_with_policy(
        response_varbind_count: usize,
        response_shape_policy: ResponseShapePolicy,
    ) -> Client<TruncatingTransport> {
        let transport = TruncatingTransport::new(response_varbind_count);
        let config = ClientConfig {
            auth: crate::Auth::v2c("public"),
            max_oids_per_request: 10,
            retry: crate::client::retry::Retry::none(),
            response_shape_policy,
            ..Default::default()
        };
        Client::new(transport, config).expect("valid client config")
    }

    /// Returns exact scripted response bindings, preserving their order and values.
    #[derive(Clone)]
    struct ScriptedResponseTransport {
        responses: Arc<Mutex<VecDeque<Vec<VarBind>>>>,
        pending: Arc<Mutex<VecDeque<i32>>>,
    }

    impl ScriptedResponseTransport {
        fn new(responses: Vec<Vec<VarBind>>) -> Self {
            Self {
                responses: Arc::new(Mutex::new(responses.into())),
                pending: Arc::new(Mutex::new(VecDeque::new())),
            }
        }
    }

    impl Transport for ScriptedResponseTransport {
        fn send(&self, data: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send {
            let request_id = crate::transport::extract_request_id(data).unwrap_or(1);
            self.pending.lock().unwrap().push_back(request_id);
            async { Ok(()) }
        }

        fn recv(
            &self,
            _registration: crate::transport::RequestRegistration,
        ) -> impl std::future::Future<Output = Result<(Bytes, SocketAddr)>> + Send {
            let request_id = self.pending.lock().unwrap().pop_front().unwrap_or(1);
            let varbinds = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("missing scripted response");
            async move {
                let pdu = Pdu::response(request_id, 0, 0, varbinds);
                let message = CommunityMessage::v2c(Bytes::from_static(b"public"), pdu).unwrap();
                Ok((message.encode().unwrap(), "127.0.0.1:161".parse().unwrap()))
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

    fn scripted_client(
        responses: Vec<Vec<VarBind>>,
        response_shape_policy: ResponseShapePolicy,
    ) -> Client<ScriptedResponseTransport> {
        Client::new(
            ScriptedResponseTransport::new(responses),
            ClientConfig {
                auth: crate::Auth::v2c("public"),
                retry: crate::client::retry::Retry::none(),
                response_shape_policy,
                ..Default::default()
            },
        )
        .expect("valid client config")
    }

    fn response_shape_error(result: Result<FixedCardinalityResponse>) -> FixedCardinalityResponse {
        match *result.expect_err("strict policy must reject the scripted anomaly") {
            Error::ResponseShape { response, .. } => response,
            ref other => panic!("expected ResponseShape, got {other:?}"),
        }
    }

    #[derive(Clone)]
    struct CountingTransport {
        sends: Arc<AtomicUsize>,
        allocations: Arc<AtomicUsize>,
    }

    #[derive(Clone)]
    struct SendTimeoutProbe {
        timeouts: Arc<Mutex<Vec<Duration>>>,
    }

    impl Transport for SendTimeoutProbe {
        async fn send(&self, _data: &[u8]) -> Result<()> {
            panic!("client trap sending must use the bounded send contract")
        }

        async fn send_with_timeout(&self, _data: &[u8], timeout: Duration) -> Result<()> {
            self.timeouts.lock().unwrap().push(timeout);
            Ok(())
        }

        fn peer_addr(&self) -> SocketAddr {
            "127.0.0.1:162".parse().unwrap()
        }

        fn local_addr(&self) -> SocketAddr {
            "127.0.0.1:0".parse().unwrap()
        }

        fn is_reliable(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn v1_v2c_and_v3_traps_use_configured_send_timeout() {
        let timeouts = Arc::new(Mutex::new(Vec::new()));
        let trap_oid = crate::oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
        let send_timeout = Duration::from_secs(7);

        for auth in [crate::Auth::v1("public"), crate::Auth::v2c("public")] {
            let client = Client::new(
                SendTimeoutProbe {
                    timeouts: Arc::clone(&timeouts),
                },
                ClientConfig {
                    auth,
                    send_timeout,
                    ..Default::default()
                },
            )
            .unwrap();
            client.send_trap(&trap_oid, 0, vec![]).await.unwrap();
        }

        let authoritative_engine =
            crate::AuthoritativeEngine::install(b"test-trap-engine".to_vec(), |_| {
                Ok::<(), std::convert::Infallible>(())
            })
            .unwrap();
        let v3_client = Client::new(
            SendTimeoutProbe {
                timeouts: Arc::clone(&timeouts),
            },
            ClientConfig {
                auth: crate::Auth::usm("trapuser").into(),
                send_timeout,
                local_authoritative_engine: Some(authoritative_engine),
                ..Default::default()
            },
        )
        .unwrap();
        v3_client.send_trap(&trap_oid, 0, vec![]).await.unwrap();

        assert_eq!(*timeouts.lock().unwrap(), [send_timeout; 3]);
    }

    #[derive(Clone)]
    struct CapacityTransport {
        capacity: usize,
        requests: Arc<AtomicUsize>,
    }

    impl Transport for CapacityTransport {
        async fn send(&self, _data: &[u8]) -> Result<()> {
            Ok(())
        }

        async fn recv(
            &self,
            _registration: crate::transport::RequestRegistration,
        ) -> Result<(Bytes, SocketAddr)> {
            panic!("capacity test overrides request_with")
        }

        async fn request_with<U, F>(
            &self,
            _data: &[u8],
            _registration: crate::transport::RequestRegistration,
            _validate: F,
        ) -> Result<U>
        where
            U: Send,
            F: FnMut(Bytes, SocketAddr) -> Result<crate::transport::Candidate<U>> + Send,
        {
            self.requests.fetch_add(1, Ordering::Relaxed);
            Err(Error::Config("capacity boundary reached transport".into()).boxed())
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

        fn send_capacity(&self) -> usize {
            self.capacity
        }
    }

    #[tokio::test]
    async fn community_atomic_requests_enforce_exact_transport_boundary_before_send() {
        for (version, auth) in [
            (Version::V1, crate::Auth::v1("public")),
            (Version::V2c, crate::Auth::v2c("public")),
        ] {
            let pdu = Pdu::get_request(7, &[crate::oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)]);
            let exact_size =
                CommunityMessage::new(version, Bytes::from_static(b"public"), pdu.clone())
                    .unwrap()
                    .encode()
                    .unwrap()
                    .len();

            let exact_requests = Arc::new(AtomicUsize::new(0));
            let exact_client = Client::new(
                CapacityTransport {
                    capacity: exact_size,
                    requests: Arc::clone(&exact_requests),
                },
                ClientConfig {
                    auth: auth.clone(),
                    retry: crate::client::retry::Retry::none(),
                    ..Default::default()
                },
            )
            .unwrap();
            let error = exact_client.send_request(pdu.clone()).await.unwrap_err();
            assert!(matches!(*error, Error::Config(_)));
            assert_eq!(exact_requests.load(Ordering::Relaxed), 1);

            let oversized_requests = Arc::new(AtomicUsize::new(0));
            let oversized_client = Client::new(
                CapacityTransport {
                    capacity: exact_size - 1,
                    requests: Arc::clone(&oversized_requests),
                },
                ClientConfig {
                    auth,
                    retry: crate::client::retry::Retry::none(),
                    ..Default::default()
                },
            )
            .unwrap();
            let error = oversized_client.send_request(pdu).await.unwrap_err();
            assert!(matches!(
                *error,
                Error::OutboundMessageTooLarge { size, limit }
                    if size == exact_size && limit == exact_size - 1
            ));
            assert_eq!(oversized_requests.load(Ordering::Relaxed), 0);
        }
    }

    impl Transport for CountingTransport {
        fn send(&self, _data: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send {
            self.sends.fetch_add(1, Ordering::Relaxed);
            async { Ok(()) }
        }

        async fn recv(
            &self,
            _registration: crate::transport::RequestRegistration,
        ) -> Result<(Bytes, SocketAddr)> {
            panic!("receive must not be reached after encode failure")
        }

        fn peer_addr(&self) -> SocketAddr {
            "127.0.0.1:161".parse().unwrap()
        }

        fn local_addr(&self) -> SocketAddr {
            "127.0.0.1:0".parse().unwrap()
        }

        fn alloc_request_id(&self) -> i32 {
            self.allocations.fetch_add(1, Ordering::Relaxed);
            1
        }

        fn is_reliable(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn get_bulk_parameter_ranges_are_checked_before_request_side_effects() {
        let client = make_client(0);
        for (non_repeaters, max_repetitions) in [
            (0, 0),
            (crate::pdu::MAX_GET_BULK_VALUE, 0),
            (0, crate::pdu::MAX_GET_BULK_VALUE),
        ] {
            assert!(
                client
                    .get_bulk(&[], non_repeaters, max_repetitions)
                    .await
                    .is_ok()
            );
        }

        let sends = Arc::new(AtomicUsize::new(0));
        let allocations = Arc::new(AtomicUsize::new(0));
        let transport = CountingTransport {
            sends: Arc::clone(&sends),
            allocations: Arc::clone(&allocations),
        };
        let client = Client::new(
            transport,
            ClientConfig {
                auth: crate::Auth::v2c("public"),
                retry: crate::client::retry::Retry::none(),
                ..Default::default()
            },
        )
        .unwrap();

        for (non_repeaters, max_repetitions) in [
            (crate::pdu::MAX_GET_BULK_VALUE + 1, 0),
            (0, crate::pdu::MAX_GET_BULK_VALUE + 1),
        ] {
            let error = client
                .get_bulk(&[], non_repeaters, max_repetitions)
                .await
                .unwrap_err();
            assert!(matches!(*error, Error::InvalidMessage(_)));
        }
        assert_eq!(allocations.load(Ordering::Relaxed), 0);
        assert_eq!(sends.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn bulk_walk_parameter_range_is_checked_before_stream_construction() {
        let sends = Arc::new(AtomicUsize::new(0));
        let allocations = Arc::new(AtomicUsize::new(0));
        let transport = CountingTransport {
            sends: Arc::clone(&sends),
            allocations: Arc::clone(&allocations),
        };
        let client = Client::new(transport, ClientConfig::default()).unwrap();
        let base = Oid::from_slice(&[1, 3, 6, 1]);

        assert!(client.bulk_walk(base.clone(), 0).is_ok());
        assert!(
            client
                .bulk_walk(base.clone(), crate::pdu::MAX_GET_BULK_VALUE)
                .is_ok()
        );
        let error = client
            .bulk_walk(base, crate::pdu::MAX_GET_BULK_VALUE + 1)
            .err()
            .expect("out-of-range bulk walk must not return a stream");
        assert!(matches!(*error, Error::InvalidMessage(_)));
        assert_eq!(allocations.load(Ordering::Relaxed), 0);
        assert_eq!(sends.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn invalid_oid_is_not_sent() {
        fn assert_invalid<T>(result: Result<T>) {
            match result {
                Err(error) => assert!(matches!(&*error, Error::InvalidOid(_))),
                Ok(_) => panic!("invalid OID operation succeeded"),
            }
        }

        let sends = Arc::new(AtomicUsize::new(0));
        let transport = CountingTransport {
            sends: Arc::clone(&sends),
            allocations: Arc::new(AtomicUsize::new(0)),
        };
        let client = Client::new(
            transport.clone(),
            ClientConfig {
                auth: crate::Auth::v2c("public"),
                retry: crate::client::retry::Retry::none(),
                ..Default::default()
            },
        )
        .expect("valid client config");
        let invalid = Oid::empty();
        let valid = Oid::from_slice(&[1, 3, 6, 1]);

        assert_invalid(client.get(&invalid).await);
        assert_invalid(client.get_next(&invalid).await);
        assert_invalid(client.get_bulk(std::slice::from_ref(&invalid), 0, 10).await);
        assert_invalid(client.set(&invalid, Value::Integer(1)).await);
        assert_invalid(
            client
                .set(&valid, Value::ObjectIdentifier(invalid.clone()))
                .await,
        );
        assert_invalid(client.send_trap(&invalid, 1, vec![]).await);
        assert_invalid(
            client
                .send_trap(&valid, 1, vec![VarBind::null(invalid.clone())])
                .await,
        );
        assert_invalid(client.send_inform(&invalid, 1, vec![]).await);

        let v1_client = Client::new(
            transport.clone(),
            ClientConfig {
                auth: crate::Auth::v1("public"),
                retry: crate::client::retry::Retry::none(),
                ..Default::default()
            },
        )
        .expect("valid client config");
        let trap = TrapV1Pdu::new(
            invalid.clone(),
            [127, 0, 0, 1],
            crate::pdu::GenericTrap::EnterpriseSpecific,
            1,
            1,
            vec![],
        );
        assert_invalid(v1_client.send_v1_trap(trap).await);

        // The uncached V3 client must reject malformed request PDUs before
        // engine discovery can write its own packet to the transport.
        let v3_client = Client::new(
            transport,
            ClientConfig {
                auth: crate::Auth::Usm(crate::v3::UsmConfig::new("user")),
                retry: crate::client::retry::Retry::none(),
                ..Default::default()
            },
        )
        .expect("valid client config");
        assert_invalid(v3_client.get(&invalid).await);
        assert_invalid(v3_client.get_next(&invalid).await);
        assert_invalid(
            v3_client
                .get_bulk(std::slice::from_ref(&invalid), 0, 10)
                .await,
        );
        assert_invalid(v3_client.set(&invalid, Value::Integer(1)).await);
        assert_invalid(
            v3_client
                .set(&valid, Value::ObjectIdentifier(invalid.clone()))
                .await,
        );
        assert_invalid(v3_client.send_inform(&invalid, 1, vec![]).await);

        assert_eq!(sends.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn client_config_validation() {
        fn assert_config_error<T: Transport>(result: Result<Client<T>>) {
            match result {
                Err(error) => assert!(matches!(*error, Error::Config(_))),
                Ok(_) => panic!("invalid client configuration was accepted"),
            }
        }

        let sends = Arc::new(AtomicUsize::new(0));
        let transport = CountingTransport {
            sends: Arc::clone(&sends),
            allocations: Arc::new(AtomicUsize::new(0)),
        };

        assert_config_error(Client::new(
            transport.clone(),
            ClientConfig {
                request_timeout: Duration::MAX,
                ..ClientConfig::default()
            },
        ));
        assert_config_error(Client::new(
            transport.clone(),
            ClientConfig {
                send_timeout: Duration::MAX,
                ..ClientConfig::default()
            },
        ));
        assert_config_error(Client::new(
            transport.clone(),
            ClientConfig {
                max_oids_per_request: 0,
                ..ClientConfig::default()
            },
        ));
        assert_config_error(Client::new(
            transport.clone(),
            ClientConfig {
                max_repetitions: crate::pdu::MAX_GET_BULK_VALUE + 1,
                ..ClientConfig::default()
            },
        ));
        assert_config_error(Client::new(
            transport.clone(),
            ClientConfig {
                auth: Auth::v1("public"),
                walk_mode: WalkMode::GetBulk,
                ..ClientConfig::default()
            },
        ));
        assert_config_error(Client::new(
            transport.clone(),
            ClientConfig {
                oid_ordering: OidOrdering::AllowNonIncreasing,
                max_walk_results: None,
                ..ClientConfig::default()
            },
        ));
        assert_config_error(Client::with_engine_cache(
            transport.clone(),
            ClientConfig {
                max_oids_per_request: 0,
                ..ClientConfig::default()
            },
            Arc::new(EngineCache::new()),
        ));

        Client::new(
            transport.clone(),
            ClientConfig {
                request_timeout: Duration::ZERO,
                ..ClientConfig::default()
            },
        )
        .expect("zero timeout remains an explicit immediate deadline");
        Client::new(
            transport.clone(),
            ClientConfig {
                send_timeout: Duration::ZERO,
                ..ClientConfig::default()
            },
        )
        .expect("zero send timeout remains an explicit immediate deadline");

        for auth in [
            Auth::v1("public"),
            Auth::v2c("public"),
            Auth::Usm(UsmConfig::new("user")),
        ] {
            Client::new(
                transport.clone(),
                ClientConfig {
                    auth,
                    ..ClientConfig::default()
                },
            )
            .expect("valid v1, v2c, and v3 configs must construct");
        }

        assert_eq!(sends.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn single_operations_preserve_empty_and_excess_responses() {
        let oid = Oid::from_slice(&[1, 3, 6, 1, 1]);

        for response_count in [0, 2] {
            let get = make_client(response_count).get(&oid).await.unwrap();
            let get_next = make_client(response_count).get_next(&oid).await.unwrap();
            let set = make_client(response_count)
                .set(&oid, Value::Integer(1))
                .await
                .unwrap();

            for response in [get, get_next, set] {
                assert_eq!(response.varbinds.len(), response_count);
                if response_count == 0 {
                    assert!(matches!(
                        response.anomalies[0],
                        ResponseShapeAnomaly::Truncated { .. }
                    ));
                } else {
                    assert!(matches!(
                        response.anomalies[0],
                        ResponseShapeAnomaly::Excess { .. }
                    ));
                }
            }
        }
    }

    #[tokio::test]
    async fn strict_policy_returns_observable_shape_error() {
        let oid = Oid::from_slice(&[1, 3, 6, 1, 1]);
        let error = make_client_with_policy(2, ResponseShapePolicy::Strict)
            .get(&oid)
            .await
            .unwrap_err();
        match *error {
            Error::ResponseShape { response, .. } => {
                assert_eq!(response.varbinds.len(), 2);
                assert!(matches!(
                    response.anomalies[0],
                    ResponseShapeAnomaly::Excess { .. }
                ));
            }
            other => panic!("expected ResponseShape, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inform_requires_exact_echoed_varbinds() {
        let trap_oid = Oid::from_slice(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 1]);
        let additional = VarBind::new(
            Oid::from_slice(&[1, 3, 6, 1, 4, 1, 9999, 1]),
            Value::Integer(7),
        );
        let expected = Pdu::inform_request(1, 123, &trap_oid, vec![additional.clone()]).varbinds;

        for policy in [ResponseShapePolicy::Compatible, ResponseShapePolicy::Strict] {
            scripted_client(vec![expected.clone()], policy)
                .send_inform(&trap_oid, 123, vec![additional.clone()])
                .await
                .expect("an exact Inform echo must be accepted");

            let mut renamed = expected.clone();
            renamed[0].oid = Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 4, 0]);
            let mut reordered = expected.clone();
            reordered.swap(0, 1);
            let mut changed = expected.clone();
            changed[2].value = Value::Integer(8);

            for response in [Vec::new(), renamed, reordered, changed] {
                let error = scripted_client(vec![response], policy)
                    .send_inform(&trap_oid, 123, vec![additional.clone()])
                    .await
                    .expect_err("a malformed Inform acknowledgement must be rejected");
                assert!(matches!(*error, Error::MalformedResponse { .. }));
            }
        }
    }

    #[tokio::test]
    async fn compatible_policy_preserves_scripted_semantics_across_all_fixed_operations() {
        let a = Oid::from_slice(&[1, 3, 6, 1, 1]);
        let b = Oid::from_slice(&[1, 3, 6, 1, 2]);
        let c = Oid::from_slice(&[1, 3, 6, 1, 3]);
        let responses = vec![
            vec![VarBind::new(c.clone(), Value::Integer(10))],
            vec![
                VarBind::new(b.clone(), Value::Integer(20)),
                VarBind::new(a.clone(), Value::Integer(10)),
            ],
            vec![VarBind::new(a.clone(), Value::Integer(10))],
            vec![
                VarBind::new(b.clone(), Value::Integer(20)),
                VarBind::new(b.clone(), Value::EndOfMibView),
            ],
            vec![VarBind::new(a.clone(), Value::Integer(2))],
            vec![
                VarBind::new(a.clone(), Value::Integer(1)),
                VarBind::new(b.clone(), Value::Integer(3)),
            ],
        ];
        let client = scripted_client(responses.clone(), ResponseShapePolicy::Compatible);

        let get = client.get(&a).await.unwrap();
        assert_eq!(get.varbinds, responses[0]);
        assert!(matches!(
            get.anomalies.as_slice(),
            [ResponseShapeAnomaly::OidMismatch { .. }]
        ));

        let get_many = client.get_many(&[a.clone(), b.clone()]).await.unwrap();
        assert_eq!(get_many.varbinds, responses[1]);
        assert!(matches!(
            get_many.anomalies.as_slice(),
            [ResponseShapeAnomaly::Reordered { .. }]
        ));

        let get_next = client.get_next(&a).await.unwrap();
        assert_eq!(get_next.varbinds, responses[2]);
        assert!(matches!(
            get_next.anomalies.as_slice(),
            [ResponseShapeAnomaly::GetNextNotSuccessor { .. }]
        ));

        let get_next_many = client.get_next_many(&[a.clone(), b.clone()]).await.unwrap();
        assert_eq!(get_next_many.varbinds, responses[3]);
        assert!(get_next_many.anomalies.is_empty());

        let set = client.set(&a, Value::Integer(1)).await.unwrap();
        assert_eq!(set.varbinds, responses[4]);
        assert!(matches!(
            set.anomalies.as_slice(),
            [ResponseShapeAnomaly::SetValueMismatch { .. }]
        ));

        let set_many = client
            .set_many(&[
                (a.clone(), Value::Integer(1)),
                (b.clone(), Value::Integer(2)),
            ])
            .await
            .unwrap();
        assert_eq!(set_many.varbinds, responses[5]);
        assert!(matches!(
            set_many.anomalies.as_slice(),
            [ResponseShapeAnomaly::SetValueMismatch { .. }]
        ));
    }

    #[tokio::test]
    async fn strict_policy_retains_scripted_evidence_across_all_fixed_operations() {
        let a = Oid::from_slice(&[1, 3, 6, 1, 1]);
        let b = Oid::from_slice(&[1, 3, 6, 1, 2]);
        let c = Oid::from_slice(&[1, 3, 6, 1, 3]);
        let responses = vec![
            vec![VarBind::new(c.clone(), Value::Integer(10))],
            vec![
                VarBind::new(b.clone(), Value::Integer(20)),
                VarBind::new(a.clone(), Value::Integer(10)),
            ],
            vec![VarBind::new(a.clone(), Value::Integer(10))],
            vec![
                VarBind::new(b.clone(), Value::Integer(20)),
                VarBind::new(c.clone(), Value::EndOfMibView),
            ],
            vec![VarBind::new(a.clone(), Value::Integer(2))],
            vec![
                VarBind::new(a.clone(), Value::Integer(1)),
                VarBind::new(b.clone(), Value::Integer(3)),
            ],
        ];
        let client = scripted_client(responses.clone(), ResponseShapePolicy::Strict);

        let errors = [
            response_shape_error(client.get(&a).await),
            response_shape_error(client.get_many(&[a.clone(), b.clone()]).await),
            response_shape_error(client.get_next(&a).await),
            response_shape_error(client.get_next_many(&[a.clone(), b.clone()]).await),
            response_shape_error(client.set(&a, Value::Integer(1)).await),
            response_shape_error(
                client
                    .set_many(&[
                        (a.clone(), Value::Integer(1)),
                        (b.clone(), Value::Integer(2)),
                    ])
                    .await,
            ),
        ];

        for (response, expected) in errors.iter().zip(responses) {
            assert_eq!(response.varbinds, expected);
            assert!(!response.anomalies.is_empty());
        }
        assert!(matches!(
            errors[3].anomalies.as_slice(),
            [ResponseShapeAnomaly::GetNextEndOfMibNameMismatch { .. }]
        ));
    }

    #[tokio::test]
    async fn walk_does_not_consume_an_anomalous_single_response() {
        let oid = Oid::from_slice(&[1, 3, 6, 1, 1]);
        let mut walk = make_client(2).walk_getnext(oid);
        let error = walk.next().await.unwrap().unwrap_err();
        assert!(matches!(*error, Error::ResponseShape { .. }));
        assert!(walk.next().await.is_none());
    }

    #[tokio::test]
    async fn get_many_preserves_truncated_response() {
        let client = make_client(1);
        let oids = [
            Oid::from_slice(&[1, 3, 6, 1, 1]),
            Oid::from_slice(&[1, 3, 6, 1, 2]),
            Oid::from_slice(&[1, 3, 6, 1, 3]),
        ];

        let response = client.get_many(&oids).await.unwrap();
        assert_eq!(response.varbinds.len(), 1);
        assert!(matches!(
            response.anomalies.as_slice(),
            [ResponseShapeAnomaly::Truncated { .. }]
        ));
    }

    #[tokio::test]
    async fn get_many_preserves_inflated_response() {
        let client = make_client(5);
        let oids = [
            Oid::from_slice(&[1, 3, 6, 1, 1]),
            Oid::from_slice(&[1, 3, 6, 1, 2]),
            Oid::from_slice(&[1, 3, 6, 1, 3]),
        ];

        let response = client.get_many(&oids).await.unwrap();
        assert_eq!(response.varbinds.len(), 5);
        assert!(matches!(
            response.anomalies.as_slice(),
            [ResponseShapeAnomaly::Excess { .. }]
        ));
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
        assert_eq!(result.unwrap().varbinds.len(), 3);
    }

    #[tokio::test]
    async fn get_next_many_preserves_truncated_response() {
        let client = make_client(1);
        let oids = [
            Oid::from_slice(&[1, 3, 6, 1, 1]),
            Oid::from_slice(&[1, 3, 6, 1, 2]),
            Oid::from_slice(&[1, 3, 6, 1, 3]),
        ];

        let response = client.get_next_many(&oids).await.unwrap();
        assert_eq!(response.varbinds.len(), 1);
        assert!(matches!(
            response.anomalies.as_slice(),
            [ResponseShapeAnomaly::Truncated { .. }]
        ));
    }

    #[tokio::test]
    async fn get_next_many_preserves_inflated_response() {
        let client = make_client(5);
        let oids = [
            Oid::from_slice(&[1, 3, 6, 1, 1]),
            Oid::from_slice(&[1, 3, 6, 1, 2]),
            Oid::from_slice(&[1, 3, 6, 1, 3]),
        ];

        let response = client.get_next_many(&oids).await.unwrap();
        assert_eq!(response.varbinds.len(), 5);
        assert!(matches!(
            response.anomalies.as_slice(),
            [ResponseShapeAnomaly::Excess { .. }]
        ));
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
        assert_eq!(result.unwrap().varbinds.len(), 3);
    }

    #[tokio::test]
    async fn set_many_preserves_truncated_response() {
        // Request 3 varbinds but the mock returns only 1.
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
        assert_eq!(result.unwrap().varbinds.len(), 1);
    }

    #[tokio::test]
    async fn set_many_preserves_inflated_response() {
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

        let response = client.set_many(&varbinds).await.unwrap();
        assert_eq!(response.varbinds.len(), 5);
        assert!(matches!(
            response.anomalies.as_slice(),
            [ResponseShapeAnomaly::Excess { .. }]
        ));
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
        assert_eq!(result.unwrap().varbinds.len(), 3);
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
            let varbind_count = msg.pdu().standard().unwrap().varbinds.len();
            {
                let mut q = self.pending.lock().unwrap();
                q.push_back((request_id, varbind_count));
            }
            async { Ok(()) }
        }

        fn recv(
            &self,
            _registration: crate::transport::RequestRegistration,
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
                    Pdu::response(request_id, ErrorStatus::TooBig.as_i32(), 0, vec![])
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
                    Pdu::response(request_id, 0, 0, varbinds)
                };

                let msg = CommunityMessage::v2c(Bytes::from_static(b"public"), pdu).unwrap();
                Ok((msg.encode().unwrap(), peer))
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
    async fn inform_preserves_empty_varbind_too_big_response() {
        let client = Client::new(
            TooBigTransport::new(0),
            ClientConfig {
                auth: crate::Auth::v2c("public"),
                retry: Retry::none(),
                ..Default::default()
            },
        )
        .expect("valid client config");
        let trap_oid = Oid::from_slice(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 1]);

        let error = client
            .send_inform(&trap_oid, 123, Vec::new())
            .await
            .expect_err("tooBig must remain an SNMP protocol error");
        assert!(matches!(
            *error,
            Error::Snmp {
                status: ErrorStatus::TooBig,
                ..
            }
        ));
    }

    #[derive(Clone)]
    struct InformMetadataTransport {
        pending: Arc<Mutex<VecDeque<Pdu>>>,
        malformed_echo: bool,
    }

    impl Transport for InformMetadataTransport {
        fn send(&self, data: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send {
            let message = CommunityMessage::decode(Bytes::copy_from_slice(data)).unwrap();
            self.pending
                .lock()
                .unwrap()
                .push_back(message.pdu().standard().unwrap().clone());
            async { Ok(()) }
        }

        fn recv(
            &self,
            _registration: crate::transport::RequestRegistration,
        ) -> impl std::future::Future<Output = Result<(Bytes, SocketAddr)>> + Send {
            let request = self.pending.lock().unwrap().pop_front().unwrap();
            let malformed_echo = self.malformed_echo;
            async move {
                let mut varbinds = request.varbinds;
                if malformed_echo {
                    varbinds.pop();
                }
                let response = Pdu::response(request.request_id, 0, 0, varbinds);
                let message =
                    CommunityMessage::v2c(Bytes::from_static(b"public"), response).unwrap();
                let mut encoded = message.encode().unwrap().to_vec();
                encoded.extend_from_slice(&[0xaa, 0xbb]);
                Ok((Bytes::from(encoded), "127.0.0.1:161".parse().unwrap()))
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
    async fn inform_metadata_api_retains_acknowledgement_anomalies() {
        let client = Client::new(
            InformMetadataTransport {
                pending: Arc::new(Mutex::new(VecDeque::new())),
                malformed_echo: false,
            },
            ClientConfig {
                auth: crate::Auth::v2c("public"),
                retry: Retry::none(),
                ..Default::default()
            },
        )
        .unwrap();
        let metadata = client
            .send_inform_with_metadata(
                &Oid::from_slice(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 1]),
                123,
                vec![],
            )
            .await
            .unwrap();
        assert_eq!(
            metadata.decode_anomalies,
            vec![crate::DecodeAnomaly::TrailingBytes {
                original_length: 2,
                canonical_length: 0,
            }]
        );
    }

    #[tokio::test]
    async fn malformed_inform_acknowledgement_retains_decode_anomalies() {
        let client = Client::new(
            InformMetadataTransport {
                pending: Arc::new(Mutex::new(VecDeque::new())),
                malformed_echo: true,
            },
            ClientConfig {
                auth: crate::Auth::v2c("public"),
                retry: Retry::none(),
                ..Default::default()
            },
        )
        .unwrap();
        let error = client
            .send_inform_with_metadata(
                &Oid::from_slice(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 1]),
                123,
                vec![],
            )
            .await
            .expect_err("a malformed acknowledgement must be rejected");

        assert_eq!(error.kind(), crate::ErrorKind::MalformedResponse);
        assert_eq!(
            error.response_metadata().unwrap().decode_anomalies,
            vec![crate::DecodeAnomaly::TrailingBytes {
                original_length: 2,
                canonical_length: 0,
            }]
        );
    }

    #[tokio::test]
    async fn get_many_bisects_on_too_big() {
        // Agent can handle at most 3 varbinds per request. We ask for 8.
        // With max_oids_per_request=10, the initial batch is all 8 OIDs.
        // That triggers tooBig, so it bisects to 4+4, each of which still
        // triggers tooBig, then bisects to 2+2+2+2 which all succeed.
        let transport = TooBigTransport::new(3);
        let config = ClientConfig {
            auth: crate::Auth::v2c("public"),
            max_oids_per_request: 10,
            retry: crate::client::retry::Retry::none(),
            ..Default::default()
        };
        let client = Client::new(transport, config).expect("valid client config");

        let oids: Vec<Oid> = (0..8u32)
            .map(|i| Oid::from_slice(&[1, 3, 6, 1, i]))
            .collect();

        let result = client.get_many(&oids).await.unwrap();
        assert_eq!(result.varbinds.len(), 8);
    }

    #[tokio::test]
    async fn get_many_single_oid_too_big_is_unrecoverable() {
        // Agent returns tooBig even for a single OID - can't bisect further.
        let transport = TooBigTransport::new(0);
        let config = ClientConfig {
            auth: crate::Auth::v2c("public"),
            max_oids_per_request: 10,
            retry: crate::client::retry::Retry::none(),
            ..Default::default()
        };
        let client = Client::new(transport, config).expect("valid client config");

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
            auth: crate::Auth::v2c("public"),
            max_oids_per_request: 10,
            retry: crate::client::retry::Retry::none(),
            ..Default::default()
        };
        let client = Client::new(transport, config).expect("valid client config");

        let oids: Vec<Oid> = (0..8u32)
            .map(|i| Oid::from_slice(&[1, 3, 6, 1, i]))
            .collect();

        let result = client.get_next_many(&oids).await.unwrap();
        assert_eq!(result.varbinds.len(), 8);
    }

    // Batched path: get_many with more OIDs than max_per_request.
    #[tokio::test]
    async fn get_many_batched_preserves_truncated_response_offsets() {
        // max_oids_per_request = 10, request 12 OIDs, mock returns 1 per batch.
        // Request and response ranges remain globally meaningful after each under-count.
        let transport = TruncatingTransport::new(1);
        let config = ClientConfig {
            auth: crate::Auth::v2c("public"),
            max_oids_per_request: 10,
            retry: crate::client::retry::Retry::none(),
            ..Default::default()
        };
        let client = Client::new(transport, config).expect("valid client config");

        let oids: Vec<Oid> = (0..12u32)
            .map(|i| Oid::from_slice(&[1, 3, 6, 1, i]))
            .collect();

        let response = client.get_many(&oids).await.unwrap();
        assert_eq!(response.varbinds.len(), 2);
        assert!(matches!(
            response.anomalies.as_slice(),
            [
                ResponseShapeAnomaly::Truncated { request_range, response_range, .. },
                ResponseShapeAnomaly::Truncated { request_range: second_request, response_range: second_response, .. }
            ] if request_range == &(0..10)
                && response_range == &(0..1)
                && second_request == &(10..12)
                && second_response == &(1..2)
        ));
    }

    #[tokio::test]
    async fn get_many_batched_preserves_inflated_response_offsets() {
        // max_oids_per_request = 10, request 12 OIDs, mock returns 12 per batch.
        let transport = TruncatingTransport::new(12);
        let config = ClientConfig {
            auth: crate::Auth::v2c("public"),
            max_oids_per_request: 10,
            retry: crate::client::retry::Retry::none(),
            ..Default::default()
        };
        let client = Client::new(transport, config).expect("valid client config");

        let oids: Vec<Oid> = (0..12u32)
            .map(|i| Oid::from_slice(&[1, 3, 6, 1, i]))
            .collect();

        let response = client.get_many(&oids).await.unwrap();
        assert_eq!(response.varbinds.len(), 24);
        assert!(matches!(
            response.anomalies.as_slice(),
            [
                ResponseShapeAnomaly::Excess { request_range, response_range, .. },
                ResponseShapeAnomaly::Excess { request_range: second_request, response_range: second_response, .. }
            ] if request_range == &(0..10)
                && response_range == &(0..12)
                && second_request == &(10..12)
                && second_response == &(12..24)
        ));
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
            _registration: crate::transport::RequestRegistration,
        ) -> impl std::future::Future<Output = Result<(Bytes, SocketAddr)>> + Send {
            let request_id = self.pending.lock().unwrap().pop_front().unwrap_or(1);
            let peer: SocketAddr = "127.0.0.1:161".parse().unwrap();
            let pdu = Pdu::standard(
                crate::pdu::StandardPduType::try_from(self.pdu_type).unwrap(),
                request_id,
                0,
                0,
                vec![VarBind::new(
                    Oid::from_slice(&[1, 3, 6, 1, 1]),
                    crate::value::Value::Null,
                )],
            );
            let community = Bytes::from_static(self.community);
            let msg = if self.respond_as_v1 {
                CommunityMessage::v1(community, pdu)
            } else {
                CommunityMessage::v2c(community, pdu)
            }
            .unwrap();
            let encoded = msg.encode().unwrap();
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
            auth: crate::Auth::v2c("public"),
            retry: crate::client::retry::Retry::none(),
            ..Default::default()
        };
        Client::new(transport, config).expect("valid client config")
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

    /// A custom transport cannot bypass the exact-match default.
    #[tokio::test]
    async fn response_validation_rejects_community_mismatch() {
        let client = adversarial_client(PduType::Response, b"other", false);
        let err = client
            .get(&Oid::from_slice(&[1, 3, 6, 1, 1]))
            .await
            .unwrap_err();
        assert!(matches!(*err, Error::MalformedResponse { .. }));
    }

    #[tokio::test]
    async fn response_validation_accepts_explicit_any_source_rewrite() {
        let transport = AdversarialTransport::new(PduType::Response, b"other", false);
        let config = ClientConfig {
            community_response_policy:
                crate::transport::CommunityResponsePolicy::AllowMismatchFromAnySource,
            retry: crate::client::retry::Retry::none(),
            ..Default::default()
        };
        let client = Client::new(transport, config).expect("valid client config");
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
