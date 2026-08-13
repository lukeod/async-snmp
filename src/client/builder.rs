//! New unified client builder.
//!
//! [`ClientBuilder`] configures authentication and client policy independently
//! of transport construction. [`TargetClientBuilder`] adds the target-only
//! policy used to construct built-in UDP and TCP transports.

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use super::Client;
use crate::client::retry::Retry;
use crate::client::walk::{OidOrdering, WalkMode};
use crate::client::{
    Auth, ClientConfig, DEFAULT_MAX_OIDS_PER_REQUEST, DEFAULT_MAX_REPETITIONS,
    DEFAULT_REQUEST_TIMEOUT, DEFAULT_SEND_TIMEOUT,
};
use crate::error::{ConstructionStage, Error, Result};
use crate::transport::{
    CommunityResponsePolicy, TcpTransport, Transport, UdpControl, UdpHandle, UdpTransport,
};
use crate::v3::{AuthoritativeEngine, EngineCache};

/// Target address for an SNMP client.
///
/// Specifies where to connect. Accepts either a combined address string
/// or a separate host and port, which is useful when host and port are
/// stored independently (avoids needing to format IPv6 bracket syntax).
///
/// # Examples
///
/// ```rust
/// use async_snmp::Target;
///
/// // From a string (port defaults to 161 if omitted)
/// let t: Target = "192.168.1.1:161".into();
/// let t: Target = "switch.local".into();
///
/// // From a (host, port) tuple - no bracket formatting needed for IPv6
/// let t: Target = ("fe80::1", 161).into();
/// let t: Target = ("switch.local".to_string(), 162).into();
///
/// // From a SocketAddr
/// let t: Target = "192.168.1.1:161".parse::<std::net::SocketAddr>().unwrap().into();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A combined address string, e.g. `"192.168.1.1:161"` or `"[::1]:162"`.
    /// Port defaults to 161 if not specified.
    Address(String),
    /// A separate host and port, e.g. `("fe80::1", 161)`.
    HostPort(String, u16),
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Address(addr) => f.write_str(addr),
            Target::HostPort(host, port) => {
                if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
                    write!(f, "[{host}]:{port}")
                } else {
                    write!(f, "{host}:{port}")
                }
            }
        }
    }
}

impl From<&str> for Target {
    fn from(s: &str) -> Self {
        Target::Address(s.to_string())
    }
}

impl From<String> for Target {
    fn from(s: String) -> Self {
        Target::Address(s)
    }
}

impl From<&String> for Target {
    fn from(s: &String) -> Self {
        Target::Address(s.clone())
    }
}

impl From<(&str, u16)> for Target {
    fn from((host, port): (&str, u16)) -> Self {
        Target::HostPort(host.to_string(), port)
    }
}

impl From<(String, u16)> for Target {
    fn from((host, port): (String, u16)) -> Self {
        Target::HostPort(host, port)
    }
}

impl From<SocketAddr> for Target {
    fn from(addr: SocketAddr) -> Self {
        Target::HostPort(addr.ip().to_string(), addr.port())
    }
}

/// Builder for SNMP protocol and client configuration.
///
/// This builder deliberately has no target or built-in transport settings.
/// Call [`target`](Self::target) to configure library-created UDP or TCP
/// transport, or [`build_with_transport`](Self::build_with_transport) when the
/// caller already owns any type that implements [`Transport`]. Shared
/// [`UdpTransport`] socket owners are the exception: call
/// [`TargetClientBuilder::build_with`] to resolve a target and derive a
/// per-target [`UdpHandle`].
///
/// # Example
///
/// ```rust,no_run
/// use async_snmp::{Auth, ClientBuilder, Retry};
/// use std::time::Duration;
///
/// # async fn example() -> async_snmp::Result<()> {
/// // Simple v2c client
/// let client = ClientBuilder::new(Auth::v2c("public"))
///     .target("192.168.1.1:161")
///     .connect().await?;
///
/// // Using separate host and port (convenient for IPv6)
/// let client = ClientBuilder::new(Auth::v2c("public"))
///     .target(("fe80::1", 161))
///     .connect().await?;
///
/// // v3 client with authentication
/// let client = ClientBuilder::new(Auth::usm_builder("admin")
///     .auth(async_snmp::AuthProtocol::Sha256, "password")
///     .build())
///     .request_timeout(Duration::from_secs(10))
///     .retry(Retry::fixed(5, Duration::ZERO))
///     .target("192.168.1.1:161")
///     .connect().await?;
/// # Ok(())
/// # }
/// ```
///
/// Target-only policy cannot be attached to a preconfigured transport:
///
/// ```compile_fail
/// use async_snmp::{Auth, ClientBuilder};
/// use std::time::Duration;
///
/// let builder = ClientBuilder::new(Auth::v2c("public"))
///     .construction_timeout(Duration::from_secs(2));
/// ```
#[derive(Debug, Clone)]
pub struct ClientBuilder {
    auth: Auth,
    request_timeout: Duration,
    send_timeout: Duration,
    retry: Retry,
    max_oids_per_request: usize,
    decode_policy: crate::message::DecodePolicy,
    compatibility_policy: crate::CompatibilityPolicy,
    response_shape_policy: crate::client::ResponseShapePolicy,
    max_repetitions: u32,
    walk_mode: WalkMode,
    oid_ordering: OidOrdering,
    max_walk_results: Option<usize>,
    engine_cache: Option<Arc<EngineCache>>,
    community_response_policy: CommunityResponsePolicy,
    allow_unauthenticated_v3_time_correction: bool,
    local_authoritative_engine: Option<AuthoritativeEngine>,
}

/// Builder for constructing a client using a library-maintained target
/// transport.
///
/// This state is entered with [`ClientBuilder::target`]. Target resolution,
/// UDP source validation, and construction deadlines apply only here and
/// cannot be configured on a preconstructed transport.
///
/// A target builder cannot silently discard its transport settings by
/// switching to a preconfigured transport:
///
/// ```compile_fail
/// use async_snmp::{TargetClientBuilder, TcpTransport};
///
/// fn invalid(builder: TargetClientBuilder, transport: TcpTransport) {
///     let _ = builder.build_with_transport(transport);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct TargetClientBuilder {
    client: ClientBuilder,
    target: Target,
    construction_timeout: Duration,
    strict_source: bool,
}

impl ClientBuilder {
    /// Create a new client builder.
    ///
    /// # Arguments
    ///
    /// * `auth` - Authentication configuration (community or USM)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::{Auth, ClientBuilder};
    ///
    /// // Using Auth::default() for v2c with "public" community
    /// let builder = ClientBuilder::new(Auth::default());
    ///
    /// // Using separate host and port
    /// let builder = ClientBuilder::new(Auth::default()).target(("192.168.1.1", 161));
    ///
    /// // Using Auth::v1() for SNMPv1
    /// let builder = ClientBuilder::new(Auth::v1("private"));
    ///
    /// // Using Auth::usm_builder() for authenticated SNMPv3
    /// let builder = ClientBuilder::new(Auth::usm_builder("admin")
    ///     .auth(async_snmp::AuthProtocol::Sha256, "password")
    ///     .build());
    /// ```
    pub fn new(auth: impl Into<Auth>) -> Self {
        Self {
            auth: auth.into(),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            send_timeout: DEFAULT_SEND_TIMEOUT,
            retry: Retry::default(),
            max_oids_per_request: DEFAULT_MAX_OIDS_PER_REQUEST,
            decode_policy: crate::message::DecodePolicy::Compatible,
            compatibility_policy: crate::CompatibilityPolicy::default(),
            response_shape_policy: crate::client::ResponseShapePolicy::Compatible,
            max_repetitions: DEFAULT_MAX_REPETITIONS,
            walk_mode: WalkMode::Auto,
            oid_ordering: OidOrdering::Strict,
            max_walk_results: None,
            engine_cache: None,
            community_response_policy: CommunityResponsePolicy::Exact,
            allow_unauthenticated_v3_time_correction: false,
            local_authoritative_engine: None,
        }
    }

    /// Configure a target for a library-created UDP or TCP transport.
    ///
    /// The target accepts address strings, `(host, port)` tuples, and
    /// [`SocketAddr`]. Strings without an explicit port default to 161.
    #[must_use]
    pub fn target(self, target: impl Into<Target>) -> TargetClientBuilder {
        TargetClientBuilder {
            client: self,
            target: target.into(),
            construction_timeout: DEFAULT_CONSTRUCTION_TIMEOUT,
            strict_source: false,
        }
    }

    /// Set the request timeout (default: 5 seconds).
    ///
    /// This is the time to wait for a response before retrying or failing.
    /// The total time for a request may be `timeout * (retries + 1)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, ClientBuilder};
    /// use std::time::Duration;
    ///
    /// let builder = ClientBuilder::new(Auth::v2c("public"))
    ///     .request_timeout(Duration::from_secs(10));
    /// ```
    #[must_use]
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Set the timeout for standalone sends (default: 5 seconds).
    ///
    /// This bounds transport queueing and write I/O for unconfirmed traps.
    /// Inform requests and other confirmed operations use
    /// [`request_timeout`](Self::request_timeout) instead.
    #[must_use]
    pub fn send_timeout(mut self, timeout: Duration) -> Self {
        self.send_timeout = timeout;
        self
    }

    /// Set the retry configuration (default: 3 retries, 1-second delay).
    ///
    /// On timeout, the client resends the request up to this many times before
    /// returning an error. Timeout retransmissions are disabled for TCP (which
    /// handles reliability at the transport layer). SNMPv3 protocol correction
    /// is independent of this setting and remains available with
    /// [`Retry::none`] and on reliable transports.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, ClientBuilder, Retry};
    /// use std::time::Duration;
    ///
    /// // No retries
    /// let builder = async_snmp::Client::builder("192.168.1.1:161", Auth::v2c("public"))
    ///     .retry(Retry::none());
    ///
    /// // 5 retries with no delay (immediate retry on timeout)
    /// let builder = async_snmp::Client::builder("192.168.1.1:161", Auth::v2c("public"))
    ///     .retry(Retry::fixed(5, Duration::ZERO));
    ///
    /// // Fixed delay between retries
    /// let builder = async_snmp::Client::builder("192.168.1.1:161", Auth::v2c("public"))
    ///     .retry(Retry::fixed(3, Duration::from_millis(200)));
    ///
    /// // Exponential backoff with jitter
    /// let builder = async_snmp::Client::builder("192.168.1.1:161", Auth::v2c("public"))
    ///     .retry(Retry::exponential(5)
    ///         .max_delay(Duration::from_secs(5))
    ///         .jitter(0.25)
    ///         .build()
    ///         .expect("valid retry configuration"));
    /// ```
    #[must_use]
    pub fn retry(mut self, retry: impl Into<Retry>) -> Self {
        self.retry = retry.into();
        self
    }

    /// Set the maximum OIDs per request (default: 10).
    ///
    /// Requests with more OIDs than this limit are automatically split
    /// into multiple batches. Some devices have lower limits on the number
    /// of OIDs they can handle in a single request. Values must be greater
    /// than zero.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, ClientBuilder};
    ///
    /// // For devices with limited request handling capacity
    /// let builder = async_snmp::Client::builder("192.168.1.1:161", Auth::v2c("public"))
    ///     .max_oids_per_request(5);
    ///
    /// // For high-capacity devices, increase to reduce round-trips
    /// let builder = async_snmp::Client::builder("192.168.1.1:161", Auth::v2c("public"))
    ///     .max_oids_per_request(50);
    /// ```
    #[must_use]
    pub fn max_oids_per_request(mut self, max: usize) -> Self {
        self.max_oids_per_request = max;
        self
    }

    /// Set top-level response-envelope handling (default: compatible).
    ///
    /// Compatible mode accepts a bounded suffix following one complete
    /// declared SNMP message in a UDP datagram. Strict mode rejects the whole
    /// datagram. This is a device-compatibility allowance: RFC 3417 specifies
    /// one SNMP message per UDP datagram. Correlation and full response decoding
    /// use this same policy.
    #[must_use]
    pub fn decode_policy(mut self, policy: crate::message::DecodePolicy) -> Self {
        self.decode_policy = policy;
        self
    }

    /// Set BER/value interoperability handling (default: compatible).
    ///
    /// Each field of [`crate::CompatibilityPolicy`] controls one known
    /// malformed-input deviation. This policy is applied to v1/v2c responses
    /// and to every staged v3 decode, including discovery, Reports, security
    /// parameters, plaintext scoped PDUs, and decrypted scoped PDUs.
    #[must_use]
    pub fn compatibility_policy(mut self, policy: crate::CompatibilityPolicy) -> Self {
        self.compatibility_policy = policy;
        self
    }

    /// Require a canonical top-level envelope and canonical BER/value input.
    ///
    /// This is convenience for selecting [`crate::message::DecodePolicy::Strict`]
    /// and [`crate::CompatibilityPolicy::STRICT`] together. Either policy can
    /// subsequently be replaced independently for a targeted device quirk.
    #[must_use]
    pub fn strict_decoding(mut self) -> Self {
        self.decode_policy = crate::message::DecodePolicy::Strict;
        self.compatibility_policy = crate::CompatibilityPolicy::STRICT;
        self
    }

    /// Set fixed-cardinality response-shape handling (default: compatible).
    ///
    /// Compatible mode preserves every decoded binding and reports anomalies in
    /// the successful outcome. Strict mode returns [`Error::ResponseShape`]
    /// whenever the count, OID, GETNEXT successor, or SET echo shape is invalid.
    #[must_use]
    pub fn response_shape_policy(mut self, policy: crate::client::ResponseShapePolicy) -> Self {
        self.response_shape_policy = policy;
        self
    }

    /// Set max-repetitions for GETBULK operations (default: 25).
    ///
    /// Controls how many values are requested per GETBULK PDU during walks.
    /// This is a performance tuning parameter with trade-offs:
    ///
    /// - **Higher values**: Fewer network round-trips, faster walks on reliable
    ///   networks. But larger responses risk UDP fragmentation or may exceed
    ///   agent response buffer limits (causing truncation).
    /// - **Lower values**: More round-trips (higher latency), but smaller
    ///   responses that fit within MTU limits.
    ///
    /// The default of 25 is conservative. For local/reliable networks with
    /// capable agents, values of 50-100 can significantly speed up large walks.
    /// Values above `i32::MAX` are rejected when the client is built or connected.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, ClientBuilder};
    ///
    /// // Lower value for agents with small response buffers or lossy networks
    /// let builder = async_snmp::Client::builder("192.168.1.1:161", Auth::v2c("public"))
    ///     .max_repetitions(10);
    ///
    /// // Higher value for fast local network walks
    /// let builder = async_snmp::Client::builder("192.168.1.1:161", Auth::v2c("public"))
    ///     .max_repetitions(50);
    /// ```
    #[must_use]
    pub fn max_repetitions(mut self, max: u32) -> Self {
        self.max_repetitions = max;
        self
    }

    /// Override walk behavior for devices with buggy GETBULK (default: Auto).
    ///
    /// - `WalkMode::Auto`: Use GETNEXT for v1, GETBULK for v2c/v3
    /// - `WalkMode::GetNext`: Always use GETNEXT (slower but more compatible)
    /// - `WalkMode::GetBulk`: Always use GETBULK (faster, errors on v1)
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, ClientBuilder, WalkMode};
    ///
    /// // Force GETNEXT for devices with broken GETBULK implementation
    /// let builder = async_snmp::Client::builder("192.168.1.1:161", Auth::v2c("public"))
    ///     .walk_mode(WalkMode::GetNext);
    ///
    /// // Force GETBULK for faster walks (only v2c/v3)
    /// let builder = async_snmp::Client::builder("192.168.1.1:161", Auth::v2c("public"))
    ///     .walk_mode(WalkMode::GetBulk);
    /// ```
    #[must_use]
    pub fn walk_mode(mut self, mode: WalkMode) -> Self {
        self.walk_mode = mode;
        self
    }

    /// Set OID ordering behavior for walk operations (default: Strict).
    ///
    /// - `OidOrdering::Strict`: Require strictly increasing OIDs. Most efficient.
    /// - `OidOrdering::AllowNonIncreasing`: Allow non-increasing OIDs with cycle
    ///   detection. Uses O(n) memory to track seen OIDs.
    ///
    /// Use `AllowNonIncreasing` for buggy agents that return OIDs out of order.
    ///
    /// **Warning**: `AllowNonIncreasing` uses O(n) memory. Always pair with
    /// [`max_walk_results`](Self::max_walk_results) to bound memory usage.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, ClientBuilder, OidOrdering};
    ///
    /// // Use relaxed ordering with a safety limit
    /// let builder = async_snmp::Client::builder("192.168.1.1:161", Auth::v2c("public"))
    ///     .oid_ordering(OidOrdering::AllowNonIncreasing)
    ///     .max_walk_results(10_000);
    /// ```
    #[must_use]
    pub fn oid_ordering(mut self, ordering: OidOrdering) -> Self {
        self.oid_ordering = ordering;
        self
    }

    /// Set maximum results from a single walk operation (default: unlimited).
    ///
    /// Safety limit to prevent runaway walks. After yielding this many results,
    /// the walk inspects exactly one additional candidate. Definite truncation
    /// ends with [`WalkAbortReason::ResultLimitExceeded`](crate::WalkAbortReason::ResultLimitExceeded);
    /// observed natural completion ends normally. The look-ahead can require one
    /// extra request.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, ClientBuilder};
    ///
    /// // Limit walks to at most 10,000 results
    /// let builder = async_snmp::Client::builder("192.168.1.1:161", Auth::v2c("public"))
    ///     .max_walk_results(10_000);
    /// ```
    #[must_use]
    pub fn max_walk_results(mut self, limit: usize) -> Self {
        self.max_walk_results = Some(limit);
        self
    }

    /// Set the persisted local authoritative engine state for V3 trap sending.
    ///
    /// Per RFC 3412 Section 6.4, the sender is the authoritative engine for
    /// trap PDUs. Required when sending V3 traps; not needed for V3 informs
    /// (which use engine discovery against the receiver). Construct the value
    /// with [`AuthoritativeEngine::install`] on first installation or
    /// [`AuthoritativeEngine::restart`] on subsequent process starts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, AuthProtocol, ClientBuilder};
    /// use async_snmp::v3::AuthoritativeEngine;
    /// use std::convert::Infallible;
    ///
    /// let engine = AuthoritativeEngine::install(b"my-engine-id".to_vec(), |_| {
    ///     Ok::<(), Infallible>(())
    /// }).unwrap();
    /// let builder = async_snmp::Client::builder(("192.168.1.1", 162),
    ///     Auth::usm_builder("trapuser").auth(AuthProtocol::Sha256, "password").build())
    ///     .local_authoritative_engine(engine);
    /// ```
    #[must_use]
    pub fn local_authoritative_engine(mut self, engine: AuthoritativeEngine) -> Self {
        self.local_authoritative_engine = Some(engine);
        self
    }

    /// Set shared engine cache (V3 only, for polling many targets).
    ///
    /// Allows multiple clients to share target-to-engine identity mappings and
    /// per-authoritative-engine trusted time, reducing discovery requests and
    /// keeping clients that reach the same engine coherent. Cache expiry affects
    /// lookup by newly constructed clients; it does not replace an identity
    /// already established by a live client. Use
    /// [`Client::rediscover_engine`](crate::Client::rediscover_engine) for an
    /// intentional identity replacement.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, AuthProtocol, ClientBuilder, EngineCache};
    /// use std::sync::Arc;
    ///
    /// // Create a shared engine cache
    /// let cache = Arc::new(EngineCache::new());
    ///
    /// // Multiple clients can share the same cache
    /// let builder1 = async_snmp::Client::builder("192.168.1.1:161",
    ///     Auth::usm_builder("admin").auth(AuthProtocol::Sha256, "password").build())
    ///     .engine_cache(cache.clone());
    ///
    /// let builder2 = async_snmp::Client::builder("192.168.1.2:161",
    ///     Auth::usm_builder("admin").auth(AuthProtocol::Sha256, "password").build())
    ///     .engine_cache(cache.clone());
    /// ```
    #[must_use]
    pub fn engine_cache(mut self, cache: Arc<EngineCache>) -> Self {
        self.engine_cache = Some(cache);
        self
    }

    /// Set the v1/v2c response-community correlation policy.
    ///
    /// Exact byte matching is the default while UDP source checking remains
    /// permissive. `AllowMismatchFromTarget` supports proxies that rewrite the
    /// community but requires rewritten responses to come from the configured
    /// target. `AllowMismatchFromAnySource` explicitly accepts both identity
    /// mismatches and weakens spoof resistance.
    /// [`TargetClientBuilder::strict_source`]
    /// remains independent and always rejects off-target UDP responses.
    #[must_use]
    pub fn community_response_policy(mut self, policy: CommunityResponsePolicy) -> Self {
        self.community_response_policy = policy;
        self
    }

    /// Allow one packet-local correction from an unauthenticated SNMPv3
    /// `usmStatsNotInTimeWindows` Report (default: false).
    ///
    /// Some devices reply to an authenticated request with a noAuthNoPriv
    /// time-window Report, contrary to RFC 3414. When enabled, a correlated
    /// Report with the established engine ID and exact status shape may supply
    /// the boots/time tuple for one authenticated corrected packet. The tuple
    /// is not written to live or shared trusted state. Only a subsequent
    /// authenticated, correlated, fully matched Response can advance trusted
    /// time normally.
    ///
    /// Enabling this weakens spoof resistance: an attacker able to inject a
    /// matching Report can choose the time fields on one outbound authenticated
    /// packet. Use [`TargetClientBuilder::strict_source`] for UDP when the
    /// device does not legitimately reply from another address.
    #[must_use]
    pub fn allow_unauthenticated_v3_time_correction(mut self, allow: bool) -> Self {
        self.allow_unauthenticated_v3_time_correction = allow;
        self
    }

    /// Validate non-credential configuration without preparing credentials.
    #[cfg(test)]
    fn validate(&self) -> Result<()> {
        self.build_config().validate()
    }

    fn validate_and_precompute(&mut self) -> Result<()> {
        let mut config = self.build_config();
        config.validate_and_precompute()?;
        self.auth = config.auth;
        Ok(())
    }

    /// Build a client around an already-created transport implementation.
    ///
    /// This accepts any [`Transport`], including a [`TcpTransport`], a
    /// per-target [`UdpHandle`], a [`BuiltinTransport`](crate::BuiltinTransport),
    /// or a custom transport.
    /// The supplied transport owns its peer address, source-validation policy,
    /// construction, and any construction deadline. This path performs no
    /// target resolution or socket creation.
    ///
    /// A shared [`UdpTransport`] is a socket owner rather than a per-target
    /// [`Transport`]. Use [`TargetClientBuilder::build_with`] to resolve the
    /// target and create its [`UdpHandle`] on that shared socket.
    ///
    /// # Errors
    ///
    /// Returns an error when the client configuration is invalid.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::{Auth, ClientBuilder, TcpTransport};
    ///
    /// # async fn example() -> async_snmp::Result<()> {
    /// let target = "192.0.2.1:161".parse().unwrap();
    /// let transport = TcpTransport::connect(target).await?;
    /// let client = ClientBuilder::new(Auth::v2c("public"))
    ///     .build_with_transport(transport)?;
    /// # let _ = client;
    /// # Ok(())
    /// # }
    /// ```
    pub fn build_with_transport<T: Transport>(self, transport: T) -> Result<Client<T>> {
        self.build_inner(transport)
    }

    /// Build `ClientConfig` from the builder settings.
    fn build_config(&self) -> ClientConfig {
        ClientConfig {
            auth: self.auth.clone(),
            decode_policy: self.decode_policy,
            compatibility_policy: self.compatibility_policy,
            community_response_policy: self.community_response_policy,
            request_timeout: self.request_timeout,
            send_timeout: self.send_timeout,
            retry: self.retry.clone(),
            max_oids_per_request: self.max_oids_per_request,
            response_shape_policy: self.response_shape_policy,
            allow_unauthenticated_v3_time_correction: self.allow_unauthenticated_v3_time_correction,
            walk_mode: self.walk_mode,
            oid_ordering: self.oid_ordering,
            max_walk_results: self.max_walk_results,
            max_repetitions: self.max_repetitions,
            local_authoritative_engine: self.local_authoritative_engine.clone(),
        }
    }

    /// Build the client with the given transport.
    fn build_inner<T: Transport>(self, transport: T) -> Result<Client<T>> {
        let config = self.build_config();

        if let Some(cache) = self.engine_cache {
            Client::with_engine_cache(transport, config, cache)
        } else {
            Client::new(transport, config)
        }
    }
}

impl TargetClientBuilder {
    #[cfg(test)]
    fn validate(&self) -> Result<()> {
        self.client.validate()
    }

    #[cfg(test)]
    fn build_config(&self) -> ClientConfig {
        self.client.build_config()
    }

    /// Replace the target while retaining all client and target policies.
    #[must_use]
    pub fn target(mut self, target: impl Into<Target>) -> Self {
        self.target = target.into();
        self
    }

    /// Set the total timeout for client construction (default: 5 seconds).
    ///
    /// One absolute deadline is shared by target resolution and any UDP bind or
    /// TCP connect work. This setting has no effect on requests after the
    /// client has been constructed. [`Duration::ZERO`] is an immediate
    /// deadline.
    #[must_use]
    pub fn construction_timeout(mut self, timeout: Duration) -> Self {
        self.construction_timeout = timeout;
        self
    }

    /// Require UDP responses to originate from the configured target.
    ///
    /// By default, a UDP source mismatch only logs a warning, which permits
    /// multihomed agents to reply from another address. Enabling this option
    /// drops off-target datagrams while leaving the request pending for a
    /// response from the configured target. TCP is inherently connected to one
    /// peer.
    #[must_use]
    pub fn strict_source(mut self, strict: bool) -> Self {
        self.strict_source = strict;
        self
    }

    /// Set the confirmed-request timeout.
    #[must_use]
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.client = self.client.request_timeout(timeout);
        self
    }

    /// Set the standalone-send timeout.
    #[must_use]
    pub fn send_timeout(mut self, timeout: Duration) -> Self {
        self.client = self.client.send_timeout(timeout);
        self
    }

    /// Set request retry policy.
    #[must_use]
    pub fn retry(mut self, retry: impl Into<Retry>) -> Self {
        self.client = self.client.retry(retry);
        self
    }

    /// Set the maximum OIDs encoded in one request.
    #[must_use]
    pub fn max_oids_per_request(mut self, max: usize) -> Self {
        self.client = self.client.max_oids_per_request(max);
        self
    }

    /// Set BER decoding policy.
    #[must_use]
    pub fn decode_policy(mut self, policy: crate::message::DecodePolicy) -> Self {
        self.client = self.client.decode_policy(policy);
        self
    }

    /// Set protocol compatibility policy.
    #[must_use]
    pub fn compatibility_policy(mut self, policy: crate::CompatibilityPolicy) -> Self {
        self.client = self.client.compatibility_policy(policy);
        self
    }

    /// Select strict decoding and compatibility policies.
    #[must_use]
    pub fn strict_decoding(mut self) -> Self {
        self.client = self.client.strict_decoding();
        self
    }

    /// Set response-shape validation policy.
    #[must_use]
    pub fn response_shape_policy(mut self, policy: crate::client::ResponseShapePolicy) -> Self {
        self.client = self.client.response_shape_policy(policy);
        self
    }

    /// Set the default GETBULK max-repetitions value.
    #[must_use]
    pub fn max_repetitions(mut self, max: u32) -> Self {
        self.client = self.client.max_repetitions(max);
        self
    }

    /// Set walk operation mode.
    #[must_use]
    pub fn walk_mode(mut self, mode: WalkMode) -> Self {
        self.client = self.client.walk_mode(mode);
        self
    }

    /// Set walk OID ordering policy.
    #[must_use]
    pub fn oid_ordering(mut self, ordering: OidOrdering) -> Self {
        self.client = self.client.oid_ordering(ordering);
        self
    }

    /// Bound the number of results returned by a walk.
    #[must_use]
    pub fn max_walk_results(mut self, limit: usize) -> Self {
        self.client = self.client.max_walk_results(limit);
        self
    }

    /// Set the local authoritative engine for notifications.
    #[must_use]
    pub fn local_authoritative_engine(mut self, engine: AuthoritativeEngine) -> Self {
        self.client = self.client.local_authoritative_engine(engine);
        self
    }

    /// Use a shared SNMPv3 engine cache.
    #[must_use]
    pub fn engine_cache(mut self, cache: Arc<EngineCache>) -> Self {
        self.client = self.client.engine_cache(cache);
        self
    }

    /// Set v1/v2c response-community correlation policy.
    #[must_use]
    pub fn community_response_policy(mut self, policy: CommunityResponsePolicy) -> Self {
        self.client = self.client.community_response_policy(policy);
        self
    }

    /// Allow packet-local correction from an unauthenticated v3 time report.
    #[must_use]
    pub fn allow_unauthenticated_v3_time_correction(mut self, allow: bool) -> Self {
        self.client = self.client.allow_unauthenticated_v3_time_correction(allow);
        self
    }

    /// Resolve all target addresses, defaulting to port 161.
    ///
    /// Accepts IPv4 (`192.168.1.1`, `192.168.1.1:162`), IPv6 (`::1`,
    /// `[::1]:162`), hostnames (`switch.local`, `switch.local:162`), and
    /// `(host, port)` tuples. When no port is specified, SNMP port 161 is used.
    #[cfg(test)]
    async fn resolve_targets(&self) -> Result<Vec<SocketAddr>> {
        let deadline = ConstructionDeadline::new(&self.target, self.construction_timeout)?;
        self.resolve_targets_with(&deadline, |host, port| async move {
            tokio::net::lookup_host((host.as_str(), port))
                .await
                .map(|addresses| addresses.collect())
                .map_err(|error| {
                    Error::Config(format!("could not resolve address '{host}': {error}").into())
                        .boxed()
                })
        })
        .await
    }

    async fn resolve_targets_with<F, Fut>(
        &self,
        deadline: &ConstructionDeadline,
        resolver: F,
    ) -> Result<Vec<SocketAddr>>
    where
        F: FnOnce(String, u16) -> Fut,
        Fut: Future<Output = Result<Vec<SocketAddr>>>,
    {
        let (host, port) = match &self.target {
            Target::Address(addr) => split_host_port(addr),
            Target::HostPort(host, port) => (host.as_str(), *port),
        };
        let host = host.to_owned();
        let original_target = self.target.clone();

        deadline
            .run(ConstructionStage::Resolve, async move {
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    return Ok(vec![SocketAddr::new(ip, port)]);
                }

                let addresses = resolver(host, port).await?;
                if addresses.is_empty() {
                    return Err(Error::Config(
                        format!("could not resolve address '{original_target}'").into(),
                    )
                    .boxed());
                }
                Ok(addresses)
            })
            .await
    }

    fn select_udp_handle(
        transport: &UdpTransport,
        target: &Target,
        candidates: &[SocketAddr],
    ) -> Result<UdpHandle> {
        for candidate in candidates {
            if let Ok(handle) = transport.handle(*candidate) {
                return Ok(handle);
            }
        }

        Err(Error::Config(
            format!(
                "no resolved address for '{target}' is compatible with UDP socket {}",
                transport.local_addr()
            )
            .into(),
        )
        .boxed())
    }

    /// Connect via UDP (default).
    ///
    /// Creates a new UDP socket for this client. Each call allocates a
    /// separate socket and recv loop.
    ///
    /// To share a single socket across multiple clients, use
    /// [`build_with()`](Self::build_with) instead.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid or the connection fails.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::{Auth, ClientBuilder};
    ///
    /// # async fn example() -> async_snmp::Result<()> {
    /// let client = async_snmp::Client::builder("192.168.1.1:161", Auth::v2c("public"))
    ///     .connect()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect(self) -> Result<Client<UdpHandle>> {
        self.connect_with_control()
            .await
            .map(|(client, _control)| client)
    }

    /// Connect via a dedicated UDP endpoint and return lifecycle authority.
    ///
    /// The returned [`UdpControl`] controls the whole endpoint. Shutdown is
    /// irreversible and affects the returned client and all of its clones.
    /// Use [`connect()`](Self::connect) when drop-managed cleanup is sufficient.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid or endpoint creation
    /// fails.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::{Auth, ClientBuilder};
    ///
    /// # async fn example() -> async_snmp::Result<()> {
    /// let (client, control) =
    ///     async_snmp::Client::builder("192.168.1.1:161", Auth::v2c("public"))
    ///         .connect_with_control()
    ///         .await?;
    ///
    /// control.shutdown().await;
    /// assert!(control.is_shutdown());
    /// # let _ = client;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect_with_control(self) -> Result<(Client<UdpHandle>, UdpControl)> {
        self.connect_with_control_using(
            |host, port| async move {
                tokio::net::lookup_host((host.as_str(), port))
                    .await
                    .map(|addresses| addresses.collect())
                    .map_err(|error| {
                        Error::Config(format!("could not resolve address '{host}': {error}").into())
                            .boxed()
                    })
            },
            |bind_addr| async move { UdpTransport::bind(bind_addr).await },
        )
        .await
    }

    async fn connect_with_control_using<R, RFut, B, BFut>(
        mut self,
        resolver: R,
        binder: B,
    ) -> Result<(Client<UdpHandle>, UdpControl)>
    where
        R: FnOnce(String, u16) -> RFut,
        RFut: Future<Output = Result<Vec<SocketAddr>>>,
        B: FnOnce(&'static str) -> BFut,
        BFut: Future<Output = Result<UdpTransport>>,
    {
        self.client.validate_and_precompute()?;
        let deadline = ConstructionDeadline::new(&self.target, self.construction_timeout)?;
        let addr = self.resolve_targets_with(&deadline, resolver).await?[0];
        // Match bind address to target address family for cross-platform
        // compatibility. Dual-stack ([::]:0) only works reliably on Linux;
        // macOS/BSD default to IPV6_V6ONLY=1 and reject IPv4 targets.
        let bind_addr = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let transport = deadline
            .run(ConstructionStage::Bind, binder(bind_addr))
            .await?;
        let control = transport.control();
        let handle = transport.handle(addr)?.strict_source(self.strict_source);
        let client = self.client.build_inner(handle)?;
        Ok((client, control))
    }

    /// Build a per-target client handle on a shared UDP transport.
    ///
    /// This method specifically accepts a preconstructed [`UdpTransport`]
    /// socket owner. It resolves the builder's target and creates a
    /// [`UdpHandle`] for the first compatible address. All clients built this
    /// way share one socket and one recv loop. For an arbitrary already-created
    /// type that implements [`Transport`], use
    /// [`ClientBuilder::build_with_transport`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when resolution produces no address compatible
    /// with the transport's socket family.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::{Auth, ClientBuilder};
    /// use async_snmp::transport::UdpTransport;
    ///
    /// # async fn example() -> async_snmp::Result<()> {
    /// let transport = UdpTransport::bind("0.0.0.0:0").await?;
    ///
    /// let client1 = async_snmp::Client::builder("192.168.1.1:161", Auth::v2c("public"))
    ///     .build_with(&transport).await?;
    /// let client2 = async_snmp::Client::builder("192.168.1.2:161", Auth::v2c("public"))
    ///     .build_with(&transport).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn build_with(self, transport: &UdpTransport) -> Result<Client<UdpHandle>> {
        self.build_with_resolver(transport, |host, port| async move {
            tokio::net::lookup_host((host.as_str(), port))
                .await
                .map(|addresses| addresses.collect())
                .map_err(|error| {
                    Error::Config(format!("could not resolve address '{host}': {error}").into())
                        .boxed()
                })
        })
        .await
    }

    async fn build_with_resolver<R, RFut>(
        mut self,
        transport: &UdpTransport,
        resolver: R,
    ) -> Result<Client<UdpHandle>>
    where
        R: FnOnce(String, u16) -> RFut,
        RFut: Future<Output = Result<Vec<SocketAddr>>>,
    {
        self.client.validate_and_precompute()?;
        let deadline = ConstructionDeadline::new(&self.target, self.construction_timeout)?;
        let candidates = self.resolve_targets_with(&deadline, resolver).await?;
        let handle = Self::select_udp_handle(transport, &self.target, &candidates)?
            .strict_source(self.strict_source);
        self.client.build_inner(handle)
    }

    /// Connect via TCP.
    ///
    /// Establishes a TCP connection to the target. Use this when:
    /// - UDP is blocked by firewalls
    /// - Messages exceed UDP's maximum datagram size
    /// - Reliable delivery is required
    ///
    /// Note that TCP has higher overhead than UDP due to connection setup
    /// and per-message framing.
    ///
    /// When a hostname resolves to multiple addresses, each address is tried
    /// in resolver order until a connection succeeds. Resolution and all
    /// connection attempts share the configured construction timeout.
    ///
    /// For advanced TCP configuration (connection timeout, keepalive, buffer
    /// sizes), construct a [`TcpTransport`] directly and pass it to
    /// [`ClientBuilder::build_with_transport`]. [`TcpTransport::connect`]
    /// remains unbounded for applications that own a different deadline
    /// policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid or the connection fails.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::{Auth, ClientBuilder};
    ///
    /// # async fn example() -> async_snmp::Result<()> {
    /// let client = async_snmp::Client::builder("192.168.1.1:161", Auth::v2c("public"))
    ///     .connect_tcp()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect_tcp(self) -> Result<Client<TcpTransport>> {
        self.connect_tcp_with(
            |host, port| async move {
                tokio::net::lookup_host((host.as_str(), port))
                    .await
                    .map(|addresses| addresses.collect())
                    .map_err(|error| {
                        Error::Config(format!("could not resolve address '{host}': {error}").into())
                            .boxed()
                    })
            },
            |address| async move { TcpTransport::connect(address).await },
        )
        .await
    }

    async fn connect_tcp_with<R, RFut, C, CFut>(
        mut self,
        resolver: R,
        mut connector: C,
    ) -> Result<Client<TcpTransport>>
    where
        R: FnOnce(String, u16) -> RFut,
        RFut: Future<Output = Result<Vec<SocketAddr>>>,
        C: FnMut(SocketAddr) -> CFut,
        CFut: Future<Output = Result<TcpTransport>>,
    {
        self.client.validate_and_precompute()?;
        let deadline = ConstructionDeadline::new(&self.target, self.construction_timeout)?;
        let candidates = self.resolve_targets_with(&deadline, resolver).await?;
        let mut last_error = None;

        for address in candidates {
            match deadline
                .run(ConstructionStage::Connect, connector(address))
                .await
            {
                Ok(transport) => return self.client.build_inner(transport),
                Err(error) if matches!(*error, Error::ConstructionTimeout { .. }) => {
                    return Err(error);
                }
                Err(error) => last_error = Some(error),
            }
        }

        match last_error {
            Some(error) => Err(error),
            None => Err(Error::Config(
                format!(
                    "could not connect to any resolved address for '{}'",
                    self.target
                )
                .into(),
            )
            .boxed()),
        }
    }
}

struct ConstructionDeadline {
    target: Target,
    started: tokio::time::Instant,
    deadline: tokio::time::Instant,
}

impl ConstructionDeadline {
    fn new(target: &Target, timeout: Duration) -> Result<Self> {
        let started = tokio::time::Instant::now();
        let deadline = started.checked_add(timeout).ok_or_else(|| {
            Error::Config("construction timeout exceeds the representable deadline".into()).boxed()
        })?;
        Ok(Self {
            target: target.clone(),
            started,
            deadline,
        })
    }

    async fn run<T, F>(&self, stage: ConstructionStage, future: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        if tokio::time::Instant::now() >= self.deadline {
            return Err(self.timeout_error(stage));
        }

        tokio::time::timeout_at(self.deadline, future)
            .await
            .map_err(|_| self.timeout_error(stage))?
    }

    fn timeout_error(&self, stage: ConstructionStage) -> Box<Error> {
        Error::ConstructionTimeout {
            target: self.target.clone(),
            stage,
            elapsed: self.started.elapsed(),
        }
        .boxed()
    }
}

/// Default total timeout for resolving and creating a built-in transport.
pub const DEFAULT_CONSTRUCTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Default SNMP port.
const DEFAULT_PORT: u16 = 161;

/// Split a target string into (host, port), defaulting to port 161.
///
/// Handles IPv4 (`192.168.1.1`), IPv4 with port (`192.168.1.1:162`),
/// bare IPv6 (`fe80::1`), bracketed IPv6 (`[::1]`, `[::1]:162`),
/// and hostnames (`switch.local`, `switch.local:162`).
fn split_host_port(target: &str) -> (&str, u16) {
    // Bracketed IPv6: [addr]:port or [addr]
    if let Some(rest) = target.strip_prefix('[') {
        if let Some((addr, port)) = rest.rsplit_once("]:")
            && let Ok(p) = port.parse()
        {
            return (addr, p);
        }
        return (rest.trim_end_matches(']'), DEFAULT_PORT);
    }

    // IPv4 or hostname: last colon is the port separator, but only if the
    // host part doesn't also contain colons (which would make it bare IPv6)
    if let Some((host, port)) = target.rsplit_once(':')
        && !host.contains(':')
        && let Ok(p) = port.parse::<u16>()
    {
        return (host, p);
    }

    // No port found (bare IPv4, IPv6, or hostname)
    (target, DEFAULT_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    use crate::v3::MasterKeys;
    use crate::v3::{AuthProtocol, PrivProtocol, UsmConfig};

    #[test]
    fn test_builder_defaults() {
        let builder = ClientBuilder::new(Auth::default());
        assert_eq!(builder.request_timeout, DEFAULT_REQUEST_TIMEOUT);
        assert_eq!(builder.send_timeout, DEFAULT_SEND_TIMEOUT);
        assert_eq!(
            ClientConfig::default().request_timeout,
            Duration::from_secs(5)
        );
        assert_eq!(DEFAULT_REQUEST_TIMEOUT, Duration::from_secs(5));
        assert_eq!(DEFAULT_SEND_TIMEOUT, Duration::from_secs(5));
        assert_eq!(DEFAULT_CONSTRUCTION_TIMEOUT, Duration::from_secs(5));
        assert_eq!(builder.retry.max_attempts(), 3);
        assert_eq!(builder.max_oids_per_request, DEFAULT_MAX_OIDS_PER_REQUEST);
        assert_eq!(
            builder.response_shape_policy,
            crate::client::ResponseShapePolicy::Compatible
        );
        assert_eq!(builder.max_repetitions, DEFAULT_MAX_REPETITIONS);
        assert_eq!(builder.walk_mode, WalkMode::Auto);
        assert_eq!(builder.oid_ordering, OidOrdering::Strict);
        assert!(builder.max_walk_results.is_none());
        assert!(builder.engine_cache.is_none());
        assert_eq!(
            builder.community_response_policy,
            CommunityResponsePolicy::Exact
        );
        assert_eq!(
            builder.build_config().community_response_policy,
            ClientConfig::default().community_response_policy
        );
        assert!(!builder.allow_unauthenticated_v3_time_correction);

        let target = builder.target("192.168.1.1:161");
        assert!(matches!(target.target, Target::Address(ref s) if s == "192.168.1.1:161"));
        assert_eq!(target.construction_timeout, DEFAULT_CONSTRUCTION_TIMEOUT);
        assert!(!target.strict_source);
    }

    #[test]
    fn test_builder_with_options() {
        let cache = Arc::new(EngineCache::new());
        let builder = ClientBuilder::new(Auth::v2c("private"))
            .request_timeout(Duration::from_secs(10))
            .send_timeout(Duration::from_secs(8))
            .retry(Retry::fixed(5, Duration::ZERO))
            .max_oids_per_request(20)
            .response_shape_policy(crate::client::ResponseShapePolicy::Strict)
            .max_repetitions(50)
            .walk_mode(WalkMode::GetNext)
            .oid_ordering(OidOrdering::AllowNonIncreasing)
            .max_walk_results(1000)
            .engine_cache(cache.clone())
            .target("192.168.1.1:161")
            .construction_timeout(Duration::from_secs(7))
            .strict_source(true)
            .community_response_policy(CommunityResponsePolicy::AllowMismatchFromTarget)
            .allow_unauthenticated_v3_time_correction(true);

        assert_eq!(builder.client.request_timeout, Duration::from_secs(10));
        assert_eq!(builder.client.send_timeout, Duration::from_secs(8));
        assert_eq!(
            builder.client.build_config().send_timeout,
            Duration::from_secs(8)
        );
        assert_eq!(builder.construction_timeout, Duration::from_secs(7));
        assert_eq!(builder.client.retry.max_attempts(), 5);
        assert_eq!(builder.client.max_oids_per_request, 20);
        assert_eq!(
            builder.client.build_config().response_shape_policy,
            crate::client::ResponseShapePolicy::Strict
        );
        assert_eq!(builder.client.max_repetitions, 50);
        assert_eq!(builder.client.walk_mode, WalkMode::GetNext);
        assert_eq!(builder.client.oid_ordering, OidOrdering::AllowNonIncreasing);
        assert_eq!(builder.client.max_walk_results, Some(1000));
        assert!(builder.client.engine_cache.is_some());
        assert!(builder.strict_source);
        assert_eq!(
            builder.client.community_response_policy,
            CommunityResponsePolicy::AllowMismatchFromTarget
        );
        assert!(builder.client.allow_unauthenticated_v3_time_correction);
        assert!(
            builder
                .client
                .build_config()
                .allow_unauthenticated_v3_time_correction
        );
    }

    #[tokio::test]
    async fn tcp_connect_tries_later_resolved_addresses() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reachable = listener.local_addr().unwrap();
        let unreachable = "192.0.2.1:161".parse().unwrap();
        let attempts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let connector_attempts = Arc::clone(&attempts);

        let client = Client::builder("device.example", Auth::v2c("public"))
            .connect_tcp_with(
                move |_, _| async move { Ok(vec![unreachable, reachable]) },
                move |address| {
                    let connector_attempts = Arc::clone(&connector_attempts);
                    async move {
                        connector_attempts.lock().unwrap().push(address);
                        if address == unreachable {
                            return Err(Error::Network {
                                target: address,
                                source: std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
                            }
                            .boxed());
                        }
                        TcpTransport::connect(address).await
                    }
                },
            )
            .await
            .unwrap();

        assert_eq!(client.peer_addr(), reachable);
        assert_eq!(*attempts.lock().unwrap(), vec![unreachable, reachable]);
    }

    #[tokio::test]
    async fn tcp_connect_returns_last_candidate_error() {
        let first = "192.0.2.1:161".parse().unwrap();
        let last = "192.0.2.2:161".parse().unwrap();
        let attempts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let connector_attempts = Arc::clone(&attempts);

        let error = Client::builder("device.example", Auth::v2c("public"))
            .connect_tcp_with(
                move |_, _| async move { Ok(vec![first, last]) },
                move |address| {
                    let connector_attempts = Arc::clone(&connector_attempts);
                    async move {
                        connector_attempts.lock().unwrap().push(address);
                        Err::<TcpTransport, _>(
                            Error::Network {
                                target: address,
                                source: std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
                            }
                            .boxed(),
                        )
                    }
                },
            )
            .await
            .err()
            .expect("all connection attempts must fail");

        assert!(matches!(*error, Error::Network { target, .. } if target == last));
        assert_eq!(*attempts.lock().unwrap(), vec![first, last]);
    }

    #[tokio::test(start_paused = true)]
    async fn pending_tcp_connect_uses_construction_deadline_and_diagnostics() {
        let future = Client::builder("device.example:1161", Auth::v2c("public"))
            .request_timeout(Duration::from_secs(91))
            .construction_timeout(Duration::from_secs(5))
            .connect_tcp_with(
                |_, _| async { Ok(vec!["192.0.2.1:1161".parse().unwrap()]) },
                |_| std::future::pending::<Result<TcpTransport>>(),
            );
        let task = tokio::spawn(future);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;

        let error = task
            .await
            .unwrap()
            .err()
            .expect("construction must time out");
        match *error {
            Error::ConstructionTimeout {
                target,
                stage,
                elapsed,
            } => {
                assert_eq!(target, Target::Address("device.example:1161".to_owned()));
                assert_eq!(stage, ConstructionStage::Connect);
                assert_eq!(elapsed, Duration::from_secs(5));
            }
            other => panic!("expected construction timeout, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn resolution_and_tcp_connect_share_one_total_budget() {
        let future = Client::builder("device.example", Auth::v2c("public"))
            .construction_timeout(Duration::from_secs(5))
            .connect_tcp_with(
                |_, _| async {
                    tokio::time::sleep(Duration::from_secs(4)).await;
                    Ok(vec!["192.0.2.1:161".parse().unwrap()])
                },
                |_| std::future::pending::<Result<TcpTransport>>(),
            );
        let task = tokio::spawn(future);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(4)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;

        let error = task
            .await
            .unwrap()
            .err()
            .expect("construction must time out");
        assert!(matches!(
            *error,
            Error::ConstructionTimeout {
                stage: ConstructionStage::Connect,
                elapsed,
                ..
            } if elapsed == Duration::from_secs(5)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn udp_resolution_uses_construction_deadline() {
        let future = Client::builder("device.example", Auth::v2c("public"))
            .construction_timeout(Duration::from_secs(3))
            .connect_with_control_using(
                |_, _| std::future::pending::<Result<Vec<SocketAddr>>>(),
                |_| async { panic!("bind must not begin while resolution is pending") },
            );
        let task = tokio::spawn(future);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(3)).await;

        let error = task
            .await
            .unwrap()
            .err()
            .expect("construction must time out");
        assert!(matches!(
            *error,
            Error::ConstructionTimeout {
                stage: ConstructionStage::Resolve,
                elapsed,
                ..
            } if elapsed == Duration::from_secs(3)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn udp_bind_uses_remaining_construction_deadline() {
        let future = Client::builder("192.0.2.1", Auth::v2c("public"))
            .construction_timeout(Duration::from_secs(2))
            .connect_with_control_using(
                |_, _| async { panic!("numeric targets must not invoke the resolver") },
                |_| std::future::pending::<Result<UdpTransport>>(),
            );
        let task = tokio::spawn(future);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(2)).await;

        let error = task
            .await
            .unwrap()
            .err()
            .expect("construction must time out");
        assert!(matches!(
            *error,
            Error::ConstructionTimeout {
                stage: ConstructionStage::Bind,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn local_tcp_listener_connects_with_construction_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });

        let client = Client::builder(address, Auth::v2c("public"))
            .construction_timeout(Duration::from_secs(5))
            .connect_tcp()
            .await
            .unwrap();
        assert_eq!(client.peer_addr(), address);
        accept.await.unwrap();
    }

    #[tokio::test]
    async fn unrepresentable_construction_timeout_precedes_resolution() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&calls);
        let error = Client::builder("device.example", Auth::v2c("public"))
            .construction_timeout(Duration::MAX)
            .connect_tcp_with(
                move |_, _| {
                    resolver_calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    async { Ok(vec!["127.0.0.1:161".parse().unwrap()]) }
                },
                |_| std::future::pending::<Result<TcpTransport>>(),
            )
            .await
            .err()
            .expect("unrepresentable timeout must fail");

        assert!(matches!(*error, Error::Config(_)));
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn zero_construction_timeout_is_immediate() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&calls);
        let error = Client::builder("device.example", Auth::v2c("public"))
            .construction_timeout(Duration::ZERO)
            .connect_tcp_with(
                move |_, _| {
                    resolver_calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    async { Ok(vec!["127.0.0.1:161".parse().unwrap()]) }
                },
                |_| std::future::pending::<Result<TcpTransport>>(),
            )
            .await
            .err()
            .expect("zero timeout must fail");

        assert!(matches!(
            *error,
            Error::ConstructionTimeout {
                target: Target::Address(ref target),
                stage: ConstructionStage::Resolve,
                ..
            } if target == "device.example"
        ));
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn request_and_construction_settings_are_independent() {
        let builder = Client::builder("192.0.2.1", Auth::v2c("public"))
            .request_timeout(Duration::from_secs(11))
            .construction_timeout(Duration::from_secs(17));
        assert_eq!(
            builder.client.build_config().request_timeout,
            Duration::from_secs(11)
        );
        assert_eq!(builder.construction_timeout, Duration::from_secs(17));
    }

    #[test]
    fn test_validate_community_ok() {
        let builder = ClientBuilder::new(Auth::v2c("public"));
        assert!(builder.validate().is_ok());
    }

    #[test]
    fn test_validate_zero_max_oids_per_request_error() {
        let builder = ClientBuilder::new(Auth::v2c("public")).max_oids_per_request(0);
        let err = builder.validate().unwrap_err();
        assert!(matches!(
            *err,
            Error::Config(ref msg) if msg.contains("max_oids_per_request must be greater than 0")
        ));
    }

    #[derive(Clone)]
    struct CustomTransport {
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Transport for CustomTransport {
        async fn send(&self, _data: &[u8]) -> Result<()> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }

        async fn recv(
            &self,
            _registration: crate::transport::RequestRegistration,
        ) -> Result<(bytes::Bytes, std::net::SocketAddr)> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Err(Error::Config("unexpected custom transport receive".into()).boxed())
        }

        fn peer_addr(&self) -> std::net::SocketAddr {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            "127.0.0.1:161".parse().unwrap()
        }

        fn local_addr(&self) -> std::net::SocketAddr {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            "127.0.0.1:0".parse().unwrap()
        }

        fn is_reliable(&self) -> bool {
            true
        }
    }

    #[test]
    fn test_build_with_transport() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let transport = CustomTransport {
            calls: Arc::clone(&calls),
        };
        let client = ClientBuilder::new(Auth::v2c("private"))
            .request_timeout(Duration::from_secs(9))
            .retry(Retry::none())
            .max_oids_per_request(7)
            .walk_mode(WalkMode::GetNext)
            .oid_ordering(OidOrdering::AllowNonIncreasing)
            .max_walk_results(99)
            .max_repetitions(11)
            .build_with_transport(transport.clone())
            .expect("valid custom-transport client");

        assert_eq!(client.inner.config.request_timeout, Duration::from_secs(9));
        assert_eq!(client.inner.config.retry.max_attempts(), 0);
        assert_eq!(client.inner.config.max_oids_per_request, 7);
        assert_eq!(client.inner.config.walk_mode, WalkMode::GetNext);
        assert_eq!(
            client.inner.config.oid_ordering,
            OidOrdering::AllowNonIncreasing
        );
        assert_eq!(client.inner.config.max_walk_results, Some(99));
        assert_eq!(client.inner.config.max_repetitions, 11);
        assert!(matches!(
            &client.inner.config.auth,
            Auth::Community {
                version: crate::CommunityVersion::V2c,
                community,
            } if community.matches(b"private")
        ));
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);

        let invalid = ClientBuilder::new(Auth::v2c("public"))
            .max_oids_per_request(0)
            .build_with_transport(transport.clone());
        assert!(matches!(invalid, Err(ref error) if matches!(&**error, Error::Config(_))));
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);

        let invalid_usm = ClientBuilder::new(Auth::Usm(
            UsmConfig::new("").auth(AuthProtocol::Sha256, b"password"),
        ))
        .build_with_transport(transport);
        assert!(matches!(
            invalid_usm,
            Err(ref error)
                if matches!(&**error, Error::Config(message) if message.contains("USM username"))
        ));
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn preconfigured_custom_and_builtin_transports_cover_all_versions() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let custom = CustomTransport {
            calls: Arc::clone(&calls),
        };
        let endpoint = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let peer = "127.0.0.1:161".parse().unwrap();

        for (auth, expected) in [
            (Auth::v1("private"), crate::Version::V1),
            (Auth::v2c("public"), crate::Version::V2c),
            (Auth::usm("operator"), crate::Version::V3),
        ] {
            let custom_client = ClientBuilder::new(auth.clone())
                .build_with_transport(custom.clone())
                .unwrap();
            assert_eq!(custom_client.version(), expected);

            let builtin = crate::BuiltinTransport::from(endpoint.handle(peer).unwrap());
            let builtin_client = ClientBuilder::new(auth)
                .build_with_transport(builtin)
                .unwrap();
            assert_eq!(builtin_client.version(), expected);
        }

        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn client_builder_reuse_and_target_override_preserve_last_setting() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let base = ClientBuilder::new(Auth::v2c("public")).request_timeout(Duration::from_secs(7));

        let custom = base
            .clone()
            .build_with_transport(CustomTransport {
                calls: Arc::clone(&calls),
            })
            .unwrap();
        assert_eq!(custom.inner.config.request_timeout, Duration::from_secs(7));

        let targeted = base
            .target("192.0.2.1:161")
            .request_timeout(Duration::from_secs(11))
            .target("192.0.2.2:1161");
        assert_eq!(targeted.client.request_timeout, Duration::from_secs(11));
        assert_eq!(
            targeted.target,
            Target::Address("192.0.2.2:1161".to_owned())
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn target_resolution_errors_are_confined_to_builtin_construction() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        ClientBuilder::new(Auth::v2c("public"))
            .build_with_transport(CustomTransport {
                calls: Arc::clone(&calls),
            })
            .unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);

        let endpoint = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let error = ClientBuilder::new(Auth::v2c("public"))
            .target("unresolvable.invalid")
            .build_with_resolver(&endpoint, |_, _| async {
                Err(Error::Config("synthetic resolution failure".into()).boxed())
            })
            .await
            .err()
            .expect("synthetic resolution error must be returned");
        assert!(error.to_string().contains("synthetic resolution failure"));
    }

    #[test]
    fn test_validate_local_authoritative_engine() {
        let engine = AuthoritativeEngine::install(b"valid-engine".to_vec(), |_| {
            Ok::<(), std::convert::Infallible>(())
        })
        .unwrap();
        let valid = ClientBuilder::new(Auth::usm("trapuser")).local_authoritative_engine(engine);
        assert!(valid.validate().is_ok());
    }

    #[test]
    fn test_validate_usm_no_auth_no_priv_ok() {
        let builder = ClientBuilder::new(Auth::usm("readonly"));
        assert!(builder.validate().is_ok());
    }

    #[test]
    fn test_validate_usm_auth_no_priv_ok() {
        let builder = Client::builder(
            "192.168.1.1:161",
            Auth::usm_builder("admin")
                .auth(AuthProtocol::Sha256, "authpass")
                .build(),
        );
        assert!(builder.validate().is_ok());
    }

    #[test]
    fn test_validate_usm_auth_priv_ok() {
        let builder = Client::builder(
            "192.168.1.1:161",
            Auth::usm_builder("admin")
                .auth_priv(
                    AuthProtocol::Sha256,
                    "authpass",
                    PrivProtocol::Aes128,
                    "privpass",
                )
                .build(),
        );
        assert!(builder.validate().is_ok());
    }

    #[test]
    fn test_builder_with_usm_config() {
        let builder = Client::builder(
            "192.168.1.1:161",
            Auth::usm_builder("admin")
                .auth(AuthProtocol::Sha256, "pass")
                .build(),
        );
        assert!(builder.validate().is_ok());
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn test_validate_master_keys_configs() {
        let auth_only = MasterKeys::new(AuthProtocol::Sha256, b"authpass").unwrap();
        let builder = Client::builder(
            "192.168.1.1:161",
            Auth::usm_builder("user")
                .with_master_keys(auth_only)
                .build(),
        );
        assert!(builder.validate().is_ok());

        let auth_priv = MasterKeys::new(AuthProtocol::Sha256, b"authpass")
            .unwrap()
            .with_privacy(PrivProtocol::Aes128, b"privpass")
            .unwrap();
        let builder = Client::builder(
            "192.168.1.1:161",
            Auth::usm_builder("user")
                .with_master_keys(auth_priv)
                .build(),
        );
        assert!(builder.validate().is_ok());
    }

    #[test]
    fn test_build_config_preserves_v3_context_name() {
        let builder = Client::builder(
            "192.168.1.1:161",
            Auth::usm_builder("admin")
                .auth(AuthProtocol::Sha256, "authpass")
                .context_name("vlan100")
                .build(),
        );

        let config = builder.build_config();
        let Auth::Usm(security) = config.auth else {
            panic!("expected v3 security config to be built");
        };

        assert_eq!(security.configured_context_name().as_ref(), b"vlan100");
    }

    #[test]
    fn test_builder_with_host_port_tuple() {
        let builder = Client::builder(("fe80::1", 161), Auth::default());
        assert!(matches!(
            builder.target,
            Target::HostPort(ref h, 161) if h == "fe80::1"
        ));
    }

    #[test]
    fn test_builder_with_string_host_port_tuple() {
        let builder = Client::builder(("switch.local".to_string(), 162), Auth::v2c("public"));
        assert!(matches!(
            builder.target,
            Target::HostPort(ref h, 162) if h == "switch.local"
        ));
    }

    #[test]
    fn test_target_from_str() {
        let t: Target = "192.168.1.1:161".into();
        assert!(matches!(t, Target::Address(ref s) if s == "192.168.1.1:161"));
    }

    #[test]
    fn test_target_from_tuple() {
        let t: Target = ("fe80::1", 161).into();
        assert!(matches!(t, Target::HostPort(ref h, 161) if h == "fe80::1"));
    }

    #[test]
    fn test_target_from_socket_addr() {
        let addr: SocketAddr = "192.168.1.1:162".parse().unwrap();
        let t: Target = addr.into();
        assert!(matches!(t, Target::HostPort(ref h, 162) if h == "192.168.1.1"));
    }

    #[test]
    fn test_target_display() {
        let t: Target = "192.168.1.1:161".into();
        assert_eq!(t.to_string(), "192.168.1.1:161");

        let t: Target = ("fe80::1", 161).into();
        assert_eq!(t.to_string(), "[fe80::1]:161");

        let addr: SocketAddr = "[::1]:162".parse().unwrap();
        let t: Target = addr.into();
        assert_eq!(t.to_string(), "[::1]:162");
    }

    #[tokio::test]
    async fn test_udp_candidate_selection_skips_incompatible_family() {
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let target = Target::from("example.invalid");
        let candidates = [
            "[2001:db8::1]:161".parse().unwrap(),
            "192.0.2.1:161".parse().unwrap(),
        ];

        let handle =
            TargetClientBuilder::select_udp_handle(&transport, &target, &candidates).unwrap();
        assert_eq!(handle.peer_addr(), candidates[1]);
    }

    #[tokio::test]
    async fn test_udp_candidate_selection_rejects_ipv6_only_for_ipv4_transport() {
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let target = Target::from("example.invalid");
        let candidates = [
            "[2001:db8::1]:161".parse().unwrap(),
            "[2001:db8::2]:161".parse().unwrap(),
        ];

        let error = TargetClientBuilder::select_udp_handle(&transport, &target, &candidates)
            .err()
            .expect("IPv6-only candidates must be rejected for an IPv4 transport");
        assert!(matches!(*error, Error::Config(_)));
        assert!(error.to_string().contains("no resolved address"));
    }

    #[tokio::test]
    async fn test_udp_candidate_selection_normalizes_mapped_ipv6() {
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let target = Target::from("example.invalid");
        let candidates = ["[::ffff:192.0.2.1]:161".parse().unwrap()];

        let handle =
            TargetClientBuilder::select_udp_handle(&transport, &target, &candidates).unwrap();
        assert_eq!(handle.peer_addr(), "192.0.2.1:161".parse().unwrap());
    }

    #[tokio::test]
    async fn test_build_with_rejects_explicit_native_ipv6_for_ipv4_transport() {
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let error = Client::builder("[2001:db8::1]:161", Auth::v2c("public"))
            .build_with(&transport)
            .await
            .err()
            .expect("native IPv6 target must fail during client construction");

        assert!(matches!(*error, Error::Config(_)));
        assert!(error.to_string().contains("no resolved address"));
    }

    #[tokio::test]
    async fn test_resolve_target_socket_addr() {
        let addr: SocketAddr = "10.0.0.1:162".parse().unwrap();
        let builder = Client::builder(addr, Auth::default());
        let resolved = builder.resolve_targets().await.unwrap();
        assert_eq!(resolved, vec![addr]);
    }

    #[tokio::test]
    async fn test_resolve_target_host_port_ipv4() {
        let builder = Client::builder(("192.168.1.1", 162), Auth::default());
        let addrs = builder.resolve_targets().await.unwrap();
        assert_eq!(addrs, vec!["192.168.1.1:162".parse().unwrap()]);
    }

    #[tokio::test]
    async fn test_resolve_target_host_port_ipv6() {
        let builder = Client::builder(("::1", 161), Auth::default());
        let addrs = builder.resolve_targets().await.unwrap();
        assert_eq!(addrs, vec!["[::1]:161".parse().unwrap()]);
    }

    #[tokio::test]
    async fn test_resolve_target_string_still_works() {
        let builder = Client::builder("10.0.0.1:162", Auth::default());
        let addrs = builder.resolve_targets().await.unwrap();
        assert_eq!(addrs, vec!["10.0.0.1:162".parse().unwrap()]);
    }

    #[test]
    fn test_split_host_port_ipv4_with_port() {
        assert_eq!(split_host_port("192.168.1.1:162"), ("192.168.1.1", 162));
    }

    #[test]
    fn test_split_host_port_ipv4_default() {
        assert_eq!(split_host_port("192.168.1.1"), ("192.168.1.1", 161));
    }

    #[test]
    fn test_split_host_port_ipv6_bare() {
        assert_eq!(split_host_port("fe80::1"), ("fe80::1", 161));
    }

    #[test]
    fn test_split_host_port_ipv6_loopback() {
        assert_eq!(split_host_port("::1"), ("::1", 161));
    }

    #[test]
    fn test_split_host_port_ipv6_bracketed_with_port() {
        assert_eq!(split_host_port("[fe80::1]:162"), ("fe80::1", 162));
    }

    #[test]
    fn test_split_host_port_ipv6_bracketed_default() {
        assert_eq!(split_host_port("[::1]"), ("::1", 161));
    }

    #[test]
    fn test_split_host_port_hostname() {
        assert_eq!(split_host_port("switch.local"), ("switch.local", 161));
    }

    #[test]
    fn test_split_host_port_hostname_with_port() {
        assert_eq!(split_host_port("switch.local:162"), ("switch.local", 162));
    }

    #[test]
    fn decoding_policy_defaults_strict_preset_and_targeted_override() {
        let default = ClientBuilder::new(Auth::v2c("public")).build_config();
        assert_eq!(
            default.decode_policy,
            crate::message::DecodePolicy::Compatible
        );
        assert_eq!(
            default.compatibility_policy,
            crate::CompatibilityPolicy::DEFAULT
        );

        let mut targeted = crate::CompatibilityPolicy::STRICT;
        targeted.empty_counter64_as_zero = true;
        let configured = ClientBuilder::new(Auth::v2c("public"))
            .strict_decoding()
            .compatibility_policy(targeted)
            .build_config();
        assert_eq!(
            configured.decode_policy,
            crate::message::DecodePolicy::Strict
        );
        assert_eq!(configured.compatibility_policy, targeted);
    }
}
