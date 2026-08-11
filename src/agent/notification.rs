//! Agent notification sending (trap/inform).
//!
//! Provides trap sink configuration and methods for sending notifications
//! from an agent to configured destinations.

use std::net::SocketAddr;
use std::sync::RwLock;
use std::time::Duration;

use bytes::Bytes;
use futures_util::future::join_all;
use tokio::sync::Mutex as AsyncMutex;

use crate::Community;
use crate::client::{Auth, Client, ClientConfig, CommunityVersion, Retry};
use crate::error::{Error, Result};
use crate::handler::SecurityModel;
use crate::message::{CommunityMessage, SecurityLevel};
use crate::oid::Oid;
use crate::pdu::Pdu;
use crate::transport::{UdpHandle, UdpTransport};
use crate::v3::{DerivedKeys, UsmConfig};
use crate::varbind::VarBind;
use crate::version::Version;

/// A configured notification destination.
///
/// Stores resolved credentials and cached keys for sending traps and informs
/// to a specific target.
pub(crate) struct TrapSink {
    pub(crate) dest: SocketAddr,
    auth: Auth,
    pub(crate) version: Version,
    pub(crate) community: Community,
    pub(crate) v3_security: Option<UsmConfig>,
    /// Keys derived against the agent's `engine_id` for V3 trap sending.
    /// Lazily populated on first use.
    pub(crate) derived_keys: RwLock<Option<DerivedKeys>>,
    /// Inform request timeout and retry policy.
    inform_timeout: Duration,
    inform_retry: Retry,
    /// Cached client for inform sending. Lazily created on first inform.
    /// Holds both the transport (to keep the socket alive) and the client.
    inform_client: AsyncMutex<Option<(UdpTransport, Client<UdpHandle>)>>,
}

impl TrapSink {
    /// Create from an Auth configuration and resolved destination address.
    pub(crate) fn new(
        dest: SocketAddr,
        auth: Auth,
        inform_timeout: Duration,
        inform_retry: Retry,
    ) -> Self {
        let sink_auth = auth.clone();
        match auth {
            Auth::Community { version, community } => {
                let snmp_version = match version {
                    CommunityVersion::V1 => Version::V1,
                    CommunityVersion::V2c => Version::V2c,
                };
                TrapSink {
                    dest,
                    auth: sink_auth,
                    version: snmp_version,
                    community: community.clone(),
                    v3_security: None,
                    derived_keys: RwLock::new(None),
                    inform_timeout,
                    inform_retry,
                    inform_client: AsyncMutex::new(None),
                }
            }
            Auth::Usm(security) => TrapSink {
                dest,
                auth: sink_auth,
                version: Version::V3,
                community: Community::default(),
                v3_security: Some(security),
                derived_keys: RwLock::new(None),
                inform_timeout,
                inform_retry,
                inform_client: AsyncMutex::new(None),
            },
        }
    }

    /// Ensure keys are derived against the given `engine_id` for V3 trap sending.
    fn ensure_keys_derived(&self, engine_id: &[u8]) -> Result<()> {
        {
            let keys = self.derived_keys.read().map_err(|_| {
                Error::Config("trap sink derived_keys lock poisoned".into()).boxed()
            })?;
            if keys.is_some() {
                return Ok(());
            }
        }

        let security = self.v3_security.as_ref().ok_or_else(|| {
            Error::Config("V3 security not configured for trap sink".into()).boxed()
        })?;

        let keys = security
            .derive_keys(engine_id)
            .map_err(|e| Error::Config(e.to_string().into()).boxed())?;

        let mut derived = self
            .derived_keys
            .write()
            .map_err(|_| Error::Config("trap sink derived_keys lock poisoned".into()).boxed())?;
        *derived = Some(keys);

        Ok(())
    }

    /// Get or create the cached inform client for this sink.
    async fn get_or_create_inform_client(&self) -> Result<Client<UdpHandle>> {
        let mut guard = self.inform_client.lock().await;
        if let Some((_, ref client)) = *guard {
            return Ok(client.clone());
        }

        if self.version == Version::V1 {
            unreachable!("v1 does not support informs");
        }
        let config = ClientConfig {
            auth: self.auth.clone(),
            request_timeout: self.inform_timeout,
            retry: self.inform_retry.clone(),
            ..ClientConfig::default()
        };

        let bind_addr = if self.dest.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let transport = UdpTransport::bind(bind_addr).await?;
        let handle = transport.handle(self.dest)?;
        let client = Client::new(handle, config)?;
        *guard = Some((transport, client.clone()));
        Ok(client)
    }
}

/// Reason that a configured notification sink was not attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SinkSkipReason {
    /// SNMPv1 does not support Inform requests.
    InformUnsupportedForV1,
    /// VACM did not resolve a notify view containing the notification.
    NotInNotifyView,
}

impl std::fmt::Display for SinkSkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InformUnsupportedForV1 => write!(f, "SNMPv1 does not support informs"),
            Self::NotInNotifyView => write!(f, "notification is not in the sink's notify view"),
        }
    }
}

/// Delivery status for a configured notification sink.
#[derive(Debug)]
pub enum SinkStatus {
    /// Encoding and the local socket write succeeded for a trap, or the Inform
    /// was acknowledged.
    Succeeded,
    /// The delivery attempt failed.
    Failed(Box<Error>),
    /// The configured sink could not be attempted for the stated reason.
    Skipped(SinkSkipReason),
}

/// Delivery outcome for a single configured notification sink.
///
/// For traps, success reflects encoding and the local socket write, not remote
/// receipt. For confirmed informs, success reflects the full request/response
/// exchange, including acknowledgement.
#[derive(Debug)]
pub struct SinkOutcome {
    /// The sink destination address.
    pub dest: SocketAddr,
    /// The delivery status for this sink.
    pub status: SinkStatus,
}

/// Aggregate outcome of sending a notification to all configured sinks.
///
/// Returned by [`Agent::send_trap`](super::Agent::send_trap) and
/// [`Agent::send_inform`](super::Agent::send_inform) so callers can observe
/// success, failure, or an explicit skip for every configured sink.
#[must_use = "inspect notification outcomes or use the explicit best-effort helper"]
#[derive(Debug)]
pub struct NotificationOutcome {
    sinks: Vec<SinkOutcome>,
}

impl NotificationOutcome {
    /// Per-sink outcomes, in sink configuration order.
    pub fn sinks(&self) -> &[SinkOutcome] {
        &self.sinks
    }

    /// Iterator over the sinks whose delivery failed.
    pub fn failures(&self) -> impl Iterator<Item = &SinkOutcome> {
        self.sinks
            .iter()
            .filter(|s| matches!(s.status, SinkStatus::Failed(_)))
    }

    /// Iterator over configured sinks that were not attempted.
    pub fn skipped(&self) -> impl Iterator<Item = &SinkOutcome> {
        self.sinks
            .iter()
            .filter(|s| matches!(s.status, SinkStatus::Skipped(_)))
    }

    /// `true` if every configured sink succeeded.
    ///
    /// This is also `true` when no sinks are configured, but is `false` when
    /// any configured sink failed or was skipped.
    pub fn all_succeeded(&self) -> bool {
        self.sinks
            .iter()
            .all(|s| matches!(s.status, SinkStatus::Succeeded))
    }

    /// Number of configured sinks represented in this outcome.
    pub fn len(&self) -> usize {
        self.sinks.len()
    }

    /// `true` if no sinks were configured.
    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }

    /// Consume the outcome, returning the per-sink outcomes.
    pub fn into_sinks(self) -> Vec<SinkOutcome> {
        self.sinks
    }
}

impl super::Agent {
    /// Send a trap to all configured trap sinks, reporting every outcome.
    ///
    /// Constructs a `TrapV2` PDU with the mandatory sysUpTime.0 and
    /// snmpTrapOID.0 prefix and sends it to each destination. Trap success
    /// means encoding and the local socket write succeeded; traps are
    /// fire-and-forget and remote receipt is not confirmed.
    ///
    /// V1 trap sinks receive a converted v1 trap (RFC 3584 Section 3.2).
    /// For a V3 sink, this Agent is authoritative and sends its persisted
    /// engine ID with the current boots/time tuple.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use async_snmp::agent::Agent;
    /// # use async_snmp::{Auth, oid};
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// let agent = Agent::builder()
    ///     .bind("0.0.0.0:1161")
    ///     .community(b"public")
    ///     .trap_sink("192.168.1.100:162", Auth::v2c("public"))
    ///     .build()
    ///     .await?;
    ///
    /// let outcome = agent
    ///     .send_trap(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), 0, vec![])
    ///     .await;
    /// assert!(outcome.all_succeeded());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_trap(
        &self,
        trap_oid: &Oid,
        uptime: u32,
        varbinds: Vec<VarBind>,
    ) -> NotificationOutcome {
        let sinks = &self.inner.trap_sinks;
        let mut outcomes = Vec::with_capacity(sinks.len());
        if sinks.is_empty() {
            return NotificationOutcome { sinks: outcomes };
        }

        let request_id = self.next_notification_id();
        let pdu = Pdu::trap_v2(request_id, uptime, trap_oid, varbinds.clone());

        for sink in sinks {
            let status = if !self.notification_allowed(sink, trap_oid, &varbinds) {
                SinkStatus::Skipped(SinkSkipReason::NotInNotifyView)
            } else {
                match self.send_trap_to_sink(sink, &pdu).await {
                    Ok(()) => SinkStatus::Succeeded,
                    Err(error) => SinkStatus::Failed(error),
                }
            };
            outcomes.push(SinkOutcome {
                dest: sink.dest,
                status,
            });
        }

        NotificationOutcome { sinks: outcomes }
    }

    /// Send a trap to all configured sinks, warning and discarding outcomes.
    ///
    /// Use [`send_trap`](Self::send_trap) when the caller needs to observe
    /// per-sink success or failure.
    pub async fn send_trap_best_effort(&self, trap_oid: &Oid, uptime: u32, varbinds: Vec<VarBind>) {
        let outcome = self.send_trap(trap_oid, uptime, varbinds).await;
        for sink in outcome.sinks() {
            match &sink.status {
                SinkStatus::Failed(error) => {
                    tracing::warn!(target: "async_snmp::agent", { snmp.dest = %sink.dest, error = %error }, "failed to send trap");
                }
                SinkStatus::Skipped(reason) => {
                    tracing::warn!(target: "async_snmp::agent", { snmp.dest = %sink.dest, reason = %reason }, "skipped trap sink");
                }
                SinkStatus::Succeeded => {}
            }
        }
    }

    /// Send an inform to all configured trap sinks, reporting every outcome.
    ///
    /// Constructs an `InformRequest` PDU and sends it to each destination,
    /// waiting for acknowledgement from each. Sink exchanges run concurrently,
    /// and outcomes remain in sink configuration order. Reuses a cached client
    /// per sink for the request/response exchange.
    ///
    /// V1 trap sinks are explicitly reported as skipped because v1 does not
    /// support informs. For a V3 sink, the receiver is authoritative; the
    /// cached client discovers and uses the sink's engine identity and trusted
    /// time rather than the Agent's local authoritative state.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use async_snmp::agent::Agent;
    /// # use async_snmp::{Auth, oid};
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// let agent = Agent::builder()
    ///     .bind("0.0.0.0:1161")
    ///     .community(b"public")
    ///     .trap_sink("192.168.1.100:162", Auth::v2c("public"))
    ///     .build()
    ///     .await?;
    ///
    /// let outcome = agent
    ///     .send_inform(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2), 0, vec![])
    ///     .await;
    /// assert!(outcome.all_succeeded());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_inform(
        &self,
        trap_oid: &Oid,
        uptime: u32,
        varbinds: Vec<VarBind>,
    ) -> NotificationOutcome {
        let sinks = &self.inner.trap_sinks;
        let varbinds = &varbinds;
        let outcomes = join_all(sinks.iter().map(|sink| async move {
            let status = if sink.version == Version::V1 {
                SinkStatus::Skipped(SinkSkipReason::InformUnsupportedForV1)
            } else if !self.notification_allowed(sink, trap_oid, varbinds) {
                SinkStatus::Skipped(SinkSkipReason::NotInNotifyView)
            } else {
                match self
                    .send_inform_to_sink(sink, trap_oid, uptime, varbinds)
                    .await
                {
                    Ok(()) => SinkStatus::Succeeded,
                    Err(error) => SinkStatus::Failed(error),
                }
            };
            SinkOutcome {
                dest: sink.dest,
                status,
            }
        }))
        .await;

        NotificationOutcome { sinks: outcomes }
    }

    /// Send an inform to all configured sinks, warning and discarding outcomes.
    ///
    /// Use [`send_inform`](Self::send_inform) when the caller needs to observe
    /// per-sink acknowledgement, failure, or skip status.
    pub async fn send_inform_best_effort(
        &self,
        trap_oid: &Oid,
        uptime: u32,
        varbinds: Vec<VarBind>,
    ) {
        let outcome = self.send_inform(trap_oid, uptime, varbinds).await;
        for sink in outcome.sinks() {
            match &sink.status {
                SinkStatus::Failed(error) => {
                    tracing::warn!(target: "async_snmp::agent", { snmp.dest = %sink.dest, error = %error }, "failed to send inform");
                }
                SinkStatus::Skipped(reason) => {
                    tracing::warn!(target: "async_snmp::agent", { snmp.dest = %sink.dest, reason = %reason }, "skipped inform sink");
                }
                SinkStatus::Succeeded => {}
            }
        }
    }

    /// Resolve and apply the target sink's VACM notify view.
    fn notification_allowed(&self, sink: &TrapSink, trap_oid: &Oid, varbinds: &[VarBind]) -> bool {
        let Some(vacm) = self.inner.vacm.as_ref() else {
            return true;
        };

        let (model, security_name, security_level, context_name) = match &sink.auth {
            Auth::Community { version, community } => {
                let model = match version {
                    CommunityVersion::V1 => SecurityModel::V1,
                    CommunityVersion::V2c => SecurityModel::V2c,
                };
                (
                    model,
                    community.as_bytes(),
                    SecurityLevel::NoAuthNoPriv,
                    &[][..],
                )
            }
            Auth::Usm(security) => (
                SecurityModel::Usm,
                security.username().as_ref(),
                security.security_level(),
                security.configured_context_name().as_ref(),
            ),
        };

        let Some(group) = vacm.get_group(model, security_name) else {
            return false;
        };
        let Some(access) = vacm.get_access(group, context_name, model, security_level) else {
            return false;
        };
        let notify_view = Some(&access.notify_view);

        if !vacm.check_access(notify_view, trap_oid)
            || varbinds
                .iter()
                .any(|varbind| !vacm.check_access(notify_view, &varbind.oid))
        {
            return false;
        }

        // SNMPv2c/v3 notifications carry these mandatory varbind names. In v1
        // they are represented by Trap-PDU fields instead.
        sink.version == Version::V1
            || (vacm.check_access(notify_view, &crate::notification::oids::sys_uptime())
                && vacm.check_access(notify_view, &crate::notification::oids::snmp_trap_oid()))
    }

    /// Send a trap PDU to a single sink.
    async fn send_trap_to_sink(&self, sink: &TrapSink, pdu: &Pdu) -> Result<()> {
        let data = match sink.version {
            Version::V1 => {
                // Convert the v2 PDU to a v1 TrapV1Pdu (RFC 3584 Section 3.2).
                // Use the agent's bound address as agent_addr if available.
                let local_ip = match self.inner.socket.local_addr() {
                    Ok(addr) => match addr.ip() {
                        std::net::IpAddr::V4(v4) => v4.octets(),
                        std::net::IpAddr::V6(_) => [0, 0, 0, 0],
                    },
                    Err(_) => [0, 0, 0, 0],
                };
                let trap = pdu.to_v1_trap(local_ip).ok_or_else(|| {
                    Error::Config("cannot convert trap to v1 for sink (Counter64 varbind?)".into())
                        .boxed()
                })?;
                let msg = CommunityMessage::v1_trap(sink.community.clone(), trap)?;
                msg.encode()
            }
            Version::V2c => {
                let msg = CommunityMessage::new(Version::V2c, sink.community.clone(), pdu.clone())?;
                msg.encode()
            }
            Version::V3 => {
                let security = sink.v3_security.as_ref().ok_or_else(|| {
                    Error::Config("V3 security not configured for trap sink".into()).boxed()
                })?;

                sink.ensure_keys_derived(&self.inner.state.engine_id)?;
                let derived = sink.derived_keys.read().map_err(|_| {
                    Error::Config("trap sink derived_keys lock poisoned".into()).boxed()
                })?;

                let (engine_boots, engine_time) = self.inner.state.authoritative_boots_time()?;

                let msg_id = self.next_notification_id();
                let encoded = crate::v3::encode::encode_v3_message(
                    pdu,
                    msg_id,
                    &self.inner.state.engine_id,
                    engine_boots,
                    engine_time,
                    security,
                    derived.as_ref(),
                    &self.inner.salt_counter,
                    false, // reportable=false for traps
                    self.inner.state.local_receive_capacity,
                )?;
                Ok(Bytes::from(encoded))
            }
        }?;

        tracing::debug!(target: "async_snmp::agent", { snmp.dest = %sink.dest, snmp.bytes = data.len() }, "sending trap");
        self.inner
            .socket
            .send_to(&data, sink.dest)
            .await
            .map_err(|e| Error::Network {
                target: sink.dest,
                source: e,
            })?;

        Ok(())
    }

    /// Send an inform to a single sink, reusing a cached client.
    async fn send_inform_to_sink(
        &self,
        sink: &TrapSink,
        trap_oid: &Oid,
        uptime: u32,
        varbinds: &[VarBind],
    ) -> Result<()> {
        let client = sink.get_or_create_inform_client().await?;
        client
            .send_inform(trap_oid, uptime, varbinds.to_vec())
            .await?;

        Ok(())
    }

    /// Generate a notification request/message ID.
    fn next_notification_id(&self) -> i32 {
        use std::sync::atomic::Ordering;
        self.inner
            .notification_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(if v == i32::MAX { 1 } else { v + 1 })
            })
            .unwrap_or(1)
    }
}

#[cfg(test)]
mod tests {
    use super::{SinkSkipReason, SinkStatus, TrapSink};
    use crate::agent::{Agent, SecurityModel};
    use crate::{Auth, AuthProtocol, Error, PrivProtocol, Value, VarBind, oid};
    use bytes::Bytes;

    fn test_sink(auth: impl Into<Auth>) -> TrapSink {
        TrapSink::new(
            "127.0.0.1:9".parse().unwrap(),
            auth.into(),
            std::time::Duration::from_millis(10),
            crate::client::Retry::default(),
        )
    }

    #[tokio::test]
    async fn notify_view_uses_each_sink_identity_context_and_security_level() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .vacm(|v| {
                v.group("v1-community", SecurityModel::V1, "v1")
                    .group("v2-community", SecurityModel::V2c, "v2")
                    .group("context-user", SecurityModel::Usm, "context")
                    .group("security-user", SecurityModel::Usm, "security")
                    .access("v1", |a| a.notify_view("all"))
                    .access("v2", |a| a.notify_view("all"))
                    .access("context", |a| {
                        a.context_prefix("tenant/")
                            .context_match_prefix()
                            .security_model(SecurityModel::Usm)
                            .notify_view("empty")
                    })
                    .access("context", |a| {
                        a.context_prefix("tenant/blue")
                            .security_model(SecurityModel::Usm)
                            .notify_view("all")
                    })
                    .access("security", |a| {
                        a.context_prefix("secure")
                            .security_model(SecurityModel::Usm)
                            .notify_view("empty")
                    })
                    .access("security", |a| {
                        a.context_prefix("secure")
                            .security_model(SecurityModel::Usm)
                            .security_level(crate::message::SecurityLevel::AuthPriv)
                            .notify_view("all")
                    })
                    .view("all", |view| view.include(oid!(1, 3, 6)))
                    .view("empty", |view| view)
            })
            .build()
            .await
            .unwrap();
        let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);

        assert!(agent.notification_allowed(&test_sink(Auth::v1("v1-community")), &trap_oid, &[]));
        assert!(agent.notification_allowed(&test_sink(Auth::v2c("v2-community")), &trap_oid, &[]));
        assert!(agent.notification_allowed(
            &test_sink(Auth::usm("context-user").context_name("tenant/blue")),
            &trap_oid,
            &[]
        ));
        assert!(!agent.notification_allowed(
            &test_sink(Auth::usm("context-user").context_name("tenant/red")),
            &trap_oid,
            &[]
        ));
        assert!(
            !agent.notification_allowed(
                &test_sink(
                    Auth::usm("security-user")
                        .auth(AuthProtocol::Sha256, "auth-password")
                        .context_name("secure")
                ),
                &trap_oid,
                &[]
            )
        );
        assert!(
            agent.notification_allowed(
                &test_sink(
                    Auth::usm("security-user")
                        .auth_priv(
                            AuthProtocol::Sha256,
                            "auth-password",
                            PrivProtocol::Aes128,
                            "privacy-password",
                        )
                        .context_name("secure")
                ),
                &trap_oid,
                &[]
            )
        );
    }

    #[tokio::test]
    async fn notify_view_denies_trap_oid_extra_varbind_and_missing_views() {
        let denied_trap = oid!(1, 3, 6, 1, 4, 1, 9999, 1);
        let allowed_trap = oid!(1, 3, 6, 1, 4, 1, 9999, 2);
        let denied_extra = oid!(1, 3, 6, 1, 4, 1, 9999, 3);
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .vacm(|v| {
                v.group("trap-denied", SecurityModel::V2c, "trap-denied")
                    .group("extra-denied", SecurityModel::V2c, "extra-denied")
                    .group("missing", SecurityModel::V2c, "missing")
                    .group("empty", SecurityModel::V2c, "empty")
                    .group("no-access", SecurityModel::V2c, "no-access")
                    .access("trap-denied", |a| a.notify_view("trap-view"))
                    .access("extra-denied", |a| a.notify_view("extra-view"))
                    .access("missing", |a| a.notify_view("not-defined"))
                    .access("empty", |a| a)
                    .view("trap-view", |view| {
                        view.include(oid!(1, 3, 6)).exclude(denied_trap.clone())
                    })
                    .view("extra-view", |view| {
                        view.include(oid!(1, 3, 6)).exclude(denied_extra.clone())
                    })
            })
            .build()
            .await
            .unwrap();
        let extra = VarBind::new(denied_extra, Value::Integer(1));

        assert!(!agent.notification_allowed(
            &test_sink(Auth::v2c("trap-denied")),
            &denied_trap,
            &[]
        ));
        assert!(!agent.notification_allowed(
            &test_sink(Auth::v2c("extra-denied")),
            &allowed_trap,
            &[extra]
        ));
        assert!(!agent.notification_allowed(&test_sink(Auth::v2c("missing")), &allowed_trap, &[]));
        assert!(!agent.notification_allowed(&test_sink(Auth::v2c("empty")), &allowed_trap, &[]));
        assert!(!agent.notification_allowed(
            &test_sink(Auth::v2c("no-access")),
            &allowed_trap,
            &[]
        ));
        assert!(!agent.notification_allowed(&test_sink(Auth::v2c("no-group")), &allowed_trap, &[]));
    }

    #[tokio::test]
    async fn notify_view_checks_v2_mandatory_varbind_names_but_not_v1_fields() {
        let trap_oid = oid!(1, 3, 6, 1, 4, 1, 9999, 1);
        let extra_oid = oid!(1, 3, 6, 1, 4, 1, 9999, 2);
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .vacm(|v| {
                v.group("v1", SecurityModel::V1, "group")
                    .group("v2", SecurityModel::V2c, "group")
                    .access("group", |a| a.notify_view("notification-only"))
                    .view("notification-only", |view| {
                        view.include(trap_oid.clone()).include(extra_oid.clone())
                    })
            })
            .build()
            .await
            .unwrap();
        let extra = VarBind::new(extra_oid, Value::Integer(1));

        assert!(agent.notification_allowed(
            &test_sink(Auth::v1("v1")),
            &trap_oid,
            std::slice::from_ref(&extra)
        ));
        assert!(!agent.notification_allowed(&test_sink(Auth::v2c("v2")), &trap_oid, &[extra]));
    }

    #[tokio::test]
    async fn notification_vacm_is_permissive_when_unconfigured_and_mixed_per_sink() {
        let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
        let permissive = Agent::builder().bind("127.0.0.1:0").build().await.unwrap();
        assert!(permissive.notification_allowed(
            &test_sink(Auth::v2c("unmapped")),
            &trap_oid,
            &[VarBind::new(oid!(9, 9), Value::Integer(1))]
        ));

        let mixed = Agent::builder()
            .bind("127.0.0.1:0")
            .trap_sink("127.0.0.1:9", Auth::v2c("allowed"))
            .trap_sink("127.0.0.1:9", Auth::v2c("denied"))
            .vacm(|v| {
                v.group("allowed", SecurityModel::V2c, "allowed")
                    .group("denied", SecurityModel::V2c, "denied")
                    .access("allowed", |a| a.notify_view("all"))
                    .access("denied", |a| a.notify_view("empty"))
                    .view("all", |view| view.include(oid!(1, 3, 6)))
                    .view("empty", |view| view)
            })
            .build()
            .await
            .unwrap();
        let outcome = mixed.send_trap(&trap_oid, 0, vec![]).await;
        assert!(matches!(outcome.sinks()[0].status, SinkStatus::Succeeded));
        assert!(matches!(
            outcome.sinks()[1].status,
            SinkStatus::Skipped(SinkSkipReason::NotInNotifyView)
        ));

        let denied_inform = Agent::builder()
            .bind("127.0.0.1:0")
            .trap_sink("127.0.0.1:9", Auth::v2c("denied"))
            .vacm(|v| {
                v.group("denied", SecurityModel::V2c, "denied")
                    .access("denied", |a| a.notify_view("empty"))
                    .view("empty", |view| view)
            })
            .build()
            .await
            .unwrap()
            .send_inform(&trap_oid, 0, vec![])
            .await;
        assert!(matches!(
            denied_inform.sinks()[0].status,
            SinkStatus::Skipped(SinkSkipReason::NotInNotifyView)
        ));

        let denied_v1_inform = Agent::builder()
            .bind("127.0.0.1:0")
            .trap_sink("127.0.0.1:9", Auth::v1("denied"))
            .vacm(|v| v)
            .build()
            .await
            .unwrap()
            .send_inform(&trap_oid, 0, vec![])
            .await;
        assert!(matches!(
            denied_v1_inform.sinks()[0].status,
            SinkStatus::Skipped(SinkSkipReason::InformUnsupportedForV1)
        ));
    }

    #[tokio::test]
    async fn public_agent_notification_path_rejects_receive_only_values() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .trap_sink("127.0.0.1:9", Auth::v2c("public"))
            .build()
            .await
            .unwrap();
        let malformed = VarBind::new(
            oid!(1, 3, 6, 1, 4, 1, 9999, 1),
            Value::Unknown {
                tag: 0x48,
                data: Bytes::from_static(b"raw"),
            },
        );

        let outcome = agent
            .send_trap(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), 0, vec![malformed])
            .await;
        assert_eq!(outcome.len(), 1);
        match &outcome.sinks()[0].status {
            SinkStatus::Failed(error) => {
                assert!(matches!(&**error, Error::InvalidMessage(_)));
            }
            status => panic!("expected outbound validation failure, got {status:?}"),
        }
    }

    #[tokio::test]
    async fn test_notification_ids_are_per_agent() {
        // Each Agent must own its own notification id sequence; two independent
        // agents must not share a process-global counter.
        let agent_a = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .build()
            .await
            .unwrap();
        let agent_b = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .build()
            .await
            .unwrap();

        // Advance agent_a's sequence a few times.
        let a1 = agent_a.next_notification_id();
        let a2 = agent_a.next_notification_id();
        let a3 = agent_a.next_notification_id();
        assert_eq!((a1, a2, a3), (1, 2, 3));

        // agent_b is unaffected by agent_a's advancement and starts fresh.
        let b1 = agent_b.next_notification_id();
        let b2 = agent_b.next_notification_id();
        assert_eq!((b1, b2), (1, 2));

        // agent_a continues its own monotonic sequence.
        assert_eq!(agent_a.next_notification_id(), 4);
    }
}
