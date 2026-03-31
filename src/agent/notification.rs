//! Agent notification sending (trap/inform).
//!
//! Provides trap sink configuration and methods for sending notifications
//! from an agent to configured destinations.

use std::net::SocketAddr;
use std::sync::RwLock;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::Mutex as AsyncMutex;

use crate::client::{Auth, Client, ClientConfig, CommunityVersion, Retry, UsmAuth};
use crate::error::{Error, Result};
use crate::message::CommunityMessage;
use crate::notification::{DerivedKeys, UsmConfig};
use crate::oid::Oid;
use crate::pdu::Pdu;
use crate::transport::{UdpHandle, UdpTransport};
use crate::v3::compute_engine_boots_time;
use crate::varbind::VarBind;
use crate::version::Version;

/// A configured notification destination.
///
/// Stores resolved credentials and cached keys for sending traps and informs
/// to a specific target.
pub(crate) struct TrapSink {
    pub(crate) dest: SocketAddr,
    pub(crate) version: Version,
    pub(crate) community: Bytes,
    pub(crate) v3_security: Option<UsmConfig>,
    /// Keys derived against the agent's engine_id for V3 trap sending.
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
        match auth {
            Auth::Community { version, community } => {
                let snmp_version = match version {
                    CommunityVersion::V1 => Version::V1,
                    CommunityVersion::V2c => Version::V2c,
                };
                TrapSink {
                    dest,
                    version: snmp_version,
                    community: Bytes::copy_from_slice(community.as_bytes()),
                    v3_security: None,
                    derived_keys: RwLock::new(None),
                    inform_timeout,
                    inform_retry,
                    inform_client: AsyncMutex::new(None),
                }
            }
            Auth::Usm(usm) => {
                let security = resolve_usm_config(&usm);
                TrapSink {
                    dest,
                    version: Version::V3,
                    community: Bytes::new(),
                    v3_security: Some(security),
                    derived_keys: RwLock::new(None),
                    inform_timeout,
                    inform_retry,
                    inform_client: AsyncMutex::new(None),
                }
            }
        }
    }

    /// Ensure keys are derived against the given engine_id for V3 trap sending.
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

        let config = match self.version {
            Version::V1 => unreachable!("v1 does not support informs"),
            Version::V2c => ClientConfig {
                version: Version::V2c,
                community: self.community.clone(),
                timeout: self.inform_timeout,
                retry: self.inform_retry.clone(),
                v3_security: None,
                ..ClientConfig::default()
            },
            Version::V3 => ClientConfig {
                version: Version::V3,
                community: Bytes::new(),
                timeout: self.inform_timeout,
                retry: self.inform_retry.clone(),
                v3_security: self.v3_security.clone(),
                ..ClientConfig::default()
            },
        };

        let bind_addr = if self.dest.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let transport = UdpTransport::bind(bind_addr).await?;
        let handle = transport.handle(self.dest);
        let client = Client::new(handle, config);
        *guard = Some((transport, client.clone()));
        Ok(client)
    }
}

/// Convert UsmAuth (builder-level) to UsmConfig (runtime-level).
fn resolve_usm_config(usm: &UsmAuth) -> UsmConfig {
    let mut security = UsmConfig::new(Bytes::copy_from_slice(usm.username.as_bytes()));
    if let Some(context_name) = &usm.context_name {
        security = security.context_name(Bytes::copy_from_slice(context_name.as_bytes()));
    }

    if let Some(ref master_keys) = usm.master_keys {
        security = security.with_master_keys(master_keys.clone());
    } else {
        if let (Some(auth_proto), Some(auth_pass)) = (usm.auth_protocol, &usm.auth_password) {
            security = security.auth(auth_proto, auth_pass.as_bytes());
        }
        if let (Some(priv_proto), Some(priv_pass)) = (usm.priv_protocol, &usm.priv_password) {
            security = security.privacy(priv_proto, priv_pass.as_bytes());
        }
    }

    security
}

impl super::Agent {
    /// Send a trap to all configured trap sinks.
    ///
    /// Constructs a TrapV2 PDU with the mandatory sysUpTime.0 and snmpTrapOID.0
    /// prefix and sends it to each destination. Fire-and-forget: no response
    /// expected.
    ///
    /// V1 trap sinks receive a converted v1 trap (RFC 3584 Section 3.2).
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
    /// // Send coldStart trap to all sinks
    /// agent.send_trap(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), 0, vec![]).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_trap(
        &self,
        trap_oid: &Oid,
        uptime: u32,
        varbinds: Vec<VarBind>,
    ) -> Result<()> {
        let sinks = &self.inner.trap_sinks;
        if sinks.is_empty() {
            return Ok(());
        }

        let request_id = self.next_notification_id();
        let pdu = Pdu::trap_v2(request_id, uptime, trap_oid, varbinds);

        for sink in sinks {
            if let Err(e) = self.send_trap_to_sink(sink, &pdu).await {
                tracing::warn!(target: "async_snmp::agent", { snmp.dest = %sink.dest, error = %e }, "failed to send trap");
            }
        }

        Ok(())
    }

    /// Send an inform to all configured trap sinks.
    ///
    /// Constructs an InformRequest PDU and sends it to each destination,
    /// waiting for acknowledgement from each. Reuses a cached client per
    /// sink for the request/response exchange.
    ///
    /// V1 trap sinks are skipped (v1 does not support informs).
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
    /// // Send warmStart inform to all sinks (waits for acknowledgement)
    /// agent.send_inform(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2), 0, vec![]).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_inform(
        &self,
        trap_oid: &Oid,
        uptime: u32,
        varbinds: Vec<VarBind>,
    ) -> Result<()> {
        let sinks = &self.inner.trap_sinks;
        if sinks.is_empty() {
            return Ok(());
        }

        for sink in sinks {
            if sink.version == Version::V1 {
                continue;
            }

            if let Err(e) = self
                .send_inform_to_sink(sink, trap_oid, uptime, &varbinds)
                .await
            {
                tracing::warn!(target: "async_snmp::agent", { snmp.dest = %sink.dest, error = %e }, "failed to send inform");
            }
        }

        Ok(())
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
                let msg = CommunityMessage::v1_trap(sink.community.clone(), trap);
                msg.encode()
            }
            Version::V2c => {
                let msg = CommunityMessage::new(Version::V2c, sink.community.clone(), pdu.clone());
                msg.encode()
            }
            Version::V3 => {
                let security = sink.v3_security.as_ref().ok_or_else(|| {
                    Error::Config("V3 security not configured for trap sink".into()).boxed()
                })?;

                sink.ensure_keys_derived(&self.inner.engine_id)?;
                let derived = sink.derived_keys.read().map_err(|_| {
                    Error::Config("trap sink derived_keys lock poisoned".into()).boxed()
                })?;

                let elapsed_secs = self.inner.engine_start.elapsed().as_secs();
                let (engine_boots, engine_time) =
                    compute_engine_boots_time(self.inner.engine_boots_base, elapsed_secs);

                let msg_id = self.next_notification_id();
                let encoded = crate::v3::encode::encode_v3_message(
                    pdu,
                    msg_id,
                    &self.inner.engine_id,
                    engine_boots,
                    engine_time,
                    security,
                    derived.as_ref(),
                    &self.inner.salt_counter,
                    false, // reportable=false for traps
                    crate::v3::DEFAULT_MSG_MAX_SIZE,
                )?;
                Bytes::from(encoded)
            }
        };

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
        static COUNTER: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(1);
        COUNTER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(if v >= i32::MAX { 1 } else { v + 1 })
            })
            .unwrap_or(1)
    }
}
