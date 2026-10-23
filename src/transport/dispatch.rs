//! Preparation-time roles and bounded complete-message classification.
//!
//! Classification authenticates/decrypts without publishing timeliness or Reports.
//! Exactly one selected application then performs its ordered security processing;
//! client candidates retain their exchange-specific validation. Failure never tries
//! another credential context. Application roles on one endpoint share USM users.
use super::{
    CorrelationEnvelope, ReceivedMessage, RequestRegistration, ingress::ApplicationIngress,
    udp_core::UdpCore,
};
use crate::message::{CommunityMessage, RawMsgData, RawV3Message, decode_scoped_pdu};
use crate::v3::{UsmSecurityParams, UsmUser};
use crate::{Error, PduType, Result, Version};
use bytes::Bytes;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

pub(crate) struct DispatchRoles {
    pub(crate) commands: Option<ApplicationIngress>,
    pub(crate) notifications: Option<crate::notification::NotificationProcessor>,
    pub(crate) users: HashMap<Bytes, UsmUser>,
    pub(crate) client_exchanges: bool,
    application: Arc<Semaphore>,
    exchanges: Arc<Semaphore>,
    application_bytes: Arc<Semaphore>,
    exchange_bytes: Arc<Semaphore>,
    peer_exchange_bytes: Mutex<HashMap<SocketAddr, Weak<Semaphore>>>,
}
impl DispatchRoles {
    pub(crate) fn new(
        commands: Option<ApplicationIngress>,
        notifications: Option<crate::notification::NotificationProcessor>,
        users: HashMap<Bytes, UsmUser>,
        client_exchanges: bool,
        application_limit: usize,
    ) -> Self {
        Self {
            commands,
            notifications,
            users,
            client_exchanges,
            application: Arc::new(Semaphore::new(application_limit)),
            exchanges: Arc::new(Semaphore::new(64)),
            application_bytes: Arc::new(Semaphore::new(
                application_limit
                    .saturating_mul(crate::UDP_RECEIVE_BUFFER_SIZE)
                    .min(4 * 1024 * 1024),
            )),
            exchange_bytes: Arc::new(Semaphore::new(4 * 1024 * 1024)),
            peer_exchange_bytes: Mutex::new(HashMap::new()),
        }
    }
    pub(crate) fn validate_registration(&self, registration: &RequestRegistration) -> Result<()> {
        if !self.client_exchanges {
            return Err(Error::Config(
                "client exchanges were not enabled during endpoint preparation".into(),
            )
            .boxed());
        }
        if let Some(context) = &registration.classification_security
            && let Some(user) = self.users.get(context.usm.username())
            && !user.supports_outbound_credentials(&context.usm)?
        {
            return Err(Error::Config("shared endpoint USM identity has conflicting client credentials; use a distinct identity or endpoint".into()).boxed());
        }
        Ok(())
    }
    fn note_drop(&self) {
        if let Some(commands) = &self.commands {
            commands
                .drops
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else if let Some(notifications) = &self.notifications {
            notifications.note_overload();
        }
    }
    fn peer_response_budget(&self, peer: SocketAddr) -> Option<Arc<Semaphore>> {
        let mut peers = self.peer_exchange_bytes.lock().unwrap();
        if let Some(budget) = peers.get(&peer).and_then(Weak::upgrade) {
            return Some(budget);
        }
        if peers.len() >= 1024 {
            peers.retain(|_, budget| budget.strong_count() != 0);
        }
        if peers.len() >= 1024 {
            return None;
        }
        let budget = Arc::new(Semaphore::new(1024 * 1024));
        peers.insert(peer, Arc::downgrade(&budget));
        Some(budget)
    }
    pub(crate) fn dispatch(
        self: &Arc<Self>,
        message: ReceivedMessage,
        core: Arc<UdpCore>,
        tasks: &mut JoinSet<()>,
    ) {
        let envelope = CorrelationEnvelope::parse(&message.bytes);
        let registration = if self.client_exchanges {
            envelope.and_then(|e| {
                e.request_id(&message.bytes).and_then(|id| {
                    core.candidate_registration(id, &message.bytes, e, message.info.peer_addr())
                })
            })
        } else {
            None
        };
        let candidate = registration.is_some();
        let slots = if candidate {
            &self.exchanges
        } else {
            &self.application
        };
        let budget = if candidate {
            &self.exchange_bytes
        } else {
            &self.application_bytes
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            message.observe(super::MessageDisposition::Overloaded);
            self.note_drop();
            return;
        };
        let Ok(buffer) = budget
            .clone()
            .try_acquire_many_owned(message.bytes.len() as u32)
        else {
            message.observe(super::MessageDisposition::Overloaded);
            self.note_drop();
            return;
        };
        let peer_buffer = if candidate {
            let Some(budget) = self.peer_response_budget(message.info.peer_addr()) else {
                message.observe(super::MessageDisposition::Overloaded);
                self.note_drop();
                return;
            };
            let Ok(permit) = budget.try_acquire_many_owned(message.bytes.len() as u32) else {
                message.observe(super::MessageDisposition::Overloaded);
                self.note_drop();
                return;
            };
            Some(permit)
        } else {
            None
        };
        let roles = self.clone();
        tasks.spawn(async move {
            let mut client_context = candidate;
            let class = roles.classify(
                &message,
                registration.as_ref(),
                envelope,
                &mut client_context,
            );
            let is_response = matches!(class, Ok(Some(PduType::Response | PduType::Report)));
            if is_response || (client_context && !matches!(class, Ok(Some(_)))) {
                if candidate
                    && let Some(envelope) = envelope
                    && let Some(id) = envelope.request_id(&message.bytes)
                {
                    core.deliver_parsed_buffered(
                        id,
                        envelope,
                        message.bytes,
                        message.info,
                        super::framing::BufferPermits {
                            _local: buffer,
                            _shared: peer_buffer,
                        },
                    );
                } else {
                    message.observe(super::MessageDisposition::Unmatched);
                }
                return;
            }
            // Correlation is only a classification allowance. Application work
            // must obtain its own admission before releasing that allowance.
            let (_slot, _buffer) = if candidate {
                let Ok(app_slot) = roles.application.clone().try_acquire_owned() else {
                    message.observe(super::MessageDisposition::Overloaded);
                    roles.note_drop();
                    return;
                };
                let Ok(app_buffer) = roles
                    .application_bytes
                    .clone()
                    .try_acquire_many_owned(message.bytes.len() as u32)
                else {
                    message.observe(super::MessageDisposition::Overloaded);
                    roles.note_drop();
                    return;
                };
                drop(slot);
                drop(buffer);
                drop(peer_buffer);
                (app_slot, app_buffer)
            } else {
                (slot, buffer)
            };
            let commands = roles
                .commands
                .as_ref()
                .filter(|commands| commands.is_enabled());
            match class {
                Ok(Some(PduType::TrapV1 | PduType::TrapV2 | PduType::InformRequest)) => {
                    if let Some(processor) = &roles.notifications {
                        processor.process(message).await;
                    } else if let Some(commands) = commands {
                        commands.deliver_udp(message);
                    } else {
                        message.observe(super::MessageDisposition::Disabled);
                    }
                }
                Ok(Some(_)) => {
                    if let Some(commands) = commands {
                        commands.deliver_udp(message);
                    } else if let Some(processor) = &roles.notifications {
                        processor.process(message).await;
                    } else {
                        message.observe(super::MessageDisposition::Disabled);
                    }
                }
                // Unresolved application security needs the combined local /
                // remote authority rules when notifications are registered.
                // This is one selected context, with no second application try.
                Err(_) | Ok(None) => {
                    if let Some(processor) = roles
                        .notifications
                        .as_ref()
                        .filter(|processor| processor.is_enabled())
                    {
                        processor.process(message).await;
                    } else if let Some(commands) = commands {
                        commands.deliver_udp(message);
                    } else {
                        message.observe(super::MessageDisposition::Disabled);
                    }
                }
            }
        });
    }
    /// TCP reuses frame/session/service byte permits rather than UDP classifier
    /// budgets. Admission pauses occur between complete frames, outside peer
    /// framing deadlines. Mixed-role sessions fail immediately on app overload.
    pub(crate) async fn dispatch_tcp(
        self: &Arc<Self>,
        message: ReceivedMessage,
        buffers: super::framing::BufferPermits,
        core: Arc<UdpCore>,
        ingress: &ApplicationIngress,
        tasks: &mut JoinSet<()>,
    ) -> Result<()> {
        let envelope = CorrelationEnvelope::parse(&message.bytes);
        let registration = if self.client_exchanges {
            envelope.and_then(|e| {
                e.request_id(&message.bytes).and_then(|id| {
                    core.candidate_registration(id, &message.bytes, e, message.info.peer_addr())
                })
            })
        } else {
            None
        };
        let mut client_context = registration.is_some();
        let class = self.classify(
            &message,
            registration.as_ref(),
            envelope,
            &mut client_context,
        );
        if matches!(class, Ok(Some(PduType::Response | PduType::Report)))
            || (client_context && !matches!(class, Ok(Some(_))))
        {
            if registration.is_some()
                && let Some(envelope) = envelope
                && let Some(id) = envelope.request_id(&message.bytes)
            {
                core.deliver_parsed_buffered(id, envelope, message.bytes, message.info, buffers);
            } else {
                message.observe(super::MessageDisposition::Unmatched);
            }
            return Ok(());
        }
        let needs_delivery = matches!(
            class,
            Ok(Some(
                PduType::TrapV1 | PduType::TrapV2 | PduType::InformRequest
            ))
        );
        let commands = self.commands.as_ref().filter(|role| role.is_enabled());
        let notification = match class {
            Ok(Some(PduType::TrapV1 | PduType::TrapV2 | PduType::InformRequest)) => {
                self.notifications.as_ref()
            }
            Ok(Some(_)) if commands.is_some() => None,
            Ok(Some(_)) => self.notifications.as_ref(),
            Err(_) | Ok(None) => self.notifications.as_ref().filter(|role| role.is_enabled()),
        };
        let observation = message.reply.observation().clone();
        let info = message.info;
        let target = message.info.peer_addr();
        let session = message.info.session_id();
        let admit = async {
            if let Some(processor) = notification {
                if !processor.is_enabled() {
                    message.observe(super::MessageDisposition::Disabled);
                    return Ok::<(), Box<Error>>(());
                }
                let admission = async {
                    let slot = acquire_tcp(self.application.clone(), self.client_exchanges).await?;
                    let session_slot = if let Some(limit) = &ingress.session {
                        Some(acquire_tcp(limit.clone(), self.client_exchanges).await?)
                    } else {
                        None
                    };
                    let admission = if needs_delivery {
                        let Some(admission) = processor.reserve_tcp(self.client_exchanges).await?
                        else {
                            message.observe(super::MessageDisposition::Disabled);
                            return Ok::<(), Box<Error>>(());
                        };
                        admission
                    } else {
                        crate::notification::NotificationAdmission::default()
                    };
                    let work = processor.process_admitted(message, admission);
                    tasks.spawn(async move {
                        let (_slot, _session_slot, _buffers) = (slot, session_slot, buffers);
                        work.await;
                    });
                    Ok::<(), Box<Error>>(())
                };
                tokio::select! { biased;
                    () = processor.admission_closed() => { observation.disposition(info, super::MessageDisposition::Disabled); },
                    result = admission => result?,
                }
            } else if commands.is_some() {
                ingress
                    .deliver_tcp(message, buffers, self.client_exchanges)
                    .await?;
            } else {
                message.observe(super::MessageDisposition::Disabled);
            }
            Ok(())
        };
        let result = match tokio::time::timeout(ingress.overload_timeout, admit).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(Error::Network {
                target,
                source: std::io::Error::other(format!(
                    "TCP session {session:?} admission failed: {error}"
                )),
            }
            .boxed()),
            Err(_) => Err(Error::Network {
                target,
                source: std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("TCP session {session:?} admission overload deadline"),
                ),
            }
            .boxed()),
        };
        if result.is_err() && notification.is_some() {
            // Admission errors race with consumer/role closure. An independently
            // disabled role does not make a shared session overloaded.
            if notification.is_some_and(|processor| !processor.is_enabled()) {
                observation.disposition(info, super::MessageDisposition::Disabled);
                return Ok(());
            }
            observation.disposition(info, super::MessageDisposition::Overloaded);
        }
        result
    }
    fn classify(
        &self,
        message: &ReceivedMessage,
        registration: Option<&RequestRegistration>,
        envelope: Option<CorrelationEnvelope>,
        client_context: &mut bool,
    ) -> Result<Option<PduType>> {
        let decode = crate::DecodeConfig {
            malformed_exception_payloads: true,
            ..crate::DecodeConfig::DEFAULT
        };
        let source = message.info.peer_addr();
        match crate::message::peek_version(message.bytes.clone(), source)? {
            Version::V1 | Version::V2c => {
                let decoded = CommunityMessage::decode_with_target(
                    message.bytes.clone(),
                    Some(source),
                    decode,
                )?;
                Ok(Some(match decoded.value.pdu() {
                    crate::message::CommunityPdu::TrapV1(_) => PduType::TrapV1,
                    crate::message::CommunityPdu::Standard(pdu) => pdu.pdu_type(),
                }))
            }
            Version::V3 => {
                let raw = RawV3Message::decode_bounded_with_target(
                    message.bytes.clone(),
                    message.reply.limits.receive.accepted(),
                    source,
                    decode,
                )?
                .value;
                let usm = UsmSecurityParams::decode_with_context(
                    raw.security_params.clone(),
                    raw.security_params_offset,
                    source,
                    decode,
                )?
                .value;
                let level = raw.security_level();
                // Failure ownership follows the pending exchange's security
                // identity, including its known authoritative engine. Sharing a
                // user's keys does not turn a rejected response into a request.
                *client_context = registration.is_some_and(|registration| {
                    registration
                        .classification_security
                        .as_ref()
                        .is_none_or(|context| {
                            context.usm.username() == &usm.username
                                && context
                                    .engine_id
                                    .as_ref()
                                    .is_none_or(|id| id == &usm.engine_id)
                        })
                });
                // Plaintext only supplies an untrusted class; the selected role
                // performs all security checks before user-visible acceptance.
                if let RawMsgData::Plaintext { data, offset } = &raw.msg_data {
                    return Ok(Some(
                        decode_scoped_pdu(data.clone(), *offset, source, None, decode)?
                            .value
                            .pdu
                            .pdu_type(),
                    ));
                }
                let keys = if let Some(user) = self.users.get(&usm.username) {
                    user.derive_keys(&usm.engine_id)
                } else if let Some(config) = registration
                    .and_then(|r| r.classification_security.as_ref())
                    .map(|context| &context.usm)
                    .filter(|c| c.username() == &usm.username)
                {
                    config.derive_keys_inner(&usm.engine_id)
                } else {
                    *client_context = registration.is_some();
                    return Ok(None);
                }
                .map_err(|_| Error::Auth { target: source }.boxed())?;
                let auth = keys
                    .auth_key
                    .as_ref()
                    .ok_or_else(|| Error::Auth { target: source }.boxed())?;
                let (offset, length) = UsmSecurityParams::find_auth_params_offset(&message.bytes)
                    .ok_or_else(|| Error::Auth { target: source }.boxed())?;
                let envelope = envelope.ok_or_else(|| Error::Auth { target: source }.boxed())?;
                if !level.requires_auth()
                    || !crate::v3::auth::verify_message(
                        auth,
                        &message.bytes[..envelope.content_end],
                        offset,
                        length,
                    )
                    .map_err(|_| Error::Auth { target: source }.boxed())?
                {
                    return Err(Error::Auth { target: source }.boxed());
                }
                let key = keys
                    .priv_key
                    .as_ref()
                    .ok_or_else(|| Error::Auth { target: source }.boxed())?;
                let RawMsgData::Encrypted(data) = &raw.msg_data else {
                    unreachable!()
                };
                let decrypted = key
                    .decrypt(data, usm.engine_boots, usm.engine_time, &usm.priv_params)
                    .map_err(|_| Error::Auth { target: source }.boxed())?;
                Ok(Some(
                    decode_scoped_pdu(decrypted, 0, source, Some(key.protocol()), decode)?
                        .value
                        .pdu
                        .pdu_type(),
                ))
            }
        }
    }
}

async fn acquire_tcp(
    limit: Arc<Semaphore>,
    fail_fast: bool,
) -> Result<tokio::sync::OwnedSemaphorePermit> {
    if fail_fast {
        limit
            .try_acquire_owned()
            .map_err(|_| Error::Config("TCP application capacity exhausted".into()).boxed())
    } else {
        limit
            .acquire_owned()
            .await
            .map_err(|_| Error::Config("TCP application admission closed".into()).boxed())
    }
}
