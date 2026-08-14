//! Scripted SNMPv3 peers and packet builders for adversarial client tests.

use async_snmp::ber::{Decoder, EncodeBuf};
use async_snmp::message::{
    MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, V3Message, V3MessageData,
};
use async_snmp::pdu::{Pdu, PduBody, PduType, ResponsePdu};
use async_snmp::transport::Transport;
use async_snmp::v3::auth::{authenticate_message, verify_message};
use async_snmp::v3::{SaltCounter, UsmSecurityParams};
use async_snmp::{Error, Oid, ReceiveLimits, UDP_RECEIVE_LIMITS, UsmConfig, Value, VarBind};
use bytes::Bytes;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// An authoritative engine profile used to decode requests and build replies.
#[derive(Clone)]
pub struct TestV3Engine {
    pub engine_id: Bytes,
    pub engine_boots: u32,
    pub engine_time: u32,
    pub msg_max_size: i32,
    pub users: Vec<UsmConfig>,
    salt: Arc<SaltCounter>,
}

impl TestV3Engine {
    pub fn new(engine_id: impl Into<Bytes>) -> Self {
        Self {
            engine_id: engine_id.into(),
            engine_boots: 1,
            engine_time: 1,
            msg_max_size: 65_507,
            users: Vec::new(),
            salt: Arc::new(SaltCounter::new().unwrap()),
        }
    }

    pub fn boots_time(mut self, engine_boots: u32, engine_time: u32) -> Self {
        self.engine_boots = engine_boots;
        self.engine_time = engine_time;
        self
    }

    pub fn user(mut self, user: UsmConfig) -> Self {
        self.users.push(user);
        self
    }

    fn user_for(&self, username: &[u8]) -> Option<&UsmConfig> {
        self.users
            .iter()
            .find(|user| user.username().as_ref() == username)
    }
}

/// Decoded fields and exact bytes from one request received by a test peer.
#[derive(Clone, Debug)]
pub struct CapturedV3Request {
    pub raw: Bytes,
    pub source: SocketAddr,
    /// The ID passed to `Transport::request`; network peers leave this unset.
    pub transport_request_id: Option<i32>,
    pub global_data: MsgGlobalData,
    pub usm: UsmSecurityParams,
    pub wire_data: V3MessageData,
    pub scoped_pdu: Option<ScopedPdu>,
    /// `None` for noAuthNoPriv, otherwise whether the received HMAC verified.
    pub authentication_valid: Option<bool>,
}

impl CapturedV3Request {
    fn decode(
        raw: Bytes,
        source: SocketAddr,
        transport_request_id: Option<i32>,
        engine: &TestV3Engine,
    ) -> Result<Self, String> {
        let message = V3Message::decode(raw.clone(), async_snmp::DecodeConfig::default())
            .map_err(|error| error.to_string())?
            .value;
        let usm = UsmSecurityParams::decode(
            message.security_params().clone(),
            async_snmp::DecodeConfig::default(),
        )
        .map_err(|error| error.to_string())?
        .value;
        let level = message.global_data().msg_flags().security_level;

        let keys = engine
            .user_for(usm.username())
            .map(|user| user.derive_keys(usm.engine_id()))
            .transpose()
            .map_err(|error| error.to_string())?;

        let authentication_valid = if level.requires_auth() {
            let valid = keys
                .as_ref()
                .and_then(|keys| keys.auth_key.as_ref())
                .and_then(|key| {
                    UsmSecurityParams::find_auth_params_offset(&raw)
                        .map(|(offset, len)| verify_message(key, &raw, offset, len))
                })
                .transpose()
                .map_err(|error| error.to_string())?
                .unwrap_or(false);
            Some(valid)
        } else {
            None
        };

        let scoped_pdu = match message.data() {
            V3MessageData::Plaintext(scoped) => Some(scoped.clone()),
            V3MessageData::Encrypted(ciphertext) => {
                let priv_key = keys
                    .as_ref()
                    .and_then(|keys| keys.priv_key.as_ref())
                    .ok_or_else(|| "no privacy key available for encrypted request".to_string())?;
                let plaintext = priv_key
                    .decrypt(
                        ciphertext,
                        usm.engine_boots(),
                        usm.engine_time(),
                        usm.priv_params(),
                    )
                    .map_err(|error| error.to_string())?;
                let mut decoder = Decoder::new(plaintext);
                Some(ScopedPdu::decode(&mut decoder).map_err(|error| error.to_string())?)
            }
        };

        Ok(Self {
            raw,
            source,
            transport_request_id,
            global_data: message.global_data().clone(),
            usm,
            wire_data: message.data().clone(),
            scoped_pdu,
            authentication_valid,
        })
    }
}

/// Shared request log retained after a peer has stopped.
#[derive(Clone, Default)]
pub struct V3RequestLog(Arc<Mutex<Vec<CapturedV3Request>>>);

impl V3RequestLog {
    pub fn snapshot(&self) -> Vec<CapturedV3Request> {
        self.0.lock().unwrap().clone()
    }

    pub fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    fn push(&self, request: CapturedV3Request) {
        self.0.lock().unwrap().push(request);
    }
}

fn encode_raw_scoped_pdu(scoped: &ScopedPdu) -> Result<Bytes, String> {
    encode_raw_scoped_pdu_with_first_integer(scoped, None)
}

fn encode_raw_scoped_pdu_with_first_integer(
    scoped: &ScopedPdu,
    first_integer_value_content: Option<&[u8]>,
) -> Result<Bytes, String> {
    let (tag, first_field, second_field) = match scoped.pdu.raw_body() {
        PduBody::Standard {
            pdu_type,
            error_status,
            error_index,
        } => (pdu_type.pdu_type().tag(), *error_status, *error_index),
        PduBody::GetBulk {
            non_repeaters,
            max_repetitions,
        } => (
            PduType::GetBulkRequest.tag(),
            i32::try_from(*non_repeaters)
                .map_err(|_| "GETBULK non_repeaters exceeds i32::MAX".to_owned())?,
            i32::try_from(*max_repetitions)
                .map_err(|_| "GETBULK max_repetitions exceeds i32::MAX".to_owned())?,
        ),
    };

    let mut buf = EncodeBuf::new();
    buf.push_sequence(|buf| {
        buf.push_constructed(tag, |buf| {
            buf.push_sequence(|buf| {
                for (index, varbind) in scoped.pdu.varbinds().iter().enumerate().rev() {
                    if index == 0
                        && let Some(content) = first_integer_value_content
                    {
                        buf.push_sequence(|buf| {
                            buf.push_bytes(&raw_ber::integer_from_content(content));
                            buf.push_oid(&varbind.oid)
                        })?;
                    } else {
                        varbind.encode(buf)?;
                    }
                }
                Ok(())
            })?;
            buf.push_integer(second_field);
            buf.push_integer(first_field);
            buf.push_integer(scoped.pdu.request_id());
            Ok(())
        })?;
        buf.push_octet_string(&scoped.context_name)?;
        buf.push_octet_string(&scoped.context_engine_id)?;
        Ok(())
    })
    .map_err(|error| error.to_string())?;
    Ok(buf.finish())
}

fn encode_raw_usm(
    engine_id: &[u8],
    engine_boots: u32,
    engine_time: u32,
    username: &[u8],
    auth_params: &[u8],
    priv_params: &[u8],
) -> Bytes {
    let mut buf = EncodeBuf::new();
    buf.push_sequence(|buf| {
        buf.push_octet_string(priv_params)?;
        buf.push_octet_string(auth_params)?;
        buf.push_octet_string(username)?;
        buf.push_unsigned32(async_snmp::ber::tag::universal::INTEGER, engine_time);
        buf.push_unsigned32(async_snmp::ber::tag::universal::INTEGER, engine_boots);
        buf.push_octet_string(engine_id)
    })
    .unwrap();
    buf.finish()
}

fn encode_raw_plaintext_message(
    global: &MsgGlobalData,
    security_params: &[u8],
    scoped: &ScopedPdu,
) -> Result<Vec<u8>, String> {
    let scoped = encode_raw_scoped_pdu(scoped)?;
    encode_raw_plaintext_message_bytes(global, security_params, &scoped)
}

fn encode_raw_plaintext_message_bytes(
    global: &MsgGlobalData,
    security_params: &[u8],
    scoped: &[u8],
) -> Result<Vec<u8>, String> {
    let mut buf = EncodeBuf::new();
    buf.push_sequence(|buf| {
        buf.push_bytes(scoped);
        buf.push_octet_string(security_params)?;
        global.encode(buf)?;
        buf.push_integer(3);
        Ok(())
    })
    .map_err(|error| error.to_string())?;
    Ok(buf.finish().to_vec())
}

fn encode_raw_encrypted_message(
    global: &MsgGlobalData,
    security_params: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let mut buf = EncodeBuf::new();
    buf.push_sequence(|buf| {
        buf.push_octet_string(ciphertext)?;
        buf.push_octet_string(security_params)?;
        global.encode(buf)?;
        buf.push_integer(3);
        Ok(())
    })
    .map_err(|error| error.to_string())?;
    Ok(buf.finish().to_vec())
}

/// Builder for a valid response whose individual correlation/security fields
/// can be changed independently. Adversarial field combinations use a test-only
/// raw encoder so production structured encoders remain canonical.
pub struct V3ReplyBuilder {
    msg_id: i32,
    msg_max_size: i32,
    security_level: SecurityLevel,
    reportable: bool,
    raw_msg_flags: Option<u8>,
    engine_id: Bytes,
    engine_boots: u32,
    engine_time: u32,
    username: Bytes,
    auth_params_override: Option<Bytes>,
    priv_params_override: Option<Bytes>,
    signing_user: Option<UsmConfig>,
    key_engine_id: Option<Bytes>,
    ciphertext_override: Option<Bytes>,
    first_integer_value_content_override: Option<Bytes>,
    context_engine_id: Bytes,
    context_name: Bytes,
    pdu: Pdu,
    salt: Arc<SaltCounter>,
}

impl V3ReplyBuilder {
    pub fn response_to(request: &CapturedV3Request, engine: &TestV3Engine) -> Self {
        let scoped = request
            .scoped_pdu
            .as_ref()
            .expect("response requires a decoded request scopedPDU");
        Self {
            msg_id: request.global_data.msg_id(),
            msg_max_size: engine.msg_max_size,
            security_level: request.global_data.msg_flags().security_level,
            reportable: false,
            raw_msg_flags: None,
            engine_id: engine.engine_id.clone(),
            engine_boots: engine.engine_boots,
            engine_time: engine.engine_time,
            username: request.usm.username().clone(),
            auth_params_override: None,
            priv_params_override: None,
            signing_user: engine.user_for(request.usm.username()).cloned(),
            key_engine_id: None,
            ciphertext_override: None,
            first_integer_value_content_override: None,
            context_engine_id: scoped.context_engine_id.clone(),
            context_name: scoped.context_name.clone(),
            pdu: ResponsePdu::success(
                async_snmp::Version::V3,
                scoped.pdu.request_id(),
                scoped.pdu.varbinds().to_vec(),
            )
            .unwrap()
            .into_raw(),
            salt: engine.salt.clone(),
        }
    }

    pub fn report_to(
        request: &CapturedV3Request,
        engine: &TestV3Engine,
        oid: Oid,
        counter: u32,
    ) -> Self {
        let mut builder = Self::response_to(request, engine);
        builder.security_level = SecurityLevel::NoAuthNoPriv;
        // Reports default to the reporting entity's context, not the request context.
        builder.context_engine_id = engine.engine_id.clone();
        builder.context_name = Bytes::new();
        builder.pdu = ResponsePdu::report(0, vec![VarBind::new(oid, Value::Counter32(counter))])
            .unwrap()
            .into_raw();
        builder
    }

    pub fn msg_id(mut self, msg_id: i32) -> Self {
        self.msg_id = msg_id;
        self
    }

    pub fn msg_max_size(mut self, msg_max_size: i32) -> Self {
        self.msg_max_size = msg_max_size;
        self
    }

    pub fn security_level(mut self, security_level: SecurityLevel) -> Self {
        self.security_level = security_level;
        self
    }

    pub fn reportable(mut self, reportable: bool) -> Self {
        self.reportable = reportable;
        self
    }

    /// Override the encoded flags byte after ordinary message construction.
    /// This permits reserved bits and invalid priv-without-auth packets.
    pub fn raw_msg_flags(mut self, raw_msg_flags: u8) -> Self {
        self.raw_msg_flags = Some(raw_msg_flags);
        self
    }

    pub fn engine_id(mut self, engine_id: impl Into<Bytes>) -> Self {
        self.engine_id = engine_id.into();
        self
    }

    pub fn engine_boots(mut self, engine_boots: u32) -> Self {
        self.engine_boots = engine_boots;
        self
    }

    pub fn engine_time(mut self, engine_time: u32) -> Self {
        self.engine_time = engine_time;
        self
    }

    pub fn username(mut self, username: impl Into<Bytes>) -> Self {
        self.username = username.into();
        self
    }

    pub fn auth_params(mut self, auth_params: impl Into<Bytes>) -> Self {
        self.auth_params_override = Some(auth_params.into());
        self
    }

    pub fn priv_params(mut self, priv_params: impl Into<Bytes>) -> Self {
        self.priv_params_override = Some(priv_params.into());
        self
    }

    /// Select credentials independently from the username put on the wire.
    pub fn signing_user(mut self, signing_user: UsmConfig) -> Self {
        self.signing_user = Some(signing_user);
        self
    }

    /// Localize signing/encryption keys against an engine ID independently
    /// from the authoritative engine ID placed on the wire.
    pub fn key_engine_id(mut self, engine_id: impl Into<Bytes>) -> Self {
        self.key_engine_id = Some(engine_id.into());
        self
    }

    /// Replace authPriv ciphertext after producing valid privacy parameters;
    /// the final message is still authenticated over the replacement bytes.
    pub fn ciphertext(mut self, ciphertext: impl Into<Bytes>) -> Self {
        self.ciphertext_override = Some(ciphertext.into());
        self
    }

    /// Override the first varbind INTEGER BER content.
    pub fn first_integer_value_content(mut self, content: impl Into<Bytes>) -> Self {
        self.first_integer_value_content_override = Some(content.into());
        self
    }

    pub fn context_engine_id(mut self, context_engine_id: impl Into<Bytes>) -> Self {
        self.context_engine_id = context_engine_id.into();
        self
    }

    pub fn context_name(mut self, context_name: impl Into<Bytes>) -> Self {
        self.context_name = context_name.into();
        self
    }

    pub fn pdu_type(mut self, pdu_type: PduType) -> Self {
        let (request_id, body, varbinds) = self.pdu.into_raw_parts();
        let PduBody::Standard {
            error_status,
            error_index,
            ..
        } = body
        else {
            panic!("raw reply type mutation requires a standard-layout PDU");
        };
        self.pdu = Pdu::from_raw_parts(
            request_id,
            PduBody::Standard {
                pdu_type: async_snmp::pdu::StandardPduType::try_from(pdu_type).unwrap(),
                error_status,
                error_index,
            },
            varbinds,
        );
        self
    }

    pub fn request_id(mut self, request_id: i32) -> Self {
        let (_, body, varbinds) = self.pdu.into_raw_parts();
        self.pdu = Pdu::from_raw_parts(request_id, body, varbinds);
        self
    }

    pub fn error_status(mut self, error_status: i32) -> Self {
        let (request_id, body, varbinds) = self.pdu.into_raw_parts();
        let PduBody::Standard {
            pdu_type,
            error_index,
            ..
        } = body
        else {
            panic!("raw error-status mutation requires a standard-layout PDU");
        };
        self.pdu = Pdu::from_raw_parts(
            request_id,
            PduBody::Standard {
                pdu_type,
                error_status,
                error_index,
            },
            varbinds,
        );
        self
    }

    pub fn error_index(mut self, error_index: i32) -> Self {
        let (request_id, body, varbinds) = self.pdu.into_raw_parts();
        let PduBody::Standard {
            pdu_type,
            error_status,
            ..
        } = body
        else {
            panic!("raw error-index mutation requires a standard-layout PDU");
        };
        self.pdu = Pdu::from_raw_parts(
            request_id,
            PduBody::Standard {
                pdu_type,
                error_status,
                error_index,
            },
            varbinds,
        );
        self
    }

    pub fn varbinds(mut self, varbinds: Vec<VarBind>) -> Self {
        let (request_id, body, _) = self.pdu.into_raw_parts();
        self.pdu = Pdu::from_raw_parts(request_id, body, varbinds);
        self
    }

    pub fn build(self) -> Result<Bytes, String> {
        let keys = self
            .signing_user
            .as_ref()
            .map(|user| {
                let key_engine_id = self.key_engine_id.as_ref().unwrap_or(&self.engine_id);
                user.derive_keys(key_engine_id)
            })
            .transpose()
            .map_err(|error| error.to_string())?;

        let scoped = ScopedPdu::new(self.context_engine_id, self.context_name, self.pdu);
        let mut auth_params = self.auth_params_override.unwrap_or_default();
        let mut priv_params = self.priv_params_override.unwrap_or_default();

        let msg_max_size = async_snmp::MessageSize::from_i32(self.msg_max_size)
            .map_err(|error| error.to_string())?;
        let global = MsgGlobalData::new(
            self.msg_id,
            msg_max_size,
            MsgFlags::new(self.security_level, self.reportable),
        )
        .map_err(|error| error.to_string())?;
        let mut encoded = if self.security_level.requires_priv() {
            let priv_key = keys
                .as_ref()
                .and_then(|keys| keys.priv_key.as_ref())
                .ok_or_else(|| "no privacy key configured for encrypted reply".to_string())?;
            let scoped_bytes = encode_raw_scoped_pdu_with_first_integer(
                &scoped,
                self.first_integer_value_content_override.as_deref(),
            )?;
            let (ciphertext, generated_priv_params) = priv_key
                .encrypt(
                    &scoped_bytes,
                    self.engine_boots,
                    self.engine_time,
                    &self.salt,
                )
                .map_err(|error| error.to_string())?;
            let ciphertext = self.ciphertext_override.unwrap_or(ciphertext);
            priv_params = generated_priv_params;
            if let Some(auth_key) = keys.as_ref().and_then(|keys| keys.auth_key.as_ref()) {
                auth_params = Bytes::from(vec![0; auth_key.mac_len()]);
            }
            let usm = encode_raw_usm(
                &self.engine_id,
                self.engine_boots,
                self.engine_time,
                &self.username,
                &auth_params,
                &priv_params,
            );
            encode_raw_encrypted_message(&global, &usm, &ciphertext)?
        } else {
            if self.security_level.requires_auth() {
                let auth_key = keys
                    .as_ref()
                    .and_then(|keys| keys.auth_key.as_ref())
                    .ok_or_else(|| {
                        "no authentication key configured for signed reply".to_string()
                    })?;
                auth_params = Bytes::from(vec![0; auth_key.mac_len()]);
            }
            let usm = encode_raw_usm(
                &self.engine_id,
                self.engine_boots,
                self.engine_time,
                &self.username,
                &auth_params,
                &priv_params,
            );
            if self.first_integer_value_content_override.is_some() {
                let scoped = encode_raw_scoped_pdu_with_first_integer(
                    &scoped,
                    self.first_integer_value_content_override.as_deref(),
                )?;
                encode_raw_plaintext_message_bytes(&global, &usm, &scoped)?
            } else {
                encode_raw_plaintext_message(&global, &usm, &scoped)?
            }
        };
        if let Some(flags) = self.raw_msg_flags {
            raw_ber::patch_msg_flags(&mut encoded, flags)?;
        }
        if self.security_level.requires_auth() {
            let auth_key = keys
                .as_ref()
                .and_then(|keys| keys.auth_key.as_ref())
                .ok_or_else(|| "no authentication key configured for signed reply".to_string())?;
            let (offset, len) = UsmSecurityParams::find_auth_params_offset(&encoded)
                .ok_or_else(|| "authentication parameters not found".to_string())?;
            authenticate_message(auth_key, &mut encoded, offset, len)
                .map_err(|error| error.to_string())?;
        }
        Ok(Bytes::from(encoded))
    }
}

enum ScriptOutput {
    Replies(Vec<Bytes>),
    RepliesFromOtherSource(Vec<Bytes>),
    Silence,
    TransportError(Box<Error>),
}

type ScriptFn =
    Box<dyn FnOnce(&CapturedV3Request) -> Result<ScriptOutput, String> + Send + 'static>;

/// One request/reply action consumed in FIFO order.
pub struct ScriptStep(ScriptFn);

impl ScriptStep {
    pub fn reply(
        build: impl FnOnce(&CapturedV3Request) -> Result<Bytes, String> + Send + 'static,
    ) -> Self {
        Self(Box::new(move |request| {
            build(request).map(|reply| ScriptOutput::Replies(vec![reply]))
        }))
    }

    pub fn replies(
        build: impl FnOnce(&CapturedV3Request) -> Result<Vec<Bytes>, String> + Send + 'static,
    ) -> Self {
        Self(Box::new(move |request| {
            build(request).map(ScriptOutput::Replies)
        }))
    }

    pub fn reply_from_other_source(
        build: impl FnOnce(&CapturedV3Request) -> Result<Bytes, String> + Send + 'static,
    ) -> Self {
        Self(Box::new(move |request| {
            build(request).map(|reply| ScriptOutput::RepliesFromOtherSource(vec![reply]))
        }))
    }

    pub fn bytes(bytes: impl Into<Bytes>) -> Self {
        let bytes = bytes.into();
        Self::reply(move |_| Ok(bytes))
    }

    pub fn silence() -> Self {
        Self(Box::new(|_| Ok(ScriptOutput::Silence)))
    }

    pub fn silence_with(observe: impl FnOnce(&CapturedV3Request) + Send + 'static) -> Self {
        Self(Box::new(move |request| {
            observe(request);
            Ok(ScriptOutput::Silence)
        }))
    }

    pub fn transport_error(error: Error) -> Self {
        Self(Box::new(move |_| {
            Ok(ScriptOutput::TransportError(error.boxed()))
        }))
    }

    fn run(self, request: &CapturedV3Request) -> Result<ScriptOutput, String> {
        (self.0)(request)
    }
}

struct PeerState {
    steps: Mutex<VecDeque<ScriptStep>>,
    log: V3RequestLog,
    error: Mutex<Option<String>>,
}

impl PeerState {
    fn new(steps: Vec<ScriptStep>) -> Self {
        Self {
            steps: Mutex::new(steps.into()),
            log: V3RequestLog::default(),
            error: Mutex::new(None),
        }
    }

    fn set_error(&self, error: impl Into<String>) {
        let mut slot = self.error.lock().unwrap();
        if slot.is_none() {
            *slot = Some(error.into());
        }
    }

    fn handle_request(
        &self,
        raw: Bytes,
        source: SocketAddr,
        transport_request_id: Option<i32>,
        engine: &TestV3Engine,
    ) -> Result<(CapturedV3Request, Option<ScriptStep>), String> {
        let request = CapturedV3Request::decode(raw, source, transport_request_id, engine)?;
        self.log.push(request.clone());
        let step = self.steps.lock().unwrap().pop_front();
        Ok((request, step))
    }
}

/// A scripted UDP or TCP SNMPv3 peer.
pub struct ScriptedV3Peer {
    addr: SocketAddr,
    state: Arc<PeerState>,
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl ScriptedV3Peer {
    pub async fn udp(engine: TestV3Engine, steps: Vec<ScriptStep>) -> Self {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = socket.local_addr().unwrap();
        let state = Arc::new(PeerState::new(steps));
        let cancel = CancellationToken::new();
        let task_state = state.clone();
        let task_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            let mut buffer = vec![0_u8; 65_535];
            loop {
                let received = tokio::select! {
                    _ = task_cancel.cancelled() => break,
                    received = socket.recv_from(&mut buffer) => received,
                };
                let (len, source) = match received {
                    Ok(received) => received,
                    Err(error) => {
                        task_state.set_error(format!("UDP receive failed: {error}"));
                        break;
                    }
                };
                let raw = Bytes::copy_from_slice(&buffer[..len]);
                let (request, step) = match task_state.handle_request(raw, source, None, &engine) {
                    Ok(result) => result,
                    Err(error) => {
                        task_state.set_error(format!("request decode failed: {error}"));
                        break;
                    }
                };
                let output = match step {
                    Some(step) => step.run(&request),
                    None => {
                        task_state.set_error("received more requests than the script defines");
                        Ok(ScriptOutput::Replies(vec![correlated_malformed_reply(
                            request.global_data.msg_id(),
                        )]))
                    }
                };
                match output {
                    Ok(ScriptOutput::Replies(replies)) => {
                        for reply in replies {
                            if let Err(error) = socket.send_to(&reply, source).await {
                                task_state.set_error(format!("UDP send failed: {error}"));
                                return;
                            }
                        }
                    }
                    Ok(ScriptOutput::RepliesFromOtherSource(replies)) => {
                        let other = match UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await {
                            Ok(socket) => socket,
                            Err(error) => {
                                task_state.set_error(format!(
                                    "alternate UDP source bind failed: {error}"
                                ));
                                return;
                            }
                        };
                        for reply in replies {
                            if let Err(error) = other.send_to(&reply, source).await {
                                task_state.set_error(format!(
                                    "alternate UDP source send failed: {error}"
                                ));
                                return;
                            }
                        }
                    }
                    Ok(ScriptOutput::Silence) => {}
                    Ok(ScriptOutput::TransportError(error)) => {
                        task_state.set_error(format!(
                            "transport-only script error used by UDP peer: {error}"
                        ));
                        let reply = correlated_malformed_reply(request.global_data.msg_id());
                        let _ = socket.send_to(&reply, source).await;
                    }
                    Err(error) => {
                        task_state.set_error(format!("reply build failed: {error}"));
                        let reply = correlated_malformed_reply(request.global_data.msg_id());
                        let _ = socket.send_to(&reply, source).await;
                    }
                }
            }
        });
        Self {
            addr,
            state,
            cancel,
            task: Some(task),
        }
    }

    pub async fn tcp(engine: TestV3Engine, steps: Vec<ScriptStep>) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(PeerState::new(steps));
        let cancel = CancellationToken::new();
        let task_state = state.clone();
        let task_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            let accepted = tokio::select! {
                _ = task_cancel.cancelled() => return,
                accepted = listener.accept() => accepted,
            };
            let (mut stream, source) = match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    task_state.set_error(format!("TCP accept failed: {error}"));
                    return;
                }
            };
            loop {
                let raw = tokio::select! {
                    _ = task_cancel.cancelled() => break,
                    raw = read_ber_message(&mut stream) => raw,
                };
                let raw = match raw {
                    Ok(raw) => raw,
                    Err(error) => {
                        task_state.set_error(format!("TCP frame read failed: {error}"));
                        break;
                    }
                };
                let (request, step) = match task_state.handle_request(raw, source, None, &engine) {
                    Ok(result) => result,
                    Err(error) => {
                        task_state.set_error(format!("request decode failed: {error}"));
                        break;
                    }
                };
                let output = match step {
                    Some(step) => step.run(&request),
                    None => {
                        task_state.set_error("received more requests than the script defines");
                        Ok(ScriptOutput::Replies(vec![correlated_malformed_reply(
                            request.global_data.msg_id(),
                        )]))
                    }
                };
                match output {
                    Ok(ScriptOutput::Replies(replies)) => {
                        for reply in replies {
                            let result = tokio::select! {
                                _ = task_cancel.cancelled() => return,
                                result = stream.write_all(&reply) => result,
                            };
                            if let Err(error) = result {
                                task_state.set_error(format!("TCP send failed: {error}"));
                                return;
                            }
                        }
                    }
                    Ok(ScriptOutput::RepliesFromOtherSource(_)) => {
                        task_state.set_error(
                            "alternate-source script output is only supported by UDP peers",
                        );
                        return;
                    }
                    Ok(ScriptOutput::Silence) => {}
                    Ok(ScriptOutput::TransportError(error)) => {
                        task_state.set_error(format!(
                            "transport-only script error used by TCP peer: {error}"
                        ));
                        let reply = correlated_malformed_reply(request.global_data.msg_id());
                        let _ = tokio::select! {
                            _ = task_cancel.cancelled() => return,
                            result = stream.write_all(&reply) => result,
                        };
                    }
                    Err(error) => {
                        task_state.set_error(format!("reply build failed: {error}"));
                        let reply = correlated_malformed_reply(request.global_data.msg_id());
                        let _ = tokio::select! {
                            _ = task_cancel.cancelled() => return,
                            result = stream.write_all(&reply) => result,
                        };
                    }
                }
            }
        });
        Self {
            addr,
            state,
            cancel,
            task: Some(task),
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn log(&self) -> V3RequestLog {
        self.state.log.clone()
    }

    pub async fn finish(mut self) -> Result<(), String> {
        self.cancel.cancel();
        if let Some(mut task) = self.task.take() {
            match tokio::time::timeout(Duration::from_secs(1), &mut task).await {
                Ok(result) => result.map_err(|error| error.to_string())?,
                Err(_) => {
                    task.abort();
                    return Err("peer task did not stop after cancellation".to_string());
                }
            }
        }
        if let Some(error) = self.state.error.lock().unwrap().take() {
            return Err(error);
        }
        let remaining = self.state.steps.lock().unwrap().len();
        if remaining != 0 {
            return Err(format!("script finished with {remaining} unconsumed steps"));
        }
        Ok(())
    }
}

impl Drop for ScriptedV3Peer {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

struct ScriptedTransportInner {
    engine: TestV3Engine,
    state: PeerState,
    peer: SocketAddr,
    local: SocketAddr,
    next_id: AtomicI32,
    reliable: bool,
    receive_limits: ReceiveLimits,
}

/// A custom transport that deliberately returns the next scripted bytes
/// without filtering them by the `request_id` argument.
#[derive(Clone)]
pub struct ScriptedTransport(Arc<ScriptedTransportInner>);

impl ScriptedTransport {
    pub fn new(
        engine: TestV3Engine,
        steps: Vec<ScriptStep>,
        first_request_id: i32,
        reliable: bool,
    ) -> Self {
        Self::new_with_receive_limits(
            engine,
            steps,
            first_request_id,
            reliable,
            UDP_RECEIVE_LIMITS,
        )
    }

    pub fn new_with_receive_limits(
        engine: TestV3Engine,
        steps: Vec<ScriptStep>,
        first_request_id: i32,
        reliable: bool,
        receive_limits: ReceiveLimits,
    ) -> Self {
        Self(Arc::new(ScriptedTransportInner {
            engine,
            state: PeerState::new(steps),
            peer: SocketAddr::from((Ipv4Addr::LOCALHOST, 161)),
            local: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            next_id: AtomicI32::new(first_request_id),
            reliable,
            receive_limits,
        }))
    }

    pub fn log(&self) -> V3RequestLog {
        self.0.state.log.clone()
    }

    pub fn remaining_steps(&self) -> usize {
        self.0.state.steps.lock().unwrap().len()
    }
}

impl Transport for ScriptedTransport {
    async fn send(&self, _data: &[u8]) -> async_snmp::Result<()> {
        Ok(())
    }

    async fn recv_with<T, F>(
        &self,
        _registration: async_snmp::RequestRegistration,
        _validate: F,
    ) -> async_snmp::Result<T>
    where
        T: Send,
        F: FnMut(Bytes, SocketAddr) -> async_snmp::Result<async_snmp::Candidate<T>> + Send,
    {
        Err(Error::Config("ScriptedTransport uses request_with()".into()).boxed())
    }

    async fn request_with<T, F>(
        &self,
        data: &[u8],
        registration: async_snmp::RequestRegistration,
        mut validate: F,
    ) -> async_snmp::Result<T>
    where
        T: Send,
        F: FnMut(Bytes, SocketAddr) -> async_snmp::Result<async_snmp::Candidate<T>> + Send,
    {
        let request_id = registration.request_id();
        let (request, step) = self
            .0
            .state
            .handle_request(
                Bytes::copy_from_slice(data),
                self.0.local,
                Some(request_id),
                &self.0.engine,
            )
            .map_err(|error| Error::Config(error.into()).boxed())?;
        let step =
            step.ok_or_else(|| Error::Config("scripted transport exhausted".into()).boxed())?;
        match step
            .run(&request)
            .map_err(|error| Error::Config(error.into()).boxed())?
        {
            ScriptOutput::Replies(replies) => {
                for reply in replies {
                    if let async_snmp::Candidate::Accept(value) = validate(reply, self.0.peer)? {
                        return Ok(value);
                    }
                }
                Err(Error::Timeout {
                    target: self.0.peer,
                    elapsed: Duration::ZERO,
                    retries: 0,
                }
                .boxed())
            }
            ScriptOutput::RepliesFromOtherSource(_) => Err(Error::Config(
                "alternate-source script output is only supported by UDP peers".into(),
            )
            .boxed()),
            ScriptOutput::Silence => Err(Error::Timeout {
                target: self.0.peer,
                elapsed: Duration::ZERO,
                retries: 0,
            }
            .boxed()),
            ScriptOutput::TransportError(error) => Err(error),
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        self.0.peer
    }

    fn local_addr(&self) -> SocketAddr {
        self.0.local
    }

    fn alloc_request_id(&self) -> i32 {
        self.0.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn is_reliable(&self) -> bool {
        self.0.reliable
    }

    fn receive_limits(&self) -> ReceiveLimits {
        self.0.receive_limits
    }
}

async fn read_ber_message(stream: &mut TcpStream) -> Result<Bytes, String> {
    let mut header = vec![0_u8; 2];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|error| error.to_string())?;
    if header[0] != 0x30 {
        return Err(format!("expected SEQUENCE tag, got 0x{:02x}", header[0]));
    }
    let content_len = if header[1] < 0x80 {
        usize::from(header[1])
    } else {
        let octets = usize::from(header[1] & 0x7f);
        if octets == 0 || octets > 4 {
            return Err("invalid BER frame length".to_string());
        }
        let mut length = vec![0_u8; octets];
        stream
            .read_exact(&mut length)
            .await
            .map_err(|error| error.to_string())?;
        header.extend_from_slice(&length);
        length
            .into_iter()
            .fold(0_usize, |value, byte| (value << 8) | usize::from(byte))
    };
    if content_len > 1_048_576 {
        return Err("BER frame exceeds test peer allocation limit".to_string());
    }
    let mut content = vec![0_u8; content_len];
    stream
        .read_exact(&mut content)
        .await
        .map_err(|error| error.to_string())?;
    header.extend_from_slice(&content);
    Ok(Bytes::from(header))
}

fn correlated_malformed_reply(msg_id: i32) -> Bytes {
    let usm = raw_ber::usm_security_params(&[], &[0], &[0], &[], &[], &[]);
    raw_ber::v3_message(
        &raw_ber::signed_integer_content(msg_id),
        &[0x00, 0xff, 0xe3],
        &[0],
        &[3],
        &usm,
        &raw_ber::tlv(0x05, &[]),
    )
}

/// Minimal forward BER construction for values the production encoder cannot
/// represent, such as over-width integers and invalid flags.
pub mod raw_ber {
    use bytes::Bytes;

    pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(1 + content.len() + 5);
        encoded.push(tag);
        push_length(&mut encoded, content.len());
        encoded.extend_from_slice(content);
        encoded
    }

    pub fn sequence(elements: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
        let content: Vec<u8> = elements.into_iter().flatten().collect();
        tlv(0x30, &content)
    }

    pub fn integer_from_content(content: &[u8]) -> Vec<u8> {
        tlv(0x02, content)
    }

    pub fn signed_integer_content(value: i32) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let mut start = 0;
        while start < bytes.len() - 1
            && ((bytes[start] == 0 && bytes[start + 1] & 0x80 == 0)
                || (bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0))
        {
            start += 1;
        }
        bytes[start..].to_vec()
    }

    pub fn usm_security_params(
        engine_id: &[u8],
        engine_boots_content: &[u8],
        engine_time_content: &[u8],
        username: &[u8],
        auth_params: &[u8],
        priv_params: &[u8],
    ) -> Bytes {
        Bytes::from(sequence([
            tlv(0x04, engine_id),
            integer_from_content(engine_boots_content),
            integer_from_content(engine_time_content),
            tlv(0x04, username),
            tlv(0x04, auth_params),
            tlv(0x04, priv_params),
        ]))
    }

    pub fn v3_message(
        msg_id_content: &[u8],
        msg_max_size_content: &[u8],
        msg_flags: &[u8],
        security_model_content: &[u8],
        encoded_usm: &[u8],
        encoded_msg_data_tlv: &[u8],
    ) -> Bytes {
        let global = sequence([
            integer_from_content(msg_id_content),
            integer_from_content(msg_max_size_content),
            tlv(0x04, msg_flags),
            integer_from_content(security_model_content),
        ]);
        Bytes::from(sequence([
            integer_from_content(&[3]),
            global,
            tlv(0x04, encoded_usm),
            encoded_msg_data_tlv.to_vec(),
        ]))
    }

    pub fn patch_msg_flags(packet: &mut [u8], flags: u8) -> Result<(), String> {
        let (outer_tag, mut position, outer_end) = read_tlv(packet, 0)?;
        if outer_tag != 0x30 {
            return Err("message is not a SEQUENCE".to_string());
        }
        let (_, _, version_end) = read_tlv(packet, position)?;
        position = version_end;
        let (global_tag, mut global_position, global_end) = read_tlv(packet, position)?;
        if global_tag != 0x30 {
            return Err("msgGlobalData is not a SEQUENCE".to_string());
        }
        let (_, _, msg_id_end) = read_tlv(packet, global_position)?;
        global_position = msg_id_end;
        let (_, _, msg_max_end) = read_tlv(packet, global_position)?;
        global_position = msg_max_end;
        let (flags_tag, flags_start, flags_end) = read_tlv(packet, global_position)?;
        if flags_tag != 0x04 || flags_end - flags_start != 1 {
            return Err("msgFlags is not a one-byte OCTET STRING".to_string());
        }
        if flags_end > global_end || global_end > outer_end {
            return Err("msgFlags lies outside its containing SEQUENCE".to_string());
        }
        packet[flags_start] = flags;
        Ok(())
    }

    fn push_length(output: &mut Vec<u8>, len: usize) {
        if len < 0x80 {
            output.push(len as u8);
            return;
        }
        let bytes = len.to_be_bytes();
        let first = bytes.iter().position(|byte| *byte != 0).unwrap();
        let significant = &bytes[first..];
        output.push(0x80 | significant.len() as u8);
        output.extend_from_slice(significant);
    }

    fn read_tlv(data: &[u8], position: usize) -> Result<(u8, usize, usize), String> {
        let tag = *data
            .get(position)
            .ok_or_else(|| "truncated BER tag".to_string())?;
        let first_length = *data
            .get(position + 1)
            .ok_or_else(|| "truncated BER length".to_string())?;
        let (len, header_len) = if first_length < 0x80 {
            (usize::from(first_length), 2)
        } else {
            let octets = usize::from(first_length & 0x7f);
            if octets == 0 || octets > std::mem::size_of::<usize>() {
                return Err("invalid BER length".to_string());
            }
            let length_end = position
                .checked_add(2 + octets)
                .ok_or_else(|| "BER length overflow".to_string())?;
            let length_bytes = data
                .get(position + 2..length_end)
                .ok_or_else(|| "truncated BER length".to_string())?;
            let len = length_bytes
                .iter()
                .fold(0_usize, |value, byte| (value << 8) | usize::from(*byte));
            (len, 2 + octets)
        };
        let content_start = position
            .checked_add(header_len)
            .ok_or_else(|| "BER offset overflow".to_string())?;
        let end = content_start
            .checked_add(len)
            .ok_or_else(|| "BER length overflow".to_string())?;
        if end > data.len() {
            return Err("truncated BER content".to_string());
        }
        Ok((tag, content_start, end))
    }
}
