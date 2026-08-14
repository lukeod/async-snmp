//! `SNMPv3` message format (RFC 3412).
//!
//! V3 messages have a more complex structure than v1/v2c:
//! ```text
//! SEQUENCE {
//!     INTEGER version (3)
//!     SEQUENCE msgGlobalData {
//!         INTEGER msgID
//!         INTEGER msgMaxSize
//!         OCTET STRING msgFlags (1 byte)
//!         INTEGER msgSecurityModel
//!     }
//!     OCTET STRING msgSecurityParameters (opaque, USM-encoded)
//!     msgData (ScopedPDU or encrypted OCTET STRING)
//! }
//! ```
//!
//! The msgData field is either:
//! - A plaintext `ScopedPDU` (SEQUENCE) for noAuthNoPriv/authNoPriv
//! - An encrypted OCTET STRING for authPriv (decrypts to `ScopedPDU`)

use bytes::Bytes;
use std::net::SocketAddr;

use crate::ber::{Decoder, EncodeBuf};
use crate::compatibility::DecodeConfig;
use crate::error::internal::{DecodeErrorKind, DecodeErrorOrigin};
use crate::error::{DecodeError, Error, Result};
use crate::message::{DecodeOutcome, finalize_envelope};
use crate::message_size::{MESSAGE_SIZE_MINIMUM, MessageSize};
use crate::pdu::Pdu;

/// `SNMPv3` security model identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum V3SecurityModel {
    /// User-based Security Model (RFC 3414)
    Usm = 3,
}

impl V3SecurityModel {
    /// Create from raw value.
    #[must_use]
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            3 => Some(Self::Usm),
            _ => None,
        }
    }

    /// Get the raw value.
    #[must_use]
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

/// `SNMPv3` security level.
///
/// The variants are ordered from least secure to most secure,
/// supporting VACM-style level comparisons (e.g., `actual >= required`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecurityLevel {
    /// No authentication, no privacy
    NoAuthNoPriv,
    /// Authentication only
    AuthNoPriv,
    /// Authentication and privacy (encryption)
    AuthPriv,
}

impl SecurityLevel {
    /// Decode from msgFlags byte.
    #[must_use]
    pub fn from_flags(flags: u8) -> Option<Self> {
        let auth = flags & 0x01 != 0;
        let priv_ = flags & 0x02 != 0;

        match (auth, priv_) {
            (false, false) => Some(Self::NoAuthNoPriv),
            (true, false) => Some(Self::AuthNoPriv),
            (true, true) => Some(Self::AuthPriv),
            (false, true) => None, // Invalid: priv without auth
        }
    }

    /// Encode to msgFlags byte (without reportable flag).
    #[must_use]
    pub fn to_flags(self) -> u8 {
        match self {
            Self::NoAuthNoPriv => 0x00,
            Self::AuthNoPriv => 0x01,
            Self::AuthPriv => 0x03,
        }
    }

    /// Check if authentication is required.
    #[must_use]
    pub fn requires_auth(self) -> bool {
        matches!(self, Self::AuthNoPriv | Self::AuthPriv)
    }

    /// Check if privacy (encryption) is required.
    #[must_use]
    pub fn requires_priv(self) -> bool {
        matches!(self, Self::AuthPriv)
    }
}

impl TryFrom<u8> for SecurityLevel {
    type Error = u8;

    fn try_from(flags: u8) -> std::result::Result<Self, u8> {
        Self::from_flags(flags).ok_or(flags)
    }
}

impl From<SecurityLevel> for u8 {
    fn from(level: SecurityLevel) -> u8 {
        level.to_flags()
    }
}

/// Message flags (RFC 3412 Section 6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsgFlags {
    /// Security level
    pub security_level: SecurityLevel,
    /// Whether a report PDU may be sent on error
    pub reportable: bool,
}

impl MsgFlags {
    /// Create new message flags.
    #[must_use]
    pub fn new(security_level: SecurityLevel, reportable: bool) -> Self {
        Self {
            security_level,
            reportable,
        }
    }

    /// Decode from byte.
    pub fn from_byte(byte: u8) -> Result<Self> {
        let security_level = SecurityLevel::from_flags(byte).ok_or_else(|| {
            tracing::debug!(target: "async_snmp::v3", { byte }, "invalid msgFlags semantics");
            Error::InvalidMessage("SNMPv3 privacy flag requires authentication".into()).boxed()
        })?;
        let reportable = byte & 0x04 != 0;
        Ok(Self {
            security_level,
            reportable,
        })
    }

    /// Encode to byte.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        let mut flags = self.security_level.to_flags();
        if self.reportable {
            flags |= 0x04;
        }
        flags
    }
}

/// Message global data header (msgGlobalData).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgGlobalData {
    /// Message identifier for request/response correlation
    pub(crate) msg_id: i32,
    /// Maximum message size the sender can accept
    pub(crate) msg_max_size: MessageSize,
    /// Message flags (security level + reportable)
    pub(crate) msg_flags: MsgFlags,
    /// Security model (always USM=3 for our implementation)
    pub(crate) msg_security_model: V3SecurityModel,
}

impl MsgGlobalData {
    /// Create validated global data.
    pub fn new(msg_id: i32, msg_max_size: MessageSize, msg_flags: MsgFlags) -> Result<Self> {
        if msg_id < 0 {
            return Err(Error::Config("SNMPv3 msgID must be in 0..=i32::MAX".into()).boxed());
        }
        Ok(Self {
            msg_id,
            msg_max_size,
            msg_flags,
            msg_security_model: V3SecurityModel::Usm,
        })
    }

    /// Return the message identifier.
    #[must_use]
    pub fn msg_id(&self) -> i32 {
        self.msg_id
    }

    /// Return the sender's accepted maximum message size.
    #[must_use]
    pub fn msg_max_size(&self) -> MessageSize {
        self.msg_max_size
    }

    /// Return the message flags.
    #[must_use]
    pub fn msg_flags(&self) -> MsgFlags {
        self.msg_flags
    }

    /// Return the selected security model.
    #[must_use]
    pub fn msg_security_model(&self) -> V3SecurityModel {
        self.msg_security_model
    }

    fn validate(&self) -> Result<()> {
        if self.msg_id < 0 || self.msg_security_model != V3SecurityModel::Usm {
            return Err(Error::Config("invalid SNMPv3 global data".into()).boxed());
        }
        Ok(())
    }

    /// Encode to buffer after revalidating all construction invariants.
    pub fn encode(&self, buf: &mut EncodeBuf) -> Result<()> {
        self.validate()?;
        buf.push_sequence(|buf| {
            buf.push_integer(self.msg_security_model.as_i32());
            // msgFlags is a 1-byte OCTET STRING
            buf.push_octet_string(&[self.msg_flags.to_byte()])?;
            buf.push_integer(self.msg_max_size.as_i32());
            buf.push_integer(self.msg_id);
            Ok(())
        })
    }

    /// Decode from decoder.
    ///
    /// Validates that:
    /// - `msgID` is in range 0..2147483647 (RFC 3412 `HeaderData`)
    /// - `msgMaxSize` is in range 484..2147483647 (RFC 3412 `HeaderData`)
    /// - `msgSecurityModel` is a known value (currently only USM=3)
    pub fn decode(decoder: &mut Decoder) -> Result<Self> {
        let mut seq = decoder.read_sequence()?;

        // These ASN.1 constraints must be checked against the complete BER
        // value before it is narrowed to i32.
        let msg_id = seq.read_bounded_integer(0, i32::MAX)?;
        let msg_max_size_raw = seq.read_bounded_integer(MESSAGE_SIZE_MINIMUM as i32, i32::MAX)?;
        let msg_max_size =
            MessageSize::from_i32(msg_max_size_raw).expect("bounded msgMaxSize must construct");

        let flags_bytes = seq.read_octet_string()?;
        let flags_offset = seq.local_offset().saturating_sub(flags_bytes.len());
        if flags_bytes.len() != 1 {
            tracing::debug!(target: "async_snmp::v3", { offset = seq.offset(), expected = 1, actual = flags_bytes.len() }, "invalid msgFlags length");
            return Err(seq.malformed_at(
                flags_offset,
                DecodeErrorKind::InvalidMsgFlagsLength {
                    length: flags_bytes.len(),
                },
            ));
        }
        let msg_flags = MsgFlags::from_byte(flags_bytes[0])
            .map_err(|_| seq.malformed_at(flags_offset, DecodeErrorKind::InvalidMsgFlags))?;

        let msg_security_model_raw = seq.read_bounded_integer(1, i32::MAX)?;
        // Reject unknown security models per RFC 3412 Section 7.2
        let msg_security_model =
            V3SecurityModel::from_i32(msg_security_model_raw).ok_or_else(|| {
                tracing::debug!(target: "async_snmp::v3", { offset = seq.offset(), model = msg_security_model_raw, kind = %DecodeErrorKind::UnknownSecurityModel(msg_security_model_raw) }, "decode error");
                seq.malformed(DecodeErrorKind::UnknownSecurityModel(msg_security_model_raw))
            })?;

        if !seq.is_empty() {
            return Err(seq.malformed(DecodeErrorKind::TrailingData {
                remaining: seq.remaining(),
            }));
        }

        Ok(Self {
            msg_id,
            msg_max_size,
            msg_flags,
            msg_security_model,
        })
    }
}

/// Scoped PDU (contextEngineID + contextName + PDU).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedPdu {
    /// Context engine ID (typically same as authoritative engine ID)
    pub context_engine_id: Bytes,
    /// Context name (typically empty string)
    pub context_name: Bytes,
    /// The actual PDU
    pub pdu: Pdu,
}

impl ScopedPdu {
    /// Create a new scoped PDU.
    pub fn new(
        context_engine_id: impl Into<Bytes>,
        context_name: impl Into<Bytes>,
        pdu: impl Into<Pdu>,
    ) -> Self {
        Self {
            context_engine_id: context_engine_id.into(),
            context_name: context_name.into(),
            pdu: pdu.into(),
        }
    }

    /// Create with empty context (most common case).
    #[must_use]
    pub fn with_empty_context(pdu: impl Into<Pdu>) -> Self {
        Self {
            context_engine_id: Bytes::new(),
            context_name: Bytes::new(),
            pdu: pdu.into(),
        }
    }

    fn validate_outbound(&self) -> Result<()> {
        self.pdu
            .validate_outbound(crate::Version::V3, self.pdu.outbound_direction())
    }

    /// Encode to buffer after applying SNMPv3 outbound PDU validation.
    pub fn encode(&self, buf: &mut EncodeBuf) -> Result<()> {
        self.validate_outbound()?;
        buf.push_sequence(|buf| {
            self.pdu
                .encode_for(buf, crate::Version::V3, self.pdu.outbound_direction())?;
            buf.push_octet_string(&self.context_name)?;
            buf.push_octet_string(&self.context_engine_id)?;
            Ok(())
        })
    }

    /// Encode to bytes.
    pub fn encode_to_bytes(&self) -> Result<Bytes> {
        let mut buf = EncodeBuf::new();
        self.encode(&mut buf)?;
        Ok(buf.finish())
    }

    /// Decode from decoder.
    pub fn decode(decoder: &mut Decoder) -> Result<Self> {
        let mut seq = decoder.read_sequence()?;

        let context_engine_id = seq.read_octet_string()?;
        let context_name = seq.read_octet_string()?;
        let pdu = Pdu::decode(&mut seq)?;

        if !seq.is_empty() {
            return Err(seq.malformed(DecodeErrorKind::TrailingData {
                remaining: seq.remaining(),
            }));
        }

        Ok(Self {
            context_engine_id,
            context_name,
            pdu,
        })
    }
}

/// Decode one captured or decrypted scoped-PDU TLV and validate its suffix.
///
/// Plaintext and AES-CFB data must end exactly after the TLV. DES and 3DES
/// may carry at most seven padding octets from their eight-octet CBC block.
#[cfg(test)]
fn decode_scoped_pdu_with_consumption(
    data: Bytes,
    base_offset: usize,
    source: SocketAddr,
    privacy: Option<crate::v3::PrivProtocol>,
) -> Result<ScopedPdu> {
    Ok(decode_scoped_pdu_with_anomalies(data, base_offset, source, privacy)?.value)
}

#[cfg(test)]
fn decode_scoped_pdu_with_anomalies(
    data: Bytes,
    base_offset: usize,
    source: SocketAddr,
    privacy: Option<crate::v3::PrivProtocol>,
) -> Result<DecodeOutcome<ScopedPdu>> {
    decode_scoped_pdu(data, base_offset, source, privacy, DecodeConfig::default())
}

pub(crate) fn decode_scoped_pdu(
    data: Bytes,
    base_offset: usize,
    source: SocketAddr,
    privacy: Option<crate::v3::PrivProtocol>,
    config: DecodeConfig,
) -> Result<DecodeOutcome<ScopedPdu>> {
    let origin = if privacy.is_some() {
        DecodeErrorOrigin::DecryptedScopedPdu
    } else {
        DecodeErrorOrigin::Packet
    };
    let anomalies = std::cell::RefCell::new(Vec::new());
    let mut decoder = Decoder::with_origin_context(data, base_offset, origin, Some(source))
        .with_decode_config(config)
        .with_anomaly_sink(&anomalies);
    let scoped = ScopedPdu::decode(&mut decoder)?;
    let maximum_suffix = match privacy {
        Some(crate::v3::PrivProtocol::Des | crate::v3::PrivProtocol::Des3) => 7,
        Some(
            crate::v3::PrivProtocol::Aes128
            | crate::v3::PrivProtocol::Aes192
            | crate::v3::PrivProtocol::Aes256,
        )
        | None => 0,
    };
    if decoder.remaining() > maximum_suffix {
        return Err(decoder.malformed(DecodeErrorKind::TrailingData {
            remaining: decoder.remaining(),
        }));
    }
    drop(decoder);
    Ok(DecodeOutcome {
        value: scoped,
        anomalies: anomalies.into_inner(),
    })
}

/// Combine a raw outer-envelope decode with the subsequently decoded scoped
/// PDU. The order matches full plaintext decoding: outer header/security
/// fields, scoped-PDU (or decrypted plaintext) fields, then a top-level suffix.
pub(crate) fn combine_staged_v3_anomalies(
    mut outer: Vec<crate::DecodeAnomaly>,
    inner: Vec<crate::DecodeAnomaly>,
) -> Vec<crate::DecodeAnomaly> {
    let suffix = matches!(
        outer.last(),
        Some(crate::DecodeAnomaly::TrailingBytes { .. })
    )
    .then(|| outer.pop())
    .flatten();
    outer.extend(inner);
    outer.extend(suffix);
    outer
}

/// `SNMPv3` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3Message {
    /// Global data (header)
    pub(crate) global_data: MsgGlobalData,
    /// Security parameters (opaque, USM-encoded)
    pub(crate) security_params: Bytes,
    /// Message data - either plaintext `ScopedPdu` or encrypted bytes
    pub(crate) data: V3MessageData,
}

/// Message data payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V3MessageData {
    /// Plaintext scoped PDU (noAuthNoPriv or authNoPriv)
    Plaintext(ScopedPdu),
    /// Encrypted scoped PDU (authPriv) - raw ciphertext
    Encrypted(Bytes),
}

impl V3Message {
    /// Create a validated V3 message with plaintext scoped data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMessage`] when the scoped PDU violates SNMPv3
    /// outbound invariants. Header and security-parameter contradictions are
    /// also rejected.
    pub fn new(
        global_data: MsgGlobalData,
        security_params: Bytes,
        scoped_pdu: ScopedPdu,
    ) -> Result<Self> {
        let value = Self {
            global_data,
            security_params,
            data: V3MessageData::Plaintext(scoped_pdu),
        };
        value.validate_outbound()?;
        Ok(value)
    }

    /// Create an SNMPv3 message from opaque encrypted scoped-PDU bytes.
    ///
    /// This is a trusted/raw escape hatch for callers that already encrypted a
    /// complete encoded `ScopedPdu`. The constructor validates the global
    /// header, USM security parameters, privacy flag, and their relationships,
    /// but cannot inspect the ciphertext to validate the enclosed PDU's
    /// outbound invariants. Prefer [`Self::new`] whenever the scoped PDU is
    /// available as structured plaintext.
    pub fn new_with_opaque_encrypted_scoped_pdu(
        global_data: MsgGlobalData,
        security_params: Bytes,
        encrypted: Bytes,
    ) -> Result<Self> {
        let value = Self {
            global_data,
            security_params,
            data: V3MessageData::Encrypted(encrypted),
        };
        value.validate_outbound()?;
        Ok(value)
    }

    /// Return the global header.
    #[must_use]
    pub fn global_data(&self) -> &MsgGlobalData {
        &self.global_data
    }

    /// Return the opaque encoded USM security parameters.
    #[must_use]
    pub fn security_params(&self) -> &Bytes {
        &self.security_params
    }

    /// Return the message data.
    #[must_use]
    pub fn data(&self) -> &V3MessageData {
        &self.data
    }

    // Decode validates only the received envelope here. In particular, it must
    // not impose outbound canonical-PDU rules on input accepted for
    // interoperability.
    fn validate_inbound_envelope(&self) -> Result<()> {
        self.global_data.validate()?;
        let level = self.global_data.msg_flags.security_level;
        if level.requires_priv() != matches!(self.data, V3MessageData::Encrypted(_)) {
            return Err(Error::InvalidMessage(
                "SNMPv3 privacy flag contradicts the msgData representation".into(),
            )
            .boxed());
        }
        let usm = crate::v3::UsmSecurityParams::decode(
            self.security_params.clone(),
            DecodeConfig::STRICT,
        )?;
        self.validate_decoded_inbound_envelope(&usm.value)
    }

    fn validate_decoded_inbound_envelope(&self, usm: &crate::v3::UsmSecurityParams) -> Result<()> {
        usm.validate_for_security_level(self.global_data.msg_flags.security_level)
            .map_err(|error| Error::InvalidMessage(error.to_string().into()).boxed())
    }

    fn validate_outbound(&self) -> Result<()> {
        self.validate_inbound_envelope()?;
        if let V3MessageData::Plaintext(scoped_pdu) = &self.data {
            scoped_pdu.validate_outbound()?;
        }
        Ok(())
    }

    /// Get the scoped PDU if available (plaintext only).
    pub fn scoped_pdu(&self) -> Option<&ScopedPdu> {
        match &self.data {
            V3MessageData::Plaintext(pdu) => Some(pdu),
            V3MessageData::Encrypted(_) => None,
        }
    }

    /// Consume and return the scoped PDU if available.
    pub fn into_scoped_pdu(self) -> Option<ScopedPdu> {
        match self.data {
            V3MessageData::Plaintext(pdu) => Some(pdu),
            V3MessageData::Encrypted(_) => None,
        }
    }

    /// Get the PDU if available (convenience method).
    pub fn pdu(&self) -> Option<&Pdu> {
        self.scoped_pdu().map(|s| &s.pdu)
    }

    /// Consume and return the PDU.
    pub fn into_pdu(self) -> Option<Pdu> {
        self.into_scoped_pdu().map(|s| s.pdu)
    }

    /// Get the message ID.
    pub fn msg_id(&self) -> i32 {
        self.global_data.msg_id
    }

    /// Get the security level.
    pub fn security_level(&self) -> SecurityLevel {
        self.global_data.msg_flags.security_level
    }

    /// Encode to BER.
    ///
    /// Note: For authenticated messages, the caller must:
    /// 1. Encode with placeholder auth params (12 zero bytes for HMAC-96)
    /// 2. Compute HMAC over the entire encoded message
    /// 3. Replace the placeholder with the actual HMAC
    pub fn encode(&self) -> Result<Bytes> {
        self.validate_outbound()?;
        let mut buf = EncodeBuf::new();

        buf.push_sequence(|buf| {
            // msgData
            match &self.data {
                V3MessageData::Plaintext(scoped_pdu) => scoped_pdu.encode(buf)?,
                V3MessageData::Encrypted(ciphertext) => buf.push_octet_string(ciphertext)?,
            }

            // msgSecurityParameters (as OCTET STRING)
            buf.push_octet_string(&self.security_params)?;

            // msgGlobalData
            self.global_data.encode(buf)?;

            // version
            buf.push_integer(3);
            Ok(())
        })?;

        Ok(buf.finish())
    }

    /// Decode a complete V3 message and retain every accepted anomaly.
    ///
    /// For encrypted messages this retains the ciphertext. Plaintext scoped
    /// data is parsed without USM authentication; untrusted receive paths use
    /// [`RawV3Message::decode`] and staged security processing instead.
    pub fn decode(data: Bytes, config: DecodeConfig) -> Result<DecodeOutcome<Self>> {
        let anomalies = std::cell::RefCell::new(Vec::new());
        let mut decoder = Decoder::new(data)
            .with_decode_config(config)
            .with_anomaly_sink(&anomalies);
        let mut seq = decoder.read_sequence()?;

        let version = seq.read_bounded_integer(0, i32::MAX)?;
        if version != 3 {
            tracing::debug!(target: "async_snmp::v3", { offset = seq.offset(), version, kind = %DecodeErrorKind::UnknownVersion(version) }, "decode error");
            return Err(seq.malformed(DecodeErrorKind::UnknownVersion(version)));
        }

        let value = Self::decode_from_sequence(&mut seq)?;
        finalize_envelope(&seq, &decoder, config)?;
        drop(seq);
        drop(decoder);
        Ok(DecodeOutcome {
            value,
            anomalies: anomalies.into_inner(),
        })
    }

    /// Decode from a sequence decoder where version has already been read.
    pub(crate) fn decode_from_sequence(seq: &mut Decoder) -> Result<Self> {
        // msgGlobalData
        let global_data = MsgGlobalData::decode(seq)?;

        // msgSecurityParameters (OCTET STRING containing USM params)
        let security_params = seq.read_octet_string()?;
        let security_params_offset = seq.offset().saturating_sub(security_params.len());
        let mut security_decoder =
            seq.decoder_for_same_origin(security_params.clone(), security_params_offset);
        let usm = crate::v3::UsmSecurityParams::decode_from(&mut security_decoder)?;
        if !security_decoder.is_empty() {
            return Err(security_decoder.malformed(DecodeErrorKind::TrailingData {
                remaining: security_decoder.remaining(),
            }));
        }

        // msgData - either plaintext SEQUENCE or encrypted OCTET STRING
        let data = if global_data.msg_flags.security_level.requires_priv() {
            // Encrypted: expect OCTET STRING
            let encrypted = seq.read_octet_string()?;
            V3MessageData::Encrypted(encrypted)
        } else {
            // Plaintext: expect SEQUENCE (ScopedPDU)
            let scoped_pdu = ScopedPdu::decode(seq)?;
            V3MessageData::Plaintext(scoped_pdu)
        };

        let value = Self {
            global_data,
            security_params,
            data,
        };
        value.validate_decoded_inbound_envelope(&usm)?;
        Ok(value)
    }

    /// Create a discovery request message.
    ///
    /// This is sent to discover a remote SNMP engine's identity and message-size
    /// limit. The response is unauthenticated, so its boots/time tuple must not
    /// establish trusted time; authenticated communication performs that step.
    /// Uses empty security parameters and no authentication. The supplied local
    /// receive capacity is advertised to the remote engine.
    pub fn discovery_request(msg_id: i32, local_receive_capacity: MessageSize) -> Result<Self> {
        let global_data = MsgGlobalData::new(
            msg_id,
            local_receive_capacity,
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, true),
        )?;

        // Empty USM security parameters for discovery
        let security_params = crate::v3::UsmSecurityParams::discovery().encode()?;

        // Empty scoped PDU with Report request
        let pdu = Pdu::get_request(0, &[]);
        let scoped_pdu = ScopedPdu::with_empty_context(pdu);

        Self::new(global_data, security_params, scoped_pdu)
    }
}

/// An `SNMPv3` message whose msgData has not been through security
/// processing.
///
/// [`RawV3Message::decode`] parses only the outer envelope: version, global
/// header, and the opaque security parameters. The scoped PDU stays as raw
/// bytes (plaintext or ciphertext) so that authentication and decryption can
/// run before any PDU parsing, in the RFC 3412 Section 7.2 order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawV3Message {
    /// Global data (header)
    pub(crate) global_data: MsgGlobalData,
    /// Security parameters (opaque, USM-encoded)
    pub(crate) security_params: Bytes,
    pub(crate) security_params_offset: usize,
    /// Raw msgData, form selected by the received privacy flag
    pub(crate) msg_data: RawMsgData,
}

/// Raw msgData payload of a [`RawV3Message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawMsgData {
    /// Unparsed plaintext `ScopedPDU` TLV bytes (noAuthNoPriv or authNoPriv)
    Plaintext {
        /// Complete scoped-PDU TLV.
        data: Bytes,
        /// Packet-relative start of `data`.
        offset: usize,
    },
    /// Encrypted `ScopedPDU` ciphertext (authPriv)
    Encrypted(Bytes),
}

impl RawV3Message {
    /// Decode the unprocessed outer V3 envelope and retain accepted anomalies.
    pub fn decode(data: Bytes, config: DecodeConfig) -> Result<DecodeOutcome<Self>> {
        let input_len = data.len();
        Self::decode_bounded(data, input_len, None, config)
    }

    pub(crate) fn decode_bounded_with_target(
        data: Bytes,
        maximum: usize,
        target: SocketAddr,
        config: DecodeConfig,
    ) -> Result<DecodeOutcome<Self>> {
        Self::decode_bounded(data, maximum, Some(target), config)
    }

    fn decode_bounded(
        data: Bytes,
        maximum: usize,
        peer: Option<SocketAddr>,
        config: DecodeConfig,
    ) -> Result<DecodeOutcome<Self>> {
        if data.len() > maximum {
            let mut error = DecodeError::new(
                0,
                DecodeErrorKind::MessageTooLarge {
                    size: data.len(),
                    maximum,
                },
            );
            error.peer = peer;
            return Err(Error::Decode(error).boxed());
        }
        let anomalies = std::cell::RefCell::new(Vec::new());
        let mut decoder = Decoder::with_optional_peer(data, peer)
            .with_decode_config(config)
            .with_anomaly_sink(&anomalies);
        let mut seq = decoder.read_sequence()?;

        let version = seq.read_bounded_integer(0, i32::MAX)?;
        if version != 3 {
            tracing::debug!(target: "async_snmp::v3", { offset = seq.offset(), version, kind = %DecodeErrorKind::UnknownVersion(version) }, "decode error");
            return Err(seq.malformed(DecodeErrorKind::UnknownVersion(version)));
        }

        let global_data = MsgGlobalData::decode(&mut seq)?;
        let security_params = seq.read_octet_string()?;
        let security_params_offset = seq.offset().saturating_sub(security_params.len());

        let msg_data = if global_data.msg_flags.security_level.requires_priv() {
            RawMsgData::Encrypted(seq.read_octet_string()?)
        } else {
            // Capture the complete plaintext ScopedPDU TLV unparsed.
            let start = seq.local_offset();
            let packet_offset = seq.offset();
            seq.skip_tlv()?;
            RawMsgData::Plaintext {
                data: seq.as_bytes().slice(start..seq.local_offset()),
                offset: packet_offset,
            }
        };

        let value = Self {
            global_data,
            security_params,
            security_params_offset,
            msg_data,
        };
        finalize_envelope(&seq, &decoder, config)?;
        drop(seq);
        drop(decoder);
        Ok(DecodeOutcome {
            value,
            anomalies: anomalies.into_inner(),
        })
    }

    /// Get the decoded global header.
    pub fn global_data(&self) -> &MsgGlobalData {
        &self.global_data
    }

    /// Get the opaque security parameters.
    pub fn security_params(&self) -> &Bytes {
        &self.security_params
    }

    /// Get the unprocessed message data.
    pub fn msg_data(&self) -> &RawMsgData {
        &self.msg_data
    }

    /// Get the message ID.
    pub fn msg_id(&self) -> i32 {
        self.global_data.msg_id
    }

    /// Get the security level indicated by the received flags.
    pub fn security_level(&self) -> SecurityLevel {
        self.global_data.msg_flags.security_level
    }
}

/// RFC 3412 MPD failures that must be counted before the message is
/// discarded (Sections 7.2.4 and 7.2.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MpdFailure {
    /// Invalid msgFlags (priv without auth) - snmpInvalidMsgs.
    InvalidMsgFlags,
    /// Unrecognized msgSecurityModel - snmpUnknownSecurityModels.
    UnknownSecurityModel,
}

/// Classify a failed [`V3Message::decode`] as an MPD-countable failure.
///
/// Re-parses only the header path so it stays in lockstep with
/// [`MsgGlobalData::decode`]: the first countable defect wins, and `None`
/// means the failure was some other malformation.
pub(crate) fn classify_mpd_failure(data: Bytes) -> Option<MpdFailure> {
    let mut decoder = Decoder::new(data);
    let mut seq = decoder.read_sequence().ok()?;
    if seq.read_bounded_integer(0, i32::MAX).ok()? != 3 {
        return None;
    }
    let mut global = seq.read_sequence().ok()?;
    // Mirror `MsgGlobalData::decode`'s fail-fast order so a failure is only
    // attributed to the field that actually caused decode to reject. A
    // countable defect at a later field is unreachable once decode would have
    // stopped at an earlier one (out-of-range msgID/msgMaxSize, wrong-length
    // msgFlags), and those earlier rejections are ASN.1/header errors rather
    // than snmpInvalidMsgs/snmpUnknownSecurityModels, so they return None.
    global.read_bounded_integer(0, i32::MAX).ok()?;
    global
        .read_bounded_integer(MESSAGE_SIZE_MINIMUM as i32, i32::MAX)
        .ok()?;
    let flags_bytes = global.read_octet_string().ok()?;
    if flags_bytes.len() != 1 {
        return None;
    }
    if MsgFlags::from_byte(flags_bytes[0]).is_err() {
        return Some(MpdFailure::InvalidMsgFlags);
    }
    let model = global.read_bounded_integer(1, i32::MAX).ok()?;
    if V3SecurityModel::from_i32(model).is_none() {
        return Some(MpdFailure::UnknownSecurityModel);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staged_plaintext_and_authpriv_anomaly_order_places_top_level_suffix_last() {
        let outer_field = crate::DecodeAnomaly::SignedIntegerTruncation {
            encoded_length: 5,
            original: i32::MAX as i64 + 1,
            canonical: i32::MIN,
        };
        let inner_field = crate::DecodeAnomaly::EmptyCounter64 {
            original_length: 0,
            canonical: 0,
        };
        let suffix = crate::DecodeAnomaly::TrailingBytes {
            original_length: 2,
            canonical_length: 0,
        };
        let expected = vec![outer_field.clone(), inner_field.clone(), suffix.clone()];

        // Plaintext staged decoding must match the observation order of the
        // full decoder. authPriv uses the same logical order, with decrypted
        // plaintext occupying the scoped-PDU position.
        for combined in [
            combine_staged_v3_anomalies(
                vec![outer_field.clone(), suffix.clone()],
                vec![inner_field.clone()],
            ),
            combine_staged_v3_anomalies(
                vec![outer_field.clone(), suffix.clone()],
                vec![inner_field.clone()],
            ),
        ] {
            assert_eq!(combined, expected);
        }
    }
    use crate::oid;

    fn valid_scoped_bytes() -> Bytes {
        ScopedPdu::with_empty_context(Pdu::get_request(1, &[]))
            .encode_to_bytes()
            .unwrap()
    }

    fn no_auth_security_params() -> Bytes {
        crate::v3::UsmSecurityParams::new(b"engine".as_slice(), 0, 0, Bytes::new())
            .unwrap()
            .encode()
            .unwrap()
    }

    fn auth_security_params(with_privacy: bool) -> Bytes {
        let params =
            crate::v3::UsmSecurityParams::new(b"engine".as_slice(), 0, 0, b"user".as_slice())
                .unwrap()
                .with_auth_params([0_u8; 12].as_slice())
                .unwrap();
        let params = if with_privacy {
            params.with_priv_params([0_u8; 8].as_slice()).unwrap()
        } else {
            params
        };
        params.encode().unwrap()
    }

    fn raw_too_big_message_with_varbind() -> Bytes {
        let global = MsgGlobalData::new(
            1,
            crate::MessageSize::new(65_507).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, false),
        )
        .unwrap();
        let security_params = no_auth_security_params();
        let varbinds = [crate::VarBind::null(oid!(1, 3, 6, 1))];
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_sequence(|buf| {
                buf.push_constructed(crate::ber::tag::pdu::RESPONSE, |buf| {
                    crate::varbind::encode_varbind_list(buf, &varbinds).unwrap();
                    buf.push_integer(0);
                    buf.push_integer(crate::ErrorStatus::TooBig.as_i32());
                    buf.push_integer(1);
                    Ok(())
                })?;
                buf.push_octet_string(b"")?;
                buf.push_octet_string(b"engine")
            })?;
            buf.push_octet_string(&security_params)?;
            global.encode(buf)?;
            buf.push_integer(3);
            Ok(())
        })
        .unwrap();
        buf.finish()
    }

    #[test]
    fn public_v3_constructors_and_encode_recheck_invariants() {
        let size = crate::MessageSize::new(65_507).unwrap();
        assert!(
            MsgGlobalData::new(-1, size, MsgFlags::new(SecurityLevel::NoAuthNoPriv, false))
                .is_err()
        );
        assert!(
            MsgGlobalData::new(0, size, MsgFlags::new(SecurityLevel::NoAuthNoPriv, false)).is_ok()
        );
        assert!(
            MsgGlobalData::new(
                i32::MAX,
                size,
                MsgFlags::new(SecurityLevel::NoAuthNoPriv, false)
            )
            .is_ok()
        );

        let mut global =
            MsgGlobalData::new(1, size, MsgFlags::new(SecurityLevel::NoAuthNoPriv, false)).unwrap();
        global.msg_id = -1;
        let mut buf = EncodeBuf::new();
        assert!(global.encode(&mut buf).is_err());

        let no_auth = crate::v3::UsmSecurityParams::new(b"engine".as_slice(), 0, 0, Bytes::new())
            .unwrap()
            .encode()
            .unwrap();
        let scoped = ScopedPdu::with_empty_context(Pdu::get_request(1, &[]));
        let private =
            MsgGlobalData::new(1, size, MsgFlags::new(SecurityLevel::AuthPriv, false)).unwrap();
        assert!(V3Message::new(private.clone(), no_auth.clone(), scoped.clone()).is_err());
        assert!(
            V3Message::new_with_opaque_encrypted_scoped_pdu(
                private,
                no_auth,
                Bytes::from_static(b"ciphertext"),
            )
            .is_err()
        );

        let mut message = V3Message::discovery_request(1, size).unwrap();
        message.global_data.msg_flags = MsgFlags::new(SecurityLevel::AuthPriv, true);
        assert!(message.encode().is_err());
    }

    #[test]
    fn structured_v3_envelopes_reject_nonempty_too_big_response() {
        let too_big = Pdu::response(
            1,
            crate::ErrorStatus::TooBig.as_i32(),
            0,
            vec![crate::VarBind::null(oid!(1, 3, 6, 1))],
        );
        let scoped = ScopedPdu::new(b"engine".as_slice(), Bytes::new(), too_big);
        assert!(scoped.encode_to_bytes().is_err());

        let global = MsgGlobalData::new(
            1,
            crate::MessageSize::new(65_507).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, false),
        )
        .unwrap();
        let error = V3Message::new(global, no_auth_security_params(), scoped).unwrap_err();
        assert!(matches!(error.as_ref(), Error::InvalidMessage(_)));
        assert_eq!(error.kind(), crate::ErrorKind::InvalidMessage);

        let empty = ScopedPdu::new(
            b"engine".as_slice(),
            Bytes::new(),
            Pdu::response(1, crate::ErrorStatus::TooBig.as_i32(), 0, vec![]),
        );
        empty.encode_to_bytes().unwrap();
    }

    #[test]
    fn v3_decode_remains_permissive_for_noncanonical_too_big_response() {
        let decoded =
            V3Message::decode(raw_too_big_message_with_varbind(), DecodeConfig::default())
                .expect("receive path accepts the PDU")
                .value;
        let pdu = decoded.pdu().unwrap();
        assert_eq!(pdu.error_status(), crate::ErrorStatus::TooBig.as_i32());
        assert_eq!(pdu.error_index(), 0);
        assert_eq!(pdu.varbinds.len(), 1);
        let error = decoded.encode().unwrap_err();
        assert!(matches!(error.as_ref(), Error::InvalidMessage(_)));
        assert_eq!(error.kind(), crate::ErrorKind::InvalidMessage);
    }

    #[test]
    fn scoped_pdu_suffix_rules_match_privacy_protocols() {
        let source = "127.0.0.1:161".parse().unwrap();
        for suffix in 0..=8 {
            let mut bytes = valid_scoped_bytes().to_vec();
            bytes.extend(std::iter::repeat_n(0, suffix));
            let bytes = Bytes::from(bytes);
            assert_eq!(
                decode_scoped_pdu_with_consumption(
                    bytes.clone(),
                    0,
                    source,
                    Some(crate::v3::PrivProtocol::Des)
                )
                .is_ok(),
                suffix <= 7
            );
            assert_eq!(
                decode_scoped_pdu_with_consumption(
                    bytes.clone(),
                    0,
                    source,
                    Some(crate::v3::PrivProtocol::Des3)
                )
                .is_ok(),
                suffix <= 7
            );
            assert_eq!(
                decode_scoped_pdu_with_consumption(
                    bytes.clone(),
                    0,
                    source,
                    Some(crate::v3::PrivProtocol::Aes128)
                )
                .is_ok(),
                suffix == 0
            );
            assert_eq!(
                decode_scoped_pdu_with_consumption(
                    bytes.clone(),
                    0,
                    source,
                    Some(crate::v3::PrivProtocol::Aes192)
                )
                .is_ok(),
                suffix == 0
            );
            assert_eq!(
                decode_scoped_pdu_with_consumption(
                    bytes.clone(),
                    0,
                    source,
                    Some(crate::v3::PrivProtocol::Aes256)
                )
                .is_ok(),
                suffix == 0
            );
            assert_eq!(
                decode_scoped_pdu_with_consumption(bytes, 0, source, None).is_ok(),
                suffix == 0
            );
        }
    }

    #[test]
    fn decrypted_scoped_pdu_errors_use_plaintext_coordinates_and_retain_peer() {
        let source = "192.0.2.80:161".parse().unwrap();
        let mut plaintext = valid_scoped_bytes().to_vec();
        let pdu_offset = plaintext
            .iter()
            .position(|byte| *byte == crate::ber::tag::pdu::GET_REQUEST)
            .unwrap();
        plaintext[pdu_offset] = 0xaf;

        let error = decode_scoped_pdu_with_consumption(
            Bytes::from(plaintext),
            0,
            source,
            Some(crate::v3::PrivProtocol::Aes128),
        )
        .unwrap_err();
        assert!(matches!(&*error, Error::Decode(error)
            if error.origin == DecodeErrorOrigin::DecryptedScopedPdu
                && error.offset == pdu_offset
                && error.kind == DecodeErrorKind::UnknownPduType(0xaf)
                && error.peer == Some(source)));
        assert!(
            error
                .to_string()
                .contains("decrypted scoped-PDU plaintext offset")
        );
    }

    #[test]
    fn decoded_v3_semantic_failures_are_not_structural_decode_errors() {
        let global = MsgGlobalData::new(
            7,
            crate::MessageSize::new(1472).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, true),
        )
        .unwrap();
        let security_params =
            crate::v3::UsmSecurityParams::new(b"engine".as_slice(), 0, 0, Bytes::new())
                .unwrap()
                .with_auth_params([0_u8; 12].as_slice())
                .unwrap()
                .encode()
                .unwrap();
        let scoped = ScopedPdu::with_empty_context(Pdu::get_request(42, &[]));
        let mut encoded = EncodeBuf::new();
        encoded
            .push_sequence(|buf| {
                scoped.encode(buf)?;
                buf.push_octet_string(&security_params)?;
                global.encode(buf)?;
                buf.push_integer(3);
                Ok(())
            })
            .unwrap();

        let error = V3Message::decode(encoded.finish(), DecodeConfig::default()).unwrap_err();
        assert!(matches!(&*error, Error::InvalidMessage(_)));
    }

    #[test]
    fn full_v3_envelope_reports_multi_octet_pdu_tag_at_packet_offset() {
        let global = MsgGlobalData::new(
            7,
            crate::MessageSize::new(1472).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, true),
        )
        .unwrap();
        let message = V3Message::new(
            global,
            no_auth_security_params(),
            ScopedPdu::with_empty_context(Pdu::get_request(42, &[])),
        )
        .unwrap();
        let mut encoded = message.encode().unwrap().to_vec();
        let pdu_offset = encoded
            .iter()
            .position(|byte| *byte == crate::ber::tag::pdu::GET_REQUEST)
            .unwrap();
        encoded[pdu_offset] = 0xbf;

        let error = V3Message::decode(Bytes::from(encoded), DecodeConfig::default()).unwrap_err();
        assert!(matches!(&*error, Error::Decode(error)
            if error.origin == DecodeErrorOrigin::Packet
                && error.offset == pdu_offset
                && error.kind == DecodeErrorKind::UnsupportedMultiOctetTag { first_octet: 0xbf }));
    }

    #[test]
    fn v3_nested_decode_offsets_remain_packet_relative_across_raw_transitions() {
        let global = MsgGlobalData::new(
            7,
            crate::MessageSize::new(1472).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, true),
        )
        .unwrap();
        let message = V3Message::new(
            global,
            no_auth_security_params(),
            ScopedPdu::with_empty_context(Pdu::get_request(42, &[])),
        )
        .unwrap();
        let mut encoded = message.encode().unwrap().to_vec();
        let pdu_offset = encoded
            .iter()
            .position(|byte| *byte == crate::ber::tag::pdu::GET_REQUEST)
            .unwrap();
        encoded[pdu_offset] = 0xaf;

        let standalone =
            V3Message::decode(Bytes::from(encoded.clone()), DecodeConfig::default()).unwrap_err();
        assert!(matches!(&*standalone, Error::Decode(error)
            if error.origin == DecodeErrorOrigin::Packet
                && error.offset == pdu_offset
                && error.kind == DecodeErrorKind::UnknownPduType(0xaf)
                && error.peer.is_none()));

        let raw = RawV3Message::decode(Bytes::from(encoded), DecodeConfig::default())
            .unwrap()
            .value;
        let RawMsgData::Plaintext { data, offset } = raw.msg_data else {
            panic!("expected plaintext msgData");
        };
        let peer = "192.0.2.70:161".parse().unwrap();
        let network = decode_scoped_pdu_with_consumption(data, offset, peer, None).unwrap_err();
        assert!(matches!(&*network, Error::Decode(error)
            if error.origin == DecodeErrorOrigin::Packet
                && error.offset == pdu_offset
                && error.kind == DecodeErrorKind::UnknownPduType(0xaf)
                && error.peer == Some(peer)));
    }

    #[test]
    fn v3_embedded_usm_decode_offset_is_packet_relative() {
        let global = MsgGlobalData::new(
            7,
            crate::MessageSize::new(1472).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, true),
        )
        .unwrap();
        let security_params = no_auth_security_params();
        let message = V3Message::new(
            global,
            security_params.clone(),
            ScopedPdu::with_empty_context(Pdu::get_request(42, &[])),
        )
        .unwrap();
        let mut encoded = message.encode().unwrap().to_vec();
        let usm_offset = encoded
            .windows(security_params.len())
            .position(|window| window == security_params.as_ref())
            .unwrap();
        encoded[usm_offset] = 0x31;

        let error = V3Message::decode(Bytes::from(encoded), DecodeConfig::default()).unwrap_err();
        assert!(matches!(&*error, Error::Decode(error)
            if error.origin == DecodeErrorOrigin::Packet
                && error.offset == usm_offset
                && error.kind == DecodeErrorKind::UnexpectedTag { expected: 0x30, actual: 0x31 }
                && error.peer.is_none()));
    }

    #[test]
    fn constructor_rejects_malformed_pdu_without_mutating_it() {
        let pdu = Pdu {
            request_id: 1,
            body: crate::pdu::PduBody::GetBulk {
                non_repeaters: crate::pdu::MAX_GET_BULK_VALUE + 1,
                max_repetitions: 0,
            },
            varbinds: vec![],
        };
        let original = pdu.clone();
        let scoped = ScopedPdu::with_empty_context(pdu.clone());
        let global = MsgGlobalData::new(
            1,
            crate::MessageSize::new(65_507).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, false),
        )
        .unwrap();
        let error = V3Message::new(global, no_auth_security_params(), scoped).unwrap_err();
        assert!(matches!(error.as_ref(), Error::InvalidMessage(_)));
        assert_eq!(error.kind(), crate::ErrorKind::InvalidMessage);
        assert_eq!(pdu, original);
    }

    #[test]
    fn construction_rejects_invalid_oid() {
        let pdu = Pdu::get_request(1, &[crate::oid::Oid::empty()]);
        let scoped = ScopedPdu::with_empty_context(pdu);
        let global = MsgGlobalData::new(
            1,
            crate::MessageSize::new(65_507).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, false),
        )
        .unwrap();
        let error = V3Message::new(global, no_auth_security_params(), scoped).unwrap_err();
        assert!(matches!(&*error, Error::InvalidOid(_)));
    }

    fn push_integer_content(buf: &mut EncodeBuf, content: &[u8]) {
        buf.push_bytes(content);
        buf.push_length(content.len()).unwrap();
        buf.push_tag(crate::ber::tag::universal::INTEGER);
    }

    fn global_data_with_integer_contents(
        msg_id: &[u8],
        msg_max_size: &[u8],
        security_model: &[u8],
    ) -> Bytes {
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            push_integer_content(buf, security_model);
            buf.push_octet_string(&[0x04])?;
            push_integer_content(buf, msg_max_size);
            push_integer_content(buf, msg_id);
            Ok(())
        })
        .unwrap();
        buf.finish()
    }

    #[test]
    fn test_security_level_flags() {
        assert_eq!(SecurityLevel::NoAuthNoPriv.to_flags(), 0x00);
        assert_eq!(SecurityLevel::AuthNoPriv.to_flags(), 0x01);
        assert_eq!(SecurityLevel::AuthPriv.to_flags(), 0x03);

        assert_eq!(
            SecurityLevel::from_flags(0x00),
            Some(SecurityLevel::NoAuthNoPriv)
        );
        assert_eq!(
            SecurityLevel::from_flags(0x01),
            Some(SecurityLevel::AuthNoPriv)
        );
        assert_eq!(
            SecurityLevel::from_flags(0x03),
            Some(SecurityLevel::AuthPriv)
        );
        assert_eq!(SecurityLevel::from_flags(0x02), None); // Invalid
    }

    #[test]
    fn security_level_try_from_u8() {
        assert_eq!(
            SecurityLevel::try_from(0x00),
            Ok(SecurityLevel::NoAuthNoPriv)
        );
        assert_eq!(SecurityLevel::try_from(0x01), Ok(SecurityLevel::AuthNoPriv));
        assert_eq!(SecurityLevel::try_from(0x03), Ok(SecurityLevel::AuthPriv));
        assert_eq!(SecurityLevel::try_from(0x02), Err(0x02));
    }

    #[test]
    fn security_level_into_u8() {
        assert_eq!(u8::from(SecurityLevel::NoAuthNoPriv), 0x00);
        assert_eq!(u8::from(SecurityLevel::AuthNoPriv), 0x01);
        assert_eq!(u8::from(SecurityLevel::AuthPriv), 0x03);
    }

    #[test]
    fn test_msg_flags_roundtrip() {
        let flags = MsgFlags::new(SecurityLevel::AuthPriv, true);
        let byte = flags.to_byte();
        assert_eq!(byte, 0x07); // auth=1, priv=1, reportable=1

        let decoded = MsgFlags::from_byte(byte).unwrap();
        assert_eq!(decoded.security_level, SecurityLevel::AuthPriv);
        assert!(decoded.reportable);
    }

    /// `classify_mpd_failure` must attribute a failure only to the field that
    /// actually caused `MsgGlobalData::decode` to reject, matching its
    /// fail-fast order: a message rejected at an earlier field (here a
    /// negative msgID) must not be blamed on a later unknown security model.
    #[test]
    fn classify_mpd_failure_mirrors_decode_fail_fast() {
        use crate::pdu::Pdu;
        use crate::v3::UsmSecurityParams;

        // Valid noAuthNoPriv v3 message; single-byte msgID and model keep the
        // byte patches below length-preserving.
        let global = MsgGlobalData::new(
            1,
            crate::MessageSize::new(65507).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, true),
        )
        .unwrap();
        let usm = UsmSecurityParams::new(
            Bytes::from_static(b"engine"),
            0,
            0,
            Bytes::from_static(b"u"),
        )
        .unwrap();
        let scoped = ScopedPdu::new(
            Bytes::from_static(b"engine"),
            Bytes::new(),
            Pdu::get_request(42, &[]),
        );
        let base = V3Message::new(global, usm.encode().unwrap(), scoped)
            .unwrap()
            .encode()
            .unwrap();

        let patch = |data: &Bytes, pattern: &[u8], off: usize, val: u8| -> Bytes {
            let mut b = data.to_vec();
            let pos = b
                .windows(pattern.len())
                .position(|w| w == pattern)
                .expect("pattern not found");
            b[pos + off] = val;
            Bytes::from(b)
        };

        // Only the security model is unknown -> UnknownSecurityModel.
        let model_pattern = [0x04, 0x01, 0x04, 0x02, 0x01, 0x03];
        let unknown_model = patch(&base, &model_pattern, 5, 99);
        assert_eq!(
            classify_mpd_failure(unknown_model),
            Some(MpdFailure::UnknownSecurityModel)
        );

        // Decode rejects at the negative msgID before reaching the model, so
        // the unknown model must not be attributed.
        let neg_id = patch(&base, &[0x02, 0x01, 0x01, 0x02, 0x03], 2, 0x81);
        let neg_id_unknown_model = patch(&neg_id, &model_pattern, 5, 99);
        assert_eq!(classify_mpd_failure(neg_id_unknown_model), None);
    }

    /// A valid envelope around a malformed plaintext scoped PDU must decode
    /// as a raw message (the scoped PDU is not parsed), while the eager
    /// decode fails. This is the invariant that lets HMAC verification run
    /// before plaintext PDU parsing.
    #[test]
    fn raw_decode_does_not_parse_plaintext_scoped_pdu() {
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            // msgData: structurally a SEQUENCE TLV, but garbage inside
            buf.push_sequence(|buf| {
                buf.push_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]);
                Ok(())
            })?;
            buf.push_octet_string(b"usm-params")?;
            MsgGlobalData::new(
                7,
                crate::MessageSize::new(65507).unwrap(),
                MsgFlags::new(SecurityLevel::AuthNoPriv, false),
            )
            .unwrap()
            .encode(buf)
            .unwrap();
            buf.push_integer(3);
            Ok(())
        })
        .unwrap();
        let encoded = buf.finish();

        assert!(
            V3Message::decode(encoded.clone(), DecodeConfig::default()).is_err(),
            "eager decode must reject the malformed scoped PDU"
        );

        let raw = RawV3Message::decode(encoded, DecodeConfig::default())
            .unwrap()
            .value;
        assert_eq!(raw.msg_id(), 7);
        assert_eq!(raw.security_level(), SecurityLevel::AuthNoPriv);
        assert_eq!(raw.security_params.as_ref(), b"usm-params");
        let RawMsgData::Plaintext { data: scoped, .. } = raw.msg_data else {
            panic!("expected plaintext msgData");
        };
        assert_eq!(scoped.as_ref(), &[0x30, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn v3_decoders_reject_over_width_version_alias() {
        let global = MsgGlobalData::new(
            7,
            crate::MessageSize::new(1472).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, true),
        )
        .unwrap();
        let scoped = ScopedPdu::with_empty_context(Pdu::get_request(42, &[]));
        let security_params = crate::v3::UsmSecurityParams::discovery().encode().unwrap();

        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            scoped.encode(buf).unwrap();
            buf.push_octet_string(&security_params)?;
            global.encode(buf).unwrap();
            // 2^32 + 3 previously narrowed to the accepted v3 value.
            push_integer_content(buf, &[0x01, 0x00, 0x00, 0x00, 0x03]);
            Ok(())
        })
        .unwrap();
        let encoded = buf.finish();

        assert!(V3Message::decode(encoded.clone(), DecodeConfig::default()).is_err());
        assert!(RawV3Message::decode(encoded.clone(), DecodeConfig::default()).is_err());
        assert!(crate::message::Message::decode(encoded, DecodeConfig::default()).is_err());
    }

    /// The captured plaintext bytes are the complete ScopedPDU TLV, so a
    /// later parse of a well-formed message succeeds from the raw bytes.
    #[test]
    fn raw_plaintext_bytes_reparse_as_scoped_pdu() {
        let global = MsgGlobalData::new(
            9,
            crate::MessageSize::new(1472).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, true),
        )
        .unwrap();
        let pdu = Pdu::get_request(42, &[oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)]);
        let scoped = ScopedPdu::new(b"engine".as_slice(), b"ctx".as_slice(), pdu);
        let msg = V3Message::new(global, no_auth_security_params(), scoped).unwrap();

        let raw = RawV3Message::decode(msg.encode().unwrap(), DecodeConfig::default())
            .unwrap()
            .value;
        let RawMsgData::Plaintext { data: bytes, .. } = raw.msg_data else {
            panic!("expected plaintext msgData");
        };
        let mut decoder = Decoder::new(bytes);
        let reparsed = ScopedPdu::decode(&mut decoder).unwrap();
        assert_eq!(reparsed.context_engine_id.as_ref(), b"engine");
        assert_eq!(reparsed.context_name.as_ref(), b"ctx");
        assert_eq!(reparsed.pdu.request_id, 42);
    }

    /// authPriv messages keep their ciphertext untouched.
    #[test]
    fn raw_decode_keeps_ciphertext() {
        let global = MsgGlobalData::new(
            200,
            crate::MessageSize::new(1472).unwrap(),
            MsgFlags::new(SecurityLevel::AuthPriv, false),
        )
        .unwrap();
        let msg = V3Message::new_with_opaque_encrypted_scoped_pdu(
            global,
            auth_security_params(true),
            Bytes::from_static(b"encrypted-data"),
        )
        .unwrap();

        let raw = RawV3Message::decode(msg.encode().unwrap(), DecodeConfig::default())
            .unwrap()
            .value;
        assert_eq!(raw.security_level(), SecurityLevel::AuthPriv);
        let RawMsgData::Encrypted(ciphertext) = raw.msg_data else {
            panic!("expected encrypted msgData");
        };
        assert_eq!(ciphertext.as_ref(), b"encrypted-data");
    }

    /// Privacy without authentication is rejected during envelope decode,
    /// before any authentication or PDU work can start.
    #[test]
    fn raw_decode_rejects_priv_without_auth_flags() {
        let global = MsgGlobalData::new(
            1,
            crate::MessageSize::new(65507).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, true),
        )
        .unwrap();
        let pdu = Pdu::get_request(1, &[]);
        let msg = V3Message::new(
            global,
            no_auth_security_params(),
            ScopedPdu::with_empty_context(pdu),
        )
        .unwrap();
        let mut bytes = msg.encode().unwrap().to_vec();
        // Locate the single-byte msgFlags OCTET STRING (0x04 0x01 0x04) and
        // patch it to priv-without-auth (0x02).
        let pos = bytes
            .windows(3)
            .position(|w| w == [0x04, 0x01, 0x04])
            .expect("msgFlags not found");
        bytes[pos + 2] = 0x02;

        let error = RawV3Message::decode(Bytes::from(bytes), DecodeConfig::default()).unwrap_err();
        assert!(matches!(&*error, Error::Decode(error)
            if error.origin == DecodeErrorOrigin::Packet
                && error.offset == pos + 2
                && error.kind == DecodeErrorKind::InvalidMsgFlags));
    }

    /// Reserved and reportable flag bits do not alter the derived security
    /// level (RFC 3412 Section 7.2 derives the level from the auth/priv bits
    /// only).
    #[test]
    fn raw_decode_ignores_reserved_bits_for_level() {
        let global = MsgGlobalData::new(
            1,
            crate::MessageSize::new(65507).unwrap(),
            MsgFlags::new(SecurityLevel::AuthNoPriv, false),
        )
        .unwrap();
        let pdu = Pdu::get_request(1, &[]);
        let msg = V3Message::new(
            global,
            auth_security_params(false),
            ScopedPdu::with_empty_context(pdu),
        )
        .unwrap();
        let mut bytes = msg.encode().unwrap().to_vec();
        let pos = bytes
            .windows(3)
            .position(|w| w == [0x04, 0x01, 0x01])
            .expect("msgFlags not found");
        // auth + reportable + a reserved bit
        bytes[pos + 2] = 0x01 | 0x04 | 0x08;

        let raw = RawV3Message::decode(Bytes::from(bytes), DecodeConfig::default())
            .unwrap()
            .value;
        assert_eq!(raw.security_level(), SecurityLevel::AuthNoPriv);
        assert!(raw.global_data.msg_flags.reportable);
    }

    #[test]
    fn v3_decoders_share_envelope_and_root_suffix_policy() {
        let global = MsgGlobalData::new(
            17,
            crate::MessageSize::new(1472).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, false),
        )
        .unwrap();
        let scoped = ScopedPdu::with_empty_context(Pdu::get_request(23, &[]));

        // Encode an extra INTEGER after msgData inside the outer sequence.
        let mut with_outer_field = EncodeBuf::new();
        with_outer_field
            .push_sequence(|buf| {
                buf.push_integer(99);
                scoped.encode(buf).unwrap();
                buf.push_octet_string(&no_auth_security_params())?;
                global.encode(buf).unwrap();
                buf.push_integer(3);
                Ok(())
            })
            .unwrap();
        let with_outer_field = with_outer_field.finish();
        assert!(RawV3Message::decode(with_outer_field.clone(), DecodeConfig::default()).is_err());
        assert!(V3Message::decode(with_outer_field.clone(), DecodeConfig::default()).is_err());
        assert!(
            crate::message::Message::decode(with_outer_field, DecodeConfig::default()).is_err()
        );

        // Encode an extra INTEGER inside msgGlobalData.
        let mut with_global_field = EncodeBuf::new();
        with_global_field
            .push_sequence(|buf| {
                scoped.encode(buf).unwrap();
                buf.push_octet_string(&no_auth_security_params())?;
                buf.push_sequence(|buf| {
                    buf.push_integer(99);
                    buf.push_integer(V3SecurityModel::Usm.as_i32());
                    buf.push_octet_string(&[0])?;
                    buf.push_integer(1472);
                    buf.push_integer(17);
                    Ok(())
                })?;
                buf.push_integer(3);
                Ok(())
            })
            .unwrap();
        let with_global_field = with_global_field.finish();
        assert!(RawV3Message::decode(with_global_field.clone(), DecodeConfig::default()).is_err());
        assert!(V3Message::decode(with_global_field.clone(), DecodeConfig::default()).is_err());
        assert!(
            crate::message::Message::decode(with_global_field, DecodeConfig::default()).is_err()
        );

        // Append another top-level TLV after an otherwise complete message.
        let message = V3Message::new(global, no_auth_security_params(), scoped).unwrap();
        let valid = message.encode().unwrap();
        assert_eq!(
            RawV3Message::decode(valid.clone(), DecodeConfig::default())
                .unwrap()
                .anomalies,
            Vec::<crate::DecodeAnomaly>::new()
        );
        assert_eq!(
            V3Message::decode(valid.clone(), DecodeConfig::STRICT)
                .unwrap()
                .anomalies,
            Vec::<crate::DecodeAnomaly>::new()
        );
        assert_eq!(
            crate::message::Message::decode(valid.clone(), DecodeConfig::STRICT)
                .unwrap()
                .anomalies,
            Vec::<crate::DecodeAnomaly>::new()
        );
        let mut with_root_trailing = valid.to_vec();
        with_root_trailing.extend_from_slice(&[0x05, 0]);
        let with_root_trailing = Bytes::from(with_root_trailing);

        for anomalies in [
            RawV3Message::decode(with_root_trailing.clone(), DecodeConfig::default())
                .unwrap()
                .anomalies,
            V3Message::decode(with_root_trailing.clone(), DecodeConfig::default())
                .unwrap()
                .anomalies,
            crate::message::Message::decode(with_root_trailing.clone(), DecodeConfig::default())
                .unwrap()
                .anomalies,
        ] {
            assert_eq!(
                anomalies,
                vec![crate::DecodeAnomaly::TrailingBytes {
                    original_length: 2,
                    canonical_length: 0,
                }]
            );
        }

        assert!(RawV3Message::decode(with_root_trailing.clone(), DecodeConfig::STRICT).is_err());
        assert!(V3Message::decode(with_root_trailing.clone(), DecodeConfig::STRICT).is_err());
        assert!(crate::message::Message::decode(with_root_trailing, DecodeConfig::STRICT).is_err());
    }

    #[test]
    fn test_msg_global_data_roundtrip() {
        let global = MsgGlobalData::new(
            12345,
            crate::MessageSize::new(1472).unwrap(),
            MsgFlags::new(SecurityLevel::AuthNoPriv, true),
        )
        .unwrap();

        let mut buf = EncodeBuf::new();
        global.encode(&mut buf).unwrap();
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let decoded = MsgGlobalData::decode(&mut decoder).unwrap();

        assert_eq!(decoded.msg_id, 12345);
        assert_eq!(decoded.msg_max_size, 1472);
        assert_eq!(decoded.msg_flags.security_level, SecurityLevel::AuthNoPriv);
        assert!(decoded.msg_flags.reportable);
        assert_eq!(decoded.msg_security_model, V3SecurityModel::Usm);
    }

    #[test]
    fn test_scoped_pdu_roundtrip() {
        let pdu = Pdu::get_request(42, &[oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)]);
        let scoped = ScopedPdu::new(b"engine".as_slice(), b"ctx".as_slice(), pdu);

        let mut buf = EncodeBuf::new();
        scoped.encode(&mut buf).unwrap();
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let decoded = ScopedPdu::decode(&mut decoder).unwrap();

        assert_eq!(decoded.context_engine_id.as_ref(), b"engine");
        assert_eq!(decoded.context_name.as_ref(), b"ctx");
        assert_eq!(decoded.pdu.request_id, 42);
    }

    #[test]
    fn scoped_pdu_rejects_trailing_sequence_fields() {
        let pdu = Pdu::get_request(42, &[]);
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_integer(99);
            pdu.encode(buf).unwrap();
            buf.push_octet_string(b"ctx")?;
            buf.push_octet_string(b"engine")
        })
        .unwrap();

        let mut decoder = Decoder::new(buf.finish());
        assert!(ScopedPdu::decode(&mut decoder).is_err());
    }

    #[test]
    fn test_v3_message_plaintext_roundtrip() {
        let global = MsgGlobalData::new(
            100,
            crate::MessageSize::new(1472).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, true),
        )
        .unwrap();
        let pdu = Pdu::get_request(42, &[oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)]);
        let scoped = ScopedPdu::with_empty_context(pdu);
        let msg = V3Message::new(global, no_auth_security_params(), scoped).unwrap();

        let encoded = msg.encode().unwrap();
        let decoded = V3Message::decode(encoded, DecodeConfig::default())
            .unwrap()
            .value;

        assert_eq!(decoded.global_data.msg_id, 100);
        assert_eq!(decoded.security_level(), SecurityLevel::NoAuthNoPriv);
        assert_eq!(decoded.security_params, no_auth_security_params());

        let scoped_pdu = decoded.scoped_pdu().unwrap();
        assert_eq!(scoped_pdu.pdu.request_id, 42);
    }

    #[test]
    fn test_v3_message_encrypted_roundtrip() {
        let global = MsgGlobalData::new(
            200,
            crate::MessageSize::new(1472).unwrap(),
            MsgFlags::new(SecurityLevel::AuthPriv, false),
        )
        .unwrap();
        let msg = V3Message::new_with_opaque_encrypted_scoped_pdu(
            global,
            auth_security_params(true),
            Bytes::from_static(b"encrypted-data"),
        )
        .unwrap();

        let encoded = msg.encode().unwrap();
        let decoded = V3Message::decode(encoded, DecodeConfig::default())
            .unwrap()
            .value;

        assert_eq!(decoded.global_data.msg_id, 200);
        assert_eq!(decoded.security_level(), SecurityLevel::AuthPriv);

        match &decoded.data {
            V3MessageData::Encrypted(data) => {
                assert_eq!(data.as_ref(), b"encrypted-data");
            }
            V3MessageData::Plaintext(_) => panic!("expected encrypted data"),
        }
    }

    #[test]
    fn test_msg_global_data_rejects_msg_max_size_below_minimum() {
        // Build a low-level malformed inbound vector: safe construction cannot
        // represent this below-minimum msgMaxSize.
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_integer(V3SecurityModel::Usm.as_i32());
            buf.push_octet_string(&[MsgFlags::new(SecurityLevel::NoAuthNoPriv, true).to_byte()])?;
            buf.push_integer(400);
            buf.push_integer(100);
            Ok(())
        })
        .unwrap();
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let result = MsgGlobalData::decode(&mut decoder);

        assert!(result.is_err());
        assert!(matches!(*result.unwrap_err(), Error::Decode(_)));
    }

    #[test]
    fn test_msg_global_data_accepts_msg_max_size_at_minimum() {
        // 484 is exactly the RFC 3412 minimum
        let global = MsgGlobalData::new(
            100,
            crate::MessageSize::new(484).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, true),
        )
        .unwrap();

        let mut buf = EncodeBuf::new();
        global.encode(&mut buf).unwrap();
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let decoded = MsgGlobalData::decode(&mut decoder).unwrap();

        assert_eq!(decoded.msg_max_size, 484);
    }

    #[test]
    fn v3_security_model_accepts_only_usm() {
        assert_eq!(V3SecurityModel::from_i32(3), Some(V3SecurityModel::Usm));
        for model in [i32::MIN, -1, 0, 1, 2, 4, 99, i32::MAX] {
            assert_eq!(V3SecurityModel::from_i32(model), None);
        }
    }

    #[test]
    fn msg_global_data_rejects_non_usm_security_models() {
        for model in [-1, 0, 1, 2, 4, 99, i32::MAX] {
            let mut buf = EncodeBuf::new();
            buf.push_sequence(|buf| {
                buf.push_integer(model);
                buf.push_octet_string(&[0x04])?;
                buf.push_integer(1472);
                buf.push_integer(100);
                Ok(())
            })
            .unwrap();

            let mut decoder = Decoder::new(buf.finish());
            assert!(matches!(
                *MsgGlobalData::decode(&mut decoder).unwrap_err(),
                Error::Decode(_)
            ));
        }
    }

    #[test]
    fn msg_global_data_rejects_over_width_integer_aliases() {
        const ZERO: &[u8] = &[0x00];
        const MSG_MAX_SIZE: &[u8] = &[0x05, 0xC0];
        const USM: &[u8] = &[0x03];

        // Each value is 2^32 plus an otherwise accepted field value.
        let aliased_msg_id =
            global_data_with_integer_contents(&[0x01, 0x00, 0x00, 0x00, 0x00], MSG_MAX_SIZE, USM);
        let aliased_msg_max_size =
            global_data_with_integer_contents(ZERO, &[0x01, 0x00, 0x00, 0x05, 0xC0], USM);
        let aliased_security_model =
            global_data_with_integer_contents(ZERO, MSG_MAX_SIZE, &[0x01, 0x00, 0x00, 0x00, 0x03]);

        for encoded in [aliased_msg_id, aliased_msg_max_size, aliased_security_model] {
            let mut decoder = Decoder::new(encoded);
            assert!(MsgGlobalData::decode(&mut decoder).is_err());
        }
    }

    #[test]
    fn test_msg_global_data_rejects_zero_length_msg_flags() {
        // RFC 3412 Section 6.4: msgFlags OCTET STRING (SIZE(1))
        // SEQUENCE { msg_id, msg_max_size, msgFlags=<empty>, msgSecurityModel=3(Usm) }
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_integer(3); // Usm
            buf.push_octet_string(&[])?; // zero-length msgFlags
            buf.push_integer(1472); // msg_max_size
            buf.push_integer(100); // msg_id
            Ok(())
        })
        .unwrap();
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let result = MsgGlobalData::decode(&mut decoder);

        assert!(result.is_err());
        assert!(matches!(*result.unwrap_err(), Error::Decode(_)));
    }

    #[test]
    fn test_msg_global_data_rejects_two_byte_msg_flags() {
        // RFC 3412 Section 6.4: msgFlags OCTET STRING (SIZE(1))
        // SEQUENCE { msg_id, msg_max_size, msgFlags=<two bytes>, msgSecurityModel=3(Usm) }
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_integer(3); // Usm
            buf.push_octet_string(&[0x04, 0x00])?; // two-byte msgFlags
            buf.push_integer(1472); // msg_max_size
            buf.push_integer(100); // msg_id
            Ok(())
        })
        .unwrap();
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let result = MsgGlobalData::decode(&mut decoder);

        assert!(result.is_err());
        assert!(matches!(*result.unwrap_err(), Error::Decode(_)));
    }

    #[test]
    fn test_msg_global_data_accepts_one_byte_msg_flags() {
        // Control: a valid single-byte msgFlags (reportable, noAuthNoPriv) must be accepted
        // SEQUENCE { msg_id, msg_max_size, msgFlags=[0x04], msgSecurityModel=3(Usm) }
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_integer(3); // Usm
            buf.push_octet_string(&[0x04])?; // reportable, noAuthNoPriv
            buf.push_integer(1472); // msg_max_size
            buf.push_integer(100); // msg_id
            Ok(())
        })
        .unwrap();
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let decoded = MsgGlobalData::decode(&mut decoder).unwrap();

        assert_eq!(decoded.msg_flags, MsgFlags::from_byte(0x04).unwrap());
        assert_eq!(decoded.msg_security_model, V3SecurityModel::Usm);
    }

    #[test]
    fn test_msg_global_data_accepts_usm_security_model() {
        // USM (3) should be accepted
        let global = MsgGlobalData::new(
            100,
            crate::MessageSize::new(1472).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, true),
        )
        .unwrap();

        let mut buf = EncodeBuf::new();
        global.encode(&mut buf).unwrap();
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let decoded = MsgGlobalData::decode(&mut decoder).unwrap();

        assert_eq!(decoded.msg_security_model, V3SecurityModel::Usm);
    }

    // RFC 3412 bounds tests for msgID and msgMaxSize
    //
    // RFC 3412 HeaderData definition specifies:
    //   msgID INTEGER (0..2147483647)
    //   msgMaxSize INTEGER (484..2147483647)
    //
    // Values outside these ranges should be rejected.

    #[test]
    fn test_msg_global_data_rejects_negative_msg_id() {
        // RFC 3412: msgID must be in range [0..2147483647]
        // Negative values should be rejected
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_integer(3); // USM security model
            buf.push_octet_string(&[0x04])?; // reportable, noAuthNoPriv
            buf.push_integer(1472); // valid msg_max_size
            buf.push_integer(-1); // negative msg_id
            Ok(())
        })
        .unwrap();
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let result = MsgGlobalData::decode(&mut decoder);

        assert!(result.is_err());
        assert!(matches!(*result.unwrap_err(), Error::Decode(_)));
    }

    #[test]
    fn test_msg_global_data_rejects_negative_msg_max_size() {
        // RFC 3412: msgMaxSize must be in range [484..2147483647]
        // Negative values (from signed integer interpretation) should be rejected
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_integer(3); // USM security model
            buf.push_octet_string(&[0x04])?; // reportable, noAuthNoPriv
            buf.push_integer(-1); // negative msg_max_size (would be > 2^31-1 unsigned)
            buf.push_integer(100); // valid msg_id
            Ok(())
        })
        .unwrap();
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let result = MsgGlobalData::decode(&mut decoder);

        assert!(result.is_err());
        assert!(matches!(*result.unwrap_err(), Error::Decode(_)));
    }

    #[test]
    fn test_msg_global_data_accepts_msg_id_at_zero() {
        // RFC 3412: msgID 0 is at the lower bound, should be accepted
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_integer(3); // USM
            buf.push_octet_string(&[0x04])?; // reportable, noAuthNoPriv
            buf.push_integer(1472); // valid msg_max_size
            buf.push_integer(0); // msg_id at lower bound
            Ok(())
        })
        .unwrap();
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let decoded = MsgGlobalData::decode(&mut decoder).unwrap();

        assert_eq!(decoded.msg_id, 0);
    }

    #[test]
    fn test_msg_global_data_accepts_msg_id_at_maximum() {
        // RFC 3412: msgID 2147483647 is at the upper bound, should be accepted
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_integer(3); // USM
            buf.push_octet_string(&[0x04])?; // reportable, noAuthNoPriv
            buf.push_integer(1472); // valid msg_max_size
            buf.push_integer(i32::MAX); // msg_id at upper bound (2147483647)
            Ok(())
        })
        .unwrap();
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let decoded = MsgGlobalData::decode(&mut decoder).unwrap();

        assert_eq!(decoded.msg_id, i32::MAX);
    }

    #[test]
    fn test_msg_global_data_accepts_msg_max_size_at_maximum() {
        // RFC 3412: msgMaxSize 2147483647 is at the upper bound, should be accepted
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_integer(3); // USM
            buf.push_octet_string(&[0x04])?; // reportable, noAuthNoPriv
            buf.push_integer(i32::MAX); // msg_max_size at upper bound (2147483647)
            buf.push_integer(100); // valid msg_id
            Ok(())
        })
        .unwrap();
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let decoded = MsgGlobalData::decode(&mut decoder).unwrap();

        assert_eq!(decoded.msg_max_size, i32::MAX);
    }
}
