//! SNMP message wrappers.
//!
//! Messages encapsulate PDUs with version and authentication information.
//!
//! # Message Types
//!
//! - [`CommunityMessage`] - V1/V2c messages with community string auth
//! - [`V3Message`] - V3 messages with USM security

mod community;
mod v3;

pub use community::{CommunityMessage, CommunityPdu};
pub(crate) use v3::{MpdFailure, classify_mpd_failure};
pub use v3::{
    MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, SecurityModel, V3Message, V3MessageData,
};

use crate::ber::Decoder;
use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, Result, UNKNOWN_TARGET};
use crate::pdu::Pdu;
use crate::version::Version;
use bytes::Bytes;

/// Decoded SNMP message (any version).
///
/// This enum provides a unified interface for working with SNMP messages
/// regardless of version. Use [`Message::decode`] to parse incoming data.
#[derive(Debug)]
pub enum Message {
    /// `SNMPv1` or `SNMPv2c` message with community string
    Community(CommunityMessage),
    /// `SNMPv3` message with USM security
    V3(V3Message),
}

impl Message {
    /// Get a reference to the PDU.
    ///
    /// Returns `None` for encrypted V3 messages or `SNMPv1` Trap messages.
    pub fn pdu(&self) -> Option<&Pdu> {
        match self {
            Message::Community(m) => m.pdu.standard(),
            Message::V3(m) => m.pdu(),
        }
    }

    /// Consume and return the PDU.
    ///
    /// Returns `None` for encrypted V3 messages or `SNMPv1` Trap messages.
    pub fn into_pdu(self) -> Option<Pdu> {
        match self {
            Message::Community(m) => match m.pdu {
                CommunityPdu::Standard(p) => Some(p),
                CommunityPdu::TrapV1(_) => None,
            },
            Message::V3(m) => m.into_pdu(),
        }
    }

    /// Get the SNMP version.
    pub fn version(&self) -> Version {
        match self {
            Message::Community(m) => m.version,
            Message::V3(_) => Version::V3,
        }
    }

    /// Decode a message from bytes.
    ///
    /// Automatically detects the SNMP version and parses accordingly.
    pub fn decode(data: Bytes) -> Result<Self> {
        let mut decoder = Decoder::new(data);
        let mut seq = decoder.read_sequence()?;

        // Read version to determine message type
        let version_num = seq.read_integer()?;
        let version = Version::from_i32(version_num).ok_or_else(|| {
            tracing::debug!(target: "async_snmp::message", { offset = seq.offset(), kind = %DecodeErrorKind::UnknownVersion(version_num) }, "decode error");
            Error::MalformedResponse {
                target: UNKNOWN_TARGET,
            }
            .boxed()
        })?;

        // Decode remainder using version-specific handler
        match version {
            Version::V1 | Version::V2c => {
                let msg = CommunityMessage::decode_from_sequence(&mut seq, version)?;
                Ok(Message::Community(msg))
            }
            Version::V3 => {
                let msg = V3Message::decode_from_sequence(&mut seq)?;
                Ok(Message::V3(msg))
            }
        }
    }
}

/// Peek at the version integer of an encoded SNMP message without decoding
/// the rest, for version-based dispatch. `target` is only used as the
/// error's target address.
pub(crate) fn peek_version(data: Bytes, target: std::net::SocketAddr) -> Result<Version> {
    let mut decoder = Decoder::with_target(data, target);
    let mut seq = decoder.read_sequence()?;
    let version_num = seq.read_integer()?;
    Version::from_i32(version_num).ok_or_else(|| {
        tracing::debug!(target: "async_snmp::message", { source = %target, kind = %DecodeErrorKind::UnknownVersion(version_num) }, "unknown SNMP version");
        Error::MalformedResponse { target }.boxed()
    })
}

// Convenience conversions
impl From<CommunityMessage> for Message {
    fn from(msg: CommunityMessage) -> Self {
        Message::Community(msg)
    }
}

impl From<V3Message> for Message {
    fn from(msg: V3Message) -> Self {
        Message::V3(msg)
    }
}
