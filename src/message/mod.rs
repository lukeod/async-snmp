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

pub use community::CommunityMessage;
pub use v3::{
    MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, SecurityModel, V3Message, V3MessageData,
};

use crate::ber::Decoder;
use crate::error::{DecodeErrorKind, Error, Result};
use crate::pdu::Pdu;
use crate::version::Version;
use bytes::Bytes;

/// Decoded SNMP message (any version).
///
/// This enum provides a unified interface for working with SNMP messages
/// regardless of version. Use [`Message::decode`] to parse incoming data.
#[derive(Debug)]
pub enum Message {
    /// SNMPv1 or SNMPv2c message with community string
    Community(CommunityMessage),
    /// SNMPv3 message with USM security
    V3(V3Message),
}

impl Message {
    /// Get a reference to the PDU.
    ///
    /// For V3 messages with encrypted data, this will panic.
    /// Use `try_pdu()` for a fallible version.
    pub fn pdu(&self) -> &Pdu {
        match self {
            Message::Community(m) => &m.pdu,
            Message::V3(m) => m.pdu().expect("V3 message is encrypted; use try_pdu()"),
        }
    }

    /// Try to get a reference to the PDU.
    ///
    /// Returns `None` for encrypted V3 messages.
    pub fn try_pdu(&self) -> Option<&Pdu> {
        match self {
            Message::Community(m) => Some(&m.pdu),
            Message::V3(m) => m.pdu(),
        }
    }

    /// Consume and return the PDU.
    ///
    /// For V3 messages with encrypted data, this will panic.
    /// Use `try_into_pdu()` for a fallible version.
    pub fn into_pdu(self) -> Pdu {
        match self {
            Message::Community(m) => m.into_pdu(),
            Message::V3(m) => m.into_pdu().expect("V3 message is encrypted"),
        }
    }

    /// Try to consume and return the PDU.
    ///
    /// Returns `None` for encrypted V3 messages.
    pub fn try_into_pdu(self) -> Option<Pdu> {
        match self {
            Message::Community(m) => Some(m.into_pdu()),
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
        let mut decoder = Decoder::new(data.clone());

        // Peek at version to determine message type
        let mut seq = decoder.read_sequence()?;
        let version_num = seq.read_integer()?;
        let version = Version::from_i32(version_num).ok_or_else(|| {
            Error::decode(seq.offset(), DecodeErrorKind::UnknownVersion(version_num))
        })?;

        // Re-decode from start with appropriate handler
        match version {
            Version::V1 | Version::V2c => {
                let msg = CommunityMessage::decode(data)?;
                Ok(Message::Community(msg))
            }
            Version::V3 => {
                let msg = V3Message::decode(data)?;
                Ok(Message::V3(msg))
            }
        }
    }
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
