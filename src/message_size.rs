//! Validated SNMP message-size policy.
//!
//! `MessageSize` is the wire value used by SNMPv3 `msgMaxSize`. `ReceiveLimits`
//! additionally records the hard receive/decode bound, which intentionally may
//! be slightly larger for UDP so bounded oversized datagrams can be tolerated
//! without advertising that tolerance.

use std::fmt;

/// RFC 3412 minimum value for `msgMaxSize`.
pub const MESSAGE_SIZE_MINIMUM: usize = 484;
/// RFC 3412 maximum value for `msgMaxSize`.
pub const MESSAGE_SIZE_MAXIMUM: usize = i32::MAX as usize;
/// Largest UDP payload advertised by this crate.
pub const MAX_UDP_PAYLOAD: usize = 65_507;
/// Bounded UDP receive-buffer size.
pub const UDP_RECEIVE_BUFFER_SIZE: usize = 65_535;

/// Error returned when a message-size value is outside its valid range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageSizeError {
    value: i128,
    maximum: usize,
}

impl MessageSizeError {
    const fn new(value: i128, maximum: usize) -> Self {
        Self { value, maximum }
    }
}

impl fmt::Display for MessageSizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "message size {} is outside {}..={}",
            self.value, MESSAGE_SIZE_MINIMUM, self.maximum
        )
    }
}

impl std::error::Error for MessageSizeError {}

/// A wire-valid SNMPv3 `msgMaxSize` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageSize(i32);

impl MessageSize {
    /// Construct from an unsigned platform-sized value.
    pub const fn new(value: usize) -> std::result::Result<Self, MessageSizeError> {
        if value < MESSAGE_SIZE_MINIMUM || value > MESSAGE_SIZE_MAXIMUM {
            Err(MessageSizeError::new(value as i128, MESSAGE_SIZE_MAXIMUM))
        } else {
            Ok(Self(value as i32))
        }
    }

    /// Construct from the signed wire representation.
    pub const fn from_i32(value: i32) -> std::result::Result<Self, MessageSizeError> {
        if value < MESSAGE_SIZE_MINIMUM as i32 {
            Err(MessageSizeError::new(value as i128, MESSAGE_SIZE_MAXIMUM))
        } else {
            Ok(Self(value))
        }
    }

    /// Return the value as `usize`.
    #[must_use]
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }

    /// Return the value as `u32`.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0 as u32
    }

    /// Return the wire representation.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self.0
    }
}

impl PartialEq<i32> for MessageSize {
    fn eq(&self, other: &i32) -> bool {
        self.0 == *other
    }
}

impl PartialEq<u32> for MessageSize {
    fn eq(&self, other: &u32) -> bool {
        self.as_u32() == *other
    }
}

impl PartialEq<usize> for MessageSize {
    fn eq(&self, other: &usize) -> bool {
        self.as_usize() == *other
    }
}

impl fmt::Display for MessageSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl TryFrom<usize> for MessageSize {
    type Error = MessageSizeError;
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<u32> for MessageSize {
    type Error = MessageSizeError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value as usize)
    }
}

impl TryFrom<i32> for MessageSize {
    type Error = MessageSizeError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Self::from_i32(value)
    }
}

/// Validated local receive and advertisement limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiveLimits {
    advertised: MessageSize,
    accepted: usize,
}

impl ReceiveLimits {
    /// Validate a UDP advertisement while retaining the fixed receive tolerance.
    pub const fn udp(advertised: usize) -> std::result::Result<Self, MessageSizeError> {
        if advertised > MAX_UDP_PAYLOAD {
            return Err(MessageSizeError::new(advertised as i128, MAX_UDP_PAYLOAD));
        }
        match MessageSize::new(advertised) {
            Ok(advertised) => Ok(Self {
                advertised,
                accepted: UDP_RECEIVE_BUFFER_SIZE,
            }),
            Err(error) => Err(error),
        }
    }

    /// Validate one exact total-message limit for TCP framing and advertisement.
    pub const fn tcp(limit: usize) -> std::result::Result<Self, MessageSizeError> {
        match MessageSize::new(limit) {
            Ok(advertised) => Ok(Self {
                advertised,
                accepted: limit,
            }),
            Err(error) => Err(error),
        }
    }

    /// The local capacity placed in V3 `msgMaxSize`.
    #[must_use]
    pub const fn advertised(self) -> MessageSize {
        self.advertised
    }

    /// Hard total input size accepted by the receive/decode path.
    #[must_use]
    pub const fn accepted(self) -> usize {
        self.accepted
    }
}

/// Maximum UDP receive limits used by agents and notification receivers.
pub const UDP_RECEIVE_LIMITS: ReceiveLimits = ReceiveLimits {
    advertised: MessageSize(MAX_UDP_PAYLOAD as i32),
    accepted: UDP_RECEIVE_BUFFER_SIZE,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_size_boundaries() {
        for rejected in [0usize, 483, i32::MAX as usize + 1, usize::MAX] {
            assert!(MessageSize::new(rejected).is_err(), "accepted {rejected}");
        }
        assert_eq!(MessageSize::new(484).unwrap().as_i32(), 484);
        assert_eq!(
            MessageSize::new(i32::MAX as usize).unwrap().as_i32(),
            i32::MAX
        );
        assert!(MessageSize::from_i32(-1).is_err());
    }

    #[test]
    fn udp_limits_distinguish_advertised_and_accepted() {
        let limits = ReceiveLimits::udp(MAX_UDP_PAYLOAD).unwrap();
        assert_eq!(limits.advertised().as_usize(), MAX_UDP_PAYLOAD);
        assert_eq!(limits.accepted(), UDP_RECEIVE_BUFFER_SIZE);
        assert!(ReceiveLimits::udp(483).is_err());
        assert!(ReceiveLimits::udp(MAX_UDP_PAYLOAD + 1).is_err());
        assert!(ReceiveLimits::udp(usize::MAX).is_err());
    }

    #[test]
    fn tcp_limit_is_exact() {
        for value in [484usize, 10 * 1024 * 1024, i32::MAX as usize] {
            let limits = ReceiveLimits::tcp(value).unwrap();
            assert_eq!(limits.advertised().as_usize(), value);
            assert_eq!(limits.accepted(), value);
        }
        assert!(ReceiveLimits::tcp(483).is_err());
        assert!(ReceiveLimits::tcp(i32::MAX as usize + 1).is_err());
    }
}
