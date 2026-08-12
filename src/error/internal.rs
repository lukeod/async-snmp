//! Internal error types for tracing and debugging.

pub(crate) use super::{DecodeErrorKind, DecodeErrorOrigin};

/// Authentication error kinds (`SNMPv3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthErrorKind {
    /// No credentials configured for this operation.
    NoCredentials,
    /// No authentication key available.
    NoAuthKey,
    /// HMAC verification failed.
    HmacMismatch,
    /// Could not locate auth params in message.
    AuthParamsNotFound,
}

impl std::fmt::Display for AuthErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCredentials => write!(f, "no credentials configured"),
            Self::NoAuthKey => write!(f, "no authentication key available"),
            Self::HmacMismatch => write!(f, "HMAC verification failed"),
            Self::AuthParamsNotFound => write!(f, "could not locate auth params in message"),
        }
    }
}

/// Cryptographic error kinds (encryption/decryption).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CryptoErrorKind {
    /// No privacy key available.
    NoPrivKey,
}

impl std::fmt::Display for CryptoErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPrivKey => write!(f, "no privacy key available"),
        }
    }
}

/// BER encode error kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EncodeErrorKind {
    /// Could not locate auth params position in encoded message.
    MissingAuthParams,
}

impl std::fmt::Display for EncodeErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAuthParams => {
                write!(f, "could not find auth params position in encoded message")
            }
        }
    }
}
