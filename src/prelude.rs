//! Common types, traits, and macros for async-snmp applications.
//!
//! # Usage
//!
//! ```rust,no_run
//! use async_snmp::prelude::*;
//! ```
//!
//! The prelude imports:
//!
//! - Client configuration: [`Auth`], [`Client`], [`ClientBuilder`], [`Retry`],
//!   and [`TargetClientBuilder`]
//! - Protocol data: [`Oid`], [`Value`], [`VarBind`], and [`Version`]
//! - Decode compatibility: [`DecodeAnomaly`] and [`DecodeConfig`]
//! - Error handling: [`Error`] and [`Result`]
//! - SNMPv3 protocols: [`AuthProtocol`] and [`PrivProtocol`]
//! - The [`oid!`] macro for OID construction (wire validity is checked during
//!   encoding)

pub use crate::client::{Auth, Client, ClientBuilder, Retry, TargetClientBuilder};
pub use crate::compatibility::{DecodeAnomaly, DecodeConfig};
pub use crate::error::{Error, Result};
pub use crate::oid::Oid;
pub use crate::v3::{AuthProtocol, PrivProtocol};
pub use crate::value::Value;
pub use crate::varbind::VarBind;
pub use crate::version::Version;

#[doc(no_inline)]
pub use crate::oid;
