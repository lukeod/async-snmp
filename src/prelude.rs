//! Prelude module for convenient imports.
//!
//! This module provides a convenient set of commonly-used types and traits
//! for working with the async-snmp library.
//!
//! # Usage
//!
//! ```rust,no_run
//! use async_snmp::prelude::*;
//! ```
//!
//! This imports:
//! - Core types: [`Client`], [`Oid`], [`Value`], [`VarBind`]
//! - Error handling: [`Error`], [`Result`]
//! - V3 protocols: [`AuthProtocol`], [`PrivProtocol`]
//! - The [`oid!`] macro for compile-time OID construction

pub use crate::client::Client;
pub use crate::error::{Error, Result};
pub use crate::oid::Oid;
pub use crate::v3::{AuthProtocol, PrivProtocol};
pub use crate::value::Value;
pub use crate::varbind::VarBind;
pub use crate::version::Version;

#[doc(no_inline)]
pub use crate::oid;
