//! BER (Basic Encoding Rules) codec for SNMP.
//!
//! This module provides encoding and decoding of BER-encoded data as used in SNMP.
//! The implementation follows X.690 with permissive parsing aligned with net-snmp behavior.

mod decode;
mod encode;
mod length;
pub mod tag;

pub use decode::*;
pub use encode::*;
pub use length::*;
pub use tag::*;
