//! BER (Basic Encoding Rules) codec for SNMP.
//!
//! Encodes and decodes the Basic Encoding Rules (BER) used by SNMP.
//! The implementation follows X.690 with permissive parsing aligned with net-snmp behavior.

mod decode;
mod encode;
pub(crate) mod length;
pub mod tag;

pub use decode::*;
pub use encode::*;
pub use length::*;
pub use tag::*;
