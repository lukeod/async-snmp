//! BER tag definitions for SNMP.
//!
//! Tag encoding follows X.690 Section 8.1.2:
//! - Bits 7-6: Class (00=Universal, 01=Application, 10=Context-specific, 11=Private)
//! - Bit 5: Primitive (0) or Constructed (1)
//! - Bits 4-0: Tag number (0-30, or 31 for long form)

/// Tag class bits (bits 7-6)
pub mod class {
    pub const UNIVERSAL: u8 = 0x00;
    pub const APPLICATION: u8 = 0x40;
    pub const CONTEXT_SPECIFIC: u8 = 0x80;
    pub const PRIVATE: u8 = 0xC0;
}

/// Constructed bit (bit 5)
pub const CONSTRUCTED: u8 = 0x20;

/// Universal tags (class bits 00)
pub mod universal {
    pub const INTEGER: u8 = 0x02;
    pub const OCTET_STRING: u8 = 0x04;
    /// Constructed OCTET STRING (0x24) - not supported, should be rejected
    pub const OCTET_STRING_CONSTRUCTED: u8 = 0x24;
    pub const NULL: u8 = 0x05;
    pub const OBJECT_IDENTIFIER: u8 = 0x06;
    pub const SEQUENCE: u8 = 0x30; // Constructed
}

/// Application tags (class bits 01) - SNMP-specific types
pub mod application {
    pub const IP_ADDRESS: u8 = 0x40;
    pub const COUNTER32: u8 = 0x41;
    pub const GAUGE32: u8 = 0x42; // Also Unsigned32
    pub const TIMETICKS: u8 = 0x43;
    pub const OPAQUE: u8 = 0x44;
    pub const COUNTER64: u8 = 0x46;
}

/// Context-specific tags (class bits 10) - Exception values
pub mod context {
    pub const NO_SUCH_OBJECT: u8 = 0x80;
    pub const NO_SUCH_INSTANCE: u8 = 0x81;
    pub const END_OF_MIB_VIEW: u8 = 0x82;
}

/// PDU tags (context-specific, constructed)
pub mod pdu {
    use super::CONSTRUCTED;
    use super::class::CONTEXT_SPECIFIC;

    pub const GET_REQUEST: u8 = CONTEXT_SPECIFIC | CONSTRUCTED; // 0xA0
    pub const GET_NEXT_REQUEST: u8 = CONTEXT_SPECIFIC | CONSTRUCTED | 0x01; // 0xA1
    pub const RESPONSE: u8 = CONTEXT_SPECIFIC | CONSTRUCTED | 0x02; // 0xA2
    pub const SET_REQUEST: u8 = CONTEXT_SPECIFIC | CONSTRUCTED | 0x03; // 0xA3
    pub const TRAP_V1: u8 = CONTEXT_SPECIFIC | CONSTRUCTED | 0x04; // 0xA4
    pub const GET_BULK_REQUEST: u8 = CONTEXT_SPECIFIC | CONSTRUCTED | 0x05; // 0xA5
    pub const INFORM_REQUEST: u8 = CONTEXT_SPECIFIC | CONSTRUCTED | 0x06; // 0xA6
    pub const TRAP_V2: u8 = CONTEXT_SPECIFIC | CONSTRUCTED | 0x07; // 0xA7
    pub const REPORT: u8 = CONTEXT_SPECIFIC | CONSTRUCTED | 0x08; // 0xA8
}

/// Check if a tag indicates a constructed type
#[inline]
pub const fn is_constructed(tag: u8) -> bool {
    tag & CONSTRUCTED != 0
}

/// Get the class of a tag
#[inline]
pub const fn tag_class(tag: u8) -> u8 {
    tag & 0xC0
}

/// Get the tag number (bits 4-0)
#[inline]
pub const fn tag_number(tag: u8) -> u8 {
    tag & 0x1F
}
