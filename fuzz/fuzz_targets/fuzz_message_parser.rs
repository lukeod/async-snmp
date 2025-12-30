#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;

use async_snmp::message::{CommunityMessage, Message, V3Message};
use async_snmp::pdu::Pdu;

fuzz_target!(|data: &[u8]| {
    let bytes = Bytes::copy_from_slice(data);

    // Fuzz the unified Message decoder (auto-detects version)
    let _ = Message::decode(bytes.clone());

    // Fuzz v1/v2c community message decoder directly
    let _ = CommunityMessage::decode(bytes.clone());

    // Fuzz v3 message decoder directly
    let _ = V3Message::decode(bytes.clone());

    // Fuzz PDU decoder
    let mut decoder = async_snmp::ber::Decoder::new(bytes.clone());
    let _ = Pdu::decode(&mut decoder);
});
