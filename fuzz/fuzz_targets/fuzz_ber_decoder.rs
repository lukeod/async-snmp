#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;

use async_snmp::ber::Decoder;
use async_snmp::value::Value;
use async_snmp::varbind::VarBind;

fuzz_target!(|data: &[u8]| {
    let bytes = Bytes::copy_from_slice(data);

    // Fuzz the BER decoder primitives
    let mut decoder = Decoder::new(bytes.clone());
    let _ = decoder.read_integer();

    let mut decoder = Decoder::new(bytes.clone());
    let _ = decoder.read_octet_string();

    let mut decoder = Decoder::new(bytes.clone());
    let _ = decoder.read_null();

    let mut decoder = Decoder::new(bytes.clone());
    let _ = decoder.read_oid();

    let mut decoder = Decoder::new(bytes.clone());
    let _ = decoder.read_sequence();

    let mut decoder = Decoder::new(bytes.clone());
    let _ = decoder.read_ip_address();

    // Fuzz Value decoding (covers all SNMP value types)
    let mut decoder = Decoder::new(bytes.clone());
    let _ = Value::decode(&mut decoder);

    // Fuzz VarBind decoding
    let mut decoder = Decoder::new(bytes.clone());
    let _ = VarBind::decode(&mut decoder);
});
