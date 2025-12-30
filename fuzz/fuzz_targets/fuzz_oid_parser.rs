#![no_main]

use libfuzzer_sys::fuzz_target;

use async_snmp::oid::Oid;

fuzz_target!(|data: &[u8]| {
    // Fuzz OID from BER encoding
    let _ = Oid::from_ber(data);

    // Fuzz OID from dotted string notation (if data is valid UTF-8)
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Oid::parse(s);
    }
});
