//! Value Extraction Examples
//!
//! This example demonstrates the Value type methods designed for NMS (Network
//! Management Systems) and metrics collection use cases:
//!
//! - Numeric extraction for metrics pipelines (f64, wrapped counters, fixed-point)
//! - RFC 2579 enumeration helpers (TruthValue, RowStatus, StorageType)
//! - Opaque sub-type extraction (net-snmp float/double extensions)
//! - OID suffix methods for SNMP table index extraction
//!
//! Run with: cargo run --example value_extraction

use async_snmp::{RowStatus, StorageType, Value, oid};
use bytes::Bytes;

fn main() {
    // =========================================================================
    // Section 1: Numeric Extraction for Metrics
    // =========================================================================
    //
    // Metrics systems (Prometheus, InfluxDB, etc.) typically work with f64.
    // These methods convert SNMP values to f64 for easy integration.

    println!("=== Numeric Extraction for Metrics ===\n");

    // --- as_f64(): Universal numeric conversion ---
    // Converts any numeric SNMP value to f64. Works for Integer, Counter32,
    // Gauge32, TimeTicks, and Counter64.

    let interface_speed = Value::Gauge32(1_000_000_000); // 1 Gbps
    let bytes_in = Value::Counter32(4_294_967_200);
    let bytes_in_64 = Value::Counter64(10_000_000_000_000); // 10 TB
    let error_count = Value::Integer(42);

    println!("Interface speed (Gauge32): {:?}", interface_speed.as_f64());
    println!("Bytes in (Counter32): {:?}", bytes_in.as_f64());
    println!("Bytes in (Counter64): {:?}", bytes_in_64.as_f64());
    println!("Error count (Integer): {:?}", error_count.as_f64());

    // Non-numeric values return None
    let sys_descr = Value::OctetString(Bytes::from_static(b"Linux router"));
    println!("String value: {:?}", sys_descr.as_f64());

    // --- as_f64_wrapped(): Safe Counter64 handling ---
    // IEEE 754 double-precision floats have a 53-bit mantissa, so Counter64
    // values above 2^53 (~9 petabytes) lose precision. This method wraps at
    // 2^53 to preserve precision for rate calculations.

    println!("\n--- Counter64 Precision Handling ---");

    let small_counter = Value::Counter64(1_000_000_000);
    let large_counter = Value::Counter64(1u64 << 54); // 2^54, beyond f64 precision

    println!(
        "Small counter (direct): {:?}",
        small_counter.as_f64_wrapped()
    );
    println!(
        "Large counter (direct): {:?}",
        large_counter.as_f64().map(|v| format!("{v:.0}"))
    );
    println!(
        "Large counter (wrapped): {:?}",
        large_counter.as_f64_wrapped()
    );

    // For rate calculations: (current_wrapped - previous_wrapped) gives correct
    // delta even with wrap-around, as long as both values use the same wrapping.

    // --- as_decimal(): Fixed-point value extraction ---
    // Many sensors report values as integers with an implied decimal point.
    // The DISPLAY-HINT "d-2" means 2350 represents 23.50 degrees.

    println!("\n--- Fixed-Point Sensor Values ---");

    // Temperature sensor: 2350 = 23.50 degrees (d-2 hint)
    let temp_raw = Value::Integer(2350);
    println!(
        "Temperature raw: {}, as decimal(2): {:?}",
        temp_raw.as_i32().unwrap(),
        temp_raw.as_decimal(2)
    );

    // Voltage sensor: 12500 = 12.500 volts (d-3 hint)
    let voltage_raw = Value::Integer(12500);
    println!(
        "Voltage raw: {}, as decimal(3): {:?}",
        voltage_raw.as_i32().unwrap(),
        voltage_raw.as_decimal(3)
    );

    // Percentage: 9999 = 99.99% (d-2 hint)
    let percent_raw = Value::Integer(9999);
    println!(
        "Percentage raw: {}, as decimal(2): {:?}",
        percent_raw.as_i32().unwrap(),
        percent_raw.as_decimal(2)
    );

    // Negative values work too
    let negative_temp = Value::Integer(-500);
    println!(
        "Negative temp raw: {}, as decimal(2): {:?}",
        negative_temp.as_i32().unwrap(),
        negative_temp.as_decimal(2)
    );

    // --- as_duration(): TimeTicks to std::time::Duration ---
    // TimeTicks are hundredths of a second. as_duration() converts to Duration
    // for idiomatic Rust time handling.

    println!("\n--- TimeTicks to Duration ---");

    // sysUpTime: 360000 ticks = 3600 seconds = 1 hour
    let sys_uptime = Value::TimeTicks(360_000);
    if let Some(duration) = sys_uptime.as_duration() {
        println!(
            "sysUpTime ticks: {}, duration: {:?} ({} hours)",
            360_000,
            duration,
            duration.as_secs() / 3600
        );
    }

    // Small value: 100 ticks = 1 second
    let one_second = Value::TimeTicks(100);
    println!("100 ticks = {:?}", one_second.as_duration());

    // Sub-second precision: 1 tick = 10 milliseconds
    let ten_ms = Value::TimeTicks(1);
    println!("1 tick = {:?}", ten_ms.as_duration());

    // Non-TimeTicks return None
    let not_ticks = Value::Integer(100);
    println!("Integer value: {:?}", not_ticks.as_duration());

    // =========================================================================
    // Section 2: RFC 2579 Enumeration Helpers
    // =========================================================================
    //
    // RFC 2579 defines common textual conventions used across MIBs.
    // These methods extract typed enumerations from SNMP Integer values.

    println!("\n=== RFC 2579 Enumeration Helpers ===\n");

    // --- as_truth_value(): Boolean from TruthValue ---
    // TruthValue: true(1), false(2)

    println!("--- TruthValue (boolean) ---");

    let enabled = Value::Integer(1);
    let disabled = Value::Integer(2);
    let invalid = Value::Integer(0);

    println!("Integer(1) as TruthValue: {:?}", enabled.as_truth_value());
    println!("Integer(2) as TruthValue: {:?}", disabled.as_truth_value());
    println!(
        "Integer(0) as TruthValue: {:?} (invalid)",
        invalid.as_truth_value()
    );

    // --- as_row_status(): Table row lifecycle management ---
    // RowStatus controls SNMP table row creation, modification, and deletion.

    println!("\n--- RowStatus (table management) ---");

    // Reading existing rows
    let active_row = Value::Integer(1);
    let not_in_service = Value::Integer(2);
    let not_ready = Value::Integer(3);

    println!("RowStatus values and their meanings:");
    println!(
        "  active(1): {:?} - {}",
        active_row.as_row_status(),
        active_row.as_row_status().unwrap()
    );
    println!(
        "  notInService(2): {:?} - {}",
        not_in_service.as_row_status(),
        not_in_service.as_row_status().unwrap()
    );
    println!(
        "  notReady(3): {:?} - {}",
        not_ready.as_row_status(),
        not_ready.as_row_status().unwrap()
    );

    // Creating values for SET operations
    println!("\nRowStatus values for SET operations:");
    let create_and_go: Value = RowStatus::CreateAndGo.into();
    let create_and_wait: Value = RowStatus::CreateAndWait.into();
    let destroy: Value = RowStatus::Destroy.into();

    println!("  CreateAndGo -> {create_and_go:?}");
    println!("  CreateAndWait -> {create_and_wait:?}");
    println!("  Destroy -> {destroy:?}");

    // Display trait for logging
    println!("\nRowStatus Display representations:");
    for status in [
        RowStatus::Active,
        RowStatus::NotInService,
        RowStatus::NotReady,
        RowStatus::CreateAndGo,
        RowStatus::CreateAndWait,
        RowStatus::Destroy,
    ] {
        println!("  {status:?} displays as \"{status}\"");
    }

    // --- as_storage_type(): Row persistence configuration ---
    // StorageType indicates how row data is stored and persisted.

    println!("\n--- StorageType (persistence) ---");

    println!("StorageType values:");
    for i in 1..=5 {
        let value = Value::Integer(i);
        if let Some(storage) = value.as_storage_type() {
            println!("  {storage}({i}): \"{storage}\"");
        }
    }

    // Creating values for SET operations
    println!("\nCreating StorageType values:");
    let volatile: Value = StorageType::Volatile.into();
    let non_volatile: Value = StorageType::NonVolatile.into();
    println!("  Volatile -> {volatile:?}");
    println!("  NonVolatile -> {non_volatile:?}");

    // =========================================================================
    // Section 3: Opaque Sub-type Extraction (net-snmp Extensions)
    // =========================================================================
    //
    // Standard SNMP doesn't support floating-point values. Net-snmp encodes
    // floats inside Opaque values with a special ASN.1 structure.

    println!("\n=== Opaque Sub-type Extraction ===\n");

    // --- as_opaque_float(): IEEE 754 single-precision ---
    // Encoding: 0x9f (extension) + 0x78 (float type) + 0x04 (length) + 4 bytes

    println!("--- Opaque Float (net-snmp extension) ---");

    // Pi encoded as IEEE 754 single-precision float
    let pi_float_data = Bytes::from_static(&[0x9f, 0x78, 0x04, 0x40, 0x49, 0x0f, 0xdb]);
    let pi_float = Value::Opaque(pi_float_data);

    if let Some(value) = pi_float.as_opaque_float() {
        println!("Opaque float (pi): {value:.6}");
        println!(
            "  Difference from f32::PI: {:.10}",
            (value - std::f32::consts::PI).abs()
        );
    }

    // Temperature from a sensor that uses Opaque floats
    // 23.5 degrees in IEEE 754: 0x41BC0000
    let temp_float_data = Bytes::from_static(&[0x9f, 0x78, 0x04, 0x41, 0xbc, 0x00, 0x00]);
    let temp_float = Value::Opaque(temp_float_data);
    println!(
        "Temperature sensor (Opaque float): {:?} degrees",
        temp_float.as_opaque_float()
    );

    // Non-float Opaque returns None
    let raw_opaque = Value::Opaque(Bytes::from_static(&[0x01, 0x02, 0x03]));
    println!(
        "Raw Opaque (not a float): {:?}",
        raw_opaque.as_opaque_float()
    );

    // --- as_opaque_double(): IEEE 754 double-precision ---
    // Encoding: 0x9f (extension) + 0x79 (double type) + 0x08 (length) + 8 bytes

    println!("\n--- Opaque Double (net-snmp extension) ---");

    // Pi encoded as IEEE 754 double-precision
    let pi_double_data = Bytes::from_static(&[
        0x9f, 0x79, 0x08, 0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18,
    ]);
    let pi_double = Value::Opaque(pi_double_data);

    if let Some(value) = pi_double.as_opaque_double() {
        println!("Opaque double (pi): {value:.15}");
        println!(
            "  Difference from f64::PI: {:.20}",
            (value - std::f64::consts::PI).abs()
        );
    }

    // --- as_opaque_counter64(): 64-bit counter for SNMPv1 ---
    // SNMPv1 doesn't support Counter64 natively. Net-snmp encodes it in Opaque.

    println!("\n--- Opaque Counter64 (SNMPv1 compatibility) ---");

    let counter64_data = Bytes::from_static(&[
        0x9f, 0x76, 0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    ]);
    let counter64 = Value::Opaque(counter64_data);
    println!(
        "Opaque Counter64: {:?} (0x{:016X})",
        counter64.as_opaque_counter64(),
        counter64.as_opaque_counter64().unwrap_or(0)
    );

    // =========================================================================
    // Section 4: OID Suffix Methods for Table Indexing
    // =========================================================================
    //
    // SNMP tables use OID suffixes as row indexes. These methods help extract
    // and work with table indexes from walked OIDs.

    println!("\n=== OID Suffix Methods for Table Indexing ===\n");

    // --- strip_prefix(): Extract table row index ---
    // Given a column OID and a row OID, extract the index suffix.

    println!("--- strip_prefix(): Extracting table indexes ---");

    // ifTable example: ifDescr.5 = ifEntry.2.5
    let if_entry = oid!(1, 3, 6, 1, 2, 1, 2, 2, 1); // ifEntry
    let if_descr = oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2); // ifDescr column
    let if_descr_5 = oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 5); // ifDescr for interface 5

    // Extract the column and index from a walked OID
    if let Some(suffix) = if_descr_5.strip_prefix(&if_entry) {
        println!("ifEntry OID: {if_entry}");
        println!("Walked OID:  {if_descr_5}");
        if let [column, index, ..] = suffix.arcs() {
            println!("Suffix:      {suffix} (column={column}, index={index})");
        } else {
            println!("Suffix:      {suffix} (unexpected format)");
        }
    }

    // Extract just the index from a column OID
    if let Some(index) = if_descr_5.strip_prefix(&if_descr) {
        println!("\nColumn OID:  {if_descr}");
        println!("Walked OID:  {if_descr_5}");
        if let Some(if_number) = index.arcs().first() {
            println!("Index:       {index} (interface #{if_number})");
        } else {
            println!("Index:       {index} (unexpected format)");
        }
    }

    // --- Composite indexes (multi-component) ---
    // ipNetToMediaTable has a composite index: (ifIndex, IpAddress)

    println!("\n--- Composite indexes ---");

    // ipNetToMediaPhysAddress.1.192.168.1.100
    let ip_net_to_media_phys = oid!(1, 3, 6, 1, 2, 1, 4, 22, 1, 2); // column
    let ip_net_to_media_entry = oid!(1, 3, 6, 1, 2, 1, 4, 22, 1, 2, 1, 192, 168, 1, 100);

    if let Some(index) = ip_net_to_media_entry.strip_prefix(&ip_net_to_media_phys) {
        println!("ipNetToMediaPhysAddress composite index:");
        println!("  Full index OID: {index}");
        if let [if_index, a, b, c, d] = index.arcs() {
            println!("  ifIndex: {if_index}");
            println!("  IP Address: {a}.{b}.{c}.{d}");
        } else {
            println!("  (unexpected format)");
        }
    }

    // --- suffix(): Get last N arcs ---
    // Useful when you know the index size but not the full prefix.

    println!("\n--- suffix(): Get last N arcs ---");

    let walked_oid = oid!(1, 3, 6, 1, 2, 1, 4, 22, 1, 2, 1, 192, 168, 1, 100);

    // Get the 5-arc composite index (ifIndex + 4-byte IP)
    if let Some(index) = walked_oid.suffix(5) {
        println!("Last 5 arcs of {walked_oid}: {index:?}");
        if let [if_index, a, b, c, d] = index {
            println!("  Parsed: ifIndex={if_index}, IP={a}.{b}.{c}.{d}");
        } else {
            unreachable!("suffix(5) always returns 5 arcs");
        }
    }

    // Get just the last arc (useful for simple integer indexes)
    if let Some(last) = walked_oid.suffix(1) {
        println!("Last arc: {last:?}");
    }

    // suffix(0) returns empty slice
    println!("suffix(0): {:?}", walked_oid.suffix(0));

    // Too large returns None
    println!("suffix(100): {:?}", walked_oid.suffix(100));

    // --- Table grouping pattern ---
    // Common pattern: group walk results by table index.

    println!("\n--- Table grouping pattern ---");

    // Simulated walk results for ifTable
    let walk_results = vec![
        (oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1), "ifIndex.1"),
        (oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 2), "ifIndex.2"),
        (oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1), "ifDescr.1"),
        (oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 2), "ifDescr.2"),
        (oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 3, 1), "ifType.1"),
        (oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 3, 2), "ifType.2"),
    ];

    let if_entry_base = oid!(1, 3, 6, 1, 2, 1, 2, 2, 1);

    println!("Grouping walk results by column and index:");
    for (oid, name) in &walk_results {
        if let Some(suffix) = oid.strip_prefix(&if_entry_base) {
            let arcs = suffix.arcs();
            if arcs.len() >= 2 {
                println!(
                    "  {} -> column={}, index={} ({})",
                    oid, arcs[0], arcs[1], name
                );
            }
        }
    }

    println!("\nExample complete!");
}
