use async_snmp::{
    DecodeErrorKind, EndpointId, Error, ProcessingInput, ProcessingLimits, ReceiveLimits,
    ReceivedMessageInfo, ReceivedPacket, SessionId,
};
use bytes::Bytes;
use tokio::time::Instant;

fn udp_info(len: usize) -> ReceivedMessageInfo {
    ReceivedMessageInfo::udp(
        EndpointId::new(),
        "192.0.2.1:162".parse().unwrap(),
        "192.0.2.2:40000".parse().unwrap(),
        Some("192.0.2.1".parse().unwrap()),
        Instant::now(),
        len,
    )
}

fn tcp_info(len: usize) -> ReceivedMessageInfo {
    ReceivedMessageInfo::tcp(
        EndpointId::new(),
        SessionId::new(),
        "192.0.2.1:162".parse().unwrap(),
        "192.0.2.2:40000".parse().unwrap(),
        Instant::now(),
        len,
    )
}

#[test]
fn processing_input_preserves_original_storage_and_reception_identity() {
    let bytes = Bytes::from(vec![0x30, 0x01, 0x00]);
    let address = bytes.as_ptr();
    let info = udp_info(bytes.len());
    let limits = ProcessingLimits::new(ReceiveLimits::udp(1472).unwrap(), 1200).unwrap();
    let input = ProcessingInput::new(ReceivedPacket::new(bytes, info), limits).unwrap();

    assert_eq!(input.bytes().as_ptr(), address);
    assert_eq!(input.info(), info);
    assert_eq!(input.limits(), limits);
    assert_eq!(input.limits().receive().advertised().as_usize(), 1472);
    assert_eq!(input.limits().send(), 1200);
    let (packet, recovered_limits) = input.into_parts();
    assert_eq!(recovered_limits, limits);
    let (bytes, recovered_info) = packet.into_parts();
    assert_eq!(bytes.as_ptr(), address);
    assert_eq!(recovered_info, info);
}

#[test]
fn processing_input_rejects_inconsistent_received_length() {
    for length in [0, 2, 4] {
        let packet = ReceivedPacket::new(Bytes::from_static(b"abc"), udp_info(length));
        let error = ProcessingInput::new(packet, ProcessingLimits::UDP).unwrap_err();
        assert!(matches!(*error, Error::InvalidMessage(_)));
    }
}

#[test]
fn udp_input_uses_hard_bound_including_tolerated_suffixes() {
    let limits = ProcessingLimits::new(ReceiveLimits::udp(484).unwrap(), 484).unwrap();
    for length in [484, async_snmp::MAX_UDP_PAYLOAD, 65_535] {
        let bytes = Bytes::from(vec![0; length]);
        let input =
            ProcessingInput::new(ReceivedPacket::new(bytes, udp_info(length)), limits).unwrap();
        assert_eq!(input.bytes().len(), length);
        assert_eq!(input.info().received_len(), length);
    }

    let length = 65_536;
    let info = udp_info(length);
    let packet = ReceivedPacket::new(Bytes::from(vec![0; length]), info);
    let error = ProcessingInput::new(packet, limits).unwrap_err();
    assert!(matches!(
        *error,
        Error::Decode(ref error)
            if error.kind == DecodeErrorKind::MessageTooLarge { size: length, maximum: 65_535 }
                && error.peer == Some(info.peer_addr())
    ));
}

#[test]
fn tcp_input_has_its_own_bound_above_udp_capacity() {
    let maximum = 128 * 1024;
    let limits = ProcessingLimits::new(ReceiveLimits::tcp(maximum).unwrap(), maximum).unwrap();
    for length in [async_snmp::UDP_RECEIVE_BUFFER_SIZE + 1, maximum] {
        let bytes = Bytes::from(vec![0; length]);
        let info = tcp_info(length);
        let input = ProcessingInput::new(ReceivedPacket::new(bytes, info), limits).unwrap();
        assert_eq!(input.info().session_id(), info.session_id());
        assert_eq!(input.limits().receive().accepted(), maximum);
    }

    let length = maximum + 1;
    let packet = ReceivedPacket::new(Bytes::from(vec![0; length]), tcp_info(length));
    let error = ProcessingInput::new(packet, limits).unwrap_err();
    assert!(matches!(
        *error,
        Error::Decode(ref error)
            if error.kind == DecodeErrorKind::MessageTooLarge { size: length, maximum }
    ));
}

#[test]
fn processing_send_capacity_is_separate_from_wire_advertisement() {
    let receive = ReceiveLimits::tcp(8192).unwrap();
    for send in [0, 1, 483, async_snmp::MESSAGE_SIZE_MAXIMUM] {
        let limits = ProcessingLimits::new(receive, send).unwrap();
        assert_eq!(limits.receive(), receive);
        assert_eq!(limits.send(), send);
    }
    let error = ProcessingLimits::new(receive, async_snmp::MESSAGE_SIZE_MAXIMUM + 1).unwrap_err();
    assert!(matches!(*error, Error::Config(_)));
}
