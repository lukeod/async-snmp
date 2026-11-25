use async_snmp::{
    Candidate, Error, ReceiveLimits, ReceivedPacket, RequestRegistration, RequestTransport, Result,
    UDP_RECEIVE_LIMITS,
};
use std::net::{Ipv4Addr, SocketAddr};

include!("common/transport_contract.rs");
