use async_snmp::{
    Candidate, Error, ReceivedMessageInfo, RequestRegistration, RequestTransport, Result,
};
use bytes::Bytes;
use std::net::{Ipv4Addr, SocketAddr};

include!("common/transport_contract.rs");
