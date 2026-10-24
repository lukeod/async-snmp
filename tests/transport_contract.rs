use async_snmp::{Candidate, Error, ReceivedPacket, RequestRegistration, RequestTransport, Result};
use std::net::{Ipv4Addr, SocketAddr};

include!("common/transport_contract.rs");
