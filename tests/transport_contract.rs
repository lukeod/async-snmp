use async_snmp::{Candidate, Error, RequestRegistration, Result, Transport};
use bytes::Bytes;
use std::net::{Ipv4Addr, SocketAddr};

include!("common/transport_contract.rs");
