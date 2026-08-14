use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use async_snmp::{
    Auth, BoundedStringKind, Candidate, ClientBuilder, DecodeAnomaly, DecodeConfig, Error,
    Notification, NotificationReceiver, Oid, RequestRegistration, Retry, Transport, Value,
};
use bytes::Bytes;
use tokio::net::UdpSocket;

#[derive(Clone)]
struct CommunityPolicyTransport {
    replies: Arc<Mutex<VecDeque<Bytes>>>,
    reply_values: Arc<Vec<Vec<u8>>>,
}

impl CommunityPolicyTransport {
    fn new(send_canonical_fallback: bool) -> Self {
        let mut reply_values = vec![tlv(0x02, &[1, 0, 0, 0, 9])];
        if send_canonical_fallback {
            reply_values.push(tlv(0x02, &[9]));
        }
        Self::with_values(reply_values)
    }

    fn with_values(reply_values: Vec<Vec<u8>>) -> Self {
        Self {
            replies: Arc::new(Mutex::new(VecDeque::new())),
            reply_values: Arc::new(reply_values),
        }
    }
}

impl Transport for CommunityPolicyTransport {
    async fn send(&self, data: &[u8]) -> async_snmp::Result<()> {
        let request = async_snmp::message::CommunityMessage::decode(
            Bytes::copy_from_slice(data),
            DecodeConfig::default(),
        )?
        .value;
        let request_id = request.pdu().standard().unwrap().request_id();
        let version = request.version();
        let community = request.community();
        let mut replies = self.replies.lock().unwrap();
        for value in self.reply_values.iter() {
            replies.push_back(raw_community_response(
                version,
                community.as_bytes(),
                request_id,
                value,
            ));
        }
        Ok(())
    }

    async fn recv_with<T, F>(
        &self,
        registration: RequestRegistration,
        mut validate: F,
    ) -> async_snmp::Result<T>
    where
        T: Send,
        F: FnMut(Bytes, SocketAddr) -> async_snmp::Result<Candidate<T>> + Send,
    {
        let peer = self.peer_addr();
        loop {
            let Some(data) = self.replies.lock().unwrap().pop_front() else {
                return Err(Error::Timeout {
                    target: peer,
                    elapsed: registration.timeout(),
                    retries: 0,
                }
                .boxed());
            };
            if registration.evaluate_response_identity(&data, true)
                == async_snmp::ResponseIdentity::Reject
            {
                continue;
            }
            if let Candidate::Accept(value) = validate(data, peer)? {
                return Ok(value);
            }
        }
    }

    async fn request_with<T, F>(
        &self,
        data: &[u8],
        registration: RequestRegistration,
        validate: F,
    ) -> async_snmp::Result<T>
    where
        T: Send,
        F: FnMut(Bytes, SocketAddr) -> async_snmp::Result<Candidate<T>> + Send,
    {
        self.send(data).await?;
        self.recv_with(registration, validate).await
    }

    fn peer_addr(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 161))
    }

    fn local_addr(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
    }

    fn is_reliable(&self) -> bool {
        true
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    assert!(content.len() < 128);
    let mut bytes = vec![tag, content.len() as u8];
    bytes.extend_from_slice(content);
    bytes
}

fn sequence(elements: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    let content: Vec<u8> = elements.into_iter().flatten().collect();
    tlv(0x30, &content)
}

fn integer(value: i32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut start = 0;
    while start < 3
        && ((bytes[start] == 0 && bytes[start + 1] & 0x80 == 0)
            || (bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0))
    {
        start += 1;
    }
    tlv(0x02, &bytes[start..])
}

fn raw_community_response(
    version: async_snmp::Version,
    community: &[u8],
    request_id: i32,
    value: &[u8],
) -> Bytes {
    let oid = tlv(0x06, &[0x2b, 6, 1, 2, 1, 1, 1, 0]);
    let varbind = sequence([oid, value.to_vec()]);
    let varbinds = sequence([varbind]);
    let pdu_content: Vec<u8> = [integer(request_id), integer(0), integer(0), varbinds]
        .into_iter()
        .flatten()
        .collect();
    let version = match version {
        async_snmp::Version::V1 => 0,
        async_snmp::Version::V2c => 1,
        async_snmp::Version::V3 => unreachable!(),
        _ => unreachable!(),
    };
    let packet = Bytes::from(sequence([
        integer(version),
        tlv(0x04, community),
        tlv(0xa2, &pdu_content),
    ]));
    let _ = async_snmp::message::CommunityMessage::decode(packet.clone(), DecodeConfig::DEFAULT)
        .unwrap();
    packet
}

fn raw_v2c_trap(request_id: i32, extra_value: Vec<u8>) -> Bytes {
    let sys_uptime = sequence([tlv(0x06, &[0x2b, 6, 1, 2, 1, 1, 3, 0]), tlv(0x43, &[1])]);
    let trap_oid = sequence([
        tlv(0x06, &[0x2b, 6, 1, 6, 3, 1, 1, 4, 1, 0]),
        tlv(0x06, &[0x2b, 6, 1, 6, 3, 1, 1, 5, 3]),
    ]);
    let extra = sequence([tlv(0x06, &[0x2b, 6, 1, 2, 1, 1, 1, 0]), extra_value]);
    let varbinds = sequence([sys_uptime, trap_oid, extra]);
    let pdu_content: Vec<u8> = [integer(request_id), integer(0), integer(0), varbinds]
        .into_iter()
        .flatten()
        .collect();
    Bytes::from(sequence([
        integer(1),
        tlv(0x04, b"public"),
        tlv(0xa7, &pdu_content),
    ]))
}

#[tokio::test]
async fn community_clients_apply_default_strict_and_targeted_value_policies() {
    let oid = Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]);
    for auth in [Auth::v1("public"), Auth::v2c("public")] {
        let default = ClientBuilder::new(auth.clone())
            .retry(Retry::none())
            .build_with_transport(CommunityPolicyTransport::new(false))
            .unwrap();
        let response = default.get(&oid).await.unwrap();
        assert!(matches!(
            response.metadata.decode_anomalies.as_slice(),
            [async_snmp::DecodeAnomaly::SignedIntegerTruncation {
                encoded_length: 5,
                ..
            }]
        ));

        let strict = ClientBuilder::new(auth.clone())
            .decode_config(DecodeConfig::STRICT)
            .retry(Retry::none())
            .build_with_transport(CommunityPolicyTransport::new(true))
            .unwrap();
        assert!(
            strict
                .get(&oid)
                .await
                .unwrap()
                .metadata
                .decode_anomalies
                .is_empty()
        );

        let mut targeted = DecodeConfig::STRICT;
        targeted.truncate_numeric_values = true;
        let targeted = ClientBuilder::new(auth)
            .decode_config(targeted)
            .retry(Retry::none())
            .build_with_transport(CommunityPolicyTransport::new(false))
            .unwrap();
        assert!(matches!(
            targeted
                .get(&oid)
                .await
                .unwrap()
                .metadata
                .decode_anomalies
                .as_slice(),
            [async_snmp::DecodeAnomaly::SignedIntegerTruncation { .. }]
        ));
    }
}

#[tokio::test]
async fn community_client_applies_only_targeted_bounded_string_clamping() {
    let oid = Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]);
    let mut targeted = DecodeConfig::STRICT;
    targeted.clamp_bounded_strings = true;

    let rejects_unselected = ClientBuilder::new(Auth::v2c("public"))
        .decode_config(targeted)
        .retry(Retry::none())
        .build_with_transport(CommunityPolicyTransport::new(false))
        .unwrap();
    assert!(rejects_unselected.get(&oid).await.is_err());

    let accepts_selected = ClientBuilder::new(Auth::v2c("public"))
        .decode_config(targeted)
        .retry(Retry::none())
        .build_with_transport(CommunityPolicyTransport::with_values(vec![vec![
            0x04, 3, b'a', b'b',
        ]]))
        .unwrap();
    let response = accepts_selected.get(&oid).await.unwrap();
    assert_eq!(
        response.varbinds[0].value,
        Value::OctetString(Bytes::from_static(b"ab"))
    );
    assert_eq!(
        response.metadata.decode_anomalies,
        [DecodeAnomaly::BoundedStringClamp {
            kind: BoundedStringKind::OctetString,
            declared_length: 3,
            canonical_length: 2,
        }]
    );
}

#[tokio::test]
async fn notification_receiver_applies_only_targeted_empty_oid_normalization() {
    let mut targeted = DecodeConfig::STRICT;
    targeted.empty_object_identifier = true;
    let receiver = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .decode_config(targeted)
        .build()
        .await
        .unwrap();
    let receiver_addr = receiver.local_addr();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    sender
        .send_to(&raw_v2c_trap(1, tlv(0x02, &[1, 0, 0, 0, 9])), receiver_addr)
        .await
        .unwrap();
    sender
        .send_to(&raw_v2c_trap(2, tlv(0x06, &[])), receiver_addr)
        .await
        .unwrap();
    let notification = tokio::time::timeout(std::time::Duration::from_secs(5), receiver.recv())
        .await
        .expect("timeout waiting for targeted empty-OID trap")
        .unwrap()
        .0;
    assert_eq!(
        notification.decode_anomalies(),
        [DecodeAnomaly::EmptyObjectIdentifier {
            original_length: 0,
            canonical_arc_count: 0,
        }]
    );
    let Notification::TrapV2c {
        request_id,
        varbinds,
        ..
    } = notification
    else {
        panic!("expected v2c trap")
    };
    assert_eq!(request_id, 2);
    assert_eq!(varbinds[0].value, Value::ObjectIdentifier(Oid::empty()));
}
