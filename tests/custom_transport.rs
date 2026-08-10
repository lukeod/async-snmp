use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_snmp::{
    Candidate, CommunityResponsePolicy, CommunityVersion, Error, RequestRegistration,
    ResponseIdentity, Transport,
};
use bytes::Bytes;
use tokio::sync::oneshot;

#[derive(Clone)]
struct ExternalTransport {
    inner: Arc<ExternalTransportInner>,
}

struct ExternalTransportInner {
    peer: SocketAddr,
    local: SocketAddr,
    replies: Mutex<VecDeque<(Bytes, SocketAddr)>>,
    deadlines_armed: AtomicUsize,
    identity_rejections: AtomicUsize,
    validator_calls: AtomicUsize,
}

impl ExternalTransport {
    fn new(peer: SocketAddr, replies: Vec<(Bytes, SocketAddr)>) -> Self {
        Self {
            inner: Arc::new(ExternalTransportInner {
                peer,
                local: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                replies: Mutex::new(replies.into()),
                deadlines_armed: AtomicUsize::new(0),
                identity_rejections: AtomicUsize::new(0),
                validator_calls: AtomicUsize::new(0),
            }),
        }
    }
}

impl Transport for ExternalTransport {
    async fn send(&self, _data: &[u8]) -> async_snmp::Result<()> {
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
        self.inner.deadlines_armed.fetch_add(1, Ordering::Relaxed);
        let deadline = tokio::time::Instant::now()
            .checked_add(registration.timeout())
            .ok_or_else(|| Error::Config("custom transport deadline overflow".into()).boxed())?;

        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::Timeout {
                    target: self.inner.peer,
                    elapsed: registration.timeout(),
                    retries: 0,
                }
                .boxed());
            }

            let Some((data, source)) = self.inner.replies.lock().unwrap().pop_front() else {
                return Err(Error::Timeout {
                    target: self.inner.peer,
                    elapsed: registration.timeout(),
                    retries: 0,
                }
                .boxed());
            };
            if registration.evaluate_response_identity(&data, source == self.inner.peer)
                == ResponseIdentity::Reject
            {
                self.inner
                    .identity_rejections
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }

            self.inner.validator_calls.fetch_add(1, Ordering::Relaxed);
            match validate(data, source)? {
                Candidate::Accept(value) => return Ok(value),
                Candidate::Reject => continue,
            }
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        self.inner.peer
    }

    fn local_addr(&self) -> SocketAddr {
        self.inner.local
    }

    fn is_reliable(&self) -> bool {
        true
    }
}

#[derive(Clone)]
struct ImmediateResponseTransport {
    inner: Arc<ImmediateResponseTransportInner>,
}

struct ImmediateResponseTransportInner {
    peer: SocketAddr,
    local: SocketAddr,
    response: Bytes,
    pending: Mutex<Option<oneshot::Sender<(Bytes, SocketAddr)>>>,
    unmatched_responses: AtomicUsize,
}

struct ImmediateResponseRegistration {
    inner: Arc<ImmediateResponseTransportInner>,
}

impl Drop for ImmediateResponseRegistration {
    fn drop(&mut self) {
        self.inner.pending.lock().unwrap().take();
    }
}

impl ImmediateResponseTransport {
    fn new(peer: SocketAddr, response: Bytes) -> Self {
        Self {
            inner: Arc::new(ImmediateResponseTransportInner {
                peer,
                local: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                response,
                pending: Mutex::new(None),
                unmatched_responses: AtomicUsize::new(0),
            }),
        }
    }
}

impl Transport for ImmediateResponseTransport {
    async fn send(&self, _data: &[u8]) -> async_snmp::Result<()> {
        let Some(pending) = self.inner.pending.lock().unwrap().take() else {
            self.inner
                .unmatched_responses
                .fetch_add(1, Ordering::Relaxed);
            return Ok(());
        };
        pending
            .send((self.inner.response.clone(), self.inner.peer))
            .map_err(|_| Error::Config("custom transport registration closed".into()).boxed())
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
        let (sender, receiver) = oneshot::channel();
        assert!(self.inner.pending.lock().unwrap().replace(sender).is_none());
        let _registration = ImmediateResponseRegistration {
            inner: Arc::clone(&self.inner),
        };
        let (data, source) = tokio::time::timeout(registration.timeout(), receiver)
            .await
            .map_err(|_| {
                Error::Timeout {
                    target: self.inner.peer,
                    elapsed: registration.timeout(),
                    retries: 0,
                }
                .boxed()
            })?
            .map_err(|_| Error::Config("custom transport response closed".into()).boxed())?;

        assert_ne!(
            registration.evaluate_response_identity(&data, source == self.inner.peer),
            ResponseIdentity::Reject
        );
        match validate(data, source)? {
            Candidate::Accept(value) => Ok(value),
            Candidate::Reject => Err(Error::MalformedResponse {
                target: self.inner.peer,
            }
            .boxed()),
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        self.inner.peer
    }

    fn local_addr(&self) -> SocketAddr {
        self.inner.local
    }

    fn is_reliable(&self) -> bool {
        true
    }
}

fn v2c_response(request_id: u8, community: &[u8]) -> Bytes {
    let pdu = [
        0xa2, 0x0b, 0x02, 0x01, request_id, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
    ];
    let outer_len = 3 + 2 + community.len() + pdu.len();
    assert!(outer_len < 128);
    assert!(community.len() < 128);

    let mut packet = Vec::with_capacity(outer_len + 2);
    packet.extend_from_slice(&[0x30, outer_len as u8, 0x02, 0x01, 0x01]);
    packet.extend_from_slice(&[0x04, community.len() as u8]);
    packet.extend_from_slice(community);
    packet.extend_from_slice(&pdu);
    Bytes::from(packet)
}

fn v3_identity(msg_id: u8) -> Bytes {
    Bytes::from(vec![
        0x30, 0x08, 0x02, 0x01, 0x03, 0x30, 0x03, 0x02, 0x01, msg_id,
    ])
}

#[tokio::test]
async fn default_request_registers_before_an_immediate_response() {
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 161));
    let response = v2c_response(6, b"public");
    let transport = ImmediateResponseTransport::new(peer, response.clone());
    let registration = RequestRegistration::community(
        6,
        Duration::from_millis(50),
        CommunityVersion::V2c,
        Bytes::from_static(b"public"),
        CommunityResponsePolicy::Exact,
    );

    let received = transport.request(b"request", registration).await.unwrap();

    assert_eq!(received, (response, peer));
    assert_eq!(
        transport.inner.unmatched_responses.load(Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn custom_transport_enforces_identity_policies_and_keeps_one_deadline() {
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 161));
    let other = SocketAddr::from(([127, 0, 0, 2], 161));
    let timeout = Duration::from_secs(1);

    let exact = ExternalTransport::new(
        peer,
        vec![
            (v2c_response(7, b"rewritten"), peer),
            (v2c_response(7, b"public"), other),
            (v2c_response(7, b"public"), peer),
        ],
    );
    let registration = RequestRegistration::community(
        7,
        timeout,
        CommunityVersion::V2c,
        Bytes::from_static(b"public"),
        CommunityResponsePolicy::Exact,
    );
    let mut candidates = 0;
    let accepted = exact
        .request_with(b"request", registration, |_, source| {
            candidates += 1;
            if candidates == 1 {
                Ok(Candidate::Reject)
            } else {
                Ok(Candidate::Accept(source))
            }
        })
        .await
        .unwrap();
    assert_eq!(accepted, peer);
    assert_eq!(candidates, 2);
    assert_eq!(exact.inner.deadlines_armed.load(Ordering::Relaxed), 1);
    assert_eq!(exact.inner.identity_rejections.load(Ordering::Relaxed), 1);
    assert_eq!(exact.inner.validator_calls.load(Ordering::Relaxed), 2);

    let target_only = ExternalTransport::new(
        peer,
        vec![
            (v2c_response(8, b"rewritten"), other),
            (v2c_response(8, b"rewritten"), peer),
        ],
    );
    let accepted = target_only
        .request(
            b"request",
            RequestRegistration::community(
                8,
                timeout,
                CommunityVersion::V2c,
                Bytes::from_static(b"public"),
                CommunityResponsePolicy::AllowMismatchFromTarget,
            ),
        )
        .await
        .unwrap();
    assert_eq!(accepted.1, peer);
    assert_eq!(
        target_only
            .inner
            .identity_rejections
            .load(Ordering::Relaxed),
        1
    );

    let any_source = ExternalTransport::new(peer, vec![(v2c_response(9, b"rewritten"), other)]);
    let accepted = any_source
        .request(
            b"request",
            RequestRegistration::community(
                9,
                timeout,
                CommunityVersion::V2c,
                Bytes::from_static(b"public"),
                CommunityResponsePolicy::AllowMismatchFromAnySource,
            ),
        )
        .await
        .unwrap();
    assert_eq!(accepted.1, other);
    assert_eq!(
        any_source.inner.identity_rejections.load(Ordering::Relaxed),
        0
    );
}

#[test]
fn response_identity_covers_protocols_ids_and_malformed_envelopes() {
    let v3 = RequestRegistration::v3(11, Duration::from_secs(1)).with_aliases([10]);

    // Identity matching intentionally stops before security/scoped-PDU checks:
    // this minimal but correctly nested outer identity remains a candidate.
    assert_eq!(
        v3.evaluate_response_identity(&v3_identity(11), true),
        ResponseIdentity::Match
    );
    assert_eq!(
        v3.evaluate_response_identity(&v3_identity(10), false),
        ResponseIdentity::Match
    );
    assert_eq!(
        v3.evaluate_response_identity(&v3_identity(12), true),
        ResponseIdentity::Reject
    );
    assert_eq!(
        v3.evaluate_response_identity(&v2c_response(11, b"public"), true),
        ResponseIdentity::Reject
    );

    // The apparent msgID is outside the zero-length msgGlobalData SEQUENCE.
    let malformed_v3 = [0x30, 0x08, 0x02, 0x01, 0x03, 0x30, 0x00, 0x02, 0x01, 0x0b];
    assert_eq!(
        v3.evaluate_response_identity(&malformed_v3, true),
        ResponseIdentity::Reject
    );

    let v2c = RequestRegistration::community(
        7,
        Duration::from_secs(1),
        CommunityVersion::V2c,
        Bytes::from_static(b"public"),
        CommunityResponsePolicy::Exact,
    )
    .with_aliases([6]);
    assert_eq!(
        v2c.evaluate_response_identity(&v2c_response(7, b"public"), false),
        ResponseIdentity::Match
    );
    assert_eq!(
        v2c.evaluate_response_identity(&v2c_response(6, b"public"), true),
        ResponseIdentity::Match
    );
    assert_eq!(
        v2c.evaluate_response_identity(&v2c_response(8, b"public"), true),
        ResponseIdentity::Reject
    );

    let mut v1_packet = v2c_response(7, b"public").to_vec();
    v1_packet[4] = 0;
    assert_eq!(
        v2c.evaluate_response_identity(&v1_packet, true),
        ResponseIdentity::Reject
    );
    let v1 = RequestRegistration::community(
        7,
        Duration::from_secs(1),
        CommunityVersion::V1,
        Bytes::from_static(b"public"),
        CommunityResponsePolicy::Exact,
    );
    assert_eq!(
        v1.evaluate_response_identity(&v1_packet, true),
        ResponseIdentity::Match
    );

    // The apparent request-id is outside the zero-length PDU.
    let malformed_v2c = [
        0x30, 0x10, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa2, 0x00,
        0x02, 0x01, 0x07,
    ];
    assert_eq!(
        v2c.evaluate_response_identity(&malformed_v2c, true),
        ResponseIdentity::Reject
    );

    // An INTEGER wider than the registered i32 domain must not wrap to a match.
    let overlong_id = [
        0x30, 0x14, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa2, 0x07,
        0x02, 0x05, 0x00, 0x00, 0x00, 0x00, 0x07,
    ];
    assert_eq!(
        v2c.evaluate_response_identity(&overlong_id, true),
        ResponseIdentity::Reject
    );
}
