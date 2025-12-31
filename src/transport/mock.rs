//! Mock transport for testing.
//!
//! Provides a programmable transport that can simulate various scenarios
//! without needing an actual network connection.

use super::Transport;
use crate::error::{Error, Result};
use bytes::Bytes;
use std::collections::VecDeque;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A mock response to return for a request.
#[derive(Clone, Debug)]
pub enum MockResponse {
    /// Return this data as the response
    Data(Bytes),
    /// Simulate a timeout
    Timeout,
    /// Simulate an IO error
    IoError(String),
}

/// A recorded request sent through the mock transport.
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    /// The raw request data
    pub data: Bytes,
    /// The request ID extracted from the message (if possible)
    pub request_id: Option<i32>,
}

/// Mock transport state shared between clones.
struct MockTransportInner {
    /// Target address
    target: SocketAddr,
    /// Queued responses
    responses: VecDeque<MockResponse>,
    /// Recorded requests
    requests: Vec<RecordedRequest>,
    /// Default response when queue is empty
    default_response: Option<MockResponse>,
}

/// Mock transport for testing SNMP client functionality.
///
/// # Example
///
/// ```rust
/// use async_snmp::transport::MockTransport;
/// use bytes::Bytes;
///
/// let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());
///
/// // Queue a response (a valid SNMP GET response)
/// mock.queue_response(Bytes::from_static(&[
///     // SNMP message bytes...
/// ]));
///
/// // Or simulate a timeout
/// mock.queue_timeout();
/// ```
#[derive(Clone)]
pub struct MockTransport {
    inner: Arc<Mutex<MockTransportInner>>,
}

impl MockTransport {
    /// Create a new mock transport.
    pub fn new(target: SocketAddr) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockTransportInner {
                target,
                responses: VecDeque::new(),
                requests: Vec::new(),
                default_response: None,
            })),
        }
    }

    /// Queue a data response.
    pub fn queue_response(&mut self, data: impl Into<Bytes>) {
        let mut inner = self.inner.lock().unwrap();
        inner.responses.push_back(MockResponse::Data(data.into()));
    }

    /// Queue a timeout.
    pub fn queue_timeout(&mut self) {
        let mut inner = self.inner.lock().unwrap();
        inner.responses.push_back(MockResponse::Timeout);
    }

    /// Queue an IO error.
    pub fn queue_io_error(&mut self, msg: impl Into<String>) {
        let mut inner = self.inner.lock().unwrap();
        inner.responses.push_back(MockResponse::IoError(msg.into()));
    }

    /// Set a default response when the queue is empty.
    pub fn set_default_response(&mut self, response: MockResponse) {
        let mut inner = self.inner.lock().unwrap();
        inner.default_response = Some(response);
    }

    /// Get all recorded requests.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        let inner = self.inner.lock().unwrap();
        inner.requests.clone()
    }

    /// Clear recorded requests.
    pub fn clear_requests(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.requests.clear();
    }

    /// Get the number of queued responses remaining.
    pub fn queued_response_count(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.responses.len()
    }

    /// Extract request ID from SNMP message bytes.
    ///
    /// This is a best-effort extraction for recording purposes.
    fn extract_request_id(data: &[u8]) -> Option<i32> {
        // Very simple extraction - just look for the pattern
        // This assumes standard BER encoding
        use crate::message::Message;

        let decoder_result = Message::decode(Bytes::copy_from_slice(data));
        if let Ok(msg) = decoder_result {
            return msg.try_pdu().map(|pdu| pdu.request_id);
        }
        None
    }
}

impl Transport for MockTransport {
    fn send(&self, data: &[u8]) -> impl Future<Output = Result<()>> + Send {
        let data = Bytes::copy_from_slice(data);
        let request_id = Self::extract_request_id(&data);

        let mut inner = self.inner.lock().unwrap();
        inner.requests.push(RecordedRequest { data, request_id });

        async { Ok(()) }
    }

    fn recv(
        &self,
        request_id: i32,
        timeout: Duration,
    ) -> impl Future<Output = Result<(Bytes, SocketAddr)>> + Send {
        let inner = self.inner.clone();
        let target = {
            let guard = inner.lock().unwrap();
            guard.target
        };

        async move {
            let response = {
                let mut guard = inner.lock().unwrap();
                guard
                    .responses
                    .pop_front()
                    .or_else(|| guard.default_response.clone())
            };

            match response {
                Some(MockResponse::Data(data)) => Ok((data, target)),
                Some(MockResponse::Timeout) => Err(Error::Timeout {
                    target: Some(target),
                    elapsed: timeout,
                    request_id,
                    retries: 0,
                }),
                Some(MockResponse::IoError(msg)) => Err(Error::Io {
                    target: Some(target),
                    source: std::io::Error::other(msg),
                }),
                None => Err(Error::Timeout {
                    target: Some(target),
                    elapsed: timeout,
                    request_id,
                    retries: 0,
                }),
            }
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        let inner = self.inner.lock().unwrap();
        inner.target
    }

    fn local_addr(&self) -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    fn is_stream(&self) -> bool {
        false
    }
}

/// Builder for creating SNMP response messages for testing.
///
/// This helps construct valid SNMP response bytes without manually
/// crafting BER encoding.
pub struct ResponseBuilder {
    request_id: i32,
    varbinds: Vec<(crate::Oid, crate::Value)>,
    error_status: i32,
    error_index: i32,
}

impl ResponseBuilder {
    /// Create a new response builder with the given request ID.
    pub fn new(request_id: i32) -> Self {
        Self {
            request_id,
            varbinds: Vec::new(),
            error_status: 0,
            error_index: 0,
        }
    }

    /// Add a varbind to the response.
    pub fn varbind(mut self, oid: crate::Oid, value: crate::Value) -> Self {
        self.varbinds.push((oid, value));
        self
    }

    /// Set the error status.
    pub fn error_status(mut self, status: i32) -> Self {
        self.error_status = status;
        self
    }

    /// Set the error index.
    pub fn error_index(mut self, index: i32) -> Self {
        self.error_index = index;
        self
    }

    /// Build a v2c SNMP response message.
    pub fn build_v2c(self, community: &[u8]) -> Bytes {
        use crate::message::CommunityMessage;
        use crate::pdu::{Pdu, PduType};
        use crate::varbind::VarBind;
        use crate::version::Version;

        let varbinds: Vec<VarBind> = self
            .varbinds
            .into_iter()
            .map(|(oid, value)| VarBind::new(oid, value))
            .collect();

        let pdu = Pdu {
            pdu_type: PduType::Response,
            request_id: self.request_id,
            error_status: self.error_status,
            error_index: self.error_index,
            varbinds,
        };
        let msg = CommunityMessage::new(Version::V2c, Bytes::copy_from_slice(community), pdu);

        msg.encode()
    }

    /// Build a v1 SNMP response message.
    pub fn build_v1(self, community: &[u8]) -> Bytes {
        use crate::message::CommunityMessage;
        use crate::pdu::{Pdu, PduType};
        use crate::varbind::VarBind;
        use crate::version::Version;

        let varbinds: Vec<VarBind> = self
            .varbinds
            .into_iter()
            .map(|(oid, value)| VarBind::new(oid, value))
            .collect();

        let pdu = Pdu {
            pdu_type: PduType::Response,
            request_id: self.request_id,
            error_status: self.error_status,
            error_index: self.error_index,
            varbinds,
        };
        let msg = CommunityMessage::new(Version::V1, Bytes::copy_from_slice(community), pdu);

        msg.encode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Value, oid};

    #[tokio::test]
    async fn test_mock_transport_queue_response() {
        let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

        // Build a response using the helper
        let response = ResponseBuilder::new(1)
            .varbind(
                oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
                Value::OctetString("test".into()),
            )
            .build_v2c(b"public");

        mock.queue_response(response.clone());

        // Simulate send
        mock.send(b"dummy request").await.unwrap();

        // Receive should return our response
        let (data, _addr) = mock.recv(1, Duration::from_secs(1)).await.unwrap();
        assert_eq!(data, response);
    }

    #[tokio::test]
    async fn test_mock_transport_timeout() {
        let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());
        mock.queue_timeout();

        mock.send(b"request").await.unwrap();

        let result = mock.recv(1, Duration::from_millis(100)).await;
        assert!(matches!(result, Err(Error::Timeout { .. })));
    }

    #[tokio::test]
    async fn test_mock_transport_records_requests() {
        let mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

        mock.send(b"request 1").await.unwrap();
        mock.send(b"request 2").await.unwrap();

        let requests = mock.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].data.as_ref(), b"request 1");
        assert_eq!(requests[1].data.as_ref(), b"request 2");
    }

    #[tokio::test]
    async fn test_mock_transport_default_response() {
        let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

        let response = ResponseBuilder::new(1)
            .varbind(
                oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
                Value::OctetString("default".into()),
            )
            .build_v2c(b"public");

        mock.set_default_response(MockResponse::Data(response.clone()));

        // First recv uses default
        let (data1, _) = mock.recv(1, Duration::from_secs(1)).await.unwrap();
        assert_eq!(data1, response);

        // Second recv also uses default
        let (data2, _) = mock.recv(2, Duration::from_secs(1)).await.unwrap();
        assert_eq!(data2, response);
    }
}
