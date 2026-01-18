//! In-process SNMP agent for testing.
//!
//! Wraps the library's Agent with automatic lifecycle management.
//! Agents bind to ephemeral localhost ports and shut down cleanly on drop.

use crate::common::fixtures;
use crate::common::handler::TestHandler;

use async_snmp::handler::MibHandler;
use async_snmp::v3::{AuthProtocol, PrivProtocol};
use async_snmp::{Agent, Oid, Value, oid};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// An in-process SNMP agent for testing.
///
/// Automatically starts on creation and stops on drop.
/// Uses ephemeral localhost ports to avoid conflicts.
///
/// # Example
///
/// ```ignore
/// let agent = TestAgent::new().await;
/// let client = Client::builder(agent.addr(), Auth::v2c("public"))
///     .connect().await?;
/// let result = client.get(&oid!(1,3,6,1,2,1,1,1,0)).await?;
/// // Agent automatically stops when dropped
/// ```
pub struct TestAgent {
    addr: SocketAddr,
    handler: Arc<TestHandler>,
    cancel: CancellationToken,
    _task: JoinHandle<()>,
}

impl TestAgent {
    /// Create an agent with default system MIB data.
    pub async fn new() -> Self {
        Self::with_data(fixtures::system_mib()).await
    }

    /// Create an agent with custom initial data.
    pub async fn with_data(initial: BTreeMap<Oid, Value>) -> Self {
        let handler = Arc::new(TestHandler::new(initial));
        Self::with_handler(handler).await
    }

    /// Create an agent with a custom handler.
    pub async fn with_handler(handler: Arc<TestHandler>) -> Self {
        let cancel = CancellationToken::new();

        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .cancel(cancel.clone())
            .handler(oid!(1, 3, 6), handler.clone())
            .build()
            .await
            .expect("failed to build test agent");

        let addr = agent.local_addr();

        let task = tokio::spawn(async move {
            if let Err(e) = agent.run().await {
                // Only log if not cancelled
                if !e.to_string().contains("cancelled") {
                    eprintln!("TestAgent error: {}", e);
                }
            }
        });

        // Yield to let the agent task start its receive loop
        tokio::task::yield_now().await;

        Self {
            addr,
            handler,
            cancel,
            _task: task,
        }
    }

    /// Get the agent's listening address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Get a reference to the handler for data manipulation.
    pub fn handler(&self) -> &TestHandler {
        &self.handler
    }

    /// Insert or update a value in the MIB.
    pub fn set(&self, oid: Oid, value: Value) {
        self.handler.set(oid, value);
    }

    /// Remove a value from the MIB.
    pub fn remove(&self, oid: &Oid) -> Option<Value> {
        self.handler.remove(oid)
    }

    /// Get a value from the MIB (cloned).
    pub fn get(&self, oid: &Oid) -> Option<Value> {
        self.handler.get(oid)
    }

    /// Get the number of entries in the MIB.
    pub fn len(&self) -> usize {
        self.handler.len()
    }

    /// Check if MIB is empty.
    pub fn is_empty(&self) -> bool {
        self.handler.is_empty()
    }

    /// Explicitly stop the agent.
    ///
    /// Called automatically on drop, but can be called early if needed.
    pub fn stop(&self) {
        self.cancel.cancel();
    }
}

impl Drop for TestAgent {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// V3 user configuration for testing.
pub struct V3User {
    pub username: Vec<u8>,
    pub auth: Option<(AuthProtocol, Vec<u8>)>,
    pub priv_: Option<(PrivProtocol, Vec<u8>)>,
}

impl V3User {
    /// Create a noAuthNoPriv user.
    pub fn no_auth(username: impl Into<Vec<u8>>) -> Self {
        Self {
            username: username.into(),
            auth: None,
            priv_: None,
        }
    }

    /// Create an authNoPriv user.
    pub fn auth_only(
        username: impl Into<Vec<u8>>,
        protocol: AuthProtocol,
        password: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            username: username.into(),
            auth: Some((protocol, password.into())),
            priv_: None,
        }
    }

    /// Create an authPriv user.
    pub fn auth_priv(
        username: impl Into<Vec<u8>>,
        auth_protocol: AuthProtocol,
        auth_password: impl Into<Vec<u8>>,
        priv_protocol: PrivProtocol,
        priv_password: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            username: username.into(),
            auth: Some((auth_protocol, auth_password.into())),
            priv_: Some((priv_protocol, priv_password.into())),
        }
    }
}

/// Builder for TestAgent with V3 configuration.
pub struct TestAgentBuilder {
    data: BTreeMap<Oid, Value>,
    communities: Vec<Vec<u8>>,
    usm_users: Vec<V3User>,
}

impl TestAgentBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            data: fixtures::system_mib(),
            communities: vec![b"public".to_vec()],
            usm_users: Vec::new(),
        }
    }

    /// Set the initial MIB data.
    pub fn data(mut self, data: BTreeMap<Oid, Value>) -> Self {
        self.data = data;
        self
    }

    /// Add a community string.
    pub fn community(mut self, community: &[u8]) -> Self {
        self.communities.push(community.to_vec());
        self
    }

    /// Add a V3 USM user.
    pub fn usm_user(mut self, user: V3User) -> Self {
        self.usm_users.push(user);
        self
    }

    /// Build the agent.
    pub async fn build(self) -> TestAgent {
        let handler = Arc::new(TestHandler::new(self.data));
        let cancel = CancellationToken::new();

        let mut builder = Agent::builder()
            .bind("127.0.0.1:0")
            .cancel(cancel.clone())
            .handler(oid!(1, 3, 6), handler.clone());

        for community in &self.communities {
            builder = builder.community(community);
        }

        for user in &self.usm_users {
            builder = builder.usm_user(user.username.clone(), |u| {
                let mut u = u;
                if let Some((proto, pass)) = &user.auth {
                    u = u.auth(*proto, pass);
                }
                if let Some((proto, pass)) = &user.priv_ {
                    u = u.privacy(*proto, pass);
                }
                u
            });
        }

        let agent = builder.build().await.expect("failed to build test agent");
        let addr = agent.local_addr();

        let task = tokio::spawn(async move {
            let _ = agent.run().await;
        });

        TestAgent {
            addr,
            handler,
            cancel,
            _task: task,
        }
    }
}

impl Default for TestAgentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_snmp::{Auth, Client};

    #[tokio::test]
    async fn test_agent_starts_and_responds() {
        let agent = TestAgent::new().await;

        let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
            .connect()
            .await
            .expect("failed to connect");

        let result = client
            .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
            .await
            .expect("GET failed");

        assert_eq!(result.value.as_str(), Some("Test SNMP Agent"));
    }

    #[tokio::test]
    async fn test_agent_dynamic_data() {
        let agent = TestAgent::new().await;

        // Add custom data
        agent.set(oid!(1, 3, 6, 1, 99, 1, 0), Value::Integer(12345));

        let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
            .connect()
            .await
            .expect("failed to connect");

        let result = client
            .get(&oid!(1, 3, 6, 1, 99, 1, 0))
            .await
            .expect("GET failed");

        assert_eq!(result.value, Value::Integer(12345));
    }

    #[tokio::test]
    async fn test_agent_stops_cleanly() {
        let agent = TestAgent::new().await;
        let addr = agent.addr();

        agent.stop();

        // Give it a moment to shut down
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Connection should fail now
        let result = Client::builder(addr.to_string(), Auth::v2c("public"))
            .timeout(std::time::Duration::from_millis(100))
            .connect()
            .await;

        // Either connection fails or GET times out
        if let Ok(client) = result {
            let get_result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;
            assert!(get_result.is_err());
        }
    }
}
