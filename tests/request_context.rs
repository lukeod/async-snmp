#![cfg(feature = "agent")]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
use std::convert::Infallible;

use async_snmp::{
    Agent, Auth, BoxFuture, Client, GetNextResult, GetResult, HandlerResult, MibHandler, Oid,
    PduType, RequestContext, SecurityLevel, SecurityModel, SecurityName, UdpTransport, Value,
    Version, oid,
};
use bytes::Bytes;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const READ_VIEW: &[u8] = b"read\xfd";
const WRITE_VIEW: &[u8] = b"write\xfc";

fn test_oid() -> Oid {
    oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0)
}

#[derive(Default)]
struct ContextCapture(Mutex<Vec<RequestContext>>);

impl ContextCapture {
    fn take(&self) -> RequestContext {
        self.0
            .lock()
            .unwrap()
            .pop()
            .expect("handler did not capture a request context")
    }
}

impl MibHandler for ContextCapture {
    fn get<'a>(
        &'a self,
        ctx: &'a RequestContext,
        _oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetResult>> {
        self.0.lock().unwrap().push(ctx.clone());
        Box::pin(async { Ok(GetResult::Value(Value::Integer(1))) })
    }

    fn get_next<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
        Box::pin(async { Ok(GetNextResult::EndOfMibView) })
    }
}

struct RunningAgent {
    address: SocketAddr,
    capture: Arc<ContextCapture>,
    cancel: CancellationToken,
    task: JoinHandle<async_snmp::Result<()>>,
}

impl RunningAgent {
    async fn stop(self) {
        self.cancel.cancel();
        self.task.await.unwrap().unwrap();
    }
}

async fn capture_get(agent: &RunningAgent, transport: &UdpTransport, auth: Auth) -> RequestContext {
    let client = Client::builder(agent.address, auth)
        .build_with(transport)
        .await
        .unwrap();
    client.get(&test_oid()).await.unwrap();
    agent.capture.take()
}

struct ExpectedContext<'a> {
    source: SocketAddr,
    version: Version,
    security_model: SecurityModel,
    security_name: &'a [u8],
    security_level: SecurityLevel,
    context_name: &'a [u8],
    group_name: &'a [u8],
    msg_max_size: Option<usize>,
}

fn assert_context(context: &RequestContext, expected: ExpectedContext<'_>) {
    assert_eq!(context.source(), expected.source);
    assert_eq!(context.version(), expected.version);
    assert_eq!(context.security_model(), expected.security_model);
    assert_eq!(context.security_name().as_bytes(), expected.security_name);
    match (expected.security_model, context.security_name()) {
        (SecurityModel::V1 | SecurityModel::V2c, SecurityName::Community(_))
        | (SecurityModel::Usm, SecurityName::Usm(_)) => {}
        _ => panic!("security model and security-name variant differ"),
    }
    assert_eq!(context.security_level(), expected.security_level);
    assert_eq!(context.context_name().as_ref(), expected.context_name);
    assert!(context.request_id() > 0);
    assert_eq!(context.pdu_type(), PduType::GetRequest);
    assert_eq!(
        context.group_name().map(Bytes::as_ref),
        Some(expected.group_name)
    );
    assert_eq!(context.read_view().map(Bytes::as_ref), Some(READ_VIEW));
    assert_eq!(context.write_view().map(Bytes::as_ref), Some(WRITE_VIEW));
    assert_eq!(context.msg_max_size(), expected.msg_max_size);
}

#[tokio::test]
async fn agent_captures_complete_v1_and_v2c_contexts() {
    const V1_COMMUNITY: &[u8] = b"v1\xff";
    const V2C_COMMUNITY: &[u8] = b"v2c\xfe";
    const V1_GROUP: &[u8] = b"v1-group\xfb";
    const V2C_GROUP: &[u8] = b"v2c-group\xfa";

    let capture = Arc::new(ContextCapture::default());
    let cancel = CancellationToken::new();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(V1_COMMUNITY)
        .community(V2C_COMMUNITY)
        .handler(oid!(1, 3, 6, 1, 4, 1, 99999), capture.clone())
        .without_builtin_handlers()
        .vacm(|vacm| {
            vacm.group(V1_COMMUNITY, SecurityModel::V1, V1_GROUP)
                .group(V2C_COMMUNITY, SecurityModel::V2c, V2C_GROUP)
                .access(
                    V1_GROUP,
                    SecurityModel::V1,
                    SecurityLevel::NoAuthNoPriv,
                    |access| access.read_view(READ_VIEW).write_view(WRITE_VIEW),
                )
                .access(
                    V2C_GROUP,
                    SecurityModel::V2c,
                    SecurityLevel::NoAuthNoPriv,
                    |access| access.read_view(READ_VIEW).write_view(WRITE_VIEW),
                )
                .view(READ_VIEW, |view| view.include(oid!(1, 3, 6)))
                .view(WRITE_VIEW, |view| view.include(oid!(1, 3, 6)))
        })
        .cancel(cancel.clone())
        .build()
        .await
        .unwrap();
    let address = agent.local_addr();
    let task = tokio::spawn(async move { agent.run().await });
    let agent = RunningAgent {
        address,
        capture,
        cancel,
        task,
    };
    let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
    let source = transport.local_addr();

    let v1 = capture_get(&agent, &transport, Auth::v1(V1_COMMUNITY)).await;
    assert_context(
        &v1,
        ExpectedContext {
            source,
            version: Version::V1,
            security_model: SecurityModel::V1,
            security_name: V1_COMMUNITY,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_name: b"",
            group_name: V1_GROUP,
            msg_max_size: None,
        },
    );

    let v2c = capture_get(&agent, &transport, Auth::v2c(V2C_COMMUNITY)).await;
    assert_context(
        &v2c,
        ExpectedContext {
            source,
            version: Version::V2c,
            security_model: SecurityModel::V2c,
            security_name: V2C_COMMUNITY,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_name: b"",
            group_name: V2C_GROUP,
            msg_max_size: None,
        },
    );

    transport.control().shutdown().await;
    agent.stop().await;
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn agent_captures_complete_v3_contexts_at_every_security_level() {
    use async_snmp::{AuthProtocol, AuthoritativeEngine, PrivProtocol};

    const USERNAME: &[u8] = b"operator\xff";
    const CONTEXT_NAME: &[u8] = b"tenant\x80";
    const GROUP: &[u8] = b"operators\xfe";
    const AUTH_PASSWORD: &[u8] = b"authpassword123";
    const PRIV_PASSWORD: &[u8] = b"privpassword123";
    const CLIENT_MAX_MESSAGE_SIZE: usize = 4096;

    let capture = Arc::new(ContextCapture::default());
    let cancel = CancellationToken::new();
    let engine =
        AuthoritativeEngine::install(
            b"context-test-engine".to_vec(),
            |_| Ok::<(), Infallible>(()),
        )
        .unwrap();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .authoritative_engine(engine)
        .usm_user(USERNAME, |user| {
            user.auth_priv(
                AuthProtocol::Sha256,
                AUTH_PASSWORD,
                PrivProtocol::Aes128,
                PRIV_PASSWORD,
            )
        })
        .handler(oid!(1, 3, 6, 1, 4, 1, 99999), capture.clone())
        .without_builtin_handlers()
        .vacm(|vacm| {
            let vacm = vacm.group(USERNAME, SecurityModel::Usm, GROUP);
            let vacm = [
                SecurityLevel::NoAuthNoPriv,
                SecurityLevel::AuthNoPriv,
                SecurityLevel::AuthPriv,
            ]
            .into_iter()
            .fold(vacm, |vacm, level| {
                vacm.access(GROUP, SecurityModel::Usm, level, |access| {
                    access
                        .context_prefix(CONTEXT_NAME)
                        .read_view(READ_VIEW)
                        .write_view(WRITE_VIEW)
                })
            });
            vacm.view(READ_VIEW, |view| view.include(oid!(1, 3, 6)))
                .view(WRITE_VIEW, |view| view.include(oid!(1, 3, 6)))
        })
        .cancel(cancel.clone())
        .build()
        .await
        .unwrap();
    let address = agent.local_addr();
    let task = tokio::spawn(async move { agent.run().await });
    let agent = RunningAgent {
        address,
        capture,
        cancel,
        task,
    };
    let transport = UdpTransport::builder()
        .bind("127.0.0.1:0")
        .receive_capacity(CLIENT_MAX_MESSAGE_SIZE)
        .build()
        .await
        .unwrap();
    let source = transport.local_addr();

    let auth = |level| {
        let builder = Auth::usm_builder(USERNAME).context_name(CONTEXT_NAME);
        match level {
            SecurityLevel::NoAuthNoPriv => builder.build(),
            SecurityLevel::AuthNoPriv => builder.auth(AuthProtocol::Sha256, AUTH_PASSWORD).build(),
            SecurityLevel::AuthPriv => builder
                .auth_priv(
                    AuthProtocol::Sha256,
                    AUTH_PASSWORD,
                    PrivProtocol::Aes128,
                    PRIV_PASSWORD,
                )
                .build(),
        }
    };

    for level in [
        SecurityLevel::NoAuthNoPriv,
        SecurityLevel::AuthNoPriv,
        SecurityLevel::AuthPriv,
    ] {
        let context = capture_get(&agent, &transport, auth(level)).await;
        assert_context(
            &context,
            ExpectedContext {
                source,
                version: Version::V3,
                security_model: SecurityModel::Usm,
                security_name: USERNAME,
                security_level: level,
                context_name: CONTEXT_NAME,
                group_name: GROUP,
                msg_max_size: Some(CLIENT_MAX_MESSAGE_SIZE),
            },
        );
    }

    transport.control().shutdown().await;
    agent.stop().await;
}
