//! Independent net-snmp manager/originator coverage of library listeners.
//! Run: cargo test --locked --test net_snmp_cli --all-features -- --ignored
#![cfg(feature = "agent")]

use async_snmp::handler::{
    BoxFuture, GetNextResult, GetResult, HandlerResult, MibHandler, PreparedSet, RequestContext,
    SetCommitResult, SetTestError, SetTestResult, SetUndoResult,
};
use async_snmp::{
    Agent, AuthoritativeEngine, InformAckOutcome, ListenerSource, NotificationReceiver, Oid,
    TransportKind, Value, VarBind, oid,
};
use std::{
    convert::Infallible,
    io,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicI32, Ordering},
    },
    time::Duration,
};

const SCALAR: &str = ".1.3.6.1.4.1.99999.1.0";
const ROOT: &str = ".1.3.6.1.4.1.99999";
const COLD: &str = ".1.3.6.1.6.3.1.1.5.1";
const WAIT: Duration = Duration::from_secs(10);
fn scalar() -> Oid {
    oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0)
}
fn engine() -> AuthoritativeEngine {
    AuthoritativeEngine::install(b"net-snmp-cli-receiver".to_vec(), |_| {
        Ok::<_, Infallible>(())
    })
    .unwrap()
}
async fn available(programs: &[&str]) -> bool {
    for program in programs {
        match Command::new(program)
            .arg("-V")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                eprintln!("Skipping net-snmp CLI test: {program} is not installed");
                return false;
            }
            Err(error) => panic!("could not execute {program}: {error}"),
            Ok(child) => {
                wait_for(program, &mut ChildGuard(child)).await;
            }
        }
    }
    true
}
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
async fn wait_for(program: &str, child: &mut ChildGuard) -> std::process::ExitStatus {
    tokio::time::timeout(WAIT, async {
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{program} exceeded {WAIT:?}"))
}
async fn run(program: &str, args: &[String]) -> String {
    let directory = tempfile::tempdir().unwrap();
    let stdout = tempfile::NamedTempFile::new().unwrap();
    let stderr = tempfile::NamedTempFile::new().unwrap();
    let mut child = ChildGuard(
        Command::new(program)
            .args(args)
            .env("MIBS", "")
            .env("MIBDIRS", directory.path())
            .env("SNMPCONFPATH", directory.path())
            .env("SNMP_PERSISTENT_DIR", directory.path())
            .stdin(Stdio::null())
            .stdout(stdout.reopen().unwrap())
            .stderr(stderr.reopen().unwrap())
            .spawn()
            .unwrap_or_else(|e| panic!("starting {program}: {e}")),
    );
    let status = wait_for(program, &mut child).await;
    let out = std::fs::read_to_string(stdout.path()).unwrap();
    let err = std::fs::read_to_string(stderr.path()).unwrap();
    assert!(status.success(), "{program} exited {status}: {out}\n{err}");
    out.trim().to_owned()
}
fn args(auth: &[&str], target: &str, tail: &[&str]) -> Vec<String> {
    [
        vec!["-t", "2", "-r", "0", "-On", "-Oqv"],
        auth.to_vec(),
        vec![target],
        tail.to_vec(),
    ]
    .concat()
    .into_iter()
    .map(str::to_owned)
    .collect()
}
fn target(bound: &async_snmp::BoundListener) -> String {
    format!(
        "{}:{}",
        if bound.transport == TransportKind::Udp {
            "udp"
        } else {
            "tcp"
        },
        bound.local_addr
    )
}
struct Scalar(Arc<AtomicI32>);
struct Change {
    state: Arc<AtomicI32>,
    value: i32,
    previous: i32,
}
impl PreparedSet for Change {
    fn commit<'a>(
        &'a mut self,
        _: &'a RequestContext,
        _: &'a Oid,
        _: &'a Value,
    ) -> BoxFuture<'a, SetCommitResult> {
        Box::pin(async move {
            self.previous = self.state.swap(self.value, Ordering::SeqCst);
            Ok(())
        })
    }
    fn undo<'a>(
        &'a mut self,
        _: &'a RequestContext,
        _: &'a Oid,
        _: &'a Value,
    ) -> BoxFuture<'a, SetUndoResult> {
        Box::pin(async move {
            self.state.store(self.previous, Ordering::SeqCst);
            Ok(())
        })
    }
}
impl MibHandler for Scalar {
    fn get<'a>(
        &'a self,
        _: &'a RequestContext,
        oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetResult>> {
        Box::pin(async move {
            Ok(if oid == &scalar() {
                GetResult::Value(Value::Integer(self.0.load(Ordering::SeqCst)))
            } else {
                GetResult::NoSuchObject
            })
        })
    }
    fn get_next<'a>(
        &'a self,
        _: &'a RequestContext,
        oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
        Box::pin(async move {
            Ok(if oid < &scalar() {
                GetNextResult::Value(VarBind::new(
                    scalar(),
                    Value::Integer(self.0.load(Ordering::SeqCst)),
                ))
            } else {
                GetNextResult::EndOfMibView
            })
        })
    }
    fn test_set<'a>(
        &'a self,
        _: &'a RequestContext,
        oid: &'a Oid,
        value: &'a Value,
    ) -> BoxFuture<'a, SetTestResult> {
        Box::pin(async move {
            if oid != &scalar() {
                return Err(SetTestError::NotWritable);
            }
            let Value::Integer(value) = value else {
                return Err(SetTestError::WrongType);
            };
            Ok(Box::new(Change {
                state: self.0.clone(),
                value: *value,
                previous: 0,
            }) as Box<dyn PreparedSet>)
        })
    }
}
fn command_builder() -> async_snmp::agent::AgentBuilder {
    Agent::builder()
        .community("public")
        .allow_all_access()
        .authoritative_engine(engine())
        .handler(
            oid!(1, 3, 6, 1, 4, 1, 99999),
            Arc::new(Scalar(Arc::new(AtomicI32::new(42)))),
        )
        .listener(ListenerSource::udp("127.0.0.1:0"))
        .listener(ListenerSource::tcp("127.0.0.1:0"))
}
async fn commands(agent: &async_snmp::RunningAgent, auth: &[&str], bulk: bool) {
    for bound in agent.bound_addresses() {
        let target = target(bound);
        assert_eq!(
            run("snmpset", &args(auth, &target, &[SCALAR, "i", "42"])).await,
            "42"
        );
        assert_eq!(run("snmpget", &args(auth, &target, &[SCALAR])).await, "42");
        assert_eq!(
            run("snmpgetnext", &args(auth, &target, &[ROOT])).await,
            "42"
        );
        if bulk {
            let mut bulk_args = args(auth, &target, &[ROOT]);
            bulk_args.splice(0..0, ["-Cn0".into(), "-Cr1".into()]);
            assert_eq!(run("snmpbulkget", &bulk_args).await, "42");
        }
        assert_eq!(
            run("snmpset", &args(auth, &target, &[SCALAR, "i", "57"])).await,
            "57"
        );
        // The other transport sees the same responder/SET state.
        let other = agent
            .bound_addresses()
            .iter()
            .find(|other| other.endpoint_id != bound.endpoint_id)
            .unwrap();
        assert_eq!(
            run("snmpget", &args(auth, &self::target(other), &[SCALAR])).await,
            "57"
        );
    }
}
#[tokio::test]
#[ignore = "requires local net-snmp command-line tools"]
async fn community_commands_over_udp_and_tcp() {
    if !available(&["snmpget", "snmpgetnext", "snmpbulkget", "snmpset"]).await {
        return;
    }
    let agent = command_builder().spawn().await.unwrap();
    commands(&agent, &["-v", "1", "-c", "public"], false).await;
    commands(&agent, &["-v", "2c", "-c", "public"], true).await;
    agent.shutdown().await.unwrap();
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
fn v3_auth(level: &str) -> Vec<&str> {
    let mut auth = vec!["-v", "3", "-u", level, "-l", level];
    if level != "noAuthNoPriv" {
        auth.extend(["-a", "SHA-256", "-A", "authpassword123"]);
    }
    if level == "authPriv" {
        auth.extend(["-x", "AES", "-X", "privpassword123"]);
    }
    auth
}
#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
#[ignore = "requires local net-snmp command-line tools"]
async fn v3_commands_discover_and_secure_udp_and_tcp() {
    use async_snmp::{AuthProtocol, PrivProtocol};
    if !available(&["snmpget", "snmpgetnext", "snmpbulkget", "snmpset"]).await {
        return;
    }
    let agent = command_builder()
        .usm_user("noAuthNoPriv", Ok)
        .unwrap()
        .usm_user("authNoPriv", |u| {
            u.auth(AuthProtocol::Sha256, b"authpassword123")
        })
        .unwrap()
        .usm_user("authPriv", |u| {
            u.auth_priv(
                AuthProtocol::Sha256,
                b"authpassword123",
                PrivProtocol::Aes128,
                b"privpassword123",
            )
        })
        .unwrap()
        .spawn()
        .await
        .unwrap();
    for level in ["noAuthNoPriv", "authNoPriv", "authPriv"] {
        commands(&agent, &v3_auth(level), true).await;
    }
    agent.shutdown().await.unwrap();
}

async fn receive(
    receiver: &mut async_snmp::RunningNotificationReceiver,
    transport: TransportKind,
    inform: bool,
) -> async_snmp::ReceivedNotification {
    let event = tokio::time::timeout(WAIT, receiver.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.receive_info.transport(), transport);
    assert_eq!(
        event.receive_info.session_id().is_some(),
        transport == TransportKind::Tcp
    );
    assert!(event.receive_info.received_len() > 0);
    assert_eq!(
        event.notification.varbinds().last().unwrap().value,
        Value::Integer(77)
    );
    if inform {
        assert!(matches!(event.inform_ack, Some(InformAckOutcome::Sent)));
    } else {
        assert!(event.inform_ack.is_none());
    }
    event
}
#[tokio::test]
#[ignore = "requires local net-snmp command-line tools"]
async fn community_traps_and_informs_over_udp_and_tcp() {
    if !available(&["snmptrap", "snmpinform"]).await {
        return;
    }
    let mut receiver = NotificationReceiver::builder()
        .communities(["public"])
        .listener(ListenerSource::udp("127.0.0.1:0"))
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .spawn()
        .await
        .unwrap();
    for bound in receiver.bound_addresses().to_vec() {
        run(
            "snmptrap",
            &args(
                &["-v", "1", "-c", "public"],
                &target(&bound),
                &[ROOT, "127.0.0.1", "6", "7", "123", SCALAR, "i", "77"],
            ),
        )
        .await;
        let event = receive(&mut receiver, bound.transport, false).await;
        assert_eq!(event.notification.version(), async_snmp::Version::V1);
        for (program, inform) in [("snmptrap", false), ("snmpinform", true)] {
            run(
                program,
                &args(
                    &["-v", "2c", "-c", "public"],
                    &target(&bound),
                    &["123", COLD, SCALAR, "i", "77"],
                ),
            )
            .await;
            let event = receive(&mut receiver, bound.transport, inform).await;
            assert_eq!(event.notification.version(), async_snmp::Version::V2c);
        }
    }
    receiver.shutdown().await.unwrap();
}
#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
#[ignore = "requires local net-snmp command-line tools"]
async fn v3_traps_and_informs_over_udp_and_tcp() {
    use async_snmp::{AuthProtocol, PrivProtocol};
    if !available(&["snmptrap", "snmpinform"]).await {
        return;
    }
    let mut receiver = NotificationReceiver::builder()
        .accept_all_notifications()
        .authoritative_engine(engine())
        .usm_user("noAuthNoPriv", Ok)
        .unwrap()
        .usm_user("authNoPriv", |u| {
            u.auth(AuthProtocol::Sha256, b"authpassword123")
        })
        .unwrap()
        .usm_user("authPriv", |u| {
            u.auth_priv(
                AuthProtocol::Sha256,
                b"authpassword123",
                PrivProtocol::Aes128,
                b"privpassword123",
            )
        })
        .unwrap()
        .listener(ListenerSource::udp("127.0.0.1:0"))
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .spawn()
        .await
        .unwrap();
    for bound in receiver.bound_addresses().to_vec() {
        for level in ["noAuthNoPriv", "authNoPriv", "authPriv"] {
            for (program, inform) in [("snmptrap", false), ("snmpinform", true)] {
                let mut auth = v3_auth(level);
                if !inform {
                    auth.extend(["-e", "0x80000000010203040506070809", "-Z", "1,0"]);
                }
                run(
                    program,
                    &args(&auth, &target(&bound), &["123", COLD, SCALAR, "i", "77"]),
                )
                .await;
                let event = receive(&mut receiver, bound.transport, inform).await;
                assert_eq!(event.notification.version(), async_snmp::Version::V3);
                let expected_level = match level {
                    "noAuthNoPriv" => async_snmp::SecurityLevel::NoAuthNoPriv,
                    "authNoPriv" => async_snmp::SecurityLevel::AuthNoPriv,
                    _ => async_snmp::SecurityLevel::AuthPriv,
                };
                assert_eq!(event.notification.security_level(), Some(expected_level));
                let identity = event.wire_identity.v3.unwrap();
                assert_eq!(identity.username.as_ref(), level.as_bytes());
                let expected_engine: &[u8] = if inform {
                    b"net-snmp-cli-receiver"
                } else {
                    &[0x80, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
                };
                assert_eq!(identity.authoritative_engine_id.as_ref(), expected_engine);
            }
        }
    }
    receiver.shutdown().await.unwrap();
}
