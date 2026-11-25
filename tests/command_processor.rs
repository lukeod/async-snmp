#![cfg(feature = "agent")]

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::time::Duration;

use async_snmp::message::{
    CommunityMessage, MsgFlags, MsgGlobalData, ScopedPdu, V3Message, V3MessageData,
};
use async_snmp::v3::UsmSecurityParams;
use async_snmp::{
    AuthoritativeEngine, BoxFuture, CommandProcessor, CommandProcessorBuilder, Error, GetBulkPdu,
    GetNextResult, GetResult, HandlerResult, LocalEngine, MessageSize, MibHandler, NotificationPdu,
    Oid, Pdu, PreparedSet, ProcessingInput, ProcessingLimits, ReceiveLimits, ReceivedMessageInfo,
    ReceivedPacket, RequestContext, RequestPdu, SecurityLevel, SetCommitResult, SetTestResult,
    SetUndoResult, UsmSecurityContext, UsmUser, UsmUserEntry, Value, VarBind, Version, oid,
};
use bytes::Bytes;
use tokio::sync::Semaphore;

const WAIT: Duration = Duration::from_secs(3);
fn object() -> Oid {
    oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0)
}
fn prefix() -> Oid {
    oid!(1, 3, 6, 1, 4, 1, 99999)
}
fn limits() -> ProcessingLimits {
    ProcessingLimits::new(ReceiveLimits::tcp(8192).unwrap(), 8192).unwrap()
}
fn received(bytes: Bytes, limits: ProcessingLimits) -> ProcessingInput {
    let info = ReceivedMessageInfo::tcp(
        async_snmp::EndpointId::new(),
        async_snmp::SessionId::new(),
        "127.0.0.1:161".parse().unwrap(),
        "127.0.0.1:40000".parse().unwrap(),
        tokio::time::Instant::now(),
        bytes.len(),
    );
    ProcessingInput::new(ReceivedPacket::new(bytes, info), limits).unwrap()
}
fn community(version: Version, pdu: Pdu, limits: ProcessingLimits) -> ProcessingInput {
    let version = if version == Version::V1 {
        async_snmp::CommunityVersion::V1
    } else {
        async_snmp::CommunityVersion::V2c
    };
    received(
        CommunityMessage::new(version, "public", pdu)
            .unwrap()
            .encode()
            .unwrap(),
        limits,
    )
}
fn get(version: Version) -> Pdu {
    RequestPdu::get(version, 11, &[object()])
        .unwrap()
        .into_raw()
}
fn set(version: Version, value: Value) -> Pdu {
    RequestPdu::set(version, 11, vec![VarBind::new(object(), value)])
        .unwrap()
        .into_raw()
}
fn inform(version: Version) -> Pdu {
    NotificationPdu::inform(
        version,
        12,
        0,
        &async_snmp::notification::oids::cold_start(),
        vec![],
    )
    .unwrap()
    .into_raw()
}
fn decoded(bytes: Bytes) -> Pdu {
    CommunityMessage::decode(bytes, async_snmp::DecodeConfig::DEFAULT)
        .unwrap()
        .value
        .into_pdu()
        .unwrap()
}
fn local_engine() -> LocalEngine {
    LocalEngine::new(
        AuthoritativeEngine::install(
            b"socketless-command".as_slice(),
            |_| Ok::<_, Infallible>(()),
        )
        .unwrap(),
    )
    .unwrap()
}
async fn entered(signal: &Semaphore) {
    tokio::time::timeout(WAIT, signal.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
}

struct State {
    value: AtomicI32,
    gets: AtomicUsize,
    tests: AtomicUsize,
    commits: AtomicUsize,
    finalized: AtomicUsize,
    freed: AtomicUsize,
    block_test: AtomicBool,
    active_commits: AtomicUsize,
    max_commits: AtomicUsize,
    panic_commit: AtomicBool,
    block_commit: AtomicBool,
    block_get: AtomicBool,
    started: Semaphore,
    release: Semaphore,
    metadata: std::sync::Mutex<Option<ReceivedMessageInfo>>,
    payload: Option<Bytes>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            value: AtomicI32::new(42),
            gets: AtomicUsize::new(0),
            tests: AtomicUsize::new(0),
            commits: AtomicUsize::new(0),
            finalized: AtomicUsize::new(0),
            freed: AtomicUsize::new(0),
            block_test: AtomicBool::new(false),
            active_commits: AtomicUsize::new(0),
            max_commits: AtomicUsize::new(0),
            panic_commit: AtomicBool::new(false),
            block_commit: AtomicBool::new(false),
            block_get: AtomicBool::new(false),
            started: Semaphore::new(0),
            release: Semaphore::new(0),
            metadata: std::sync::Mutex::new(None),
            payload: None,
        }
    }
}
struct Handler(Arc<State>);
struct Mutation {
    state: Arc<State>,
    value: i32,
}
impl PreparedSet for Mutation {
    fn commit<'a>(
        &'a mut self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
        _value: &'a Value,
    ) -> BoxFuture<'a, SetCommitResult> {
        Box::pin(async move {
            let count = self.state.active_commits.fetch_add(1, Ordering::SeqCst) + 1;
            self.state.max_commits.fetch_max(count, Ordering::SeqCst);
            self.state.started.add_permits(1);
            if self.state.block_commit.load(Ordering::SeqCst) {
                self.state.release.acquire().await.unwrap().forget();
            }
            assert!(
                !self.state.panic_commit.load(Ordering::SeqCst),
                "injected commit panic"
            );
            self.state.value.store(self.value, Ordering::SeqCst);
            self.state.commits.fetch_add(1, Ordering::SeqCst);
            self.state.active_commits.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        })
    }
    fn undo<'a>(
        &'a mut self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
        _value: &'a Value,
    ) -> BoxFuture<'a, SetUndoResult> {
        Box::pin(async { Ok(()) })
    }
    fn free<'a>(
        &'a mut self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
        _value: &'a Value,
    ) -> BoxFuture<'a, ()> {
        self.state.freed.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {})
    }
    fn finalize<'a>(
        &'a mut self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
        _value: &'a Value,
    ) -> BoxFuture<'a, ()> {
        self.state.finalized.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {})
    }
}
impl MibHandler for Handler {
    fn get<'a>(
        &'a self,
        ctx: &'a RequestContext,
        oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetResult>> {
        Box::pin(async move {
            self.0.gets.fetch_add(1, Ordering::SeqCst);
            *self.0.metadata.lock().unwrap() = ctx.receive_info().copied();
            if self.0.block_get.load(Ordering::SeqCst) {
                self.0.started.add_permits(1);
                self.0.release.acquire().await.unwrap().forget();
            }
            if oid != &object() {
                return Ok(GetResult::NoSuchObject);
            }
            Ok(GetResult::Value(self.0.payload.as_ref().map_or_else(
                || Value::Integer(self.0.value.load(Ordering::SeqCst)),
                |payload| Value::OctetString(payload.clone()),
            )))
        })
    }
    fn get_next<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
        Box::pin(async move {
            if oid < &object() {
                Ok(GetNextResult::Value(VarBind::new(
                    object(),
                    Value::Integer(self.0.value.load(Ordering::SeqCst)),
                )))
            } else {
                Ok(GetNextResult::EndOfMibView)
            }
        })
    }
    fn test_set<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
        value: &'a Value,
    ) -> BoxFuture<'a, SetTestResult> {
        self.0.tests.fetch_add(1, Ordering::SeqCst);
        let value = if let Value::Integer(value) = value {
            *value
        } else {
            0
        };
        Box::pin(async move {
            if self.0.block_test.load(Ordering::SeqCst) {
                self.0.started.add_permits(1);
                self.0.release.acquire().await.unwrap().forget();
            }
            Ok(Box::new(Mutation {
                state: self.0.clone(),
                value,
            }) as Box<dyn PreparedSet>)
        })
    }
}
fn builder(state: Arc<State>) -> CommandProcessorBuilder {
    CommandProcessor::builder()
        .community("public")
        .handler(prefix(), Arc::new(Handler(state)))
        .allow_all_access()
        .without_builtin_handlers()
}

#[test]
fn application_build_and_capacity_declaration_require_no_runtime_or_network() {
    assert!(tokio::runtime::Handle::try_current().is_err());
    let processor = builder(Arc::new(State::default())).build().unwrap();
    let engine = processor.local_engine();
    assert!(engine.receive_capacity().is_none());
    let registration = engine.register_receive_capacity(MessageSize::new(8192).unwrap());
    assert_eq!(engine.receive_capacity().unwrap().as_usize(), 8192);
    drop(registration);
    assert!(engine.receive_capacity().is_none());
    assert!(!processor.control().is_shutdown());
    assert!(tokio::runtime::Handle::try_current().is_err());
}

#[tokio::test]
async fn community_operations_share_handlers_and_original_input_metadata() {
    for version in [Version::V1, Version::V2c] {
        let state = Arc::new(State::default());
        let processor = builder(state.clone()).build().unwrap();
        let _registration = processor
            .local_engine()
            .register_receive_capacity(limits().receive().advertised());
        let input = community(version, get(version), limits());
        let info = input.info();
        let reply = processor.process(input).await.unwrap().unwrap();
        assert_eq!(reply.receive_info, info);
        assert_eq!(*state.metadata.lock().unwrap(), Some(info));
        assert_eq!(decoded(reply.bytes).varbinds()[0].value, Value::Integer(42));
        let next = RequestPdu::get_next(version, 12, &[prefix()])
            .unwrap()
            .into_raw();
        let response = processor
            .process(community(version, next, limits()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            decoded(response.bytes).varbinds()[0].value,
            Value::Integer(42)
        );
        if version == Version::V2c {
            let bulk =
                GetBulkPdu::new(version, 13, 0, 2, vec![VarBind::new(prefix(), Value::Null)])
                    .unwrap()
                    .into_raw();
            let response = processor
                .process(community(version, bulk, limits()))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                decoded(response.bytes).varbinds()[0].value,
                Value::Integer(42)
            );
        }
        let response = processor
            .process(community(
                version,
                set(version, Value::Integer(77)),
                limits(),
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decoded(response.bytes).error_status(), 0);
        assert_eq!(state.value.load(Ordering::SeqCst), 77);
        assert_eq!(state.finalized.load(Ordering::SeqCst), 1);
        processor.control().shutdown(WAIT).await.unwrap();
    }
}

#[tokio::test]
async fn v2c_command_role_ignores_informs_with_read_only_vacm() {
    use async_snmp::handler::SecurityModel;

    let processor = CommandProcessor::builder()
        .community("public")
        .handler(prefix(), Arc::new(Handler(Arc::new(State::default()))))
        .vacm(|vacm| {
            vacm.group("public", SecurityModel::V2c, "readers")
                .access(
                    "readers",
                    SecurityModel::V2c,
                    SecurityLevel::NoAuthNoPriv,
                    |access| access.read_view("read"),
                )
                .view("read", |view| view.include(prefix()))
        })
        .build()
        .unwrap();
    let _registration = processor
        .local_engine()
        .register_receive_capacity(limits().receive().advertised());
    let response = processor
        .process(community(Version::V2c, get(Version::V2c), limits()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        decoded(response.bytes).varbinds()[0].value,
        Value::Integer(42)
    );
    assert!(
        processor
            .process(community(Version::V2c, inform(Version::V2c), limits()))
            .await
            .unwrap()
            .is_none()
    );
}

fn v3_input(local: &LocalEngine, username: &str, request: Pdu) -> ProcessingInput {
    v3_input_with_context(local, username, local.engine_id(), request)
}
fn v3_input_with_context(
    local: &LocalEngine,
    username: &str,
    context_engine: &[u8],
    request: Pdu,
) -> ProcessingInput {
    let (boots, time) = local.current_boots_time().unwrap();
    let usm = UsmSecurityParams::new(
        Bytes::copy_from_slice(local.engine_id()),
        boots,
        time,
        Bytes::copy_from_slice(username.as_bytes()),
    )
    .unwrap();
    let wire = V3Message::new(
        MsgGlobalData::new(
            71,
            MessageSize::new(8192).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, true),
        )
        .unwrap(),
        usm.encode().unwrap(),
        ScopedPdu::new(
            Bytes::copy_from_slice(context_engine),
            Bytes::new(),
            request,
        ),
    )
    .unwrap()
    .encode()
    .unwrap();
    received(wire, limits())
}
fn v3_pdu(bytes: Bytes) -> Pdu {
    let message = V3Message::decode(bytes, async_snmp::DecodeConfig::DEFAULT)
        .unwrap()
        .value;
    let V3MessageData::Plaintext(scoped) = message.data() else {
        panic!("expected plaintext")
    };
    scoped.pdu.clone()
}

#[tokio::test]
async fn v3_command_role_ignores_informs_before_scoped_context_checks() {
    let local = local_engine();
    let context = UsmSecurityContext::new([UsmUserEntry::new(UsmUser::new("user"))]).unwrap();
    let processor = CommandProcessor::builder()
        .local_engine(local.clone())
        .security_context(context)
        .allow_all_access()
        .build()
        .unwrap();
    let _registration = local.register_receive_capacity(limits().receive().advertised());
    let foreign_context = b"foreign-context-engine";
    for context_engine in [local.engine_id(), foreign_context] {
        let input = v3_input_with_context(&local, "user", context_engine, inform(Version::V3));
        assert!(processor.process(input).await.unwrap().is_none());
    }

    let unknown_user =
        v3_input_with_context(&local, "unknown", foreign_context, inform(Version::V3));
    let response = processor.process(unknown_user).await.unwrap().unwrap();
    assert_eq!(
        async_snmp::v3::classify_report(&v3_pdu(response.bytes)).unwrap(),
        async_snmp::v3::ReportStatus::UnknownUserName { counter: 1 }
    );

    let query = v3_input_with_context(&local, "user", foreign_context, get(Version::V3));
    let response = processor.process(query).await.unwrap().unwrap();
    assert_eq!(
        async_snmp::v3::classify_report(&v3_pdu(response.bytes)).unwrap(),
        async_snmp::v3::ReportStatus::Other {
            oid: oid!(1, 3, 6, 1, 6, 3, 12, 1, 5, 0),
            value: Value::Counter32(1),
        }
    );
}

#[tokio::test]
async fn v3_commands_and_reports_use_selected_runtime_credentials() {
    let state = Arc::new(State::default());
    let local = local_engine();
    let context = UsmSecurityContext::new([UsmUserEntry::for_engine(
        Bytes::copy_from_slice(local.engine_id()),
        UsmUser::new("first"),
    )
    .unwrap()])
    .unwrap();
    let processor = builder(state.clone())
        .local_engine(local.clone())
        .security_context(context.clone())
        .build()
        .unwrap();
    let _registration = local.register_receive_capacity(limits().receive().advertised());
    for request in [
        get(Version::V3),
        RequestPdu::get_next(Version::V3, 12, &[prefix()])
            .unwrap()
            .into_raw(),
        GetBulkPdu::new(
            Version::V3,
            13,
            0,
            2,
            vec![VarBind::new(prefix(), Value::Null)],
        )
        .unwrap()
        .into_raw(),
        set(Version::V3, Value::Integer(77)),
    ] {
        let response = processor
            .process(v3_input(&local, "first", request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            v3_pdu(response.bytes).pdu_type(),
            async_snmp::PduType::Response
        );
    }
    context
        .replace_users([UsmUserEntry::for_engine(
            Bytes::copy_from_slice(local.engine_id()),
            UsmUser::new("second"),
        )
        .unwrap()])
        .unwrap();
    let report = processor
        .process(v3_input(&local, "first", get(Version::V3)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v3_pdu(report.bytes).pdu_type(), async_snmp::PduType::Report);
    assert_eq!(local.usm_stats().unknown_usernames, 1);
    let response = processor
        .process(v3_input(&local, "second", get(Version::V3)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        v3_pdu(response.bytes).varbinds()[0].value,
        Value::Integer(77)
    );
    processor.control().shutdown(WAIT).await.unwrap();
}

#[tokio::test]
async fn stream_sizes_and_set_preflight_use_exact_input_limits() {
    let state = Arc::new(State {
        payload: Some(Bytes::from(vec![b'x'; 70 * 1024])),
        ..State::default()
    });
    let processor = builder(state.clone()).build().unwrap();
    let big = ProcessingLimits::new(ReceiveLimits::tcp(128 * 1024).unwrap(), 128 * 1024).unwrap();
    let _registration = processor
        .local_engine()
        .register_receive_capacity(big.receive().advertised());
    let response = processor
        .process(community(Version::V2c, get(Version::V2c), big))
        .await
        .unwrap()
        .unwrap();
    assert!(response.bytes.len() > async_snmp::MAX_UDP_PAYLOAD);
    let small_send = ProcessingLimits::new(big.receive(), 64).unwrap();
    let request = set(
        Version::V2c,
        Value::OctetString(Bytes::from(vec![b'y'; 70 * 1024])),
    );
    let response = processor
        .process(community(Version::V2c, request, small_send))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(decoded(response.bytes).error_status(), 1);
    assert_eq!(state.tests.load(Ordering::SeqCst), 0);
    processor.control().shutdown(WAIT).await.unwrap();
}

#[tokio::test]
async fn cancellation_retains_commit_cleanup_and_drain_visibility() {
    let state = Arc::new(State::default());
    state.block_commit.store(true, Ordering::SeqCst);
    let processor = builder(state.clone()).build().unwrap();
    let _registration = processor
        .local_engine()
        .register_receive_capacity(limits().receive().advertised());
    let control = processor.control();
    let request_processor = processor.clone();
    let task = tokio::spawn(async move {
        request_processor
            .process(community(
                Version::V2c,
                set(Version::V2c, Value::Integer(91)),
                limits(),
            ))
            .await
    });
    entered(&state.started).await;
    assert_eq!(control.outstanding_mutations(), 1);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    control.request_shutdown();
    assert!(
        control
            .drain_mutations(Duration::from_millis(10))
            .await
            .is_err()
    );
    assert_eq!(control.outstanding_requests(), 1);
    state.release.add_permits(1);
    control.drain_requests(WAIT).await.unwrap();
    assert_eq!(state.value.load(Ordering::SeqCst), 91);
    assert_eq!(state.finalized.load(Ordering::SeqCst), 1);
    assert_eq!(control.outstanding_mutations(), 0);
    assert!(
        processor
            .process(community(Version::V2c, get(Version::V2c), limits()))
            .await
            .is_err()
    );
}

#[tokio::test(start_paused = true)]
async fn request_deadline_returns_while_commit_remains_owned() {
    let state = Arc::new(State::default());
    state.block_commit.store(true, Ordering::SeqCst);
    let processor = builder(state.clone())
        .request_deadline(Some(Duration::from_secs(1)))
        .build()
        .unwrap();
    let _registration = processor
        .local_engine()
        .register_receive_capacity(limits().receive().advertised());
    let control = processor.control();
    let copy = processor.clone();
    let task = tokio::spawn(async move {
        copy.process(community(
            Version::V2c,
            set(Version::V2c, Value::Integer(94)),
            limits(),
        ))
        .await
    });
    entered(&state.started).await;
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(matches!(
        *task.await.unwrap().unwrap_err(),
        Error::Timeout { .. }
    ));
    assert_eq!(control.outstanding_mutations(), 1);
    control.request_shutdown();
    state.release.add_permits(1);
    control.drain_requests(WAIT).await.unwrap();
    assert_eq!(state.finalized.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn concurrent_sets_share_one_coordinator() {
    let state = Arc::new(State::default());
    state.block_commit.store(true, Ordering::SeqCst);
    let processor = builder(state.clone())
        .max_concurrent_requests(2)
        .build()
        .unwrap();
    let _registration = processor
        .local_engine()
        .register_receive_capacity(limits().receive().advertised());
    let first = processor.clone();
    let first = tokio::spawn(async move {
        first
            .process(community(
                Version::V2c,
                set(Version::V2c, Value::Integer(1)),
                limits(),
            ))
            .await
    });
    entered(&state.started).await;
    let second = processor.clone();
    let second = tokio::spawn(async move {
        second
            .process(community(
                Version::V2c,
                set(Version::V2c, Value::Integer(2)),
                limits(),
            ))
            .await
    });
    tokio::time::timeout(WAIT, async {
        while processor.control().outstanding_requests() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(state.commits.load(Ordering::SeqCst), 0);
    assert_eq!(state.active_commits.load(Ordering::SeqCst), 1);
    state.release.add_permits(1);
    entered(&state.started).await;
    state.release.add_permits(1);
    first.await.unwrap().unwrap();
    second.await.unwrap().unwrap();
    assert_eq!(state.max_commits.load(Ordering::SeqCst), 1);
    assert_eq!(state.finalized.load(Ordering::SeqCst), 2);
    processor.control().shutdown(WAIT).await.unwrap();
}

#[tokio::test]
async fn mutation_drain_wakes_when_registered_request_classifies_as_retrieval() {
    let state = Arc::new(State::default());
    state.block_get.store(true, Ordering::SeqCst);
    let processor = builder(state.clone()).build().unwrap();
    let _registration = processor
        .local_engine()
        .register_receive_capacity(limits().receive().advertised());
    let control = processor.control();
    let mut request =
        Box::pin(processor.process(community(Version::V2c, get(Version::V2c), limits())));

    // Register the owned child without yielding to it, so drain sees Unclassified.
    assert!(futures_util::poll!(&mut request).is_pending());
    assert_eq!(control.outstanding_requests(), 1);
    assert_eq!(state.gets.load(Ordering::SeqCst), 0);
    control.request_shutdown();
    let mut mutation_drain = Box::pin(control.drain_mutations(WAIT));
    assert!(futures_util::poll!(&mut mutation_drain).is_pending());

    // Classification must wake the already waiting drain while GET remains blocked.
    entered(&state.started).await;
    assert!(matches!(
        futures_util::poll!(&mut mutation_drain),
        std::task::Poll::Ready(Ok(()))
    ));
    assert_eq!(control.outstanding_requests(), 1);
    assert_eq!(control.outstanding_mutations(), 0);
    let mut full_drain = Box::pin(control.drain_requests(WAIT));
    assert!(futures_util::poll!(&mut full_drain).is_pending());

    drop(request);
    state.release.add_permits(1);
    full_drain.await.unwrap();
    assert_eq!(control.outstanding_requests(), 0);
}

#[tokio::test]
async fn queued_admission_rechecks_endpoint_capacity_atomically() {
    let state = Arc::new(State::default());
    state.block_get.store(true, Ordering::SeqCst);
    let processor = builder(state.clone())
        .max_concurrent_requests(1)
        .build()
        .unwrap();
    let engine = processor.local_engine();
    let registration = engine.register_receive_capacity(limits().receive().advertised());
    let _larger = engine.register_receive_capacity(MessageSize::new(32768).unwrap());
    let first = processor.clone();
    let first = tokio::spawn(async move {
        first
            .process(community(Version::V2c, get(Version::V2c), limits()))
            .await
    });
    entered(&state.started).await;
    let queued = processor.clone();
    let queued_input = community(Version::V2c, get(Version::V2c), limits());
    let mut queued = Box::pin(async move { queued.process(queued_input).await });
    assert!(futures_util::poll!(&mut queued).is_pending());
    drop(registration);
    assert_eq!(engine.receive_capacity().unwrap().as_usize(), 8192);
    state.release.add_permits(1);
    first.await.unwrap().unwrap();
    assert!(matches!(*queued.await.unwrap_err(), Error::Config(_)));
    assert_eq!(engine.receive_capacity().unwrap().as_usize(), 32768);
    assert_eq!(state.gets.load(Ordering::SeqCst), 1);
    processor.control().shutdown(WAIT).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_mutation_panics_are_reported_by_concurrent_drains() {
    let state = Arc::new(State::default());
    state.panic_commit.store(true, Ordering::SeqCst);
    state.block_commit.store(true, Ordering::SeqCst);
    let processor = builder(state.clone()).build().unwrap();
    let _registration = processor
        .local_engine()
        .register_receive_capacity(limits().receive().advertised());
    let control = processor.control();
    let request = tokio::spawn(async move {
        processor
            .process(community(
                Version::V2c,
                set(Version::V2c, Value::Integer(9)),
                limits(),
            ))
            .await
    });
    entered(&state.started).await;
    assert_eq!(control.outstanding_mutations(), 1);
    control.request_shutdown();
    let mut mutations = Box::pin(control.drain_mutations(WAIT));
    let mut requests = Box::pin(control.drain_requests(WAIT));
    assert!(futures_util::poll!(&mut mutations).is_pending());
    assert!(futures_util::poll!(&mut requests).is_pending());

    state.release.add_permits(1);
    let (mutations, requests) = tokio::join!(mutations, requests);
    for result in [mutations, requests] {
        assert!(matches!(
            *result.unwrap_err(),
            Error::Config(reason) if &*reason == "retained mutation cleanup failed"
        ));
    }
    assert_eq!(control.outstanding_requests(), 0);
    assert!(request.await.unwrap().is_err());
}

#[tokio::test]
async fn runtime_shutdown_interrupts_retained_mutation_drain() {
    let state = Arc::new(State::default());
    state.block_commit.store(true, Ordering::SeqCst);
    let processor = builder(state.clone()).build().unwrap();
    let _registration = processor
        .local_engine()
        .register_receive_capacity(limits().receive().advertised());
    let control = processor.control();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .build()
        .unwrap();
    runtime.spawn(async move {
        processor
            .process(community(
                Version::V2c,
                set(Version::V2c, Value::Integer(9)),
                limits(),
            ))
            .await
    });
    entered(&state.started).await;
    assert_eq!(control.outstanding_mutations(), 1);
    control.request_shutdown();
    let mut mutations = Box::pin(control.drain_mutations(WAIT));
    assert!(futures_util::poll!(&mut mutations).is_pending());

    runtime.shutdown_background();

    assert!(matches!(
        *mutations.await.unwrap_err(),
        Error::Config(reason) if &*reason == "retained mutation cleanup failed"
    ));
    assert_eq!(control.outstanding_requests(), 0);
    assert_eq!(state.finalized.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn spawning_on_a_stopped_runtime_leaves_no_retained_request() {
    let state = Arc::new(State::default());
    let processor = builder(state.clone()).build().unwrap();
    let _registration = processor
        .local_engine()
        .register_receive_capacity(limits().receive().advertised());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let stopped = runtime.handle().clone();
    runtime.shutdown_background();

    let mut request =
        Box::pin(processor.process(community(Version::V2c, get(Version::V2c), limits())));
    let first_poll = {
        let _enter = stopped.enter();
        futures_util::poll!(&mut request)
    };
    let result = match first_poll {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => request.await,
    };
    assert!(result.is_err());
    assert_eq!(state.gets.load(Ordering::SeqCst), 0);

    let control = processor.control();
    control.request_shutdown();
    control.drain_mutations(Duration::ZERO).await.unwrap();
    control.drain_requests(Duration::ZERO).await.unwrap();
    assert_eq!(control.outstanding_requests(), 0);
}

#[tokio::test]
async fn in_flight_holds_do_not_authorize_departed_endpoint_admission() {
    for keep_larger_endpoint in [false, true] {
        let state = Arc::new(State::default());
        state.block_get.store(true, Ordering::SeqCst);
        let processor = builder(state.clone())
            .max_concurrent_requests(2)
            .build()
            .unwrap();
        let engine = processor.local_engine();
        let declared = engine.register_receive_capacity(limits().receive().advertised());
        let _larger = keep_larger_endpoint
            .then(|| engine.register_receive_capacity(MessageSize::new(32768).unwrap()));
        let first = processor.clone();
        let task = tokio::spawn(async move {
            first
                .process(community(Version::V2c, get(Version::V2c), limits()))
                .await
        });
        entered(&state.started).await;
        drop(declared);
        assert_eq!(engine.receive_capacity().unwrap().as_usize(), 8192);
        assert!(
            processor
                .process(community(Version::V2c, get(Version::V2c), limits()))
                .await
                .is_err()
        );
        assert_eq!(processor.control().outstanding_requests(), 1);
        assert_eq!(state.gets.load(Ordering::SeqCst), 1);
        state.release.add_permits(1);
        task.await.unwrap().unwrap();
        assert_eq!(
            engine.receive_capacity().map(MessageSize::as_usize),
            keep_larger_endpoint.then_some(32768)
        );
        processor.control().shutdown(WAIT).await.unwrap();
    }
}

#[tokio::test]
async fn cancelled_precommit_wait_retains_and_frees_prepared_state() {
    let state = Arc::new(State::default());
    state.block_test.store(true, Ordering::SeqCst);
    let processor = builder(state.clone()).build().unwrap();
    let _registration = processor
        .local_engine()
        .register_receive_capacity(limits().receive().advertised());
    let control = processor.control();
    let copy = processor.clone();
    let task = tokio::spawn(async move {
        copy.process(community(
            Version::V2c,
            set(Version::V2c, Value::Integer(9)),
            limits(),
        ))
        .await
    });
    entered(&state.started).await;
    task.abort();
    task.await.unwrap_err();
    control.request_shutdown();
    assert_eq!(control.outstanding_mutations(), 1);
    state.release.add_permits(1);
    control.drain_mutations(WAIT).await.unwrap();
    assert_eq!(state.freed.load(Ordering::SeqCst), 1);
    assert_eq!(state.commits.load(Ordering::SeqCst), 0);
    assert_eq!(state.finalized.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn caller_capacity_declarations_determine_engine_mib_without_udp_fallback() {
    let processor = CommandProcessor::builder()
        .community("public")
        .allow_all_access()
        .build()
        .unwrap();
    let engine = processor.local_engine();
    let query = || {
        RequestPdu::get(Version::V2c, 13, &[oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 4, 0)])
            .unwrap()
            .into_raw()
    };
    assert!(
        processor
            .process(community(Version::V2c, query(), limits()))
            .await
            .is_err()
    );
    let larger = engine.register_receive_capacity(MessageSize::new(32768).unwrap());
    assert!(
        processor
            .process(community(Version::V2c, query(), limits()))
            .await
            .is_err()
    );
    let smaller = engine.register_receive_capacity(limits().receive().advertised());
    let response = processor
        .process(community(Version::V2c, query(), limits()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        decoded(response.bytes).varbinds()[0].value,
        Value::Integer(8192)
    );
    drop(smaller);
    let big = ProcessingLimits::new(ReceiveLimits::tcp(32768).unwrap(), 32768).unwrap();
    let response = processor
        .process(community(Version::V2c, query(), big))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        decoded(response.bytes).varbinds()[0].value,
        Value::Integer(32768)
    );
    drop(larger);
    assert!(engine.receive_capacity().is_none());
    processor.control().shutdown(WAIT).await.unwrap();
}

#[test]
fn explicit_usm_context_cannot_bypass_engine_or_access_prerequisites() {
    assert!(
        CommandProcessor::builder()
            .security_context(UsmSecurityContext::default())
            .allow_all_access()
            .build()
            .is_err()
    );
    assert!(
        CommandProcessor::builder()
            .local_engine(local_engine())
            .security_context(UsmSecurityContext::default())
            .build()
            .is_err()
    );
    assert!(
        CommandProcessor::builder()
            .community("public")
            .build()
            .is_err()
    );
    assert!(
        CommandProcessor::builder()
            .community("public")
            .allow_all_access()
            .vacm(|builder| builder)
            .build()
            .is_err()
    );
}
