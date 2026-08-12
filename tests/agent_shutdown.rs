#![cfg(feature = "agent")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use async_snmp::handler::{
    BoxFuture, GetNextResult, GetResult, HandlerResult, MibHandler, RequestContext, SetResult,
};
use async_snmp::{Agent, Auth, Client, Oid, Retry, Value, oid};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const TEST_TIMEOUT: Duration = Duration::from_secs(2);

fn test_oid() -> Oid {
    oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0)
}

fn panic_oid() -> Oid {
    oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0)
}

fn fast_oid() -> Oid {
    oid!(1, 3, 6, 1, 4, 1, 99999, 3, 0)
}

async fn start_agent(
    handler: Arc<dyn MibHandler>,
    max_concurrent_requests: Option<usize>,
) -> (
    SocketAddr,
    CancellationToken,
    JoinHandle<async_snmp::Result<()>>,
) {
    let cancel = CancellationToken::new();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .cancel(cancel.clone())
        .handler(oid!(1, 3, 6, 1, 4, 1, 99999), handler)
        .max_concurrent_requests(max_concurrent_requests)
        .without_builtin_handlers()
        .allow_all_access()
        .build()
        .await
        .expect("agent should build");
    let addr = agent.local_addr();
    let run_task = tokio::spawn(async move { agent.run().await });
    tokio::task::yield_now().await;
    (addr, cancel, run_task)
}

async fn client(addr: SocketAddr) -> Client {
    Client::builder(addr.to_string(), Auth::v2c("public"))
        .request_timeout(TEST_TIMEOUT)
        .retry(Retry::none())
        .connect()
        .await
        .expect("client should connect")
}

async fn wait_for(semaphore: &Semaphore) {
    tokio::time::timeout(TEST_TIMEOUT, semaphore.acquire())
        .await
        .expect("handler should be entered")
        .expect("semaphore should remain open")
        .forget();
}

async fn await_shutdown(run_task: JoinHandle<async_snmp::Result<()>>) {
    tokio::time::timeout(TEST_TIMEOUT, run_task)
        .await
        .expect("agent shutdown should complete")
        .expect("agent task should not panic")
        .expect("agent run should succeed");
}

struct BlockingGetHandler {
    started: Arc<Semaphore>,
    release: Arc<Semaphore>,
    calls: Arc<AtomicUsize>,
}

impl MibHandler for BlockingGetHandler {
    fn get<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetResult>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.add_permits(1);
        Box::pin(async move {
            self.release
                .acquire()
                .await
                .expect("release semaphore should remain open")
                .forget();
            Ok(GetResult::Value(Value::Integer(42)))
        })
    }

    fn get_next<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
        Box::pin(async { Ok(GetNextResult::EndOfMibView) })
    }
}

#[tokio::test]
async fn cancellation_drains_a_dispatched_get_through_its_response() {
    let started = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    let handler = Arc::new(BlockingGetHandler {
        started: started.clone(),
        release: release.clone(),
        calls: Arc::new(AtomicUsize::new(0)),
    });
    let (addr, cancel, run_task) = start_agent(handler, Some(1)).await;
    let client = client(addr).await;

    let request_task = tokio::spawn(async move { client.get(&test_oid()).await });
    wait_for(&started).await;

    cancel.cancel();
    tokio::task::yield_now().await;
    assert!(
        !run_task.is_finished(),
        "run returned while a dispatched handler was still blocked"
    );

    release.add_permits(1);
    let response = tokio::time::timeout(TEST_TIMEOUT, request_task)
        .await
        .expect("request should receive the drained response")
        .expect("client task should not panic")
        .expect("GET should succeed after handler release");
    assert_eq!(response.varbinds[0].value, Value::Integer(42));
    await_shutdown(run_task).await;
}

struct BlockingSetHandler {
    commit_started: Arc<Semaphore>,
    release_commit: Arc<Semaphore>,
    committed: Arc<AtomicBool>,
}

impl MibHandler for BlockingSetHandler {
    fn get<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetResult>> {
        Box::pin(async { Ok(GetResult::Value(Value::Integer(0))) })
    }

    fn get_next<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
        Box::pin(async { Ok(GetNextResult::EndOfMibView) })
    }

    fn test_set<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
        _value: &'a Value,
    ) -> BoxFuture<'a, SetResult> {
        Box::pin(async { SetResult::Ok })
    }

    fn commit_set<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
        _value: &'a Value,
    ) -> BoxFuture<'a, SetResult> {
        self.commit_started.add_permits(1);
        Box::pin(async move {
            self.release_commit
                .acquire()
                .await
                .expect("release semaphore should remain open")
                .forget();
            self.committed.store(true, Ordering::SeqCst);
            SetResult::Ok
        })
    }
}

#[tokio::test]
async fn cancellation_does_not_abort_set_commit() {
    let commit_started = Arc::new(Semaphore::new(0));
    let release_commit = Arc::new(Semaphore::new(0));
    let committed = Arc::new(AtomicBool::new(false));
    let handler = Arc::new(BlockingSetHandler {
        commit_started: commit_started.clone(),
        release_commit: release_commit.clone(),
        committed: committed.clone(),
    });
    let (addr, cancel, run_task) = start_agent(handler, Some(1)).await;
    let client = client(addr).await;

    let request_task =
        tokio::spawn(async move { client.set(&test_oid(), Value::Integer(7)).await });
    wait_for(&commit_started).await;

    cancel.cancel();
    tokio::task::yield_now().await;
    assert!(
        !run_task.is_finished(),
        "run returned while commit_set was still blocked"
    );
    assert!(!committed.load(Ordering::SeqCst));

    release_commit.add_permits(1);
    let response = tokio::time::timeout(TEST_TIMEOUT, request_task)
        .await
        .expect("SET should receive the drained response")
        .expect("client task should not panic")
        .expect("SET should succeed after commit release");
    assert_eq!(response.varbinds[0].value, Value::Integer(7));
    assert!(committed.load(Ordering::SeqCst));
    await_shutdown(run_task).await;
}

#[tokio::test]
async fn externally_aborting_run_does_not_abort_set_commit() {
    let commit_started = Arc::new(Semaphore::new(0));
    let release_commit = Arc::new(Semaphore::new(0));
    let committed = Arc::new(AtomicBool::new(false));
    let handler = Arc::new(BlockingSetHandler {
        commit_started: commit_started.clone(),
        release_commit: release_commit.clone(),
        committed: committed.clone(),
    });
    let (addr, _cancel, run_task) = start_agent(handler, Some(1)).await;
    let client = client(addr).await;

    let request_task =
        tokio::spawn(async move { client.set(&test_oid(), Value::Integer(7)).await });
    wait_for(&commit_started).await;

    run_task.abort();
    let run_error = run_task
        .await
        .expect_err("externally aborted run task should report cancellation");
    assert!(run_error.is_cancelled());
    assert!(!committed.load(Ordering::SeqCst));
    assert!(
        !request_task.is_finished(),
        "dropping the run future aborted the blocked SET request task"
    );

    release_commit.add_permits(1);
    let response = tokio::time::timeout(TEST_TIMEOUT, request_task)
        .await
        .expect("SET should receive a response after the run future is dropped")
        .expect("client task should not panic")
        .expect("SET should succeed after commit release");
    assert_eq!(response.varbinds[0].value, Value::Integer(7));
    assert!(committed.load(Ordering::SeqCst));
}

#[tokio::test]
async fn cancellation_drops_a_datagram_waiting_for_a_permit() {
    let started = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let handler = Arc::new(BlockingGetHandler {
        started: started.clone(),
        release: release.clone(),
        calls: calls.clone(),
    });
    let (addr, cancel, run_task) = start_agent(handler, Some(1)).await;
    let first_client = client(addr).await;
    let second_client = client(addr).await;

    let first_request = tokio::spawn(async move { first_client.get(&test_oid()).await });
    wait_for(&started).await;

    let second_request = tokio::spawn(async move { second_client.get(&test_oid()).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    cancel.cancel();
    release.add_permits(1);
    tokio::time::timeout(TEST_TIMEOUT, first_request)
        .await
        .expect("first request should finish")
        .expect("first client task should not panic")
        .expect("first GET should succeed");
    await_shutdown(run_task).await;

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "request waiting for the sole permit was dispatched during shutdown"
    );
    second_request.abort();
    let _ = second_request.await;
}

struct PanicAndBlockHandler {
    blocked_started: Arc<Semaphore>,
    release_blocked: Arc<Semaphore>,
    panic_started: Arc<Semaphore>,
}

impl MibHandler for PanicAndBlockHandler {
    fn get<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetResult>> {
        if oid == &panic_oid() {
            self.panic_started.add_permits(1);
            return Box::pin(async { panic!("intentional request task panic") });
        }
        if oid == &fast_oid() {
            return Box::pin(async { Ok(GetResult::Value(Value::Integer(3))) });
        }

        self.blocked_started.add_permits(1);
        Box::pin(async move {
            self.release_blocked
                .acquire()
                .await
                .expect("release semaphore should remain open")
                .forget();
            Ok(GetResult::Value(Value::Integer(1)))
        })
    }

    fn get_next<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
        Box::pin(async { Ok(GetNextResult::EndOfMibView) })
    }
}

#[tokio::test]
async fn panicking_task_does_not_prevent_other_tasks_from_draining() {
    let blocked_started = Arc::new(Semaphore::new(0));
    let release_blocked = Arc::new(Semaphore::new(0));
    let panic_started = Arc::new(Semaphore::new(0));
    let handler = Arc::new(PanicAndBlockHandler {
        blocked_started: blocked_started.clone(),
        release_blocked: release_blocked.clone(),
        panic_started: panic_started.clone(),
    });
    let (addr, cancel, run_task) = start_agent(handler, None).await;
    let blocked_client = client(addr).await;
    let panic_client = client(addr).await;
    let fast_client = client(addr).await;

    let blocked_request = tokio::spawn(async move { blocked_client.get(&test_oid()).await });
    wait_for(&blocked_started).await;

    let panic_request = tokio::spawn(async move { panic_client.get(&panic_oid()).await });
    wait_for(&panic_started).await;

    let fast_response = fast_client
        .get(&fast_oid())
        .await
        .expect("agent should continue serving after a request task panic");
    assert_eq!(fast_response.varbinds[0].value, Value::Integer(3));

    cancel.cancel();
    tokio::task::yield_now().await;
    assert!(
        !run_task.is_finished(),
        "task panic caused shutdown to skip another running task"
    );

    release_blocked.add_permits(1);
    tokio::time::timeout(TEST_TIMEOUT, blocked_request)
        .await
        .expect("blocked request should finish")
        .expect("blocked client task should not panic")
        .expect("blocked GET should receive its response");
    await_shutdown(run_task).await;

    panic_request.abort();
    let _ = panic_request.await;
}
