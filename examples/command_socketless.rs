//! Caller-owned UDP I/O, explicit receive capacity, and bounded command drain.
//! Run: cargo run --example command_socketless --features agent
//! Try: snmpget -v2c -c public 127.0.0.1:1161 1.3.6.1.6.3.10.2.1.1.0
//! Serves for 60 seconds. Built-in engine/statistics objects are read-only.

use std::time::Duration;

use async_snmp::{
    CommandProcessor, EndpointId, ProcessingInput, ProcessingLimits, ReceiveCapacityRegistration,
    ReceivedMessageInfo, ReceivedPacket,
};
use bytes::Bytes;
use tokio::net::UdpSocket;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configuration creates no sockets/tasks and needs no Tokio runtime.
    let processor = CommandProcessor::builder()
        .community("public")
        .allow_all_access()
        .request_deadline(Some(Duration::from_secs(5)))
        .build()?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(serve(processor))
}

async fn serve(processor: CommandProcessor) -> Result<(), Box<dyn std::error::Error>> {
    // Bind a concrete address: recv_from does not supply wildcard destination
    // ancillary data. This socket is the sole reader and the original reply path.
    let socket = UdpSocket::bind("127.0.0.1:1161").await?;
    let local = socket.local_addr()?;
    let endpoint = EndpointId::new();
    let limits = ProcessingLimits::UDP;
    let capacity: ReceiveCapacityRegistration = processor
        .local_engine()
        .register_receive_capacity(limits.receive().advertised());
    let control = processor.control();
    let result: Result<(), Box<dyn std::error::Error>> = async {
        let stop = tokio::time::sleep(Duration::from_secs(60));
        tokio::pin!(stop);
        let mut buffer = vec![0; limits.receive().accepted()];
        println!("Serving commands on {local} for 60 seconds");
        loop {
            let (len, peer) = tokio::select! {
                () = &mut stop => break,
                input = socket.recv_from(&mut buffer) => input?,
            };
            let info = ReceivedMessageInfo::udp(
                endpoint,
                local,
                peer,
                None,
                tokio::time::Instant::now(),
                len,
            );
            let input = ProcessingInput::new(
                ReceivedPacket::new(Bytes::copy_from_slice(&buffer[..len]), info),
                limits,
            )?;
            match processor.process(input).await {
                Ok(Some(response)) => {
                    // Send on this input's endpoint, preserving its peer route.
                    tokio::time::timeout(
                        Duration::from_secs(5),
                        socket.send_to(&response.bytes, response.receive_info.peer_addr()),
                    )
                    .await??;
                }
                Ok(None) => {}
                Err(error) => eprintln!("Command failed: {error}"),
            }
        }
        Ok(())
    }
    .await;

    // Close admission first. A cancelled caller/deadline can return before SET
    // undo/free finishes. Mutation drain includes unclassified work; full request
    // drain also waits for retrievals. Timeout does not abort retained cleanup.
    control.request_shutdown();
    let drained = control.drain_requests(Duration::from_secs(5)).await;
    drop(socket);
    drop(capacity);
    // On timeout this demonstration exits; runtime teardown cannot guarantee
    // remaining asynchronous cleanup. A long-lived host can keep driving it.
    drained?;
    result
}
