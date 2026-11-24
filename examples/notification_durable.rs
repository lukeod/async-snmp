//! Persist accepted notification content before acknowledging an Inform.
//! Run: cargo run --example notification_durable -- ./notifications.log
//! Receives one event on 127.0.0.1:1162, then shuts down. This v2c example
//! needs no authoritative engine persistence; the log uses append + fsync.
//! Retransmissions are independent records: this is not an exactly-once store.
//! The platform and filesystem must support opening and syncing the log's
//! parent directory.

#[path = "support/notification_log.rs"]
mod notification_log;

use std::path::PathBuf;

use async_snmp::{InformAcknowledgementMode, NotificationAcknowledgement, NotificationReceiver};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let log = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "notifications.log".into()),
    );
    let mut running = NotificationReceiver::builder()
        .bind("127.0.0.1:1162")
        .community("public")
        .acknowledgement_mode(InformAcknowledgementMode::ApplicationControlled)
        .max_pending_informs(256)
        .pending_inform_timeout(std::time::Duration::from_secs(30))
        .spawn()
        .await?;
    println!("Waiting for one v1/v2c notification on 127.0.0.1:1162");

    let persistence = if let Some(received) = running.recv().await {
        // The text format is a demonstration application record, not a journal
        // schema or deduplication key. Preserve the content before responding.
        let record = format!("{:?} {:?}", received.receive_info, received.notification);
        let persisted = notification_log::append(log, record).await;
        match (persisted, received.inform_ack) {
            (Ok(()), NotificationAcknowledgement::Pending(pending)) => {
                println!("Inform completion: {:?}", pending.acknowledge().await);
                Ok(())
            }
            (Err(error), NotificationAcknowledgement::Pending(pending)) => {
                pending.reject(); // No acknowledgement after a failed sync.
                Err(error)
            }
            (result, acknowledgement) => result.inspect(|_| {
                println!("Acknowledgement state: {acknowledgement:?}");
            }),
        }
    } else {
        Ok(())
    };
    let shutdown = running.shutdown().await;
    persistence?;
    shutdown?;
    Ok(())
}
