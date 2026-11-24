//! Managed notification admission, automatic response sending and delivery.

use super::{
    EncodedInformResponse, InformAckOutcome, InformAcknowledgementMode, InformResponse,
    NotificationAcknowledgement, NotificationAdmission, NotificationProcessResult,
    NotificationRole, ProcessedNotification, ReceivedNotification,
};
use crate::error::{Error, Result};
use crate::v3::UsmFailure;

impl NotificationRole {
    pub(super) async fn parse_and_respond(
        &self,
        message: crate::transport::ReceivedMessage,
        admission: &mut NotificationAdmission,
    ) -> Result<Option<ReceivedNotification>> {
        let (input, route) = message.into_processing()?;
        let source = input.info().peer_addr();
        let result = self.inner.protocol.process_admitted(input, &mut |kind| {
            admission.reserve_inform(&self.inner, kind)
        })?;
        match result {
            NotificationProcessResult::Rejected => Ok(None),
            NotificationProcessResult::InformTooBig { response } => {
                if let Some(response) = response
                    && let Err(error) = self.send_response(response, &route).await
                {
                    tracing::debug!(target: "async_snmp::notification", { snmp.source = %source, error = %error }, "failed to send Inform tooBig response");
                }
                Ok(None)
            }
            NotificationProcessResult::UsmFailed { failure, report } => {
                tracing::warn!(target: "async_snmp::notification", { snmp.source = %source, snmp.failure = ?failure }, "USM processing failed for inbound message");
                if let Some(report) = report
                    && let Err(error) = self.send_response(report, &route).await
                {
                    tracing::debug!(target: "async_snmp::notification", { snmp.source = %source, error = %error }, "failed to send USM Report");
                }
                match failure {
                    UsmFailure::WrongDigests
                    | UsmFailure::NotInTimeWindows
                    | UsmFailure::DecryptionErrors => Err(Error::Auth { target: source }.boxed()),
                    UsmFailure::UnknownEngineIds
                    | UsmFailure::UnknownUserNames
                    | UsmFailure::UnsupportedSecLevels => Ok(None),
                }
            }
            NotificationProcessResult::RemoteNotInTimeWindow => {
                Err(Error::Auth { target: source }.boxed())
            }
            NotificationProcessResult::Accepted(event) => {
                let ProcessedNotification {
                    notification,
                    receive_info,
                    wire_identity,
                    inform_response,
                } = *event;
                let Some(response) = inform_response else {
                    return Ok(Some(ReceivedNotification::trap(
                        notification,
                        receive_info,
                        wire_identity,
                    )));
                };
                if self.inner.acknowledgement_mode
                    == InformAcknowledgementMode::ApplicationControlled
                {
                    let permit = admission
                        .pending_permit
                        .take()
                        .expect("manual Inform admission reserved outstanding work");
                    let deadline = tokio::time::Instant::now() + self.inner.pending_inform_timeout;
                    let inform_ack = match self
                        .inner
                        .pending
                        .install(response, route, source, permit, deadline)
                    {
                        Ok(pending) => NotificationAcknowledgement::Pending(pending),
                        Err(outcome) => NotificationAcknowledgement::Completed(outcome),
                    };
                    return Ok(Some(ReceivedNotification {
                        notification,
                        receive_info,
                        wire_identity,
                        inform_ack,
                    }));
                }
                let outcome = self
                    .complete_response(response, route, source, None, None)
                    .await;
                Ok(Some(ReceivedNotification::inform(
                    notification,
                    receive_info,
                    wire_identity,
                    outcome,
                )))
            }
        }
    }

    pub(super) async fn complete_response(
        &self,
        response: InformResponse,
        route: crate::transport::ReplyRoute,
        source: std::net::SocketAddr,
        deadline: Option<tokio::time::Instant>,
        cancel: Option<tokio_util::sync::CancellationToken>,
    ) -> InformAckOutcome {
        #[cfg(test)]
        let injected = self
            .inner
            .response_construction_errors
            .lock()
            .unwrap()
            .pop_front();
        #[cfg(not(test))]
        let injected: Option<Box<Error>> = None;
        let encoded = match injected {
            Some(error) => Err(error),
            None => response.encode(),
        };
        if cancel.as_ref().is_some_and(|cancel| cancel.is_cancelled()) {
            return super::pending::failed(
                source,
                std::io::ErrorKind::NotConnected,
                "notification completion cancelled",
            );
        }
        if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
            return super::pending::failed(
                source,
                std::io::ErrorKind::TimedOut,
                "pending Inform expired",
            );
        }
        let (bytes, outcome) = match encoded {
            Ok(EncodedInformResponse::Response(bytes)) => (bytes, InformAckOutcome::Sent),
            Ok(EncodedInformResponse::TooBig(bytes)) => (bytes, InformAckOutcome::SentTooBig),
            Ok(EncodedInformResponse::Suppressed) => return InformAckOutcome::SuppressedBySize,
            Err(error) => return InformAckOutcome::Failed(error),
        };
        let sent = match deadline {
            Some(deadline) => self.send_response_before(bytes, &route, deadline).await,
            None => self.send_response(bytes, &route).await,
        };
        match sent {
            Ok(()) => outcome,
            Err(error) => InformAckOutcome::Failed(
                Error::Network {
                    target: source,
                    source: error,
                }
                .boxed(),
            ),
        }
    }

    #[cfg(test)]
    pub(super) async fn handle_v1(
        &self,
        data: bytes::Bytes,
        source: std::net::SocketAddr,
    ) -> Result<Option<ReceivedNotification>> {
        self.parse_and_respond(
            self.test_message(data, source, None),
            &mut NotificationAdmission::default(),
        )
        .await
    }

    #[cfg(test)]
    pub(super) async fn handle_v2c(
        &self,
        data: bytes::Bytes,
        source: std::net::SocketAddr,
    ) -> Result<Option<ReceivedNotification>> {
        self.handle_v2c_at(data, source, None).await
    }

    #[cfg(test)]
    pub(super) async fn handle_v2c_at(
        &self,
        data: bytes::Bytes,
        source: std::net::SocketAddr,
        destination: Option<crate::udp_responder::DestinationMetadata>,
    ) -> Result<Option<ReceivedNotification>> {
        self.parse_and_respond(
            self.test_message(data, source, destination),
            &mut NotificationAdmission::default(),
        )
        .await
    }

    #[cfg(test)]
    pub(super) async fn handle_v3(
        &self,
        data: bytes::Bytes,
        source: std::net::SocketAddr,
    ) -> Result<Option<ReceivedNotification>> {
        self.handle_v3_at(data, source, None).await
    }

    #[cfg(test)]
    pub(super) async fn handle_v3_at(
        &self,
        data: bytes::Bytes,
        source: std::net::SocketAddr,
        destination: Option<crate::udp_responder::DestinationMetadata>,
    ) -> Result<Option<ReceivedNotification>> {
        self.parse_and_respond(
            self.test_message(data, source, destination),
            &mut NotificationAdmission::default(),
        )
        .await
    }
}
