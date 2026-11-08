//! Managed notification admission, automatic response sending and delivery.

use super::{
    EncodedInformResponse, InformAckOutcome, NotificationAdmission, NotificationProcessResult,
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
        let result = self
            .inner
            .protocol
            .process_admitted(input, &mut || admission.reserve(&self.inner.delivery))?;
        match result {
            NotificationProcessResult::Rejected => Ok(None),
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
                let outcome = match encoded {
                    Ok(EncodedInformResponse::Suppressed) => InformAckOutcome::SuppressedBySize,
                    Ok(
                        EncodedInformResponse::Response(bytes)
                        | EncodedInformResponse::TooBig(bytes),
                    ) => match self.send_response(bytes, &route).await {
                        Ok(()) => InformAckOutcome::Sent,
                        Err(error) => InformAckOutcome::Failed(
                            Error::Network {
                                target: source,
                                source: error,
                            }
                            .boxed(),
                        ),
                    },
                    Err(error) => InformAckOutcome::Failed(error),
                };
                Ok(Some(ReceivedNotification::inform(
                    notification,
                    receive_info,
                    wire_identity,
                    outcome,
                )))
            }
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
