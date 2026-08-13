//! Crate-internal request fixtures.

use std::net::{Ipv4Addr, SocketAddr};

use bytes::Bytes;

use crate::handler::RequestContext;
use crate::{Community, CommunityVersion, PduType, SecurityLevel, Version};

const TEST_MSG_MAX_SIZE: usize = 65_507;

pub(crate) fn request_context(pdu_type: PduType) -> RequestContext {
    community_request_context(CommunityVersion::V2c, pdu_type)
}

pub(crate) fn request_context_for_version(version: Version, pdu_type: PduType) -> RequestContext {
    match version {
        Version::V1 => community_request_context(CommunityVersion::V1, pdu_type),
        Version::V2c => community_request_context(CommunityVersion::V2c, pdu_type),
        Version::V3 => usm_request_context(SecurityLevel::NoAuthNoPriv, pdu_type),
    }
}

pub(crate) fn community_request_context(
    version: CommunityVersion,
    pdu_type: PduType,
) -> RequestContext {
    community_request_context_with(
        version,
        Community::from("public"),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 12_345)),
        1,
        pdu_type,
    )
}

pub(crate) fn community_request_context_with(
    version: CommunityVersion,
    community: Community,
    source: SocketAddr,
    request_id: i32,
    pdu_type: PduType,
) -> RequestContext {
    RequestContext::community(source, version, community, request_id, pdu_type)
}

pub(crate) fn usm_request_context(
    security_level: SecurityLevel,
    pdu_type: PduType,
) -> RequestContext {
    usm_request_context_with(
        Bytes::from_static(b"user"),
        security_level,
        Bytes::new(),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 12_345)),
        1,
        pdu_type,
        TEST_MSG_MAX_SIZE,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn usm_request_context_with(
    username: Bytes,
    security_level: SecurityLevel,
    context_name: Bytes,
    source: SocketAddr,
    request_id: i32,
    pdu_type: PduType,
    msg_max_size: usize,
) -> RequestContext {
    RequestContext::usm(
        source,
        username,
        security_level,
        context_name,
        request_id,
        pdu_type,
        msg_max_size,
    )
}

pub(crate) fn with_vacm_views(
    mut context: RequestContext,
    read_view: impl Into<Bytes>,
    write_view: impl Into<Bytes>,
) -> RequestContext {
    context.set_vacm_access(
        Bytes::from_static(b"test-group"),
        read_view.into(),
        write_view.into(),
    );
    context
}
