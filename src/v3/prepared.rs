//! Packet-bound reusable parsing and cryptographic work; never an acceptance token.
use super::{DerivedKeys, UsmSecurityParams};
use crate::ber::Decoder;
use crate::error::internal::DecodeErrorKind;
use crate::message::{DecodeOutcome, RawMsgData, RawV3Message};
use crate::{DecodeConfig, Error, PduType, Result, Version};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use subtle::ConstantTimeEq;

pub(crate) struct PreparedV3 {
    wire: Bytes,
    config: DecodeConfig,
    pub(crate) raw: Option<DecodeOutcome<RawV3Message>>,
    pub(crate) usm: Option<DecodeOutcome<UsmSecurityParams>>,
    pub(crate) crypto: Option<PreparedCrypto>,
    pub(crate) selected_users: Option<Arc<super::security::UsmUsers>>,
    pub(crate) client_conflict: bool,
}
pub(crate) struct PreparedCrypto {
    pub(crate) identity: Arc<()>,
    pub(crate) engine_id: Bytes,
    pub(crate) keys: DerivedKeys,
    pub(crate) plaintext: Option<Bytes>,
    pub(crate) prefix: Option<PduPrefix>,
}

/// The routing and correlation fields recoverable without validating the PDU body.
#[derive(Clone, Copy)]
pub(crate) struct PduPrefix {
    pub(crate) kind: PduType,
    pub(crate) request_id: Option<i32>,
}

impl PduPrefix {
    pub(crate) fn read(data: Bytes, offset: usize, source: SocketAddr) -> Result<Self> {
        // Limit both the scoped sequence and the PDU to their declared TLVs.
        // Context strings and the request-id use strict, bounded decoders under
        // every receive policy. Scope suffixes and varbinds are validated later.
        let mut scoped = Decoder::with_context(data, offset, Some(source)).read_sequence()?;
        scoped.read_octet_string()?;
        scoped.read_octet_string()?;
        let tag = scoped
            .peek_byte()
            .ok_or_else(|| scoped.malformed(DecodeErrorKind::TruncatedData))?;
        let kind = PduType::from_tag(tag)
            .filter(|kind| crate::pdu::pdu_type_valid_for_version(*kind, Version::V3))
            .ok_or_else(|| scoped.malformed(DecodeErrorKind::UnknownPduType(tag)))?;
        let mut pdu = scoped.read_constructed(tag)?;
        let request_id = pdu.read_bounded_integer(i32::MIN, i32::MAX).ok();
        Ok(Self { kind, request_id })
    }
}
impl PreparedV3 {
    #[cfg(all(test, any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
    pub(crate) fn new(
        wire: Bytes,
        config: DecodeConfig,
        raw: DecodeOutcome<RawV3Message>,
        usm: DecodeOutcome<UsmSecurityParams>,
    ) -> Self {
        Self {
            wire,
            config,
            raw: Some(raw),
            usm: Some(usm),
            crypto: None,
            selected_users: None,
            client_conflict: false,
        }
    }

    pub(crate) fn selected(
        wire: Bytes,
        config: DecodeConfig,
        users: Arc<super::security::UsmUsers>,
    ) -> Self {
        Self {
            wire,
            config,
            raw: None,
            usm: None,
            crypto: None,
            selected_users: Some(users),
            client_conflict: false,
        }
    }

    pub(crate) fn matches(&self, wire: &Bytes) -> bool {
        self.wire.as_ptr() == wire.as_ptr() && self.wire.len() == wire.len()
    }
    pub(crate) fn decode_raw(
        &mut self,
        wire: Bytes,
        maximum: usize,
        source: SocketAddr,
        config: DecodeConfig,
    ) -> Result<DecodeOutcome<RawV3Message>> {
        if self.matches(&wire)
            && self.config == config
            && wire.len() <= maximum
            && let Some(raw) = self.raw.take()
        {
            return Ok(raw);
        }
        RawV3Message::decode_bounded_with_target(wire, maximum, source, config)
    }
    pub(crate) fn decode_usm(
        &mut self,
        raw: &RawV3Message,
        source: SocketAddr,
        config: DecodeConfig,
    ) -> Result<DecodeOutcome<UsmSecurityParams>> {
        if self.config == config
            && let Some(usm) = self.usm.take()
        {
            return Ok(usm);
        }
        UsmSecurityParams::decode_with_context(
            raw.security_params.clone(),
            raw.security_params_offset,
            source,
            config,
        )
    }
    pub(crate) fn plaintext_len(&self) -> usize {
        self.crypto
            .as_ref()
            .and_then(|crypto| crypto.plaintext.as_ref())
            .map_or(0, Bytes::len)
    }
}
impl PreparedCrypto {
    /// Verify and decrypt for routing without committing USM state or counters.
    pub(crate) fn authenticate_and_decrypt(
        bytes: &Bytes,
        authenticated_data: &[u8],
        raw: &RawV3Message,
        usm: &UsmSecurityParams,
        keys: DerivedKeys,
        identity: Arc<()>,
        source: SocketAddr,
    ) -> Result<(Self, Result<PduPrefix>)> {
        let auth_error = || Error::Auth { target: source }.boxed();
        let auth_key = keys.auth_key.as_ref().ok_or_else(auth_error)?;
        let priv_key = keys.priv_key.as_ref().ok_or_else(auth_error)?;
        let (offset, length) =
            UsmSecurityParams::find_auth_params_offset(bytes).ok_or_else(auth_error)?;
        if !raw.security_level().requires_auth()
            || !super::auth::verify_message(auth_key, authenticated_data, offset, length)
                .map_err(|_| auth_error())?
        {
            return Err(auth_error());
        }
        let RawMsgData::Encrypted(ciphertext) = &raw.msg_data else {
            unreachable!("encrypted classification requires an encrypted scoped PDU")
        };
        let (plaintext, prefix) = match priv_key.decrypt(
            ciphertext,
            usm.engine_boots,
            usm.engine_time,
            &usm.priv_params,
        ) {
            Ok(plaintext) => {
                let prefix = PduPrefix::read(plaintext.clone(), 0, source);
                (Some(plaintext), prefix)
            }
            Err(_) => (None, Err(auth_error())),
        };
        let crypto = Self {
            identity,
            engine_id: usm.engine_id.clone(),
            keys,
            plaintext,
            prefix: prefix.as_ref().ok().copied(),
        };
        Ok((crypto, prefix))
    }

    pub(crate) fn matches_user(&self, user: &super::UsmUser, engine_id: &Bytes) -> bool {
        self.engine_id == *engine_id && Arc::ptr_eq(&self.identity, &user.credential_identity())
    }

    pub(crate) fn matches_keys(&self, keys: &DerivedKeys, engine_id: &Bytes) -> bool {
        if self.engine_id != *engine_id {
            return false;
        }
        let auth = match (&self.keys.auth_key, &keys.auth_key) {
            (Some(a), Some(b)) => {
                a.protocol() == b.protocol()
                    && a.crypto_backend() == b.crypto_backend()
                    && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
            }
            (None, None) => true,
            _ => false,
        };
        let privacy = match (&self.keys.priv_key, &keys.priv_key) {
            (Some(a), Some(b)) => {
                a.protocol() == b.protocol()
                    && a.crypto_backend() == b.crypto_backend()
                    && bool::from(a.key_material().ct_eq(b.key_material()))
            }
            (None, None) => true,
            _ => false,
        };
        auth && privacy
    }
}

#[cfg(test)]
pub(crate) mod test_counts {
    use std::cell::Cell;
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(crate) struct Counts {
        pub raw: usize,
        pub usm: usize,
        pub auth: usize,
        pub decrypt: usize,
    }
    thread_local! { static COUNTS: Cell<Option<Counts>> = const { Cell::new(None) }; }
    pub(crate) fn record(update: impl FnOnce(&mut Counts)) {
        COUNTS.with(|slot| {
            if let Some(mut counts) = slot.get() {
                update(&mut counts);
                slot.set(Some(counts));
            }
        });
    }
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    pub(crate) fn measure<T>(work: impl FnOnce() -> T) -> (T, Counts) {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                COUNTS.with(|slot| slot.set(None));
            }
        }
        let _reset = Reset;
        COUNTS.with(|slot| slot.set(Some(Counts::default())));
        let value = work();
        (value, COUNTS.with(|slot| slot.get().unwrap()))
    }
}
