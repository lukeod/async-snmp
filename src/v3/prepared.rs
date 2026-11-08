//! Packet-bound reusable parsing and cryptographic work; never an acceptance token.
use super::{DerivedKeys, UsmSecurityParams};
use crate::message::{DecodeOutcome, RawV3Message};
use crate::{DecodeConfig, Result};
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
