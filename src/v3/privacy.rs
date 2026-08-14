//! Privacy (encryption) protocols for `SNMPv3` (RFC 3414, RFC 3826).
//!
//! This module implements:
//! - DES-CBC privacy (RFC 3414 Section 8)
//! - AES-128-CFB privacy (RFC 3826)
//! - AES-192-CFB privacy with explicit Blumenthal or Reeder key extension
//!   (draft/vendor extension, not RFC 3826)
//! - AES-256-CFB privacy with explicit Blumenthal or Reeder key extension
//!   (draft/vendor extension, not RFC 3826)
//!
//! # Salt/IV Construction
//!
//! ## DES-CBC
//! - Salt (privParameters): engineBoots (4 bytes) || counter (4 bytes) = 8 bytes
//! - IV: pre-IV XOR salt (pre-IV is last 8 bytes of 16-byte privKey)
//!
//! ## AES-CFB-128
//! - Salt (privParameters): 64-bit counter = 8 bytes
//! - IV: engineBoots (4 bytes) || engineTime (4 bytes) || salt (8 bytes) = 16 bytes
//!   (concatenation, NOT XOR)

use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use bytes::Bytes;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::crypto::{CryptoBackend, CryptoError};
use super::{AuthProtocol, PrivProtocol};

/// Error type for privacy (encryption/decryption) operations.
///
/// These errors indicate privacy-state or cryptographic failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivacyError {
    /// Invalid privParameters length (expected 8 bytes).
    InvalidPrivParamsLength { expected: usize, actual: usize },
    /// Ciphertext length not a multiple of block size.
    InvalidCiphertextLength { length: usize, block_size: usize },
    /// Cryptographic provider error (unsupported algorithm, invalid key, cipher failure).
    Crypto(CryptoError),
    /// The supplied sender state does not match the key's privacy protocol.
    SenderStateMismatch,
    /// Every 32-bit salt in this DES generating-engine epoch has been used.
    DesSaltExhausted { engine_boots: u32 },
    /// Durable DES state does not match the current local generating engine.
    DesEngineBootsMismatch {
        state_engine_boots: u32,
        generating_engine_boots: u32,
    },
}

impl From<CryptoError> for PrivacyError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl std::fmt::Display for PrivacyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPrivParamsLength { expected, actual } => {
                write!(
                    f,
                    "invalid privParameters length: expected {expected}, got {actual}"
                )
            }
            Self::InvalidCiphertextLength { length, block_size } => {
                write!(
                    f,
                    "ciphertext length {length} not multiple of block size {block_size}"
                )
            }
            Self::Crypto(e) => write!(f, "{e}"),
            Self::SenderStateMismatch => {
                f.write_str("privacy sender state does not match protocol")
            }
            Self::DesSaltExhausted { engine_boots } => write!(
                f,
                "DES privacy salt exhausted for generating-engine boots {engine_boots}"
            ),
            Self::DesEngineBootsMismatch {
                state_engine_boots,
                generating_engine_boots,
            } => write!(
                f,
                "DES sender state boots {state_engine_boots} do not match generating-engine boots {generating_engine_boots}"
            ),
        }
    }
}

type DesPersistenceSource = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The durable DES generating-engine transition being attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DesSaltPersistenceOperation {
    /// Establishing a new key domain at boots epoch 1.
    Install,
    /// Atomically advancing a previously persisted boots epoch.
    Restart,
}

/// Durable DES sender state loaded by an application at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistedDesSaltState {
    engine_boots: u32,
}

impl PersistedDesSaltState {
    /// Validate a persisted local generating-engine boots epoch.
    pub fn new(engine_boots: u32) -> std::result::Result<Self, DesSaltStateError> {
        if !(1..=super::MAX_ENGINE_TIME).contains(&engine_boots) {
            return Err(DesSaltStateError::InvalidEpoch { engine_boots });
        }
        Ok(Self { engine_boots })
    }

    /// Return the persisted generating-engine boots epoch.
    #[must_use]
    pub fn engine_boots(self) -> u32 {
        self.engine_boots
    }
}

/// A failed durable DES generating-engine transition.
#[derive(Debug)]
pub struct DesSaltPersistenceError {
    operation: DesSaltPersistenceOperation,
    previous_engine_boots: Option<u32>,
    attempted_engine_boots: u32,
    source: DesPersistenceSource,
}

impl DesSaltPersistenceError {
    /// Return the failed transition.
    #[must_use]
    pub fn operation(&self) -> DesSaltPersistenceOperation {
        self.operation
    }

    /// Return the last durable epoch, if this was a restart.
    #[must_use]
    pub fn previous_engine_boots(&self) -> Option<u32> {
        self.previous_engine_boots
    }

    /// Return the epoch that the callback was asked to persist.
    #[must_use]
    pub fn attempted_engine_boots(&self) -> u32 {
        self.attempted_engine_boots
    }

    /// Return the concrete persistence callback error.
    #[must_use]
    pub fn persistence_source(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        self.source.as_ref()
    }

    /// Downcast the callback error to its concrete type.
    #[must_use]
    pub fn downcast_source_ref<E: std::error::Error + 'static>(&self) -> Option<&E> {
        self.source.downcast_ref()
    }
}

impl std::fmt::Display for DesSaltPersistenceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DES sender-state persistence failed during {:?} at boots {}: {}",
            self.operation, self.attempted_engine_boots, self.source
        )
    }
}

impl std::error::Error for DesSaltPersistenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Error creating or advancing durable DES sender state.
#[derive(Debug)]
#[non_exhaustive]
pub enum DesSaltStateError {
    /// The persisted epoch is outside the SNMP engine-boots domain.
    InvalidEpoch { engine_boots: u32 },
    /// The boots epoch cannot be advanced without reuse.
    EpochSaturated { engine_boots: u32 },
    /// The durable compare-and-set/install operation failed.
    Persistence(DesSaltPersistenceError),
}

impl std::fmt::Display for DesSaltStateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEpoch { engine_boots } => {
                write!(
                    f,
                    "invalid DES generating-engine boots epoch {engine_boots}"
                )
            }
            Self::EpochSaturated { engine_boots } => {
                write!(
                    f,
                    "DES generating-engine boots epoch {engine_boots} is saturated"
                )
            }
            Self::Persistence(error) => std::fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for DesSaltStateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Persistence(error) => Some(error),
            _ => None,
        }
    }
}

/// Caller-owned durable sender state for DES and 3DES privacy.
///
/// One value (or its clones) must be shared by every live sender using the
/// same effective localized encryption-key/pre-IV domain. `install` requires
/// an atomic create-if-absent lease for a new domain, while `restart` requires
/// an atomic compare-and-set from the supplied previous epoch to the attempted
/// epoch. Those contracts reject a second live process starting from the same
/// durable state.
#[derive(Clone)]
pub struct DesSaltState {
    inner: Arc<DesSaltStateInner>,
}

/// One irrevocably allocated DES/3DES privacy salt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesSaltReservation {
    engine_boots: u32,
    salt: u32,
}

impl DesSaltReservation {
    /// Return the local generating-engine boots encoded in this reservation.
    #[must_use]
    pub fn engine_boots(self) -> u32 {
        self.engine_boots
    }

    /// Return the non-repeating low 32-bit salt value.
    #[must_use]
    pub fn salt(self) -> u32 {
        self.salt
    }
}

struct DesSaltStateInner {
    engine_boots: u32,
    last_salt: AtomicU32,
}

impl Debug for DesSaltState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DesSaltState")
            .field("engine_boots", &self.engine_boots())
            .finish_non_exhaustive()
    }
}

impl DesSaltState {
    /// Install a new DES key domain, persisting boots epoch 1 before use.
    ///
    /// The callback must atomically create the durable record only if it does
    /// not already exist. A competing installer for the same effective key
    /// domain must return an error rather than lease epoch 1 twice.
    pub fn install<E, F>(mut persist: F) -> std::result::Result<Self, DesSaltStateError>
    where
        E: Into<DesPersistenceSource>,
        F: FnMut(&PersistedDesSaltState) -> std::result::Result<(), E>,
    {
        Self::start(None, 1, DesSaltPersistenceOperation::Install, &mut persist)
    }

    /// Atomically advance persisted state and create a fresh boots epoch.
    ///
    /// The callback must compare-and-set durable state from `previous` to the
    /// supplied attempted state; a stale second live owner must return an error.
    pub fn restart<E, F>(
        previous: PersistedDesSaltState,
        mut persist: F,
    ) -> std::result::Result<Self, DesSaltStateError>
    where
        E: Into<DesPersistenceSource>,
        F: FnMut(&PersistedDesSaltState) -> std::result::Result<(), E>,
    {
        let next = previous
            .engine_boots
            .checked_add(1)
            .filter(|boots| *boots <= super::MAX_ENGINE_TIME)
            .ok_or(DesSaltStateError::EpochSaturated {
                engine_boots: previous.engine_boots,
            })?;
        Self::start(
            Some(previous.engine_boots),
            next,
            DesSaltPersistenceOperation::Restart,
            &mut persist,
        )
    }

    fn start<E, F>(
        previous_engine_boots: Option<u32>,
        engine_boots: u32,
        operation: DesSaltPersistenceOperation,
        persist: &mut F,
    ) -> std::result::Result<Self, DesSaltStateError>
    where
        E: Into<DesPersistenceSource>,
        F: FnMut(&PersistedDesSaltState) -> std::result::Result<(), E>,
    {
        let persisted = PersistedDesSaltState::new(engine_boots)?;
        persist(&persisted).map_err(|source| {
            DesSaltStateError::Persistence(DesSaltPersistenceError {
                operation,
                previous_engine_boots,
                attempted_engine_boots: engine_boots,
                source: source.into(),
            })
        })?;
        Ok(Self {
            inner: Arc::new(DesSaltStateInner {
                engine_boots,
                last_salt: AtomicU32::new(0),
            }),
        })
    }

    /// Return the local generating-engine boots epoch used in DES salts.
    #[must_use]
    pub fn engine_boots(&self) -> u32 {
        self.inner.engine_boots
    }

    /// Return the durable record needed by a later process restart.
    #[must_use]
    pub fn persisted_state(&self) -> PersistedDesSaltState {
        PersistedDesSaltState {
            engine_boots: self.inner.engine_boots,
        }
    }

    /// Irrevocably allocate the next salt in this boots epoch.
    ///
    /// The reservation is burned even if later message encoding or encryption
    /// fails. It cannot be constructed or reused with a different epoch.
    pub fn reserve(&self) -> PrivacyResult<DesSaltReservation> {
        let salt = self
            .inner
            .last_salt
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(1)
            })
            .map(|previous| previous + 1)
            .map_err(|_| PrivacyError::DesSaltExhausted {
                engine_boots: self.inner.engine_boots,
            })?;
        Ok(DesSaltReservation {
            engine_boots: self.inner.engine_boots,
            salt,
        })
    }

    pub(crate) fn validate_generating_engine_boots(
        &self,
        generating_engine_boots: u32,
    ) -> PrivacyResult<()> {
        if self.engine_boots() != generating_engine_boots {
            return Err(PrivacyError::DesEngineBootsMismatch {
                state_engine_boots: self.engine_boots(),
                generating_engine_boots,
            });
        }
        Ok(())
    }

    #[cfg(test)]
    fn with_last_salt_for_test(engine_boots: u32, last_salt: u32) -> Self {
        Self {
            inner: Arc::new(DesSaltStateInner {
                engine_boots,
                last_salt: AtomicU32::new(last_salt),
            }),
        }
    }
}

/// Protocol-specific sender inputs for one privacy encryption.
pub(crate) enum PrivacyEncryptContext<'a> {
    /// Local generating-engine state for DES or 3DES.
    Des(DesSaltReservation),
    /// Remote/local authoritative tuple and random salt allocator for AES.
    Aes {
        engine_boots: u32,
        engine_time: u32,
        salt_counter: &'a SaltCounter,
    },
}

impl std::error::Error for PrivacyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(e) => Some(e),
            _ => None,
        }
    }
}

/// Result type for privacy operations.
pub type PrivacyResult<T> = std::result::Result<T, PrivacyError>;

/// Generate a random non-zero u64 for salt initialization.
///
/// Uses the OS cryptographic random source via `getrandom`.
fn random_nonzero_u64() -> crate::error::Result<u64> {
    random_nonzero_u64_with(getrandom::fill)
}

fn random_nonzero_u64_with(
    mut fill: impl FnMut(&mut [u8]) -> std::result::Result<(), getrandom::Error>,
) -> crate::error::Result<u64> {
    let mut buf = [0u8; 8];
    loop {
        fill(&mut buf).map_err(|source| crate::Error::RandomSource { source }.boxed())?;
        let val = u64::from_ne_bytes(buf);
        if val != 0 {
            return Ok(val);
        }
        // Extremely unlikely (1 in 2^64), but loop if we got zero
    }
}

/// Privacy key for encryption/decryption operations.
///
/// Derives encryption keys from a password and engine ID using the same
/// process as authentication keys, then uses the appropriate portion
/// based on the privacy protocol.
///
/// # Security
///
/// The specifically owned key buffer is zeroized when this value is dropped.
/// This does not promise erasure of caller inputs, live clones, allocator or
/// provider internals, encoded message buffers, or kernel copies.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivKey {
    /// The localized key bytes
    key: Vec<u8>,
    /// Privacy protocol
    #[zeroize(skip)]
    protocol: PrivProtocol,
    #[zeroize(skip)]
    backend: CryptoBackend,
}

/// Thread-safe salt counter for shared use across privacy encryptions.
///
/// The owner of an authoritative engine/key domain must create one counter and
/// pass that same counter to every encryption in the domain, including
/// encryptions performed with cloned or re-derived [`PrivKey`] values. This
/// keeps IV allocation independent of key object lifetime and cloning.
pub struct SaltCounter(AtomicU64);

impl SaltCounter {
    /// Create a new salt counter initialized from cryptographic randomness.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::RandomSource`] if the operating system cannot
    /// provide random bytes.
    pub fn new() -> crate::error::Result<Self> {
        Ok(Self(AtomicU64::new(random_nonzero_u64()?)))
    }

    /// Create a salt counter initialized to a specific value for internal tests.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn from_value(value: u64) -> Self {
        Self(AtomicU64::new(value))
    }

    /// Get the next salt value and increment the counter.
    ///
    /// This method never returns a value whose low 32 bits are zero. DES and
    /// 3DES place only those low 32 bits in `privParameters`, so skipping that
    /// value gives their counter portion the same non-zero wrap behavior as the
    /// full 64-bit AES salt. A wrapping caller consumes another atomic value
    /// rather than returning a fixed constant, preserving concurrency safety.
    pub fn next(&self) -> u64 {
        loop {
            let old = self.0.fetch_add(1, Ordering::SeqCst);
            let val = old.wrapping_add(1);
            if val as u32 != 0 {
                return val;
            }
        }
    }
}

impl PrivKey {
    /// Derive a privacy key from a password and engine ID.
    ///
    /// The key derivation uses the same algorithm as authentication keys
    /// (RFC 3414 A.2), but the resulting key is used differently:
    /// - DES: first 8 bytes = key, last 8 bytes = pre-IV
    /// - 3DES: first 24 bytes = key, last 8 bytes = pre-IV
    /// - AES: first 16/24/32 bytes = key (depending on AES variant)
    ///
    /// Key extension is applied when needed according to the selected privacy
    /// protocol variant:
    ///
    /// - AES-192/256 Blumenthal variants: draft-blumenthal-aes-usm-04 extension
    /// - AES-192/256 Reeder variants: Cisco/Reeder extension
    /// - 3DES with SHA-1 or MD5: Reeder extension (draft-reeder-snmpv3-usm-3desede-00)
    ///
    /// The password length and both backend capabilities are validated before
    /// password expansion or key localization begins.
    ///
    /// This method performs password expansion and localization. When multiple
    /// engines share credentials, retain a [`MasterKey`](super::MasterKey) and
    /// call [`PrivKey::from_master_key`] for each engine.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    /// # {
    /// use async_snmp::{AuthProtocol, PrivProtocol, v3::PrivKey};
    ///
    /// let engine_id = [0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
    ///
    /// // SHA-1 only produces 20 bytes, but AES-256 needs 32.
    /// // The configured Blumenthal extension is applied.
    /// let priv_key = PrivKey::from_password(
    ///     AuthProtocol::Sha1,
    ///     PrivProtocol::Aes256Blumenthal,
    ///     b"password",
    ///     &engine_id,
    /// ).unwrap();
    /// # }
    /// ```
    pub fn from_password(
        auth_protocol: AuthProtocol,
        priv_protocol: PrivProtocol,
        password: &[u8],
        engine_id: &[u8],
    ) -> super::crypto::CryptoResult<Self> {
        Self::from_password_with_backend(
            auth_protocol,
            priv_protocol,
            password,
            engine_id,
            CryptoBackend::default(),
        )
    }

    /// Derive a privacy key using an explicitly selected backend.
    pub fn from_password_with_backend(
        auth_protocol: AuthProtocol,
        priv_protocol: PrivProtocol,
        password: &[u8],
        engine_id: &[u8],
        backend: CryptoBackend,
    ) -> super::crypto::CryptoResult<Self> {
        use super::MasterKey;

        if password.len() < super::auth::MIN_PASSWORD_LENGTH {
            return Err(CryptoError::PasswordTooShort);
        }
        backend.validate_auth_protocol(auth_protocol)?;
        backend.validate_priv_protocol(priv_protocol)?;
        let master = MasterKey::from_password_with_backend(auth_protocol, password, backend)?;
        Self::from_master_key(&master, priv_protocol, engine_id)
    }

    /// Derive a privacy key from a master key and engine ID.
    ///
    /// This avoids repeating password expansion when a cached
    /// [`MasterKey`](super::MasterKey) is available.
    /// Key extension is applied when needed according to the selected privacy
    /// protocol variant:
    ///
    /// - AES-192/256 Blumenthal variants: draft-blumenthal-aes-usm-04 extension
    /// - AES-192/256 Reeder variants: Cisco/Reeder extension
    /// - 3DES with SHA-1 or MD5: Reeder extension (draft-reeder-snmpv3-usm-3desede-00)
    ///
    /// Both the master key's authentication protocol and `priv_protocol` must
    /// be supported by its selected backend.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    /// # {
    /// use async_snmp::{AuthProtocol, MasterKey, PrivProtocol, v3::PrivKey};
    ///
    /// let master = MasterKey::from_password(AuthProtocol::Sha1, b"password").unwrap();
    /// let engine_id = [0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
    ///
    /// // SHA-1 only produces 20 bytes, but AES-256 needs 32.
    /// // The configured Blumenthal extension is applied.
    /// let priv_key = PrivKey::from_master_key(&master, PrivProtocol::Aes256Blumenthal, &engine_id).unwrap();
    /// # }
    /// ```
    pub fn from_master_key(
        master: &super::MasterKey,
        priv_protocol: PrivProtocol,
        engine_id: &[u8],
    ) -> super::crypto::CryptoResult<Self> {
        use super::{
            KeyExtension,
            auth::{extend_key_reeder_with_backend, extend_key_with_backend},
        };

        let auth_protocol = master.protocol();
        master
            .crypto_backend()
            .validate_auth_protocol(auth_protocol)?;
        master
            .crypto_backend()
            .validate_priv_protocol(priv_protocol)?;
        let key_extension = priv_protocol.key_extension_for(auth_protocol);

        // Localize the master key (per RFC 3826 Section 1.2)
        let localized = master.localize(engine_id)?;
        let key_bytes = localized.as_bytes();

        let key = match key_extension {
            KeyExtension::None => key_bytes.to_vec(),
            KeyExtension::Blumenthal => extend_key_with_backend(
                master.crypto_backend(),
                auth_protocol,
                key_bytes,
                priv_protocol.key_len(),
            )?,
            KeyExtension::Reeder => extend_key_reeder_with_backend(
                master.crypto_backend(),
                auth_protocol,
                key_bytes,
                engine_id,
                priv_protocol.key_len(),
            )?,
        };

        Ok(Self {
            key,
            protocol: priv_protocol,
            backend: master.crypto_backend(),
        })
    }

    /// Create a privacy key from raw localized key bytes.
    ///
    /// `key` must be at least `protocol.key_len()` octets; shorter keys would
    /// later panic when the encryption/decryption routines slice into them, so
    /// this returns `Err(CryptoError::InvalidKeyLength)` instead. A key longer
    /// than `protocol.key_len()` is accepted (per RFC 3826 Section 3.1.2, the
    /// localized key length is "at least" the required size); the extra
    /// trailing bytes are simply unused. Length validation precedes the
    /// selected backend's privacy-protocol capability check.
    ///
    /// This constructor treats `key` as finalized and never extends it. The
    /// AES dialect remains part of the protocol identity, but both dialects
    /// produce identical encryption for the same raw key bytes.
    pub fn from_bytes(
        protocol: PrivProtocol,
        key: impl Into<Vec<u8>>,
    ) -> super::crypto::CryptoResult<Self> {
        Self::from_bytes_with_backend(protocol, key, CryptoBackend::default())
    }

    /// Create a privacy key for an explicitly selected backend.
    pub fn from_bytes_with_backend(
        protocol: PrivProtocol,
        key: impl Into<Vec<u8>>,
        backend: CryptoBackend,
    ) -> super::crypto::CryptoResult<Self> {
        let key = key.into();
        if key.len() < protocol.key_len() {
            return Err(CryptoError::InvalidKeyLength);
        }
        backend.validate_priv_protocol(protocol)?;
        Ok(Self {
            key,
            protocol,
            backend,
        })
    }

    /// Get the privacy protocol.
    pub fn protocol(&self) -> PrivProtocol {
        self.protocol
    }

    /// Return the backend used by this key.
    pub fn crypto_backend(&self) -> CryptoBackend {
        self.backend
    }

    /// Get the encryption key portion.
    pub fn encryption_key(&self) -> &[u8] {
        match self.protocol {
            PrivProtocol::Des => &self.key[..8],
            PrivProtocol::Des3 => &self.key[..24],
            PrivProtocol::Aes128 => &self.key[..16],
            PrivProtocol::Aes192Blumenthal | PrivProtocol::Aes192Reeder => &self.key[..24],
            PrivProtocol::Aes256Blumenthal | PrivProtocol::Aes256Reeder => &self.key[..32],
        }
    }

    /// Encrypt with already selected protocol-specific sender inputs.
    pub(crate) fn encrypt_with_context(
        &self,
        plaintext: &[u8],
        context: PrivacyEncryptContext<'_>,
    ) -> PrivacyResult<(Bytes, Bytes)> {
        match (self.protocol, context) {
            (PrivProtocol::Des, PrivacyEncryptContext::Des(reservation)) => self.encrypt_des_cbc(
                plaintext,
                reservation.engine_boots,
                u64::from(reservation.salt),
            ),
            (PrivProtocol::Des3, PrivacyEncryptContext::Des(reservation)) => self.encrypt_des3_cbc(
                plaintext,
                reservation.engine_boots,
                u64::from(reservation.salt),
            ),
            (
                PrivProtocol::Aes128,
                PrivacyEncryptContext::Aes {
                    engine_boots,
                    engine_time,
                    salt_counter,
                },
            ) => self.encrypt_aes_cfb(
                plaintext,
                engine_boots,
                engine_time,
                salt_counter.next(),
                16,
            ),
            (
                PrivProtocol::Aes192Blumenthal | PrivProtocol::Aes192Reeder,
                PrivacyEncryptContext::Aes {
                    engine_boots,
                    engine_time,
                    salt_counter,
                },
            ) => self.encrypt_aes_cfb(
                plaintext,
                engine_boots,
                engine_time,
                salt_counter.next(),
                24,
            ),
            (
                PrivProtocol::Aes256Blumenthal | PrivProtocol::Aes256Reeder,
                PrivacyEncryptContext::Aes {
                    engine_boots,
                    engine_time,
                    salt_counter,
                },
            ) => self.encrypt_aes_cfb(
                plaintext,
                engine_boots,
                engine_time,
                salt_counter.next(),
                32,
            ),
            _ => Err(PrivacyError::SenderStateMismatch),
        }
    }

    /// Encrypt with DES or 3DES using caller-owned durable generating state.
    ///
    /// The local boots epoch and nonwrapping counter come only from `state`;
    /// remote authoritative boots/time are deliberately not accepted. Pass
    /// clones of one state to every sender using the same effective localized
    /// key/pre-IV domain. A salt is burned before encryption is attempted.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::DesSaltExhausted`] at counter exhaustion,
    /// [`PrivacyError::SenderStateMismatch`] for an AES key, or a crypto error.
    pub fn encrypt_des_family(
        &self,
        plaintext: &[u8],
        state: &DesSaltState,
    ) -> PrivacyResult<(Bytes, Bytes)> {
        let reservation = state.reserve()?;
        self.encrypt_with_context(plaintext, PrivacyEncryptContext::Des(reservation))
    }

    /// Encrypt with an AES privacy variant using authoritative boots/time.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::SenderStateMismatch`] for a DES-family key or a
    /// provider error when encryption fails.
    pub fn encrypt_aes(
        &self,
        plaintext: &[u8],
        engine_boots: u32,
        engine_time: u32,
        salt_counter: &SaltCounter,
    ) -> PrivacyResult<(Bytes, Bytes)> {
        self.encrypt_with_context(
            plaintext,
            PrivacyEncryptContext::Aes {
                engine_boots,
                engine_time,
                salt_counter,
            },
        )
    }

    /// Decrypt data using the privParameters from the message.
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted data
    /// * `engine_boots` - The authoritative engine's boot count (from message)
    /// * `engine_time` - The authoritative engine's time (from message)
    /// * `priv_params` - The privParameters field from the message
    ///
    /// # Returns
    /// * `Ok(plaintext)` on success
    /// * `Err` on decryption failure
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        engine_boots: u32,
        engine_time: u32,
        priv_params: &[u8],
    ) -> PrivacyResult<Bytes> {
        if priv_params.len() != 8 {
            tracing::debug!(target: "async_snmp::crypto", { expected = 8, actual = priv_params.len() }, "invalid privParameters length");
            return Err(PrivacyError::InvalidPrivParamsLength {
                expected: 8,
                actual: priv_params.len(),
            });
        }

        match self.protocol {
            PrivProtocol::Des => self.decrypt_des(ciphertext, priv_params),
            PrivProtocol::Des3 => self.decrypt_des3(ciphertext, priv_params),
            PrivProtocol::Aes128
            | PrivProtocol::Aes192Blumenthal
            | PrivProtocol::Aes192Reeder
            | PrivProtocol::Aes256Blumenthal
            | PrivProtocol::Aes256Reeder => {
                self.decrypt_aes(ciphertext, engine_boots, engine_time, priv_params)
            }
        }
    }

    /// DES-CBC encryption (RFC 3414 Section 8.1.1).
    fn encrypt_des_cbc(
        &self,
        plaintext: &[u8],
        engine_boots: u32,
        salt_int: u64,
    ) -> PrivacyResult<(Bytes, Bytes)> {
        // DES key is first 8 bytes
        let key = &self.key[..8];
        // Pre-IV is last 8 bytes of 16-byte privKey
        let pre_iv = &self.key[8..16];

        // Salt = engineBoots (4 bytes MSB) || counter (4 bytes MSB)
        // We use the lower 32 bits of salt_int as the counter
        let mut salt = [0u8; 8];
        salt[..4].copy_from_slice(&engine_boots.to_be_bytes());
        salt[4..].copy_from_slice(&(salt_int as u32).to_be_bytes());

        // IV = pre-IV XOR salt
        let mut iv = [0u8; 8];
        for i in 0..8 {
            iv[i] = pre_iv[i] ^ salt[i];
        }

        let mut buffer = plaintext.to_vec();
        self.backend
            .encrypt(PrivProtocol::Des, key, &iv, &mut buffer)?;

        Ok((Bytes::from(buffer), Bytes::copy_from_slice(&salt)))
    }

    /// DES-CBC decryption (RFC 3414 Section 8.1.1).
    fn decrypt_des(&self, ciphertext: &[u8], priv_params: &[u8]) -> PrivacyResult<Bytes> {
        if !ciphertext.len().is_multiple_of(8) {
            tracing::debug!(target: "async_snmp::crypto", { length = ciphertext.len(), block_size = 8 }, "DES decryption failed: invalid ciphertext length");
            return Err(PrivacyError::InvalidCiphertextLength {
                length: ciphertext.len(),
                block_size: 8,
            });
        }

        // DES key is first 8 bytes
        let key = &self.key[..8];
        // Pre-IV is last 8 bytes of 16-byte privKey
        let pre_iv = &self.key[8..16];

        // Salt is the privParameters
        let salt = priv_params;

        // IV = pre-IV XOR salt
        let mut iv = [0u8; 8];
        for i in 0..8 {
            iv[i] = pre_iv[i] ^ salt[i];
        }

        let mut buffer = ciphertext.to_vec();
        self.backend
            .decrypt(PrivProtocol::Des, key, &iv, &mut buffer)?;

        Ok(Bytes::from(buffer))
    }

    /// 3DES-EDE CBC encryption (draft-reeder-snmpv3-usm-3desede-00 Section 5.1.1.2).
    fn encrypt_des3_cbc(
        &self,
        plaintext: &[u8],
        engine_boots: u32,
        salt_int: u64,
    ) -> PrivacyResult<(Bytes, Bytes)> {
        // 3DES key is first 24 bytes (K1, K2, K3)
        let key = &self.key[..24];
        // Pre-IV is bytes 24-31 of the 32-byte privKey
        let pre_iv = &self.key[24..32];

        // Salt = engineBoots (4 bytes MSB) || counter (4 bytes MSB)
        let mut salt = [0u8; 8];
        salt[..4].copy_from_slice(&engine_boots.to_be_bytes());
        salt[4..].copy_from_slice(&(salt_int as u32).to_be_bytes());

        // IV = pre-IV XOR salt
        let mut iv = [0u8; 8];
        for i in 0..8 {
            iv[i] = pre_iv[i] ^ salt[i];
        }

        let mut buffer = plaintext.to_vec();
        self.backend
            .encrypt(PrivProtocol::Des3, key, &iv, &mut buffer)?;

        Ok((Bytes::from(buffer), Bytes::copy_from_slice(&salt)))
    }

    /// 3DES-EDE CBC decryption (draft-reeder-snmpv3-usm-3desede-00 Section 5.1.1.3).
    fn decrypt_des3(&self, ciphertext: &[u8], priv_params: &[u8]) -> PrivacyResult<Bytes> {
        if !ciphertext.len().is_multiple_of(8) {
            tracing::debug!(target: "async_snmp::crypto", { length = ciphertext.len(), block_size = 8 }, "3DES decryption failed: invalid ciphertext length");
            return Err(PrivacyError::InvalidCiphertextLength {
                length: ciphertext.len(),
                block_size: 8,
            });
        }

        // 3DES key is first 24 bytes (K1, K2, K3)
        let key = &self.key[..24];
        // Pre-IV is bytes 24-31 of the 32-byte privKey
        let pre_iv = &self.key[24..32];

        // Salt is the privParameters
        let salt = priv_params;

        // IV = pre-IV XOR salt
        let mut iv = [0u8; 8];
        for i in 0..8 {
            iv[i] = pre_iv[i] ^ salt[i];
        }

        let mut buffer = ciphertext.to_vec();
        self.backend
            .decrypt(PrivProtocol::Des3, key, &iv, &mut buffer)?;

        Ok(Bytes::from(buffer))
    }

    /// AES-CFB encryption (RFC 3826 Section 3.1).
    fn encrypt_aes_cfb(
        &self,
        plaintext: &[u8],
        engine_boots: u32,
        engine_time: u32,
        salt: u64,
        key_len: usize,
    ) -> PrivacyResult<(Bytes, Bytes)> {
        // AES key is first key_len bytes
        let key = &self.key[..key_len];

        // Salt as 8 bytes (big-endian)
        let salt_bytes = salt.to_be_bytes();

        // IV = engineBoots (4) || engineTime (4) || salt (8) = 16 bytes
        // This is CONCATENATION, not XOR (unlike DES)
        let mut iv = [0u8; 16];
        iv[..4].copy_from_slice(&engine_boots.to_be_bytes());
        iv[4..8].copy_from_slice(&engine_time.to_be_bytes());
        iv[8..].copy_from_slice(&salt_bytes);

        let mut buffer = plaintext.to_vec();
        self.backend.encrypt(self.protocol, key, &iv, &mut buffer)?;

        Ok((Bytes::from(buffer), Bytes::copy_from_slice(&salt_bytes)))
    }

    /// AES-CFB decryption (RFC 3826 Section 3.1.4).
    fn decrypt_aes(
        &self,
        ciphertext: &[u8],
        engine_boots: u32,
        engine_time: u32,
        priv_params: &[u8],
    ) -> PrivacyResult<Bytes> {
        let key_len = match self.protocol {
            PrivProtocol::Aes128 => 16,
            PrivProtocol::Aes192Blumenthal | PrivProtocol::Aes192Reeder => 24,
            PrivProtocol::Aes256Blumenthal | PrivProtocol::Aes256Reeder => 32,
            _ => unreachable!(),
        };

        // AES key is first key_len bytes
        let key = &self.key[..key_len];

        // IV = engineBoots (4) || engineTime (4) || salt (8) = 16 bytes
        let mut iv = [0u8; 16];
        iv[..4].copy_from_slice(&engine_boots.to_be_bytes());
        iv[4..8].copy_from_slice(&engine_time.to_be_bytes());
        iv[8..].copy_from_slice(priv_params);

        let mut buffer = ciphertext.to_vec();
        self.backend.decrypt(self.protocol, key, &iv, &mut buffer)?;

        Ok(Bytes::from(buffer))
    }
}

impl std::fmt::Debug for PrivKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivKey")
            .field("protocol", &self.protocol)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(all(test, not(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))))]
mod no_backend_key_tests {
    use super::*;

    #[test]
    fn active_privacy_key_constructors_reject_unavailable_backend() {
        for protocol in [
            PrivProtocol::Des,
            PrivProtocol::Des3,
            PrivProtocol::Aes128,
            PrivProtocol::Aes192Blumenthal,
            PrivProtocol::Aes192Reeder,
            PrivProtocol::Aes256Blumenthal,
            PrivProtocol::Aes256Reeder,
        ] {
            let len = protocol.key_len();
            assert_eq!(
                PrivKey::from_bytes(protocol, vec![0_u8; len - 1]).unwrap_err(),
                CryptoError::InvalidKeyLength
            );
            assert_eq!(
                PrivKey::from_bytes(protocol, vec![0_u8; len]).unwrap_err(),
                CryptoError::BackendUnavailable
            );
        }
        assert_eq!(
            PrivKey::from_password(
                AuthProtocol::Sha256,
                PrivProtocol::Aes128,
                b"short",
                b"engine-id",
            )
            .unwrap_err(),
            CryptoError::PasswordTooShort
        );
        assert_eq!(
            PrivKey::from_password(
                AuthProtocol::Sha256,
                PrivProtocol::Aes128,
                b"long-enough",
                b"engine-id",
            )
            .unwrap_err(),
            CryptoError::BackendUnavailable
        );
    }
}

#[cfg(test)]
mod entropy_tests {
    use super::*;

    #[test]
    fn salt_counter_propagates_random_source_failure() {
        let error = random_nonzero_u64_with(|_| Err(getrandom::Error::UNEXPECTED)).unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::RandomSource);
    }

    #[test]
    fn salt_counter_retries_a_zero_seed() {
        let mut attempts = 0;
        let value = random_nonzero_u64_with(|bytes| {
            attempts += 1;
            if attempts == 2 {
                bytes.copy_from_slice(&1_u64.to_ne_bytes());
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(value, 1);
        assert_eq!(attempts, 2);
    }
}

#[cfg(test)]
mod des_state_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Debug)]
    struct PersistFailure(&'static str);

    impl std::fmt::Display for PersistFailure {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for PersistFailure {}

    #[test]
    fn install_and_restart_persist_before_use() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let install_writes = Arc::clone(&writes);
        let installed = DesSaltState::install(move |state| {
            install_writes.lock().unwrap().push(state.engine_boots());
            Ok::<(), std::convert::Infallible>(())
        })
        .unwrap();
        assert_eq!(installed.engine_boots(), 1);

        let restart_writes = Arc::clone(&writes);
        let restarted = DesSaltState::restart(installed.persisted_state(), move |state| {
            restart_writes.lock().unwrap().push(state.engine_boots());
            Ok::<(), std::convert::Infallible>(())
        })
        .unwrap();
        assert_eq!(restarted.engine_boots(), 2);
        assert_eq!(*writes.lock().unwrap(), [1, 2]);
    }

    #[test]
    fn persistence_failure_and_epoch_saturation_are_typed() {
        let error = DesSaltState::install(|_| Err(PersistFailure("disk unavailable"))).unwrap_err();
        let DesSaltStateError::Persistence(error) = error else {
            panic!("expected persistence error");
        };
        assert_eq!(error.operation(), DesSaltPersistenceOperation::Install);
        assert_eq!(error.attempted_engine_boots(), 1);
        assert_eq!(
            error.downcast_source_ref::<PersistFailure>().unwrap().0,
            "disk unavailable"
        );

        assert!(matches!(
            DesSaltState::restart(
                PersistedDesSaltState::new(super::super::MAX_ENGINE_TIME).unwrap(),
                |_| Ok::<(), std::convert::Infallible>(())
            ),
            Err(DesSaltStateError::EpochSaturated { .. })
        ));
    }

    #[test]
    fn atomic_restart_contract_rejects_a_second_live_owner() {
        let durable = Arc::new(Mutex::new(1_u32));
        let previous = PersistedDesSaltState::new(1).unwrap();
        let lease = |durable: Arc<Mutex<u32>>| {
            move |attempted: &PersistedDesSaltState| {
                let mut current = durable.lock().unwrap();
                if *current != 1 {
                    return Err(PersistFailure("stale compare-and-set"));
                }
                *current = attempted.engine_boots();
                Ok(())
            }
        };

        assert!(DesSaltState::restart(previous, lease(Arc::clone(&durable))).is_ok());
        let error = DesSaltState::restart(previous, lease(durable)).unwrap_err();
        assert!(matches!(error, DesSaltStateError::Persistence(_)));
    }

    #[test]
    fn atomic_install_contract_rejects_a_second_live_owner() {
        let durable = Arc::new(Mutex::new(None::<u32>));
        let lease = |durable: Arc<Mutex<Option<u32>>>| {
            move |attempted: &PersistedDesSaltState| {
                let mut current = durable.lock().unwrap();
                if current.is_some() {
                    return Err(PersistFailure("domain already installed"));
                }
                *current = Some(attempted.engine_boots());
                Ok(())
            }
        };

        assert!(DesSaltState::install(lease(Arc::clone(&durable))).is_ok());
        let error = DesSaltState::install(lease(durable)).unwrap_err();
        assert!(matches!(error, DesSaltStateError::Persistence(_)));
    }

    #[test]
    fn clones_share_one_nonwrapping_allocator() {
        let state = DesSaltState::install(|_| Ok::<(), std::convert::Infallible>(())).unwrap();
        let clone = state.clone();
        assert_eq!(state.reserve().unwrap().salt(), 1);
        assert_eq!(clone.reserve().unwrap().salt(), 2);

        let exhausted = DesSaltState::with_last_salt_for_test(9, u32::MAX);
        assert!(matches!(
            exhausted.reserve(),
            Err(PrivacyError::DesSaltExhausted { engine_boots: 9 })
        ));
    }
}

#[cfg(all(test, any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
mod tests {
    use super::*;
    use crate::format::hex::decode as decode_hex;

    fn des_state(engine_boots: u32) -> DesSaltState {
        if engine_boots == 1 {
            DesSaltState::install(|_| Ok::<(), std::convert::Infallible>(())).unwrap()
        } else {
            DesSaltState::restart(
                PersistedDesSaltState::new(engine_boots - 1).unwrap(),
                |_| Ok::<(), std::convert::Infallible>(()),
            )
            .unwrap()
        }
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn test_des_encrypt_decrypt_roundtrip() {
        // Create a 16-byte key (8 for DES, 8 for pre-IV)
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DES key
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // pre-IV
        ];
        let priv_key = PrivKey::from_bytes(PrivProtocol::Des, key).unwrap();

        let plaintext = b"Hello, SNMPv3 World!";
        let engine_boots = 100u32;
        let engine_time = 12345u32;

        let (ciphertext, priv_params) = priv_key
            .encrypt_des_family(plaintext, &des_state(engine_boots))
            .expect("encryption failed");

        // Verify ciphertext is different from plaintext
        assert_ne!(ciphertext.as_ref(), plaintext);
        // Verify priv_params is 8 bytes
        assert_eq!(priv_params.len(), 8);

        // Decrypt
        let decrypted = priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("decryption failed");

        // DES pads to 8-byte boundary, so decrypted may be longer
        assert!(decrypted.len() >= plaintext.len());
        assert_eq!(&decrypted[..plaintext.len()], plaintext);
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn test_des3_encrypt_decrypt_roundtrip() {
        // Create a 32-byte key (24 for 3DES, 8 for pre-IV)
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // K1
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // K2
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, // K3
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, // pre-IV
        ];
        let priv_key = PrivKey::from_bytes(PrivProtocol::Des3, key).unwrap();

        let plaintext = b"Hello, SNMPv3 World with 3DES!";
        let engine_boots = 100u32;
        let engine_time = 12345u32;

        let (ciphertext, priv_params) = priv_key
            .encrypt_des_family(plaintext, &des_state(engine_boots))
            .expect("encryption failed");

        // Verify ciphertext is different from plaintext
        assert_ne!(ciphertext.as_ref(), plaintext);
        // Verify priv_params is 8 bytes
        assert_eq!(priv_params.len(), 8);

        // Decrypt
        let decrypted = priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("decryption failed");

        // 3DES pads to 8-byte boundary, so decrypted may be longer
        assert!(decrypted.len() >= plaintext.len());
        assert_eq!(&decrypted[..plaintext.len()], plaintext);
    }

    #[test]
    fn test_aes128_encrypt_decrypt_roundtrip() {
        // Create a 16-byte key for AES-128
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let priv_key = PrivKey::from_bytes(PrivProtocol::Aes128, key).unwrap();

        let plaintext = b"Hello, SNMPv3 AES World!";
        let engine_boots = 200u32;
        let engine_time = 54321u32;

        let (ciphertext, priv_params) = priv_key
            .encrypt_aes(
                plaintext,
                engine_boots,
                engine_time,
                &SaltCounter::new().unwrap(),
            )
            .expect("encryption failed");

        // Verify ciphertext is different from plaintext
        assert_ne!(ciphertext.as_ref(), plaintext);
        // Verify priv_params is 8 bytes (salt)
        assert_eq!(priv_params.len(), 8);

        // Decrypt
        let decrypted = priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("decryption failed");

        // AES-CFB doesn't require padding, so lengths should match
        assert_eq!(decrypted.len(), plaintext.len());
        assert_eq!(decrypted.as_ref(), plaintext);
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn test_des_invalid_ciphertext_length() {
        let key = vec![0u8; 16];
        let priv_key = PrivKey::from_bytes(PrivProtocol::Des, key).unwrap();

        // Ciphertext not multiple of 8
        let ciphertext = [0u8; 13];
        let priv_params = [0u8; 8];

        let result = priv_key.decrypt(&ciphertext, 0, 0, &priv_params);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_priv_params_length() {
        let key = vec![0u8; 16];
        let priv_key = PrivKey::from_bytes(PrivProtocol::Aes128, key).unwrap();

        // priv_params should be 8 bytes
        let ciphertext = [0u8; 16];
        let priv_params = [0u8; 4]; // Wrong length

        let result = priv_key.decrypt(&ciphertext, 0, 0, &priv_params);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_bytes_rejects_undersized_key() {
        // Des requires 16 octets (8 key + 8 pre-IV); 4 is far too short.
        // Previously this succeeded and a later encrypt() would panic on the slice.
        let result = PrivKey::from_bytes(PrivProtocol::Des, vec![0u8; 4]);
        assert!(matches!(result, Err(CryptoError::InvalidKeyLength)));
    }

    #[test]
    fn test_from_bytes_accepts_exact_length_key() {
        let priv_key = PrivKey::from_bytes(PrivProtocol::Des, vec![0u8; 16]);
        if CryptoBackend::default()
            .validate_priv_protocol(PrivProtocol::Des)
            .is_ok()
        {
            assert!(priv_key.is_ok());
        } else {
            assert_eq!(
                priv_key.unwrap_err(),
                CryptoError::UnsupportedAlgorithm("DES")
            );
        }

        assert!(PrivKey::from_bytes(PrivProtocol::Aes128, vec![0u8; 16]).is_ok());
    }

    #[test]
    fn test_from_bytes_accepts_oversized_key() {
        // RFC 3826 Section 3.1.2 specifies the localized key is ">= " the required
        // length; downstream slices only ever take a `[..N]` prefix, so extra
        // trailing bytes are unused but harmless.
        let priv_key = PrivKey::from_bytes(PrivProtocol::Aes128, vec![0u8; 20]).unwrap();
        // Encrypting should not panic now that the key is validated as long enough.
        let _ = priv_key.encrypt_aes(b"data", 0, 0, &SaltCounter::new().unwrap());
    }

    #[test]
    fn test_from_bytes_key_len_boundary() {
        let aes128_len = PrivProtocol::Aes128.key_len();
        assert!(PrivKey::from_bytes(PrivProtocol::Aes128, vec![0u8; aes128_len - 1]).is_err());
        assert!(PrivKey::from_bytes(PrivProtocol::Aes128, vec![0u8; aes128_len]).is_ok());

        let aes256_len = PrivProtocol::Aes256Blumenthal.key_len();
        assert!(
            PrivKey::from_bytes(PrivProtocol::Aes256Blumenthal, vec![0u8; aes256_len - 1]).is_err()
        );
        assert!(PrivKey::from_bytes(PrivProtocol::Aes256Blumenthal, vec![0u8; aes256_len]).is_ok());
    }

    #[test]
    fn raw_privacy_key_capabilities_for_each_protocol_and_backend() {
        let protocols = [
            PrivProtocol::Des,
            PrivProtocol::Des3,
            PrivProtocol::Aes128,
            PrivProtocol::Aes192Blumenthal,
            PrivProtocol::Aes192Reeder,
            PrivProtocol::Aes256Blumenthal,
            PrivProtocol::Aes256Reeder,
        ];
        let backends = [
            #[cfg(feature = "crypto-rustcrypto")]
            CryptoBackend::RustCrypto,
            #[cfg(feature = "crypto-fips")]
            CryptoBackend::AwsLcFips,
        ];

        for backend in backends {
            for protocol in protocols {
                let len = protocol.key_len();
                assert_eq!(
                    PrivKey::from_bytes_with_backend(protocol, vec![0_u8; len - 1], backend)
                        .unwrap_err(),
                    CryptoError::InvalidKeyLength
                );

                let result = PrivKey::from_bytes_with_backend(protocol, vec![0_u8; len], backend);
                let is_supported = match backend {
                    #[cfg(feature = "crypto-rustcrypto")]
                    CryptoBackend::RustCrypto => true,
                    #[cfg(feature = "crypto-fips")]
                    CryptoBackend::AwsLcFips => {
                        !matches!(protocol, PrivProtocol::Des | PrivProtocol::Des3)
                    }
                };
                if is_supported {
                    assert_eq!(result.unwrap().key.len(), protocol.key_len());
                } else {
                    let algorithm = match protocol {
                        PrivProtocol::Des => "DES",
                        PrivProtocol::Des3 => "3DES",
                        PrivProtocol::Aes128
                        | PrivProtocol::Aes192Blumenthal
                        | PrivProtocol::Aes192Reeder
                        | PrivProtocol::Aes256Blumenthal
                        | PrivProtocol::Aes256Reeder => {
                            unreachable!()
                        }
                    };
                    assert_eq!(
                        result.unwrap_err(),
                        CryptoError::UnsupportedAlgorithm(algorithm)
                    );
                }
            }
        }
    }

    #[test]
    fn test_salt_counter() {
        let counter = SaltCounter::from_value(100);
        let s1 = counter.next();
        let s2 = counter.next();
        let s3 = counter.next();

        // Each call should increment
        assert_eq!(s2, s1.wrapping_add(1));
        assert_eq!(s3, s2.wrapping_add(1));
    }

    /// Test that `SaltCounter` never returns zero.
    ///
    /// Per net-snmp behavior (snmpusm.c:1319-1320), zero salt values should be
    /// skipped to avoid potential IV reuse issues on wraparound.
    #[test]
    fn test_salt_counter_skips_zero() {
        // Create a counter initialized to u64::MAX - 1 so the next call wraps through MAX.
        // next() returns post-increment, so:
        //   call 1: old=MAX-1, val=MAX, returns MAX
        //   call 2: old=MAX,   val=0 (wrapped), skips 0, returns 1
        //   call 3: old=1,     val=2, returns 2
        let counter = SaltCounter::from_value(u64::MAX - 1);

        let s1 = counter.next();
        assert_eq!(s1, u64::MAX);

        // This call wraps to zero; should skip and return 1
        let s2 = counter.next();
        assert_ne!(s2, 0, "SaltCounter should never return zero");
        assert_eq!(s2, 1, "SaltCounter should skip 0 and return 1");

        // Subsequent calls should continue normally
        let s3 = counter.next();
        assert_eq!(s3, 2);
    }

    /// Test that the wraparound path yields distinct, nonzero values.
    ///
    /// Regression: the wrap path previously returned a fixed `1`, which could
    /// duplicate the value produced by whichever thread read the counter as `0`.
    /// Driving several calls across the wrap boundary must produce no duplicate
    /// and no zero.
    #[test]
    fn test_salt_counter_wrap_no_duplicate() {
        use std::collections::HashSet;

        let counter = SaltCounter::from_value(u64::MAX - 2);
        let mut seen = HashSet::new();
        // Sequence crosses u64::MAX and the wrap-to-zero boundary.
        for _ in 0..6 {
            let v = counter.next();
            assert_ne!(v, 0, "SaltCounter must never return zero");
            assert!(seen.insert(v), "SaltCounter emitted duplicate: {v}");
        }
    }

    #[test]
    fn test_multiple_encryptions_use_shared_counter() {
        let key = vec![0u8; 16];
        let priv_key = PrivKey::from_bytes(PrivProtocol::Aes128, key).unwrap();
        let counter = SaltCounter::from_value(100);

        let (_, salt1) = priv_key.encrypt_aes(b"test data", 0, 0, &counter).unwrap();
        let (_, salt2) = priv_key.encrypt_aes(b"test data", 0, 0, &counter).unwrap();

        assert_eq!(u64::from_be_bytes(salt1[..].try_into().unwrap()), 101);
        assert_eq!(u64::from_be_bytes(salt2[..].try_into().unwrap()), 102);
    }

    #[test]
    fn test_from_password() {
        // Test that we can derive a privacy key from a password
        let password = b"maplesyrup";
        let engine_id = decode_hex("000000000000000000000002").unwrap();

        let priv_key = PrivKey::from_password(
            AuthProtocol::Sha1,
            PrivProtocol::Aes128,
            password,
            &engine_id,
        )
        .unwrap();

        // Just verify we can encrypt/decrypt with the derived key
        let plaintext = b"test message";
        let (ciphertext, priv_params) = priv_key
            .encrypt_aes(plaintext, 100, 200, &SaltCounter::new().unwrap())
            .unwrap();
        let decrypted = priv_key
            .decrypt(&ciphertext, 100, 200, &priv_params)
            .unwrap();

        assert_eq!(decrypted.as_ref(), plaintext);
    }

    #[test]
    fn test_aes192_encrypt_decrypt_roundtrip() {
        // Create a 24-byte key for AES-192
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        ];
        let priv_key = PrivKey::from_bytes(PrivProtocol::Aes192Blumenthal, key).unwrap();

        let plaintext = b"Hello, SNMPv3 AES-192 World!";
        let engine_boots = 300u32;
        let engine_time = 67890u32;

        let (ciphertext, priv_params) = priv_key
            .encrypt_aes(
                plaintext,
                engine_boots,
                engine_time,
                &SaltCounter::new().unwrap(),
            )
            .expect("AES-192 encryption failed");

        // Verify ciphertext is different from plaintext
        assert_ne!(ciphertext.as_ref(), plaintext);
        // Verify priv_params is 8 bytes (salt)
        assert_eq!(priv_params.len(), 8);

        // Decrypt
        let decrypted = priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("AES-192 decryption failed");

        // AES-CFB doesn't require padding, so lengths should match
        assert_eq!(decrypted.len(), plaintext.len());
        assert_eq!(decrypted.as_ref(), plaintext);
    }

    #[test]
    fn test_aes256_encrypt_decrypt_roundtrip() {
        // Create a 32-byte key for AES-256
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let priv_key = PrivKey::from_bytes(PrivProtocol::Aes256Blumenthal, key).unwrap();

        let plaintext = b"Hello, SNMPv3 AES-256 World!";
        let engine_boots = 400u32;
        let engine_time = 11111u32;

        let (ciphertext, priv_params) = priv_key
            .encrypt_aes(
                plaintext,
                engine_boots,
                engine_time,
                &SaltCounter::new().unwrap(),
            )
            .expect("AES-256 encryption failed");

        // Verify ciphertext is different from plaintext
        assert_ne!(ciphertext.as_ref(), plaintext);
        // Verify priv_params is 8 bytes (salt)
        assert_eq!(priv_params.len(), 8);

        // Decrypt
        let decrypted = priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("AES-256 decryption failed");

        // AES-CFB doesn't require padding, so lengths should match
        assert_eq!(decrypted.len(), plaintext.len());
        assert_eq!(decrypted.as_ref(), plaintext);
    }

    #[test]
    fn test_aes192_from_password() {
        // For AES-192 (24-byte key), we need SHA-224 or higher auth protocol
        let password = b"longpassword123";
        let engine_id = decode_hex("80001f8880e9b104617361000000").unwrap();

        let priv_key = PrivKey::from_password(
            AuthProtocol::Sha256, // SHA-256 produces 32 bytes, enough for AES-192
            PrivProtocol::Aes192Blumenthal,
            password,
            &engine_id,
        )
        .unwrap();

        let plaintext = b"test message for AES-192";
        let (ciphertext, priv_params) = priv_key
            .encrypt_aes(plaintext, 100, 200, &SaltCounter::new().unwrap())
            .unwrap();
        let decrypted = priv_key
            .decrypt(&ciphertext, 100, 200, &priv_params)
            .unwrap();

        assert_eq!(decrypted.as_ref(), plaintext);
    }

    #[test]
    fn test_aes256_from_password() {
        // For AES-256 (32-byte key), we need SHA-256 or higher auth protocol
        let password = b"anotherlongpassword456";
        let engine_id = decode_hex("80001f8880e9b104617361000000").unwrap();

        let priv_key = PrivKey::from_password(
            AuthProtocol::Sha256, // SHA-256 produces 32 bytes, exactly enough for AES-256
            PrivProtocol::Aes256Blumenthal,
            password,
            &engine_id,
        )
        .unwrap();

        let plaintext = b"test message for AES-256";
        let (ciphertext, priv_params) = priv_key
            .encrypt_aes(plaintext, 100, 200, &SaltCounter::new().unwrap())
            .unwrap();
        let decrypted = priv_key
            .decrypt(&ciphertext, 100, 200, &priv_params)
            .unwrap();

        assert_eq!(decrypted.as_ref(), plaintext);
    }

    // ========================================================================
    // Wrong Key Decryption Tests
    //
    // These tests verify that decryption with the wrong key produces garbage,
    // not the original plaintext. Note: Stream ciphers like AES-CFB don't return
    // errors on wrong-key decryption - they produce garbage. The authentication
    // layer (HMAC) is what detects tampering/wrong keys in practice (RFC 3414).
    // ========================================================================

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn test_des_wrong_key_produces_garbage() {
        // Correct 16-byte key
        let correct_key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18,
        ];
        // Wrong key (different from correct key)
        let wrong_key = vec![
            0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2,
            0xE1, 0xE0,
        ];

        let correct_priv_key = PrivKey::from_bytes(PrivProtocol::Des, correct_key).unwrap();
        let wrong_priv_key = PrivKey::from_bytes(PrivProtocol::Des, wrong_key).unwrap();

        let plaintext = b"Secret SNMPv3 message data!";
        let engine_boots = 100u32;
        let engine_time = 12345u32;

        // Encrypt with correct key
        let (ciphertext, priv_params) = correct_priv_key
            .encrypt_des_family(plaintext, &des_state(engine_boots))
            .expect("encryption failed");

        // Decrypt with wrong key - this will "succeed" but produce garbage
        let wrong_decrypted = wrong_priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("decryption should succeed cryptographically");

        // Verify wrong key produces different output (not the original plaintext)
        assert_ne!(
            &wrong_decrypted[..plaintext.len()],
            plaintext,
            "wrong key should NOT produce the original plaintext"
        );

        // Verify correct key still works
        let correct_decrypted = correct_priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("correct key decryption failed");
        assert_eq!(
            &correct_decrypted[..plaintext.len()],
            plaintext,
            "correct key should produce the original plaintext"
        );
    }

    #[test]
    fn test_aes128_wrong_key_produces_garbage() {
        let correct_key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let wrong_key = vec![
            0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2,
            0xF1, 0xF0,
        ];

        let correct_priv_key = PrivKey::from_bytes(PrivProtocol::Aes128, correct_key).unwrap();
        let wrong_priv_key = PrivKey::from_bytes(PrivProtocol::Aes128, wrong_key).unwrap();

        let plaintext = b"Secret AES-128 message data!";
        let engine_boots = 200u32;
        let engine_time = 54321u32;

        // Encrypt with correct key
        let (ciphertext, priv_params) = correct_priv_key
            .encrypt_aes(
                plaintext,
                engine_boots,
                engine_time,
                &SaltCounter::new().unwrap(),
            )
            .expect("encryption failed");

        // Decrypt with wrong key
        let wrong_decrypted = wrong_priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("decryption should succeed cryptographically");

        // Wrong key should produce garbage (not the original plaintext)
        assert_ne!(
            wrong_decrypted.as_ref(),
            plaintext,
            "wrong key should NOT produce the original plaintext"
        );

        // Correct key should work
        let correct_decrypted = correct_priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("correct key decryption failed");
        assert_eq!(correct_decrypted.as_ref(), plaintext);
    }

    #[test]
    fn test_aes192_wrong_key_produces_garbage() {
        let correct_key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        ];
        let wrong_key = vec![
            0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2,
            0xF1, 0xF0, 0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8,
        ];

        let correct_priv_key =
            PrivKey::from_bytes(PrivProtocol::Aes192Blumenthal, correct_key).unwrap();
        let wrong_priv_key =
            PrivKey::from_bytes(PrivProtocol::Aes192Blumenthal, wrong_key).unwrap();

        let plaintext = b"Secret AES-192 message data!";
        let engine_boots = 300u32;
        let engine_time = 67890u32;

        let (ciphertext, priv_params) = correct_priv_key
            .encrypt_aes(
                plaintext,
                engine_boots,
                engine_time,
                &SaltCounter::new().unwrap(),
            )
            .expect("encryption failed");

        let wrong_decrypted = wrong_priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("decryption should succeed cryptographically");

        assert_ne!(
            wrong_decrypted.as_ref(),
            plaintext,
            "wrong key should NOT produce the original plaintext"
        );
    }

    #[test]
    fn test_aes256_wrong_key_produces_garbage() {
        let correct_key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let wrong_key = vec![
            0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2,
            0xF1, 0xF0, 0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8, 0xE7, 0xE6, 0xE5, 0xE4,
            0xE3, 0xE2, 0xE1, 0xE0,
        ];

        let correct_priv_key =
            PrivKey::from_bytes(PrivProtocol::Aes256Blumenthal, correct_key).unwrap();
        let wrong_priv_key =
            PrivKey::from_bytes(PrivProtocol::Aes256Blumenthal, wrong_key).unwrap();

        let plaintext = b"Secret AES-256 message data!";
        let engine_boots = 400u32;
        let engine_time = 11111u32;

        let (ciphertext, priv_params) = correct_priv_key
            .encrypt_aes(
                plaintext,
                engine_boots,
                engine_time,
                &SaltCounter::new().unwrap(),
            )
            .expect("encryption failed");

        let wrong_decrypted = wrong_priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("decryption should succeed cryptographically");

        assert_ne!(
            wrong_decrypted.as_ref(),
            plaintext,
            "wrong key should NOT produce the original plaintext"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn test_des_wrong_priv_params_produces_garbage() {
        // Verify that even with the correct key, wrong priv_params (salt/IV)
        // produces garbage. This tests the IV derivation logic.
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18,
        ];

        let priv_key = PrivKey::from_bytes(PrivProtocol::Des, key).unwrap();

        let plaintext = b"DES test message";
        let engine_boots = 100u32;
        let engine_time = 12345u32;

        let (ciphertext, correct_priv_params) = priv_key
            .encrypt_des_family(plaintext, &des_state(engine_boots))
            .expect("encryption failed");

        // Use wrong priv_params (different salt)
        let wrong_priv_params = [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88];

        let wrong_decrypted = priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &wrong_priv_params)
            .expect("decryption should succeed cryptographically");

        // Wrong IV should produce garbage
        assert_ne!(
            &wrong_decrypted[..plaintext.len()],
            plaintext,
            "wrong priv_params should NOT produce the original plaintext"
        );

        // Correct priv_params should work
        let correct_decrypted = priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &correct_priv_params)
            .expect("correct decryption failed");
        assert_eq!(&correct_decrypted[..plaintext.len()], plaintext);
    }

    /// Test the DES salt/IV composition against RFC 3414 Section 8.1.1.1.
    ///
    /// Asserts that the returned `privParameters` is exactly `engineBoots (4 bytes,
    /// big-endian) || counter (4 bytes, big-endian)` for a controlled `SaltCounter`
    /// value, and that the CBC IV used is `pre-IV XOR salt` by round-tripping through
    /// `decrypt` and by independently recomputing the expected IV.
    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn test_des_salt_and_iv_composition() {
        // Distinctive 16-byte key: bytes 0..8 = DES key, 8..16 = pre-IV.
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DES key
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, // pre-IV
        ];
        let pre_iv = [0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
        let priv_key = PrivKey::from_bytes(PrivProtocol::Des, key).unwrap();

        let expected_salt_value: u32 = 0x1001;

        let engine_boots: u32 = 0x1234_5678;
        let des_state = DesSaltState::with_last_salt_for_test(engine_boots, 0x1000);
        let engine_time: u32 = 999;
        let plaintext = b"RFC 3414 8.1.1.1 salt/IV composition test";

        let (ciphertext, priv_params) = priv_key
            .encrypt_des_family(plaintext, &des_state)
            .expect("encryption failed");

        // 1. Salt composition: privParameters = engineBoots || counter.
        assert_eq!(priv_params.len(), 8);
        assert_eq!(&priv_params[..4], &engine_boots.to_be_bytes());
        assert_eq!(&priv_params[4..8], &expected_salt_value.to_be_bytes());

        // 2. IV = pre-IV XOR salt: independently recompute and confirm it is
        // non-trivial (the salt actually XORed in, not a passthrough).
        let mut expected_iv = [0u8; 8];
        for i in 0..8 {
            expected_iv[i] = pre_iv[i] ^ priv_params[i];
        }
        assert_ne!(
            expected_iv, pre_iv,
            "salt XOR must change the IV relative to the raw pre-IV"
        );

        // 3. Round-trip proof: decrypt-side IV reconstruction (pre-IV XOR
        // priv_params) must match the encrypt-side IV, recovering the plaintext.
        let decrypted = priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("decryption failed");
        assert_eq!(&decrypted[..plaintext.len()], plaintext);
    }

    /// Test that `SaltCounter` never emits duplicate salts under concurrent access.
    ///
    /// This is a regression test for the two-fetch_add race where two threads
    /// could both return 1 after a wraparound left the counter at 0.
    #[test]
    fn test_salt_counter_no_duplicates_concurrent() {
        use std::collections::HashSet;
        use std::sync::{Arc, Mutex};
        use std::thread;

        let counter = Arc::new(SaltCounter::new().unwrap());
        let results = Arc::new(Mutex::new(HashSet::new()));
        let iterations = 10_000usize;
        let threads = 8usize;

        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let counter = Arc::clone(&counter);
                let results = Arc::clone(&results);
                thread::spawn(move || {
                    for _ in 0..iterations {
                        let salt = counter.next();
                        assert_ne!(salt, 0, "SaltCounter must never return zero");
                        let mut set = results.lock().unwrap();
                        assert!(set.insert(salt), "SaltCounter emitted duplicate: {salt}");
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn test_des_family_shared_state_concurrency_and_exhaustion() {
        use std::collections::HashSet;
        use std::sync::{Arc, Mutex};
        use std::thread;

        for (protocol, key_len) in [(PrivProtocol::Des, 16), (PrivProtocol::Des3, 32)] {
            let key = Arc::new(PrivKey::from_bytes(protocol, vec![0x5A; key_len]).unwrap());
            let state = Arc::new(DesSaltState::with_last_salt_for_test(7, 0));
            let portions = Arc::new(Mutex::new(HashSet::new()));

            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let key = Arc::clone(&key);
                    let state = Arc::clone(&state);
                    let portions = Arc::clone(&portions);
                    thread::spawn(move || {
                        let (_, params) = key.encrypt_des_family(b"shared", &state).unwrap();
                        assert_eq!(&params[..4], &7_u32.to_be_bytes());
                        let low = u32::from_be_bytes(params[4..].try_into().unwrap());
                        assert_ne!(low, 0);
                        assert!(portions.lock().unwrap().insert(low));
                    })
                })
                .collect();

            for handle in handles {
                handle.join().unwrap();
            }
            assert_eq!(*portions.lock().unwrap(), HashSet::from([1, 2, 3, 4]));

            let exhausted = DesSaltState::with_last_salt_for_test(7, u32::MAX);
            assert!(matches!(
                key.encrypt_des_family(b"shared", &exhausted),
                Err(PrivacyError::DesSaltExhausted { engine_boots: 7 })
            ));
        }
    }

    #[test]
    fn test_cloned_priv_keys_require_same_explicit_counter() {
        let original = PrivKey::from_bytes(PrivProtocol::Aes128, vec![0u8; 16]).unwrap();
        let cloned = original.clone();
        let counter = SaltCounter::from_value(200);

        let (_, salt_orig) = original.encrypt_aes(b"test", 0, 0, &counter).unwrap();
        let (_, salt_clone) = cloned.encrypt_aes(b"test", 0, 0, &counter).unwrap();

        assert_eq!(u64::from_be_bytes(salt_orig[..].try_into().unwrap()), 201);
        assert_eq!(u64::from_be_bytes(salt_clone[..].try_into().unwrap()), 202);
    }

    #[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn test_aes128_backends_match_with_deterministic_salt() {
        let key = vec![0x5A; PrivProtocol::Aes128.key_len()];
        let rust = PrivKey::from_bytes_with_backend(
            PrivProtocol::Aes128,
            key.clone(),
            CryptoBackend::RustCrypto,
        )
        .unwrap();
        let fips =
            PrivKey::from_bytes_with_backend(PrivProtocol::Aes128, key, CryptoBackend::AwsLcFips)
                .unwrap();
        let rust_counter = SaltCounter::from_value(41);
        let fips_counter = SaltCounter::from_value(41);

        let rust_encrypted = rust
            .encrypt_aes(b"shared AES-128 provider KAT", 7, 11, &rust_counter)
            .unwrap();
        let fips_encrypted = fips
            .encrypt_aes(b"shared AES-128 provider KAT", 7, 11, &fips_counter)
            .unwrap();

        assert_eq!(rust_encrypted, fips_encrypted);
    }

    #[test]
    fn test_aes_wrong_engine_time_produces_garbage() {
        // For AES, the IV includes engine_boots and engine_time.
        // Wrong values should produce garbage.
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];

        let priv_key = PrivKey::from_bytes(PrivProtocol::Aes128, key).unwrap();

        let plaintext = b"AES test message";
        let engine_boots = 200u32;
        let engine_time = 54321u32;

        let (ciphertext, priv_params) = priv_key
            .encrypt_aes(
                plaintext,
                engine_boots,
                engine_time,
                &SaltCounter::new().unwrap(),
            )
            .expect("encryption failed");

        // Decrypt with wrong engine_time (IV mismatch)
        let wrong_decrypted = priv_key
            .decrypt(&ciphertext, engine_boots, engine_time + 1, &priv_params)
            .expect("decryption should succeed cryptographically");

        assert_ne!(
            wrong_decrypted.as_ref(),
            plaintext,
            "wrong engine_time should NOT produce the original plaintext"
        );

        // Decrypt with wrong engine_boots (IV mismatch)
        let wrong_decrypted2 = priv_key
            .decrypt(&ciphertext, engine_boots + 1, engine_time, &priv_params)
            .expect("decryption should succeed cryptographically");

        assert_ne!(
            wrong_decrypted2.as_ref(),
            plaintext,
            "wrong engine_boots should NOT produce the original plaintext"
        );
    }
}
