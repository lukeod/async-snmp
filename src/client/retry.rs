//! Retry configuration for SNMP requests.
//!
//! This module provides configurable retry strategies including fixed delay
//! and exponential backoff with jitter.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Retry configuration for SNMP requests.
///
/// Controls how the client handles timeouts on UDP transports. TCP transports
/// ignore timeout retry configuration since the transport layer handles
/// reliability. SNMPv3 protocol correction is separate from timeout retry
/// policy: one authenticated time-window correction remains available with
/// [`Retry::none`] and on reliable transports.
///
/// Each SNMPv3 timeout transmission uses a fresh outer msgID while retaining
/// the PDU request-id, and a response to any transmission in the current
/// exchange may correlate. Stable request-id reuse matches deployed stacks but
/// deliberately deviates from RFC 3414 Section 11.1. A protocol correction
/// uses fresh message and PDU IDs and resets that acceptance window.
///
/// # Examples
///
/// ```rust
/// use async_snmp::Retry;
/// use std::time::Duration;
///
/// // No retries
/// let retry = Retry::none();
///
/// // Fixed delay between retries
/// let retry = Retry::fixed(3, Duration::from_millis(200));
///
/// // Exponential backoff with jitter (1s, 2s, 4s, 5s, 5s)
/// let retry = Retry::exponential(5)
///     .max_delay(Duration::from_secs(5))
///     .jitter(0.25)
///     .build()
///     .expect("valid retry configuration");
/// ```
#[derive(Clone, Debug)]
pub struct Retry {
    /// Maximum number of retry attempts (0 = no retries, request sent once)
    max_attempts: u32,
    /// Backoff strategy between retries
    backoff: Backoff,
}

/// Error returned when a retry configuration is invalid.
#[derive(Clone, Copy, Debug, PartialEq, thiserror::Error)]
pub enum RetryConfigError {
    /// The jitter factor is not finite or lies outside the supported range.
    #[error("jitter must be finite and between 0.0 and 1.0 (got {0})")]
    InvalidJitter(f64),
}

/// Backoff strategy between retry attempts.
#[derive(Clone, Copy, Debug, Default)]
enum Backoff {
    /// No delay between retries (immediate retry on timeout).
    #[default]
    None,

    /// Fixed delay between each retry attempt.
    Fixed {
        /// Delay before each retry
        delay: Duration,
    },

    /// Exponential backoff: delay doubles after each attempt.
    ///
    /// With jitter enabled (recommended), the actual delay is randomized
    /// within a range to prevent synchronized retries from multiple clients.
    Exponential {
        /// Initial delay before first retry
        initial: Duration,
        /// Maximum delay cap
        max: Duration,
        /// Jitter factor (0.0-1.0). E.g., 0.25 means ±25% randomization.
        jitter: f64,
    },
}

impl Default for Retry {
    /// Default: 3 retries with 1-second fixed delay between attempts.
    fn default() -> Self {
        Self {
            max_attempts: 3,
            backoff: Backoff::Fixed {
                delay: Duration::from_secs(1),
            },
        }
    }
}

impl Retry {
    /// No retries - request is sent once and fails on timeout.
    #[must_use]
    pub fn none() -> Self {
        Self {
            max_attempts: 0,
            backoff: Backoff::None,
        }
    }

    /// Fixed delay between retries.
    ///
    /// # Arguments
    ///
    /// * `attempts` - Maximum number of retry attempts
    /// * `delay` - Fixed delay before each retry
    #[must_use]
    pub fn fixed(attempts: u32, delay: Duration) -> Self {
        Self {
            max_attempts: attempts,
            backoff: Backoff::Fixed { delay },
        }
    }

    /// Start building an exponential backoff retry configuration.
    ///
    /// Returns a [`RetryBuilder`] for configuring the backoff parameters.
    ///
    /// # Arguments
    ///
    /// * `attempts` - Maximum number of retry attempts
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::Retry;
    /// use std::time::Duration;
    ///
    /// let retry = Retry::exponential(5)
    ///     .max_delay(Duration::from_secs(5))
    ///     .jitter(0.25)
    ///     .build()
    ///     .expect("valid retry configuration");
    /// ```
    #[must_use]
    pub fn exponential(attempts: u32) -> RetryBuilder {
        RetryBuilder {
            max_attempts: attempts,
            ..Default::default()
        }
    }

    /// Return the maximum number of retry attempts.
    #[must_use]
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Compute the delay before the next retry attempt.
    ///
    /// Returns `Duration::ZERO` when no delay is configured.
    #[must_use]
    pub fn compute_delay(&self, attempt: u32) -> Duration {
        match &self.backoff {
            Backoff::None => Duration::ZERO,
            Backoff::Fixed { delay } => *delay,
            Backoff::Exponential {
                initial,
                max,
                jitter,
            } => {
                // Exponential: initial * 2^attempt, capped at max
                // Clamp attempt to prevent overflow (32 is more than enough)
                let shift = attempt.min(31);
                let multiplier = 1u32.checked_shl(shift).unwrap_or(u32::MAX);
                let base = initial.saturating_mul(multiplier);
                let capped = base.min(*max);

                // Apply jitter. A valid jitter can still push Duration::MAX
                // beyond the representable range, so preserve the existing
                // saturating backoff behavior at the conversion boundary.
                let factor = jitter_factor(*jitter);
                Duration::try_from_secs_f64(capped.as_secs_f64() * factor).unwrap_or(Duration::MAX)
            }
        }
    }
}

/// Builder for exponential backoff retry configuration.
#[derive(Debug, Clone)]
pub struct RetryBuilder {
    max_attempts: u32,
    initial: Duration,
    max: Duration,
    jitter: f64,
}

impl Default for RetryBuilder {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial: Duration::from_secs(1),
            max: Duration::from_secs(5),
            jitter: 0.25,
        }
    }
}

impl RetryBuilder {
    /// Set the initial delay before the first retry (default: 1 second).
    #[must_use]
    pub fn initial_delay(mut self, delay: Duration) -> Self {
        self.initial = delay;
        self
    }

    /// Set the maximum delay cap (default: 5 seconds).
    #[must_use]
    pub fn max_delay(mut self, delay: Duration) -> Self {
        self.max = delay;
        self
    }

    /// Set the jitter factor (default: 0.25, meaning ±25% randomization).
    ///
    /// Jitter helps prevent synchronized retries when multiple clients
    /// experience timeouts simultaneously.
    ///
    /// The value is validated by [`RetryBuilder::build`].
    #[must_use]
    pub fn jitter(mut self, jitter: f64) -> Self {
        self.jitter = jitter;
        self
    }

    /// Build the [`Retry`] configuration.
    ///
    /// # Errors
    ///
    /// Returns [`RetryConfigError::InvalidJitter`] when jitter is NaN,
    /// infinite, or outside `0.0..=1.0`.
    pub fn build(self) -> Result<Retry, RetryConfigError> {
        Retry::validate_jitter(self.jitter)?;
        Ok(Retry {
            max_attempts: self.max_attempts,
            backoff: Backoff::Exponential {
                initial: self.initial,
                max: self.max,
                jitter: self.jitter,
            },
        })
    }
}

impl Retry {
    pub(crate) fn validate_jitter(jitter: f64) -> Result<(), RetryConfigError> {
        if jitter.is_finite() && (0.0..=1.0).contains(&jitter) {
            Ok(())
        } else {
            Err(RetryConfigError::InvalidJitter(jitter))
        }
    }
}

/// Global counter for jitter generation.
static JITTER_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Compute a jitter factor in the range [1-jitter, 1+jitter].
///
/// Uses a multiplicative hash of an atomic counter to generate pseudo-random
/// values. This is sufficient for retry desynchronization without requiring
/// true randomness.
#[allow(
    clippy::cast_precision_loss,
    reason = "u64->f64 cast is intentional part of hash-like algorithm"
)]
fn jitter_factor(jitter: f64) -> f64 {
    if jitter <= 0.0 {
        return 1.0;
    }
    // Multiplicative hash of counter (Knuth's method)
    let counter = JITTER_COUNTER.fetch_add(1, Ordering::Relaxed);
    let hash = counter.wrapping_mul(0x5851_f42d_4c95_7f2d);
    // Convert to [0, 1) range using upper bits (better distribution)
    let random = (hash >> 11) as f64 / ((1u64 << 53) as f64);
    // Return factor in [1-jitter, 1+jitter]
    1.0 + (random - 0.5) * 2.0 * jitter
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_none() {
        let retry = Retry::none();
        assert_eq!(retry.max_attempts(), 0);
        assert_eq!(retry.compute_delay(0), Duration::ZERO);
    }

    #[test]
    fn test_retry_default() {
        let retry = Retry::default();
        assert_eq!(retry.max_attempts(), 3);
        assert_eq!(retry.compute_delay(0), Duration::from_secs(1));
    }

    #[test]
    fn test_retry_fixed() {
        let retry = Retry::fixed(5, Duration::from_millis(200));
        assert_eq!(retry.max_attempts(), 5);
        assert_eq!(retry.compute_delay(0), Duration::from_millis(200));
    }

    #[test]
    fn test_retry_exponential_builder() {
        let retry = Retry::exponential(4)
            .initial_delay(Duration::from_millis(50))
            .max_delay(Duration::from_millis(75))
            .jitter(0.0)
            .build()
            .unwrap();

        assert_eq!(retry.max_attempts(), 4);
        assert_eq!(retry.compute_delay(0), Duration::from_millis(50));
        assert_eq!(retry.compute_delay(1), Duration::from_millis(75));
    }

    #[test]
    fn test_builder_rejects_invalid_jitter() {
        for jitter in [-0.1, 1.1, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(matches!(
                Retry::exponential(1).jitter(jitter).build(),
                Err(RetryConfigError::InvalidJitter(value)) if value.to_bits() == jitter.to_bits()
            ));
        }
    }

    #[test]
    fn test_builder_accepts_jitter_endpoints() {
        assert!(Retry::exponential(1).jitter(0.0).build().is_ok());
        assert!(Retry::exponential(1).jitter(1.0).build().is_ok());
    }

    #[test]
    fn test_compute_delay_none() {
        let retry = Retry::none();
        assert_eq!(retry.compute_delay(0), Duration::ZERO);
        assert_eq!(retry.compute_delay(5), Duration::ZERO);
    }

    #[test]
    fn test_compute_delay_default() {
        let retry = Retry::default();
        assert_eq!(retry.compute_delay(0), Duration::from_secs(1));
        assert_eq!(retry.compute_delay(5), Duration::from_secs(1));
    }

    #[test]
    fn test_compute_delay_fixed() {
        let retry = Retry::fixed(3, Duration::from_millis(100));
        assert_eq!(retry.compute_delay(0), Duration::from_millis(100));
        assert_eq!(retry.compute_delay(1), Duration::from_millis(100));
        assert_eq!(retry.compute_delay(10), Duration::from_millis(100));
    }

    #[test]
    fn test_compute_delay_exponential_no_jitter() {
        let retry = Retry::exponential(5)
            .initial_delay(Duration::from_millis(100))
            .max_delay(Duration::from_secs(10))
            .jitter(0.0)
            .build()
            .unwrap();

        assert_eq!(retry.compute_delay(0), Duration::from_millis(100));
        assert_eq!(retry.compute_delay(1), Duration::from_millis(200));
        assert_eq!(retry.compute_delay(2), Duration::from_millis(400));
        assert_eq!(retry.compute_delay(3), Duration::from_millis(800));
    }

    #[test]
    fn test_compute_delay_exponential_capped() {
        let retry = Retry::exponential(10)
            .initial_delay(Duration::from_millis(100))
            .max_delay(Duration::from_millis(500))
            .jitter(0.0)
            .build()
            .unwrap();

        assert_eq!(retry.compute_delay(0), Duration::from_millis(100));
        assert_eq!(retry.compute_delay(1), Duration::from_millis(200));
        assert_eq!(retry.compute_delay(2), Duration::from_millis(400));
        // Should be capped at 500ms
        assert_eq!(retry.compute_delay(3), Duration::from_millis(500));
        assert_eq!(retry.compute_delay(10), Duration::from_millis(500));
    }

    #[test]
    fn test_compute_delay_exponential_with_jitter() {
        let retry = Retry::exponential(3)
            .initial_delay(Duration::from_millis(100))
            .max_delay(Duration::from_secs(1))
            .jitter(0.25)
            .build()
            .unwrap();

        // With jitter, delay should be in [75ms, 125ms] for attempt 0
        // Run multiple times to verify it's in range
        for _ in 0..10 {
            let delay = retry.compute_delay(0);
            let millis = delay.as_millis();
            assert!((75..=125).contains(&millis), "delay was {millis}ms");
        }
    }

    #[test]
    fn test_jitter_factor_range() {
        // Test that jitter_factor produces values in expected range
        for _ in 0..100 {
            let factor = jitter_factor(0.5);
            assert!((0.5..=1.5).contains(&factor), "factor was {factor}");
        }
    }

    #[test]
    fn test_jitter_factor_zero() {
        assert_eq!(jitter_factor(0.0), 1.0);
        assert_eq!(jitter_factor(-0.1), 1.0);
    }

    #[test]
    fn test_public_retry_configurations_compute_delays_without_panicking() {
        let configurations = [
            Retry::none(),
            Retry::default(),
            Retry::fixed(2, Duration::MAX),
            Retry::exponential(2)
                .initial_delay(Duration::MAX)
                .max_delay(Duration::MAX)
                .jitter(0.0)
                .build()
                .unwrap(),
            Retry::exponential(2)
                .initial_delay(Duration::MAX)
                .max_delay(Duration::MAX)
                .jitter(1.0)
                .build()
                .unwrap(),
        ];

        for retry in configurations {
            for attempt in [0, 1, u32::MAX] {
                let _ = retry.compute_delay(attempt);
            }
        }
    }
}
