//! Shared test infrastructure for async-snmp.
//!
//! Provides `TestAgent` (in-process SNMP agent), fixtures, and utilities.

// Allow dead code and unused imports since not all test files use all utilities
#![allow(dead_code)]
#![allow(unused_imports)]

pub mod fixtures;
pub mod handler;

#[cfg(feature = "agent")]
pub mod agent;
#[cfg(feature = "agent")]
pub mod faulty;

// Re-export MIB data fixtures
pub use fixtures::system_mib;

// Re-export OID helpers
pub use fixtures::{
    interfaces_subtree, nonexistent_oid, sys_contact, sys_descr, sys_location, sys_name,
    sys_object_id, sys_services, sys_uptime, system_subtree,
};

// Re-export container test constants
pub use fixtures::{
    AUTH_PASSWORD, COMMUNITY_RO, COMMUNITY_RW, PRIV_PASSWORD, parse_image, snmpd_image, users,
};

// Re-export BTreeMap fixtures
pub use fixtures::{combined, interface_table};

#[cfg(feature = "agent")]
pub use agent::{TestAgent, TestAgentBuilder, V3User};
#[cfg(feature = "agent")]
pub use faulty::{LossyAgent, PausableAgent, SlowAgent};
pub use handler::TestHandler;
