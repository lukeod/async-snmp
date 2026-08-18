//! View-based Access Control Model (RFC 3415).
//!
//! VACM selects read, write, and notification views from a request's security
//! model, security name, security level, and context.
//!
//! `SecurityModel` is canonical at [`crate::handler::SecurityModel`] and the
//! crate root; it is not re-exported from this nested module.
//!
//! ```compile_fail
//! use async_snmp::agent::vacm::SecurityModel;
//! ```
//!
//! # Architecture
//!
//! VACM controls access through three tables:
//!
//! 1. **Security-to-group table**: Maps `(securityModel, securityName)` to a
//!    group name.
//!
//! 2. **Access table**: Maps `(groupName, contextPrefix, securityModel,
//!    securityLevel)` to view names for read, write, and notify operations.
//!
//! 3. **View-tree-family table**: Defines views as included or excluded OID
//!    subtrees, with optional wildcard masks.
//!
//! # Read-only community
//!
//! Configure read-only access for "public" community:
//!
//! ```rust
//! use async_snmp::agent::{Agent, SecurityModel, VacmBuilder};
//! use async_snmp::{SecurityLevel, oid};
//!
//! # fn example() {
//! let vacm = VacmBuilder::new()
//!     // Map "public" community to "readonly_group"
//!     .group("public", SecurityModel::V2c, "readonly_group")
//!     // Grant read access to full_view
//!     .access("readonly_group", SecurityModel::V2c, SecurityLevel::NoAuthNoPriv,
//!         |a| a.read_view("full_view"))
//!     // Define what OIDs are in full_view
//!     .view("full_view", |v| v.include(oid!(1, 3, 6, 1)))
//!     .build().unwrap();
//! # }
//! ```
//!
//! # Read and write access
//!
//! Configure different access levels for different users:
//!
//! ```rust
//! use async_snmp::agent::{Agent, SecurityModel, VacmBuilder};
//! use async_snmp::message::SecurityLevel;
//! use async_snmp::oid;
//!
//! # fn example() {
//! let vacm = VacmBuilder::new()
//!     // Read-only community
//!     .group("public", SecurityModel::V2c, "readers")
//!     // Read-write community
//!     .group("private", SecurityModel::V2c, "writers")
//!     // SNMPv3 admin user
//!     .group("admin", SecurityModel::Usm, "admins")
//!
//!     // Readers can only read
//!     .access("readers", SecurityModel::V2c, SecurityLevel::NoAuthNoPriv, |a| a
//!         .read_view("system_view"))
//!
//!     // Writers can read everything and write to ifAdminStatus
//!     .access("writers", SecurityModel::V2c, SecurityLevel::NoAuthNoPriv, |a| a
//!         .read_view("full_view")
//!         .write_view("if_admin_view"))
//!
//!     // Admins require encryption and can read/write everything
//!     .access("admins", SecurityModel::Usm, SecurityLevel::AuthPriv, |a| a
//!         .read_view("full_view")
//!         .write_view("full_view"))
//!
//!     // Define views
//!     .view("system_view", |v| v
//!         .include(oid!(1, 3, 6, 1, 2, 1, 1)))  // system MIB only
//!     .view("full_view", |v| v
//!         .include(oid!(1, 3, 6, 1)))           // everything
//!     .view("if_admin_view", |v| v
//!         .include(oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 7)))  // ifAdminStatus
//!     .build().unwrap();
//! # }
//! ```
//!
//! # View exclusions
//!
//! Views can exclude specific subtrees from a broader include:
//!
//! ```rust
//! use async_snmp::agent::View;
//! use async_snmp::{SecurityLevel, oid};
//!
//! // Include all of system MIB except sysServices
//! let view = View::new()
//!     .include(oid!(1, 3, 6, 1, 2, 1, 1))        // system MIB
//!     .exclude(oid!(1, 3, 6, 1, 2, 1, 1, 7));    // except sysServices
//!
//! assert!(view.contains(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)));   // sysDescr.0 - allowed
//! assert!(!view.contains(&oid!(1, 3, 6, 1, 2, 1, 1, 7, 0)));  // sysServices.0 - blocked
//! ```
//!
//! # Wildcard masks
//!
//! Masks allow matching OIDs with wildcards at specific positions:
//!
//! ```rust
//! use async_snmp::agent::ViewSubtree;
//! use async_snmp::oid;
//!
//! // Match ifDescr for any interface index (ifDescr.*)
//! // OID: 1.3.6.1.2.1.2.2.1.2 (10 arcs, indices 0-9)
//! // Mask: 0xFF 0xC0 = 11111111 11000000 (arcs 0-9 must match, 10+ wildcard)
//! let subtree = ViewSubtree {
//!     oid: oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2),  // ifDescr
//!     mask: vec![0xFF, 0xC0],
//!     included: true,
//! };
//!
//! // Matches any interface index
//! assert!(subtree.matches(&oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1)));    // ifDescr.1
//! assert!(subtree.matches(&oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 100)));  // ifDescr.100
//!
//! // Does not match different columns
//! assert!(!subtree.matches(&oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 3, 1)));   // ifType.1
//! ```
//!
//! # Agent integration
//!
//! Use [`AgentBuilder::vacm()`](super::AgentBuilder::vacm) to configure VACM:
//!
//! ```rust,no_run
//! use async_snmp::agent::{Agent, SecurityModel};
//! use async_snmp::{SecurityLevel, oid};
//!
//! # async fn example() -> Result<(), Box<async_snmp::Error>> {
//! let agent = Agent::builder()
//!     .bind("0.0.0.0:1161")
//!     .community(b"public")
//!     .community(b"private")
//!     .vacm(|v| v
//!         .group("public", SecurityModel::V2c, "readonly")
//!         .group("private", SecurityModel::V2c, "readwrite")
//!         .access("readonly", SecurityModel::V2c, SecurityLevel::NoAuthNoPriv,
//!             |a| a.read_view("all"))
//!         .access("readwrite", SecurityModel::V2c, SecurityLevel::NoAuthNoPriv,
//!             |a| a.read_view("all").write_view("all"))
//!         .view("all", |v| v.include(oid!(1, 3, 6, 1))))
//!     .build()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Denied requests
//!
//! When VACM denies access:
//! - **`SNMPv1`**: Returns `noSuchName` error
//! - **SNMPv2c/v3 GET**: Returns `noAccess` error or `NoSuchObject` per RFC 3416
//! - **SNMPv2c/v3 SET**: Returns `noAccess` error

use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;

use bytes::Bytes;

use crate::message::SecurityLevel;
use crate::oid::Oid;

use crate::handler::SecurityModel;

/// Security model selector used by VACM mappings and access entries.
///
/// A concrete [`SecurityModel`] converts to [`VacmSecurityModel::Exact`], so
/// builders accept concrete request models directly. Use [`Self::Any`] only
/// where a mapping should match every concrete request model.
///
/// ```rust
/// use async_snmp::agent::{SecurityModel, VacmSecurityModel};
///
/// let exact = VacmSecurityModel::from(SecurityModel::Usm);
/// assert_eq!(exact, VacmSecurityModel::Exact(SecurityModel::Usm));
/// assert_eq!(VacmSecurityModel::default(), VacmSecurityModel::Any);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum VacmSecurityModel {
    /// Match every concrete request security model.
    #[default]
    Any,
    /// Match one concrete request security model.
    Exact(SecurityModel),
}

impl From<SecurityModel> for VacmSecurityModel {
    fn from(model: SecurityModel) -> Self {
        Self::Exact(model)
    }
}

impl VacmSecurityModel {
    fn matches(self, model: SecurityModel) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(exact) => exact == model,
        }
    }

    fn is_exact(self, model: SecurityModel) -> bool {
        self == Self::Exact(model)
    }
}

/// Context matching mode for access entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ContextMatch {
    /// Exact context name match.
    #[default]
    Exact,
    /// Context name prefix match.
    Prefix,
}

/// A view is a collection of OID subtrees defining accessible objects.
///
/// Views are used by VACM to determine which OIDs a user can access.
/// Each view consists of included and/or excluded subtrees.
///
/// # Example
///
/// ```rust
/// use async_snmp::agent::View;
/// use async_snmp::oid;
///
/// // Create a view that includes the system MIB but excludes sysContact
/// let view = View::new()
///     .include(oid!(1, 3, 6, 1, 2, 1, 1))        // system MIB
///     .exclude(oid!(1, 3, 6, 1, 2, 1, 1, 4));    // sysContact
///
/// assert!(view.contains(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)));   // sysDescr.0
/// assert!(!view.contains(&oid!(1, 3, 6, 1, 2, 1, 1, 4, 0)));  // sysContact.0
/// assert!(!view.contains(&oid!(1, 3, 6, 1, 2, 1, 2)));        // interfaces MIB
/// ```
#[derive(Debug, Clone, Default)]
pub struct View {
    subtrees: Vec<ViewSubtree>,
}

impl View {
    /// Create an empty view.
    ///
    /// An empty view contains no OIDs. Add subtrees with [`include()`](View::include)
    /// or [`exclude()`](View::exclude).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an included subtree to the view.
    ///
    /// All OIDs starting with `oid` will be included unless the RFC 3415
    /// precedence rules select another matching family.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::agent::View;
    /// use async_snmp::oid;
    ///
    /// let view = View::new()
    ///     .include(oid!(1, 3, 6, 1, 2, 1))  // MIB-2
    ///     .include(oid!(1, 3, 6, 1, 4, 1)); // enterprises
    ///
    /// assert!(view.contains(&oid!(1, 3, 6, 1, 2, 1, 1, 0)));
    /// assert!(view.contains(&oid!(1, 3, 6, 1, 4, 1, 99999, 1)));
    /// ```
    #[must_use]
    pub fn include(mut self, oid: Oid) -> Self {
        self.subtrees.push(ViewSubtree {
            oid,
            mask: Vec::new(),
            included: true,
        });
        self
    }

    /// Add an included subtree with a wildcard mask.
    ///
    /// The mask allows wildcards at specific OID arc positions.
    /// See [`ViewSubtree::mask`] for mask format details.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::agent::View;
    /// use async_snmp::oid;
    ///
    /// // Include ifDescr for any interface (mask makes arc 10 a wildcard)
    /// let view = View::new()
    ///     .include_masked(
    ///         oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2),  // ifDescr
    ///         vec![0xFF, 0xC0]  // First 10 arcs must match
    ///     );
    ///
    /// assert!(view.contains(&oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1)));   // ifDescr.1
    /// assert!(view.contains(&oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 100))); // ifDescr.100
    /// ```
    #[must_use]
    pub fn include_masked(mut self, oid: Oid, mask: Vec<u8>) -> Self {
        self.subtrees.push(ViewSubtree {
            oid,
            mask,
            included: true,
        });
        self
    }

    /// Add an excluded subtree to the view.
    ///
    /// This family excludes matching OIDs when RFC 3415 precedence selects it:
    /// the matching family with the most sub-identifiers wins, followed by the
    /// lexicographically greatest subtree OID when lengths are equal.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::agent::View;
    /// use async_snmp::oid;
    ///
    /// let view = View::new()
    ///     .include(oid!(1, 3, 6, 1, 2, 1, 1))     // system MIB
    ///     .exclude(oid!(1, 3, 6, 1, 2, 1, 1, 6)); // except sysLocation
    ///
    /// assert!(view.contains(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)));  // sysDescr
    /// assert!(!view.contains(&oid!(1, 3, 6, 1, 2, 1, 1, 6, 0))); // sysLocation
    /// ```
    #[must_use]
    pub fn exclude(mut self, oid: Oid) -> Self {
        self.subtrees.push(ViewSubtree {
            oid,
            mask: Vec::new(),
            included: false,
        });
        self
    }

    /// Add an excluded subtree with a wildcard mask.
    ///
    /// See [`include_masked()`](View::include_masked) for mask usage.
    #[must_use]
    pub fn exclude_masked(mut self, oid: Oid, mask: Vec<u8>) -> Self {
        self.subtrees.push(ViewSubtree {
            oid,
            mask,
            included: false,
        });
        self
    }

    /// Check if an OID is in this view.
    ///
    /// Per RFC 3415 Section 4, matching applies each subtree's mask and the
    /// match with the most sub-identifiers determines inclusion/exclusion. If
    /// equally long masked entries match, the lexicographically greatest
    /// subtree OID decides. The result does not depend on insertion order.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::agent::View;
    /// use async_snmp::oid;
    ///
    /// let view = View::new()
    ///     .include(oid!(1, 3, 6, 1, 2, 1))
    ///     .exclude(oid!(1, 3, 6, 1, 2, 1, 25));  // host resources
    ///
    /// assert!(view.contains(&oid!(1, 3, 6, 1, 2, 1, 1, 0)));
    /// assert!(!view.contains(&oid!(1, 3, 6, 1, 2, 1, 25, 1, 0)));
    /// assert!(!view.contains(&oid!(1, 3, 6, 1, 4, 1)));  // not included
    /// ```
    #[must_use]
    pub fn contains(&self, oid: &Oid) -> bool {
        let mut best: Option<(&[u32], bool)> = None;

        for subtree in &self.subtrees {
            if subtree.matches(oid) {
                let arcs = subtree.oid.arcs();
                if view_match_wins(best, arcs, subtree.included) {
                    best = Some((arcs, subtree.included));
                }
            }
        }

        best.is_some_and(|(_, included)| included)
    }
}

/// RFC 3415 precedence for overlapping masked MIB-view subtree matches.
///
/// More sub-identifiers wins. At equal lengths, the lexicographically greatest
/// subtree OID wins. Identical invalid duplicate indices resolve to exclusion.
fn view_match_wins(best: Option<(&[u32], bool)>, arcs: &[u32], included: bool) -> bool {
    match best {
        None => true,
        Some((best_arcs, best_included)) => {
            arcs.len() > best_arcs.len()
                || (arcs.len() == best_arcs.len()
                    && (arcs > best_arcs
                        // Duplicate subtree indices are not valid VACM rows,
                        // but resolve them conservatively and independently
                        // of insertion order if a View is manually assembled.
                        || (arcs == best_arcs && best_included && !included)))
        }
    }
}

/// A subtree in a view with optional mask.
#[derive(Debug, Clone)]
pub struct ViewSubtree {
    /// Base OID of subtree.
    pub oid: Oid,
    /// Bit mask for wildcard matching (empty = exact match).
    ///
    /// Each bit position corresponds to an arc in the OID:
    /// - Bit 7 (MSB) of byte 0 = arc 0
    /// - Bit 6 of byte 0 = arc 1
    /// - etc.
    ///
    /// A bit value of 1 means the arc must match exactly.
    /// A bit value of 0 means any value is accepted (wildcard).
    pub mask: Vec<u8>,
    /// Include (true) or exclude (false) this subtree.
    pub included: bool,
}

impl ViewSubtree {
    /// Whether arc position `i` requires an exact match.
    ///
    /// A mask bit of 1 (or a position past the mask) means the arc must match
    /// exactly; a bit of 0 is a wildcard. Bit 7 (MSB) of byte 0 is arc 0.
    fn arc_is_exact(&self, i: usize) -> bool {
        if i / 8 < self.mask.len() {
            (self.mask[i / 8] >> (7 - (i % 8))) & 1 == 1
        } else {
            true // Default: exact match required
        }
    }

    /// Whether the first `arcs.len()` arcs of this subtree match `arcs` under
    /// the mask. Callers guarantee `self.oid` has at least `arcs.len()` arcs.
    fn prefix_matches(&self, arcs: &[u32]) -> bool {
        let subtree_arcs = self.oid.arcs();
        arcs.iter()
            .enumerate()
            .all(|(i, &arc)| !self.arc_is_exact(i) || subtree_arcs[i] == arc)
    }

    /// Check if an OID matches this subtree (with mask).
    #[must_use]
    pub fn matches(&self, oid: &Oid) -> bool {
        let subtree_arcs = self.oid.arcs();
        let oid_arcs = oid.arcs();

        // OID must be at least as long as subtree
        if oid_arcs.len() < subtree_arcs.len() {
            return false;
        }

        // Every subtree arc must match the OID under the mask.
        self.prefix_matches(&oid_arcs[..subtree_arcs.len()])
    }
}

/// Access table entry.
#[derive(Debug, Clone)]
pub struct VacmAccessEntry {
    /// Group name this entry applies to.
    pub group_name: Bytes,
    /// Context prefix for matching.
    pub context_prefix: Bytes,
    /// Security model selector.
    pub security_model: VacmSecurityModel,
    /// Minimum security level required.
    pub security_level: SecurityLevel,
    /// Context matching mode.
    pub(crate) context_match: ContextMatch,
    /// View name for read access.
    pub read_view: Bytes,
    /// View name for write access.
    pub write_view: Bytes,
    /// View name for notify access (traps/informs).
    pub notify_view: Bytes,
}

impl VacmAccessEntry {
    /// Return the RFC 3415 `vacmAccessEntry` row index for this entry.
    #[must_use]
    pub fn index(&self) -> VacmAccessIndex {
        VacmAccessIndex {
            group_name: self.group_name.clone(),
            context_prefix: self.context_prefix.clone(),
            security_model: self.security_model,
            security_level: self.security_level,
        }
    }
}

/// RFC 3415 `vacmAccessEntry` row index.
///
/// `context_match` and the view names are mutable columns of the conceptual
/// row and are therefore deliberately absent from this key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VacmAccessIndex {
    /// Group name component of the row index.
    pub group_name: Bytes,
    /// Context prefix component of the row index.
    pub context_prefix: Bytes,
    /// Security model component of the row index.
    pub security_model: VacmSecurityModel,
    /// Security level component of the row index.
    pub security_level: SecurityLevel,
}

/// Error returned when an access row is added at an occupied row index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateVacmAccessEntry {
    index: VacmAccessIndex,
}

impl DuplicateVacmAccessEntry {
    /// Return the duplicate row index.
    #[must_use]
    pub fn index(&self) -> &VacmAccessIndex {
        &self.index
    }
}

impl fmt::Display for DuplicateVacmAccessEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "duplicate VACM access entry at index {:?}", self.index)
    }
}

impl StdError for DuplicateVacmAccessEntry {}

/// Builder for access entries.
///
/// Configure what views a group can access for different operations.
/// Typically used via [`VacmBuilder::access()`].
///
/// # Example
///
/// ```rust
/// use async_snmp::agent::{SecurityModel, VacmBuilder};
/// use async_snmp::message::SecurityLevel;
/// use async_snmp::oid;
///
/// let vacm = VacmBuilder::new()
///     .group("admin", SecurityModel::Usm, "admin_group")
///     .access("admin_group", SecurityModel::Usm, SecurityLevel::AuthPriv, |a| a
///         .read_view("full_view")
///         .write_view("config_view")
///         .notify_view("trap_view"))
///     .view("full_view", |v| v.include(oid!(1, 3, 6, 1)))
///     .view("config_view", |v| v.include(oid!(1, 3, 6, 1, 4, 1)))
///     .view("trap_view", |v| v.include(oid!(1, 3, 6, 1)))
///     .build().unwrap();
/// ```
pub struct AccessEntryBuilder {
    group_name: Bytes,
    context_prefix: Bytes,
    security_model: VacmSecurityModel,
    security_level: SecurityLevel,
    context_match: ContextMatch,
    read_view: Bytes,
    write_view: Bytes,
    notify_view: Bytes,
}

impl AccessEntryBuilder {
    /// Create an access entry with explicit security model and minimum level.
    pub fn new(
        group_name: impl Into<Bytes>,
        security_model: impl Into<VacmSecurityModel>,
        security_level: SecurityLevel,
    ) -> Self {
        Self {
            group_name: group_name.into(),
            context_prefix: Bytes::new(),
            security_model: security_model.into(),
            security_level,
            context_match: ContextMatch::Exact,
            read_view: Bytes::new(),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        }
    }

    /// Set the context prefix for matching.
    ///
    /// Context is an `SNMPv3` concept that allows partitioning MIB views.
    /// Most deployments use an empty context (the default).
    #[must_use]
    pub fn context_prefix(mut self, prefix: impl Into<Bytes>) -> Self {
        self.context_prefix = prefix.into();
        self
    }

    /// Set context matching to prefix mode.
    ///
    /// When enabled, the context prefix is matched against the start of
    /// the request context name rather than requiring an exact match.
    /// The default is exact matching.
    #[must_use]
    pub fn context_match_prefix(mut self) -> Self {
        self.context_match = ContextMatch::Prefix;
        self
    }

    /// Set the read view name.
    ///
    /// The view must be defined with [`VacmBuilder::view()`].
    /// If not set, read operations are denied.
    #[must_use]
    pub fn read_view(mut self, view: impl Into<Bytes>) -> Self {
        self.read_view = view.into();
        self
    }

    /// Set the write view name.
    ///
    /// The view must be defined with [`VacmBuilder::view()`].
    /// If not set, write (SET) operations are denied.
    #[must_use]
    pub fn write_view(mut self, view: impl Into<Bytes>) -> Self {
        self.write_view = view.into();
        self
    }

    /// Set the notify view name.
    ///
    /// Used for trap/inform generation (not access control).
    /// The view must be defined with [`VacmBuilder::view()`].
    #[must_use]
    pub fn notify_view(mut self, view: impl Into<Bytes>) -> Self {
        self.notify_view = view.into();
        self
    }

    /// Build the access entry.
    pub fn build(self) -> VacmAccessEntry {
        VacmAccessEntry {
            group_name: self.group_name,
            context_prefix: self.context_prefix,
            security_model: self.security_model,
            security_level: self.security_level,
            context_match: self.context_match,
            read_view: self.read_view,
            write_view: self.write_view,
            notify_view: self.notify_view,
        }
    }
}

/// VACM configuration.
#[derive(Clone, Default)]
pub struct VacmConfig {
    /// (securityModel selector, securityName) → groupName
    security_to_group: HashMap<(VacmSecurityModel, Bytes), Bytes>,
    /// RFC 3415 row index → access table entry.
    access_entries: HashMap<VacmAccessIndex, VacmAccessEntry>,
    /// viewName → View
    views: HashMap<Bytes, View>,
}

impl fmt::Debug for VacmConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VacmConfig")
            .field(
                "security_to_group",
                &RedactedSecurityMappings(&self.security_to_group),
            )
            .field("access_entries", &self.access_entries)
            .field("views", &self.views)
            .finish()
    }
}

struct RedactedSecurityMappings<'a>(&'a HashMap<(VacmSecurityModel, Bytes), Bytes>);

impl fmt::Debug for RedactedSecurityMappings<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();
        for ((security_model, _security_name), group_name) in self.0 {
            list.entry(&RedactedSecurityMapping {
                security_model,
                security_name: "[REDACTED]",
                group_name,
            });
        }
        list.finish()
    }
}

struct RedactedSecurityMapping<'a> {
    security_model: &'a VacmSecurityModel,
    security_name: &'static str,
    group_name: &'a Bytes,
}

impl fmt::Debug for RedactedSecurityMapping<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityMapping")
            .field("security_model", self.security_model)
            .field("security_name", &self.security_name)
            .field("group_name", self.group_name)
            .finish()
    }
}

impl VacmConfig {
    /// Create an empty VACM configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Map a security name to a group for a security model selector.
    ///
    /// Concrete [`SecurityModel`] values create exact mappings; pass
    /// [`VacmSecurityModel::Any`] for a wildcard mapping.
    pub fn add_group(
        &mut self,
        security_name: impl Into<Bytes>,
        security_model: impl Into<VacmSecurityModel>,
        group_name: impl Into<Bytes>,
    ) {
        self.security_to_group.insert(
            (security_model.into(), security_name.into()),
            group_name.into(),
        );
    }

    /// Add an access entry, preserving the existing row on an index collision.
    ///
    /// Use [`replace_access`](Self::replace_access) when replacement is
    /// intentional.
    pub fn add_access(&mut self, entry: VacmAccessEntry) -> Result<(), DuplicateVacmAccessEntry> {
        let index = entry.index();
        if self.access_entries.contains_key(&index) {
            return Err(DuplicateVacmAccessEntry { index });
        }
        self.access_entries.insert(index, entry);
        Ok(())
    }

    /// Insert an access entry or explicitly replace the row at the same index.
    ///
    /// Returns the replaced row, if the index was already occupied.
    pub fn replace_access(&mut self, entry: VacmAccessEntry) -> Option<VacmAccessEntry> {
        self.access_entries.insert(entry.index(), entry)
    }

    /// Add a view.
    pub fn add_view(&mut self, name: impl Into<Bytes>, view: View) {
        self.views.insert(name.into(), view);
    }

    /// Return whether a non-empty view name is defined.
    #[must_use]
    pub(crate) fn has_view(&self, name: &[u8]) -> bool {
        !name.is_empty() && self.views.contains_key(name)
    }

    /// Resolve group name for a request.
    #[must_use]
    pub fn get_group(&self, model: SecurityModel, name: &[u8]) -> Option<&Bytes> {
        // Try exact model match first, then fall back to Any.
        // Iterate to avoid allocating a Bytes for the lookup key.
        let mut any_match = None;
        for ((entry_model, entry_name), group) in &self.security_to_group {
            if entry_name.as_ref() == name {
                if entry_model.is_exact(model) {
                    return Some(group);
                } else if *entry_model == VacmSecurityModel::Any {
                    any_match = Some(group);
                }
            }
        }
        any_match
    }

    /// Returns the access entry for a context.
    ///
    /// Returns the best matching entry per RFC 3415 Section 4 (vacmAccessTable DESCRIPTION).
    /// Selection uses a 4-tier preference order:
    /// 1. Prefer specific securityModel over Any
    /// 2. Prefer a contextPrefix identical to the request contextName
    /// 3. Prefer longer contextPrefix
    /// 4. Prefer higher securityLevel
    #[must_use]
    pub fn get_access(
        &self,
        group: &[u8],
        context: &[u8],
        model: SecurityModel,
        level: SecurityLevel,
    ) -> Option<&VacmAccessEntry> {
        self.access_entries
            .values()
            .filter(|e| {
                e.group_name.as_ref() == group
                    && self.context_matches(&e.context_prefix, context, e.context_match)
                    && e.security_model.matches(model)
                    && level >= e.security_level
            })
            .max_by_key(|e| {
                // RFC 3415 Section 4 preference order (tuple comparison is lexicographic)
                let model_score: u8 = u8::from(e.security_model.is_exact(model));
                let match_score: u8 = u8::from(e.context_prefix.as_ref() == context);
                let prefix_len = e.context_prefix.len();
                let level_score = e.security_level as u8;
                (model_score, match_score, prefix_len, level_score)
            })
    }

    /// Check if context matches the prefix.
    fn context_matches(&self, prefix: &[u8], context: &[u8], mode: ContextMatch) -> bool {
        match mode {
            ContextMatch::Exact => prefix == context,
            ContextMatch::Prefix => context.starts_with(prefix),
        }
    }

    /// Check if OID access is permitted.
    #[must_use]
    pub fn check_access(&self, view_name: Option<&Bytes>, oid: &Oid) -> bool {
        let Some(view_name) = view_name else {
            return false;
        };

        if view_name.is_empty() {
            return false;
        }

        let Some(view) = self.views.get(view_name) else {
            return false;
        };

        view.contains(oid)
    }
}

/// Builder for VACM configuration.
///
/// Use this to configure access control for your SNMP agent. The typical
/// workflow is:
///
/// 1. Map security names (communities/usernames) to groups with [`group()`](VacmBuilder::group)
/// 2. Define access rules for groups with [`access()`](VacmBuilder::access)
/// 3. Define views (OID collections) with [`view()`](VacmBuilder::view)
/// 4. Build with [`build()`](VacmBuilder::build)
///
/// # Example
///
/// ```rust
/// use async_snmp::agent::{SecurityModel, VacmBuilder};
/// use async_snmp::message::SecurityLevel;
/// use async_snmp::oid;
///
/// let vacm = VacmBuilder::new()
///     // Step 1: Map security names to groups
///     .group("public", SecurityModel::V2c, "readers")
///     .group("admin", SecurityModel::Usm, "admins")
///
///     // Step 2: Define access for each group
///     .access("readers", SecurityModel::V2c, SecurityLevel::NoAuthNoPriv, |a| a
///         .read_view("system_view"))
///     .access("admins", SecurityModel::Usm, SecurityLevel::AuthPriv, |a| a
///         .read_view("full_view")
///         .write_view("full_view"))
///
///     // Step 3: Define views
///     .view("system_view", |v| v
///         .include(oid!(1, 3, 6, 1, 2, 1, 1)))
///     .view("full_view", |v| v
///         .include(oid!(1, 3, 6, 1)))
///
///     // Step 4: Build
///     .build().unwrap();
/// ```
pub struct VacmBuilder {
    config: VacmConfig,
    duplicate_access_entries: Vec<VacmAccessIndex>,
}

impl VacmBuilder {
    /// Create a VACM builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: VacmConfig::new(),
            duplicate_access_entries: Vec::new(),
        }
    }

    /// Map a security name to a group.
    ///
    /// The security name is:
    /// - For SNMPv1/v2c: the community string
    /// - For `SNMPv3`: the USM username
    ///
    /// Multiple security names can map to the same group. Concrete
    /// [`SecurityModel`] values create exact mappings; pass
    /// [`VacmSecurityModel::Any`] for a wildcard mapping.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::agent::{SecurityModel, VacmBuilder};
    ///
    /// let vacm = VacmBuilder::new()
    ///     // Multiple communities in same group
    ///     .group("public", SecurityModel::V2c, "readonly")
    ///     .group("monitor", SecurityModel::V2c, "readonly")
    ///     // Different users in different groups
    ///     .group("admin", SecurityModel::Usm, "admin_group")
    ///     .build().unwrap();
    /// ```
    #[must_use]
    pub fn group(
        mut self,
        security_name: impl Into<Bytes>,
        security_model: impl Into<VacmSecurityModel>,
        group_name: impl Into<Bytes>,
    ) -> Self {
        self.config
            .add_group(security_name, security_model, group_name);
        self
    }

    /// Add an access entry using a builder function.
    ///
    /// Access entries define what views a group can use for read, write,
    /// and notify operations. Use the closure to configure the entry.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::agent::{SecurityModel, VacmBuilder};
    /// use async_snmp::message::SecurityLevel;
    /// use async_snmp::oid;
    ///
    /// let vacm = VacmBuilder::new()
    ///     .group("public", SecurityModel::V2c, "readers")
    ///     .access("readers", SecurityModel::V2c, SecurityLevel::NoAuthNoPriv, |a| a
    ///         .read_view("system_view")
    ///         // No write_view = read-only
    ///     )
    ///     .view("system_view", |v| v.include(oid!(1, 3, 6, 1, 2, 1, 1)))
    ///     .build().unwrap();
    /// ```
    #[must_use]
    pub fn access<F>(
        mut self,
        group_name: impl Into<Bytes>,
        security_model: impl Into<VacmSecurityModel>,
        security_level: SecurityLevel,
        configure: F,
    ) -> Self
    where
        F: FnOnce(AccessEntryBuilder) -> AccessEntryBuilder,
    {
        let builder = AccessEntryBuilder::new(group_name, security_model, security_level);
        let entry = configure(builder).build();
        if let Err(error) = self.config.add_access(entry) {
            self.duplicate_access_entries.push(error.index);
        }
        self
    }

    /// Insert an access entry or explicitly replace the row at the same index.
    ///
    /// This has the same row-building API as [`access`](Self::access), but its
    /// name makes replacement intentional. A replacement also resolves a
    /// previous duplicate for that row in this builder.
    #[must_use]
    pub fn replace_access<F>(
        mut self,
        group_name: impl Into<Bytes>,
        security_model: impl Into<VacmSecurityModel>,
        security_level: SecurityLevel,
        configure: F,
    ) -> Self
    where
        F: FnOnce(AccessEntryBuilder) -> AccessEntryBuilder,
    {
        let entry = configure(AccessEntryBuilder::new(
            group_name,
            security_model,
            security_level,
        ))
        .build();
        let index = entry.index();
        self.duplicate_access_entries
            .retain(|duplicate| duplicate != &index);
        self.config.replace_access(entry);
        self
    }

    /// Add a view using a builder function.
    ///
    /// Views define collections of OID subtrees. Use the closure to add
    /// included and excluded subtrees.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::agent::VacmBuilder;
    /// use async_snmp::oid;
    ///
    /// let vacm = VacmBuilder::new()
    ///     .view("system_only", |v| v
    ///         .include(oid!(1, 3, 6, 1, 2, 1, 1)))  // system MIB
    ///     .view("all_except_private", |v| v
    ///         .include(oid!(1, 3, 6, 1))
    ///         .exclude(oid!(1, 3, 6, 1, 4, 1, 99999)))  // exclude our enterprise
    ///     .build().unwrap();
    /// ```
    #[must_use]
    pub fn view<F>(mut self, name: impl Into<Bytes>, configure: F) -> Self
    where
        F: FnOnce(View) -> View,
    {
        let view = configure(View::new());
        self.config.add_view(name, view);
        self
    }

    /// Build the VACM configuration.
    pub fn build(self) -> Result<VacmConfig, DuplicateVacmAccessEntry> {
        if let Some(index) = self.duplicate_access_entries.into_iter().next() {
            return Err(DuplicateVacmAccessEntry { index });
        }
        Ok(self.config)
    }
}

impl Default for VacmBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid;
    use proptest::prelude::*;

    fn access_entry(
        context_prefix: &'static [u8],
        security_model: VacmSecurityModel,
        security_level: SecurityLevel,
        context_match: ContextMatch,
        read_view: &'static [u8],
    ) -> VacmAccessEntry {
        VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::from_static(context_prefix),
            security_model,
            security_level,
            context_match,
            read_view: Bytes::from_static(read_view),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        }
    }

    #[test]
    fn test_view_contains_simple() {
        let view = View::new().include(oid!(1, 3, 6, 1, 2, 1)); // system MIB

        // OID within the subtree
        assert!(view.contains(&oid!(1, 3, 6, 1, 2, 1, 1, 0)));
        assert!(view.contains(&oid!(1, 3, 6, 1, 2, 1, 2, 1, 1)));

        // OID exactly at subtree
        assert!(view.contains(&oid!(1, 3, 6, 1, 2, 1)));

        // OID outside the subtree
        assert!(!view.contains(&oid!(1, 3, 6, 1, 4, 1)));
        assert!(!view.contains(&oid!(1, 3, 6, 1, 2)));
    }

    #[test]
    fn test_view_exclude() {
        let view = View::new()
            .include(oid!(1, 3, 6, 1, 2, 1)) // system MIB
            .exclude(oid!(1, 3, 6, 1, 2, 1, 1, 7)); // sysServices

        // Included OIDs
        assert!(view.contains(&oid!(1, 3, 6, 1, 2, 1, 1, 0)));
        assert!(view.contains(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)));

        // Excluded OID
        assert!(!view.contains(&oid!(1, 3, 6, 1, 2, 1, 1, 7)));
        assert!(!view.contains(&oid!(1, 3, 6, 1, 2, 1, 1, 7, 0)));
    }

    #[test]
    fn test_view_longest_match_wins() {
        // RFC 3415 Section 4: when multiple subtrees match, longest match wins.
        // include(1.3.6.1) + exclude(1.3.6.1.2) + include(1.3.6.1.2.1)
        // For OID 1.3.6.1.2.1.1.0, all three match. Longest is include(1.3.6.1.2.1),
        // so the OID should be accessible.
        let view = View::new()
            .include(oid!(1, 3, 6, 1))
            .exclude(oid!(1, 3, 6, 1, 2))
            .include(oid!(1, 3, 6, 1, 2, 1));

        // Longest match is include(1.3.6.1.2.1), so this should be included
        assert!(view.contains(&oid!(1, 3, 6, 1, 2, 1, 1, 0)));

        // OID under the exclude but not re-included
        assert!(!view.contains(&oid!(1, 3, 6, 1, 2, 3, 1, 0)));

        // OID only under the top-level include, not under exclude
        assert!(view.contains(&oid!(1, 3, 6, 1, 4, 1, 0)));
    }

    #[test]
    fn test_view_longest_match_exclude_wins() {
        // When longest match is an exclude, OID should be excluded
        let view = View::new()
            .include(oid!(1, 3, 6, 1))
            .exclude(oid!(1, 3, 6, 1, 2, 1));

        assert!(!view.contains(&oid!(1, 3, 6, 1, 2, 1, 1, 0)));
        assert!(view.contains(&oid!(1, 3, 6, 1, 4, 1, 0)));
    }

    #[test]
    fn test_view_identical_oid_collision_resolves_to_exclusion() {
        // Identical subtree OIDs cannot coexist in a valid VACM table. A View
        // assembled with that collision resolves conservatively to exclusion.
        let view = View::new()
            .include(oid!(1, 3, 6, 1, 2, 1))
            .exclude(oid!(1, 3, 6, 1, 2, 1));

        assert!(!view.contains(&oid!(1, 3, 6, 1, 2, 1, 1, 0)));
    }

    #[test]
    fn test_view_equal_length_identical_oid_order_independent() {
        // An include and an exclude on the same subtree OID form an index
        // collision that cannot occur in a valid vacmViewTreeFamilyTable.
        // The conservative exclusion fallback is independent of insertion order.
        let include_first = View::new()
            .include(oid!(1, 3, 6, 1, 2, 1))
            .exclude(oid!(1, 3, 6, 1, 2, 1));
        let exclude_first = View::new()
            .exclude(oid!(1, 3, 6, 1, 2, 1))
            .include(oid!(1, 3, 6, 1, 2, 1));

        let query = oid!(1, 3, 6, 1, 2, 1, 1, 0);
        assert_eq!(
            include_first.contains(&query),
            exclude_first.contains(&query),
            "identical-OID collision must be order-independent"
        );
        assert!(
            !include_first.contains(&query),
            "identical-OID collision resolves conservatively to excluded"
        );
    }

    #[test]
    fn test_view_equal_length_masked_lexicographically_greatest_subtree_wins() {
        // RFC 3415 Section 4: the lexicographically greatest subtree OID
        // decides when equal-length masked rows both match.
        let query = oid!(1, 3, 6, 1, 2, 1, 5, 5);
        let mask = vec![0xFE]; // arcs 0-6 exact, arc 7 wildcard

        for excluded_high in [
            View::new()
                .include_masked(oid!(1, 3, 6, 1, 2, 1, 5, 1), mask.clone())
                .exclude_masked(oid!(1, 3, 6, 1, 2, 1, 5, 9), mask.clone()),
            View::new()
                .exclude_masked(oid!(1, 3, 6, 1, 2, 1, 5, 9), mask.clone())
                .include_masked(oid!(1, 3, 6, 1, 2, 1, 5, 1), mask.clone()),
        ] {
            assert!(!excluded_high.contains(&query));
        }

        for included_high in [
            View::new()
                .exclude_masked(oid!(1, 3, 6, 1, 2, 1, 5, 1), mask.clone())
                .include_masked(oid!(1, 3, 6, 1, 2, 1, 5, 9), mask.clone()),
            View::new()
                .include_masked(oid!(1, 3, 6, 1, 2, 1, 5, 9), mask.clone())
                .exclude_masked(oid!(1, 3, 6, 1, 2, 1, 5, 1), mask.clone()),
        ] {
            assert!(included_high.contains(&query));
        }
    }

    #[test]
    fn test_view_subtree_mask() {
        // Create a view that matches ifDescr.* (any interface index)
        // The subtree OID is ifDescr (1.3.6.1.2.1.2.2.1.2) with 10 arcs (indices 0-9)
        // We want arcs 0-9 to match exactly, and arc 10+ to be wildcard
        // Mask: 0xFF = 11111111 (arcs 0-7 must match)
        //       0xC0 = 11000000 (arcs 8-9 must match, 10-15 wildcard)
        let subtree = ViewSubtree {
            oid: oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2), // ifDescr
            mask: vec![0xFF, 0xC0],                  // 11111111 11000000 - arcs 0-9 must match
            included: true,
        };

        // Should match with any interface index in position 10
        assert!(subtree.matches(&oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1)));
        assert!(subtree.matches(&oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 999)));

        // Should not match if arc 9 differs (the "2" in ifDescr)
        assert!(!subtree.matches(&oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 3, 1)));
    }

    #[test]
    fn test_vacm_group_lookup() {
        let mut config = VacmConfig::new();
        config.add_group("public", SecurityModel::V2c, "readonly_group");
        config.add_group("admin", SecurityModel::Usm, "admin_group");

        assert_eq!(
            config.get_group(SecurityModel::V2c, b"public"),
            Some(&Bytes::from_static(b"readonly_group"))
        );
        assert_eq!(
            config.get_group(SecurityModel::Usm, b"admin"),
            Some(&Bytes::from_static(b"admin_group"))
        );
        assert_eq!(config.get_group(SecurityModel::V1, b"public"), None);
    }

    #[test]
    fn test_vacm_group_prefers_exact_model_and_falls_back_to_any() {
        let mut config = VacmConfig::new();
        config.add_group("shared", VacmSecurityModel::Any, "fallback_group");
        config.add_group("shared", SecurityModel::V2c, "v2c_group");

        assert_eq!(
            config.get_group(SecurityModel::V2c, b"shared"),
            Some(&Bytes::from_static(b"v2c_group"))
        );
        assert_eq!(
            config.get_group(SecurityModel::V1, b"shared"),
            Some(&Bytes::from_static(b"fallback_group"))
        );
    }

    #[test]
    fn test_vacm_access_lookup() {
        let mut config = VacmConfig::new();
        config
            .add_access(VacmAccessEntry {
                group_name: Bytes::from_static(b"readonly_group"),
                context_prefix: Bytes::new(),
                security_model: VacmSecurityModel::Any,
                security_level: SecurityLevel::NoAuthNoPriv,
                context_match: ContextMatch::Exact,
                read_view: Bytes::from_static(b"full_view"),
                write_view: Bytes::new(),
                notify_view: Bytes::new(),
            })
            .unwrap();

        let access = config.get_access(
            b"readonly_group",
            b"",
            SecurityModel::V2c,
            SecurityLevel::NoAuthNoPriv,
        );
        assert!(access.is_some());
        assert_eq!(access.unwrap().read_view, Bytes::from_static(b"full_view"));
    }

    #[test]
    fn test_vacm_access_security_level() {
        let mut config = VacmConfig::new();
        config
            .add_access(VacmAccessEntry {
                group_name: Bytes::from_static(b"admin_group"),
                context_prefix: Bytes::new(),
                security_model: SecurityModel::Usm.into(),
                security_level: SecurityLevel::AuthPriv, // Require encryption
                context_match: ContextMatch::Exact,
                read_view: Bytes::from_static(b"full_view"),
                write_view: Bytes::from_static(b"full_view"),
                notify_view: Bytes::new(),
            })
            .unwrap();

        // Should not match with lower security level
        let access = config.get_access(
            b"admin_group",
            b"",
            SecurityModel::Usm,
            SecurityLevel::AuthNoPriv,
        );
        assert!(access.is_none());

        // Should match with required level
        let access = config.get_access(
            b"admin_group",
            b"",
            SecurityModel::Usm,
            SecurityLevel::AuthPriv,
        );
        assert!(access.is_some());
    }

    #[test]
    fn test_vacm_check_access() {
        let mut config = VacmConfig::new();
        config.add_view("full_view", View::new().include(oid!(1, 3, 6, 1)));

        assert!(config.check_access(
            Some(&Bytes::from_static(b"full_view")),
            &oid!(1, 3, 6, 1, 2, 1, 1, 0),
        ));

        // Empty view name = no access
        assert!(!config.check_access(Some(&Bytes::new()), &oid!(1, 3, 6, 1, 2, 1, 1, 0),));

        // None = no access
        assert!(!config.check_access(None, &oid!(1, 3, 6, 1, 2, 1, 1, 0),));

        // Unknown view = no access
        assert!(!config.check_access(
            Some(&Bytes::from_static(b"unknown_view")),
            &oid!(1, 3, 6, 1, 2, 1, 1, 0),
        ));
    }

    #[test]
    fn test_vacm_builder() {
        let config = VacmBuilder::new()
            .group("public", SecurityModel::V2c, "readonly_group")
            .group("admin", SecurityModel::Usm, "admin_group")
            .access(
                "readonly_group",
                VacmSecurityModel::Any,
                SecurityLevel::NoAuthNoPriv,
                |a| a.context_prefix("").read_view("full_view"),
            )
            .access(
                "admin_group",
                SecurityModel::Usm,
                SecurityLevel::AuthPriv,
                |a| a.read_view("full_view").write_view("full_view"),
            )
            .view("full_view", |v| v.include(oid!(1, 3, 6, 1)))
            .build()
            .unwrap();

        assert!(config.get_group(SecurityModel::V2c, b"public").is_some());
        assert!(config.get_group(SecurityModel::Usm, b"admin").is_some());
    }

    #[test]
    fn duplicate_access_row_is_rejected_and_preserves_existing_entry() {
        let mut config = VacmConfig::new();
        let first = access_entry(
            b"ctx",
            SecurityModel::Usm.into(),
            SecurityLevel::AuthNoPriv,
            ContextMatch::Exact,
            b"first",
        );
        let duplicate = access_entry(
            b"ctx",
            SecurityModel::Usm.into(),
            SecurityLevel::AuthNoPriv,
            ContextMatch::Prefix,
            b"duplicate",
        );

        config.add_access(first).unwrap();
        let error = config.add_access(duplicate).unwrap_err();
        assert_eq!(error.index().group_name.as_ref(), b"test_group");
        assert_eq!(error.index().context_prefix.as_ref(), b"ctx");
        assert_eq!(error.index().security_model, SecurityModel::Usm.into());
        assert_eq!(error.index().security_level, SecurityLevel::AuthNoPriv);
        assert_eq!(
            config
                .get_access(
                    b"test_group",
                    b"ctx",
                    SecurityModel::Usm,
                    SecurityLevel::AuthNoPriv,
                )
                .unwrap()
                .read_view
                .as_ref(),
            b"first"
        );
    }

    #[test]
    fn explicit_access_replacement_is_deterministic() {
        let mut config = VacmConfig::new();
        let first = access_entry(
            b"ctx",
            SecurityModel::Usm.into(),
            SecurityLevel::AuthNoPriv,
            ContextMatch::Exact,
            b"first",
        );
        let replacement = access_entry(
            b"ctx",
            SecurityModel::Usm.into(),
            SecurityLevel::AuthNoPriv,
            ContextMatch::Prefix,
            b"replacement",
        );

        assert!(config.replace_access(first).is_none());
        let replaced = config.replace_access(replacement).unwrap();
        assert_eq!(replaced.read_view.as_ref(), b"first");
        let selected = config
            .get_access(
                b"test_group",
                b"ctx/child",
                SecurityModel::Usm,
                SecurityLevel::AuthNoPriv,
            )
            .unwrap();
        assert_eq!(selected.read_view.as_ref(), b"replacement");
        assert_eq!(selected.context_match, ContextMatch::Prefix);
    }

    #[test]
    fn builder_rejects_duplicates_unless_replacement_is_explicit() {
        let duplicate = VacmBuilder::new()
            .access(
                "test_group",
                SecurityModel::Usm,
                SecurityLevel::AuthNoPriv,
                |entry| entry.context_prefix("ctx").read_view("first"),
            )
            .access(
                "test_group",
                SecurityModel::Usm,
                SecurityLevel::AuthNoPriv,
                |entry| {
                    entry
                        .context_prefix("ctx")
                        .context_match_prefix()
                        .read_view("duplicate")
                },
            )
            .build()
            .unwrap_err();
        assert_eq!(duplicate.index().context_prefix.as_ref(), b"ctx");

        let config = VacmBuilder::new()
            .access(
                "test_group",
                SecurityModel::Usm,
                SecurityLevel::AuthNoPriv,
                |entry| entry.context_prefix("ctx").read_view("first"),
            )
            .replace_access(
                "test_group",
                SecurityModel::Usm,
                SecurityLevel::AuthNoPriv,
                |entry| {
                    entry
                        .context_prefix("ctx")
                        .context_match_prefix()
                        .read_view("replacement")
                },
            )
            .build()
            .unwrap();
        assert_eq!(
            config
                .get_access(
                    b"test_group",
                    b"ctx/child",
                    SecurityModel::Usm,
                    SecurityLevel::AuthNoPriv,
                )
                .unwrap()
                .read_view
                .as_ref(),
            b"replacement"
        );
    }

    #[test]
    fn absent_group_and_view_references_remain_valid_configuration() {
        let config = VacmBuilder::new()
            .access(
                "unmapped_group",
                SecurityModel::Usm,
                SecurityLevel::NoAuthNoPriv,
                |entry| entry.read_view("undefined_view"),
            )
            .build()
            .unwrap();
        let access = config
            .get_access(
                b"unmapped_group",
                b"",
                SecurityModel::Usm,
                SecurityLevel::NoAuthNoPriv,
            )
            .unwrap();
        assert!(!config.check_access(Some(&access.read_view), &oid!(1, 3, 6, 1)));
    }

    #[test]
    fn authpriv_user_can_have_distinct_authnopriv_and_authpriv_access() {
        let config = VacmBuilder::new()
            .group("operator", SecurityModel::Usm, "operators")
            .access(
                "operators",
                SecurityModel::Usm,
                SecurityLevel::AuthNoPriv,
                |access| access.read_view("read"),
            )
            .access(
                "operators",
                SecurityModel::Usm,
                SecurityLevel::AuthPriv,
                |access| access.read_view("read").write_view("write"),
            )
            .view("read", |view| view.include(oid!(1, 3, 6)))
            .view("write", |view| view.include(oid!(1, 3, 6, 1, 4, 1)))
            .build()
            .unwrap();
        let group = config.get_group(SecurityModel::Usm, b"operator").unwrap();

        assert!(
            config
                .get_access(group, b"", SecurityModel::Usm, SecurityLevel::NoAuthNoPriv,)
                .is_none()
        );
        let authenticated = config
            .get_access(group, b"", SecurityModel::Usm, SecurityLevel::AuthNoPriv)
            .unwrap();
        assert_eq!(authenticated.read_view.as_ref(), b"read");
        assert!(authenticated.write_view.is_empty());
        let private = config
            .get_access(group, b"", SecurityModel::Usm, SecurityLevel::AuthPriv)
            .unwrap();
        assert_eq!(private.read_view.as_ref(), b"read");
        assert_eq!(private.write_view.as_ref(), b"write");
    }

    // RFC 3415 Section 4 preference order tests
    // The vacmAccessTable DESCRIPTION specifies a 4-tier preference order:
    // 1. Prefer specific securityModel over Any
    // 2. Prefer a contextPrefix identical to the request contextName
    // 3. Prefer longer contextPrefix
    // 4. Prefer higher securityLevel

    #[test]
    fn test_vacm_access_prefers_specific_security_model_over_any() {
        // Tier 1: Specific securityModel should be preferred over Any
        let mut config = VacmConfig::new();

        // Add entry with Any security model
        config
            .add_access(VacmAccessEntry {
                group_name: Bytes::from_static(b"test_group"),
                context_prefix: Bytes::new(),
                security_model: VacmSecurityModel::Any,
                security_level: SecurityLevel::NoAuthNoPriv,
                context_match: ContextMatch::Exact,
                read_view: Bytes::from_static(b"any_view"),
                write_view: Bytes::new(),
                notify_view: Bytes::new(),
            })
            .unwrap();

        // Add entry with specific V2c security model
        config
            .add_access(VacmAccessEntry {
                group_name: Bytes::from_static(b"test_group"),
                context_prefix: Bytes::new(),
                security_model: SecurityModel::V2c.into(),
                security_level: SecurityLevel::NoAuthNoPriv,
                context_match: ContextMatch::Exact,
                read_view: Bytes::from_static(b"v2c_view"),
                write_view: Bytes::new(),
                notify_view: Bytes::new(),
            })
            .unwrap();

        // Query with V2c - should get the specific V2c entry
        let access = config
            .get_access(
                b"test_group",
                b"",
                SecurityModel::V2c,
                SecurityLevel::NoAuthNoPriv,
            )
            .expect("should find access entry");
        assert_eq!(
            access.read_view,
            Bytes::from_static(b"v2c_view"),
            "should prefer specific security model over Any"
        );

        // Query with V1 - the wildcard entry remains the fallback.
        let access = config
            .get_access(
                b"test_group",
                b"",
                SecurityModel::V1,
                SecurityLevel::NoAuthNoPriv,
            )
            .expect("should fall back to wildcard access entry");
        assert_eq!(access.read_view, Bytes::from_static(b"any_view"));
    }

    #[test]
    fn test_vacm_access_prefers_identical_context_prefix() {
        // Tier 2: a contextPrefix identical to contextName is preferred even
        // when the row's contextMatch column is Prefix.
        let mut config = VacmConfig::new();

        // A shorter prefix requires a higher security level.
        config
            .add_access(VacmAccessEntry {
                group_name: Bytes::from_static(b"test_group"),
                context_prefix: Bytes::from_static(b"c"),
                security_model: VacmSecurityModel::Any,
                security_level: SecurityLevel::AuthPriv,
                context_match: ContextMatch::Prefix,
                read_view: Bytes::from_static(b"short_high_view"),
                write_view: Bytes::new(),
                notify_view: Bytes::new(),
            })
            .unwrap();

        // Prefix mode still has an identical contextPrefix for context "ctx".
        config
            .add_access(VacmAccessEntry {
                group_name: Bytes::from_static(b"test_group"),
                context_prefix: Bytes::from_static(b"ctx"),
                security_model: VacmSecurityModel::Any,
                security_level: SecurityLevel::NoAuthNoPriv,
                context_match: ContextMatch::Prefix,
                read_view: Bytes::from_static(b"identical_view"),
                write_view: Bytes::new(),
                notify_view: Bytes::new(),
            })
            .unwrap();

        let access = config
            .get_access(
                b"test_group",
                b"ctx",
                SecurityModel::V2c,
                SecurityLevel::AuthPriv,
            )
            .expect("should find access entry");
        assert_eq!(
            access.read_view,
            Bytes::from_static(b"identical_view"),
            "an identical contextPrefix has RFC preference"
        );
    }

    #[test]
    fn test_vacm_access_prefers_longer_context_prefix() {
        // Tier 3: Longer contextPrefix should be preferred
        let mut config = VacmConfig::new();

        // Add entry with shorter context prefix
        config
            .add_access(VacmAccessEntry {
                group_name: Bytes::from_static(b"test_group"),
                context_prefix: Bytes::from_static(b"ctx"),
                security_model: VacmSecurityModel::Any,
                security_level: SecurityLevel::NoAuthNoPriv,
                context_match: ContextMatch::Prefix,
                read_view: Bytes::from_static(b"short_view"),
                write_view: Bytes::new(),
                notify_view: Bytes::new(),
            })
            .unwrap();

        // Add entry with longer context prefix
        config
            .add_access(VacmAccessEntry {
                group_name: Bytes::from_static(b"test_group"),
                context_prefix: Bytes::from_static(b"ctx_longer"),
                security_model: VacmSecurityModel::Any,
                security_level: SecurityLevel::NoAuthNoPriv,
                context_match: ContextMatch::Prefix,
                read_view: Bytes::from_static(b"long_view"),
                write_view: Bytes::new(),
                notify_view: Bytes::new(),
            })
            .unwrap();

        // Query with context that matches both - should get the longer prefix
        let access = config
            .get_access(
                b"test_group",
                b"ctx_longer_suffix",
                SecurityModel::V2c,
                SecurityLevel::NoAuthNoPriv,
            )
            .expect("should find access entry");
        assert_eq!(
            access.read_view,
            Bytes::from_static(b"long_view"),
            "should prefer longer context prefix"
        );
    }

    #[test]
    fn test_vacm_access_prefers_higher_security_level() {
        // Tier 4: Higher securityLevel should be preferred
        let mut config = VacmConfig::new();

        // Add entry with NoAuthNoPriv
        config
            .add_access(VacmAccessEntry {
                group_name: Bytes::from_static(b"test_group"),
                context_prefix: Bytes::new(),
                security_model: VacmSecurityModel::Any,
                security_level: SecurityLevel::NoAuthNoPriv,
                context_match: ContextMatch::Exact,
                read_view: Bytes::from_static(b"noauth_view"),
                write_view: Bytes::new(),
                notify_view: Bytes::new(),
            })
            .unwrap();

        // Add entry with AuthNoPriv
        config
            .add_access(VacmAccessEntry {
                group_name: Bytes::from_static(b"test_group"),
                context_prefix: Bytes::new(),
                security_model: VacmSecurityModel::Any,
                security_level: SecurityLevel::AuthNoPriv,
                context_match: ContextMatch::Exact,
                read_view: Bytes::from_static(b"auth_view"),
                write_view: Bytes::new(),
                notify_view: Bytes::new(),
            })
            .unwrap();

        // Add entry with AuthPriv
        config
            .add_access(VacmAccessEntry {
                group_name: Bytes::from_static(b"test_group"),
                context_prefix: Bytes::new(),
                security_model: VacmSecurityModel::Any,
                security_level: SecurityLevel::AuthPriv,
                context_match: ContextMatch::Exact,
                read_view: Bytes::from_static(b"authpriv_view"),
                write_view: Bytes::new(),
                notify_view: Bytes::new(),
            })
            .unwrap();

        for (level, expected_view) in [
            (SecurityLevel::NoAuthNoPriv, b"noauth_view".as_slice()),
            (SecurityLevel::AuthNoPriv, b"auth_view".as_slice()),
            (SecurityLevel::AuthPriv, b"authpriv_view".as_slice()),
        ] {
            let access = config
                .get_access(b"test_group", b"", SecurityModel::V2c, level)
                .expect("should find access entry");
            assert_eq!(access.read_view.as_ref(), expected_view);
        }
    }

    #[test]
    fn test_vacm_access_preference_tier_ordering() {
        // Test that tier 1 takes precedence over tier 2, which takes precedence
        // over tier 3, which takes precedence over tier 4.
        let mut config = VacmConfig::new();

        // Entry: Any model, prefix match, short prefix, high security
        config
            .add_access(VacmAccessEntry {
                group_name: Bytes::from_static(b"test_group"),
                context_prefix: Bytes::from_static(b"ctx"),
                security_model: VacmSecurityModel::Any,
                security_level: SecurityLevel::AuthPriv, // highest security
                context_match: ContextMatch::Prefix,
                read_view: Bytes::from_static(b"any_prefix_short_high"),
                write_view: Bytes::new(),
                notify_view: Bytes::new(),
            })
            .unwrap();

        // Entry: Specific model, prefix match, short prefix, low security
        // Tier 1 (specific model) should beat tier 4 (high security)
        config
            .add_access(VacmAccessEntry {
                group_name: Bytes::from_static(b"test_group"),
                context_prefix: Bytes::from_static(b"ctx"),
                security_model: SecurityModel::V2c.into(),
                security_level: SecurityLevel::NoAuthNoPriv,
                context_match: ContextMatch::Prefix,
                read_view: Bytes::from_static(b"v2c_prefix_short_low"),
                write_view: Bytes::new(),
                notify_view: Bytes::new(),
            })
            .unwrap();

        // Query - specific model (V2c) should win over Any even though Any has higher security
        let access = config
            .get_access(
                b"test_group",
                b"ctx_test",
                SecurityModel::V2c,
                SecurityLevel::AuthPriv,
            )
            .expect("should find access entry");
        assert_eq!(
            access.read_view,
            Bytes::from_static(b"v2c_prefix_short_low"),
            "tier 1 (specific model) should take precedence over tier 4 (security level)"
        );
    }

    #[test]
    fn test_vacm_access_preference_prefix_length_over_security() {
        // Tier 3 (longer prefix) should beat tier 4 (higher security)
        let mut config = VacmConfig::new();

        // Entry: short prefix with high security
        config
            .add_access(VacmAccessEntry {
                group_name: Bytes::from_static(b"test_group"),
                context_prefix: Bytes::from_static(b"ctx"),
                security_model: VacmSecurityModel::Any,
                security_level: SecurityLevel::AuthPriv,
                context_match: ContextMatch::Prefix,
                read_view: Bytes::from_static(b"short_high_sec"),
                write_view: Bytes::new(),
                notify_view: Bytes::new(),
            })
            .unwrap();

        // Entry: longer prefix with low security
        config
            .add_access(VacmAccessEntry {
                group_name: Bytes::from_static(b"test_group"),
                context_prefix: Bytes::from_static(b"ctx_test"),
                security_model: VacmSecurityModel::Any,
                security_level: SecurityLevel::NoAuthNoPriv,
                context_match: ContextMatch::Prefix,
                read_view: Bytes::from_static(b"long_low_sec"),
                write_view: Bytes::new(),
                notify_view: Bytes::new(),
            })
            .unwrap();

        // Query - longer prefix should win even though short prefix has higher security
        let access = config
            .get_access(
                b"test_group",
                b"ctx_test_suffix",
                SecurityModel::V2c,
                SecurityLevel::AuthPriv,
            )
            .expect("should find access entry");
        assert_eq!(
            access.read_view,
            Bytes::from_static(b"long_low_sec"),
            "tier 3 (longer prefix) should take precedence over tier 4 (security level)"
        );
    }

    #[test]
    fn test_vacm_access_all_tiers_combined() {
        // Test with multiple entries that differ in all tiers
        let mut config = VacmConfig::new();

        // Entry 1: Any, prefix, short, NoAuth
        config
            .add_access(VacmAccessEntry {
                group_name: Bytes::from_static(b"test_group"),
                context_prefix: Bytes::from_static(b"a"),
                security_model: VacmSecurityModel::Any,
                security_level: SecurityLevel::NoAuthNoPriv,
                context_match: ContextMatch::Prefix,
                read_view: Bytes::from_static(b"entry1"),
                write_view: Bytes::new(),
                notify_view: Bytes::new(),
            })
            .unwrap();

        // Entry 2: V2c (specific), exact, short, NoAuth - should win for "a" context
        config
            .add_access(VacmAccessEntry {
                group_name: Bytes::from_static(b"test_group"),
                context_prefix: Bytes::from_static(b"a"),
                security_model: SecurityModel::V2c.into(),
                security_level: SecurityLevel::NoAuthNoPriv,
                context_match: ContextMatch::Exact,
                read_view: Bytes::from_static(b"entry2"),
                write_view: Bytes::new(),
                notify_view: Bytes::new(),
            })
            .unwrap();

        let access = config
            .get_access(
                b"test_group",
                b"a",
                SecurityModel::V2c,
                SecurityLevel::NoAuthNoPriv,
            )
            .expect("should find access entry");
        assert_eq!(
            access.read_view,
            Bytes::from_static(b"entry2"),
            "specific model + exact match should win"
        );
    }

    // Tests that verify preference ordering is independent of insertion order
    #[test]
    fn test_vacm_access_context_modes_and_selection_are_insertion_independent() {
        let exact = VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::from_static(b"ctx"),
            security_model: VacmSecurityModel::Any,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_match: ContextMatch::Exact,
            read_view: Bytes::from_static(b"exact_view"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        };
        let prefix = VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::from_static(b"ctx/"),
            security_model: VacmSecurityModel::Any,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_match: ContextMatch::Prefix,
            read_view: Bytes::from_static(b"prefix_view"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        };

        for rows in [
            [exact.clone(), prefix.clone()],
            [prefix.clone(), exact.clone()],
        ] {
            let mut config = VacmConfig::new();
            for row in rows {
                config.add_access(row).unwrap();
            }

            assert_eq!(
                config
                    .get_access(
                        b"test_group",
                        b"ctx",
                        SecurityModel::V2c,
                        SecurityLevel::NoAuthNoPriv,
                    )
                    .unwrap()
                    .read_view
                    .as_ref(),
                b"exact_view"
            );
            assert_eq!(
                config
                    .get_access(
                        b"test_group",
                        b"ctx/child",
                        SecurityModel::V2c,
                        SecurityLevel::NoAuthNoPriv,
                    )
                    .unwrap()
                    .read_view
                    .as_ref(),
                b"prefix_view"
            );
        }
    }

    #[test]
    fn test_vacm_access_higher_security_wins_regardless_of_insertion_order() {
        // Add higher security first, lower second - higher should still win
        let mut config = VacmConfig::new();

        config
            .add_access(VacmAccessEntry {
                group_name: Bytes::from_static(b"test_group"),
                context_prefix: Bytes::new(),
                security_model: VacmSecurityModel::Any,
                security_level: SecurityLevel::AuthPriv,
                context_match: ContextMatch::Exact,
                read_view: Bytes::from_static(b"authpriv_view"),
                write_view: Bytes::new(),
                notify_view: Bytes::new(),
            })
            .unwrap();

        config
            .add_access(VacmAccessEntry {
                group_name: Bytes::from_static(b"test_group"),
                context_prefix: Bytes::new(),
                security_model: VacmSecurityModel::Any,
                security_level: SecurityLevel::NoAuthNoPriv,
                context_match: ContextMatch::Exact,
                read_view: Bytes::from_static(b"noauth_view"),
                write_view: Bytes::new(),
                notify_view: Bytes::new(),
            })
            .unwrap();

        let access = config
            .get_access(
                b"test_group",
                b"",
                SecurityModel::V2c,
                SecurityLevel::AuthPriv,
            )
            .expect("should find access entry");
        assert_eq!(
            access.read_view,
            Bytes::from_static(b"authpriv_view"),
            "higher security level should win regardless of insertion order"
        );
    }

    proptest! {
        #[test]
        fn access_selection_is_independent_of_insertion_order(order_keys in any::<[u32; 4]>()) {
            let rows = [
                access_entry(
                    b"c",
                    VacmSecurityModel::Any,
                    SecurityLevel::NoAuthNoPriv,
                    ContextMatch::Prefix,
                    b"any_short",
                ),
                access_entry(
                    b"ctx",
                    VacmSecurityModel::Any,
                    SecurityLevel::NoAuthNoPriv,
                    ContextMatch::Prefix,
                    b"any_identical",
                ),
                access_entry(
                    b"c",
                    SecurityModel::V2c.into(),
                    SecurityLevel::AuthPriv,
                    ContextMatch::Prefix,
                    b"exact_model_short_high",
                ),
                access_entry(
                    b"ctx",
                    SecurityModel::V2c.into(),
                    SecurityLevel::AuthNoPriv,
                    ContextMatch::Prefix,
                    b"winner",
                ),
            ];
            let mut order = [0, 1, 2, 3];
            order.sort_by_key(|&index| (order_keys[index], index));

            let mut config = VacmConfig::new();
            for index in order {
                config.add_access(rows[index].clone()).unwrap();
            }

            prop_assert_eq!(
                config
                    .get_access(
                        b"test_group",
                        b"ctx",
                        SecurityModel::V2c,
                        SecurityLevel::AuthPriv,
                    )
                    .unwrap()
                    .read_view
                    .as_ref(),
                b"winner"
            );
        }

        #[test]
        fn equal_length_masked_view_uses_lexicographically_greatest_subtree(
            first_arc in 0u32..=255,
            second_arc in 0u32..=255,
            query_arc in any::<u32>(),
            first_included in any::<bool>(),
            second_included in any::<bool>(),
            reverse in any::<bool>(),
        ) {
            prop_assume!(first_arc != second_arc);
            let first = Oid::new([1, 3, 6, 1, 2, 1, 5, first_arc]);
            let second = Oid::new([1, 3, 6, 1, 2, 1, 5, second_arc]);
            let query = Oid::new([1, 3, 6, 1, 2, 1, 5, query_arc]);
            let add = |view: View, oid: Oid, included: bool| {
                if included {
                    view.include_masked(oid, vec![0xfe])
                } else {
                    view.exclude_masked(oid, vec![0xfe])
                }
            };
            let view = if reverse {
                add(
                    add(View::new(), second, second_included),
                    first,
                    first_included,
                )
            } else {
                add(
                    add(View::new(), first, first_included),
                    second,
                    second_included,
                )
            };
            let expected = if first_arc > second_arc {
                first_included
            } else {
                second_included
            };

            prop_assert_eq!(view.contains(&query), expected);
        }
    }
}
