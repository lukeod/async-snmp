//! View-based Access Control Model (RFC 3415).
//!
//! VACM controls access to MIB objects based on who is making the request
//! and what they are trying to access. It implements fine-grained access control
//! through a three-table architecture.
//!
//! # Overview
//!
//! VACM (View-based Access Control Model) is the standard access control mechanism
//! for SNMPv3, though it can also be used with SNMPv1/v2c. It answers the question:
//! "Can this user perform this operation on this OID?"
//!
//! # Architecture
//!
//! VACM controls access through three tables:
//!
//! 1. **Security-to-Group Table**: Maps (securityModel, securityName) to groupName.
//!    This groups users/communities with similar access rights.
//!
//! 2. **Access Table**: Maps (groupName, contextPrefix, securityModel, securityLevel)
//!    to view names for read, write, and notify operations.
//!
//! 3. **View Tree Family Table**: Defines views as collections of OID subtrees,
//!    with optional inclusion/exclusion and wildcard masks.
//!
//! # Basic Example
//!
//! Configure read-only access for "public" community:
//!
//! ```rust
//! use async_snmp::agent::{Agent, SecurityModel, VacmBuilder};
//! use async_snmp::oid;
//!
//! # fn example() {
//! let vacm = VacmBuilder::new()
//!     // Map "public" community to "readonly_group"
//!     .group("public", SecurityModel::V2c, "readonly_group")
//!     // Grant read access to full_view
//!     .access("readonly_group", |a| a.read_view("full_view"))
//!     // Define what OIDs are in full_view
//!     .view("full_view", |v| v.include(oid!(1, 3, 6, 1)))
//!     .build();
//! # }
//! ```
//!
//! # Read/Write Access Example
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
//!     .access("readers", |a| a
//!         .read_view("system_view"))
//!
//!     // Writers can read everything and write to ifAdminStatus
//!     .access("writers", |a| a
//!         .read_view("full_view")
//!         .write_view("if_admin_view"))
//!
//!     // Admins require encryption and can read/write everything
//!     .access("admins", |a| a
//!         .security_model(SecurityModel::Usm)
//!         .security_level(SecurityLevel::AuthPriv)
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
//!     .build();
//! # }
//! ```
//!
//! # View Exclusions
//!
//! Views can exclude specific subtrees from a broader include:
//!
//! ```rust
//! use async_snmp::agent::View;
//! use async_snmp::oid;
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
//! # Wildcard Masks
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
//! # Integration with Agent
//!
//! Use [`AgentBuilder::vacm()`](super::AgentBuilder::vacm) to configure VACM:
//!
//! ```rust,no_run
//! use async_snmp::agent::{Agent, SecurityModel};
//! use async_snmp::oid;
//!
//! # async fn example() -> Result<(), async_snmp::Error> {
//! let agent = Agent::builder()
//!     .bind("0.0.0.0:161")
//!     .community(b"public")
//!     .community(b"private")
//!     .vacm(|v| v
//!         .group("public", SecurityModel::V2c, "readonly")
//!         .group("private", SecurityModel::V2c, "readwrite")
//!         .access("readonly", |a| a.read_view("all"))
//!         .access("readwrite", |a| a.read_view("all").write_view("all"))
//!         .view("all", |v| v.include(oid!(1, 3, 6, 1))))
//!     .build()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Access Denied Behavior
//!
//! When VACM denies access:
//! - **SNMPv1**: Returns `noSuchName` error
//! - **SNMPv2c/v3 GET**: Returns `noAccess` error or `NoSuchObject` per RFC 3416
//! - **SNMPv2c/v3 SET**: Returns `noAccess` error

use std::collections::HashMap;

use bytes::Bytes;

use crate::message::SecurityLevel;
use crate::oid::Oid;

/// Security model identifiers (RFC 3411).
///
/// Used to specify which SNMP version/security mechanism a mapping applies to.
///
/// # Example
///
/// ```rust
/// use async_snmp::agent::{SecurityModel, VacmBuilder};
///
/// let vacm = VacmBuilder::new()
///     // Map communities to groups by security model
///     .group("public", SecurityModel::V2c, "readonly")
///     .group("admin", SecurityModel::Usm, "admin_group")
///     // Any model can match as a fallback
///     .group("universal", SecurityModel::Any, "universal_group")
///     .build();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityModel {
    /// Wildcard for VACM matching (matches any model).
    ///
    /// Use this when the same mapping should apply regardless of SNMP version.
    Any = 0,
    /// SNMPv1.
    V1 = 1,
    /// SNMPv2c.
    V2c = 2,
    /// SNMPv3 User-based Security Model.
    Usm = 3,
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
    /// Create a new empty view.
    ///
    /// An empty view contains no OIDs. Add subtrees with [`include()`](View::include)
    /// or [`exclude()`](View::exclude).
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an included subtree to the view.
    ///
    /// All OIDs starting with `oid` will be included in the view,
    /// unless excluded by a later [`exclude()`](View::exclude) call.
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
    /// OIDs starting with `oid` will be excluded, even if they match
    /// an included subtree. Exclusions take precedence.
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
    /// Per RFC 3415 Section 5, an OID is in the view if:
    /// - At least one included subtree matches, AND
    /// - No excluded subtree matches
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
    pub fn contains(&self, oid: &Oid) -> bool {
        let mut dominated_by_include = false;
        let mut dominated_by_exclude = false;

        for subtree in &self.subtrees {
            if subtree.matches(oid) {
                if subtree.included {
                    dominated_by_include = true;
                } else {
                    dominated_by_exclude = true;
                }
            }
        }

        // Included and not excluded
        dominated_by_include && !dominated_by_exclude
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
    /// Check if an OID matches this subtree (with mask).
    pub fn matches(&self, oid: &Oid) -> bool {
        let subtree_arcs = self.oid.arcs();
        let oid_arcs = oid.arcs();

        // OID must be at least as long as subtree
        if oid_arcs.len() < subtree_arcs.len() {
            return false;
        }

        // Check each arc against mask
        for (i, &subtree_arc) in subtree_arcs.iter().enumerate() {
            let mask_bit = if i / 8 < self.mask.len() {
                (self.mask[i / 8] >> (7 - (i % 8))) & 1
            } else {
                1 // Default: exact match required
            };

            if mask_bit == 1 && oid_arcs[i] != subtree_arc {
                return false;
            }
            // mask_bit == 0: wildcard, any value matches
        }

        true
    }
}

/// Access table entry.
#[derive(Debug, Clone)]
pub struct VacmAccessEntry {
    /// Group name this entry applies to.
    pub group_name: Bytes,
    /// Context prefix for matching.
    pub context_prefix: Bytes,
    /// Security model (or Any for wildcard).
    pub security_model: SecurityModel,
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
///     .access("admin_group", |a| a
///         .security_model(SecurityModel::Usm)
///         .security_level(SecurityLevel::AuthPriv)
///         .read_view("full_view")
///         .write_view("config_view")
///         .notify_view("trap_view"))
///     .view("full_view", |v| v.include(oid!(1, 3, 6, 1)))
///     .view("config_view", |v| v.include(oid!(1, 3, 6, 1, 4, 1)))
///     .view("trap_view", |v| v.include(oid!(1, 3, 6, 1)))
///     .build();
/// ```
pub struct AccessEntryBuilder {
    group_name: Bytes,
    context_prefix: Bytes,
    security_model: SecurityModel,
    security_level: SecurityLevel,
    context_match: ContextMatch,
    read_view: Bytes,
    write_view: Bytes,
    notify_view: Bytes,
}

impl AccessEntryBuilder {
    /// Create a new access entry builder for a group.
    pub fn new(group_name: impl Into<Bytes>) -> Self {
        Self {
            group_name: group_name.into(),
            context_prefix: Bytes::new(),
            security_model: SecurityModel::Any,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_match: ContextMatch::Exact,
            read_view: Bytes::new(),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        }
    }

    /// Set the context prefix for matching.
    ///
    /// Context is an SNMPv3 concept that allows partitioning MIB views.
    /// Most deployments use an empty context (the default).
    pub fn context_prefix(mut self, prefix: impl Into<Bytes>) -> Self {
        self.context_prefix = prefix.into();
        self
    }

    /// Set the security model this entry applies to.
    ///
    /// Default is [`SecurityModel::Any`] which matches all models.
    pub fn security_model(mut self, model: SecurityModel) -> Self {
        self.security_model = model;
        self
    }

    /// Set the minimum security level required.
    ///
    /// Requests with lower security levels will be denied access.
    /// Default is [`SecurityLevel::NoAuthNoPriv`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::agent::{SecurityModel, VacmBuilder};
    /// use async_snmp::message::SecurityLevel;
    /// use async_snmp::oid;
    ///
    /// let vacm = VacmBuilder::new()
    ///     .group("admin", SecurityModel::Usm, "secure_group")
    ///     .access("secure_group", |a| a
    ///         // Require authentication and encryption
    ///         .security_level(SecurityLevel::AuthPriv)
    ///         .read_view("full_view"))
    ///     .view("full_view", |v| v.include(oid!(1, 3, 6, 1)))
    ///     .build();
    /// ```
    pub fn security_level(mut self, level: SecurityLevel) -> Self {
        self.security_level = level;
        self
    }

    /// Set context matching to prefix mode.
    ///
    /// When enabled, the context prefix is matched against the start of
    /// the request context name rather than requiring an exact match.
    /// The default is exact matching.
    pub fn context_match_prefix(mut self) -> Self {
        self.context_match = ContextMatch::Prefix;
        self
    }

    /// Set the read view name.
    ///
    /// The view must be defined with [`VacmBuilder::view()`].
    /// If not set, read operations are denied.
    pub fn read_view(mut self, view: impl Into<Bytes>) -> Self {
        self.read_view = view.into();
        self
    }

    /// Set the write view name.
    ///
    /// The view must be defined with [`VacmBuilder::view()`].
    /// If not set, write (SET) operations are denied.
    pub fn write_view(mut self, view: impl Into<Bytes>) -> Self {
        self.write_view = view.into();
        self
    }

    /// Set the notify view name.
    ///
    /// Used for trap/inform generation (not access control).
    /// The view must be defined with [`VacmBuilder::view()`].
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
#[derive(Debug, Clone, Default)]
pub struct VacmConfig {
    /// (securityModel, securityName) → groupName
    security_to_group: HashMap<(SecurityModel, Bytes), Bytes>,
    /// Access table entries.
    access_entries: Vec<VacmAccessEntry>,
    /// viewName → View
    views: HashMap<Bytes, View>,
}

impl VacmConfig {
    /// Create a new empty VACM configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Map a security name to a group for a specific security model.
    pub fn add_group(
        &mut self,
        security_name: impl Into<Bytes>,
        security_model: SecurityModel,
        group_name: impl Into<Bytes>,
    ) {
        self.security_to_group
            .insert((security_model, security_name.into()), group_name.into());
    }

    /// Add an access entry.
    pub fn add_access(&mut self, entry: VacmAccessEntry) {
        self.access_entries.push(entry);
    }

    /// Add a view.
    pub fn add_view(&mut self, name: impl Into<Bytes>, view: View) {
        self.views.insert(name.into(), view);
    }

    /// Resolve group name for a request.
    pub fn get_group(&self, model: SecurityModel, name: &[u8]) -> Option<&Bytes> {
        let name_bytes = Bytes::copy_from_slice(name);
        // Try exact match first
        self.security_to_group
            .get(&(model, name_bytes.clone()))
            // Fall back to Any security model
            .or_else(|| {
                self.security_to_group
                    .get(&(SecurityModel::Any, name_bytes))
            })
    }

    /// Get access entry for context.
    ///
    /// Returns the best matching entry per RFC 3415 Section 4 (vacmAccessTable DESCRIPTION).
    /// Selection uses a 4-tier preference order:
    /// 1. Prefer specific securityModel over Any
    /// 2. Prefer exact contextMatch over prefix
    /// 3. Prefer longer contextPrefix
    /// 4. Prefer higher securityLevel
    pub fn get_access(
        &self,
        group: &[u8],
        context: &[u8],
        model: SecurityModel,
        level: SecurityLevel,
    ) -> Option<&VacmAccessEntry> {
        self.access_entries
            .iter()
            .filter(|e| {
                e.group_name.as_ref() == group
                    && self.context_matches(&e.context_prefix, context, e.context_match)
                    && (e.security_model == model || e.security_model == SecurityModel::Any)
                    && level >= e.security_level
            })
            .max_by_key(|e| {
                // RFC 3415 Section 4 preference order (tuple comparison is lexicographic)
                let model_score: u8 = if e.security_model == model { 1 } else { 0 };
                let match_score: u8 = if e.context_match == ContextMatch::Exact {
                    1
                } else {
                    0
                };
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
///     .access("readers", |a| a
///         .read_view("system_view"))
///     .access("admins", |a| a
///         .security_level(SecurityLevel::AuthPriv)
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
///     .build();
/// ```
pub struct VacmBuilder {
    config: VacmConfig,
}

impl VacmBuilder {
    /// Create a new VACM builder.
    pub fn new() -> Self {
        Self {
            config: VacmConfig::new(),
        }
    }

    /// Map a security name to a group.
    ///
    /// The security name is:
    /// - For SNMPv1/v2c: the community string
    /// - For SNMPv3: the USM username
    ///
    /// Multiple security names can map to the same group.
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
    ///     .build();
    /// ```
    pub fn group(
        mut self,
        security_name: impl Into<Bytes>,
        security_model: SecurityModel,
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
    ///     .access("readers", |a| a
    ///         .security_model(SecurityModel::V2c)
    ///         .security_level(SecurityLevel::NoAuthNoPriv)
    ///         .read_view("system_view")
    ///         // No write_view = read-only
    ///     )
    ///     .view("system_view", |v| v.include(oid!(1, 3, 6, 1, 2, 1, 1)))
    ///     .build();
    /// ```
    pub fn access<F>(mut self, group_name: impl Into<Bytes>, configure: F) -> Self
    where
        F: FnOnce(AccessEntryBuilder) -> AccessEntryBuilder,
    {
        let builder = AccessEntryBuilder::new(group_name);
        let entry = configure(builder).build();
        self.config.add_access(entry);
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
    ///     .build();
    /// ```
    pub fn view<F>(mut self, name: impl Into<Bytes>, configure: F) -> Self
    where
        F: FnOnce(View) -> View,
    {
        let view = configure(View::new());
        self.config.add_view(name, view);
        self
    }

    /// Build the VACM configuration.
    pub fn build(self) -> VacmConfig {
        self.config
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
    fn test_vacm_group_any_model() {
        let mut config = VacmConfig::new();
        config.add_group("universal", SecurityModel::Any, "universal_group");

        // Should match any security model
        assert_eq!(
            config.get_group(SecurityModel::V1, b"universal"),
            Some(&Bytes::from_static(b"universal_group"))
        );
        assert_eq!(
            config.get_group(SecurityModel::V2c, b"universal"),
            Some(&Bytes::from_static(b"universal_group"))
        );
    }

    #[test]
    fn test_vacm_access_lookup() {
        let mut config = VacmConfig::new();
        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"readonly_group"),
            context_prefix: Bytes::new(),
            security_model: SecurityModel::Any,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_match: ContextMatch::Exact,
            read_view: Bytes::from_static(b"full_view"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

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
        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"admin_group"),
            context_prefix: Bytes::new(),
            security_model: SecurityModel::Usm,
            security_level: SecurityLevel::AuthPriv, // Require encryption
            context_match: ContextMatch::Exact,
            read_view: Bytes::from_static(b"full_view"),
            write_view: Bytes::from_static(b"full_view"),
            notify_view: Bytes::new(),
        });

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
            .access("readonly_group", |a| {
                a.context_prefix("")
                    .security_model(SecurityModel::Any)
                    .security_level(SecurityLevel::NoAuthNoPriv)
                    .read_view("full_view")
            })
            .access("admin_group", |a| {
                a.security_model(SecurityModel::Usm)
                    .security_level(SecurityLevel::AuthPriv)
                    .read_view("full_view")
                    .write_view("full_view")
            })
            .view("full_view", |v| v.include(oid!(1, 3, 6, 1)))
            .build();

        assert!(config.get_group(SecurityModel::V2c, b"public").is_some());
        assert!(config.get_group(SecurityModel::Usm, b"admin").is_some());
    }

    // RFC 3415 Section 4 preference order tests
    // The vacmAccessTable DESCRIPTION specifies a 4-tier preference order:
    // 1. Prefer specific securityModel over Any
    // 2. Prefer exact contextMatch over prefix
    // 3. Prefer longer contextPrefix
    // 4. Prefer higher securityLevel

    #[test]
    fn test_vacm_access_prefers_specific_security_model_over_any() {
        // Tier 1: Specific securityModel should be preferred over Any
        let mut config = VacmConfig::new();

        // Add entry with Any security model
        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::new(),
            security_model: SecurityModel::Any,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_match: ContextMatch::Exact,
            read_view: Bytes::from_static(b"any_view"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

        // Add entry with specific V2c security model
        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::new(),
            security_model: SecurityModel::V2c,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_match: ContextMatch::Exact,
            read_view: Bytes::from_static(b"v2c_view"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

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
    }

    #[test]
    fn test_vacm_access_prefers_exact_context_match_over_prefix() {
        // Tier 2: Exact contextMatch should be preferred over prefix match
        let mut config = VacmConfig::new();

        // Add entry with prefix context match
        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::from_static(b"ctx"),
            security_model: SecurityModel::Any,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_match: ContextMatch::Prefix,
            read_view: Bytes::from_static(b"prefix_view"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

        // Add entry with exact context match (same prefix)
        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::from_static(b"ctx"),
            security_model: SecurityModel::Any,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_match: ContextMatch::Exact,
            read_view: Bytes::from_static(b"exact_view"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

        // Query with exact context "ctx" - should get the exact match entry
        let access = config
            .get_access(
                b"test_group",
                b"ctx",
                SecurityModel::V2c,
                SecurityLevel::NoAuthNoPriv,
            )
            .expect("should find access entry");
        assert_eq!(
            access.read_view,
            Bytes::from_static(b"exact_view"),
            "should prefer exact context match over prefix"
        );
    }

    #[test]
    fn test_vacm_access_prefers_longer_context_prefix() {
        // Tier 3: Longer contextPrefix should be preferred
        let mut config = VacmConfig::new();

        // Add entry with shorter context prefix
        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::from_static(b"ctx"),
            security_model: SecurityModel::Any,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_match: ContextMatch::Prefix,
            read_view: Bytes::from_static(b"short_view"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

        // Add entry with longer context prefix
        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::from_static(b"ctx_longer"),
            security_model: SecurityModel::Any,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_match: ContextMatch::Prefix,
            read_view: Bytes::from_static(b"long_view"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

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
        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::new(),
            security_model: SecurityModel::Any,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_match: ContextMatch::Exact,
            read_view: Bytes::from_static(b"noauth_view"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

        // Add entry with AuthNoPriv
        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::new(),
            security_model: SecurityModel::Any,
            security_level: SecurityLevel::AuthNoPriv,
            context_match: ContextMatch::Exact,
            read_view: Bytes::from_static(b"auth_view"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

        // Add entry with AuthPriv
        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::new(),
            security_model: SecurityModel::Any,
            security_level: SecurityLevel::AuthPriv,
            context_match: ContextMatch::Exact,
            read_view: Bytes::from_static(b"authpriv_view"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

        // Query with AuthPriv - should get the AuthPriv entry (highest matching)
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
            "should prefer higher security level"
        );
    }

    #[test]
    fn test_vacm_access_preference_tier_ordering() {
        // Test that tier 1 takes precedence over tier 2, which takes precedence
        // over tier 3, which takes precedence over tier 4.
        let mut config = VacmConfig::new();

        // Entry: Any model, prefix match, short prefix, high security
        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::from_static(b"ctx"),
            security_model: SecurityModel::Any,
            security_level: SecurityLevel::AuthPriv, // highest security
            context_match: ContextMatch::Prefix,
            read_view: Bytes::from_static(b"any_prefix_short_high"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

        // Entry: Specific model, prefix match, short prefix, low security
        // Tier 1 (specific model) should beat tier 4 (high security)
        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::from_static(b"ctx"),
            security_model: SecurityModel::V2c,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_match: ContextMatch::Prefix,
            read_view: Bytes::from_static(b"v2c_prefix_short_low"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

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
    fn test_vacm_access_preference_context_match_over_prefix_length() {
        // Tier 2 (exact match) should beat tier 3 (longer prefix)
        let mut config = VacmConfig::new();

        // Entry: prefix match with longer prefix
        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::from_static(b"context"),
            security_model: SecurityModel::Any,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_match: ContextMatch::Prefix,
            read_view: Bytes::from_static(b"long_prefix_view"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

        // Entry: exact match with shorter prefix
        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::from_static(b"ctx"),
            security_model: SecurityModel::Any,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_match: ContextMatch::Exact,
            read_view: Bytes::from_static(b"short_exact_view"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

        // Query with "ctx" - exact match should win even though it's shorter
        let access = config
            .get_access(
                b"test_group",
                b"ctx",
                SecurityModel::V2c,
                SecurityLevel::NoAuthNoPriv,
            )
            .expect("should find access entry");
        assert_eq!(
            access.read_view,
            Bytes::from_static(b"short_exact_view"),
            "tier 2 (exact match) should take precedence over tier 3 (longer prefix)"
        );
    }

    #[test]
    fn test_vacm_access_preference_prefix_length_over_security() {
        // Tier 3 (longer prefix) should beat tier 4 (higher security)
        let mut config = VacmConfig::new();

        // Entry: short prefix with high security
        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::from_static(b"ctx"),
            security_model: SecurityModel::Any,
            security_level: SecurityLevel::AuthPriv,
            context_match: ContextMatch::Prefix,
            read_view: Bytes::from_static(b"short_high_sec"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

        // Entry: longer prefix with low security
        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::from_static(b"ctx_test"),
            security_model: SecurityModel::Any,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_match: ContextMatch::Prefix,
            read_view: Bytes::from_static(b"long_low_sec"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

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
        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::from_static(b"a"),
            security_model: SecurityModel::Any,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_match: ContextMatch::Prefix,
            read_view: Bytes::from_static(b"entry1"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

        // Entry 2: V2c (specific), exact, short, NoAuth - should win for "a" context
        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::from_static(b"a"),
            security_model: SecurityModel::V2c,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_match: ContextMatch::Exact,
            read_view: Bytes::from_static(b"entry2"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

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
    fn test_vacm_access_exact_wins_regardless_of_insertion_order() {
        // Add exact first, prefix second - exact should still win
        let mut config = VacmConfig::new();

        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::from_static(b"ctx"),
            security_model: SecurityModel::Any,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_match: ContextMatch::Exact,
            read_view: Bytes::from_static(b"exact_view"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::from_static(b"ctx"),
            security_model: SecurityModel::Any,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_match: ContextMatch::Prefix,
            read_view: Bytes::from_static(b"prefix_view"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

        let access = config
            .get_access(
                b"test_group",
                b"ctx",
                SecurityModel::V2c,
                SecurityLevel::NoAuthNoPriv,
            )
            .expect("should find access entry");
        assert_eq!(
            access.read_view,
            Bytes::from_static(b"exact_view"),
            "exact match should win regardless of insertion order"
        );
    }

    #[test]
    fn test_vacm_access_higher_security_wins_regardless_of_insertion_order() {
        // Add higher security first, lower second - higher should still win
        let mut config = VacmConfig::new();

        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::new(),
            security_model: SecurityModel::Any,
            security_level: SecurityLevel::AuthPriv,
            context_match: ContextMatch::Exact,
            read_view: Bytes::from_static(b"authpriv_view"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

        config.add_access(VacmAccessEntry {
            group_name: Bytes::from_static(b"test_group"),
            context_prefix: Bytes::new(),
            security_model: SecurityModel::Any,
            security_level: SecurityLevel::NoAuthNoPriv,
            context_match: ContextMatch::Exact,
            read_view: Bytes::from_static(b"noauth_view"),
            write_view: Bytes::new(),
            notify_view: Bytes::new(),
        });

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
}
