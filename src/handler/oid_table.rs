//! OID table for implementing GETNEXT with sorted OID storage.

use crate::oid::Oid;

/// Helper for implementing GETNEXT with lexicographic OID ordering.
///
/// This struct simplifies implementing the `get_next` method of [`MibHandler`](super::MibHandler)
/// by maintaining a sorted list of OID-value pairs and providing efficient
/// lookup for the next OID.
///
/// # Example
///
/// ```rust
/// use async_snmp::handler::{MibHandler, RequestContext, GetResult, GetNextResult, OidTable, BoxFuture};
/// use async_snmp::{Oid, Value, VarBind, oid};
///
/// struct MyHandler {
///     table: OidTable<Value>,
/// }
///
/// impl MyHandler {
///     fn new() -> Self {
///         let mut table = OidTable::new();
///         table.insert(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(42));
///         table.insert(oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0), Value::OctetString("test".into()));
///         Self { table }
///     }
/// }
///
/// impl MibHandler for MyHandler {
///     fn get<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetResult> {
///         Box::pin(async move {
///             self.table.get(oid)
///                 .cloned()
///                 .map(GetResult::Value)
///                 .unwrap_or(GetResult::NoSuchObject)
///         })
///     }
///
///     fn get_next<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetNextResult> {
///         Box::pin(async move {
///             self.table.get_next(oid)
///                 .map(|(next_oid, value)| GetNextResult::Value(VarBind::new(next_oid.clone(), value.clone())))
///                 .unwrap_or(GetNextResult::EndOfMibView)
///         })
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct OidTable<V> {
    /// Entries are kept sorted by OID for efficient GETNEXT
    entries: Vec<(Oid, V)>,
}

impl<V> OidTable<V> {
    /// Create a new empty OID table.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Create an OID table with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
        }
    }

    /// Insert an OID-value pair, maintaining sorted order.
    ///
    /// If the OID already exists, its value is replaced.
    pub fn insert(&mut self, oid: Oid, value: V) {
        match self.entries.binary_search_by(|(o, _)| o.cmp(&oid)) {
            Ok(idx) => self.entries[idx].1 = value,
            Err(idx) => self.entries.insert(idx, (oid, value)),
        }
    }

    /// Remove an OID from the table.
    ///
    /// Returns the removed value if the OID was present.
    pub fn remove(&mut self, oid: &Oid) -> Option<V> {
        match self.entries.binary_search_by(|(o, _)| o.cmp(oid)) {
            Ok(idx) => Some(self.entries.remove(idx).1),
            Err(_) => None,
        }
    }

    /// Get the value for an exact OID match.
    pub fn get(&self, oid: &Oid) -> Option<&V> {
        match self.entries.binary_search_by(|(o, _)| o.cmp(oid)) {
            Ok(idx) => Some(&self.entries[idx].1),
            Err(_) => None,
        }
    }

    /// Get the lexicographically next OID and value after the given OID.
    ///
    /// Returns `None` if there are no OIDs greater than the given one.
    pub fn get_next(&self, oid: &Oid) -> Option<(&Oid, &V)> {
        match self.entries.binary_search_by(|(o, _)| o.cmp(oid)) {
            Ok(idx) => {
                // Exact match, return the next one
                self.entries.get(idx + 1).map(|(o, v)| (o, v))
            }
            Err(idx) => {
                // No exact match, return the entry at insertion point
                self.entries.get(idx).map(|(o, v)| (o, v))
            }
        }
    }

    /// Get the number of entries in the table.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries from the table.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Iterate over all OID-value pairs in lexicographic order.
    pub fn iter(&self) -> impl Iterator<Item = (&Oid, &V)> {
        self.entries.iter().map(|(o, v)| (o, v))
    }
}

impl<V> Default for OidTable<V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid;

    #[test]
    fn test_oid_table_insert_and_get() {
        let mut table: OidTable<i32> = OidTable::new();

        table.insert(oid!(1, 3, 6, 1, 2), 100);
        table.insert(oid!(1, 3, 6, 1, 1), 50);
        table.insert(oid!(1, 3, 6, 1, 3), 150);

        // Should maintain sorted order
        assert_eq!(table.get(&oid!(1, 3, 6, 1, 1)), Some(&50));
        assert_eq!(table.get(&oid!(1, 3, 6, 1, 2)), Some(&100));
        assert_eq!(table.get(&oid!(1, 3, 6, 1, 3)), Some(&150));
        assert_eq!(table.get(&oid!(1, 3, 6, 1, 4)), None);
    }

    #[test]
    fn test_oid_table_update_existing() {
        let mut table: OidTable<i32> = OidTable::new();

        table.insert(oid!(1, 3, 6, 1, 1), 50);
        table.insert(oid!(1, 3, 6, 1, 1), 100);

        assert_eq!(table.get(&oid!(1, 3, 6, 1, 1)), Some(&100));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_oid_table_get_next() {
        let mut table: OidTable<i32> = OidTable::new();

        table.insert(oid!(1, 3, 6, 1, 1), 50);
        table.insert(oid!(1, 3, 6, 1, 2), 100);
        table.insert(oid!(1, 3, 6, 1, 3), 150);

        // Before first
        let next = table.get_next(&oid!(1, 3, 6, 1, 0));
        assert!(next.is_some());
        assert_eq!(next.unwrap().0, &oid!(1, 3, 6, 1, 1));

        // Exact match returns next
        let next = table.get_next(&oid!(1, 3, 6, 1, 1));
        assert!(next.is_some());
        assert_eq!(next.unwrap().0, &oid!(1, 3, 6, 1, 2));

        // Between entries
        let next = table.get_next(&oid!(1, 3, 6, 1, 1, 5));
        assert!(next.is_some());
        assert_eq!(next.unwrap().0, &oid!(1, 3, 6, 1, 2));

        // After last
        let next = table.get_next(&oid!(1, 3, 6, 1, 3));
        assert!(next.is_none());

        let next = table.get_next(&oid!(1, 3, 6, 1, 4));
        assert!(next.is_none());
    }

    #[test]
    fn test_oid_table_remove() {
        let mut table: OidTable<i32> = OidTable::new();

        table.insert(oid!(1, 3, 6, 1, 1), 50);
        table.insert(oid!(1, 3, 6, 1, 2), 100);

        assert_eq!(table.remove(&oid!(1, 3, 6, 1, 1)), Some(50));
        assert_eq!(table.remove(&oid!(1, 3, 6, 1, 1)), None);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_oid_table_iter() {
        let mut table: OidTable<i32> = OidTable::new();

        table.insert(oid!(1, 3, 6, 1, 3), 150);
        table.insert(oid!(1, 3, 6, 1, 1), 50);
        table.insert(oid!(1, 3, 6, 1, 2), 100);

        let entries: Vec<_> = table.iter().collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].0, &oid!(1, 3, 6, 1, 1));
        assert_eq!(entries[1].0, &oid!(1, 3, 6, 1, 2));
        assert_eq!(entries[2].0, &oid!(1, 3, 6, 1, 3));
    }

    #[test]
    fn test_oid_table_empty() {
        let table: OidTable<i32> = OidTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert!(table.get_next(&oid!(1, 3, 6, 1)).is_none());
    }
}
