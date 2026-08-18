//! OID table for implementing GETNEXT with sorted OID storage.

use crate::oid::Oid;

/// Helper for implementing GETNEXT with lexicographic OID ordering.
///
/// Maintains a sorted list of OID-value pairs and efficiently finds the next
/// OID for [`MibHandler::get_next`](super::MibHandler::get_next).
///
/// For a static or otherwise already-collected table, prefer [`Iterator::collect`]
/// or [`FromIterator`] over repeated unsorted [`insert`](Self::insert) calls.
/// Bulk construction sorts once and retains the last value for duplicate OIDs.
///
/// # Example
///
/// ```rust
/// use async_snmp::handler::{MibHandler, RequestContext, GetResult, GetNextResult, HandlerResult, OidTable, BoxFuture};
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
///     fn get<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, HandlerResult<GetResult>> {
///         Box::pin(async move {
///             Ok(self.table.get(oid)
///                 .cloned()
///                 .map(GetResult::Value)
///                 .unwrap_or(GetResult::NoSuchObject))
///         })
///     }
///
///     fn get_next<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
///         Box::pin(async move {
///             Ok(self.table.get_next(oid)
///                 .map(|(next_oid, value)| GetNextResult::Value(VarBind::new(next_oid.clone(), value.clone())))
///                 .unwrap_or(GetNextResult::EndOfMibView))
///         })
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidTable<V> {
    /// Entries are kept sorted by OID for efficient GETNEXT
    entries: Vec<(Oid, V)>,
}

impl<V> OidTable<V> {
    /// Create an empty OID table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Create an OID table with pre-allocated capacity.
    #[must_use]
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

    /// Returns the value for an exact OID match.
    #[must_use]
    pub fn get(&self, oid: &Oid) -> Option<&V> {
        match self.entries.binary_search_by(|(o, _)| o.cmp(oid)) {
            Ok(idx) => Some(&self.entries[idx].1),
            Err(_) => None,
        }
    }

    /// Returns the lexicographically next OID and value after the given OID.
    ///
    /// Returns `None` if there are no OIDs greater than the given one.
    #[must_use]
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

    /// Returns the number of entries in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the table is empty.
    #[must_use]
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

impl<V> FromIterator<(Oid, V)> for OidTable<V> {
    /// Build a table by sorting all entries once.
    ///
    /// When an OID occurs more than once, the last value in iteration order is
    /// retained, matching repeated calls to [`OidTable::insert`].
    fn from_iter<T: IntoIterator<Item = (Oid, V)>>(iter: T) -> Self {
        let mut entries = iter.into_iter().collect::<Vec<_>>();
        // Stable sorting preserves iteration order among duplicate OIDs so the
        // final duplicate can replace the earlier values below.
        entries.sort_by(|(left, _), (right, _)| left.cmp(right));

        let mut deduplicated: Vec<(Oid, V)> = Vec::with_capacity(entries.len());
        for entry in entries {
            if let Some(previous) = deduplicated.last_mut()
                && previous.0 == entry.0
            {
                *previous = entry;
                continue;
            }
            deduplicated.push(entry);
        }
        Self {
            entries: deduplicated,
        }
    }
}

impl<V> Extend<(Oid, V)> for OidTable<V> {
    /// Add entries in bulk, retaining the last value for duplicate OIDs.
    fn extend<T: IntoIterator<Item = (Oid, V)>>(&mut self, iter: T) {
        let existing = std::mem::take(&mut self.entries);
        *self = existing.into_iter().chain(iter).collect();
    }
}

impl<V> IntoIterator for OidTable<V> {
    type Item = (Oid, V);
    type IntoIter = std::vec::IntoIter<(Oid, V)>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<'a, V> IntoIterator for &'a OidTable<V> {
    type Item = (&'a Oid, &'a V);
    type IntoIter =
        std::iter::Map<std::slice::Iter<'a, (Oid, V)>, fn(&'a (Oid, V)) -> (&'a Oid, &'a V)>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter().map(|(o, v)| (o, v))
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

    #[test]
    fn from_iter_sorts_once_and_retains_last_duplicate() {
        let first = oid!(1, 3, 6, 1, 1);
        let second = oid!(1, 3, 6, 1, 2);
        let third = oid!(1, 3, 6, 1, 3);
        let table = OidTable::from_iter([
            (third.clone(), "third"),
            (first.clone(), "old first"),
            (second.clone(), "second"),
            (first.clone(), "new first"),
        ]);

        assert_eq!(table.len(), 3);
        assert_eq!(table.get(&first), Some(&"new first"));
        assert_eq!(
            table.iter().map(|(oid, _)| oid).collect::<Vec<_>>(),
            [&first, &second, &third]
        );
    }

    #[test]
    fn extend_uses_last_new_value_and_owned_iteration_is_sorted() {
        let first = oid!(1, 3, 6, 1, 1);
        let second = oid!(1, 3, 6, 1, 2);
        let third = oid!(1, 3, 6, 1, 3);
        let mut table = OidTable::from_iter([(first.clone(), 1), (second.clone(), 2)]);

        table.extend([(third.clone(), 3), (first.clone(), 10), (first.clone(), 11)]);

        assert_eq!(
            table.into_iter().collect::<Vec<_>>(),
            [(first, 11), (second, 2), (third, 3)]
        );
    }
}
