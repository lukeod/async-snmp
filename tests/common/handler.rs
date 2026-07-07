//! BTreeMap-backed `MibHandler` for testing.
//!
//! Stores OID->Value mappings with correct lexicographic ordering
//! for GETNEXT operations.

use async_snmp::handler::{
    BoxFuture, GetNextResult, GetResult, MibHandler, RequestContext, SetResult,
};
use async_snmp::{Oid, Value, VarBind};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// A simple `MibHandler` backed by an in-memory `BTreeMap`.
///
/// Thread-safe for concurrent access. Supports GET, GETNEXT, and SET.
/// The `BTreeMap` provides correct lexicographic ordering for GETNEXT.
pub struct TestHandler {
    data: Arc<RwLock<BTreeMap<Oid, Value>>>,
}

impl TestHandler {
    /// Create a new handler with initial data.
    pub fn new(initial: BTreeMap<Oid, Value>) -> Self {
        Self {
            data: Arc::new(RwLock::new(initial)),
        }
    }

    /// Create an empty handler.
    pub fn empty() -> Self {
        Self::new(BTreeMap::new())
    }

    /// Get a reference to the data for external access.
    pub fn data(&self) -> Arc<RwLock<BTreeMap<Oid, Value>>> {
        self.data.clone()
    }

    /// Insert or update a value.
    pub fn set(&self, oid: Oid, value: Value) {
        self.data.write().unwrap().insert(oid, value);
    }

    /// Remove a value.
    pub fn remove(&self, oid: &Oid) -> Option<Value> {
        self.data.write().unwrap().remove(oid)
    }

    /// Get a value (cloned).
    pub fn get(&self, oid: &Oid) -> Option<Value> {
        self.data.read().unwrap().get(oid).cloned()
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.data.read().unwrap().len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.data.read().unwrap().is_empty()
    }
}

impl MibHandler for TestHandler {
    fn get<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetResult> {
        let result = match self.data.read().unwrap().get(oid) {
            Some(v) => GetResult::Value(v.clone()),
            None => GetResult::NoSuchInstance,
        };
        Box::pin(async move { result })
    }

    fn get_next<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        oid: &'a Oid,
    ) -> BoxFuture<'a, GetNextResult> {
        let data = self.data.read().unwrap();

        // Find the first OID strictly greater than the requested OID.
        // BTreeMap::range with exclusive start isn't directly available,
        // so we use range(oid..) and skip if equal.
        let result = data
            .range(oid..)
            .find(|(k, _)| *k > oid)
            .map_or(GetNextResult::EndOfMibView, |(k, v)| {
                GetNextResult::Value(VarBind::new(k.clone(), v.clone()))
            });

        Box::pin(async move { result })
    }

    fn test_set<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
        _value: &'a Value,
    ) -> BoxFuture<'a, SetResult> {
        // Accept all SET operations for testing
        Box::pin(async { SetResult::Ok })
    }

    fn commit_set<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        oid: &'a Oid,
        value: &'a Value,
    ) -> BoxFuture<'a, SetResult> {
        self.data
            .write()
            .unwrap()
            .insert(oid.clone(), value.clone());
        Box::pin(async { SetResult::Ok })
    }

    fn undo_set<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
        _value: &'a Value,
    ) -> BoxFuture<'a, SetResult> {
        Box::pin(async { SetResult::Ok })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_snmp::oid;

    #[test]
    fn test_get_existing() {
        let handler = TestHandler::new(
            [(oid!(1, 3, 6, 1), Value::Integer(42))]
                .into_iter()
                .collect(),
        );

        assert_eq!(handler.get(&oid!(1, 3, 6, 1)), Some(Value::Integer(42)));
    }

    #[test]
    fn test_get_missing() {
        let handler = TestHandler::empty();
        assert_eq!(handler.get(&oid!(1, 3, 6, 1)), None);
    }

    #[test]
    fn test_set_and_get() {
        let handler = TestHandler::empty();
        handler.set(oid!(1, 3, 6, 1), Value::Integer(99));
        assert_eq!(handler.get(&oid!(1, 3, 6, 1)), Some(Value::Integer(99)));
    }

    #[tokio::test]
    async fn test_mib_get_existing() {
        let handler = TestHandler::new(
            [(oid!(1, 3, 6, 1), Value::Integer(42))]
                .into_iter()
                .collect(),
        );
        let ctx = RequestContext::test_context();

        let result = MibHandler::get(&handler, &ctx, &oid!(1, 3, 6, 1)).await;
        assert!(matches!(result, GetResult::Value(Value::Integer(42))));
    }

    #[tokio::test]
    async fn test_mib_get_missing() {
        let handler = TestHandler::empty();
        let ctx = RequestContext::test_context();

        let result = MibHandler::get(&handler, &ctx, &oid!(1, 3, 6, 1)).await;
        assert!(matches!(result, GetResult::NoSuchInstance));
    }

    #[tokio::test]
    async fn test_mib_get_next() {
        let handler = TestHandler::new(
            [
                (oid!(1, 3, 6, 1), Value::Integer(1)),
                (oid!(1, 3, 6, 2), Value::Integer(2)),
                (oid!(1, 3, 6, 3), Value::Integer(3)),
            ]
            .into_iter()
            .collect(),
        );
        let ctx = RequestContext::test_context();

        // GETNEXT on 1.3.6.1 should return 1.3.6.2
        let result = MibHandler::get_next(&handler, &ctx, &oid!(1, 3, 6, 1)).await;
        match result {
            GetNextResult::Value(vb) => {
                assert_eq!(vb.oid, oid!(1, 3, 6, 2));
                assert_eq!(vb.value, Value::Integer(2));
            }
            GetNextResult::EndOfMibView => panic!("expected Value, got {result:?}"),
        }
    }

    #[tokio::test]
    async fn test_mib_get_next_end() {
        let handler = TestHandler::new(
            [(oid!(1, 3, 6, 1), Value::Integer(1))]
                .into_iter()
                .collect(),
        );
        let ctx = RequestContext::test_context();

        // GETNEXT on last OID should return EndOfMibView
        let result = MibHandler::get_next(&handler, &ctx, &oid!(1, 3, 6, 1)).await;
        assert!(matches!(result, GetNextResult::EndOfMibView));
    }
}
