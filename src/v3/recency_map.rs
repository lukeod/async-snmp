use std::collections::{BTreeSet, HashMap};
use std::hash::Hash;
use std::time::Instant;

#[derive(Debug)]
struct TimedValue<V> {
    value: V,
    updated_at: Instant,
}

/// Capacity-bounded map with an exact, deterministic oldest-update index.
///
/// Each key occurs once in both collections. Refreshing or replacing an entry
/// removes its former index key before inserting the new one, so the auxiliary
/// index cannot accumulate stale records.
#[derive(Debug)]
pub(crate) struct RecencyMap<K, V> {
    entries: HashMap<K, TimedValue<V>>,
    order: BTreeSet<(Instant, K)>,
    capacity: usize,
}

impl<K, V> RecencyMap<K, V>
where
    K: Clone + Eq + Hash + Ord,
{
    pub(crate) fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "RecencyMap capacity must be non-zero");
        Self {
            entries: HashMap::with_capacity(capacity),
            order: BTreeSet::new(),
            capacity,
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    /// Insert or replace an entry, returning the capacity-evicted entry.
    pub(crate) fn insert(&mut self, key: K, value: V, updated_at: Instant) -> Option<(K, V)> {
        if let Some(previous) = self.entries.remove(&key) {
            let removed = self.order.remove(&(previous.updated_at, key.clone()));
            debug_assert!(removed, "entry must have exactly one recency index record");
        }

        let evicted = if self.entries.len() >= self.capacity {
            self.order.pop_first().map(|(_, oldest_key)| {
                let oldest = self
                    .entries
                    .remove(&oldest_key)
                    .expect("recency index key must identify a map entry");
                (oldest_key, oldest.value)
            })
        } else {
            None
        };

        let inserted = self.order.insert((updated_at, key.clone()));
        debug_assert!(inserted, "new entry must have a unique recency index key");
        self.entries.insert(key, TimedValue { value, updated_at });
        debug_assert_eq!(self.entries.len(), self.order.len());
        evicted
    }

    /// Mutate an entry and atomically synchronize its returned update time.
    pub(crate) fn update<R>(
        &mut self,
        key: &K,
        update: impl FnOnce(&mut V) -> (R, Instant),
    ) -> Option<R> {
        let (result, previous_at, updated_at) = {
            let entry = self.entries.get_mut(key)?;
            let previous_at = entry.updated_at;
            let (result, updated_at) = update(&mut entry.value);
            entry.updated_at = updated_at;
            (result, previous_at, updated_at)
        };

        if previous_at != updated_at {
            let removed = self.order.remove(&(previous_at, key.clone()));
            debug_assert!(removed, "entry must have exactly one recency index record");
            let inserted = self.order.insert((updated_at, key.clone()));
            debug_assert!(inserted, "updated entry must have a unique index record");
            debug_assert_eq!(self.entries.len(), self.order.len());
        }
        Some(result)
    }

    #[cfg(test)]
    pub(crate) fn index_len(&self) -> usize {
        self.order.len()
    }

    #[cfg(test)]
    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key).map(|entry| &entry.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn evicts_oldest_with_key_as_deterministic_tie_breaker() {
        let now = Instant::now();
        let mut map = RecencyMap::new(3);
        map.insert(3, "three", now);
        map.insert(1, "one", now);
        map.insert(2, "two", now + Duration::from_nanos(1));

        let evicted = map.insert(4, "four", now + Duration::from_nanos(2));

        assert_eq!(evicted, Some((1, "one")));
        assert!(!map.contains_key(&1));
        assert!(map.contains_key(&3));
        assert_eq!(map.len(), 3);
        assert_eq!(map.index_len(), 3);
    }

    #[test]
    #[should_panic(expected = "RecencyMap capacity must be non-zero")]
    fn zero_capacity_is_rejected() {
        let _ = RecencyMap::<u8, u8>::new(0);
    }

    #[test]
    fn capacity_one_replaces_the_only_entry() {
        let now = Instant::now();
        let mut map = RecencyMap::new(1);
        assert_eq!(map.insert(1, "one", now), None);

        assert_eq!(
            map.insert(2, "two", now + Duration::from_nanos(1)),
            Some((1, "one"))
        );
        assert_eq!(map.len(), 1);
        assert_eq!(map.index_len(), 1);
        assert!(!map.contains_key(&1));
        assert_eq!(map.get(&2), Some(&"two"));
    }

    #[test]
    fn unchanged_authenticated_update_time_does_not_refresh_eviction_order() {
        let now = Instant::now();
        let mut map = RecencyMap::new(2);
        map.insert(1, "one", now);
        map.insert(2, "two", now + Duration::from_nanos(1));

        map.update(&1, |value| (*value, now));
        let evicted = map.insert(3, "three", now + Duration::from_nanos(2));

        assert_eq!(evicted, Some((1, "one")));
        assert!(map.contains_key(&2));
        assert!(map.contains_key(&3));
    }

    #[test]
    fn repeated_refresh_and_replacement_do_not_leave_stale_index_entries() {
        let now = Instant::now();
        let mut map = RecencyMap::new(2);
        map.insert(1, "one", now);

        for offset in 1..=1_000 {
            map.update(&1, |value| (*value, now + Duration::from_nanos(offset)));
        }
        map.insert(1, "replacement", now + Duration::from_secs(1));

        assert_eq!(map.len(), 1);
        assert_eq!(map.index_len(), 1);
        assert_eq!(map.get(&1), Some(&"replacement"));
    }

    #[test]
    fn capacity_is_never_exceeded_under_churn() {
        let now = Instant::now();
        let mut map = RecencyMap::new(8);
        for key in 0..10_000 {
            map.insert(key, key, now + Duration::from_nanos(key));
            assert!(map.len() <= 8);
            assert_eq!(map.len(), map.index_len());
        }
    }

    proptest! {
        #[test]
        fn indexed_map_matches_simple_recency_model(
            capacity in 1_usize..16,
            keys in prop::collection::vec(0_u8..32, 0..2_000),
        ) {
            let start = Instant::now();
            let mut map = RecencyMap::new(capacity);
            let mut model = Vec::<(u8, u64)>::new();

            for (tick, key) in keys.into_iter().enumerate() {
                let tick = tick as u64 + 1;
                let updated_at = start + Duration::from_nanos(tick);
                if map.contains_key(&key) {
                    map.update(&key, |value| (*value, updated_at));
                    model.retain(|(candidate, _)| *candidate != key);
                } else {
                    map.insert(key, key, updated_at);
                    if model.len() >= capacity {
                        let oldest = model
                            .iter()
                            .enumerate()
                            .min_by_key(|(_, (candidate, timestamp))| (*timestamp, *candidate))
                            .map(|(index, _)| index)
                            .unwrap();
                        model.remove(oldest);
                    }
                }
                model.push((key, tick));

                prop_assert_eq!(map.len(), model.len());
                prop_assert_eq!(map.index_len(), model.len());
                for candidate in 0_u8..32 {
                    prop_assert_eq!(
                        map.contains_key(&candidate),
                        model.iter().any(|(key, _)| *key == candidate)
                    );
                }
            }
        }
    }

    #[test]
    fn mutex_serialized_concurrent_churn_keeps_index_bounded_and_exact() {
        let capacity = 64;
        let map = Arc::new(Mutex::new(RecencyMap::new(capacity)));
        let start = Instant::now();
        let workers = (0_u64..8)
            .map(|worker| {
                let map = Arc::clone(&map);
                thread::spawn(move || {
                    for offset in 0_u64..2_000 {
                        let key = worker * 2_000 + offset;
                        let updated_at = start + Duration::from_nanos(key + 1);
                        map.lock().unwrap().insert(key, key, updated_at);
                    }
                })
            })
            .collect::<Vec<_>>();

        for worker in workers {
            worker.join().unwrap();
        }

        let map = map.lock().unwrap();
        assert_eq!(map.len(), capacity);
        assert_eq!(map.index_len(), capacity);
    }
}
