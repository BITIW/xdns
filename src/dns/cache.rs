use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::dns::wire;

#[derive(Debug, Clone)]
pub struct DnsCache {
    inner: Arc<Mutex<CacheInner>>,
    max_entries: usize,
    max_ttl: u32,
    negative_ttl: u32,
}

#[derive(Debug)]
struct CacheInner {
    map: HashMap<Vec<u8>, CacheEntry>,
    order: VecDeque<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    expires_at: Instant,
    response: Vec<u8>,
}

impl DnsCache {
    pub fn new(max_entries: usize, max_ttl: u32, negative_ttl: u32) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CacheInner {
                map: HashMap::new(),
                order: VecDeque::new(),
            })),
            max_entries,
            max_ttl,
            negative_ttl,
        }
    }

    pub async fn get(&self, query: &[u8]) -> Option<Vec<u8>> {
        let key = wire::cache_key(query);
        let response_id = wire::query_id(query).unwrap_or_default();

        let mut guard = self.inner.lock().await;
        let entry = guard.map.get(&key).cloned();
        let Some(entry) = entry else {
            return None;
        };

        if entry.expires_at <= Instant::now() {
            guard.map.remove(&key);
            return None;
        }

        let mut response = entry.response;
        wire::set_query_id(&mut response, response_id);
        Some(response)
    }

    pub async fn insert(&self, query: &[u8], response: &[u8]) {
        if self.max_entries == 0 {
            return;
        }

        let ttl = self.compute_ttl(response);
        if ttl == 0 {
            return;
        }

        let key = wire::cache_key(query);
        let mut cached_response = response.to_vec();
        wire::set_query_id(&mut cached_response, 0);

        let expires_at = Instant::now() + Duration::from_secs(ttl as u64);

        let mut guard = self.inner.lock().await;
        guard.map.insert(
            key.clone(),
            CacheEntry {
                expires_at,
                response: cached_response,
            },
        );
        guard.order.push_back(key);

        while guard.map.len() > self.max_entries {
            let Some(oldest_key) = guard.order.pop_front() else {
                break;
            };
            guard.map.remove(&oldest_key);
        }
    }

    fn compute_ttl(&self, response: &[u8]) -> u32 {
        if wire::is_negative_response(response) {
            return self.negative_ttl.min(self.max_ttl).max(1);
        }

        wire::min_ttl(response)
            .unwrap_or(self.max_ttl)
            .min(self.max_ttl)
    }
}
